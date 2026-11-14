//! Serialized scan, admission and recovery through the journal/publication interface.
use super::journal::{
    Journal, MAX_LETTER_BYTES, MailError, PRUNE_INTERVAL_SECONDS, Phase, Pins, Record, Result,
    Witness, digest,
};
use super::{
    Address, Outgoing,
    directory::{Actor, Directory, Inventory},
    instant::Instant,
    io, publication, refusal, retry,
};
use nix::fcntl::{RenameFlags, renameat2};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};
use std::path::Path;
use std::time::{Duration, Instant as Monotonic};

trait Clock {
    fn now(&mut self) -> Result<Instant>;
    fn wait(&mut self);
}
struct HostClock;
impl Clock for HostClock {
    fn now(&mut self) -> Result<Instant> {
        Instant::now()
    }
    fn wait(&mut self) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) enum Wake {
    Scan,
    Retry,
}

pub(super) struct Service {
    pub directory: Directory,
    pub journal: Journal,
    last_prune: Option<Monotonic>,
    clock: Box<dyn Clock>,
    last_scan: Option<Monotonic>,
    retries: retry::Queue,
}
impl Service {
    pub fn new(directory: Directory, journal: Journal) -> Self {
        Self {
            directory,
            journal,
            last_prune: None,
            clock: Box::new(HostClock),
            last_scan: None,
            retries: retry::Queue::default(),
        }
    }
    fn pins(inventory: &Inventory, records: &[Record]) -> Result<Pins> {
        let mut pins = Pins::default();
        // Probe only journalled names. Unrelated inbox history cannot affect retention.
        for record in records {
            let recipient = Address::parse(&record.recipient)
                .map_err(|_| MailError::Invalid("invalid-directory: journal recipient"))?;
            if let Some(actor) = inventory.actors.get(&recipient) {
                if actor.active {
                    match nix::sys::stat::fstatat(
                        &actor.inbox,
                        record.inbox_name.as_str(),
                        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                    ) {
                        Ok(_) => {
                            pins.active_inboxes.insert(record.delivery.clone());
                        }
                        Err(nix::errno::Errno::ENOENT) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            } else if record.phase == Phase::Complete
                && inventory.loops.contains(recipient.loop_name())
                && !inventory.retired.contains(&recipient)
            {
                // Unavailability does not establish that an active inbox is empty.
                pins.active_inboxes.insert(record.delivery.clone());
            }
        }
        Ok(pins)
    }
    fn prune(&mut self, inventory: &Inventory) -> Result<()> {
        self.journal
            .prune_projected(&Instant::now()?, |records| Self::pins(inventory, records))?;
        self.last_prune = Some(Monotonic::now());
        Ok(())
    }
    fn prune_due(&self) -> bool {
        self.last_prune
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(PRUNE_INTERVAL_SECONDS))
    }
    fn maintenance_wait(&self, notifications: &super::notify::Notifications) -> Duration {
        let retention = self.last_prune.map_or(Duration::ZERO, |last| {
            Duration::from_secs(PRUNE_INTERVAL_SECONDS).saturating_sub(last.elapsed())
        });
        if notifications.degraded() {
            retention.min(self.last_scan.map_or(Duration::ZERO, |last| {
                FALLBACK_INTERVAL.saturating_sub(last.elapsed())
            }))
        } else {
            retention
        }
    }
    pub fn wait_for_change(
        &self,
        notifications: &mut super::notify::Notifications,
    ) -> Result<Wake> {
        loop {
            let maintenance = self.maintenance_wait(notifications);
            let wait = self
                .retries
                .wait(Monotonic::now())
                .map_or(maintenance, |retry| retry.min(maintenance));
            for change in notifications.wait(wait)? {
                match change {
                    super::notify::Change::Reconcile => return Ok(Wake::Scan),
                    super::notify::Change::Timer => {
                        if self.maintenance_wait(notifications).is_zero() {
                            return Ok(Wake::Scan);
                        }
                        if self
                            .retries
                            .wait(Monotonic::now())
                            .is_some_and(|wait| wait.is_zero())
                        {
                            return Ok(Wake::Retry);
                        }
                    }
                    super::notify::Change::Outbox(path, sender, name) => {
                        // Ignore only an exact, protected service sidecar. A suffix grants nothing.
                        let recognized = io::absolute(&path, true).and_then(|outbox| {
                            refusal::recognized(&self.journal, &outbox, &sender.to_string(), &name)
                        });
                        if !matches!(recognized, Ok(true)) {
                            return Ok(Wake::Scan);
                        }
                    }
                }
            }
        }
    }
    fn retry_later(&mut self, sender: &Address, name: &OsStr, work: retry::Work) {
        self.retries
            .schedule((sender.clone(), name.to_owned()), work, Monotonic::now());
    }
    /// The retry clock enumerates only due keys, never sender outboxes or a discovery scan.
    pub fn retry_due(&mut self) -> Vec<String> {
        self.retry_due_at(Monotonic::now())
    }
    fn retry_due_at(&mut self, now: Monotonic) -> Vec<String> {
        let mut failures = Vec::new();
        let mut entries = self
            .retries
            .due(now)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for key in retry_order(entries.keys().cloned()) {
            let Some(entry) = entries.remove(&key) else {
                continue;
            };
            let result = self.retry_letter(&key.0, &key.1, &entry.work);
            tracing::debug!(sender = %key.0, letter = %key.1.to_string_lossy(), success = result.is_ok(), "mail retry complete");
            if let Err(error) = result {
                failures.push(format!("{}: {error}", key.0));
                self.retries.failed(key, entry, Monotonic::now());
            } else {
                self.retries.remove(&key);
            }
        }
        failures
    }
    fn retry_letter(&mut self, sender: &Address, name: &OsStr, work: &retry::Work) -> Result<()> {
        match work {
            retry::Work::Accepted(delivery) => {
                let record = self.journal.record(delivery)?;
                if record.completed.is_none() {
                    let inventory = self.directory.inventory()?;
                    let recipient = Address::parse(&record.recipient)
                        .map_err(|_| MailError::Invalid("journal recipient"))?;
                    publication::reconcile_retry_preparation(
                        &self.journal,
                        &actor(&inventory, sender)?.endpoint,
                        &actor(&inventory, &recipient)?.endpoint,
                        &record.outgoing,
                    )?;
                    self.finish(&inventory, &record)?;
                }
                Ok(())
            }
            retry::Work::Restoration(recipient) => {
                let inventory = self.directory.inventory()?;
                let text = name
                    .to_str()
                    .ok_or(MailError::Invalid("restoration name encoding"))?;
                self.reconcile(&inventory, sender, recipient, text)?;
                self.retry_source(sender, name)
            }
            retry::Work::Source => self.retry_source(sender, name),
        }
    }
    fn retry_source(&mut self, sender: &Address, name: &OsStr) -> Result<()> {
        // Presence is only a hint; candidate performs every fresh admission check itself.
        let path = self
            .directory
            .home
            .join(".var/loops")
            .join(sender.relative_mailbox())
            .join("outbox");
        let outbox = io::absolute(&path, true)?;
        match nix::sys::stat::fstatat(&outbox, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(nix::errno::Errno::ENOENT) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => self.candidate(sender, name),
        }
    }
    pub fn scan_watching(
        &mut self,
        notifications: &mut super::notify::Notifications,
    ) -> Result<Vec<String>> {
        let now = Monotonic::now();
        std::thread::sleep(scan_delay(self.last_scan, now));
        self.last_scan = Some(Monotonic::now());
        tracing::debug!("mail scan started");
        notifications.begin_scan();
        self.directory.watch_roots(notifications)?;
        let mut inventory = self.directory.inventory()?;
        // Only configuration needs a second identity check after inventory. Roots were armed first.
        self.directory.watch_configuration(notifications)?;
        let root = self.directory.home.join(".var/loops");
        let mut failures = Vec::new();
        inventory.actors.retain(|address, actor| {
            let mailbox = root.join(address.relative_mailbox());
            let registered = (|| -> Result<()> {
                notifications.path(&mailbox, true)?;
                notifications.add(&mailbox.join("outbox"), &actor.outbox, Some(address.clone()))?;
                notifications.add(&mailbox.join("inbox"), &actor.inbox, None)?;
                notifications.current(&mailbox.join("outbox"), &actor.outbox, true)?;
                notifications.current(&mailbox.join("inbox"), &actor.inbox, true)
            })();
            if let Err(error) = registered {
                tracing::warn!(%address, reason = %error, "mailbox watch registration failed; mailbox skipped");
                failures.push(format!("{address}: notification registration: {error}"));
                false
            } else { true }
        });
        inventory.failures.extend(failures);
        notifications.finish_scan();
        // Arming precedes candidate enumeration, including the first scan after restart.
        let count = inventory.actors.len();
        let result = self.scan_inventory(&inventory);
        drop(inventory);
        tracing::debug!(mailboxes = count, "mail scan complete");
        result
    }
    fn tick(&mut self) -> Result<Instant> {
        let mut waiting = None;
        loop {
            let now = self.clock.now()?;
            match self.journal.check_clock(&now) {
                Ok(()) => {
                    if waiting.is_some() {
                        tracing::info!(now = %now, reserved = ?self.journal.greatest_reserved(), "clock wait left");
                    }
                    return Ok(now);
                }
                Err(MailError::ClockWait) => {
                    if waiting.is_none() {
                        waiting = Some(tracing::info_span!("mail.clock_wait", reserved = ?self.journal.greatest_reserved()).entered());
                        tracing::info!(reserved = ?self.journal.greatest_reserved(), "clock wait entered");
                        writeln!(
                            std::io::stderr().lock(),
                            "mail condition: {}",
                            MailError::ClockWait
                        )?;
                    }
                    if self.last_prune.is_some() && self.prune_due() {
                        let inventory = self.directory.inventory()?;
                        self.prune(&inventory)?;
                    }
                    tracing::trace!(now = %now, "clock wait tick");
                    self.clock.wait();
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn recover(&mut self, inventory: &Inventory) -> Result<Vec<String>> {
        let mut failures = Vec::new();
        for (sender, recipient, name) in publication::pending_restorations(&self.journal)? {
            let _span = tracing::info_span!("mail.recover_restoration", %sender, %recipient, letter = %name).entered();
            if let Err(error) = self.reconcile(inventory, &sender, &recipient, &name) {
                self.retry_later(
                    &sender,
                    OsStr::new(&name),
                    retry::Work::Restoration(recipient.clone()),
                );
                tracing::warn!(reason = %error, "recovery failed");
                failures.push(error.to_string());
            }
        }
        for (sender, recipient, name) in publication::pending_preparations(&self.journal)? {
            let _span = tracing::info_span!("mail.recover_preparation", %sender, %recipient, letter = %name).entered();
            let accepted = self.journal.records()?.into_iter().find(|record| {
                record.sender == sender.to_string()
                    && record.outgoing == name
                    && record.completed.is_none()
            });
            let result = (|| -> Result<()> {
                if accepted.is_some() {
                    publication::reconcile_accepted_preparation(
                        &self.journal,
                        &actor(inventory, &sender)?.endpoint,
                        &actor(inventory, &recipient)?.endpoint,
                        &name,
                    )
                    .map(|_| ())
                } else {
                    self.reconcile(inventory, &sender, &recipient, &name)
                }
            })();
            if let Err(error) = result {
                let work = accepted.map_or_else(
                    || retry::Work::Restoration(recipient.clone()),
                    |record| retry::Work::Accepted(record.delivery),
                );
                self.retry_later(&sender, OsStr::new(&name), work);
                tracing::warn!(reason = %error, "recovery failed");
                failures.push(error.to_string());
            }
        }
        failures.extend(self.recover_accepted(inventory)?);
        let pending = self
            .journal
            .records()?
            .into_iter()
            .filter(|record| record.completed.is_none())
            .map(|record| (record.sender, record.outgoing))
            .collect::<BTreeSet<_>>();
        for (sender, actor) in &inventory.actors {
            if let Err(error) = refusal::maintain_pending(
                &self.journal,
                &actor.outbox,
                &actor.staging,
                &sender.to_string(),
                &pending,
            ) {
                tracing::warn!(%sender, reason = %error, "refusal maintenance failed");
                failures.push(error.to_string());
            }
            for name in io::names(&actor.staging)? {
                if let Some(name) = name.to_str()
                    && let Ok(outgoing) = Outgoing::parse(name)
                    && !pending.contains(&(sender.to_string(), name.to_owned()))
                    && let Err(error) = self.reconcile(inventory, sender, &outgoing.recipient, name)
                {
                    self.retry_later(
                        sender,
                        OsStr::new(name),
                        retry::Work::Restoration(outgoing.recipient.clone()),
                    );
                    tracing::warn!(%sender, recipient = %outgoing.recipient, letter = %name, reason = %error, "recovery failed");
                    failures.push(error.to_string());
                }
            }
        }
        Ok(failures)
    }
    fn recover_accepted(&mut self, inventory: &Inventory) -> Result<Vec<String>> {
        let mut failures = Vec::new();
        for record in self
            .journal
            .records()?
            .into_iter()
            .filter(|record| record.completed.is_none())
        {
            let _span = tracing::info_span!("mail.recover_publication", sender = %record.sender, recipient = %record.recipient, letter = %record.outgoing, delivery = %record.delivery).entered();
            tracing::info!("recovering pending publication");
            if let Err(error) = self.finish(inventory, &record) {
                tracing::warn!(reason = %error, "publication remains pending");
                self.journal.pending(&record.delivery, &error.to_string())?;
                let sender = Address::parse(&record.sender)
                    .map_err(|_| MailError::Invalid("journal sender"))?;
                self.retry_later(
                    &sender,
                    OsStr::new(&record.outgoing),
                    retry::Work::Accepted(record.delivery.clone()),
                );
                if let Err(projection) = (|| -> Result<()> {
                    self.project(
                        actor(inventory, &sender)?,
                        &sender,
                        OsStr::new(&record.outgoing),
                        Some((record.bytes, record.digest.clone())),
                        ("pending-delivery", &error.to_string()),
                        Some(record.delivery.clone()),
                    )
                })() {
                    failures.push(projection.to_string());
                }
                failures.push(error.to_string());
            }
        }
        Ok(failures)
    }
    fn reconcile(
        &mut self,
        inventory: &Inventory,
        sender: &Address,
        recipient: &Address,
        name: &str,
    ) -> Result<()> {
        let _span =
            tracing::info_span!("mail.reconcile", %sender, %recipient, letter = %name).entered();
        let sender = actor(inventory, sender)?;
        let recipient = actor(inventory, recipient)?;
        publication::reconcile_unpublished(
            &mut self.journal,
            &sender.endpoint,
            &recipient.endpoint,
            name,
        )
    }
    fn finish(&mut self, inventory: &Inventory, record: &Record) -> Result<()> {
        let _span = tracing::info_span!("mail.finish", sender = %record.sender, recipient = %record.recipient, letter = %record.outgoing, delivery = %record.delivery).entered();
        let sender_address =
            Address::parse(&record.sender).map_err(|_| MailError::Invalid("journal sender"))?;
        let recipient_address = Address::parse(&record.recipient)
            .map_err(|_| MailError::Invalid("journal recipient"))?;
        let sender = actor(inventory, &sender_address)?;
        let recipient = actor(inventory, &recipient_address)?;
        if record.phase == Phase::Discarded {
            publication::discard(
                &mut self.journal,
                &sender.endpoint,
                &recipient.endpoint,
                &record.delivery,
            )?;
            self.project(
                sender,
                &sender_address,
                OsStr::new(&record.outgoing),
                Some((record.bytes, record.digest.clone())),
                (
                    "io-failure",
                    record
                        .discard_disposition
                        .as_deref()
                        .unwrap_or("discarded transport"),
                ),
                None,
            )?;
            self.journal
                .finish_discard(&record.delivery, Instant::now()?)?;
        } else {
            publication::publish(
                &mut self.journal,
                &sender.endpoint,
                &recipient.endpoint,
                &record.delivery,
            )?;
            let current = self.journal.record(&record.delivery)?;
            publication::cleanup_source(&sender.endpoint, &recipient.endpoint, &current)?;
            refusal::clear(
                &self.journal,
                &sender.outbox,
                &sender.staging,
                &record.sender,
                OsStr::new(&record.outgoing),
            )?;
            self.journal.advance(
                &record.delivery,
                Phase::Complete,
                &Witness::Absent,
                Instant::now()?,
            )?;
            tracing::info!(delivered = 1, "letter delivered");
        }
        self.retries
            .remove(&(sender_address, OsString::from(&record.outgoing)));
        Ok(())
    }
    fn project(
        &self,
        actor: &Actor,
        sender: &Address,
        name: &OsStr,
        observation: Option<(u64, String)>,
        diagnostic: (&str, &str),
        delivery: Option<Instant>,
    ) -> Result<()> {
        let recipient = name
            .to_str()
            .and_then(|name| Outgoing::parse(name).ok())
            .map(|outgoing| outgoing.recipient.to_string());
        let _span = tracing::info_span!("mail.refusal", %sender, recipient = recipient.as_deref(), letter = %name.to_string_lossy(), code = diagnostic.0).entered();
        refusal::project(
            &self.journal,
            &actor.outbox,
            &actor.staging,
            refusal::Projection {
                sender: &sender.to_string(),
                name,
                group: actor.group,
                observation,
                code: diagnostic.0,
                reason: diagnostic.1,
                now: Instant::now()?,
                delivery,
                staging_bytes: publication::staging_bytes(
                    &self
                        .directory
                        .inventory()?
                        .actors
                        .values()
                        .map(|actor| &actor.endpoint)
                        .collect::<Vec<_>>(),
                )?,
            },
        )?;
        if diagnostic.0 == "pending-delivery" {
            tracing::warn!(
                pending = 1,
                code = diagnostic.0,
                reason = diagnostic.1,
                "letter pending"
            );
        } else {
            tracing::warn!(
                refused = 1,
                code = diagnostic.0,
                reason = diagnostic.1,
                "letter refused"
            );
        }
        Ok(())
    }
    fn candidates(&self, inventory: &Inventory) -> Result<BTreeMap<Address, VecDeque<OsString>>> {
        let mut queues = BTreeMap::new();
        for (sender, actor) in &inventory.actors {
            if !actor.active {
                continue;
            }
            let mut names = Vec::new();
            for name in io::names(&actor.outbox)? {
                if !refusal::recognized(&self.journal, &actor.outbox, &sender.to_string(), &name)? {
                    names.push(name);
                }
            }
            names.sort_by_cached_key(|name| sort_key(name));
            queues.insert(sender.clone(), names.into());
        }
        Ok(queues)
    }
    /// One finite round-robin scan; arrivals during it wait for the next call.
    pub fn scan(&mut self) -> Result<Vec<String>> {
        let _span = tracing::trace_span!("mail.scan").entered();
        let inventory = self.directory.inventory()?;
        self.scan_inventory(&inventory)
    }
    fn scan_inventory(&mut self, inventory: &Inventory) -> Result<Vec<String>> {
        let mut failures = inventory.failures.clone();
        failures.extend(self.recover(inventory)?);
        if self.prune_due() {
            self.prune(inventory)?;
        }
        let queues = self.candidates(inventory)?;
        for (sender, name) in schedule(queues) {
            if let Err(error) = self.candidate(&sender, &name) {
                failures.push(format!("{sender}: {error}"));
            }
        }
        Ok(failures)
    }
    fn candidate(&mut self, sender_address: &Address, name: &OsStr) -> Result<()> {
        let result = self.try_candidate(sender_address, name);
        if result.as_ref().is_err_and(timed_retry) {
            self.retry_later(sender_address, name, retry::Work::Source);
        } else if result.is_ok() {
            self.retries
                .remove(&(sender_address.clone(), name.to_owned()));
        }
        result
    }
    fn try_candidate(&mut self, sender_address: &Address, name: &OsStr) -> Result<()> {
        let recipient = name
            .to_str()
            .and_then(|name| Outgoing::parse(name).ok())
            .map(|outgoing| outgoing.recipient.to_string());
        let _span = tracing::info_span!("mail.delivery", sender = %sender_address, recipient = recipient.as_deref(), letter = %name.to_string_lossy()).entered();
        let inventory = self.directory.inventory()?;
        if self.prune_due() {
            self.prune(&inventory)?;
        }
        let sender = actor(&inventory, sender_address)?;
        let observation = observe(sender, name).ok();
        match self.deliver(&inventory, sender_address, name) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.refuse_candidate(&inventory, sender_address, name, observation, error)
            }
        }
    }
    fn refuse_candidate(
        &mut self,
        inventory: &Inventory,
        sender_address: &Address,
        name: &OsStr,
        observation: Option<(u64, String)>,
        error: MailError,
    ) -> Result<()> {
        let sender = actor(inventory, sender_address)?;
        let accepted = self.journal.records()?.into_iter().find(|record| {
            record.sender == sender_address.to_string()
                && Some(record.outgoing.as_str()) == name.to_str()
                && record.completed.is_none()
        });
        if let Some(record) = accepted {
            self.retry_later(
                sender_address,
                name,
                retry::Work::Accepted(record.delivery.clone()),
            );
            self.journal.pending(&record.delivery, &error.to_string())?;
            self.project(
                sender,
                sender_address,
                name,
                Some((record.bytes, record.digest)),
                ("pending-delivery", &error.to_string()),
                Some(record.delivery),
            )?;
        } else {
            if let Some(text) = name.to_str()
                && let Ok(outgoing) = Outgoing::parse(text)
                && inventory.actors.contains_key(&outgoing.recipient)
                && nix::sys::stat::fstatat(
                    &sender.staging,
                    text,
                    nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .is_ok()
                && let Err(error) =
                    self.reconcile(inventory, sender_address, &outgoing.recipient, text)
            {
                self.retry_later(
                    sender_address,
                    name,
                    retry::Work::Restoration(outgoing.recipient),
                );
                return Err(error);
            }
            self.project(
                sender,
                sender_address,
                name,
                observation,
                (refusal::code(&error), &error.to_string()),
                None,
            )?;
        }
        Err(error)
    }
    fn deliver(
        &mut self,
        inventory: &Inventory,
        sender_address: &Address,
        name: &OsStr,
    ) -> Result<()> {
        let text = name.to_str().ok_or(MailError::Invalid(
            "invalid-name: outgoing filename is not UTF-8",
        ))?;
        let outgoing = Outgoing::parse(text)
            .map_err(|_| MailError::Invalid("invalid-name: outgoing filename"))?;
        let decision = self
            .directory
            .decision(sender_address, &outgoing.recipient)?;
        let sender = actor(inventory, sender_address)?;
        let recipient = actor(inventory, &outgoing.recipient)?;
        self.prune(inventory)?;
        self.journal.capacity(publication::staging_bytes(
            &inventory
                .actors
                .values()
                .map(|actor| &actor.endpoint)
                .collect::<Vec<_>>(),
        )?)?;
        let (original, observed) = observe_file(sender, name)?;
        let original_info = original.metadata()?;
        let identity = super::journal::Identity {
            device: original_info.dev(),
            inode: original_info.ino(),
        };
        refusal::clear(
            &self.journal,
            &sender.outbox,
            &sender.staging,
            &sender_address.to_string(),
            name,
        )?;
        renameat2(
            &sender.outbox,
            name,
            &sender.staging,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )?;
        sender.outbox.sync_all()?;
        sender.staging.sync_all()?;
        let prepared =
            publication::prepare(&self.journal, &sender.endpoint, &recipient.endpoint, text)?;
        if !prepared.matches_source(&identity, observed.0, &observed.1) {
            return Err(MailError::Invalid(
                "changed-source: snapshot differs from inspected submission",
            ));
        }
        let now = self.tick()?;
        decision.current()?;
        let configs = decision.digests();
        let record = prepared.accept(&mut self.journal, now, decision.registry_digest, configs)?;
        self.finish(inventory, &record)
    }
}
/// Whether a failed attempt can clear without a watched change and so joins the retry clock.
/// The listed refusals clear only by the sender's own edit or a watched authorization change,
/// either of which wakes the scan that retries the letter; a timer would repeat the refusal.
fn timed_retry(error: &MailError) -> bool {
    !matches!(
        refusal::code(error),
        "invalid-name"
            | "invalid-file"
            | "oversize"
            | "unknown-recipient"
            | "retired-worker"
            | "outside-estate"
            | "not-whitelisted"
            | "unsafe-storage"
    )
}
const FALLBACK_INTERVAL: Duration = Duration::from_secs(5);
const SCAN_GAP: Duration = Duration::from_millis(250);
fn scan_delay(last: Option<Monotonic>, now: Monotonic) -> Duration {
    last.map_or(Duration::ZERO, |last| {
        SCAN_GAP.saturating_sub(now.saturating_duration_since(last))
    })
}

fn actor<'a>(inventory: &'a Inventory, address: &Address) -> Result<&'a Actor> {
    inventory.actors.get(address).ok_or_else(|| {
        MailError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("unavailable endpoint {address}"),
        ))
    })
}
fn observe(actor: &Actor, name: &OsStr) -> Result<(u64, String)> {
    observe_file(actor, name).map(|(_, observation)| observation)
}
fn observe_file(actor: &Actor, name: &OsStr) -> Result<(std::fs::File, (u64, String))> {
    let observed = nix::sys::stat::fstatat(
        &actor.outbox,
        name,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )?;
    if observed.st_mode & libc::S_IFMT != libc::S_IFREG || observed.st_nlink != 1 {
        return Err(MailError::Invalid(
            "invalid-file: single-link regular submission required",
        ));
    }
    let file = io::child(&actor.outbox, Path::new(name), false)?;
    if file.metadata()?.uid() != actor.uid {
        return Err(MailError::Invalid("unsafe-storage: submitted source owner"));
    }
    let info = file.metadata()?;
    if info.dev() != observed.st_dev || info.ino() != observed.st_ino {
        return Err(MailError::Invalid(
            "changed-source: outbox entry replaced during inspection",
        ));
    }
    let bytes = io::bounded(&file, MAX_LETTER_BYTES)?;
    Ok((file, (bytes.len() as u64, digest(&bytes))))
}
fn retry_order(keys: impl IntoIterator<Item = retry::Key>) -> Vec<retry::Key> {
    let mut queues = BTreeMap::<Address, VecDeque<OsString>>::new();
    for (sender, name) in keys {
        queues.entry(sender).or_default().push_back(name);
    }
    for names in queues.values_mut() {
        names
            .make_contiguous()
            .sort_by_cached_key(|name| sort_key(name));
    }
    schedule(queues)
}
fn sort_key(name: &OsStr) -> (Vec<u8>, Vec<u8>) {
    name.to_str()
        .and_then(|name| Outgoing::parse(name).ok())
        .map_or_else(
            || (Vec::new(), name.as_bytes().to_vec()),
            |outgoing| {
                (
                    outgoing.slug.into_bytes(),
                    outgoing.recipient.to_string().into_bytes(),
                )
            },
        )
}

fn schedule(mut queues: BTreeMap<Address, VecDeque<OsString>>) -> Vec<(Address, OsString)> {
    let mut result = Vec::new();
    while queues.values().any(|queue| !queue.is_empty()) {
        for (sender, queue) in &mut queues {
            if let Some(name) = queue.pop_front() {
                result.push((sender.clone(), name));
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_runtime_tests.rs"]
mod runtime_tests;
