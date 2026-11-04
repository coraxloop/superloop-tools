//! Serialized scan, admission and recovery through the journal/publication interface.
use super::journal::{
    Journal, MAX_LETTER_BYTES, MailError, PRUNE_INTERVAL_SECONDS, Phase, Pins, Record, Result,
    Witness, digest,
};
use super::{
    Address, Outgoing,
    directory::{Actor, Directory, Inventory},
    instant::Instant,
    io, publication, refusal,
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

pub(super) struct Service {
    pub directory: Directory,
    pub journal: Journal,
    last_prune: Monotonic,
    clock: Box<dyn Clock>,
}
impl Service {
    pub fn new(directory: Directory, journal: Journal) -> Self {
        Self {
            directory,
            journal,
            last_prune: Monotonic::now(),
            clock: Box::new(HostClock),
        }
    }
    fn pins(&self, inventory: &Inventory) -> Result<Pins> {
        let mut pins = Pins {
            reservations: self.journal.reservation_pins()?,
            ..Pins::default()
        };
        // Unavailability is not evidence that an active inbox is empty. Only
        // explicit retirement in a fresh trusted configuration releases that pin.
        for record in self.journal.records()? {
            let recipient = Address::parse(&record.recipient)
                .map_err(|_| MailError::Invalid("invalid-directory: journal recipient"))?;
            if record.phase == Phase::Complete
                && !inventory.actors.contains_key(&recipient)
                && !inventory.retired.contains(&recipient)
            {
                pins.active_inboxes.insert(record.delivery);
            }
        }
        for (address, actor) in &inventory.actors {
            if !actor.active {
                continue;
            }
            for name in io::names(&actor.inbox)? {
                let Some(name) = name.to_str() else {
                    continue;
                };
                let Some((_, tail)) = name.split_once('.') else {
                    continue;
                };
                let Some(time) = tail
                    .strip_suffix(".letter")
                    .and_then(|value| Instant::parse(value).ok())
                else {
                    continue;
                };
                if let Ok(record) = self.journal.record(&time)
                    && record.recipient == address.to_string()
                    && record.inbox_name == name
                {
                    pins.active_inboxes.insert(time);
                }
            }
        }
        Ok(pins)
    }
    fn prune(&mut self, inventory: &Inventory) -> Result<()> {
        let pins = self.pins(inventory)?;
        self.journal.prune(&Instant::now()?, &pins)?;
        self.last_prune = Monotonic::now();
        Ok(())
    }
    fn tick(&mut self) -> Result<Instant> {
        let mut waiting = false;
        loop {
            let now = self.clock.now()?;
            match self.journal.check_clock(&now) {
                Ok(()) => return Ok(now),
                Err(MailError::ClockWait) => {
                    if !waiting {
                        writeln!(
                            std::io::stderr().lock(),
                            "mail condition: {}",
                            MailError::ClockWait
                        )?;
                        waiting = true;
                    }
                    if self.last_prune.elapsed() >= Duration::from_secs(PRUNE_INTERVAL_SECONDS) {
                        let inventory = self.directory.inventory()?;
                        self.prune(&inventory)?;
                    }
                    self.clock.wait();
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn recover(&mut self, inventory: &Inventory) -> Result<Vec<String>> {
        let mut failures = Vec::new();
        for (sender, recipient, name) in publication::pending_restorations(&self.journal)? {
            if let Err(error) = self.reconcile(inventory, &sender, &recipient, &name) {
                failures.push(error.to_string());
            }
        }
        for (sender, recipient, name) in publication::pending_preparations(&self.journal)? {
            let accepted = self.journal.records()?.into_iter().any(|record| {
                record.sender == sender.to_string()
                    && record.outgoing == name
                    && record.completed.is_none()
            });
            let result = if accepted {
                publication::reconcile_accepted_preparation(
                    &self.journal,
                    &actor(inventory, &sender)?.endpoint,
                    &actor(inventory, &recipient)?.endpoint,
                    &name,
                )
                .map(|_| ())
            } else {
                self.reconcile(inventory, &sender, &recipient, &name)
            };
            if let Err(error) = result {
                failures.push(error.to_string());
            }
        }
        for record in self
            .journal
            .records()?
            .into_iter()
            .filter(|record| record.completed.is_none())
        {
            if let Err(error) = self.finish(inventory, &record) {
                self.journal.pending(&record.delivery, &error.to_string())?;
                let sender = Address::parse(&record.sender)
                    .map_err(|_| MailError::Invalid("journal sender"))?;
                if let Err(projection) = self.project(
                    actor(inventory, &sender)?,
                    &sender,
                    OsStr::new(&record.outgoing),
                    Some((record.bytes, record.digest.clone())),
                    ("pending-delivery", &error.to_string()),
                    Some(record.delivery.clone()),
                ) {
                    failures.push(projection.to_string());
                }
                failures.push(error.to_string());
            }
        }
        let pending = self
            .journal
            .records()?
            .into_iter()
            .filter(|record| record.completed.is_none())
            .map(|record| (record.sender, record.outgoing))
            .collect::<BTreeSet<_>>();
        for (sender, actor) in &inventory.actors {
            if let Err(error) = refusal::maintain(
                &self.journal,
                &actor.outbox,
                &actor.staging,
                &sender.to_string(),
            ) {
                failures.push(error.to_string());
            }
            for name in io::names(&actor.staging)? {
                if let Some(name) = name.to_str()
                    && let Ok(outgoing) = Outgoing::parse(name)
                    && !pending.contains(&(sender.to_string(), name.to_owned()))
                    && let Err(error) = self.reconcile(inventory, sender, &outgoing.recipient, name)
                {
                    failures.push(error.to_string());
                }
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
        }
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
        )
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
        let inventory = self.directory.inventory()?;
        let mut failures = inventory.failures.clone();
        failures.extend(self.recover(&inventory)?);
        self.prune(&inventory)?;
        let queues = self.candidates(&inventory)?;
        for (sender, name) in schedule(queues) {
            if let Err(error) = self.candidate(&sender, &name) {
                failures.push(format!("{sender}: {error}"));
            }
        }
        Ok(failures)
    }
    fn candidate(&mut self, sender_address: &Address, name: &OsStr) -> Result<()> {
        let inventory = self.directory.inventory()?;
        if self.last_prune.elapsed() >= Duration::from_secs(PRUNE_INTERVAL_SECONDS) {
            self.prune(&inventory)?;
        }
        let sender = actor(&inventory, sender_address)?;
        let observation = observe(sender, name).ok();
        match self.deliver(&inventory, sender_address, name) {
            Ok(()) => Ok(()),
            Err(error) => {
                let accepted = self.journal.records()?.into_iter().find(|record| {
                    record.sender == sender_address.to_string()
                        && Some(record.outgoing.as_str()) == name.to_str()
                        && record.completed.is_none()
                });
                if let Some(record) = accepted {
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
                    {
                        self.reconcile(&inventory, sender_address, &outgoing.recipient, text)?;
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
        }
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
