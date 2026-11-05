//! Filesystem half of ``req:mail:inbox-publication``.
//!
//! Journal state precedes
//! publication; the recipient temporary disappears only by inbox rename or a
//! durable discard. Provisioning supplies the isolated endpoint identities.

use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use nix::fcntl::{AtFlags, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, UnlinkatFlags, fchown, geteuid, linkat, unlinkat};

use serde::{Deserialize, Serialize};

use super::instant::Instant;
use super::journal::{
    Identity, Journal, MAX_LETTER_BYTES, MailError, Phase, Record, Recovery, Result, Temporary,
    Witness, digest, recover,
};
use super::{Address, Outgoing, store};

/// Provisioner's declaration of the backing filesystem's crash guarantees.
///
/// Successful syscalls alone cannot certify power-loss behavior; every operation
/// also checks its actual sync/rename results and refuses unsupported operations.
#[derive(Clone, Copy, Debug)]
pub struct Durability {
    /// Atomic rename remains crash consistent on this backing filesystem.
    pub crash_consistent_rename: bool,
    /// File and directory synchronization provide durable publication ordering.
    pub durable_sync: bool,
}

fn identity(info: &Metadata) -> Identity {
    Identity {
        device: info.dev(),
        inode: info.ino(),
    }
}
fn child(parent: &File, name: &str, directory: bool) -> Result<File> {
    Ok(File::from(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(
                OFlag::O_RDONLY
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NONBLOCK
                    | if directory {
                        OFlag::O_DIRECTORY
                    } else {
                        OFlag::empty()
                    },
            )
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
fn absolute_directory(path: &Path) -> Result<File> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| MailError::Invalid("absolute endpoint root required"))?;
    Ok(File::from(openat2(
        File::open("/")?,
        relative,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
fn component(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.contains('/')
    {
        return Err(MailError::Invalid("invalid staging component"));
    }
    Ok(())
}

fn mailbox_custody(mailbox: &File, actor_group: u32) -> Result<()> {
    let info = mailbox.metadata()?;
    if info.uid() != geteuid().as_raw()
        || info.gid() != actor_group
        || info.mode() & 0o027 != 0
        || info.mode() & 0o010 == 0
    {
        return Err(MailError::Invalid("unsafe-storage: mailbox root custody"));
    }
    Ok(())
}

fn retired_mailbox_custody(mailbox: &File) -> Result<()> {
    let info = mailbox.metadata()?;
    if info.uid() != geteuid().as_raw()
        || info.gid() != geteuid().as_raw()
        || info.mode() & 0o7777 != 0o700
    {
        return Err(MailError::Invalid(
            "unsafe-storage: retired mailbox root custody",
        ));
    }
    Ok(())
}

fn publication_custody(directory: &File, actor_group: u32, device: u64) -> Result<()> {
    let observed = directory.metadata()?;
    if observed.uid() != geteuid().as_raw()
        || observed.gid() != actor_group
        || observed.mode() & 0o777 != 0o770
        || observed.dev() != device
    {
        return Err(MailError::Invalid(
            "unsafe-storage: publication directory custody or filesystem",
        ));
    }
    Ok(())
}

/// Pinned service publication directories for one registered actor.
///
/// Actor identity
/// allocation, ACL provisioning and directory registry freshness belong to the
/// provisioner and admission service, not to a body or an outgoing filename.
pub struct Endpoint {
    retired: bool,
    address: Address,
    group: u32,
    mailbox_path: PathBuf,
    staging_path: PathBuf,
    inbox: File,
    sent: File,
    outbox: File,
    staging: File,
}

impl Endpoint {
    /// Open the exact service-owned publication tree and same-filesystem staging.
    ///
    /// # Errors
    /// Refuses undeclared durability, symlinks, wrong custody/modes and cross-device staging.
    pub fn open(
        loops_root: &Path,
        address: Address,
        actor_group: u32,
        durability: Durability,
    ) -> Result<Self> {
        Self::open_with(loops_root, address, actor_group, durability, false)
    }

    pub(super) fn open_retired(
        loops_root: &Path,
        address: Address,
        actor_group: u32,
        durability: Durability,
    ) -> Result<Self> {
        if address.worker().is_none() {
            return Err(MailError::Invalid(
                "unsafe-storage: retired worker endpoint required",
            ));
        }
        Self::open_with(loops_root, address, actor_group, durability, true)
    }

    fn open_with(
        loops_root: &Path,
        address: Address,
        actor_group: u32,
        durability: Durability,
        retired: bool,
    ) -> Result<Self> {
        if !durability.crash_consistent_rename || !durability.durable_sync {
            return Err(MailError::Invalid(
                "unsafe-storage: durability is not established",
            ));
        }
        let root = absolute_directory(loops_root)?;
        let mailbox_path = loops_root.join(address.relative_mailbox());
        let staging_path = mailbox_path
            .parent()
            .ok_or(MailError::Invalid("endpoint parent"))?
            .join(".mail-staging");
        let mailbox = address.open_mailbox(&root)?;
        if retired {
            retired_mailbox_custody(&mailbox)?;
        } else {
            mailbox_custody(&mailbox, actor_group)?;
        }
        let inbox = child(&mailbox, "inbox", true)?;
        let sent = child(&mailbox, "sent", true)?;
        let outbox = child(&mailbox, "outbox", true)?;
        let staging = absolute_directory(&staging_path)?;
        store::private(&staging, true)?;
        for directory in [&inbox, &sent] {
            publication_custody(directory, actor_group, staging.metadata()?.dev())?;
            directory.sync_all()?;
        }
        staging.sync_all()?;
        Ok(Self {
            retired,
            address,
            group: actor_group,
            mailbox_path,
            staging_path,
            inbox,
            sent,
            outbox,
            staging,
        })
    }

    fn fresh(&self) -> Result<()> {
        let mailbox = absolute_directory(&self.mailbox_path)?;
        if self.retired {
            retired_mailbox_custody(&mailbox)?;
        } else {
            mailbox_custody(&mailbox, self.group)?;
        }
        store::private(&self.staging, true)?;
        for directory in [&self.inbox, &self.sent] {
            publication_custody(directory, self.group, self.staging.metadata()?.dev())?;
        }
        for (name, pinned) in [
            ("inbox", &self.inbox),
            ("sent", &self.sent),
            ("outbox", &self.outbox),
        ] {
            if identity(&child(&mailbox, name, true)?.metadata()?) != identity(&pinned.metadata()?)
            {
                return Err(MailError::Invalid("endpoint identity changed"));
            }
        }
        if identity(&absolute_directory(&self.staging_path)?.metadata()?)
            != identity(&self.staging.metadata()?)
        {
            return Err(MailError::Invalid("staging identity changed"));
        }
        Ok(())
    }

    fn temporary(&self, name: &str, bytes: &[u8]) -> Result<Temporary> {
        component(name)?;
        let mut file = File::from(openat2(
            &self.staging,
            name,
            OpenHow::new()
                .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?);
        #[cfg(test)]
        boundary(1)?;
        file.write_all(bytes)?;
        fchown(&file, None, Some(Gid::from_raw(self.group)))?;
        fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP)?;
        #[cfg(test)]
        boundary(2)?;
        file.sync_all()?;
        #[cfg(test)]
        boundary(3)?;
        self.staging.sync_all()?;
        #[cfg(test)]
        boundary(4)?;
        Ok(Temporary {
            path: self
                .staging_path
                .join(name)
                .to_str()
                .ok_or(MailError::Invalid("endpoint path encoding"))?
                .to_owned(),
            identity: identity(&file.metadata()?),
        })
    }

    fn temporary_name<'a>(&self, temporary: &'a Temporary) -> Result<&'a str> {
        let path = Path::new(&temporary.path);
        if path.parent() != Some(self.staging_path.as_path()) {
            return Err(MailError::Invalid("temporary belongs to another endpoint"));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(MailError::Invalid("temporary name encoding"))?;
        component(name)?;
        Ok(name)
    }

    fn payload(
        &self,
        directory: &File,
        name: &str,
        expected: &Identity,
        record: &Record,
    ) -> Result<File> {
        let mut file = child(directory, name, false)?;
        let info = file.metadata()?;
        if !info.is_file()
            || identity(&info) != *expected
            || info.uid() != geteuid().as_raw()
            || info.gid() != self.group
            || info.mode() & 0o777 != 0o640
            || info.len() != record.bytes
        {
            return Err(MailError::Invalid(
                "mismatched publication identity or permissions",
            ));
        }
        let bytes = bounded(&mut file)?;
        if digest(&bytes) != record.digest {
            return Err(MailError::Invalid("mismatched publication digest"));
        }
        Ok(file)
    }

    /// Observe the protected recipient temporary; the inbox pathname is not read.
    ///
    /// # Errors
    /// Refuses changed endpoint identity or a record pointing outside this staging root.
    pub fn witness(&self, record: &Record) -> Result<Witness> {
        self.fresh()?;
        let name = self.temporary_name(&record.recipient_temporary)?;
        match self.payload(
            &self.staging,
            name,
            &record.recipient_temporary.identity,
            record,
        ) {
            Ok(_) => Ok(Witness::Present {
                identity: record.recipient_temporary.identity.clone(),
                bytes: record.bytes,
                digest: record.digest.clone(),
            }),
            Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(Witness::Absent)
            }
            Err(_) => Ok(Witness::Invalid),
        }
    }
}

fn bounded(file: &mut File) -> Result<Vec<u8>> {
    file.rewind()?;
    let mut bytes = Vec::new();
    file.take(MAX_LETTER_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LETTER_BYTES {
        return Err(MailError::Invalid("oversize"));
    }
    Ok(bytes)
}
fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    identity(before) == identity(after)
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

/// Synced immutable snapshots that are not deliveries until journal acceptance.
///
/// Dropping this value never deletes payloads: interrupted acceptance is reconciled
/// against the journal and recoverable source at startup.
pub struct Prepared {
    sender: String,
    recipient: String,
    outgoing: String,
    preparation: String,
    journal_identity: Identity,
    bytes: u64,
    digest: String,
    source_path: String,
    source_identity: Identity,
    recipient_temporary: Temporary,
    sender_temporary: Option<Temporary>,
}
impl Prepared {
    pub(super) fn matches_source(&self, identity: &Identity, bytes: u64, digest: &str) -> bool {
        self.source_identity == *identity && self.bytes == bytes && self.digest == digest
    }

    /// Reserve actual UTC and durably accept metadata after both snapshots sync.
    ///
    /// # Errors
    /// Refuses clock rollback, journal capacity, duplicate acceptance or invalid metadata.
    pub fn accept(
        self,
        journal: &mut Journal,
        now: Instant,
        registry_digest: String,
        configuration_digests: Vec<String>,
    ) -> Result<Record> {
        if identity(&journal.publication_root().metadata()?) != self.journal_identity {
            return Err(MailError::Invalid("preparation belongs to another journal"));
        }
        let delivery = journal.reserve(now)?;
        let record = Record {
            version: 1,
            acceptance: delivery.clone(),
            sent_name: format!("{}.{}.letter", self.recipient, delivery),
            inbox_name: format!("{}.{}.letter", self.sender, delivery),
            delivery,
            sender: self.sender,
            recipient: self.recipient,
            outgoing: self.outgoing,
            bytes: self.bytes,
            digest: self.digest,
            registry_digest,
            configuration_digests,
            source_path: self.source_path,
            source_identity: self.source_identity,
            recipient_temporary: self.recipient_temporary,
            sender_temporary: self.sender_temporary,
            phase: Phase::Accepted,
            completed: None,
            pending_error: None,
            discard_disposition: None,
        };
        journal.accept(&record)?;
        #[cfg(test)]
        boundary(17)?;
        store::remove(journal.publication_root(), &self.preparation)?;
        Ok(record)
    }
}

/// Snapshot a claimed source under its exact outgoing basename in sender staging.
///
/// The admission service claims it only after reserving capacity for all copies.
/// Deterministic private snapshot names preserve source mapping before acceptance.
///
/// # Errors
/// Refuses changed/nonregular/multiply-linked/oversized sources, unsafe endpoints,
/// occupied staging names and permissions or durability failures.
pub fn prepare(
    journal: &Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
) -> Result<Prepared> {
    sender.fresh()?;
    recipient.fresh()?;
    let parsed = Outgoing::parse(outgoing).map_err(|_| MailError::Invalid("invalid-name"))?;
    if parsed.recipient != recipient.address {
        return Err(MailError::Invalid("recipient binding"));
    }
    if sender.group == recipient.group && sender.address != recipient.address {
        return Err(MailError::Invalid("peer actors share a mailbox group"));
    }
    let mut source = child(&sender.staging, outgoing, false)?;
    let before = source.metadata()?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(MailError::Invalid("invalid-file"));
    }
    if before.len() > MAX_LETTER_BYTES {
        return Err(MailError::Invalid("oversize"));
    }
    let bytes = bounded(&mut source)?;
    #[cfg(test)]
    boundary(0)?;
    if !unchanged(&before, &source.metadata()?) {
        return Err(MailError::Invalid("changed-source"));
    }
    let records = journal.records()?;
    if records.iter().any(|record| {
        record.sender == sender.address.to_string()
            && record.outgoing == outgoing
            && record.completed.is_none()
    }) || preparation_names(journal, sender, recipient, outgoing)?.is_some()
    {
        return Err(MailError::Invalid("source preparation requires recovery"));
    }
    let preparation = allocate_preparation(
        journal,
        sender,
        recipient,
        outgoing,
        &identity(&before),
        &records,
    )?;
    let (snapshot_name, copy_name) = preparation_names(journal, sender, recipient, outgoing)?
        .ok_or(MailError::Invalid("missing preparation intent"))?;
    let receiver = recipient.temporary(&snapshot_name, &bytes)?;
    let shared = sender.group == recipient.group
        && sender.staging.metadata()?.dev() == recipient.staging.metadata()?.dev();
    let copy = if shared {
        None
    } else {
        Some(sender.temporary(&copy_name, &bytes)?)
    };
    Ok(Prepared {
        sender: sender.address.to_string(),
        recipient: recipient.address.to_string(),
        outgoing: outgoing.to_owned(),
        preparation,
        journal_identity: identity(&journal.publication_root().metadata()?),
        bytes: bytes.len() as u64,
        digest: digest(&bytes),
        source_path: sender
            .staging_path
            .join(outgoing)
            .to_str()
            .ok_or(MailError::Invalid("source path encoding"))?
            .to_owned(),
        source_identity: identity(&before),
        recipient_temporary: receiver,
        sender_temporary: copy,
    })
}

fn bindings(sender: &Endpoint, recipient: &Endpoint, record: &Record) -> Result<()> {
    record.validate()?;
    sender.fresh()?;
    recipient.fresh()?;
    if record.sender != sender.address.to_string()
        || record.recipient != recipient.address.to_string()
        || Path::new(&record.source_path) != sender.staging_path.join(&record.outgoing)
    {
        return Err(MailError::Invalid("transaction endpoint binding"));
    }
    recipient.temporary_name(&record.recipient_temporary)?;
    if let Some(temporary) = &record.sender_temporary {
        sender.temporary_name(temporary)?;
    }
    Ok(())
}

fn sent(sender: &Endpoint, recipient: &Endpoint, record: &Record) -> Result<()> {
    if let Some(temporary) = &record.sender_temporary {
        let name = sender.temporary_name(temporary)?;
        match sender.payload(&sender.staging, name, &temporary.identity, record) {
            Ok(file) => {
                file.sync_all()?;
                renameat2(
                    &sender.staging,
                    name,
                    &sender.sent,
                    record.sent_name.as_str(),
                    RenameFlags::RENAME_NOREPLACE,
                )?;
            }
            Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                // This journaled sender temporary is removed only by this rename
                // (or a durable discard, which never reaches this branch).
            }
            Err(error) => return Err(error),
        }
    } else {
        if sender.group != recipient.group
            || sender.address != recipient.address
            || sender.staging.metadata()?.dev() != recipient.staging.metadata()?.dev()
        {
            return Err(MailError::Invalid(
                "shared inode cannot satisfy actor read permissions",
            ));
        }
        let name = recipient.temporary_name(&record.recipient_temporary)?;
        match linkat(
            &recipient.staging,
            name,
            &sender.sent,
            record.sent_name.as_str(),
            AtFlags::empty(),
        ) {
            Ok(()) => (),
            Err(nix::errno::Errno::EEXIST) => {
                sender.payload(
                    &sender.sent,
                    &record.sent_name,
                    &record.recipient_temporary.identity,
                    record,
                )?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(test)]
    boundary(5)?;
    sender.sent.sync_all()?;
    sender.staging.sync_all()?;
    #[cfg(test)]
    boundary(6)?;
    Ok(())
}

/// Resume accepted publication behind the journal interface, stopping at phase
/// `inbox`.
///
/// The service then cleans the claimed source and refusal sidecar and
/// records `complete`; this adapter never treats an inbox listing as evidence.
///
/// # Errors
/// Refuses corrupt witnesses, discarded transactions, destination collisions,
/// changed endpoints and any failed durability operation; no overwrite fallback exists.
pub fn publish(
    journal: &mut Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    delivery: &Instant,
) -> Result<()> {
    let record = journal.record(delivery)?;
    bindings(sender, recipient, &record)?;
    if record.phase == Phase::Complete {
        return Ok(());
    }
    let witness = recipient.witness(&record)?;
    match recover(&record, &witness)? {
        Recovery::Publish => {
            sent(sender, recipient, &record)?;
            if record.phase == Phase::Accepted {
                journal.advance(delivery, Phase::Sent, &witness, delivery.clone())?;
            }
            #[cfg(test)]
            boundary(7)?;
            let name = recipient.temporary_name(&record.recipient_temporary)?;
            renameat2(
                &recipient.staging,
                name,
                &recipient.inbox,
                record.inbox_name.as_str(),
                RenameFlags::RENAME_NOREPLACE,
            )?;
            #[cfg(test)]
            boundary(8)?;
            recipient.staging.sync_all()?;
            recipient.inbox.sync_all()?;
            #[cfg(test)]
            boundary(9)?;
            journal.advance(delivery, Phase::Inbox, &Witness::Absent, delivery.clone())?;
            #[cfg(test)]
            boundary(10)?;
        }
        Recovery::Finish => {
            recipient.staging.sync_all()?;
            recipient.inbox.sync_all()?;
            if record.phase != Phase::Inbox {
                journal.advance(delivery, Phase::Inbox, &Witness::Absent, delivery.clone())?;
            }
        }
        Recovery::Terminal => (),
        Recovery::Discard => {
            return Err(MailError::Invalid("discard must resume source restoration"));
        }
    }
    Ok(())
}

fn remove_matching(parent: &File, name: &str, expected: &Identity) -> Result<()> {
    match child(parent, name, false) {
        Ok(file) => {
            if identity(&file.metadata()?) != *expected {
                return Err(MailError::Invalid("cleanup identity changed"));
            }
            unlinkat(parent, name, UnlinkatFlags::NoRemoveDir)?;
            parent.sync_all()?;
            Ok(())
        }
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Remove only the matching claimed source after proven inbox publication. The
/// caller must also remove its bound refusal sidecar before recording completion.
///
/// # Errors
/// Refuses cleanup before publication or for a changed source identity.
pub fn cleanup_source(sender: &Endpoint, recipient: &Endpoint, record: &Record) -> Result<()> {
    bindings(sender, recipient, record)?;
    if record.phase == Phase::Complete {
        return Ok(());
    }
    if record.phase != Phase::Inbox
        || !matches!(
            recover(record, &recipient.witness(record)?)?,
            Recovery::Finish | Recovery::Terminal
        )
        || record.phase == Phase::Discarded
    {
        return Err(MailError::Invalid("source cleanup before publication"));
    }
    remove_matching(&sender.staging, &record.outgoing, &record.source_identity)
}

/// Resume a previously journaled discard.
///
/// The claimed source disappears only by
/// atomic no-replace restoration, so restart does not depend on outbox survival.
/// The service projects the refusal reason and then calls `Journal::finish_discard`.
///
/// # Errors
/// Refuses an unjournaled discard, mutated source, restoration collision or unknown
/// sender-copy identity. Protected payloads remain pending when restoration fails.
pub fn discard(
    journal: &mut Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    delivery: &Instant,
) -> Result<()> {
    let record = journal.record(delivery)?;
    bindings(sender, recipient, &record)?;
    if record.phase != Phase::Discarded {
        return Err(MailError::Invalid("discard decision is not durable"));
    }
    if record.completed.is_some() {
        return Ok(());
    }
    recover(&record, &recipient.witness(&record)?)?;
    match child(&sender.staging, &record.outgoing, false) {
        Ok(mut source) => {
            if identity(&source.metadata()?) != record.source_identity
                || digest(&bounded(&mut source)?) != record.digest
            {
                return Err(MailError::Invalid(
                    "source restoration requires reconciliation",
                ));
            }
            renameat2(
                &sender.staging,
                record.outgoing.as_str(),
                &sender.outbox,
                record.outgoing.as_str(),
                RenameFlags::RENAME_NOREPLACE,
            )?;
        }
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    #[cfg(test)]
    boundary(11)?;
    sender.staging.sync_all()?;
    sender.outbox.sync_all()?;
    if let Some(temporary) = &record.sender_temporary {
        remove_matching(&sender.sent, &record.sent_name, &temporary.identity)?;
        remove_matching(
            &sender.staging,
            sender.temporary_name(temporary)?,
            &temporary.identity,
        )?;
    } else {
        remove_matching(
            &sender.sent,
            &record.sent_name,
            &record.recipient_temporary.identity,
        )?;
    }
    #[cfg(test)]
    boundary(12)?;
    remove_matching(
        &recipient.staging,
        recipient.temporary_name(&record.recipient_temporary)?,
        &record.recipient_temporary.identity,
    )?;
    #[cfg(test)]
    boundary(13)?;
    Ok(())
}

/// Count distinct private payload inodes over the complete provisioned endpoint
/// inventory, including claimed originals and unjournaled snapshots.
///
/// The service
/// supplies every endpoint before it calls journal capacity admission.
///
/// # Errors
/// Refuses unsafe entries and count overflow; never counts a hard-link alias twice.
pub fn staging_bytes(endpoints: &[&Endpoint]) -> Result<u64> {
    let mut identities = BTreeSet::new();
    let mut bytes = 0u64;
    for endpoint in endpoints {
        endpoint.fresh()?;
        for name in store::names(&endpoint.staging)? {
            let file = child(&endpoint.staging, &name, false)?;
            let info = file.metadata()?;
            if !info.is_file() {
                return Err(MailError::Invalid("invalid staging file"));
            }
            if identities.insert((info.dev(), info.ino())) {
                bytes = bytes.checked_add(info.len()).ok_or(MailError::Capacity)?;
            }
        }
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupIntent {
    version: u32,
    sender: String,
    recipient: String,
    outgoing: String,
    source_identity: Identity,
    bytes: u64,
    digest: String,
    snapshot_name: String,
    copy_name: String,
    snapshot: Option<Identity>,
    copy: Option<Identity>,
    uncommitted: Option<Instant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    version: u32,
    sender: String,
    recipient: String,
    outgoing: String,
    source_identity: Identity,
    snapshot_path: String,
    copy_path: Option<String>,
}
fn preparation_key(sender: &Address, outgoing: &str) -> String {
    format!(
        "prepare-{}.toml",
        digest(format!("{sender}\0{outgoing}").as_bytes())
    )
}
fn preparations(journal: &Journal) -> Result<Vec<Preparation>> {
    store::names(journal.publication_root())?
        .into_iter()
        .filter(|name| name.starts_with("prepare-"))
        .map(|name| {
            let intent: Preparation = store::read(
                journal.publication_root(),
                &name,
                super::journal::RECORD_MAX_BYTES,
            )?;
            let sender = Address::parse(&intent.sender)
                .map_err(|_| MailError::Invalid("preparation sender"))?;
            let recipient = Address::parse(&intent.recipient)
                .map_err(|_| MailError::Invalid("preparation recipient"))?;
            let outgoing = Outgoing::parse(&intent.outgoing)
                .map_err(|_| MailError::Invalid("preparation outgoing"))?;
            if intent.version != 1
                || outgoing.recipient != recipient
                || name != preparation_key(&sender, &intent.outgoing)
                || !Path::new(&intent.snapshot_path).is_absolute()
                || intent
                    .copy_path
                    .as_ref()
                    .is_some_and(|path| !Path::new(path).is_absolute())
            {
                return Err(MailError::Invalid("corrupt preparation intent"));
            }
            Ok(intent)
        })
        .collect()
}
fn preparation_names(
    journal: &Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
) -> Result<Option<(String, String)>> {
    let key = preparation_key(&sender.address, outgoing);
    let intent: Preparation = match store::read(
        journal.publication_root(),
        &key,
        super::journal::RECORD_MAX_BYTES,
    ) {
        Ok(value) => value,
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if intent.version != 1
        || intent.sender != sender.address.to_string()
        || intent.recipient != recipient.address.to_string()
        || intent.outgoing != outgoing
    {
        return Err(MailError::Invalid("preparation intent binding"));
    }
    let name = |endpoint: &Endpoint, path: &str| -> Result<String> {
        if Path::new(path).parent() != Some(endpoint.staging_path.as_path()) {
            return Err(MailError::Invalid("preparation staging binding"));
        }
        let value = Path::new(path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(MailError::Invalid("preparation name"))?;
        component(value)?;
        Ok(value.to_owned())
    };
    Ok(Some((
        name(recipient, &intent.snapshot_path)?,
        intent
            .copy_path
            .as_ref()
            .map_or_else(|| Ok("unused-copy".to_owned()), |path| name(sender, path))?,
    )))
}
fn allocate_preparation(
    journal: &Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
    source_identity: &Identity,
    records: &[Record],
) -> Result<String> {
    let uncommitted = journal.uncommitted();
    let mut used: BTreeSet<String> = records
        .iter()
        .chain(uncommitted.iter())
        .flat_map(|record| {
            std::iter::once(record.recipient_temporary.path.clone()).chain(
                record
                    .sender_temporary
                    .iter()
                    .map(|temporary| temporary.path.clone()),
            )
        })
        .collect();
    for preparation in preparations(journal)? {
        used.insert(preparation.snapshot_path);
        used.extend(preparation.copy_path);
    }
    for endpoint in [sender, recipient] {
        for name in store::names(&endpoint.staging)? {
            used.insert(
                endpoint
                    .staging_path
                    .join(name)
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    let (snapshot, copy) = (0..=u64::MAX)
        .map(|serial| {
            (
                recipient.staging_path.join(format!("payload-{serial}")),
                sender.staging_path.join(format!("copy-{serial}")),
            )
        })
        .find(|(snapshot, copy)| {
            !used.contains(snapshot.to_string_lossy().as_ref())
                && !used.contains(copy.to_string_lossy().as_ref())
        })
        .ok_or(MailError::Capacity)?;
    let shared = sender.group == recipient.group
        && sender.staging.metadata()?.dev() == recipient.staging.metadata()?.dev();
    let intent = Preparation {
        version: 1,
        sender: sender.address.to_string(),
        recipient: recipient.address.to_string(),
        outgoing: outgoing.to_owned(),
        source_identity: source_identity.clone(),
        snapshot_path: snapshot
            .to_str()
            .ok_or(MailError::Invalid("staging path encoding"))?
            .to_owned(),
        copy_path: if shared {
            None
        } else {
            Some(
                copy.to_str()
                    .ok_or(MailError::Invalid("staging path encoding"))?
                    .to_owned(),
            )
        },
    };
    let key = preparation_key(&sender.address, outgoing);
    store::write(
        journal.publication_root(),
        journal.publication_root(),
        &key,
        &intent,
        false,
    )?;
    Ok(key)
}

/// List unpublished preparation intents for registry-resolved startup recovery.
///
/// # Errors
/// Refuses malformed private metadata; the inventory is not an address registry.
pub fn pending_preparations(journal: &Journal) -> Result<Vec<(Address, Address, String)>> {
    preparations(journal)?
        .into_iter()
        .map(|intent| {
            Ok((
                Address::parse(&intent.sender)
                    .map_err(|_| MailError::Invalid("preparation sender"))?,
                Address::parse(&intent.recipient)
                    .map_err(|_| MailError::Invalid("preparation recipient"))?,
                intent.outgoing,
            ))
        })
        .collect()
}

/// Retire a preparation intent whose matching acceptance is already durable.
/// This handles interruption after acceptance but before intent cleanup.
///
/// # Errors
/// Refuses missing or mismatched acceptance evidence without touching payloads.
pub fn reconcile_accepted_preparation(
    journal: &Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
) -> Result<Instant> {
    preparation_names(journal, sender, recipient, outgoing)?
        .ok_or(MailError::Invalid("missing preparation"))?;
    let key = preparation_key(&sender.address, outgoing);
    let intent: Preparation = store::read(
        journal.publication_root(),
        &key,
        super::journal::RECORD_MAX_BYTES,
    )?;
    let record = journal
        .records()?
        .into_iter()
        .find(|record| {
            record.sender == intent.sender
                && record.recipient == intent.recipient
                && record.outgoing == intent.outgoing
                && record.source_identity == intent.source_identity
                && record.recipient_temporary.path == intent.snapshot_path
                && record
                    .sender_temporary
                    .as_ref()
                    .map(|temporary| &temporary.path)
                    == intent.copy_path.as_ref()
        })
        .ok_or(MailError::Invalid("preparation lacks matching acceptance"))?;
    store::remove(journal.publication_root(), &key)?;
    Ok(record.delivery)
}

fn unpublished_identity(endpoint: &Endpoint, name: &str) -> Result<Option<Identity>> {
    match child(&endpoint.staging, name, false) {
        Ok(file) => {
            let info = file.metadata()?;
            if !info.is_file() || info.uid() != geteuid().as_raw() {
                return Err(MailError::Invalid("unsafe unpublished snapshot"));
            }
            Ok(Some(identity(&info)))
        }
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// List interrupted source-restoration intents for the service's startup inventory.
/// The names are addresses to resolve through the registries, never new registrations.
///
/// # Errors
/// Refuses malformed or unsafe private restoration metadata.
pub fn pending_restorations(journal: &Journal) -> Result<Vec<(Address, Address, String)>> {
    store::names(journal.publication_root())?
        .into_iter()
        .filter(|name| name.starts_with("cleanup-"))
        .map(|name| {
            let intent: CleanupIntent = store::read(
                journal.publication_root(),
                &name,
                super::journal::RECORD_MAX_BYTES,
            )?;
            Ok((
                Address::parse(&intent.sender).map_err(|_| MailError::Invalid("cleanup sender"))?,
                Address::parse(&intent.recipient)
                    .map_err(|_| MailError::Invalid("cleanup recipient"))?,
                intent.outgoing,
            ))
        })
        .collect()
}

fn build_intent(
    journal: &Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
    snapshot_name: &str,
    copy_name: &str,
) -> Result<CleanupIntent> {
    let mut source = child(&sender.staging, outgoing, false)?;
    let info = source.metadata()?;
    if !info.is_file() {
        return Err(MailError::Invalid("unrecoverable source"));
    }
    if preparations(journal)?.iter().any(|intent| {
        intent.sender == sender.address.to_string()
            && intent.outgoing == outgoing
            && intent.source_identity != identity(&info)
    }) {
        return Err(MailError::Invalid("preparation source identity changed"));
    }
    let bytes = if info.len() <= MAX_LETTER_BYTES {
        bounded(&mut source)?
    } else {
        Vec::new()
    };
    if !unchanged(&info, &source.metadata()?) {
        return Err(MailError::Invalid("changed-source"));
    }
    let uncommitted = journal
        .uncommitted()
        .into_iter()
        .find(|record| record.sender == sender.address.to_string() && record.outgoing == outgoing);
    if uncommitted.as_ref().is_some_and(|record| {
        record.source_identity != identity(&info)
            || record.bytes != bytes.len() as u64
            || record.digest != digest(&bytes)
    }) {
        return Err(MailError::Invalid(
            "uncommitted source requires reconciliation",
        ));
    }
    let intent = CleanupIntent {
        version: 1,
        sender: sender.address.to_string(),
        recipient: recipient.address.to_string(),
        outgoing: outgoing.to_owned(),
        source_identity: identity(&info),
        bytes: info.len(),
        digest: if info.len() <= MAX_LETTER_BYTES {
            digest(&bytes)
        } else {
            String::new()
        },
        snapshot_name: snapshot_name.to_owned(),
        copy_name: copy_name.to_owned(),
        snapshot: if snapshot_name == "unused-snapshot" {
            None
        } else {
            unpublished_identity(recipient, snapshot_name)?
        },
        copy: if copy_name == "unused-copy" {
            None
        } else {
            unpublished_identity(sender, copy_name)?
        },
        uncommitted: uncommitted.map(|record| record.delivery),
    };
    Ok(intent)
}

fn restore_unpublished(sender: &Endpoint, outgoing: &str, intent: &CleanupIntent) -> Result<()> {
    match child(&sender.staging, outgoing, false) {
        Ok(mut source) => {
            let before = source.metadata()?;
            if identity(&before) != intent.source_identity
                || before.len() != intent.bytes
                || (intent.bytes <= MAX_LETTER_BYTES
                    && digest(&bounded(&mut source)?) != intent.digest)
                || !unchanged(&before, &source.metadata()?)
            {
                return Err(MailError::Invalid(
                    "source restoration requires reconciliation",
                ));
            }
            renameat2(
                &sender.staging,
                outgoing,
                &sender.outbox,
                outgoing,
                RenameFlags::RENAME_NOREPLACE,
            )?;
        }
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Reconcile an unpublished preparation.
///
/// Persist the source-restoration intent
/// before restoring without overwrite, then remove only its recorded snapshots.
/// An interrupted initial acceptance is reconciled through the journal interface;
/// terminal records for an earlier use of this outgoing name do not pin new work.
///
/// # Errors
/// Refuses pending accepted evidence, absent sources without an intent, collisions,
/// mutated sources and unsafe metadata. A failed cleanup remains capacity-accounted.
pub fn reconcile_unpublished(
    journal: &mut Journal,
    sender: &Endpoint,
    recipient: &Endpoint,
    outgoing: &str,
) -> Result<()> {
    let parsed = Outgoing::parse(outgoing).map_err(|_| MailError::Invalid("invalid-name"))?;
    if parsed.recipient != recipient.address {
        return Err(MailError::Invalid("recipient binding"));
    }
    sender.fresh()?;
    recipient.fresh()?;
    let matches = |record: &Record| {
        record.sender == sender.address.to_string() && record.outgoing == outgoing
    };
    if journal
        .records()?
        .iter()
        .any(|record| matches(record) && record.completed.is_none())
    {
        return Err(MailError::Invalid(
            "preparation has accepted journal evidence",
        ));
    }
    if preparation_names(journal, sender, recipient, outgoing)?.is_none()
        && journal.uncommitted().iter().any(matches)
    {
        return Err(MailError::Invalid(
            "uncommitted acceptance has no preparation intent",
        ));
    }
    let (snapshot_name, copy_name) = preparation_names(journal, sender, recipient, outgoing)?
        .unwrap_or_else(|| ("unused-snapshot".to_owned(), "unused-copy".to_owned()));
    let intent_name = format!(
        "cleanup-{}.toml",
        digest(format!("{}\0{outgoing}", sender.address).as_bytes())
    );
    let intent = match store::read::<CleanupIntent>(
        journal.publication_root(),
        &intent_name,
        super::journal::RECORD_MAX_BYTES,
    ) {
        Ok(intent) => intent,
        Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            let intent = build_intent(
                journal,
                sender,
                recipient,
                outgoing,
                &snapshot_name,
                &copy_name,
            )?;
            store::write(
                journal.publication_root(),
                journal.publication_root(),
                &intent_name,
                &intent,
                false,
            )?;
            intent
        }
        Err(error) => return Err(error),
    };
    if intent.version != 1
        || intent.sender != sender.address.to_string()
        || intent.recipient != recipient.address.to_string()
        || intent.outgoing != outgoing
    {
        return Err(MailError::Invalid("cleanup intent binding"));
    }
    component(&intent.snapshot_name)?;
    component(&intent.copy_name)?;
    #[cfg(test)]
    boundary(14)?;
    restore_unpublished(sender, outgoing, &intent)?;
    #[cfg(test)]
    boundary(15)?;
    sender.staging.sync_all()?;
    sender.outbox.sync_all()?;
    for (endpoint, name, expected) in [
        (recipient, intent.snapshot_name.clone(), &intent.snapshot),
        (sender, intent.copy_name.clone(), &intent.copy),
    ] {
        if let Some(expected) = expected {
            remove_matching(&endpoint.staging, &name, expected)?;
        }
    }
    #[cfg(test)]
    boundary(16)?;
    if let Some(delivery) = &intent.uncommitted
        && journal
            .uncommitted()
            .iter()
            .any(|record| &record.delivery == delivery)
    {
        journal.reconcile_uncommitted(delivery, outgoing, intent.bytes, &intent.digest)?;
    }
    let key = preparation_key(&sender.address, outgoing);
    if store::names(journal.publication_root())?.contains(&key) {
        store::remove(journal.publication_root(), &key)?;
    }
    store::remove(journal.publication_root(), &intent_name)
}

#[cfg(test)]
type Observer = Option<Box<dyn FnMut(u8)>>;

#[cfg(test)]
thread_local! {
    static STOP: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) };
    static OBSERVE: std::cell::RefCell<Observer> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn boundary(point: u8) -> Result<()> {
    OBSERVE.with(|observer| {
        if let Some(callback) = observer.borrow_mut().as_mut() {
            callback(point);
        }
    });
    if STOP.with(|stop| stop.get() == Some(point) && stop.replace(None).is_some()) {
        return Err(MailError::Invalid("injected publication interruption"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
