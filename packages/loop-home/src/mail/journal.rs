//! Protected persistence and witness-driven recovery under
//! ``req:mail:records-recovery-retention``. Filesystem publication is a separate adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io;

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::instant::Instant;
use super::store;
use super::{Address, Outgoing};

/// Inclusive opaque payload bound, in bytes.
pub const MAX_LETTER_BYTES: u64 = 1_048_576;
/// Terminal history age before compaction, in seconds.
pub const JOURNAL_HISTORY_SECONDS: u64 = 2_592_000;
/// Hard journal cap including metadata replacement scratch.
pub const JOURNAL_MAX_BYTES: u64 = 268_435_456;
/// Hard cap on distinct private payload inodes across all endpoints.
pub const STAGING_MAX_BYTES: u64 = 67_108_864;
/// Maximum interval between service retention passes, in seconds.
pub const PRUNE_INTERVAL_SECONDS: u64 = 3_600;
/// Inclusive bound on the sole cumulative checkpoint.
pub const SUMMARY_MAX_BYTES: u64 = 4_096;
/// Implementation constant bounding one delivery record, including exact paths.
/// The specification does not declare this bound; reserved scratch uses it.
pub const RECORD_MAX_BYTES: u64 = 65_536;
/// Implementation bound for the protected reservation pin projection, which holds
/// every live steering and reply binding of every active worker; retirement
/// releases a worker's family.
pub const RESERVATION_PINS_MAX_BYTES: u64 = 1_048_576;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Transport error without letter contents.
#[derive(Debug)]
pub enum MailError {
    /// Unsafe, malformed or inconsistent transport state.
    Invalid(&'static str),
    /// Named backing filesystem failure.
    Io(io::Error),
    /// Retention cannot free space safely.
    Capacity,
    /// Actual UTC has not advanced past the durable watermark.
    ClockWait,
}
/// Mail transport result.
pub type Result<T> = std::result::Result<T, MailError>;
impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Io(error) => write!(f, "io-failure: {error}"),
            Self::Capacity => f.write_str("service-capacity"),
            Self::ClockWait => f.write_str("UTC has not advanced past the reserved instant"),
        }
    }
}
impl std::error::Error for MailError {}
impl From<io::Error> for MailError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<nix::errno::Errno> for MailError {
    fn from(error: nix::errno::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error as i32))
    }
}

/// SHA-256 commitment, used for records and opaque payloads.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Opened filesystem identity, never a pathname-only assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Device number.
    pub device: u64,
    /// Inode number.
    pub inode: u64,
}

/// A private payload's exact path and recorded filesystem identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Temporary {
    /// Absolute service-only staging pathname.
    pub path: String,
    /// Identity observed through the opened temporary.
    pub identity: Identity,
}

/// Durable transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Journal synced before any publication.
    Accepted,
    /// Sender history is durable; inbox rename may have occurred.
    Sent,
    /// Inbox publication is proven; source cleanup may remain.
    Inbox,
    /// Publication and source cleanup are durable.
    Complete,
    /// Durable decision to restore the source instead of publishing.
    Discarded,
}

/// Schema-one delivery metadata; contains no letter bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Schema version.
    pub version: u32,
    /// Delivery instant and journal key.
    pub delivery: Instant,
    /// Acceptance instant equals delivery.
    pub acceptance: Instant,
    /// Identity derived from the registered source outbox.
    pub sender: String,
    /// Resolved recipient.
    pub recipient: String,
    /// Exact submission basename.
    pub outgoing: String,
    /// Payload byte length.
    pub bytes: u64,
    /// Payload SHA-256.
    pub digest: String,
    /// Accepted global registry snapshot digest.
    pub registry_digest: String,
    /// Applicable loop configuration digests, in address resolution order.
    pub configuration_digests: Vec<String>,
    /// Exact claimed source location.
    pub source_path: String,
    /// Opened claimed source identity.
    pub source_identity: Identity,
    /// The recipient-side rename witness.
    pub recipient_temporary: Temporary,
    /// Sender-side copy temporary, when sharing an inode is unsuitable.
    pub sender_temporary: Option<Temporary>,
    /// Final sender-history basename.
    pub sent_name: String,
    /// Final recipient inbox basename.
    pub inbox_name: String,
    /// Durable phase.
    pub phase: Phase,
    /// Terminal completion time; absent until cleanup/restoration is durable.
    pub completed: Option<Instant>,
    /// Transport-only pending error, without payload quotations.
    pub pending_error: Option<String>,
    /// Exact recoverable source disposition for a discarded transaction.
    pub discard_disposition: Option<String>,
}

impl Record {
    /// Validate all fields before persistence or recovery trusts this record.
    ///
    /// # Errors
    /// Refuses schema, name, digest, phase, path and instant inconsistencies.
    pub fn validate(&self) -> Result<()> {
        let sender =
            Address::parse(&self.sender).map_err(|_| MailError::Invalid("record sender"))?;
        let recipient =
            Address::parse(&self.recipient).map_err(|_| MailError::Invalid("record recipient"))?;
        let outgoing =
            Outgoing::parse(&self.outgoing).map_err(|_| MailError::Invalid("record outgoing"))?;
        if self.version != 1
            || self.delivery != self.acceptance
            || outgoing.recipient != recipient
            || self.bytes > MAX_LETTER_BYTES
            || !valid_digest(&self.digest)
            || !valid_digest(&self.registry_digest)
            || self.configuration_digests.iter().any(|d| !valid_digest(d))
            || self.inbox_name != format!("{sender}.{}.letter", self.delivery)
            || self.sent_name != format!("{recipient}.{}.letter", self.delivery)
            || (self.phase == Phase::Complete && self.completed.is_none())
            || (self.completed.is_some()
                && !matches!(self.phase, Phase::Complete | Phase::Discarded))
            || (self.phase == Phase::Discarded) != self.discard_disposition.is_some()
        {
            return Err(MailError::Invalid("inconsistent journal record"));
        }
        for path in std::iter::once(self.source_path.as_str())
            .chain(std::iter::once(self.recipient_temporary.path.as_str()))
            .chain(self.sender_temporary.iter().map(|t| t.path.as_str()))
        {
            if !std::path::Path::new(path).is_absolute()
                || std::path::Path::new(path).components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || path.as_bytes().contains(&0)
            {
                return Err(MailError::Invalid("journal payload path"));
            }
        }
        if store::encode(self)?.len() as u64 > RECORD_MAX_BYTES {
            return Err(MailError::Invalid(
                "unrepresentable complete journal record",
            ));
        }
        Ok(())
    }
}

/// The filesystem adapter's observation of the recorded recipient temporary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Witness {
    /// Same private inode, byte count and digest remain; publication did not occur.
    Present {
        identity: Identity,
        bytes: u64,
        digest: String,
    },
    /// Recorded name is absent under the protected, durable rename protocol.
    Absent,
    /// Mismatched identity, payload or durability; reconciliation is required.
    Invalid,
}

/// Recovery decisions; no decision uses inbox pathname survival as its oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// Complete sent publication and the one inbox rename.
    Publish,
    /// Record the proven rename and finish source cleanup, without redelivery.
    Finish,
    /// Resume durable discard/source restoration, never interpret absence as delivery.
    Discard,
    /// Terminal cleanup is durable; reap only proven leftovers.
    Terminal,
}

/// Interpret the adapter witness against the durable journal phase.
///
/// # Errors
/// Refuses a mismatched witness or a surviving witness after recorded publication.
pub fn recover(record: &Record, witness: &Witness) -> Result<Recovery> {
    record.validate()?;
    if matches!(witness, Witness::Invalid) {
        return Err(MailError::Invalid(
            "publication witness requires reconciliation",
        ));
    }
    if let Witness::Present {
        identity,
        bytes,
        digest,
    } = witness
        && (identity != &record.recipient_temporary.identity
            || *bytes != record.bytes
            || digest != &record.digest)
    {
        return Err(MailError::Invalid("mismatched publication witness"));
    }
    if record.phase == Phase::Discarded {
        return Ok(if record.completed.is_some() {
            Recovery::Terminal
        } else {
            Recovery::Discard
        });
    }
    match (record.phase, witness) {
        (Phase::Accepted | Phase::Sent, Witness::Present { .. }) => Ok(Recovery::Publish),
        (Phase::Accepted | Phase::Sent | Phase::Inbox, Witness::Absent) => Ok(Recovery::Finish),
        (Phase::Complete, Witness::Absent) => Ok(Recovery::Terminal),
        _ => Err(MailError::Invalid("witness contradicts publication phase")),
    }
}

/// Individual verification outcome, separate from aggregate history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    /// Exact inbox delivery has protected publication evidence.
    Delivered,
    /// Unrecorded or mismatched entry cannot establish sender authority.
    ForgedLocalEntry,
    /// Sender history is older than the compaction watermark, without individual attestation.
    CompactedHistory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    greatest_reserved: Option<Instant>,
    acceptance_available: bool,
    greatest_observed: Option<Instant>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Removal {
    delivery: Instant,
    digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    previous_head: String,
    last_record_digest: String,
    head: String,
    count: u64,
    greatest_compacted: Option<Instant>,
    greatest_reserved: Option<Instant>,
    pending: Option<Removal>,
}

/// References that pin individual records. The service builds this snapshot under
/// its admission/configuration serialization; sent copies never appear here.
#[derive(Clone, Debug, Default)]
pub struct Pins {
    /// Deliveries referenced by live reservations.
    pub reservations: BTreeSet<Instant>,
    /// Deliveries still in an active endpoint's inbox; retired endpoints are excluded.
    pub active_inboxes: BTreeSet<Instant>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationPins {
    version: u32,
    deliveries: BTreeMap<String, Instant>,
}

/// Exclusive, descriptor-pinned service journal. Provisioning supplies a private
/// directory; opening never invents missing recovery state.
pub struct Journal {
    root: File,
    records: File,
    _lock: Flock<File>,
    state: State,
    checkpoint: Checkpoint,
    uncommitted: BTreeMap<Instant, Record>,
}

impl Journal {
    /// Initialize an empty, service-private journal. This is explicit provisioning.
    ///
    /// # Errors
    /// Refuses unsafe/nonempty storage, unsupported sync or concurrent access.
    pub fn create(root: File) -> Result<Self> {
        store::private(&root, true)?;
        if !store::names(&root)?.is_empty() {
            return Err(MailError::Invalid("journal is not empty"));
        }
        store::write(
            &root,
            &root,
            "writer.lock",
            &std::collections::BTreeMap::<String, String>::new(),
            false,
        )?;
        let lock = Flock::lock(
            store::open(&root, "writer.lock", false)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| MailError::from(error))?;
        let records = store::directory(&root, "deliveries")?;
        let state = State {
            version: 1,
            greatest_reserved: None,
            acceptance_available: false,
            greatest_observed: None,
        };
        let checkpoint = Checkpoint {
            version: 1,
            previous_head: ZERO_DIGEST.to_owned(),
            last_record_digest: ZERO_DIGEST.to_owned(),
            head: ZERO_DIGEST.to_owned(),
            count: 0,
            greatest_compacted: None,
            greatest_reserved: None,
            pending: None,
        };
        store::write(&root, &root, "state.toml", &state, false)?;
        store::write(&root, &root, "checkpoint.toml", &checkpoint, false)?;
        store::write(
            &root,
            &root,
            "reservation-pins.toml",
            &ReservationPins {
                version: 1,
                deliveries: BTreeMap::new(),
            },
            false,
        )?;
        Ok(Self {
            root,
            records,
            _lock: lock,
            state,
            checkpoint,
            uncommitted: BTreeMap::new(),
        })
    }

    /// Open existing recovery state, reconcile checkpoint deletion, and validate
    /// every retained record before admitting work.
    ///
    /// # Errors
    /// Missing/corrupt state, unsafe objects and a second writer refuse opening.
    pub fn open(root: File) -> Result<Self> {
        store::private(&root, true)?;
        let lock = Flock::lock(
            store::open(&root, "writer.lock", false)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| MailError::from(error))?;
        let records = store::open(&root, "deliveries", true)?;
        let state: State = store::read(&root, "state.toml", SUMMARY_MAX_BYTES)?;
        let checkpoint: Checkpoint = store::read(&root, "checkpoint.toml", SUMMARY_MAX_BYTES)?;
        if state.version != 1
            || checkpoint.version != 1
            || !valid_digest(&checkpoint.head)
            || !valid_digest(&checkpoint.previous_head)
            || !valid_digest(&checkpoint.last_record_digest)
            || (checkpoint.count == 0
                && (checkpoint.head != ZERO_DIGEST
                    || checkpoint.greatest_compacted.is_some()
                    || checkpoint.pending.is_some()))
            || (checkpoint.count > 0
                && (checkpoint.greatest_compacted.is_none()
                    || checkpoint.head
                        != digest(
                            format!(
                                "{}\n{}\n",
                                checkpoint.previous_head, checkpoint.last_record_digest
                            )
                            .as_bytes(),
                        )))
            || checkpoint.pending.as_ref().is_some_and(|pending| {
                pending.digest != checkpoint.last_record_digest
                    || checkpoint
                        .greatest_compacted
                        .as_ref()
                        .is_none_or(|bound| &pending.delivery > bound)
            })
            || checkpoint
                .greatest_reserved
                .as_ref()
                .max(checkpoint.greatest_compacted.as_ref())
                > state.greatest_reserved.as_ref()
        {
            return Err(MailError::Invalid("corrupt journal state"));
        }
        let mut journal = Self {
            root,
            records,
            _lock: lock,
            state,
            checkpoint,
            uncommitted: BTreeMap::new(),
        };
        {
            let _admission = reservation_admission(&journal.root)?;
            journal.clean_scratch()?;
            journal.finish_compaction()?;
        }
        for record in journal.records()? {
            if journal
                .state
                .greatest_reserved
                .as_ref()
                .is_none_or(|watermark| &record.delivery > watermark)
            {
                return Err(MailError::Invalid("record exceeds durable watermark"));
            }
        }
        journal.reservation_pins()?;
        Ok(journal)
    }

    /// Read the protected live-reservation projection under the admission lock.
    /// The round transport records a pin before exposing a delivery binding and
    /// releases it only after the reservation ceases to reference that delivery.
    ///
    /// # Errors
    /// Refuses corrupt state or a pin whose individual record is missing.
    pub fn reservation_pins(&self) -> Result<BTreeSet<Instant>> {
        let pins = self.read_reservation_pins()?;
        for delivery in pins.deliveries.values() {
            self.record(delivery)?;
        }
        Ok(pins.deliveries.into_values().collect())
    }

    fn read_reservation_pins(&self) -> Result<ReservationPins> {
        let pins: ReservationPins = store::read(
            &self.root,
            "reservation-pins.toml",
            RESERVATION_PINS_MAX_BYTES,
        )?;
        if pins.version != 1 {
            return Err(MailError::Invalid("invalid reservation pin projection"));
        }
        Ok(pins)
    }

    /// Persist or release a service-authenticated reservation's delivery binding.
    /// This is a service-side interface, not an actor-writable file or authority.
    ///
    /// # Errors
    /// Refuses an empty reference, missing record, capacity or unsafe storage.
    pub fn pin_reservation(&mut self, reference: &str, delivery: Option<Instant>) -> Result<()> {
        let _admission = reservation_admission(&self.root)?;
        if reference.is_empty() {
            return Err(MailError::Invalid("empty reservation reference"));
        }
        let mut pins = self.read_reservation_pins()?;
        let key = digest(reference.as_bytes());
        if let Some(delivery) = delivery {
            self.record(&delivery)?;
            pins.deliveries.insert(key, delivery);
        } else {
            pins.deliveries.remove(&key);
        }
        if store::encode(&pins)?.len() as u64 > RESERVATION_PINS_MAX_BYTES {
            return Err(MailError::Capacity);
        }
        store::write(&self.root, &self.root, "reservation-pins.toml", &pins, true)
    }

    fn clean_scratch(&mut self) -> Result<()> {
        for (directory, records) in [(&self.root, false), (&self.records, true)] {
            for name in store::names(directory)? {
                if let Some(target) = name
                    .strip_prefix('.')
                    .and_then(|name| name.strip_suffix(".replace"))
                {
                    let _scratch = store::open(directory, &name, false)?;
                    match store::open(directory, target, false) {
                        Ok(_committed) => {
                            if records {
                                let committed: Record = store::read(
                                    directory,
                                    target,
                                    if target == "reservation-pins.toml" {
                                        RESERVATION_PINS_MAX_BYTES
                                    } else {
                                        RECORD_MAX_BYTES
                                    },
                                )?;
                                committed.validate()?;
                            } else if target.starts_with("cleanup-")
                                || target.starts_with("prepare-")
                                || target.starts_with("refusal-")
                                || target == "reservation-pins.toml"
                            {
                                let _intent: toml::Value = store::read(
                                    directory,
                                    target,
                                    if target == "reservation-pins.toml" {
                                        RESERVATION_PINS_MAX_BYTES
                                    } else {
                                        RECORD_MAX_BYTES
                                    },
                                )?;
                            } else if target != "state.toml" && target != "checkpoint.toml" {
                                return Err(MailError::Invalid("unknown root replacement scratch"));
                            }
                            store::remove(directory, &name)?;
                        }
                        Err(MailError::Io(error))
                            if records && error.kind() == io::ErrorKind::NotFound =>
                        {
                            let record: Record = store::read(directory, &name, RECORD_MAX_BYTES)?;
                            record.validate()?;
                            if record.phase != Phase::Accepted
                                || target != format!("{}.toml", record.delivery)
                                || self
                                    .state
                                    .greatest_reserved
                                    .as_ref()
                                    .is_none_or(|watermark| &record.delivery > watermark)
                            {
                                return Err(MailError::Invalid("uncommitted acceptance metadata"));
                            }
                            self.uncommitted.insert(record.delivery.clone(), record);
                        }
                        Err(MailError::Io(error))
                            if !records
                                && (target.starts_with("cleanup-")
                                    || target.starts_with("prepare-")
                                    || target.starts_with("refusal-")
                                    || target == "reservation-pins.toml")
                                && error.kind() == io::ErrorKind::NotFound =>
                        {
                            // The adapter performs no restoration until this intent's
                            // atomic publication and directory sync have returned.
                            let _intent: toml::Value = store::read(
                                directory,
                                &name,
                                if target == "reservation-pins.toml" {
                                    RESERVATION_PINS_MAX_BYTES
                                } else {
                                    RECORD_MAX_BYTES
                                },
                            )?;
                            store::remove(directory, &name)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(())
    }

    /// Unpublished acceptance scratch retained until the adapter proves source
    /// restoration. These records never establish delivery provenance.
    #[must_use]
    pub fn uncommitted(&self) -> Vec<Record> {
        self.uncommitted.values().cloned().collect()
    }

    /// Remove metadata scratch only after the adapter restores the exact outgoing
    /// bytes without overwrite and durably cleans its unpublished payloads.
    ///
    /// # Errors
    /// Refuses absent scratch or a mismatched source-restoration witness.
    pub fn reconcile_uncommitted(
        &mut self,
        instant: &Instant,
        outgoing: &str,
        bytes: u64,
        payload_digest: &str,
    ) -> Result<()> {
        let record = self
            .uncommitted
            .get(instant)
            .ok_or(MailError::Invalid("no uncommitted acceptance"))?;
        if record.outgoing != outgoing || record.bytes != bytes || record.digest != payload_digest {
            return Err(MailError::Invalid("source reconciliation mismatch"));
        }
        store::remove(&self.records, &format!(".{instant}.toml.replace"))?;
        self.uncommitted.remove(instant);
        Ok(())
    }

    pub(super) const fn publication_root(&self) -> &File {
        &self.root
    }

    /// Check actual UTC before preparing admission; the writer lock prevents races.
    ///
    /// # Errors
    /// Returns `ClockWait` until actual UTC exceeds the durable watermark.
    pub fn check_clock(&self, now: &Instant) -> Result<()> {
        if self
            .state
            .greatest_reserved
            .as_ref()
            .is_some_and(|prior| now <= prior)
        {
            return Err(MailError::ClockWait);
        }
        Ok(())
    }

    /// Persist an actual UTC millisecond strictly beyond every reserved instant.
    ///
    /// # Errors
    /// Returns `ClockWait` on equal/backward UTC; never advances the clock itself.
    pub fn reserve(&mut self, now: Instant) -> Result<Instant> {
        if store::names(&self.root)?
            .iter()
            .any(|name| name.starts_with("cleanup-"))
        {
            return Err(MailError::Invalid(
                "publication cleanup requires reconciliation",
            ));
        }
        if !self.uncommitted.is_empty() {
            return Err(MailError::Invalid(
                "unpublished sources require reconciliation",
            ));
        }
        self.check_clock(&now)?;
        let next = State {
            version: 1,
            greatest_reserved: Some(now.clone()),
            acceptance_available: true,
            greatest_observed: Some(
                self.state
                    .greatest_observed
                    .clone()
                    .map_or_else(|| now.clone(), |prior| prior.max(now.clone())),
            ),
        };
        store::write(&self.root, &self.root, "state.toml", &next, true)?;
        self.state = next;
        Ok(now)
    }

    /// Check full transaction capacity before claiming a source or reserving time.
    /// The adapter accounts distinct inodes across all staging filesystems, including
    /// unjournaled leftovers; aliases count once. Three copies cover claimed source,
    /// recipient snapshot and an independent sender temporary.
    ///
    /// # Errors
    /// Refuses backpressure without evicting pinned evidence or pending payloads.
    pub fn capacity(&self, staging_bytes: u64) -> Result<()> {
        let scratch = 3 * RECORD_MAX_BYTES + 3 * SUMMARY_MAX_BYTES + RESERVATION_PINS_MAX_BYTES;
        if store::size(&self.root)?
            .checked_add(scratch)
            .is_none_or(|n| n > JOURNAL_MAX_BYTES)
            || staging_bytes
                .checked_add(MAX_LETTER_BYTES * 3)
                .is_none_or(|n| n > STAGING_MAX_BYTES)
        {
            return Err(MailError::Capacity);
        }
        Ok(())
    }

    /// Store the acceptance record before publication. The adapter must have synced
    /// the payload and containing directory before calling this entry.
    ///
    /// # Errors
    /// Refuses reused/unreserved instants, invalid fields and metadata capacity.
    pub fn accept(&mut self, record: &Record) -> Result<()> {
        record.validate()?;
        if self.state.greatest_reserved.as_ref() != Some(&record.delivery)
            || !self.state.acceptance_available
            || record.phase != Phase::Accepted
            || record.completed.is_some()
        {
            return Err(MailError::Invalid("acceptance is not the reserved instant"));
        }
        let mut consumed = self.state.clone();
        consumed.acceptance_available = false;
        store::write(&self.root, &self.root, "state.toml", &consumed, true)?;
        self.state = consumed;
        store::write(
            &self.root,
            &self.records,
            &format!("{}.toml", record.delivery),
            record,
            false,
        )
    }

    /// Read one exact protected delivery record.
    ///
    /// # Errors
    /// Refuses missing, malformed or inconsistent metadata.
    pub fn record(&self, instant: &Instant) -> Result<Record> {
        let record: Record =
            store::read(&self.records, &format!("{instant}.toml"), RECORD_MAX_BYTES)?;
        record.validate()?;
        if &record.delivery != instant {
            return Err(MailError::Invalid("journal key mismatch"));
        }
        Ok(record)
    }

    /// Read the complete sorted retained record set.
    ///
    /// # Errors
    /// Refuses unknown entries or corrupt records rather than silently skipping them.
    pub fn records(&self) -> Result<Vec<Record>> {
        store::names(&self.records)?
            .into_iter()
            .filter(|name| {
                !self
                    .uncommitted
                    .keys()
                    .any(|instant| name == &format!(".{instant}.toml.replace"))
            })
            .map(|name| {
                let instant = Instant::parse(
                    name.strip_suffix(".toml")
                        .ok_or(MailError::Invalid("record filename"))?,
                )?;
                self.record(&instant)
            })
            .collect()
    }

    fn replace(&self, record: &Record) -> Result<()> {
        record.validate()?;
        store::write(
            &self.root,
            &self.records,
            &format!("{}.toml", record.delivery),
            record,
            true,
        )
    }

    /// Measure terminal age from the latest known instant, including on rollback.
    fn terminal_instant(&self, record: &Record, now: Instant) -> Instant {
        let mut terminal = now.max(record.acceptance.clone());
        for known in [&self.state.greatest_observed, &self.state.greatest_reserved]
            .into_iter()
            .flatten()
        {
            terminal = terminal.max(known.clone());
        }
        terminal
    }

    /// Advance a publication phase only with the corresponding adapter witness.
    ///
    /// # Errors
    /// Refuses skipped/reversed phases or contradictory publication evidence.
    pub fn advance(
        &mut self,
        instant: &Instant,
        phase: Phase,
        witness: &Witness,
        now: Instant,
    ) -> Result<()> {
        let mut record = self.record(instant)?;
        let action = recover(&record, witness)?;
        let allowed = matches!(
            (record.phase, phase, action),
            (Phase::Accepted, Phase::Sent, Recovery::Publish)
                | (
                    Phase::Accepted | Phase::Sent,
                    Phase::Inbox,
                    Recovery::Finish
                )
                | (Phase::Inbox, Phase::Complete, Recovery::Finish)
        );
        if !allowed {
            return Err(MailError::Invalid("invalid phase transition"));
        }
        record.phase = phase;
        if phase == Phase::Complete {
            // Completion resolves transport failure; conservative age postpones pruning.
            record.pending_error = None;
            record.completed = Some(self.terminal_instant(&record, now));
        }
        self.replace(&record)
    }

    /// Persist discard before any temporary removal, retaining the exact source
    /// disposition. A collision during restoration leaves this record pending.
    ///
    /// # Errors
    /// Refuses discard after publication or without an intact matching witness.
    pub fn discard(
        &mut self,
        instant: &Instant,
        witness: &Witness,
        disposition: &str,
    ) -> Result<()> {
        let mut record = self.record(instant)?;
        if recover(&record, witness)? != Recovery::Publish || disposition.is_empty() {
            return Err(MailError::Invalid(
                "discard requires recoverable unpublished payload",
            ));
        }
        record.phase = Phase::Discarded;
        record.discard_disposition = Some(disposition.to_owned());
        self.replace(&record)
    }

    /// Mark discard terminal only after source restoration, artifact cleanup sync
    /// and any required refusal-sidecar projection.
    ///
    /// # Errors
    /// Refuses a nondiscarded transaction or failed durable metadata replacement.
    pub fn finish_discard(&mut self, instant: &Instant, now: Instant) -> Result<()> {
        let mut record = self.record(instant)?;
        if record.phase != Phase::Discarded {
            return Err(MailError::Invalid("not discarded"));
        }
        record.pending_error = None;
        record.completed = Some(self.terminal_instant(&record, now));
        self.replace(&record)
    }

    /// Retain a transport-only failure for pending repair; callers must never include
    /// letter content in the reason.
    ///
    /// # Errors
    /// Refuses a terminal record or a reason too large for the bounded record.
    pub fn pending(&mut self, instant: &Instant, reason: &str) -> Result<()> {
        let mut record = self.record(instant)?;
        if record.completed.is_some() {
            return Err(MailError::Invalid("terminal transaction"));
        }
        record.pending_error = Some(reason.to_owned());
        self.replace(&record)
    }

    /// Verify a scoped inbox entry against protected metadata and publication proof.
    ///
    /// # Errors
    /// Corrupt existing records fail closed; missing records yield a forged verdict.
    pub fn verify(
        &self,
        recipient: &Address,
        instant: &Instant,
        name: &str,
        bytes: u64,
        payload_digest: &str,
        witness: &Witness,
    ) -> Result<Verification> {
        let record = match self.record(instant) {
            Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Verification::ForgedLocalEntry);
            }
            result => result?,
        };
        let published = matches!(
            recover(&record, witness)?,
            Recovery::Finish | Recovery::Terminal
        ) && record.phase != Phase::Discarded;
        Ok(
            if published
                && record.recipient == recipient.to_string()
                && record.inbox_name == name
                && record.bytes == bytes
                && record.digest == payload_digest
            {
                Verification::Delivered
            } else {
                Verification::ForgedLocalEntry
            },
        )
    }

    /// Classify unrecorded sender history without manufacturing an attestation.
    #[must_use]
    pub fn unrecorded_sent(&self, instant: &Instant) -> Verification {
        if self
            .checkpoint
            .greatest_compacted
            .as_ref()
            .is_some_and(|bound| instant <= bound)
        {
            Verification::CompactedHistory
        } else {
            Verification::ForgedLocalEntry
        }
    }

    fn checkpoint(&mut self, next: Checkpoint) -> Result<()> {
        if store::encode(&next)?.len() as u64 > SUMMARY_MAX_BYTES {
            return Err(MailError::Capacity);
        }
        store::write(&self.root, &self.root, "checkpoint.toml", &next, true)?;
        self.checkpoint = next;
        Ok(())
    }

    fn finish_compaction(&mut self) -> Result<()> {
        if let Some(removal) = &self.checkpoint.pending {
            let name = format!("{}.toml", removal.delivery);
            match store::bytes(&self.records, &name, RECORD_MAX_BYTES) {
                Ok(bytes) => {
                    if digest(&bytes) != removal.digest {
                        return Err(MailError::Invalid("compaction record changed"));
                    }
                    store::remove(&self.records, &name)?;
                }
                Err(MailError::Io(error)) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            let mut next = self.checkpoint.clone();
            next.pending = None;
            self.checkpoint(next)?;
        }
        Ok(())
    }

    /// Compact eligible terminal records in delivery order, retaining all live pins.
    /// Checkpoint-before-delete makes interrupted folding exactly once. Backward or
    /// uncertain UTC postpones eligibility; the watermark is never lowered.
    ///
    /// # Errors
    /// Refuses corrupt metadata, changed compacted records and storage failure.
    pub fn prune(&mut self, now: &Instant, pins: &Pins) -> Result<u64> {
        self.prune_projected(now, |_| Ok(pins.clone()))
    }
    /// Project inventory pins from the compactor's single record read under admission.
    pub(super) fn prune_projected(
        &mut self,
        now: &Instant,
        project: impl FnOnce(&[Record]) -> Result<Pins>,
    ) -> Result<u64> {
        let _admission = reservation_admission(&self.root)?;
        let live_reservations = self.reservation_pins()?;
        self.finish_compaction()?;
        if self
            .state
            .greatest_observed
            .as_ref()
            .is_some_and(|seen| now < seen)
        {
            return Ok(0);
        }
        let mut observed = self.state.clone();
        observed.greatest_observed = Some(now.clone());
        store::write(&self.root, &self.root, "state.toml", &observed, true)?;
        self.state = observed;
        let mut removed = 0;
        let records = self.records()?;
        let pins = project(&records)?;
        for record in records {
            let Some(completed) = &record.completed else {
                continue;
            };
            if !matches!(record.phase, Phase::Complete | Phase::Discarded)
                || record.pending_error.is_some()
                || now
                    .millis()
                    .checked_sub(completed.millis())
                    .is_none_or(|age| age < JOURNAL_HISTORY_SECONDS * 1000)
                || live_reservations.contains(&record.delivery)
                || pins.reservations.contains(&record.delivery)
                || pins.active_inboxes.contains(&record.delivery)
            {
                continue;
            }
            let bytes = store::bytes(
                &self.records,
                &format!("{}.toml", record.delivery),
                RECORD_MAX_BYTES,
            )?;
            let record_digest = digest(&bytes);
            let mut next = self.checkpoint.clone();
            next.previous_head.clone_from(&next.head);
            next.last_record_digest.clone_from(&record_digest);
            next.head = digest(format!("{}\n{}\n", next.previous_head, record_digest).as_bytes());
            next.count = next.count.checked_add(1).ok_or(MailError::Capacity)?;
            next.greatest_compacted = Some(next.greatest_compacted.map_or_else(
                || record.delivery.clone(),
                |prior| prior.max(record.delivery.clone()),
            ));
            next.greatest_reserved
                .clone_from(&self.state.greatest_reserved);
            next.pending = Some(Removal {
                delivery: record.delivery,
                digest: record_digest,
            });
            self.checkpoint(next)?;
            #[cfg(test)]
            if CRASH_AFTER_CHECKPOINT.with(|flag| flag.replace(false)) {
                return Err(MailError::Invalid("injected checkpoint interruption"));
            }
            self.finish_compaction()?;
            removed += 1;
        }
        Ok(removed)
    }
}

/// Serialize external reservation publication with compaction on the pinned
/// service directory. Holders are bounded critical sections, so acquisition waits.
fn reservation_admission(root: &File) -> Result<Flock<File>> {
    Flock::lock(store::open(root, ".", true)?, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))
}

/// Verify a terminal delivery and durably pin it before exposing its binding.
///
/// The caller runs under the service identity; actors cannot access this root.
/// Verification and pin publication share the compactor's admission lock.
///
/// # Errors
/// Refuses unfinished, compacted, missing or unverifiable delivery evidence.
pub fn bind_reservation<T>(
    root: &File,
    family: &str,
    reference: &str,
    instant: &Instant,
    verify: impl FnOnce(&Record) -> Result<T>,
) -> Result<T> {
    reservation_binding(root, family, reference, instant, false, verify)
}

/// Verify an existing delivery pin without creating or replacing any evidence.
///
/// # Errors
/// Refuses unavailable delivery evidence, an absent pin or a changed binding.
pub fn verify_reservation<T>(
    root: &File,
    family: &str,
    reference: &str,
    instant: &Instant,
    verify: impl FnOnce(&Record) -> Result<T>,
) -> Result<T> {
    reservation_binding(root, family, reference, instant, true, verify)
}

fn reservation_binding<T>(
    root: &File,
    family: &str,
    reference: &str,
    instant: &Instant,
    verify_only: bool,
    verify: impl FnOnce(&Record) -> Result<T>,
) -> Result<T> {
    store::private(root, true)?;
    let _admission = reservation_admission(root)?;
    let checkpoint: Checkpoint = store::read(root, "checkpoint.toml", SUMMARY_MAX_BYTES)?;
    if family.is_empty()
        || reference.is_empty()
        || checkpoint.version != 1
        || !valid_digest(&checkpoint.head)
        || checkpoint
            .pending
            .as_ref()
            .is_some_and(|pending| &pending.delivery == instant)
    {
        return Err(MailError::Invalid(
            "invalid-directory: unavailable journal delivery",
        ));
    }
    let records = store::open(root, "deliveries", true)?;
    let record: Record = store::read(&records, &format!("{instant}.toml"), RECORD_MAX_BYTES)?;
    record.validate()?;
    if &record.delivery != instant
        || record.phase != Phase::Complete
        || record.pending_error.is_some()
    {
        return Err(MailError::Invalid(
            "pending-delivery: steering delivery is not complete",
        ));
    }
    let verified = verify(&record)?;
    let mut pins: ReservationPins =
        store::read(root, "reservation-pins.toml", RESERVATION_PINS_MAX_BYTES)?;
    if pins.version != 1 {
        return Err(MailError::Invalid("invalid reservation pin projection"));
    }
    let key = format!(
        "{}:{}",
        digest(family.as_bytes()),
        digest(reference.as_bytes())
    );
    if pins
        .deliveries
        .get(&key)
        .is_some_and(|prior| prior != instant)
    {
        return Err(MailError::Invalid(
            "invalid-directory: reservation delivery changed",
        ));
    }
    if verify_only {
        if pins.deliveries.get(&key) != Some(instant) {
            return Err(MailError::Invalid(
                "invalid-directory: reservation delivery is not pinned",
            ));
        }
        return Ok(verified);
    }
    pins.deliveries.insert(key, instant.clone());
    if store::encode(&pins)?.len() as u64 > RESERVATION_PINS_MAX_BYTES {
        return Err(MailError::Capacity);
    }
    store::write(root, root, "reservation-pins.toml", &pins, true)?;
    Ok(verified)
}

/// Release a retired worker's pin family after custody and configuration retirement.
///
/// # Errors
/// Requires service custody and exclusive admission; corrupt pin state refuses.
pub fn release_reservation_family(root: &File, family: &str) -> Result<()> {
    store::private(root, true)?;
    let _admission = reservation_admission(root)?;
    let mut pins: ReservationPins =
        match store::read(root, "reservation-pins.toml", RESERVATION_PINS_MAX_BYTES) {
            Ok(pins) => pins,
            Err(MailError::Io(error))
                if error.kind() == io::ErrorKind::NotFound && store::names(root)?.is_empty() =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
    if pins.version != 1 || family.is_empty() {
        return Err(MailError::Invalid("invalid reservation pin projection"));
    }
    let prefix = format!("{}:", digest(family.as_bytes()));
    pins.deliveries
        .retain(|reference, _| !reference.starts_with(&prefix));
    store::write(root, root, "reservation-pins.toml", &pins, true)
}

#[cfg(test)]
thread_local! { static CRASH_AFTER_CHECKPOINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
