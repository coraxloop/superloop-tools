#![deny(clippy::indexing_slicing)]

//! Private append-only escalation journal.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

use crate::hook::{ApprovalRequest, EscalationRecord, EscalationSink, Mode};
use crate::proc;
use crate::request::Scope;
use crate::role::{
    self, CallerRole, OPEN_NO_FOLLOW, Registry, open_directory_no_follow, open_public_root,
    open_state_root,
};
use crate::rubric::sha256_digest;

/// Maximum size of one complete journal line, including its terminating newline.
pub const MAX_JOURNAL_RECORD_BYTES: usize = 8 * 1024;

const STATE_ROOT_VARIABLE: &str = "PERMISSION_TRIAGE_STATE_ROOT";
const JOURNAL_NAME: &str = "escalations.jsonl";
const LOCK_NAME: &str = "escalations.lock";
const LOOP_ERROR: i32 = 40;
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const PUBLIC_FILE_MODE: u32 = 0o644;
const SCHEMA: u64 = 1;
const VERDICT_SCHEMA: u64 = 2;
const LOCK_WAIT: Duration = Duration::from_secs(4);
pub(crate) const LOCK_POLL: Duration = Duration::from_millis(2);
const LOCK_RELEASE_BUDGET_DIVISOR: u32 = 4;
const LOCK_STALE_AFTER: Duration = Duration::from_secs(60);
const LOCK_BUDGET_FLOOR: Duration = Duration::from_millis(10);
mod owner;
mod request_lock;
mod requests;
static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LOCK_CLAIM_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static OWNER_PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
type ReleaseObserver = Box<dyn FnMut(&str)>;

#[cfg(test)]
thread_local! {
    static RELEASE_OBSERVER: std::cell::RefCell<Option<ReleaseObserver>> = const { std::cell::RefCell::new(None) };
    static RELEASE_ELAPSED: Cell<Option<Duration>> = const { Cell::new(None) };
    static STEAL_OBSERVER: std::cell::RefCell<Option<ReleaseObserver>> = const { std::cell::RefCell::new(None) };
    static OWNER_PROBE_FAILURE: Cell<bool> = const { Cell::new(false) };
}

/// One owner disposition accepted by the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispositionOutcome {
    /// The owner wrote a narrow rule before recording this disposition.
    AdjudicatedRuleAdded,
    /// The owner rejected the escalated request.
    AdjudicatedRejected,
    /// A corrected request was subsequently rerun.
    CorrectedAndRerun,
    /// The next identical request from the same loop's orchestrator may run once.
    AdjudicatedApproved,
}

impl DispositionOutcome {
    /// Stable journal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdjudicatedRuleAdded => "adjudicated-rule-added",
            Self::AdjudicatedRejected => "adjudicated-rejected",
            Self::CorrectedAndRerun => "corrected-and-rerun",
            Self::AdjudicatedApproved => "adjudicated-approved",
        }
    }
}

/// Detail retained with an owner disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispositionDetail {
    /// Identifier of an owner-rubric rule that has already been written.
    Rule(String),
    /// Owner explanation for rejecting the request.
    Rejection(String),
    /// Digest of the corrected request that was rerun.
    CorrectedRequestDigest(String),
    /// Digest of the request approved for one identical rerun.
    ApprovedRequestDigest(String),
}

/// Journal configuration selected without touching the filesystem.
#[derive(Clone, Debug)]
pub struct Journal {
    state_root: Option<OsString>,
    lock_wait: Duration,
    scope: Scope,
    root_handle: Option<Arc<File>>,
    registered_root: Option<PathBuf>,
    shape: RootShape,
    #[cfg(test)]
    test_hooks: AcquireTestHooks,
}

/// Access shape of a registered journal root and its journal file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootShape {
    /// Owner-only 0700 root and 0600 journal.
    Private,
    /// Owner-writable root and journal without group or other write permission.
    Public,
}

/// Read-only journal handle selected for owner review.
#[derive(Clone, Debug)]
pub struct ReviewJournal {
    journal: Journal,
}

impl ReviewJournal {
    /// Read the selected stream without creating a file or taking its write lock.
    ///
    /// # Errors
    ///
    /// Returns the same private-file and read errors as the journal reader.
    pub fn read(&self) -> Result<Vec<u8>, JournalError> {
        self.journal.read()
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct AcquireTestHooks {
    validation_failure: bool,
    vanish_before_open: bool,
    reap_read_dir_failure: bool,
    reap_entry_failure: Option<OsString>,
    effective_uid: Option<u32>,
    acquire_polls: Arc<AtomicU64>,
    directory_syncs: Arc<AtomicU64>,
}

#[cfg(test)]
impl AcquireTestHooks {
    const fn validation_failure(&self) -> bool {
        self.validation_failure
    }

    const fn vanish_before_open(&self) -> bool {
        self.vanish_before_open
    }

    const fn reap_read_dir_failure(&self) -> bool {
        self.reap_read_dir_failure
    }

    fn reap_entry_failure(&self) -> Option<&std::ffi::OsStr> {
        self.reap_entry_failure.as_deref()
    }

    const fn effective_uid(&self) -> Option<u32> {
        self.effective_uid
    }

    fn record_acquire_poll(&self) {
        self.acquire_polls.fetch_add(1, Ordering::Relaxed);
    }

    fn acquire_poll_count(&self) -> u64 {
        self.acquire_polls.load(Ordering::Relaxed)
    }

    fn record_directory_sync(&self) {
        self.directory_syncs.fetch_add(1, Ordering::Relaxed);
    }

    fn directory_sync_count(&self) -> u64 {
        self.directory_syncs.load(Ordering::Relaxed)
    }
}

impl Journal {
    /// Select the state root from `PERMISSION_TRIAGE_STATE_ROOT` lazily.
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            state_root: env::var_os(STATE_ROOT_VARIABLE),
            lock_wait: LOCK_WAIT,
            scope: Scope::Loop,
            root_handle: None,
            registered_root: None,
            shape: RootShape::Private,
            #[cfg(test)]
            test_hooks: AcquireTestHooks::default(),
        }
    }

    /// Select an explicit state root without consulting the environment.
    #[must_use]
    pub fn from_state_root(path: &Path) -> Self {
        Self {
            state_root: Some(path.as_os_str().to_owned()),
            lock_wait: LOCK_WAIT,
            scope: Scope::Loop,
            root_handle: None,
            registered_root: None,
            shape: RootShape::Private,
            #[cfg(test)]
            test_hooks: AcquireTestHooks::default(),
        }
    }

    /// Open a registered root and retain its descriptor for all journal accesses.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, missing, symlinked, or foreign-owned roots.
    pub fn from_registered_root(path: &Path, scope: Scope) -> Result<Self, JournalError> {
        let directory = open_state_root(path)
            .map_err(|error| JournalError::RootMetadata(io::Error::other(error)))?;
        Ok(Self::from_registered_root_handle(
            directory,
            path,
            scope,
            RootShape::Private,
        ))
    }

    /// Bind a journal to an already validated registered-root descriptor.
    ///
    /// # Errors
    ///
    /// Returns journal configuration errors if the descriptor cannot be retained.
    pub fn from_registered_descriptor(
        directory: File,
        path: &Path,
        scope: Scope,
        shape: RootShape,
    ) -> Result<Self, JournalError> {
        Ok(Self::from_registered_root_handle(
            directory, path, scope, shape,
        ))
    }

    fn from_registered_root_handle(
        directory: File,
        path: &Path,
        scope: Scope,
        shape: RootShape,
    ) -> Self {
        let anchored = PathBuf::from("/proc/self/fd")
            .join(directory.as_raw_fd().to_string())
            .join(".");
        let mut journal = Self::from_state_root(&anchored);
        journal.root_handle = Some(Arc::new(directory));
        journal.registered_root = Some(path.to_path_buf());
        journal.scope = scope;
        journal.shape = shape;
        journal
    }

    /// Bind an already validated registered-root descriptor to a read-only review handle.
    ///
    /// The descriptor's opener performed the root validation; this constructor repeats no check and
    /// can fail in no way of its own. Write-freedom rests on the returned type, which exposes no
    /// append path, rather than on a promise made in prose.
    #[must_use]
    pub fn from_registered_descriptor_for_review(
        directory: File,
        path: &Path,
        scope: Scope,
    ) -> ReviewJournal {
        ReviewJournal {
            journal: Self::from_registered_root_handle(directory, path, scope, RootShape::Private),
        }
    }

    /// Read the selected stream without creating a file or taking its write lock.
    ///
    /// # Errors
    ///
    /// Returns the same private-file and read errors as the journal reader.
    pub fn read(&self) -> Result<Vec<u8>, JournalError> {
        if let Some(directory) = &self.root_handle {
            let actual = directory
                .metadata()
                .map_err(JournalError::RootMetadata)?
                .uid();
            let effective = match effective_uid_override(self) {
                Some(uid) => uid,
                None => fs::metadata("/proc/self")
                    .map_err(JournalError::RootMetadata)?
                    .uid(),
            };
            if actual != effective {
                return Err(JournalError::RootOwner { actual, effective });
            }
        }
        read_scoped_journal_bytes(self.state_root()?, self.scope, self.shape)
    }

    pub(crate) fn root_descriptor(&self) -> Option<File> {
        self.root_handle
            .as_deref()
            .and_then(|directory| directory.try_clone().ok())
    }

    /// Append one owner disposition after validating it against the locked event stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe or unavailable state root, a malformed journal, an unknown
    /// event identifier, an already adjudicated event, or an append failure.
    pub fn append_disposition(
        &self,
        caller: &CallerRole,
        event_id: &str,
        outcome: DispositionOutcome,
        detail: DispositionDetail,
    ) -> Result<(), JournalError> {
        if self.scope == Scope::Estate {
            return Err(JournalError::RecordShape(
                "estate adjudication authority is not provisioned",
            ));
        }
        if self.registered_root.as_deref().is_some_and(|root| {
            caller
                .entry()
                .and_then(crate::role::RegistryEntry::state_root)
                != Some(root)
        }) {
            return Err(JournalError::RecordShape(
                "adjudicator root does not match its registration",
            ));
        }
        let root = self.state_root()?;
        establish_journal_root(root, self)?;
        let _lock = acquire_lock(root, self)?;
        let mut journal = open_journal_file(&root.join(journal_filename(self.scope)), self)?;
        journal
            .seek(SeekFrom::Start(0))
            .map_err(JournalError::Read)?;
        let mut bytes = Vec::new();
        journal
            .read_to_end(&mut bytes)
            .map_err(JournalError::Read)?;
        let source = disposition_source(&bytes, event_id)?;
        if !caller.is_orchestrator()
            || source.get("scope").and_then(Value::as_str) != Some("loop")
            || source.get("loop_name").and_then(Value::as_str) != caller.loop_name()
            || (outcome == DispositionOutcome::AdjudicatedApproved
                && source.get("role").and_then(Value::as_str) != Some("orchestrator"))
        {
            return Err(JournalError::RecordShape(
                "adjudicator has no authority for this caller and scope",
            ));
        }
        let value = disposition_value(&source, outcome, detail, caller)?;
        append_value(&mut journal, value)
    }

    fn state_root(&self) -> Result<&Path, JournalError> {
        let value = self
            .state_root
            .as_deref()
            .ok_or(JournalError::StateRootUnset)?;
        let path = Path::new(value);
        if !path.is_absolute() {
            return Err(JournalError::StateRootNotAbsolute);
        }
        Ok(path)
    }

    fn append_escalation(&self, record: &EscalationRecord) -> Result<(), JournalError> {
        let root = self.state_root()?;
        establish_journal_root(root, self)?;
        let _lock = acquire_lock(root, self)?;
        let mut journal = open_journal_file(&root.join(journal_filename(self.scope)), self)?;
        append_value(&mut journal, escalation_value(record)?)
    }

    fn consume_matching_approval(
        &self,
        request: &ApprovalRequest<'_>,
    ) -> Result<Option<String>, JournalError> {
        if request.scope() != Scope::Loop || !request.role().is_orchestrator() {
            return Ok(None);
        }
        if request.mode() == Mode::Audit {
            let Some(root) = self.optional_existing_root()? else {
                return Ok(None);
            };
            let bytes = read_journal_bytes(root)?;
            return unconsumed_approval_source(&bytes, request)?
                .map(|source| string_field(&source, "event_id").map(str::to_owned))
                .transpose();
        }
        let Some(root) = self.optional_existing_root()? else {
            return Ok(None);
        };
        let journal_path = root.join(JOURNAL_NAME);
        match journal_path.symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(JournalError::FileMetadata(error)),
            Ok(_) => {}
        }
        establish_journal_root(root, self)?;
        let _lock = acquire_lock(root, self)?;
        let mut journal = open_journal_file(&journal_path, self)?;
        journal
            .seek(SeekFrom::Start(0))
            .map_err(JournalError::Read)?;
        let mut bytes = Vec::new();
        journal
            .read_to_end(&mut bytes)
            .map_err(JournalError::Read)?;
        let Some(source) = unconsumed_approval_source(&bytes, request)? else {
            return Ok(None);
        };
        let event_id = string_field(&source, "event_id")?.to_owned();
        let value = approval_consumed_value(&source, request)?;
        let mut lines = encoded_value(value)?;
        lines.extend(encoded_value(escalation_value(request.verdict())?)?);
        separate_torn_tail(&mut journal)?;
        journal.write_all(&lines).map_err(JournalError::Append)?;
        journal.sync_data().map_err(JournalError::Sync)?;
        Ok(Some(event_id))
    }

    fn optional_existing_root(&self) -> Result<Option<&Path>, JournalError> {
        let root = self.state_root()?;
        match root.symlink_metadata() {
            Ok(_) => Ok(Some(root)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(JournalError::RootMetadata(error)),
        }
    }

    #[cfg(test)]
    pub(crate) fn append_test_escalation(
        &self,
        command: &str,
        reason: &str,
    ) -> Result<(), JournalError> {
        let root = self.state_root()?;
        establish_journal_root(root, self)?;
        let _lock = acquire_lock(root, self)?;
        let mut journal = open_journal_file(&root.join(journal_filename(self.scope)), self)?;
        let recorded_at = recorded_at()?;
        let digest = request_digest("Bash", "/workspace/project", command);
        let mut value = schema_2_test_value(base_value(BaseFields {
            event: "escalated",
            event_id: event_id(&recorded_at, &digest),
            recorded_at,
            tool_use_id: "use-test".to_owned(),
            request_digest: digest,
            tool: "Bash".to_owned(),
            cwd: "/workspace/project".to_owned(),
            command: command.to_owned(),
            classification: "suspicious".to_owned(),
            reason: reason.to_owned(),
            general_rubric_digest: "general-digest".to_owned(),
            owner_rubric_digest: None,
            role: "unknown".to_owned(),
            loop_name: None,
            stale_session: false,
            domain_rubric_digest: None,
            model_status: "success".to_owned(),
        }));
        let object = value
            .as_object_mut()
            .ok_or(JournalError::RecordShape("fixture is not an object"))?;
        object.insert("scope".to_owned(), Value::from("loop"));
        object.insert("role".to_owned(), Value::from("orchestrator"));
        object.insert("loop_name".to_owned(), Value::from("orchestration"));
        append_value(&mut journal, value)
    }

    #[cfg(test)]
    pub(crate) const fn set_test_lock_wait(&mut self, wait: Duration) {
        self.lock_wait = wait;
    }

    #[cfg(test)]
    pub(crate) const fn set_test_lock_validation_failure(&mut self) {
        self.test_hooks.validation_failure = true;
    }

    #[cfg(test)]
    pub(crate) const fn set_test_lock_vanish_before_open(&mut self) {
        self.test_hooks.vanish_before_open = true;
    }

    #[cfg(test)]
    pub(crate) const fn set_test_reap_read_dir_failure(&mut self) {
        self.test_hooks.reap_read_dir_failure = true;
    }

    #[cfg(test)]
    pub(crate) fn set_test_reap_entry_failure(&mut self, name: OsString) {
        self.test_hooks.reap_entry_failure = Some(name);
    }

    #[cfg(test)]
    pub(crate) const fn set_test_effective_uid(&mut self, uid: u32) {
        self.test_hooks.effective_uid = Some(uid);
    }

    #[cfg(test)]
    pub(crate) fn set_test_ownership_probe_failure(fail: bool) {
        OWNER_PROBE_FAILURE.with(|failure| failure.set(fail));
    }

    #[cfg(test)]
    pub(crate) fn test_lock_acquire_polls(&self) -> u64 {
        self.test_hooks.acquire_poll_count()
    }

    #[cfg(test)]
    pub(crate) fn test_directory_syncs(&self) -> u64 {
        self.test_hooks.directory_sync_count()
    }
}

#[cfg(test)]
const fn effective_uid_override(journal: &Journal) -> Option<u32> {
    journal.test_hooks.effective_uid()
}

#[cfg(not(test))]
const fn effective_uid_override(_journal: &Journal) -> Option<u32> {
    None
}

#[cfg(test)]
fn record_directory_sync(journal: &Journal) {
    journal.test_hooks.record_directory_sync();
}

#[cfg(not(test))]
const fn record_directory_sync(_journal: &Journal) {}

impl EscalationSink for Journal {
    type Error = JournalError;

    fn record(&mut self, record: &EscalationRecord) -> Result<(), Self::Error> {
        self.append_escalation(record)
    }

    fn set_lock_budget(&mut self, remaining: Duration) {
        self.lock_wait = lock_budget(remaining);
    }

    fn consume_approval(
        &mut self,
        request: &ApprovalRequest<'_>,
    ) -> Result<Option<String>, Self::Error> {
        self.consume_matching_approval(request)
    }
}

pub(crate) fn lock_budget(remaining: Duration) -> Duration {
    (remaining / 2).clamp(LOCK_BUDGET_FLOOR, LOCK_WAIT)
}

/// Scope selects one fixed journal filename.
#[must_use]
pub const fn journal_filename(scope: Scope) -> &'static str {
    match scope {
        Scope::Loop => JOURNAL_NAME,
        Scope::Estate => "estate-escalations.jsonl",
    }
}

const fn lock_filename(scope: Scope) -> &'static str {
    match scope {
        Scope::Loop => LOCK_NAME,
        Scope::Estate => "estate-escalations.lock",
    }
}

/// The hook's two streams, bound once to its identity snapshot.
#[derive(Debug)]
pub struct RoutedJournal {
    estate_root: Option<PathBuf>,
    registry_path: Option<PathBuf>,
    owner_rubric: Option<PathBuf>,
    loop_journal: Option<Journal>,
    estate_journal: Option<Journal>,
    outbox: Option<OutboxDestination>,
    configuration_error: Option<String>,
    worker: bool,
}

#[derive(Debug)]
struct OutboxDestination {
    path: PathBuf,
    expected_owner: u32,
}

impl RoutedJournal {
    /// Retain only the configured estate path until the registry snapshot is selected.
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            estate_root: env::var_os(STATE_ROOT_VARIABLE).map(PathBuf::from),
            registry_path: env::var_os(crate::role::LOOP_REGISTRY_VARIABLE).map(PathBuf::from),
            owner_rubric: env::var_os("PERMISSION_TRIAGE_OWNER_RUBRIC").map(PathBuf::from),
            loop_journal: None,
            estate_journal: None,
            outbox: None,
            configuration_error: None,
            worker: false,
        }
    }

    #[cfg(test)]
    pub(crate) const fn test_loop_journal(&self) -> Option<&Journal> {
        self.loop_journal.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn test_set_registry_path(&mut self, path: PathBuf) {
        self.registry_path = Some(path);
    }

    #[cfg(test)]
    pub(crate) fn test_set_estate_root(&mut self, path: PathBuf) {
        self.estate_root = Some(path);
    }

    fn write_outbox(&self, record: &EscalationRecord) -> Result<(), JournalError> {
        let destination = self
            .outbox
            .as_ref()
            .ok_or_else(|| JournalError::OutboxUnavailable {
                detail: "registered loop uid or registry path is absent".to_owned(),
            })?;
        let directory = open_directory_no_follow(&destination.path).map_err(|error| {
            JournalError::OutboxUnavailable {
                detail: format!("{}: {error}", destination.path.display()),
            }
        })?;
        let metadata = directory
            .metadata()
            .map_err(|error| JournalError::OutboxUnavailable {
                detail: format!("{}: {error}", destination.path.display()),
            })?;
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o1775 {
            return Err(JournalError::OutboxShape { mode });
        }
        if metadata.uid() != destination.expected_owner {
            return Err(JournalError::OutboxOwner {
                actual: metadata.uid(),
                expected: destination.expected_owner,
            });
        }
        let id = record.event_id();
        if id.len() != 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(JournalError::OutboxUnavailable {
                detail: "event identifier is not path-safe".to_owned(),
            });
        }
        let line = encoded_value(escalation_value(record)?)?;
        write_outbox_file(&directory, &destination.path, id, &line, |file, bytes| {
            file.write_all(bytes)
        })
    }
}

pub(crate) fn write_outbox_file(
    directory: &File,
    outbox_path: &Path,
    id: &str,
    line: &[u8],
    write_line: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
) -> Result<(), JournalError> {
    let path = PathBuf::from("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PUBLIC_FILE_MODE)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(&path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                JournalError::OutboxCollision {
                    event_id: id.to_owned(),
                }
            } else {
                JournalError::OutboxUnavailable {
                    detail: format!("{}: {error}", outbox_path.display()),
                }
            }
        })?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(PUBLIC_FILE_MODE))
            .map_err(JournalError::OutboxWrite)?;
        let owner = file.metadata().map_err(JournalError::OutboxWrite)?.uid();
        let writer = role::effective_uid().map_err(|error| JournalError::OutboxUnavailable {
            detail: error.to_string(),
        })?;
        if owner != writer {
            return Err(JournalError::OutboxFileOwner {
                actual: owner,
                expected: writer,
            });
        }
        write_line(&mut file, line).map_err(JournalError::OutboxWrite)?;
        file.sync_data().map_err(JournalError::OutboxSync)?;
        directory.sync_data().map_err(JournalError::OutboxSync)
    })();
    if result.is_err() {
        drop(file);
        let _cleanup = fs::remove_file(&path);
    }
    result
}

impl EscalationSink for RoutedJournal {
    type Error = JournalError;

    fn configure(&mut self, registry: Option<&Registry>, role: &CallerRole) -> bool {
        self.configuration_error = None;
        self.outbox = None;
        self.worker =
            matches!(role, CallerRole::OrchestratorSubagent(loop_match) if loop_match.worker());
        let sources: Vec<&Path> = [self.registry_path.as_deref(), self.owner_rubric.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        if let Some(error) = registry.and_then(|registry| {
            registry
                .validate_deployment_structure(None)
                .and_then(|()| {
                    registry.validate_root_layout(&sources, self.registry_path.as_deref())
                })
                .and_then(|()| registry.validate_rubric_layout(self.owner_rubric.as_deref()))
                .err()
        }) {
            self.loop_journal = None;
            self.estate_journal = None;
            self.configuration_error = Some(error.to_string());
            return false;
        }
        if self.worker {
            self.outbox = role.entry().and_then(|entry| {
                let expected_owner = entry.uid()?;
                let parent = self.registry_path.as_deref()?.parent()?;
                Some(OutboxDestination {
                    path: parent.join("outboxes").join(entry.name()),
                    expected_owner,
                })
            });
            let effective_uid = match role::effective_uid() {
                Ok(uid) => uid,
                Err(error) => {
                    self.configuration_error = Some(error.to_string());
                    self.loop_journal = None;
                    self.estate_journal = None;
                    return false;
                }
            };
            self.loop_journal = role.entry().and_then(|entry| {
                let root = entry.worker_run_root(effective_uid)?;
                let directory = open_public_root(&root, effective_uid).ok()?;
                Journal::from_registered_descriptor(
                    directory,
                    &root,
                    Scope::Loop,
                    RootShape::Public,
                )
                .ok()
            });
            self.estate_journal = None;
            return self.loop_journal.is_some();
        }
        if let Some(error) = registry.and_then(|registry| registry.validate_deployment().err()) {
            self.loop_journal = None;
            self.estate_journal = None;
            self.configuration_error = Some(error.to_string());
            return false;
        }
        self.loop_journal = role.entry().and_then(|entry| {
            let root = entry.state_root()?;
            let directory = entry.validated_state_root().ok()?;
            Journal::from_registered_descriptor(directory, root, Scope::Loop, RootShape::Private)
                .ok()
        });
        let estate_entry = registry.and_then(|registry| {
            let mut matches = registry
                .entries()
                .iter()
                .filter(|entry| entry.state_root() == self.estate_root.as_deref());
            matches.next().filter(|_| matches.next().is_none())
        });
        self.estate_journal = if let Some(entry) = estate_entry {
            entry.state_root().and_then(|root| {
                let directory = entry.validated_state_root().ok()?;
                Journal::from_registered_descriptor(
                    directory,
                    root,
                    Scope::Estate,
                    RootShape::Private,
                )
                .ok()
            })
        } else if registry.is_none() {
            self.estate_root.as_deref().and_then(|root| {
                let directory = open_state_root(root).ok()?;
                Journal::from_registered_descriptor(
                    directory,
                    root,
                    Scope::Estate,
                    RootShape::Private,
                )
                .ok()
            })
        } else {
            None
        };
        self.estate_journal.is_some() && (role.entry().is_none() || self.loop_journal.is_some())
    }

    fn configuration_error(&self) -> Option<&str> {
        self.configuration_error.as_deref()
    }

    fn classifier_root(&self) -> Option<File> {
        self.loop_journal.as_ref()?.root_descriptor()
    }

    fn destination(&self, scope: Scope) -> Option<&'static str> {
        if self.worker && scope == Scope::Estate {
            return self.outbox.as_ref().map(|_outbox| "loop-outbox");
        }
        let journal = match scope {
            Scope::Loop => self.loop_journal.as_ref(),
            Scope::Estate => self.estate_journal.as_ref(),
        }?;
        journal.registered_root.as_ref().map(|_| match scope {
            Scope::Loop => "caller-loop-journal",
            Scope::Estate => "estate-journal",
        })
    }

    fn record(&mut self, record: &EscalationRecord) -> Result<(), Self::Error> {
        if self.worker && record.scope() == "estate" {
            return self.write_outbox(record);
        }
        let journal = match record.scope() {
            "loop" => &mut self.loop_journal,
            _ => &mut self.estate_journal,
        };
        journal
            .as_mut()
            .ok_or(JournalError::StateRootUnset)?
            .record(record)
    }

    fn set_lock_budget(&mut self, remaining: Duration) {
        for journal in [&mut self.loop_journal, &mut self.estate_journal]
            .into_iter()
            .flatten()
        {
            journal.set_lock_budget(remaining);
        }
    }

    fn consume_approval(
        &mut self,
        request: &ApprovalRequest<'_>,
    ) -> Result<Option<String>, Self::Error> {
        self.loop_journal
            .as_mut()
            .ok_or(JournalError::StateRootUnset)?
            .consume_approval(request)
    }
}

/// Failure to configure, validate, read, lock, or append the private journal.
#[derive(Debug)]
pub enum JournalError {
    /// The required state-root variable was absent.
    StateRootUnset,
    /// The registered outbox is absent or cannot be opened safely.
    OutboxUnavailable {
        /// The path or missing registration and its failure.
        detail: String,
    },
    /// The outbox directory does not have mode 1775.
    OutboxShape {
        /// Observed directory mode.
        mode: u32,
    },
    /// The outbox directory is not owned by its registered loop uid.
    OutboxOwner {
        /// Observed directory owner.
        actual: u32,
        /// Registered loop uid.
        expected: u32,
    },
    /// An event file with the same identifier already exists.
    OutboxCollision {
        /// Colliding event identifier.
        event_id: String,
    },
    /// A newly created outbox file does not belong to the caller.
    OutboxFileOwner {
        /// Observed file owner.
        actual: u32,
        /// Caller effective uid.
        expected: u32,
    },
    /// Creating or writing the new outbox file failed.
    OutboxWrite(io::Error),
    /// Synchronizing the outbox file or directory failed.
    OutboxSync(io::Error),
    /// The selected state root was not absolute.
    StateRootNotAbsolute,
    /// State-root metadata could not be read.
    RootMetadata(io::Error),
    /// The state root could not be created.
    RootCreate(io::Error),
    /// Permissions on a newly created state root could not be enforced.
    RootPermissions(io::Error),
    /// A newly created private dirent could not be synchronized through its parent directory.
    DirectorySync(io::Error),
    /// The state root was not a directory.
    RootNotDirectory,
    /// A pre-existing state root did not have mode 0700.
    RootMode(u32),
    /// A public root grants group or other write permission.
    PublicRootWritable(u32),
    /// The state root was not owned by the process's effective uid.
    RootOwner {
        /// Owner reported by state-root metadata.
        actual: u32,
        /// Effective uid reported by a file created beneath the root.
        effective: u32,
    },
    /// The effective-uid ownership probe could not be created or removed safely.
    RootOwnershipProbe(io::Error),
    /// A private file could not be created or opened safely.
    Open(io::Error),
    /// A private file's metadata could not be read.
    FileMetadata(io::Error),
    /// A final path component was a symbolic link.
    FinalSymlink,
    /// A private path was not a regular file.
    NotRegularFile,
    /// A private file did not have mode 0600.
    FileMode(u32),
    /// A public journal file grants group or other write permission.
    PublicFileWritable(u32),
    /// A public journal file is not owned by the process's effective uid.
    PublicFileOwner {
        /// Owner reported by file metadata.
        actual: u32,
        /// Effective uid of the process.
        effective: u32,
    },
    /// Permissions on a newly created private file could not be enforced.
    FilePermissions(io::Error),
    /// The journal lock could not be acquired.
    Lock {
        /// Absolute lock-file path.
        path: PathBuf,
        /// Underlying lock failure.
        source: io::Error,
    },
    /// Existing journal bytes could not be read.
    Read(io::Error),
    /// A complete existing journal line was malformed.
    Parse(serde_json::Error),
    /// An existing journal event did not have the required shape.
    RecordShape(&'static str),
    /// The requested event identifier was not present.
    UnknownEventId,
    /// The requested event already had a disposition.
    AlreadyAdjudicated,
    /// A serialized record could not be formed.
    Serialize(serde_json::Error),
    /// Fixed record fields alone exceeded the line cap.
    RecordTooLarge,
    /// A complete journal line could not be appended.
    Append(io::Error),
    /// Appended journal data could not be synchronized.
    Sync(io::Error),
    /// The system clock could not supply a record timestamp.
    Clock,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateRootUnset => write!(formatter, "permission triage state root is unset"),
            Self::OutboxUnavailable { detail } => {
                write!(formatter, "loop outbox unavailable: {detail}")
            }
            Self::OutboxShape { mode } => {
                write!(formatter, "loop outbox mode is {mode:04o}, not 1775")
            }
            Self::OutboxOwner { actual, expected } => write!(
                formatter,
                "loop outbox owner uid is {actual}, not registered loop uid {expected}"
            ),
            Self::OutboxCollision { event_id } => write!(
                formatter,
                "loop outbox event identifier already exists: {event_id}"
            ),
            Self::OutboxFileOwner { actual, expected } => write!(
                formatter,
                "loop outbox file owner uid is {actual}, not caller uid {expected}"
            ),
            Self::OutboxWrite(error) => write!(formatter, "loop outbox write failed: {error}"),
            Self::OutboxSync(error) => {
                write!(formatter, "loop outbox synchronization failed: {error}")
            }
            Self::StateRootNotAbsolute => {
                write!(formatter, "permission triage state root is not absolute")
            }
            Self::RootMetadata(error) => write!(formatter, "state-root metadata failed: {error}"),
            Self::RootCreate(error) => write!(formatter, "state-root creation failed: {error}"),
            Self::RootPermissions(error) => {
                write!(
                    formatter,
                    "state-root permission enforcement failed: {error}"
                )
            }
            Self::DirectorySync(error) => {
                write!(
                    formatter,
                    "private directory synchronization failed: {error}"
                )
            }
            Self::RootNotDirectory => write!(formatter, "state root is not a directory"),
            Self::RootMode(mode) => write!(formatter, "state-root mode is {mode:04o}, not 0700"),
            Self::PublicRootWritable(mode) => write!(
                formatter,
                "public state-root mode {mode:04o} grants group or other write permission"
            ),
            Self::RootOwner { actual, effective } => write!(
                formatter,
                "state-root owner uid is {actual}, not process effective uid {effective}"
            ),
            Self::RootOwnershipProbe(error) => {
                write!(formatter, "state-root ownership probe failed: {error}")
            }
            Self::Open(error) => write!(formatter, "private journal file open failed: {error}"),
            Self::FileMetadata(error) => {
                write!(formatter, "private journal file metadata failed: {error}")
            }
            Self::FinalSymlink => write!(formatter, "journal final component is a symbolic link"),
            Self::NotRegularFile => write!(formatter, "journal path is not a regular file"),
            Self::FileMode(mode) => write!(formatter, "private file mode is {mode:04o}, not 0600"),
            Self::PublicFileWritable(mode) => write!(
                formatter,
                "public journal mode {mode:04o} grants group or other write permission"
            ),
            Self::PublicFileOwner { actual, effective } => write!(
                formatter,
                "public journal owner uid is {actual}, not process effective uid {effective}"
            ),
            Self::FilePermissions(error) => {
                write!(
                    formatter,
                    "private file permission enforcement failed: {error}"
                )
            }
            Self::Lock { path, source } => {
                write!(
                    formatter,
                    "journal lock failed at {}: {source}",
                    path.display()
                )
            }
            Self::Read(error) => write!(formatter, "journal read failed: {error}"),
            Self::Parse(error) => write!(formatter, "journal record JSON is malformed: {error}"),
            Self::RecordShape(detail) => write!(formatter, "journal record is invalid: {detail}"),
            Self::UnknownEventId => write!(formatter, "journal event identifier is unknown"),
            Self::AlreadyAdjudicated => write!(formatter, "journal event is already adjudicated"),
            Self::Serialize(error) => {
                write!(formatter, "journal record serialization failed: {error}")
            }
            Self::RecordTooLarge => write!(formatter, "journal fixed fields exceed the record cap"),
            Self::Append(error) => write!(formatter, "journal append failed: {error}"),
            Self::Sync(error) => write!(formatter, "journal data synchronization failed: {error}"),
            Self::Clock => write!(formatter, "system clock precedes the Unix epoch"),
        }
    }
}

impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RootMetadata(error)
            | Self::RootCreate(error)
            | Self::RootPermissions(error)
            | Self::DirectorySync(error)
            | Self::RootOwnershipProbe(error)
            | Self::Open(error)
            | Self::FileMetadata(error)
            | Self::FilePermissions(error)
            | Self::OutboxWrite(error)
            | Self::OutboxSync(error)
            | Self::Read(error)
            | Self::Append(error)
            | Self::Sync(error) => Some(error),
            Self::Lock { source, .. } => Some(source),
            Self::Parse(error) | Self::Serialize(error) => Some(error),
            Self::StateRootUnset
            | Self::OutboxUnavailable { .. }
            | Self::OutboxShape { .. }
            | Self::OutboxOwner { .. }
            | Self::OutboxCollision { .. }
            | Self::OutboxFileOwner { .. }
            | Self::StateRootNotAbsolute
            | Self::RootNotDirectory
            | Self::RootMode(_)
            | Self::PublicRootWritable(_)
            | Self::RootOwner { .. }
            | Self::FinalSymlink
            | Self::NotRegularFile
            | Self::FileMode(_)
            | Self::PublicFileWritable(_)
            | Self::PublicFileOwner { .. }
            | Self::RecordShape(_)
            | Self::UnknownEventId
            | Self::AlreadyAdjudicated
            | Self::RecordTooLarge
            | Self::Clock => None,
        }
    }
}

/// Read the journal through the same root and file checks without creating or writing anything.
///
/// A valid state root with no journal yet is an empty journal.
///
/// # Errors
///
/// Returns an error when the root is absent or unsafe, or the journal cannot be opened and read.
pub fn read_journal_bytes(state_root: &Path) -> Result<Vec<u8>, JournalError> {
    read_scoped_journal_bytes(state_root, Scope::Loop, RootShape::Private)
}

fn read_scoped_journal_bytes(
    state_root: &Path,
    scope: Scope,
    shape: RootShape,
) -> Result<Vec<u8>, JournalError> {
    match shape {
        RootShape::Private => verify_existing_root_for_review(state_root)?,
        RootShape::Public => verify_existing_public_root(state_root)?,
    }
    let path = state_root.join(journal_filename(scope));
    match open_existing_journal_read_only(&path, shape) {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(JournalError::Read)?;
            Ok(bytes)
        }
        Err(JournalError::Open(error)) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Compute the canonical request-shape digest retained by the journal.
#[must_use]
pub fn request_digest(tool: &str, cwd: &str, command: &str) -> String {
    let mut canonical = Vec::with_capacity(tool.len() + cwd.len() + command.len() + 24);
    for field in [tool, cwd, command] {
        let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(field.as_bytes());
    }
    sha256_digest(&canonical)
}

pub(crate) fn establish_root(root: &Path, effective_uid: Option<u32>) -> Result<(), JournalError> {
    if !root.is_absolute() {
        return Err(JournalError::StateRootNotAbsolute);
    }
    match root.symlink_metadata() {
        Ok(metadata) => verify_root_metadata(root, &metadata, effective_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(ROOT_MODE);
            match builder.create(root) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    return verify_existing_root(root, effective_uid);
                }
                Err(error) => return Err(JournalError::RootCreate(error)),
            }
            fs::set_permissions(root, fs::Permissions::from_mode(ROOT_MODE))
                .map_err(JournalError::RootPermissions)?;
            verify_existing_root(root, effective_uid)
        }
        Err(error) => Err(JournalError::RootMetadata(error)),
    }
}

fn establish_journal_root(root: &Path, journal: &Journal) -> Result<(), JournalError> {
    match journal.shape {
        RootShape::Private => establish_root(root, effective_uid_override(journal)),
        RootShape::Public => verify_existing_public_root(root),
    }
}

fn verify_existing_public_root(root: &Path) -> Result<(), JournalError> {
    let metadata = existing_root_metadata(root)?;
    if !metadata.is_dir() {
        return Err(JournalError::RootNotDirectory);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(JournalError::PublicRootWritable(mode));
    }
    let effective = fs::metadata("/proc/self")
        .map_err(JournalError::RootMetadata)?
        .uid();
    if metadata.uid() != effective {
        return Err(JournalError::RootOwner {
            actual: metadata.uid(),
            effective,
        });
    }
    Ok(())
}

fn verify_existing_root(root: &Path, effective_uid: Option<u32>) -> Result<(), JournalError> {
    let metadata = existing_root_metadata(root)?;
    verify_root_metadata(root, &metadata, effective_uid)
}

fn verify_existing_root_for_review(root: &Path) -> Result<(), JournalError> {
    let metadata = existing_root_metadata(root)?;
    verify_read_only_root_shape(&metadata)
}

fn existing_root_metadata(root: &Path) -> Result<fs::Metadata, JournalError> {
    if !root.is_absolute() {
        return Err(JournalError::StateRootNotAbsolute);
    }
    root.symlink_metadata().map_err(JournalError::RootMetadata)
}

fn verify_read_only_root_shape(metadata: &fs::Metadata) -> Result<(), JournalError> {
    if !metadata.is_dir() {
        return Err(JournalError::RootNotDirectory);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if !matches!(mode, ROOT_MODE | 0o500) {
        return Err(JournalError::RootMode(mode));
    }
    Ok(())
}

fn verify_root_metadata(
    root: &Path,
    metadata: &fs::Metadata,
    effective_uid: Option<u32>,
) -> Result<(), JournalError> {
    verify_root_shape(metadata)?;
    verify_root_owner(root, metadata, effective_uid)
}

fn verify_root_shape(metadata: &fs::Metadata) -> Result<(), JournalError> {
    if !metadata.is_dir() {
        return Err(JournalError::RootNotDirectory);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != ROOT_MODE {
        return Err(JournalError::RootMode(mode));
    }
    Ok(())
}

fn verify_root_owner(
    root: &Path,
    metadata: &fs::Metadata,
    effective_uid: Option<u32>,
) -> Result<(), JournalError> {
    let effective = match effective_uid {
        Some(uid) => uid,
        None => probe_effective_uid(root)?,
    };
    let actual = metadata.uid();
    if actual != effective {
        return Err(JournalError::RootOwner { actual, effective });
    }
    Ok(())
}

fn probe_effective_uid(root: &Path) -> Result<u32, JournalError> {
    #[cfg(test)]
    if OWNER_PROBE_FAILURE.with(Cell::get) {
        return Err(JournalError::RootOwnershipProbe(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected state-root ownership probe failure",
        )));
    }
    let path = owner_probe_path(root)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(&path)
        .map_err(JournalError::RootOwnershipProbe)?;
    let uid = file
        .metadata()
        .map(|metadata| metadata.uid())
        .map_err(JournalError::RootOwnershipProbe);
    drop(file);
    let removed = fs::remove_file(path).map_err(JournalError::RootOwnershipProbe);
    match (uid, removed) {
        (Ok(uid), Ok(())) => Ok(uid),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn owner_probe_path(root: &Path) -> Result<PathBuf, JournalError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| {
            JournalError::RootOwnershipProbe(io::Error::other("system clock precedes Unix epoch"))
        })?
        .as_nanos();
    let sequence = OWNER_PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(
        ".permission-triage-owner-probe.{}.{nanos}-{sequence}",
        std::process::id()
    )))
}

#[cfg(test)]
pub(crate) fn test_owner_probe_path(root: &Path) -> Result<PathBuf, JournalError> {
    owner_probe_path(root)
}

fn open_journal_file(path: &Path, journal: &Journal) -> Result<File, JournalError> {
    let file_mode = match journal.shape {
        RootShape::Private => FILE_MODE,
        RootShape::Public => PUBLIC_FILE_MODE,
    };
    let mut create = OpenOptions::new();
    create
        .read(true)
        .write(false)
        .append(true)
        .create_new(true)
        .mode(file_mode)
        .custom_flags(OPEN_NO_FOLLOW);
    match create.open(path) {
        Ok(file) => {
            file.set_permissions(fs::Permissions::from_mode(file_mode))
                .map_err(JournalError::FilePermissions)?;
            verify_journal_file(&file, journal.shape)?;
            sync_parent_directory(path, journal)?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing
                .read(true)
                .write(false)
                .append(true)
                .custom_flags(OPEN_NO_FOLLOW);
            let file = existing.open(path).map_err(open_error)?;
            verify_journal_file(&file, journal.shape)?;
            Ok(file)
        }
        Err(error) => Err(open_error(error)),
    }
}

fn sync_parent_directory(path: &Path, journal: &Journal) -> Result<(), JournalError> {
    let parent = path.parent().ok_or_else(|| {
        JournalError::DirectorySync(io::Error::other("private path has no parent directory"))
    })?;
    let directory = File::open(parent).map_err(JournalError::DirectorySync)?;
    directory.sync_data().map_err(JournalError::DirectorySync)?;
    record_directory_sync(journal);
    Ok(())
}

struct LockGuard {
    path: PathBuf,
    file: File,
    release_wait: Duration,
}

#[cfg(test)]
fn observe_release(step: &str) {
    RELEASE_OBSERVER.with(|observer| {
        if let Some(action) = observer.borrow_mut().as_mut() {
            action(step);
        }
    });
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let started = Instant::now();
        loop {
            if file_owns_path(&self.file, &self.path) {
                #[cfg(test)]
                observe_release("owned");
                let _removed = fs::remove_file(&self.path);
                return;
            }
            #[cfg(test)]
            observe_release("lookup");
            match self.path.symlink_metadata() {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    #[cfg(test)]
                    observe_release("missing");
                    let elapsed = started.elapsed();
                    #[cfg(test)]
                    let elapsed = RELEASE_ELAPSED.with(|clock| clock.get().unwrap_or(elapsed));
                    let Some(delay) = lock_retry_delay(elapsed, self.release_wait) else {
                        return;
                    };
                    thread::sleep(delay);
                }
                Ok(metadata) => {
                    if self
                        .file
                        .metadata()
                        .is_ok_and(|own| own.dev() == metadata.dev() && own.ino() == metadata.ino())
                    {
                        let _removed = fs::remove_file(&self.path);
                    }
                    return;
                }
                Err(_) => return,
            }
        }
    }
}

fn file_owns_path(file: &File, path: &Path) -> bool {
    let Ok(file_metadata) = file.metadata() else {
        return false;
    };
    let Ok(path_metadata) = path.symlink_metadata() else {
        return false;
    };
    file_metadata.dev() == path_metadata.dev() && file_metadata.ino() == path_metadata.ino()
}

fn lock_release_window(remaining: Duration) -> Duration {
    remaining / LOCK_RELEASE_BUDGET_DIVISOR
}

#[cfg(test)]
pub(crate) fn test_lock_guard_restored_after(root: &Path) -> Result<bool, JournalError> {
    let path = root.join(LOCK_NAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(&path)
        .map_err(open_error)?;
    let guard = LockGuard {
        path: path.clone(),
        file,
        release_wait: lock_release_window(LOCK_WAIT),
    };
    let claim = root.join("escalations.lock.steal.fixture");
    fs::rename(&path, &claim).map_err(|error| lock_error(&path, error))?;
    let restore_path = path.clone();
    let (restore_tx, restore_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let restorer = thread::spawn(move || {
        // These bounds detect a broken fixture protocol; no elapsed wall decides the claim.
        restore_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("missing-path signal");
        let result = fs::rename(claim, restore_path);
        done_tx.send(()).expect("restoration signal");
        result
    });
    let steps = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&steps);
    RELEASE_ELAPSED.with(|clock| clock.set(Some(Duration::ZERO)));
    RELEASE_OBSERVER.with(|observer| {
        *observer.borrow_mut() = Some(Box::new(move |step| {
            if step == "missing" {
                observed.borrow_mut().push("missing");
                restore_tx
                    .send(())
                    .expect("request restoration after both missing checks");
                done_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("restoration completed");
                observed.borrow_mut().push("restored");
            } else if step == "owned" {
                observed.borrow_mut().push("owned");
            }
        }));
    });
    drop(guard);
    RELEASE_OBSERVER.with(|observer| drop(observer.borrow_mut().take()));
    RELEASE_ELAPSED.with(|clock| clock.set(None));
    let restore_result = restorer
        .join()
        .map_err(|_| lock_error(&path, io::Error::other("lock restorer panicked")))?;
    restore_result.map_err(|error| lock_error(&path, error))?;
    let ordered = *steps.borrow() == ["missing", "restored", "owned"];
    Ok(ordered && !path.exists())
}

fn acquire_lock(root: &Path, journal: &Journal) -> Result<LockGuard, JournalError> {
    let path = root.join(lock_filename(journal.scope));
    reap_orphaned_claims(root, journal);
    let started = Instant::now();
    #[cfg(test)]
    let mut vanish_before_open = journal.test_hooks.vanish_before_open();
    loop {
        #[cfg(test)]
        journal.test_hooks.record_acquire_poll();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(OPEN_NO_FOLLOW)
            .open(&path);
        match file {
            Ok(file) => {
                let guard = LockGuard {
                    path: path.clone(),
                    file,
                    release_wait: lock_release_window(
                        journal.lock_wait.saturating_sub(started.elapsed()),
                    ),
                };
                write_lock_pid(&guard.file, &path)?;
                guard
                    .file
                    .set_permissions(fs::Permissions::from_mode(FILE_MODE))
                    .map_err(JournalError::FilePermissions)?;
                #[cfg(test)]
                if journal.test_hooks.validation_failure() {
                    return Err(lock_error(
                        &path,
                        io::Error::other("injected lock validation failure"),
                    ));
                }
                verify_private_file(&guard.file)?;
                sync_parent_directory(&path, journal)?;
                return Ok(guard);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                #[cfg(test)]
                if vanish_before_open {
                    fs::remove_file(&path).map_err(|error| lock_error(&path, error))?;
                    vanish_before_open = false;
                }
                match open_existing_read_only(&path) {
                    Ok(existing) => drop(existing),
                    Err(JournalError::Open(error)) if error.kind() == io::ErrorKind::NotFound => {
                        let Some(delay) = lock_retry_delay(started.elapsed(), journal.lock_wait)
                        else {
                            return Err(lock_error(
                                &path,
                                io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "lock-file race continued through the wait deadline",
                                ),
                            ));
                        };
                        thread::sleep(delay);
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                match steal_stale_lock(&path)? {
                    StealOutcome::Recovered => {
                        if started.elapsed() >= journal.lock_wait {
                            return Err(lock_error(
                                &path,
                                io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "stale lock recovery exhausted the wait deadline",
                                ),
                            ));
                        }
                    }
                    StealOutcome::Fresh | StealOutcome::Retry => {
                        let Some(delay) = lock_retry_delay(started.elapsed(), journal.lock_wait)
                        else {
                            return Err(lock_error(
                                &path,
                                io::Error::new(io::ErrorKind::WouldBlock, "lock-file wait elapsed"),
                            ));
                        };
                        thread::sleep(delay);
                    }
                }
            }
            Err(error) => return Err(open_error(error)),
        }
    }
}

fn reap_orphaned_claims(root: &Path, journal: &Journal) {
    let Ok(entries) = read_orphaned_entries(root, journal) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = orphaned_private_file_pid(&name) else {
            continue;
        };
        let _reaped = reap_orphaned_entry(&entry.path(), pid, journal);
    }
}

#[cfg(test)]
fn reap_orphaned_entry(path: &Path, pid: u32, journal: &Journal) -> Result<(), JournalError> {
    if path.file_name() == journal.test_hooks.reap_entry_failure() {
        return Err(lock_error(
            path,
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected orphan-reaper entry failure",
            ),
        ));
    }
    reap_orphaned_claim(path, pid)
}

#[cfg(not(test))]
fn reap_orphaned_entry(path: &Path, pid: u32, _journal: &Journal) -> Result<(), JournalError> {
    reap_orphaned_claim(path, pid)
}

#[cfg(test)]
fn read_orphaned_entries(root: &Path, journal: &Journal) -> io::Result<fs::ReadDir> {
    if journal.test_hooks.reap_read_dir_failure() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected orphan-reaper directory read failure",
        ));
    }
    fs::read_dir(root)
}

#[cfg(not(test))]
fn read_orphaned_entries(root: &Path, _journal: &Journal) -> io::Result<fs::ReadDir> {
    fs::read_dir(root)
}

fn orphaned_private_file_pid(name: &std::ffi::OsStr) -> Option<u32> {
    let name = name.to_str()?;
    if let Some(suffix) = name
        .strip_prefix("escalations.lock.steal.")
        .or_else(|| name.strip_prefix("estate-escalations.lock.steal."))
    {
        return current_orphan_pid(suffix);
    }
    let suffix = name.strip_prefix(".permission-triage-owner-probe.")?;
    current_orphan_pid(suffix).or_else(|| legacy_probe_pid(suffix))
}

fn current_orphan_pid(suffix: &str) -> Option<u32> {
    let (pid, identity) = suffix.split_once('.')?;
    let (nanos, sequence) = identity.split_once('-')?;
    if nanos.is_empty()
        || sequence.is_empty()
        || !nanos.bytes().all(|byte| byte.is_ascii_digit())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    pid.parse().ok()
}

fn legacy_probe_pid(suffix: &str) -> Option<u32> {
    let (pid, sequence) = suffix.split_once('-')?;
    if pid.is_empty()
        || sequence.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    pid.parse().ok()
}

fn reap_orphaned_claim(path: &Path, pid: u32) -> Result<(), JournalError> {
    let first = match lock_snapshot(path) {
        Ok(snapshot) => snapshot,
        Err(error) if journal_error_is_not_found(&error) => return Ok(()),
        Err(error) => return Err(steal_error(path, &error)),
    };
    let too_old = SystemTime::now()
        .duration_since(first.modified)
        .is_ok_and(|age| age >= LOCK_STALE_AFTER);
    if pid_is_live(pid) || !too_old {
        return Ok(());
    }
    let recovery_claim = lock_claim_path(path)?;
    match fs::rename(path, &recovery_claim) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(lock_error(path, error)),
    }
    match lock_snapshot(&recovery_claim) {
        Ok(claimed) if claimed == first => match fs::remove_file(&recovery_claim) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(lock_error(path, error)),
        },
        Ok(_) | Err(_) => {}
    }
    restore_displaced_lock(path, &recovery_claim);
    Ok(())
}

pub(crate) fn lock_retry_delay(elapsed: Duration, wait: Duration) -> Option<Duration> {
    let remaining = wait.saturating_sub(elapsed);
    (!remaining.is_zero()).then(|| LOCK_POLL.min(remaining))
}

fn write_lock_pid(mut file: &File, path: &Path) -> Result<(), JournalError> {
    writeln!(file, "{}", std::process::id()).map_err(|error| lock_error(path, error))?;
    file.sync_data().map_err(|error| lock_error(path, error))
}

#[derive(PartialEq, Eq)]
struct LockSnapshot {
    device: u64,
    inode: u64,
    modified: SystemTime,
    contents: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StealOutcome {
    Fresh,
    Recovered,
    Retry,
}

pub(crate) fn steal_stale_lock(path: &Path) -> Result<StealOutcome, JournalError> {
    let first = match lock_snapshot(path) {
        Ok(snapshot) => snapshot,
        Err(error) if journal_error_is_not_found(&error) => return Ok(StealOutcome::Retry),
        Err(error) => return Err(steal_error(path, &error)),
    };
    let pid_dead = std::str::from_utf8(&first.contents)
        .ok()
        .map(str::trim)
        .and_then(|value| value.parse::<u32>().ok())
        .is_none_or(|pid| !pid_is_live(pid));
    let too_old = SystemTime::now()
        .duration_since(first.modified)
        .is_ok_and(|age| age >= LOCK_STALE_AFTER);
    if !pid_dead || !too_old {
        return Ok(StealOutcome::Fresh);
    }
    #[cfg(test)]
    observe_steal("snapshot");
    let claim = lock_claim_path(path)?;
    match fs::rename(path, &claim) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(StealOutcome::Retry);
        }
        Err(error) => return Err(lock_error(path, error)),
    }
    match lock_snapshot(&claim) {
        Ok(claimed) if claimed == first => match fs::remove_file(&claim) {
            Ok(()) => return Ok(StealOutcome::Recovered),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(StealOutcome::Retry);
            }
            Err(error) => return Err(lock_error(path, error)),
        },
        Ok(_) | Err(_) => {}
    }
    #[cfg(test)]
    observe_steal("restore");
    restore_displaced_lock(path, &claim);
    Ok(StealOutcome::Retry)
}

#[cfg(test)]
fn observe_steal(step: &str) {
    STEAL_OBSERVER.with(|observer| {
        if let Some(action) = observer.borrow_mut().as_mut() {
            action(step);
        }
    });
}

/// # Panics
/// Panics only if the fixture rendezvous fails, which production cannot arrange.
#[cfg(test)]
pub(crate) fn test_two_stealers_restore_during_release(root: &Path) -> Result<bool, JournalError> {
    use std::sync::mpsc::channel;
    let path = root.join(LOCK_NAME);
    let (snapshot_tx, snapshot_rx) = channel();
    let (claim_tx, claim_rx) = channel();
    let (displaced_tx, displaced_rx) = channel();
    let (restore_tx, restore_rx) = channel();
    let (done_tx, done_rx) = channel();
    let stealing_path = path.clone();
    let stealer = thread::spawn(move || {
        STEAL_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Box::new(move |step| {
                if step == "snapshot" {
                    snapshot_tx.send(()).expect("stale snapshot");
                    claim_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("fresh lock");
                } else {
                    displaced_tx.send(()).expect("fresh lock displaced");
                    restore_rx
                        .recv_timeout(Duration::from_secs(10))
                        .expect("release lookup");
                }
            }));
        });
        let result = steal_stale_lock(&stealing_path);
        done_tx.send(()).expect("restoration complete");
        result
    });
    snapshot_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("first snapshot");
    let recovered = steal_stale_lock(&path)? == StealOutcome::Recovered;
    let guard = acquire_lock(root, &Journal::from_state_root(root))?;
    claim_tx.send(()).expect("second stealer may claim");
    displaced_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("displaced lock");
    RELEASE_OBSERVER.with(|observer| {
        *observer.borrow_mut() = Some(Box::new(move |step| {
            if step == "lookup" {
                restore_tx.send(()).expect("restore between lookups");
                done_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("restored lock");
            }
        }));
    });
    drop(guard);
    RELEASE_OBSERVER.with(|observer| drop(observer.borrow_mut().take()));
    let retried = stealer.join().expect("stealer joined")? == StealOutcome::Retry;
    Ok(recovered && retried && !path.exists())
}

fn journal_error_is_not_found(error: &JournalError) -> bool {
    match error {
        JournalError::Open(source) | JournalError::Lock { source, .. } => {
            source.kind() == io::ErrorKind::NotFound
        }
        _ => false,
    }
}

fn steal_error(path: &Path, error: &JournalError) -> JournalError {
    lock_error(path, io::Error::other(error.to_string()))
}

fn lock_claim_path(path: &Path) -> Result<PathBuf, JournalError> {
    let root = path
        .parent()
        .ok_or_else(|| lock_error(path, io::Error::other("lock path has no state-root parent")))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| lock_error(path, io::Error::other("system clock precedes Unix epoch")))?
        .as_nanos();
    let sequence = LOCK_CLAIM_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(
        "{}.steal.{}.{nanos}-{sequence}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| lock_error(path, io::Error::other("invalid lock filename")))?,
        std::process::id()
    )))
}

fn restore_displaced_lock(path: &Path, claim: &Path) {
    let path_is_absent = path
        .symlink_metadata()
        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
    if path_is_absent && fs::rename(claim, path).is_ok() {
        return;
    }
    let _removed = fs::remove_file(claim);
}

fn lock_snapshot(path: &Path) -> Result<LockSnapshot, JournalError> {
    let mut file = open_existing_read_only(path)?;
    let metadata = file.metadata().map_err(|error| lock_error(path, error))?;
    let modified = metadata
        .modified()
        .map_err(|error| lock_error(path, error))?;
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(64)
        .read_to_end(&mut contents)
        .map_err(|error| lock_error(path, error))?;
    Ok(LockSnapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        modified,
        contents,
    })
}

fn pid_is_live(pid: u32) -> bool {
    match fs::read(Path::new("/proc").join(pid.to_string()).join("stat")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Ok(stat) => proc::state(&stat) != Some(b'Z'),
        Err(_) => true,
    }
}

fn lock_error(path: &Path, source: io::Error) -> JournalError {
    JournalError::Lock {
        path: path.to_path_buf(),
        source,
    }
}

fn open_existing_read_only(path: &Path) -> Result<File, JournalError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(path)
        .map_err(open_error)?;
    verify_private_file(&file)?;
    Ok(file)
}

fn open_existing_journal_read_only(path: &Path, shape: RootShape) -> Result<File, JournalError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(path)
        .map_err(open_error)?;
    verify_journal_file(&file, shape)?;
    Ok(file)
}

fn verify_journal_file(file: &File, shape: RootShape) -> Result<(), JournalError> {
    if shape == RootShape::Private {
        return verify_private_file(file);
    }
    let metadata = file.metadata().map_err(JournalError::FileMetadata)?;
    if !metadata.is_file() {
        return Err(JournalError::NotRegularFile);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(JournalError::PublicFileWritable(mode));
    }
    let effective = fs::metadata("/proc/self")
        .map_err(JournalError::FileMetadata)?
        .uid();
    if metadata.uid() != effective {
        return Err(JournalError::PublicFileOwner {
            actual: metadata.uid(),
            effective,
        });
    }
    Ok(())
}

fn open_error(error: io::Error) -> JournalError {
    if error.raw_os_error() == Some(LOOP_ERROR) {
        JournalError::FinalSymlink
    } else {
        JournalError::Open(error)
    }
}

fn verify_private_file(file: &File) -> Result<(), JournalError> {
    let metadata = file.metadata().map_err(JournalError::FileMetadata)?;
    if !metadata.is_file() {
        return Err(JournalError::NotRegularFile);
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != FILE_MODE {
        return Err(JournalError::FileMode(mode));
    }
    Ok(())
}

fn escalation_value(record: &EscalationRecord) -> Result<Value, JournalError> {
    if !record.recorded_at_valid() {
        return Err(JournalError::Clock);
    }
    let mut object = Map::new();
    object.insert("schema".to_owned(), Value::from(VERDICT_SCHEMA));
    object.insert(
        "event".to_owned(),
        Value::from(if record.classification() == Some("suspicious") {
            "escalated"
        } else {
            "verdict"
        }),
    );
    object.insert("event_id".to_owned(), Value::from(record.event_id()));
    object.insert("recorded_at".to_owned(), Value::from(record.recorded_at()));
    object.insert(
        "tool_use_id".to_owned(),
        record.tool_use_id().map_or(Value::Null, Value::from),
    );
    object.insert(
        "request_digest".to_owned(),
        record.request_digest().map_or(Value::Null, Value::from),
    );
    object.insert(
        "tool".to_owned(),
        record.tool().map_or(Value::Null, Value::from),
    );
    object.insert(
        "cwd".to_owned(),
        record.cwd().map_or(Value::Null, Value::from),
    );
    object.insert(
        "command".to_owned(),
        record.command().map_or(Value::Null, Value::from),
    );
    object.insert(
        "classification".to_owned(),
        record.classification().map_or(Value::Null, Value::from),
    );
    object.insert("reason".to_owned(), Value::from(record.reason()));
    object.insert("scope".to_owned(), Value::from(record.scope()));
    object.insert("mode".to_owned(), Value::from(record.mode().as_str()));
    object.insert(
        "would_be_decision".to_owned(),
        Value::from(record.would_be_decision().as_str()),
    );
    object.insert(
        "emitted_decision".to_owned(),
        record
            .emitted_decision()
            .map_or(Value::Null, |decision| Value::from(decision.as_str())),
    );
    object.insert("role".to_owned(), Value::from(record.role()));
    object.insert(
        "loop_name".to_owned(),
        record.loop_name().map_or(Value::Null, Value::from),
    );
    object.insert(
        "stale_session".to_owned(),
        Value::from(record.stale_session()),
    );
    object.insert(
        "general_rubric_digest".to_owned(),
        Value::from(record.general_rubric_digest()),
    );
    object.insert(
        "owner_rubric_digest".to_owned(),
        record
            .owner_rubric_digest()
            .map_or(Value::Null, Value::from),
    );
    object.insert(
        "domain_rubric_digest".to_owned(),
        record
            .domain_rubric_digest()
            .map_or(Value::Null, Value::from),
    );
    object.insert(
        "model_status".to_owned(),
        Value::from(record.model_status()),
    );
    object.insert(
        "wall_ms".to_owned(),
        Value::from(u64::try_from(record.wall_ms()).unwrap_or(u64::MAX)),
    );
    object.insert(
        "model_wall_ms".to_owned(),
        record.model_wall_ms().map_or(Value::Null, |wall| {
            Value::from(u64::try_from(wall).unwrap_or(u64::MAX))
        }),
    );
    Ok(Value::Object(object))
}

#[cfg(test)]
struct BaseFields {
    event: &'static str,
    event_id: String,
    recorded_at: String,
    tool_use_id: String,
    request_digest: String,
    tool: String,
    cwd: String,
    command: String,
    classification: String,
    reason: String,
    general_rubric_digest: String,
    owner_rubric_digest: Option<String>,
    role: String,
    loop_name: Option<String>,
    stale_session: bool,
    domain_rubric_digest: Option<String>,
    model_status: String,
}

#[cfg(test)]
fn base_value(fields: BaseFields) -> Value {
    let mut object = Map::new();
    object.insert("schema".to_owned(), Value::from(SCHEMA));
    object.insert("event".to_owned(), Value::from(fields.event));
    object.insert("event_id".to_owned(), Value::from(fields.event_id));
    object.insert("recorded_at".to_owned(), Value::from(fields.recorded_at));
    object.insert("tool_use_id".to_owned(), Value::from(fields.tool_use_id));
    object.insert(
        "request_digest".to_owned(),
        Value::from(fields.request_digest),
    );
    object.insert("tool".to_owned(), Value::from(fields.tool));
    object.insert("cwd".to_owned(), Value::from(fields.cwd));
    object.insert("command".to_owned(), Value::from(fields.command));
    object.insert(
        "classification".to_owned(),
        Value::from(fields.classification),
    );
    object.insert("reason".to_owned(), Value::from(fields.reason));
    object.insert(
        "general_rubric_digest".to_owned(),
        Value::from(fields.general_rubric_digest),
    );
    object.insert(
        "owner_rubric_digest".to_owned(),
        fields.owner_rubric_digest.map_or(Value::Null, Value::from),
    );
    object.insert("role".to_owned(), Value::from(fields.role));
    object.insert(
        "loop_name".to_owned(),
        fields.loop_name.map_or(Value::Null, Value::from),
    );
    object.insert(
        "stale_session".to_owned(),
        Value::from(fields.stale_session),
    );
    object.insert(
        "domain_rubric_digest".to_owned(),
        fields.domain_rubric_digest.map_or(Value::Null, Value::from),
    );
    object.insert("model_status".to_owned(), Value::from(fields.model_status));
    Value::Object(object)
}

#[cfg(test)]
pub(crate) fn serialized_order_fixture() -> Result<Vec<u8>, JournalError> {
    serde_json::to_vec(&schema_2_test_value(base_value(BaseFields {
        event: "escalated",
        event_id: "event-fixed".to_owned(),
        recorded_at: "2026-09-03T00:00:00.000000000Z".to_owned(),
        tool_use_id: "use-fixed".to_owned(),
        request_digest: "request-fixed".to_owned(),
        tool: "Bash".to_owned(),
        cwd: "/workspace/project".to_owned(),
        command: "printf fixed".to_owned(),
        classification: "suspicious".to_owned(),
        reason: "fixture reason".to_owned(),
        general_rubric_digest: "general-fixed".to_owned(),
        owner_rubric_digest: None,
        role: "unknown".to_owned(),
        loop_name: None,
        stale_session: false,
        domain_rubric_digest: None,
        model_status: "success".to_owned(),
    })))
    .map_err(JournalError::Serialize)
}

#[cfg(test)]
fn schema_2_test_value(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("schema".to_owned(), Value::from(VERDICT_SCHEMA));
        object.insert("scope".to_owned(), Value::from("estate"));
        object.insert("mode".to_owned(), Value::from("enforce"));
        object.insert("would_be_decision".to_owned(), Value::from("deny"));
        object.insert("emitted_decision".to_owned(), Value::from("deny"));
        object.insert("wall_ms".to_owned(), Value::from(0));
        object.insert("model_wall_ms".to_owned(), Value::from(0));
    }
    value
}

fn disposition_source(bytes: &[u8], event_id: &str) -> Result<Map<String, Value>, JournalError> {
    let mut source = None;
    for line in complete_lines(bytes) {
        let object = match complete_record(line) {
            Ok(object) => object,
            Err(JournalError::Parse(_) | JournalError::RecordShape(_)) => continue,
            Err(error) => return Err(error),
        };
        if string_field(&object, "event_id")? != event_id {
            continue;
        }
        if object.get("schema").and_then(Value::as_u64) != Some(VERDICT_SCHEMA) {
            continue;
        }
        let event = string_field(&object, "event")?.to_owned();
        match event.as_str() {
            "escalated" => {
                if source.replace(object).is_some() {
                    return Err(JournalError::RecordShape(
                        "event identifier has multiple escalation records",
                    ));
                }
            }
            "disposition" => return Err(JournalError::AlreadyAdjudicated),
            _ => {
                return Err(JournalError::RecordShape(
                    "event field is outside the vocabulary",
                ));
            }
        }
    }
    source.ok_or(JournalError::UnknownEventId)
}

fn unconsumed_approval_source(
    bytes: &[u8],
    request: &ApprovalRequest<'_>,
) -> Result<Option<Map<String, Value>>, JournalError> {
    let loop_name = request.role().loop_name().ok_or(JournalError::RecordShape(
        "approval request has no loop name",
    ))?;
    // Deserialize only enough to locate candidate records. Full schema and correlation validation
    // is deliberately limited to a matching escalation and records that name its identifier.
    let records = complete_lines(bytes)
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|value| match value {
            Value::Object(object) => Some(object),
            _ => None,
        })
        .collect::<Vec<_>>();
    let sources = records
        .iter()
        .filter(|record| {
            record.get("schema").and_then(Value::as_u64) == Some(VERDICT_SCHEMA)
                && record.get("event").and_then(Value::as_str) == Some("escalated")
                && record.get("mode").and_then(Value::as_str) == Some("enforce")
                && record.get("scope").and_then(Value::as_str) == Some(request.scope().as_str())
                && record.get("general_rubric_digest").and_then(Value::as_str)
                    == Some(request.general_rubric_digest())
                && record.get("owner_rubric_digest").and_then(Value::as_str)
                    == request.owner_rubric_digest()
                && record.get("domain_rubric_digest").and_then(Value::as_str)
                    == request.domain_rubric_digest()
                && record.get("tool").and_then(Value::as_str) == Some(request.tool())
                && record.get("cwd").and_then(Value::as_str) == Some(request.cwd())
                && record.get("request_digest").and_then(Value::as_str)
                    == Some(request.request_digest())
                && record.get("role").and_then(Value::as_str) == Some("orchestrator")
                && record.get("loop_name").and_then(Value::as_str) == Some(loop_name)
        })
        .collect::<Vec<_>>();
    let mut source_counts = HashMap::new();
    for source in &sources {
        if let Some(event_id) = source.get("event_id").and_then(Value::as_str) {
            *source_counts.entry(event_id).or_insert(0_usize) += 1;
        }
    }
    let mut dispositions = HashMap::<&str, Vec<&Map<String, Value>>>::new();
    let mut consumptions = HashMap::<&str, Vec<&Map<String, Value>>>::new();
    for record in &records {
        let Some(event_id) = record.get("event_id").and_then(Value::as_str) else {
            continue;
        };
        match record.get("event").and_then(Value::as_str) {
            Some("disposition") => dispositions.entry(event_id).or_default().push(record),
            Some("approval-consumed") => consumptions.entry(event_id).or_default().push(record),
            _ => {}
        }
    }
    // Candidate records are evaluated in journal order. Damage encountered before an approval
    // fails closed, but once one candidate is independently valid and unconsumed, later candidates
    // cannot change that authorization and are deliberately left unparsed.
    for source in sources {
        validate_record(source)?;
        let event_id = string_field(source, "event_id")?;
        if source_counts.get(event_id).copied().unwrap_or_default() > 1 {
            return Err(JournalError::RecordShape(
                "event identifier has multiple escalation records",
            ));
        }
        let candidate_dispositions = dispositions.get(event_id).map_or(&[][..], Vec::as_slice);
        let candidate_consumptions = consumptions.get(event_id).map_or(&[][..], Vec::as_slice);
        if candidate_has_unconsumed_approval(
            candidate_dispositions,
            candidate_consumptions,
            source,
            loop_name,
        )? {
            validate_approval_binding(source, request)?;
            return Ok(Some(source.clone()));
        }
    }
    Ok(None)
}

fn validate_approval_binding(
    source: &Map<String, Value>,
    request: &ApprovalRequest<'_>,
) -> Result<(), JournalError> {
    use execute_command::escalation::{Answer, ReviewAnswer, validate_answer};
    use execute_command::request::{Text, VerdictStatus};
    use execute_command::triage::Scope;
    let text = |value: &str| {
        Text::try_from(value.to_owned())
            .map_err(|_| JournalError::RecordShape("execute-command-escalation-shape"))
    };
    let current = crate::command_checks::binding_from_digests(
        request.request_digest(),
        request.general_rubric_digest(),
        request.owner_rubric_digest(),
        request.domain_rubric_digest(),
    );
    let answered = crate::command_checks::binding_from_digests(
        string_field(source, "request_digest")?,
        string_field(source, "general_rubric_digest")?,
        source.get("owner_rubric_digest").and_then(Value::as_str),
        source.get("domain_rubric_digest").and_then(Value::as_str),
    );
    let verdict = execute_command::triage::referral(
        &current,
        Scope::Loop,
        VerdictStatus::Valid,
        text("hook approval consumption")?,
    );
    let Some(escalation) = verdict.escalation else {
        return Err(JournalError::RecordShape(
            "execute-command-escalation-shape",
        ));
    };
    let answer = Answer {
        binding: answered,
        review: None,
        answer: ReviewAnswer::Approve,
        adjudicator: text(&request.role().prompt_line())?,
        reason: text("consume one current journal approval")?,
    };
    validate_answer(&escalation, &answer, None)
        .map_err(|_| JournalError::RecordShape("execute-command-escalation-shape"))
}

fn candidate_has_unconsumed_approval(
    dispositions: &[&Map<String, Value>],
    consumptions: &[&Map<String, Value>],
    source: &Map<String, Value>,
    loop_name: &str,
) -> Result<bool, JournalError> {
    for disposition in dispositions {
        validate_record(disposition)?;
    }
    if dispositions.len() > 1 {
        return Err(JournalError::AlreadyAdjudicated);
    }
    let Some(disposition) = dispositions.first() else {
        return Ok(false);
    };
    if !disposition_matches_source(disposition, source)
        || disposition.get("adjudicator_role").and_then(Value::as_str) != Some("orchestrator")
        || disposition
            .get("adjudicator_loop_name")
            .and_then(Value::as_str)
            != Some(loop_name)
        || disposition.get("source_scope").and_then(Value::as_str) != Some("loop")
    {
        return Err(JournalError::RecordShape(
            "approval disposition correlation mismatch",
        ));
    }
    for consumption in consumptions {
        validate_record(consumption)?;
    }
    if consumptions.len() > 1 {
        return Err(JournalError::RecordShape(
            "event identifier has multiple approval consumption records",
        ));
    }
    let disposition_is_approval =
        disposition.get("outcome").and_then(Value::as_str) == Some("adjudicated-approved");
    if let Some(consumption) = consumptions.first() {
        if !disposition_is_approval || !consumption_matches_source(consumption, source) {
            return Err(JournalError::RecordShape(
                "approval consumption correlation mismatch",
            ));
        }
        return Ok(false);
    }
    Ok(disposition_is_approval)
}

fn disposition_matches_source(
    disposition: &Map<String, Value>,
    source: &Map<String, Value>,
) -> bool {
    for field in [
        "event_id",
        "tool_use_id",
        "request_digest",
        "tool",
        "cwd",
        "command",
        "classification",
        "scope",
        "mode",
        "general_rubric_digest",
        "owner_rubric_digest",
        "role",
        "loop_name",
        "stale_session",
        "domain_rubric_digest",
    ] {
        if disposition.get(field) != source.get(field) {
            return false;
        }
    }
    true
}

fn consumption_matches_source(
    consumption: &Map<String, Value>,
    source: &Map<String, Value>,
) -> bool {
    for field in [
        "schema",
        "event_id",
        "request_digest",
        "tool",
        "cwd",
        "command",
        "general_rubric_digest",
        "owner_rubric_digest",
        "role",
        "loop_name",
        "stale_session",
        "domain_rubric_digest",
    ] {
        if consumption.get(field) != source.get(field) {
            return false;
        }
    }
    consumption.get("source_scope") == source.get("scope")
}

fn approval_consumed_value(
    source: &Map<String, Value>,
    request: &ApprovalRequest<'_>,
) -> Result<Value, JournalError> {
    let mut object = correlated_schema_2_value(
        source,
        "approval-consumed",
        "one identical orchestrator request consumed its approval",
        "journal-approval",
    )?;
    object.insert("tool_use_id".to_owned(), Value::from(request.tool_use_id()));
    object.insert(
        "classification".to_owned(),
        Value::from("routine-superloop"),
    );
    object.insert("would_be_decision".to_owned(), Value::from("allow"));
    object.insert("emitted_decision".to_owned(), Value::from("allow"));
    object.insert("mode".to_owned(), Value::from("enforce"));
    object.insert(
        "source_scope".to_owned(),
        source.get("scope").cloned().unwrap_or(Value::Null),
    );
    Ok(Value::Object(object))
}

fn complete_record(line: &[u8]) -> Result<Map<String, Value>, JournalError> {
    let value: Value = serde_json::from_slice(line).map_err(JournalError::Parse)?;
    let Value::Object(object) = value else {
        return Err(JournalError::RecordShape("top level is not an object"));
    };
    validate_record(&object)?;
    Ok(object)
}

pub(crate) fn validate_record(object: &Map<String, Value>) -> Result<(), JournalError> {
    match object.get("schema").and_then(Value::as_u64) {
        Some(SCHEMA) => validate_legacy_record(object),
        Some(VERDICT_SCHEMA) => validate_verdict_record(object),
        _ => Err(JournalError::RecordShape("schema is not 1 or 2")),
    }
}

fn validate_legacy_record(object: &Map<String, Value>) -> Result<(), JournalError> {
    for field in [
        "event",
        "event_id",
        "recorded_at",
        "tool_use_id",
        "request_digest",
        "tool",
        "cwd",
        "command",
        "classification",
        "reason",
        "general_rubric_digest",
        "role",
        "model_status",
    ] {
        string_field(object, field)?;
    }
    validate_record_shape_fields(object)?;
    let maximum_fields = match string_field(object, "event")? {
        "escalated"
            if !object.contains_key("outcome")
                && string_field(object, "classification")? == "suspicious" =>
        {
            19
        }
        "disposition"
            if object
                .get("outcome")
                .and_then(Value::as_str)
                .is_some_and(|outcome| {
                    matches!(
                        outcome,
                        "adjudicated-rule-added"
                            | "adjudicated-rejected"
                            | "corrected-and-rerun"
                            | "adjudicated-approved"
                    )
                }) =>
        {
            20
        }
        "approval-consumed"
            if !object.contains_key("outcome")
                && string_field(object, "classification")? == "adjudicated-approved"
                && string_field(object, "model_status")? == "journal-approval" =>
        {
            19
        }
        "escalated" => {
            return Err(JournalError::RecordShape(
                "escalation classification or outcome is invalid",
            ));
        }
        "disposition" => {
            return Err(JournalError::RecordShape(
                "outcome field is outside the vocabulary",
            ));
        }
        "approval-consumed" => {
            return Err(JournalError::RecordShape(
                "approval consumption shape is invalid",
            ));
        }
        _ => {
            return Err(JournalError::RecordShape(
                "event field is outside the vocabulary",
            ));
        }
    };
    let expected_fields = maximum_fields - usize::from(!object.contains_key("truncated"));
    if object.len() != expected_fields {
        return Err(JournalError::RecordShape(
            "record has missing or additional fields",
        ));
    }
    Ok(())
}

fn validate_verdict_record(object: &Map<String, Value>) -> Result<(), JournalError> {
    validate_verdict_fields(object)?;
    let classification = object.get("classification").and_then(Value::as_str);
    validate_verdict_event(object, classification)?;
    if Scope::parse(string_field(object, "scope")?).is_none() {
        return Err(JournalError::RecordShape(
            "verdict scope is not loop or estate",
        ));
    }
    let mode = string_field(object, "mode")?;
    if !matches!(mode, "audit" | "enforce") {
        return Err(JournalError::RecordShape("mode is outside the vocabulary"));
    }
    let would_be = string_field(object, "would_be_decision")?;
    if !matches!(would_be, "allow" | "deny") {
        return Err(JournalError::RecordShape(
            "would_be_decision is outside the vocabulary",
        ));
    }
    let expected = execute_command::record::hook_emission(mode == "audit", would_be == "deny")
        .map_or(Value::Null, |decision| {
            Value::from(if decision == execute_command::request::Judgement::Refuse {
                "deny"
            } else {
                "allow"
            })
        });
    if object.get("emitted_decision") != Some(&expected) {
        return Err(JournalError::RecordShape(
            "mode and emitted_decision disagree",
        ));
    }
    match (string_field(object, "role")?, object.get("loop_name")) {
        ("unknown", Some(Value::Null))
        | ("orchestrator" | "orchestrator-subagent", Some(Value::String(_))) => {}
        _ => return Err(JournalError::RecordShape("role and loop_name disagree")),
    }
    if object
        .get("truncated")
        .is_some_and(|truncated| truncated.as_bool() != Some(true))
    {
        return Err(JournalError::RecordShape("truncated is not true"));
    }
    let base_fields = match string_field(object, "event")? {
        "disposition" => 28,
        "approval-consumed" => 25,
        _ => 24,
    };
    let expected_fields = base_fields + usize::from(object.contains_key("truncated"));
    if object.len() != expected_fields {
        return Err(JournalError::RecordShape(
            "record has missing or additional fields",
        ));
    }
    Ok(())
}

fn validate_verdict_fields(object: &Map<String, Value>) -> Result<(), JournalError> {
    for field in [
        "event",
        "event_id",
        "recorded_at",
        "reason",
        "scope",
        "mode",
        "would_be_decision",
        "role",
        "general_rubric_digest",
        "model_status",
    ] {
        string_field(object, field)?;
    }
    for field in [
        "tool_use_id",
        "request_digest",
        "tool",
        "cwd",
        "command",
        "classification",
        "emitted_decision",
        "loop_name",
        "owner_rubric_digest",
        "domain_rubric_digest",
    ] {
        optional_string_field(object, field)?;
    }
    if object
        .get("stale_session")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(JournalError::RecordShape("stale_session is not a boolean"));
    }
    if object.get("wall_ms").and_then(Value::as_u64).is_none() {
        return Err(JournalError::RecordShape(
            "wall_ms is not a nonnegative integer",
        ));
    }
    match object.get("model_wall_ms") {
        Some(Value::Null) => {}
        Some(value) if value.as_u64().is_some() => {}
        _ => {
            return Err(JournalError::RecordShape(
                "model_wall_ms is not a nonnegative integer or null",
            ));
        }
    }
    let classification = object.get("classification").and_then(Value::as_str);
    if classification.is_some_and(|classification| {
        !matches!(
            classification,
            "routine-general"
                | "routine-superloop"
                | "safe"
                | "advanced-read-only"
                | "agent-error"
                | "suspicious"
        )
    }) {
        return Err(JournalError::RecordShape(
            "classification is outside the vocabulary",
        ));
    }
    Ok(())
}

fn validate_verdict_event(
    object: &Map<String, Value>,
    classification: Option<&str>,
) -> Result<(), JournalError> {
    let event = string_field(object, "event")?;
    if matches!(
        (event, classification),
        ("escalated", Some("suspicious")) | ("verdict", None)
    ) || event == "verdict" && classification.is_some_and(|value| value != "suspicious")
    {
        return Ok(());
    }
    match (event, classification) {
        ("disposition", Some("suspicious")) => {
            let outcome = string_field(object, "outcome")?;
            if !matches!(
                outcome,
                "adjudicated-rule-added"
                    | "adjudicated-rejected"
                    | "corrected-and-rerun"
                    | "adjudicated-approved"
            ) {
                return Err(JournalError::RecordShape(
                    "outcome field is outside the vocabulary",
                ));
            }
            string_field(object, "adjudicator_role")?;
            optional_string_field(object, "adjudicator_loop_name")?;
            // Writers copy both fields from the same source record; this comparison guards only
            // journals that were hand-edited after publication.
            if string_field(object, "source_scope")? != string_field(object, "scope")? {
                return Err(JournalError::RecordShape(
                    "disposition source scope does not match",
                ));
            }
        }
        ("approval-consumed", Some("routine-superloop")) => {
            // Writers copy both fields from the same source record; this comparison guards only
            // journals that were hand-edited after publication.
            if string_field(object, "source_scope")? != string_field(object, "scope")? {
                return Err(JournalError::RecordShape(
                    "approval source scope does not match",
                ));
            }
        }
        _ => {
            return Err(JournalError::RecordShape(
                "event and classification disagree",
            ));
        }
    }
    Ok(())
}

fn validate_record_shape_fields(object: &Map<String, Value>) -> Result<(), JournalError> {
    match object.get("owner_rubric_digest") {
        Some(Value::Null | Value::String(_)) => {}
        _ => {
            return Err(JournalError::RecordShape(
                "owner_rubric_digest is not a string or null",
            ));
        }
    }
    optional_string_field(object, "loop_name")?;
    match object.get("stale_session") {
        Some(Value::Bool(_)) => {}
        _ => return Err(JournalError::RecordShape("stale_session is not a boolean")),
    }
    optional_string_field(object, "domain_rubric_digest")?;
    match (string_field(object, "role")?, object.get("loop_name")) {
        ("unknown", Some(Value::Null))
        | ("orchestrator" | "orchestrator-subagent", Some(Value::String(_))) => {}
        _ => return Err(JournalError::RecordShape("role and loop_name disagree")),
    }
    if object
        .get("truncated")
        .is_some_and(|truncated| truncated.as_bool() != Some(true))
    {
        return Err(JournalError::RecordShape("truncated is not true"));
    }
    Ok(())
}

fn disposition_value(
    source: &Map<String, Value>,
    outcome: DispositionOutcome,
    detail: DispositionDetail,
    caller: &CallerRole,
) -> Result<Value, JournalError> {
    let expected_detail = match outcome {
        DispositionOutcome::AdjudicatedRuleAdded => {
            matches!(&detail, DispositionDetail::Rule(_))
        }
        DispositionOutcome::AdjudicatedRejected => {
            matches!(&detail, DispositionDetail::Rejection(_))
        }
        DispositionOutcome::CorrectedAndRerun => {
            matches!(&detail, DispositionDetail::CorrectedRequestDigest(_))
        }
        DispositionOutcome::AdjudicatedApproved => {
            matches!(&detail, DispositionDetail::ApprovedRequestDigest(_))
        }
    };
    if !expected_detail {
        return Err(JournalError::RecordShape(
            "disposition detail does not match its outcome",
        ));
    }
    let original_digest = string_field(source, "request_digest")?;
    let (reason, digest) = match detail {
        DispositionDetail::Rule(rule) => (format!("rule={rule}"), original_digest.to_owned()),
        DispositionDetail::Rejection(reason) => (reason, original_digest.to_owned()),
        DispositionDetail::CorrectedRequestDigest(digest) => {
            ("corrected request rerun".to_owned(), digest)
        }
        DispositionDetail::ApprovedRequestDigest(digest) if digest == original_digest => (
            "one identical orchestrator request approved".to_owned(),
            digest,
        ),
        DispositionDetail::ApprovedRequestDigest(_) => {
            return Err(JournalError::RecordShape(
                "approved request digest does not match its escalation",
            ));
        }
    };
    let mut object = correlated_schema_2_value(source, "disposition", &reason, "owner-mark")?;
    object.insert("request_digest".to_owned(), Value::from(digest));
    object.insert("outcome".to_owned(), Value::from(outcome.as_str()));
    object.insert("adjudicator_role".to_owned(), Value::from(caller.as_str()));
    object.insert(
        "adjudicator_loop_name".to_owned(),
        caller.loop_name().map_or(Value::Null, Value::from),
    );
    object.insert(
        "source_scope".to_owned(),
        source.get("scope").cloned().unwrap_or(Value::Null),
    );
    Ok(Value::Object(object))
}

fn correlated_schema_2_value(
    source: &Map<String, Value>,
    event: &str,
    reason: &str,
    model_status: &str,
) -> Result<Map<String, Value>, JournalError> {
    if source.get("schema").and_then(Value::as_u64) != Some(VERDICT_SCHEMA) {
        return Err(JournalError::RecordShape(
            "legacy schema cannot supply an active journal event",
        ));
    }
    let mut object = source.clone();
    object.remove("truncated");
    object.insert("event".to_owned(), Value::from(event));
    object.insert("recorded_at".to_owned(), Value::from(recorded_at()?));
    object.insert("reason".to_owned(), Value::from(reason));
    object.insert("model_status".to_owned(), Value::from(model_status));
    Ok(object)
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, JournalError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(JournalError::RecordShape(field))
}

fn optional_string_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, JournalError> {
    match object.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(JournalError::RecordShape(field)),
    }
}

fn complete_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split_inclusive(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_suffix(b"\n"))
        .filter(|line| !line.is_empty())
}

fn append_value(file: &mut File, value: Value) -> Result<(), JournalError> {
    let line = encoded_value(value)?;
    separate_torn_tail(file)?;
    file.write_all(&line).map_err(JournalError::Append)?;
    file.sync_data().map_err(JournalError::Sync)
}

fn encoded_value(mut value: Value) -> Result<Vec<u8>, JournalError> {
    let mut line = serde_json::to_vec(&value).map_err(JournalError::Serialize)?;
    if line.len() + 1 > MAX_JOURNAL_RECORD_BYTES {
        value
            .as_object_mut()
            .ok_or(JournalError::RecordShape(
                "serialized journal value is not an object",
            ))?
            .insert("truncated".to_owned(), Value::Bool(true));
        truncate_record(&mut value)?;
        line = serde_json::to_vec(&value).map_err(JournalError::Serialize)?;
    }
    if line.len() + 1 > MAX_JOURNAL_RECORD_BYTES {
        return Err(JournalError::RecordTooLarge);
    }
    line.push(b'\n');
    Ok(line)
}

fn separate_torn_tail(file: &mut File) -> Result<(), JournalError> {
    let length = file.metadata().map_err(JournalError::FileMetadata)?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1)).map_err(JournalError::Read)?;
    let mut last = [0_u8; 1];
    file.read_exact(&mut last).map_err(JournalError::Read)?;
    if last != *b"\n" {
        file.write_all(b"\n").map_err(JournalError::Append)?;
    }
    Ok(())
}

fn truncate_record(value: &mut Value) -> Result<(), JournalError> {
    let object = value
        .as_object_mut()
        .ok_or(JournalError::RecordShape("top level is not an object"))?;
    let mut command = string_field(object, "command")?.to_owned();
    let mut reason = string_field(object, "reason")?.to_owned();
    loop {
        object.insert("command".to_owned(), Value::from(command.clone()));
        object.insert("reason".to_owned(), Value::from(reason.clone()));
        let size = serde_json::to_vec(object)
            .map_err(JournalError::Serialize)?
            .len()
            + 1;
        if size <= MAX_JOURNAL_RECORD_BYTES {
            return Ok(());
        }
        if command.is_empty() && reason.is_empty() {
            return Err(JournalError::RecordTooLarge);
        }
        if command.len() >= reason.len() && !command.is_empty() {
            shrink_utf8(&mut command);
        } else {
            shrink_utf8(&mut reason);
        }
    }
}

fn shrink_utf8(value: &mut String) {
    let target = value.len().saturating_sub((value.len() / 8).max(1));
    let mut boundary = target;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

pub(crate) fn verdict_event_id(request_digest: &str) -> Result<(String, String), JournalError> {
    let recorded_at = recorded_at()?;
    // The process identifier and atomic sequence retain uniqueness when timestamps coincide.
    Ok((event_id(&recorded_at, request_digest), recorded_at))
}

fn event_id(recorded_at: &str, request_digest: &str) -> String {
    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut seed = Vec::new();
    seed.extend_from_slice(recorded_at.as_bytes());
    seed.push(0);
    seed.extend_from_slice(&std::process::id().to_be_bytes());
    seed.extend_from_slice(&sequence.to_be_bytes());
    seed.extend_from_slice(request_digest.as_bytes());
    sha256_digest(&seed)
}

fn recorded_at() -> Result<String, JournalError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| JournalError::Clock)?;
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_date(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let mut value = String::with_capacity(30);
    write!(
        value,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:09}Z",
        duration.subsec_nanos()
    )
    .map_err(|_error| JournalError::Clock)?;
    Ok(value)
}

fn civil_date(days_since_epoch: u64) -> (i64, u64, u64) {
    let days_since_epoch = i64::try_from(days_since_epoch).unwrap_or(i64::MAX - 719_468);
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let month = u64::try_from(month).unwrap_or(1);
    let day = u64::try_from(day).unwrap_or(1);
    (year, month, day)
}
