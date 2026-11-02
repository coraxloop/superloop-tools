//! Descriptor-pinned request custody and per-loop shape evidence.

#[path = "channel.rs"]
mod channel;
#[path = "rewrite.rs"]
mod rewrite;
mod snapshot;
#[cfg(test)]
#[path = "test_helper.rs"]
pub(super) mod test_helper;

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode as FileMode, SFlag, fchmod, fstat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};

use super::{
    Mode, RequestRecord,
    modes::{ModeLedger, ModeTarget},
};
use crate::error::LaneError;

const RUN_FILE: &str = "door-requests.json";
const SHAPES_FILE: &str = "door-shapes.json";
const LEARNED_FILE: &str = "door-learned.json";
const MAX_LEARNED_BYTES: usize = 4 * 1_048_576;
const LOCK_FILE: &str = "door-requests.lock";
// A writer holds the lock through every leaf and directory sync, and loaded-disk
// journal waits can exceed two seconds; readers get the writers' 15-second
// acquisition allowance. This bounds acquisition, not a stalled kernel sync.
const READER_LOCK_WAIT: Duration = Duration::from_secs(15);
const WRITER_LOCK_WAIT: Duration = Duration::from_secs(15);
const ATTEMPT_FILE: &str = "door-requests-attempt.json";
const MODES_FILE: &str = "door-modes.json";
const MAX_RUN_BYTES: usize = 8 * 1_048_576;
const MAX_SHAPES_BYTES: usize = 16 * 1_048_576;
const MAX_ATTEMPT_BYTES: usize = 12_288;
const MAX_MODES_BYTES: usize = 1_048_576;
const MAX_REQUESTS_PER_RUN: usize = 2048;
const MAX_RUNS: usize = 512;
const MAX_REQUESTS: usize = 16_384;
pub(crate) const RUN_CAP_REMEDY: &str = "this run is at its own cap; once its round ends, retire LOOP RUN and continue the work in a new run";
pub(crate) const LOOP_CAP_REMEDY: &str = "retire LOOP RUN for a finished run to free room";
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
type RunSnapshot = (Option<Vec<u8>>, u64, Vec<RequestRecord>);

#[cfg(not(test))]
const fn writer_lock_wait() -> Duration {
    WRITER_LOCK_WAIT
}

#[cfg(test)]
fn writer_lock_wait() -> Duration {
    if let Some(wait) = WRITER_LOCK_WAIT_OVERRIDE.with(std::cell::Cell::get) {
        return wait;
    }
    WRITER_LOCK_WAIT
}

// Diagnostic only: flock remains authoritative. Other processes and shared
// readers have an unknown holder; never infer an identity from stale disk data.
static LOCK_HOLDERS: Mutex<BTreeMap<(u64, u64), String>> = Mutex::new(BTreeMap::new());

#[derive(Debug)]
pub(crate) struct StoreLock {
    _file: File,
    holder: Option<(u64, u64)>,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        if let Some(key) = self.holder
            && let Ok(mut holders) = LOCK_HOLDERS.lock()
        {
            holders.remove(&key);
        }
    }
}

pub(super) enum ReadFailure {
    Contended(LaneError),
    Other(LaneError),
}

impl ReadFailure {
    pub(super) const fn is_contention(&self) -> bool {
        matches!(self, Self::Contended(_))
    }

    pub(super) fn into_error(self) -> LaneError {
        match self {
            Self::Contended(error) | Self::Other(error) => error,
        }
    }
}

impl From<LaneError> for ReadFailure {
    fn from(error: LaneError) -> Self {
        Self::Other(error)
    }
}

fn problem(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

pub(crate) fn is_lock_contention(error: &LaneError) -> bool {
    error.kind == "requests-record-refusal"
        && error.detail.starts_with(&format!(
            "request lock: {}",
            std::io::Error::from_raw_os_error(libc::EAGAIN)
        ))
}

fn open_child(
    parent: &impl AsFd,
    name: &str,
    flags: OFlag,
    mode: u32,
) -> Result<OwnedFd, LaneError> {
    openat2(
        parent,
        Path::new(name),
        OpenHow::new()
            .flags(flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .mode(FileMode::from_bits_truncate(mode))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| problem("requests-record-refusal", format!("{name}: {error}")))
}

fn checked_dir(fd: &OwnedFd, owner: u32) -> Result<(), LaneError> {
    let stat = fstat(fd).map_err(|error| problem("requests-record-refusal", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(problem(
            "requests-record-refusal",
            "directory owner or mode differs",
        ));
    }
    Ok(())
}

pub(super) fn read_leaf(
    parent: &impl AsFd,
    name: &str,
    owner: u32,
    limit: usize,
) -> Result<Option<Vec<u8>>, LaneError> {
    let fd = match openat2(
        parent,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(problem(
                "requests-record-refusal",
                format!("{name}: {error}"),
            ));
        }
    };
    let stat = fstat(&fd).map_err(|error| problem("requests-record-refusal", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(problem(
            "requests-record-refusal",
            format!("{name} owner, mode or size differs"),
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
    if bytes.len() > limit {
        return Err(problem(
            "requests-record-refusal",
            format!("{name} exceeds reader limit"),
        ));
    }
    Ok(Some(bytes))
}

pub(super) fn replace_leaf(
    parent: &OwnedFd,
    name: &str,
    bytes: &[u8],
    owner: u32,
    limit: usize,
) -> Result<(), LaneError> {
    if bytes.len() > limit {
        return Err(problem(
            "requests-record-refusal",
            format!("{name} exceeds reader limit"),
        ));
    }
    let _prior = read_leaf(parent, name, owner, limit)?;
    let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(".{name}.{}.{sequence}.tmp", std::process::id());
    let fd = open_child(
        parent,
        &temporary,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
        0o600,
    )?;
    let mut file = File::from(fd);
    let result = (|| {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        file.write_all(bytes)
            .and_then(|()| {
                #[cfg(test)]
                BEFORE_LEAF_SYNC.with(|hook| {
                    if let Some(action) = hook.borrow_mut().take() {
                        action();
                    }
                });
                file.sync_data()
            })
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        renameat(parent, temporary.as_str(), parent, name)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        File::from(
            nix::unistd::dup(parent)
                .map_err(|error| problem("requests-record-refusal", error.to_string()))?,
        )
        .sync_data()
        .map_err(|error| problem("requests-record-refusal", error.to_string()))
    })();
    if result.is_err() {
        let _removed = unlinkat(parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

#[cfg(test)]
thread_local! {
    pub(crate) static WRITER_LOCK_WAIT_OVERRIDE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    pub(crate) static READER_LOCK_WAIT_OVERRIDE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    pub(crate) static BEFORE_LEAF_SYNC: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static FAIL_SHAPE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_MODE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FILE_CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static LOOP_CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static RUN_CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_WAIT_READ: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_EFFECT_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_WAITING_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_OBSERVED_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CHANGE_FILE_SNAPSHOT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_INCOMPLETE_ID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static AFTER_READER_RECORDS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_FIRST_LOCK_MISS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_READER_LOCK_CONTENTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_READER_LOCK_TIMEOUT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_READER_LOCK_ACQUIRED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_WRITER_LOCK_CONTENTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_WRITER_LOCK_ACQUIRED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static AFTER_WRITER_LOCK_TIMEOUT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static STRETCH_SHARED_HOLD: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn after_reader_records() {
    AFTER_READER_RECORDS.with(|hook| {
        if let Some(action) = hook.borrow_mut().take() {
            action();
        }
    });
}

#[cfg(test)]
fn after_first_lock_miss() {
    AFTER_FIRST_LOCK_MISS.with(|hook| {
        if let Some(action) = hook.borrow_mut().take() {
            action();
        }
    });
}

#[cfg(test)]
fn after_reader_lock_contention() {
    AFTER_READER_LOCK_CONTENTION.with(|hook| {
        if let Some(action) = hook.borrow_mut().take() {
            action();
        }
    });
}

#[cfg(test)]
fn after_reader_lock_timeout() {
    AFTER_READER_LOCK_TIMEOUT.with(|hook| {
        if let Some(action) = hook.borrow_mut().take() {
            action();
        }
    });
}

#[cfg(test)]
fn after_reader_lock_acquired() {
    AFTER_READER_LOCK_ACQUIRED.with(|hook| {
        if let Some(action) = hook.borrow_mut().take() {
            action();
        }
    });
}

#[cfg(test)]
fn stretch_shared_hold() {
    STRETCH_SHARED_HOLD.with(|duration| {
        if let Some(duration) = duration.get() {
            std::thread::sleep(duration);
        }
    });
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum FixtureFault {
    WaitRead,
    EffectWrite,
    WaitingWrite,
    ObservedWrite,
    ChangedSnapshot,
    LoopFull,
    RunsFull,
    InvalidIncomplete,
}

#[cfg(test)]
pub(crate) fn fixture_fault(fault: Option<FixtureFault>) {
    FAIL_WAIT_READ.with(|value| value.set(matches!(fault, Some(FixtureFault::WaitRead))));
    FAIL_EFFECT_WRITE.with(|value| value.set(matches!(fault, Some(FixtureFault::EffectWrite))));
    FAIL_WAITING_WRITE.with(|value| value.set(matches!(fault, Some(FixtureFault::WaitingWrite))));
    FAIL_OBSERVED_WRITE.with(|value| value.set(matches!(fault, Some(FixtureFault::ObservedWrite))));
    CHANGE_FILE_SNAPSHOT
        .with(|value| value.set(matches!(fault, Some(FixtureFault::ChangedSnapshot))));
    FAIL_INCOMPLETE_ID
        .with(|value| value.set(matches!(fault, Some(FixtureFault::InvalidIncomplete))));
    if matches!(fault, Some(FixtureFault::InvalidIncomplete)) {
        FILE_CAP.with(|cap| cap.set(Some(0)));
    }
    LOOP_CAP.with(|value| {
        value.set(if matches!(fault, Some(FixtureFault::LoopFull)) {
            Some(0)
        } else {
            None
        });
    });
    RUN_CAP.with(|value| {
        value.set(if matches!(fault, Some(FixtureFault::RunsFull)) {
            Some(0)
        } else {
            None
        });
    });
}

#[cfg(test)]
fn file_cap() -> usize {
    #[cfg(test)]
    if let Some(limit) = FILE_CAP.with(std::cell::Cell::get) {
        return limit;
    }
    MAX_REQUESTS_PER_RUN
}

#[cfg(not(test))]
const fn file_cap() -> usize {
    MAX_REQUESTS_PER_RUN
}

#[cfg(test)]
pub(crate) fn fixture_file_cap(limit: Option<usize>) {
    FILE_CAP.with(|cap| cap.set(limit));
}

fn write_shapes_after_run(
    parent: &OwnedFd,
    name: &str,
    bytes: &[u8],
    owner: u32,
    limit: usize,
) -> Result<(), LaneError> {
    #[cfg(test)]
    if FAIL_SHAPE_WRITE.with(|fail| fail.replace(false)) {
        return Err(problem(
            "requests-record-refusal",
            "fixture shape write failure",
        ));
    }
    replace_leaf(parent, name, bytes, owner, limit)
}

fn decode_run(bytes: Option<&[u8]>, run: &str) -> Result<(u64, Vec<RequestRecord>), LaneError> {
    let Some(bytes) = bytes else {
        return Ok((0, Vec::new()));
    };
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| problem("requests-record-refusal", "run record is not JSON"))?;
    let object = value
        .as_object()
        .ok_or_else(|| problem("requests-record-refusal", "run record is not an object"))?;
    if object.len() != 4
        || !["schema", "run", "revision", "requests"]
            .iter()
            .all(|key| object.contains_key(*key))
        || value["schema"] != 1
        || value["run"] != run
    {
        return Err(problem(
            "requests-record-refusal",
            "run record shape differs",
        ));
    }
    let revision = value["revision"]
        .as_u64()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| problem("requests-record-refusal", "run revision is invalid"))?;
    let rows = value["requests"]
        .as_array()
        .filter(|rows| rows.len() <= MAX_REQUESTS_PER_RUN)
        .ok_or_else(|| {
            problem(
                "requests-record-refusal",
                format!("run request list exceeds limit; {RUN_CAP_REMEDY}"),
            )
        })?;
    let mut seen = HashSet::new();
    let mut requests = Vec::with_capacity(rows.len());
    for row in rows {
        let request = RequestRecord::decode(row.clone())?;
        if request.run() != run || !seen.insert(request.id().to_owned()) {
            return Err(problem(
                "requests-record-refusal",
                "run request identity differs",
            ));
        }
        requests.push(request);
    }
    Ok((revision, requests))
}

fn encode_run(run: &str, revision: u64, requests: &[RequestRecord]) -> Result<Vec<u8>, LaneError> {
    let bytes = serde_json::to_vec(&json!({"schema":1,"run":run,"revision":revision,
        "requests":requests.iter().map(RequestRecord::value).collect::<Vec<_>>()}))
    .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
    if bytes.len() > MAX_RUN_BYTES || requests.len() > MAX_REQUESTS_PER_RUN {
        return Err(problem(
            "requests-store-full",
            format!("run request list exceeds limit; {RUN_CAP_REMEDY}"),
        ));
    }
    Ok(bytes)
}

/// An owner-held per-loop door store. The run's custody owns its requests.
pub struct Store {
    runs: OwnedFd,
    state: OwnedFd,
    owner: u32,
    loop_uid: u32,
    loop_name: String,
    floor: Mode,
    state_path: PathBuf,
    loop_root: PathBuf,
    registry_digest: String,
    reader_deadline: Option<Instant>,
    reader_budget: Option<Duration>,
    writer_deadline: Option<Instant>,
    request_id: Option<String>,
}

impl Store {
    /// Pin a request's store view with one deadline for all of its lock waits.
    pub(crate) fn for_request(&self, deadline: Instant) -> Result<Self, LaneError> {
        Ok(Self {
            runs: self
                .runs
                .try_clone()
                .map_err(|error| problem("requests-record-refusal", error.to_string()))?,
            state: self
                .state
                .try_clone()
                .map_err(|error| problem("requests-record-refusal", error.to_string()))?,
            owner: self.owner,
            loop_uid: self.loop_uid,
            loop_name: self.loop_name.clone(),
            floor: self.floor,
            state_path: self.state_path.clone(),
            loop_root: self.loop_root.clone(),
            registry_digest: self.registry_digest.clone(),
            reader_deadline: Some(deadline),
            reader_budget: None,
            writer_deadline: Some(deadline),
            request_id: None,
        })
    }

    pub(crate) fn with_request_id(mut self, id: &str) -> Self {
        self.request_id = Some(id.to_owned());
        self
    }

    /// Retry only shared-lock contention until this caller's absolute deadline.
    /// Record validation errors and writer acquisition retain their own rules.
    pub(crate) const fn with_reader_deadline(mut self, deadline: Instant) -> Self {
        self.reader_deadline = Some(deadline);
        self.reader_budget = None;
        self
    }

    /// Give each measurement read a fresh budget for retrying shared-lock contention.
    pub(crate) const fn with_reader_budget(mut self, budget: Duration) -> Self {
        self.reader_budget = Some(budget);
        self.reader_deadline = None;
        self
    }

    fn read_deadline(&self) -> Option<Instant> {
        self.reader_budget
            .map(|budget| Instant::now() + budget)
            .or(self.reader_deadline)
    }

    /// Resolve the registry grant and pin both roots in the entry namespace.
    ///
    /// # Errors
    ///
    /// Refuses unsafe ancestry, an invalid grant, or a changed state directory.
    pub fn open(owner_home: &Path, loop_name: &str, _create: bool) -> Result<Self, LaneError> {
        Self::open_inner(owner_home, loop_name, false)
    }

    /// Open policy inputs for any registered loop, including one without a door grant.
    ///
    /// # Errors
    /// Refuses unsafe standard roots or invalid owner-held configuration.
    pub fn open_for_snapshot(owner_home: &Path, loop_name: &str) -> Result<Self, LaneError> {
        Self::open_inner(owner_home, loop_name, true)
    }

    fn open_inner(owner_home: &Path, loop_name: &str, snapshot: bool) -> Result<Self, LaneError> {
        loop_home::validate_name(loop_name)
            .map_err(|error| problem("requests-record-refusal", error.message()))?;
        let owner = nix::unistd::Uid::effective().as_raw();
        let registry_parent = owner_home.join(".config/loops");
        let registry_dir = crate::home::pin_parent(&registry_parent, owner)?;
        let registry_fd = open_child(&registry_dir, "registry.toml", OFlag::O_RDONLY, 0)?;
        let stat = fstat(&registry_fd)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
            || stat.st_uid != owner
            || stat.st_mode & 0o7777 != 0o600
        {
            return Err(problem(
                "requests-record-refusal",
                "registry owner or mode differs",
            ));
        }
        let registry = loop_home::registry::load_registry_from_file(&mut File::from(registry_fd))
            .map_err(|error| problem("requests-record-refusal", error.message()))?;
        let row = registry
            .row(loop_name, owner_home)
            .map_err(|error| problem("requests-record-refusal", error.message()))?;
        let standard_runs = row.home.join("runs");
        let runs_root = registry
            .runs_root(loop_name)
            .or_else(|| snapshot.then_some(standard_runs.as_path()))
            .ok_or_else(|| problem("requests-record-refusal", "runs root is absent"))?;
        let runs = crate::home::pin_parent(runs_root, owner)?;
        let config_path = registry_parent.join(loop_name);
        let config = crate::home::pin_parent(&config_path, owner)?;
        let state = config;
        let floor = row.door_floor.map_or(Mode::Audit, |floor| match floor {
            loop_home::registry::DoorFloor::Audit => Mode::Audit,
            loop_home::registry::DoorFloor::Enforce => Mode::Enforce,
            loop_home::registry::DoorFloor::Allow => Mode::Allow,
        });
        Ok(Self {
            reader_deadline: None,
            reader_budget: None,
            writer_deadline: None,
            request_id: None,
            runs,
            state,
            owner,
            loop_uid: row.uid,
            loop_name: loop_name.to_owned(),
            floor,
            state_path: config_path.join(SHAPES_FILE),
            loop_root: row.home.clone(),
            registry_digest: execute_command::rubric::sha256_digest(
                row.to_registry_json().as_bytes(),
            ),
        })
    }

    /// Path of the per-loop shape record, for host reporting only.
    #[must_use]
    pub fn shape_path(&self) -> &Path {
        &self.state_path
    }

    /// The registry's most permissive admitted mode.
    #[must_use]
    pub const fn floor(&self) -> Mode {
        self.floor
    }

    pub(crate) fn retirement_guard(
        &self,
        run: &str,
        runs: &impl AsFd,
        dry_run: bool,
    ) -> Result<Option<StoreLock>, LaneError> {
        let held =
            fstat(runs).map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        let opened = fstat(&self.runs)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        if (held.st_dev, held.st_ino) != (opened.st_dev, opened.st_ino) {
            return Err(problem(
                "requests-record-refusal",
                "retirement runs descriptor differs from request custody",
            ));
        }
        let guard =
            if dry_run && read_leaf(self.state_dir(), LOCK_FILE, self.owner, 4096)?.is_none() {
                None
            } else {
                Some(self.lock(!dry_run)?)
            };
        let rows = match openat2(
            &self.runs,
            format!(".launch-{run}").as_str(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Err(Errno::ENOENT) => Vec::new(),
            Err(error) => return Err(problem("requests-record-refusal", error.to_string())),
            Ok(custody) => {
                let collection = self.channel_read()?;
                self.read_run_from_custody(run, &custody, collection.as_ref())?
                    .2
            }
        };
        let ledger = self.read_modes()?;
        let mut waiting = Vec::new();
        let mut corrections = Vec::new();
        for request in &rows {
            let value = request.value();
            if matches!(value["state"].as_str(), Some("waiting" | "marked")) {
                waiting.push(request.id());
            }
            if correction_pending(request, &ledger)? {
                corrections.push(request.id());
            }
        }
        if !waiting.is_empty() || !corrections.is_empty() {
            return Err(problem(
                "retire-requests-pending",
                format!(
                    "waiting request ids: {}; pending correction ids: {}; use requests triage {} {} or requests adjudicate for waiting ids, and requests correct-mode {} for corrections before retire",
                    waiting.join(", "),
                    corrections.join(", "),
                    self.loop_name,
                    run,
                    self.loop_name
                ),
            ));
        }
        Ok(guard)
    }

    const fn state_dir(&self) -> &OwnedFd {
        &self.state
    }

    fn read_modes(&self) -> Result<ModeLedger, LaneError> {
        let bytes = read_leaf(self.state_dir(), MODES_FILE, self.owner, MAX_MODES_BYTES)?;
        bytes.map_or_else(
            || Ok(ModeLedger::empty(&self.loop_name)),
            |bytes| {
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| problem("door-mode-record-refusal", "mode history is not JSON"))?;
                ModeLedger::decode(&value, &self.loop_name)
            },
        )
    }

    fn write_modes(&self, ledger: &ModeLedger) -> Result<Value, LaneError> {
        #[cfg(test)]
        if FAIL_MODE_WRITE.with(|fail| fail.replace(false)) {
            return Err(problem(
                "door-mode-record-refusal",
                "fixture mode write failure",
            ));
        }
        self.withdraw_snapshot_for_write();
        let bytes = serde_json::to_vec(&ledger.value())
            .map_err(|error| problem("door-mode-record-refusal", error.to_string()))?;
        replace_leaf(
            self.state_dir(),
            MODES_FILE,
            &bytes,
            self.owner,
            MAX_MODES_BYTES,
        )?;
        Ok(self.publish_after_write())
    }

    /// Read the protected class and loop-wide mode history without changing it.
    ///
    /// # Errors
    ///
    /// Refuses a changed mode record or lock.
    pub fn modes(&self) -> Result<Value, LaneError> {
        if read_leaf(self.state_dir(), LOCK_FILE, self.owner, 4096)?.is_none() {
            let initial = read_leaf(self.state_dir(), MODES_FILE, self.owner, MAX_MODES_BYTES)?;
            #[cfg(test)]
            after_reader_records();
            if read_leaf(self.state_dir(), LOCK_FILE, self.owner, 4096)?.is_none() {
                if initial.is_some() {
                    return Err(problem(
                        "door-mode-record-refusal",
                        "mode history exists without lock",
                    ));
                }
                return Ok(ModeLedger::empty(&self.loop_name).value());
            }
        }
        let _lock = self.lock(false)?;
        Ok(self.read_modes()?.value())
    }

    /// Read the effective mode and both setting snapshots for a class.
    ///
    /// # Errors
    ///
    /// Refuses a class lacking either required first setting.
    pub fn effective_mode(&self, class: &str) -> Result<Value, LaneError> {
        let _lock = self.lock(false)?;
        let ledger = self.read_modes()?;
        self.effective_locked(&ledger, class)
    }

    fn effective_locked(&self, ledger: &ModeLedger, class: &str) -> Result<Value, LaneError> {
        let mut effective = ledger.effective(class, self.floor).ok_or_else(|| {
            problem(
                "door-mode-setting-refusal",
                "class or loop first setting is absent",
            )
        })?;
        if effective["mode"] != "audit" {
            let pending = self
                .all_runs(None)?
                .iter()
                .flat_map(|(_, _, rows)| rows)
                .filter(|request| request.value()["class"] == class)
                .try_fold(false, |pending, request| -> Result<bool, LaneError> {
                    Ok(pending || correction_pending(request, ledger)?)
                })?;
            if pending {
                let mode =
                    execute_command::policy::DoorMode::from_record(effective["mode"].as_str())
                        .map_err(super::command::shape)?;
                effective["mode"] = json!(
                    execute_command::policy::effective_mode(mode, mode, self.floor.domain(), true)
                        .as_str()
                );
                effective["correction_pending"] = json!(true);
            }
        }
        Ok(effective)
    }

    /// Record floor-derived absent settings before a new class files a request.
    ///
    /// # Errors
    ///
    /// Refuses a changed history or an invalid class without filing a request.
    pub fn ensure_first_mode(&self, class: &str) -> Result<Value, LaneError> {
        let target = ModeTarget::class(class)?;
        let _lock = self.lock(true)?;
        let mut ledger = self.read_modes()?;
        let initial = execute_command::policy::initial_setting(None, self.floor.domain())
            .map_err(super::command::shape)?
            .ok_or_else(|| problem("door-mode-record-refusal", "absent initial setting"))?;
        let evidence = initial.evidence.as_str();
        let at = now_nanos().to_string();
        let loop_changed = if ledger.current(&ModeTarget::Loop).is_none() {
            ledger.set(
                &ModeTarget::Loop,
                self.floor,
                self.floor,
                "door-service",
                evidence,
                &at,
                &[],
            )?;
            true
        } else {
            false
        };
        let class_changed = if ledger.current(&target).is_none() {
            ledger.set(
                &target,
                self.floor,
                self.floor,
                "door-service",
                evidence,
                &at,
                &[],
            )?;
            true
        } else {
            false
        };
        if loop_changed || class_changed {
            self.write_modes(&ledger)?;
        }
        self.effective_locked(&ledger, class)
    }

    fn apply_corrections_locked(&self, rows: &[RequestRecord], at: &str) -> Vec<Value> {
        let corrections = rows
            .iter()
            .filter(|request| is_correction(request))
            .collect::<Vec<_>>();
        if corrections.is_empty() {
            return Vec::new();
        }
        let outcome = (|| -> Result<Vec<Value>, LaneError> {
            if read_leaf(self.state_dir(), MODES_FILE, self.owner, MAX_MODES_BYTES)?.is_none() {
                return Ok(corrections
                    .iter()
                    .filter(|request| !is_enforce_correction(request))
                    .map(|request| rubric_row_report(request))
                    .collect());
            }
            let mut ledger = self.read_modes()?;
            let mut reports = Vec::new();
            for request in &corrections {
                let value = request.value();
                let class = value["class"].as_str().unwrap_or_default();
                let id = request.id();
                if !is_enforce_correction(request) {
                    reports.push(rubric_row_report(request));
                    continue;
                }
                let target = ModeTarget::class(class)?;
                let Some(current) = ledger.current(&target) else {
                    continue;
                };
                if current.value()["mode"] == "audit" {
                    continue;
                }
                let evidence = format!("rubric correction on {id}");
                let mut report = ledger.set(
                    &target,
                    Mode::Audit,
                    self.floor,
                    "owner-adjudicate",
                    &evidence,
                    at,
                    &[id.to_owned()],
                )?;
                report["changed"] = json!(true);
                report["correction_request"] = json!(id);
                report["reason"] = value["label"]["reason"].clone();
                reports.push(report);
            }
            if reports.iter().any(|report| report["changed"] == true) {
                self.write_modes(&ledger)?;
            }
            Ok(reports)
        })();
        match outcome {
            Ok(reports) => reports,
            Err(error) => corrections.iter().map(|request| {
                if is_enforce_correction(request) {
                    json!({"target":request.value()["class"],"mode":"audit","changed":false,
                        "record":"pending","correction_request":request.id(),"reason":request.value()["label"]["reason"],"error_kind":error.kind})
                } else {
                    rubric_row_report(request)
                }
            }).collect(),
        }
    }

    fn preflight_correction_modes(&self, rows: &[RequestRecord]) -> Result<(), LaneError> {
        if rows.iter().any(is_enforce_correction)
            && read_leaf(self.state_dir(), MODES_FILE, self.owner, MAX_MODES_BYTES)?.is_some()
        {
            let _ledger = self.read_modes()?;
        }
        Ok(())
    }

    fn check_citations(
        &self,
        target: &ModeTarget,
        citations: &[String],
        require_agreement: bool,
    ) -> Result<(), LaneError> {
        if citations.len() > 32 {
            return Err(problem(
                "door-mode-evidence-refusal",
                "citation list exceeds limit",
            ));
        }
        let runs = self.all_runs(None)?;
        let requests = runs.iter().flat_map(|(_, _, rows)| rows);
        let by_id = requests
            .map(|request| (request.id(), request))
            .collect::<BTreeMap<_, _>>();
        let labels = citations
            .iter()
            .filter_map(|id| by_id.get(id.as_str()))
            .map(|record| super::command::label(record))
            .collect::<Result<Vec<_>, _>>()?;
        let class = match target {
            ModeTarget::Loop => None,
            ModeTarget::Class(name) => Some(super::command::text(name)?),
        };
        let binding = super::command::binding(&json!({"citations":citations,"class":class}));
        super::command::accept(
            execute_command::policy::citation_evidence(
                &binding,
                class.as_ref(),
                citations,
                &labels,
                require_agreement,
            )
            .map_err(super::command::shape)?,
        )
    }

    /// Recover an interrupted agent exercise under the mode lock.
    pub(crate) fn recover_agent_loop(&self) -> Result<Value, LaneError> {
        let _lock = self.lock(true)?;
        let mut ledger = self.read_modes()?;
        let report = ledger.recover_agent_loop(self.floor, &now_nanos().to_string())?;
        if report["status"] == "restored" {
            self.write_modes(&ledger)?;
        }
        Ok(report)
    }

    /// Record a first mode or a move under the current registry floor.
    ///
    /// # Errors
    ///
    /// Refuses a changed record, below-floor choice or unsupported relaxation.
    #[allow(clippy::too_many_arguments)]
    pub fn set_mode(
        &self,
        target: &ModeTarget,
        mode: Mode,
        setter: &str,
        evidence: &str,
        at: &str,
        citations: &[String],
    ) -> Result<Value, LaneError> {
        mode.within(self.floor)?;
        let _lock = self.lock(true)?;
        let mut ledger = self.read_modes()?;
        if !citations.is_empty() {
            let relaxing = ledger
                .current(target)
                .and_then(|prior| prior.value()["mode"].as_str())
                .and_then(Mode::parse)
                .is_some_and(|previous| mode.domain() > previous.domain());
            self.check_citations(target, citations, relaxing)?;
        }
        let mut report = ledger.set(target, mode, self.floor, setter, evidence, at, citations)?;
        report["direct_policy"] = self.write_modes(&ledger)?;
        Ok(report)
    }

    /// Return a corrected class to audit and report the cited wrong rubric row.
    ///
    /// # Errors
    ///
    /// Refuses a missing, unadjudicated or non-correcting request.
    pub fn correct_mode(
        &self,
        class: &str,
        id: &str,
        setter: &str,
        at: &str,
    ) -> Result<Value, LaneError> {
        let target = ModeTarget::class(class)?;
        let _lock = self.lock(true)?;
        let runs = self.all_runs(None)?;
        let request = runs
            .iter()
            .flat_map(|(_, _, rows)| rows)
            .find(|request| request.id() == id)
            .ok_or_else(|| problem("door-mode-evidence-refusal", "correction request is absent"))?;
        let value = request.value();
        let binding = super::command::binding(value);
        super::command::accept(
            execute_command::checks::correction_evidence(
                &binding,
                &super::command::text(class)?,
                &super::command::text(id)?,
                Some(&super::command::label(request)?),
            )
            .map_err(super::command::shape)?,
        )?;
        if !is_enforce_correction(request) {
            return Ok(rubric_row_report(request));
        }
        let mut ledger = self.read_modes()?;
        let current = ledger
            .current(&target)
            .ok_or_else(|| problem("door-mode-setting-refusal", "class first setting is absent"))?;
        if current.value()["mode"] == "audit" {
            return Ok(
                json!({"target":class,"mode":"audit","changed":false,"correction_request":id,"reason":value["label"]["reason"]}),
            );
        }
        let evidence = format!("rubric correction on {id}");
        let mut report = ledger.set(
            &target,
            Mode::Audit,
            self.floor,
            setter,
            &evidence,
            at,
            &[id.to_owned()],
        )?;
        report["direct_policy"] = self.write_modes(&ledger)?;
        report["changed"] = json!(true);
        report["correction_request"] = json!(id);
        report["reason"] = value["label"]["reason"].clone();
        Ok(report)
    }

    fn lock_inner(&self, changing: bool) -> Result<StoreLock, ReadFailure> {
        self.lock_retry(
            changing,
            if changing {
                self.writer_deadline
            } else {
                self.read_deadline()
            },
        )
    }

    fn lock_retry(
        &self,
        changing: bool,
        deadline: Option<Instant>,
    ) -> Result<StoreLock, ReadFailure> {
        let started = Instant::now();
        // A late effect, deadline outcome or agent publication still gets the
        // base writer allowance. Fix this bound once, never at each retry.
        let deadline = if changing {
            deadline.map(|end| end.max(started + writer_lock_wait()))
        } else {
            deadline
        };
        loop {
            let result = self.lock_attempt(changing, deadline, true);
            match result {
                Err(ReadFailure::Contended(_))
                    if deadline.is_some_and(|end| Instant::now() < end) =>
                {
                    // Yield between bounded acquisitions just as wait callers do.
                    std::thread::sleep(
                        Duration::from_millis(10).min(
                            deadline
                                .unwrap_or_else(Instant::now)
                                .saturating_duration_since(Instant::now()),
                        ),
                    );
                }
                Err(ReadFailure::Contended(mut error)) => {
                    use std::fmt::Write as _;
                    let _written = write!(
                        error.detail,
                        "; total_wait_seconds={:.3}",
                        started.elapsed().as_secs_f64()
                    );
                    return Err(ReadFailure::Contended(error));
                }
                result => return result,
            }
        }
    }

    #[allow(unsafe_code, clippy::too_many_lines)]
    fn lock_attempt(
        &self,
        changing: bool,
        caller_deadline: Option<Instant>,
        retry: bool,
    ) -> Result<StoreLock, ReadFailure> {
        let state = self.state_dir();
        let flags = if changing {
            OFlag::O_RDWR
        } else {
            OFlag::O_RDONLY
        };
        let fd = match openat2(
            state,
            Path::new(LOCK_FILE),
            OpenHow::new()
                .flags(flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) if changing => {
                #[cfg(test)]
                after_first_lock_miss();
                match openat2(
                    state,
                    Path::new(LOCK_FILE),
                    OpenHow::new()
                        .flags(
                            OFlag::O_RDWR
                                | OFlag::O_CREAT
                                | OFlag::O_EXCL
                                | OFlag::O_CLOEXEC
                                | OFlag::O_NOFOLLOW,
                        )
                        .mode(FileMode::from_bits_truncate(0o600))
                        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
                ) {
                    Ok(created) => {
                        fchmod(&created, FileMode::from_bits_truncate(0o600)).map_err(|error| {
                            problem("requests-record-refusal", error.to_string())
                        })?;
                        created
                    }
                    Err(Errno::EEXIST) => openat2(
                        state,
                        Path::new(LOCK_FILE),
                        OpenHow::new()
                            .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                            .resolve(
                                ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS,
                            ),
                    )
                    .map_err(|error| {
                        problem("requests-record-refusal", format!("{LOCK_FILE}: {error}"))
                    })?,
                    Err(error) => {
                        return Err(problem(
                            "requests-record-refusal",
                            format!("{LOCK_FILE}: {error}"),
                        )
                        .into());
                    }
                }
            }
            Err(error) => {
                return Err(
                    problem("requests-record-refusal", format!("{LOCK_FILE}: {error}")).into(),
                );
            }
        };
        let stat =
            fstat(&fd).map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
            || stat.st_uid != self.owner
            || stat.st_mode & 0o7777 != 0o600
        {
            return Err(problem(
                "requests-record-refusal",
                "request lock owner or mode differs",
            )
            .into());
        }
        let operation = if changing {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        } | libc::LOCK_NB;
        // A full run can make concurrent shared reads last several seconds; the
        // answer writer must remain eligible while bounded waiters back off.
        let reader_wait = READER_LOCK_WAIT;
        #[cfg(test)]
        let reader_wait =
            READER_LOCK_WAIT_OVERRIDE.with(|bound| bound.get().unwrap_or(reader_wait));
        let writer_wait = writer_lock_wait();
        let started = Instant::now();
        let mut contended = false;
        let mut holder = None;
        let key = (stat.st_dev, stat.st_ino);
        let mut deadline = started + if changing { writer_wait } else { reader_wait };
        if let Some(caller_deadline) = caller_deadline {
            deadline = deadline.min(caller_deadline);
        }
        loop {
            // SAFETY: flock receives a live file descriptor and a fixed operation.
            if unsafe { libc::flock(fd.as_raw_fd(), operation) } == 0 {
                if contended {
                    self.log_lock_wait(changing, started, "acquired", holder.as_deref());
                }
                let holder_key = if changing && let Some(id) = &self.request_id {
                    if let Ok(mut holders) = LOCK_HOLDERS.lock() {
                        holders.insert(key, id.clone());
                    }
                    Some(key)
                } else {
                    None
                };
                let guard = StoreLock {
                    _file: File::from(fd),
                    holder: holder_key,
                };
                #[cfg(test)]
                if changing {
                    AFTER_WRITER_LOCK_ACQUIRED.with(|hook| {
                        if let Some(action) = hook.borrow_mut().take() {
                            action();
                        }
                    });
                }
                #[cfg(test)]
                if !changing {
                    after_reader_lock_acquired();
                }
                return Ok(guard);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                contended = true;
                holder = LOCK_HOLDERS
                    .lock()
                    .ok()
                    .and_then(|holders| holders.get(&key).cloned());
            }
            #[cfg(test)]
            if !changing && error.kind() == std::io::ErrorKind::WouldBlock {
                after_reader_lock_contention();
            }
            #[cfg(test)]
            if changing && error.kind() == std::io::ErrorKind::WouldBlock {
                AFTER_WRITER_LOCK_CONTENTION.with(|hook| {
                    if let Some(action) = hook.borrow_mut().take() {
                        action();
                    }
                });
            }
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            }
            let refusal = problem(
                "requests-record-refusal",
                format!(
                    "request lock: {error}; wait_seconds={:.3}; holder_request_id={}",
                    started.elapsed().as_secs_f64(),
                    holder.as_deref().unwrap_or("unknown")
                ),
            );
            if error.kind() == std::io::ErrorKind::WouldBlock {
                let outcome = if retry && caller_deadline.is_some_and(|end| Instant::now() < end) {
                    "retry"
                } else {
                    "timeout"
                };
                self.log_lock_wait(changing, started, outcome, holder.as_deref());
                #[cfg(test)]
                if changing {
                    AFTER_WRITER_LOCK_TIMEOUT.with(|hook| {
                        if let Some(action) = hook.borrow_mut().take() {
                            action();
                        }
                    });
                }
                #[cfg(test)]
                if !changing {
                    after_reader_lock_timeout();
                }
                return Err(ReadFailure::Contended(refusal));
            }
            return Err(ReadFailure::Other(refusal));
        }
    }

    fn log_lock_wait(&self, changing: bool, started: Instant, outcome: &str, holder: Option<&str>) {
        if self.request_id.is_none() {
            return;
        }
        let _logged = writeln!(
            std::io::stderr().lock(),
            "door-request-lock {}",
            json!({
                "loop":self.loop_name,"request_id":self.request_id,"lock":LOCK_FILE,
                "operation":if changing {"write"} else {"read"},"outcome":outcome,
                "wait_seconds":started.elapsed().as_secs_f64(),"holder_request_id":holder
            })
        );
    }

    fn lock(&self, changing: bool) -> Result<StoreLock, LaneError> {
        self.lock_inner(changing).map_err(ReadFailure::into_error)
    }

    fn custody(&self, run: &str) -> Result<OwnedFd, LaneError> {
        if !crate::valid_run_name(run) {
            return Err(problem("requests-request-refusal", "run name is invalid"));
        }
        let fd = open_child(
            &self.runs,
            &format!(".launch-{run}"),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            0,
        )?;
        checked_dir(&fd, self.owner)?;
        Ok(fd)
    }

    fn read_run(&self, run: &str) -> Result<RunSnapshot, LaneError> {
        let collection = self.channel_read()?;
        self.read_run_with_channel(run, collection.as_ref())
    }

    fn read_run_with_channel(
        &self,
        run: &str,
        collection: Option<&request_core::Collection>,
    ) -> Result<RunSnapshot, LaneError> {
        let custody = self.custody(run)?;
        self.read_run_from_custody(run, &custody, collection)
    }

    fn read_run_from_custody(
        &self,
        run: &str,
        custody: &OwnedFd,
        collection: Option<&request_core::Collection>,
    ) -> Result<RunSnapshot, LaneError> {
        checked_dir(custody, self.owner)?;
        let bytes = read_leaf(custody, RUN_FILE, self.owner, MAX_RUN_BYTES)?;
        let (revision, mut requests) = decode_run(bytes.as_deref(), run)?;
        for request in &requests {
            if request.value()["loop"] != self.loop_name
                || request.value()["worker_uid"] == self.owner
                || request.value()["worker_uid"] == self.loop_uid
            {
                return Err(problem("requests-record-refusal", "request grant differs"));
            }
        }
        self.channel_project(&mut requests, collection)?;
        Ok((bytes, revision, requests))
    }

    fn all_runs(
        &self,
        candidate: Option<(&str, u64, &[RequestRecord])>,
    ) -> Result<Vec<(String, u64, Vec<RequestRecord>)>, LaneError> {
        let mut directory = Dir::openat(
            &self.runs,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            FileMode::empty(),
        )
        .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        let mut runs = Vec::new();
        let mut candidate_found = false;
        let collection = self.channel_read()?;
        for entry in directory.iter() {
            let entry =
                entry.map_err(|error| problem("requests-record-refusal", error.to_string()))?;
            let Some(name) = entry.file_name().to_str().ok() else {
                continue;
            };
            let Some(run) = name.strip_prefix(".launch-") else {
                continue;
            };
            if !crate::valid_run_name(run) {
                return Err(problem(
                    "requests-record-refusal",
                    "custody name is invalid",
                ));
            }
            let (_, revision, requests) = self.read_run_with_channel(run, collection.as_ref())?;
            if let Some((wanted, next_revision, next_requests)) = candidate
                && run == wanted
            {
                candidate_found = true;
                runs.push((run.to_owned(), next_revision, next_requests.to_vec()));
            } else if revision > 0 {
                runs.push((run.to_owned(), revision, requests));
            }
            if runs.len() > MAX_RUNS {
                return Err(problem(
                    "requests-store-full",
                    format!("run list exceeds limit; {LOOP_CAP_REMEDY}"),
                ));
            }
        }
        if let Some((run, revision, requests)) = candidate
            && !candidate_found
        {
            runs.push((run.to_owned(), revision, requests.to_vec()));
        }
        runs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(runs)
    }

    fn shapes(runs: &[(String, u64, Vec<RequestRecord>)]) -> Result<Value, LaneError> {
        let mut revisions = serde_json::Map::new();
        let mut groups: BTreeMap<(String, String), Value> = BTreeMap::new();
        let mut total = 0;
        for (run, revision, requests) in runs {
            revisions.insert(run.clone(), json!(revision));
            for request in requests {
                total += 1;
                if total > MAX_REQUESTS {
                    return Err(problem(
                        "requests-store-full",
                        format!("loop request list exceeds limit; {LOOP_CAP_REMEDY}"),
                    ));
                }
                let value = request.value();
                let key = (
                    value["class"].as_str().unwrap_or_default().to_owned(),
                    value["shape_key"].as_str().unwrap_or_default().to_owned(),
                );
                let group = groups.entry(key.clone()).or_insert_with(|| {
                    json!({
                        "class":key.0,"shape_key":key.1,"requests":0,"would_allow":0,
                        "would_refuse":0,"would_undecided":0,"would_refer":0,"labels_allow":0,"labels_refuse":0,
                        "agreements":0,"corrections":0,"labels_after_undecided":0,"labels_after_refer":0,"effect_completed":0,"effect_refused":0,
                        "request_ids":[],"settings":[]
                    })
                });
                for name in [
                    "requests",
                    match value["would_do"]["decision"].as_str().unwrap_or_default() {
                        "allow" => "would_allow",
                        "refuse" => "would_refuse",
                        "refer" => "would_refer",
                        _ => "would_undecided",
                    },
                ] {
                    group[name] = json!(group[name].as_u64().unwrap_or(0) + 1);
                }
                if let Some(treatment) = value["label"]["treatment"].as_str() {
                    let name = if treatment == "allow" {
                        "labels_allow"
                    } else {
                        "labels_refuse"
                    };
                    group[name] = json!(group[name].as_u64().unwrap_or(0) + 1);
                    if let Some(name) = super::command::feedback(value).comparison_group() {
                        group[name] = json!(group[name].as_u64().unwrap_or(0) + 1);
                    }
                }
                if matches!(
                    value["effect"]["state"].as_str(),
                    Some("completed" | "refused")
                ) {
                    let name = if value["effect"]["state"] == "completed" {
                        "effect_completed"
                    } else {
                        "effect_refused"
                    };
                    group[name] = json!(group[name].as_u64().unwrap_or(0) + 1);
                }
                if let Some(ids) = group["request_ids"].as_array_mut() {
                    ids.push(value["id"].clone());
                }
                let settings = json!({"class":value["class_setting"],"loop":value["loop_setting"],"floor":value["floor"]});
                if let Some(saved) = group["settings"].as_array_mut()
                    && !saved.contains(&settings)
                {
                    saved.push(settings);
                }
            }
        }
        let groups = groups.into_values().collect::<Vec<_>>();
        Ok(json!({"schema":1,"revisions":revisions,"groups":groups}))
    }

    fn shape_status(&self, runs: &[(String, u64, Vec<RequestRecord>)]) -> Result<bool, LaneError> {
        let expected = Self::shapes(runs)?;
        let actual = read_leaf(self.state_dir(), SHAPES_FILE, self.owner, MAX_SHAPES_BYTES)?;
        if runs.is_empty() && actual.is_none() {
            return Ok(false);
        }
        Ok(actual
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            != Some(expected))
    }

    fn record_attempt(&self, event: Value) -> Result<(), LaneError> {
        let phase = event["phase"]
            .as_str()
            .ok_or_else(|| problem("requests-record-refusal", "attempt phase is absent"))?;
        if !matches!(
            phase,
            "withdrawn" | "withdrawal-failed" | "repaired" | "incomplete"
        ) {
            return Err(problem(
                "requests-record-refusal",
                "attempt phase is invalid",
            ));
        }
        let prior = read_leaf(
            self.state_dir(),
            ATTEMPT_FILE,
            self.owner,
            MAX_ATTEMPT_BYTES,
        )?;
        let mut journal: Value = if let Some(bytes) = prior {
            serde_json::from_slice(&bytes)
                .map_err(|_| problem("requests-record-refusal", "attempt journal is not JSON"))?
        } else {
            json!({"schema":2,"latest":{}})
        };
        if journal["schema"] != 2 || journal.as_object().is_none_or(|object| object.len() != 2) {
            return Err(problem(
                "requests-record-refusal",
                "attempt journal shape differs",
            ));
        }
        let latest = journal["latest"]
            .as_object_mut()
            .ok_or_else(|| problem("requests-record-refusal", "attempt journal latest differs"))?;
        if latest.len() > 4
            || latest.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "withdrawn" | "withdrawal-failed" | "repaired" | "incomplete"
                )
            })
        {
            return Err(problem(
                "requests-record-refusal",
                "attempt journal phases differ",
            ));
        }
        for (saved_phase, saved) in latest.iter() {
            let keys = ["phase", "run", "reason", "rollback", "at_unix_ns"];
            if saved.as_object().is_none_or(|row| {
                row.len() != keys.len() || keys.iter().any(|key| !row.contains_key(*key))
            }) || saved["phase"] != *saved_phase
                || saved["reason"]
                    .as_str()
                    .is_none_or(|reason| reason.is_empty() || reason.len() > 256)
                || saved["at_unix_ns"].as_u64().is_none()
                || (saved_phase == "repaired"
                    && (!saved["run"].is_null() || !saved["rollback"].is_null()))
                || (saved_phase != "repaired"
                    && (saved["run"]
                        .as_str()
                        .is_none_or(|run| run.is_empty() || run.len() > 64)
                        || (saved_phase == "incomplete" && saved["rollback"] != "not-required")
                        || (saved_phase != "incomplete"
                            && !matches!(
                                saved["rollback"].as_str(),
                                Some("completed" | "failed")
                            ))))
            {
                return Err(problem(
                    "requests-record-refusal",
                    "attempt journal event differs",
                ));
            }
        }
        latest.insert(phase.to_owned(), event);
        let bytes = serde_json::to_vec(&journal)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        replace_leaf(
            self.state_dir(),
            ATTEMPT_FILE,
            &bytes,
            self.owner,
            MAX_ATTEMPT_BYTES,
        )
    }

    /// Keep the latest request that could not be durably completed, even when the run is full.
    ///
    /// # Errors
    ///
    /// Refuses a changed attempt journal or a record that cannot be published.
    pub fn record_incomplete(&self, run: &str, id: &str, reason: &str) -> Result<(), LaneError> {
        #[cfg(test)]
        if FAIL_INCOMPLETE_ID.with(|fault| fault.replace(false)) {
            return self.record_incomplete(run, "S:fixture", reason);
        }
        if id.len() > 128 || reason.len() > 96 || !id.starts_with(&format!("{run}:")) {
            return Err(problem(
                "requests-record-refusal",
                "incomplete outcome identity differs",
            ));
        }
        let _lock = self.lock(true)?;
        self.record_attempt(json!({"phase":"incomplete","run":run,
            "reason":format!("{id}: {reason}"),"rollback":"not-required",
            "at_unix_ns":now_nanos()}))
    }

    fn repair_shapes(&self, runs: &[(String, u64, Vec<RequestRecord>)]) -> Result<(), LaneError> {
        if self.shape_status(runs)? {
            let expected = Self::shapes(runs)?;
            let bytes = serde_json::to_vec(&expected)
                .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
            replace_leaf(
                self.state_dir(),
                SHAPES_FILE,
                &bytes,
                self.owner,
                MAX_SHAPES_BYTES,
            )?;
            self.record_attempt(json!({"phase":"repaired","run":null,"reason":"shape record differed from run custody","rollback":null,"at_unix_ns":now_nanos()}))?;
        }
        Ok(())
    }

    fn commit_run(
        &self,
        run: &str,
        old: Option<&[u8]>,
        revision: u64,
        requests: &[RequestRecord],
    ) -> Result<(), LaneError> {
        let custody = self.custody(run)?;
        let prior_runs = self.all_runs(None)?;
        self.repair_shapes(&prior_runs)?;
        let mut learned = self
            .read_learned()
            .unwrap_or_else(|_| json!({"unavailable":true}));
        if learned.is_null() {
            learned = if prior_runs.is_empty() && !self.has_retired_custody().unwrap_or(true) {
                json!({"schema":1,"groups":{}})
            } else {
                json!({"unavailable":true})
            };
        }
        let old_rows = decode_run(old, run)?.1;
        for row in requests {
            let prior = old_rows.iter().find(|old| old.id() == row.id());
            Self::index_judgement(&mut learned, row.value(), prior.map(RequestRecord::value));
        }
        let prior_shapes = read_leaf(self.state_dir(), SHAPES_FILE, self.owner, MAX_SHAPES_BYTES)?;
        let next = encode_run(run, revision, requests)?;
        let runs = self.all_runs(Some((run, revision, requests)))?;
        let shapes = serde_json::to_vec(&Self::shapes(&runs)?)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        if shapes.len() > MAX_SHAPES_BYTES {
            return Err(problem(
                "requests-store-full",
                format!("shape record exceeds limit; {LOOP_CAP_REMEDY}"),
            ));
        }
        // Invalidate before changing custody. A crash or failed publication
        // leaves a miss, never an index that can grant from stale labels.
        self.withdraw_snapshot_for_write();
        replace_leaf(
            self.state_dir(),
            LEARNED_FILE,
            b"{\"unavailable\":true}",
            self.owner,
            MAX_LEARNED_BYTES,
        )?;
        replace_leaf(&custody, RUN_FILE, &next, self.owner, MAX_RUN_BYTES)?;
        if let Err(error) = write_shapes_after_run(
            self.state_dir(),
            SHAPES_FILE,
            &shapes,
            self.owner,
            MAX_SHAPES_BYTES,
        ) {
            let rollback = old.map_or_else(
                || {
                    unlinkat(&custody, RUN_FILE, UnlinkatFlags::NoRemoveDir)
                        .map_err(|failure| problem("requests-record-refusal", failure.to_string()))
                },
                |bytes| replace_leaf(&custody, RUN_FILE, bytes, self.owner, MAX_RUN_BYTES),
            );
            let shape_rollback = prior_shapes.as_deref().map_or_else(
                || match unlinkat(self.state_dir(), SHAPES_FILE, UnlinkatFlags::NoRemoveDir) {
                    Ok(()) | Err(Errno::ENOENT) => Ok(()),
                    Err(failure) => Err(problem("requests-record-refusal", failure.to_string())),
                },
                |bytes| {
                    replace_leaf(
                        self.state_dir(),
                        SHAPES_FILE,
                        bytes,
                        self.owner,
                        MAX_SHAPES_BYTES,
                    )
                },
            );
            let withdrawn = rollback.is_ok() && shape_rollback.is_ok();
            let attempt = json!({"run":run,"phase":if withdrawn {"withdrawn"} else {"withdrawal-failed"},"reason":error.kind,
                "rollback":if withdrawn {"completed"} else {"failed"},"at_unix_ns":now_nanos()});
            self.record_attempt(attempt)?;
            rollback?;
            shape_rollback?;
            return Err(error);
        }
        // Index publication is optional for recording a request. Its tombstone
        // survives failure; the one-time rewrite can rebuild it from custody.
        let _published = self.write_learned(&learned);
        self.publish_after_write();
        Ok(())
    }

    /// File a new service-derived request before the service proceeds.
    ///
    /// # Errors
    ///
    /// Refuses duplicate IDs, changed grants or a full record before any effect.
    pub fn file(&self, request: RequestRecord) -> Result<(), LaneError> {
        let _lock = self.lock(true)?;
        let run = request.run().to_owned();
        let (old, revision, mut requests) = self.read_run(&run)?;
        #[cfg(test)]
        if CHANGE_FILE_SNAPSHOT.with(|fault| fault.replace(false)) {
            let mut changed = self.read_modes()?;
            changed.set(
                &ModeTarget::class("ssh")?,
                Mode::Enforce,
                self.floor,
                "fixture owner",
                "fixture changed snapshot",
                "2",
                &[],
            )?;
            self.write_modes(&changed)?;
        }
        if read_leaf(self.state_dir(), MODES_FILE, self.owner, MAX_MODES_BYTES)?.is_some() {
            let class = request.value()["class"].as_str().unwrap_or_default();
            let snapshot = self.effective_locked(&self.read_modes()?, class)?;
            if request.value()["class_setting"] != snapshot["class"]
                || request.value()["loop_setting"] != snapshot["loop"]
                || request.value()["mode"] != snapshot["mode"]
            {
                return Err(problem(
                    "requests-record-refusal",
                    "request mode snapshot differs",
                ));
            }
        }
        if request.value()["loop"] != self.loop_name
            || request.value()["floor"] != self.floor.as_str()
            || request.value()["worker_uid"] == self.owner
            || request.value()["worker_uid"] == self.loop_uid
            || requests.iter().any(|saved| saved.id() == request.id())
        {
            return Err(problem(
                "requests-record-refusal",
                "request grant or identifier differs",
            ));
        }
        let runs = self.all_runs(None)?;
        #[cfg(test)]
        let loop_limit = LOOP_CAP.with(|cap| cap.get().unwrap_or(MAX_REQUESTS));
        #[cfg(not(test))]
        let loop_limit = MAX_REQUESTS;
        #[cfg(test)]
        let run_limit = RUN_CAP.with(|cap| cap.get().unwrap_or(MAX_RUNS));
        #[cfg(not(test))]
        let run_limit = MAX_RUNS;
        if requests.len() >= file_cap() {
            return Err(problem(
                "requests-store-full",
                format!("run request capacity is full; {RUN_CAP_REMEDY}"),
            ));
        }
        if runs.iter().map(|(_, _, rows)| rows.len()).sum::<usize>() >= loop_limit
            || (old.is_none() && runs.len() >= run_limit)
        {
            return Err(problem(
                "requests-store-full",
                format!("loop request capacity is full; {LOOP_CAP_REMEDY}"),
            ));
        }
        requests.push(request);
        self.commit_run(&run, old.as_deref(), revision + 1, &requests)
    }

    /// Persist the observed effect without making an immediate allow intent waiting yet.
    ///
    /// # Errors
    ///
    /// Refuses a missing request, repeated outcome or changed custody.
    pub fn record_effect(&self, id: &str, effect: Value) -> Result<RequestRecord, LaneError> {
        #[cfg(test)]
        if FAIL_EFFECT_WRITE.with(|fault| fault.replace(false)) {
            return Err(problem(
                "requests-record-refusal",
                "fixture effect write failure",
            ));
        }
        let _lock = self.lock(true)?;
        if let Some(record) = self.channel_record_effect(id, &effect)? {
            return Ok(record);
        }
        self.change_one_locked(id, false, |request| request.record_effect(effect))
            .map(|(request, _)| request)
    }

    /// Merge one agent result under the same lock as effect and label changes.
    ///
    /// # Errors
    /// Refuses missing custody or invalid judgement evidence.
    pub fn record_agent(
        &self,
        id: &str,
        result: &crate::door::agent::RunnerOutcome,
        digest: Option<&str>,
        model: Option<&str>,
    ) -> Result<RequestRecord, LaneError> {
        self.change_one(id, false, |request| {
            let mut value = request.value().clone();
            super::judgement::apply(&mut value, result, digest, model);
            if value["state"].is_null()
                && (value["mode"] == "audit"
                    || (value["mode"] == "enforce" && result.verdict == "refer"))
            {
                value["state"] = json!("waiting");
            }
            *request = RequestRecord::decode(value)?;
            Ok(())
        })
        .map(|(request, _)| request)
    }

    fn read_learned(&self) -> Result<Value, LaneError> {
        let bytes = read_leaf(
            self.state_dir(),
            LEARNED_FILE,
            self.owner,
            MAX_LEARNED_BYTES,
        )?;
        let index: Value = bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| problem("requests-learned-index", error.to_string()))?
            .unwrap_or(Value::Null);
        if index.is_null() || index["unavailable"] == true {
            return Ok(index);
        }
        if index["schema"] != 1
            || index["groups"].as_object().is_none_or(|groups| {
                groups.len() > 512
                    || groups.iter().any(|(key, group)| {
                        serde_json::from_str::<Vec<String>>(key)
                            .ok()
                            .is_none_or(|parts| parts.len() != 3)
                            || !super::exact(group, &["allow", "refuse", "history", "citations"])
                            || group["allow"].as_u64().is_none()
                            || group["refuse"].as_u64().is_none()
                            || group["history"].as_array().is_none_or(|rows| {
                                rows.len() > 8
                                    || serde_json::to_vec(rows)
                                        .is_ok_and(|bytes| bytes.len() > 65_536)
                            })
                            || group["citations"].as_array().is_none_or(|ids| {
                                ids.len() > 8
                                    || ((group["allow"] != 0 || group["refuse"] != 0)
                                        && ids.is_empty())
                                    || ids.iter().any(|id| !super::word(id, 160))
                            })
                    })
            })
        {
            return Err(problem("requests-learned-index", "index shape differs"));
        }
        Ok(index)
    }

    fn write_learned(&self, value: &Value) -> Result<(), LaneError> {
        self.withdraw_snapshot_for_write();
        let bytes = serde_json::to_vec(value)
            .map_err(|error| problem("requests-learned-index", error.to_string()))?;
        let bounded = if bytes.len() > MAX_LEARNED_BYTES {
            b"{\"unavailable\":true,\"reason\":\"index byte capacity\"}".as_slice()
        } else {
            &bytes
        };
        replace_leaf(
            self.state_dir(),
            LEARNED_FILE,
            bounded,
            self.owner,
            MAX_LEARNED_BYTES,
        )?;
        self.publish_after_write();
        Ok(())
    }

    fn index_judgement(index: &mut Value, row: &Value, prior: Option<&Value>) {
        if index["schema"] != 1 {
            return;
        }
        let key = json!([row["class"], row["operation"], row["shape_key"]]).to_string();
        let Some(groups) = index["groups"].as_object_mut() else {
            return;
        };
        if !groups.contains_key(&key) && groups.len() >= 512 {
            *index = json!({"unavailable":true,"reason":"shape index capacity"});
            return;
        }
        let group = groups
            .entry(key)
            .or_insert_with(|| json!({"allow":0,"refuse":0,"history":[],"citations":[]}));
        if !row["label"].is_null() && prior.is_none_or(|old| old["label"].is_null()) {
            let treatment = row["label"]["treatment"].as_str().unwrap_or("refuse");
            group[treatment] = json!(group[treatment].as_u64().unwrap_or(0).saturating_add(1));
            if let Some(ids) = group["citations"].as_array_mut() {
                ids.insert(0, row["id"].clone());
                ids.truncate(8);
            }
        }
        if let Some(history) = group["history"].as_array_mut() {
            history.retain(|old| old["id"] != row["id"]);
            // Only bounded judgement evidence enters the prompt, never a full
            // request, environment, effect, or an unbounded custody history.
            history.push(json!({"id":row["id"],"filed_at":row["filed_at"],"would_do":row["would_do"],"label":row["label"]}));
            history.sort_by(|a, b| {
                let time = |v: &Value| {
                    v["filed_at"]
                        .as_str()
                        .and_then(|s| s.parse::<u128>().ok())
                        .unwrap_or(0)
                };
                time(b)
                    .cmp(&time(a))
                    .then_with(|| b["id"].as_str().cmp(&a["id"].as_str()))
            });
            history.truncate(8);
        }
    }

    /// Read the bounded label index, including labels retained after retirement.
    ///
    /// # Errors
    /// Refuses an absent, invalid or interrupted index, which the door files as a miss; lock contention past the reader deadline is returned to the caller unfiled.
    pub fn learned_judgement(
        &self,
        class: &str,
        operation: &str,
        shape: &str,
    ) -> Result<(Value, Value, Value), LaneError> {
        let _lock = self.lock(false)?;
        let index = self.read_learned()?;
        if index["schema"] != 1 || !index["groups"].is_object() {
            return Err(problem(
                "requests-learned-index",
                "index unavailable; requests rebuild-index LOOP rebuilds schema-four custody; older records need requests rewrite",
            ));
        }
        let key = json!([class, operation, shape]).to_string();
        let group = &index["groups"][key];
        let match_key = super::command::key(class, operation, shape)?;
        let observation = execute_command::request::LearnedGroup {
            key: match_key.clone(),
            allow: group["allow"].as_u64().unwrap_or(0),
            refuse: group["refuse"].as_u64().unwrap_or(0),
            citations: super::command::texts(
                &serde_json::from_value::<Vec<String>>(group["citations"].clone())
                    .unwrap_or_default(),
            )?,
        };
        let binding = super::command::binding(
            &json!({"class":class,"operation":operation,"shape_key":shape}),
        );
        let evaluation =
            execute_command::checks::learned_exact_match(&binding, &match_key, Some(&observation))
                .map_err(super::command::shape)?;
        let evidence = if matches!(
            evaluation,
            execute_command::request::MatchEvaluation::Decided(_)
        ) {
            json!({"class":class,"operation":operation,"shape_key":shape,"request_ids":group["citations"]})
        } else {
            Value::Null
        };
        let would_do = super::command::would_do(evaluation);
        let history = group["history"].as_array().cloned().unwrap_or_default();
        Ok((would_do, evidence, json!(history)))
    }

    /// File a completed immediate effect for later adjudication.
    ///
    /// # Errors
    ///
    /// Refuses an unfinished intent or changed custody.
    pub fn publish_waiting(&self, id: &str) -> Result<RequestRecord, LaneError> {
        #[cfg(test)]
        if FAIL_WAITING_WRITE.with(|fault| fault.replace(false)) {
            return Err(problem(
                "requests-record-refusal",
                "fixture waiting write failure",
            ));
        }
        self.change_one(id, false, RequestRecord::publish_waiting)
            .map(|(request, _)| request)
    }

    /// Publish a decided enforced outcome without a waiting request.
    ///
    /// # Errors
    ///
    /// Refuses an unfinished or changed request.
    pub fn publish_observed(&self, id: &str) -> Result<RequestRecord, LaneError> {
        #[cfg(test)]
        if FAIL_OBSERVED_WRITE.with(|fault| fault.replace(false)) {
            return Err(problem(
                "requests-record-refusal",
                "fixture observed write failure",
            ));
        }
        self.change_one(id, false, RequestRecord::publish_observed)
            .map(|(request, _)| request)
    }

    /// Read only one run while a filed request waits for its answer.
    ///
    /// # Errors
    ///
    /// Refuses a changed run or absent request.
    pub fn waiting_request(&self, id: &str) -> Result<RequestRecord, LaneError> {
        self.waiting_request_inner(id, self.read_deadline(), true)
    }

    pub(crate) fn waiting_request_until(
        &self,
        id: &str,
        deadline: Instant,
    ) -> Result<RequestRecord, LaneError> {
        self.waiting_request_inner(id, Some(deadline), false)
    }

    fn waiting_request_inner(
        &self,
        id: &str,
        deadline: Option<Instant>,
        retry: bool,
    ) -> Result<RequestRecord, LaneError> {
        #[cfg(test)]
        if FAIL_WAIT_READ.with(|fault| fault.replace(false)) {
            return Err(problem(
                "requests-record-refusal",
                "fixture waiting read failure",
            ));
        }
        let run = id
            .split_once(':')
            .map(|(run, _)| run)
            .ok_or_else(|| problem("requests-request-refusal", "request identifier is invalid"))?;
        // wait_answer owns the retry and its timeout observation; cap this one
        // acquisition to its remaining budget without swallowing contention.
        let _lock = if retry {
            self.lock_retry(false, deadline)
        } else {
            self.lock_attempt(false, deadline, false)
        }
        .map_err(ReadFailure::into_error)?;
        self.read_run(run)?
            .2
            .into_iter()
            .find(|request| request.id() == id)
            .ok_or_else(|| problem("requests-request-refusal", "request is absent"))
    }

    /// List one run's protected requests under one shared lock.
    ///
    /// # Errors
    ///
    /// Refuses an invalid run or changed custody.
    pub fn list_run(&self, run: &str) -> Result<Vec<RequestRecord>, LaneError> {
        self.list_run_inner(run, self.read_deadline())
            .map(|(rows, _)| rows)
            .map_err(ReadFailure::into_error)
    }

    pub(crate) fn list_run_until(
        &self,
        run: &str,
        deadline: Instant,
    ) -> Result<Vec<RequestRecord>, LaneError> {
        self.list_run_inner(run, Some(deadline))
            .map(|(rows, _)| rows)
            .map_err(ReadFailure::into_error)
    }

    pub(super) fn list_run_for_wait(
        &self,
        run: &str,
    ) -> Result<(Vec<RequestRecord>, Duration), ReadFailure> {
        self.list_run_inner(run, self.read_deadline())
    }

    fn list_run_inner(
        &self,
        run: &str,
        deadline: Option<Instant>,
    ) -> Result<(Vec<RequestRecord>, Duration), ReadFailure> {
        if !crate::valid_run_name(run) {
            return Err(problem("requests-request-refusal", "run name is invalid").into());
        }
        if read_leaf(self.state_dir(), LOCK_FILE, self.owner, 4096)?.is_none() {
            let (initial, _, rows) = self.read_run(run)?;
            #[cfg(test)]
            after_reader_records();
            if read_leaf(self.state_dir(), LOCK_FILE, self.owner, 4096)?.is_none() {
                if initial.is_some() {
                    return Err(problem(
                        "requests-record-refusal",
                        "request custody exists without lock",
                    )
                    .into());
                }
                return Ok((rows, Duration::ZERO));
            }
        }
        let _lock = self.lock_retry(false, deadline)?;
        let started = Instant::now();
        #[cfg(test)]
        stretch_shared_hold();
        let rows = self.read_run(run)?.2;
        Ok((rows, started.elapsed()))
    }

    #[cfg(test)]
    pub(crate) fn fixture_replace_run_bytes(
        &self,
        run: &str,
        bytes: &[u8],
    ) -> Result<(), LaneError> {
        let _lock = self.lock(true)?;
        let custody = self.custody(run)?;
        replace_leaf(&custody, RUN_FILE, bytes, self.owner, MAX_RUN_BYTES)
    }

    #[cfg(test)]
    pub(crate) fn fixture_edit_run(
        &self,
        run: &str,
        edit: impl FnOnce(&mut Value),
    ) -> Result<(), LaneError> {
        let _lock = self.lock(true)?;
        let (bytes, _, _) = self.read_run(run)?;
        let bytes =
            bytes.ok_or_else(|| problem("requests-record-refusal", "fixture run is absent"))?;
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| problem("requests-record-refusal", "fixture run is not JSON"))?;
        edit(&mut value);
        let next = serde_json::to_vec(&value)
            .map_err(|error| problem("requests-record-refusal", error.to_string()))?;
        decode_run(Some(&next), run)?;
        let custody = self.custody(run)?;
        replace_leaf(&custody, RUN_FILE, &next, self.owner, MAX_RUN_BYTES)?;
        let runs = self.all_runs(None)?;
        self.repair_shapes(&runs)
    }

    #[cfg(test)]
    pub(crate) fn fixture_edit_modes(
        &self,
        edit: impl FnOnce(&mut Value),
    ) -> Result<(), LaneError> {
        let _lock = self.lock(true)?;
        let mut value = self.read_modes()?.value();
        edit(&mut value);
        let ledger = ModeLedger::decode(&value, &self.loop_name)?;
        self.write_modes(&ledger).map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn fixture_exclusive_lock(&self) -> Result<StoreLock, LaneError> {
        self.lock(true)
    }

    /// Read one request selected by its service-generated ID.
    ///
    /// # Errors
    ///
    /// Refuses a missing request or inconsistent shape record.
    pub fn request(&self, id: &str) -> Result<RequestRecord, LaneError> {
        let run = id
            .split_once(':')
            .map(|(run, _)| run)
            .ok_or_else(|| problem("requests-request-refusal", "request identifier is invalid"))?;
        if read_leaf(&self.state, LOCK_FILE, self.owner, 4096)?.is_none() {
            let initial_runs = self.all_runs(None)?;
            let initial_shapes = read_leaf(&self.state, SHAPES_FILE, self.owner, MAX_SHAPES_BYTES)?;
            #[cfg(test)]
            after_reader_records();
            if read_leaf(&self.state, LOCK_FILE, self.owner, 4096)?.is_none() {
                if initial_runs.is_empty() && initial_shapes.is_none() {
                    return Err(problem("requests-request-refusal", "request is absent"));
                }
                return Err(problem(
                    "requests-record-refusal",
                    "shape record exists without lock",
                ));
            }
        }
        let _lock = self.lock(false)?;
        let runs = self.all_runs(None)?;
        let _stale = self.shape_status(&runs)?;
        runs.into_iter()
            .find(|(name, _, _)| name == run)
            .and_then(|(_, _, requests)| requests.into_iter().find(|request| request.id() == id))
            .ok_or_else(|| problem("requests-request-refusal", "request is absent"))
    }

    /// Read all bounded requests and the per-loop shape record.
    ///
    /// # Errors
    ///
    /// Refuses a missing or inconsistent record.
    pub fn list(&self) -> Result<(Vec<RequestRecord>, Value), LaneError> {
        self.list_with_status()
            .map(|(requests, shapes, _)| (requests, shapes))
    }

    /// Read request rows and report whether the durable shape copy is stale.
    ///
    /// # Errors
    ///
    /// Refuses an invalid authoritative run record.
    pub fn list_with_status(&self) -> Result<(Vec<RequestRecord>, Value, bool), LaneError> {
        self.list_with_status_inner()
            .map(|(rows, shapes, stale, _)| (rows, shapes, stale))
            .map_err(ReadFailure::into_error)
    }

    pub(super) fn list_with_status_for_wait(
        &self,
    ) -> Result<(Vec<RequestRecord>, Value, bool, Duration), ReadFailure> {
        self.list_with_status_inner()
    }

    fn list_with_status_inner(
        &self,
    ) -> Result<(Vec<RequestRecord>, Value, bool, Duration), ReadFailure> {
        if read_leaf(&self.state, LOCK_FILE, self.owner, 4096)?.is_none() {
            let initial_runs = self.all_runs(None)?;
            let initial_shapes = read_leaf(&self.state, SHAPES_FILE, self.owner, MAX_SHAPES_BYTES)?;
            #[cfg(test)]
            after_reader_records();
            if read_leaf(&self.state, LOCK_FILE, self.owner, 4096)?.is_none() {
                if !initial_runs.is_empty() || initial_shapes.is_some() {
                    return Err(problem(
                        "requests-record-refusal",
                        "shape record exists without lock",
                    )
                    .into());
                }
                return Ok((Vec::new(), Self::shapes(&[])?, false, Duration::ZERO));
            }
        }
        let _lock = self.lock_inner(false)?;
        let started = Instant::now();
        #[cfg(test)]
        stretch_shared_hold();
        let runs = self.all_runs(None)?;
        let stale = self.shape_status(&runs)?;
        let shapes = Self::shapes(&runs)?;
        Ok((
            runs.into_iter().flat_map(|(_, _, rows)| rows).collect(),
            shapes,
            stale,
            started.elapsed(),
        ))
    }

    /// Apply one validated batch to one run, with no write on any refusal.
    ///
    /// # Errors
    ///
    /// Refuses the whole batch if any member is malformed, duplicate or stale.
    pub fn triage(
        &self,
        run: &str,
        decisions: &[Value],
        adjudicator: &str,
        at: &str,
    ) -> Result<usize, LaneError> {
        self.triage_with_reports(run, decisions, adjudicator, at)
            .map(|(count, _)| count)
    }

    /// Apply one batch and return any immediate rubric correction reports.
    ///
    /// # Errors
    ///
    /// Refuses a malformed batch before changing any request.
    pub fn triage_with_reports(
        &self,
        run: &str,
        decisions: &[Value],
        adjudicator: &str,
        at: &str,
    ) -> Result<(usize, Vec<Value>), LaneError> {
        if decisions.is_empty() || decisions.len() > MAX_REQUESTS_PER_RUN {
            return Err(problem("requests-batch-refusal", "batch size is invalid"));
        }
        let guard = self.lock(true)?;
        if self.channel_bound()? {
            drop(guard);
            return self
                .collection_legacy_triage(run, decisions)
                .map(|count| (count, Vec::new()));
        }
        let (old, revision, mut requests) = self.read_run(run)?;
        let mut ids = HashSet::new();
        for decision in decisions {
            let object = decision
                .as_object()
                .ok_or_else(|| problem("requests-batch-refusal", "decision is not an object"))?;
            let id = decision["id"]
                .as_str()
                .ok_or_else(|| problem("requests-batch-refusal", "request identifier is absent"))?;
            if !ids.insert(id) || !id.starts_with(&format!("{run}:")) {
                return Err(problem(
                    "requests-batch-refusal",
                    "duplicate or cross-run request",
                ));
            }
            let request = requests
                .iter_mut()
                .find(|request| request.id() == id)
                .ok_or_else(|| problem("requests-batch-refusal", "request is absent"))?;
            match decision["action"].as_str() {
                Some("mark") if object.len() == 3 && object.contains_key("reason") => {
                    request
                        .mark(decision["reason"].as_str().unwrap_or_default())
                        .map_err(|error| problem("requests-batch-refusal", error.line()))?;
                }
                Some("adjudicate")
                    if object.len() == 4
                        && object.contains_key("treatment")
                        && object.contains_key("reason") =>
                {
                    request
                        .triage(
                            decision["treatment"].as_str().unwrap_or_default(),
                            decision["reason"].as_str().unwrap_or_default(),
                            adjudicator,
                            at,
                        )
                        .map_err(|error| problem("requests-batch-refusal", error.line()))?;
                }
                _ => return Err(problem("requests-batch-refusal", "decision shape differs")),
            }
        }
        let changed = requests
            .iter()
            .filter(|request| ids.contains(request.id()))
            .cloned()
            .collect::<Vec<_>>();
        self.preflight_correction_modes(&changed)?;
        self.commit_run(run, old.as_deref(), revision + 1, &requests)?;
        let reports = self.apply_corrections_locked(&changed, &now_nanos().to_string());
        Ok((decisions.len(), reports))
    }

    /// Save a fresh review ID while preserving the marked request state.
    ///
    /// # Errors
    ///
    /// Refuses an unknown or unmarked request.
    pub fn review(&self, id: &str, at: &str) -> Result<RequestRecord, LaneError> {
        let guard = self.lock(true)?;
        if self.channel_bound()? {
            drop(guard);
            return self.collection_legacy_review(id);
        }
        self.change_one_locked(id, false, |request| {
            if request.value()["state"] == "observed" {
                request.mark_observed()?;
            }
            let review_id = format!(
                "{:x}{:x}",
                now_nanos(),
                STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            request.review(&review_id, at)
        })
        .map(|(request, _)| request)
    }

    /// Adjudicate exactly one marked request with its current review ID.
    ///
    /// # Errors
    ///
    /// Refuses an unknown request, old review ID or wrong state.
    pub fn adjudicate(
        &self,
        id: &str,
        review_id: &str,
        treatment: &str,
        reason: &str,
        adjudicator: &str,
        at: &str,
    ) -> Result<RequestRecord, LaneError> {
        self.adjudicate_with_reports(id, review_id, treatment, reason, adjudicator, at)
            .map(|(request, _)| request)
    }

    /// Adjudicate one request and return its immediate mode correction report.
    ///
    /// # Errors
    ///
    /// Refuses a stale review or changed protected record.
    pub fn adjudicate_with_reports(
        &self,
        id: &str,
        review_id: &str,
        treatment: &str,
        reason: &str,
        adjudicator: &str,
        at: &str,
    ) -> Result<(RequestRecord, Vec<Value>), LaneError> {
        let guard = self.lock(true)?;
        if self.channel_bound()? {
            drop(guard);
            return self
                .collection_legacy_adjudicate(id, review_id, treatment, reason)
                .map(|record| (record, Vec::new()));
        }
        self.change_one_locked(id, true, |request| {
            request.adjudicate(review_id, treatment, reason, adjudicator, at)
        })
    }

    fn change_one(
        &self,
        id: &str,
        apply_correction: bool,
        change: impl FnOnce(&mut RequestRecord) -> Result<(), LaneError>,
    ) -> Result<(RequestRecord, Vec<Value>), LaneError> {
        let _lock = self.lock(true)?;
        self.change_one_locked(id, apply_correction, change)
    }

    fn change_one_locked(
        &self,
        id: &str,
        apply_correction: bool,
        change: impl FnOnce(&mut RequestRecord) -> Result<(), LaneError>,
    ) -> Result<(RequestRecord, Vec<Value>), LaneError> {
        let run = id
            .split_once(':')
            .map(|(run, _)| run)
            .ok_or_else(|| problem("requests-request-refusal", "request identifier is invalid"))?;
        let (old, revision, mut requests) = self.read_run(run)?;
        let request = requests
            .iter_mut()
            .find(|request| request.id() == id)
            .ok_or_else(|| problem("requests-request-refusal", "request is absent"))?;
        change(request)?;
        let result = request.clone();
        if apply_correction {
            self.preflight_correction_modes(std::slice::from_ref(&result))?;
        }
        self.commit_run(run, old.as_deref(), revision + 1, &requests)?;
        let reports = if apply_correction {
            self.apply_corrections_locked(std::slice::from_ref(&result), &now_nanos().to_string())
        } else {
            Vec::new()
        };
        Ok((result, reports))
    }
}

fn correction_pending(request: &RequestRecord, ledger: &ModeLedger) -> Result<bool, LaneError> {
    if !is_enforce_correction(request) {
        return Ok(false);
    }
    let value = request.value();
    let target = ModeTarget::class(value["class"].as_str().unwrap_or_default())?;
    Ok(
        super::command::feedback(value).correction_pending(ledger.current(&target).map(
            |setting| {
                (
                    setting.value()["mode"] == "audit",
                    setting.value()["set_at"]
                        .as_str()
                        .and_then(|at| at.parse().ok()),
                )
            },
        )),
    )
}

fn is_correction(request: &RequestRecord) -> bool {
    super::command::feedback(request.value()).is_correction()
}

fn is_enforce_correction(request: &RequestRecord) -> bool {
    is_correction(request) && request.value()["mode"] == "enforce"
}

fn rubric_row_report(request: &RequestRecord) -> Value {
    let value = request.value();
    json!({"target":value["class"],"mode":value["mode"],"changed":false,
        "action":execute_command::learning::correction_action(),"correction_request":request.id(),"reason":value["label"]["reason"]})
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::{
        AFTER_FIRST_LOCK_MISS, AFTER_READER_LOCK_ACQUIRED, AFTER_READER_LOCK_CONTENTION,
        AFTER_READER_LOCK_TIMEOUT, AFTER_READER_RECORDS, ATTEMPT_FILE, FAIL_MODE_WRITE,
        FAIL_SHAPE_WRITE, LOCK_FILE, LOOP_CAP, LOOP_CAP_REMEDY, RUN_FILE, SHAPES_FILE, Store,
    };
    use crate::requests::{Mode, RequestRecord, modes::ModeTarget, tests::waiting};

    pub fn with_shape_write_failure<T>(f: impl FnOnce() -> T) -> T {
        FAIL_SHAPE_WRITE.with(|fail| fail.set(true));
        let result = f();
        FAIL_SHAPE_WRITE.with(|fail| fail.set(false));
        result
    }

    pub fn arm_mode_write_failure() {
        FAIL_MODE_WRITE.with(|fail| fail.set(true));
    }

    /// # Panics
    /// Panics only if the synchronized fixture fails to preserve both completed effects.
    /// ´test:unit:request-writers-retry-record-until-request-deadline´
    #[test]
    fn request_writers_retry_record_until_request_deadline() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let store = fixture.store();
        let first = waiting("R", "1a", 3000, Mode::Audit);
        let second = waiting("S", "2b", 3001, Mode::Audit);
        let mut effect = first.value()["effect"].clone();
        effect["state"] = json!("completed");
        effect["reason"] = json!("door-complete");
        effect["exit_status"] = json!(0);
        effect["ref_check"] = json!("not-applicable");
        store.file(first).expect("first reservation");
        store.file(second).expect("second reservation");
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = store
            .for_request(deadline)
            .expect("first view")
            .with_request_id("R:1a");
        let second = store
            .for_request(deadline)
            .expect("second view")
            .with_request_id("S:2b");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let effect = &effect;
            let first = scope.spawn(move || {
                super::BEFORE_LEAF_SYNC.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        held_tx.send(()).expect("first syncing");
                        release_rx
                            .recv_timeout(Duration::from_secs(4))
                            .expect("second exhausted one wait");
                    }));
                });
                first
                    .record_effect("R:1a", effect.clone())
                    .expect("first completed")
            });
            held_rx
                .recv_timeout(Duration::from_secs(4))
                .expect("first holds record lock");
            super::WRITER_LOCK_WAIT_OVERRIDE
                .with(|bound| bound.set(Some(Duration::from_millis(20))));
            super::AFTER_WRITER_LOCK_TIMEOUT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    release_tx.send(()).expect("release first after timeout");
                }));
            });
            second
                .record_effect("S:2b", effect.clone())
                .expect("retry preserves second completed effect");
            super::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(None));
            first.join().expect("first writer");
        });
        for id in ["R:1a", "S:2b"] {
            assert_eq!(
                store.request(id).expect("durable effect").value()["effect"],
                effect
            );
        }
    }

    /// # Panics
    /// Panics only if contention ignores the request deadline or masks a different refusal.
    /// ´test:unit:request-writer-deadline-names-lock-wait-and-holder´
    #[test]
    fn request_writer_deadline_names_lock_wait_and_holder() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let store = fixture.store().with_request_id("R:holder");
        let held = store.fixture_exclusive_lock().expect("holder");
        let started = Instant::now();
        let waiter = store
            .for_request(started + Duration::from_millis(30))
            .expect("waiter");
        for fd in [&waiter.runs, &waiter.state] {
            let flags =
                nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("descriptor flags");
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "request custody must not reach spawned commands"
            );
        }
        super::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(Some(Duration::from_millis(30))));
        let error = waiter.ensure_first_mode("ssh").expect_err("deadline");
        super::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(None));
        assert!(super::is_lock_contention(&error));
        assert!(error.detail.contains("wait_seconds="));
        assert!(error.detail.contains("holder_request_id=R:holder"));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(held);
        store
            .ensure_first_mode("ssh")
            .expect("record after holder release");
        assert!(!super::is_lock_contention(&crate::error::LaneError::input(
            "requests-record-refusal",
            "request lock owner or mode differs"
        )));
    }

    /// # Panics
    /// Panics only if a completed effect loses its base wait after the request deadline.
    /// ´test:unit:request-effect-after-deadline-retains-writer-allowance´
    #[test]
    fn request_effect_after_deadline_retains_writer_allowance() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let store = fixture.store();
        let request = waiting("R", "1a", 3000, Mode::Audit);
        let mut effect = request.value()["effect"].clone();
        effect["state"] = json!("completed");
        effect["reason"] = json!("door-complete");
        effect["exit_status"] = json!(0);
        effect["ref_check"] = json!("not-applicable");
        store.file(request).expect("reservation");
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("past deadline");
        let waiter = store
            .for_request(expired)
            .expect("expired view")
            .with_request_id("R:1a");
        let holder = store.with_request_id("S:holder");
        let held = holder.fixture_exclusive_lock().expect("sibling holder");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                release_rx
                    .recv_timeout(Duration::from_secs(4))
                    .expect("late writer contends");
                drop(held);
            });
            super::WRITER_LOCK_WAIT_OVERRIDE
                .with(|bound| bound.set(Some(Duration::from_millis(200))));
            super::AFTER_WRITER_LOCK_CONTENTION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    release_tx.send(()).expect("release after contention");
                }));
            });
            waiter
                .record_effect("R:1a", effect.clone())
                .expect("late completed effect");
            super::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(None));
        });
        assert_eq!(
            holder.request("R:1a").expect("durable effect").value()["effect"],
            effect
        );
    }

    /// ´test:unit:agent-merge-preserves-effect-and-supervisory-label´
    #[test]
    fn agent_merge_preserves_effect_and_supervisory_label() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let request = waiting("R", "1a", 3000, Mode::Audit);
        let mut effect = request.value()["effect"].clone();
        effect["state"] = json!("completed");
        effect["reason"] = json!("door-complete");
        effect["exit_status"] = json!(0);
        effect["ref_check"] = json!("not-applicable");
        store.file(request).expect("intent");
        let result = crate::door::agent::RunnerOutcome::referral(
            "timeout",
            "deadline",
            std::time::Instant::now(),
        );
        std::thread::scope(|scope| {
            let judgement =
                scope.spawn(|| store.record_agent("R:1a", &result, None, Some("configured")));
            let completion = scope.spawn(|| store.record_effect("R:1a", effect.clone()));
            let supervision = scope.spawn(|| store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"supervisory answer"})], "superloop", "2"));
            judgement
                .join()
                .expect("judgement thread")
                .expect("judgement");
            completion.join().expect("effect thread").expect("effect");
            supervision
                .join()
                .expect("supervision thread")
                .expect("supervision");
        });
        let record = store.list_run("R").expect("merged").remove(0).into_value();
        assert_eq!(record["effect"], effect);
        assert_eq!(record["label"]["treatment"], "allow");
        assert_eq!(record["label"]["would_do"]["decision"], "refer");
        assert_eq!(record["decision_tier"], "superloop");
        assert_eq!(record["would_do_source"], "agent");
        assert_eq!(record["agent_status"], "timeout");
    }

    /// ´test:unit:learned-rubric-keeps-retired-conflicts-and-citations´
    #[test]
    fn learned_rubric_keeps_retired_conflicts_and_citations() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("first request");
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("miss")
                .0["decision"],
            "undecided"
        );
        store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"read-only"})], "superloop", "2").expect("label");
        let (decision, evidence, _) = store
            .learned_judgement("git", "git-upload", "git:upload")
            .expect("hit");
        assert_eq!(decision["decision"], "allow");
        assert_eq!(evidence["request_ids"], json!(["R:1a"]));
        store
            .file(waiting("S", "2b", 3001, Mode::Audit))
            .expect("second uid");
        store.triage("S", &[json!({"id":"S:2b","action":"adjudicate","treatment":"refuse","reason":"conflicting evidence"})], "superloop", "3").expect("correction");
        fs::rename(
            fixture.runs.join(".launch-S"),
            fixture.runs.join(".retired-S-custody"),
        )
        .expect("retained custody");
        let (decision, evidence, history) = store
            .learned_judgement("git", "git-upload", "git:upload")
            .expect("retired conflict");
        assert_eq!(decision["decision"], "undecided");
        assert!(evidence.is_null());
        assert_eq!(history.as_array().expect("history").len(), 2);
        fs::write(
            fixture.runs.join(".retired-S-custody").join(RUN_FILE),
            b"broken retired JSON",
        )
        .expect("damaged archive");
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("index independent of archive")
                .0["decision"],
            "undecided"
        );
        let mut index = store.read_learned().expect("index");
        for sequence in 0..16_400 {
            let mut row = waiting("R", "1a", 3000, Mode::Audit).into_value();
            row["id"] = json!(format!("R:{sequence}"));
            row["filed_at"] = json!(sequence.to_string());
            Store::index_judgement(&mut index, &row, None);
        }
        store.write_learned(&index).expect("bounded index");
        let (_, _, history) = store
            .learned_judgement("git", "git-upload", "git:upload")
            .expect("busy shape remains a miss");
        assert_eq!(history.as_array().expect("slice").len(), 8);
        assert_eq!(history[0]["id"], "R:16399");
        assert!(history.to_string().len() < 32_768);
        fs::write(
            fixture
                .home
                .join(".config/loops/alpha")
                .join(super::LEARNED_FILE),
            b"bad JSON",
        )
        .expect("bad index");
        assert!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .is_err()
        );
        store
            .file(waiting("R", "3c", 3000, Mode::Audit))
            .expect("lookup failure does not prevent filing");
        let malformed = json!({"schema":1,"groups":{"[\"git\",\"git-upload\",\"git:upload\"]":{"allow":1,"refuse":0,"history":[],"citations":null}}});
        store
            .write_learned(&malformed)
            .expect("malformed index fixture");
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect_err("malformed citation is a lookup miss")
                .kind,
            "requests-learned-index"
        );
        store
            .file(waiting("R", "4d", 3000, Mode::Audit))
            .expect("malformed index does not prevent filing");
        store
            .write_learned(&json!({"oversized":"x".repeat(super::MAX_LEARNED_BYTES)}))
            .expect("oversized index becomes unavailable");
        assert!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .is_err()
        );
    }

    /// ´test:unit:learned-index-status-and-rebuild-retain-retired-labels´
    #[test]
    fn learned_index_status_and_rebuild_retain_retired_labels() {
        let fixture = Fixture::new();
        fixture.configure_door();
        let store = fixture.store();
        assert_eq!(
            fixture.command(&["status", "alpha"], b"").expect("status")["learned_index"]["state"],
            "absent"
        );
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("request");
        store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"refuse","reason":"retained refusal"})], "superloop", "2").expect("label");
        let retained = fs::read(fixture.run_file("R")).expect("retained bytes");
        fs::rename(
            fixture.runs.join(".launch-R"),
            fixture.runs.join(".retired-R-custody"),
        )
        .expect("retire all recorded runs");
        let index = fixture
            .home
            .join(".config/loops/alpha")
            .join(super::LEARNED_FILE);
        fs::remove_file(&index).expect("missing index");
        store
            .file(waiting("S", "2b", 3001, Mode::Audit))
            .expect("filing remains available");
        assert_eq!(
            fixture.command(&["status", "alpha"], b"").expect("status")["learned_index"]["state"],
            "unavailable"
        );
        assert!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .is_err()
        );
        assert_eq!(
            fixture
                .command(&["rebuild-index", "alpha"], b"")
                .expect("rebuild")["state"],
            "current"
        );
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("retired label")
                .0["decision"],
            "refuse"
        );
        store.triage("S", &[json!({"id":"S:2b","action":"adjudicate","treatment":"allow","reason":"conflicting label"})], "superloop", "3").expect("label");
        fs::write(&index, b"broken JSON").expect("damage index");
        assert_eq!(
            fixture.command(&["status", "alpha"], b"").expect("status")["learned_index"]["state"],
            "invalid"
        );
        fixture
            .command(&["rebuild-index", "alpha"], b"")
            .expect("repair damaged index");
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("retired conflict")
                .0["decision"],
            "undecided"
        );
        assert_eq!(
            fs::read(fixture.runs.join(".retired-R-custody").join(RUN_FILE))
                .expect("unchanged custody"),
            retained
        );
        fs::write(
            fixture.runs.join(".retired-R-custody").join(RUN_FILE),
            b"broken custody",
        )
        .expect("invalid archive");
        assert!(fixture.command(&["rebuild-index", "alpha"], b"").is_err());
        assert_eq!(store.learned_status()["state"], "unavailable");
        fs::write(
            fixture.runs.join(".retired-R-custody").join(RUN_FILE),
            retained,
        )
        .expect("repair archive");
        assert_eq!(
            fixture
                .command(&["rebuild-index", "alpha"], b"")
                .expect("retry rebuild")["state"],
            "current"
        );
    }

    /// ´test:unit:rebuild-and-rewrite-accept-retirement-mixed-root´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn rebuild_and_rewrite_accept_retirement_mixed_root() {
        use serde_json::Value;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        use std::os::unix::net::UnixListener;

        let fixture = Fixture::new();
        fixture.configure_door();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("request");
        store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"refuse","reason":"retired refusal"})], "superloop", "2").expect("label");
        store
            .file(waiting("S", "2b", 3001, Mode::Audit))
            .expect("second worker request");
        store.triage("S", &[json!({"id":"S:2b","action":"adjudicate","treatment":"refuse","reason":"live refusal"})], "superloop", "3").expect("second label");
        let driver = fixture.runs.join("R");
        fs::create_dir(&driver).expect("driver");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("driver mode");
        let worker_home = fixture.home.join("worker-R");
        fs::create_dir(&worker_home).expect("worker home");
        fs::write(driver.join("evidence"), b"driver evidence").expect("driver evidence");
        fs::write(worker_home.join("evidence"), b"home evidence").expect("home evidence");
        let identity = crate::plan::protected_identity_dir(&driver).expect("identity path");
        let observed = fixture.runs.join(".observed-R.txt");
        fs::write(&observed, b"observed host").expect("observed file");
        let mut sources = vec![
            (driver.clone(), 0),
            (worker_home.clone(), 1),
            (identity, 2),
            (observed, 3),
        ];
        for (path, index) in [
            (
                crate::container_helper::socket_path(&driver).expect("helper path"),
                4,
            ),
            (
                crate::container_helper::control_socket_path(&driver).expect("control path"),
                5,
            ),
        ] {
            let slot = crate::SocketSlot::pinned(&path, nix::unistd::Uid::effective().as_raw())
                .expect("socket slot");
            drop(UnixListener::bind(slot.address()).expect("ended helper socket"));
            assert!(
                fs::symlink_metadata(&path)
                    .expect("socket metadata")
                    .file_type()
                    .is_socket()
            );
            sources.push((path, index));
        }
        for attempt in 1..=4 {
            let path =
                crate::plan::protected_identifier_path(&driver, attempt).expect("identifier path");
            fs::write(&path, format!("container-{attempt}")).expect("identifier file");
            sources.push((path, attempt + 5));
        }
        let held: std::os::fd::OwnedFd = fs::File::open(&fixture.runs).expect("runs root").into();
        let initial = json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":worker_home,"driver_dir":driver,"round_dir":driver.join("first-dispatch"),"preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"evidence":"driver directory outside home","wall_seconds":1.0});
        crate::launch::report::publish(&held, "R", None, &initial).expect("initial report");
        let resumed = json!({"schema":1,"command":"launch","dry_run":false,"round":"review","round_dir":driver.join("review"),"budget_seconds":3600,"letter":"letter.md","letter_reconciliation":[],"thread_id":"thread","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"wall_seconds":2.0});
        crate::launch::report::publish(&held, "R", Some("review"), &resumed)
            .expect("resumed report");
        for (step, index) in [(None, 21), (Some("review"), 22)] {
            sources.push((
                fixture
                    .runs
                    .join(crate::launch::report::name("R", step).expect("report name")),
                index,
            ));
        }
        let snapshots: Vec<_> = sources
            .iter()
            .map(|(path, index)| {
                let metadata = fs::symlink_metadata(path).expect("source metadata");
                let bytes = metadata
                    .is_file()
                    .then(|| fs::read(path).expect("source bytes"));
                (path.clone(), *index, metadata, bytes)
            })
            .collect();
        let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"rounds":[{"step":"dispatch"},{"step":"review"}],"plan":{"home":worker_home,"driver_dir":driver,"runtime_argv":["/usr/bin/podman"]},"launcher_pid":321,"launcher_start":88,"helper_pid":322,"helper_start":89,"helper_parent_pid":325,"helper_parent_start":92,"driver_entry_pid":323,"driver_entry_start":90,"observer_pid":324,"observer_start":91,"observer_state":"running"});
        crate::launch::publish_reservation(
            &crate::launch::reservation_path(&fixture.runs, "R"),
            &record,
        )
        .expect("reservation");
        let retired = crate::launch::retire::retire_record_with(
            &fixture.runs,
            "R",
            &worker_home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("production retirement");
        let paths = retired["journal"]["planned_paths"]
            .as_array()
            .expect("paths");
        let target = |source: &Path| {
            PathBuf::from(
                paths
                    .iter()
                    .find(|pair| pair["source"] == json!(source))
                    .expect("retired source")["target"]
                    .as_str()
                    .expect("target"),
            )
        };
        let custody = target(&fixture.runs.join(".launch-R"));
        let retired_driver = target(&driver);
        assert_eq!(paths.len(), snapshots.len());
        let check_artifacts = || {
            for (source, index, before, bytes) in &snapshots {
                let destination = target(source);
                assert_eq!(
                    destination,
                    source.parent().expect("parent").join(format!(
                        ".retired-R-{index}-{}-{}",
                        before.dev(),
                        before.ino()
                    ))
                );
                assert!(!source.exists(), "source moved: {}", source.display());
                let after = fs::symlink_metadata(&destination).expect("retired metadata");
                assert_eq!(after.file_type(), before.file_type());
                assert_eq!(
                    (after.dev(), after.ino(), after.mode(), after.uid()),
                    (before.dev(), before.ino(), before.mode(), before.uid())
                );
                if let Some(bytes) = bytes {
                    assert_eq!(&fs::read(&destination).expect("retired bytes"), bytes);
                }
            }
            assert_eq!(
                fs::read(target(&driver).join("evidence")).expect("driver retained"),
                b"driver evidence"
            );
            assert_eq!(
                fs::read(target(&worker_home).join("evidence")).expect("home retained"),
                b"home evidence"
            );
        };
        check_artifacts();
        let check_index = || {
            let index = store.read_learned().expect("complete index");
            let groups = index["groups"].as_object().expect("groups");
            assert_eq!(groups.len(), 1);
            let group = groups.values().next().expect("shape");
            assert_eq!(group["allow"], 0);
            assert_eq!(group["refuse"], 2);
            let mut ids: Vec<_> = group["citations"]
                .as_array()
                .expect("citations")
                .iter()
                .map(|id| id.as_str().expect("id"))
                .collect();
            ids.sort_unstable();
            assert_eq!(ids, ["R:1a", "S:2b"]);
        };
        let archive = PathBuf::from(retired["record"].as_str().expect("archive"));
        assert!(
            archive
                .file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with(".retired-R-20-")
        );
        assert!(fs::metadata(&archive).expect("archive metadata").is_file());
        assert_eq!(
            fs::metadata(&archive).expect("archive mode").mode() & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(&custody).expect("custody mode").mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&retired_driver).expect("driver mode").mode() & 0o7777,
            0o755
        );
        let archive_bytes = fs::read(&archive).expect("archive bytes");
        let request_path = custody.join(RUN_FILE);
        let retained = fs::read(&request_path).expect("retained");
        assert_eq!(
            fixture
                .command(&["rebuild-index", "alpha"], b"")
                .expect("rebuild")["state"],
            "current"
        );
        check_artifacts();
        check_index();
        assert_eq!(
            fs::read(&request_path).expect("unchanged custody"),
            retained
        );
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("retired label")
                .0["decision"],
            "refuse"
        );
        let mut historical: Value = serde_json::from_slice(&retained).expect("record");
        for row in historical["requests"].as_array_mut().expect("rows") {
            for key in crate::requests::judgement::KEYS {
                row.as_object_mut().expect("row").remove(key);
            }
            row["schema"] = json!(3);
        }
        fs::write(
            &request_path,
            serde_json::to_vec(&historical).expect("old bytes"),
        )
        .expect("schema three");
        let preview = fixture
            .command(&["rewrite", "alpha", "--dry-run"], b"")
            .expect("rewrite plan");
        assert_eq!(preview["plan"]["files"].as_array().expect("files").len(), 2);
        fixture
            .command(
                &[
                    "rewrite",
                    "alpha",
                    "--expect-digest",
                    preview["preview_sha256"].as_str().expect("digest"),
                ],
                b"",
            )
            .expect("rewrite");
        check_artifacts();
        check_index();
        assert_eq!(
            store
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("rewritten label")
                .0["decision"],
            "refuse"
        );
        let converted: Value =
            serde_json::from_slice(&fs::read(&request_path).expect("converted")).expect("JSON");
        assert_eq!(converted["requests"][0]["schema"], 4);
        assert_eq!(
            fs::read(&archive).expect("archive unchanged"),
            archive_bytes
        );
        fs::write(&request_path, b"broken custody").expect("real failure");
        assert!(fixture.command(&["rebuild-index", "alpha"], b"").is_err());
        assert_eq!(store.learned_status()["reason"], "index rebuild incomplete");
        assert_eq!(store.learned_status()["state"], "unavailable");
    }

    /// ´test:unit:learned-index-capacity-status-names-limit´
    #[test]
    fn learned_index_capacity_status_names_limit() {
        let fixture = Fixture::new();
        let store = fixture.store();
        for (reason, limit) in [
            ("shape index capacity", json!({"shapes":512})),
            (
                "index byte capacity",
                json!({"bytes":super::MAX_LEARNED_BYTES}),
            ),
        ] {
            store
                .write_learned(&json!({"unavailable":true,"reason":reason}))
                .expect("capacity fixture");
            let status = fixture
                .command(&["status", "alpha"], b"")
                .expect("capacity status");
            assert_eq!(status["learned_index"]["limit"], limit);
            assert!(status["learned_index"]["rebuild"].is_null());
        }
    }

    /// ´test:unit:rebuild-requires-idle-and-measures-retired-scan´
    #[test]
    fn rebuild_requires_idle_and_measures_retired_scan() {
        use std::io::Write as _;

        let fixture = Fixture::new();
        let door = fixture.configure_door();
        let service = nix::fcntl::Flock::lock(
            File::open(&door).expect("service directory"),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .expect("live service lock");
        let writer = fixture.store();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let filing = scope.spawn(|| {
                barrier.wait();
                let setting = writer.ensure_first_mode("git").expect("request mode");
                let mut row = waiting("R", "1a", 3000, Mode::Audit).into_value();
                row["class_setting"] = setting["class"].clone();
                row["loop_setting"] = setting["loop"].clone();
                row["mode"] = setting["mode"].clone();
                writer
                    .file(RequestRecord::decode(row).expect("request snapshot"))
                    .expect("concurrent request filed");
            });
            barrier.wait();
            let refusal = fixture
                .command(&["rebuild-index", "alpha"], b"")
                .expect_err("live rebuild refused before store lock");
            assert_eq!(refusal.kind, "requests-rebuild-idle");
            assert!(refusal.detail.contains("rebuild_wall_ms="));
            filing.join().expect("filing thread");
        });
        assert_eq!(writer.list_run("R").expect("filed request").len(), 1);
        drop(service);
        for sequence in 0..320 {
            let run = format!("archive{sequence}");
            let custody = fixture.runs.join(format!(".retired-{run}-custody"));
            fs::create_dir(&custody).expect("retired directory");
            fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
            let mut row = waiting(&run, "1a", 3000 + sequence % 2, Mode::Audit);
            row.mark("review").expect("mark");
            row.review("review-1", "2").expect("review");
            row.adjudicate("review-1", "allow", "retained label", "superloop", "3")
                .expect("label");
            let path = custody.join(RUN_FILE);
            fs::write(
                &path,
                super::encode_run(&run, 1, &[row]).expect("run bytes"),
            )
            .expect("retired file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("record mode");
        }
        let report = fixture
            .command(&["rebuild-index", "alpha"], b"")
            .expect("idle rebuild");
        assert_eq!(report["state"], "current");
        assert!(report["wall_ms"].as_f64().is_some_and(|wall| wall > 0.0));
        writeln!(
            std::io::stderr().lock(),
            "rebuild_retired_runs=320 rebuild_wall_ms={}",
            report["wall_ms"]
        )
        .expect("rebuild measurement");
        assert_eq!(
            writer
                .learned_judgement("git", "git-upload", "git:upload")
                .expect("rebuilt labels")
                .0["decision"],
            "allow"
        );
    }

    pub struct Fixture {
        _temp: tempfile::TempDir,
        _namespace: crate::home::PrivateHomeGuard,
        pub home: PathBuf,
        runs: PathBuf,
        permission_registry: PathBuf,
    }

    impl Fixture {
        fn configure_door(&self) -> PathBuf {
            let socket = self.home.join("socket");
            let door = socket.join("door");
            for path in [&socket, &door] {
                fs::create_dir(path).expect("socket directory");
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("socket mode");
            }
            let settings = self.home.join(".config/loops/alpha/workers.toml");
            fs::write(&settings, format!("socket_dir = {}\n", json!(socket))).expect("settings");
            fs::set_permissions(&settings, fs::Permissions::from_mode(0o600))
                .expect("settings mode");
            door
        }

        pub fn new() -> Self {
            Self::with_temp(tempfile::tempdir().expect("temporary fixture"))
        }

        pub fn with_temp(temp: tempfile::TempDir) -> Self {
            let home = std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME")
                .map_or_else(|| temp.path().join("owner"), PathBuf::from);
            let runs = home.join("runs");
            for path in [
                home.clone(),
                home.join(".config"),
                home.join(".config/loops"),
                home.join(".config/loops/alpha"),
                runs.clone(),
                runs.join(".launch-R"),
                runs.join(".launch-S"),
            ] {
                fs::create_dir_all(&path).expect("fixture directory");
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(
                        if path == home && std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_some()
                        {
                            0o711
                        } else {
                            0o700
                        },
                    ),
                )
                .expect("fixture mode");
            }
            let registry = format!(
                "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"{}\" }}]\n",
                runs.display()
            );
            let registry_path = home.join(".config/loops/registry.toml");
            fs::write(&registry_path, registry).expect("registry");
            fs::set_permissions(&registry_path, fs::Permissions::from_mode(0o600))
                .expect("registry mode");
            let home_fd = File::open(&home).expect("inherited home");
            let runs_fd = File::open(&runs).expect("inherited runs");
            let owner = nix::unistd::Uid::effective().as_raw();
            let namespace =
                crate::home::activate_private_launch(&home, &home_fd, &runs, &runs_fd, None, owner)
                    .expect("private namespace fixture");
            let permission_registry = super::test_helper::registry(temp.path(), "alpha");
            Self {
                _temp: temp,
                _namespace: namespace,
                home,
                runs,
                permission_registry,
            }
        }

        pub fn store(&self) -> Store {
            Store::open(&self.home, "alpha", true).expect("store")
        }

        pub fn snapshot_store(&self) -> Store {
            let store = self.store();
            for path in [
                self.home.join(".var"),
                self.home.join(".var/loops"),
                store.loop_root.clone(),
            ] {
                fs::create_dir_all(&path).expect("owner loop root");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).expect("root mode");
            }
            fs::create_dir_all(store.loop_root.join("policy")).expect("policy tier");
            fs::set_permissions(
                store.loop_root.join("policy"),
                fs::Permissions::from_mode(0o2750),
            )
            .expect("policy mode");
            store
        }

        fn run_file(&self, run: &str) -> PathBuf {
            self.runs.join(format!(".launch-{run}/{RUN_FILE}"))
        }
        fn shape_file(&self) -> PathBuf {
            self.home.join(".config/loops/alpha").join(SHAPES_FILE)
        }

        pub(crate) fn command(
            &self,
            args: &[&str],
            mut input: &[u8],
        ) -> Result<serde_json::Value, crate::error::LaneError> {
            let mut output = Vec::new();
            let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
            if args.first().is_some_and(|action| {
                matches!(
                    action.as_str(),
                    "status" | "list" | "triage" | "review" | "adjudicate"
                )
            }) {
                super::channel::with_test_client(
                    super::test_helper::binary(),
                    &self.permission_registry,
                    || crate::requests::commands::run(&self.home, &args, &mut input, &mut output),
                )?;
            } else {
                crate::requests::commands::run(&self.home, &args, &mut input, &mut output)?;
            }
            Ok(serde_json::from_slice(&output).expect("command JSON"))
        }

        pub fn set_floor(&self, floor: &str) {
            let registry = format!(
                "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"dev/alpha\", runs_root = \"{}\", door_floor = \"{floor}\" }}]\n",
                self.runs.display()
            );
            fs::write(self.home.join(".config/loops/registry.toml"), registry).expect("floor edit");
        }
    }

    fn fixture_request(
        run: &str,
        nonce: &str,
        worker: u32,
        floor: Mode,
        decision: &str,
    ) -> RequestRecord {
        let mut value = waiting(run, nonce, worker, floor).into_value();
        value["class"] = json!("fixture");
        value["shape_key"] = json!("fixture:read");
        value["would_do"]["decision"] = json!(decision);
        value["would_do"]["reason"] = json!("fixture rubric reason");
        crate::requests::judgement::initialize(&mut value);
        RequestRecord::decode(value).expect("fixture request")
    }

    /// ´test:unit:snapshot-failure-preserves-durable-door-filings´
    #[test]
    fn snapshot_failure_preserves_durable_door_filings() {
        let fixture = Fixture::new();
        let store = fixture.snapshot_store();
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_some() {
            store.publish_snapshot().expect("initial policy");
        }
        super::replace_leaf(
            store.state_dir(),
            "door.toml",
            b"rubric_root = '/absent-rubric'\nexecutable = '/usr/bin/true'\nmodel = 'fixture'\n",
            store.owner,
            65_536,
        )
        .expect("unavailable rubric configuration");
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("durable filing succeeds despite publication failure");
        let referral = crate::door::agent::RunnerOutcome::referral(
            "failure",
            "door-rubric-unavailable",
            std::time::Instant::now(),
        );
        store
            .record_agent("R:1a", &referral, None, None)
            .expect("durable referral");
        let (rows, _) = store.list().expect("read committed filing");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value()["would_do"]["decision"], "refer");
        assert!(!store.loop_root.join("policy/snapshot.json").exists());
        let report = store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Audit,
                "owner",
                "retain audit",
                "2",
                &[],
            )
            .expect("mode source committed");
        assert_eq!(report["direct_policy"]["published"], false);
        assert!(report["direct_policy"]["rule"].as_str().is_some());
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_some() {
            assert_eq!(report["direct_policy"]["rule"], "door-rubric-unavailable");
        }
        assert_eq!(
            store.modes().expect("durable ledger")["loop_settings"][0]["mode"],
            "audit"
        );
    }

    /// ´test:unit:request-retirement-read-retains-probed-custody´
    #[test]
    fn request_retirement_read_retains_probed_custody() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(fixture_request("R", "1a", 3000, Mode::Audit, "allow"))
            .expect("request");
        let custody = store.custody("R").expect("probed custody");
        let collection = store.channel_read().expect("channel");
        let before = store
            .read_run_from_custody("R", &custody, collection.as_ref())
            .expect("initial");
        fs::rename(
            fixture.runs.join(".launch-R"),
            fixture.runs.join(".retained-R"),
        )
        .expect("replace name");
        fs::create_dir(fixture.runs.join(".launch-R")).expect("replacement");
        fs::set_permissions(
            fixture.runs.join(".launch-R"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private replacement");
        let after = store
            .read_run_from_custody("R", &custody, collection.as_ref())
            .expect("held custody");
        assert_eq!(before.0, after.0);
        assert_eq!(after.2[0].id(), "R:1a");
        assert!(
            store
                .read_run("R")
                .expect("new custody is empty")
                .2
                .is_empty()
        );
    }

    /// ´test:unit:request-loop-cap-is-freed-by-production-retirement´
    #[test]
    fn request_loop_cap_is_freed_by_production_retirement() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(fixture_request("R", "1a", 3000, Mode::Audit, "allow"))
            .expect("first run request");
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"owner answer"})],
                "owner",
                "2",
            )
            .expect("adjudicated custody");
        let original = fs::read(fixture.run_file("R")).expect("original custody");
        LOOP_CAP.with(|cap| cap.set(Some(1)));
        let error = store
            .file(fixture_request("S", "2b", 3000, Mode::Audit, "allow"))
            .expect_err("loop-wide cap");
        assert_eq!(error.kind, "requests-store-full");
        assert!(error.detail.contains(LOOP_CAP_REMEDY));

        let driver = fixture.runs.join("R");
        fs::create_dir(&driver).expect("driver directory");
        let identity = crate::plan::protected_identity_dir(&driver).expect("identity path");
        assert_eq!(identity, fixture.runs.join(".launch-R"));
        let home = fixture.home.join("home-R");
        fs::create_dir(&home).expect("worker home");
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":home,"driver_dir":driver,"runtime_argv":["/usr/bin/podman"]},"launcher_pid":321,"launcher_start":88,"helper_pid":322,"helper_start":89,"helper_parent_pid":325,"helper_parent_start":92,"driver_entry_pid":323,"driver_entry_start":90,"observer_pid":324,"observer_start":91,"observer_state":"ended"});
        crate::launch::publish_reservation(
            &crate::launch::reservation_path(&fixture.runs, "R"),
            &record,
        )
        .expect("reservation");
        let retired = crate::launch::retire::retire_record_with(
            &fixture.runs,
            "R",
            &home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("production retirement");
        let custody = retired["journal"]["planned_paths"]
            .as_array()
            .expect("planned paths")
            .iter()
            .find(|path| path["source"] == fixture.runs.join(".launch-R").display().to_string())
            .expect("request custody move");
        let target = custody["target"].as_str().expect("retired target");
        assert!(target.contains(".retired-R-2-"));
        assert_eq!(
            fs::read(Path::new(target).join(RUN_FILE)).expect("retired custody"),
            original
        );
        assert!(!fixture.runs.join(".launch-R").exists());
        store
            .file(fixture_request("S", "2b", 3000, Mode::Audit, "allow"))
            .expect("filing after retirement");
        LOOP_CAP.with(|cap| cap.set(None));
    }

    /// ´test:unit:request-list-run-reads-empty-store-before-lock-creation´
    #[test]
    fn request_list_run_reads_empty_store_before_lock_creation() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let lock = fixture.home.join(".config/loops/alpha/door-requests.lock");
        assert!(!lock.exists());
        assert!(store.list_run("R").expect("empty read").is_empty());
        assert!(!lock.exists());
    }

    /// ´test:unit:request-readers-survive-first-request-between-record-and-lock-reads´
    #[test]
    fn request_readers_survive_first_request_between_record_and_lock_reads() {
        for reader in ["modes", "list_run", "request", "list_with_status"] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let home = fixture.home.clone();
            AFTER_READER_RECORDS.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let writer = Store::open(&home, "alpha", true).expect("writer store");
                    if reader == "modes" {
                        writer
                            .ensure_first_mode("fixture")
                            .expect("first mode setting");
                    } else {
                        writer
                            .file(fixture_request("R", "1a", 3000, Mode::Audit, "undecided"))
                            .expect("first request");
                    }
                }));
            });
            match reader {
                "modes" => {
                    assert_eq!(
                        store.modes().expect("first mode reader")["classes"][0]["class"],
                        "fixture"
                    );
                }
                "list_run" => {
                    assert_eq!(store.list_run("R").expect("run reader").len(), 1);
                }
                "request" => {
                    assert_eq!(store.request("R:1a").expect("request reader").id(), "R:1a");
                }
                _ => {
                    assert_eq!(store.list_with_status().expect("list reader").0.len(), 1);
                }
            }
            assert!(
                fixture
                    .home
                    .join(".config/loops/alpha/door-requests.lock")
                    .exists()
            );
            AFTER_READER_RECORDS.with(|hook| assert!(hook.borrow().is_none()));
        }
    }

    /// ´test:unit:request-first-writers-reopen-the-created-lock´
    #[test]
    fn request_first_writers_reopen_the_created_lock() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let home = fixture.home;
        AFTER_FIRST_LOCK_MISS.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let writer = Store::open(&home, "alpha", true).expect("competing writer");
                let lock = super::open_child(
                    writer.state_dir(),
                    LOCK_FILE,
                    nix::fcntl::OFlag::O_RDWR
                        | nix::fcntl::OFlag::O_CREAT
                        | nix::fcntl::OFlag::O_EXCL,
                    0o600,
                )
                .expect("competing lock creation");
                nix::sys::stat::fchmod(&lock, nix::sys::stat::Mode::from_bits_truncate(0o600))
                    .expect("lock mode");
            }));
        });
        let _lock = store
            .fixture_exclusive_lock()
            .expect("losing writer reopens lock");
        AFTER_FIRST_LOCK_MISS.with(|hook| assert!(hook.borrow().is_none()));
    }

    fn fixture_request_with_mode(
        store: &Store,
        run: &str,
        nonce: &str,
        worker: u32,
        floor: Mode,
        decision: &str,
    ) -> RequestRecord {
        let mut value = fixture_request(run, nonce, worker, floor, decision).into_value();
        let setting = store.effective_mode("fixture").expect("mode snapshot");
        value["class_setting"] = setting["class"].clone();
        value["loop_setting"] = setting["loop"].clone();
        value["mode"] = setting["mode"].clone();
        RequestRecord::decode(value).expect("mode-bound request")
    }

    /// ´test:unit:mode-setting-cites-labels-and-correction-returns-to-audit´
    #[test]
    fn mode_setting_cites_labels_and_correction_returns_to_audit() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        store
            .file(fixture_request("R", "1a", 3000, Mode::Allow, "allow"))
            .expect("agreeing request");
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"agrees"})],
                "owner",
                "2",
            )
            .expect("agreeing label");
        let loop_first = store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "owner",
                "row floor admits fixture",
                "1",
                &[],
            )
            .expect("loop first");
        assert_eq!(loop_first["direction"], "first");
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(
                &class,
                Mode::Audit,
                "owner",
                "first fixture audit",
                "2",
                &[],
            )
            .expect("class first");
        assert_eq!(
            store.effective_mode("fixture").expect("effective")["mode"],
            "audit"
        );
        let move_report = store
            .set_mode(
                &class,
                Mode::Enforce,
                "owner",
                "cited agreement",
                "3",
                &["R:1a".to_owned()],
            )
            .expect("cited fixture move");
        assert_eq!(move_report["direction"], "relaxed");
        assert_eq!(
            store.effective_mode("fixture").expect("effective")["mode"],
            "enforce"
        );
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "2b",
                3001,
                Mode::Allow,
                "refuse",
            ))
            .expect("correction request");
        let (_, reports) = store.triage_with_reports("R", &[json!({"id":"R:2b","action":"adjudicate","treatment":"allow","reason":"rubric wrong"})], "owner", "4").expect("correction label");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["mode"], "audit");
        assert_eq!(
            store.effective_mode("fixture").expect("immediate audit")["mode"],
            "audit"
        );
        let report = store
            .correct_mode("fixture", "R:2b", "owner", "5")
            .expect("return to audit");
        assert_eq!(report["mode"], "audit");
        assert_eq!(report["correction_request"], "R:2b");
        assert_eq!(report["reason"], "rubric wrong");
        assert_eq!(
            store.effective_mode("fixture").expect("effective")["mode"],
            "audit"
        );
        let history = store.modes().expect("history");
        assert_eq!(
            history["classes"][0]["settings"]
                .as_array()
                .expect("settings")
                .len(),
            3
        );
        let (_, shapes) = store.list().expect("shape counts");
        assert_eq!(shapes["groups"][0]["requests"], 2);
        assert_eq!(shapes["groups"][0]["agreements"], 1);
        assert_eq!(shapes["groups"][0]["corrections"], 1);
        assert_eq!(shapes["groups"][0]["request_ids"], json!(["R:1a", "R:2b"]));
    }

    /// ´test:unit:mode-refusals-leave-protected-history-unchanged´
    #[test]
    fn mode_refusals_leave_protected_history_unchanged() {
        let fixture = Fixture::new();
        let store = fixture.store();
        assert_eq!(
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Enforce,
                    "owner",
                    "below floor",
                    "1",
                    &[]
                )
                .expect_err("floor")
                .kind,
            "door-mode-floor-refusal"
        );
        assert!(
            !fixture
                .home
                .join(".config/loops/alpha/door-modes.json")
                .exists()
        );
        fixture.set_floor("allow");
        let store = fixture.store();
        store
            .set_mode(&ModeTarget::Loop, Mode::Audit, "owner", "first", "1", &[])
            .expect("first");
        let before =
            fs::read(fixture.home.join(".config/loops/alpha/door-modes.json")).expect("history");
        assert_eq!(
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Enforce,
                    "owner",
                    "uncited",
                    "2",
                    &[]
                )
                .expect_err("uncited")
                .kind,
            "door-mode-evidence-refusal"
        );
        assert_eq!(
            store
                .set_mode(
                    &ModeTarget::Loop,
                    Mode::Enforce,
                    "owner",
                    "missing",
                    "2",
                    &["R:ff".to_owned()]
                )
                .expect_err("missing citation")
                .kind,
            "door-mode-evidence-refusal"
        );
        assert_eq!(
            store
                .correct_mode("fixture", "R:ff", "owner", "2")
                .expect_err("missing correction")
                .kind,
            "door-mode-evidence-refusal"
        );
        assert_eq!(
            fs::read(fixture.home.join(".config/loops/alpha/door-modes.json"))
                .expect("same history"),
            before
        );
        fixture.set_floor("audit");
        assert_eq!(
            fixture.store().modes().expect("historical floor readable")["revision"],
            1
        );
    }

    /// ´test:unit:mode-commands-and-linked-history-refuse-by-name´
    #[test]
    fn mode_commands_and_linked_history_refuse_by_name() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        for args in [
            vec!["set-mode", "alpha", "class", "fixture"],
            vec!["set-mode", "alpha", "loop", "audit", "owner"],
            vec!["correct-mode", "alpha", "fixture", "R:1a"],
        ] {
            assert_eq!(
                fixture
                    .command(&args, b"")
                    .expect_err("malformed mode usage")
                    .kind,
                "requests-usage"
            );
        }
        assert_eq!(
            fixture
                .command(&["modes", "alpha"], b"")
                .expect("empty history")["revision"],
            0
        );
        assert_eq!(
            fixture
                .command(
                    &["set-mode", "alpha", "loop", "allow", "owner", "row floor"],
                    b""
                )
                .expect("loop command")["mode"],
            "allow"
        );
        assert_eq!(
            fixture
                .command(
                    &[
                        "set-mode", "alpha", "class", "fixture", "audit", "owner", "first"
                    ],
                    b""
                )
                .expect("class command")["mode"],
            "audit"
        );
        assert_eq!(
            fixture.command(&["modes", "alpha"], b"").expect("history")["classes"][0]["class"],
            "fixture"
        );
        assert_eq!(
            fixture
                .command(
                    &[
                        "set-mode", "alpha", "class", "../other", "audit", "owner", "bad"
                    ],
                    b""
                )
                .expect_err("bad class")
                .kind,
            "door-mode-setting-refusal"
        );
        assert_eq!(
            fixture
                .command(
                    &["set-mode", "alpha", "loop", "unknown", "owner", "bad"],
                    b""
                )
                .expect_err("bad mode")
                .kind,
            "door-mode-setting-refusal"
        );
        assert_eq!(
            fixture
                .command(&["correct-mode", "alpha", "fixture", "R:ff", "owner"], b"")
                .expect_err("missing correction")
                .kind,
            "door-mode-evidence-refusal"
        );
        let path = fixture.home.join(".config/loops/alpha/door-modes.json");
        fs::remove_file(&path).expect("remove mode history");
        std::os::unix::fs::symlink("door-shapes.json", &path).expect("linked mode history");
        assert_eq!(
            fixture
                .command(&["modes", "alpha"], b"")
                .expect_err("linked history")
                .kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:shape-record-counts-undecided-labels-and-actual-effects´
    #[test]
    fn shape_record_counts_undecided_labels_and_actual_effects() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut completed = fixture_request("R", "1a", 3000, Mode::Audit, "undecided").into_value();
        completed["effect"]["state"] = json!("completed");
        completed["effect"]["ref_check"] = json!("not-applicable");
        completed["effect"]["exit_status"] = json!(0);
        store
            .file(RequestRecord::decode(completed).expect("completed request"))
            .expect("file completed");
        let mut refused = fixture_request("R", "2b", 3001, Mode::Audit, "refuse").into_value();
        refused["effect"]["state"] = json!("refused");
        refused["effect"]["ref_check"] = json!("not-applicable");
        refused["effect"]["exit_status"] = json!(125);
        store
            .file(RequestRecord::decode(refused).expect("refused request"))
            .expect("file refused");
        store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"owner answer"})], "owner", "2").expect("undecided label");
        let (_, shapes) = store.list().expect("shapes");
        let group = &shapes["groups"][0];
        assert_eq!(group["requests"], 2);
        assert_eq!(group["would_undecided"], 1);
        assert_eq!(group["would_refuse"], 1);
        assert_eq!(group["labels_after_undecided"], 1);
        assert_eq!(group["corrections"], 0);
        assert_eq!(group["effect_completed"], 1);
        assert_eq!(group["effect_refused"], 1);
    }

    fn assert_published_correction(store: &Store, pending: bool) {
        if std::env::var_os("SUPERLOOP_TEST_POLICY_DRIFT").is_some() {
            assert!(!store.loop_root.join("policy/snapshot.json").exists());
            return;
        }
        if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_some() {
            let snapshot: serde_json::Value = serde_json::from_slice(
                &fs::read(store.loop_root.join("policy/snapshot.json"))
                    .expect("correction snapshot"),
            )
            .expect("snapshot shape");
            let effective = &snapshot["modes"]["value"]["effective"]["fixture"];
            assert_eq!(effective["mode"], "audit");
            assert_eq!(effective["correction_pending"] == true, pending);
        }
    }

    /// ´test:unit:failed-mode-publication-keeps-corrected-class-in-audit´
    #[test]
    fn failed_mode_publication_keeps_corrected_class_in_audit() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = if std::env::var_os("SUPERLOOP_TEST_DIRECT_HOME").is_some() {
            fixture.snapshot_store()
        } else {
            fixture.store()
        };
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "owner",
                "fixture floor",
                "1",
                &[],
            )
            .expect("loop first");
        store
            .set_mode(&class, Mode::Enforce, "owner", "fixture only", "2", &[])
            .expect("class first");
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "1a",
                3000,
                Mode::Allow,
                "refuse",
            ))
            .expect("request");
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "2b",
                3001,
                Mode::Allow,
                "allow",
            ))
            .expect("second worker");
        FAIL_MODE_WRITE.with(|fail| fail.set(true));
        let (_, reports) = store.triage_with_reports("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"rubric wrong"})], "owner", "3").expect("label saved");
        assert_eq!(reports[0]["record"], "pending");
        let effective = store.effective_mode("fixture").expect("conservative mode");
        assert_eq!(effective["mode"], "audit");
        assert_eq!(effective["correction_pending"], true);
        assert_published_correction(&store, true);
        let held = File::open(&fixture.runs).expect("held runs");
        let retirement = store
            .retirement_guard("R", &held, true)
            .expect_err("pending correction blocks retirement");
        assert_eq!(retirement.kind, "retire-requests-pending");
        assert!(retirement.detail.contains("pending correction ids: R:1a"));
        assert!(retirement.detail.contains("requests correct-mode"));
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "3c",
                3001,
                Mode::Allow,
                "allow",
            ))
            .expect("pending correction snapshot files at audit");
        assert_eq!(
            store.modes().expect("unchanged mode history")["classes"][0]["settings"][0]["mode"],
            "enforce"
        );
        let report = store
            .correct_mode("fixture", "R:1a", "owner", "4")
            .expect("reconcile correction");
        assert_eq!(report["changed"], true);
        if std::env::var_os("SUPERLOOP_TEST_POLICY_DRIFT").is_some() {
            assert_eq!(
                report["direct_policy"]["rule"],
                "execute-command-snapshot-custody"
            );
        }
        assert_published_correction(&store, false);
        assert_eq!(
            store.effective_mode("fixture").expect("recorded audit")["mode"],
            "audit"
        );
        store.triage("R", &[
            json!({"id":"R:2b","action":"adjudicate","treatment":"allow","reason":"answer"}),
            json!({"id":"R:3c","action":"adjudicate","treatment":"allow","reason":"answer"}),
        ], "owner", "5").expect("resolve remaining requests");
        let held = File::open(&fixture.runs).expect("held runs");
        store
            .retirement_guard("R", &held, true)
            .expect("reconciled correction admits retirement");
    }

    /// ´test:unit:marked-adjudication-corrects-fixture-class-before-answer´
    #[test]
    fn marked_adjudication_corrects_fixture_class_before_answer() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "owner",
                "fixture floor",
                "1",
                &[],
            )
            .expect("loop first");
        store
            .set_mode(&class, Mode::Enforce, "owner", "fixture only", "2", &[])
            .expect("class first");
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "1a",
                3000,
                Mode::Allow,
                "refuse",
            ))
            .expect("first worker");
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "2b",
                3001,
                Mode::Allow,
                "allow",
            ))
            .expect("second worker");
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"mark","reason":"owner review"})],
                "owner",
                "3",
            )
            .expect("mark");
        let held = File::open(&fixture.runs).expect("held runs");
        let retirement = store
            .retirement_guard("R", &held, true)
            .expect_err("marked request still awaits adjudication");
        assert_eq!(retirement.kind, "retire-requests-pending");
        assert!(retirement.detail.contains("R:1a"));
        let review = store.review("R:1a", "4").expect("review");
        let review_id = review.value()["review"]["id"].as_str().expect("review id");
        let (answer, reports) = store
            .adjudicate_with_reports("R:1a", review_id, "allow", "rubric wrong", "owner", "5")
            .expect("adjudicate");
        assert_eq!(answer.value()["state"], "adjudicated");
        assert_eq!(reports[0]["mode"], "audit");
        assert_eq!(reports[0]["correction_request"], "R:1a");
        assert_eq!(
            store.effective_mode("fixture").expect("immediate audit")["mode"],
            "audit"
        );
    }

    /// ´test:unit:request-filing-refuses-a-different-mode-snapshot´
    #[test]
    fn request_filing_refuses_a_different_mode_snapshot() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "owner",
                "fixture floor",
                "1",
                &[],
            )
            .expect("loop first");
        store
            .set_mode(&class, Mode::Enforce, "owner", "fixture only", "2", &[])
            .expect("class first");
        for (nonce, worker) in [("1a", 3000), ("2b", 3001)] {
            assert_eq!(
                store
                    .file(fixture_request("R", nonce, worker, Mode::Allow, "allow"))
                    .expect_err("stale snapshot")
                    .kind,
                "requests-record-refusal"
            );
        }
        assert!(!fixture.run_file("R").exists());
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "1a",
                3000,
                Mode::Allow,
                "allow",
            ))
            .expect("current snapshot");
    }

    /// ´test:unit:whole-batch-refusal-writes-nothing´
    #[test]
    fn whole_batch_refusal_writes_nothing() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("file first");
        store
            .file(waiting("R", "2b", 3001, Mode::Audit))
            .expect("file second");
        let before_run = fs::read(fixture.run_file("R")).expect("run bytes");
        let before_shapes = fs::read(fixture.shape_file()).expect("shape bytes");
        let failure = store.triage("R", &[
            json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"evidence"}),
            json!({"id":"R:missing","action":"mark","reason":"review"}),
        ], "owner", "2").expect_err("whole batch");
        assert_eq!(failure.kind, "requests-batch-refusal");
        assert_eq!(
            fs::read(fixture.run_file("R")).expect("run after"),
            before_run
        );
        assert_eq!(
            fs::read(fixture.shape_file()).expect("shapes after"),
            before_shapes
        );
        assert_eq!(
            store.request("R:1a").expect("first").value()["state"],
            "waiting"
        );
    }

    /// ´test:unit:second-review-invalidates-old-id-and-one-request-adjudicates´
    #[test]
    fn second_review_invalidates_old_id_and_one_request_adjudicates() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("file first");
        store
            .file(waiting("S", "2b", 3001, Mode::Audit))
            .expect("file second");
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"mark","reason":"owner review"})],
                "owner",
                "2",
            )
            .expect("mark");
        let first = store.review("R:1a", "3").expect("first review");
        let old = first.value()["review"]["id"]
            .as_str()
            .expect("old id")
            .to_owned();
        let second = store.review("R:1a", "4").expect("second review");
        let current = second.value()["review"]["id"].as_str().expect("current id");
        assert_ne!(old, current);
        assert_eq!(
            store
                .adjudicate("R:1a", &old, "allow", "evidence", "owner", "5")
                .expect_err("stale review")
                .kind,
            "requests-review-id-refusal"
        );
        let done = store
            .adjudicate("R:1a", current, "allow", "evidence", "owner", "5")
            .expect("adjudicate one");
        assert_eq!(done.value()["state"], "adjudicated");
        assert_eq!(
            store.request("S:2b").expect("other request").value()["state"],
            "waiting"
        );
        let (_, shapes) = store.list().expect("shape reader");
        assert_eq!(shapes["groups"][0]["labels_allow"], 1);
        assert_eq!(
            shapes["groups"][0]["settings"][0]["class"]["evidence"],
            "first setting from row"
        );
    }

    /// ´test:unit:stale-shape-read-is-pure-and-changing-command-repairs´
    #[test]
    fn stale_shape_read_is_pure_and_changing_command_repairs() {
        let fixture = Fixture::new();
        let store = fixture.store();
        assert_eq!(
            store.request("bad").expect_err("bad id").kind,
            "requests-request-refusal"
        );
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("file");
        assert_eq!(
            store.request("R:ff").expect_err("missing").kind,
            "requests-request-refusal"
        );
        fs::write(fixture.shape_file(), b"{}").expect("change shape");
        let failed = json!({"phase":"withdrawal-failed","run":"S","reason":"fixture","rollback":"failed","at_unix_ns":1});
        let journal = json!({"schema":2,"latest":{"withdrawal-failed":failed}});
        let attempt_path = fixture
            .home
            .join(".config/loops/alpha/door-requests-attempt.json");
        fs::write(
            &attempt_path,
            serde_json::to_vec(&journal).expect("journal"),
        )
        .expect("old attempt");
        fs::set_permissions(&attempt_path, fs::Permissions::from_mode(0o600))
            .expect("attempt mode");
        let (_, shapes, stale) = store.list_with_status().expect("derived shape in memory");
        assert!(stale);
        assert_eq!(shapes["groups"][0]["requests"], 1);
        assert_eq!(
            fixture.command(&["status", "alpha"], b"").expect("status")["shape_record"],
            "stale"
        );
        assert_eq!(
            fixture.command(&["list", "alpha"], b"").expect("list")["shape_record"],
            "stale"
        );
        assert_eq!(fs::read(fixture.shape_file()).expect("stale bytes"), b"{}");
        assert_eq!(store.request("R:1a").expect("read request").id(), "R:1a");
        assert_eq!(fs::read(fixture.shape_file()).expect("still stale"), b"{}");
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"mark","reason":"review"})],
                "owner",
                "2",
            )
            .expect("changing repair");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.shape_file()).expect("repaired bytes"))
                .expect("shape JSON");
        assert_eq!(saved["groups"][0]["requests"], 1);
        let attempt: serde_json::Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .home
                    .join(".config/loops/alpha/door-requests-attempt.json"),
            )
            .expect("repair attempt"),
        )
        .expect("attempt JSON");
        assert_eq!(attempt["latest"]["repaired"]["phase"], "repaired");
        assert_eq!(attempt["latest"]["withdrawal-failed"], failed);
    }

    /// ´test:unit:commands-cover-forms-batches-and-state-filter´
    #[test]
    fn commands_cover_forms_batches_and_state_filter() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("first");
        store
            .file(waiting("R", "2b", 3001, Mode::Audit))
            .expect("second");
        assert_eq!(
            fixture.command(&["status", "alpha"], b"").expect("status")["shapes"]["groups"][0]["requests"],
            2
        );
        assert_eq!(
            fixture
                .command(&["list", "alpha", "--state", "waiting"], b"")
                .expect("filtered list")["requests"]
                .as_array()
                .expect("rows")
                .len(),
            2
        );
        assert_eq!(
            fixture
                .command(&["list", "alpha", "--state", "marked"], b"")
                .expect("empty filter")["requests"]
                .as_array()
                .expect("rows")
                .len(),
            0
        );
        assert_eq!(
            fixture.command(&["list", "alpha"], b"").expect("list")["requests"]
                .as_array()
                .expect("rows")
                .len(),
            2
        );
        let marked = json!([{"id":"R:1a","action":"mark","reason":"review"}]);
        assert_eq!(
            fixture
                .command(
                    &["triage", "alpha", "R"],
                    &serde_json::to_vec(&marked).expect("batch")
                )
                .expect("triage")["changed"],
            1
        );
        assert_eq!(
            fixture
                .command(&["list", "alpha", "--state", "marked"], b"")
                .expect("marked list")["requests"]
                .as_array()
                .expect("rows")
                .len(),
            1
        );
        let reviewed = fixture
            .command(&["review", "alpha", "R:1a"], b"")
            .expect("review");
        let review_id = reviewed["review"]["id"].as_str().expect("review id");
        assert_eq!(
            fixture
                .command(
                    &[
                        "adjudicate",
                        "alpha",
                        "R:1a",
                        review_id,
                        "allow",
                        "evidence"
                    ],
                    b""
                )
                .expect("adjudicate")["state"],
            "adjudicated"
        );
        assert_eq!(
            fixture
                .command(&["list", "alpha", "--state", "adjudicated"], b"")
                .expect("adjudicated list")["requests"]
                .as_array()
                .expect("rows")
                .len(),
            1
        );
    }

    /// ´test:unit:requests-wait-immediate-run-and-usage´
    #[test]
    fn requests_wait_immediate_run_and_usage() {
        use std::io::Write as _;
        use std::time::{Duration, Instant};

        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("waiting request");
        store
            .file(waiting("S", "2b", 3001, Mode::Audit))
            .expect("other run");

        let read_started = Instant::now();
        let rows = store.list_run("R").expect("one read iteration");
        let read_wall = read_started.elapsed();
        writeln!(
            std::io::stderr(),
            "requests_wait_read_iteration_seconds={:.6}",
            read_wall.as_secs_f64()
        )
        .expect("read wall report");
        assert_eq!(rows.len(), 1);

        let started = Instant::now();
        let waited = fixture
            .command(&["wait", "alpha", "--run", "R"], b"")
            .expect("immediate wait");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(waited["requests"].as_array().expect("rows").len(), 1);
        assert_eq!(waited["requests"][0]["run"], "R");
        assert_eq!(waited["shape_record"], "current");
        assert_eq!(
            fixture.command(&["wait", "alpha"], b"").expect("all runs"),
            fixture
                .command(&["list", "alpha", "--state", "waiting"], b"")
                .expect("matching list")
        );
        for args in [
            vec!["wait", "alpha", "--state", "unknown"],
            vec!["wait", "alpha", "--timeout", "601"],
            vec!["wait", "alpha", "--timeout", "-1"],
            vec!["wait", "alpha", "--run", "bad/name"],
            vec!["wait", "alpha", "--state", "waiting", "--state", "waiting"],
        ] {
            assert_eq!(
                fixture.command(&args, b"").expect_err("usage").kind,
                "requests-usage"
            );
        }
    }

    /// ´test:unit:requests-wait-timeout-has-no-rows-and-a-refusal´
    #[test]
    fn requests_wait_timeout_has_no_rows_and_a_refusal() {
        use std::io::Write as _;
        use std::time::{Duration, Instant};

        let fixture = Fixture::new();
        let args = ["wait", "alpha", "--run", "R", "--timeout", "1"].map(str::to_owned);
        let mut input = &b""[..];
        let mut output = Vec::new();
        let started = Instant::now();
        let error = crate::requests::commands::run(&fixture.home, &args, &mut input, &mut output)
            .expect_err("timeout refusal");
        let wall = started.elapsed();
        writeln!(
            std::io::stderr(),
            "requests_wait_timeout_seconds={:.6}",
            wall.as_secs_f64()
        )
        .expect("timeout wall report");
        assert_eq!(error.kind, "requests-wait-timeout");
        assert_eq!(error.status, 1);
        assert_eq!(error.detail, "no waiting requests before timeout");
        assert_eq!(output, Vec::<u8>::new());
        assert!(wall >= Duration::from_secs(1));
        assert!(wall < Duration::from_secs(3));
    }

    /// # Panics
    /// Panics only if fixture setup or synchronized writer/reader assertions fail.
    /// ´test:unit:request-reader-outlasts-slow-writer-sync´
    #[test]
    fn request_reader_outlasts_slow_writer_sync() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let writer = fixture.store();
        writer
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("initial request");
        let reader = fixture.store();
        let snapshot = crate::home::snapshot_private_home().expect("fixture anchors");
        let (sync_tx, sync_rx) = std::sync::mpsc::channel();
        let (read_tx, read_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || {
                let _guard =
                    crate::home::activate_private_snapshot(snapshot).expect("writer anchors");
                super::BEFORE_LEAF_SYNC.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        sync_tx.send(()).expect("sync reached under exclusive lock");
                        read_rx
                            .recv_timeout(Duration::from_secs(30))
                            .expect("reader contended");
                        std::thread::sleep(Duration::from_millis(2300));
                    }));
                });
                writer
                    .file(waiting("R", "2b", 3000, Mode::Audit))
                    .expect("writer committed");
            });
            sync_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("writer reached sync");
            AFTER_READER_LOCK_CONTENTION.with(|hook| {
                *hook.borrow_mut() =
                    Some(Box::new(move || read_tx.send(()).expect("reader signal")));
            });
            let started = Instant::now();
            let rows = reader
                .list_run("R")
                .expect("reader waits through slow sync");
            assert!(started.elapsed() >= Duration::from_millis(2300));
            assert_eq!(rows.len(), 2);
            writer.join().expect("writer joined");
        });
    }

    /// # Panics
    /// Panics only if fixture setup or the bounded contention assertions fail.
    /// ´test:unit:request-reader-refuses-after-lock-bound´
    #[test]
    fn request_reader_refuses_after_lock_bound() {
        use std::time::{Duration, Instant};
        assert_eq!(super::READER_LOCK_WAIT, Duration::from_secs(15));
        let reader_bound = Duration::from_millis(300);
        super::READER_LOCK_WAIT_OVERRIDE.set(Some(reader_bound));
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("request");
        let _lock = store.fixture_exclusive_lock().expect("writer lock");
        let started = Instant::now();
        let error = store.list_run("R").expect_err("reader bound");
        assert!(super::is_lock_contention(&error), "{}", error.line());
        assert!(started.elapsed() >= reader_bound);
        assert!(started.elapsed() < reader_bound + Duration::from_secs(5));
        let started = Instant::now();
        let error = store
            .list_run_until("R", started + Duration::from_millis(100))
            .expect_err("caller bound");
        assert!(super::is_lock_contention(&error));
        assert!(started.elapsed() < Duration::from_secs(2));
        super::READER_LOCK_WAIT_OVERRIDE.set(None);
    }

    /// # Panics
    /// Panics only if fixture setup or the renewed-budget read fails.
    /// ´test:unit:request-reader-renews-budget-per-read´
    #[test]
    fn request_reader_renews_budget_per_read() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let store = fixture.store().with_reader_budget(Duration::from_secs(1));
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("request");
        std::thread::sleep(Duration::from_millis(1200));
        let lock = store.fixture_exclusive_lock().expect("writer lock");
        let started = Instant::now();
        let error = store
            .list_run_until("R", started)
            .expect_err("expired explicit deadline");
        assert!(super::is_lock_contention(&error));
        assert!(started.elapsed() < Duration::from_millis(500));
        let (contended_tx, contended_rx) = std::sync::mpsc::channel();
        AFTER_READER_LOCK_CONTENTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                contended_tx.send(()).expect("reader contention");
            }));
        });
        std::thread::scope(|scope| {
            let holder = scope.spawn(move || {
                contended_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("reader started");
                std::thread::sleep(Duration::from_millis(300));
                drop(lock);
            });
            let started = Instant::now();
            assert_eq!(
                store.list_run("R").expect("read with renewed budget").len(),
                1
            );
            assert!(started.elapsed() >= Duration::from_millis(300));
            holder.join().expect("writer released");
        });
    }

    /// ´test:unit:requests-wait-retries-reader-lock-contention´
    #[test]
    fn requests_wait_retries_reader_lock_contention() {
        use std::sync::mpsc;
        use std::time::Duration;

        let fixture = Fixture::new();
        fixture
            .store()
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("waiting request");
        let lock = fixture
            .store()
            .fixture_exclusive_lock()
            .expect("exclusive request lock");
        let (missed_tx, missed_rx) = mpsc::channel();
        let (timed_out_tx, timed_out_rx) = mpsc::channel();
        let snapshot = crate::home::snapshot_private_home().expect("private fixture anchors");
        std::thread::scope(|scope| {
            let home = &fixture.home;
            let waiter = scope.spawn(move || {
                super::READER_LOCK_WAIT_OVERRIDE.set(Some(Duration::from_millis(300)));
                let _guard = crate::home::activate_private_snapshot(snapshot)
                    .expect("activate fixture anchors on waiter");
                AFTER_READER_LOCK_CONTENTION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        missed_tx.send(()).expect("first contention signal");
                    }));
                });
                AFTER_READER_LOCK_TIMEOUT.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        timed_out_tx.send(()).expect("reader timeout signal");
                    }));
                });
                let args = ["wait", "alpha", "--run", "R", "--timeout", "6"].map(str::to_owned);
                let mut input = &b""[..];
                let mut output = Vec::new();
                crate::requests::commands::run(home, &args, &mut input, &mut output)
                    .expect("wait succeeds after lock release");
                serde_json::from_slice::<serde_json::Value>(&output).expect("wait JSON")
            });
            missed_rx.recv().expect("waiter met exclusive lock");
            timed_out_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("contended reader refusal occurred");
            drop(lock);
            let result = waiter.join().expect("waiter joined");
            assert_eq!(result["requests"].as_array().expect("rows").len(), 1);
            assert_eq!(result["requests"][0]["run"], "R");
        });
    }

    /// ´test:unit:requests-wait-unread-timeout-names-lock-contention´
    #[test]
    fn requests_wait_unread_timeout_names_lock_contention() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let fixture = Fixture::new();
        fixture
            .store()
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("waiting request");
        let lock = fixture
            .store()
            .fixture_exclusive_lock()
            .expect("exclusive request lock");
        let (missed_tx, missed_rx) = mpsc::channel();
        let snapshot = crate::home::snapshot_private_home().expect("private fixture anchors");
        std::thread::scope(|scope| {
            let home = &fixture.home;
            let waiter = scope.spawn(move || {
                let _guard = crate::home::activate_private_snapshot(snapshot)
                    .expect("activate fixture anchors on waiter");
                AFTER_READER_LOCK_CONTENTION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        missed_tx.send(()).expect("contention signal");
                    }));
                });
                let args = ["wait", "alpha", "--run", "R", "--timeout", "1"].map(str::to_owned);
                let mut input = &b""[..];
                let mut output = Vec::new();
                let started = Instant::now();
                let error = crate::requests::commands::run(home, &args, &mut input, &mut output)
                    .expect_err("unread timeout");
                (error, output, started.elapsed())
            });
            missed_rx.recv().expect("waiter met exclusive lock");
            let (error, output, wall) = waiter.join().expect("waiter joined");
            assert_eq!(error.kind, "requests-wait-timeout");
            assert_eq!(error.status, 1);
            assert!(
                error
                    .detail
                    .starts_with("no read completed before timeout: request lock:")
            );
            assert_eq!(output, Vec::<u8>::new());
            assert!(wall <= Duration::from_secs(1 + 2 + 1));
            drop(lock);
        });
    }

    /// ´test:unit:requests-wait-keeps-non-contention-record-refusal´
    #[test]
    fn requests_wait_keeps_non_contention_record_refusal() {
        let fixture = Fixture::new();
        fixture
            .store()
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("waiting request");
        fs::set_permissions(
            fixture.home.join(".config/loops/alpha/door-requests.lock"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("corrupt lock mode");
        let args = ["wait", "alpha", "--run", "R", "--timeout", "1"].map(str::to_owned);
        let mut input = &b""[..];
        let mut output = Vec::new();
        let error = crate::requests::commands::run(&fixture.home, &args, &mut input, &mut output)
            .expect_err("record refusal");
        assert_eq!(error.kind, "requests-record-refusal");
        assert_eq!(error.status, 2);
        assert!(
            error
                .detail
                .contains("door-requests.lock owner, mode or size differs")
        );
        assert_eq!(output, Vec::<u8>::new());
    }

    fn dense_wait_fixture() -> (Fixture, usize, usize) {
        use super::MAX_RUN_BYTES;

        let fixture = Fixture::new();
        fixture
            .store()
            .file(waiting("R", "1", 3000, Mode::Audit))
            .expect("create request lock");
        let store = fixture.store();
        let padding = "x".repeat(1000);
        let mut total_requests = 0;
        let mut total_bytes = 0;
        for index in 0..64 {
            let run = match index {
                0 => "R".to_owned(),
                1 => "S".to_owned(),
                _ => format!("N{index:02}"),
            };
            if index > 1 {
                let path = fixture.runs.join(format!(".launch-{run}"));
                fs::create_dir(&path).expect("run custody");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("run custody mode");
            }
            let count = if index == 0 { 2048 } else { 227 };
            total_requests += count;
            let requests = (0..count)
                .map(|row| {
                    let mut value =
                        waiting(&run, &format!("{:x}", row + 1), 3000, Mode::Audit).into_value();
                    value["would_do"]["reason"] = json!(padding);
                    value["class_setting"]["evidence"] = json!(padding);
                    value["loop_setting"]["evidence"] = json!(padding);
                    value
                })
                .collect::<Vec<_>>();
            let bytes = serde_json::to_vec(&json!({"schema":1,"run":run,
                "revision":1,"requests":requests}))
            .expect("run bytes");
            assert!(
                bytes.len() <= MAX_RUN_BYTES,
                "run {run} is too large: {}",
                bytes.len()
            );
            total_bytes += bytes.len();
            store
                .fixture_replace_run_bytes(&run, &bytes)
                .expect("dense run record");
        }
        (fixture, total_requests, total_bytes)
    }

    /// ´test:unit:requests-wait-measures-loop-wide-read-at-representative-size´
    #[test]
    #[ignore = "explicit 64-run read measurement"]
    fn requests_wait_measures_loop_wide_read_at_representative_size() {
        use std::io::Write as _;
        use std::time::Instant;

        let (fixture, count, bytes) = dense_wait_fixture();
        assert_eq!(count, 16_349);
        let store = fixture.store();
        for iteration in 0..3 {
            let started = Instant::now();
            let (rows, _, _) = store.list_with_status().expect("loop-wide read");
            writeln!(
                std::io::stderr(),
                "requests_wait_loop_read_iteration={iteration} seconds={:.6} runs=64 requests={count} bytes={bytes}",
                started.elapsed().as_secs_f64(),
            )
            .expect("read wall report");
            assert_eq!(rows.len(), count);
        }
    }

    fn staggered_reader_hooks(
        index: usize,
        acquired: std::sync::mpsc::Sender<usize>,
        release: std::sync::mpsc::Receiver<()>,
        paused: std::sync::mpsc::Sender<usize>,
        resume: std::sync::mpsc::Receiver<()>,
    ) {
        use crate::requests::commands::{WAIT_TEST_HOLD, WAIT_TEST_PAUSE};
        use std::time::Duration;
        AFTER_READER_LOCK_ACQUIRED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                acquired.send(index).expect("shared hold acquired");
                release
                    .recv_timeout(Duration::from_secs(120))
                    .expect("release shared hold");
            }));
        });
        WAIT_TEST_HOLD.with(|hold| hold.set(Some(Duration::from_millis(500))));
        WAIT_TEST_PAUSE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |pause| {
                assert_eq!(
                    pause,
                    Duration::from_secs(1),
                    "slow reads must back off twice their hold, not a fixed 200 ms"
                );
                paused
                    .send(index)
                    .expect("reader released lock for backoff");
                resume
                    .recv_timeout(Duration::from_secs(120))
                    .expect("writer used the shared gap");
            }));
        });
    }

    /// ´test:unit:requests-wait-two-staggered-readers-leave-writer-gap´
    #[test]
    fn requests_wait_two_staggered_readers_leave_writer_gap() {
        use std::sync::mpsc;
        use std::time::Duration;

        let fixture = Fixture::new();
        drop(
            fixture
                .store()
                .fixture_exclusive_lock()
                .expect("create request lock"),
        );
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let (paused_tx, paused_rx) = mpsc::channel();
        // The command deadline and channel bounds detect a stuck fixture; the
        // claim uses event order and a synthetic hold, never scheduler latency.
        let wait_args = ["wait", "alpha", "--state", "waiting", "--timeout", "600"];
        std::thread::scope(|scope| {
            let mut waiters = Vec::new();
            let mut releases = Vec::new();
            let mut resumes = Vec::new();
            for index in 0..2 {
                let snapshot = crate::home::snapshot_private_home().expect("waiter anchors");
                let home = &fixture.home;
                let acquired = acquired_tx.clone();
                let paused = paused_tx.clone();
                let (release_tx, release_rx) = mpsc::channel();
                let (resume_tx, resume_rx) = mpsc::channel();
                releases.push(release_tx);
                resumes.push(resume_tx);
                waiters.push(scope.spawn(move || {
                    let _guard =
                        crate::home::activate_private_snapshot(snapshot).expect("waiter anchors");
                    staggered_reader_hooks(index, acquired, release_rx, paused, resume_rx);
                    let args = wait_args.map(str::to_owned);
                    let mut output = Vec::new();
                    crate::requests::commands::run(home, &args, &mut &b""[..], &mut output)
                        .expect("writer request wakes waiter");
                    let waited: serde_json::Value =
                        serde_json::from_slice(&output).expect("wait response");
                    assert_eq!(waited["requests"][0]["run"], "S");
                }));
                // Reader two starts only after reader one holds the shared lock;
                // reader one cannot release until both have signalled acquisition.
                assert_eq!(
                    acquired_rx
                        .recv_timeout(Duration::from_secs(120))
                        .expect("reader holds lock"),
                    index
                );
            }
            let (contended_tx, contended_rx) = mpsc::channel();
            let store = fixture.store();
            let snapshot = crate::home::snapshot_private_home().expect("writer anchors");
            let writer = scope.spawn(move || {
                let _guard =
                    crate::home::activate_private_snapshot(snapshot).expect("writer anchors");
                super::AFTER_WRITER_LOCK_CONTENTION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        contended_tx.send(()).expect("writer contended");
                    }));
                });
                store
                    .file(waiting("S", "ffff", 3000, Mode::Audit))
                    .expect("writer completed in reader gap");
            });
            contended_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("writer attempted while both readers held locks");
            for (index, release) in releases.into_iter().enumerate() {
                release.send(()).expect("release reader in order");
                assert_eq!(
                    paused_rx
                        .recv_timeout(Duration::from_secs(120))
                        .expect("reader entered backoff"),
                    index
                );
            }
            writer
                .join()
                .expect("writer used the gap before readers resumed");
            for resume in resumes {
                resume.send(()).expect("resume reader");
            }
            for waiter in waiters {
                waiter.join().expect("waiter joined");
            }
        });
    }

    /// ´test:unit:requests-wait-two-loop-readers-leave-writer-gap´
    #[test]
    #[ignore = "explicit 64-run two-waiter measurement"]
    fn requests_wait_two_loop_readers_leave_writer_gap() {
        use std::io::Write as _;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let (fixture, count, bytes) = dense_wait_fixture();
        assert_eq!(count, 16_349);
        let (reading_tx, reading_rx) = mpsc::channel();
        let snapshots = [
            crate::home::snapshot_private_home().expect("first waiter anchors"),
            crate::home::snapshot_private_home().expect("second waiter anchors"),
        ];
        std::thread::scope(|scope| {
            let mut waiters = Vec::new();
            for snapshot in snapshots {
                let reading_tx = reading_tx.clone();
                let home = &fixture.home;
                waiters.push(scope.spawn(move || {
                    let _guard = crate::home::activate_private_snapshot(snapshot)
                        .expect("activate fixture anchors on waiter");
                    AFTER_READER_LOCK_ACQUIRED.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            reading_tx.send(()).expect("reader lock signal");
                        }));
                    });
                    let args = ["wait", "alpha", "--state", "marked", "--timeout", "12"]
                        .map(str::to_owned);
                    let mut input = &b""[..];
                    let mut output = Vec::new();
                    let error =
                        crate::requests::commands::run(home, &args, &mut input, &mut output)
                            .expect_err("marked request absent");
                    assert_eq!(error.kind, "requests-wait-timeout");
                    assert_eq!(output, Vec::<u8>::new());
                }));
            }
            reading_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("first reader acquired lock");
            reading_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("second reader acquired lock");
            let started = Instant::now();
            fixture
                .store()
                .file(waiting("S", "ffff", 3000, Mode::Audit))
                .expect("writer completed beside two waiters");
            let wall = started.elapsed();
            writeln!(
                std::io::stderr(),
                "requests_wait_two_readers_writer_seconds={:.6} runs=64 requests={count} bytes={bytes}",
                wall.as_secs_f64()
            )
            .expect("writer wall report");
            assert!(wall < Duration::from_secs(15));
            for waiter in waiters {
                waiter.join().expect("waiter joined");
            }
        });
    }

    /// ´test:unit:requests-wait-publish-does-not-hold-the-writer-lock´
    #[test]
    fn requests_wait_publish_does_not_hold_the_writer_lock() {
        use std::io::Write as _;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let fixture = Fixture::new();
        let (started_tx, started_rx) = mpsc::channel();
        let snapshot = crate::home::snapshot_private_home().expect("private fixture anchors");
        std::thread::scope(|scope| {
            let home = &fixture.home;
            let waiter = scope.spawn(move || {
                let _guard = crate::home::activate_private_snapshot(snapshot)
                    .expect("activate fixture anchors on waiter");
                let args = ["wait", "alpha", "--run", "R", "--timeout", "5"].map(str::to_owned);
                let mut input = &b""[..];
                let mut output = Vec::new();
                started_tx.send(()).expect("start signal");
                crate::requests::commands::run(home, &args, &mut input, &mut output)
                    .expect("published request");
                serde_json::from_slice::<serde_json::Value>(&output).expect("wait JSON")
            });
            started_rx.recv().expect("waiter started");
            std::thread::sleep(Duration::from_millis(350));
            let publish_started = Instant::now();
            fixture
                .store()
                .file(waiting("R", "1a", 3000, Mode::Audit))
                .expect("writer completed while waiter ran");
            let publish_wall = publish_started.elapsed();
            let result = waiter.join().expect("waiter joined");
            let response_wall = publish_started.elapsed();
            writeln!(
                std::io::stderr(),
                "requests_wait_writer_seconds={:.6} requests_wait_publish_to_response_seconds={:.6}",
                publish_wall.as_secs_f64(),
                response_wall.as_secs_f64()
            )
            .expect("publication wall report");
            assert_eq!(result["requests"].as_array().expect("rows").len(), 1);
            // A loaded node may schedule the reader late; the 200 ms cadence
            // leaves 2.8 s for its read, the writer and scheduling.
            assert!(response_wall < Duration::from_secs(3));
            assert!(publish_wall < Duration::from_secs(3));
        });
    }

    /// ´test:unit:commands-refuse-usage-input-and-whole-batches´
    #[test]
    fn commands_refuse_usage_input_and_whole_batches() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("first");
        store
            .file(waiting("R", "2b", 3001, Mode::Audit))
            .expect("second");
        for args in [
            vec!["unknown", "alpha"],
            vec!["list", "alpha", "--state", "bad"],
            vec!["triage", "alpha", "R", "extra"],
        ] {
            assert_eq!(
                fixture.command(&args, b"").expect_err("usage").kind,
                "requests-usage"
            );
        }
        for size in [65_537, 100_000] {
            let error = fixture
                .command(&["triage", "alpha", "R"], &vec![b' '; size])
                .expect_err("oversized batch");
            assert_eq!(error.kind, "requests-batch-refusal");
            assert_eq!(
                error.detail,
                "input exceeds cap of 65,536 bytes; at least 65,537 bytes received"
            );
        }
        for input in [b"not-json".to_vec(), b"{}".to_vec()] {
            assert_eq!(
                fixture
                    .command(&["triage", "alpha", "R"], &input)
                    .expect_err("batch input")
                    .kind,
                "requests-batch-refusal"
            );
        }
        let before = fs::read(fixture.run_file("R")).expect("before");
        for batch in [
            json!([]),
            json!([{"id":"R:1a","action":"mark","reason":"why"},{"id":"R:1a","action":"mark","reason":"why"}]),
            json!([{"id":"S:2b","action":"mark","reason":"why"}]),
        ] {
            assert_eq!(
                fixture
                    .command(
                        &["triage", "alpha", "R"],
                        &serde_json::to_vec(&batch).expect("batch")
                    )
                    .expect_err("whole batch")
                    .kind,
                "requests-batch-refusal"
            );
            assert_eq!(fs::read(fixture.run_file("R")).expect("unchanged"), before);
        }
    }

    /// ´test:unit:failed-shape-publication-withdraws-run-and-records-attempt´
    #[test]
    fn failed_shape_publication_withdraws_run_and_records_attempt() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("first");
        let before = fs::read(fixture.run_file("R")).expect("before");
        FAIL_SHAPE_WRITE.with(|fail| fail.set(true));
        assert_eq!(
            store
                .file(waiting("R", "2b", 3001, Mode::Audit))
                .expect_err("forced shape failure")
                .kind,
            "requests-record-refusal"
        );
        assert_eq!(fs::read(fixture.run_file("R")).expect("restored"), before);
        let attempt: serde_json::Value = serde_json::from_slice(
            &fs::read(
                fixture
                    .home
                    .join(".config/loops/alpha/door-requests-attempt.json"),
            )
            .expect("attempt"),
        )
        .expect("JSON");
        assert_eq!(attempt["latest"]["withdrawn"]["phase"], "withdrawn");
    }

    /// ´test:unit:stored-floor-is-history-and-owner-worker-grants-refuse´
    #[test]
    fn stored_floor_is_history_and_owner_worker_grants_refuse() {
        let fixture = Fixture::new();
        let store = fixture.store();
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("first");
        fixture.set_floor("allow");
        let newer = fixture.store();
        assert_eq!(newer.list().expect("old floor readable").0.len(), 1);
        newer
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"mark","reason":"review"})],
                "owner",
                "2",
            )
            .expect("old floor triage");
        let reviewed = newer.review("R:1a", "3").expect("review");
        newer
            .adjudicate(
                "R:1a",
                reviewed.value()["review"]["id"].as_str().expect("id"),
                "allow",
                "evidence",
                "owner",
                "4",
            )
            .expect("old floor adjudication");
        for worker in [41001, nix::unistd::Uid::effective().as_raw()] {
            assert_eq!(
                newer
                    .file(waiting("S", "2b", worker, Mode::Allow))
                    .expect_err("worker grant")
                    .kind,
                "requests-record-refusal"
            );
        }
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.run_file("R")).expect("bytes")).expect("JSON");
        record["requests"][0]["worker_uid"] = json!(41001);
        fs::write(
            fixture.run_file("R"),
            serde_json::to_vec(&record).expect("bytes"),
        )
        .expect("changed record");
        assert_eq!(
            newer.list().expect_err("stored loop uid").kind,
            "requests-record-refusal"
        );
        record["requests"][0]["worker_uid"] = json!(nix::unistd::Uid::effective().as_raw());
        fs::write(
            fixture.run_file("R"),
            serde_json::to_vec(&record).expect("bytes"),
        )
        .expect("changed record");
        assert_eq!(
            newer.list().expect_err("stored owner uid").kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:descriptor-reader-refuses-linked-custody´
    #[test]
    fn descriptor_reader_refuses_linked_custody() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let custody = fixture.runs.join(".launch-R");
        fs::remove_dir(&custody).expect("remove empty fixture custody");
        std::os::unix::fs::symlink(Path::new(".launch-S"), &custody).expect("linked custody");
        assert_eq!(
            store
                .file(waiting("R", "1a", 3000, Mode::Audit))
                .expect_err("linked custody")
                .kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:mode-citations-refuse-every-non-agreeing-source´
    #[test]
    fn mode_citations_refuse_every_non_agreeing_source() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        store
            .file(fixture_request("R", "1a", 3000, Mode::Allow, "allow"))
            .expect("waiting");
        store
            .file(fixture_request("R", "2b", 3001, Mode::Allow, "refuse"))
            .expect("corrected");
        store
            .file(fixture_request("R", "3c", 3000, Mode::Allow, "undecided"))
            .expect("undecided");
        store
            .file(fixture_request("R", "5e", 3001, Mode::Allow, "allow"))
            .expect("agreement");
        let mut foreign = fixture_request("S", "4d", 3001, Mode::Allow, "allow").into_value();
        foreign["class"] = json!("other");
        store
            .file(RequestRecord::decode(foreign).expect("other class"))
            .expect("foreign");
        store.triage("R", &[
            json!({"id":"R:2b","action":"adjudicate","treatment":"allow","reason":"correction"}),
            json!({"id":"R:3c","action":"adjudicate","treatment":"allow","reason":"undecided"}),
            json!({"id":"R:5e","action":"adjudicate","treatment":"allow","reason":"agreement"}),
        ], "owner", "2").expect("R labels");
        store.triage("S", &[json!({"id":"S:4d","action":"adjudicate","treatment":"allow","reason":"other class"})], "owner", "2").expect("S label");
        store
            .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "floor", "3", &[])
            .expect("loop first");
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(&class, Mode::Audit, "owner", "first", "3", &[])
            .expect("class first");
        let path = fixture.home.join(".config/loops/alpha/door-modes.json");
        let before = fs::read(&path).expect("history");
        for id in ["R:1a", "R:2b", "R:3c", "S:4d"] {
            let refusal = store
                .set_mode(
                    &class,
                    Mode::Enforce,
                    "owner",
                    "invalid label",
                    "4",
                    &[id.to_owned()],
                )
                .expect_err("non-agreeing citation");
            assert_eq!(refusal.kind, "door-mode-evidence-refusal", "{id}");
            assert_eq!(fs::read(&path).expect("unchanged history"), before);
        }
        let citations = vec!["R:5e".to_owned(); 33];
        assert_eq!(
            store
                .set_mode(&class, Mode::Enforce, "owner", "too many", "4", &citations)
                .expect_err("citation cap")
                .kind,
            "door-mode-evidence-refusal"
        );
        assert_eq!(
            store
                .correct_mode("fixture", "R:5e", "owner", "4")
                .expect_err("agreement is no correction")
                .kind,
            "door-mode-evidence-refusal"
        );
        let other = ModeTarget::class("other").expect("other target");
        assert_eq!(
            store
                .set_mode(
                    &other,
                    Mode::Audit,
                    "owner",
                    "first with citation",
                    "4",
                    &["S:4d".to_owned()]
                )
                .expect_err("first needs no label basis")
                .kind,
            "door-mode-evidence-refusal"
        );
        assert_eq!(fs::read(&path).expect("still unchanged"), before);
    }

    /// ´test:unit:mode-history-lock-and-first-settings-refuse-by-name´
    #[test]
    fn mode_history_lock_and_first_settings_refuse_by_name() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        let mut request = fixture_request("R", "1a", 3000, Mode::Allow, "refuse").into_value();
        request["mode"] = json!("enforce");
        request["class_setting"]["mode"] = json!("enforce");
        request["loop_setting"]["mode"] = json!("allow");
        store
            .file(RequestRecord::decode(request).expect("request"))
            .expect("file before settings");
        assert_eq!(
            store
                .effective_mode("fixture")
                .expect_err("no first settings")
                .kind,
            "door-mode-setting-refusal"
        );
        store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"wrong rubric"})], "owner", "2").expect("label");
        store
            .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "first", "3", &[])
            .expect("loop first");
        assert_eq!(
            store
                .effective_mode("fixture")
                .expect_err("class first absent")
                .kind,
            "door-mode-setting-refusal"
        );
        assert_eq!(
            store
                .correct_mode("fixture", "R:1a", "owner", "4")
                .expect_err("correction without class first")
                .kind,
            "door-mode-setting-refusal"
        );
        assert_eq!(
            store
                .file(fixture_request("S", "2b", 3001, Mode::Allow, "allow"))
                .expect_err("file without class first")
                .kind,
            "door-mode-setting-refusal"
        );
        let state = fixture.home.join(".config/loops/alpha");
        fs::remove_file(state.join(LOCK_FILE)).expect("remove lock");
        assert_eq!(
            store.modes().expect_err("history without lock").kind,
            "door-mode-record-refusal"
        );
        assert_eq!(
            store
                .list_with_status()
                .expect_err("list without lock")
                .kind,
            "requests-record-refusal"
        );
        assert_eq!(
            store
                .request("R:1a")
                .expect_err("request without lock")
                .kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:allow-correction-reports-rubric-row-and-row-floor-bounds-mode´
    #[test]
    fn allow_correction_reports_rubric_row_and_row_floor_bounds_mode() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        let class = ModeTarget::class("fixture").expect("class");
        store
            .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "first", "1", &[])
            .expect("loop");
        store
            .set_mode(&class, Mode::Allow, "owner", "first", "1", &[])
            .expect("class");
        store
            .file(fixture_request_with_mode(
                &store,
                "R",
                "1a",
                3000,
                Mode::Allow,
                "refuse",
            ))
            .expect("allow request");
        let (_, reports) = store.triage_with_reports("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"allow","reason":"rubric needs row"})], "owner", "2").expect("allow label");
        assert_eq!(reports[0]["action"], "rubric-row-needed");
        assert_eq!(reports[0]["changed"], false);
        assert_eq!(
            store.effective_mode("fixture").expect("still allow")["mode"],
            "allow"
        );
        assert_eq!(
            store
                .correct_mode("fixture", "R:1a", "owner", "3")
                .expect("report only")["action"],
            "rubric-row-needed"
        );
        fixture.set_floor("audit");
        let bounded = fixture.store();
        let effective = bounded
            .effective_mode("fixture")
            .expect("row bounds settings");
        assert_eq!(effective["mode"], "audit");
        assert_eq!(effective["floor"], "audit");
        assert_eq!(effective["floor_bounded"], true);
        bounded
            .file(fixture_request_with_mode(
                &bounded,
                "S",
                "2b",
                3001,
                Mode::Audit,
                "allow",
            ))
            .expect("bounded snapshot files");
    }

    /// ´test:unit:attempt-journal-refuses-each-invalid-shape-without-write´
    #[test]
    fn attempt_journal_refuses_each_invalid_shape_without_write() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let path = fixture.home.join(".config/loops/alpha").join(ATTEMPT_FILE);
        let event = json!({"phase":"repaired","run":null,"reason":"fixture","rollback":null,"at_unix_ns":1});
        for bytes in [
            b"not JSON".to_vec(),
            serde_json::to_vec(&json!({"schema":1,"latest":{}})).expect("schema one"),
            serde_json::to_vec(&json!({"schema":2,"latest":[]})).expect("latest list"),
            serde_json::to_vec(&json!({"schema":2,"latest":{"unknown":event}}))
                .expect("unknown phase"),
            serde_json::to_vec(&json!({"schema":2,"latest":{"repaired":{"phase":"repaired"}}}))
                .expect("invalid event"),
        ] {
            fs::write(&path, &bytes).expect("journal fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("journal mode");
            assert_eq!(
                store
                    .record_attempt(event.clone())
                    .expect_err("invalid journal")
                    .kind,
                "requests-record-refusal"
            );
            assert_eq!(fs::read(&path).expect("unchanged journal"), bytes);
        }
    }

    /// ´test:unit:incomplete-attempt-refuses-cross-run-identifier´
    #[test]
    fn incomplete_attempt_refuses_cross_run_identifier() {
        let fixture = Fixture::new();
        let store = fixture.store();
        assert_eq!(
            store
                .record_incomplete("R", "S:1a", "fixture failure")
                .expect_err("cross-run incomplete")
                .kind,
            "requests-record-refusal"
        );
        assert!(
            !fixture
                .home
                .join(".config/loops/alpha")
                .join(ATTEMPT_FILE)
                .exists()
        );
    }
}
