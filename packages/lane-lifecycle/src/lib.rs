#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::libc;
use nix::sys::signal::{SigSet, Signal};

pub mod execution_settings;
mod observation;
pub use observation::{escape_name as escape_mailbox_name, parse_utc_instant};

/// Ratified no-growth window for a step that is already over budget.
/// An approved or registered gateway run in flight is progress under this window.
pub const STALL_WINDOW_SECONDS: u64 = 120;

/// Ratified absolute runaway multiple.
pub const RUNAWAY_MULTIPLIER: u64 = 4;

/// A boxed attempt stopped at its planned wall, independently of budget notices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptWall {
    /// Elapsed attempt seconds at the stop decision.
    pub wall_seconds: u64,
    /// Planned attempt bound in seconds.
    pub bound_seconds: u64,
}

impl AttemptWall {
    /// Encode the helper's terminal diagnostic, after its output workers finish.
    #[must_use]
    pub fn diagnostic(self) -> String {
        format!(
            "attempt-wall wall_seconds={} bound_seconds={}\n",
            self.wall_seconds, self.bound_seconds
        )
    }

    /// Publish the helper client's typed completion outside the worker's streams.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the driver-selected file cannot be published.
    pub fn publish(self, path: &Path) -> io::Result<()> {
        atomic_write(path, self.diagnostic().as_bytes())
    }

    /// Read a complete terminal helper diagnostic.
    #[must_use]
    pub fn from_diagnostic(text: &str) -> Option<Self> {
        let line = text.lines().last()?;
        let rest = line.strip_prefix("attempt-wall wall_seconds=")?;
        let (wall, bound) = rest.split_once(" bound_seconds=")?;
        let result = Self {
            wall_seconds: wall.parse().ok()?,
            bound_seconds: bound.parse().ok()?,
        };
        (result.bound_seconds > 0 && result.wall_seconds >= result.bound_seconds).then_some(result)
    }

    /// Add the cause to a failed run report without changing its verdict.
    pub fn annotate_report(self, report: &mut Vec<u8>) {
        if report.last() == Some(&b'\n') {
            report.pop();
        }
        report.extend_from_slice(
            format!(
                " cause=attempt-wall attempt_elapsed_seconds={} attempt_bound_seconds={}\n",
                self.wall_seconds, self.bound_seconds
            )
            .as_bytes(),
        );
    }
}

fn step_attempt_wall(backend: &dyn Backend, run_dir: &Path) -> Option<AttemptWall> {
    if !backend.boxed_runtime() {
        return None;
    }
    let file = File::open(run_dir.join(".attempt-end")).ok()?;
    let mut text = String::new();
    file.take(256).read_to_string(&mut text).ok()?;
    AttemptWall::from_diagnostic(&text)
}

/// Small whole-second tolerance for clock sampling jitter.
pub const SUSPEND_GAP_THRESHOLD_SECONDS: u64 = 2;

const POLL_SECONDS: u64 = 1;
const CAPACITY_MAX_ATTEMPTS: u8 = 4;
const CAPACITY_BACKOFF_SECONDS: [u64; 3] = [60, 120, 240];
const CAPACITY_ATTEMPTS_FILE: &str = "capacity-attempts.txt";
const MILLISECONDS_PER_SECOND: u64 = 1_000;
const DEFAULT_NAME: &str = "lane";
const MAX_FRESH_RUN_DIR_ATTEMPTS: u32 = 32;
const DEFAULT_SANDBOX: &str = "workspace-write";
const STEP_NAME_FILE: &str = ".step-name";
const EVENT_START_FILE: &str = ".event-start";
const STARTED_AT_FILE: &str = ".started-at";
const THREAD_ID_FILE: &str = "thread-id.txt";
const MONITOR_FILE_PREFIX: &str = ".monitor-";
const RECONSTRUCTED_FILE: &str = ".reconstructed";
const RATE_LIMIT_FILE: &str = "rate-limit.txt";
const CONTEXT_FILE: &str = "context.jsonl";
const POOL_FILE: &str = "lane-pool.json";
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: u64 = 86_400;

/// Utilization at or above which a recorded pool state refuses a dispatch.
pub const DEFAULT_POOL_THRESHOLD: f64 = 0.95;

const POOL_THRESHOLD_OPTION: &[u8] = b"--pool-threshold";
const IGNORE_POOL_OPTION: &[u8] = b"--ignore-pool";
const GATEWAY_LANE_OPTION: &[u8] = b"--gateway-lane";

static NEXT_ATOMIC_FILE: AtomicU64 = AtomicU64::new(0);
static NEXT_MONITOR_FILE: AtomicU64 = AtomicU64::new(0);

/// One turn's measured context, or the named reason it cannot be measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextUse {
    pub used: Option<u64>,
    pub window: Option<u64>,
    pub source: &'static str,
    pub reason: &'static str,
}

impl ContextUse {
    #[must_use]
    pub const fn unknown(source: &'static str, reason: &'static str) -> Self {
        Self {
            used: None,
            window: None,
            source,
            reason,
        }
    }

    #[must_use]
    pub fn measured(used: u64, window: u64, source: &'static str) -> Option<Self> {
        (window > 0).then_some(Self {
            used: Some(used),
            window: Some(window),
            source,
            reason: "measured",
        })
    }

    const fn state(self) -> &'static str {
        if self.used.is_some() && self.window.is_some() {
            "measured"
        } else {
            "unknown"
        }
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fraction(self) -> Option<f64> {
        Some(self.used? as f64 / self.window? as f64)
    }
}

fn monitor_file(run_dir: &Path) -> PathBuf {
    run_dir.join(format!(
        "{MONITOR_FILE_PREFIX}{}-{}",
        std::process::id(),
        NEXT_MONITOR_FILE.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Signals that ask the driver to stop, with the word the evidence records.
const FORWARDED_SIGNALS: [(Signal, &str); 2] =
    [(Signal::SIGTERM, "SIGTERM"), (Signal::SIGINT, "SIGINT")];

static FORWARDED_SIGNAL: AtomicI32 = AtomicI32::new(0);
static SIGNAL_WATCH: OnceLock<bool> = OnceLock::new();

/// Backend-specific construction and event interpretation for one lane CLI.
#[allow(clippy::result_unit_err)]
pub trait Backend {
    /// Binary name that prefixes every diagnostic emitted by this backend.
    fn name(&self) -> &'static str;

    /// Whether this step invokes the box helper through a runtime argument file.
    fn boxed_runtime(&self) -> bool {
        false
    }

    /// Resolve the child program from its configured argument vector.
    fn program(&self) -> Option<OsString>;

    /// Validate configured execution dependencies before any run allocation.
    ///
    /// # Errors
    ///
    /// Names an absent or invalid required setting.
    fn execution_evidence(&self) -> Result<Option<serde_json::Value>, String> {
        Ok(None)
    }

    /// Compose the child command for one prepared step.
    ///
    /// # Errors
    ///
    /// Names the program or backend-specific configuration that refused.
    fn command(&self, config: &Config, run_dir: &Path) -> Result<Command, String>;

    /// Extract the durable thread identifier from an event stream.
    fn thread_id(&self, events: &[u8]) -> Option<String>;

    /// Extract the last nonempty assistant message from an event stream.
    fn last_message(&self, events: &[u8]) -> Option<Vec<u8>>;

    /// Read the terminal result the transcript's last complete line carries.
    ///
    /// A backend whose event shape has no terminal result event answers
    /// `None` for every transcript, which leaves its interrupted steps
    /// unreconstructed.
    fn terminal_result(&self, events: &[u8]) -> Option<TerminalResult>;

    /// Interpret one completed event line without estimating context from
    /// cumulative billing counters.
    fn context_use(&self, _event: &[u8]) -> Option<ContextUse> {
        None
    }

    /// Read a refused dispatch from one step's own event region.
    ///
    /// A backend whose event shape is not known to carry a refusal answers
    /// `None` for every transcript, which leaves its refused dispatches
    /// indistinguishable from steps that ran and failed.
    fn rate_limit_rejection(&self, events: &[u8]) -> Option<RateLimitRejection>;

    /// Read the last pool state one step's own event region records.
    ///
    /// The last event is the state the next dispatch inherits, whether the
    /// pool allowed, warned, or refused.
    fn rate_limit_state(&self, events: &[u8]) -> Option<RateLimitState>;

    /// Recognize a provider capacity refusal eligible for a bounded retry.
    fn retryable_capacity(&self, _events: &[u8]) -> bool {
        false
    }

    /// Resolve the lane home whose pool state this backend shares.
    ///
    /// Several lane homes can sign into one account and share one window, so
    /// the home a step dispatched from is where its observation belongs.
    fn config_dir(&self) -> Option<PathBuf>;

    /// Name of the per-backend exclusive step lock.
    fn lock_file(&self) -> &'static str;

    /// Prepare the isolated home and force the pure execution configuration.
    ///
    /// # Errors
    ///
    /// Returns `()` when the isolated home cannot be created or is contaminated.
    fn configure_pure(&self, config: &mut Config, run_dir: &Path) -> Result<(), ()>;
}

/// Classed evidence for invalid arguments.
#[must_use]
pub fn usage_diagnostic(name: &str) -> Vec<u8> {
    diagnostic_line(name, "usage_error", "invalid command-line arguments")
}

fn step_stderr_diagnostic(name: &str, path: &Path, start: u64) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let end = file.metadata().ok()?.len();
    if end <= start {
        return None;
    }
    file.seek(SeekFrom::Start(end.saturating_sub(4096).max(start)))
        .ok()?;
    let mut bytes = Vec::new();
    file.take(4096).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text
        .lines()
        .filter(|line| !line.is_empty())
        .rev()
        .take(3)
        .collect::<Vec<_>>();
    lines.reverse();
    let mut diagnostic = String::new();
    for line in lines {
        let printable: String = line
            .chars()
            .map(|part| if part.is_control() { '�' } else { part })
            .collect();
        let _ignored = writeln!(
            &mut diagnostic,
            "{name}: runtime_failure: child stderr: {printable}"
        );
    }
    (!diagnostic.is_empty()).then(|| diagnostic.into_bytes())
}

/// The finish one terminal result event records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalResult {
    is_error: bool,
    duration_ms: Option<u64>,
}

impl TerminalResult {
    /// Construct one terminal result from its decoded event fields.
    #[must_use]
    pub const fn new(is_error: bool, duration_ms: Option<u64>) -> Self {
        Self {
            is_error,
            duration_ms,
        }
    }

    /// Whether the backend reported the turn as failed.
    #[must_use]
    pub const fn is_error(self) -> bool {
        self.is_error
    }

    /// Child-measured duration, when the event carries one.
    #[must_use]
    pub const fn duration_ms(self) -> Option<u64> {
        self.duration_ms
    }

    /// Exit status and verdict this finish would have published.
    const fn finish(self) -> (u8, Verdict) {
        if self.is_error {
            (1, Verdict::Failed)
        } else {
            (0, Verdict::Ok)
        }
    }
}

/// The pool state one rate-limit event records.
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitState {
    status: String,
    rate_limit_type: Option<String>,
    utilization: Option<f64>,
    resets_at: Option<u64>,
}

impl RateLimitState {
    /// Construct one pool state from its decoded event fields.
    #[must_use]
    pub const fn new(
        status: String,
        rate_limit_type: Option<String>,
        utilization: Option<f64>,
        resets_at: Option<u64>,
    ) -> Self {
        Self {
            status,
            rate_limit_type,
            utilization,
            resets_at,
        }
    }

    /// Status word the event carried.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Window the status speaks for, when the event names one.
    #[must_use]
    pub fn rate_limit_type(&self) -> Option<&str> {
        self.rate_limit_type.as_deref()
    }

    /// Fraction of the window consumed, when the event measures one.
    #[must_use]
    pub const fn utilization(&self) -> Option<f64> {
        self.utilization
    }

    /// Epoch second at which the window resets, when the event states one.
    #[must_use]
    pub const fn resets_at(&self) -> Option<u64> {
        self.resets_at
    }

    /// Whether this state is the pool refusing a dispatch.
    #[must_use]
    pub fn rejected(&self) -> bool {
        self.status == "rejected"
    }

    /// The window this state speaks for, named for an operator.
    fn window(&self) -> &str {
        self.rate_limit_type().unwrap_or("the window")
    }
}

/// A dispatch the pool refused, as the step's own event recorded it.
///
/// The type exists only for a state whose status is a refusal, so holding one
/// is the evidence that this step never got to run.
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitRejection {
    state: RateLimitState,
}

impl RateLimitRejection {
    /// Accept one pool state as a refusal, or reject it as something else.
    #[must_use]
    pub fn from_state(state: RateLimitState) -> Option<Self> {
        state.rejected().then_some(Self { state })
    }

    /// The pool state this refusal carries.
    #[must_use]
    pub const fn state(&self) -> &RateLimitState {
        &self.state
    }
}

/// Where a reconstructed report's wall figure came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WallDerivation {
    /// The terminal result event's own duration.
    DurationMs,
    /// Nothing in the transcript measures the step.
    Unknown,
}

impl WallDerivation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DurationMs => "duration_ms",
            Self::Unknown => "unknown",
        }
    }
}

/// Classed evidence for allocation, persistence, spawn, or monitor failures.
#[must_use]
pub fn runtime_diagnostic(name: &str) -> Vec<u8> {
    diagnostic_line(name, "runtime_failure", "lane execution failed")
}

/// Classed evidence for a suppressed panic.
#[must_use]
pub fn internal_diagnostic(name: &str) -> Vec<u8> {
    diagnostic_line(name, "internal_failure", "unexpected internal failure")
}

/// Classed fallback when the owned standard-output stream rejects publication.
#[must_use]
pub fn publication_diagnostic(name: &str) -> Vec<u8> {
    diagnostic_line(name, "publication_failure", "agent-text publication failed")
}

fn diagnostic_line(name: &str, class: &str, message: &str) -> Vec<u8> {
    let mut diagnostic = String::new();
    writeln!(&mut diagnostic, "{name}: {class}: {message}")
        .expect("writing to a String cannot fail");
    diagnostic.into_bytes()
}

/// Parsed lane invocation.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    budget: u64,
    pool_threshold: f64,
    ignore_pool: bool,
    gateway_lane: Option<String>,
    workdir: PathBuf,
    sandbox: OsString,
    model: Option<OsString>,
    effort: Option<OsString>,
    name: String,
    session: Option<String>,
    resume_dir: Option<PathBuf>,
    crash_recovery: Option<CrashRecovery>,
    pure: bool,
    prompt: Prompt,
    step_letter: Option<Vec<u8>>,
}

impl Config {
    /// Effective reporting budget.
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }

    /// Utilization at or above which a recorded pool state refuses a dispatch.
    #[must_use]
    pub const fn pool_threshold(&self) -> f64 {
        self.pool_threshold
    }

    /// Whether this invocation dispatches without consulting the pool state.
    #[must_use]
    pub const fn ignore_pool(&self) -> bool {
        self.ignore_pool
    }

    /// Registered gateway lane whose approved run can credit this step.
    #[must_use]
    pub fn gateway_lane(&self) -> Option<&str> {
        self.gateway_lane.as_deref()
    }

    /// Report and fresh-directory identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this invocation resumes a prior thread.
    #[must_use]
    pub const fn is_resume(&self) -> bool {
        self.session.is_some()
    }

    /// Classed evidence when this invocation recovered a dead host lock.
    #[must_use]
    pub fn crash_recovery_diagnostic(&self, backend_name: &str) -> Option<Vec<u8>> {
        self.crash_recovery
            .as_ref()
            .map(|recovery| recovery.diagnostic(backend_name))
    }

    /// Child working directory.
    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// Requested sandbox name.
    #[must_use]
    pub fn sandbox(&self) -> &OsStr {
        &self.sandbox
    }

    /// Optional backend model selector.
    #[must_use]
    pub fn model(&self) -> Option<&OsStr> {
        self.model.as_deref()
    }

    /// Optional backend effort selector.
    #[must_use]
    pub fn effort(&self) -> Option<&OsStr> {
        self.effort.as_deref()
    }

    /// Optional durable session identifier.
    #[must_use]
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// Whether pure mode was requested.
    #[must_use]
    pub const fn pure(&self) -> bool {
        self.pure
    }

    /// Force the shared pure-mode working directory and read-only sandbox.
    pub fn force_pure_workdir(&mut self, workdir: PathBuf) {
        self.workdir = workdir;
        self.sandbox = OsString::from("read-only");
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Prompt {
    Argument(OsString),
    Stdin,
}

/// Argument failure retaining the best valid budget seen before refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageError {
    budget: u64,
    resume_refusal: Option<ResumeRefusal>,
    runs_root_refusal: Option<RootRefusal>,
    step_letter_refusal: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootRefusal {
    Required,
    Selected,
    Directory,
}

impl UsageError {
    /// Budget value safe to place in the fallback report.
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }

    /// Classed fresh-root or resume-boundary evidence.
    #[must_use]
    pub fn refusal_diagnostic(&self, backend_name: &str) -> Option<Vec<u8>> {
        if let Some(detail) = &self.step_letter_refusal {
            return Some(diagnostic_line(backend_name, "step-letter", detail));
        }
        if let Some(refusal) = self.runs_root_refusal {
            let (kind, detail) = match refusal {
                RootRefusal::Required => (
                    "runs_root_required",
                    "LANE_RUNS_ROOT must be an absolute path",
                ),
                RootRefusal::Selected => (
                    "run_dir_invalid",
                    "LANE_RUN_DIR must be a direct child of LANE_RUNS_ROOT",
                ),
                RootRefusal::Directory => (
                    "run_dir_invalid",
                    "-d must name a direct child of the selected run directory or runs root",
                ),
            };
            return Some(diagnostic_line(backend_name, kind, detail));
        }
        self.resume_refusal
            .as_ref()
            .map(|refusal| refusal.diagnostic(backend_name))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ResumeRefusal {
    MissingReport(PathBuf),
    StepCollision(PathBuf),
    LiveLock { path: PathBuf, pid: Option<u32> },
    CrashRecovery { path: PathBuf, pid: Option<u32> },
    ContextRecord(String),
    MissingEvents(PathBuf),
    UnreadableEvents(PathBuf),
    ThreadMismatch(PathBuf),
}

impl ResumeRefusal {
    fn diagnostic(&self, backend_name: &str) -> Vec<u8> {
        let mut diagnostic = String::new();
        match self {
            Self::MissingReport(path) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_missing_report: prior step report is missing: {}",
                path.display()
            ),
            Self::StepCollision(path) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_step_collision: step name is already used: {}",
                path.display()
            ),
            Self::LiveLock {
                path,
                pid: Some(pid),
            } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_live_lock: holder pid {pid} is still live: {}",
                path.display()
            ),
            Self::LiveLock { path, pid: None } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_live_lock: a step lock has no valid holder pid: {}",
                path.display()
            ),
            Self::CrashRecovery {
                path,
                pid: Some(pid),
            } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_crash_recovery: failed to recover dead holder pid {pid}: {}",
                path.display()
            ),
            Self::CrashRecovery { path, pid: None } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_crash_recovery: failed to undo an unfinished preparation: {}",
                path.display()
            ),
            Self::ContextRecord(detail) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_context_record: {detail}"
            ),
            Self::MissingEvents(path) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_thread_mismatch: event stream is missing: {}",
                path.display()
            ),
            Self::UnreadableEvents(path) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_thread_mismatch: event stream is unreadable: {}",
                path.display()
            ),
            Self::ThreadMismatch(path) => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_thread_mismatch: first thread id does not match resume session: {}",
                path.display()
            ),
        }
        .expect("writing to a String cannot fail");
        diagnostic.into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CrashRecovery {
    Crashed {
        path: PathBuf,
        pid: u32,
    },
    Reconstructed {
        path: PathBuf,
        pid: u32,
    },
    Settled {
        path: PathBuf,
        pid: u32,
    },
    /// A preparation that never reached the step it was starting was undone,
    /// restoring the prior step. `path` is the cleared lock when a dead
    /// holder left one, and the run directory when the preparation released
    /// its own lock on the way out.
    Unprepared {
        path: PathBuf,
        pid: Option<u32>,
        prior: String,
        step: String,
    },
}

impl CrashRecovery {
    fn diagnostic(&self, backend_name: &str) -> Vec<u8> {
        let mut diagnostic = String::new();
        match self {
            Self::Crashed { path, pid } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_crash_recovered: wrote a CRASHED report for dead holder pid {pid} and cleared lock: {}",
                path.display()
            ),
            Self::Reconstructed { path, pid } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_finish_reconstructed: rebuilt the finished step report from the terminal result event for dead holder pid {pid} and cleared lock: {}",
                path.display()
            ),
            Self::Settled { path, pid } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_settled_report_kept: kept the published report of dead holder pid {pid} and cleared lock: {}",
                path.display()
            ),
            Self::Unprepared {
                path,
                pid: Some(pid),
                prior,
                step,
            } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_preparation_rolled_back: step {step} never started, so {prior} was restored and the lock of dead holder pid {pid} was cleared: {}",
                path.display()
            ),
            Self::Unprepared {
                path,
                pid: None,
                prior,
                step,
            } => writeln!(
                &mut diagnostic,
                "{backend_name}: resume_preparation_rolled_back: step {step} never started, so {prior} was restored: {}",
                path.display()
            ),
        }
        .expect("writing to a String cannot fail");
        diagnostic.into_bytes()
    }
}

/// One monitor action at a sampled awake-time instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonitorDecision {
    /// The child is producing or has not yet met a diagnostic bound.
    Continue,
    /// No event bytes grew for the ratified window.
    Stalled,
    /// Awake duration crossed the diagnostic runaway multiple.
    Runaway,
}

impl MonitorDecision {
    const fn state(self) -> &'static str {
        match self {
            Self::Continue => "growing",
            Self::Stalled => "stalled",
            Self::Runaway => "runaway",
        }
    }
}

/// One injectable pair of process-progress and suspend-inclusive clock values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSample {
    monotonic: u64,
    boottime: u64,
}

impl ClockSample {
    /// Construct one whole-second sample.
    #[must_use]
    pub const fn new(monotonic: u64, boottime: u64) -> Self {
        Self {
            monotonic,
            boottime,
        }
    }

    /// Suspend-inclusive elapsed seconds since an earlier sample.
    #[must_use]
    pub const fn boottime_elapsed_since(self, earlier: Self) -> u64 {
        self.boottime.saturating_sub(earlier.boottime)
    }

    /// Elapsed seconds the host was awake for, since an earlier sample.
    ///
    /// This is the clock that stops while the host sleeps, so it is the one
    /// basis on which a budget and a stall window mean what they say: time a
    /// child had in which to make progress.
    #[must_use]
    pub const fn awake_elapsed_since(self, earlier: Self) -> u64 {
        self.monotonic.saturating_sub(earlier.monotonic)
    }
}

/// Pure clock-divergence arithmetic for detecting host suspension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspendDetector {
    started: ClockSample,
}

impl SuspendDetector {
    /// Begin detection from the step's initial paired clock sample.
    #[must_use]
    pub const fn new(started: ClockSample) -> Self {
        Self { started }
    }

    /// Seconds the host slept during the step, or zero below the tolerance.
    ///
    /// The two clocks diverge by exactly the time the host spent suspended,
    /// which is a measurement and not a fault: the child that was frozen with
    /// the host is still there when it wakes. Sub-tolerance divergence is
    /// whole-second sampling jitter between the two reads rather than sleep,
    /// so it answers zero and nothing records it.
    #[must_use]
    pub const fn gap(self, now: ClockSample) -> u64 {
        let gap = now
            .boottime_elapsed_since(self.started)
            .saturating_sub(now.awake_elapsed_since(self.started));
        if gap > SUSPEND_GAP_THRESHOLD_SECONDS {
            gap
        } else {
            0
        }
    }
}

/// Pure arithmetic state for event-growth, stall, and runaway classification.
///
/// Every instant it is given is awake time (`ClockSample::awake_elapsed_since`).
/// A host that sleeps mid-step therefore moves none of these bounds: the step
/// keeps the budget it had when the host slept, and the no-growth window
/// cannot expire over an interval in which no child could have grown anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetMonitor {
    budget: u64,
    started: u64,
    last_size: u64,
    last_growth: u64,
    last_awaited: u64,
}

impl BudgetMonitor {
    /// Construct a monitor from the current step's own event boundary.
    #[must_use]
    pub const fn new(budget: u64, started: u64, starting_size: u64) -> Self {
        Self {
            budget,
            started,
            last_size: starting_size,
            last_growth: started,
            last_awaited: started,
        }
    }

    /// Record an awaited run observed at an awake instant.
    pub const fn observe_awaited(&mut self, now: u64) {
        if now > self.last_awaited {
            self.last_awaited = now;
        }
    }

    /// Apply one sampled clock and event-size observation.
    #[must_use]
    pub const fn probe(&mut self, now: u64, size: u64) -> MonitorDecision {
        if size > self.last_size {
            self.last_size = size;
            self.last_growth = now;
        }
        let wall = now.saturating_sub(self.started);
        let quiet_basis = if self.last_growth > self.last_awaited {
            self.last_growth
        } else {
            self.last_awaited
        };
        let quiet = now.saturating_sub(quiet_basis);
        if wall > self.budget && quiet > STALL_WINDOW_SECONDS {
            MonitorDecision::Stalled
        } else if wall > self.budget.saturating_mul(RUNAWAY_MULTIPLIER) {
            MonitorDecision::Runaway
        } else {
            MonitorDecision::Continue
        }
    }

    const fn last_size(&self) -> u64 {
        self.last_size
    }

    const fn last_growth(&self) -> u64 {
        self.last_growth
    }

    const fn last_awaited(&self) -> u64 {
        self.last_awaited
    }
}

/// Governed lane verdict vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Natural success at or below budget.
    Ok,
    /// Natural success above budget.
    OverBudget,
    /// Usage or runtime failure.
    Failed,
    /// Historical protocol stall kill; no new report writes this value.
    StalledKilled,
    /// Historical protocol runaway kill; no new report writes this value.
    RunawayKilled,
    /// The pool refused the dispatch, so no work was done.
    RateLimited,
}

impl Verdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::OverBudget => "OVER-BUDGET",
            Self::Failed => "FAILED",
            Self::StalledKilled => "STALLED-KILLED",
            Self::RunawayKilled => "RUNAWAY-KILLED",
            Self::RateLimited => "RATE-LIMITED",
        }
    }
}

/// Complete owned result for one invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneResult {
    status: u8,
    report: Vec<u8>,
    diagnostic: Option<Vec<u8>>,
    stderr_diagnostic: Option<Vec<u8>>,
}

impl LaneResult {
    /// Shared process status returned to the caller.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Classed evidence, when this path failed.
    #[must_use]
    pub fn diagnostic(&self) -> Option<&[u8]> {
        self.diagnostic.as_deref()
    }

    /// Final report bytes.
    #[must_use]
    pub fn report(&self) -> &[u8] {
        &self.report
    }

    /// Classed operator diagnostic published on standard error.
    #[must_use]
    pub fn stderr_diagnostic(&self) -> Option<&[u8]> {
        self.stderr_diagnostic.as_deref()
    }
}

/// Parse short options with the deployed getopts clustering and attachment
/// behavior.
///
/// # Errors
///
/// Returns a usage failure for a missing or invalid option value, an invalid
/// report token, a nonpositive budget, an invalid working directory, a fresh
/// launch without an absolute runs root, a resume continuity failure, or a
/// positional-argument mismatch.
pub fn parse_args<I, A>(arguments: I) -> Result<Config, UsageError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    let budget_hint = budget_hint(&arguments);
    let mut step_letter_refusal = None;
    let config =
        parse_arguments_with_refusal(&arguments, &mut step_letter_refusal).ok_or(UsageError {
            budget: budget_hint,
            resume_refusal: None,
            runs_root_refusal: None,
            step_letter_refusal,
        })?;
    if let Err(refusal) = validate_run_selection(
        &config,
        std::env::var_os("LANE_RUNS_ROOT").as_deref(),
        std::env::var_os("LANE_RUN_DIR").as_deref(),
    ) {
        return Err(UsageError {
            budget: config.budget,
            resume_refusal: None,
            runs_root_refusal: Some(refusal),
            step_letter_refusal: None,
        });
    }
    Ok(config)
}

/// Validate backend-specific lock and thread boundaries for a parsed resume.
///
/// # Errors
///
/// Returns a classed usage error when the durable resume boundary is invalid.
pub fn validate_resume(backend: &dyn Backend, config: &mut Config) -> Result<(), UsageError> {
    if let (Some(session), Some(run_dir)) = (&config.session, &config.resume_dir) {
        match valid_resume_boundary(backend, run_dir, session, &config.name) {
            Ok(recovery) => config.crash_recovery = recovery,
            Err(resume_refusal) => {
                return Err(UsageError {
                    budget: config.budget,
                    resume_refusal: Some(resume_refusal),
                    runs_root_refusal: None,
                    step_letter_refusal: None,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn parse_arguments(arguments: &[OsString]) -> Option<Config> {
    parse_arguments_with_refusal(arguments, &mut None)
}

fn read_step_letter(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 1_048_576 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file of at most 1 MiB",
        ));
    }
    let mut body = Vec::new();
    file.take(1_048_577).read_to_end(&mut body)?;
    if body.len() > 1_048_576 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "letter exceeds 1 MiB",
        ));
    }
    Ok(body)
}

#[allow(clippy::too_many_lines)]
fn parse_arguments_with_refusal(
    arguments: &[OsString],
    step_letter_refusal: &mut Option<String>,
) -> Option<Config> {
    let mut budget = None;
    let mut workdir = std::env::current_dir().ok()?;
    let mut sandbox = OsString::from(DEFAULT_SANDBOX);
    let mut model = None;
    let mut effort = None;
    let mut name = String::from(DEFAULT_NAME);
    let mut session = None;
    let mut resume_dir = None;
    let mut pure = false;
    let mut pool_threshold = DEFAULT_POOL_THRESHOLD;
    let mut ignore_pool = false;
    let mut gateway_lane = None;
    let mut step_letter = None;
    let mut step_digest = None;
    let mut position = 0;

    while position < arguments.len() {
        let bytes = arguments[position].as_os_str().as_bytes();
        if bytes == b"--" {
            position += 1;
            break;
        }
        if bytes == IGNORE_POOL_OPTION {
            ignore_pool = true;
            position += 1;
            continue;
        }
        if bytes == POOL_THRESHOLD_OPTION {
            position += 1;
            pool_threshold = parse_threshold(arguments.get(position)?)?;
            position += 1;
            continue;
        }
        if bytes == GATEWAY_LANE_OPTION {
            position += 1;
            gateway_lane = Some(parse_gateway_lane(arguments.get(position)?)?);
            position += 1;
            continue;
        }
        if bytes == b"--step-letter-sha256" {
            position += 1;
            let digest = arguments.get(position)?.to_str()?;
            if step_digest.is_some()
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                *step_letter_refusal = Some("invalid or repeated step evidence digest".into());
                return None;
            }
            step_digest = Some(digest.to_owned());
            position += 1;
            continue;
        }
        if bytes == b"--step-letter" {
            position += 1;
            let Some(path) = arguments.get(position) else {
                *step_letter_refusal = Some("--step-letter requires a path".into());
                return None;
            };
            if step_letter.is_some() {
                *step_letter_refusal = Some(format!(
                    "--step-letter {}: repeated option",
                    Path::new(path).display()
                ));
                return None;
            }
            let body = read_step_letter(Path::new(path))
                .map_err(|error| {
                    *step_letter_refusal = Some(format!(
                        "--step-letter {}: {error}",
                        Path::new(path).display()
                    ));
                })
                .ok()?;
            step_letter = Some(body);
            position += 1;
            continue;
        }
        if bytes == b"-" || !bytes.starts_with(b"-") {
            break;
        }
        if bytes.len() < 2 {
            break;
        }
        let mut option_position = 1;
        while option_position < bytes.len() {
            let option = bytes[option_position];
            option_position += 1;
            if option == b'P' {
                pure = true;
                continue;
            }
            if !matches!(
                option,
                b't' | b'C' | b's' | b'm' | b'e' | b'n' | b'r' | b'd'
            ) {
                return None;
            }
            let value = if option_position < bytes.len() {
                let value = OsStr::from_bytes(&bytes[option_position..]).to_owned();
                option_position = bytes.len();
                value
            } else {
                position += 1;
                arguments.get(position)?.clone()
            };
            match option {
                b't' => budget = parse_positive_u64(&value),
                b'C' => workdir = PathBuf::from(value),
                b's' => sandbox = value,
                b'm' => model = nonempty(value),
                b'e' => effort = nonempty(value),
                b'n' => name = value.into_string().ok()?,
                b'r' => session = nonempty(value)?.into_string().ok(),
                b'd' => resume_dir = Some(PathBuf::from(value)),
                _ => return None,
            }
            if option == b't' && budget.is_none() {
                return None;
            }
            if matches!(option, b'm' | b'e' | b'r') {
                match option {
                    b'm' if model.is_none() => return None,
                    b'e' if effort.is_none() => return None,
                    b'r' if session.is_none() => return None,
                    _ => {}
                }
            }
        }
        position += 1;
    }

    let positional = &arguments[position..];
    if positional.len() != 1 {
        return None;
    }
    let prompt = if positional[0] == OsStr::new("-") {
        Prompt::Stdin
    } else {
        Prompt::Argument(positional[0].clone())
    };
    let budget = budget?;
    if !workdir.is_dir()
        || !valid_sandbox(&sandbox)
        || !valid_token(&name)
        || effort
            .as_ref()
            .is_some_and(|value| value.to_str().is_none())
    {
        return None;
    }
    if session.is_some() {
        let directory = resume_dir.as_ref()?;
        if !directory.is_dir() || !valid_report_path(directory) {
            return None;
        }
    }
    if let Some(expected) = step_digest {
        use sha2::{Digest as _, Sha256};
        if step_letter.as_ref().is_none_or(|bytes| {
            Sha256::digest(bytes)
                .iter()
                .flat_map(|byte| {
                    let digits = b"0123456789abcdef";
                    [
                        digits[usize::from(byte >> 4)],
                        digits[usize::from(byte & 15)],
                    ]
                })
                .ne(expected.bytes())
        }) {
            *step_letter_refusal =
                Some("step evidence differs from its verified mail delivery".into());
            return None;
        }
    }
    Some(Config {
        budget,
        pool_threshold,
        ignore_pool,
        gateway_lane,
        workdir,
        sandbox,
        model,
        effort,
        name,
        session,
        resume_dir,
        crash_recovery: None,
        pure,
        prompt,
        step_letter,
    })
}

fn nonempty(value: OsString) -> Option<OsString> {
    (!value.is_empty()).then_some(value)
}

fn valid_runs_root(root: &OsStr) -> bool {
    !root.is_empty()
        && Path::new(root).is_absolute()
        && !root
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
}

fn validate_run_selection(
    config: &Config,
    root: Option<&OsStr>,
    selected: Option<&OsStr>,
) -> Result<(), RootRefusal> {
    // A standalone resume retains its recorded directory. Entry launches carry
    // both values, so their resumed step must still belong to the selected run.
    if config.session.is_some() && selected.is_none() {
        return Ok(());
    }
    let root = root
        .filter(|root| valid_runs_root(root))
        .ok_or(RootRefusal::Required)?;
    let base = if let Some(selected) = selected {
        if !valid_runs_root(selected) || Path::new(selected).parent() != Some(Path::new(root)) {
            return Err(RootRefusal::Selected);
        }
        Path::new(selected)
    } else {
        Path::new(root)
    };
    if let Some(directory) = &config.resume_dir
        && (!valid_runs_root(directory.as_os_str()) || directory.parent() != Some(base))
    {
        return Err(RootRefusal::Directory);
    }
    Ok(())
}

fn parse_positive_u64(value: &OsStr) -> Option<u64> {
    let text = value.to_str()?;
    let parsed = text.parse::<u64>().ok()?;
    (parsed > 0).then_some(parsed)
}

/// A utilization threshold is a fraction of one window, so nothing outside
/// the closed unit interval is a threshold at all.
fn parse_threshold(value: &OsStr) -> Option<f64> {
    let parsed = value.to_str()?.parse::<f64>().ok()?;
    (parsed.is_finite() && (0.0..=1.0).contains(&parsed)).then_some(parsed)
}

fn parse_gateway_lane(value: &OsStr) -> Option<String> {
    let lane = value.to_str()?;
    (!lane.is_empty()
        && !matches!(lane, "." | "..")
        && lane
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then(|| lane.to_owned())
}

fn budget_hint(arguments: &[OsString]) -> u64 {
    let mut position = 0;
    while position < arguments.len() {
        let bytes = arguments[position].as_os_str().as_bytes();
        if bytes == b"--" || bytes == b"-" || !bytes.starts_with(b"-") {
            break;
        }
        if bytes == IGNORE_POOL_OPTION {
            position += 1;
            continue;
        }
        if bytes == POOL_THRESHOLD_OPTION {
            position += 2;
            continue;
        }
        if bytes == GATEWAY_LANE_OPTION
            || bytes == b"--step-letter"
            || bytes == b"--step-letter-sha256"
        {
            position += 2;
            continue;
        }
        let mut option_position = 1;
        while option_position < bytes.len() {
            let option = bytes[option_position];
            option_position += 1;
            if option == b'P' {
                continue;
            }
            if !matches!(
                option,
                b't' | b'C' | b's' | b'm' | b'e' | b'n' | b'r' | b'd'
            ) {
                return 0;
            }
            let value = if option_position < bytes.len() {
                let value = OsStr::from_bytes(&bytes[option_position..]);
                option_position = bytes.len();
                Some(value)
            } else {
                position += 1;
                arguments.get(position).map(OsString::as_os_str)
            };
            if option == b't' {
                return value.and_then(parse_positive_u64).unwrap_or(0);
            }
        }
        position += 1;
    }
    0
}

fn valid_sandbox(value: &OsStr) -> bool {
    matches!(
        value.to_str(),
        Some("read-only" | "workspace-write" | "danger-full-access")
    )
}

fn valid_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_report_path(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        !text.is_empty() && !text.bytes().any(|byte| byte.is_ascii_whitespace())
    })
}

fn valid_resume_boundary(
    backend: &dyn Backend,
    run_dir: &Path,
    session: &str,
    name: &str,
) -> Result<Option<CrashRecovery>, ResumeRefusal> {
    let recovery = match recover_dead_lock(backend, run_dir)? {
        Some(recovery) => Some(recovery),
        // A preparation that fails before it removes the report releases its
        // own lock on the way out, so the mismatch it leaves behind has no
        // dead holder to find. The state is the same and so is the repair.
        None => roll_back_unprepared(run_dir, None)?,
    };
    let report = run_dir.join("run-report.txt");
    if !report.is_file() {
        return Err(ResumeRefusal::MissingReport(report));
    }
    let step_input = run_dir.join(format!("step-{name}.txt"));
    if step_input.exists() {
        return Err(ResumeRefusal::StepCollision(step_input));
    }
    let history = run_dir.join("steps").join(name);
    if history.exists() {
        return Err(ResumeRefusal::StepCollision(history));
    }
    let events_path = run_dir.join("events.jsonl");
    let events = match fs::read(&events_path) {
        Ok(events) => events,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ResumeRefusal::MissingEvents(events_path));
        }
        Err(_error) => return Err(ResumeRefusal::UnreadableEvents(events_path)),
    };
    if backend.thread_id(&events).as_deref() != Some(session) {
        return Err(ResumeRefusal::ThreadMismatch(events_path));
    }
    let thread_path = run_dir.join(THREAD_ID_FILE);
    // The events already match the session. Only a present, disagreeing sidecar
    // conflicts; the after-child writer or a later resume can refill a sidecar
    // whose read or write failed.
    match write_thread_id(run_dir, session) {
        Ok(false) => Err(ResumeRefusal::ThreadMismatch(thread_path)),
        Ok(true) | Err(_) => Ok(()),
    }?;
    Ok(recovery)
}

fn recover_dead_lock(
    backend: &dyn Backend,
    run_dir: &Path,
) -> Result<Option<CrashRecovery>, ResumeRefusal> {
    let path = run_dir.join(backend.lock_file());
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_error) => return Err(ResumeRefusal::LiveLock { path, pid: None }),
    };
    let (pid, child) = parse_lock(&bytes).ok_or_else(|| ResumeRefusal::LiveLock {
        path: path.clone(),
        pid: None,
    })?;
    if process_exists(pid) {
        return Err(ResumeRefusal::LiveLock {
            path,
            pid: Some(pid),
        });
    }
    // A dead driver whose child is still alive is not a crashed step: the work
    // is still being done, the transcript is still growing, and a CRASHED
    // report written over it would settle a step that has not ended and
    // publish a finish nobody reached. The lock is live for as long as the
    // process it names is, whichever of the two that is.
    if let Some(child) = child.filter(|child| process_exists(*child)) {
        return Err(ResumeRefusal::LiveLock {
            path,
            pid: Some(child),
        });
    }
    let report_path = run_dir.join("run-report.txt");
    let rollback = if report_path.is_file() {
        // A report naming another step settles nothing about the one
        // `.step-name` now names, so the driver died inside a preparation and
        // the lock goes with the preparation it was holding. Restore its
        // boundaries before reconciling the event-side context record.
        roll_back_unprepared(run_dir, Some((&path, pid)))?
    } else {
        None
    };
    if run_dir.join("events.jsonl").exists() {
        ContextTracker::reconcile(backend, &run_dir.join("events.jsonl"), run_dir)
            .map_err(|error| ResumeRefusal::ContextRecord(error.to_string()))?;
    }
    if let Some(recovery) = rollback {
        return Ok(Some(recovery));
    }
    if report_path.is_file() {
        // The step published before its driver died, so its own report is the
        // settled record of it. Only the lock is stale.
        fs::remove_file(&path)
            .and_then(|()| sync_directory(run_dir))
            .map_err(|_error| ResumeRefusal::CrashRecovery {
                path: path.clone(),
                pid: Some(pid),
            })?;
        return Ok(Some(CrashRecovery::Settled { path, pid }));
    }
    let prior_name = current_step_name(run_dir).ok_or_else(|| ResumeRefusal::CrashRecovery {
        path: path.clone(),
        pid: Some(pid),
    })?;
    let run_text = run_dir
        .to_str()
        .ok_or_else(|| ResumeRefusal::CrashRecovery {
            path: path.clone(),
            pid: Some(pid),
        })?;
    if let Some((events, result)) = transcript_terminal_result(backend, run_dir, false) {
        reconstruct_finish(
            backend,
            run_dir,
            pid,
            &prior_name,
            run_text,
            &events,
            result,
        )
        .map_err(|_error| ResumeRefusal::CrashRecovery {
            path: path.clone(),
            pid: Some(pid),
        })?;
        return Ok(Some(CrashRecovery::Reconstructed { path, pid }));
    }
    let report = crashed_report_bytes(&prior_name, pid, run_text);
    atomic_write(&report_path, &report)
        .and_then(|()| remove_optional(run_dir.join(RECONSTRUCTED_FILE)))
        .and_then(|()| fs::remove_file(&path))
        .and_then(|()| sync_directory(run_dir))
        .map_err(|_error| ResumeRefusal::CrashRecovery {
            path: path.clone(),
            pid: Some(pid),
        })?;
    Ok(Some(CrashRecovery::Crashed { path, pid }))
}

/// Undo a preparation that never reached the step it was starting.
///
/// A resume writes `.step-name`, `.event-start`, and `.started-at` for its new
/// step and only then removes the prior step's report, and no child runs until
/// that removal has happened. A surviving report whose `lane=` disagrees with
/// `.step-name` therefore says exactly one thing: a driver stopped inside that
/// window, and the named step never started. Settling the report under that
/// name would file the prior step's outcome as the new step's, and the resume
/// that followed would archive the prior step's report a second time under a
/// directory named for a step that never ran.
///
/// The undo is the preparation's own archive read backwards. It holds the
/// offset `.event-start` carried before the flip and the sidecars the
/// preparation had already removed, which are put back first; what is left is
/// a copy of a report that still stands, so discarding the archive then loses
/// nothing, and the retried preparation rebuilds it from the same bytes. The
/// archive cannot predate this preparation, because a preparation refuses to
/// start when the prior step's history already exists.
///
/// Restoring `.step-name` last makes it the commit point: until then the
/// mismatch is still on disk and the undo can simply run again. An
/// interruption after it and before the lock goes leaves the settled state, so
/// the next invocation finds a report that agrees with `.step-name` and says
/// it kept a settled report rather than that it undid a preparation. The disk
/// is right either way, and that line is the honest account of what it found.
fn roll_back_unprepared(
    run_dir: &Path,
    holder: Option<(&Path, u32)>,
) -> Result<Option<CrashRecovery>, ResumeRefusal> {
    let Some((prior, step)) = unprepared_step(run_dir) else {
        return Ok(None);
    };
    let path = holder.map_or_else(|| run_dir.to_path_buf(), |(lock, _pid)| lock.to_path_buf());
    let pid = holder.map(|(_lock, pid)| pid);
    undo_preparation(run_dir, &prior, &step)
        .and_then(|()| match holder {
            Some((lock, _pid)) => fs::remove_file(lock),
            None => Ok(()),
        })
        .and_then(|()| sync_directory(run_dir))
        .map_err(|_error| ResumeRefusal::CrashRecovery {
            path: path.clone(),
            pid,
        })?;
    Ok(Some(CrashRecovery::Unprepared {
        path,
        pid,
        prior,
        step,
    }))
}

/// The prior and new step names of a preparation that never finished.
fn unprepared_step(run_dir: &Path) -> Option<(String, String)> {
    let step = recorded_step_name(run_dir)?;
    let prior = report_lane(run_dir)?;
    (prior != step).then_some((prior, step))
}

/// The step name the run directory records, without the report's fallback.
fn recorded_step_name(run_dir: &Path) -> Option<String> {
    let bytes = fs::read(run_dir.join(STEP_NAME_FILE)).ok()?;
    let name = std::str::from_utf8(&bytes).ok()?.trim_end_matches('\n');
    valid_token(name).then(|| name.to_owned())
}

/// The lane the standing report names.
///
/// `current_step_name` answers a different question — which name the run
/// directory goes by, from whichever file still records it — and its fallback
/// to this same field would hide the disagreement these two are read for.
fn report_lane(run_dir: &Path) -> Option<String> {
    let report = fs::read_to_string(run_dir.join("run-report.txt")).ok()?;
    let lane = report
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("lane="))?;
    valid_token(lane).then(|| lane.to_owned())
}

/// Return the run directory to the state the prior step settled in.
///
/// The preparation flips `.step-name`, `.event-start`, and `.started-at` for
/// its new step; the undo restores the prior step's markers before retrying.
///
/// The sidecars come back before the history goes, because the preparation
/// removes them from the run directory inside this same window: a driver
/// stopped after that removal leaves the prior step's answer, follower cursor,
/// and evidence standing only inside the archive, and discarding the archive
/// then would destroy them for good and silently — the retried preparation
/// would archive absences, and a follower reading no offset would start again
/// from the beginning of the transcript. Each is put back only where the run
/// directory lacks it, so a file the removal had not yet reached keeps the
/// bytes it has.
fn undo_preparation(run_dir: &Path, prior: &str, step: &str) -> io::Result<()> {
    let history = run_dir.join("steps").join(prior);
    if let Ok(start) = fs::read(history.join("event-start.txt")) {
        atomic_write(&run_dir.join(EVENT_START_FILE), &start)?;
    }
    match fs::read(history.join("started-at.txt")) {
        Ok(started_at) => atomic_write(&run_dir.join(STARTED_AT_FILE), &started_at)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // `event-start.txt` is archived after the step start, so only an
            // archive still holding it can say the prior step had none.
            if history.join("event-start.txt").exists() {
                remove_optional(run_dir.join(STARTED_AT_FILE))?;
            }
        }
        Err(error) => return Err(error),
    }
    for (archived, live) in [
        ("last-message.txt", "last-message.txt"),
        ("feed-offset.txt", ".feed-offset"),
        ("reconstructed.txt", RECONSTRUCTED_FILE),
        (RATE_LIMIT_FILE, RATE_LIMIT_FILE),
        (CAPACITY_ATTEMPTS_FILE, CAPACITY_ATTEMPTS_FILE),
        ("kill-evidence.txt", "kill-evidence.txt"),
    ] {
        restore_optional(&history.join(archived), &run_dir.join(live))?;
    }
    if history.exists() {
        fs::remove_dir_all(&history)?;
    }
    remove_optional(run_dir.join(format!("step-{step}.txt")))?;
    remove_optional(run_dir.join(format!("step-{step}.prompt.txt")))?;
    atomic_write(
        &run_dir.join(STEP_NAME_FILE),
        format!("{prior}\n").as_bytes(),
    )
}

/// Put one archived sidecar back when the run directory no longer carries it.
///
/// The inverse of `archive_optional`: an archive with no surviving original is
/// the only copy left, and one that still has its original is already settled.
fn restore_optional(source: &Path, destination: &Path) -> io::Result<()> {
    if destination.exists() {
        return Ok(());
    }
    match fs::read(source) {
        Ok(bytes) => atomic_write(destination, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// The terminal result of the step's own transcript region, with that region.
fn transcript_terminal_result(
    backend: &dyn Backend,
    run_dir: &Path,
    record_thread: bool,
) -> Option<(Vec<u8>, TerminalResult)> {
    let events = step_events(run_dir, record_thread.then_some(backend))?;
    let result = backend.terminal_result(&events)?;
    Some((events, result))
}

/// The event bytes this step itself produced.
///
/// A step's events begin where `.event-start` records; everything before that
/// offset belongs to earlier steps of the same run. Reading the whole
/// cumulative stream would let an earlier step's terminal result stand in for
/// this step's finish, so a missing, unreadable, or out-of-range start bounds
/// nothing and yields no region at all.
fn step_events(run_dir: &Path, backend: Option<&dyn Backend>) -> Option<Vec<u8>> {
    let recorded = fs::read(run_dir.join(EVENT_START_FILE)).ok()?;
    let start = std::str::from_utf8(&recorded)
        .ok()?
        .trim_end_matches('\n')
        .parse::<usize>()
        .ok()?;
    let events = fs::read(run_dir.join("events.jsonl")).ok()?;
    if let Some(backend) = backend
        && let Some(thread_id) = backend.thread_id(&events)
    {
        let _ignored = write_thread_id(run_dir, &thread_id);
    }
    events.get(start..).map(<[u8]>::to_vec)
}

fn attempt_events(path: &Path, start: u64) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let end = file.metadata().ok()?.len();
    let tail = start.max(end.saturating_sub(1_048_576));
    file.seek(SeekFrom::Start(tail)).ok()?;
    let mut bytes = Vec::new();
    file.take(end.saturating_sub(tail))
        .read_to_end(&mut bytes)
        .ok()?;
    if tail > start {
        // Never classify a fragment cut out of an oversized JSON line.
        let boundary = bytes.iter().position(|byte| *byte == b'\n')?;
        bytes.drain(..=boundary);
    }
    Some(bytes)
}

/// Settle the finish the dead driver reached but never published.
///
/// The child's own result event supplies the exit and verdict, so the step
/// keeps the outcome the transcript already carries instead of paying for the
/// whole step again. Both the result and the message come from the step's own
/// region of the transcript, so nothing an earlier step said can be published
/// as this one's. The run directory records no budget for the finished step,
/// so this report cannot judge over budget and states the budget it knows:
/// none. The sidecar records how the wall figure was derived, because a
/// derived wall is not a measured one.
fn reconstruct_finish(
    backend: &dyn Backend,
    run_dir: &Path,
    pid: u32,
    prior_name: &str,
    run_text: &str,
    events: &[u8],
    result: TerminalResult,
) -> io::Result<()> {
    let (status, verdict) = result.finish();
    let (wall, derivation) =
        result
            .duration_ms()
            .map_or((0, WallDerivation::Unknown), |duration| {
                (
                    duration / MILLISECONDS_PER_SECOND,
                    WallDerivation::DurationMs,
                )
            });
    let stamp = utc_stamp().unwrap_or_else(|| String::from("unknown"));
    publish_last_message(backend, run_dir, events)?;
    atomic_write(
        &run_dir.join(RECONSTRUCTED_FILE),
        &reconstructed_sidecar_bytes(result, derivation, wall, pid, &stamp),
    )?;
    atomic_write(
        &run_dir.join("run-report.txt"),
        &report_bytes(prior_name, status, wall, 0, verdict, 0, run_text),
    )?;
    fs::remove_file(run_dir.join(backend.lock_file()))?;
    sync_directory(run_dir)
}

fn process_exists(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// Read the prompt exactly as the deployed wrapper does.
///
/// An argument prompt receives one LF. Standard-input bytes are retained
/// exactly.
///
/// # Errors
///
/// Returns an I/O error when standard input cannot be completely read.
pub fn read_prompt(config: &Config) -> io::Result<Vec<u8>> {
    match &config.prompt {
        Prompt::Argument(argument) => {
            let mut bytes = argument.as_os_str().as_bytes().to_vec();
            bytes.push(b'\n');
            Ok(bytes)
        }
        Prompt::Stdin => {
            let mut bytes = Vec::new();
            io::stdin().lock().read_to_end(&mut bytes)?;
            Ok(bytes)
        }
    }
}

/// Execute one fresh or resume step and settle its terminal marker.
#[must_use]
pub fn execute(backend: &dyn Backend, config: &Config, prompt: &[u8]) -> LaneResult {
    let Ok(mut clock) = Clock::from_environment() else {
        return fallback_result(
            1,
            config.budget,
            runtime_diagnostic(backend.name()),
            config.name(),
            "unknown",
            0,
        );
    };
    execute_with_clock(backend, config, prompt, &mut clock)
}

#[allow(clippy::too_many_lines)]
fn execute_with_clock(
    backend: &dyn Backend,
    config: &Config,
    prompt: &[u8],
    clock: &mut Clock,
) -> LaneResult {
    let execution_evidence = match backend.execution_evidence() {
        Ok(evidence) => evidence,
        Err(detail) => {
            let mut refusal =
                fallback_report(2, config.budget, config.name(), refused_dir(config), 0);
            refusal.stderr_diagnostic =
                Some(diagnostic_line(backend.name(), "missing-setting", &detail));
            return refusal;
        }
    };
    // The pool state is read before anything is allocated, so a dispatch the
    // window would refuse leaves no run directory behind it. The refusal is
    // still a terminal path of an agent-text command, so it ends in one
    // report line naming whatever directory the step can name, with the
    // classed reason on standard error beside it.
    if let Some(diagnostic) = pool_refusal(backend, config) {
        let mut refusal = fallback_report(2, config.budget, config.name(), refused_dir(config), 0);
        refusal.stderr_diagnostic = Some(diagnostic);
        return refusal;
    }
    let Ok(mut run_dir) = resolve_run_dir(config) else {
        return fallback_result(
            1,
            config.budget,
            runtime_diagnostic(backend.name()),
            config.name(),
            "unknown",
            0,
        );
    };
    let mut run_text = match run_dir.to_str() {
        Some(text) if valid_report_path(&run_dir) => text.to_owned(),
        _ => {
            return fallback_result(
                1,
                config.budget,
                runtime_diagnostic(backend.name()),
                config.name(),
                "unknown",
                0,
            );
        }
    };
    let fresh = config.session.is_none();
    if fresh {
        let exact = config.resume_dir.is_some();
        run_dir = match create_fresh_run_dir(&run_dir, exact) {
            Ok(allocated) => allocated,
            Err(error) if exact && error.kind() == io::ErrorKind::AlreadyExists => {
                let mut refusal = fallback_report(2, config.budget, config.name(), "unknown", 0);
                refusal.stderr_diagnostic = Some(diagnostic_line(
                    backend.name(),
                    "run_dir_exists",
                    "directory exists",
                ));
                return refusal;
            }
            Err(_error) => {
                return fallback_result(
                    1,
                    config.budget,
                    runtime_diagnostic(backend.name()),
                    config.name(),
                    "unknown",
                    0,
                );
            }
        };
        run_text = run_dir.to_string_lossy().into_owned();
    }

    let Ok(lock) = StepLock::acquire(backend, &run_dir) else {
        let result = fallback_result(
            1,
            config.budget,
            runtime_diagnostic(backend.name()),
            config.name(),
            &run_text,
            0,
        );
        if fresh {
            let _ignored = atomic_write(&run_dir.join("run-report.txt"), result.report());
        }
        return result;
    };
    let prepared = if fresh {
        prepare_fresh(config, prompt, &run_dir)
    } else {
        prepare_resume(config, prompt, &run_dir)
    };
    if let Err(kind) = prepared {
        let status = kind.status();
        let report = report_bytes(
            config.name(),
            status,
            0,
            config.budget,
            Verdict::Failed,
            0,
            &run_text,
        );
        if fresh || kind.live() {
            let _ignored = atomic_write(&run_dir.join("run-report.txt"), &report);
        }
        drop(lock);
        return LaneResult {
            status,
            report,
            diagnostic: Some(kind.diagnostic(backend.name())),
            stderr_diagnostic: None,
        };
    }

    if let Some(evidence) = &execution_evidence
        && let Err(error) = atomic_write(
            &run_dir.join("backend-settings.json"),
            evidence.to_string().as_bytes(),
        )
    {
        return fallback_result(
            1,
            config.budget,
            diagnostic_line(backend.name(), "settings-evidence", &error.to_string()),
            config.name(),
            &run_text,
            0,
        );
    }
    let mut effective = config.clone();
    if effective.pure && backend.configure_pure(&mut effective, &run_dir).is_err() {
        let report = report_bytes(
            effective.name(),
            2,
            0,
            effective.budget,
            Verdict::Failed,
            0,
            &run_text,
        );
        let _ignored = atomic_write(&run_dir.join("run-report.txt"), &report);
        drop(lock);
        return LaneResult {
            status: 2,
            report,
            diagnostic: Some(usage_diagnostic(backend.name())),
            stderr_diagnostic: None,
        };
    }

    let Ok(start) = clock.sample() else {
        let report = report_bytes(
            effective.name(),
            1,
            0,
            effective.budget,
            Verdict::Failed,
            0,
            &run_text,
        );
        let _ignored = atomic_write(&run_dir.join("run-report.txt"), &report);
        drop(lock);
        return LaneResult {
            status: 1,
            report,
            diagnostic: Some(runtime_diagnostic(backend.name())),
            stderr_diagnostic: None,
        };
    };
    let events_path = run_dir.join("events.jsonl");
    let starting_size = file_size(&events_path);
    let stderr_path = run_dir.join("stderr.txt");
    let mut stderr_start = file_size(&stderr_path);
    let mut child_result = run_child(
        backend,
        &effective,
        &run_dir,
        &lock,
        start,
        starting_size,
        clock,
    );
    let mut attempts = 1_u8;
    let mut attempt_start = starting_size;
    let mut capacity_log = String::new();
    let mut capacity_seen = false;
    let mut capacity_waits = Vec::new();
    let mut capacity_end = "failed".to_owned();
    let mut suspend_resumes = 0_u8;
    let mut suspend_start = start;
    let mut suspend_log = String::new();
    loop {
        clock.fixture_boundary("suspend-before-resume");
        let resumed = resume_after_suspend(
            backend,
            &mut effective,
            &run_dir,
            &child_result,
            suspend_start,
            clock.sample(),
            start,
            &mut suspend_resumes,
            &mut suspend_log,
        );
        match resumed {
            Ok(Some(now)) => {
                suspend_start = now;
                attempt_start = file_size(&events_path);
                stderr_start = file_size(&stderr_path);
                child_result = run_child(
                    backend,
                    &effective,
                    &run_dir,
                    &lock,
                    start,
                    attempt_start,
                    clock,
                );
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                capacity_end.clone_from(&error);
                child_result = Err(error);
                break;
            }
        }
        let capacity = matches!(&child_result, Ok(ChildResult::Natural(status)) if !status.success())
            && step_attempt_wall(backend, &run_dir).is_none()
            && attempt_events(&events_path, attempt_start)
                .is_some_and(|events| backend.retryable_capacity(&events));
        capacity_seen |= capacity;
        if capacity {
            "model-at-capacity; bound-reached"
        } else {
            "failed"
        }
        .clone_into(&mut capacity_end);
        if capacity {
            clock.fixture_boundary("capacity-before-retry");
            if attempts < CAPACITY_MAX_ATTEMPTS && forwarded_signal().is_some() {
                capacity_end = "model-at-capacity; retry-stopped".into();
                break;
            }
        }
        if capacity && attempts < CAPACITY_MAX_ATTEMPTS {
            let delay = CAPACITY_BACKOFF_SECONDS[usize::from(attempts - 1)];
            let Ok(now) = clock.sample() else {
                capacity_end = "clock sample failed".into();
                child_result = Err("clock sample failed".into());
                break;
            };
            if effective
                .budget
                .saturating_sub(now.awake_elapsed_since(start))
                <= delay
            {
                capacity_end = "model-at-capacity; budget-exhausted".into();
                break;
            }
            match prepare_same_thread_resume(backend, &mut effective, &run_dir, "capacity") {
                Ok(true) => {}
                Ok(false) => {
                    capacity_end = "model-at-capacity; thread-unavailable".into();
                    break;
                }
                Err(error) => {
                    capacity_end.clone_from(&error);
                    child_result = Err(error);
                    break;
                }
            }
            let _ignored = writeln!(
                &mut capacity_log,
                "attempt={attempts} result=model-at-capacity retry_in={delay}s"
            );
            let _ignored = atomic_write(
                &run_dir.join(CAPACITY_ATTEMPTS_FILE),
                capacity_log.as_bytes(),
            );
            let _ignored = writeln!(
                io::stderr().lock(),
                "{}: model at capacity; attempt {attempts}/{CAPACITY_MAX_ATTEMPTS}; retry in {delay}s",
                backend.name()
            );
            let waited = clock.wait(delay);
            capacity_waits.push(waited);
            let _ignored = writeln!(&mut capacity_log, "attempt={attempts} waited={waited}s");
            let _ignored = atomic_write(
                &run_dir.join(CAPACITY_ATTEMPTS_FILE),
                capacity_log.as_bytes(),
            );
            clock.fixture_boundary("capacity-wait-recorded");
            let Ok(retry_start) = clock.sample() else {
                capacity_end = "clock sample failed".into();
                child_result = Err("clock sample failed".into());
                break;
            };
            if forwarded_signal().is_some()
                || retry_start.awake_elapsed_since(start) >= effective.budget
            {
                capacity_end = "model-at-capacity; retry-stopped".into();
                break;
            }
            attempts += 1;
            attempt_start = file_size(&events_path);
            stderr_start = file_size(&stderr_path);
            suspend_start = retry_start;
            child_result = run_child(
                backend,
                &effective,
                &run_dir,
                &lock,
                start,
                attempt_start,
                clock,
            );
            continue;
        }
        break;
    }
    if capacity_seen {
        let result = if matches!(&child_result, Ok(ChildResult::Natural(status)) if status.success())
        {
            "completed"
        } else {
            &capacity_end
        };
        let _ignored = writeln!(&mut capacity_log, "attempt={attempts} result={result}");
        let _ignored = writeln!(
            &mut capacity_log,
            "capacity_attempts={attempts} capacity_waits={}s",
            capacity_wait_list(&capacity_waits)
        );
        let _ignored = atomic_write(
            &run_dir.join(CAPACITY_ATTEMPTS_FILE),
            capacity_log.as_bytes(),
        );
        let _ignored = writeln!(
            io::stderr().lock(),
            "{}: capacity retry attempt {attempts}/{CAPACITY_MAX_ATTEMPTS}: {result}",
            backend.name()
        );
    }
    // Wall is awake time and the gap is what the host slept, so the two sum to
    // real elapsed while the budget comparison stays a statement about time the
    // child actually had.
    let (wall, suspend_gap) = clock.sample().map_or_else(
        |()| {
            child_result = Err("clock sample failed".into());
            (0, 0)
        },
        |finished| {
            (
                finished.awake_elapsed_since(start),
                SuspendDetector::new(start).gap(finished),
            )
        },
    );
    // A child that reached its own finish owes its readers the message that
    // finish carried, including when an explicit stop reaped an idle child.
    let finished = matches!(
        &child_result,
        Ok(ChildResult::Natural(_) | ChildResult::Terminal(_))
    );
    // Only the step's own region can speak for this step: an earlier step's
    // refusal is not this one's, and a whole cumulative transcript would
    // supply one.
    let step_region = step_events(&run_dir, Some(backend));
    let failed_result = matches!(&child_result, Ok(ChildResult::Natural(exit)) if !exit.success())
        || matches!(&child_result, Ok(ChildResult::Terminal(result)) if result.is_error());
    let rejection = (failed_result && step_attempt_wall(backend, &run_dir).is_none())
        .then(|| {
            step_region
                .as_ref()
                .and_then(|events| backend.rate_limit_rejection(events))
        })
        .flatten();
    if let Some(rejection) = &rejection {
        let _ignored = atomic_write(
            &run_dir.join(RATE_LIMIT_FILE),
            &rate_limit_evidence(rejection.state()),
        );
    }
    if let Some(state) = step_region
        .as_ref()
        .and_then(|events| backend.rate_limit_state(events))
    {
        let _ignored = record_pool_state(backend, &state, &run_text);
    }
    let (status, verdict, diagnostic, mut stderr_diagnostic) = match child_result {
        Ok(ChildResult::Natural(exit)) if exit.success() && wall > effective.budget => {
            (0, Verdict::OverBudget, None, None)
        }
        Ok(ChildResult::Natural(exit)) if exit.success() => (0, Verdict::Ok, None, None),
        Ok(ChildResult::Terminal(result)) if !result.is_error() && wall > effective.budget => {
            (0, Verdict::OverBudget, None, None)
        }
        Ok(ChildResult::Terminal(result)) if !result.is_error() => (0, Verdict::Ok, None, None),
        Ok(ChildResult::Natural(_) | ChildResult::Terminal(_)) => {
            let tail = step_stderr_diagnostic(backend.name(), &stderr_path, stderr_start);
            rejection
                .as_ref()
                .map_or((1, Verdict::Failed, tail, None), |rejection| {
                    (
                        1,
                        Verdict::RateLimited,
                        None,
                        Some(rate_limited_diagnostic(backend.name(), rejection.state())),
                    )
                })
        }
        Ok(ChildResult::Terminated) => (1, Verdict::Failed, None, None),
        Err(cause) => {
            let mut diagnostic = runtime_diagnostic(backend.name());
            diagnostic.extend_from_slice(
                format!("{}: runtime_failure: {cause}\n", backend.name()).as_bytes(),
            );
            let _ignored = OpenOptions::new()
                .create(true)
                .append(true)
                .open(run_dir.join("stderr.txt"))
                .and_then(|mut file| file.write_all(&diagnostic));
            (1, Verdict::Failed, Some(diagnostic), None)
        }
    };

    if finished {
        match settle_last_message(backend, &run_dir, step_region.as_deref()) {
            MessageSettlement::Settled => {}
            MessageSettlement::Withheld => stderr_diagnostic
                .get_or_insert_default()
                .extend_from_slice(&withheld_message_diagnostic(backend.name())),
            MessageSettlement::Unwritten { path, error } => stderr_diagnostic
                .get_or_insert_default()
                .extend_from_slice(&unwritten_message_diagnostic(backend.name(), &path, &error)),
        }
    }
    let mut report = report_bytes(
        effective.name(),
        status,
        wall,
        effective.budget,
        verdict,
        suspend_gap,
        &run_text,
    );
    annotate_suspend_resumes(&mut report, suspend_resumes);
    annotate_capacity_attempts(&mut report, capacity_seen, attempts, &capacity_waits);
    if failed_result && let Some(end) = step_attempt_wall(backend, &run_dir) {
        end.annotate_report(&mut report);
    }
    if let Some(evidence) = &execution_evidence {
        execution_settings::annotate(&mut report, evidence);
    }
    let publication = atomic_write(&run_dir.join("run-report.txt"), &report);
    drop(lock);
    if publication.is_err() {
        let mut failed_report = report_bytes(
            effective.name(),
            1,
            wall,
            effective.budget,
            Verdict::Failed,
            suspend_gap,
            &run_text,
        );
        annotate_suspend_resumes(&mut failed_report, suspend_resumes);
        annotate_capacity_attempts(&mut failed_report, capacity_seen, attempts, &capacity_waits);
        if failed_result && let Some(end) = step_attempt_wall(backend, &run_dir) {
            end.annotate_report(&mut failed_report);
        }
        if let Some(evidence) = &execution_evidence {
            execution_settings::annotate(&mut failed_report, evidence);
        }
        return LaneResult {
            status: 1,
            report: failed_report,
            diagnostic: Some(runtime_diagnostic(backend.name())),
            stderr_diagnostic: None,
        };
    }
    LaneResult {
        status,
        report,
        diagnostic,
        stderr_diagnostic,
    }
}

fn capacity_wait_list(waits: &[u64]) -> String {
    if waits.is_empty() {
        return "0".into();
    }
    waits
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn annotate_capacity_attempts(report: &mut Vec<u8>, seen: bool, attempts: u8, waits: &[u64]) {
    if seen {
        if report.last() == Some(&b'\n') {
            report.pop();
        }
        let _ignored = writeln!(
            report,
            " capacity_attempts={attempts} capacity_waits={}s",
            capacity_wait_list(waits)
        );
    }
}

fn annotate_suspend_resumes(report: &mut Vec<u8>, count: u8) {
    if count > 0 {
        if report.last() == Some(&b'\n') {
            report.pop();
        }
        let _ignored = writeln!(report, " suspend_resumes={count}");
    }
}

// Keep the step boundary and lock: this is another vendor invocation of the
// same saved duty, not a new externally named step prepared by prepare_resume.
#[allow(clippy::too_many_arguments)]
fn resume_after_suspend(
    backend: &dyn Backend,
    config: &mut Config,
    run_dir: &Path,
    child: &Result<ChildResult, String>,
    attempt_start: ClockSample,
    now: Result<ClockSample, ()>,
    step_start: ClockSample,
    count: &mut u8,
    log: &mut String,
) -> Result<Option<ClockSample>, String> {
    let now = now.map_err(|()| "clock sample failed".to_owned())?;
    let gap = SuspendDetector::new(attempt_start).gap(now);
    if gap == 0
        || !matches!(child, Ok(ChildResult::Natural(status)) if status.code().is_some())
        || forwarded_signal().is_some()
        || step_attempt_wall(backend, run_dir).is_some()
        || *count >= 3
        || now.awake_elapsed_since(step_start) >= config.budget
    {
        return Ok(None);
    }
    let Some(events) = step_events(run_dir, Some(backend)) else {
        return Ok(None);
    };
    if events
        .split_inclusive(|byte| *byte == b'\n')
        .any(|line| backend.terminal_result(line).is_some())
    {
        return Ok(None);
    }
    if !prepare_same_thread_resume(backend, config, run_dir, "suspend")? {
        return Ok(None);
    }
    let next = *count + 1;
    let _ignored = writeln!(
        log,
        "suspend_resumes={next} suspend_gap={gap}s awake={}s",
        now.awake_elapsed_since(step_start)
    );
    atomic_write(
        &run_dir.join(format!("suspend-resumes-{}.txt", config.name)),
        log.as_bytes(),
    )
    .map_err(|error| format!("suspend resume record: {error}"))?;
    *count = next;
    Ok(Some(now))
}

// Both automatic recoveries keep the saved duty and step boundary. In
// particular, a fresh dispatch becomes a resume, never another fresh thread.
fn prepare_same_thread_resume(
    backend: &dyn Backend,
    config: &mut Config,
    run_dir: &Path,
    recovery: &str,
) -> Result<bool, String> {
    let Some(session) = step_events(run_dir, Some(backend))
        .and_then(|events| backend.thread_id(&events))
        .or_else(|| config.session.clone())
    else {
        return Ok(false);
    };
    if config.session.is_none() && config.step_letter.is_none() {
        let brief = fs::read(run_dir.join("brief.txt"))
            .map_err(|error| format!("{recovery} resume brief: {error}"))?;
        atomic_write(&run_dir.join(format!("step-{}.txt", config.name)), &brief)
            .map_err(|error| format!("{recovery} resume input: {error}"))?;
    }
    config.session = Some(session);
    Ok(true)
}

/// The run directory a refused dispatch is able to name.
///
/// A refused resume was given its run directory on the command line and that
/// directory was validated before the pool was read, so the refusal names the
/// run the step would have continued and a reader can find it. A fresh
/// dispatch is refused before any directory is allocated and has none to
/// name. The validation is repeated here because the report grammar admits no
/// whitespace in a field, and a report that cannot be parsed is worse than
/// one that says nothing.
fn refused_dir(config: &Config) -> &str {
    if config.session.is_none() {
        return "unknown";
    }
    config
        .resume_dir
        .as_deref()
        .filter(|directory| valid_report_path(directory))
        .and_then(Path::to_str)
        .unwrap_or("unknown")
}

fn resolve_run_dir(config: &Config) -> Result<PathBuf, ()> {
    if let Some(directory) = &config.resume_dir {
        return Ok(directory.clone());
    }
    let root = std::env::var_os("LANE_RUN_DIR")
        .or_else(|| std::env::var_os("LANE_RUNS_ROOT"))
        .ok_or(())?;
    let stamp = utc_stamp().ok_or(())?;
    fresh_run_dir(&config.name, &root, &stamp)
}

fn fresh_run_dir(name: &str, root: &OsStr, stamp: &str) -> Result<PathBuf, ()> {
    if !valid_runs_root(root) {
        return Err(());
    }
    Ok(Path::new(root).join(format!("{stamp}-{name}")))
}

fn allocate_fresh_run_dir(base: &Path) -> io::Result<PathBuf> {
    let parent = base.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "run directory has no parent")
    })?;
    fs::create_dir_all(parent)?;
    for attempt in 1..=MAX_FRESH_RUN_DIR_ATTEMPTS {
        let candidate = if attempt == 1 {
            base.to_path_buf()
        } else {
            let mut path = base.as_os_str().to_os_string();
            path.push(format!("-{attempt}"));
            PathBuf::from(path)
        };
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free run directory suffix",
    ))
}

fn create_fresh_run_dir(base: &Path, exact: bool) -> io::Result<PathBuf> {
    if exact {
        fs::create_dir(base)?;
        Ok(base.to_path_buf())
    } else {
        allocate_fresh_run_dir(base)
    }
}

fn utc_stamp() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(stamp) = std::env::var("CODEX_LANE_TEST_UTC_STAMP") {
        return valid_utc_stamp(&stamp).then_some(stamp);
    }
    let output = Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stamp = String::from_utf8(output.stdout).ok()?;
    let stamp = stamp.trim_end_matches('\n').to_owned();
    valid_utc_stamp(&stamp).then_some(stamp)
}

fn valid_utc_stamp(stamp: &str) -> bool {
    stamp.len() == 16
        && stamp.bytes().enumerate().all(|(index, byte)| match index {
            8 => byte == b'T',
            15 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparationFailure {
    Usage,
    EventSize,
    Runtime { live: bool },
}

impl PreparationFailure {
    const fn status(self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::EventSize | Self::Runtime { .. } => 1,
        }
    }

    fn diagnostic(self, backend_name: &str) -> Vec<u8> {
        match self {
            Self::Usage => usage_diagnostic(backend_name),
            Self::EventSize => {
                format!("{backend_name}: resume_event_size: event stream metadata failed\n")
                    .into_bytes()
            }
            Self::Runtime { .. } => runtime_diagnostic(backend_name),
        }
    }

    const fn live(self) -> bool {
        matches!(self, Self::Runtime { live: true })
    }
}

fn prepare_fresh(config: &Config, prompt: &[u8], run_dir: &Path) -> Result<(), PreparationFailure> {
    atomic_write(&run_dir.join("brief.txt"), prompt)
        .map_err(|_error| PreparationFailure::Runtime { live: true })?;
    if config.step_letter.is_some() {
        write_step_input(config, prompt, run_dir)
            .map_err(|_error| PreparationFailure::Runtime { live: true })?;
    }
    atomic_write(
        &run_dir.join(STEP_NAME_FILE),
        format!("{}\n", config.name).as_bytes(),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: true })?;
    atomic_write(&run_dir.join(EVENT_START_FILE), b"0\n")
        .map_err(|_error| PreparationFailure::Runtime { live: true })?;
    write_started_at(run_dir).map_err(|_error| PreparationFailure::Runtime { live: true })?;
    create_append_file(&run_dir.join("events.jsonl"))
        .and_then(|()| create_append_file(&run_dir.join("stderr.txt")))
        .map_err(|_error| PreparationFailure::Runtime { live: true })
}

fn write_step_input(config: &Config, prompt: &[u8], run_dir: &Path) -> io::Result<()> {
    if config.step_letter.is_some() {
        atomic_write(
            &run_dir.join(format!("step-{}.prompt.txt", config.name)),
            prompt,
        )?;
    }
    atomic_write(
        &run_dir.join(format!("step-{}.txt", config.name)),
        config.step_letter.as_deref().unwrap_or(prompt),
    )
}

fn child_input_path(config: &Config, run_dir: &Path) -> PathBuf {
    if config.step_letter.is_some() {
        run_dir.join(format!("step-{}.prompt.txt", config.name))
    } else if config.session.is_some() {
        run_dir.join(format!("step-{}.txt", config.name))
    } else {
        run_dir.join("brief.txt")
    }
}

fn prepare_resume(
    config: &Config,
    prompt: &[u8],
    run_dir: &Path,
) -> Result<(), PreparationFailure> {
    prepare_resume_with_size(config, prompt, run_dir, |path| {
        fs::metadata(path).map(|metadata| metadata.len())
    })
}

fn prepare_resume_with_size<F: FnOnce(&Path) -> io::Result<u64>>(
    config: &Config,
    prompt: &[u8],
    run_dir: &Path,
    size: F,
) -> Result<(), PreparationFailure> {
    let prior_name = current_step_name(run_dir).ok_or(PreparationFailure::Usage)?;
    let history = run_dir.join("steps").join(&prior_name);
    if history.exists() {
        return Err(PreparationFailure::Usage);
    }
    // One successful size read identifies both sides of the step boundary.
    // Refuse before creating an archive if the event stream cannot be measured.
    let event_size =
        size(&run_dir.join("events.jsonl")).map_err(|_error| PreparationFailure::EventSize)?;
    let event_boundary = format!("{event_size}\n");
    fs::create_dir_all(run_dir.join("steps"))
        .and_then(|()| fs::create_dir(&history))
        .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_required(
        &run_dir.join("run-report.txt"),
        &history.join("run-report.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join("backend-settings.json"),
        &history.join("backend-settings.json"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join(".feed-offset"),
        &history.join("feed-offset.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join("last-message.txt"),
        &history.join("last-message.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join(RECONSTRUCTED_FILE),
        &history.join("reconstructed.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join(RATE_LIMIT_FILE),
        &history.join(RATE_LIMIT_FILE),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join(CAPACITY_ATTEMPTS_FILE),
        &history.join(CAPACITY_ATTEMPTS_FILE),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join("kill-evidence.txt"),
        &history.join("kill-evidence.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    archive_optional(
        &run_dir.join(STARTED_AT_FILE),
        &history.join("started-at.txt"),
    )
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    let start = fs::read(run_dir.join(EVENT_START_FILE)).unwrap_or_else(|_error| b"0\n".to_vec());
    atomic_write(&history.join("event-start.txt"), &start)
        .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    atomic_write(&history.join("event-end.txt"), event_boundary.as_bytes())
        .map_err(|_error| PreparationFailure::Runtime { live: false })?;

    write_step_input(config, prompt, run_dir)
        .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    atomic_write(
        &run_dir.join(STEP_NAME_FILE),
        format!("{}\n", config.name).as_bytes(),
    )
    .and_then(|()| atomic_write(&run_dir.join(EVENT_START_FILE), event_boundary.as_bytes()))
    .and_then(|()| write_started_at(run_dir))
    .map_err(|_error| PreparationFailure::Runtime { live: false })?;

    remove_optional(run_dir.join(".feed-offset"))
        .and_then(|()| remove_optional(run_dir.join("last-message.txt")))
        .and_then(|()| remove_optional(run_dir.join(RECONSTRUCTED_FILE)))
        .and_then(|()| remove_optional(run_dir.join(RATE_LIMIT_FILE)))
        .and_then(|()| remove_optional(run_dir.join(CAPACITY_ATTEMPTS_FILE)))
        .and_then(|()| remove_optional(run_dir.join("kill-evidence.txt")))
        .map_err(|_error| PreparationFailure::Runtime { live: false })?;
    fs::remove_file(run_dir.join("run-report.txt"))
        .and_then(|()| sync_directory(run_dir))
        .map_err(|_error| PreparationFailure::Runtime { live: true })
}

/// Record the driver's UTC wall second for readers of the step's evidence.
///
/// Without a clock it leaves no marker rather than the prior step's.
fn write_started_at(run_dir: &Path) -> io::Result<()> {
    let Some(second) = epoch_seconds() else {
        return remove_optional(run_dir.join(STARTED_AT_FILE));
    };
    atomic_write(
        &run_dir.join(STARTED_AT_FILE),
        format!("{}\n", iso8601_utc(second)).as_bytes(),
    )
}

/// Record the run's thread once, without replacing an id already recorded.
///
/// A dispatch capture can collide with another or be lost, and otherwise the
/// id is recoverable only by reading the events. The run directory therefore
/// names its own thread beside its report.
fn write_thread_id(run_dir: &Path, thread_id: &str) -> io::Result<bool> {
    let path = run_dir.join(THREAD_ID_FILE);
    let expected = format!("{thread_id}\n");
    match fs::read(&path) {
        Ok(recorded) => Ok(recorded == expected.as_bytes()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            atomic_write(&path, expected.as_bytes()).map(|()| true)
        }
        Err(error) => Err(error),
    }
}

fn current_step_name(run_dir: &Path) -> Option<String> {
    if let Ok(bytes) = fs::read(run_dir.join(STEP_NAME_FILE)) {
        let name = std::str::from_utf8(&bytes).ok()?.trim_end_matches('\n');
        return valid_token(name).then(|| name.to_owned());
    }
    let report = fs::read_to_string(run_dir.join("run-report.txt")).ok()?;
    let lane = report
        .split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("lane="))?;
    valid_token(lane).then(|| lane.to_owned())
}

fn archive_required(source: &Path, destination: &Path) -> io::Result<()> {
    let bytes = fs::read(source)?;
    atomic_write(destination, &bytes)
}

fn archive_optional(source: &Path, destination: &Path) -> io::Result<()> {
    match fs::read(source) {
        Ok(bytes) => atomic_write(destination, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_optional(path: PathBuf) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
enum ChildResult {
    Natural(ExitStatus),
    /// A terminal event was durable when an explicit stop reaped an idle child.
    Terminal(TerminalResult),
    /// A signal asked the driver to stop, and the driver stopped its child
    /// with it rather than leaving it producing under no supervision.
    Terminated,
}

/// The monitor's own readings at one awake-time poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MonitorReadings {
    wall: u64,
    budget: u64,
    event_size: u64,
    last_growth: u64,
    quiet: u64,
}

/// Immutable reading latched on the first poll beyond the step budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BudgetExpiry {
    readings: MonitorReadings,
    state: MonitorDecision,
}

/// Read-only gateway evidence for one registered step.
struct GatewayWatch {
    lane: String,
    state_root: PathBuf,
    expected_worktree: String,
    roster_budgets: BTreeMap<String, u64>,
    roster_runs: BTreeMap<u64, u64>,
    settled: BTreeSet<u64>,
    audit_offset: u64,
}

impl GatewayWatch {
    fn new(lane: &str, state_root: &Path, workdir: &Path) -> Option<Self> {
        let worktree = workdir.to_str()?;
        if worktree
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
        {
            return None;
        }
        let registration = fs::read_to_string(
            state_root
                .join("registrations")
                .join(format!("{lane}.toml")),
        )
        .ok()?;
        let expected = format!("worktree = \"{worktree}\"");
        if !registration.lines().any(|line| line == expected) {
            return None;
        }
        Some(Self {
            lane: lane.to_owned(),
            state_root: state_root.to_path_buf(),
            expected_worktree: expected,
            roster_budgets: BTreeMap::new(),
            roster_runs: BTreeMap::new(),
            settled: BTreeSet::new(),
            audit_offset: 0,
        })
    }

    /// An approved or registered, unexpired run without an audited result.
    fn in_flight(&mut self, unix_ms: u64) -> Option<u64> {
        let registration = fs::read_to_string(
            self.state_root
                .join("registrations")
                .join(format!("{}.toml", self.lane)),
        )
        .ok()?;
        if !registration
            .lines()
            .any(|line| line == self.expected_worktree)
        {
            return None;
        }
        self.roster_budgets = roster_budgets(&registration);
        self.scan_audit()?;
        self.roster_runs
            .retain(|seq, expires| !self.settled.contains(seq) && unix_ms < *expires);
        let mut candidates: Vec<_> = self.roster_runs.keys().copied().collect();
        let verdict_dir = self.state_root.join("proposal-verdicts").join(&self.lane);
        let verdicts = match fs::read_dir(verdict_dir) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_error) => return None,
        };
        for entry in verdicts.into_iter().flatten() {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            let Some(seq_text) = name.strip_suffix(".json") else {
                continue;
            };
            let seq = seq_text.parse::<u64>().ok()?;
            if self.settled.contains(&seq) {
                continue;
            }
            let resolution = fs::read(entry.path()).ok()?;
            let verdict = object_value(&resolution, "verdict")?;
            if top_level_u64_value(verdict, "seq")? != seq {
                return None;
            }
            if top_level_string_value(verdict, "decision")?.as_str() != "approved" {
                self.settled.insert(seq);
                continue;
            }
            let resolved = top_level_u64_value(&resolution, "resolved_unix_ms")?;
            let proposal = fs::read(
                self.state_root
                    .join("execution-budgets")
                    .join(&self.lane)
                    .join(format!("{seq}.json")),
            )
            .ok()?;
            if top_level_u64_value(&proposal, "seq")? != seq
                || top_level_string_value(&proposal, "lane")? != self.lane
            {
                return None;
            }
            let timeout = top_level_u64_value(&proposal, "timeout_seconds")?;
            let expires = resolved.checked_add(timeout.checked_mul(MILLISECONDS_PER_SECOND)?)?;
            if unix_ms >= expires {
                self.settled.insert(seq);
                continue;
            }
            candidates.push(seq);
        }
        candidates.sort_unstable();
        candidates
            .into_iter()
            .find(|seq| !self.settled.contains(seq))
    }

    fn scan_audit(&mut self) -> Option<()> {
        let path = self
            .state_root
            .join("audit")
            .join(format!("{}.jsonl", self.lane));
        let mut file = File::open(path).ok()?;
        if file.metadata().ok()?.len() < self.audit_offset {
            return None;
        }
        file.seek(SeekFrom::Start(self.audit_offset)).ok()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).ok()?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |at| at + 1);
        let mut audited = Vec::new();
        if complete_len > 0 {
            for line in bytes[..complete_len - 1].split(|byte| *byte == b'\n') {
                let event = object_value(line, "event")?;
                match top_level_string_value(event, "kind")?.as_str() {
                    "request" => {
                        let request = object_value(event, "request")?;
                        if top_level_string_value(request, "encoding")?.as_str() != "json" {
                            continue;
                        }
                        let Some(value) = object_value(request, "value") else {
                            continue;
                        };
                        if top_level_string_value(value, "op").as_deref() != Some("run") {
                            continue;
                        }
                        let Some(command) = top_level_string_value(value, "command") else {
                            continue;
                        };
                        let Some(budget) = self.roster_budgets.get(&command) else {
                            continue;
                        };
                        let Some(seq) = top_level_u64_value(value, "seq") else {
                            continue;
                        };
                        let started = top_level_u64_value(line, "timestamp_unix_ms")?;
                        let expires =
                            started.checked_add(budget.checked_mul(MILLISECONDS_PER_SECOND)?)?;
                        self.roster_runs.insert(seq, expires);
                    }
                    "result" => {
                        let result = object_value(event, "result")?;
                        let seq = top_level_u64_value(result, "seq")?;
                        if top_level_string_value(result, "operation")?.as_str() == "run" {
                            audited.push(seq);
                        }
                    }
                    "refusal" => {
                        let refusal = object_value(event, "refusal")?;
                        if let Some(seq) = top_level_u64_value(refusal, "seq") {
                            self.roster_runs.remove(&seq);
                        }
                    }
                    _ => {}
                }
            }
        }
        self.audit_offset = self
            .audit_offset
            .checked_add(u64::try_from(complete_len).ok()?)?;
        self.settled.extend(audited);
        Some(())
    }
}

fn roster_budgets(registration: &str) -> BTreeMap<String, u64> {
    let mut budgets = BTreeMap::new();
    let mut command = None;
    for line in registration.lines().map(str::trim) {
        if line.starts_with('[') {
            command = line
                .strip_prefix("[commands.")
                .and_then(|name| name.strip_suffix(']'));
        } else if let Some(name) = command {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "wall_budget_seconds" {
                continue;
            }
            let Ok(seconds) = value.trim().parse::<u64>() else {
                continue;
            };
            if seconds > 0 {
                budgets.insert(name.to_owned(), seconds);
            }
        }
    }
    budgets
}

fn gateway_state_root() -> Option<PathBuf> {
    if let Some(configured) =
        std::env::var_os("LANE_GATEWAY_STATE").filter(|value| !value.is_empty())
    {
        return Some(PathBuf::from(configured));
    }
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(xdg).join("lane-gateway"));
    }
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(".local/state/lane-gateway"))
}

fn epoch_millis() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

/// Watch for a request to stop, without letting it end the driver alone.
///
/// A driver that dies on its default disposition leaves the child it spawned
/// running and unsupervised: nothing else knows that process, so the step goes
/// on producing with no monitor, no budget, and no report (measured: a
/// `SIGTERM` to a lane driver ended the driver and left its `codex exec` child
/// alive). Blocking the two signals and reading them from a thread that does
/// nothing but record the arrival keeps the monitor loop the single place that
/// stops a child, and it needs no signal handler, whose only safe act would be
/// this same store. `std::process::Command` restores an empty mask in each
/// child before exec, so the child a step spawns is unaffected by the block.
///
/// The watch is advisory in the same sense as the monitor sidecar: a host that
/// refuses the block or the thread leaves the driver on its default
/// disposition, which is what every earlier driver had, rather than refusing
/// to run the step at all.
fn install_termination_watch() -> bool {
    let mut watched = SigSet::empty();
    for (signal, _name) in FORWARDED_SIGNALS {
        watched.add(signal);
    }
    if watched.thread_block().is_err() {
        return false;
    }
    *SIGNAL_WATCH.get_or_init(|| {
        std::thread::Builder::new()
            .name("lane-termination-watch".to_owned())
            .spawn(move || {
                while let Ok(signal) = watched.wait() {
                    FORWARDED_SIGNAL.store(signal as i32, Ordering::Relaxed);
                }
            })
            .is_ok()
    })
}

/// The stop request this driver has received, named as the evidence records it.
fn forwarded_signal() -> Option<&'static str> {
    let observed = FORWARDED_SIGNAL.load(Ordering::Relaxed);
    FORWARDED_SIGNALS
        .into_iter()
        .find(|(signal, _name)| *signal as i32 == observed)
        .map(|(_signal, name)| name)
}

#[derive(Clone)]
struct ContextTracker {
    offset: u64,
    pending: Vec<u8>,
    turn: u64,
    latest: Option<(ContextUse, String)>,
    records: Vec<u8>,
}

impl ContextTracker {
    const fn new(offset: u64) -> Self {
        Self {
            offset,
            pending: Vec::new(),
            turn: 0,
            latest: None,
            records: Vec::new(),
        }
    }

    fn reconcile(backend: &dyn Backend, events_path: &Path, run_dir: &Path) -> io::Result<Self> {
        let events = fs::read(events_path)?;
        let record_path = run_dir.join(CONTEXT_FILE);
        let existing = match fs::read(&record_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut instants = BTreeMap::new();
        for line in existing.split_inclusive(|byte| *byte == b'\n') {
            if !line.ends_with(b"\n") {
                break;
            }
            let event_end =
                top_level_u64_value(&line[..line.len() - 1], "event_end").ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "context-record: event boundary is absent",
                    )
                })?;
            let at = top_level_string_value(&line[..line.len() - 1], "at")
                .filter(|value| context_instant(value))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "context-record: instant is malformed",
                    )
                })?;
            instants.entry(event_end).or_insert(at);
        }
        let mut tracker = Self::new(0);
        let mut start = 0;
        for boundary in context_step_boundaries(run_dir, events.len())? {
            tracker.scan_bytes(backend, &events[start..boundary], &instants);
            // The raw stream retains an earlier step's unterminated line, but
            // that fragment cannot become the next child's first JSON line.
            tracker.pending.clear();
            start = boundary;
        }
        tracker.scan_bytes(backend, &events[start..], &instants);
        if tracker.records != existing {
            atomic_write(&record_path, &tracker.records)?;
        }
        Ok(tracker)
    }

    fn monitor_fields(&self) -> (ContextUse, u64, String) {
        self.latest.as_ref().map_or_else(
            || {
                let instant = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                (
                    ContextUse::unknown("none", "no-turn"),
                    0,
                    iso8601_utc(instant),
                )
            },
            |(state, at)| (*state, self.turn, at.clone()),
        )
    }

    fn observe_durable(
        &mut self,
        backend: &dyn Backend,
        events_path: &Path,
        run_dir: &Path,
    ) -> io::Result<()> {
        self.observe_with(backend, events_path, run_dir, atomic_write)
    }

    fn observe_with<F: Fn(&Path, &[u8]) -> io::Result<()>>(
        &mut self,
        backend: &dyn Backend,
        events_path: &Path,
        run_dir: &Path,
        publish: F,
    ) -> io::Result<()> {
        let mut candidate = self.clone();
        match candidate.observe(backend, events_path, run_dir, publish) {
            Ok(()) => {
                *self = candidate;
                Ok(())
            }
            Err(error) => {
                let instant = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs());
                self.latest = Some((
                    ContextUse::unknown("driver", "record-error"),
                    iso8601_utc(instant),
                ));
                Err(error)
            }
        }
    }

    fn observe<F: Fn(&Path, &[u8]) -> io::Result<()>>(
        &mut self,
        backend: &dyn Backend,
        events_path: &Path,
        run_dir: &Path,
        publish: F,
    ) -> io::Result<()> {
        let mut events = File::open(events_path)?;
        events.seek(SeekFrom::Start(self.offset))?;
        let mut added = Vec::new();
        events.read_to_end(&mut added)?;
        if added.is_empty() {
            return Ok(());
        }
        let prior = self.records.len();
        self.scan_bytes(backend, &added, &BTreeMap::new());
        if self.records.len() != prior {
            publish(&run_dir.join(CONTEXT_FILE), &self.records)?;
        }
        Ok(())
    }

    fn scan_bytes(
        &mut self,
        backend: &dyn Backend,
        added: &[u8],
        instants: &BTreeMap<u64, String>,
    ) {
        let base = self.offset - self.pending.len() as u64;
        self.offset += added.len() as u64;
        self.pending.extend_from_slice(added);
        let mut complete = 0;
        for (index, byte) in self.pending.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            if let Some(context) = backend.context_use(&self.pending[complete..index]) {
                self.turn += 1;
                let event_end = base + index as u64 + 1;
                let at = instants.get(&event_end).cloned().unwrap_or_else(|| {
                    iso8601_utc(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_or(0, |duration| duration.as_secs()),
                    )
                });
                self.records.extend_from_slice(
                    context_record_line(context, self.turn, event_end, &at).as_bytes(),
                );
                self.latest = Some((context, at));
            }
            complete = index + 1;
        }
        self.pending.drain(..complete);
    }
}

fn context_step_boundaries(run_dir: &Path, event_size: usize) -> io::Result<Vec<usize>> {
    fn read_boundary(path: &Path, event_size: usize) -> io::Result<usize> {
        let bytes = fs::read(path)?;
        let text = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.strip_suffix('\n'));
        text.and_then(|text| text.parse::<usize>().ok())
            .filter(|boundary| *boundary <= event_size)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "context-boundary: invalid offset",
                )
            })
    }

    let current_start = read_boundary(&run_dir.join(EVENT_START_FILE), event_size)?;
    let mut archives = Vec::new();
    let history = run_dir.join("steps");
    let entries = match fs::read_dir(&history) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Some(entries) = entries {
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "context-boundary: invalid step archive",
                ));
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .filter(|name| valid_token(name))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "context-boundary: invalid step name",
                    )
                })?;
            let end = entry.path().join("event-end.txt");
            match read_boundary(&end, event_size) {
                Ok(end) => {
                    let start = read_boundary(&entry.path().join("event-start.txt"), event_size)
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!("context-boundary: step {name}: archived start: {error}"),
                            )
                        })?;
                    archives.push((name.to_owned(), start, end));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Before the next child starts, preparation can archive
                    // the reported step without reaching its ending offset.
                    let same_step = recorded_step_name(run_dir).as_deref() == Some(name)
                        && report_lane(run_dir).as_deref() == Some(name)
                        && entry.path().join("run-report.txt").is_file();
                    let same_start =
                        match read_boundary(&entry.path().join("event-start.txt"), event_size) {
                            Ok(start) => start == current_start,
                            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                            Err(error) => return Err(error),
                        };
                    if !same_step || !same_start {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "context-boundary: step {name}: archived event-end.txt is missing"
                            ),
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    validate_context_archive_chain(Some(run_dir), current_start, archives)
}

/// Validate the complete archived event offset chain before an outside reader renders deltas.
///
/// # Errors
///
/// Refuses a missing, malformed or disagreeing step boundary.
pub fn validated_event_boundaries(run_dir: &Path, event_size: usize) -> io::Result<Vec<usize>> {
    context_step_boundaries(run_dir, event_size)
}

fn boundary_open_at(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "context-boundary: invalid component",
        ));
    }
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "context-boundary: NUL name"))?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
    // SAFETY: parent remains open and name is a terminated, single-component name.
    #[allow(unsafe_code)]
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat gives this File sole ownership of the descriptor.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn boundary_text_at(parent: &File, name: &str) -> io::Result<String> {
    let file = boundary_open_at(parent, name, false)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("context-boundary: {name} is not a regular file"),
        ));
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("context-boundary: {name} exceeds size bound"),
        ));
    }
    Ok(text)
}

fn parse_boundary_at(parent: &File, name: &str, event_size: usize) -> io::Result<usize> {
    let text = boundary_text_at(parent, name).map_err(|error| {
        io::Error::new(error.kind(), format!("context-boundary: {name}: {error}"))
    })?;
    text.strip_suffix('\n')
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|boundary| *boundary <= event_size)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "context-boundary: invalid offset",
            )
        })
}

fn boundary_owner(uid: u32, mode: u32, name: &str, loop_uid: u32) -> io::Result<()> {
    if uid != loop_uid || mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "context-boundary: {name}: uid {uid} mode {mode:04o}; expected uid {loop_uid} without group or other write"
            ),
        ));
    }
    Ok(())
}

fn boundary_archive_names(steps: &File) -> io::Result<Vec<String>> {
    // SAFETY: the duplicate gives fdopendir its own descriptor to close.
    #[allow(unsafe_code)]
    let duplicate = unsafe { libc::fcntl(steps.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of the successful duplicate.
    #[allow(unsafe_code)]
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir left ownership with this function on failure.
        #[allow(unsafe_code)]
        unsafe {
            libc::close(duplicate);
        }
        return Err(error);
    }
    let mut names = Vec::new();
    let read = (|| {
        loop {
            // SAFETY: this thread owns the DIR stream and clears errno before readdir.
            #[allow(unsafe_code)]
            let entry = unsafe {
                *libc::__errno_location() = 0;
                libc::readdir(stream)
            };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error);
                }
                break;
            }
            // SAFETY: readdir returned a live entry with a terminated name.
            #[allow(unsafe_code)]
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = std::str::from_utf8(bytes)
                .ok()
                .filter(|name| valid_token(name))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "context-boundary: invalid step name",
                    )
                })?;
            names.push(name.to_owned());
        }
        Ok(())
    })();
    // SAFETY: fdopendir owns the duplicate on success, including after a read error.
    #[allow(unsafe_code)]
    let closed = unsafe { libc::closedir(stream) };
    read?;
    if closed < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
}

/// One validated event chain, retained for the outside reader's rendering pass.
pub struct ValidatedEventBoundaries {
    pub current_start: usize,
    pub archives: BTreeMap<String, (usize, usize)>,
}

/// Validate archived event boundaries beneath a held step directory without following links.
///
/// # Errors
///
/// Refuses a link, foreign-owned or writable archive, or a missing, malformed or disagreeing boundary.
pub fn validated_event_boundaries_at(
    run_dir: &File,
    event_size: usize,
    loop_uid: u32,
) -> io::Result<ValidatedEventBoundaries> {
    validated_event_boundaries_at_with_metadata(run_dir, event_size, loop_uid, |directory, _| {
        let metadata = directory.metadata()?;
        Ok((metadata.uid(), metadata.mode() & 0o7777))
    })
}

/// Validate a pinned chain with supplied directory metadata for an identity fixture.
///
/// # Errors
///
/// Refuses a link, foreign-owned or writable archive, or a broken boundary chain.
pub fn validated_event_boundaries_at_with_metadata(
    run_dir: &File,
    event_size: usize,
    loop_uid: u32,
    metadata: impl Fn(&File, &str) -> io::Result<(u32, u32)>,
) -> io::Result<ValidatedEventBoundaries> {
    let current_start = parse_boundary_at(run_dir, EVENT_START_FILE, event_size)?;
    let steps = match boundary_open_at(run_dir, "steps", true) {
        Ok(steps) => Some(steps),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("context-boundary: steps: {error}"),
            ));
        }
    };
    let mut archives = Vec::new();
    if let Some(steps) = steps {
        let (uid, mode) = metadata(&steps, "steps")?;
        boundary_owner(uid, mode, "steps", loop_uid)?;
        for name in boundary_archive_names(&steps)? {
            let archive = boundary_open_at(&steps, &name, true).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("context-boundary: step {name}: {error}"),
                )
            })?;
            let label = format!("step {name}");
            let (uid, mode) = metadata(&archive, &label)?;
            boundary_owner(uid, mode, &label, loop_uid)?;
            let end =
                parse_boundary_at(&archive, "event-end.txt", event_size).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("context-boundary: step {name}: {error}"),
                    )
                })?;
            let start =
                parse_boundary_at(&archive, "event-start.txt", event_size).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("context-boundary: step {name}: {error}"),
                    )
                })?;
            archives.push((name, start, end));
        }
    }
    validate_context_archive_chain(None, current_start, archives.clone())?;
    Ok(ValidatedEventBoundaries {
        current_start,
        archives: archives
            .into_iter()
            .map(|(name, start, end)| (name, (start, end)))
            .collect(),
    })
}

// A bounded offset is useful only when every neighboring step agrees on it.
fn validate_context_archive_chain(
    run_dir: Option<&Path>,
    current_start: usize,
    mut archives: Vec<(String, usize, usize)>,
) -> io::Result<Vec<usize>> {
    archives.sort_unstable_by(|a, b| (a.1, a.2, &a.0).cmp(&(b.1, b.2, &b.0)));
    if let Some((name, start, _end)) = archives.first()
        && *start != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("context-boundary: step {name}: first start {start} != 0"),
        ));
    }
    for (index, (name, start, end)) in archives.iter().enumerate() {
        if end < start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("context-boundary: step {name}: end {end} < start {start}"),
            ));
        }
        let next_start = archives.get(index + 1).map_or(current_start, |next| next.1);
        if *end != next_start {
            let label = if index + 1 == archives.len() {
                "current start"
            } else {
                "next start"
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("context-boundary: step {name}: end {end} != {label} {next_start}"),
            ));
        }
    }
    if archives.is_empty() && current_start != 0 {
        let name = run_dir
            .and_then(recorded_step_name)
            .unwrap_or_else(|| "current".to_owned());
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("context-boundary: step {name}: first start {current_start} != 0"),
        ));
    }
    let mut boundaries = archives
        .into_iter()
        .map(|(_name, _start, end)| end)
        .collect::<Vec<_>>();
    boundaries.push(current_start);
    boundaries.sort_unstable();
    boundaries.dedup();
    Ok(boundaries)
}

fn context_instant(value: &str) -> bool {
    value.len() == 20
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"-:TZ".contains(&byte))
}

fn context_record_line(context: ContextUse, turn: u64, event_end: u64, at: &str) -> String {
    let used = context
        .used
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let window = context
        .window
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let fraction = context
        .fraction()
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    format!(
        "{{\"state\":\"{}\",\"used\":{used},\"window\":{window},\"fraction\":{fraction},\"source\":\"{}\",\"reason\":\"{}\",\"turn\":{turn},\"event_end\":{event_end},\"at\":\"{at}\"}}\n",
        context.state(),
        context.source,
        context.reason
    )
}

#[allow(clippy::too_many_lines)]
fn run_child(
    backend: &dyn Backend,
    config: &Config,
    run_dir: &Path,
    lock: &StepLock,
    start: ClockSample,
    starting_size: u64,
    clock: &mut Clock,
) -> Result<ChildResult, String> {
    let events_path = run_dir.join("events.jsonl");
    let events = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&events_path)
        .map_err(|error| format!("events file {}: {error}", events_path.display()))?;
    let mut context = ContextTracker::reconcile(backend, &events_path, run_dir)
        .map_err(|error| format!("context record: {error}"))?;
    let diagnostics_path = run_dir.join("stderr.txt");
    let diagnostics = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&diagnostics_path)
        .map_err(|error| format!("diagnostics file {}: {error}", diagnostics_path.display()))?;
    let input_path = child_input_path(config, run_dir);
    let input = File::open(&input_path)
        .map_err(|error| format!("input {}: {error}", input_path.display()))?;
    let mut command = backend
        .command(config, run_dir)
        .map_err(|error| format!("command build: {error}"))?;
    if backend.boxed_runtime() {
        let attempt_end = run_dir.join(".attempt-end");
        match fs::remove_file(&attempt_end) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("attempt end reset: {error}")),
        }
        command.env("LANE_ATTEMPT_END", &attempt_end);
    } else {
        command.env_remove("LANE_ATTEMPT_END");
    }
    let program = command.get_program().to_string_lossy().into_owned();
    let _watched = install_termination_watch();
    let mut child = command
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(events))
        .stderr(Stdio::from(diagnostics))
        .spawn()
        .map_err(|error| format!("spawn {program}: {error}"))?;
    // The lock has named only this driver until now, and a recovery that finds
    // it dead cannot tell a driver that died before its child from one whose
    // child is still producing. Recording the child makes that difference
    // readable. The write is best-effort for the same reason the monitor
    // sidecar is: the child already exists, and refusing the step over a lock
    // rewrite would kill work that is running, so a failure leaves the
    // one-line lock every earlier run wrote and recovery reads it as it always
    // did.
    let _ignored = lock.record_child(child.id());
    let mut monitor = BudgetMonitor::new(config.budget, start.monotonic, starting_size);
    let monitor_file = monitor_file(run_dir);
    let mut gateway_watch = config.gateway_lane().and_then(|lane| {
        gateway_state_root().and_then(|root| GatewayWatch::new(lane, &root, config.workdir()))
    });
    let mut expiry = None;
    loop {
        let child_status = child
            .try_wait()
            .map_err(|error| format!("wait {program}: {error}"))?;
        let context_error = context
            .observe_durable(backend, &events_path, run_dir)
            .err();
        clock.pause();
        let now = clock
            .sample()
            .map_err(|()| "clock sample failed".to_owned())?;
        let size = file_size(&events_path);
        let credited_seq = gateway_watch
            .as_mut()
            .and_then(|watch| epoch_millis().and_then(|unix_ms| watch.in_flight(unix_ms)));
        if credited_seq.is_some() {
            monitor.observe_awaited(now.monotonic);
        }
        // A host suspend freezes the child with the driver rather than ending
        // it, so a boot-clock gap is not an observation about the child at all
        // and no bound is read from it. The monitor sees awake time only.
        let decision = monitor.probe(now.monotonic, size);
        let readings = MonitorReadings {
            wall: now.awake_elapsed_since(start),
            budget: config.budget,
            event_size: monitor.last_size(),
            last_growth: monitor.last_growth().saturating_sub(start.monotonic),
            quiet: now
                .monotonic
                .saturating_sub(monitor.last_growth().max(monitor.last_awaited())),
        };
        if expiry.is_none() && readings.wall > readings.budget {
            expiry = Some(BudgetExpiry {
                readings,
                state: decision,
            });
        }
        // An outside reader sees only file timestamps, which run on real time
        // and so cannot separate a frozen host from a silent child. The monitor
        // can, because its quiet interval is measured on the clock that stops
        // with the host, so it publishes that reading on every poll. The write
        // is advisory: a run directory that refuses it leaves the step running,
        // because no reader's convenience is worth ending a producing child.
        let (context_state, context_turn, context_at) = context.monitor_fields();
        let sidecar = monitor_sidecar_with_context(
            readings.quiet,
            now.monotonic.saturating_sub(start.monotonic),
            monitor.last_size(),
            now,
            credited_seq.and_then(|seq| {
                gateway_watch
                    .as_ref()
                    .map(|watch| (watch.lane.as_str(), seq))
            }),
            Some((context_state, context_turn, &context_at)),
            Some((readings, expiry, decision)),
        );
        let _ignored = atomic_write(&monitor_file, &sidecar);
        if let Some(status) = child_status {
            if let Some(error) = context_error {
                return Err(format!("context record: {error}"));
            }
            return Ok(ChildResult::Natural(status));
        }
        // An explicit request stops the child. Its own terminal event, if
        // already durable, still determines the result and last message.
        if forwarded_signal().is_some() {
            let raced = stop_child(&mut child);
            let context_end = finish_context(
                backend,
                run_dir,
                &mut context,
                &monitor_file,
                readings,
                expiry,
                decision,
                now,
                credited_seq.and_then(|seq| {
                    gateway_watch
                        .as_ref()
                        .map(|watch| (watch.lane.as_str(), seq))
                }),
            );
            context_end?;
            let raced = raced.map_err(|()| format!("stop {program}: child wait failed"))?;
            if let Some((_, result)) = transcript_terminal_result(backend, run_dir, true) {
                return Ok(ChildResult::Terminal(result));
            }
            return Ok(raced.map_or(ChildResult::Terminated, ChildResult::Natural));
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn mailbox_failure_after_poll(
    backend: &dyn Backend,
    child: &mut Child,
    child_finished: bool,
    run_dir: &Path,
    context: &mut ContextTracker,
    monitor_file: &Path,
    readings: MonitorReadings,
    expiry: Option<BudgetExpiry>,
    decision: MonitorDecision,
    sample: ClockSample,
    awaiting: Option<(&str, u64)>,
    error: &io::Error,
) -> String {
    let child_end = if child_finished {
        "already-exited"
    } else if stop_child(child).is_ok() {
        "stopped-and-reaped"
    } else {
        "stop-or-reap-failed"
    };
    let context_end = finish_context(
        backend,
        run_dir,
        context,
        monitor_file,
        readings,
        expiry,
        decision,
        sample,
        awaiting,
    )
    .err()
    .unwrap_or_else(|| "complete".to_owned());
    format!("mailbox watcher: {error}; child={child_end}; final-context={context_end}")
}

#[allow(clippy::too_many_arguments)]
fn finish_context(
    backend: &dyn Backend,
    run_dir: &Path,
    context: &mut ContextTracker,
    monitor_file: &Path,
    readings: MonitorReadings,
    expiry: Option<BudgetExpiry>,
    decision: MonitorDecision,
    sample: ClockSample,
    awaiting: Option<(&str, u64)>,
) -> Result<(), String> {
    let events_path = run_dir.join("events.jsonl");
    context
        .observe_durable(backend, &events_path, run_dir)
        .map_err(|error| format!("context record: {error}"))?;
    let (state, turn, at) = context.monitor_fields();
    let sidecar = monitor_sidecar_with_context(
        readings.quiet,
        readings.wall,
        file_size(&events_path),
        sample,
        awaiting,
        Some((state, turn, &at)),
        Some((readings, expiry, decision)),
    );
    let _ignored = atomic_write(monitor_file, &sidecar);
    Ok(())
}

/// Stop and reap a child after an explicit driver stop or mailbox failure.
///
/// The step is classified by its terminal result when its own region ends in one;
/// otherwise the waited status supplies the disposition.
fn stop_child(child: &mut Child) -> Result<Option<ExitStatus>, ()> {
    let kill_sent = child.kill().is_ok();
    let status = child.wait().map_err(|_error| ())?;
    if !kill_sent {
        return Ok(Some(status));
    }
    if status.signal().is_none() {
        return Ok(Some(status));
    }
    Ok(None)
}

/// One line of the monitor's own accounting, for a reader of a live step.
///
/// `quiet` and `wall` are awake seconds, the basis every bound is read on, and
/// `boot` and `awake` are the two clock readings the sample came from, carried
/// as they were read. Their difference is the seconds this host has spent
/// suspended, so a reader holding two such lines — or this line and its own
/// reading of the boot clock — can separate time a child had from time the
/// host was away, which no file timestamp records.
///
/// # Panics
///
/// Panics only if writing to a `String` fails, which `String` cannot arrange.
#[cfg(test)]
fn monitor_sidecar_bytes(
    quiet: u64,
    wall: u64,
    event_size: u64,
    sample: ClockSample,
    awaiting: Option<(&str, u64)>,
) -> Vec<u8> {
    monitor_sidecar_with_context(quiet, wall, event_size, sample, awaiting, None, None)
}

/// # Panics
///
/// Panics only if writing to a `String` fails, which `String` cannot arrange.
#[allow(clippy::too_many_arguments)]
fn monitor_sidecar_with_context(
    quiet: u64,
    wall: u64,
    event_size: u64,
    sample: ClockSample,
    awaiting: Option<(&str, u64)>,
    context: Option<(ContextUse, u64, &str)>,
    budget_observation: Option<(MonitorReadings, Option<BudgetExpiry>, MonitorDecision)>,
) -> Vec<u8> {
    let mut record = String::new();
    write!(
        &mut record,
        "quiet={quiet}s wall={wall}s event_size={event_size} boot={}s awake={}s",
        sample.boottime, sample.monotonic
    )
    .expect("writing to a String cannot fail");
    if let Some((lane, seq)) = awaiting {
        write!(&mut record, " awaiting={lane}:{seq}").expect("writing to a String cannot fail");
    }
    if let Some((state, turn, at)) = context {
        let used = state
            .used
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        let window = state
            .window
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        let fraction = state
            .fraction()
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
        write!(&mut record, " context_state={} context_used={used} context_window={window} context_fraction={fraction} context_source={} context_reason={} context_turn={turn} context_at={at}", state.state(), state.source, state.reason).expect("writing to a String cannot fail");
    }

    if let Some((readings, expiry, decision)) = budget_observation {
        write!(
            &mut record,
            " budget={}s last_growth={}s",
            readings.budget, readings.last_growth
        )
        .expect("writing to a String cannot fail");
        if let Some(expiry) = expiry {
            write!(&mut record, " state={}", decision.state())
                .expect("writing to a String cannot fail");
            write!(
                &mut record,
                " expired_wall={}s expired_event_size={} expired_last_growth={}s expired_quiet={}s expired_state={}",
                expiry.readings.wall,
                expiry.readings.event_size,
                expiry.readings.last_growth,
                expiry.readings.quiet,
                expiry.state.state()
            )
            .expect("writing to a String cannot fail");
        }
    }
    record.push('\n');
    record.into_bytes()
}

/// What became of the finished step's own message.
enum MessageSettlement {
    /// The question is closed: a message stands, or none was ever owed.
    Settled,
    /// The step's own region carried none while the rest of the transcript
    /// did, so an earlier step's text was refused as this step's answer.
    Withheld,
    /// The message file could not be settled: either the step had a message
    /// and the write failed, or the path could not be examined at all, which
    /// leaves what the step said unknown rather than absent.
    Unwritten { path: PathBuf, error: io::Error },
}

/// Settle the finished step's own message and answer what became of it.
///
/// Only the step's own region can speak for this step. Reading the whole
/// cumulative transcript would hand an earlier step's text to a step whose
/// child emitted neither a terminal result string nor an assistant text
/// block, which is exactly the stale text the reconstruction path already
/// refuses to publish; the natural finish owes its readers the same refusal.
/// A region carrying no message therefore publishes no file at all.
///
/// The answer is `Withheld` only when the rest of the transcript does carry a
/// message, because that is the case where the refusal changed the outcome
/// and a reader would otherwise see an empty run directory without knowing
/// whether the step was silent or its text was withheld. A backend whose
/// child writes the message file itself has already settled the question and
/// withholds nothing.
///
/// A failed write is reported as itself. The two states are indistinguishable
/// in the run directory — no message file either way — and only this function
/// knows which happened, so discarding the error here would publish an
/// absence as a refusal and tell a reader the step said nothing when it did.
fn settle_last_message(
    backend: &dyn Backend,
    run_dir: &Path,
    region: Option<&[u8]>,
) -> MessageSettlement {
    if let Err(error) = publish_last_message(backend, run_dir, region.unwrap_or_default()) {
        return MessageSettlement::Unwritten {
            path: run_dir.join("last-message.txt"),
            error,
        };
    }
    if message_recovered(run_dir).unwrap_or(false) {
        return MessageSettlement::Settled;
    }
    let withheld = fs::read(run_dir.join("events.jsonl"))
        .ok()
        .and_then(|events| backend.last_message(&events))
        .is_some();
    if withheld {
        MessageSettlement::Withheld
    } else {
        MessageSettlement::Settled
    }
}

/// Write the last message the given event bytes carry, if none stands yet.
fn publish_last_message(backend: &dyn Backend, run_dir: &Path, events: &[u8]) -> io::Result<()> {
    if message_recovered(run_dir)? {
        return Ok(());
    }
    if let Some(message) = backend.last_message(events) {
        atomic_write(&run_dir.join("last-message.txt"), &message)?;
    }
    Ok(())
}

/// Whether a message already stands in the run directory.
///
/// Only a nonempty regular file is one. A directory standing at that path
/// carries a size of its own on some filesystems and none on others, so a
/// length test alone would call it a published message on one machine and not
/// on the next, and the step's own write would be skipped rather than tried
/// and reported.
fn message_recovered(run_dir: &Path) -> io::Result<bool> {
    match fs::metadata(run_dir.join("last-message.txt")) {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() > 0),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether adjacent decoded JSON strings contain the requested key/value pair.
#[must_use]
pub fn contains_pair(strings: &[String], key: &str, value: &str) -> bool {
    strings
        .windows(2)
        .any(|pair| pair[0] == key && pair[1] == value)
}

/// Last decoded string immediately following the requested key.
#[must_use]
pub fn value_after_key<'a>(strings: &'a [String], key: &str) -> Option<&'a str> {
    strings
        .windows(2)
        .rev()
        .find_map(|pair| (pair[0] == key).then_some(pair[1].as_str()))
}

/// Decode every JSON string token in one byte slice.
#[must_use]
pub fn json_strings(bytes: &[u8]) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        if bytes[position] != b'"' {
            position += 1;
            continue;
        }
        let (value, end) = parse_json_string(bytes, position)?;
        strings.push(value);
        position = end;
    }
    Some(strings)
}

/// Decode a string value belonging to a key in one top-level JSON object.
///
/// Nested objects and arrays are skipped structurally, so strings inside a
/// preceding value cannot be mistaken for top-level key/value pairs.
#[must_use]
pub fn top_level_string_value(bytes: &[u8], key: &str) -> Option<String> {
    let (start, end) = top_level_value_span(bytes, key, |byte| byte == b'"')?;
    let (value, string_end) = parse_json_string(bytes, start)?;
    (string_end == end).then_some(value)
}

/// Decode a boolean value belonging to a key in one top-level JSON object.
#[must_use]
pub fn top_level_bool_value(bytes: &[u8], key: &str) -> Option<bool> {
    let (start, end) = top_level_value_span(bytes, key, |byte| matches!(byte, b't' | b'f'))?;
    match bytes.get(start..end)? {
        b"true" => Some(true),
        b"false" => Some(false),
        _ => None,
    }
}

/// Decode a whole-number value belonging to a key in one top-level JSON
/// object.
///
/// A negative, fractional, or exponent-bearing number is not a count and has
/// no value here.
#[must_use]
pub fn top_level_u64_value(bytes: &[u8], key: &str) -> Option<u64> {
    let (start, end) = top_level_value_span(bytes, key, |byte| byte.is_ascii_digit())?;
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()?
        .parse()
        .ok()
}

/// Decode a fractional value belonging to a key in one top-level JSON object.
///
/// A utilization is a fraction of one window, so unlike a count it is read as
/// a real number and keeps whatever precision the event wrote.
#[must_use]
pub fn top_level_f64_value(bytes: &[u8], key: &str) -> Option<f64> {
    let (start, end) =
        top_level_value_span(bytes, key, |byte| byte.is_ascii_digit() || byte == b'-')?;
    std::str::from_utf8(bytes.get(start..end)?)
        .ok()?
        .parse()
        .ok()
}

/// The bytes of one object value belonging to a key in one JSON object.
///
/// The span returned is itself one complete object, so the same top-level
/// readers decode its members and one structural walker reaches every depth.
/// A reader that searched the whole line instead would accept a key belonging
/// to some other nested object.
#[must_use]
pub fn object_value<'a>(bytes: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let (start, end) = top_level_value_span(bytes, key, |byte| byte == b'{')?;
    bytes.get(start..end)
}

/// Whether a complete top-level JSON object carries a member of any value shape.
#[must_use]
pub fn top_level_has_key(bytes: &[u8], key: &str) -> bool {
    top_level_value_span(bytes, key, |_| true).is_some()
}

/// Byte span of the last top-level value of the wanted shape under one key.
fn top_level_value_span(bytes: &[u8], key: &str, wanted: fn(u8) -> bool) -> Option<(usize, usize)> {
    let mut position = skip_json_whitespace(bytes, 0);
    if bytes.get(position) != Some(&b'{') {
        return None;
    }
    position += 1;
    let mut found = None;
    loop {
        position = skip_json_whitespace(bytes, position);
        if bytes.get(position) == Some(&b'}') {
            position += 1;
            break;
        }
        let (member, end) = parse_json_string(bytes, position)?;
        position = skip_json_whitespace(bytes, end);
        if bytes.get(position) != Some(&b':') {
            return None;
        }
        position = skip_json_whitespace(bytes, position + 1);
        let value_start = position;
        position = skip_json_value(bytes, position)?;
        if member == key && bytes.get(value_start).copied().is_some_and(wanted) {
            found = Some((value_start, position));
        }
        position = skip_json_whitespace(bytes, position);
        match bytes.get(position) {
            Some(b',') => position += 1,
            Some(b'}') => {
                position += 1;
                break;
            }
            _ => return None,
        }
    }
    (skip_json_whitespace(bytes, position) == bytes.len())
        .then_some(found)
        .flatten()
}

/// The last event line a line feed closed.
///
/// Bytes after the final line feed are a write the dead driver's child never
/// finished, so they are not a line.
#[must_use]
pub fn last_complete_line(events: &[u8]) -> Option<&[u8]> {
    let end = events.iter().rposition(|byte| *byte == b'\n')?;
    let start = events
        .get(..end)?
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    events.get(start..end)
}

fn skip_json_whitespace(bytes: &[u8], mut position: usize) -> usize {
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        position += 1;
    }
    position
}

fn skip_json_value(bytes: &[u8], position: usize) -> Option<usize> {
    match *bytes.get(position)? {
        b'"' => parse_json_string(bytes, position).map(|(_value, end)| end),
        b'{' => skip_json_object(bytes, position),
        b'[' => skip_json_array(bytes, position),
        b't' => skip_json_literal(bytes, position, b"true"),
        b'f' => skip_json_literal(bytes, position, b"false"),
        b'n' => skip_json_literal(bytes, position, b"null"),
        b'-' | b'0'..=b'9' => skip_json_number(bytes, position),
        _ => None,
    }
}

fn skip_json_object(bytes: &[u8], mut position: usize) -> Option<usize> {
    position += 1;
    loop {
        position = skip_json_whitespace(bytes, position);
        if bytes.get(position) == Some(&b'}') {
            return Some(position + 1);
        }
        let (_key, end) = parse_json_string(bytes, position)?;
        position = skip_json_whitespace(bytes, end);
        if bytes.get(position) != Some(&b':') {
            return None;
        }
        position = skip_json_whitespace(bytes, position + 1);
        position = skip_json_value(bytes, position)?;
        position = skip_json_whitespace(bytes, position);
        match bytes.get(position) {
            Some(b',') => position += 1,
            Some(b'}') => return Some(position + 1),
            _ => return None,
        }
    }
}

fn skip_json_array(bytes: &[u8], mut position: usize) -> Option<usize> {
    position += 1;
    loop {
        position = skip_json_whitespace(bytes, position);
        if bytes.get(position) == Some(&b']') {
            return Some(position + 1);
        }
        position = skip_json_value(bytes, position)?;
        position = skip_json_whitespace(bytes, position);
        match bytes.get(position) {
            Some(b',') => position += 1,
            Some(b']') => return Some(position + 1),
            _ => return None,
        }
    }
}

fn skip_json_literal(bytes: &[u8], position: usize, literal: &[u8]) -> Option<usize> {
    let end = position.checked_add(literal.len())?;
    (bytes.get(position..end) == Some(literal)).then_some(end)
}

fn skip_json_number(bytes: &[u8], mut position: usize) -> Option<usize> {
    if bytes.get(position) == Some(&b'-') {
        position += 1;
    }
    match bytes.get(position)? {
        b'0' => position += 1,
        b'1'..=b'9' => {
            position += 1;
            while bytes.get(position).is_some_and(u8::is_ascii_digit) {
                position += 1;
            }
        }
        _ => return None,
    }
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == start {
            return None;
        }
    }
    if bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b'e' | b'E'))
    {
        position += 1;
        if bytes
            .get(position)
            .is_some_and(|byte| matches!(byte, b'+' | b'-'))
        {
            position += 1;
        }
        let start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        if position == start {
            return None;
        }
    }
    Some(position)
}

fn parse_json_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut output = Vec::new();
    let mut position = start.checked_add(1)?;
    while position < bytes.len() {
        match bytes[position] {
            b'"' => {
                return String::from_utf8(output)
                    .ok()
                    .map(|value| (value, position + 1));
            }
            b'\\' => {
                position += 1;
                let escaped = *bytes.get(position)?;
                match escaped {
                    b'"' | b'\\' | b'/' => output.push(escaped),
                    b'b' => output.push(8),
                    b'f' => output.push(12),
                    b'n' => output.push(b'\n'),
                    b'r' => output.push(b'\r'),
                    b't' => output.push(b'\t'),
                    b'u' => {
                        let (scalar, end) = parse_unicode_escape(bytes, position + 1)?;
                        let character = std::char::from_u32(scalar)?;
                        let mut encoded = [0; 4];
                        output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        position = end - 1;
                    }
                    _ => return None,
                }
            }
            byte if byte < 0x20 => return None,
            byte => output.push(byte),
        }
        position += 1;
    }
    None
}

fn parse_unicode_escape(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    let high = parse_hex_quad(bytes, start)?;
    let end = start.checked_add(4)?;
    if !(0xd800..=0xdbff).contains(&high) {
        return Some((high, end));
    }
    if bytes.get(end..end + 2)? != b"\\u" {
        return None;
    }
    let low = parse_hex_quad(bytes, end + 2)?;
    if !(0xdc00..=0xdfff).contains(&low) {
        return None;
    }
    let scalar = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
    Some((scalar, end + 6))
}

fn parse_hex_quad(bytes: &[u8], start: usize) -> Option<u32> {
    bytes
        .get(start..start + 4)?
        .iter()
        .try_fold(0, |value, byte| {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return None,
            };
            Some((value << 4) | digit)
        })
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

fn create_append_file(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_file| ())
}

/// Form one report line, disclosing a host sleep beside the earned verdict.
///
/// `suspend_gap` is seconds the host slept during the step, zero when it did
/// not. It is a measurement rather than an outcome, so it qualifies whichever
/// verdict the step earned instead of replacing it, and it is what makes the
/// awake `wall` reconcile with the time an observer outside the host saw pass.
fn report_bytes(
    name: &str,
    status: u8,
    wall: u64,
    budget: u64,
    verdict: Verdict,
    suspend_gap: u64,
    run_dir: &str,
) -> Vec<u8> {
    let mut report = String::new();
    write!(
        &mut report,
        "RUN-REPORT lane={name} exit={status} wall={wall}s budget={budget}s verdict={}",
        verdict.as_str()
    )
    .expect("writing to a String cannot fail");
    if suspend_gap > 0 {
        write!(&mut report, " suspend_gap={suspend_gap}s")
            .expect("writing to a String cannot fail");
    }
    writeln!(&mut report, " dir={run_dir}").expect("writing to a String cannot fail");
    report.into_bytes()
}

/// Classed evidence that an earlier step's text was not published as this
/// step's answer.
fn withheld_message_diagnostic(backend_name: &str) -> Vec<u8> {
    let mut diagnostic = String::new();
    writeln!(
        &mut diagnostic,
        "{backend_name}: step_message_withheld: the step's own transcript region carries no message; an earlier step's text is not this step's answer"
    )
    .expect("writing to a String cannot fail");
    diagnostic.into_bytes()
}

/// Classed evidence that the step's own message could not be written.
///
/// The path and the error are the whole of the finding: a reader who sees no
/// message file needs to know that one existed and what stopped it, and a
/// failed write is an I/O fault of this step, not a statement about what its
/// transcript said.
fn unwritten_message_diagnostic(backend_name: &str, path: &Path, error: &io::Error) -> Vec<u8> {
    let mut diagnostic = String::new();
    writeln!(
        &mut diagnostic,
        "{backend_name}: step_message_unwritten: the step's message could not be written to {}: {error}",
        path.display()
    )
    .expect("writing to a String cannot fail");
    diagnostic.into_bytes()
}

/// Classed evidence that the pool refused this step's dispatch.
fn rate_limited_diagnostic(backend_name: &str, state: &RateLimitState) -> Vec<u8> {
    let mut diagnostic = String::new();
    write!(
        &mut diagnostic,
        "{backend_name}: rate_limited: the pool rejected the dispatch"
    )
    .expect("writing to a String cannot fail");
    if let Some(resets_at) = state.resets_at() {
        write!(
            &mut diagnostic,
            "; {} resets at {} ({resets_at})",
            state.window(),
            iso8601_utc(resets_at)
        )
        .expect("writing to a String cannot fail");
    }
    diagnostic.push('\n');
    diagnostic.into_bytes()
}

/// The sidecar a refused dispatch leaves beside its report.
///
/// A verdict word states that the pool refused; the window and its reset
/// state when the next dispatch can succeed, which the report line has no
/// field for.
fn rate_limit_evidence(state: &RateLimitState) -> Vec<u8> {
    let mut evidence = String::new();
    write!(&mut evidence, "status={}", state.status()).expect("writing to a String cannot fail");
    if let Some(window) = state.rate_limit_type() {
        write!(&mut evidence, " type={window}").expect("writing to a String cannot fail");
    }
    if let Some(utilization) = state.utilization() {
        write!(&mut evidence, " utilization={utilization}")
            .expect("writing to a String cannot fail");
    }
    if let Some(resets_at) = state.resets_at() {
        write!(
            &mut evidence,
            " resets_at={resets_at} resets_at_iso={}",
            iso8601_utc(resets_at)
        )
        .expect("writing to a String cannot fail");
    }
    let stamp = utc_stamp().unwrap_or_else(|| String::from("unknown"));
    writeln!(&mut evidence, " at={stamp}").expect("writing to a String cannot fail");
    evidence.into_bytes()
}

/// One lane home's record of the pool state a step observed.
struct PoolReading {
    state: RateLimitState,
    observed_at: u64,
}

/// Record the pool state this step observed in the lane home it dispatched
/// from.
///
/// # Errors
///
/// Returns an I/O error when the lane home or the driver's clock is
/// unavailable, or when the record cannot be made durable.
fn record_pool_state(
    backend: &dyn Backend,
    state: &RateLimitState,
    run_text: &str,
) -> io::Result<()> {
    let home = backend
        .config_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no lane home"))?;
    let observed_at = epoch_seconds().ok_or_else(|| io::Error::other("no wall clock"))?;
    atomic_write(
        &home.join(POOL_FILE),
        &pool_bytes(state, observed_at, run_text),
    )
}

fn pool_bytes(state: &RateLimitState, observed_at: u64, run_text: &str) -> Vec<u8> {
    let mut record = String::new();
    write!(
        &mut record,
        "{{\"status\":\"{}\"",
        json_escaped(state.status())
    )
    .expect("writing to a String cannot fail");
    if let Some(window) = state.rate_limit_type() {
        write!(
            &mut record,
            ",\"rate_limit_type\":\"{}\"",
            json_escaped(window)
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(utilization) = state.utilization() {
        write!(&mut record, ",\"utilization\":{utilization}")
            .expect("writing to a String cannot fail");
    }
    if let Some(resets_at) = state.resets_at() {
        write!(&mut record, ",\"resets_at\":{resets_at}").expect("writing to a String cannot fail");
    }
    writeln!(
        &mut record,
        ",\"observed_at\":{observed_at},\"run_dir\":\"{}\"}}",
        json_escaped(run_text)
    )
    .expect("writing to a String cannot fail");
    record.into_bytes()
}

fn json_escaped(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for letter in value.chars() {
        match letter {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            control if control < ' ' => {
                write!(&mut escaped, "\\u{:04x}", u32::from(control))
                    .expect("writing to a String cannot fail");
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Refuse a dispatch the lane home's last reading says the window will not
/// take.
///
/// The reading is advisory: it is one step old, it can be absent or
/// unreadable, and only a rejection event in a step's own region proves a
/// refusal. What it buys is the difference between paying for a doomed
/// dispatch and not paying for it.
fn pool_refusal(backend: &dyn Backend, config: &Config) -> Option<Vec<u8>> {
    if config.ignore_pool() {
        return None;
    }
    let reading = read_pool_reading(&backend.config_dir()?.join(POOL_FILE))?;
    let resets_at = reading.state.resets_at()?;
    let now = epoch_seconds()?;
    // A reading taken at or after its own reset, or a window that has since
    // reset, is spent evidence and refuses nothing.
    if reading.observed_at >= resets_at || now >= resets_at {
        return None;
    }
    let refusing = reading.state.rejected()
        || reading
            .state
            .utilization()
            .is_some_and(|utilization| utilization >= config.pool_threshold());
    refusing.then(|| dispatch_rate_limited_diagnostic(backend.name(), &reading, resets_at))
}

fn read_pool_reading(path: &Path) -> Option<PoolReading> {
    let bytes = fs::read(path).ok()?;
    Some(PoolReading {
        state: RateLimitState::new(
            top_level_string_value(&bytes, "status")?,
            top_level_string_value(&bytes, "rate_limit_type"),
            top_level_f64_value(&bytes, "utilization"),
            top_level_u64_value(&bytes, "resets_at"),
        ),
        observed_at: top_level_u64_value(&bytes, "observed_at")?,
    })
}

fn dispatch_rate_limited_diagnostic(
    backend_name: &str,
    reading: &PoolReading,
    resets_at: u64,
) -> Vec<u8> {
    let state = &reading.state;
    let observed = state.utilization().map_or_else(
        || state.status().to_owned(),
        |utilization| {
            let mut text = String::new();
            write!(&mut text, "{utilization}").expect("writing to a String cannot fail");
            text
        },
    );
    let mut diagnostic = String::new();
    writeln!(
        &mut diagnostic,
        "{backend_name}: dispatch_rate_limited: the pool read {observed} at {}; {} resets at {} ({resets_at}); pass --ignore-pool to dispatch anyway",
        iso8601_utc(reading.observed_at),
        state.window(),
        iso8601_utc(resets_at)
    )
    .expect("writing to a String cannot fail");
    diagnostic.into_bytes()
}

/// Seconds since the epoch on the driver's own wall clock.
fn epoch_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// ISO-8601 UTC rendering of one epoch second.
///
/// A reset time is useless to an operator as an epoch alone, and a driver
/// that shells out for the conversion would fail exactly when the shell is
/// unavailable.
fn iso8601_utc(epoch: u64) -> String {
    let (year, month, day) = civil_from_days(epoch / SECONDS_PER_DAY);
    let second_of_day = epoch % SECONDS_PER_DAY;
    let mut stamp = String::new();
    write!(
        &mut stamp,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / SECONDS_PER_HOUR,
        (second_of_day / SECONDS_PER_MINUTE) % SECONDS_PER_MINUTE,
        second_of_day % SECONDS_PER_MINUTE
    )
    .expect("writing to a String cannot fail");
    stamp
}

/// The civil year, month, and day of one count of days since 1970-01-01.
///
/// The era arithmetic is the standard shift to a 400-year cycle beginning in
/// March, which makes the leap day the last day of its cycle and needs no
/// table.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    if month <= 2 {
        (year + 1, month, day)
    } else {
        (year, month, day)
    }
}

fn reconstructed_sidecar_bytes(
    result: TerminalResult,
    derivation: WallDerivation,
    wall: u64,
    pid: u32,
    stamp: &str,
) -> Vec<u8> {
    let (status, verdict) = result.finish();
    let mut record = String::new();
    writeln!(
        &mut record,
        "reason=DRIVER-EXIT derivation={} wall={wall}s exit={status} verdict={} pid={pid} at={stamp}",
        derivation.as_str(),
        verdict.as_str()
    )
    .expect("writing to a String cannot fail");
    record.into_bytes()
}

fn crashed_report_bytes(name: &str, pid: u32, run_dir: &str) -> Vec<u8> {
    let mut report = String::new();
    writeln!(
        &mut report,
        "RUN-REPORT lane={name} exit=1 wall=0s budget=0s verdict=CRASHED-HOST-EXIT pid={pid} dir={run_dir}"
    )
    .expect("writing to a String cannot fail");
    report.into_bytes()
}

/// Construct a fallback report for argument or panic paths.
#[must_use]
pub fn fallback_result(
    status: u8,
    budget: u64,
    diagnostic: Vec<u8>,
    name: &str,
    run_dir: &str,
    wall: u64,
) -> LaneResult {
    LaneResult {
        status,
        report: report_bytes(name, status, wall, budget, Verdict::Failed, 0, run_dir),
        diagnostic: Some(diagnostic),
        stderr_diagnostic: None,
    }
}

/// Construct a diagnostic-free fallback report for a refusal diagnosed on
/// standard error.
#[must_use]
pub fn fallback_report(
    status: u8,
    budget: u64,
    name: &str,
    run_dir: &str,
    wall: u64,
) -> LaneResult {
    LaneResult {
        status,
        report: report_bytes(name, status, wall, budget, Verdict::Failed, 0, run_dir),
        diagnostic: None,
        stderr_diagnostic: None,
    }
}

/// Publish fixed evidence followed by the final report to the owned stream.
///
/// # Errors
///
/// Returns an I/O error if any byte or the final flush is rejected.
pub fn publish<W: io::Write>(output: &mut W, result: &LaneResult) -> io::Result<()> {
    if let Some(diagnostic) = result.diagnostic() {
        output.write_all(diagnostic)?;
    }
    output.write_all(&result.report)?;
    output.flush()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?;
    let sequence = NEXT_ATOMIC_FILE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        report_publication_barrier(path)?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result
}

fn report_publication_barrier(path: &Path) -> io::Result<()> {
    // The parameter is read only by the debug-assertions test barrier; release
    // builds compile that away, so discard it there to stay under deny(unused).
    #[cfg(not(debug_assertions))]
    let _ = path;
    #[cfg(debug_assertions)]
    if path.file_name() == Some(OsStr::new("run-report.txt"))
        && let Some(barrier) = std::env::var_os("CODEX_LANE_TEST_REPORT_BARRIER")
    {
        let barrier = PathBuf::from(barrier);
        let mut ready = barrier.as_os_str().to_owned();
        ready.push(".ready");
        fs::write(PathBuf::from(ready), b"ready\n")?;
        while !barrier.exists() {
            std::thread::yield_now();
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

struct StepLock {
    path: PathBuf,
}

impl StepLock {
    fn acquire(backend: &dyn Backend, run_dir: &Path) -> Result<Self, ()> {
        let path = run_dir.join(backend.lock_file());
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| {
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()
            })
            .map_err(|_error| ())?;
        Ok(Self { path })
    }

    /// Name the spawned child beneath the driver that holds this lock.
    ///
    /// The rewrite is a rename over the same path, so the lock never stops
    /// existing and no second driver can slip between the two shapes.
    ///
    /// # Errors
    ///
    /// Returns the I/O error that prevented the lock from naming the child.
    fn record_child(&self, child: u32) -> io::Result<()> {
        atomic_write(
            &self.path,
            format!("{}\n{child}\n", std::process::id()).as_bytes(),
        )
    }
}

/// The driver and, once it exists, the child one step lock records.
///
/// The first line has been the driver that holds the lock since the first
/// lock, and stays that; the second names the process the step is actually
/// paying for. A lock with no second line is a driver that died before its
/// child existed, or one from a run that never recorded a child, and it is
/// read exactly as it always was. Anything else is not a lock this driver
/// wrote, and a holder that cannot be identified is never assumed dead.
fn parse_lock(bytes: &[u8]) -> Option<(u32, Option<u32>)> {
    let mut lines = std::str::from_utf8(bytes).ok()?.lines();
    let driver = lines.next()?.parse().ok()?;
    let child = lines.next().map(str::parse).transpose().ok()?;
    lines.next().is_none().then_some((driver, child))
}

impl Drop for StepLock {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.path);
    }
}

enum Clock {
    Real {
        started: Instant,
    },
    #[cfg(debug_assertions)]
    Synthetic {
        values: Vec<ClockSample>,
        position: usize,
        waited: u64,
    },
    #[cfg(debug_assertions)]
    FixtureFile {
        path: PathBuf,
        waited: u64,
    },
}

impl Clock {
    // Only a controlled clock can rendezvous with a subprocess fixture. Real
    // clocks never consult these inputs or block on this test channel.
    fn fixture_boundary(&self, name: &str) {
        #[cfg(debug_assertions)]
        use std::os::linux::net::SocketAddrExt as _;
        #[cfg(not(debug_assertions))]
        let _ = name;
        #[cfg(debug_assertions)]
        if !matches!(self, Self::Real { .. })
            && std::env::var("CODEX_LANE_TEST_BOUNDARY").as_deref() == Ok(name)
            && let Some(path) = std::env::var_os("CODEX_LANE_TEST_BOUNDARY_SOCKET")
            && let Ok(address) =
                std::os::unix::net::SocketAddr::from_abstract_name(path.as_encoded_bytes())
            && let Ok(mut channel) = std::os::unix::net::UnixStream::connect_addr(&address)
        {
            let _ignored = channel.set_read_timeout(Some(Duration::from_secs(10)));
            let _ignored = channel.write_all(b"ready");
            let mut release = [0];
            if channel.read_exact(&mut release).is_ok() && release == *b"s" {
                let deadline = Instant::now() + Duration::from_secs(5);
                while forwarded_signal().is_none() && Instant::now() < deadline {
                    std::thread::yield_now();
                }
            }
        }
    }

    fn from_environment() -> Result<Self, ()> {
        #[cfg(debug_assertions)]
        if let Ok(script) = std::env::var("CODEX_LANE_TEST_CLOCK")
            && let Some(path) = script.strip_prefix('@')
        {
            return Ok(Self::FixtureFile {
                path: PathBuf::from(path),
                waited: 0,
            });
        }
        #[cfg(debug_assertions)]
        if let Ok(script) = std::env::var("CODEX_LANE_TEST_CLOCK")
            && let Some(values) = parse_clock_samples(&script)
        {
            return Ok(Self::Synthetic {
                values,
                position: 0,
                waited: 0,
            });
        }
        boottime_seconds().map_err(|_error| ())?;
        Ok(Self::Real {
            started: Instant::now(),
        })
    }

    fn sample(&mut self) -> Result<ClockSample, ()> {
        match self {
            #[cfg(debug_assertions)]
            Self::FixtureFile { path, waited } => fs::read_to_string(path)
                .ok()
                .and_then(|text| parse_clock_samples(text.trim()))
                .and_then(|values| values.first().copied())
                .map(|value| {
                    ClockSample::new(
                        value.monotonic.saturating_add(*waited),
                        value.boottime.saturating_add(*waited),
                    )
                })
                .ok_or(()),
            Self::Real { started } => Ok(ClockSample::new(
                started.elapsed().as_secs(),
                boottime_seconds().map_err(|_error| ())?,
            )),
            #[cfg(debug_assertions)]
            Self::Synthetic {
                values,
                position,
                waited,
            } => {
                let value = values
                    .get(*position)
                    .copied()
                    .or_else(|| values.last().copied())
                    .unwrap_or_else(|| ClockSample::new(0, 0));
                *position = position.saturating_add(1);
                Ok(ClockSample::new(
                    value.monotonic.saturating_add(*waited),
                    value.boottime.saturating_add(*waited),
                ))
            }
        }
    }

    fn pause(&self) {
        match self {
            Self::Real { .. } => std::thread::sleep(Duration::from_secs(POLL_SECONDS)),
            #[cfg(debug_assertions)]
            Self::Synthetic { .. } | Self::FixtureFile { .. } => std::thread::yield_now(),
        }
    }

    fn wait(&mut self, seconds: u64) -> u64 {
        self.fixture_boundary("capacity-waiting");
        match self {
            Self::Real { .. } => {
                let start = Instant::now();
                let delay = Duration::from_secs(seconds);
                while start.elapsed() < delay && forwarded_signal().is_none() {
                    std::thread::sleep(
                        delay
                            .saturating_sub(start.elapsed())
                            .min(Duration::from_secs(1)),
                    );
                }
                start.elapsed().as_secs()
            }
            #[cfg(debug_assertions)]
            Self::Synthetic { waited, .. } | Self::FixtureFile { waited, .. } => {
                let elapsed = if forwarded_signal().is_some() {
                    0
                } else {
                    seconds
                };
                *waited = waited.saturating_add(elapsed);
                elapsed
            }
        }
    }
}

#[cfg(debug_assertions)]
fn parse_clock_samples(script: &str) -> Option<Vec<ClockSample>> {
    let values = script
        .split(',')
        .map(|value| {
            let (monotonic, boottime) = value.split_once(':').unwrap_or((value, value));
            Some(ClockSample::new(
                monotonic.parse().ok()?,
                boottime.parse().ok()?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    (!values.is_empty()
        && values.windows(2).all(|pair| {
            pair[0].monotonic <= pair[1].monotonic && pair[0].boottime <= pair[1].boottime
        }))
    .then_some(values)
}

fn boottime_seconds() -> io::Result<u64> {
    let uptime = fs::read_to_string("/proc/uptime")?;
    let value = uptime
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid /proc/uptime"))?;
    let whole = value
        .split_once('.')
        .map_or(value, |(whole, _fraction)| whole);
    whole
        .parse()
        .map_err(|_error| io::Error::new(io::ErrorKind::InvalidData, "invalid /proc/uptime"))
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::{self, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        Backend, BudgetExpiry, ClockSample, Config, ContextTracker, ContextUse, CrashRecovery,
        DEFAULT_POOL_THRESHOLD, GatewayWatch, MAX_FRESH_RUN_DIR_ATTEMPTS, MonitorDecision,
        MonitorReadings, PreparationFailure, Prompt, RateLimitRejection, RateLimitState,
        ResumeRefusal, SUSPEND_GAP_THRESHOLD_SECONDS, TerminalResult, UsageError, WallDerivation,
        allocate_fresh_run_dir, budget_hint, create_fresh_run_dir, epoch_millis, finish_context,
        fresh_run_dir, internal_diagnostic, iso8601_utc, last_complete_line, monitor_file,
        monitor_sidecar_bytes, monitor_sidecar_with_context, parse_arguments, parse_lock,
        prepare_resume_with_size, publication_diagnostic, reconstructed_sidecar_bytes,
        recover_dead_lock, resolve_run_dir, runtime_diagnostic, top_level_bool_value,
        top_level_string_value, top_level_u64_value, usage_diagnostic, write_thread_id,
    };

    /// ´claim:lifecycle:two-monitors-in-one-run-get-distinct-capture-paths´
    /// ´test:unit:two-monitors-in-one-run-get-distinct-capture-paths´
    #[test]
    fn two_monitors_in_one_run_get_distinct_capture_paths() {
        let run = Path::new("/fixture/run");
        let first = monitor_file(run);
        let second = monitor_file(run);
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(run));
        assert_eq!(second.parent(), Some(run));
    }

    struct TestBackend;

    /// # Panics
    /// Panics only if fixture setup or the saved letter contract fails.
    ///
    /// ´claim:lifecycle:resumed-round-saves-letter-beside-pointer-input´
    /// ´test:unit:resumed-round-saves-letter-beside-pointer-input´
    #[test]
    fn resumed_round_saves_letter_beside_pointer_input() {
        for fresh in [false, true] {
            let fixture = FreshRunFixture::new("step-letter");
            let letter = fixture.0.join("resume.md");
            let body = b"Resume the interrupted work.\n\nKeep the final newline.\n";
            fs::write(&letter, body).expect("write letter");
            let pointer = b"Read /home/worker/.local/inbox/resume.md.\n";
            let arguments = [
                OsString::from("--step-letter"),
                letter.into_os_string(),
                OsString::from("-t"),
                OsString::from("60"),
                OsString::from("-n"),
                OsString::from("resume"),
                OsString::from("pointer"),
            ];
            let mut config = parse_arguments(&arguments).expect("parse letter option");
            assert_eq!(budget_hint(&arguments), 60);
            if fresh {
                super::prepare_fresh(&config, pointer, &fixture.0).expect("fresh continuation");
                assert_eq!(
                    fs::read(fixture.0.join("brief.txt")).expect("brief"),
                    pointer
                );
            } else {
                let mut dispatch = config.clone();
                dispatch.name = "dispatch".into();
                dispatch.step_letter = None;
                super::prepare_fresh(&dispatch, b"first pointer\n", &fixture.0)
                    .expect("first round");
                fs::write(
                    fixture.0.join("run-report.txt"),
                    b"RUN-REPORT lane=dispatch exit=0\n",
                )
                .expect("prior report");
                config.session = Some("session-1".into());
                super::prepare_resume(&config, pointer, &fixture.0).expect("resumed round");
                assert_eq!(
                    fs::read(fixture.0.join("brief.txt")).expect("first brief"),
                    b"first pointer\n"
                );
            }
            assert_eq!(
                fs::read(fixture.0.join("step-resume.txt")).expect("saved step letter"),
                body
            );
            config.session = Some("session-1".into());
            for recovery in ["capacity", "suspend"] {
                assert!(
                    super::prepare_same_thread_resume(
                        &TestBackend,
                        &mut config,
                        &fixture.0,
                        recovery
                    )
                    .expect("same-thread retry")
                );
                assert_eq!(
                    fs::read(super::child_input_path(&config, &fixture.0)).expect("child input"),
                    pointer
                );
                assert_eq!(
                    fs::read(fixture.0.join("step-resume.txt")).expect("retained letter"),
                    body
                );
            }
        }
    }

    /// # Panics
    /// Panics only if fixture setup or the letter option refusal contract fails.
    ///
    /// ´claim:lifecycle:step-letter-option-refuses-missing-oversized-and-repeated-inputs´
    /// ´test:unit:step-letter-option-refuses-missing-oversized-and-repeated-inputs´
    #[test]
    fn step_letter_option_refuses_missing_oversized_and_repeated_inputs() {
        let fixture = FreshRunFixture::new("invalid-step-letter");
        let letter = fixture.0.join("letter");
        let mut arguments = vec![
            OsString::from("-t"),
            OsString::from("60"),
            OsString::from("--step-letter"),
            letter.clone().into_os_string(),
            OsString::from("pointer"),
        ];
        assert!(parse_arguments(&arguments).is_none());
        fs::write(&letter, vec![b'x'; 1_048_577]).expect("oversized letter");
        assert!(parse_arguments(&arguments).is_none());
        fs::write(&letter, b"letter").expect("valid letter");
        let config = parse_arguments(&arguments).expect("single valid letter parses");
        super::prepare_fresh(&config, b"pointer\n", &fixture.0).expect("save valid letter");
        assert_eq!(
            fs::read(fixture.0.join(format!("step-{}.txt", config.name)))
                .expect("saved valid letter"),
            b"letter"
        );
        arguments.splice(
            4..4,
            [OsString::from("--step-letter"), letter.into_os_string()],
        );
        assert!(parse_arguments(&arguments).is_none());
    }

    /// ´claim:lifecycle:step-evidence-must-match-verified-mail-digest´
    /// ´test:unit:step-evidence-must-match-verified-mail-digest´
    #[test]
    fn step_evidence_must_match_verified_mail_digest() {
        let fixture = FreshRunFixture::new("mail-evidence-digest");
        let letter = fixture.0.join("mail.txt");
        fs::write(&letter, b"abc").expect("verified bytes");
        let args = vec![
            OsString::from("-t"),
            OsString::from("60"),
            OsString::from("--step-letter"),
            letter.clone().into_os_string(),
            OsString::from("--step-letter-sha256"),
            OsString::from("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            OsString::from("Read /mail/inbox/alpha.2026-01-01T00:00:00.000Z.letter."),
        ];
        let config = parse_arguments(&args).expect("matching delivery digest");
        fs::write(&letter, b"changed").expect("race after parsing");
        super::prepare_fresh(&config, b"pointer\n", &fixture.0)
            .expect("retained verified snapshot");
        assert_eq!(
            fs::read(fixture.0.join(format!("step-{}.txt", config.name))).expect("evidence"),
            b"abc"
        );
        assert!(
            parse_arguments(&args).is_none(),
            "changed source refuses another launch"
        );
        let mut repeated = args.clone();
        repeated.splice(6..6, [args[4].clone(), args[5].clone()]);
        assert!(parse_arguments(&repeated).is_none());
    }

    struct FreshRunFixture(PathBuf);

    impl FreshRunFixture {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after the epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "lane-lifecycle-fresh-{}-{unique}-{label}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create fresh run fixture");
            Self(root)
        }

        fn candidate(&self, attempt: u32) -> PathBuf {
            let suffix = if attempt == 1 {
                String::new()
            } else {
                format!("-{attempt}")
            };
            self.0.join(format!("20260926T120000Z-lane{suffix}"))
        }
    }

    impl Drop for FreshRunFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove fresh run fixture");
        }
    }

    struct GatewayFixture {
        root: PathBuf,
        state: PathBuf,
        workdir: PathBuf,
        unix_ms: u64,
    }

    impl GatewayFixture {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after the epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "lane-lifecycle-gateway-{}-{unique}-{label}",
                std::process::id()
            ));
            let state = root.join("gateway");
            let workdir = root.join("worktree");
            for directory in [
                state.join("registrations"),
                state.join("execution-budgets/gw"),
                state.join("proposal-verdicts/gw"),
                state.join("audit"),
                workdir.clone(),
            ] {
                fs::create_dir_all(directory).expect("create gateway fixture directory");
            }
            fs::write(
                state.join("registrations/gw.toml"),
                format!("worktree = \"{}\"\n", workdir.display()),
            )
            .expect("write registration");
            fs::write(state.join("audit/gw.jsonl"), b"").expect("write empty audit");
            let fixture = Self {
                root,
                state,
                workdir,
                unix_ms: epoch_millis().expect("current unix millisecond"),
            };
            fixture.proposal(3_600);
            fixture.verdict("approved", fixture.unix_ms);
            fixture
        }

        fn proposal(&self, timeout: u64) {
            fs::write(
                self.state.join("execution-budgets/gw/7.json"),
                format!(
                    "{{\"schema\":1,\"lane\":\"gw\",\"seq\":7,\"argv\":[\"true\"],\"reason\":\"r\",\"queued_unix_ms\":{},\"timeout_seconds\":{timeout}}}",
                    self.unix_ms
                ),
            )
            .expect("write proposal");
        }

        fn verdict(&self, decision: &str, resolved: u64) {
            fs::write(
                self.state.join("proposal-verdicts/gw/7.json"),
                format!(
                    "{{\"schema\":1,\"actor\":\"orchestrator\",\"verdict\":{{\"seq\":7,\"decision\":\"{decision}\",\"wall_millis\":1}},\"resolved_unix_ms\":{resolved}}}"
                ),
            )
            .expect("write verdict");
        }

        fn audited_result(&self) {
            fs::write(
                self.state.join("audit/gw.jsonl"),
                format!(
                    "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"result\",\"result\":{{\"seq\":7,\"operation\":\"run\",\"exit_code\":0,\"verdict\":\"ok\"}}}}}}\n",
                    self.unix_ms
                ),
            )
            .expect("write audited result");
        }

        fn roster_request(&self, budget: u64) {
            fs::remove_file(self.state.join("proposal-verdicts/gw/7.json"))
                .expect("remove proposal verdict");
            fs::remove_dir(self.state.join("proposal-verdicts/gw"))
                .expect("remove proposal verdict directory");
            fs::write(
                self.state.join("registrations/gw.toml"),
                format!(
                    "worktree = \"{}\"\n[commands.test]\nargv = [\"true\"]\nwall_budget_seconds = {budget}\n",
                    self.workdir.display()
                ),
            )
            .expect("write roster registration");
            fs::write(
                self.state.join("audit/gw.jsonl"),
                format!(
                    "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"request\",\"request\":{{\"encoding\":\"json\",\"value\":{{\"schema\":1,\"seq\":8,\"op\":\"run\",\"command\":\"test\"}},\"raw\":\"request\"}}}}}}\n",
                    self.unix_ms - 5_000
                ),
            )
            .expect("write roster request");
        }

        fn audited_roster_result(&self) {
            let path = self.state.join("audit/gw.jsonl");
            let mut audit = fs::read(&path).expect("read roster audit");
            audit.extend_from_slice(
                format!(
                    "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"result\",\"result\":{{\"seq\":8,\"operation\":\"run\",\"exit_code\":0,\"verdict\":\"ok\"}}}}}}\n",
                    self.unix_ms
                )
                .as_bytes(),
            );
            fs::write(path, audit).expect("append roster result");
        }

        fn audited_roster_refusal(&self) {
            let path = self.state.join("audit/gw.jsonl");
            let mut audit = fs::read(&path).expect("read roster audit");
            audit.extend_from_slice(
                format!(
                    "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"refusal\",\"refusal\":{{\"seq\":8,\"rule\":\"cooldown_active\"}}}}}}\n",
                    self.unix_ms
                )
                .as_bytes(),
            );
            fs::write(path, audit).expect("append roster refusal");
        }

        fn watch(&self) -> GatewayWatch {
            GatewayWatch::new("gw", &self.state, &self.workdir).expect("registered gateway watch")
        }
    }

    impl Drop for GatewayFixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    impl Backend for TestBackend {
        fn name(&self) -> &'static str {
            "test-lane"
        }

        fn program(&self) -> Option<OsString> {
            None
        }

        fn command(&self, _config: &Config, _run_dir: &Path) -> Result<Command, String> {
            Err("test backend has no command".into())
        }

        fn thread_id(&self, _events: &[u8]) -> Option<String> {
            None
        }

        fn last_message(&self, _events: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn terminal_result(&self, _events: &[u8]) -> Option<TerminalResult> {
            None
        }

        fn context_use(&self, event: &[u8]) -> Option<ContextUse> {
            (event == br#"{"type":"turn.completed"}"#)
                .then_some(ContextUse::measured(50, 100, "test-field").expect("window"))
        }

        fn rate_limit_rejection(&self, _events: &[u8]) -> Option<RateLimitRejection> {
            None
        }

        fn rate_limit_state(&self, _events: &[u8]) -> Option<RateLimitState> {
            None
        }

        fn config_dir(&self) -> Option<PathBuf> {
            None
        }

        fn lock_file(&self) -> &'static str {
            ".test-lane.lock"
        }

        fn configure_pure(&self, _config: &mut Config, _run_dir: &Path) -> Result<(), ()> {
            Ok(())
        }
    }

    /// ´claim:lifecycle:mailbox-write-error-reaps-child-and-scans-final-turn´
    /// ´test:unit:mailbox-write-error-reaps-child-and-scans-final-turn´
    #[test]
    fn mailbox_write_error_reaps_child_and_scans_final_turn() {
        let fixture = FreshRunFixture::new("mailbox-error");
        let events = fixture.0.join("events.jsonl");
        fs::write(&events, b"").expect("event stream");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("boundary");
        let mut context =
            ContextTracker::reconcile(&TestBackend, &events, &fixture.0).expect("initial context");
        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .expect("live child");
        fs::write(&events, b"{\"type\":\"turn.completed\"}\n").expect("completed turn");
        let readings = MonitorReadings {
            wall: 1,
            budget: 30,
            event_size: 26,
            last_growth: 0,
            quiet: 0,
        };
        let diagnostic = super::mailbox_failure_after_poll(
            &TestBackend,
            &mut child,
            false,
            &fixture.0,
            &mut context,
            &fixture.0.join("monitor.txt"),
            readings,
            None,
            MonitorDecision::Continue,
            ClockSample::new(1, 1),
            None,
            &io::Error::other("letter-record: write refused"),
        );
        assert!(diagnostic.contains("mailbox watcher: letter-record: write refused"));
        assert!(diagnostic.contains("child=stopped-and-reaped; final-context=complete"));
        assert!(child.try_wait().expect("wait").is_some());
        assert!(!fixture.0.join("kill-evidence.txt").exists());
        assert!(
            fs::read_to_string(fixture.0.join("context.jsonl"))
                .expect("context record")
                .contains("\"turn\":1")
        );
    }

    /// ´claim:lifecycle:context-turn-records-follow-complete-event-lines-once´
    /// ´test:unit:context-turn-records-follow-complete-event-lines-once´
    #[test]
    fn context_turn_records_follow_complete_event_lines_once() {
        let fixture = FreshRunFixture::new("context");
        let events = fixture.0.join("events.jsonl");
        fs::write(
            &events,
            b"{\"type\":\"turn.completed\"}\n{\"type\":\"turn.com",
        )
        .expect("events");
        let mut tracker = ContextTracker::new(0);
        tracker
            .observe_durable(&TestBackend, &events, &fixture.0)
            .expect("first turn");
        tracker
            .observe_durable(&TestBackend, &events, &fixture.0)
            .expect("no duplicate");
        fs::OpenOptions::new()
            .append(true)
            .open(&events)
            .expect("events file")
            .write_all(b"pleted\"}\n")
            .expect("complete second turn");
        tracker
            .observe_durable(&TestBackend, &events, &fixture.0)
            .expect("second turn");
        let lines = fs::read_to_string(fixture.0.join("context.jsonl")).expect("context record");
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.contains("\"used\":50,\"window\":100,\"fraction\":0.5"));
        assert!(lines.contains("\"turn\":2"));
        let sidecar = monitor_sidecar_with_context(
            0,
            1,
            60,
            ClockSample::new(1, 1),
            None,
            tracker
                .latest
                .as_ref()
                .map(|(state, at)| (*state, tracker.turn, at.as_str())),
            None,
        );
        assert!(String::from_utf8(sidecar).expect("monitor").contains(
            "context_state=measured context_used=50 context_window=100 context_fraction=0.5"
        ));
    }

    /// ´claim:lifecycle:dead-driver-reconciles-unrecorded-turn-by-event-boundary´
    /// ´test:unit:dead-driver-reconciles-unrecorded-turn-by-event-boundary´
    #[test]
    fn dead_driver_reconciles_unrecorded_turn_by_event_boundary() {
        let fixture = FreshRunFixture::new("context-recovery");
        let events = fixture.0.join("events.jsonl");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("step boundary");
        fs::write(&events, b"{\"type\":\"turn.completed\"}\n").expect("first turn");
        ContextTracker::reconcile(&TestBackend, &events, &fixture.0).expect("first record");
        fs::OpenOptions::new()
            .append(true)
            .open(&events)
            .expect("events")
            .write_all(b"{\"type\":\"turn.completed\"}\n")
            .expect("second turn");
        fs::write(fixture.0.join(".test-lane.lock"), b"4000000\n").expect("dead lock");
        fs::write(
            fixture.0.join("run-report.txt"),
            b"RUN-REPORT lane=lane exit=0\n",
        )
        .expect("settled report");
        recover_dead_lock(&TestBackend, &fixture.0).expect("recover dead driver");
        let record = fs::read_to_string(fixture.0.join("context.jsonl")).expect("context record");
        assert_eq!(record.lines().count(), 2);
        assert!(record.contains("\"event_end\":26"));
        assert!(record.contains("\"event_end\":52"));
    }

    /// ´claim:lifecycle:dead-preparation-restores-boundaries-before-context-reconciliation´
    /// ´test:unit:dead-preparation-restores-boundaries-before-context-reconciliation´
    #[test]
    fn dead_preparation_restores_boundaries_before_context_reconciliation() {
        let fixture = FreshRunFixture::new("dead-preparation-boundary");
        let events = b"{\"type\":\"turn.completed\"}\n";
        fs::write(fixture.0.join("events.jsonl"), events).expect("prior turn");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("unflipped start");
        fs::write(fixture.0.join(".step-name"), b"work\n").expect("flipped step name");
        let report = b"RUN-REPORT lane=gate exit=0\n";
        fs::write(fixture.0.join("run-report.txt"), report).expect("standing prior report");
        let history = fixture.0.join("steps/gate");
        fs::create_dir_all(&history).expect("preparation archive");
        fs::write(history.join("run-report.txt"), report).expect("archived prior report");
        fs::write(history.join("event-start.txt"), b"0\n").expect("archived prior start");
        fs::write(history.join("event-end.txt"), format!("{}\n", events.len()))
            .expect("archived prior end");
        let lock = fixture.0.join(".test-lane.lock");
        fs::write(&lock, b"4000000\n").expect("dead driver lock");

        let recovery = recover_dead_lock(&TestBackend, &fixture.0)
            .expect("rollback then reconciliation succeeds");
        assert!(matches!(recovery, Some(CrashRecovery::Unprepared { .. })));
        assert!(!lock.exists());
        assert!(!history.exists());
        assert_eq!(
            fs::read(fixture.0.join("run-report.txt")).expect("prior report survives"),
            report
        );
        assert_eq!(
            fs::read(fixture.0.join(".step-name")).expect("prior name restored"),
            b"gate\n"
        );
        let record = fs::read_to_string(fixture.0.join("context.jsonl"))
            .expect("prior turn reconciled after rollback");
        assert!(record.contains("\"turn\":1"));
        assert!(record.contains(&format!("\"event_end\":{}", events.len())));
        assert!(!fixture.0.join(".reconstructed").exists());
    }

    /// ´claim:lifecycle:resumed-step-boundary-keeps-new-turn-after-old-fragment´
    /// ´test:unit:resumed-step-boundary-keeps-new-turn-after-old-fragment´
    #[test]
    fn resumed_step_boundary_keeps_new_turn_after_old_fragment() {
        let fixture = FreshRunFixture::new("context-resume-boundary");
        let events = fixture.0.join("events.jsonl");
        let fragment = b"{\"type\":\"item";
        let turn = b"{\"type\":\"turn.completed\"}\n";
        fs::write(&events, fragment).expect("earlier child fragment");
        let history = fixture.0.join("steps").join("dispatch");
        fs::create_dir_all(&history).expect("prior step archive");
        let boundary = format!("{}\n", fragment.len());
        fs::write(history.join("event-start.txt"), b"0\n").expect("prior step start");
        fs::write(history.join("event-end.txt"), &boundary).expect("prior step end");
        fs::write(fixture.0.join(".event-start"), &boundary).expect("resume step start");
        let mut tracker = ContextTracker::reconcile(&TestBackend, &events, &fixture.0)
            .expect("resume reconciliation");
        assert!(tracker.pending.is_empty(), "earlier fragment is closed");
        fs::OpenOptions::new()
            .append(true)
            .open(&events)
            .expect("events")
            .write_all(turn)
            .expect("resumed child first turn");
        tracker
            .observe_durable(&TestBackend, &events, &fixture.0)
            .expect("resumed turn record");
        let record = fs::read_to_string(fixture.0.join("context.jsonl")).expect("context record");
        assert_eq!(record.lines().count(), 1);
        assert!(record.contains("\"turn\":1"));
        assert!(record.contains(&format!("\"event_end\":{}", fragment.len() + turn.len())));
        let next = fixture.0.join("steps").join("review");
        fs::create_dir(&next).expect("second step archive");
        let next_boundary = format!("{}\n", fragment.len() + turn.len());
        fs::write(next.join("event-start.txt"), &boundary).expect("second step start");
        fs::write(next.join("event-end.txt"), &next_boundary).expect("second step end");
        fs::write(fixture.0.join(".event-start"), &next_boundary).expect("following step start");
        ContextTracker::reconcile(&TestBackend, &events, &fixture.0)
            .expect("restart reconciliation");
        assert_eq!(
            fs::read_to_string(fixture.0.join("context.jsonl")).expect("reconciled record"),
            record
        );
    }

    /// ´claim:lifecycle:missing-archived-end-refuses-without-replacing-a-later-turn´
    /// ´test:unit:missing-archived-end-refuses-without-replacing-a-later-turn´
    #[test]
    fn missing_archived_end_refuses_without_replacing_a_later_turn() {
        let fixture = FreshRunFixture::new("context-missing-boundary");
        let events = fixture.0.join("events.jsonl");
        let fragment = b"{\"type\":\"item";
        let turn = b"{\"type\":\"turn.completed\"}\n";
        let mut stream = fragment.to_vec();
        stream.extend_from_slice(turn);
        fs::write(&events, &stream).expect("A fragment and B turn");
        let a = fixture.0.join("steps").join("A");
        fs::create_dir_all(&a).expect("A archive");
        fs::write(a.join("event-start.txt"), b"0\n").expect("A start");
        fs::write(a.join("event-end.txt"), format!("{}\n", fragment.len())).expect("A end");
        fs::write(
            fixture.0.join(".event-start"),
            format!("{}\n", fragment.len()),
        )
        .expect("B start");
        ContextTracker::reconcile(&TestBackend, &events, &fixture.0).expect("B record");
        let context_path = fixture.0.join("context.jsonl");
        let before = fs::read(&context_path).expect("B record bytes");
        assert!(String::from_utf8_lossy(&before).contains("\"turn\":1"));

        fs::remove_file(a.join("event-end.txt")).expect("missing A boundary");
        let b = fixture.0.join("steps").join("B");
        fs::create_dir(&b).expect("B archive");
        fs::write(b.join("event-start.txt"), format!("{}\n", fragment.len()))
            .expect("B archived start");
        fs::write(b.join("event-end.txt"), format!("{}\n", stream.len())).expect("B archived end");
        fs::write(
            fixture.0.join(".event-start"),
            format!("{}\n", stream.len()),
        )
        .expect("C start");
        fs::write(fixture.0.join(".step-name"), b"C\n").expect("current step");
        fs::write(
            fixture.0.join("run-report.txt"),
            b"RUN-REPORT lane=B exit=0\n",
        )
        .expect("B report");
        let error = ContextTracker::reconcile(&TestBackend, &events, &fixture.0)
            .err()
            .expect("missing A end refuses");
        assert!(
            error
                .to_string()
                .contains("step A: archived event-end.txt is missing")
        );
        assert_eq!(fs::read(&context_path).expect("record survives"), before);

        fs::write(fixture.0.join(".test-lane.lock"), b"4000000\n").expect("dead driver");
        let refusal = recover_dead_lock(&TestBackend, &fixture.0).expect_err("recovery refuses");
        assert!(
            String::from_utf8_lossy(&refusal.diagnostic("test-lane"))
                .contains("resume_context_record: context-boundary: step A:")
        );
        assert_eq!(
            fs::read(&context_path).expect("record still survives"),
            before
        );
    }

    fn three_step_context_fixture(label: &str) -> (FreshRunFixture, Vec<u8>, usize, usize) {
        let fixture = FreshRunFixture::new(label);
        let events = fixture.0.join("events.jsonl");
        let fragment = b"{\"type\":\"item";
        let turn = b"{\"type\":\"turn.completed\"}\n";
        let mut stream = fragment.to_vec();
        stream.extend_from_slice(turn);
        fs::write(&events, &stream).expect("A fragment and B turn");
        let a = fixture.0.join("steps").join("A");
        fs::create_dir_all(&a).expect("A archive");
        fs::write(a.join("event-start.txt"), b"0\n").expect("A start");
        fs::write(a.join("event-end.txt"), format!("{}\n", fragment.len())).expect("A end");
        fs::write(
            fixture.0.join(".event-start"),
            format!("{}\n", fragment.len()),
        )
        .expect("B start");
        ContextTracker::reconcile(&TestBackend, &events, &fixture.0).expect("B record");
        let before = fs::read(fixture.0.join("context.jsonl")).expect("B record bytes");
        assert!(String::from_utf8_lossy(&before).contains("\"turn\":1"));
        let b = fixture.0.join("steps").join("B");
        fs::create_dir(&b).expect("B archive");
        fs::write(b.join("event-start.txt"), format!("{}\n", fragment.len()))
            .expect("B archived start");
        fs::write(b.join("event-end.txt"), format!("{}\n", stream.len())).expect("B end");
        fs::write(
            fixture.0.join(".event-start"),
            format!("{}\n", stream.len()),
        )
        .expect("C start");
        fs::write(fixture.0.join(".step-name"), b"C\n").expect("C name");
        (fixture, before, fragment.len(), stream.len())
    }

    /// ´claim:lifecycle:in-range-wrong-end-refuses-without-replacing-a-later-turn´
    /// ´test:unit:in-range-wrong-end-refuses-without-replacing-a-later-turn´
    #[test]
    fn in_range_wrong_end_refuses_without_replacing_a_later_turn() {
        let (fixture, before, b_start, _c_start) = three_step_context_fixture("wrong-A-end");
        fs::write(fixture.0.join("steps/A/event-end.txt"), b"0\n").expect("wrong A end");
        let error =
            ContextTracker::reconcile(&TestBackend, &fixture.0.join("events.jsonl"), &fixture.0)
                .err()
                .expect("chain refuses wrong A end");
        assert!(
            error
                .to_string()
                .contains(&format!("step A: end 0 != next start {b_start}"))
        );
        assert_eq!(
            fs::read(fixture.0.join("context.jsonl")).expect("B record survives"),
            before
        );
    }

    /// ´claim:lifecycle:last-archived-end-must-match-current-start´
    /// ´test:unit:last-archived-end-must-match-current-start´
    #[test]
    fn last_archived_end_must_match_current_start() {
        let (fixture, before, b_start, c_start) = three_step_context_fixture("wrong-B-end");
        fs::write(
            fixture.0.join("steps/B/event-end.txt"),
            format!("{b_start}\n"),
        )
        .expect("wrong B end");
        let error =
            ContextTracker::reconcile(&TestBackend, &fixture.0.join("events.jsonl"), &fixture.0)
                .err()
                .expect("chain refuses wrong final end");
        assert!(
            error
                .to_string()
                .contains(&format!("step B: end {b_start} != current start {c_start}"))
        );
        assert_eq!(
            fs::read(fixture.0.join("context.jsonl")).expect("B record survives"),
            before
        );
    }

    /// ´claim:lifecycle:missing-end-skips-an-unfinished-preparation-with-no-later-child´
    /// ´test:unit:missing-end-skips-an-unfinished-preparation-with-no-later-child´
    #[test]
    fn missing_end_skips_an_unfinished_preparation_with_no_later_child() {
        let fixture = FreshRunFixture::new("context-preparation-boundary");
        let events = fixture.0.join("events.jsonl");
        fs::write(&events, b"{\"type\":\"item").expect("unfinished current event");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("current start");
        fs::write(fixture.0.join(".step-name"), b"A\n").expect("current name");
        fs::write(
            fixture.0.join("run-report.txt"),
            b"RUN-REPORT lane=A exit=0\n",
        )
        .expect("standing report");
        let a = fixture.0.join("steps").join("A");
        fs::create_dir_all(&a).expect("preparation archive");
        fs::write(a.join("run-report.txt"), b"RUN-REPORT lane=A exit=0\n")
            .expect("archived report");
        fs::write(a.join("event-start.txt"), b"0\n").expect("archived start");
        let tracker = ContextTracker::reconcile(&TestBackend, &events, &fixture.0)
            .expect("unfinished preparation has no later child");
        assert_eq!(tracker.pending, b"{\"type\":\"item");
        assert_eq!(tracker.records.len(), 0);
    }

    /// ´claim:lifecycle:context-publication-repairs-partial-and-sync-failed-writes´
    /// ´test:unit:context-publication-repairs-partial-and-sync-failed-writes´
    #[test]
    fn context_publication_repairs_partial_and_sync_failed_writes() {
        for partial in [true, false] {
            let fixture = FreshRunFixture::new(if partial { "partial" } else { "sync" });
            let events = fixture.0.join("events.jsonl");
            fs::write(fixture.0.join(".event-start"), b"0\n").expect("step boundary");
            fs::write(&events, b"{\"type\":\"turn.completed\"}\n").expect("turn");
            let mut tracker = ContextTracker::new(0);
            let failed = tracker.observe_with(&TestBackend, &events, &fixture.0, |path, bytes| {
                fs::write(
                    path,
                    if partial {
                        &bytes[..bytes.len() / 2]
                    } else {
                        bytes
                    },
                )?;
                Err(io::Error::other("injected sync failure"))
            });
            assert!(failed.is_err());
            assert_eq!(tracker.offset, 0);
            tracker
                .observe_durable(&TestBackend, &events, &fixture.0)
                .expect("retry publication");
            let record = fs::read_to_string(fixture.0.join("context.jsonl")).expect("record");
            assert_eq!(record.lines().count(), 1);
            assert!(record.ends_with('\n'));
            ContextTracker::reconcile(&TestBackend, &events, &fixture.0)
                .expect("restart reconciliation");
            assert_eq!(
                fs::read_to_string(fixture.0.join("context.jsonl")).expect("record after restart"),
                record
            );
        }
    }

    /// ´claim:lifecycle:stopped-child-final-scan-records-turn-and-names-write-error´
    /// ´test:unit:stopped-child-final-scan-records-turn-and-names-write-error´
    #[test]
    fn stopped_child_final_scan_records_turn_and_names_write_error() {
        let fixture = FreshRunFixture::new("context-stop");
        let events = fixture.0.join("events.jsonl");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("step boundary");
        fs::write(&events, b"{\"type\":\"turn.completed\"}\n").expect("turn after prior scan");
        let monitor = fixture.0.join(".monitor-1-0");
        let mut tracker = ContextTracker::new(0);
        let readings = MonitorReadings {
            wall: 1,
            budget: 10,
            event_size: 0,
            last_growth: 0,
            quiet: 1,
        };
        finish_context(
            &TestBackend,
            &fixture.0,
            &mut tracker,
            &monitor,
            readings,
            None,
            MonitorDecision::Continue,
            ClockSample::new(1, 1),
            None,
        )
        .expect("final scan");
        assert!(
            fs::read_to_string(&monitor)
                .expect("monitor")
                .contains("context_state=measured")
        );
        assert_eq!(
            fs::read_to_string(fixture.0.join("context.jsonl"))
                .expect("record")
                .lines()
                .count(),
            1
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&events)
            .expect("events")
            .write_all(b"{\"type\":\"turn.completed\"}\n")
            .expect("next turn");
        fs::remove_file(fixture.0.join("context.jsonl")).expect("remove record fixture");
        fs::create_dir(fixture.0.join("context.jsonl")).expect("block publication");
        let error = finish_context(
            &TestBackend,
            &fixture.0,
            &mut tracker,
            &monitor,
            readings,
            None,
            MonitorDecision::Continue,
            ClockSample::new(2, 2),
            None,
        )
        .expect_err("named stop error");
        assert!(error.starts_with("context record:"));
    }

    /// The thread-id writer distinguishes a match, a conflict, and an I/O fault.
    /// ´claim:lifecycle:the-thread-id-writer-separates-a-conflict-from-a-fault´
    /// ´test:unit:the-thread-id-writer-separates-a-conflict-from-a-fault´
    #[test]
    fn the_thread_id_writer_separates_a_conflict_from_a_fault() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos();
        let run_dir = std::env::temp_dir().join(format!(
            "lane-lifecycle-thread-id-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&run_dir).expect("create isolated run directory");
        let path = run_dir.join("thread-id.txt");

        assert!(write_thread_id(&run_dir, "session-1").expect("write new thread id"));
        assert_eq!(fs::read(&path).expect("read new thread id"), b"session-1\n");
        assert!(write_thread_id(&run_dir, "session-1").expect("match existing thread id"));
        assert!(!write_thread_id(&run_dir, "other-session").expect("read conflicting thread id"));
        assert_eq!(
            fs::read(&path).expect("read unchanged thread id"),
            b"session-1\n"
        );

        fs::remove_file(&path).expect("remove thread id");
        fs::create_dir(&path).expect("occupy thread-id path with a directory");
        assert!(write_thread_id(&run_dir, "session-1").is_err());
        fs::remove_dir_all(&run_dir).expect("remove isolated run directory");
    }

    /// ´claim:lanelifecycle:a-reset-epoch-renders-as-the-utc-instant-it-names´
    /// ´test:unit:epoch-seconds-render-as-iso-8601-utc´
    #[test]
    fn epoch_seconds_render_as_iso_8601_utc() {
        for (epoch, rendered) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_789_820_400, "2026-09-19T12:20:00Z"),
            (1_790_301_600, "2026-09-25T02:00:00Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
        ] {
            assert_eq!(iso8601_utc(epoch), rendered);
        }
    }

    /// ´claim:lanelifecycle:only-a-refusal-status-becomes-a-rejection´
    /// ´test:unit:a-rejection-accepts-only-a-refused-pool-state´
    #[test]
    fn a_rejection_accepts_only_a_refused_pool_state() {
        let refused = RateLimitState::new(
            String::from("rejected"),
            Some(String::from("five_hour")),
            Some(1.0),
            Some(1_789_820_400),
        );
        let allowed = RateLimitState::new(String::from("allowed_warning"), None, Some(0.97), None);

        assert_eq!(
            RateLimitRejection::from_state(refused.clone())
                .map(|rejection| rejection.state().clone()),
            Some(refused)
        );
        assert_eq!(RateLimitRejection::from_state(allowed), None);
    }

    /// ´claim:lifecycle:fresh-run-root-must-be-absolute-and-resume-keeps-its-directory´
    /// ´test:unit:fresh-run-root-must-be-absolute-and-resume-keeps-its-directory´
    #[test]
    fn fresh_run_root_must_be_absolute_and_resume_keeps_its_directory() {
        let stamp = "20260926T120000Z";
        assert_eq!(
            fresh_run_dir("lane", OsStr::new("/fixture/runs"), stamp),
            Ok(PathBuf::from("/fixture/runs/20260926T120000Z-lane"))
        );
        assert!(fresh_run_dir("lane", OsStr::new("relative"), stamp).is_err());
        assert!(fresh_run_dir("lane", OsStr::new(""), stamp).is_err());

        let resume = PathBuf::from("/fixture/existing-run");
        let config = Config {
            budget: 60,
            pool_threshold: DEFAULT_POOL_THRESHOLD,
            ignore_pool: false,
            gateway_lane: None,
            workdir: PathBuf::from("."),
            sandbox: OsString::from("workspace-write"),
            model: None,
            effort: None,
            name: String::from("step"),
            session: Some(String::from("session")),
            resume_dir: Some(resume.clone()),
            crash_recovery: None,
            pure: false,
            prompt: Prompt::Argument(OsString::from("prompt")),
            step_letter: None,
        };
        assert_eq!(resolve_run_dir(&config), Ok(resume));
    }

    /// ´claim:lifecycle:selected-run-binds-fresh-and-resumed-directories-to-the-configured-root´
    /// ´test:unit:selected-run-binds-fresh-and-resumed-directories-to-the-configured-root´
    #[test]
    fn selected_run_binds_fresh_and_resumed_directories_to_the_configured_root() {
        use super::{RootRefusal, validate_run_selection};
        let fixture = FreshRunFixture::new("selected-root");
        let root = fixture.0.as_os_str();
        let selected = fixture.0.join("R");
        fs::create_dir(&selected).expect("selected run");
        let mut config = super::parse_arguments(&[OsString::from("-t60"), OsString::from("hello")])
            .expect("config");
        assert_eq!(
            validate_run_selection(&config, None, Some(selected.as_os_str())),
            Err(RootRefusal::Required)
        );
        assert_eq!(
            validate_run_selection(&config, Some(root), Some(root)),
            Err(RootRefusal::Selected)
        );
        assert_eq!(
            validate_run_selection(&config, Some(root), Some(selected.as_os_str())),
            Ok(())
        );
        let directory =
            fresh_run_dir("step", selected.as_os_str(), "20261021T120000Z").expect("step path");
        config.resume_dir = Some(directory.clone());
        assert_eq!(
            validate_run_selection(&config, Some(root), Some(selected.as_os_str())),
            Ok(())
        );
        create_fresh_run_dir(&directory, true).expect("allocate only within selected run");
        assert_eq!(directory.parent(), Some(selected.as_path()));
        config.session = Some(String::from("thread"));
        assert_eq!(
            validate_run_selection(&config, Some(root), Some(selected.as_os_str())),
            Ok(())
        );
        config.resume_dir = Some(fixture.0.join("another-run/step"));
        assert_eq!(
            validate_run_selection(&config, Some(root), Some(selected.as_os_str())),
            Err(RootRefusal::Directory)
        );
        let error = UsageError {
            budget: 60,
            resume_refusal: None,
            runs_root_refusal: Some(RootRefusal::Required),
            step_letter_refusal: None,
        };
        assert_eq!(
            error.refusal_diagnostic("copied-driver"),
            Some(
                b"copied-driver: runs_root_required: LANE_RUNS_ROOT must be an absolute path\n"
                    .to_vec()
            )
        );
    }

    /// ´claim:lifecycle:failed-event-size-refuses-before-paired-boundary-publication´
    /// ´test:unit:failed-event-size-refuses-before-paired-boundary-publication´
    #[test]
    fn failed_event_size_refuses_before_paired_boundary_publication() {
        let fixture = FreshRunFixture::new("event-size-failure");
        let events = b"{\"type\":\"unfinished\"";
        fs::write(fixture.0.join("events.jsonl"), events).expect("write unfinished event");
        fs::write(fixture.0.join(".step-name"), b"A\n").expect("write prior step");
        fs::write(fixture.0.join(".event-start"), b"0\n").expect("write prior start");
        fs::write(
            fixture.0.join("run-report.txt"),
            b"RUN-REPORT lane=A exit=0\n",
        )
        .expect("write prior report");
        let config = Config {
            budget: 60,
            pool_threshold: DEFAULT_POOL_THRESHOLD,
            ignore_pool: false,
            gateway_lane: None,
            workdir: PathBuf::from("."),
            sandbox: OsString::from("workspace-write"),
            model: None,
            effort: None,
            name: String::from("B"),
            session: Some(String::from("thread")),
            resume_dir: Some(fixture.0.clone()),
            crash_recovery: None,
            pure: false,
            prompt: Prompt::Argument(OsString::from("next")),
            step_letter: None,
        };
        let mut reads = 0;
        let result = prepare_resume_with_size(&config, b"next", &fixture.0, |path| {
            assert_eq!(path, fixture.0.join("events.jsonl"));
            reads += 1;
            Err(io::Error::other("injected metadata failure"))
        });
        assert_eq!(result, Err(PreparationFailure::EventSize));
        assert_eq!(reads, 1);
        assert_eq!(PreparationFailure::EventSize.status(), 1);
        assert_eq!(
            PreparationFailure::EventSize.diagnostic("codex-lane"),
            b"codex-lane: resume_event_size: event stream metadata failed\n"
        );
        assert!(!fixture.0.join("steps").exists());
        assert_eq!(
            fs::read(fixture.0.join("events.jsonl")).expect("read unchanged events"),
            events
        );
        assert_eq!(
            fs::read(fixture.0.join(".event-start")).expect("read unchanged start"),
            b"0\n"
        );
    }

    /// A free timestamp and name keep the plain directory form.
    /// ´claim:lifecycle:a-free-fresh-run-uses-the-plain-name´
    /// ´test:unit:a-free-fresh-run-uses-the-plain-name´
    #[test]
    fn a_free_fresh_run_uses_the_plain_name() {
        let fixture = FreshRunFixture::new("plain");
        let base = fixture.candidate(1);
        assert_eq!(
            allocate_fresh_run_dir(&base).expect("allocate plain name"),
            base
        );
        assert!(base.is_dir());
    }

    /// An explicit fresh directory is created under exactly the caller's name.
    /// ´claim:lifecycle:an-explicit-fresh-run-uses-the-requested-directory´
    /// ´test:unit:an-explicit-fresh-run-uses-the-requested-directory´
    #[test]
    fn an_explicit_fresh_run_uses_the_requested_directory() {
        let fixture = FreshRunFixture::new("explicit");
        let requested = fixture.0.join("requested-dispatch");
        assert_eq!(
            create_fresh_run_dir(&requested, true).expect("create requested directory"),
            requested
        );
        assert!(requested.is_dir());
        assert!(!fixture.0.join("requested-dispatch-2").exists());
    }

    /// An occupied explicit directory refuses the invocation without choosing a suffix.
    /// ´claim:lifecycle:an-occupied-explicit-run-refuses-by-name´
    /// ´test:unit:an-occupied-explicit-run-refuses-by-name´
    #[test]
    fn an_occupied_explicit_run_refuses_by_name() {
        let fixture = FreshRunFixture::new("explicit-occupied");
        let requested = fixture.0.join("requested-dispatch");
        fs::create_dir(&requested).expect("occupy requested directory");
        let config = Config {
            budget: 60,
            pool_threshold: DEFAULT_POOL_THRESHOLD,
            ignore_pool: true,
            gateway_lane: None,
            workdir: fixture.0.clone(),
            sandbox: OsString::from("workspace-write"),
            model: None,
            effort: None,
            name: String::from("dispatch"),
            session: None,
            resume_dir: Some(requested),
            crash_recovery: None,
            pure: false,
            prompt: Prompt::Argument(OsString::from("prompt")),
            step_letter: None,
        };
        let result = super::execute(&TestBackend, &config, b"prompt");
        assert_eq!(result.status(), 2);
        assert_eq!(
            result.stderr_diagnostic(),
            Some(b"test-lane: run_dir_exists: directory exists\n".as_slice())
        );
        assert_eq!(
            result.report(),
            b"RUN-REPORT lane=dispatch exit=2 wall=0s budget=60s verdict=FAILED dir=unknown\n"
        );
        assert!(!fixture.0.join("requested-dispatch-2").exists());
    }

    /// Without an explicit name the driver's occupied-name suffix remains available.
    /// ´claim:lifecycle:default-fresh-run-still-chooses-a-suffix´
    /// ´test:unit:default-fresh-run-still-chooses-a-suffix´
    #[test]
    fn default_fresh_run_still_chooses_a_suffix() {
        let fixture = FreshRunFixture::new("default-suffix");
        let base = fixture.candidate(1);
        fs::create_dir(&base).expect("occupy plain name");
        assert_eq!(
            create_fresh_run_dir(&base, false).expect("allocate default directory"),
            fixture.candidate(2)
        );
    }

    /// An occupied plain name sends the new run to the first suffix.
    /// ´claim:lifecycle:an-occupied-fresh-run-uses-suffix-two´
    /// ´test:unit:an-occupied-fresh-run-uses-suffix-two´
    #[test]
    fn an_occupied_fresh_run_uses_suffix_two() {
        let fixture = FreshRunFixture::new("suffix-two");
        let base = fixture.candidate(1);
        fs::create_dir(&base).expect("occupy plain name");
        assert_eq!(
            allocate_fresh_run_dir(&base).expect("allocate second name"),
            fixture.candidate(2)
        );
    }

    /// Occupied plain and second names send the new run to the third.
    /// ´claim:lifecycle:two-occupied-fresh-run-names-use-suffix-three´
    /// ´test:unit:two-occupied-fresh-run-names-use-suffix-three´
    #[test]
    fn two_occupied_fresh_run_names_use_suffix_three() {
        let fixture = FreshRunFixture::new("suffix-three");
        let base = fixture.candidate(1);
        fs::create_dir(&base).expect("occupy plain name");
        fs::create_dir(fixture.candidate(2)).expect("occupy second name");
        assert_eq!(
            allocate_fresh_run_dir(&base).expect("allocate third name"),
            fixture.candidate(3)
        );
    }

    /// Exhausting the bounded suffixes returns the allocation error mapped to runtime failure.
    /// ´claim:lifecycle:exhausted-fresh-run-suffixes-return-an-allocation-error´
    /// ´test:unit:exhausted-fresh-run-suffixes-return-an-allocation-error´
    #[test]
    fn exhausted_fresh_run_suffixes_return_an_allocation_error() {
        let fixture = FreshRunFixture::new("exhausted");
        for attempt in 1..=MAX_FRESH_RUN_DIR_ATTEMPTS {
            fs::create_dir(fixture.candidate(attempt)).expect("occupy candidate");
        }
        let error = allocate_fresh_run_dir(&fixture.candidate(1))
            .expect_err("bounded allocation must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!fixture.candidate(MAX_FRESH_RUN_DIR_ATTEMPTS + 1).exists());
    }

    /// A new run never adopts or changes an existing run's evidence.
    /// ´claim:lifecycle:a-fresh-run-never-adopts-existing-evidence´
    /// ´test:unit:a-fresh-run-never-adopts-existing-evidence´
    #[test]
    fn a_fresh_run_never_adopts_existing_evidence() {
        let fixture = FreshRunFixture::new("no-adoption");
        let base = fixture.candidate(1);
        fs::create_dir(&base).expect("occupy plain name");
        let evidence = base.join("brief.txt");
        fs::write(&evidence, b"first\n").expect("seed first run evidence");
        assert_eq!(
            allocate_fresh_run_dir(&base).expect("allocate second name"),
            fixture.candidate(2)
        );
        assert_eq!(
            fs::read(evidence).expect("read first run evidence"),
            b"first\n"
        );
    }

    /// ´claim:lanelifecycle:fixed-diagnostics-use-the-backend-binary-name´
    /// ´test:unit:backend-name-prefixes-fixed-diagnostics´
    #[test]
    fn backend_name_prefixes_fixed_diagnostics() {
        let backend = TestBackend;

        assert_eq!(
            usage_diagnostic(backend.name()),
            b"test-lane: usage_error: invalid command-line arguments\n"
        );
        assert_eq!(
            runtime_diagnostic(backend.name()),
            b"test-lane: runtime_failure: lane execution failed\n"
        );
        assert_eq!(
            internal_diagnostic(backend.name()),
            b"test-lane: internal_failure: unexpected internal failure\n"
        );
        assert_eq!(
            publication_diagnostic(backend.name()),
            b"test-lane: publication_failure: agent-text publication failed\n"
        );
    }

    /// ´claim:lifecycle:failed-step-diagnostic-carries-last-stderr-lines´
    /// ´test:unit:failed-step-diagnostic-carries-last-stderr-lines´
    #[test]
    fn failed_step_diagnostic_carries_last_stderr_lines() {
        let fixture = FreshRunFixture::new("stderr-tail");
        let path = fixture.candidate(1);
        fs::write(
            &path,
            b"older step\nerror: unexpected argument '--ask-for-approval' found\n",
        )
        .expect("stderr fixture");
        let start = b"older step\n".len() as u64;
        let diagnostic = super::step_stderr_diagnostic("test-lane", &path, start)
            .expect("child stderr diagnostic");
        assert_eq!(
            diagnostic,
            b"test-lane: runtime_failure: child stderr: error: unexpected argument '--ask-for-approval' found\n"
        );
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´claim:lifecycle:attempt-wall-report-retains-failed-verdict-and-seconds´
    /// ´test:unit:attempt-wall-report-retains-failed-verdict-and-seconds´
    #[test]
    fn attempt_wall_report_retains_failed_verdict_and_seconds() {
        let fixture = FreshRunFixture::new("attempt-wall");
        let end = super::AttemptWall {
            wall_seconds: 9,
            bound_seconds: 8,
        };
        end.publish(&fixture.0.join(".attempt-end"))
            .expect("client completion");
        assert_eq!(super::step_attempt_wall(&TestBackend, &fixture.0), None);
        assert_eq!(
            super::AttemptWall::from_diagnostic(&end.diagnostic()),
            Some(end)
        );
        let mut report =
            super::report_bytes("dispatch", 1, 10, 2, super::Verdict::Failed, 0, "/runs/R");
        end.annotate_report(&mut report);
        assert_eq!(report, b"RUN-REPORT lane=dispatch exit=1 wall=10s budget=2s verdict=FAILED dir=/runs/R cause=attempt-wall attempt_elapsed_seconds=9 attempt_bound_seconds=8\n");
        for invalid in [
            "attempt-wall wall_seconds=9 bound_seconds=0\n",
            "attempt-wall wall_seconds=7 bound_seconds=8\n",
            "attempt-wall wall_seconds=9 bound_seconds=no\n",
        ] {
            assert_eq!(super::AttemptWall::from_diagnostic(invalid), None);
        }
    }

    /// ´claim:lanelifecycle:resume-diagnostics-use-the-backend-binary-name´
    /// ´test:unit:backend-name-prefixes-resume-diagnostics´
    #[test]
    fn backend_name_prefixes_resume_diagnostics() {
        let backend = TestBackend;
        let report = PathBuf::from("runs/old/run-report.txt");
        let lock = PathBuf::from("runs/old/.test-lane.lock");
        let usage = UsageError {
            budget: 60,
            resume_refusal: Some(ResumeRefusal::MissingReport(report.clone())),
            runs_root_refusal: None,
            step_letter_refusal: None,
        };
        let config = Config {
            budget: 60,
            pool_threshold: DEFAULT_POOL_THRESHOLD,
            ignore_pool: false,
            gateway_lane: None,
            workdir: PathBuf::from("."),
            sandbox: OsString::from("workspace-write"),
            model: None,
            effort: None,
            name: String::from("work"),
            session: None,
            resume_dir: None,
            crash_recovery: Some(CrashRecovery::Crashed {
                path: lock.clone(),
                pid: 9,
            }),
            pure: false,
            prompt: Prompt::Argument(OsString::from("prompt")),
            step_letter: None,
        };

        assert_eq!(
            usage.refusal_diagnostic(backend.name()),
            Some(
                format!(
                    "test-lane: resume_missing_report: prior step report is missing: {}\n",
                    report.display()
                )
                .into_bytes()
            )
        );
        assert_eq!(
            config.crash_recovery_diagnostic(backend.name()),
            Some(
                format!(
                    "test-lane: resume_crash_recovered: wrote a CRASHED report for dead holder pid 9 and cleared lock: {}\n",
                    lock.display()
                )
                .into_bytes()
            )
        );
    }

    /// ´claim:lanelifecycle:top-level-extraction-skips-every-json-value-shape´
    /// ´test:unit:top-level-key-follows-nested-values-and-scalars´
    #[test]
    fn top_level_key_follows_nested_values_and_scalars() {
        let line = br#"{"nested":{"type":"result","result":"wrong"},"array":["result",{"result":"wrong"}],"number":-1.2e+3,"literal":false,"type":"result","result":"right"}"#;
        assert_eq!(
            top_level_string_value(line, "result").as_deref(),
            Some("right")
        );
    }

    /// ´claim:lanelifecycle:top-level-extraction-decodes-json-string-escapes´
    /// ´test:unit:top-level-string-decodes-escapes-and-surrogates´
    #[test]
    fn top_level_string_decodes_escapes_and_surrogates() {
        let line = br#"{"result":"line\n\uD83D\uDE80"}"#;
        assert_eq!(
            top_level_string_value(line, "result").as_deref(),
            Some("line\n🚀")
        );
    }

    /// ´claim:lanelifecycle:malformed-or-nonobject-json-has-no-top-level-value´
    /// ´test:unit:top-level-extractor-rejects-malformed-input´
    #[test]
    fn top_level_extractor_rejects_malformed_input() {
        assert_eq!(
            top_level_string_value(br#"["result","wrong"]"#, "result"),
            None
        );
        assert_eq!(top_level_string_value(br#"{"result":"cut"#, "result"), None);
    }

    /// ´claim:lanelifecycle:top-level-extraction-reads-boolean-and-whole-number-values´
    /// ´test:unit:top-level-scalar-readers-follow-the-last-top-level-key´
    #[test]
    fn top_level_scalar_readers_follow_the_last_top_level_key() {
        let line = br#"{"nested":{"is_error":true,"duration_ms":1},"is_error":false,"duration_ms":12345,"fraction":1.5,"negative":-2}"#;
        assert_eq!(top_level_bool_value(line, "is_error"), Some(false));
        assert_eq!(top_level_u64_value(line, "duration_ms"), Some(12345));
        assert_eq!(top_level_u64_value(line, "fraction"), None);
        assert_eq!(top_level_u64_value(line, "negative"), None);
        assert_eq!(top_level_bool_value(line, "duration_ms"), None);
        assert_eq!(top_level_bool_value(line, "missing"), None);
    }

    /// ´claim:lanelifecycle:the-last-complete-line-is-the-one-the-final-line-feed-closes´
    /// ´test:unit:last-complete-line-ignores-an-unterminated-tail´
    #[test]
    fn last_complete_line_ignores_an_unterminated_tail() {
        assert_eq!(last_complete_line(b"first\nsecond\n"), Some(&b"second"[..]));
        assert_eq!(last_complete_line(b"first\npartial"), Some(&b"first"[..]));
        assert_eq!(last_complete_line(b"only\n"), Some(&b"only"[..]));
        assert_eq!(last_complete_line(b"partial"), None);
        assert_eq!(last_complete_line(b""), None);
    }

    /// ´claim:lanelifecycle:reconstruction-evidence-names-the-backend-and-the-cleared-lock´
    /// ´test:unit:backend-name-prefixes-the-reconstruction-diagnostic´
    #[test]
    fn backend_name_prefixes_the_reconstruction_diagnostic() {
        let lock = PathBuf::from("runs/old/.test-lane.lock");
        let recovery = CrashRecovery::Reconstructed {
            path: lock.clone(),
            pid: 9,
        };

        assert_eq!(
            recovery.diagnostic(TestBackend.name()),
            format!(
                "test-lane: resume_finish_reconstructed: rebuilt the finished step report from the terminal result event for dead holder pid 9 and cleared lock: {}\n",
                lock.display()
            )
            .into_bytes()
        );
    }

    /// ´claim:lanelifecycle:a-settled-report-outlives-the-lock-of-the-driver-that-published-it´
    /// ´test:unit:backend-name-prefixes-the-settled-report-diagnostic´
    #[test]
    fn backend_name_prefixes_the_settled_report_diagnostic() {
        let lock = PathBuf::from("runs/old/.test-lane.lock");
        let recovery = CrashRecovery::Settled {
            path: lock.clone(),
            pid: 9,
        };

        assert_eq!(
            recovery.diagnostic(TestBackend.name()),
            format!(
                "test-lane: resume_settled_report_kept: kept the published report of dead holder pid 9 and cleared lock: {}\n",
                lock.display()
            )
            .into_bytes()
        );
    }

    /// ´claim:lanelifecycle:the-reconstruction-record-names-the-wall-derivation-it-used´
    /// ´test:unit:the-reconstruction-record-names-its-wall-derivation´
    #[test]
    fn the_reconstruction_record_names_its_wall_derivation() {
        assert_eq!(
            reconstructed_sidecar_bytes(
                TerminalResult::new(false, Some(12_345)),
                WallDerivation::DurationMs,
                12,
                9,
                "20260912T120000Z"
            ),
            b"reason=DRIVER-EXIT derivation=duration_ms wall=12s exit=0 verdict=ok pid=9 at=20260912T120000Z\n"
        );
        assert_eq!(
            reconstructed_sidecar_bytes(
                TerminalResult::new(true, None),
                WallDerivation::Unknown,
                0,
                9,
                "unknown"
            ),
            b"reason=DRIVER-EXIT derivation=unknown wall=0s exit=1 verdict=FAILED pid=9 at=unknown\n"
        );
    }

    /// ´claim:lanelifecycle:the-monitor-record-states-awake-accounting-beside-the-two-clock-reads´
    /// ´test:unit:the-monitor-record-carries-awake-accounting-and-both-clock-reads´
    #[test]
    fn the_monitor_record_carries_awake_accounting_and_both_clock_reads() {
        assert_eq!(
            monitor_sidecar_bytes(30, 450, 8_192, ClockSample::new(450, 1_350), None),
            b"quiet=30s wall=450s event_size=8192 boot=1350s awake=450s\n"
        );
        // The same step after a fifteen-minute host sleep: the awake accounting
        // is untouched, because the child had no interval in which to grow
        // anything, and the whole divergence sits in the boot reading.
        assert_eq!(
            monitor_sidecar_bytes(30, 450, 8_192, ClockSample::new(450, 2_250), None),
            b"quiet=30s wall=450s event_size=8192 boot=2250s awake=450s\n"
        );
    }

    /// ´claim:lifecycle:budget-expiry-sidecar-retains-its-first-reading-and-current-state´
    /// ´test:unit:budget-expiry-sidecar-retains-its-first-reading-and-current-state´
    #[test]
    fn budget_expiry_sidecar_retains_its_first_reading_and_current_state() {
        let before = MonitorReadings {
            wall: 9,
            budget: 10,
            event_size: 42,
            last_growth: 7,
            quiet: 2,
        };
        let pre_expiry = monitor_sidecar_with_context(
            before.quiet,
            before.wall,
            before.event_size,
            ClockSample::new(9, 9),
            None,
            None,
            Some((before, None, MonitorDecision::Continue)),
        );
        assert_eq!(
            pre_expiry,
            b"quiet=2s wall=9s event_size=42 boot=9s awake=9s budget=10s last_growth=7s\n"
        );
        let first = MonitorReadings {
            wall: 11,
            budget: 10,
            event_size: 42,
            last_growth: 9,
            quiet: 2,
        };
        let expiry = BudgetExpiry {
            readings: first,
            state: MonitorDecision::Continue,
        };
        let later = MonitorReadings {
            wall: 131,
            quiet: 122,
            ..first
        };
        let sidecar = monitor_sidecar_with_context(
            later.quiet,
            later.wall,
            later.event_size,
            ClockSample::new(131, 131),
            None,
            None,
            Some((later, Some(expiry), MonitorDecision::Stalled)),
        );
        assert_eq!(sidecar, b"quiet=122s wall=131s event_size=42 boot=131s awake=131s budget=10s last_growth=9s state=stalled expired_wall=11s expired_event_size=42 expired_last_growth=9s expired_quiet=2s expired_state=growing\n");
    }

    /// A monitor record names the awaited run only on a credited poll.
    /// ´claim:lifecycle:the-monitor-record-names-the-awaited-run-only-while-one-is-in-flight´
    /// ´test:unit:the-monitor-record-names-the-awaited-run-only-while-one-is-in-flight´
    #[test]
    fn the_monitor_record_names_the_awaited_run_only_while_one_is_in_flight() {
        let sample = ClockSample::new(131, 1_031);
        assert_eq!(
            monitor_sidecar_bytes(0, 131, 0, sample, Some(("gw", 7))),
            b"quiet=0s wall=131s event_size=0 boot=1031s awake=131s awaiting=gw:7\n"
        );
        assert_eq!(
            monitor_sidecar_bytes(131, 131, 0, sample, None),
            b"quiet=131s wall=131s event_size=0 boot=1031s awake=131s\n"
        );
    }

    /// An approved verdict without a result is in flight.
    /// ´claim:lifecycle:an-approved-verdict-without-an-audited-result-is-in-flight´
    /// ´test:unit:an-approved-verdict-without-an-audited-result-is-in-flight´
    #[test]
    fn an_approved_verdict_without_an_audited_result_is_in_flight() {
        let fixture = GatewayFixture::new("approved");
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), Some(7));
    }

    /// An audited run result ends the flight.
    /// ´claim:lifecycle:an-audited-run-result-ends-the-flight´
    /// ´test:unit:an-audited-run-result-ends-the-flight´
    #[test]
    fn an_audited_run_result_ends_the_flight() {
        let fixture = GatewayFixture::new("audited");
        let mut watch = fixture.watch();
        assert_eq!(watch.in_flight(fixture.unix_ms), Some(7));
        fixture.audited_result();
        assert_eq!(watch.in_flight(fixture.unix_ms), None);
    }

    /// An open proposal without a verdict earns no credit.
    /// ´claim:lifecycle:an-open-proposal-without-a-verdict-is-not-in-flight´
    /// ´test:unit:an-open-proposal-without-a-verdict-is-not-in-flight´
    #[test]
    fn an_open_proposal_without_a_verdict_is_not_in_flight() {
        let fixture = GatewayFixture::new("open");
        fs::remove_file(fixture.state.join("proposal-verdicts/gw/7.json")).expect("remove verdict");
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), None);
    }

    /// Nonapproved verdicts earn no credit.
    /// ´claim:lifecycle:a-denied-expired-or-withdrawn-verdict-is-not-in-flight´
    /// ´test:unit:a-denied-expired-or-withdrawn-verdict-is-not-in-flight´
    #[test]
    fn a_denied_expired_or_withdrawn_verdict_is_not_in_flight() {
        for decision in ["denied", "expired", "withdrawn"] {
            let fixture = GatewayFixture::new(decision);
            fixture.verdict(decision, fixture.unix_ms);
            assert_eq!(fixture.watch().in_flight(fixture.unix_ms), None);
        }
    }

    /// Credit ends at the proposal timeout.
    /// ´claim:lifecycle:an-approved-run-past-its-proposal-timeout-is-not-in-flight´
    /// ´test:unit:an-approved-run-past-its-proposal-timeout-is-not-in-flight´
    #[test]
    fn an_approved_run_past_its_proposal_timeout_is_not_in_flight() {
        let fixture = GatewayFixture::new("timeout");
        fixture.proposal(1);
        fixture.verdict("approved", fixture.unix_ms - 1_000);
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), None);
    }

    /// An audited roster request remains in flight inside its command budget.
    /// ´claim:lifecycle:a-roster-run-inside-its-wall-budget-is-in-flight´
    /// ´test:unit:a-roster-run-inside-its-wall-budget-is-in-flight´
    #[test]
    fn a_roster_run_inside_its_wall_budget_is_in_flight() {
        let fixture = GatewayFixture::new("roster-running");
        fixture.roster_request(10);
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), Some(8));
    }

    /// A command registered after the watch starts still earns credit.
    /// ´claim:lifecycle:a-newly-registered-roster-run-is-in-flight´
    /// ´test:unit:a-newly-registered-roster-run-is-in-flight´
    #[test]
    fn a_newly_registered_roster_run_is_in_flight() {
        let fixture = GatewayFixture::new("roster-promoted");
        let mut watch = fixture.watch();
        fixture.roster_request(10);
        assert_eq!(watch.in_flight(fixture.unix_ms), Some(8));
    }

    /// A roster request stops earning credit at its command budget.
    /// ´claim:lifecycle:a-roster-run-past-its-wall-budget-is-not-in-flight´
    /// ´test:unit:a-roster-run-past-its-wall-budget-is-not-in-flight´
    #[test]
    fn a_roster_run_past_its_wall_budget_is_not_in_flight() {
        let fixture = GatewayFixture::new("roster-expired");
        fixture.roster_request(10);
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms + 5_000), None);
    }

    /// An audited result ends a roster run's flight.
    /// ´claim:lifecycle:a-roster-run-with-an-audited-result-is-not-in-flight´
    /// ´test:unit:a-roster-run-with-an-audited-result-is-not-in-flight´
    #[test]
    fn a_roster_run_with_an_audited_result_is_not_in_flight() {
        let fixture = GatewayFixture::new("roster-result");
        fixture.roster_request(10);
        let mut watch = fixture.watch();
        assert_eq!(watch.in_flight(fixture.unix_ms), Some(8));
        fixture.audited_roster_result();
        assert_eq!(watch.in_flight(fixture.unix_ms), None);
    }

    /// An audited refusal cannot leave a roster request credited.
    /// ´claim:lifecycle:a-refused-roster-run-is-not-in-flight´
    /// ´test:unit:a-refused-roster-run-is-not-in-flight´
    #[test]
    fn a_refused_roster_run_is_not_in_flight() {
        let fixture = GatewayFixture::new("roster-refused");
        fixture.roster_request(10);
        fixture.audited_roster_refusal();
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), None);
    }

    /// A malformed run request earns no credit and leaves an approved run in flight.
    /// ´claim:lifecycle:a-malformed-run-request-leaves-an-approved-run-in-flight´
    /// ´test:unit:a-malformed-run-request-leaves-an-approved-run-in-flight´
    #[test]
    fn a_malformed_run_request_leaves_an_approved_run_in_flight() {
        let fixture = GatewayFixture::new("malformed-request");
        fs::write(
            fixture.state.join("audit/gw.jsonl"),
            format!(
                "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"request\",\"request\":{{\"encoding\":\"json\",\"value\":{{\"schema\":1,\"seq\":8,\"op\":\"run\",\"argv\":[\"true\"]}},\"raw\":\"request\"}}}}}}\n",
                fixture.unix_ms
            ),
        )
        .expect("write malformed request");
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), Some(7));
    }

    /// A sequence refusal naming an approved proposal leaves its run in flight.
    /// ´claim:lifecycle:a-sequence-refusal-leaves-an-approved-run-in-flight´
    /// ´test:unit:a-sequence-refusal-leaves-an-approved-run-in-flight´
    #[test]
    fn a_sequence_refusal_leaves_an_approved_run_in_flight() {
        let fixture = GatewayFixture::new("sequence-refusal");
        fs::write(
            fixture.state.join("audit/gw.jsonl"),
            format!(
                "{{\"schema\":2,\"timestamp_unix_ms\":{},\"event\":{{\"kind\":\"refusal\",\"refusal\":{{\"seq\":7,\"rule\":\"sequence_replay\"}}}}}}\n",
                fixture.unix_ms
            ),
        )
        .expect("write sequence refusal");
        assert_eq!(fixture.watch().in_flight(fixture.unix_ms), Some(7));
    }

    /// A credited roster run is named in the monitor sidecar.
    /// ´claim:lifecycle:a-roster-run-in-flight-appears-in-the-monitor-sidecar´
    /// ´test:unit:a-roster-run-in-flight-appears-in-the-monitor-sidecar´
    #[test]
    fn a_roster_run_in_flight_appears_in_the_monitor_sidecar() {
        let fixture = GatewayFixture::new("roster-sidecar");
        fixture.roster_request(10);
        let awaiting = fixture
            .watch()
            .in_flight(fixture.unix_ms)
            .map(|seq| ("gw", seq));
        assert_eq!(
            monitor_sidecar_bytes(0, 131, 0, ClockSample::new(131, 1_031), awaiting),
            b"quiet=0s wall=131s event_size=0 boot=1031s awake=131s awaiting=gw:8\n"
        );
    }

    /// A registration for another worktree earns no credit.
    /// ´claim:lifecycle:a-registration-naming-another-worktree-yields-no-flight´
    /// ´test:unit:a-registration-naming-another-worktree-yields-no-flight´
    #[test]
    fn a_registration_naming_another_worktree_yields_no_flight() {
        let fixture = GatewayFixture::new("other-worktree");
        fs::write(
            fixture.state.join("registrations/gw.toml"),
            format!("worktree = \"{}\"\n", fixture.root.join("other").display()),
        )
        .expect("write other registration");
        assert!(GatewayWatch::new("gw", &fixture.state, &fixture.workdir).is_none());
    }

    /// Absent gateway state earns no credit.
    /// ´claim:lifecycle:absent-gateway-state-yields-no-flight´
    /// ´test:unit:absent-gateway-state-yields-no-flight´
    #[test]
    fn absent_gateway_state_yields_no_flight() {
        let fixture = GatewayFixture::new("absent");
        assert!(GatewayWatch::new("gw", &fixture.root.join("absent"), &fixture.workdir).is_none());
    }

    /// The gateway option parses without hiding the budget hint.
    /// ´claim:lifecycle:the-gateway-lane-option-parses-and-keeps-the-budget-hint´
    /// ´test:unit:the-gateway-lane-option-parses-and-keeps-the-budget-hint´
    #[test]
    fn the_gateway_lane_option_parses_and_keeps_the_budget_hint() {
        let before = ["--gateway-lane", "gw.7", "-t", "10", "prompt"].map(OsString::from);
        let after = ["-t", "10", "--gateway-lane", "gw.7", "prompt"].map(OsString::from);
        for arguments in [&before[..], &after[..]] {
            let config = parse_arguments(arguments).expect("gateway lane invocation");
            assert_eq!(config.gateway_lane(), Some("gw.7"));
            assert_eq!(config.budget(), 10);
            assert_eq!(budget_hint(arguments), 10);
        }
        for invalid in ["", ".", "..", "a/b", "é"] {
            let arguments = ["-t", "10", "--gateway-lane", invalid, "prompt"].map(OsString::from);
            assert!(
                parse_arguments(&arguments).is_none(),
                "invalid lane {invalid}"
            );
            assert_eq!(budget_hint(&arguments), 10);
        }
    }

    /// ´claim:lifecycle:a-monitor-decision-names-its-diagnostic-state´
    /// ´test:unit:a-monitor-decision-names-its-diagnostic-state´
    #[test]
    fn a_monitor_decision_names_its_diagnostic_state() {
        assert_eq!(MonitorDecision::Continue.state(), "growing");
        assert_eq!(MonitorDecision::Stalled.state(), "stalled");
        assert_eq!(MonitorDecision::Runaway.state(), "runaway");
    }

    /// ´claim:lanelifecycle:a-step-lock-names-its-driver-first-and-its-child-second´
    /// ´test:unit:a-step-lock-reads-as-a-driver-and-an-optional-child´
    #[test]
    fn a_step_lock_reads_as_a_driver_and_an_optional_child() {
        assert_eq!(parse_lock(b"4321\n"), Some((4321, None)));
        assert_eq!(parse_lock(b"4321"), Some((4321, None)));
        assert_eq!(parse_lock(b"4321\n8765\n"), Some((4321, Some(8765))));
        // Nothing this driver writes has a third line, an unparsable line, or
        // no line at all, so none of them identifies a holder, and a holder
        // that cannot be identified is never treated as a dead one.
        assert_eq!(parse_lock(b"4321\n8765\n99\n"), None);
        assert_eq!(parse_lock(b"4321\nchild\n"), None);
        assert_eq!(parse_lock(b"driver\n"), None);
        assert_eq!(parse_lock(b""), None);
    }

    /// ´claim:lanelifecycle:the-suspend-gap-tolerance-is-two-whole-seconds´
    /// ´test:unit:the-suspend-gap-tolerance-is-two-whole-seconds´
    #[test]
    fn the_suspend_gap_tolerance_is_two_whole_seconds() {
        // PIN: the two clocks are read a moment apart and truncated to whole
        // seconds, so each read can be off by one; two seconds is that jitter
        // and anything above it is the host having been away. Changing this
        // literal restates the claim rather than adjusting a fixture.
        assert_eq!(SUSPEND_GAP_THRESHOLD_SECONDS, 2);
    }
}
