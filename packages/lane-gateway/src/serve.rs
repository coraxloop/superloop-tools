use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2, renameat};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::Serialize;

use crate::gateway::{Gateway, GatewayError};
use crate::push::elapsed_millis;
use crate::types::{
    AuditEvent, Operation, OperationResult, OutputChunk, OutputChunkRef, OutputStream,
    RESULT_SCHEMA, Refusal, RefusalRule, ServeActivity, ServeCrashReport, ServeDeathReason,
    ServeFailureKind, ServeHeartbeat, ServeLiveness, ServeProcessState, ServeStopReason,
    ValidationOutcome, WorkerFileFailure, WorkerPathClass, WorkerPathDefect, parse_request,
};

const DEFAULT_POLL_INTERVAL_MILLIS: u64 = 500;
/// Consecutive serve cycles an unfinished request file is re-polled before the
/// gateway stops waiting and refuses the bytes it can see.
///
/// A worker that writes `.lane/request.json` with a plain redirect exposes the
/// file at creation, before any content lands. The measured occurrence of that
/// race read the file empty and read the same file complete on the very next
/// poll, so a single re-poll already covers a redirect. Four cycles — two
/// seconds at the default 500 ms cadence — also cover a writer whose
/// generating pipeline stalls mid-write, while still refusing a permanently
/// truncated file inside the worker's own attention window.
const INCOMPLETE_REQUEST_CYCLE_BOUND: u32 = 4;
/// Maximum bytes read from one worker request; larger files are refused.
const MAX_WORKER_REQUEST_BYTES: u64 = 1024 * 1024;
const DEFAULT_HEARTBEAT_INTERVAL_MILLIS: u64 = 5_000;
const DEFAULT_APPROVE_DEADLINE_MARGIN_SECONDS: u64 = 60;
const APPROVE_MARGIN_ENVIRONMENT: &str = "LANE_GATEWAY_APPROVE_MARGIN_SECONDS";
const DEFAULT_RESULT_SIZE_LIMIT_BYTES: usize = 512 * 1_024;
const HEARTBEAT_INTERVAL_ENVIRONMENT: &str = "LANE_GATEWAY_HEARTBEAT_MILLIS";
const RUNNER_ARGV_ENVIRONMENT: &str = "LANE_GATEWAY_RUNNER_ARGV";
const RESULT_SIZE_LIMIT_ENVIRONMENT: &str = "LANE_GATEWAY_RESULT_SIZE_LIMIT_BYTES";
const TARGET_ROOT_ENVIRONMENT: &str = "LANE_GATEWAY_TARGET_ROOT";
static RESULT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SERVE_STATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
/// Termination signals the serve loop observes instead of dying under.
///
/// SIGHUP belongs here with the two deliberate stops: a serve started from a
/// session that later goes away is sent SIGHUP by the kernel, and its default
/// disposition ends the process just as silently as SIGTERM's would.
const WATCHED_SIGNALS: [Signal; 3] = [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP];
/// Latest watched signal number the watch thread accepted, or zero.
static OBSERVED_SIGNAL: AtomicI32 = AtomicI32::new(0);
/// Whether this process installed the signal watch, resolved once.
static SIGNAL_WATCH: OnceLock<bool> = OnceLock::new();

/// Polling and shutdown-file settings for the gateway serve loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    poll_interval_millis: u64,
    heartbeat_interval_millis: u64,
    approve_deadline_margin_seconds: u64,
    approve_deadline: Option<Instant>,
    runner_termination_grace: Duration,
    runner_state_dir: PathBuf,
    shutdown_file: PathBuf,
    runner_prefix: Vec<String>,
    result_size_limit_bytes: usize,
    cargo_target_root: Option<PathBuf>,
}

impl ServeConfig {
    /// Use the default 500 ms interval and the gateway state's `shutdown`
    /// flag file, leaving the required runner prefix unset for a builder.
    #[must_use]
    pub fn for_gateway(gateway: &Gateway) -> Self {
        Self {
            poll_interval_millis: DEFAULT_POLL_INTERVAL_MILLIS,
            heartbeat_interval_millis: DEFAULT_HEARTBEAT_INTERVAL_MILLIS,
            approve_deadline_margin_seconds: DEFAULT_APPROVE_DEADLINE_MARGIN_SECONDS,
            approve_deadline: None,
            runner_termination_grace: crate::run::RUNNER_TERMINATION_GRACE,
            runner_state_dir: gateway.state_dir().join("runner-groups"),
            shutdown_file: gateway.state_dir().join("shutdown"),
            runner_prefix: Vec::new(),
            result_size_limit_bytes: DEFAULT_RESULT_SIZE_LIMIT_BYTES,
            cargo_target_root: None,
        }
    }

    /// Load a required JSON runner argv and optional polling, shutdown, and
    /// result-payload overrides from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the runner JSON is absent or invalid, an interval,
    /// margin, or size limit is not positive, or the shutdown-file override is empty.
    pub fn from_environment(gateway: &Gateway) -> Result<Self, GatewayError> {
        let mut config = Self::for_gateway(gateway);
        let runner_source = std::env::var(RUNNER_ARGV_ENVIRONMENT)
            .map_err(|_error| GatewayError::InvalidServeConfig)?;
        config.runner_prefix = serde_json::from_str(&runner_source)
            .map_err(|_error| GatewayError::InvalidServeConfig)?;
        if let Some(value) = std::env::var_os("LANE_GATEWAY_POLL_MILLIS") {
            let interval = value
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or(GatewayError::InvalidServeConfig)?;
            config.poll_interval_millis = interval;
        }
        if let Some(value) = std::env::var_os(HEARTBEAT_INTERVAL_ENVIRONMENT) {
            config.heartbeat_interval_millis = value
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or(GatewayError::InvalidServeConfig)?;
        }
        if let Some(value) = std::env::var_os(APPROVE_MARGIN_ENVIRONMENT) {
            config.approve_deadline_margin_seconds = value
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or(GatewayError::InvalidServeConfig)?;
        }
        if let Some(value) = std::env::var_os("LANE_GATEWAY_SHUTDOWN_FILE") {
            if value.is_empty() {
                return Err(GatewayError::InvalidServeConfig);
            }
            config.shutdown_file = PathBuf::from(value);
        }
        if let Some(value) = std::env::var_os(RESULT_SIZE_LIMIT_ENVIRONMENT) {
            config.result_size_limit_bytes = value
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .ok_or(GatewayError::InvalidServeConfig)?;
        }
        config.cargo_target_root = std::env::var_os(TARGET_ROOT_ENVIRONMENT).map(PathBuf::from);
        if !config.is_valid() {
            return Err(GatewayError::InvalidServeConfig);
        }
        Ok(config)
    }

    /// Override the non-zero watcher interval in milliseconds.
    #[must_use]
    pub const fn with_poll_interval_millis(mut self, poll_interval_millis: u64) -> Self {
        self.poll_interval_millis = poll_interval_millis;
        self
    }

    /// Override the positive heartbeat publication cadence in milliseconds.
    #[must_use]
    pub const fn with_heartbeat_interval_millis(mut self, heartbeat_interval_millis: u64) -> Self {
        self.heartbeat_interval_millis = heartbeat_interval_millis;
        self
    }

    /// Override the positive transport margin added to an approved command's wall budget.
    /// A zero margin is rejected when serving, processing a request, or approving a proposal.
    #[must_use]
    pub const fn with_approve_deadline_margin_seconds(mut self, seconds: u64) -> Self {
        self.approve_deadline_margin_seconds = seconds;
        self
    }

    /// Serve-side transport margin in seconds; the default is sixty.
    #[must_use]
    pub const fn approve_deadline_margin_seconds(&self) -> u64 {
        self.approve_deadline_margin_seconds
    }

    pub(crate) fn for_approve(&self, started: Instant, wall_budget_seconds: u64) -> Self {
        let mut config = self.clone();
        config.approve_deadline = Some(
            started
                .checked_add(Duration::from_secs(
                    wall_budget_seconds.saturating_add(self.approve_deadline_margin_seconds),
                ))
                .unwrap_or(started),
        );
        config
    }

    #[cfg(test)]
    pub(crate) const fn with_runner_termination_grace(mut self, grace: Duration) -> Self {
        self.runner_termination_grace = grace;
        self
    }

    pub(crate) const fn runner_termination_grace(&self) -> Duration {
        self.runner_termination_grace
    }

    pub(crate) fn runner_state_dir(&self) -> &Path {
        &self.runner_state_dir
    }

    pub(crate) const fn approve_deadline(&self) -> Option<Instant> {
        self.approve_deadline
    }

    /// Override the file whose presence requests a clean shutdown.
    #[must_use]
    pub fn with_shutdown_file(mut self, shutdown_file: impl Into<PathBuf>) -> Self {
        self.shutdown_file = shutdown_file.into();
        self
    }

    /// Override the typed runner argv prefix.
    #[must_use]
    pub fn with_runner_prefix(mut self, runner_prefix: Vec<String>) -> Self {
        self.runner_prefix = runner_prefix;
        self
    }

    /// Override the maximum output payload bytes stored in one chunk file.
    #[must_use]
    pub const fn with_result_size_limit_bytes(mut self, limit: usize) -> Self {
        self.result_size_limit_bytes = limit;
        self
    }

    /// Override the optional root used to derive per-checkout Cargo targets.
    #[must_use]
    pub fn with_cargo_target_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.cargo_target_root = Some(root.into());
        self
    }

    /// Configured watcher interval.
    #[must_use]
    pub const fn poll_interval_millis(&self) -> u64 {
        self.poll_interval_millis
    }

    /// Heartbeat publication cadence in milliseconds.
    #[must_use]
    pub const fn heartbeat_interval_millis(&self) -> u64 {
        self.heartbeat_interval_millis
    }

    /// File polled as the clean-shutdown flag.
    #[must_use]
    pub fn shutdown_file(&self) -> &Path {
        &self.shutdown_file
    }

    /// Typed argv prefix prepended to the mirror checkout and roster argv.
    #[must_use]
    pub fn runner_prefix(&self) -> &[String] {
        &self.runner_prefix
    }

    /// Maximum output payload bytes in one published result file.
    #[must_use]
    pub const fn result_size_limit_bytes(&self) -> usize {
        self.result_size_limit_bytes
    }

    /// Optional root used to derive a stable hashed target directory.
    #[must_use]
    pub fn cargo_target_root(&self) -> Option<&Path> {
        self.cargo_target_root.as_deref()
    }

    fn is_valid(&self) -> bool {
        self.poll_interval_millis > 0
            && self.heartbeat_interval_millis > 0
            && self.approve_deadline_margin_seconds > 0
            && self.result_size_limit_bytes > 0
            && self
                .runner_prefix
                .first()
                .is_some_and(|program| Path::new(program).is_absolute())
            && self
                .runner_prefix
                .iter()
                .all(|argument| !argument.is_empty())
    }
}

impl Gateway {
    /// Validate and serve one request source without writing into a worktree.
    ///
    /// Accepted pushes are snapshotted, scope-checked, and mirrored. Accepted
    /// runs execute their registered argv through the configured runner, while
    /// proposals are parked for an orchestrator verdict. Results for accepted
    /// operations are appended to the lane audit.
    ///
    /// # Errors
    ///
    /// Returns an error when gateway state, audit storage, or registration
    /// loading fails, or the approval margin is zero. Request and Git failures are returned as typed results.
    pub fn process_request(
        &self,
        lane: &str,
        source: &str,
        config: &ServeConfig,
    ) -> Result<OperationResult, GatewayError> {
        if config.approve_deadline_margin_seconds() == 0 {
            return Err(GatewayError::InvalidServeConfig);
        }
        let _lock = self.lock_lane(lane)?;
        self.process_request_locked(lane, source, config)
    }

    pub(crate) fn process_request_locked(
        &self,
        lane: &str,
        source: &str,
        config: &ServeConfig,
    ) -> Result<OperationResult, GatewayError> {
        let started = Instant::now();
        let validation = self.validate_request(lane, source)?;
        let request = match validation.outcome {
            ValidationOutcome::Accepted { request } => request,
            ValidationOutcome::Refused { refusal } => {
                return Ok(OperationResult::refused(
                    refusal.seq,
                    None,
                    elapsed_millis(started),
                    refusal,
                    String::new(),
                    String::new(),
                ));
            }
        };
        let accepted_unix_ms = crate::gateway::timestamp_unix_ms()?;

        let mut result = match request.op {
            Operation::Withdraw => {
                let registration = self.load_registration(lane)?;
                self.withdraw_proposal_locked(&registration, &request, config, started)?
            }
            Operation::Push => {
                let registration = self.load_registration(lane)?;
                self.push_registration(&registration, request.seq, started)
            }
            Operation::Run => {
                let registration = self.load_registration(lane)?;
                let command_name = request
                    .command
                    .as_deref()
                    .ok_or(GatewayError::CorruptState("validated_run_command"))?;
                let command = registration
                    .commands
                    .get(command_name)
                    .ok_or(GatewayError::CorruptState("validated_run_roster"))?;
                let mirror = self
                    .latest_snapshot(lane)?
                    .ok_or(GatewayError::CorruptState("validated_run_snapshot"))?;
                Self::run_registration(
                    &registration,
                    command,
                    request.seq,
                    mirror.commit_id,
                    config,
                    started,
                    accepted_unix_ms,
                )?
            }
            Operation::Propose => {
                let registration = self.load_registration(lane)?;
                self.park_proposal(&registration, &request, started)?
            }
        };
        result.command = request.command;
        self.append_audit(
            lane,
            AuditEvent::Result {
                result: Box::new(result.clone()),
            },
        )?;
        Ok(result)
    }

    /// Poll every registered lane until the configured shutdown file exists.
    ///
    /// Every distinct request file observed during this process is handled at
    /// most once. Files written below a lane worktree are confined to the
    /// `.lane/` result manifest and optional output chunks.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, unreadable gateway state,
    /// failed audit/result storage, heartbeat publication, a caught panic, or
    /// an inaccessible shutdown flag path. Every returned failure attempts to
    /// publish the fixed crash report before control returns to the caller.
    pub fn serve(&self, config: &ServeConfig) -> Result<(), GatewayError> {
        supervise_serve(self, config, |publisher| {
            self.serve_inner(config, publisher)
        })
    }

    fn serve_inner(
        &self,
        config: &ServeConfig,
        publisher: &ServeHeartbeatPublisher,
    ) -> Result<(), GatewayError> {
        let _guard = self.service_guard()?;
        if !self.legacy_proposal_bodies(None)?.is_empty() {
            return Err(GatewayError::RequestChannel(
                "predecessor proposals require held-service migration".into(),
            ));
        }
        // Entry 27a: a `.toml` dropped into the state directory without ever
        // running `register` is otherwise invisible to `serve` and to a
        // worker who can only watch their own worktree. Publish it as a
        // typed, always-refreshed startup report rather than staying silent.
        write_state_json_atomic(
            &self.unregistered_registrations_report_path(),
            "unregistered-registrations",
            &self.unregistered_toml_files()?,
        )?;
        let reaped_lock_lane = self.reconcile_action_locks()?;
        self.reconcile_runner_groups()?;
        let has_open_proposals = !self.proposals()?.proposals.is_empty();
        self.reconcile_open_proposals(config.result_size_limit_bytes)?;
        if let Some(lane) = reaped_lock_lane {
            publisher.record_activity(ServeActivity::ActionLockReaped, Some(&lane), None)?;
        }
        if has_open_proposals {
            publisher.record_activity(ServeActivity::ProposalReconciled, None, None)?;
        }
        let mut state = self.seed_seen_requests()?;
        loop {
            publisher.ensure_healthy()?;
            if let Some(activity) = stop_activity(&config.shutdown_file)? {
                publisher.record_activity(activity, None, None)?;
                return Ok(());
            }
            self.serve_cycle(&mut state, config, publisher)?;
            publisher.ensure_healthy()?;
            if let Some(activity) = stop_activity(&config.shutdown_file)? {
                publisher.record_activity(activity, None, None)?;
                return Ok(());
            }
            thread::sleep(Duration::from_millis(config.poll_interval_millis));
        }
    }

    #[allow(clippy::too_many_lines)]
    fn serve_cycle(
        &self,
        state: &mut ServeRequestState,
        config: &ServeConfig,
        publisher: &ServeHeartbeatPublisher,
    ) -> Result<(), GatewayError> {
        self.service_common_proposals(config)?;
        for registration in self.registrations()? {
            let Some(_lock) = self.try_lock_lane(&registration.lane)? else {
                continue;
            };
            self.park_due_lane_proposals_locked(&registration, config.result_size_limit_bytes)?;
            let started = Instant::now();
            let read = match read_request_file(&registration.worktree) {
                Ok(read) => read,
                Err(GatewayError::WorkerFile(failure)) => {
                    if state.faults.get(&registration.lane) == Some(&failure) {
                        continue;
                    }
                    state.faults.insert(registration.lane.clone(), failure);
                    publisher.record_activity(
                        ServeActivity::RequestStarted,
                        Some(&registration.lane),
                        None,
                    )?;
                    self.audit_worker_file_failure(
                        &registration.lane,
                        None,
                        failure.path_class,
                        failure.defect,
                        false,
                    )?;
                    let refusal = Refusal::new(RefusalRule::RequestPathInvalid);
                    self.append_audit(
                        &registration.lane,
                        AuditEvent::Refusal {
                            refusal: refusal.clone(),
                        },
                    )?;
                    let result = OperationResult::refused(
                        None,
                        None,
                        elapsed_millis(started),
                        refusal,
                        String::new(),
                        failure.defect.as_str().to_owned(),
                    );
                    self.publish_worker_result(
                        &registration,
                        &result,
                        config.result_size_limit_bytes,
                    )?;
                    publisher.record_activity(
                        ServeActivity::ResultPublished,
                        Some(&registration.lane),
                        result.seq,
                    )?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            state.faults.remove(&registration.lane);
            let (request, unfinished) = match read {
                RequestRead::Absent => {
                    state.forget_lane(&registration.lane);
                    continue;
                }
                RequestRead::Unfinished(request) => (request, true),
                RequestRead::Complete(request) => (request, false),
            };
            if state.seen.get(&registration.lane) == Some(&request) {
                continue;
            }
            if unfinished && self.wait_for_writer(state, &registration.lane, request.len())? {
                continue;
            }
            state.unfinished_cycles.remove(&registration.lane);
            if state.deferred_seed.remove(&registration.lane)
                && self.request_is_already_accepted(&registration.lane, &request)?
            {
                state.seen.insert(registration.lane, request);
                continue;
            }
            state
                .seen
                .insert(registration.lane.clone(), request.clone());
            let seq = std::str::from_utf8(&request)
                .ok()
                .and_then(|source| parse_request(source).ok())
                .map(|request| request.seq);
            publisher.record_activity(
                ServeActivity::RequestStarted,
                Some(&registration.lane),
                seq,
            )?;

            let result = match String::from_utf8(request) {
                Ok(source) => self.process_request_locked(&registration.lane, &source, config)?,
                Err(error) => {
                    let refusal = Refusal::new(RefusalRule::RequestUnreadable);
                    self.append_audit(
                        &registration.lane,
                        AuditEvent::Refusal {
                            refusal: refusal.clone(),
                        },
                    )?;
                    OperationResult::refused(
                        None,
                        None,
                        elapsed_millis(started),
                        refusal,
                        String::new(),
                        error.to_string(),
                    )
                }
            };
            self.publish_worker_result(&registration, &result, config.result_size_limit_bytes)?;
            publisher.record_activity(
                ServeActivity::ResultPublished,
                Some(&registration.lane),
                result.seq,
            )?;
        }
        Ok(())
    }

    /// Count one unfinished read and report whether to wait another cycle.
    ///
    /// The first unfinished read of an episode appends one audit record; the
    /// re-polls that follow append nothing, so waiting for a writer costs the
    /// ledger one line rather than one line per cycle.
    fn wait_for_writer(
        &self,
        state: &mut ServeRequestState,
        lane: &str,
        bytes: usize,
    ) -> Result<bool, GatewayError> {
        let cycles = state
            .unfinished_cycles
            .entry(lane.to_owned())
            .and_modify(|cycles| *cycles = cycles.saturating_add(1))
            .or_insert(1);
        let first = *cycles == 1;
        let waiting = *cycles <= INCOMPLETE_REQUEST_CYCLE_BOUND;
        if first {
            self.append_audit(
                lane,
                AuditEvent::RequestUnfinished {
                    lane: lane.to_owned(),
                    bytes,
                },
            )?;
        }
        Ok(waiting)
    }

    fn seed_seen_requests(&self) -> Result<ServeRequestState, GatewayError> {
        let mut state = ServeRequestState::default();
        for registration in self.registrations()? {
            let request = match read_request_file(&registration.worktree) {
                Err(GatewayError::WorkerFile(_failure)) => continue,
                Err(error) => return Err(error),
                Ok(read) => match read {
                    RequestRead::Absent => continue,
                    // A prefix names no sequence, so seeding cannot tell an
                    // already accepted request from a new one. The lane is seeded
                    // from the first complete read the loop makes instead.
                    RequestRead::Unfinished(_) => {
                        state.deferred_seed.insert(registration.lane);
                        continue;
                    }
                    RequestRead::Complete(request) => request,
                },
            };
            if self.request_is_already_accepted(&registration.lane, &request)? {
                state.seen.insert(registration.lane, request);
            }
        }
        Ok(state)
    }

    pub(crate) fn audit_worker_file_failure(
        &self,
        lane: &str,
        seq: Option<u64>,
        path_class: WorkerPathClass,
        defect: WorkerPathDefect,
        unpublishable: bool,
    ) -> Result<(), GatewayError> {
        self.append_audit(
            lane,
            AuditEvent::WorkerFileRefused {
                lane: lane.to_owned(),
                seq,
                path_class,
                defect,
                unpublishable,
            },
        )
        .map(|_| ())
    }

    pub(crate) fn publish_or_audit_worker_failure(
        &self,
        lane: &str,
        seq: Option<u64>,
        publication: Result<(), GatewayError>,
    ) -> Result<bool, GatewayError> {
        match publication {
            Ok(()) => Ok(true),
            Err(GatewayError::WorkerFile(failure)) => {
                self.audit_worker_file_failure(
                    lane,
                    seq,
                    failure.path_class,
                    failure.defect,
                    true,
                )?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn publish_proposal_worker_result(
        &self,
        registration: &crate::types::Registration,
        seq: u64,
        result: &OperationResult,
        limit: usize,
    ) -> Result<(), GatewayError> {
        self.publish_or_audit_worker_failure(
            &registration.lane,
            Some(seq),
            write_result(&registration.worktree, result, limit),
        )?;
        self.publish_or_audit_worker_failure(
            &registration.lane,
            Some(seq),
            write_proposal_result(&registration.worktree, seq, result, limit),
        )?;
        Ok(())
    }

    fn publish_worker_result(
        &self,
        registration: &crate::types::Registration,
        result: &OperationResult,
        limit: usize,
    ) -> Result<(), GatewayError> {
        self.publish_or_audit_worker_failure(
            &registration.lane,
            result.seq,
            write_result(&registration.worktree, result, limit),
        )?;
        if result.operation == Some(Operation::Propose)
            && let Some(seq) = result.seq
        {
            self.publish_or_audit_worker_failure(
                &registration.lane,
                Some(seq),
                write_proposal_result(&registration.worktree, seq, result, limit),
            )?;
        }
        Ok(())
    }

    /// Whether complete request bytes name a sequence this lane already accepted.
    fn request_is_already_accepted(
        &self,
        lane: &str,
        request: &[u8],
    ) -> Result<bool, GatewayError> {
        let Ok(source) = std::str::from_utf8(request) else {
            return Ok(false);
        };
        let Ok(accepted) = parse_request(source) else {
            return Ok(false);
        };
        Ok(self
            .request_watermark(lane)?
            .is_some_and(|watermark| accepted.seq <= watermark))
    }
}

/// Per-lane request-channel state carried from one serve cycle to the next.
#[derive(Debug, Default)]
struct ServeRequestState {
    /// Latest request bytes already handled or seeded, per lane.
    seen: BTreeMap<String, Vec<u8>>,
    /// Consecutive unfinished reads of the current episode, per lane.
    unfinished_cycles: BTreeMap<String, u32>,
    /// Lanes whose startup read found a file its writer had not finished.
    deferred_seed: BTreeSet<String>,
    /// The last path defect already refused for this lane.
    faults: BTreeMap<String, WorkerFileFailure>,
}

impl ServeRequestState {
    /// Drop the waiting state of a lane whose request file is gone.
    fn forget_lane(&mut self, lane: &str) {
        self.unfinished_cycles.remove(lane);
        self.deferred_seed.remove(lane);
        self.faults.remove(lane);
    }
}

/// What one read of a lane's request file found.
enum RequestRead {
    /// The lane has published no request file.
    Absent,
    /// The file exists but holds a prefix of a document, not a document.
    Unfinished(Vec<u8>),
    /// The file holds a complete document, valid or not.
    Complete(Vec<u8>),
}

fn read_request_file(worktree: &Path) -> Result<RequestRead, GatewayError> {
    let Some(request) = read_worker_regular(
        worktree,
        ".lane/request.json",
        MAX_WORKER_REQUEST_BYTES,
        WorkerPathClass::Request,
    )?
    else {
        return Ok(RequestRead::Absent);
    };
    if request_is_unfinished(&request) {
        Ok(RequestRead::Unfinished(request))
    } else {
        Ok(RequestRead::Complete(request))
    }
}

/// Read at most `limit` bytes from a worker file after a nonblocking, no-follow
/// open and regular-file check. A missing worktree or file is absent.
///
/// # Errors
///
/// Returns a typed worker failure for a refused path or read error.
pub fn read_worker_regular(
    worktree: &Path,
    relative: &str,
    limit: u64,
    path_class: WorkerPathClass,
) -> Result<Option<Vec<u8>>, GatewayError> {
    let root = match open(
        worktree,
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NONBLOCK
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(root) => root,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(worker_errno(WorkerPathClass::Worktree, error, false)),
    };
    let file = match openat2(
        &root,
        relative,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(file) => fs::File::from(file),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(worker_errno(path_class, error, false)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| worker_io(path_class, &error, false))?;
    if !metadata.is_file() {
        return Err(worker_failure(
            path_class,
            file_type_defect(metadata.file_type()),
        ));
    }
    if metadata.len() > limit {
        return Err(worker_failure(path_class, WorkerPathDefect::TooLarge));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| worker_io(path_class, &error, false))?;
    if bytes.len() as u64 > limit {
        return Err(worker_failure(path_class, WorkerPathDefect::TooLarge));
    }
    Ok(Some(bytes))
}

fn file_type_defect(kind: fs::FileType) -> WorkerPathDefect {
    if kind.is_fifo() {
        WorkerPathDefect::Fifo
    } else if kind.is_dir() {
        WorkerPathDefect::Directory
    } else if kind.is_symlink() {
        WorkerPathDefect::Symlink
    } else {
        WorkerPathDefect::NotARegularFile
    }
}

const fn worker_failure(path_class: WorkerPathClass, defect: WorkerPathDefect) -> GatewayError {
    GatewayError::WorkerFile(WorkerFileFailure { path_class, defect })
}

fn worker_errno(
    path_class: WorkerPathClass,
    error: nix::errno::Errno,
    write: bool,
) -> GatewayError {
    let defect = match error {
        nix::errno::Errno::ENOENT if path_class == WorkerPathClass::Worktree => {
            WorkerPathDefect::MissingWorktree
        }
        nix::errno::Errno::ELOOP => WorkerPathDefect::Symlink,
        nix::errno::Errno::ENOTDIR => WorkerPathDefect::NotARegularFile,
        nix::errno::Errno::EISDIR | nix::errno::Errno::ENOTEMPTY => WorkerPathDefect::Directory,
        nix::errno::Errno::EACCES | nix::errno::Errno::EPERM | nix::errno::Errno::EROFS
            if write =>
        {
            WorkerPathDefect::UnwritableDirectory
        }
        _ if write => WorkerPathDefect::WriteFailed,
        _ => WorkerPathDefect::Unreadable,
    };
    worker_failure(path_class, defect)
}

fn worker_io(path_class: WorkerPathClass, error: &io::Error, write: bool) -> GatewayError {
    match error.raw_os_error() {
        Some(code) => worker_errno(path_class, nix::errno::Errno::from_raw(code), write),
        None if write => worker_failure(path_class, WorkerPathDefect::WriteFailed),
        None => worker_failure(path_class, WorkerPathDefect::Unreadable),
    }
}

/// Whether these bytes are a prefix of a request rather than a whole one.
///
/// Emptiness, a truncated trailing UTF-8 sequence, and a JSON parse that runs
/// out of input all say the writer has not finished. Every other decoding or
/// parse failure is a complete document the gateway refuses on its merits, so
/// a genuinely malformed request is still refused on the cycle that reads it.
fn request_is_unfinished(request: &[u8]) -> bool {
    let source = match std::str::from_utf8(request) {
        Ok(source) => source,
        Err(error) => return error.error_len().is_none(),
    };
    serde_json::from_str::<serde_json::Value>(source)
        .err()
        .is_some_and(|error| error.classify() == serde_json::error::Category::Eof)
}

enum PublisherCommand {
    Stop,
}

pub struct ServeHeartbeatPublisher {
    snapshot: Arc<Mutex<ServeHeartbeat>>,
    commands: mpsc::Sender<PublisherCommand>,
    handle: Option<thread::JoinHandle<Result<(), GatewayError>>>,
}

impl ServeHeartbeatPublisher {
    fn start(
        path: PathBuf,
        interval_millis: u64,
        snapshot: Arc<Mutex<ServeHeartbeat>>,
    ) -> Result<Self, GatewayError> {
        let (commands, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread_snapshot = Arc::clone(&snapshot);
        let handle = thread::Builder::new()
            .name("lane-gateway-heartbeat".to_owned())
            .spawn(move || {
                let initial = write_heartbeat(&path, &thread_snapshot);
                if ready_sender.send(initial.is_ok()).is_err() {
                    return Err(GatewayError::HeartbeatPublisherFailed);
                }
                initial?;
                loop {
                    match receiver.recv_timeout(Duration::from_millis(interval_millis)) {
                        Ok(PublisherCommand::Stop) => {
                            write_heartbeat(&path, &thread_snapshot)?;
                            return Ok(());
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            write_heartbeat(&path, &thread_snapshot)?;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(GatewayError::HeartbeatPublisherFailed);
                        }
                    }
                }
            })
            .map_err(|_source| GatewayError::HeartbeatPublisherFailed)?;
        if ready_receiver.recv() != Ok(true) {
            drop(handle.join());
            return Err(GatewayError::HeartbeatPublisherFailed);
        }
        Ok(Self {
            snapshot,
            commands,
            handle: Some(handle),
        })
    }

    fn record_activity(
        &self,
        activity: ServeActivity,
        lane: Option<&str>,
        seq: Option<u64>,
    ) -> Result<(), GatewayError> {
        self.ensure_healthy()?;
        let timestamp = crate::gateway::timestamp_unix_ms()?;
        let mut snapshot = self
            .snapshot
            .lock()
            .map_err(|_error| GatewayError::HeartbeatPublisherFailed)?;
        snapshot.last_activity_unix_ms = timestamp;
        snapshot.activity = activity;
        snapshot.lane = lane.map(str::to_owned);
        snapshot.seq = seq;
        drop(snapshot);
        Ok(())
    }

    /// Record the stopped state and its reason before the final publication.
    ///
    /// A poisoned snapshot lock cannot be repaired here and the failure paths
    /// report themselves through the crash report, so this is best effort: a
    /// heartbeat left saying `running` is exactly the case the pid and cadence
    /// it carries exist to settle.
    fn mark_stopped(&self, reason: ServeStopReason) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            snapshot.process_state = ServeProcessState::Stopped;
            snapshot.stop_reason = Some(reason);
        }
    }

    fn ensure_healthy(&self) -> Result<(), GatewayError> {
        if self
            .handle
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
        {
            Err(GatewayError::HeartbeatPublisherFailed)
        } else {
            Ok(())
        }
    }

    fn stop_and_join(mut self) -> Result<(), GatewayError> {
        if self.commands.send(PublisherCommand::Stop).is_err() {
            let Some(handle) = self.handle.take() else {
                return Err(GatewayError::HeartbeatPublisherFailed);
            };
            drop(handle.join());
            return Err(GatewayError::HeartbeatPublisherFailed);
        }
        let Some(handle) = self.handle.take() else {
            return Err(GatewayError::HeartbeatPublisherFailed);
        };
        match handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(GatewayError::HeartbeatPublisherFailed),
        }
    }
}

pub fn supervise_serve<F>(
    gateway: &Gateway,
    config: &ServeConfig,
    serve_inner: F,
) -> Result<(), GatewayError>
where
    F: FnOnce(&ServeHeartbeatPublisher) -> Result<(), GatewayError>,
{
    let started_unix_ms = crate::gateway::timestamp_unix_ms()?;
    let snapshot = Arc::new(Mutex::new(ServeHeartbeat::new(
        std::process::id(),
        started_unix_ms,
        config.heartbeat_interval_millis,
    )));
    if !config.is_valid() {
        return report_serve_failure(
            gateway,
            &snapshot,
            started_unix_ms,
            SupervisedFailure::Error(GatewayError::InvalidServeConfig),
        );
    }
    if let Err(error) = install_signal_watch() {
        return report_serve_failure(
            gateway,
            &snapshot,
            started_unix_ms,
            SupervisedFailure::Error(error),
        );
    }
    let publisher = match ServeHeartbeatPublisher::start(
        gateway.serve_heartbeat_path(),
        config.heartbeat_interval_millis,
        Arc::clone(&snapshot),
    ) {
        Ok(publisher) => publisher,
        Err(error) => {
            return report_serve_failure(
                gateway,
                &snapshot,
                started_unix_ms,
                SupervisedFailure::Error(error),
            );
        }
    };
    let outcome = catch_unwind(AssertUnwindSafe(|| serve_inner(&publisher)));
    publisher.mark_stopped(match &outcome {
        Ok(Ok(())) => observed_termination_signal().unwrap_or(ServeStopReason::ShutdownFlag),
        Ok(Err(_error)) => ServeStopReason::Error,
        Err(_payload) => ServeStopReason::Panic,
    });
    let publisher_result = publisher.stop_and_join();
    let failure = match outcome {
        Ok(Ok(())) => match publisher_result {
            Ok(()) => return Ok(()),
            Err(error) => SupervisedFailure::Error(error),
        },
        Ok(Err(error)) => SupervisedFailure::Error(error),
        Err(payload) => SupervisedFailure::Panic(panic_message(payload.as_ref())),
    };
    report_serve_failure(gateway, &snapshot, started_unix_ms, failure)
}

enum SupervisedFailure {
    Error(GatewayError),
    Panic(String),
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload.downcast_ref::<String>().map_or_else(
        || {
            payload.downcast_ref::<&'static str>().map_or_else(
                || "non-string panic payload".to_owned(),
                |message| (*message).to_owned(),
            )
        },
        Clone::clone,
    )
}

fn report_serve_failure(
    gateway: &Gateway,
    snapshot: &Arc<Mutex<ServeHeartbeat>>,
    started_unix_ms: u64,
    failure: SupervisedFailure,
) -> Result<(), GatewayError> {
    let failed_unix_ms = crate::gateway::timestamp_unix_ms()?;
    let last_activity_unix_ms = snapshot
        .lock()
        .map_or(started_unix_ms, |snapshot| snapshot.last_activity_unix_ms);
    let (failure_kind, message, error) = match failure {
        SupervisedFailure::Error(error) => {
            let message = error.to_string();
            (ServeFailureKind::Error, message, error)
        }
        SupervisedFailure::Panic(message) => {
            let error = GatewayError::ServePanicked(message.clone());
            (ServeFailureKind::Panic, message, error)
        }
    };
    let report = ServeCrashReport::new(
        std::process::id(),
        started_unix_ms,
        failed_unix_ms,
        last_activity_unix_ms,
        failure_kind,
        message,
    );
    match write_crash_report(&gateway.serve_crash_path(), &report) {
        Ok(()) => Err(error),
        Err(report_failure) => Err(GatewayError::CrashReportWriteFailed {
            failure: Box::new(error),
            report_failure: Box::new(report_failure),
        }),
    }
}

pub fn write_heartbeat(
    path: &Path,
    snapshot: &Arc<Mutex<ServeHeartbeat>>,
) -> Result<(), GatewayError> {
    let mut heartbeat = snapshot
        .lock()
        .map_err(|_error| GatewayError::HeartbeatPublisherFailed)?;
    heartbeat.heartbeat_unix_ms = crate::gateway::timestamp_unix_ms()?;
    write_state_json_atomic(path, "serve-heartbeat", &*heartbeat)
}

pub fn write_crash_report(path: &Path, report: &ServeCrashReport) -> Result<(), GatewayError> {
    write_state_json_atomic(path, "serve-crash", report)
}

pub fn write_state_json_atomic(
    path: &Path,
    temporary_stem: &str,
    value: &impl Serialize,
) -> Result<(), GatewayError> {
    let mut encoded = serde_json::to_vec(value)
        .map_err(|_error| GatewayError::Serialization("serve_state_json"))?;
    encoded.push(b'\n');
    let parent = path
        .parent()
        .ok_or(GatewayError::CorruptState("serve_state_path"))?;
    fs::create_dir_all(parent)
        .map_err(|source| GatewayError::io("create_serve_state_directory", source))?;
    let sequence = SERVE_STATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{temporary_stem}.{}.{sequence}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| GatewayError::io("open_serve_state", source))?;
    if let Err(source) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        drop(fs::remove_file(&temporary));
        return Err(GatewayError::io("write_serve_state", source));
    }
    drop(file);
    if let Err(source) = fs::rename(&temporary, path) {
        drop(fs::remove_file(&temporary));
        return Err(GatewayError::io("publish_serve_state", source));
    }
    Ok(())
}

/// Block the watched signals on this thread and start the accepting thread.
///
/// A signal mask is per-thread, so the block is repeated for every serve
/// generation while only the accepting thread is installed once. A generation
/// entered from a second thread of the same process would otherwise serve
/// unblocked, take a watched signal with its default disposition, and end the
/// process where the heartbeat still says `running` — which is the whole
/// failure this watch exists to prevent. Blocking before the publisher thread
/// exists also makes every thread this generation goes on to create inherit
/// the block. The accepting thread records the signal for the loop, which
/// stops at its next check and exits through the ordinary stopped-heartbeat
/// path. `std::process::Command` restores an empty mask in each child before
/// exec, so a runner subprocess is unaffected by the block.
fn install_signal_watch() -> Result<(), GatewayError> {
    let mut watched = SigSet::empty();
    for signal in WATCHED_SIGNALS {
        watched.add(signal);
    }
    if watched.thread_block().is_err() {
        return Err(signal_watch_error());
    }
    let installed = *SIGNAL_WATCH.get_or_init(|| {
        thread::Builder::new()
            .name("lane-gateway-signal-watch".to_owned())
            .spawn(move || {
                while let Ok(signal) = watched.wait() {
                    OBSERVED_SIGNAL.store(signal as i32, Ordering::Relaxed);
                }
            })
            .is_ok()
    });
    if !installed {
        return Err(signal_watch_error());
    }
    // A generation starts having observed nothing. The accepting thread and
    // its record outlive any one generation, so a signal an earlier generation
    // already stopped on would otherwise stop this one on its first check,
    // before it has served a single cycle. The reset happens after the block
    // so this thread is never briefly exposed to a default disposition, and a
    // process serves one generation at a time, so it cannot discard a signal
    // another generation is still waiting to observe.
    OBSERVED_SIGNAL.store(0, Ordering::Relaxed);
    Ok(())
}

fn signal_watch_error() -> GatewayError {
    GatewayError::io(
        "install_signal_watch",
        io::Error::other("watched signals cannot be accepted"),
    )
}

/// The stop reason of a watched signal this process has already accepted.
fn observed_termination_signal() -> Option<ServeStopReason> {
    match Signal::try_from(OBSERVED_SIGNAL.load(Ordering::Relaxed)) {
        Ok(Signal::SIGTERM) => Some(ServeStopReason::SignalTerminate),
        Ok(Signal::SIGINT) => Some(ServeStopReason::SignalInterrupt),
        Ok(Signal::SIGHUP) => Some(ServeStopReason::SignalHangup),
        _ => None,
    }
}

/// Judge one published heartbeat without trusting its writer to still exist.
///
/// A generation that recorded its own stop is stopped. Otherwise the serve is
/// dead when its process is gone, or when the heartbeat is older than twice
/// the cadence the generation itself published: one missed publication can be
/// a busy host, two cannot. Readers outside this crate supply `now_unix_ms`
/// from their own clock, which also lets a runbook replay a captured file.
#[must_use]
pub fn heartbeat_liveness(heartbeat: &ServeHeartbeat, now_unix_ms: u64) -> ServeLiveness {
    if heartbeat.process_state == ServeProcessState::Stopped {
        return ServeLiveness::Stopped;
    }
    if !Path::new("/proc").join(heartbeat.pid.to_string()).exists() {
        return ServeLiveness::Dead(ServeDeathReason::ProcessGone);
    }
    if now_unix_ms.saturating_sub(heartbeat.heartbeat_unix_ms)
        > heartbeat.heartbeat_interval_millis.saturating_mul(2)
    {
        return ServeLiveness::Dead(ServeDeathReason::HeartbeatStale);
    }
    ServeLiveness::Alive
}

/// The activity to record for a stop, or none while the loop keeps serving.
///
/// A signal stop and an operator's flag are distinct activities because the
/// activity is what a reader sees first: `clean_shutdown` on a signal exit
/// would say an operator asked for the stop when nothing did, and the reader
/// would have to consult `stop_reason` to find that out.
fn stop_activity(shutdown_file: &Path) -> Result<Option<ServeActivity>, GatewayError> {
    if observed_termination_signal().is_some() {
        return Ok(Some(ServeActivity::SignalStop));
    }
    if shutdown_requested(shutdown_file)? {
        return Ok(Some(ServeActivity::CleanShutdown));
    }
    Ok(None)
}

fn shutdown_requested(path: &Path) -> Result<bool, GatewayError> {
    match fs::metadata(path) {
        Ok(_metadata) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(GatewayError::io("read_shutdown_flag", source)),
    }
}

/// Publish one operation result through the worker's result-file channel.
///
/// # Errors
///
/// Returns an error when the result directory, chunks, or atomic result file
/// cannot be written.
pub fn write_result(
    worktree: &Path,
    result: &OperationResult,
    result_size_limit_bytes: usize,
) -> Result<(), GatewayError> {
    if result.schema != RESULT_SCHEMA {
        return Err(GatewayError::CorruptState("result_schema"));
    }
    ensure_worker_directory(worktree, ".lane")?;
    let mut published = result.clone();
    published.schema = RESULT_SCHEMA;
    let combined_size = result.stdout.len().saturating_add(result.stderr.len());
    if combined_size > result_size_limit_bytes {
        let chunks = chunk_outputs(result, result_size_limit_bytes);
        published.stdout.clear();
        published.stderr.clear();
        for chunk in chunks {
            let file = chunk_file_name(result.seq, chunk.index);
            write_json(
                worktree,
                &format!(".lane/{file}"),
                WorkerPathClass::OutputChunk,
                &chunk,
            )?;
            published.output_chunks.push(OutputChunkRef {
                index: chunk.index,
                stream: chunk.stream,
                file,
            });
        }
    }
    write_json(
        worktree,
        ".lane/result.json",
        WorkerPathClass::Result,
        &published,
    )
}

/// Publish one proposal lifecycle result to its sequence-stable projection.
///
/// # Errors
///
/// Returns an error when the result schema or sequence is inconsistent, or
/// when the proposal directory, chunks, or atomic result file cannot be written.
pub fn write_proposal_result(
    worktree: &Path,
    seq: u64,
    result: &OperationResult,
    result_size_limit_bytes: usize,
) -> Result<(), GatewayError> {
    if result.schema != RESULT_SCHEMA || result.seq != Some(seq) {
        return Err(GatewayError::CorruptState("proposal_result_schema"));
    }
    ensure_worker_directory(worktree, ".lane/proposals")?;
    let mut published = result.clone();
    published.schema = RESULT_SCHEMA;
    let combined_size = result.stdout.len().saturating_add(result.stderr.len());
    if combined_size > result_size_limit_bytes {
        let chunks = chunk_outputs(result, result_size_limit_bytes);
        published.stdout.clear();
        published.stderr.clear();
        for chunk in chunks {
            let file = chunk_file_name(result.seq, chunk.index);
            write_json(
                worktree,
                &format!(".lane/{file}"),
                WorkerPathClass::OutputChunk,
                &chunk,
            )?;
            published.output_chunks.push(OutputChunkRef {
                index: chunk.index,
                stream: chunk.stream,
                file,
            });
        }
    }
    write_json(
        worktree,
        &format!(".lane/proposals/{seq}.json"),
        WorkerPathClass::ProposalResult,
        &published,
    )
}

fn chunk_outputs(result: &OperationResult, limit: usize) -> Vec<OutputChunk> {
    let mut chunks = Vec::new();
    split_output(
        &result.stdout,
        limit,
        result.seq,
        OutputStream::Stdout,
        &mut chunks,
    );
    split_output(
        &result.stderr,
        limit,
        result.seq,
        OutputStream::Stderr,
        &mut chunks,
    );
    chunks
}

fn split_output(
    output: &str,
    limit: usize,
    seq: Option<u64>,
    stream: OutputStream,
    chunks: &mut Vec<OutputChunk>,
) {
    let mut payload = String::new();
    for character in output.chars() {
        let width = character.len_utf8();
        if !payload.is_empty() && payload.len().saturating_add(width) > limit {
            let index = chunks.len();
            chunks.push(OutputChunk::new(
                seq,
                index,
                stream,
                std::mem::take(&mut payload),
            ));
        }
        payload.push(character);
    }
    if !payload.is_empty() {
        let index = chunks.len();
        chunks.push(OutputChunk::new(seq, index, stream, payload));
    }
}

fn chunk_file_name(seq: Option<u64>, index: usize) -> String {
    let sequence = seq.map_or_else(|| "unknown".to_owned(), |seq| seq.to_string());
    format!("result-{sequence}-{index:04}.json")
}

fn write_json(
    worktree: &Path,
    relative: &str,
    path_class: WorkerPathClass,
    value: &impl Serialize,
) -> Result<(), GatewayError> {
    let mut encoded =
        serde_json::to_vec(value).map_err(|_error| GatewayError::Serialization("result_json"))?;
    encoded.push(b'\n');
    let (parent_name, name) = relative
        .rsplit_once('/')
        .ok_or(GatewayError::CorruptState("result_path"))?;
    let root = open(
        worktree,
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NONBLOCK
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| worker_errno(WorkerPathClass::Worktree, error, true))?;
    let parent = openat2(
        &root,
        parent_name,
        OpenHow::new()
            .flags(
                OFlag::O_RDONLY
                    | OFlag::O_DIRECTORY
                    | OFlag::O_NONBLOCK
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| worker_errno(WorkerPathClass::ProtocolDirectory, error, true))?;
    // O_PATH inspects even an unreadable target without waiting on a FIFO.
    match openat2(
        &parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(target) => {
            let metadata = fs::File::from(target)
                .metadata()
                .map_err(|source| worker_io(path_class, &source, false))?;
            if !metadata.is_file() {
                return Err(worker_failure(
                    path_class,
                    file_type_defect(metadata.file_type()),
                ));
            }
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(worker_errno(path_class, error, false)),
    }
    let suffix = RESULT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(".result.{}.{}.tmp", std::process::id(), suffix);
    let mut file = openat2(
        &parent,
        temporary.as_str(),
        OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NONBLOCK
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(fs::File::from)
    .map_err(|error| worker_errno(path_class, error, true))?;
    if let Err(source) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ignored = unlinkat(&parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
        return Err(worker_io(path_class, &source, true));
    }
    drop(file);
    if let Err(error) = renameat(&parent, temporary.as_str(), &parent, name) {
        let _ignored = unlinkat(&parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
        return Err(worker_errno(path_class, error, true));
    }
    Ok(())
}

fn ensure_worker_directory(worktree: &Path, relative: &str) -> Result<(), GatewayError> {
    let mut parent = open(
        worktree,
        OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NONBLOCK
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| worker_errno(WorkerPathClass::Worktree, error, true))?;
    for name in relative.split('/') {
        match mkdirat(&parent, name, Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IXUSR) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
            Err(error) => {
                return Err(worker_errno(
                    WorkerPathClass::ProtocolDirectory,
                    error,
                    true,
                ));
            }
        }
        parent = openat2(
            &parent,
            name,
            OpenHow::new()
                .flags(
                    OFlag::O_RDONLY
                        | OFlag::O_DIRECTORY
                        | OFlag::O_NONBLOCK
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                )
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| worker_errno(WorkerPathClass::ProtocolDirectory, error, true))?;
    }
    Ok(())
}
