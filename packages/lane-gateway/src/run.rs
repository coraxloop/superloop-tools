//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`target_root_hashes_the_canonical_checkout_path`] |  | — |
//! | [`absent_target_root_uses_the_checkout_target_directory`] |  | — |
//! | [`target_root_hashing_falls_back_when_checkout_canonicalization_fails`] |  | — |
//! | [`runner_target_dir_overrides_an_existing_command_environment_value`] |  | — |
//! | [`runner_receives_the_lane_mirror_remote_beside_the_commit`] |  | — |
//! | [`runner_mirror_remote_with_spaces_and_a_colon_arrives_unaltered`] |  | — |
//! | [`blank_mirror_remote_is_omitted_rather_than_exported_empty`] |  | — |
//! | [`runner_group_kernel_probe_bounds_zombie_grace`] |  | — |
//! | [`runner_group_keeps_leader_until_descendants_stop`] |  | — |

use std::cmp;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use crate::gateway::{GatewayError, timestamp_unix_ms};
use crate::push::elapsed_millis;
use crate::serve::{ServeConfig, write_state_json_atomic};
use crate::sha256::digest_hex;
use crate::types::{CommandSpec, Operation, OperationResult, Refusal, RefusalRule, Registration};

const RUNNER_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const RUNNER_TERMINATION_GRACE: Duration = Duration::from_secs(10);
/// Exit code the runner transport reserves for its own failures.
///
/// ssh exits 255 for a connection it could not establish or keep — a reset, an
/// unreachable host, a keepalive that expired — and never for the status of the
/// remote command, which it passes through unchanged; the runner preserves
/// ssh's code in turn. So 255 is the one code that says the command never
/// reported at all, which is a different fact for a lane than a command that
/// ran and failed. A command that chose 255 as its own status would be read as
/// a lost transport, and no registered command does.
const RUNNER_TRANSPORT_EXIT_CODE: i32 = 255;
const WALL_BUDGET_ENVIRONMENT: &str = "LANE_GATEWAY_WALL_BUDGET_SECONDS";
const MIRROR_COMMIT_ENVIRONMENT: &str = "LANE_GATEWAY_MIRROR_COMMIT";
const MIRROR_REMOTE_ENVIRONMENT: &str = "LANE_GATEWAY_MIRROR_REMOTE";
const CARGO_TARGET_DIR_ENVIRONMENT: &str = "CARGO_TARGET_DIR";

impl crate::gateway::Gateway {
    pub(crate) fn run_registration(
        registration: &Registration,
        command: &CommandSpec,
        seq: u64,
        mirror_commit: String,
        config: &ServeConfig,
        started: Instant,
        queued_unix_ms: u64,
    ) -> Result<OperationResult, GatewayError> {
        let cargo_target_dir = runner_target_dir(
            &registration.mirror_checkout,
            config.cargo_target_root().map(Path::as_os_str),
        );
        let queue_wait_ms = timestamp_unix_ms()?.saturating_sub(queued_unix_ms);
        let outcome = execute_runner(
            registration,
            command,
            &mirror_commit,
            &cargo_target_dir,
            config,
            seq,
        );
        let wall_millis = elapsed_millis(started);
        let mut result = match outcome.state {
            RunnerState::Completed => OperationResult::completed_run(
                seq,
                wall_millis,
                mirror_commit,
                outcome.exit_code,
                outcome.stdout,
                outcome.stderr,
            ),
            RunnerState::OverBudget => OperationResult::over_budget(
                seq,
                wall_millis,
                mirror_commit,
                outcome.exit_code,
                outcome.stdout,
                outcome.stderr,
            ),
            RunnerState::Failed => refused_run(
                RefusalRule::RunnerFailed,
                seq,
                wall_millis,
                mirror_commit,
                outcome,
            ),
            RunnerState::ConnectionLost => refused_run(
                RefusalRule::RunnerConnectionLost,
                seq,
                wall_millis,
                mirror_commit,
                outcome,
            ),
        };
        result.cargo_target_dir = Some(cargo_target_dir);
        result.queue_wait_ms = Some(queue_wait_ms);
        Ok(result)
    }
}

/// One refused run carrying the evidence the execution did produce.
///
/// A refusal keeps the runner's output, exit code, and the mirror commit it was
/// executed against, so a lane reading `runner_connection_lost` can still see
/// whatever reached it before the transport died.
fn refused_run(
    rule: RefusalRule,
    seq: u64,
    wall_millis: u64,
    mirror_commit: String,
    outcome: RunnerOutcome,
) -> OperationResult {
    let refusal = Refusal::new(rule).with_seq(seq);
    let mut result = OperationResult::refused(
        Some(seq),
        Some(Operation::Run),
        wall_millis,
        refusal,
        outcome.stdout,
        outcome.stderr,
    );
    result.exit_code = outcome.exit_code;
    result.commit_id = Some(mirror_commit);
    result
}

fn execute_runner(
    registration: &Registration,
    command_spec: &CommandSpec,
    mirror_commit: &str,
    cargo_target_dir: &Path,
    config: &ServeConfig,
    seq: u64,
) -> RunnerOutcome {
    let Some(program) = config.runner_prefix().first() else {
        return RunnerOutcome::failed("runner argv prefix is empty");
    };

    let mut command = Command::new(program);
    configure_runner_target_dir(&mut command, cargo_target_dir);
    configure_runner_mirror(&mut command, mirror_commit, &registration.mirror_remote);
    command
        .process_group(0)
        .args(&config.runner_prefix()[1..])
        .arg(&registration.mirror_checkout)
        .args(&command_spec.argv)
        .env(
            WALL_BUDGET_ENVIRONMENT,
            command_spec.wall_budget_seconds.to_string(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return RunnerOutcome::failed(&error.to_string()),
    };
    let group = match RunnerGroup::capture(child.id()) {
        Ok(group) => group,
        Err(error) => {
            drop(child.kill());
            drop(reap_child(&mut child, config.approve_deadline()));
            return RunnerOutcome::failed(&error.to_string());
        }
    };
    let group_path = config
        .runner_state_dir()
        .join(&registration.lane)
        .join(format!("{seq}.json"));
    if let Err(error) = write_state_json_atomic(&group_path, "runner-group", &group) {
        let _cleanup = group.terminate(
            config.runner_termination_grace(),
            config.approve_deadline(),
            Some(&mut child),
        );
        drop(reap_child(&mut child, config.approve_deadline()));
        return RunnerOutcome::failed(&error.to_string());
    }
    let deadline = config.approve_deadline();
    let stdout_reader = child.stdout.take().map(|pipe| spawn_reader(pipe, deadline));
    let stderr_reader = child.stderr.take().map(|pipe| spawn_reader(pipe, deadline));
    let budget = Duration::from_secs(command_spec.wall_budget_seconds);
    let budget = deadline.map_or(budget, |deadline| {
        budget.min(deadline.saturating_duration_since(Instant::now()))
    });
    let mut waited = wait_for_runner(&mut child, budget, &group, config);
    if waited.state == RunnerState::ConnectionLost {
        waited.error = group
            .terminate(
                config.runner_termination_grace(),
                deadline,
                Some(&mut child),
            )
            .err();
    }
    if wait_for_output(stdout_reader.as_ref(), stderr_reader.as_ref(), config) {
        waited.state = RunnerState::OverBudget;
        waited.error = group
            .terminate(
                config.runner_termination_grace(),
                deadline,
                Some(&mut child),
            )
            .err();
    }
    let stdout = collect_reader(stdout_reader, "runner standard output pipe was unavailable");
    let stderr = collect_reader(stderr_reader, "runner standard error pipe was unavailable");

    let mut state = if stdout.timed_out || stderr.timed_out {
        RunnerState::OverBudget
    } else {
        waited.state
    };
    let mut stderr_bytes = stderr.bytes;
    let cleanup_failed = waited.error.is_some();
    if let Some(error) = waited.error {
        append_message(&mut stderr_bytes, &error.to_string());
        state = gateway_side_failure(state);
    }
    if let Some(error) = stdout.error {
        append_message(&mut stderr_bytes, &error);
        state = gateway_side_failure(state);
    }
    if let Some(error) = stderr.error {
        append_message(&mut stderr_bytes, &error);
        state = gateway_side_failure(state);
    }

    if !cleanup_failed && let Err(error) = fs::remove_file(&group_path) {
        append_message(&mut stderr_bytes, &error.to_string());
        state = gateway_side_failure(state);
    }
    RunnerOutcome {
        state,
        exit_code: waited.exit_code,
        stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    }
}

/// Fold a gateway-side wait or pipe failure into the runner's state.
///
/// A runner that already reported an over-budget kill or a dead transport keeps
/// that verdict: those name why the command did not report, which a failed pipe
/// on this side does not contradict. Only an otherwise complete run degrades.
const fn gateway_side_failure(state: RunnerState) -> RunnerState {
    match state {
        RunnerState::Completed => RunnerState::Failed,
        RunnerState::OverBudget | RunnerState::Failed | RunnerState::ConnectionLost => state,
    }
}

fn configure_runner_target_dir(command: &mut Command, cargo_target_dir: &Path) {
    command.env(CARGO_TARGET_DIR_ENVIRONMENT, cargo_target_dir);
}

/// The mirror facts one runner invocation needs: which commit the lane's work
/// is, and where that lane's bare mirror lives.
///
/// A runner that reads its host and lanes root from its own launch environment
/// places every lane of one serve on the same compute node, so a serve started
/// against a node that later carries the estate's load cannot move a single
/// lane off it. The registration already names the lane's own mirror as an
/// opaque Git remote — the gateway checks its reachability at registration and
/// pushes each snapshot to it — so passing that specification to the runner is
/// what lets placement be a per-lane fact rather than a per-serve one. The
/// value travels verbatim because only Git and the runner interpret a remote
/// specification, and a runner that does not read the variable is unaffected
/// by its presence.
///
/// A remote that is blank by the registration's own emptiness test configures
/// nothing at all, since an unset variable leaves whatever defaults the runner
/// was launched with in force where an empty one would override them with a
/// value naming no host.
fn configure_runner_mirror(command: &mut Command, mirror_commit: &str, mirror_remote: &str) {
    command.env(MIRROR_COMMIT_ENVIRONMENT, mirror_commit);
    if !mirror_remote.trim().is_empty() {
        command.env(MIRROR_REMOTE_ENVIRONMENT, mirror_remote);
    }
}

fn runner_target_dir(mirror_checkout: &Path, target_root: Option<&OsStr>) -> PathBuf {
    let Some(target_root) = target_root else {
        return mirror_checkout.join("target");
    };
    let hash_path = mirror_checkout
        .canonicalize()
        .unwrap_or_else(|_| mirror_checkout.to_path_buf());
    let digest = digest_hex(hash_path.as_os_str().as_bytes());
    Path::new(target_root).join(format!("lane-gateway-{}", &digest[..16]))
}

fn wait_for_runner(
    child: &mut Child,
    budget: Duration,
    group: &RunnerGroup,
    config: &ServeConfig,
) -> WaitOutcome {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit_code = status.code().unwrap_or(1);
                return WaitOutcome {
                    state: if exit_code == RUNNER_TRANSPORT_EXIT_CODE {
                        RunnerState::ConnectionLost
                    } else {
                        RunnerState::Completed
                    },
                    exit_code,
                    error: None,
                };
            }
            Ok(None) => {}
            Err(error) => return stop_failed_runner(child, error, group, config),
        }

        let elapsed = started.elapsed();
        if elapsed >= budget {
            let kill_error = group
                .terminate(
                    config.runner_termination_grace(),
                    config.approve_deadline(),
                    Some(child),
                )
                .err();
            let waited = reap_child(child, config.approve_deadline());
            return match waited {
                Ok(status) => WaitOutcome {
                    state: RunnerState::OverBudget,
                    exit_code: status.code().unwrap_or(1),
                    error: kill_error,
                },
                Err(error) => WaitOutcome {
                    state: RunnerState::OverBudget,
                    exit_code: 1,
                    error: Some(error),
                },
            };
        }

        thread::sleep(cmp::min(
            RUNNER_POLL_INTERVAL,
            budget.saturating_sub(elapsed),
        ));
    }
}

fn stop_failed_runner(
    child: &mut Child,
    error: io::Error,
    group: &RunnerGroup,
    config: &ServeConfig,
) -> WaitOutcome {
    let _cleanup = group.terminate(
        config.runner_termination_grace(),
        config.approve_deadline(),
        Some(child),
    );
    let exit_code = reap_child(child, config.approve_deadline())
        .ok()
        .and_then(|status| status.code())
        .unwrap_or(1);
    WaitOutcome {
        state: RunnerState::Failed,
        exit_code,
        error: Some(error),
    }
}

fn reap_child(
    child: &mut Child,
    deadline: Option<Instant>,
) -> io::Result<std::process::ExitStatus> {
    let deadline = deadline.unwrap_or_else(|| Instant::now() + RUNNER_TERMINATION_GRACE);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runner did not reap before its deadline",
            ));
        }
        thread::sleep(RUNNER_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn wait_for_output(
    stdout: Option<&JoinHandle<ReaderOutput>>,
    stderr: Option<&JoinHandle<ReaderOutput>>,
    config: &ServeConfig,
) -> bool {
    let Some(deadline) = config.approve_deadline() else {
        return false;
    };
    let reserved_grace = config.runner_termination_grace().min(Duration::from_secs(
        config.approve_deadline_margin_seconds(),
    ));
    let cleanup_at = deadline
        .checked_sub(reserved_grace)
        .unwrap_or_else(Instant::now);
    while stdout.is_some_and(|reader| !reader.is_finished())
        || stderr.is_some_and(|reader| !reader.is_finished())
    {
        if Instant::now() >= cleanup_at {
            return true;
        }
        thread::sleep(
            RUNNER_POLL_INTERVAL.min(cleanup_at.saturating_duration_since(Instant::now())),
        );
    }
    false
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerGroup {
    group: i32,
    start_ticks: u64,
    /// The boot this record's pid and start time were read under.
    ///
    /// A pid and a start tick name one process only within a single boot,
    /// because the kernel restarts both counters at boot: after a reboot an
    /// unrelated process can carry the pair a record already holds, and
    /// signalling it would reach whatever the kernel handed that pid to. The
    /// field is optional so that a record written before it existed still
    /// parses, carrying no boot and therefore matching none, which leaves the
    /// corrupt-state path to records whose shape is genuinely broken.
    boot_id: Option<String>,
}

/// Where the kernel publishes the identity of the running boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string(BOOT_ID_PATH)?.trim().to_owned())
}

impl RunnerGroup {
    fn capture(pid: u32) -> io::Result<Self> {
        let pid = i32::try_from(pid).map_err(io::Error::other)?;
        let boot_id = boot_id()?;
        let identity =
            process_identity(pid)?.ok_or_else(|| io::Error::other("runner identity is absent"))?;
        if identity.group != pid {
            return Err(io::Error::other("runner does not lead its process group"));
        }
        Ok(Self {
            group: pid,
            start_ticks: identity.start_ticks,
            boot_id: Some(boot_id),
        })
    }

    fn matches(&self) -> io::Result<bool> {
        if self.group <= 0 {
            return Err(io::Error::other("runner group identifier is invalid"));
        }
        // The boot is compared before the process table is read at all: a
        // record from another boot names no process here, so reading a pid it
        // no longer owns could only produce a false match. An unreadable boot
        // identity leaves the question unanswerable, which forbids the signal
        // for the same reason a mismatch does.
        if !boot_id().is_ok_and(|current| self.boot_id.as_deref() == Some(current.as_str())) {
            return Ok(false);
        }
        Ok(process_identity(self.group)?.is_some_and(|identity| {
            identity.start_ticks == self.start_ticks && identity.group == self.group
        }))
    }

    fn terminate(
        &self,
        grace: Duration,
        deadline: Option<Instant>,
        mut child: Option<&mut Child>,
    ) -> io::Result<()> {
        if !self.matches()? || !group_exists(self.group)? {
            return Ok(());
        }
        signal_group(self.group, Signal::SIGTERM)?;
        let started = Instant::now();
        let grace = deadline.map_or(grace, |deadline| {
            grace.min(deadline.saturating_duration_since(started))
        });
        let mut checked_zombie = false;
        while started.elapsed() < grace {
            if !checked_zombie
                && child.is_some()
                && process_identity(self.group)?.is_some_and(|identity| !identity.live)
            {
                checked_zombie = true;
                // Signal zero includes zombies. Check members once before reaping
                // our exited leader; keeping it when descendants live preserves
                // the recorded identity for safe escalation after the grace.
                if !group_has_live_descendants(self.group)? {
                    if let Some(child) = child.as_deref_mut() {
                        let _status = child.try_wait()?;
                    }
                    return Ok(());
                }
            }
            if !group_exists(self.group)? {
                return Ok(());
            }
            thread::sleep(RUNNER_POLL_INTERVAL.min(grace.saturating_sub(started.elapsed())));
        }
        if self.matches()? {
            signal_group(self.group, Signal::SIGKILL)?;
        }
        Ok(())
    }
}

fn signal_group(pid: i32, signal: Signal) -> io::Result<()> {
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

struct ProcessIdentity {
    group: i32,
    start_ticks: u64,
    live: bool,
}

fn process_identity(pid: i32) -> io::Result<Option<ProcessIdentity>> {
    let source = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(source) => source,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(Errno::ESRCH as i32) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let fields: Vec<_> = source
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("runner process identity is malformed"))?
        .1
        .split_whitespace()
        .collect();
    let group = fields
        .get(2)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("runner process group is malformed"))?;
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("runner start time is malformed"))?;
    Ok(Some(ProcessIdentity {
        group,
        start_ticks,
        live: fields
            .first()
            .is_some_and(|state| *state != "Z" && *state != "X"),
    }))
}

fn group_exists(group: i32) -> io::Result<bool> {
    match killpg(Pid::from_raw(group), None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn group_has_live_descendants(group: i32) -> io::Result<bool> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse().ok())
        else {
            continue;
        };
        if pid != group
            && process_identity(pid)?
                .is_some_and(|identity| identity.group == group && identity.live)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl crate::gateway::Gateway {
    pub(crate) fn reconcile_runner_groups(&self) -> Result<(), GatewayError> {
        let root = self.state_dir().join("runner-groups");
        let lanes = match fs::read_dir(&root) {
            Ok(lanes) => lanes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(GatewayError::io("read_runner_groups", source)),
        };
        for entry in lanes {
            let entry =
                entry.map_err(|source| GatewayError::io("read_runner_group_lane", source))?;
            let lane = entry
                .file_name()
                .into_string()
                .map_err(|_name| GatewayError::CorruptState("runner_group_lane"))?;
            let Some(_lock) = self.try_lock_lane(&lane)? else {
                continue;
            };
            let records = fs::read_dir(entry.path())
                .map_err(|source| GatewayError::io("read_runner_group_records", source))?;
            for record in records {
                let path = record
                    .map_err(|source| GatewayError::io("read_runner_group_record", source))?
                    .path();
                if path.extension() != Some(OsStr::new("json")) {
                    continue;
                }
                let seq = path
                    .file_stem()
                    .and_then(OsStr::to_str)
                    .and_then(|stem| stem.parse().ok())
                    .ok_or(GatewayError::CorruptState("runner_group_sequence"))?;
                self.reap_runner_group(&lane, seq)?;
            }
        }
        Ok(())
    }

    pub(crate) fn reap_runner_group(&self, lane: &str, seq: u64) -> Result<(), GatewayError> {
        let path = self
            .state_dir()
            .join("runner-groups")
            .join(lane)
            .join(format!("{seq}.json"));
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(GatewayError::io("read_runner_group", source)),
        };
        let group: RunnerGroup = serde_json::from_str(&source)
            .map_err(|_error| GatewayError::CorruptState("runner_group"))?;
        group
            .terminate(RUNNER_TERMINATION_GRACE, None, None)
            .map_err(|source| GatewayError::io("reap_runner_group", source))?;
        fs::remove_file(path).map_err(|source| GatewayError::io("remove_runner_group", source))
    }
}

fn spawn_reader<R>(mut reader: R, deadline: Option<Instant>) -> JoinHandle<ReaderOutput>
where
    R: Read + AsFd + Send + 'static,
{
    thread::spawn(move || {
        if let Some(deadline) = deadline {
            return read_until_deadline(&mut reader, deadline);
        }
        let mut bytes = Vec::new();
        let error = reader.read_to_end(&mut bytes).err();
        ReaderOutput {
            bytes,
            error: error.map(|error| error.to_string()),
            timed_out: false,
        }
    })
}

fn read_until_deadline(reader: &mut (impl Read + AsFd), deadline: Instant) -> ReaderOutput {
    let mut output = ReaderOutput {
        bytes: Vec::new(),
        error: None,
        timed_out: false,
    };
    if let Err(error) = fcntl(&*reader, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)) {
        output.error = Some(error.to_string());
        return output;
    }
    let mut buffer = [0; 8192];
    loop {
        if Instant::now() >= deadline {
            output.timed_out = true;
            return output;
        }
        match reader.read(&mut buffer) {
            Ok(0) => return output,
            Ok(count) => output.bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(cmp::min(
                    RUNNER_POLL_INTERVAL,
                    deadline.saturating_duration_since(Instant::now()),
                ));
            }
            Err(error) => {
                output.error = Some(error.to_string());
                return output;
            }
        }
    }
}

fn collect_reader(
    reader: Option<JoinHandle<ReaderOutput>>,
    unavailable: &'static str,
) -> ReaderOutput {
    let Some(reader) = reader else {
        return ReaderOutput {
            bytes: Vec::new(),
            error: Some(unavailable.to_owned()),
            timed_out: false,
        };
    };
    reader.join().unwrap_or_else(|_panic| ReaderOutput {
        bytes: Vec::new(),
        error: Some("runner output reader panicked".to_owned()),
        timed_out: false,
    })
}

fn append_message(bytes: &mut Vec<u8>, message: &str) {
    if bytes.last().is_some_and(|byte| *byte != b'\n') {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(message.as_bytes());
    bytes.push(b'\n');
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunnerState {
    Completed,
    OverBudget,
    Failed,
    /// The runner reported the transport's reserved exit code.
    ConnectionLost,
}

struct RunnerOutcome {
    state: RunnerState,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

impl RunnerOutcome {
    fn failed(message: &str) -> Self {
        let mut stderr = Vec::new();
        append_message(&mut stderr, message);
        Self {
            state: RunnerState::Failed,
            exit_code: 1,
            stdout: String::new(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }
    }
}

struct WaitOutcome {
    state: RunnerState,
    exit_code: i32,
    error: Option<io::Error>,
}

struct ReaderOutput {
    bytes: Vec<u8>,
    error: Option<String>,
    timed_out: bool,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;

    use super::{
        CARGO_TARGET_DIR_ENVIRONMENT, MIRROR_REMOTE_ENVIRONMENT, configure_runner_mirror,
        configure_runner_target_dir, runner_target_dir,
    };

    /// A configured cache root hashes the canonical checkout path with the
    /// same prefix and digest width as the runner contract.
    ///
    /// ´test:unit:target-root-hashes-the-canonical-checkout-path´
    #[test]
    fn target_root_hashes_the_canonical_checkout_path() {
        assert_eq!(
            runner_target_dir(Path::new("/"), Some(OsStr::new("/cache"))),
            Path::new("/cache/lane-gateway-8a5edab282632443")
        );
    }

    /// Without a configured cache root, runner artifacts stay inside the
    /// checkout so removing it also removes the cache.
    ///
    /// ´test:unit:absent-target-root-uses-the-checkout-target-directory´
    #[test]
    fn absent_target_root_uses_the_checkout_target_directory() {
        assert_eq!(
            runner_target_dir(Path::new("/mirror/checkout"), None),
            Path::new("/mirror/checkout/target")
        );
    }

    /// An unavailable checkout path is hashed as supplied instead of turning
    /// target-directory selection into a runner failure.
    ///
    /// ´test:unit:target-root-hashing-falls-back-when-checkout-canonicalization-fails´
    #[test]
    fn target_root_hashing_falls_back_when_checkout_canonicalization_fails() {
        let checkout = Path::new("lane-gateway-canonicalization-fallback");
        assert!(!checkout.exists());
        assert_eq!(
            runner_target_dir(checkout, Some(OsStr::new("/cache"))),
            Path::new("/cache/lane-gateway-17c4b8a2770cf109")
        );
    }

    /// The gateway-authored target directory replaces a value already set on
    /// the command rather than allowing a shared inherited cache to survive.
    ///
    /// ´test:unit:runner-target-dir-overrides-an-existing-command-environment-value´
    #[test]
    fn runner_target_dir_overrides_an_existing_command_environment_value() {
        let mut command = Command::new("/bin/true");
        command.env(CARGO_TARGET_DIR_ENVIRONMENT, "/shared/target");
        configure_runner_target_dir(&mut command, Path::new("/mirror/checkout/target"));

        let configured = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(CARGO_TARGET_DIR_ENVIRONMENT))
            .and_then(|(_, value)| value);
        assert_eq!(configured, Some(OsStr::new("/mirror/checkout/target")));
    }

    /// A runner sees the registration's mirror remote beside the mirror commit,
    /// so a runner deriving its host per lane can read the placement the lane
    /// was registered with instead of one alias fixed for the whole serve.
    ///
    /// ´test:unit:runner-receives-the-lane-mirror-remote-beside-the-commit´
    #[test]
    fn runner_receives_the_lane_mirror_remote_beside_the_commit() {
        let commit = "c".repeat(40);
        let remote = "lane-compute:/srv/lanes/lane-031.git";
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            r#"printf 'commit=%s\nremote=%s\n' "$LANE_GATEWAY_MIRROR_COMMIT" "$LANE_GATEWAY_MIRROR_REMOTE""#,
        ]);
        configure_runner_mirror(&mut command, &commit, remote);

        let output = command
            .output()
            .expect("shell runner reports its mirror environment");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("commit={commit}\nremote={remote}\n")
        );
    }

    /// A remote specification carrying spaces and a colon reaches the runner
    /// byte for byte, because only the runner and Git interpret it.
    ///
    /// ´test:unit:runner-mirror-remote-with-spaces-and-a-colon-arrives-unaltered´
    #[test]
    fn runner_mirror_remote_with_spaces_and_a_colon_arrives_unaltered() {
        let remote = "ssh://lane compute:2222/srv/lane mirrors/lane 031.git";
        let mut command = Command::new("/bin/sh");
        command.args(["-c", r#"printf '%s' "$LANE_GATEWAY_MIRROR_REMOTE""#]);
        configure_runner_mirror(&mut command, &"d".repeat(40), remote);

        let output = command
            .output()
            .expect("shell runner reports its mirror remote");
        assert_eq!(String::from_utf8_lossy(&output.stdout), remote);
    }

    /// A blank remote configures no variable at all, so a runner keeps whatever
    /// placement defaults it was launched with rather than reading an empty
    /// override that names no host.
    ///
    /// ´test:unit:blank-mirror-remote-is-omitted-rather-than-exported-empty´
    #[test]
    fn blank_mirror_remote_is_omitted_rather_than_exported_empty() {
        let mut command = Command::new("/bin/true");
        configure_runner_mirror(&mut command, &"e".repeat(40), "   ");

        assert!(
            command
                .get_envs()
                .all(|(name, _)| name != OsStr::new(MIRROR_REMOTE_ENVIRONMENT))
        );
    }

    /// Kernel group existence includes a zombie until its parent reaps it.
    ///
    /// ´test:unit:runner-group-kernel-probe-bounds-zombie-grace´
    #[test]
    fn runner_group_kernel_probe_bounds_zombie_grace() {
        use std::os::unix::process::CommandExt as _;
        use std::time::{Duration, Instant};

        use nix::sys::wait::{Id, WaitPidFlag, waitid};
        use nix::unistd::Pid;

        let mut child = Command::new("/bin/true")
            .process_group(0)
            .spawn()
            .expect("group leader starts");
        let pid = i32::try_from(child.id()).expect("child PID fits");
        waitid(
            Id::Pid(Pid::from_raw(pid)),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
        )
        .expect("leader becomes a zombie without being reaped");
        let group = super::RunnerGroup::capture(child.id()).expect("zombie identity is available");
        let zombie_present = super::group_exists(pid).expect("kernel probe succeeds");
        let started = Instant::now();
        group
            .terminate(Duration::from_millis(20), None, Some(&mut child))
            .expect("zombie cleanup is bounded");
        let elapsed = started.elapsed();
        child.wait().expect("direct child is reaped");
        let reaped_present = super::group_exists(pid).expect("reaped group probe succeeds");
        assert!(zombie_present, "kernel retains an unreaped group leader");
        assert!(!reaped_present, "reaped group is absent");
        assert!(
            elapsed < Duration::from_secs(1),
            "zombies cannot extend the bounded grace"
        );
    }

    /// A leader exiting on TERM must not prevent escalation to a resistant descendant.
    ///
    /// ´test:unit:runner-group-keeps-leader-until-descendants-stop´
    #[test]
    fn runner_group_keeps_leader_until_descendants_stop() {
        use std::io::{BufRead as _, BufReader};
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;
        use std::time::Duration;

        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "/bin/sh -c 'trap \"\" TERM; echo \"$$\"; exec sleep 30' & wait",
            ])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .expect("runner group starts");
        let group = super::RunnerGroup::capture(child.id()).expect("leader identity is available");
        let mut source = String::new();
        BufReader::new(child.stdout.take().expect("runner output is piped"))
            .read_line(&mut source)
            .expect("resistant descendant is ready");
        let descendant: i32 = source.trim().parse().expect("descendant PID is numeric");
        let terminated = group.terminate(Duration::from_millis(50), None, Some(&mut child));
        child.wait().expect("leader is reaped");
        std::thread::sleep(Duration::from_millis(50));
        let alive = std::fs::read_to_string(format!("/proc/{descendant}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(") ")
                .is_some_and(|(_, fields)| !fields.starts_with("Z "))
        });
        let _cleanup = kill(Pid::from_raw(descendant), Signal::SIGKILL);
        terminated.expect("group termination succeeds");
        assert!(
            !alive,
            "resistant descendant survived after its leader exited"
        );
    }
}
