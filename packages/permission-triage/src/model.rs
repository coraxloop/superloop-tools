#![deny(clippy::indexing_slicing)]

//! Deadline-bounded one-shot classifier process.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{self, Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::journal::establish_root;
use crate::proc;
use crate::rubric::{Prompt, SYSTEM_INSTRUCTION};

/// Default nested classifier model.
pub const DEFAULT_MODEL: &str = "claude-opus-5";

/// Default and maximum classifier deadline.
pub const MAX_MODEL_DEADLINE_MS: u64 = 55_000;

/// Maximum accepted standard output from the classifier CLI.
pub const MAX_STDOUT_BYTES: usize = 64 * 1024;

/// Embedded schema passed verbatim to the classifier CLI.
pub const CLASSIFICATION_SCHEMA: &str = include_str!("../schema/classification.json");

const DEFAULT_CLI: &str = "claude";
const SETTINGS_OVERRIDE: &str = r#"{"disableAllHooks":true}"#;
/// Harness 2.1.258 accepts an empty settings-source list, preserves stored OAuth without bare
/// isolation, and accepts strict MCP configuration and disabled slash commands together.
/// Both an empty source list and `disableAllHooks` suppress hooks that otherwise fire.
const SETTINGS_ISOLATION_VERIFIED: bool = true;
const STATE_ROOT_VARIABLE: &str = "PERMISSION_TRIAGE_STATE_ROOT";
const CLASSIFIER_CWD_NAME: &str = "classifier-cwd";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const NESTING_GUARD: &str = "PERMISSION_TRIAGE_NESTED";
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const TERMINATION_GRACE: Duration = Duration::from_millis(20);
const CLEANUP_GRACE: Duration = Duration::from_millis(100);
// The standard library can create a process group but cannot signal one. Absolute helpers avoid
// PATH lookup; the runner is limited to Unix hosts providing one of these standard locations.
const KILL_PROGRAMS: [&str; 2] = ["/bin/kill", "/usr/bin/kill"];

pub use execute_command::triage::{Classification, ModelResult};

/// Nested-process or structured-output failure.
#[derive(Debug)]
pub enum ModelError {
    /// A nested hook attempted to launch another classifier.
    NestedInvocation,
    /// The classifier child's nesting proof could not be minted from this process's identity.
    NestingTokenMint,
    /// `PERMISSION_TRIAGE_ISOLATION` did not name a supported mode.
    InvalidIsolation(String),
    /// `PERMISSION_TRIAGE_MODEL_DEADLINE_MS` was not a positive integer.
    InvalidDeadline(String),
    /// The classifier state root or its private working directory could not be established.
    StateRoot(io::Error),
    /// The classifier process could not be launched.
    Launch(io::Error),
    /// The complete prompt could not be sent on standard input.
    PromptWrite(io::Error),
    /// The standard-input writer thread failed internally.
    StdinWriterPanicked,
    /// The child status could not be sampled.
    Wait(io::Error),
    /// A live child could not be killed after a deadline or output violation.
    Kill(io::Error),
    /// A killed child could not be reaped.
    Reap(io::Error),
    /// Process and I/O cleanup did not finish within the shared cleanup deadline.
    CleanupTimeout,
    /// Capturing bounded standard output failed.
    StdoutRead(io::Error),
    /// The standard-output reader thread failed internally.
    StdoutReaderPanicked,
    /// The CLI exited unsuccessfully.
    NonzeroExit(Option<i32>),
    /// The maximum model deadline elapsed.
    Timeout(u64),
    /// Standard output exceeded the 64 KiB cap.
    StdoutTooLarge(usize),
    /// The top-level CLI JSON envelope was malformed or had trailing data.
    MalformedEnvelope(serde_json::Error),
    /// The top-level CLI JSON did not have exactly one supported payload field.
    EnvelopeShape,
    /// The JSON string held by `result` was malformed or had trailing data.
    MalformedResult(serde_json::Error),
    /// The structured classification object did not match the pinned schema.
    SchemaMismatch(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NestedInvocation => write!(formatter, "nested model invocation is refused"),
            Self::NestingTokenMint => write!(
                formatter,
                "nesting-token mint failed: this process's stat is unreadable or has no start time"
            ),
            Self::InvalidIsolation(value) => {
                write!(formatter, "model isolation is invalid: {value}")
            }
            Self::InvalidDeadline(value) => {
                write!(formatter, "model deadline is invalid: {value}")
            }
            Self::StateRoot(error) => write!(formatter, "classifier state root failed: {error}"),
            Self::Launch(error) => write!(formatter, "model launch failed: {error}"),
            Self::PromptWrite(error) => write!(formatter, "model stdin write failed: {error}"),
            Self::StdinWriterPanicked => write!(formatter, "model stdin writer panicked"),
            Self::Wait(error) => write!(formatter, "model status wait failed: {error}"),
            Self::Kill(error) => {
                write!(formatter, "model process-group termination failed: {error}")
            }
            Self::Reap(error) => write!(formatter, "model child reap failed: {error}"),
            Self::CleanupTimeout => write!(formatter, "model cleanup exceeded its deadline"),
            Self::StdoutRead(error) => write!(formatter, "model stdout capture failed: {error}"),
            Self::StdoutReaderPanicked => write!(formatter, "model stdout reader panicked"),
            Self::NonzeroExit(code) => write!(formatter, "model exited nonzero with code {code:?}"),
            Self::Timeout(deadline) => {
                write!(formatter, "model timed out after {deadline} milliseconds")
            }
            Self::StdoutTooLarge(limit) => {
                write!(formatter, "model stdout exceeded the {limit}-byte cap")
            }
            Self::MalformedEnvelope(error) => {
                write!(formatter, "model JSON envelope is malformed: {error}")
            }
            Self::EnvelopeShape => write!(formatter, "model JSON envelope shape is unsupported"),
            Self::MalformedResult(error) => {
                write!(formatter, "model result string is malformed JSON: {error}")
            }
            Self::SchemaMismatch(detail) => {
                write!(
                    formatter,
                    "model structured output violates schema: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for ModelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Launch(error)
            | Self::StateRoot(error)
            | Self::PromptWrite(error)
            | Self::Wait(error)
            | Self::Kill(error)
            | Self::Reap(error)
            | Self::StdoutRead(error) => Some(error),
            Self::MalformedEnvelope(error) | Self::MalformedResult(error) => Some(error),
            Self::NestedInvocation
            | Self::NestingTokenMint
            | Self::InvalidIsolation(_)
            | Self::InvalidDeadline(_)
            | Self::StdinWriterPanicked
            | Self::StdoutReaderPanicked
            | Self::CleanupTimeout
            | Self::NonzeroExit(_)
            | Self::Timeout(_)
            | Self::StdoutTooLarge(_)
            | Self::EnvelopeShape
            | Self::SchemaMismatch(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Isolation {
    Bare,
    Settings,
}

#[derive(Debug)]
struct ModelRunner {
    cli: OsString,
    model: OsString,
    isolation: Isolation,
    state_root: Option<PathBuf>,
    state_root_handle: Option<File>,
    deadline: Duration,
    #[cfg(test)]
    fixture_environment: Vec<(OsString, OsString)>,
    #[cfg(test)]
    fixture_kill_program: Option<OsString>,
    #[cfg(test)]
    fixture_self_stat: Option<Vec<u8>>,
    #[cfg(test)]
    fixture_clock: Option<Arc<PollClock>>,
    #[cfg(test)]
    fixture_reap_before_cleanup: bool,
}

/// Test seam that makes the child's exit and the deadline coincide in one poll iteration.
///
/// Before the first completion poll, observe the child exiting and both helpers finishing,
/// then arm an expired clock. A completion check before a deadline check must return the
/// child's result without querying that clock, regardless of when the child was scheduled.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct PollClock {
    settle: Duration,
    staged: AtomicBool,
    reported_expiry: AtomicBool,
}

#[cfg(test)]
impl PollClock {
    pub(crate) fn new(settle: Duration) -> Self {
        Self {
            settle,
            staged: AtomicBool::new(false),
            reported_expiry: AtomicBool::new(false),
        }
    }

    fn observe(&self) -> Duration {
        self.reported_expiry.store(true, Ordering::Release);
        Duration::MAX
    }

    /// Whether the runner was ever told its deadline had elapsed.
    pub(crate) fn reported_expiry(&self) -> bool {
        self.reported_expiry.load(Ordering::Acquire)
    }

    pub(crate) fn staged(&self) -> bool {
        self.staged.load(Ordering::Acquire)
    }
}

impl ModelRunner {
    fn from_environment() -> Result<Self, ModelError> {
        Self::from_environment_source(|name| env::var_os(name))
    }

    fn from_environment_source(
        mut value: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<Self, ModelError> {
        if value(NESTING_GUARD).is_some_and(|guard| guard == "1") {
            return Err(ModelError::NestedInvocation);
        }
        let cli = value("PERMISSION_TRIAGE_CLI").unwrap_or_else(|| OsString::from(DEFAULT_CLI));
        let model =
            value("PERMISSION_TRIAGE_MODEL").unwrap_or_else(|| OsString::from(DEFAULT_MODEL));
        let state_root = value(STATE_ROOT_VARIABLE).map(PathBuf::from);
        let isolation = match value("PERMISSION_TRIAGE_ISOLATION") {
            None => Isolation::Settings,
            Some(mode) if mode == "bare" => Isolation::Bare,
            Some(mode) if mode == "settings" && SETTINGS_ISOLATION_VERIFIED => Isolation::Settings,
            Some(mode) => {
                return Err(ModelError::InvalidIsolation(
                    mode.to_string_lossy().into_owned(),
                ));
            }
        };
        let deadline_ms = configured_deadline(value("PERMISSION_TRIAGE_MODEL_DEADLINE_MS"))?;
        Ok(Self {
            cli,
            model,
            isolation,
            state_root,
            state_root_handle: None,
            deadline: Duration::from_millis(deadline_ms),
            #[cfg(test)]
            fixture_environment: Vec::new(),
            #[cfg(test)]
            fixture_kill_program: None,
            #[cfg(test)]
            fixture_self_stat: None,
            #[cfg(test)]
            fixture_clock: None,
            #[cfg(test)]
            fixture_reap_before_cleanup: false,
        })
    }

    fn arguments(&self) -> Vec<OsString> {
        let mut arguments = vec![OsString::from("--print")];
        match self.isolation {
            Isolation::Bare => arguments.push(OsString::from("--bare")),
            Isolation::Settings => arguments.extend([
                OsString::from("--setting-sources"),
                OsString::new(),
                OsString::from("--settings"),
                OsString::from(SETTINGS_OVERRIDE),
                OsString::from("--strict-mcp-config"),
                OsString::from("--disable-slash-commands"),
            ]),
        }
        arguments.extend([
            OsString::from("--model"),
            self.model.clone(),
            OsString::from("--output-format"),
            OsString::from("json"),
            OsString::from("--json-schema"),
            OsString::from(CLASSIFICATION_SCHEMA),
            OsString::from("--tools"),
            OsString::new(),
            OsString::from("--system-prompt"),
            OsString::from(SYSTEM_INSTRUCTION),
            OsString::from("--no-session-persistence"),
        ]);
        arguments
    }

    fn run(&self, prompt: &Prompt) -> Result<ModelResult, ModelError> {
        let total = self.deadline.saturating_add(CLEANUP_GRACE);
        let cleanup_limit = execute_command::triage::budget(total, total, CLEANUP_GRACE)
            .ok_or_else(|| ModelError::InvalidDeadline("0".to_owned()))?;
        let classifier_cwd = self.classifier_cwd()?;
        let started = Instant::now();
        let framed_prompt = framed_prompt_bytes(prompt).map_err(ModelError::PromptWrite)?;
        let mut command = self.command(&classifier_cwd)?;
        let mut child = command.spawn().map_err(ModelError::Launch)?;
        let kill_program = configured_kill_program(self);
        let Some(stdin) = child.stdin.take() else {
            let _terminated =
                terminate_process_group(&mut child, false, kill_program, started, cleanup_limit);
            return Err(ModelError::PromptWrite(io::Error::other(
                "model stdin pipe is unavailable",
            )));
        };
        let Some(stdout) = child.stdout.take() else {
            let _terminated =
                terminate_process_group(&mut child, false, kill_program, started, cleanup_limit);
            return Err(ModelError::StdoutRead(io::Error::other(
                "model stdout pipe is unavailable",
            )));
        };
        let exceeded = Arc::new(AtomicBool::new(false));
        let reader = spawn_stdout_reader(stdout, Arc::clone(&exceeded));
        let writer = spawn_stdin_writer(stdin, framed_prompt);

        #[cfg(test)]
        if let Some(clock) = &self.fixture_clock {
            // The settle window opens once the child and helpers exist; the run deadline keeps its origin at started.
            let staging_started = Instant::now();
            reap_child(&mut child, staging_started, clock.settle)?;
            wait_for_helper(&reader, staging_started, clock.settle)?;
            wait_for_helper(&writer, staging_started, clock.settle)?;
            clock.staged.store(true, Ordering::Release);
        }

        let mut exit_status = None;
        let completion = loop {
            if exit_status.is_none() {
                match child.try_wait() {
                    Ok(status) => exit_status = status,
                    Err(error) => break Completion::WaitFailure(error),
                }
            }
            if writer.is_finished()
                && reader.is_finished()
                && let Some(status) = exit_status
            {
                break Completion::Natural(status);
            }
            if exceeded.load(Ordering::Acquire) {
                break Completion::StdoutTooLarge;
            }
            if let Some(deadline) = self.elapsed_deadline(started) {
                break Completion::Timeout(deadline);
            }
            thread::sleep(self.poll_pause(started));
        };

        // Drive the finite producer's exit between observing its ceiling and cleanup.
        // The seam waits on completion, not elapsed time, and never changes a deadline.
        #[cfg(test)]
        let completion = if self.fixture_reap_before_cleanup {
            reap_child(&mut child, started, cleanup_limit)?;
            exit_status = child.try_wait().map_err(ModelError::Wait)?;
            wait_for_helper(&reader, started, cleanup_limit)?;
            if exceeded.load(Ordering::Acquire) {
                Completion::StdoutTooLarge
            } else {
                completion
            }
        } else {
            completion
        };

        let termination = if matches!(&completion, Completion::Natural(_)) {
            Ok(())
        } else {
            terminate_process_group(
                &mut child,
                exit_status.is_some(),
                kill_program,
                started,
                cleanup_limit,
            )
        };
        let writer_result = join_stdin(writer, started, cleanup_limit);
        let captured_result = join_stdout(reader, started, cleanup_limit);
        finish_model_result(completion, termination, writer_result, captured_result)
    }

    /// Configured deadline in milliseconds, once the completion poll sees it as elapsed.
    fn elapsed_deadline(&self, started: Instant) -> Option<u64> {
        (observed_elapsed(self, started) >= self.deadline)
            .then(|| u64::try_from(self.deadline.as_millis()).unwrap_or(u64::MAX))
    }

    /// Pause before the next completion poll, never overrunning the deadline.
    fn poll_pause(&self, started: Instant) -> Duration {
        POLL_INTERVAL.min(
            self.deadline
                .saturating_sub(observed_elapsed(self, started)),
        )
    }

    fn command(&self, classifier_cwd: &Path) -> Result<Command, ModelError> {
        let mut command = Command::new(&self.cli);
        let nesting_guard = self.nesting_guard_token()?;
        // Stable `std` can create this process group without `unsafe`, but cannot create a new
        // session. A daemon can therefore escape with `setsid`; an inherited pipe keeps cleanup
        // open so that escape is reported as `ModelError::CleanupTimeout` instead of being hidden.
        command
            .args(self.arguments())
            .env(NESTING_GUARD, nesting_guard)
            .current_dir(classifier_cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        #[cfg(test)]
        {
            for (name, value) in &self.fixture_environment {
                command.env(name, value);
            }
        }
        Ok(command)
    }

    fn classifier_cwd(&self) -> Result<PathBuf, ModelError> {
        let state_root = self.state_root.as_deref().ok_or_else(|| {
            ModelError::StateRoot(io::Error::new(
                io::ErrorKind::NotFound,
                "permission triage state root is unset",
            ))
        })?;
        let owner = if let Some(directory) = &self.state_root_handle {
            directory
                .metadata()
                .map(|metadata| metadata.uid())
                .map_err(ModelError::StateRoot)?
        } else {
            establish_root(state_root, None)
                .map_err(|error| ModelError::StateRoot(io::Error::other(error)))?;
            state_root
                .symlink_metadata()
                .map(|metadata| metadata.uid())
                .map_err(ModelError::StateRoot)?
        };
        let classifier_cwd = state_root.join(CLASSIFIER_CWD_NAME);
        establish_classifier_cwd(&classifier_cwd, owner).map_err(ModelError::StateRoot)?;
        Ok(classifier_cwd)
    }

    /// Mint the classifier child's nesting proof from this process's own identity.
    fn nesting_guard_token(&self) -> Result<String, ModelError> {
        let stat = self_stat(self).map_err(|_unreadable| ModelError::NestingTokenMint)?;
        mint_nesting_token(&stat, process::id()).ok_or(ModelError::NestingTokenMint)
    }

    #[cfg(test)]
    fn fixture(
        cli: &std::ffi::OsStr,
        deadline: Duration,
        mut environment: Vec<(OsString, OsString)>,
        kill_program: Option<OsString>,
        self_stat: Option<Vec<u8>>,
        clock: Option<Arc<PollClock>>,
    ) -> Self {
        let state_root = environment
            .iter()
            .find_map(|(name, value)| (name == STATE_ROOT_VARIABLE).then(|| PathBuf::from(value)));
        environment.push((OsString::from(NESTING_GUARD), OsString::from("1")));
        Self {
            cli: cli.to_os_string(),
            model: OsString::from(DEFAULT_MODEL),
            isolation: Isolation::Bare,
            state_root,
            state_root_handle: None,
            deadline,
            fixture_environment: environment,
            fixture_kill_program: kill_program,
            fixture_self_stat: self_stat,
            fixture_clock: clock,
            fixture_reap_before_cleanup: false,
        }
    }
}

fn establish_classifier_cwd(path: &Path, owner: u32) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) => verify_classifier_cwd(path, &metadata, owner),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = path.symlink_metadata()?;
                    return verify_classifier_cwd(path, &metadata, owner);
                }
                Err(error) => return Err(error),
            }
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
            let metadata = path.symlink_metadata()?;
            verify_classifier_cwd(path, &metadata, owner)
        }
        Err(error) => Err(error),
    }
}

fn verify_classifier_cwd(path: &Path, metadata: &fs::Metadata, owner: u32) -> io::Result<()> {
    if !metadata.is_dir() {
        return Err(io::Error::other(
            "classifier working directory is not a directory",
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != PRIVATE_DIRECTORY_MODE {
        return Err(io::Error::other(format!(
            "classifier working directory mode is {mode:o}, expected {PRIVATE_DIRECTORY_MODE:o}"
        )));
    }
    if metadata.uid() != owner {
        return Err(io::Error::other(
            "classifier working directory is not owned by the current user",
        ));
    }
    if path.read_dir()?.next().transpose()?.is_some() {
        return Err(io::Error::other(
            "classifier working directory is not empty",
        ));
    }
    Ok(())
}

/// Format one `PID:STARTTIME` proof from a supplied `stat` buffer and process identifier.
fn mint_nesting_token(stat: &[u8], pid: u32) -> Option<String> {
    Some(format!("{pid}:{}", proc::start_time(stat)?))
}

#[cfg(test)]
pub(crate) fn mint_nesting_token_for_test(stat: &[u8], pid: u32) -> Option<String> {
    mint_nesting_token(stat, pid)
}

/// Elapsed time as the completion poll sees it.
#[cfg(test)]
fn observed_elapsed(runner: &ModelRunner, started: Instant) -> Duration {
    let actual = started.elapsed();
    runner
        .fixture_clock
        .as_ref()
        .map_or(actual, |clock| clock.observe())
}

#[cfg(not(test))]
fn observed_elapsed(_runner: &ModelRunner, started: Instant) -> Duration {
    started.elapsed()
}

#[cfg(test)]
fn self_stat(runner: &ModelRunner) -> io::Result<Vec<u8>> {
    runner
        .fixture_self_stat
        .clone()
        .map_or_else(|| fs::read("/proc/self/stat"), Ok)
}

#[cfg(not(test))]
fn self_stat(_runner: &ModelRunner) -> io::Result<Vec<u8>> {
    fs::read("/proc/self/stat")
}

#[cfg(test)]
fn configured_kill_program(runner: &ModelRunner) -> Option<&OsStr> {
    runner.fixture_kill_program.as_deref()
}

#[cfg(not(test))]
const fn configured_kill_program(_runner: &ModelRunner) -> Option<&OsStr> {
    None
}

fn framed_prompt_bytes(prompt: &Prompt) -> io::Result<Vec<u8>> {
    const HEADER: &str = "=== REPLACEMENT SYSTEM INSTRUCTION ===\n";
    const GENERAL_MARKER: &str = "----- BEGIN UNTRUSTED GENERAL RUBRIC NONCE=";
    let remainder = prompt
        .as_str()
        .strip_prefix(HEADER)
        .and_then(|value| value.strip_prefix(SYSTEM_INSTRUCTION))
        .and_then(|value| value.strip_prefix('\n'))
        .ok_or_else(|| io::Error::other("model prompt system instruction is malformed"))?;
    let nonce = remainder
        .strip_prefix(GENERAL_MARKER)
        .and_then(|value| value.split_once(" BYTES=").map(|(nonce, _)| nonce))
        .filter(|nonce| !nonce.is_empty() && !nonce.chars().any(char::is_whitespace))
        .ok_or_else(|| io::Error::other("model prompt nonce is malformed"))?;
    let mut framed = String::with_capacity(prompt.as_str().len() + 192);
    framed.push_str("=== BEGIN REPLACEMENT SYSTEM INSTRUCTION NONCE=");
    framed.push_str(nonce);
    framed.push_str(" BYTES=");
    framed.push_str(&SYSTEM_INSTRUCTION.len().to_string());
    framed.push_str(" ===\n");
    framed.push_str(SYSTEM_INSTRUCTION);
    framed.push_str("=== END REPLACEMENT SYSTEM INSTRUCTION NONCE=");
    framed.push_str(nonce);
    framed.push_str(" ===\n");
    framed.push_str(remainder);
    Ok(framed.into_bytes())
}

fn configured_deadline(value: Option<OsString>) -> Result<u64, ModelError> {
    let Some(value) = value else {
        return Ok(MAX_MODEL_DEADLINE_MS);
    };
    let text = value
        .to_str()
        .ok_or_else(|| ModelError::InvalidDeadline(value.to_string_lossy().into_owned()))?;
    let parsed = text
        .parse::<u64>()
        .ok()
        .filter(|deadline| *deadline > 0)
        .ok_or_else(|| ModelError::InvalidDeadline(text.to_owned()))?;
    Ok(parsed.min(MAX_MODEL_DEADLINE_MS))
}

/// Run one nested classification with configuration loaded from the environment.
///
/// # Errors
///
/// Returns a distinct [`ModelError`] for configuration, process, deadline, capture, envelope, or
/// schema failure.
pub fn run_model(prompt: &Prompt) -> Result<ModelResult, ModelError> {
    run_model_at_root(prompt, None)
}

/// Use the caller root selected by the hook's registry snapshot; `None` retains the estate default.
pub(crate) fn run_model_at_root(
    prompt: &Prompt,
    state_root: Option<File>,
) -> Result<ModelResult, ModelError> {
    let mut runner = ModelRunner::from_environment()?;
    if let Some(directory) = state_root {
        runner.state_root = Some(
            PathBuf::from("/proc/self/fd")
                .join(directory.as_raw_fd().to_string())
                .join("."),
        );
        runner.state_root_handle = Some(directory);
    }
    runner.run(prompt)
}

enum Completion {
    Natural(ExitStatus),
    Timeout(u64),
    StdoutTooLarge,
    WaitFailure(io::Error),
}

fn spawn_stdin_writer(mut stdin: ChildStdin, prompt: Vec<u8>) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || stdin.write_all(&prompt))
}

fn finish_model_result(
    completion: Completion,
    termination: Result<(), ModelError>,
    writer_result: Result<(), ModelError>,
    captured_result: Result<CapturedStdout, ModelError>,
) -> Result<ModelResult, ModelError> {
    if matches!(&completion, Completion::StdoutTooLarge)
        || captured_result
            .as_ref()
            .is_ok_and(|captured| captured.exceeded)
    {
        // An already-exited group is successful cleanup. Genuine signalling or
        // helper failures remain errors; neither may be inferred from timing.
        termination?;
        ignore_closed_stdin(writer_result)?;
        captured_result?;
        return Err(ModelError::StdoutTooLarge(MAX_STDOUT_BYTES));
    }
    termination?;
    if matches!(&writer_result, Err(ModelError::CleanupTimeout))
        || matches!(&captured_result, Err(ModelError::CleanupTimeout))
    {
        return Err(ModelError::CleanupTimeout);
    }

    match completion {
        Completion::Natural(status) => {
            writer_result?;
            let captured = captured_result?;
            if captured.exceeded {
                return Err(ModelError::StdoutTooLarge(MAX_STDOUT_BYTES));
            }
            validate_exit(status)?;
            parse_envelope(&captured.bytes)
        }
        Completion::Timeout(deadline) => {
            ignore_closed_stdin(writer_result)?;
            captured_result?;
            Err(ModelError::Timeout(deadline))
        }
        Completion::StdoutTooLarge => {
            ignore_closed_stdin(writer_result)?;
            captured_result?;
            Err(ModelError::StdoutTooLarge(MAX_STDOUT_BYTES))
        }
        Completion::WaitFailure(error) => {
            ignore_closed_stdin(writer_result)?;
            captured_result?;
            Err(ModelError::Wait(error))
        }
    }
}

fn join_stdin(
    writer: JoinHandle<io::Result<()>>,
    started: Instant,
    cleanup_limit: Duration,
) -> Result<(), ModelError> {
    wait_for_helper(&writer, started, cleanup_limit)?;
    writer
        .join()
        .map_err(|_panic| ModelError::StdinWriterPanicked)?
        .map_err(ModelError::PromptWrite)
}

fn ignore_closed_stdin(result: Result<(), ModelError>) -> Result<(), ModelError> {
    match result {
        Ok(()) | Err(ModelError::PromptWrite(_)) => Ok(()),
        Err(error) => Err(error),
    }
}

struct CapturedStdout {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn spawn_stdout_reader(
    stdout: ChildStdout,
    exceeded: Arc<AtomicBool>,
) -> JoinHandle<io::Result<CapturedStdout>> {
    thread::spawn(move || capture_stdout(stdout, &exceeded))
}

fn capture_stdout(mut stdout: ChildStdout, exceeded: &AtomicBool) -> io::Result<CapturedStdout> {
    let mut bytes = Vec::with_capacity(MAX_STDOUT_BYTES + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stdout.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let retained = (MAX_STDOUT_BYTES + 1).saturating_sub(bytes.len());
        if let Some(chunk) = buffer.get(..count.min(retained)) {
            bytes.extend_from_slice(chunk);
        }
        if bytes.len() > MAX_STDOUT_BYTES {
            exceeded.store(true, Ordering::Release);
        }
    }
    Ok(CapturedStdout {
        exceeded: bytes.len() > MAX_STDOUT_BYTES,
        bytes,
    })
}

fn join_stdout(
    reader: JoinHandle<io::Result<CapturedStdout>>,
    started: Instant,
    cleanup_limit: Duration,
) -> Result<CapturedStdout, ModelError> {
    wait_for_helper(&reader, started, cleanup_limit)?;
    reader
        .join()
        .map_err(|_panic| ModelError::StdoutReaderPanicked)?
        .map_err(ModelError::StdoutRead)
}

fn wait_for_helper<T>(
    helper: &JoinHandle<T>,
    started: Instant,
    cleanup_limit: Duration,
) -> Result<(), ModelError> {
    while !helper.is_finished() {
        let remaining = cleanup_limit.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ModelError::CleanupTimeout);
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
    Ok(())
}

fn terminate_process_group(
    child: &mut Child,
    already_reaped: bool,
    kill_program: Option<&OsStr>,
    started: Instant,
    cleanup_limit: Duration,
) -> Result<(), ModelError> {
    let process_group = format!("-{}", child.id());
    let graceful = signal_process_group(kill_program, &process_group, false);
    let mut reaped = already_reaped;
    let grace_started = Instant::now();
    while !reaped
        && graceful.is_ok()
        && grace_started.elapsed() < TERMINATION_GRACE
        && started.elapsed() < cleanup_limit
    {
        match child.try_wait() {
            Ok(Some(_status)) => reaped = true,
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                let _hard = signal_process_group(kill_program, &process_group, true);
                let _direct_kill = child.kill();
                reap_child(child, started, cleanup_limit)?;
                return Err(ModelError::Wait(error));
            }
        }
    }

    let hard = if reaped && graceful.is_ok() {
        Ok(GroupSignal::Delivered)
    } else {
        signal_process_group(kill_program, &process_group, true)
    };
    let reap = if reaped {
        Ok(())
    } else if hard.is_err() && child.kill().is_ok() {
        // A successful direct SIGKILL makes this child waitable. Retain ownership
        // until wait reaps it even if scheduling has consumed the cleanup budget.
        // Dropping Child after a timed try_wait would leave an unowned zombie.
        child.wait().map(|_status| ()).map_err(ModelError::Reap)
    } else {
        reap_child(child, started, cleanup_limit)
    };
    reap?;
    match (graceful, hard) {
        (Ok(_), _) | (_, Ok(_)) => Ok(()),
        (Err(_first), Err(last)) => Err(ModelError::Kill(last)),
    }
}

#[cfg(test)]
pub(crate) fn terminate_fixture_after_cleanup_deadline(
    child: &mut Child,
    kill_program: &OsStr,
) -> Result<(), ModelError> {
    terminate_process_group(
        child,
        false,
        Some(kill_program),
        Instant::now(),
        Duration::ZERO,
    )
}

fn reap_child(
    child: &mut Child,
    started: Instant,
    cleanup_limit: Duration,
) -> Result<(), ModelError> {
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) => {
                let remaining = cleanup_limit.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(ModelError::CleanupTimeout);
                }
                thread::sleep(POLL_INTERVAL.min(remaining));
            }
            Err(error) => return Err(ModelError::Reap(error)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GroupSignal {
    Delivered,
    AlreadyExited,
}

fn signal_process_group(
    program: Option<&OsStr>,
    process_group: &str,
    hard: bool,
) -> io::Result<GroupSignal> {
    if let Some(program) = program {
        return signal_process_group_with(program, process_group, hard);
    }
    let mut missing = io::Error::new(
        io::ErrorKind::NotFound,
        "neither fixed process-group signal program exists",
    );
    for program in KILL_PROGRAMS {
        match signal_process_group_with(OsStr::new(program), process_group, hard) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing = error,
            result => return result,
        }
    }
    Err(missing)
}

fn signal_process_group_with(
    program: &OsStr,
    process_group: &str,
    hard: bool,
) -> io::Result<GroupSignal> {
    let mut command = Command::new(program);
    if hard {
        command.arg("-KILL");
    }
    let status = command
        .args(["--", process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(GroupSignal::Delivered)
    } else if process_group.parse::<i32>().is_ok_and(|group| {
        group < 0
            && nix::sys::signal::kill(nix::unistd::Pid::from_raw(group), None)
                == Err(nix::errno::Errno::ESRCH)
    }) {
        // A nonzero utility status is ambiguous. Only the kernel's ESRCH proves
        // that the entire group has already exited; EPERM and live groups fail.
        Ok(GroupSignal::AlreadyExited)
    } else {
        Err(io::Error::other(format!(
            "kill command exited with {status}"
        )))
    }
}

#[cfg(test)]
pub(crate) const fn fixed_kill_programs_for_test() -> [&'static str; 2] {
    KILL_PROGRAMS
}

fn validate_exit(status: ExitStatus) -> Result<(), ModelError> {
    if status.success() {
        Ok(())
    } else {
        Err(ModelError::NonzeroExit(status.code()))
    }
}

fn parse_envelope(stdout: &[u8]) -> Result<ModelResult, ModelError> {
    let envelope: Value = serde_json::from_slice(stdout).map_err(ModelError::MalformedEnvelope)?;
    let object = envelope.as_object().ok_or(ModelError::EnvelopeShape)?;
    let result = object.get("result");
    let structured = object.get("structured_output");
    let classification = match (result, structured) {
        (Some(result), None) => {
            let result = result.as_str().ok_or(ModelError::EnvelopeShape)?;
            serde_json::from_str(result).map_err(ModelError::MalformedResult)?
        }
        (None, Some(structured)) => structured.clone(),
        (Some(result), Some(structured)) => {
            let result = result.as_str().ok_or(ModelError::EnvelopeShape)?;
            let result: Value =
                serde_json::from_str(result).map_err(ModelError::MalformedResult)?;
            if &result != structured {
                return Err(ModelError::EnvelopeShape);
            }
            result
        }
        _ => return Err(ModelError::EnvelopeShape),
    };
    validate_classification(&classification)
}

fn validate_classification(value: &Value) -> Result<ModelResult, ModelError> {
    execute_command::triage::parse_hook(value)
        .map_err(|reason| ModelError::SchemaMismatch(reason.to_owned()))
}

#[cfg(test)]
pub(crate) fn run_fixture_model(
    cli: &std::ffi::OsStr,
    prompt: &Prompt,
    deadline: Duration,
    environment: Vec<(OsString, OsString)>,
) -> Result<ModelResult, ModelError> {
    ModelRunner::fixture(cli, deadline, environment, None, None, None).run(prompt)
}

#[cfg(test)]
pub(crate) fn run_fixture_model_after_output_exit(
    cli: &std::ffi::OsStr,
    prompt: &Prompt,
    deadline: Duration,
    environment: Vec<(OsString, OsString)>,
) -> Result<ModelResult, ModelError> {
    let mut runner = ModelRunner::fixture(cli, deadline, environment, None, None, None);
    runner.fixture_reap_before_cleanup = true;
    runner.run(prompt)
}

#[cfg(test)]
pub(crate) fn run_fixture_model_with_self_stat(
    cli: &std::ffi::OsStr,
    prompt: &Prompt,
    deadline: Duration,
    environment: Vec<(OsString, OsString)>,
    self_stat: Vec<u8>,
) -> Result<ModelResult, ModelError> {
    ModelRunner::fixture(cli, deadline, environment, None, Some(self_stat), None).run(prompt)
}

#[cfg(test)]
pub(crate) fn run_fixture_model_with_kill_program(
    cli: &std::ffi::OsStr,
    prompt: &Prompt,
    deadline: Duration,
    environment: Vec<(OsString, OsString)>,
    kill_program: OsString,
) -> Result<ModelResult, ModelError> {
    ModelRunner::fixture(cli, deadline, environment, Some(kill_program), None, None).run(prompt)
}

#[cfg(test)]
pub(crate) fn run_fixture_model_with_clock(
    cli: &std::ffi::OsStr,
    prompt: &Prompt,
    deadline: Duration,
    environment: Vec<(OsString, OsString)>,
    clock: Arc<PollClock>,
) -> Result<ModelResult, ModelError> {
    ModelRunner::fixture(cli, deadline, environment, None, None, Some(clock)).run(prompt)
}

#[cfg(test)]
pub(crate) struct TestConfiguration {
    pub cli: OsString,
    pub model: OsString,
    pub isolation: &'static str,
    pub deadline_ms: u64,
    pub arguments: Vec<OsString>,
}

#[cfg(test)]
pub(crate) fn configuration_from_test_environment(
    environment: &[(&str, &str)],
) -> Result<TestConfiguration, ModelError> {
    let runner = ModelRunner::from_environment_source(|name| {
        environment
            .iter()
            .find_map(|(key, value)| (*key == name).then(|| OsString::from(value)))
    })?;
    let isolation = match runner.isolation {
        Isolation::Bare => "bare",
        Isolation::Settings => "settings",
    };
    Ok(TestConfiguration {
        cli: runner.cli.clone(),
        model: runner.model.clone(),
        isolation,
        deadline_ms: u64::try_from(runner.deadline.as_millis()).unwrap_or(u64::MAX),
        arguments: runner.arguments(),
    })
}

#[cfg(test)]
pub(crate) fn settings_arguments_for_test(model: &str) -> Vec<OsString> {
    ModelRunner {
        cli: OsString::from(DEFAULT_CLI),
        model: OsString::from(model),
        isolation: Isolation::Settings,
        state_root: None,
        state_root_handle: None,
        deadline: Duration::from_millis(MAX_MODEL_DEADLINE_MS),
        fixture_environment: Vec::new(),
        fixture_kill_program: None,
        fixture_self_stat: None,
        fixture_clock: None,
        #[cfg(test)]
        fixture_reap_before_cleanup: false,
    }
    .arguments()
}

#[cfg(test)]
pub(crate) fn run_model_from_test_environment(
    environment: &[(&str, &str)],
    prompt: &Prompt,
) -> Result<ModelResult, ModelError> {
    let runner = ModelRunner::from_environment_source(|name| {
        environment
            .iter()
            .find_map(|(key, value)| (*key == name).then(|| OsString::from(value)))
    })?;
    runner.run(prompt)
}
