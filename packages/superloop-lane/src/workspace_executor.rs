//! Unselected node executor. Admission and durable request custody belong to W3.
use crate::{error::LaneError, plan};
use execute_command::workspace::{Envelope, Execution, Measurement, Outcome, admit};
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Existing measurement shapes, not a new wire response or durable record.
#[derive(Debug)]
pub struct ExecutionMeasurements {
    pub result: Measurement,
    pub steps: Vec<Measurement>,
    /// Set immediately after any child is spawned, including a quiet child.
    pub child_started: bool,
    pub start_failure: Option<StartFailure>,
}

/// A failed attempt to start one step; no child exists for this step.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartFailure {
    pub kind: StartFailureKind,
    pub step_index: usize,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartFailureKind {
    NotFound,
    NotExecutable,
    Other,
}

impl StartFailureKind {
    #[must_use]
    pub const fn status(self) -> i32 {
        match self {
            Self::NotFound => 127,
            Self::NotExecutable | Self::Other => 126,
        }
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotFound => "not found",
            Self::NotExecutable => "not executable",
            Self::Other => "could not start",
        }
    }
}

/// Retained cwd and exact execution context. Preparing this value is not admission.
pub struct PreparedExecution {
    cwd: File,
    envelope: Envelope,
    environment: BTreeMap<String, String>,
    started: Instant,
    deadline: Instant,
    #[cfg(test)]
    after_step: Option<fn(&mut Self, usize)>,
}

fn context(detail: impl std::fmt::Display) -> LaneError {
    LaneError::input("door-workspace-context-differs", detail.to_string())
}
fn protocol(error: execute_command::workspace::Refusal) -> LaneError {
    LaneError::input(error.kind, error.detail)
}

impl PreparedExecution {
    /// The one command deadline, including time spent before start.
    #[must_use]
    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Open an existing workspace from an authenticated reservation, never settings.
    ///
    /// The caller owns reservation custody and the authenticated node identity. This
    /// checks context and paths only: W3 must authorize the exact request before run.
    /// No program, directory, checkout, target or file is created by preparation.
    /// # Errors
    /// Refuses an absent/stale grant, invalid envelope, foreign identity, missing cwd
    /// or any symlink in the root/cwd walk. Filesystem observations are contextual.
    pub fn from_reservation(
        reservation: &Value,
        node: &str,
        envelope: &Envelope,
    ) -> Result<Self, LaneError> {
        let started = Instant::now();
        let snapshot = plan::workspace_snapshot(&reservation["plan"])?;
        let grant = snapshot.as_ref().map(|snapshot| &snapshot.grant);
        admit(
            envelope,
            grant,
            reservation["loop"].as_str().unwrap_or_default(),
            reservation["run"].as_str().unwrap_or_default(),
            node,
        )
        .map_err(protocol)?;
        let grant = grant.ok_or_else(|| context("admitted grant absent"))?;
        let placement = crate::placement::snapshot(&reservation["plan"], snapshot.as_ref())?
            .ok_or_else(|| context("workspace placement is required"))?;
        let root = File::open("/").map_err(context)?;
        let flags = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
        let relative = grant.workspace.strip_prefix('/').unwrap_or_default();
        let workspace = openat2(
            &root,
            if relative.is_empty() { "." } else { relative },
            flags,
        )
        .map(File::from)
        .map_err(context)?;
        placement.bind(crate::placement::read_identity(&workspace))?;
        let relative = envelope.cwd.join("/");
        let cwd = openat2(
            &workspace,
            if relative.is_empty() { "." } else { &relative },
            flags,
        )
        .map(File::from)
        .map_err(context)?;
        let mut environment: BTreeMap<_, _> = grant.baseline_env.iter().cloned().collect();
        // Additions are ordered assignments. Quick rules already require uniqueness;
        // repeated names remain representable for judgement, with the last assignment winning.
        environment.extend(envelope.env_additions.iter().cloned());
        Ok(Self {
            cwd,
            envelope: envelope.clone(),
            environment,
            started,
            deadline: started + Duration::from_millis(envelope.deadline_ms),
            #[cfg(test)]
            after_step: None,
        })
    }

    /// Execute an already authorized request with one deadline and caller-owned streams.
    ///
    /// This is deliberately not a policy gate. No production caller selects it yet.
    /// The custody owner must bind the quick rule or judgement to this exact envelope;
    /// in particular a shell or grammar miss cannot acquire authority here. Standard
    /// input is empty. Output is streamed directly, never buffered or parsed as evidence.
    /// A started child always contributes a measurement. Spawn/wait failures are Unknown.
    /// The caller connects outer termination to `cancel`: setting it revokes the
    /// remaining budget and records `TimedOut`, including an empty pre-spawn prefix.
    /// No process-global signal handler is installed by this library.
    #[must_use]
    #[allow(unused_mut)] // Only the scoped test hook changes the prepared deadline.
    pub fn run_admitted(
        mut self,
        stdout: &File,
        stderr: &File,
        cancel: &AtomicBool,
    ) -> ExecutionMeasurements {
        let vectors = match &self.envelope.execution {
            Execution::Argv { words } => vec![words.clone()],
            Execution::Sequence { steps } => steps.clone(),
            Execution::Shell { shell, text } => vec![vec![
                shell.as_bytes().to_vec(),
                b"-c".to_vec(),
                text.as_bytes().to_vec(),
            ]],
        };
        let mut measurements = Vec::new();
        let mut child_started = false;
        let mut start_failure = None;
        let mut outcome = Outcome::TimedOut;
        for (step_index, words) in vectors.iter().enumerate() {
            let Some((measured, started, failure)) =
                self.step(words, step_index, stdout, stderr, cancel)
            else {
                break;
            };
            child_started |= started;
            start_failure = failure;
            outcome = measured.outcome.clone();
            let successful = outcome == (Outcome::Exited { code: 0 });
            measurements.push(measured);
            #[cfg(test)]
            if let Some(hook) = self.after_step {
                hook(&mut self, measurements.len());
            }
            if !successful {
                break;
            }
            if measurements.len() < vectors.len() {
                outcome = Outcome::TimedOut;
            }
        }
        let result = Measurement {
            outcome,
            wall_seconds: Some(self.started.elapsed().as_secs_f64()),
            user_cpu_seconds: measurements.iter().map(|m| m.user_cpu_seconds).sum(),
            system_cpu_seconds: measurements.iter().map(|m| m.system_cpu_seconds).sum(),
        };
        ExecutionMeasurements {
            result,
            child_started,
            start_failure,
            steps: if matches!(self.envelope.execution, Execution::Sequence { .. }) {
                measurements
            } else {
                Vec::new()
            },
        }
    }

    fn step(
        &self,
        words: &[Vec<u8>],
        step_index: usize,
        stdout: &File,
        stderr: &File,
        cancel: &AtomicBool,
    ) -> Option<(Measurement, bool, Option<StartFailure>)> {
        if self.expired(cancel) {
            return None;
        }
        let began = Instant::now();
        let command = self.command(words, stdout, stderr);
        if self.expired(cancel) {
            return None;
        }
        let mut child_started = false;
        let result = command
            .and_then(|mut command| command.spawn())
            .and_then(|child| {
                child_started = true;
                let mut child = Running {
                    child,
                    reaped: false,
                };
                let mut timed_out = false;
                loop {
                    if let Some(mut measured) = reap(child.child.id(), false)? {
                        child.reaped = true;
                        if timed_out || self.expired(cancel) {
                            measured.outcome = Outcome::TimedOut;
                        }
                        return Ok(measured);
                    }
                    if self.expired(cancel) {
                        timed_out = true;
                        child.kill_group();
                        if let Some(mut measured) = reap(child.child.id(), true)? {
                            child.reaped = true;
                            measured.outcome = Outcome::TimedOut;
                            return Ok(measured);
                        }
                    }
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(self.deadline.saturating_duration_since(Instant::now())),
                    );
                }
            });
        let start_failure = if child_started {
            None
        } else {
            result.as_ref().err().map(|error| {
                let kind = match error.kind() {
                    io::ErrorKind::NotFound => StartFailureKind::NotFound,
                    io::ErrorKind::PermissionDenied => StartFailureKind::NotExecutable,
                    _ => StartFailureKind::Other,
                };
                let program = String::from_utf8_lossy(&words[0]);
                let _written = writeln!(
                    &mut &*stderr,
                    "{}: {}",
                    program.escape_debug(),
                    kind.message()
                );
                StartFailure { kind, step_index }
            })
        };
        let mut measured = result.unwrap_or(Measurement {
            outcome: Outcome::Unknown,
            wall_seconds: None,
            user_cpu_seconds: None,
            system_cpu_seconds: None,
        });
        measured.wall_seconds = Some(began.elapsed().as_secs_f64());
        Some((measured, child_started, start_failure))
    }

    fn expired(&self, cancel: &AtomicBool) -> bool {
        cancel.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }

    fn command(&self, words: &[Vec<u8>], stdout: &File, stderr: &File) -> io::Result<Command> {
        let program = OsString::from_vec(words[0].clone());
        let mut command = Command::new(program);
        command
            .args(words[1..].iter().cloned().map(OsString::from_vec))
            .env_clear()
            .envs(&self.environment)
            // The descriptor stays live until every child is reaped. chdir happens
            // before exec closes CLOEXEC descriptors; renaming W cannot redirect it.
            .current_dir(format!("/proc/self/fd/{}", self.cwd.as_raw_fd()))
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .process_group(0);
        Ok(command)
    }
}

struct Running {
    child: Child,
    reaped: bool,
}
impl Running {
    fn kill_group(&self) {
        if let Ok(pid) = i32::try_from(self.child.id()) {
            let _stopped = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_group();
            let _reaped = self.child.wait();
        }
    }
}

fn cpu(value: libc::timeval) -> Option<f64> {
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let micros = u32::try_from(value.tv_usec).ok()?;
    (micros < 1_000_000).then(|| Duration::new(seconds, micros * 1000).as_secs_f64())
}

#[allow(unsafe_code)]
fn reap(pid: u32, blocking: bool) -> io::Result<Option<Measurement>> {
    if !blocking {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: a writable initialized signal-information object is supplied.
        // WNOWAIT retains the leader PID until its process group is stopped.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: waitid succeeded; zero si_pid means no completed child.
        if unsafe { info.assume_init().si_pid() } == 0 {
            return Ok(None);
        }
    }
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // Stop descendants while the unreaped leader still reserves the group ID.
    let _stopped = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    let mut status = 0;
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: both pointers refer to writable objects; usage is read only when
    // wait4 returns this exact child PID and has initialized the output.
    let result = unsafe { libc::wait4(pid, &raw mut status, 0, usage.as_mut_ptr()) };
    if result < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if result == 0 {
        return Ok(None);
    }
    // SAFETY: successful wait4 initialized usage above.
    let usage = unsafe { usage.assume_init() };
    let outcome = if libc::WIFEXITED(status) {
        Outcome::Exited {
            code: libc::WEXITSTATUS(status),
        }
    } else if libc::WIFSIGNALED(status) {
        Outcome::Signalled {
            signal: u32::try_from(libc::WTERMSIG(status)).map_err(io::Error::other)?,
        }
    } else {
        Outcome::Unknown
    };
    Ok(Some(Measurement {
        outcome,
        wall_seconds: None,
        user_cpu_seconds: cpu(usage.ru_utime),
        system_cpu_seconds: cpu(usage.ru_stime),
    }))
}

#[cfg(test)]
#[path = "workspace_executor_tests.rs"]
mod tests;
