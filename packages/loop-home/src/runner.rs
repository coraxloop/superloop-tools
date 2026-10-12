/// Entered-loop sign-in and rubric custody predicates shared by command callers.
pub const SIGN_IN_POLICY: &str = include_str!("runner/sign_in_policy.py");

/// Tool-free bounded door profile; callers own invocation and process custody.
pub const DOOR_AGENT_PROGRAM: &str = concat!(
    include_str!("runner/sign_in_policy.py"),
    "\n",
    include_str!("runner/agent_runner.py")
);

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{CommandSpec, IoMode};

mod signals;

pub(crate) fn watched_literal() -> String {
    // Planning and arming run synchronously in the single-threaded entry.
    // A failed disposition query must reach the relay's named refusal.
    signals::watched_bits().map_or_else(|_| "unavailable".to_owned(), |bits| bits.to_string())
}

pub(crate) fn validate_watched(value: Option<&str>) -> Result<(), crate::LoopError> {
    let valid = value.is_some_and(|value| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u32>().is_ok_and(|bits| bits & !0x4007 == 0)
    });
    if valid {
        Ok(())
    } else {
        Err(crate::LoopError::refusal(
            "relay-signals: missing or malformed watched signal set",
        ))
    }
}

/// Captured status, streams, and monotonic command wall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code; in inherited mode a forwarded or terminating signal is the negative signal number, while captured mode reports a signal termination as one.
    pub status: i32,
    /// Captured stdout, empty for inherited mode.
    pub stdout: Vec<u8>,
    /// Captured stderr, empty for inherited mode.
    pub stderr: Vec<u8>,
    /// Monotonic wall duration.
    pub wall: Duration,
}

/// A timed process-spawn or wait failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunError {
    /// Stable operating-system detail.
    pub detail: String,
    /// Monotonic wall before failure.
    pub wall: Duration,
}

/// Injectable boundary owning every external command.
pub trait Runner {
    /// Resolve the verification container route before any home inspection.
    /// Test runners may supply a fixture route without changing production lookup.
    ///
    /// # Errors
    ///
    /// Returns a status-one failure when neither fixed system route exists.
    fn verify_route(&self) -> Result<Vec<String>, crate::LoopError> {
        crate::app::resolve_verify_podman()
    }

    /// Execute one exact command request.
    ///
    /// # Errors
    ///
    /// Returns a timed spawn or wait failure.
    fn run(&mut self, command: &CommandSpec) -> Result<CommandOutput, RunError>;

    /// Execute an entry with its private relay-to-owner stop report.
    ///
    /// # Errors
    /// Returns a timed transport, spawn or wait failure.
    fn run_entry(&mut self, plan: &crate::EntryPlan) -> Result<CommandOutput, RunError> {
        self.run(&plan.command)
    }
}

/// Real process runner used only by the binary.
#[derive(Default)]
pub struct ProcessRunner;

fn status_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

impl Runner for ProcessRunner {
    fn run(&mut self, request: &CommandSpec) -> Result<CommandOutput, RunError> {
        Self::run_command(request, None)
    }

    fn run_entry(&mut self, plan: &crate::EntryPlan) -> Result<CommandOutput, RunError> {
        Self::run_command(&plan.command, Some(&plan.stop_report))
    }
}

impl ProcessRunner {
    fn run_command(
        request: &CommandSpec,
        owner_report: Option<&Path>,
    ) -> Result<CommandOutput, RunError> {
        let started = Instant::now();
        let _report = owner_report
            .map(signals::StopReport::create)
            .transpose()
            .map_err(|error| RunError {
                detail: format!("relay-stop: {error}"),
                wall: started.elapsed(),
            })?;
        let (watched, argv) = if request.label == "_supervise-command" {
            request
                .argv
                .split_first()
                .map_or((None, &[][..]), |(mask, argv)| (Some(mask.as_str()), argv))
        } else {
            (None, request.argv.as_slice())
        };
        let (stop_report, argv) = if watched.is_some() {
            argv.split_first().map_or((None, &[][..]), |(path, argv)| {
                (Some(Path::new(path)), argv)
            })
        } else {
            (owner_report, argv)
        };
        let Some(program) = argv.first() else {
            return Err(RunError {
                detail: String::from("empty argv"),
                wall: started.elapsed(),
            });
        };
        let mut command = Command::new(program);
        command.args(&argv[1..]);
        if matches!(
            request.label.as_str(),
            "verify-roots" | "verify-entry" | "verify-cleanup"
        ) {
            command.env_clear();
            // Podman and the outer shell need only system executable lookup.
            command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
            // Rootless Podman uses the caller's home for its own storage and config;
            // this is the validated caller HOME, never a value read from the loop home.
            if let Some(home) = std::env::var_os("HOME") {
                command.env("HOME", home);
            }
            if let Some(registry) = std::env::var_os("ENTER_LOOP_REGISTRY") {
                command.env("ENTER_LOOP_REGISTRY", registry);
            }
            let runtime = format!("/run/user/{}", nix::unistd::Uid::effective().as_raw());
            // Podman and flatpak-spawn use the account's fixed runtime directory.
            command.env("XDG_RUNTIME_DIR", &runtime);
            // flatpak-spawn reaches the host through this account's session bus.
            command.env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={runtime}/bus"),
            );
        }
        match request.io {
            IoMode::Inherit => {
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                let result = (|| {
                    let mut signals = signals::Signals::new(watched)?;
                    signals.stop_report = stop_report.map(Path::to_path_buf);
                    signals.relay = watched.is_some();
                    signals.prepare(&mut command);
                    let mut child = command.spawn()?;
                    signals.wait(&mut child)
                })();
                let status = result.map_err(|error: io::Error| RunError {
                    detail: error.to_string(),
                    wall: started.elapsed(),
                })?;
                Ok(CommandOutput {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    wall: started.elapsed(),
                })
            }
            IoMode::Capture => {
                command.stdin(Stdio::null());
                let output = command.output().map_err(|error| RunError {
                    detail: error.to_string(),
                    wall: started.elapsed(),
                })?;
                Ok(CommandOutput {
                    status: status_code(output.status),
                    stdout: output.stdout,
                    stderr: output.stderr,
                    wall: started.elapsed(),
                })
            }
        }
    }
}

pub(crate) fn publication_error(error: &io::Error) -> crate::LoopError {
    crate::LoopError::runtime(format!("output failure: {error}"))
}
