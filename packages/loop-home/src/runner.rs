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

/// Owned capabilities explicitly admitted across one child exec.
///
/// Clones retain the same open descriptors. Equality compares capability handles,
/// not paths or contents; separately opened files are distinct command requests.
#[derive(Clone, Debug, Default)]
pub struct CommandDescriptors {
    inherited: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
    input: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}
impl PartialEq for CommandDescriptors {
    fn eq(&self, other: &Self) -> bool {
        self.inherited
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .eq(other.inherited.iter().map(std::os::fd::AsRawFd::as_raw_fd))
            && self.input.as_ref().map(std::os::fd::AsRawFd::as_raw_fd)
                == other.input.as_ref().map(std::os::fd::AsRawFd::as_raw_fd)
    }
}
impl Eq for CommandDescriptors {}
impl CommandDescriptors {
    /// Retain a bounded set at their existing descriptor numbers above stderr.
    /// The child alone clears close-on-exec on the admitted descriptors.
    /// # Errors
    /// Refuses standard descriptors, duplicates and more than 64 capabilities.
    pub fn inherit(descriptors: Vec<std::os::fd::OwnedFd>) -> io::Result<Self> {
        use std::os::fd::AsRawFd as _;
        let mut numbers = std::collections::BTreeSet::new();
        if descriptors.len() > 64
            || descriptors
                .iter()
                .any(|fd| fd.as_raw_fd() <= 2 || !numbers.insert(fd.as_raw_fd()))
        {
            return Err(io::Error::other(
                "anchor-declaration: operation=runner purpose=inherit check=descriptor-allowlist",
            ));
        }
        Ok(Self {
            inherited: descriptors.into_iter().map(std::sync::Arc::new).collect(),
            input: None,
        })
    }

    /// Retain the private rights socket as child stdin without exposing its source number.
    #[must_use]
    pub fn with_input(mut self, descriptor: std::os::fd::OwnedFd) -> Self {
        self.input = Some(std::sync::Arc::new(descriptor));
        self
    }

    /// Configure child-only descriptor inheritance and optional private stdin.
    ///
    /// Every other descriptor above stderr is close-on-exec in this child, even
    /// if its caller accidentally left it inheritable. The parent flags stay intact.
    /// # Errors
    /// Refuses failure to duplicate the retained input; child setup failures surface at spawn.
    #[allow(unsafe_code)]
    pub fn configure(&self, command: &mut Command) -> io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        if let Some(input) = &self.input {
            command.stdin(input.try_clone()?);
        }
        let descriptors = self.inherited.clone();
        // SAFETY: the child callback uses only close_range and fcntl syscalls.
        // Owned handles remain live in the closure and no parent flags change.
        unsafe {
            command.pre_exec(move || {
                if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) == -1 {
                    return Err(io::Error::last_os_error());
                }
                for fd in &descriptors {
                    if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        Ok(())
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
                    request.descriptors.configure(&mut command)?;
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
                request
                    .descriptors
                    .configure(&mut command)
                    .map_err(|error| RunError {
                        detail: format!(
                            "anchor-missing: operation=runner purpose=descriptors: {error}"
                        ),
                        wall: started.elapsed(),
                    })?;
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

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use std::io::Write as _;
    use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
    use std::os::unix::net::UnixStream;

    /// # Panics
    /// Panics if the descriptor fixture or its custody assertions fail.
    /// ´claim:loophome:command-descriptors-confine-child-inheritance´
    /// ´test:unit:command-descriptors-confine-child-inheritance´
    #[test]
    fn command_descriptors_confine_child_inheritance() {
        let (held, mut writer) = UnixStream::pair().expect("held socket");
        writer.write_all(b"held").expect("held bytes");
        let held: OwnedFd = held.into();
        let number = held.as_raw_fd();
        let (unlisted, _peer) = UnixStream::pair().expect("unlisted socket");
        fcntl(unlisted.as_fd(), FcntlArg::F_SETFD(FdFlag::empty())).expect("inheritable fixture");
        let denied = unlisted.as_raw_fd();
        let (input, mut sender) = UnixStream::pair().expect("stdin socket");
        sender.write_all(b"private-input").expect("input bytes");
        sender
            .shutdown(std::net::Shutdown::Write)
            .expect("input EOF");
        let descriptors = CommandDescriptors::inherit(vec![held])
            .expect("allowlist")
            .with_input(input.into());
        let retained = descriptors.clone();
        let mut request = CommandSpec::new(
            "descriptor-fixture",
            vec![
                "python3".into(), "-c".into(),
                "import os,sys\nassert os.read(int(sys.argv[1]),4)==b'held'\ntry:\n os.fstat(int(sys.argv[2]))\nexcept OSError:\n pass\nelse:\n raise AssertionError('unlisted descriptor inherited')\nassert sys.stdin.read()=='private-input'\nprint('verified')".into(),
                number.to_string(), denied.to_string(),
            ],
            IoMode::Capture,
        );
        request.descriptors = descriptors;
        let output = ProcessRunner.run(&request).expect("runner");
        assert_eq!(
            output.status,
            0,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"verified\n");
        assert_eq!(request.descriptors, retained);
        let flags = fcntl(retained.inherited[0].as_fd(), FcntlArg::F_GETFD).expect("parent flags");
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(
            fcntl(unlisted.as_fd(), FcntlArg::F_GETFD).expect("unlisted flags"),
            0
        );
        drop(request);
        assert!(nix::sys::stat::fstat(retained.inherited[0].as_fd()).is_ok());
    }

    /// # Panics
    /// Panics if the descriptor fixture or its custody assertions fail.
    /// ´claim:loophome:command-descriptors-refuse-excess-capabilities´
    /// ´test:unit:command-descriptors-refuse-excess-capabilities´
    #[test]
    fn command_descriptors_refuse_excess_capabilities() {
        let (socket, _peer) = UnixStream::pair().expect("socket");
        let descriptors = (0..65)
            .map(|_| nix::unistd::dup(socket.as_fd()).expect("duplicate"))
            .collect();
        let error = CommandDescriptors::inherit(descriptors).expect_err("bounded allowlist");
        assert!(error.to_string().starts_with("anchor-declaration:"));
    }
}
