//! Two held native sealers. Only stderr is drained; plaintext descriptors go straight to stdin.
use super::{
    Result,
    channel::{self, EofProbe, Input, PipeState},
    confinement::Confinement,
    measure::{Admission, HeldArtifact},
    policy::ArtifactRole,
    require,
    state::Phase,
    store::Store,
};
use crate::process::cancel;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Completion {
    pub sealed_bytes: [u64; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exit {
    Code(i32),
    Signal(i32),
}
struct Running {
    child: Child,
    pidfd: OwnedFd,
    probe: EofProbe,
    errors: ChildStderr,
    diagnostic_count: u64,
    stderr_closed: bool,
    output: File,
    done: bool,
    exit: Option<Exit>,
}
impl Running {
    fn start(mut command: Command, probe: EofProbe, output: File) -> Result<Self> {
        let mut child = command.spawn().map_err(|_| "sealer-start")?;
        let setup = (|| {
            let pidfd = pidfd(child.id())?;
            let errors = child.stderr.take().ok_or("sealer-stderr")?;
            fcntl(&errors, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(|_| "sealer-stderr")?;
            Ok((pidfd, errors))
        })();
        match setup {
            Ok((pidfd, errors)) => Ok(Self {
                child,
                pidfd,
                probe,
                errors,
                output,
                diagnostic_count: 0,
                stderr_closed: false,
                done: false,
                exit: None,
            }),
            Err(class) => {
                let _status = cancel(&mut child);
                Err(class)
            }
        }
    }
    fn drain_errors(&mut self, limit: u64) -> Result<()> {
        let mut bytes = [0_u8; 4096];
        loop {
            match self.errors.read(&mut bytes) {
                Ok(0) => {
                    self.stderr_closed = true;
                    return Ok(());
                }
                Ok(n) => {
                    self.diagnostic_count += n as u64;
                    // Bytes are never retained, formatted, logged or serialized.
                    require(self.diagnostic_count <= limit, "sealer-diagnostic-limit")?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err("sealer-diagnostic-read"),
            }
        }
    }
    fn collect(&mut self, diagnostic_limit: u64, sealed_limit: u64) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.drain_errors(diagnostic_limit)?;
        let pid = Pid::from_raw(i32::try_from(self.child.id()).map_err(|_| "sealer-pid")?);
        let status = waitid(
            Id::Pid(pid),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        )
        .map_err(|_| "sealer-wait")?;
        if status == WaitStatus::StillAlive {
            return Ok(());
        }
        // Recheck readiness at exit collection, never infer it from event ordering.
        let drained = self.probe.observe()? == PipeState::ClosedAndDrained;
        self.exit = match status {
            WaitStatus::Exited(_, code) => Some(Exit::Code(code)),
            WaitStatus::Signaled(_, signal, _) => Some(Exit::Signal(signal as i32)),
            _ => return Err("sealer-wait"),
        };
        let zero = self.exit == Some(Exit::Code(0));
        // Keep the unreaped leader as the process-group identity until cancellation.
        let killed = killpg(pid, Signal::SIGKILL);
        let reaped = self.child.wait().map_err(|_| "sealer-wait")?;
        self.done = true;
        require(killed.is_ok(), "sealer-cancel")?;
        self.drain_errors(diagnostic_limit)?;
        require(drained, "sealer-early-exit")?;
        require(zero && reaped.success(), "sealer-exit")?;
        let size = self
            .output
            .metadata()
            .map_err(|_| "sealer-output-stat")?
            .len();
        require((1..=sealed_limit).contains(&size), "sealer-output-size")
    }
}
impl Running {
    fn cancel(&mut self) {
        if !self.done
            && let Some(status) = crate::process::cancel_pinned(&mut self.child, self.pidfd.as_fd())
        {
            self.exit = status
                .code()
                .map(Exit::Code)
                .or_else(|| status.signal().map(Exit::Signal));
            self.done = true;
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel();
    }
}
#[allow(unsafe_code)]
fn pidfd(pid: u32) -> Result<OwnedFd> {
    // SAFETY: scalar syscall, positive return is a newly owned descriptor.
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    let fd = i32::try_from(fd).map_err(|_| "sealer-pidfd")?;
    require(fd >= 0, "sealer-pidfd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn command(
    path: &Path,
    artifact: &HeldArtifact,
    name: &str,
    input: OwnedFd,
    output: &File,
    limit: u64,
    confinement: &Confinement,
) -> Result<Command> {
    require((1..=16 * 1024 * 1024).contains(&limit), "sealer-size-limit")?;
    artifact.unchanged()?;
    let mut command = Command::new(path);
    command
        .args([
            "encrypt",
            "--with-key=host",
            &format!("--name={name}"),
            "-",
            "-",
        ])
        .env_clear()
        .current_dir("/")
        .process_group(0)
        .stdin(Stdio::from(input))
        .stdout(output.try_clone().map_err(|_| "sealer-output-duplicate")?)
        .stderr(Stdio::piped());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .map_err(|_| "sealer-descriptors")?;
    child_limits(&mut command, limit);
    confinement.configure(&mut command)?;
    // Install exec LAST: the existing held executor never returns on success.
    crate::process::pin_matching(&mut command, &[], Some(&artifact.file))
        .map_err(|_| "sealer-execution-identity")?;
    artifact.unchanged()?;
    Ok(command)
}
#[allow(unsafe_code)]
fn child_limits(command: &mut Command, limit: u64) {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Capabilities {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // SAFETY: child-only callback uses stack values and async-signal-safe Linux
    // syscalls; no allocations, locks, logging or plaintext access after fork.
    unsafe {
        command.pre_exec(move || {
            let file_limit = nix::libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            let core_limit = nix::libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let capabilities = [Capabilities {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if nix::libc::setrlimit(nix::libc::RLIMIT_FSIZE, &raw const file_limit) != 0
                || nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &raw const core_limit) != 0
                || nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || nix::libc::prctl(
                    nix::libc::PR_CAP_AMBIENT,
                    nix::libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
                || nix::libc::syscall(
                    nix::libc::SYS_capset,
                    &raw const header,
                    capabilities.as_ptr(),
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub(super) struct Session<'a> {
    store: &'a mut Store,
    running: Vec<Running>,
    diagnostic_limit: u64,
    sealed_limit: u64,
    finished: bool,
    exits: [Option<Exit>; 2],
    deadline: Instant,
}
impl<'a> Session<'a> {
    pub fn start(
        admission: &Admission,
        index: usize,
        store: &'a mut Store,
        readers: [OwnedFd; 2],
    ) -> Result<Self> {
        Self::start_with(admission, index, store, readers, Running::start)
    }
    fn start_with(
        admission: &Admission,
        index: usize,
        store: &'a mut Store,
        readers: [OwnedFd; 2],
        mut spawn: impl FnMut(Command, EofProbe, File) -> Result<Running>,
    ) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_millis(admission.policy().limits.case_ms);
        let confinement = Confinement::prepare(admission)?;
        let inputs = Input::pair(readers)?;
        let outputs = store.sealer_outputs(admission, index)?;
        let case = admission
            .policy()
            .cases
            .get(index)
            .ok_or("launch-case-binding")?;
        let artifact = admission
            .artifacts()
            .iter()
            .find(|a| a.role == ArtifactRole::Sealer)
            .ok_or("launch-artifact-roster")?;
        let reference = admission
            .policy()
            .artifacts
            .iter()
            .find(|a| a.role == ArtifactRole::Sealer)
            .ok_or("launch-artifact-roster")?;
        let sealed_limit = admission.policy().limits.sealed_bytes;
        let diagnostic_limit = admission.policy().limits.diagnostic_bytes;
        let mut prepared = Vec::new();
        for ((input, output), stream) in inputs.into_iter().zip(outputs).zip(&case.streams) {
            let (reader, probe) = input.split()?;
            prepared.push((
                command(
                    &reference.path,
                    artifact,
                    &stream.name,
                    reader,
                    &output,
                    sealed_limit,
                    &confinement,
                )?,
                probe,
                output,
            ));
        }
        let mut session = Self {
            store,
            running: Vec::new(),
            diagnostic_limit,
            sealed_limit,
            finished: false,
            exits: [None; 2],
            deadline,
        };
        let result = (|| {
            for (command, probe, output) in prepared {
                session.running.push(spawn(command, probe, output)?);
            }
            session.store.advance(Phase::SealersStarted)
        })();
        if let Err(class) = result {
            return Err(session.fail(class));
        }
        Ok(session)
    }
    pub fn wait_until(&mut self, deadline: Instant) -> Result<Completion> {
        let result = self.wait_inner(deadline);
        match result {
            Ok(completion) => {
                self.finished = true;
                Ok(completion)
            }
            Err(class) => Err(self.fail(class)),
        }
    }
    fn wait_inner(&mut self, deadline: Instant) -> Result<Completion> {
        require(!self.finished, "sealer-session-terminal")?;
        loop {
            let timeout = remaining_timeout(Instant::now(), self.deadline, deadline)?;
            for (running, exit) in self.running.iter_mut().zip(&mut self.exits) {
                let result = running.collect(self.diagnostic_limit, self.sealed_limit);
                *exit = running.exit;
                result?;
            }
            if self.running.iter().all(|r| r.done) {
                self.store.check_outputs(Some(0o600))?;
                let sizes = self
                    .running
                    .iter()
                    .map(|r| {
                        r.output
                            .metadata()
                            .map(|m| m.len())
                            .map_err(|_| "sealer-output-stat")
                    })
                    .collect::<Result<Vec<_>>>()?;
                remaining_timeout(Instant::now(), self.deadline, deadline)?;
                return Ok(Completion {
                    sealed_bytes: [sizes[0], sizes[1]],
                });
            }
            let mut items = Vec::new();
            for running in self.running.iter().filter(|r| !r.done) {
                items.push(nix::libc::pollfd {
                    fd: running.pidfd.as_raw_fd(),
                    events: nix::libc::POLLIN,
                    revents: 0,
                });
                if !running.stderr_closed {
                    items.push(nix::libc::pollfd {
                        fd: running.errors.as_raw_fd(),
                        events: nix::libc::POLLIN,
                        revents: 0,
                    });
                }
            }
            channel::poll(&mut items, timeout)?;
        }
    }
    // The future keeper advances C1 while its sealers remain alive.
    pub const fn store(&mut self) -> &mut Store {
        self.store
    }
    pub const fn exits(&self) -> &[Option<Exit>; 2] {
        &self.exits
    }
    #[cfg(test)]
    pub fn test_pidfds(&self) -> Vec<OwnedFd> {
        self.running
            .iter()
            .map(|r| r.pidfd.try_clone().unwrap())
            .collect()
    }
    // Explicit cancellation is also the deterministic deadline control: tests
    // inject the event, not a claim about how quickly a shared machine ran.
    // Ambiguous manager ownership or observation loss must retain outputs.
    pub fn quarantine(&mut self, class: &'static str) -> &'static str {
        if self.finished {
            return "sealer-session-terminal";
        }
        for (running, exit) in self.running.iter_mut().zip(&mut self.exits) {
            running.cancel();
            *exit = running.exit;
        }
        self.running.clear();
        self.finished = true;
        if matches!(self.store.phase(), Phase::Failed | Phase::Uncertain) {
            return class;
        }
        if self.store.uncertain(class).is_err() {
            return "sealer-failure-custody";
        }
        class
    }
    pub fn fail(&mut self, class: &'static str) -> &'static str {
        if self.finished {
            return "sealer-session-terminal";
        }
        for (running, exit) in self.running.iter_mut().zip(&mut self.exits) {
            running.cancel();
            *exit = running.exit;
        }
        self.running.clear(); // All owned groups are cancelled before output cleanup.
        self.finished = true;
        if self
            .store
            .fail(class)
            .and_then(|()| self.store.cleanup_outputs())
            .is_err()
        {
            return "sealer-failure-custody";
        }
        class
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ignored = self.fail("sealer-abandoned");
        }
    }
}

// A pure budget conversion lets controls inject expired deadlines without a wait.
pub(super) fn remaining_timeout(now: Instant, hard: Instant, requested: Instant) -> Result<i32> {
    let deadline = hard.min(requested);
    require(deadline > now, "sealer-deadline")?;
    let remaining = deadline.saturating_duration_since(now);
    let millis = remaining
        .as_millis()
        .saturating_add(1)
        .min(i32::MAX as u128);
    i32::try_from(millis).map_err(|_| "sealer-deadline")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    /// ´test:unit:sealer-execution-compares-the-retained-image´
    #[test]
    fn sealer_execution_compares_the_retained_image() {
        let fixture = super::super::sealer_tests::make_fixture("normal");
        let admission = fixture.admit();
        let artifact = admission
            .artifacts()
            .iter()
            .find(|a| a.role == ArtifactRole::Sealer)
            .unwrap();
        let other = fixture.dir.path().join("same-bytes-different-inode");
        std::fs::copy(fixture.dir.path().join("sealer"), &other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o555)).unwrap();
        let (reader, _writer) = nix::unistd::pipe().unwrap();
        assert_eq!(
            command(
                &other,
                artifact,
                "normal",
                reader,
                &tempfile::tempfile().unwrap(),
                4096,
                &Confinement::prepare(&admission).unwrap()
            )
            .err(),
            Some("sealer-execution-identity")
        );
    }
    /// ´test:unit:sealer-second-start-failure-reaps-the-first-child´
    #[test]
    fn sealer_second_start_failure_reaps_the_first_child() {
        let fixture = super::super::sealer_tests::make_fixture("normal");
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (left, _left_writer) = nix::unistd::pipe().unwrap();
        let (right, _right_writer) = nix::unistd::pipe().unwrap();
        let mut first = None;
        let result = Session::start_with(
            &admission,
            0,
            &mut store,
            [left, right],
            |command, probe, output| {
                if first.is_some() {
                    return Err("sealer-start");
                }
                let running = Running::start(command, probe, output)?;
                first = Some(running.pidfd.try_clone().unwrap());
                Ok(running)
            },
        );
        assert_eq!(result.err(), Some("sealer-start"));
        let pidfd = first.unwrap();
        let mut item = nix::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        channel::poll(std::slice::from_mut(&mut item), 0).unwrap();
        assert_ne!(item.revents & nix::libc::POLLIN, 0);
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture.dir.path().join("evidence/sample/state-01.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["refusal_class"], "sealer-start");
        assert_eq!(store.phase(), Phase::Failed);
        assert_eq!(
            std::fs::read_dir(fixture.dir.path().join("sealed/sample"))
                .unwrap()
                .count(),
            0
        );
    }
}
