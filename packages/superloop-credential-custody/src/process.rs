//! Bounded metadata-only subprocess capture. Foreign diagnostics never escape.
use crate::record::{Limits, Result};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::Pid;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Called once, before argument parsing or any child. No threads or signal
/// handlers have been installed by this process at this point.
#[allow(unsafe_code)]
pub fn initialize() -> Result<()> {
    // SAFETY: close_range with CLOEXEC changes only this process's descriptor
    // flags; its scalar bounds cover every inherited non-standard descriptor.
    // Resetting SIGCHLD at single-threaded startup prevents inherited SIG_IGN
    // from automatically reaping children before group cancellation.
    unsafe {
        if nix::libc::syscall(nix::libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) == -1 {
            return Err("descriptor-inheritance");
        }
        nix::sys::signal::sigaction(
            Signal::SIGCHLD,
            &SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty()),
        )
        .map_err(|_| "child-signal-policy")?;
    }
    Ok(())
}

fn nonblocking(file: &impl AsFd) -> Result<()> {
    fcntl(file, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(|_| "child-pipe")?;
    Ok(())
}

fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, limit: u64) -> Result<bool> {
    let mut buffer = [0; 8192];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if bytes.len() as u64 + n as u64 > limit {
                    return Err("child-output-limit");
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err("child-read"),
        }
    }
}

/// Retain the executable through the existing descriptor-execution owner.
pub fn pin_program(
    command: &mut Command,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<()> {
    pin_matching(command, environment, None)
}

pub fn pin_matching(
    command: &mut Command,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
    expected: Option<&std::fs::File>,
) -> Result<()> {
    use loop_home::anchor::{
        HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement, Transport,
    };
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    let requested = Path::new(command.get_program());
    // Only the fixed interpreter may be a vendor symlink. Its containing
    // directory is protected before resolution; operator exclusion covers
    // concurrent replacement by the trusted owner, including symlink targets.
    let path: PathBuf = if requested == Path::new("/usr/bin/python3") {
        let _parent = crate::receipt::walk(Path::new("/usr/bin"), true, true)?;
        std::fs::canonicalize(requested).map_err(|_| "program-path")?
    } else {
        requested.into()
    };
    let file = crate::receipt::walk(&path, false, true)?;
    let meta = file.metadata().map_err(|_| "program-metadata")?;
    if !meta.is_file()
        || (meta.nlink() == 0 || (meta.uid() != 0 && meta.nlink() != 1))
        || (meta.uid() != 0 && meta.uid() != nix::unistd::geteuid().as_raw())
        || meta.mode() & 0o7022 != 0
        || meta.mode() & 0o111 == 0
    {
        return Err("program-custody");
    }
    let policy = Policy {
        kind: Kind::File,
        owner: if meta.uid() == 0 {
            Owner::RootFile
        } else {
            Owner::Host
        },
        mode: ModePolicy::Executable,
    };
    let operation = "credential-observation";
    let pin = HostVerifier::current()
        .map_err(|_| "program-custody")?
        .for_operation(operation)
        .pin(&path, "program", 0, policy)
        .map_err(|_| "program-custody")?;
    if pin.record().device != meta.dev() || pin.record().inode != meta.ino() {
        return Err("program-identity");
    }
    if let Some(expected) = expected {
        let measured = expected
            .metadata()
            .map_err(|_| "identity-interpreter-hold")?;
        if (pin.record().device, pin.record().inode) != (measured.dev(), measured.ino()) {
            return Err("interpreter-execution-identity");
        }
    }
    let manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: operation.into(),
        loop_name: String::new(),
        records: vec![pin.record()],
    };
    let anchors = Receiver::current()
        .map_err(|_| "program-custody")?
        .validate(
            &manifest,
            vec![pin.into_fd()],
            operation,
            "",
            Transport::Rights,
            &[Requirement {
                purpose: "program".into(),
                policy,
                alias_group: None,
            }],
        )
        .map_err(|_| "program-custody")?;
    let argv: Vec<_> = std::iter::once(command.get_program().to_owned())
        .chain(command.get_args().map(std::ffi::OsStr::to_owned))
        .collect();
    anchors[0]
        .configure_exec(command, &argv, environment)
        .map_err(|_| "program-exec")
}

pub fn capture(command: Command, input: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    capture_inner(command, input, limits, None, &[])
}

/// Git must not escape through a repository-configured fetch transport.
pub fn capture_git(command: Command, limits: &Limits) -> Result<Vec<u8>> {
    capture_inner(
        command,
        &[],
        limits,
        None,
        &[("GIT_ALLOW_PROTOCOL".into(), "".into())],
    )
}

/// The retained file is the very inode whose bytes supplied the identity digest.
pub fn capture_matching(
    command: Command,
    input: &[u8],
    limits: &Limits,
    measured: &std::fs::File,
) -> Result<Vec<u8>> {
    capture_inner(command, input, limits, Some(measured), &[])
}

fn capture_inner(
    mut command: Command,
    input: &[u8],
    limits: &Limits,
    measured: Option<&std::fs::File>,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<u8>> {
    pin_matching(&mut command, environment, measured)?;
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| "child-start")?;
    let result = (|| {
        let mut stdin = child.stdin.take().ok_or("child-pipe")?;
        let mut stdout = child.stdout.take().ok_or("child-pipe")?;
        let mut stderr = child.stderr.take().ok_or("child-pipe")?;
        nonblocking(&stdin)?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let mut remaining = input;
        let mut writer = Some(&mut stdin);
        let start = Instant::now();
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            if start.elapsed() >= Duration::from_millis(limits.timeout_ms) {
                return Err("child-timeout");
            }
            if let Some(pipe) = writer.as_mut() {
                if remaining.is_empty() {
                    writer = None;
                } else {
                    match pipe.write(remaining) {
                        Ok(n) => remaining = &remaining[n..],
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => return Err("child-input"),
                    }
                }
            }
            // Python's '-' source needs EOF. Ownership closes stdin once all source is sent.
            if writer.is_none() {
                break;
            }
            drain(&mut stdout, &mut output, limits.output_bytes)?;
            drain(&mut stderr, &mut errors, limits.output_bytes)?;
            std::thread::sleep(Duration::from_millis(2));
        }
        drop(stdin);
        loop {
            if start.elapsed() >= Duration::from_millis(limits.timeout_ms) {
                return Err("child-timeout");
            }
            let out_done = drain(&mut stdout, &mut output, limits.output_bytes)?;
            let err_done = drain(&mut stderr, &mut errors, limits.output_bytes)?;
            // WNOWAIT pins the exited leader's PID until killpg below. Never
            // reap here: even a leader with closed pipes can have descendants.
            let pid = i32::try_from(child.id()).map_err(|_| "child-pid")?;
            let status = waitid(
                Id::Pid(Pid::from_raw(pid)),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            )
            .map_err(|_| "child-wait")?;
            if !matches!(status, WaitStatus::StillAlive) && out_done && err_done {
                return if matches!(status, WaitStatus::Exited(_, 0)) && errors.is_empty() {
                    Ok(output)
                } else {
                    Err("child-failed")
                };
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    let _status = cancel(&mut child);
    result
}

/// Retain the leader until its process group has been cancelled.
pub fn cancel(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    cancel_observed(child, || {})
}
fn cancel_observed(
    child: &mut std::process::Child,
    after_kill: impl FnOnce(),
) -> Option<std::process::ExitStatus> {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ignored = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    after_kill();
    child.wait().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    /// ´test:unit:interpreter-execution-retains-measured-inode´
    #[test]
    fn interpreter_execution_retains_measured_inode() {
        // Exercise the real descriptor-execution boundary with native stand-ins:
        // replacing the host's fixed Python path would need host root. No CLI
        // override or production test hook is added to make that swap possible.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interpreter");
        let replacement = dir.path().join("replacement");
        for target in [&path, &replacement] {
            fs::copy("/usr/bin/printf", target).unwrap();
            fs::set_permissions(target, fs::Permissions::from_mode(0o555)).unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), fs::read(&replacement).unwrap());
        let measured = fs::File::open(&path).unwrap();
        let limits = Limits {
            file_bytes: 1024,
            output_bytes: 1024,
            timeout_ms: 5000,
        };
        let command = || {
            let mut c = Command::new(&path);
            c.arg("synthetic");
            c
        };
        assert_eq!(
            capture_matching(command(), &[], &limits, &measured).unwrap(),
            b"synthetic"
        );
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            capture_matching(command(), &[], &limits, &measured),
            Err("interpreter-execution-identity")
        );
    }
    /// ´test:unit:group-leader-is-not-reaped-before-cancellation´
    #[test]
    #[allow(unsafe_code)]
    fn group_leader_is_not_reaped_before_cancellation() {
        use std::io::BufRead as _;
        use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd};
        fn ready(fd: &impl AsRawFd) {
            let deadline = Instant::now() + Duration::from_secs(600);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "emergency event-wait guard");
                let mut item = nix::libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one live descriptor and one stack pollfd, no ownership transfer.
                let result = unsafe {
                    nix::libc::poll(
                        &raw mut item,
                        1,
                        i32::try_from(remaining.as_millis()).unwrap(),
                    )
                };
                if result < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                assert!(result > 0, "emergency event-wait guard or poll failure");
                assert_ne!(item.revents & nix::libc::POLLIN, 0);
                break;
            }
        }
        fn pidfd(pid: u32) -> OwnedFd {
            // SAFETY: pidfd_open returns a new descriptor on success.
            let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0);
            unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) }
        }
        let source = "import os, signal, sys\npid = os.fork()\nif pid == 0:\n os.close(0); os.close(1); os.close(2)\n signal.pause()\nelse:\n print('watchdog-started', pid, flush=True)\n sys.stdin.buffer.read()\n";
        let mut command = Command::new("/usr/bin/python3");
        command
            .args(["-I", "-c", source])
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        loop_home::CommandDescriptors::default()
            .configure(&mut command)
            .unwrap();
        pin_program(&mut command, &[]).unwrap();
        let mut child = command.spawn().unwrap();
        let parent = child.id();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        ready(stdout.get_ref());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], "watchdog-started");
        let descendant = pidfd(fields[1].parse().unwrap());
        let leader = pidfd(parent);
        drop(child.stdin.take());
        ready(&leader); // The exited leader remains unreaped, independent of scheduling.
        let mut retained = false;
        let status = cancel_observed(&mut child, || {
            ready(&descendant); // Group death is an event, not a sleep or timing window.
            retained = std::path::Path::new(&format!("/proc/{parent}")).exists();
        })
        .unwrap();
        assert!(status.success());
        assert!(
            retained,
            "leader reaped before group cancellation completed"
        );
    }
}
