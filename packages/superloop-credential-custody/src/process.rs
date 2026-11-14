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
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ignored = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
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
}
