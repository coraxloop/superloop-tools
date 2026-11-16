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

#[derive(Clone, Debug, serde::Serialize)]
struct KernelFailure {
    class: &'static str,
    errno: Option<i32>,
    open_descriptors: Option<usize>,
    // A fallback scan is bounded and explicitly identifies its covered range.
    descriptor_scan_ceiling: Option<u64>,
    nofile_soft: Option<u64>,
    nofile_hard: Option<u64>,
    process_threads: Option<usize>,
    test_threads: Option<usize>,
}
thread_local! {
    static KERNEL_FAILURE: std::cell::RefCell<Option<KernelFailure>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub fn test_threads() -> Option<usize> {
    static THREADS: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *THREADS.get_or_init(|| {
        let args: Vec<_> = std::env::args().collect();
        args.windows(2)
            .find(|pair| pair[0] == "--test-threads")
            .and_then(|pair| pair[1].parse().ok())
            .or_else(|| {
                args.iter()
                    .find_map(|arg| arg.strip_prefix("--test-threads=")?.parse().ok())
            })
            .or_else(|| std::env::var("RUST_TEST_THREADS").ok()?.parse().ok())
            .or_else(|| {
                std::thread::available_parallelism()
                    .ok()
                    .map(std::num::NonZeroUsize::get)
            })
    })
}

fn directory_count(path: &str) -> Option<usize> {
    std::fs::read_dir(path)
        .ok()?
        .try_fold(0, |count, entry| entry.map(|_| count + 1))
        .ok()
}

#[allow(unsafe_code)]
fn resource_failure(class: &'static str, errno: Option<i32>) -> KernelFailure {
    let mut limits = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one initialized stack object; fcntl below only
    // queries numeric descriptors and never closes or acquires an object.
    let observed = unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_NOFILE, &raw mut limits) } == 0;
    let mut scan = None;
    let descriptors = directory_count("/proc/self/fd")
        .map(|n| n.saturating_sub(1))
        .or_else(|| {
            // EMFILE must not hide the count. Scan without acquiring a descriptor.
            // A lowered hard limit or a larger kernel ceiling can leave higher
            // descriptors outside this range; report the range, never claim an
            // atomic or exhaustive process-wide snapshot in that case.
            let ceiling = if observed {
                limits.rlim_max.min(1_048_576)
            } else {
                1_048_576
            };
            scan = Some(ceiling);
            Some(
                (0..i32::try_from(ceiling).ok()?)
                    .filter(|fd| unsafe { nix::libc::fcntl(*fd, nix::libc::F_GETFD) } >= 0)
                    .count(),
            )
        });
    KernelFailure {
        class,
        errno,
        open_descriptors: descriptors,
        descriptor_scan_ceiling: scan,
        nofile_soft: observed.then_some(limits.rlim_cur),
        nofile_hard: observed.then_some(limits.rlim_max),
        process_threads: directory_count("/proc/self/task"),
        test_threads: {
            #[cfg(test)]
            {
                test_threads()
            }
            #[cfg(not(test))]
            {
                None
            }
        },
    }
}

/// Preserve numeric kernel/resource evidence at the failing operation, without
/// copying its path, arguments, foreign error text or child diagnostics.
pub fn io_failure(class: &'static str, error: impl Into<std::io::Error>) -> &'static str {
    let failure = resource_failure(class, error.into().raw_os_error());
    #[cfg(test)]
    let _diagnostic = superloop_cli_common::emit_control_plane_record(
        &superloop_cli_common::ControlPlaneRecord::diagnostic(
            "superloop-credential-custody-test",
            &serde_json::to_string(&failure).unwrap_or_default(),
        ),
    );
    KERNEL_FAILURE.with(|slot| *slot.borrow_mut() = Some(failure));
    class
}

pub fn diagnostic_message(class: &'static str) -> String {
    let failure = KERNEL_FAILURE.with(|slot| slot.borrow_mut().take());
    failure
        .and_then(|value| serde_json::to_string(&value).ok())
        .map_or_else(
            || class.into(),
            |context| format!("{class}; kernel={context}"),
        )
}

pub fn spawn(command: &mut Command, class: &'static str) -> Result<std::process::Child> {
    command.spawn().map_err(|error| io_failure(class, error))
}

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
    let mut child = spawn(&mut command, "child-start")?;
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

/// Cancel descendants by group and the retained leader independently of its group.
pub fn cancel_pinned(
    child: &mut std::process::Child,
    pidfd: std::os::fd::BorrowedFd<'_>,
) -> Option<std::process::ExitStatus> {
    cancel_targets(child.id(), pidfd, kill_pidfd);
    child.wait().ok()
}
fn cancel_targets(
    pid: u32,
    pidfd: std::os::fd::BorrowedFd<'_>,
    send: impl FnOnce(std::os::fd::BorrowedFd<'_>),
) {
    if let Ok(pid) = i32::try_from(pid) {
        let _ignored = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    send(pidfd);
}
#[allow(unsafe_code)]
fn kill_pidfd(pidfd: std::os::fd::BorrowedFd<'_>) {
    use std::os::fd::AsRawFd as _;
    // SAFETY: the caller retains this leader pidfd through wait; no PID fallback.
    let _ignored = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            nix::libc::SIGKILL,
            std::ptr::null::<u8>(),
            0,
        )
    };
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
    // Child remains unreaped, so its PID cannot have been recycled. This path
    // covers setup failure before the sealer has acquired its retained pidfd.
    let _leader = child.kill();
    after_kill();
    child.wait().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::BufRead as _;
    use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::ExitStatusExt as _;

    fn kernel_context(class: &'static str) -> serde_json::Value {
        let message = diagnostic_message(class);
        let (actual, context) = message
            .split_once("; kernel=")
            .expect("kernel context retained");
        assert_eq!(actual, class);
        serde_json::from_str(context).unwrap()
    }

    /// ´test:unit:open-and-spawn-refusals-retain-kernel-context´
    #[test]
    fn open_and_spawn_refusals_retain_kernel_context() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert_eq!(
            crate::receipt::open(&missing, false).err(),
            Some("path-open")
        );
        let opened = kernel_context("path-open");
        assert_eq!(opened["class"], "path-open");
        assert_eq!(opened["errno"], nix::libc::ENOENT);
        assert!(opened["open_descriptors"].as_u64().unwrap() >= 3);
        assert!(
            opened["nofile_soft"].as_u64().unwrap() >= opened["open_descriptors"].as_u64().unwrap()
        );
        assert!(opened["nofile_hard"].as_u64().unwrap() >= opened["nofile_soft"].as_u64().unwrap());
        assert!(opened["process_threads"].as_u64().unwrap() > 0);
        assert!(opened["test_threads"].as_u64().unwrap() > 0);
        assert_eq!(
            spawn(&mut Command::new(&missing), "child-start")
                .err()
                .unwrap(),
            "child-start"
        );
        let spawned = kernel_context("child-start");
        assert_eq!(spawned["errno"], nix::libc::ENOENT);
        assert_eq!(spawned["class"], "child-start");
        assert!(
            !serde_json::to_string(&spawned)
                .unwrap()
                .contains(missing.to_str().unwrap())
        );
        assert_eq!(diagnostic_message("another-refusal"), "another-refusal");
    }

    /// ´test:unit:descriptor-exhaustion-keeps-numeric-failure-evidence´
    #[test]
    #[allow(unsafe_code)]
    fn descriptor_exhaustion_keeps_numeric_failure_evidence() {
        const CHILD: &str = "CUSTODY_DESCRIPTOR_CONTROL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert_eq!(test_threads(), Some(1));
            let limits = nix::libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            // SAFETY: this is a dedicated subprocess test; no other test runs
            // here and its lowered hard limit dies with this process.
            assert_eq!(
                unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &raw const limits) },
                0
            );
            let mut held = Vec::new();
            while let Ok(file) = fs::File::open("/dev/null") {
                held.push(file);
            }
            assert_eq!(
                crate::receipt::open(std::path::Path::new("/"), true).err(),
                Some("path-root")
            );
            let evidence = kernel_context("path-root");
            drop(held);
            assert_eq!(evidence["errno"], nix::libc::EMFILE);
            assert_eq!(evidence["open_descriptors"], 64);
            assert_eq!(evidence["descriptor_scan_ceiling"], 64);
            assert_eq!(evidence["nofile_soft"], 64);
            assert_eq!(evidence["nofile_hard"], 64);
            assert_eq!(evidence["test_threads"], 1);
            return;
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "process::tests::descriptor_exhaustion_keeps_numeric_failure_evidence",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1");
        loop_home::CommandDescriptors::default()
            .configure(&mut command)
            .unwrap();
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
    }

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
    #[allow(unsafe_code)]
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
    #[allow(unsafe_code)]
    fn pidfd(pid: u32) -> OwnedFd {
        // SAFETY: pidfd_open returns a new descriptor on success.
        let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) }
    }
    /// ´test:unit:group-leader-is-not-reaped-before-cancellation´
    #[test]
    #[allow(unsafe_code)]
    fn group_leader_is_not_reaped_before_cancellation() {
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
        let mut leader_signalled = false;
        cancel_targets(parent, leader.as_fd(), |fd| {
            leader_signalled = true;
            kill_pidfd(fd);
        });
        assert!(leader_signalled, "retained leader pidfd must be signalled");
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
    /// ´test:unit:retained-pidfd-cancels-a-leader-after-group-escape´
    #[test]
    fn retained_pidfd_cancels_a_leader_after_group_escape() {
        // A live leader deliberately leaves its dedicated group before readiness.
        // The injected sender counter fails before waiting if the pidfd leg is removed.
        let mut escaped_command = Command::new("/usr/bin/python3");
        escaped_command.args(["-I", "-c", "import os,sys\nos.setpgid(0,os.getpgid(os.getppid()))\nprint('escaped',flush=True)\nsys.stdin.buffer.read()\n"])
            .process_group(0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        loop_home::CommandDescriptors::default()
            .configure(&mut escaped_command)
            .unwrap();
        pin_program(&mut escaped_command, &[]).unwrap();
        let mut escaped = escaped_command.spawn().unwrap();
        let escaped_pin = pidfd(escaped.id());
        let mut output = std::io::BufReader::new(escaped.stdout.take().unwrap());
        ready(output.get_ref());
        let mut event = String::new();
        output.read_line(&mut event).unwrap();
        assert_eq!(event, "escaped\n");
        let mut sent = false;
        cancel_targets(escaped.id(), escaped_pin.as_fd(), |fd| {
            sent = true;
            kill_pidfd(fd);
        });
        if !sent {
            let _cleanup = escaped.kill();
        }
        assert!(
            sent,
            "retained leader pidfd must be signalled after group escape"
        );
        ready(&escaped_pin);
        assert_eq!(escaped.wait().unwrap().signal(), Some(nix::libc::SIGKILL));
    }
}
