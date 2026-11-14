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

pub fn capture(mut command: Command, input: &[u8], limits: &Limits) -> Result<Vec<u8>> {
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
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ignored = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _ignored = child.wait();
    result
}
