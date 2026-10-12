use std::io;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

use nix::sys::signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, getpgid, getpgrp, getsid, tcgetpgrp, tcsetpgrp};

/// The binary is single threaded when it arms this guard, before spawning.
pub(super) struct Signals {
    fd: SignalFd,
    previous: SigSet,
    watched: SigSet,
    forwarded: Option<Signal>,
    foreground: Option<Pid>,
    child_group: Option<Pid>,
    pub(super) stop_report: Option<PathBuf>,
    pub(super) relay: bool,
}

// The directory is owner-only; the private UID cannot replace provenance.
// Its path travels as a literal script argument, never an inherited variable.
pub(super) struct StopReport(PathBuf);

impl StopReport {
    pub(super) fn create(path: &Path) -> io::Result<Self> {
        let directory = path
            .parent()
            .ok_or_else(|| io::Error::other("stop report has no parent"))?;
        std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        let guard = Self(path.to_path_buf());
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(guard)
    }
}

impl Drop for StopReport {
    fn drop(&mut self) {
        let _file = std::fs::remove_file(&self.0);
        if let Some(directory) = self.0.parent() {
            let _directory = std::fs::remove_dir(directory);
        }
    }
}

fn io_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[allow(unsafe_code)]
pub(super) fn watched_bits() -> io::Result<u32> {
    let mut bits = 0;
    for signal in [
        Signal::SIGTERM,
        Signal::SIGINT,
        Signal::SIGHUP,
        Signal::SIGQUIT,
    ] {
        // SAFETY: querying a valid signal only reads the caller's disposition.
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        if unsafe { libc::sigaction(signal as i32, std::ptr::null(), &raw mut action) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_IGN {
            bits |= 1 << (signal as u32 - 1);
        }
    }
    Ok(bits)
}

impl Signals {
    #[allow(unsafe_code)]
    pub(super) fn new(watched: Option<&str>) -> io::Result<Self> {
        let selected = watched
            .map(str::parse::<u32>)
            .transpose()
            .map_err(io::Error::other)?;
        let mut mask = SigSet::empty();
        for signal in [
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ] {
            // SAFETY: sigaction only reads the calling process's disposition.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            if unsafe { libc::sigaction(signal as i32, std::ptr::null(), &raw mut action) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if selected.map_or(action.sa_sigaction != libc::SIG_IGN, |bits| {
                bits & (1 << (signal as u32 - 1)) != 0
            }) {
                mask.add(signal);
            }
        }
        let mut previous = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous))
            .map_err(io_error)?;
        match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
            Ok(fd) => Ok(Self {
                fd,
                previous,
                watched: mask,
                forwarded: None,
                child_group: None,
                stop_report: None,
                relay: false,
                foreground: tcgetpgrp(io::stdin())
                    .ok()
                    .filter(|group| *group == getpgrp()),
            }),
            Err(error) => {
                let _restore = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
                Err(io_error(error))
            }
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn prepare(&self, command: &mut Command) {
        let previous = self.previous;
        let watched = self.watched;
        let foreground = self.foreground.is_some();
        command.process_group(0);
        // SAFETY: the post-fork callback uses only signal and terminal
        // syscalls. It performs no allocation and touches no Rust locks.
        unsafe {
            command.pre_exec(move || {
                // Undo only the asynchronous shell job's INT/QUIT artifact,
                // and only when the owner did not inherit an ignored action.
                for signal in [Signal::SIGINT, Signal::SIGQUIT] {
                    if watched.contains(signal)
                        && libc::signal(signal as i32, libc::SIG_DFL) == libc::SIG_ERR
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                if foreground {
                    let mut blocked = SigSet::empty();
                    blocked.add(Signal::SIGTTOU);
                    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), None)
                        .map_err(io_error)?;
                    // The private group must still be able to read inherited stdin.
                    if libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp()) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None).map_err(io_error)
            });
        }
    }

    fn stop_signal(&self, observed: Signal) -> io::Result<Signal> {
        let Some(path) = &self.stop_report else {
            return Ok(observed);
        };
        if self.relay {
            Ok(observed)
        } else {
            let value = std::fs::read_to_string(path)?;
            if value.is_empty() {
                // A direct external stop did not originate in the private command.
                return Ok(observed);
            }
            let signal = value
                .trim()
                .parse::<i32>()
                .ok()
                .and_then(|number| Signal::try_from(number).ok())
                .filter(|signal| {
                    matches!(
                        signal,
                        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                    )
                })
                .ok_or_else(|| io::Error::other("relay-stop: malformed stop report"))?;
            // Consume before resuming the relay so a later external stop cannot
            // reuse this event's provenance.
            std::fs::write(path, b"")?;
            Ok(signal)
        }
    }

    pub(super) fn wait(&mut self, child: &mut Child) -> io::Result<i32> {
        let group = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
        self.child_group = Some(group);
        loop {
            while let Some(info) = self.fd.read_signal().map_err(io_error)? {
                let number = i32::try_from(info.ssi_signo).map_err(io::Error::other)?;
                let signal = Signal::try_from(number).map_err(io_error)?;
                self.forwarded.get_or_insert(signal);
                // At the owner boundary this reaches the namespace-root relay.
                // There the same operation has permission over the switched UID.
                match killpg(group, signal) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(error) => return Err(io_error(error)),
                }
            }
            if let WaitStatus::Stopped(_, signal) =
                match waitid(Id::Pid(group), WaitPidFlag::WSTOPPED | WaitPidFlag::WNOHANG) {
                    Ok(status) => status,
                    // An exited child has no eligible stop event; try_wait
                    // below owns the exit status and reaps it exactly once.
                    Err(nix::errno::Errno::ECHILD) => WaitStatus::StillAlive,
                    Err(error) => return Err(io_error(error)),
                }
            {
                let signal = self.stop_signal(signal)?;
                // Let pending termination reach a background reader without
                // overriding explicit stops or skipping the poll pace.
                let terminating_reader =
                    self.forwarded.is_some() && matches!(signal, Signal::SIGTTIN | Signal::SIGTTOU);
                if !terminating_reader {
                    if tcgetpgrp(io::stdin()).ok() == Some(group) {
                        set_foreground(getpgrp())?;
                    }
                    if self.relay {
                        let path = self
                            .stop_report
                            .as_ref()
                            .ok_or_else(|| io::Error::other("relay-stop: missing report"))?;
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(path)?;
                        writeln!(file, "{}", signal as i32)?;
                    }
                    // Podman's rootless parent proxies terminal stop signals.
                    // The relay has published provenance before this uncatchable
                    // transport stop; only the owner chooses the caller's stop.
                    let stop = if self.relay || signal == Signal::SIGSTOP || orphaned_group()? {
                        Signal::SIGSTOP
                    } else {
                        signal
                    };
                    killpg(getpgrp(), stop).map_err(io_error)?;
                    if tcgetpgrp(io::stdin()).ok() == Some(getpgrp()) {
                        set_foreground(group)?;
                    }
                }
                killpg(group, Signal::SIGCONT).map_err(io_error)?;
            }
            if let Some(status) = child.try_wait()? {
                return Ok(self
                    .forwarded
                    .map_or_else(|| status_code(status), |signal| -(signal as i32)));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn orphaned_group() -> io::Result<bool> {
    let group = getpgrp();
    let session = getsid(None).map_err(io_error)?;
    // A group is orphaned only when no member has a parent in a different
    // group of this session. Checking our own parent alone misses a wrapper
    // or the outer shell in the same group as this waiter.
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        match getpgid(Some(Pid::from_raw(pid))) {
            Ok(member_group) if member_group == group => {}
            Ok(_) | Err(nix::errno::Errno::ESRCH) => continue,
            Err(error) => return Err(io_error(error)),
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut fields = stat
            .rsplit_once(") ")
            .ok_or_else(|| io::Error::other("process stat missing fields"))?
            .1
            .split_whitespace();
        if fields.next() == Some("Z") {
            continue;
        }
        let parent = fields
            .next()
            .ok_or_else(|| io::Error::other("process stat missing parent"))?
            .parse::<i32>()
            .map_err(io::Error::other)?;
        if parent == 0 {
            continue;
        }
        let parent = Some(Pid::from_raw(parent));
        match (getpgid(parent), getsid(parent)) {
            (Ok(parent_group), Ok(parent_session)) => {
                if parent_group != group && parent_session == session {
                    return Ok(false);
                }
            }
            (Err(nix::errno::Errno::ESRCH), _) | (_, Err(nix::errno::Errno::ESRCH)) => {}
            (Err(error), _) | (_, Err(error)) => return Err(io_error(error)),
        }
    }
    Ok(true)
}

fn set_foreground(group: Pid) -> io::Result<()> {
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTTOU);
    let mut previous = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut previous))
        .map_err(io_error)?;
    let result = tcsetpgrp(io::stdin(), group).map_err(io_error);
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None).map_err(io_error)?;
    result
}

fn status_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(1))
}

impl Drop for Signals {
    fn drop(&mut self) {
        if self
            .child_group
            .is_some_and(|group| tcgetpgrp(io::stdin()).ok() == Some(group))
        {
            let _foreground = set_foreground(getpgrp());
        }
        // Once stopping, keep termination blocked through trailer publication.
        // A second timeout signal must not cut off the report after reaping.
        if self.forwarded.is_none() {
            let _restore = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.previous), None);
        }
    }
}
