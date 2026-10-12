use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};

use super::store::{readable_directory, stat};
use super::{io_error, open_beneath, path_error};
use crate::LoopError;

pub(super) enum Ready {
    Rescan,
    Stop,
}

#[cfg(test)]
thread_local! {
    pub(super) static ARM_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static SUPPRESS_NOTICE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) struct Wake {
    // Dedicated open descriptions: closing fdopendir's scanning duplicate must
    // not cancel a dnotify mark on the same open description.
    new: OwnedFd,
    inbox: OwnedFd,
    signals: Signals,
}

pub(super) struct Signals {
    fd: SignalFd,
    previous: SigSet,
}

impl Wake {
    pub fn new(inbox: &OwnedFd, new: &OwnedFd) -> Result<Self, LoopError> {
        let inbox = readable_directory(inbox)?;
        let new = readable_directory(new)?;
        let signals = Signals::new()?;
        let wake = Self {
            new,
            inbox,
            signals,
        };
        arm(&wake.inbox, "inbox")?;
        arm(&wake.new, "inbox/new")?;
        Ok(wake)
    }

    pub fn attached(&self) -> Result<bool, LoopError> {
        let named = match open_beneath(
            &self.inbox,
            Path::new("new"),
            OFlag::O_PATH | OFlag::O_DIRECTORY,
            0,
        ) {
            Ok(fd) => fd,
            Err(
                nix::errno::Errno::ENOENT | nix::errno::Errno::ENOTDIR | nix::errno::Errno::ELOOP,
            ) => return Ok(false),
            Err(error) => return Err(path_error(Path::new("inbox/new"), error)),
        };
        let held = stat(&self.new)?;
        let named = stat(&named)?;
        Ok(held.st_nlink != 0 && (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino))
    }

    fn drain(&self) -> Result<Option<Ready>, LoopError> {
        let mut ready = None;
        while let Some(signal) = self.signals.fd.read_signal().map_err(io_error)? {
            if signal.ssi_signo == Signal::SIGTERM as u32 {
                ready = Some(Ready::Stop);
            } else if !matches!(ready, Some(Ready::Stop)) {
                // SIGIO coalesces notices (including notification queue overflow).
                // No signal payload, count or filename is treated as evidence.
                ready = Some(Ready::Rescan);
            }
        }
        Ok(ready)
    }

    #[allow(unsafe_code)]
    pub fn wait(&self, duration: Duration) -> Result<Ready, LoopError> {
        let start = Instant::now();
        loop {
            if let Some(ready) = self.drain()? {
                #[cfg(test)]
                let suppressed = matches!(ready, Ready::Rescan) && SUPPRESS_NOTICE.replace(false);
                #[cfg(not(test))]
                let suppressed = false;
                if !suppressed {
                    return Ok(ready);
                }
            }
            let timeout = duration.saturating_sub(start.elapsed()).as_millis();
            let mut descriptor = libc::pollfd {
                fd: self.signals.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll receives one initialized, live descriptor entry.
            let result = unsafe {
                libc::poll(
                    &raw mut descriptor,
                    1,
                    timeout.try_into().map_err(io_error)?,
                )
            };
            if result == 0 {
                return Ok(Ready::Rescan);
            }
            if result < 0 {
                let error = nix::errno::Errno::last();
                if error == nix::errno::Errno::EINTR {
                    continue;
                }
                return Err(io_error(error));
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io_error("letters follow signal descriptor failed"));
            }
        }
    }
}

impl Drop for Wake {
    fn drop(&mut self) {
        disarm(&self.new);
        disarm(&self.inbox);
    }
}

impl Signals {
    pub fn new() -> Result<Self, LoopError> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGIO);
        mask.add(Signal::SIGTERM);
        let mut previous = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous))
            .map_err(io_error)?;
        let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
            .map_err(io_error)?;
        Ok(Self {
            fd: signals,
            previous,
        })
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        #[cfg(test)]
        super::store::race("follow-stopping");
        while matches!(self.fd.read_signal(), Ok(Some(_))) {}
        // Retain TERM through the helper's actions report and process exit.
        let mut restored = self.previous;
        restored.add(Signal::SIGTERM);
        let _restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&restored), None);
    }
}

#[allow(unsafe_code)]
pub(super) fn arm(fd: &OwnedFd, name: &str) -> Result<(), LoopError> {
    // Linux asm-generic/fcntl.h: F_SETOWN_EX=15, F_OWNER_TID=0.
    // libc exposes F_NOTIFY but not the extended-owner ABI on glibc targets.
    #[repr(C)]
    struct Owner {
        kind: libc::c_int,
        tid: libc::pid_t,
    }
    #[cfg(test)]
    ARM_COUNT.set(ARM_COUNT.get() + 1);
    let owner = Owner {
        kind: 0,
        tid: nix::unistd::gettid().as_raw(),
    };
    // DN_CREATE | DN_DELETE | DN_RENAME | DN_ATTRIB | DN_MULTISHOT.
    // Create and rename cover publication's move into the watched directory;
    // the parent mark wakes for replacement, rename or deletion of new itself.
    let events: libc::c_long = 0x8000_003c;
    // SAFETY: the descriptor is live and the extended-owner argument matches
    // Linux's f_owner_ex layout. Notifications target this blocked thread.
    let result = unsafe {
        if libc::fcntl(fd.as_raw_fd(), 15, &raw const owner) < 0 {
            -1
        } else {
            libc::fcntl(fd.as_raw_fd(), libc::F_NOTIFY, events)
        }
    };
    if result < 0 {
        return Err(io_error(format!(
            "letters follow watch {name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn disarm(fd: &OwnedFd) {
    // SAFETY: zero removes this descriptor's dnotify subscription.
    let _removed = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_NOTIFY, 0) };
}
