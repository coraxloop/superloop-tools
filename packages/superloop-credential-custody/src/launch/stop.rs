//! Keeper-owned cooperative termination; metadata only, never signal forwarding.
use super::{Result, require};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use std::{cell::RefCell, os::fd::AsRawFd as _};

#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub(super) struct Request {
    pub signal: u32,
    pub sender_pid: u32,
    pub sender_uid: u32,
    pub later_consumed: u64,
}
struct Listener {
    fd: SignalFd,
    previous: SigSet,
    first: Option<Request>,
    recovery: bool,
}
thread_local! {
    static LISTENER: RefCell<Option<Listener>> = const {RefCell::new(None)};
}
pub(super) struct Guard {
    previous: SigSet,
    // The signal mask and listener belong to this thread.
    thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Guard {
    #[cfg(test)]
    pub fn finish(self) {
        let previous = self.previous;
        drop(self);
        pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None).unwrap();
    }
    pub fn install() -> Result<Self> {
        require(
            LISTENER.with(|s| s.borrow().is_none()),
            "campaign-stop-owner",
        )?;
        let mut watched = SigSet::empty();
        watched.add(Signal::SIGINT);
        watched.add(Signal::SIGTERM);
        let mut previous = SigSet::empty();
        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&watched), Some(&mut previous))
            .map_err(|e| crate::process::io_failure("campaign-stop-mask", e))?;
        let fd =
            match SignalFd::with_flags(&watched, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
                Ok(fd) => fd,
                Err(error) => {
                    let _restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None);
                    return Err(crate::process::io_failure(
                        "campaign-stop-descriptor",
                        error,
                    ));
                }
            };
        LISTENER.with(|s| {
            *s.borrow_mut() = Some(Listener {
                fd,
                previous,
                first: None,
                recovery: false,
            });
        });
        Ok(Self {
            previous,
            thread: std::marker::PhantomData,
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let stopped = LISTENER.with(|s| s.borrow_mut().take().is_some_and(|s| s.first.is_some()));
        // Keep later pending termination blocked through final diagnostic publication.
        if !stopped {
            let _restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.previous), None);
        }
    }
}
fn consume(listener: &mut Listener) -> Result<()> {
    // Standard signals may coalesce. Count consumed records, not sent signals;
    // a flooding sender cannot turn one checkpoint into an unbounded drain.
    for _ in 0..64 {
        let Some(info) = listener
            .fd
            .read_signal()
            .map_err(|e| crate::process::io_failure("campaign-stop-read", e))?
        else {
            break;
        };
        if let Some(first) = &mut listener.first {
            first.later_consumed = first.later_consumed.saturating_add(1);
        } else {
            listener.first = Some(Request {
                signal: info.ssi_signo,
                sender_pid: info.ssi_pid,
                sender_uid: info.ssi_uid,
                later_consumed: 0,
            });
        }
    }
    Ok(())
}
pub fn check() -> Result<()> {
    LISTENER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(listener) = slot.as_mut() else {
            return Ok(());
        };
        consume(listener)?;
        require(
            listener.recovery || listener.first.is_none(),
            "campaign-stopped",
        )
    })
}
pub(super) fn request() -> Option<Request> {
    LISTENER.with(|slot| slot.borrow().as_ref().and_then(|s| s.first.clone()))
}
pub(super) fn descriptor() -> Option<i32> {
    LISTENER.with(|slot| slot.borrow().as_ref().map(|s| s.fd.as_raw_fd()))
}
pub(super) fn recovering() {
    LISTENER.with(|slot| {
        if let Some(s) = slot.borrow_mut().as_mut() {
            s.recovery = true;
        }
    });
}

#[allow(unsafe_code)]
pub fn configure_child(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    let previous = LISTENER.with(|s| s.borrow().as_ref().map(|s| s.previous));
    if let Some(previous) = previous {
        // SAFETY: only the async-signal-safe mask operation runs after fork.
        // Register before the held-image exec hook, which never returns on success.
        unsafe {
            command.pre_exec(move || {
                pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None)
                    .map_err(std::io::Error::from)
            });
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    #[allow(unsafe_code)]
    pub(in crate::launch) fn send(signal: Signal) {
        // SAFETY: target this test thread only, never another libtest worker.
        assert_eq!(
            unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_tgkill,
                    nix::libc::getpid(),
                    nix::libc::syscall(nix::libc::SYS_gettid),
                    signal as i32,
                )
            },
            0
        );
    }
    /// ´test:unit:campaign-stop-first-request-wins-and-later-records-count´
    #[test]
    fn campaign_stop_first_request_wins_and_later_records_count() {
        let guard = Guard::install().unwrap();
        let previous = guard.previous;
        assert_eq!(Guard::install().err(), Some("campaign-stop-owner"));
        assert_eq!(check(), Ok(()));
        send(Signal::SIGTERM);
        assert_eq!(check(), Err("campaign-stopped"));
        let first = request().unwrap();
        assert_eq!(first.signal, 15);
        assert_eq!(
            first.sender_pid,
            nix::unistd::getpid().as_raw().cast_unsigned()
        );
        assert_eq!(first.sender_uid, nix::unistd::getuid().as_raw());
        assert_eq!(first.later_consumed, 0);
        send(Signal::SIGINT);
        assert_eq!(
            crate::launch::channel::poll(&mut [], 0),
            Err("campaign-stopped")
        );
        assert_eq!(request().unwrap().signal, 15);
        assert_eq!(request().unwrap().later_consumed, 1);
        recovering();
        assert_eq!(check(), Ok(()));
        drop(guard);
        pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&previous), None).unwrap();
    }
}
