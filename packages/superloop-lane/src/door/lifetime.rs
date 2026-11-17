//! One acceptance anchor and first stop for a request, distinct from cleanup time.

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) trait Clock: Send + Sync {
    fn now(&self) -> io::Result<Duration>;
}

struct BootClock;

impl Clock for BootClock {
    fn now(&self) -> io::Result<Duration> {
        let value = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
            .map_err(io::Error::other)?;
        Ok(Duration::new(
            u64::try_from(value.tv_sec()).map_err(io::Error::other)?,
            u32::try_from(value.tv_nsec()).map_err(io::Error::other)?,
        ))
    }
}

pub(super) struct Start {
    pub(super) awake: Instant,
    boot: Duration,
    clock: Arc<dyn Clock>,
}

impl Start {
    pub(super) fn now() -> io::Result<Self> {
        Self::at(Instant::now())
    }

    // Exercises already supply their acceptance instant. The service captures
    // both clocks at accept, before handing the connection to its thread.
    pub(super) fn at(awake: Instant) -> io::Result<Self> {
        let clock: Arc<dyn Clock> = Arc::new(BootClock);
        let boot = clock.now()?.saturating_sub(awake.elapsed());
        Ok(Self { awake, boot, clock })
    }

    pub(super) fn elapsed(&self) -> io::Result<Duration> {
        Ok(self.clock.now()?.saturating_sub(self.boot))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    Deadline,
    Disconnect,
    ObservationFailure,
    ChildExit,
    Refusal,
    Transport,
    HandlerFailure,
}

impl Cause {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Disconnect => "disconnect",
            Self::ObservationFailure => "observation-failure",
            Self::ChildExit => "child-exit",
            Self::Refusal => "refusal",
            Self::Transport => "transport",
            Self::HandlerFailure => "handler-failure",
        }
    }

    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::Deadline => "door-request-deadline",
            Self::Disconnect => "door-disconnect-refusal",
            Self::ObservationFailure => "door-stop-observation-refusal",
            Self::ChildExit => "door-complete",
            Self::Refusal => "door-request-refusal",
            Self::Transport => "door-transport-refusal",
            Self::HandlerFailure => "door-handler-ended",
        }
    }

    pub(super) fn for_reply(reason: &str) -> Self {
        match reason {
            "door-complete" => Self::ChildExit,
            "door-deadline-refusal" | "door-request-deadline" => Self::Deadline,
            "door-disconnect-refusal" => Self::Disconnect,
            "door-stop-observation-refusal" => Self::ObservationFailure,
            "door-transport-refusal" | "door-output-refusal" | "door-compute-io-refusal" => {
                Self::Transport
            }
            "door-handler-ended" => Self::HandlerFailure,
            _ => Self::Refusal,
        }
    }
}

/// All runtime ending causes pass through this cell; later evidence cannot replace one.
#[derive(Default)]
pub(super) struct FirstCause(Mutex<Option<Cause>>);

impl FirstCause {
    pub(super) fn select(&self, cause: Cause) -> Cause {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(cause)
    }

    pub(super) fn get(&self) -> Option<Cause> {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(super) struct Lifetime {
    start: Start,
    peer: UnixStream,
    full_close: bool,
    finished: AtomicBool,
}

impl Lifetime {
    pub(super) fn new(start: Start, peer: &UnixStream, full_close: bool) -> io::Result<Self> {
        Ok(Self {
            start,
            peer: peer.try_clone()?,
            full_close,
            finished: AtomicBool::new(false),
        })
    }

    pub(super) fn elapsed(&self) -> io::Result<Duration> {
        self.start.elapsed()
    }

    pub(super) fn remaining(&self, base: Instant, credit: Duration) -> io::Result<Duration> {
        let elapsed = self.start.elapsed()?;
        Ok(base
            .saturating_duration_since(self.start.awake)
            .saturating_add(credit)
            .saturating_sub(elapsed))
    }

    pub(super) fn poll(&self, base: Instant, credit: Duration) -> Option<Cause> {
        if self.finished.load(Ordering::Acquire) {
            return None;
        }
        match self.remaining(base, credit) {
            Err(_) => Some(Cause::ObservationFailure),
            Ok(left) if left.is_zero() => Some(Cause::Deadline),
            Ok(_) if self.full_close => match super::peer_disconnected(&self.peer) {
                Ok(true) => Some(Cause::Disconnect),
                Ok(false) => None,
                Err(_) => Some(Cause::ObservationFailure),
            },
            Ok(_) => None,
        }
    }

    pub(super) fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }

    pub(super) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}

#[cfg(test)]
pub(super) struct TestClock(std::sync::atomic::AtomicU64);

#[cfg(test)]
impl TestClock {
    pub(super) fn advance(&self, millis: u64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for TestClock {
    fn now(&self) -> io::Result<Duration> {
        Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}

#[cfg(test)]
impl Start {
    pub(super) fn controlled(awake: Instant) -> (Self, Arc<TestClock>) {
        let clock = Arc::new(TestClock(std::sync::atomic::AtomicU64::new(0)));
        (
            Self {
                awake,
                boot: Duration::ZERO,
                clock: clock.clone(),
            },
            clock,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:door-first-cause-never-replaces-an-observation´
    #[test]
    fn door_first_cause_never_replaces_an_observation() {
        for first in [
            Cause::Deadline,
            Cause::Disconnect,
            Cause::ChildExit,
            Cause::Refusal,
            Cause::Transport,
            Cause::HandlerFailure,
            Cause::ObservationFailure,
        ] {
            let cell = FirstCause::default();
            assert_eq!(cell.select(first), first);
            for later in [
                Cause::Deadline,
                Cause::Disconnect,
                Cause::Transport,
                Cause::HandlerFailure,
            ] {
                assert_eq!(
                    cell.select(later),
                    first,
                    "first {first:?}, later {later:?}"
                );
                assert_eq!(cell.get(), Some(first));
            }
        }
    }

    /// ´test:unit:door-boottime-expiry-keeps-awake-credit-capped´
    #[test]
    fn door_boottime_expiry_keeps_awake_credit_capped() {
        let (peer, server) = UnixStream::pair().expect("pair");
        let awake = Instant::now();
        let (start, clock) = Start::controlled(awake);
        let wait = crate::door::RequestWait::new(&server)
            .expect("wait")
            .with_lifetime(start, true, &server)
            .expect("lifetime");
        let end = awake + Duration::from_secs(30);
        wait.credit(Duration::from_secs(200));
        assert_eq!(wait.elapsed(), Duration::from_secs(120));
        let life = wait.lifetime.as_ref().expect("life");
        clock.advance(149_999);
        assert_eq!(
            life.remaining(end, wait.elapsed()).expect("remaining"),
            Duration::from_millis(1)
        );
        assert_eq!(wait.stop(end), None);
        clock.advance(1);
        assert_eq!(wait.stop(end), Some(Cause::Deadline));
        assert_eq!(wait.cause.get(), Some(Cause::Deadline));
        drop(peer);
        assert_eq!(
            wait.stop(end),
            Some(Cause::Deadline),
            "close cannot replace expiry"
        );
        let (peer, server) = UnixStream::pair().expect("second pair");
        let (start, clock) = Start::controlled(awake);
        let wait = crate::door::RequestWait::new(&server)
            .expect("wait")
            .with_lifetime(start, true, &server)
            .expect("lifetime");
        clock.advance(30_000);
        assert_eq!(wait.stop(end), Some(Cause::Deadline));
        wait.credit(Duration::from_secs(120));
        assert_eq!(
            wait.stop(end),
            Some(Cause::Deadline),
            "late credit cannot revive a stopped request"
        );
        drop(peer);
    }

    /// ´test:unit:door-full-close-excludes-half-close-and-git-lifetimes´
    #[test]
    fn door_full_close_excludes_half_close_and_git_lifetimes() {
        for cancellable in [true, false] {
            let (peer, server) = UnixStream::pair().expect("pair");
            let awake = Instant::now();
            let (start, clock) = Start::controlled(awake);
            let wait = crate::door::RequestWait::new(&server)
                .expect("wait")
                .with_lifetime(start, cancellable, &server)
                .expect("lifetime");
            let end = awake + Duration::from_secs(120);
            peer.shutdown(std::net::Shutdown::Write).expect("input EOF");
            assert_eq!(wait.stop(end), None, "half close is only EOF");
            drop(peer);
            assert_eq!(wait.stop(end), cancellable.then_some(Cause::Disconnect));
            clock.advance(120_000);
            assert_eq!(
                wait.stop(end),
                Some(if cancellable {
                    Cause::Disconnect
                } else {
                    Cause::Deadline
                })
            );
        }
    }

    /// ´test:unit:door-final-outcome-detaches-peer-close-from-advisory-work´
    #[test]
    fn door_final_outcome_detaches_peer_close_from_advisory_work() {
        let (peer, server) = UnixStream::pair().expect("pair");
        let awake = Instant::now();
        let (start, clock) = Start::controlled(awake);
        let wait = crate::door::RequestWait::new(&server)
            .expect("wait")
            .with_lifetime(start, true, &server)
            .expect("lifetime");
        wait.write_final(
            &serde_json::json!({"schema":2,"type":"final","reason":"door-complete","status":0}),
            awake + Duration::from_secs(120),
        )
        .expect("sent final");
        drop(peer);
        clock.advance(240_000);
        assert_eq!(
            wait.lifetime
                .as_ref()
                .expect("lifetime")
                .poll(awake + Duration::from_secs(120), Duration::ZERO),
            None
        );
        assert_eq!(wait.stop(awake + Duration::from_secs(120)), None);
        assert_eq!(wait.cause.get(), Some(Cause::ChildExit));
        assert_eq!(wait.ending_snapshot()["final_write"], "succeeded-locally");
    }
}
