//! The registered socket boundary for outward worker calls.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::stat::{SFlag, fstat};
use serde_json::{Value, json};

use crate::error::LaneError;
use crate::requests::{RequestRecord, modes::Rubric, store::Store};

pub mod agent;
mod agent_exercise;
mod agent_probes;
pub mod config;
mod lifetime;
pub mod metadata;
#[allow(dead_code)] // The serving caller is the next W3 cut.
pub(crate) mod workspace_adapter;
mod workspace_tables;
pub use workspace::{
    WorkspaceAllowance, WorkspaceIntent, WorkspaceLearned, WorkspaceRequest, workspace_request,
};

/// Print the canonical digests of a loop's protected workspace policy bodies.
///
/// # Errors
/// Refuses an invalid loop name, unsafe configuration directory or malformed table.
pub fn workspace_digests(owner_home: &Path, loop_name: &str) -> Result<String, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("door-workspace-context-differs", error.message()))?;
    let owner = nix::unistd::Uid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(loop_name);
    let directory = crate::pinned::open_protected(owner_home, &config, owner)?;
    let (quick, blacklist) = workspace_tables::digests(&directory, owner)?;
    Ok(format!(
        "[workspace_policy]\nquick_policy_digest = \"{quick}\"\nblacklist_digest = \"{blacklist}\""
    ))
}

/// Format the final door reply for the SSH command boundary.
#[must_use]
pub fn final_line(args: &[std::ffi::OsString], reply: &serde_json::Value) -> Option<String> {
    let reason = reply["reason"].as_str().unwrap_or("door-response-refusal");
    if args.len() == 1
        && matches!(
            args[0].to_str(),
            Some(
                "door-attribution-probe" | "door-attribution-status" | "door-attribution-deadline"
            )
        )
    {
        Some(reply.to_string())
    } else if let Some(next) = reply["next_step"].as_str() {
        let bounds = if reply["registered_deadline_ms"].is_u64() {
            format!(
                "registered_deadline_ms={} request_deadline_ms={}; ",
                reply["registered_deadline_ms"], reply["request_deadline_ms"]
            )
        } else {
            String::new()
        };
        let diagnostic = reply["request_record_error"]
            .as_str()
            .map_or_else(String::new, |cause| format!("; {cause}"));
        Some(format!(
            "{reason}: {bounds}stop_cause={}; {next}{diagnostic}",
            reply["stop_cause"].as_str().unwrap_or("unobserved")
        ))
    } else if reason == "door-output-limit-refusal" {
        Some(format!(
            "{reason} bound={} output_bytes={} registered={}",
            reply["bound"],
            reply["output_bytes"],
            reply["registered"].as_str().unwrap_or("unrecorded")
        ))
    } else if args.len() == 2
        && !args[1].as_encoded_bytes().starts_with(b"git-")
        && matches!(
            reason,
            "door-compute-words-refusal"
                | "door-compute-wrapper-refusal"
                | "door-compute-settings-refusal"
                | "door-compute-command-refusal"
                | "door-compute-locked-refusal"
        )
    {
        Some(format!(
            "{reason} check={reason} mediation_wall={}s{}",
            reply["mediation_wall_seconds"],
            reply["request_record_error"]
                .as_str()
                .map_or_else(String::new, |cause| format!(": {cause}"))
        ))
    } else if reason == "door-capacity-refusal"
        && reply["peer_limit"].as_u64().is_some()
        && reply["retry_after_seconds"].as_u64().is_some()
    {
        Some(format!(
            "{reason}: peer_limit={} retry_after={}s; no request was dispatched",
            reply["peer_limit"], reply["retry_after_seconds"]
        ))
    } else if matches!(reason, "door-request-deadline" | "door-deadline-refusal")
        && reply["registered_deadline_ms"].is_u64()
    {
        Some(format!(
            "{reason}: registered_deadline_ms={} request_deadline_ms={}",
            reply["registered_deadline_ms"], reply["request_deadline_ms"]
        ))
    } else if reason == "door-request-concurrent" {
        Some(format!(
            "{reason}: waited={}s retry_after={}s; {}",
            reply["waited_seconds"],
            reply["retry_after_seconds"],
            admission_window()
        ))
    } else if let Some(cause) = reply["request_record_error"].as_str() {
        Some(format!("{reason}: {cause}"))
    } else if reason != "door-complete" {
        Some(reason.to_owned())
    } else {
        None
    }
}

/// Exercise the agent tier through the ordinary request handler.
///
/// Reports unavailable fixture custody, mode grants and changed registration as evidence.
pub(crate) fn exercise_agent(owner_home: &Path, registration: &Registration) -> Value {
    agent_exercise::measure(owner_home, registration)
}

const FRAME_LIMIT: usize = 65_536;
pub const INPUT_LIMIT: usize = 16 * 1024 * 1024;
const PEER_DEADLINE: Duration = Duration::from_secs(10);
const MAX_PEERS: usize = 16;
const CAPACITY_RETRY_SECONDS: u64 = 120;
const ADMISSION_WAIT: Duration = Duration::from_secs(30);
const ADMISSION_POLL: Duration = Duration::from_millis(100);
const ADMISSION_REPLY_MARGIN: Duration = Duration::from_secs(2);
pub(crate) const FULL_STORE_REASON_PREFIX: &str = "door-requests-full-refusal: ";
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Credit measured contention sleeps, never arbitrary work, up to one bounded
// extra window per request. The shared writer keeps progress frames whole even
// when an allow-mode agent publishes beside effect output.
#[cfg(test)]
type WaitingClaimHook = Box<dyn FnOnce(&Arc<RequestWait>)>;

#[cfg(test)]
thread_local! {
    static WAIT_CREDIT_OBSERVED: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_TERMINAL_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static WAIT_CREDIT_CAP: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static POST_REPLY_EVENTS: std::cell::RefCell<Vec<Value>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(crate) const MAX_LOCK_WAIT_CREDIT_MS: u64 = 120_000;
pub(crate) struct RequestWait {
    writer: std::sync::Arc<std::sync::Mutex<transport::Writer>>,
    micros: AtomicU64,
    cap_ms: u64,
    announced: std::sync::Mutex<u64>,
    final_sent: AtomicBool,
    ending: std::sync::Mutex<Value>,
    observed_effect: std::sync::Mutex<Option<Value>>,
    lifetime: Option<lifetime::Lifetime>,
    cause: Arc<lifetime::FirstCause>,
}

impl RequestWait {
    fn remember_effect(&self, effect: Value) {
        *self
            .observed_effect
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(effect);
    }

    pub(crate) fn new(stream: &UnixStream) -> io::Result<Self> {
        let cap_ms = MAX_LOCK_WAIT_CREDIT_MS;
        #[cfg(test)]
        let cap_ms = WAIT_CREDIT_CAP
            .with(std::cell::Cell::take)
            .unwrap_or(cap_ms);
        let mut ending = crate::requests::unobserved_ending();
        ending["wall_clock"] = json!("monotonic-awake");
        Ok(Self {
            writer: std::sync::Arc::new(std::sync::Mutex::new(transport::Writer::new(
                stream.try_clone()?,
            ))),
            micros: AtomicU64::new(0),
            cap_ms,
            announced: std::sync::Mutex::new(0),
            final_sent: AtomicBool::new(false),
            ending: std::sync::Mutex::new(ending),
            observed_effect: std::sync::Mutex::new(None),
            lifetime: None,
            cause: Arc::new(lifetime::FirstCause::default()),
        })
    }

    pub(crate) const fn maximum_credit(&self) -> Duration {
        Duration::from_millis(self.cap_ms)
    }

    pub(crate) fn elapsed(&self) -> Duration {
        Duration::from_micros(self.micros.load(Ordering::Relaxed).min(self.cap_ms * 1000))
    }

    pub(crate) fn deadline(&self, base: Instant) -> Instant {
        self.lifetime.as_ref().map_or_else(
            || base + self.elapsed(),
            |life| Instant::now() + life.remaining(base, self.elapsed()).unwrap_or_default(),
        )
    }

    fn with_lifetime(
        mut self,
        start: lifetime::Start,
        full_close: bool,
        stream: &UnixStream,
    ) -> io::Result<Self> {
        self.lifetime = Some(lifetime::Lifetime::new(start, stream, full_close)?);
        Ok(self)
    }

    pub(crate) fn stop_reason(&self, base: Instant) -> Option<&'static str> {
        self.stop(base).map(lifetime::Cause::reason)
    }

    fn stop(&self, base: Instant) -> Option<lifetime::Cause> {
        let life = self.lifetime.as_ref()?;
        if life.finished() {
            return None;
        }
        if let Some(first) = self.cause.get() {
            return matches!(
                first,
                lifetime::Cause::Deadline
                    | lifetime::Cause::Disconnect
                    | lifetime::Cause::ObservationFailure
            )
            .then_some(first);
        }
        let candidate = life.poll(base, self.elapsed())?;
        let first = self.cause.select(candidate);
        matches!(
            first,
            lifetime::Cause::Deadline
                | lifetime::Cause::Disconnect
                | lifetime::Cause::ObservationFailure
        )
        .then_some(first)
    }

    fn ending_snapshot(&self) -> Value {
        let mut ending = self
            .ending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(cause) = self.cause.get() {
            ending["cause"] = json!(cause.name());
        }
        ending
    }

    pub(crate) fn credit(&self, elapsed: Duration) {
        let extra = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let mut previous = self.micros.load(Ordering::Relaxed);
        loop {
            let next = previous.saturating_add(extra);
            match self.micros.compare_exchange_weak(
                previous,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => previous = current,
            }
        }
        let total = (self.micros.load(Ordering::Relaxed) / 1000).min(self.cap_ms);
        let mut announced = self
            .announced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if total.saturating_sub(*announced) >= 50 {
            let frame = json!({"schema":2,"type":"request-lock-wait","wait_ms":total});
            #[cfg(test)]
            BEFORE_CREDIT_WRITE.with(|slot| {
                if let Some(action) = slot.borrow_mut().take() {
                    action();
                }
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let _sent = transport::with_writer(&self.writer, deadline, |stream| {
                if self.final_sent.load(Ordering::Relaxed) || stream.sealed {
                    return Ok(());
                }
                frame_write_until(&mut stream.stream, &frame, deadline)
            });
            *announced = total;
            // A fixture may release its holder only after the progress frame.
            #[cfg(test)]
            {
                drop(announced);
                WAIT_CREDIT_OBSERVED.with(|slot| {
                    if let Some(sender) = slot.borrow_mut().take() {
                        let _sent = sender.send(());
                    }
                });
            }
        }
    }

    fn final_remaining(&self, base: Instant) -> io::Result<Duration> {
        if matches!(
            self.cause.get(),
            Some(
                lifetime::Cause::Deadline
                    | lifetime::Cause::Disconnect
                    | lifetime::Cause::ObservationFailure
            )
        ) {
            return Ok(Duration::ZERO);
        }
        self.lifetime.as_ref().map_or_else(
            || {
                Ok(self
                    .deadline(base)
                    .saturating_duration_since(Instant::now()))
            },
            |life| life.remaining(base, self.elapsed()),
        )
    }

    fn write_final(&self, reply: &Value, deadline: Instant) -> io::Result<()> {
        if self
            .observed_effect
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
        {
            observed_effect(reply, self);
        }
        // An observed full close has no final reader. Record the deliberate
        // absence of a write separately from a lost write observation.
        if self.cause.get() == Some(lifetime::Cause::Disconnect) {
            self.ending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)["final_write"] =
                json!("not-attempted");
            return Ok(());
        }
        #[cfg(test)]
        BEFORE_TERMINAL_WRITE.with(|slot| {
            if let Some(action) = slot.borrow_mut().take() {
                action();
            }
        });
        let remaining = || self.final_remaining(deadline);
        let result = transport::with_writer_window(&self.writer, &remaining, |stream| {
            stream.final_reply(reply, &remaining)?;
            // credit checks this flag under this same writer lock.
            self.final_sent.store(true, Ordering::Relaxed);
            Ok(())
        });
        if result.is_err()
            && let Some(life) = &self.lifetime
        {
            // Also close when the writer could not be acquired: the connection
            // fallback and an older credit writer must not append a new frame.
            life.close_output();
        }
        self.ending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)["final_write"] =
            json!(if result.is_ok() {
                "succeeded-locally"
            } else {
                "failed"
            });
        result
    }

    fn report(&self, reply: &mut Value) {
        reply["wall_clock"] = json!("monotonic-awake");
        let ending = self.ending_snapshot();
        reply["remote"] = ending["remote"].clone();
        if ending["local_child"] == "unobserved" {
            reply["remote"]["state"] = json!("not-started");
        }
        if let Some(stop) = self.cause.get() {
            reply["stop_cause"] = json!(stop.name());
            if matches!(
                stop,
                lifetime::Cause::Deadline
                    | lifetime::Cause::Disconnect
                    | lifetime::Cause::ObservationFailure
                    | lifetime::Cause::Transport
            ) {
                reply["next_step"] = json!(if reply["remote"]["state"] == "unconfirmed"
                    && reply["remote"]["bound_seconds"].is_number()
                {
                    format!(
                        "the remote command is unconfirmed and may hold the node run lock for up to {:.0} s after it started (start not observed); report this stop to your loop; a repeat is admitted but may wait for that lock",
                        reply["remote"]["bound_seconds"]
                            .as_f64()
                            .unwrap_or_default()
                            .ceil()
                    )
                } else if reply["remote"]["state"] == "unconfirmed" {
                    "the remote command is unconfirmed and no time bound was observed; report this stop to your loop; a repeat is admitted but may duplicate remote work".to_owned()
                } else if matches!(
                    stop,
                    lifetime::Cause::ObservationFailure | lifetime::Cause::Transport
                ) {
                    "no remote command started; report this stop to your loop for inspection; a repeat through the ordinary door route is admitted".to_owned()
                } else {
                    "no remote command started; ask again through the ordinary door route when ready".to_owned()
                });
            }
            if matches!(
                stop,
                lifetime::Cause::Deadline
                    | lifetime::Cause::Disconnect
                    | lifetime::Cause::ObservationFailure
            ) && matches!(
                reply["reason"].as_str(),
                Some("door-request-record-refusal" | "door-request-read-refusal")
            ) {
                reply["reason"] = json!(stop.reason());
            }
        }
        if self.lifetime.is_some() {
            reply["deadline_clock"] = json!("boottime");
        }
        let waited = self.micros.load(Ordering::Relaxed) / 1000;
        let credit = waited.min(self.cap_ms);
        reply["request_lock_wait_ms"] = json!(waited);
        reply["request_lock_wait_credit_ms"] = json!(credit);
        reply["request_lock_wait_credit_cap_ms"] = json!(self.cap_ms);
        if let Some(requested) = reply["request_deadline_ms"].as_u64() {
            reply["effective_deadline_ms"] = json!(requested.saturating_add(credit));
        }
    }
}

/// Observe admission locks without waiting or claiming that later arrivals are excluded.
pub(crate) fn restart_probe(home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2};
    let owner = nix::unistd::Uid::effective().as_raw();
    let directory =
        crate::home::pin_parent_beneath(&home.join(".config/loops").join(loop_name), home, owner)?;
    let mut entries = nix::dir::Dir::from_fd(
        nix::unistd::dup(&directory)
            .map_err(|error| LaneError::input("door-restart-refusal", error.to_string()))?,
    )
    .map_err(|error| LaneError::input("door-restart-refusal", error.to_string()))?;
    let mut busy = Vec::new();
    let mut held = Vec::new();
    for entry in entries.iter() {
        let entry =
            entry.map_err(|error| LaneError::input("door-restart-refusal", error.to_string()))?;
        let bytes = entry.file_name().to_bytes();
        let Ok(name) = std::str::from_utf8(bytes) else {
            continue;
        };
        if !name.starts_with("door-admission-") || name.strip_suffix(".lock").is_none() {
            continue;
        }
        let fd = openat2(
            &directory,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("door-restart-refusal", error.to_string()))?;
        let stat = fstat(&fd)
            .map_err(|error| LaneError::input("door-restart-refusal", error.to_string()))?;
        if stat.st_uid != owner
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
            || SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        {
            return Err(LaneError::input(
                "door-restart-refusal",
                "admission lock custody differs",
            ));
        }
        match Flock::lock(File::from(fd), FlockArg::LockExclusiveNonblock) {
            Ok(lock) => held.push(lock),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => busy.push(name.to_owned()),
            Err((_, error)) => {
                return Err(LaneError::input("door-restart-refusal", error.to_string()));
            }
        }
    }
    busy.sort();
    let checked_locks = held.len() + busy.len();
    drop(held);
    Ok(
        json!({"status":if busy.is_empty() { "admission-idle" } else { "request-in-flight" },
        "busy_locks":busy,"checked_locks":checked_locks,"reservation":false}),
    )
}

struct RequestEnding<'a> {
    store: &'a Store,
    wait: &'a RequestWait,
    id: &'a str,
}

impl Drop for RequestEnding<'_> {
    fn drop(&mut self) {
        if let Some(life) = &self.wait.lifetime {
            life.finish();
        }
        self.wait.cause.select(lifetime::Cause::HandlerFailure);
        let ending = self.wait.ending_snapshot();
        let effect = self
            .wait
            .observed_effect
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Err(error) = self.store.finish_request(self.id, effect.clone(), &ending) {
            post_reply_event(self.id, "terminal-record", error.kind);
            request_end_event(&unrecorded_ending(self.id, effect, &ending));
        }
    }
}

fn unrecorded_ending(id: &str, effect: Option<Value>, ending: &Value) -> Value {
    let effect = effect.unwrap_or_else(|| {
        let cause = if ending["cause"] == "unobserved" {
            json!("handler-failure")
        } else {
            ending["cause"].clone()
        };
        json!({"reason":"door-handler-ended", "ending":{"cause":cause}})
    });
    json!({"request_id":id,"cause":effect["ending"]["cause"],"reason":effect["reason"],"recorded":false})
}

trait AdmissionClock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

struct RealAdmissionClock;

impl AdmissionClock for RealAdmissionClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

// The service and host exercises share this inode; never unlink a lock on release.
struct RequestGuard {
    _held: Vec<nix::fcntl::Flock<File>>,
}

// These locks count waiting workspace calls without retaining either admission
// guard. Their names are separate from admission locks, which restart probes.
struct WorkspaceWaitSlot {
    _held: nix::fcntl::Flock<File>,
}

impl WorkspaceWaitSlot {
    fn acquire(home: &Path, registration: &Registration) -> io::Result<Option<Self>> {
        for slot in 0..2 {
            let class = format!("workspace-wait-{slot}");
            if let Some(lock) = RequestGuard::acquire_lock(home, registration, &class, false)? {
                return Ok(Some(Self { _held: lock }));
            }
        }
        Ok(None)
    }
}

impl RequestGuard {
    fn acquire_wait(
        home: &Path,
        registration: &Registration,
        request: &Value,
        operation: Option<transport::Operation>,
        started: Instant,
    ) -> io::Result<(Option<Self>, Duration)> {
        #[cfg(test)]
        if let Some(clock) = ADMISSION_CLOCK.with(|slot| slot.borrow().clone()) {
            return Self::acquire_wait_with_clock(
                home,
                registration,
                request,
                operation,
                started,
                clock.as_ref(),
            );
        }
        Self::acquire_wait_with_clock(
            home,
            registration,
            request,
            operation,
            started,
            &RealAdmissionClock,
        )
    }

    fn acquire_wait_with_clock(
        home: &Path,
        registration: &Registration,
        request: &Value,
        operation: Option<transport::Operation>,
        started: Instant,
        clock: &dyn AdmissionClock,
    ) -> io::Result<(Option<Self>, Duration)> {
        Self::acquire_controlled(home, registration, request, operation, started, clock, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn acquire_controlled(
        home: &Path,
        registration: &Registration,
        request: &Value,
        operation: Option<transport::Operation>,
        started: Instant,
        clock: &dyn AdmissionClock,
        control: Option<(&RequestWait, Instant)>,
    ) -> io::Result<(Option<Self>, Duration)> {
        let began = clock.now();
        let remaining = Duration::from_millis(request["deadline_ms"].as_u64().unwrap_or(0))
            .saturating_sub(clock.now().saturating_duration_since(started))
            .saturating_sub(ADMISSION_REPLY_MARGIN);
        let budget = remaining.min(ADMISSION_WAIT);
        loop {
            if control.is_some_and(|(wait, deadline)| wait.stop(deadline).is_some()) {
                return Ok((None, clock.now().saturating_duration_since(began)));
            }
            if let Some(guard) = Self::acquire_operation(home, registration, operation)? {
                return Ok((Some(guard), clock.now().saturating_duration_since(began)));
            }
            #[cfg(test)]
            ADMISSION_CONTENDED.with(|slot| {
                if let Some(action) = slot.borrow_mut().take() {
                    action();
                }
            });
            let remaining = budget.saturating_sub(clock.now().saturating_duration_since(began));
            if remaining.is_zero() {
                return Ok((None, clock.now().saturating_duration_since(began)));
            }
            #[cfg(test)]
            if remaining <= ADMISSION_POLL {
                ADMISSION_LAST_POLL.with(|slot| {
                    if let Some(action) = slot.borrow_mut().take() {
                        action();
                    }
                });
            }
            clock.sleep(remaining.min(ADMISSION_POLL));
        }
    }

    #[cfg(test)]
    fn acquire(home: &Path, registration: &Registration) -> io::Result<Option<Self>> {
        Self::acquire_operation(home, registration, None)
    }

    fn acquire_operation(
        home: &Path,
        registration: &Registration,
        operation: Option<transport::Operation>,
    ) -> io::Result<Option<Self>> {
        let class = match operation {
            Some(transport::Operation::Compute) => Some("compute"),
            Some(transport::Operation::GitReceive) => Some("receive"),
            _ => None,
        };
        let Some(common) = Self::acquire_lock(home, registration, "", class.is_some())? else {
            return Ok(None);
        };
        let mut held = vec![common];
        if let Some(class) = class {
            let Some(slot) = Self::acquire_lock(home, registration, class, false)? else {
                return Ok(None);
            };
            held.push(slot);
        }
        Ok(Some(Self { _held: held }))
    }

    fn acquire_lock(
        home: &Path,
        registration: &Registration,
        class: &str,
        shared: bool,
    ) -> io::Result<Option<nix::fcntl::Flock<File>>> {
        use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2};
        loop_home::validate_name(&registration.loop_name).map_err(io::Error::other)?;
        let owner = nix::unistd::Uid::effective().as_raw();
        // Callers supply the registered owner home, also inside the private
        // exercise namespace where ancestors above that home are not visible.
        let directory = crate::home::pin_parent_beneath(
            &home.join(".config/loops").join(&registration.loop_name),
            home,
            owner,
        )
        .map_err(io::Error::other)?;
        let name = if class.starts_with("workspace-wait-") {
            format!("door-{}-{}.lock", class, registration.worker_uid)
        } else if class.is_empty() {
            format!("door-admission-{}.lock", registration.worker_uid)
        } else {
            format!("door-admission-{}-{class}.lock", registration.worker_uid)
        };
        let fd = openat2(
            &directory,
            Path::new(&name),
            OpenHow::new()
                .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .mode(nix::sys::stat::Mode::from_bits_truncate(0o600))
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(io::Error::from)?;
        let stat = fstat(&fd).map_err(io::Error::from)?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
            || stat.st_uid != owner
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
        {
            return Err(io::Error::other(
                "door admission lock owner, type, mode or links differ",
            ));
        }
        let operation = if shared {
            FlockArg::LockSharedNonblock
        } else {
            FlockArg::LockExclusiveNonblock
        };
        match Flock::lock(File::from(fd), operation) {
            Ok(held) => Ok(Some(held)),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, error)) => Err(io::Error::from(error)),
        }
    }
}

fn claim_workspace_under_admission(
    store: &Store,
    activity: &crate::requests::store::PublicationActivity,
    _admission: &RequestGuard,
    request: &WorkspaceRequest,
) -> Result<RequestRecord, LaneError> {
    store.claim_workspace(activity, request)
}

#[cfg(test)]
thread_local! {
    static BEFORE_CREDIT_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_ALLOW_ADMISSION_RELEASE: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static ADMISSION_CLOCK: std::cell::RefCell<Option<std::rc::Rc<dyn AdmissionClock>>> = const { std::cell::RefCell::new(None) };
    static ADMISSION_LAST_POLL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static ADMISSION_CONTENDED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static FIXTURE_ADMISSION_CLOCK: std::cell::RefCell<Option<Arc<FixtureAdmissionClock>>> = const { std::cell::RefCell::new(None) };
    static AFTER_WAITING_CLAIM: std::cell::RefCell<Option<WaitingClaimHook>> = const { std::cell::RefCell::new(None) };
    static REQUEST_END_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) struct FixtureAdmissionClock {
    now: std::sync::Mutex<Instant>,
    slept_ms: AtomicU64,
    attempts: AtomicUsize,
}

#[cfg(test)]
impl FixtureAdmissionClock {
    pub(crate) fn waited(&self) -> Duration {
        Duration::from_millis(self.slept_ms.load(Ordering::Relaxed))
    }

    pub(crate) fn attempts(&self) -> usize {
        self.attempts.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
impl AdmissionClock for Arc<FixtureAdmissionClock> {
    fn now(&self) -> Instant {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sleep(&self, duration: Duration) {
        let mut now = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now += duration;
        drop(now);
        self.slept_ms.fetch_add(
            u64::try_from(duration.as_millis()).expect("bounded admission poll"),
            Ordering::Relaxed,
        );
    }
}

#[cfg(test)]
struct FixtureClockRestore(Option<Arc<FixtureAdmissionClock>>, Option<Duration>);

#[cfg(test)]
impl Drop for FixtureClockRestore {
    fn drop(&mut self) {
        FIXTURE_ADMISSION_CLOCK.with(|slot| {
            slot.replace(self.0.take());
        });
        EXERCISE_RETRY_HANG.with(|slot| slot.set(self.1.take()));
    }
}

#[cfg(test)]
pub(crate) fn with_fixture_admission_clock<T>(
    retry_window: Duration,
    f: impl FnOnce() -> T,
) -> (T, Arc<FixtureAdmissionClock>) {
    let clock = Arc::new(FixtureAdmissionClock {
        now: std::sync::Mutex::new(Instant::now()),
        slept_ms: AtomicU64::new(0),
        attempts: AtomicUsize::new(0),
    });
    let prior_clock = FIXTURE_ADMISSION_CLOCK.with(|slot| slot.replace(Some(Arc::clone(&clock))));
    let prior_retry = EXERCISE_RETRY_HANG.with(|slot| slot.replace(Some(retry_window)));
    let _restore = FixtureClockRestore(prior_clock, prior_retry);
    (f(), clock)
}

const RETRY_AFTER_SECONDS: u64 = 30;
fn post_reply_failure(store: &Store, run: &str, id: &str, phase: &str, kind: &str) {
    post_reply_event(id, phase, kind);
    if let Err(error) = store.record_incomplete(run, id, kind) {
        post_reply_event(id, "incomplete-marker", error.kind);
    }
}

fn recover_after_success(
    store: &Store,
    run: &str,
    reply: &Value,
    admission: &mut Option<RequestGuard>,
) {
    // Every caller has delivered its final reply. Recovery must not retain admission.
    drop(admission.take());
    if reply["status"] == 0 {
        // The current request's lease is still held, so only older abandoned work is recovered.
        if let Err(error) = store.recover_if_unpublished(run) {
            post_reply_event("", "recovery-after-request", error.kind);
        }
    }
}

fn recover_at_start(home: &Path, loop_name: &str) {
    if let Err(error) = Store::open(home, loop_name, true).and_then(|store| {
        let abandoned = store.abandon_at_start();
        let recovered = store.recover_unpublished(None);
        abandoned.and(recovered)
    }) {
        post_reply_event("", "recovery-at-start", error.kind);
    }
}

pub(crate) fn request_end_event(event: &Value) {
    #[cfg(test)]
    {
        REQUEST_END_COUNT.with(|count| count.set(count.get() + 1));
        #[allow(clippy::print_stderr)] // Preserve libtest capture of terminal evidence.
        {
            eprintln!("door-request-end {event}");
        }
    }
    #[cfg(not(test))]
    {
        let _logged = writeln!(io::stderr().lock(), "door-request-end {event}");
    }
}

pub(crate) fn post_reply_event(id: &str, phase: &str, kind: &str) {
    let event = json!({"request_id":id,"phase":phase,"kind":kind});
    #[cfg(test)]
    POST_REPLY_EVENTS.with(|events| events.borrow_mut().push(event.clone()));
    let _logged = writeln!(io::stderr().lock(), "door-post-reply-failure {event}");
}

fn admission_window() -> String {
    format!(
        "the door waited for admission held through the durable effect and final reply; allow-mode agent publication may finish after admission is released; retry after {RETRY_AFTER_SECONDS} seconds"
    )
}

fn concurrent_fields(reply: &mut Value, waited: Duration) {
    reply["admission_window"] = json!(admission_window());
    reply["waited_seconds"] = json!((waited.as_secs_f64() * 1000.0).round() / 1000.0);
    reply["retry_after_seconds"] = json!(RETRY_AFTER_SECONDS);
}

fn concurrent_refusal(
    wait: &RequestWait,
    registration: &Registration,
    peer: u32,
    started: Instant,
    waited: Duration,
    deadline: Instant,
    schema: u64,
) -> io::Result<(Value, Vec<u8>)> {
    let _logged = writeln!(
        io::stderr().lock(),
        "door preflight: run={} check=door-request-concurrent",
        registration.run
    );
    let mut reply = transport::refusal(registration, peer, "door-request-concurrent", started);
    reply["schema"] = json!(schema);
    concurrent_fields(&mut reply, waited);
    wait.write_final(&reply, deadline)?;
    Ok((reply, Vec::new()))
}

#[allow(clippy::too_many_arguments)]
fn stopped_admission_refusal(
    wait: &RequestWait,
    registration: &Registration,
    peer: u32,
    started: Instant,
    waited: Duration,
    deadline: Instant,
    cause: lifetime::Cause,
    schema: u64,
) -> io::Result<(Value, Vec<u8>)> {
    let mut reply = transport::refusal(registration, peer, cause.reason(), started);
    reply["schema"] = json!(schema);
    reply["waited_seconds"] = json!(waited.as_secs_f64());
    wait.report(&mut reply);
    wait.write_final(&reply, deadline)?;
    Ok((reply, Vec::new()))
}

struct PeerGuard(Arc<AtomicUsize>);

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn admit_peer(active: &Arc<AtomicUsize>, stream: &mut UnixStream) -> Option<PeerGuard> {
    if active.fetch_add(1, Ordering::Relaxed) >= MAX_PEERS {
        active.fetch_sub(1, Ordering::Relaxed);
        if let Err(error) = frame_write_no_drain(
            stream,
            &json!({"schema":2,"type":"final","status":125,
                "reason":"door-capacity-refusal","peer_limit":MAX_PEERS,
                "retry_after_seconds":CAPACITY_RETRY_SECONDS,"ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
                "queue_state":"no-queue","queue_wall_seconds":null,"compute_exit_status":null,
                "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}),
        ) {
            let _logged = writeln!(io::stderr().lock(), "door capacity reply: {error}");
        }
        return None;
    }
    Some(PeerGuard(Arc::clone(active)))
}

pub(crate) mod compute;
#[cfg(test)]
#[path = "door/compute_tests.rs"]
mod compute_tests;
pub(crate) mod retirement;
mod transport;
#[cfg(test)]
pub(crate) use transport::Operation as RetirementOperation;
#[cfg(test)]
pub(crate) use transport::fixture_workspace_context_run;
pub(crate) use transport::read_owner_leaf_optional;
pub use transport::stub_call_stream;

/// Read only the registered route names and key pathname for a private measurement.
///
/// # Errors
///
/// Refuses a changed owner-private route without opening the named key.
pub(crate) fn registered_route(
    directory: &impl AsFd,
    config: &Path,
    loop_name: &str,
    owner: u32,
) -> Result<Value, LaneError> {
    transport::HostRunner::load(directory, config, loop_name, owner)
        .map(|route| route.probe_route())
}

/// Read the explicit node root without opening the registered key or contacting the node.
///
/// # Errors
///
/// Refuses an unprotected registration or an absent or non-absolute node root.
pub(crate) fn registered_node_root(
    directory: &impl AsFd,
    config: &Path,
    owner: u32,
) -> Result<Option<String>, LaneError> {
    match nix::sys::stat::fstatat(
        directory,
        "door-compute-registration.json",
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "door-compute-registration",
                error.to_string(),
            ));
        }
        Ok(_) => {}
    }
    let bytes = transport::read_owner_leaf(directory, "door-compute-registration.json", owner)?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("door-compute-registration", error.to_string()))?;
    transport::node_root(&value, config).map(Some)
}

/// One launcher-written grant for one worker identity and one mirror ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub loop_name: String,
    pub run: String,
    pub worker_uid: u32,
    pub loop_uid: u32,
    pub scope: Scope,
    pub mirror_ref: String,
}

/// The two independently registered worker scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Work,
    Review,
}

mod workspace {
    use std::io::{self, Write as _};
    use std::os::fd::OwnedFd;

    use execute_command::policy::DoorMode;
    use execute_command::workspace::{
        Classification, Disposition, LearnedDecision, canonical_digest, learned_key,
    };
    use serde_json::{Value, json};

    use crate::error::LaneError;
    use crate::requests::store::Store;

    use super::{Registration, Scope};

    /// A schema-three request bound to the owner-held reservation, before judgement.
    pub struct WorkspaceRequest {
        envelope: execute_command::workspace::Envelope,
        grant: execute_command::workspace::Grant,
        placement: Option<crate::placement::Placement>,
    }

    impl WorkspaceRequest {
        /// The exact request decoded from the original wire.
        #[must_use]
        pub const fn envelope(&self) -> &execute_command::workspace::Envelope {
            &self.envelope
        }

        /// The grant read from the protected reservation.
        #[must_use]
        pub const fn grant(&self) -> &execute_command::workspace::Grant {
            &self.grant
        }

        /// Owner-held placement captured with this reservation, if declared.
        #[must_use]
        pub const fn placement(&self) -> Option<&crate::placement::Placement> {
            self.placement.as_ref()
        }
    }

    /// Decode the original wire once and read its grant under the door's held runs descriptor.
    ///
    /// The caller supplies the node identity authenticated by the route; this reader
    /// never accepts the request's digest as a substitute for the protected grant.
    /// # Errors
    /// Refuses malformed wire, a missing grant or a changed run, worker or node.
    pub fn workspace_request(
        runs: &OwnedFd,
        registration: &Registration,
        owner: u32,
        node: &str,
        wire: &[u8],
    ) -> Result<WorkspaceRequest, LaneError> {
        let envelope = execute_command::workspace::Envelope::from_bytes(wire)
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
        if registration.scope != Scope::Work {
            return Err(LaneError::input(
                "door-workspace-context-differs",
                "workspace route requires work scope",
            ));
        }
        let reservation =
            crate::launch::door_reservation(runs, &registration.run, owner).map_err(|error| {
                LaneError::input(
                    "door-workspace-context-differs",
                    format!(
                        "protected workspace reservation is unavailable: {}",
                        error.line()
                    ),
                )
            })?;
        if reservation["phase"] != "started"
            || reservation["loop"] != registration.loop_name
            || reservation["run"] != registration.run
            || reservation["worker_uid"] != registration.worker_uid
        {
            return Err(LaneError::input(
                "door-workspace-context-differs",
                "workspace reservation and registered worker differ",
            ));
        }
        let snapshot = crate::plan::workspace_snapshot(&reservation["plan"]).map_err(|error| {
            LaneError::input(
                "door-workspace-context-differs",
                format!("protected workspace plan differs: {}", error.line()),
            )
        })?;
        let snapshot = snapshot.ok_or_else(|| {
            LaneError::input(
                "door-workspace-unregistered",
                "no protected workspace grant",
            )
        })?;
        let placement = crate::placement::snapshot(&reservation["plan"], Some(&snapshot))?;
        let grant = snapshot.grant;
        execute_command::workspace::admit(
            &envelope,
            Some(&grant),
            &registration.loop_name,
            &registration.run,
            node,
        )
        .map_err(|error| LaneError::input(error.kind, error.detail))?;
        Ok(WorkspaceRequest {
            envelope,
            grant,
            placement,
        })
    }

    /// An allow bound to one exact request and to the custody that answered it.
    pub struct WorkspaceAllowance {
        envelope_digest: String,
        context_key: Value,
        policy_revision: String,
        origin: AllowanceOrigin,
    }

    /// A store-owned learned answer, including a refusal that outranks a quick allow.
    pub struct WorkspaceLearned {
        context_key: Value,
        decision: bool,
        allowance: Option<WorkspaceAllowance>,
    }

    /// An allow-mode execution intent read from this request's protected record.
    pub struct WorkspaceIntent {
        record_id: String,
        envelope_digest: String,
        context_key: Value,
    }

    impl WorkspaceIntent {
        /// Read the filed intent before an allow-mode miss runs beside judgement.
        /// # Errors
        /// Refuses a changed record, envelope, grant or policy binding.
        #[allow(dead_code)] // The serving caller is the next W3 cut.
        pub fn from_store(
            store: &Store,
            id: &str,
            request: &WorkspaceRequest,
        ) -> Result<Self, LaneError> {
            let record = store.request(id)?;
            let value = record.value();
            let detail = &value["effect"]["workspace"];
            if value["schema"] != 7
                || value["class"] != "compute"
                || value["operation"] != "compute-workspace"
                || value["mode"] != "allow"
                || !value["state"].is_null()
                || value["effect"]["state"] != "pending"
                || detail["envelope"] != json!(request.envelope)
                || detail["grant"] != json!(request.grant)
                || detail["policy_revision"] != request.grant.quick_policy_digest
            {
                return Err(LaneError::input(
                    "door-workspace-context-differs",
                    "allow-mode intent and exact workspace request differ",
                ));
            }
            let envelope_digest = canonical_digest(&request.envelope)
                .map_err(|error| LaneError::input(error.kind, error.detail))?;
            let context_key = learned_key(
                "compute",
                &request.envelope,
                &request.grant,
                &request.grant.quick_policy_digest,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
            Ok(Self {
                record_id: record.id().to_owned(),
                envelope_digest,
                context_key,
            })
        }

        /// Check the same filed request at the adapter boundary.
        /// # Errors
        /// Refuses a replayed record id, envelope or context.
        pub fn check(&self, request: &WorkspaceRequest, id: &str) -> Result<(), LaneError> {
            let envelope_digest = canonical_digest(&request.envelope)
                .map_err(|error| LaneError::input(error.kind, error.detail))?;
            let context_key = learned_key(
                "compute",
                &request.envelope,
                &request.grant,
                &request.grant.quick_policy_digest,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
            if self.record_id != id
                || self.envelope_digest != envelope_digest
                || self.context_key != context_key
            {
                return Err(LaneError::input(
                    "door-workspace-context-differs",
                    "allow-mode intent belongs to another request",
                ));
            }
            Ok(())
        }
    }

    enum AllowanceOrigin {
        Store(Value),
        Judgement(String),
    }

    impl WorkspaceAllowance {
        fn bind(request: &WorkspaceRequest, origin: AllowanceOrigin) -> Result<Self, LaneError> {
            let policy_revision = request.grant.quick_policy_digest.clone();
            let context_key = learned_key(
                "compute",
                &request.envelope,
                &request.grant,
                &policy_revision,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
            let envelope_digest = canonical_digest(&request.envelope)
                .map_err(|error| LaneError::input(error.kind, error.detail))?;
            Ok(Self {
                envelope_digest,
                context_key,
                policy_revision,
                origin,
            })
        }

        /// Read a learned allow from the protected store using this request's derived key.
        ///
        /// # Errors
        /// Refuses inconsistent learned evidence; a learned-index fault accompanies a miss.
        pub fn from_store_lookup(
            store: &Store,
            request: &WorkspaceRequest,
        ) -> Result<(Option<WorkspaceLearned>, Option<LaneError>), LaneError> {
            let key = learned_key(
                "compute",
                &request.envelope,
                &request.grant,
                &request.grant.quick_policy_digest,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
            let shape = key[2].as_str().ok_or_else(|| {
                LaneError::input("door-workspace-context-differs", "learned key differs")
            })?;
            let (decision, evidence, _) =
                match store.learned_judgement("compute", "compute-workspace", shape) {
                    Ok(lookup) => lookup,
                    Err(error) => {
                        let _logged = writeln!(
                            io::stderr().lock(),
                            "door workspace learned lookup: {}",
                            error.line()
                        );
                        return Ok((None, Some(error)));
                    }
                };
            if !matches!(decision["decision"].as_str(), Some("allow" | "refuse")) {
                return Ok((None, None));
            }
            if evidence["class"] != "compute"
                || evidence["operation"] != "compute-workspace"
                || evidence["shape_key"] != shape
            {
                return Err(LaneError::input(
                    "door-workspace-context-differs",
                    "learned allowance evidence differs",
                ));
            }
            let allowed = decision["decision"] == "allow";
            let allowance = allowed
                .then(|| Self::bind(request, AllowanceOrigin::Store(evidence)))
                .transpose()?;
            Ok((
                Some(WorkspaceLearned {
                    context_key: key,
                    decision: allowed,
                    allowance,
                }),
                None,
            ))
        }

        /// Bind an agent allowance only after a protected store read by request id.
        ///
        /// # Errors
        /// Refuses a non-agent decision or any changed execution or owner context.
        pub fn from_judgement_record(
            store: &Store,
            id: &str,
            request: &WorkspaceRequest,
        ) -> Result<Self, LaneError> {
            let record = store.request(id)?;
            let value = record.value();
            let detail = &value["effect"]["workspace"];
            if value["schema"] != 7
                || value["class"] != "compute"
                || value["operation"] != "compute-workspace"
                || value["would_do_source"] != "agent"
                || value["would_do"]["decision"] != "allow"
                || (!value["label"].is_null() && value["label"]["treatment"] != "allow")
                || detail["envelope"] != json!(request.envelope)
                || detail["grant"] != json!(request.grant)
                || detail["policy_revision"] != request.grant.quick_policy_digest
            {
                return Err(LaneError::input(
                    "door-workspace-context-differs",
                    "judgement allowance and exact workspace request differ",
                ));
            }
            Self::bind(request, AllowanceOrigin::Judgement(record.id().to_owned()))
        }

        /// Whether this evidence still belongs to the exact wire and owner grant.
        ///
        /// # Errors
        /// Refuses a changed envelope, grant or policy identity.
        pub fn check(&self, request: &WorkspaceRequest) -> Result<(), LaneError> {
            let same_envelope = canonical_digest(&request.envelope)
                .map_err(|error| LaneError::input(error.kind, error.detail))?
                == self.envelope_digest;
            let same_context = learned_key(
                "compute",
                &request.envelope,
                &request.grant,
                &self.policy_revision,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?
                == self.context_key;
            if !same_envelope
                || !same_context
                || self.policy_revision != request.grant.quick_policy_digest
            {
                return Err(LaneError::input(
                    "door-workspace-context-differs",
                    "allowance belongs to another exact workspace request",
                ));
            }
            Ok(())
        }

        /// Protected evidence the later record adapter cites.
        #[must_use]
        pub fn evidence(&self) -> Value {
            match &self.origin {
                AllowanceOrigin::Store(rule) => json!({"source":"learned","rule":rule}),
                AllowanceOrigin::Judgement(id) => json!({"source":"judgement","request_id":id}),
            }
        }
    }

    impl WorkspaceLearned {
        /// Checked allowance, absent for a learned refusal.
        #[must_use]
        pub const fn allowance(&self) -> Option<&WorkspaceAllowance> {
            self.allowance.as_ref()
        }
    }

    #[cfg(test)]
    pub(super) fn fixture_allowance(request: &WorkspaceRequest) -> WorkspaceAllowance {
        WorkspaceAllowance::bind(request, AllowanceOrigin::Store(json!({"fixture":true})))
            .expect("fictional allowance")
    }

    impl WorkspaceRequest {
        /// Compose the existing door agent call with lossless workspace evidence.
        ///
        /// # Errors
        /// Refuses an envelope that no longer matches its protected grant.
        pub fn agent_input(
            &self,
            reasons: &[String],
            rubric: &str,
        ) -> Result<execute_command::rubric::DoorInput, LaneError> {
            let request =
                execute_command::workspace::agent_input(&self.envelope, &self.grant, reasons)
                    .map_err(|error| LaneError::input(error.kind, error.detail))?;
            Ok(execute_command::rubric::DoorInput {
                request,
                class: "compute".into(),
                rubric: rubric.into(),
            })
        }

        /// Select the workspace mode after any allowance is checked against this exact request.
        ///
        /// An allow-mode miss runs beside judgement; enforce and audit wait.
        /// # Errors
        /// Refuses an allowance replayed against another request or malformed context.
        pub fn disposition(
            &self,
            mode: DoorMode,
            classification: &Classification,
            learned: Option<&WorkspaceLearned>,
        ) -> Result<Disposition, LaneError> {
            if let Some(allowance) = learned.and_then(WorkspaceLearned::allowance) {
                allowance.check(self)?;
            }
            let learned = learned.map(|answer| {
                if answer.decision {
                    LearnedDecision::Allow(&answer.context_key)
                } else {
                    LearnedDecision::Refuse(&answer.context_key)
                }
            });
            execute_command::workspace::disposition(
                mode,
                classification,
                &self.envelope,
                &self.grant,
                &self.grant.quick_policy_digest,
                learned,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))
        }
    }
}

impl Registration {
    /// Derive one exact run grant from a validated row and launcher-selected identity.
    ///
    /// # Errors
    ///
    /// Refuses a mismatched row, invalid run, or a worker equal to the owner.
    pub fn from_row(
        row: &Value,
        loop_name: &str,
        run: &str,
        worker_uid: u32,
        scope: Scope,
    ) -> Result<Self, LaneError> {
        if row["name"] != loop_name || !crate::valid_run_name(run) {
            return Err(LaneError::input("door-registration", "row or run differs"));
        }
        let loop_uid = row["uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1000..=65535).contains(value))
            .ok_or_else(|| LaneError::input("door-registration", "row uid is absent"))?;
        if worker_uid < 1000 || worker_uid == loop_uid {
            return Err(LaneError::input(
                "door-registration",
                "worker uid is outside its grant",
            ));
        }
        Ok(Self {
            loop_name: loop_name.to_owned(),
            run: run.to_owned(),
            worker_uid,
            loop_uid,
            scope,
            mirror_ref: format!("refs/heads/lane/{run}"),
        })
    }

    #[must_use]
    pub fn document(&self) -> Value {
        json!({"schema":1,"loop":self.loop_name,"run":self.run,"worker_uid":self.worker_uid,"loop_uid":self.loop_uid,"scope":self.scope.name(),"mirror_ref":self.mirror_ref})
    }
}

impl Scope {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Review => "review",
        }
    }
}

fn frame_write(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    frame_write_until(stream, value, Instant::now() + PEER_DEADLINE)
}

fn write_all_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "door command deadline",
            ));
        }
        stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let written = match stream.write(bytes) {
            Ok(written) => written,
            // Timed socket calls can return EINTR after a stop and continue.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "door write closed",
            ));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn frame_write_until(stream: &mut UnixStream, value: &Value, deadline: Instant) -> io::Result<()> {
    frame_write_checked(stream, value, deadline, true)
}

// A terminal frame gets the remaining request lifetime. Even at expiry one
// nonblocking attempt can deliver the stop; waiting never renews the budget.
#[allow(unsafe_code)]
fn frame_write_final(
    stream: &mut UnixStream,
    value: &Value,
    remaining: &dyn Fn() -> io::Result<Duration>,
) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > FRAME_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "door frame is too long",
        ));
    }
    let mut bytes = u32::try_from(body.len())
        .map_err(io::Error::other)?
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(&body);
    let result = (|| {
        let mut bytes = bytes.as_slice();
        while !bytes.is_empty() {
            // SAFETY: the live socket and borrowed frame bytes remain valid for send.
            let sent = unsafe {
                libc::send(
                    stream.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error);
                }
                let left = remaining()?;
                #[cfg(test)]
                FINAL_BLOCKED.with(|slot| {
                    if let Some(action) = slot.borrow_mut().take() {
                        action(left);
                    }
                });
                if left.is_zero() || remaining()?.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "door final lifetime expired",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            let sent = usize::try_from(sent).map_err(io::Error::other)?;
            if sent == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "door final closed",
                ));
            }
            bytes = &bytes[sent..];
            if !bytes.is_empty() && remaining()?.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "door partial final lifetime expired",
                ));
            }
        }
        Ok(())
    })();
    if result.is_err() {
        // Lifetime-free callers (including agent probes) have no outer
        // RequestWait close_output; this is their only partial-final closure.
        let _closed = stream.shutdown(Shutdown::Write);
    } else if value["status"] == 125 {
        drain_refusal(stream);
    }
    result
}

#[cfg(test)]
type FinalBlocked = std::cell::RefCell<Option<Box<dyn FnOnce(Duration)>>>;

#[cfg(test)]
thread_local! {
    static FINAL_BLOCKED: FinalBlocked = const { std::cell::RefCell::new(None) };
}

fn frame_write_no_drain(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    frame_write_checked(stream, value, Instant::now() + PEER_DEADLINE, false)
}

fn frame_write_checked(
    stream: &mut UnixStream,
    value: &Value,
    deadline: Instant,
    drain_refusal: bool,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > FRAME_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "door frame is too long",
        ));
    }
    write_all_until(
        stream,
        &u32::try_from(bytes.len()).unwrap_or(0).to_be_bytes(),
        deadline,
    )?;
    write_all_until(stream, &bytes, deadline)?;
    if drain_refusal && value["type"] == "final" && value["status"] == 125 {
        self::drain_refusal(stream);
    }
    Ok(())
}

fn drain_refusal(stream: &mut UnixStream) {
    let _closed = stream.shutdown(Shutdown::Write);
    let drain_deadline = Instant::now() + Duration::from_millis(500);
    let mut remaining = INPUT_LIMIT;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 && Instant::now() < drain_deadline {
        let timeout = drain_deadline.saturating_duration_since(Instant::now());
        if stream.set_read_timeout(Some(timeout)).is_err() {
            break;
        }
        let amount = remaining.min(buffer.len());
        match stream.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(read) => remaining -= read,
            // Timed socket calls can return EINTR after a stop and continue.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
}

fn frame_read(stream: &mut UnixStream) -> io::Result<Value> {
    frame_read_until(stream, Instant::now() + PEER_DEADLINE)
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "door command deadline",
            ));
        }
        stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let read = match stream.read(bytes) {
            Ok(read) => read,
            // Timed socket calls can return EINTR after a stop and continue.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "door command deadline",
                ));
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "door peer closed",
            ));
        }
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn frame_read_until(stream: &mut UnixStream, deadline: Instant) -> io::Result<Value> {
    let mut length = [0_u8; 4];
    read_exact_until(stream, &mut length, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length > FRAME_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "door frame exceeds limit",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

// Keep the original schema-three bytes for the custody decoder. The socket
// limit is selected only after parsing the frame; schema two retains its old
// limit even when the peer supplies a longer length prefix.
fn request_frame_read_until(
    stream: &mut UnixStream,
    deadline: Instant,
) -> io::Result<(Value, Vec<u8>)> {
    let mut length = [0_u8; 4];
    read_exact_until(stream, &mut length, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length > execute_command::workspace::MAX_WIRE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "door frame exceeds limit",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > FRAME_LIMIT && value["schema"] != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "door frame exceeds limit",
        ));
    }
    Ok((value, bytes))
}

#[allow(unsafe_code)]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = u32::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: the socket descriptor and writable credential buffer live through this call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut length,
        )
    };
    if result < 0 || usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[derive(Clone, Debug)]
struct PeerUidMap(Vec<(u64, u64, u64)>);

impl PeerUidMap {
    fn parse(source: &str, owner: u32, block: (u32, u32)) -> Result<Self, LaneError> {
        let mut ranges = Vec::new();
        for line in source.lines() {
            let words = line.split_ascii_whitespace().collect::<Vec<_>>();
            let [inside, outside, count] = words.as_slice() else {
                return Err(LaneError::input(
                    "door-peer-map",
                    "UID map line is malformed",
                ));
            };
            let values = [inside, outside, count]
                .into_iter()
                .map(|word| word.parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LaneError::input("door-peer-map", "UID map number is invalid"))?;
            let (inside, outside, count) = (values[0], values[1], values[2]);
            if count == 0
                || inside
                    .checked_add(count)
                    .is_none_or(|end| end > u64::from(u32::MAX) + 1)
                || outside
                    .checked_add(count)
                    .is_none_or(|end| end > u64::from(u32::MAX) + 1)
                || ranges
                    .iter()
                    .any(|(prior_inside, prior_outside, prior_count)| {
                        inside < prior_inside + prior_count && *prior_inside < inside + count
                            || outside < prior_outside + prior_count
                                && *prior_outside < outside + count
                    })
            {
                return Err(LaneError::input("door-peer-map", "UID map ranges differ"));
            }
            ranges.push((inside, outside, count));
        }
        let map = Self(ranges);
        let end = block.0.checked_add(block.1);
        if map.host_uid(0) != Some(owner)
            || end.is_none_or(|end| end == block.0)
            || (block.0..end.unwrap_or(block.0)).any(|uid| map.host_uid(uid).is_none())
        {
            return Err(LaneError::input(
                "door-peer-map",
                "owner or worker block is absent from UID map",
            ));
        }
        Ok(map)
    }

    fn host_uid(&self, namespace_uid: u32) -> Option<u32> {
        let uid = u64::from(namespace_uid);
        self.0.iter().find_map(|(inside, outside, count)| {
            (uid >= *inside && uid < inside + count)
                .then(|| u32::try_from(outside + uid - inside).ok())
                .flatten()
        })
    }

    fn namespace_uid(&self, host_uid: u32) -> Option<u32> {
        let uid = u64::from(host_uid);
        self.0.iter().find_map(|(inside, outside, count)| {
            (uid >= *outside && uid < outside + count)
                .then(|| u32::try_from(inside + uid - outside).ok())
                .flatten()
        })
    }
}

fn mapped_peer_uid(stream: &UnixStream, map: &PeerUidMap) -> io::Result<u32> {
    map.namespace_uid(peer_uid(stream)?).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer is outside the owner UID map",
        )
    })
}

/// Serve one fixture connection through the same peer-bound request boundary.
/// A shape probe returns before route selection, so this helper needs no compute route.
///
/// # Errors
///
/// Refuses an unreadable peer, malformed frame, or a broken response channel.
fn serve_one_captured(
    stream: &mut UnixStream,
    registration: &Registration,
) -> io::Result<(Value, Vec<u8>)> {
    stream.set_read_timeout(Some(PEER_DEADLINE))?;
    stream.set_write_timeout(Some(PEER_DEADLINE))?;
    let peer = peer_uid(stream)?;
    serve_one_for_peer(stream, registration, peer)
}

fn serve_one_for_peer(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
) -> io::Result<(Value, Vec<u8>)> {
    let request = frame_read(stream)?;
    serve_one_for_peer_request(stream, registration, peer, &request)
}

fn serve_one_for_peer_request(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
) -> io::Result<(Value, Vec<u8>)> {
    serve_request(
        stream,
        registration,
        peer,
        request,
        None,
        None,
        None,
        None,
        None,
        Instant::now(),
    )
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos())
}

fn request_record(
    registration: &Registration,
    class: &str,
    operation: transport::Operation,
    setting: &Value,
    would_do: &Value,
    waiting: bool,
    words: &[String],
) -> io::Result<RequestRecord> {
    let mut value = request_record_value(
        registration,
        class,
        operation.name(),
        setting,
        would_do,
        waiting,
    );
    if operation == transport::Operation::Compute {
        value["shape_key"] = json!(compute::shape(words));
        value["effect"]["compute"] = compute::pending(words);
    }
    RequestRecord::decode(value).map_err(io::Error::other)
}

fn request_record_value(
    registration: &Registration,
    class: &str,
    operation: &str,
    setting: &Value,
    would_do: &Value,
    waiting: bool,
) -> Value {
    let at = now_nanos();
    let id = format!(
        "{}:{:x}{:x}",
        registration.run,
        at,
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut value = json!({
        "schema":3,"id":id,"loop":registration.loop_name,"run":registration.run,
        "worker_uid":registration.worker_uid,"class":class,
        "shape_key":format!("{class}:{operation}"),"operation":operation,
        "mirror_ref":registration.mirror_ref,"mode":setting["mode"],"floor":setting["floor"],
        "class_setting":setting["class"],"loop_setting":setting["loop"],
        "would_do":would_do,"effect":{"state":"pending","reason":null,"ref_check":null,
            "exit_status":null,"stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
            "queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
        "state":if waiting {json!("waiting")} else {Value::Null},
        // filed_at is decimal Unix epoch nanoseconds since 1970-01-01T00:00:00Z.
        "mark_reason":null,"review":null,"label":null,"filed_at":at.to_string()
    });
    crate::requests::judgement::initialize(&mut value);
    value
}

/// File the exact workspace intent in the schema-seven form its reader owns.
/// The serving caller supplies the effective mode and the classified answer;
/// no request text is interpreted here.
#[allow(dead_code)] // The serving caller follows this record boundary.
pub(crate) fn workspace_record(
    registration: &Registration,
    setting: &Value,
    request: &WorkspaceRequest,
    disposition: execute_command::workspace::Disposition,
    would_do: &Value,
    matched_rule: Value,
) -> io::Result<RequestRecord> {
    let mut value = request_record_value(
        registration,
        "compute",
        "compute-workspace",
        setting,
        would_do,
        disposition == execute_command::workspace::Disposition::WaitForJudgement,
    );
    let envelope = request.envelope();
    let grant = request.grant();
    let key = execute_command::workspace::learned_key(
        "compute",
        envelope,
        grant,
        &grant.quick_policy_digest,
    )
    .map_err(io::Error::other)?;
    let execution_digest = execute_command::workspace::canonical_digest(&envelope.execution)
        .map_err(io::Error::other)?;
    value["schema"] = json!(7);
    value["operation"] = json!("compute-workspace");
    value["shape_key"] = key[2].clone();
    value["matched_rule"] = matched_rule;
    value["effect"]["workspace"] = json!({
        "envelope":envelope,
        "grant":grant,
        "policy_revision":grant.quick_policy_digest,
        "blacklist_revision":grant.blacklist_digest,
        "execution_digest":execution_digest,
        "context_digest":key[2],
        "result":{"outcome":{"kind":"Unknown"},"wall_seconds":null,
            "user_cpu_seconds":null,"system_cpu_seconds":null},
        "admission_wall_seconds":null,
        "steps":[]
    });
    RequestRecord::decode(value).map_err(io::Error::other)
}

pub(crate) fn effect_from_final(reply: &Value) -> Value {
    effect_with_cause(
        reply,
        lifetime::Cause::for_reply(reply["reason"].as_str().unwrap_or_default()),
    )
}

fn effect_with_cause(reply: &Value, cause: lifetime::Cause) -> Value {
    let mut effect = json!({"state":if reply["reason"] == "door-complete" {"completed"} else {"refused"},
        "reason":reply["reason"],"exit_status":reply["status"],"ref_check":reply["ref_check"],
        "stdin_bytes":reply["stdin_bytes"],"stdout_bytes":reply["stdout_bytes"],
        "stderr_bytes":reply["stderr_bytes"],"queue_wall_seconds":reply["queue_wall_seconds"],
        "mediation_wall_seconds":reply["mediation_wall_seconds"],
        "compute_wall_seconds":reply["compute_wall_seconds"]});
    for key in ["bound", "output_bytes", "ref_packet"] {
        if let Some(value) = reply.get(key) {
            effect[key] = value.clone();
        }
    }
    if let Some(detail) = reply.get("compute") {
        effect["compute"] = detail.clone();
    }
    effect["ending"] = crate::requests::unobserved_ending();
    effect["ending"]["cause"] = json!(cause.name());
    effect["ending"]["wall_clock"] = json!("monotonic-awake");
    effect["ending"]["local_child"] = json!("not-started");
    effect["ending"]["remote"]["state"] = json!("not-started");
    effect
}

fn observed_effect(reply: &Value, wait: &RequestWait) -> Value {
    let cause = wait.cause.select(lifetime::Cause::for_reply(
        reply["reason"].as_str().unwrap_or_default(),
    ));
    if let Some(life) = &wait.lifetime {
        life.finish();
    }
    let mut effect = effect_with_cause(reply, cause);
    let observed = wait.ending_snapshot();
    if observed["local_child"] != "unobserved" {
        effect["ending"] = observed;
    }
    *wait
        .observed_effect
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(effect.clone());
    effect
}

fn queue_reply(
    registration: &Registration,
    peer: u32,
    reason: &str,
    started: Instant,
    state: &str,
    wall: f64,
    id: &str,
) -> Value {
    let mut reply = transport::refusal(registration, peer, reason, started);
    reply["queue_state"] = json!(state);
    reply["queue_wall_seconds"] = json!(wall);
    reply["mediation_wall_seconds"] = json!((started.elapsed().as_secs_f64() - wall).max(0.0));
    reply["request_id"] = json!(id);
    reply
}

#[allow(unsafe_code)]
fn peer_disconnected(stream: &UnixStream) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    // SAFETY: poll receives one live socket descriptor and a writable pollfd.
    let result = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(descriptor.revents & (libc::POLLHUP | libc::POLLERR) != 0)
}

#[cfg_attr(test, derive(Debug))]
#[derive(Clone, Copy)]
enum Answer {
    Allow(f64),
    Refuse(f64),
    Deadline(f64),
    Disconnect(f64),
    ReadFailure(f64),
}

impl Answer {
    const fn stopped(cause: lifetime::Cause, wall: f64) -> Self {
        match cause {
            lifetime::Cause::Deadline => Self::Deadline(wall),
            lifetime::Cause::Disconnect => Self::Disconnect(wall),
            _ => Self::ReadFailure(wall),
        }
    }
}

#[cfg(test)]
type RequestReadiness = Box<dyn FnOnce(&str) -> io::Result<Instant> + Send>;

#[cfg(test)]
thread_local! {
    static AFTER_WAIT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_WAIT_STOP_FAULT_LOG: std::cell::RefCell<Option<std::sync::mpsc::Sender<String>>> = const { std::cell::RefCell::new(None) };
    static AFTER_WAIT_LOCK_TIMEOUT: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static REQUEST_FILED: std::cell::RefCell<Option<std::sync::mpsc::Sender<String>>> = const { std::cell::RefCell::new(None) };
    static REQUEST_READY: std::cell::RefCell<Option<RequestReadiness>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn wait_answer(store: &Store, id: &str, stream: &UnixStream, base_deadline: Instant) -> Answer {
    wait_answer_controlled(store, id, stream, base_deadline, None)
}

fn wait_answer_controlled(
    store: &Store,
    id: &str,
    stream: &UnixStream,
    base_deadline: Instant,
    control: Option<&RequestWait>,
) -> Answer {
    let queued = Instant::now();
    let mut interval = Duration::from_millis(10);
    loop {
        if let Some(stop) = control.and_then(|wait| wait.stop(base_deadline)) {
            return Answer::stopped(stop, queued.elapsed().as_secs_f64());
        }
        let record = match store.waiting_request_until(id, base_deadline) {
            Ok(record) => record,
            Err(error) => {
                // The peer or deadline may have stopped during the store read.
                // Keep that typed first cause instead of inventing a read fault.
                if let Some(stop) = control.and_then(|wait| wait.stop(base_deadline)) {
                    let line = format!("door request stop during store read: {}", error.line());
                    #[cfg(test)]
                    let logged = writeln!(io::stderr().lock(), "{line}");
                    #[cfg(not(test))]
                    let _logged = writeln!(io::stderr().lock(), "{line}");
                    #[cfg(test)]
                    if logged.is_ok() {
                        AFTER_WAIT_STOP_FAULT_LOG.with(|slot| {
                            if let Some(sender) = slot.borrow_mut().take() {
                                let _sent = sender.send(line);
                            }
                        });
                    }
                    return Answer::stopped(stop, queued.elapsed().as_secs_f64());
                }
                if crate::requests::store::is_lock_contention(&error) {
                    let deadline = store.request_deadline(base_deadline);
                    #[cfg(test)]
                    AFTER_WAIT_LOCK_TIMEOUT.with(|slot| {
                        if let Some(sender) = slot.borrow_mut().take() {
                            let _sent = sender.send(());
                        }
                    });
                    if Instant::now() >= deadline {
                        return Answer::Deadline(queued.elapsed().as_secs_f64());
                    }
                    thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
                    interval = (interval * 2).min(Duration::from_secs(1));
                    continue;
                }
                let _logged = writeln!(io::stderr().lock(), "door request wait: {}", error.line());
                return Answer::ReadFailure(queued.elapsed().as_secs_f64());
            }
        };
        #[cfg(test)]
        AFTER_WAIT_READ.with(|hook| {
            if let Some(action) = hook.borrow_mut().take() {
                action();
            }
        });
        let deadline = store.request_deadline(base_deadline);
        match if control.is_some() {
            Ok(false)
        } else {
            peer_disconnected(stream)
        } {
            Ok(true) => return Answer::Disconnect(queued.elapsed().as_secs_f64()),
            Err(error) => {
                let _logged = writeln!(io::stderr().lock(), "door wait peer: {error}");
                return Answer::ReadFailure(queued.elapsed().as_secs_f64());
            }
            Ok(false) => {}
        }
        if record.value()["state"] == "adjudicated" {
            if let Err(error) = crate::requests::command::validate_label(record.value()) {
                let _logged =
                    writeln!(io::stderr().lock(), "door request answer: {}", error.line());
                return Answer::ReadFailure(queued.elapsed().as_secs_f64());
            }
            match store.claim_request(id) {
                Ok(true) => {}
                Ok(false) => return Answer::ReadFailure(queued.elapsed().as_secs_f64()),
                Err(error) => {
                    let _logged =
                        writeln!(io::stderr().lock(), "door request claim: {}", error.line());
                    return Answer::ReadFailure(queued.elapsed().as_secs_f64());
                }
            }
            return if record.value()["label"]["treatment"] == "allow" {
                Answer::Allow(queued.elapsed().as_secs_f64())
            } else {
                Answer::Refuse(queued.elapsed().as_secs_f64())
            };
        }
        if Instant::now() >= deadline {
            return Answer::Deadline(queued.elapsed().as_secs_f64());
        }
        thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
        interval = (interval * 2).min(Duration::from_secs(1));
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn serve_request(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    route: Option<&transport::HostRunner>,
    runner: Option<&dyn transport::Runner>,
    owner_home: Option<&Path>,
    rubric: Option<&Rubric>,
    fixture_store: Option<&Store>,
    started: Instant,
) -> io::Result<(Value, Vec<u8>)> {
    serve_request_with_agent(
        stream,
        registration,
        peer,
        request,
        route,
        runner,
        owner_home,
        rubric,
        fixture_store,
        None,
        None,
        started,
    )
}

#[allow(clippy::too_many_arguments)]
fn preflight_refusal(
    registration: &Registration,
    peer: u32,
    request: &Value,
    reason: &str,
    stderr_bytes: usize,
    owner_home: Option<&Path>,
    fixture_store: Option<&Store>,
    started: Instant,
) -> Value {
    let mut reply = transport::refusal(registration, peer, reason, started);
    reply["stderr_bytes"] = json!(stderr_bytes);
    let _logged = writeln!(
        io::stderr().lock(),
        "door preflight: run={} check={reason}",
        registration.run
    );
    if peer != registration.worker_uid {
        return reply;
    }
    let file = || -> io::Result<String> {
        let opened = if fixture_store.is_none() {
            let home = owner_home.ok_or_else(|| io::Error::other("door-requests-unregistered"))?;
            Some(Store::open(home, &registration.loop_name, true).map_err(io::Error::other)?)
        } else {
            None
        };
        let store = fixture_store
            .or(opened.as_ref())
            .ok_or_else(|| io::Error::other("door store is absent"))?;
        let maximum = if transport::argument_bytes(request)
            .as_deref()
            .is_some_and(compute::candidate)
        {
            compute::DEADLINE_MS
        } else {
            120_000
        };
        let store = store
            .for_request(
                started
                    + Duration::from_millis(
                        request["deadline_ms"]
                            .as_u64()
                            .unwrap_or(maximum)
                            .min(maximum),
                    ),
            )
            .map_err(io::Error::other)?;
        let setting = store
            .ensure_first_mode("preflight")
            .map_err(io::Error::other)?;
        let record = request_record(
            registration,
            "ssh",
            transport::Operation::GitUpload,
            &setting,
            &json!({"decision":"refuse","reason":reason}),
            false,
            &[],
        )?;
        let mut value = record.into_value();
        value["class"] = json!("preflight");
        value["operation"] = json!("preflight");
        value["shape_key"] = json!(format!("preflight:{reason}"));
        value["state"] = json!("preflight-refused");
        value["effect"] = effect_from_final(&reply);
        value["effect"]["preflight"] = json!({"check":reason,"words":request["argv"]});
        let record = RequestRecord::decode(value).map_err(io::Error::other)?;
        let id = record.id().to_owned();
        store
            .with_request_id(&id)
            .file(record)
            .map_err(io::Error::other)?;
        Ok(id)
    };
    match file() {
        Ok(id) => reply["request_id"] = json!(id),
        Err(error) => {
            let _logged = writeln!(
                io::stderr().lock(),
                "door preflight record: run={} check={reason}: {error}",
                registration.run
            );
            reply["request_record_error"] = json!(error.to_string());
            reply["request_record_state"] = json!("failed");
        }
    }
    reply
}

#[cfg(test)]
thread_local! {
    static ROOT_ADMITTED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn admission_failed_refusal(
    registration: &Registration,
    peer: u32,
    reason: &str,
    error: &io::Error,
    started: Instant,
) -> Value {
    let _logged = writeln!(
        io::stderr().lock(),
        "door preflight: run={} check={reason}",
        registration.run
    );
    let _logged = writeln!(
        io::stderr().lock(),
        "door preflight record: run={} check={reason}: {error}",
        registration.run
    );
    let mut reply = transport::refusal(registration, peer, reason, started);
    reply["request_record_state"] = json!("failed");
    reply["request_record_error"] = json!(error.to_string());
    reply
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn root_refusal(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    owner_home: &Path,
    error: &LaneError,
    started: Instant,
) -> io::Result<()> {
    root_refusal_at(
        stream,
        registration,
        peer,
        request,
        owner_home,
        error,
        lifetime::Start::at(started)?,
    )
}

fn root_refusal_at(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    owner_home: &Path,
    error: &LaneError,
    acceptance: lifetime::Start,
) -> io::Result<()> {
    let started = acceptance.awake;
    let (bounded_request, _) = announce_compute_deadline(
        stream,
        registration,
        peer,
        request,
        None,
        acceptance.elapsed().unwrap_or(Duration::MAX),
    );
    let request = &bounded_request;
    let deadline = started
        + Duration::from_millis(
            request["deadline_ms"]
                .as_u64()
                .filter(|ms| *ms > 0 && *ms <= 120_000)
                .unwrap_or(120_000),
        );
    let wait = RequestWait::new(stream)?.with_lifetime(acceptance, true, stream)?;
    let (_request_guard, admission_error) = if peer == registration.worker_uid {
        match RequestGuard::acquire_wait(owner_home, registration, request, None, started) {
            Ok((Some(guard), _)) => (Some(guard), None),
            Ok((None, waited)) => {
                return concurrent_refusal(&wait, registration, peer, started, waited, deadline, 2)
                    .map(|_| ());
            }
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    #[cfg(test)]
    ROOT_ADMITTED.with(|slot| {
        if let Some(action) = slot.borrow_mut().take() {
            action();
        }
    });
    let diagnostic = format!("{}\n", error.line());
    let reply = admission_error.map_or_else(
        || {
            preflight_refusal(
                registration,
                peer,
                request,
                "door-compute-root-refusal",
                diagnostic.len(),
                Some(owner_home),
                None,
                started,
            )
        },
        |error| {
            let mut reply = admission_failed_refusal(
                registration,
                peer,
                "door-compute-root-refusal",
                &error,
                started,
            );
            reply["stderr_bytes"] = json!(diagnostic.len());
            reply
        },
    );
    let diagnostic_deadline = Instant::now() + Duration::from_secs(2);
    for bytes in diagnostic.as_bytes().chunks(8192) {
        if let Err(error) = frame_write_until(
            stream,
            &json!({"schema":2,"type":"stderr","bytes":bytes}),
            diagnostic_deadline,
        ) {
            finish_preflight(
                &reply,
                (Some(owner_home), None, &registration.loop_name),
                &json!("unknown"),
            );
            return Err(error);
        }
    }
    write_preflight_final(
        &wait,
        &reply,
        (Some(owner_home), None, &registration.loop_name),
        deadline,
    )
}

fn finish_preflight(
    reply: &Value,
    context: (Option<&Path>, Option<&Store>, &str),
    final_write: &Value,
) {
    let Some(id) = reply["request_id"].as_str() else {
        return;
    };
    let result = (|| {
        let opened = if context.1.is_none() {
            Some(Store::open(
                context
                    .0
                    .ok_or_else(|| LaneError::input("door-record-refusal", "owner home absent"))?,
                context.2,
                true,
            )?)
        } else {
            None
        };
        context
            .1
            .or(opened.as_ref())
            .ok_or_else(|| LaneError::input("door-record-refusal", "store absent"))?
            .finish_request(id, None, &{
                let mut ending = crate::requests::unobserved_ending();
                ending["final_write"] = final_write.clone();
                ending
            })
    })();
    if let Err(error) = result {
        post_reply_event(id, "terminal-record", error.kind);
    }
}

fn write_preflight_final(
    wait: &RequestWait,
    reply: &Value,
    context: (Option<&Path>, Option<&Store>, &str),
    deadline: Instant,
) -> io::Result<()> {
    let result = wait.write_final(reply, deadline);
    let ending = wait.ending_snapshot();
    finish_preflight(reply, context, &ending["final_write"]);
    result
}

fn announce_compute_deadline(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    route: Option<&transport::HostRunner>,
    elapsed: Duration,
) -> (Value, u64) {
    // Announce every well-formed authenticated compute candidate before admission.
    // Only a route-validated work request can select a longer owner deadline.
    let mut bounded_request = request.clone();
    let mut registered_deadline_ms = compute::DEADLINE_MS;
    let compute_args = transport::argument_bytes(request);
    if peer == registration.worker_uid
        && compute_args.as_deref().is_some_and(compute::candidate)
        && request.as_object().is_some_and(|row| {
            row.len() == 3
                && row.contains_key("schema")
                && row.contains_key("argv")
                && row.contains_key("deadline_ms")
        })
        && request["schema"] == 2
        && request["deadline_ms"]
            .as_u64()
            .is_some_and(|ms| ms > 0 && ms <= compute::MAX_DEADLINE_MS)
    {
        if registration.scope == Scope::Work
            && let (Some(route), Some(args)) = (route, compute_args.as_ref())
            && route.allowed(args, registration) == Some(transport::Operation::Compute)
        {
            registered_deadline_ms = route.compute_deadline_ms(args);
        }
        let bound = request["deadline_ms"]
            .as_u64()
            .unwrap_or(0)
            .min(registered_deadline_ms);
        bounded_request["deadline_ms"] = json!(bound);
        let deadline = Instant::now() + Duration::from_millis(bound).saturating_sub(elapsed);
        // Preserve the normal disconnect record even when the peer leaves before this frame.
        let _announcement = frame_write_until(
            stream,
            &transport::compute_deadline_frame(registered_deadline_ms, bound, deadline),
            Instant::now() + Duration::from_secs(2),
        );
    }
    if compute_args.as_deref().is_some_and(compute::candidate)
        && let Some(ms) = request["deadline_ms"]
            .as_u64()
            .filter(|ms| *ms > 0 && *ms <= compute::MAX_DEADLINE_MS)
    {
        bounded_request["deadline_ms"] = json!(ms.min(registered_deadline_ms));
    }
    (bounded_request, registered_deadline_ms)
}

#[allow(clippy::too_many_arguments)]
fn finish_stopped(
    store: &Store,
    id: &str,
    wait: &RequestWait,
    registration: &Registration,
    peer: u32,
    started: Instant,
    stop: lifetime::Cause,
    deadline: Instant,
) -> io::Result<(Value, Vec<u8>)> {
    let mut reply = transport::refusal(registration, peer, stop.reason(), started);
    reply["request_id"] = json!(id);
    let effect = observed_effect(&reply, wait);
    if let Err(error) = store.record_effect(id, effect).and_then(|record| {
        if crate::requests::decided_enforce(
            record.value()["mode"].as_str().unwrap_or_default(),
            &record.value()["would_do"]["decision"],
        ) {
            store.publish_observed(id)
        } else {
            store.publish_waiting(id)
        }
    }) {
        post_reply_failure(store, &registration.run, id, "stopped-record", error.kind);
        reply["request_record_error"] = json!(error.line());
    }
    wait.report(&mut reply);
    wait.write_final(&reply, deadline)?;
    Ok((reply, Vec::new()))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn serve_request_with_agent(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    route: Option<&transport::HostRunner>,
    runner: Option<&dyn transport::Runner>,
    owner_home: Option<&Path>,
    rubric: Option<&Rubric>,
    fixture_store: Option<&Store>,
    agent: Option<&dyn agent::AgentRunner>,
    configured_model: Option<&str>,
    started: Instant,
) -> io::Result<(Value, Vec<u8>)> {
    serve_request_with_agent_at(
        stream,
        registration,
        peer,
        request,
        route,
        runner,
        owner_home,
        rubric,
        fixture_store,
        agent,
        configured_model,
        started,
        lifetime::Start::at(started)?,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn serve_request_with_agent_at(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    route: Option<&transport::HostRunner>,
    runner: Option<&dyn transport::Runner>,
    owner_home: Option<&Path>,
    rubric: Option<&Rubric>,
    fixture_store: Option<&Store>,
    agent: Option<&dyn agent::AgentRunner>,
    configured_model: Option<&str>,
    started: Instant,
    acceptance: lifetime::Start,
) -> io::Result<(Value, Vec<u8>)> {
    serve_request_with_agent_at_context(
        stream,
        registration,
        peer,
        request,
        route,
        runner,
        owner_home,
        rubric,
        fixture_store,
        agent,
        configured_model,
        started,
        acceptance,
        None,
    )
}

struct WorkspaceSocketContext<'a> {
    runs: &'a OwnedFd,
    config_directory: &'a OwnedFd,
    owner: u32,
    wire: &'a [u8],
    judgement_wait_ms: u64,
    deadline_ms: u64,
}

fn workspace_deadline_announcement(
    started: Instant,
    requested_ms: u64,
    registered_ms: u64,
    judgement_wait_ms: u64,
) -> (Instant, Value) {
    let bound_ms = requested_ms.min(registered_ms);
    let deadline = started + Duration::from_millis(bound_ms);
    let frame = json!({"schema":3,"type":"compute-deadline",
        "registered_deadline_ms":registered_ms,"request_deadline_ms":requested_ms,
        "judgement_wait_ms":judgement_wait_ms,
        "remaining_ms":deadline.saturating_duration_since(Instant::now()).as_millis()});
    (deadline, frame)
}

struct WorkspaceWaitedBounds {
    command: Instant,
    route: Instant,
    final_frame: Instant,
}

fn workspace_waited_bounds(
    request_started: Instant,
    command_started: Instant,
    requested_ms: u64,
    registered_ms: u64,
    judgement_wait_ms: u64,
) -> WorkspaceWaitedBounds {
    let bound = Duration::from_millis(requested_ms.min(registered_ms));
    let window_end = request_started + bound + Duration::from_millis(judgement_wait_ms);
    // The adapter may wait five seconds for a terminal after stop. The stub
    // keeps its separate final-frame margin after this window.
    WorkspaceWaitedBounds {
        command: (command_started + bound).min(
            window_end
                .checked_sub(workspace_adapter::STOP_TERMINAL_BOUND)
                .unwrap_or(request_started),
        ),
        route: window_end,
        final_frame: window_end + Duration::from_secs(2),
    }
}

struct WorkspaceWorkerSink<'a> {
    wait: &'a RequestWait,
    stdout: usize,
    stderr: usize,
}

struct WorkspaceWatcherDone(Arc<AtomicBool>);

impl Drop for WorkspaceWatcherDone {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl workspace_adapter::WorkspaceOutputSink for WorkspaceWorkerSink<'_> {
    fn forward(
        &mut self,
        channel: workspace_adapter::OutputChannel,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), LaneError> {
        let mut writer = self
            .wait
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if writer.sealed {
            return Err(LaneError::input(
                "door-workspace-protocol-refusal",
                "worker output route has closed",
            ));
        }
        let kind = match channel {
            workspace_adapter::OutputChannel::Stdout => "stdout",
            workspace_adapter::OutputChannel::Stderr => "stderr",
        };
        frame_write_until(
            &mut writer.stream,
            &json!({"schema":3,"type":kind,"bytes":bytes}),
            deadline,
        )
        .map_err(|error| LaneError::input("door-workspace-protocol-refusal", error.to_string()))?;
        drop(writer);
        match channel {
            workspace_adapter::OutputChannel::Stdout => self.stdout += bytes.len(),
            workspace_adapter::OutputChannel::Stderr => self.stderr += bytes.len(),
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_claimed_workspace(
    _stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &WorkspaceRequest,
    route: &transport::HostRunner,
    admission: workspace_adapter::WorkspaceAdmission<'_>,
    store: &Store,
    wait: &Arc<RequestWait>,
    id: &str,
    mut effect: Value,
    ending: Value,
    started: Instant,
    admission_deadline: Instant,
    context: &WorkspaceSocketContext<'_>,
    mode: execute_command::policy::DoorMode,
    announcement_sent: bool,
) -> Result<Value, LaneError> {
    let ending_guard = RequestEnding {
        store,
        wait: wait.as_ref(),
        id,
    };
    let command_started = if announcement_sent {
        Instant::now()
    } else {
        started
    };
    let (ordinary_deadline, announcement) = workspace_deadline_announcement(
        command_started,
        request.envelope().deadline_ms,
        context.deadline_ms,
        context.judgement_wait_ms,
    );
    let (deadline, route_lifetime, final_deadline) = if announcement_sent {
        let bounds = workspace_waited_bounds(
            started,
            command_started,
            request.envelope().deadline_ms,
            context.deadline_ms,
            context.judgement_wait_ms,
        );
        (bounds.command, bounds.route, bounds.final_frame)
    } else {
        let lifetime = ordinary_deadline + Duration::from_secs(245);
        (ordinary_deadline, lifetime, lifetime)
    };
    if let Some(stop) = wait.stop(admission_deadline.min(deadline)) {
        effect["reason"] = json!(stop.reason());
        let mut stopped_ending = ending;
        stopped_ending["cause"] = json!(stop.name());
        stopped_ending["wall_clock"] = json!("monotonic-awake");
        stopped_ending["local_child"] = json!("not-started");
        stopped_ending["remote"]["state"] = json!("not-started");
        effect["ending"] = stopped_ending.clone();
        wait.remember_effect(effect.clone());
        let finished = store.finish_request(id, Some(effect), &stopped_ending);
        finished?;
        return Err(LaneError::input(
            stop.reason(),
            "request ended before the executor call; nothing was run",
        ));
    }
    let stop_flag = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let _done_on_unwind = WorkspaceWatcherDone(Arc::clone(&done));
    let watched_wait = Arc::clone(wait);
    let watched_flag = Arc::clone(&stop_flag);
    let watched_done = Arc::clone(&done);
    let watcher = thread::spawn(move || {
        while !watched_done.load(Ordering::Acquire) {
            if watched_wait.stop(deadline).is_some() {
                watched_flag.store(true, Ordering::Release);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let mut sink = WorkspaceWorkerSink {
        wait,
        stdout: 0,
        stderr: 0,
    };
    let result = route.run_workspace(
        request,
        admission,
        id,
        &mut sink,
        workspace_adapter::WorkspaceStop {
            flag: &stop_flag,
            cause: "worker-disconnected",
            selected: Some(&wait.cause),
        },
        route_lifetime,
    );
    done.store(true, Ordering::Release);
    let _joined = watcher.join();
    let mut reply = transport::refusal(registration, peer, "door-workspace-unknown", started);
    reply["schema"] = json!(3);
    reply["stdout_bytes"] = json!(sink.stdout);
    reply["stderr_bytes"] = json!(sink.stderr);
    if let Ok(result) = &result {
        let evidence = result.evidence();
        let status = result
            .command_status()
            .unwrap_or_else(|| match &result.result.outcome {
                execute_command::workspace::Outcome::Exited { code } => *code,
                execute_command::workspace::Outcome::Signalled { signal } => {
                    i32::try_from(*signal).unwrap_or(0).saturating_add(128)
                }
                execute_command::workspace::Outcome::TimedOut => 124,
                execute_command::workspace::Outcome::Unknown => 125,
            });
        let reason = match result.ending {
            workspace_adapter::Ending::Complete => "door-complete",
            workspace_adapter::Ending::NodeDeadline => wait
                .cause
                .get()
                .filter(|cause| *cause == lifetime::Cause::Deadline)
                .map_or("door-complete", lifetime::Cause::reason),
            workspace_adapter::Ending::OutputIncomplete => "door-workspace-incomplete",
            workspace_adapter::Ending::OutputLimit => "door-output-limit-refusal",
            workspace_adapter::Ending::NothingRan(_) => "door-workspace-not-started",
            workspace_adapter::Ending::Incomplete => wait
                .cause
                .get()
                .map_or("door-workspace-unknown", lifetime::Cause::reason),
            workspace_adapter::Ending::Interrupted(_) => wait
                .cause
                .get()
                .map_or("door-disconnect-refusal", lifetime::Cause::reason),
        };
        reply["reason"] = json!(reason);
        if reason == "door-request-deadline" {
            reply["registered_deadline_ms"] = announcement["registered_deadline_ms"].clone();
            reply["request_deadline_ms"] = announcement["request_deadline_ms"].clone();
        }
        reply["status"] = json!(status);
        reply["compute_exit_status"] = json!(status);
        effect["state"] = evidence["ending"].clone();
        effect["reason"] = json!(reason);
        effect["exit_status"] = match &result.result.outcome {
            execute_command::workspace::Outcome::Exited { code } => json!(code),
            _ => result
                .command_status()
                .map_or(Value::Null, |status| json!(status)),
        };
        effect["ref_check"] = json!("not-applicable");
        effect["stdout_bytes"] = json!(sink.stdout);
        effect["stderr_bytes"] = json!(sink.stderr);
        effect["mediation_wall_seconds"] = json!(started.elapsed().as_secs_f64());
        effect["compute_wall_seconds"] = json!(result.result.wall_seconds);
        effect["workspace"]["result"] = json!(result.result);
        effect["workspace"]["steps"] = json!(result.steps);
        effect["workspace_node"] = evidence;
    } else if let Err(error) = &result {
        reply["request_record_error"] = json!(error.line());
        effect["state"] = json!("unknown");
        effect["reason"] = json!("door-workspace-unknown");
        effect["ref_check"] = json!("not-applicable");
        effect["stdout_bytes"] = json!(sink.stdout);
        effect["stderr_bytes"] = json!(sink.stderr);
        effect["mediation_wall_seconds"] = json!(started.elapsed().as_secs_f64());
        effect["workspace_node"] = json!({
            "node_reason":"unobserved","entry_version":"unobserved",
            "entry_version_differs":false,"output_incomplete":true,
            "child_started":null,"start_failure":null,
            "output_bytes":sink.stdout + sink.stderr,
            "result":effect["workspace"]["result"],"steps":[],
            "ending":"unknown","cause":"route-incomplete","door_cause":null
        });
        if let Some(stop) = wait.cause.get().filter(|cause| {
            matches!(
                cause,
                lifetime::Cause::Deadline
                    | lifetime::Cause::Disconnect
                    | lifetime::Cause::ObservationFailure
            )
        }) {
            reply["reason"] = json!(stop.reason());
            effect["reason"] = json!(stop.reason());
            effect["workspace_node"]["door_cause"] = json!(stop.name());
            if stop == lifetime::Cause::Deadline {
                reply["registered_deadline_ms"] = announcement["registered_deadline_ms"].clone();
                reply["request_deadline_ms"] = announcement["request_deadline_ms"].clone();
            }
        }
    }
    wait.cause.select(lifetime::Cause::for_reply(
        reply["reason"].as_str().unwrap_or_default(),
    ));
    effect["ending"] = wait.ending_snapshot();
    wait.remember_effect(effect.clone());
    let recorded = store.record_effect(id, effect);
    if let Err(error) = recorded {
        reply["request_record_error"] = json!(error.line());
        post_reply_event(id, "terminal-record", error.kind);
    } else if mode.as_str() == "enforce"
        && let Err(error) = store.publish_observed(id)
    {
        reply["request_record_error"] = json!(error.line());
    }
    wait.report(&mut reply);
    let sent = wait.write_final(&reply, final_deadline);
    sent.map_err(|error| LaneError::input("door-workspace-protocol-refusal", error.to_string()))?;
    drop(ending_guard);
    Ok(reply)
}

#[allow(clippy::too_many_arguments)]
fn finish_waiting_without_run(
    registration: &Registration,
    peer: u32,
    store: &Store,
    wait: &RequestWait,
    id: &str,
    mut effect: Value,
    mut ending: Value,
    reason: &str,
    detail: &str,
    started: Instant,
    deadline: Instant,
    waited: Duration,
) -> Result<Value, LaneError> {
    let cause = wait.cause.select(lifetime::Cause::for_reply(reason));
    ending["cause"] = json!(cause.name());
    ending["local_child"] = json!("not-started");
    ending["remote"]["state"] = json!("not-started");
    effect["state"] = json!("refused");
    effect["reason"] = json!(reason);
    effect["ref_check"] = json!("not-applicable");
    effect["ending"] = ending.clone();
    wait.remember_effect(effect.clone());
    store.record_effect(id, effect)?;
    let mut reply = transport::refusal(registration, peer, reason, started);
    reply["schema"] = json!(3);
    reply["request_id"] = json!(id);
    reply["request_record_error"] = json!(detail);
    if reason == "door-request-concurrent" {
        concurrent_fields(&mut reply, waited);
    }
    wait.report(&mut reply);
    wait.write_final(&reply, deadline)
        .map_err(|error| LaneError::input("door-workspace-protocol-refusal", error.to_string()))?;
    Ok(reply)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn serve_request_with_agent_at_context(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    request: &Value,
    route: Option<&transport::HostRunner>,
    runner: Option<&dyn transport::Runner>,
    owner_home: Option<&Path>,
    rubric: Option<&Rubric>,
    fixture_store: Option<&Store>,
    agent: Option<&dyn agent::AgentRunner>,
    configured_model: Option<&str>,
    started: Instant,
    acceptance: lifetime::Start,
    workspace: Option<WorkspaceSocketContext<'_>>,
) -> io::Result<(Value, Vec<u8>)> {
    let (bounded_request, registered_deadline_ms) = announce_compute_deadline(
        stream,
        registration,
        peer,
        request,
        route,
        acceptance.elapsed().unwrap_or(Duration::MAX),
    );
    let request = &bounded_request;
    // Classify only a route-validated operation; all other shapes retain exclusive admission.
    let is_workspace_request = request["schema"] == 3;
    let admission_operation = if is_workspace_request {
        Some(transport::Operation::Compute)
    } else {
        route.and_then(|route| {
            transport::argument_bytes(request).and_then(|args| route.allowed(&args, registration))
        })
    };
    let maximum = if admission_operation == Some(transport::Operation::Compute) {
        registered_deadline_ms
    } else {
        120_000
    };
    // Invalid words still reach the existing request-shape refusal below.
    let budget = request["deadline_ms"]
        .as_u64()
        .filter(|ms| *ms > 0 && *ms <= maximum)
        .unwrap_or(maximum);
    let admission_deadline = started + Duration::from_millis(budget);
    let full_close = !matches!(
        admission_operation,
        Some(
            transport::Operation::GitReceive
                | transport::Operation::GitUpload
                | transport::Operation::GitUploadV2
        )
    );
    let wait = std::sync::Arc::new(
        RequestWait::new(stream)?.with_lifetime(acceptance, full_close, stream)?,
    );
    if is_workspace_request
        && peer == registration.worker_uid
        && let Some(context) = workspace.as_ref()
        && let Some(requested_ms) = request["deadline_ms"].as_u64().filter(|ms| *ms > 0)
    {
        let (_, announcement) = workspace_deadline_announcement(
            started,
            requested_ms,
            context.deadline_ms,
            context.judgement_wait_ms,
        );
        frame_write_until(stream, &announcement, started + PEER_DEADLINE)?;
    }
    // Claim the authenticated box before any preflight or intent record write,
    // and retain it through the durable effect and sent final reply.
    let (mut request_guard, admission_error) =
        if let Some(home) = owner_home.filter(|_| peer == registration.worker_uid) {
            let clock: &dyn AdmissionClock = &RealAdmissionClock;
            #[cfg(test)]
            let fixture_clock = ADMISSION_CLOCK.with(|slot| slot.borrow().clone());
            #[cfg(test)]
            let clock = fixture_clock.as_deref().unwrap_or(clock);
            match RequestGuard::acquire_controlled(
                home,
                registration,
                request,
                admission_operation,
                started,
                clock,
                Some((&wait, admission_deadline)),
            ) {
                Ok((Some(guard), _)) => (Some(guard), None),
                Ok((None, waited)) => {
                    if let Some(stop) = wait.stop(admission_deadline) {
                        return stopped_admission_refusal(
                            &wait,
                            registration,
                            peer,
                            started,
                            waited,
                            admission_deadline,
                            stop,
                            if is_workspace_request { 3 } else { 2 },
                        );
                    }
                    return concurrent_refusal(
                        &wait,
                        registration,
                        peer,
                        started,
                        waited,
                        admission_deadline,
                        if is_workspace_request { 3 } else { 2 },
                    );
                }
                Err(error) => (None, Some(error)),
            }
        } else {
            (None, None)
        };
    let refuse = |reason| {
        // Preserve preflight evidence when custody cannot be opened, but never
        // attempt a record write without owning this box's admission lock.
        if let Some(error) = &admission_error {
            return admission_failed_refusal(registration, peer, reason, error, started);
        }
        preflight_refusal(
            registration,
            peer,
            request,
            reason,
            0,
            owner_home,
            fixture_store,
            started,
        )
    };
    if is_workspace_request {
        let mut completed_reply = None;
        let answer = (|| -> Result<String, LaneError> {
            if let Some(error) = &admission_error {
                return Err(LaneError::input("door-request-refusal", error.to_string()));
            }
            if request_guard.is_none() {
                return Err(LaneError::input(
                    "door-caller-authority-refusal",
                    "workspace request has no box admission guard",
                ));
            }
            let context = workspace.ok_or_else(|| {
                LaneError::input(
                    "door-workspace-protocol-refusal",
                    "workspace socket custody is absent",
                )
            })?;
            let route = route.ok_or_else(|| {
                LaneError::input(
                    "door-workspace-unregistered",
                    "registered node route is absent",
                )
            })?;
            let socket_request = request;
            let request = workspace_request(
                context.runs,
                registration,
                context.owner,
                route.authenticated_node().name(),
                context.wire,
            )?;
            let (quick, blacklist) =
                workspace_tables::read(context.config_directory, context.owner, &request)?;
            let classification = execute_command::workspace::classify(
                request.envelope(),
                request.grant(),
                &quick,
                &blacklist,
            )
            .map_err(|error| LaneError::input(error.kind, error.detail))?;
            let opened = if fixture_store.is_none() {
                Some(Store::open(
                    owner_home.ok_or_else(|| {
                        LaneError::input(
                            "door-workspace-unregistered",
                            "request store home is absent",
                        )
                    })?,
                    &registration.loop_name,
                    true,
                )?)
            } else {
                None
            };
            let store = fixture_store.or(opened.as_ref()).ok_or_else(|| {
                LaneError::input("door-workspace-unregistered", "request store is absent")
            })?;
            let mode_store = store
                .for_request(admission_deadline)?
                .with_stop_observer(Arc::clone(&wait));
            let setting = mode_store.ensure_first_mode("compute")?;
            let (learned, _fault) = WorkspaceAllowance::from_store_lookup(store, &request)?;
            let mode = execute_command::policy::DoorMode::from_record(setting["mode"].as_str())
                .map_err(|error| LaneError::input(error.0, "workspace mode differs"))?;
            let disposition = request.disposition(mode, &classification, learned.as_ref())?;
            if disposition == execute_command::workspace::Disposition::WaitForJudgement {
                let home = owner_home.ok_or_else(|| {
                    LaneError::input(
                        "door-workspace-unregistered",
                        "request store home is absent",
                    )
                })?;
                let Some(slot) = WorkspaceWaitSlot::acquire(home, registration)
                    .map_err(|error| LaneError::input("door-request-refusal", error.to_string()))?
                else {
                    let mut reply =
                        transport::refusal(registration, peer, "door-request-concurrent", started);
                    reply["schema"] = json!(3);
                    reply["request_record_error"] = json!(
                        "two workspace requests of this box are already waiting; nothing was run"
                    );
                    concurrent_fields(&mut reply, Duration::ZERO);
                    wait.report(&mut reply);
                    wait.write_final(&reply, admission_deadline)
                        .map_err(|error| {
                            LaneError::input("door-workspace-protocol-refusal", error.to_string())
                        })?;
                    completed_reply = Some(reply);
                    return Ok(String::new());
                };
                let waiting_reason = if agent.is_some() {
                    "workspace miss awaits judgement"
                } else {
                    "door-agent-unconfigured"
                };
                let record = workspace_record(
                    registration,
                    &setting,
                    &request,
                    disposition,
                    &json!({"decision":"undecided","reason":waiting_reason}),
                    Value::Null,
                )
                .map_err(|error| {
                    LaneError::input("door-workspace-context-differs", error.to_string())
                })?;
                let id = record.id().to_owned();
                let effect = record.value()["effect"].clone();
                let ending = crate::requests::unobserved_ending();
                let lease = store.file_active(record)?;
                let _ending_guard = RequestEnding {
                    store,
                    wait: wait.as_ref(),
                    id: &id,
                };
                let (command_deadline, _) = workspace_deadline_announcement(
                    started,
                    request.envelope().deadline_ms,
                    context.deadline_ms,
                    context.judgement_wait_ms,
                );
                frame_write_until(
                    stream,
                    &json!({"schema":3,"type":"waiting","request_id":id,
                        "reason":"judgement"}),
                    admission_deadline,
                )
                .map_err(|error| {
                    LaneError::input("door-workspace-protocol-refusal", error.to_string())
                })?;
                drop(request_guard.take());
                let reasons = match &classification {
                    execute_command::workspace::Classification::Miss { reasons } => {
                        reasons.as_slice()
                    }
                    _ => &[],
                };
                let input = request.agent_input(reasons, "")?;
                let bytes = match input.encode() {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        completed_reply = Some(finish_waiting_without_run(
                            registration,
                            peer,
                            store,
                            &wait,
                            &id,
                            effect,
                            ending,
                            "door-workspace-referred",
                            &error.to_string(),
                            started,
                            command_deadline,
                            Duration::ZERO,
                        )?);
                        drop(lease);
                        return Ok(String::new());
                    }
                };
                let Some(runner) = agent else {
                    completed_reply = Some(finish_waiting_without_run(
                        registration,
                        peer,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        "door-workspace-referred",
                        "door-agent-unconfigured",
                        started,
                        command_deadline,
                        Duration::ZERO,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                };
                let judgement_deadline =
                    Instant::now() + Duration::from_millis(context.judgement_wait_ms);
                let budget = judgement_deadline.saturating_duration_since(Instant::now());
                let returned = runner.judge_request_controlled(
                    &bytes,
                    budget,
                    &json!({"loop":registration.loop_name,"run":registration.run,
                        "request_id":id}),
                    &Instant::now,
                    &|| {
                        wait.stop(admission_deadline).is_some()
                            || Instant::now() >= judgement_deadline
                    },
                );
                let mut result = if Instant::now() >= judgement_deadline {
                    agent::RunnerOutcome::referral(
                        "timeout",
                        "door-judgement-window",
                        Instant::now(),
                    )
                } else {
                    returned
                };
                let binding = store.request(&id)?.into_value();
                let _verdict = result.apply_judgement(&binding);
                store.record_agent(
                    &id,
                    &result,
                    result.rubric_digest.as_deref(),
                    configured_model,
                    Some(&input.request),
                )?;
                if let Some(stop) = wait.stop(admission_deadline) {
                    completed_reply = Some(finish_waiting_without_run(
                        registration,
                        peer,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        stop.reason(),
                        "request ended during judgement; nothing was run",
                        started,
                        command_deadline,
                        Duration::ZERO,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                }
                if result.verdict != "allow" || result.status != "verdict" {
                    let reason = if result.verdict == "refuse" {
                        "door-rubric-refusal"
                    } else {
                        "door-workspace-referred"
                    };
                    completed_reply = Some(finish_waiting_without_run(
                        registration,
                        peer,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        reason,
                        &result.reason,
                        started,
                        command_deadline,
                        Duration::ZERO,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                }
                let clock: &dyn AdmissionClock = &RealAdmissionClock;
                #[cfg(test)]
                let fixture_clock = ADMISSION_CLOCK.with(|slot| slot.borrow().clone());
                #[cfg(test)]
                let clock = fixture_clock.as_deref().unwrap_or(clock);
                let (retaken, waited) = RequestGuard::acquire_controlled(
                    home,
                    registration,
                    socket_request,
                    admission_operation,
                    started,
                    clock,
                    Some((&wait, admission_deadline)),
                )
                .map_err(|error| LaneError::input("door-request-refusal", error.to_string()))?;
                let Some(guard) = retaken else {
                    completed_reply = Some(finish_waiting_without_run(
                        registration,
                        peer,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        "door-request-concurrent",
                        &format!("admission did not return after {waited:?}; nothing was run"),
                        started,
                        command_deadline,
                        waited,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                };
                request_guard = Some(guard);
                let fresh = workspace_request(
                    context.runs,
                    registration,
                    context.owner,
                    route.authenticated_node().name(),
                    context.wire,
                )?;
                let _tables =
                    workspace_tables::read(context.config_directory, context.owner, &fresh)?;
                if let Some(stop) = wait.stop(admission_deadline) {
                    completed_reply = Some(finish_waiting_without_run(
                        registration,
                        peer,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        stop.reason(),
                        "request ended before claim; nothing was run",
                        started,
                        command_deadline,
                        Duration::ZERO,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                }
                let allowance = match WorkspaceAllowance::from_judgement_record(store, &id, &fresh)
                {
                    Ok(allowance) => allowance,
                    Err(error) => {
                        completed_reply = Some(finish_waiting_without_run(
                            registration,
                            peer,
                            store,
                            &wait,
                            &id,
                            effect,
                            ending,
                            "door-request-refusal",
                            &error.detail,
                            started,
                            command_deadline,
                            Duration::ZERO,
                        )?);
                        drop(lease);
                        return Ok(String::new());
                    }
                };
                let claimed = match claim_workspace_under_admission(
                    store,
                    &lease,
                    request_guard.as_ref().ok_or_else(|| {
                        LaneError::input("door-request-refusal", "admission guard was lost")
                    })?,
                    &fresh,
                ) {
                    Ok(claimed) => claimed,
                    Err(error) => {
                        completed_reply = Some(finish_waiting_without_run(
                            registration,
                            peer,
                            store,
                            &wait,
                            &id,
                            effect,
                            ending,
                            "door-request-refusal",
                            &error.detail,
                            started,
                            command_deadline,
                            Duration::ZERO,
                        )?);
                        drop(lease);
                        return Ok(String::new());
                    }
                };
                drop(slot);
                #[cfg(test)]
                AFTER_WAITING_CLAIM.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().take() {
                        hook(&wait);
                    }
                });
                let mut run_effect = claimed.value()["effect"].clone();
                run_effect["state"] = json!("refused");
                run_effect["reason"] = json!("door-workspace-protocol-refusal");
                run_effect["ref_check"] = json!("not-applicable");
                run_effect["ending"] = ending.clone();
                completed_reply = Some(run_claimed_workspace(
                    stream,
                    registration,
                    peer,
                    &fresh,
                    route,
                    workspace_adapter::WorkspaceAdmission::Allowance(&allowance),
                    store,
                    &wait,
                    &id,
                    run_effect,
                    ending,
                    started,
                    admission_deadline,
                    &context,
                    mode,
                    true,
                )?);
                drop(lease);
                return Ok(String::new());
            }
            if matches!(
                disposition,
                execute_command::workspace::Disposition::Immediate
                    | execute_command::workspace::Disposition::ImmediateJudgeAlongside
                    | execute_command::workspace::Disposition::ImmediateRecordRefusal
                    | execute_command::workspace::Disposition::Block
            ) {
                let (would_do, quick_rule) = match &classification {
                    execute_command::workspace::Classification::QuickAllow(allow) => {
                        let evidence = allow.evidence();
                        (
                            json!({"decision":"allow","reason":evidence["rule"]}),
                            Some(evidence),
                        )
                    }
                    execute_command::workspace::Classification::Deny(denial) => {
                        let evidence = denial.evidence();
                        (
                            json!({"decision":"refuse","reason":format!(
                                "blacklist {}: {}",
                                evidence["blacklist_rule"].as_str().unwrap_or_default(),
                                evidence["reason"].as_str().unwrap_or_default()
                            )}),
                            None,
                        )
                    }
                    execute_command::workspace::Classification::Miss { .. } => match disposition {
                        execute_command::workspace::Disposition::ImmediateJudgeAlongside => (
                            json!({"decision":"undecided","reason":"workspace miss awaits judgement"}),
                            None,
                        ),
                        execute_command::workspace::Disposition::ImmediateRecordRefusal => (
                            json!({"decision":"refuse","reason":"learned refusal"}),
                            None,
                        ),
                        _ => (
                            json!({"decision":"allow","reason":"learned allowance"}),
                            None,
                        ),
                    },
                };
                let mut record = workspace_record(
                    registration,
                    &setting,
                    &request,
                    disposition,
                    &would_do,
                    Value::Null,
                )
                .map_err(|error| {
                    LaneError::input("door-workspace-context-differs", error.to_string())
                })?;
                if let Some(evidence) = quick_rule {
                    let mut value = record.into_value();
                    value["decision_tier"] = json!("quick-rule");
                    value["would_do_source"] = json!("quick-rule");
                    value["matched_rule"] = json!({"rule":evidence["rule"],
                        "policy_digest":request.grant().quick_policy_digest});
                    record = RequestRecord::decode(value)?;
                } else if disposition == execute_command::workspace::Disposition::Immediate
                    && let Some(allowance) = learned.as_ref().and_then(WorkspaceLearned::allowance)
                {
                    let mut value = record.into_value();
                    value["matched_rule"] = allowance.evidence()["rule"].clone();
                    record = RequestRecord::decode(value)?;
                }
                let id = record.id().to_owned();
                let mut effect = record.value()["effect"].clone();
                effect["state"] = json!("refused");
                effect["reason"] = json!(if disposition
                    == execute_command::workspace::Disposition::Block
                {
                    "door-request-refusal"
                } else {
                    "door-workspace-protocol-refusal"
                });
                effect["ref_check"] = json!("not-applicable");
                let ending = crate::requests::unobserved_ending();
                effect["ending"] = ending.clone();
                let mut check = record.value().clone();
                check["effect"] = effect.clone();
                RequestRecord::decode(check)?;
                if matches!(
                    disposition,
                    execute_command::workspace::Disposition::Immediate
                        | execute_command::workspace::Disposition::ImmediateJudgeAlongside
                        | execute_command::workspace::Disposition::ImmediateRecordRefusal
                ) {
                    if let Some(stop) = wait.stop(admission_deadline) {
                        return Err(LaneError::input(
                            stop.reason(),
                            "request ended before its workspace claim",
                        ));
                    }
                    let lease = store.file_active_workspace_claim(record, &request)?;
                    let intent =
                        if disposition == execute_command::workspace::Disposition::Immediate {
                            None
                        } else {
                            Some(WorkspaceIntent::from_store(store, &id, &request)?)
                        };
                    let admission = match &classification {
                        execute_command::workspace::Classification::QuickAllow(allow)
                            if disposition
                                == execute_command::workspace::Disposition::Immediate =>
                        {
                            workspace_adapter::WorkspaceAdmission::QuickRule(allow)
                        }
                        _ if disposition == execute_command::workspace::Disposition::Immediate => {
                            workspace_adapter::WorkspaceAdmission::Allowance(
                                learned
                                    .as_ref()
                                    .and_then(WorkspaceLearned::allowance)
                                    .ok_or_else(|| {
                                        LaneError::input(
                                            "door-workspace-context-differs",
                                            "learned allowance is absent",
                                        )
                                    })?,
                            )
                        }
                        _ => workspace_adapter::WorkspaceAdmission::AllowModeIntent(
                            intent.as_ref().ok_or_else(|| {
                                LaneError::input(
                                    "door-workspace-context-differs",
                                    "allow-mode intent is absent",
                                )
                            })?,
                        ),
                    };
                    if disposition
                        == execute_command::workspace::Disposition::ImmediateJudgeAlongside
                    {
                        let reasons = match &classification {
                            execute_command::workspace::Classification::Miss { reasons } => {
                                reasons.as_slice()
                            }
                            _ => &[],
                        };
                        let prepared = agent
                            .map(|runner| {
                                let input = request.agent_input(reasons, "")?;
                                let bytes = input.encode().map_err(|error| {
                                    LaneError::input(
                                        "door-workspace-protocol-refusal",
                                        error.to_string(),
                                    )
                                })?;
                                Ok::<_, LaneError>((runner, input, bytes))
                            })
                            .transpose();
                        let binding_source = store.request(&id)?.into_value();
                        let outcome = thread::scope(|scope| {
                            let task = prepared.as_ref().ok().and_then(Option::as_ref).map(
                                |(runner, _, bytes)| {
                                    let identity = json!({"loop":registration.loop_name,
                                        "run":registration.run,"request_id":id});
                                    scope.spawn(move || {
                                        runner.judge_request(
                                            bytes,
                                            Duration::from_millis(context.judgement_wait_ms),
                                            &identity,
                                        )
                                    })
                                },
                            );
                            let run = run_claimed_workspace(
                                stream,
                                registration,
                                peer,
                                &request,
                                route,
                                admission,
                                store,
                                &wait,
                                &id,
                                effect,
                                ending,
                                started,
                                admission_deadline,
                                &context,
                                mode,
                                false,
                            );
                            drop(request_guard.take());
                            if run.is_ok()
                                && let Err(error) = store.publish_after_reply(&id)
                            {
                                post_reply_failure(
                                    store,
                                    &registration.run,
                                    &id,
                                    "waiting-publication",
                                    error.kind,
                                );
                            }
                            match (task.map(std::thread::ScopedJoinHandle::join), &prepared) {
                                (Some(Ok(mut result)), Ok(Some((_, input, _)))) => {
                                    let _verdict = result.apply_judgement(&binding_source);
                                    if let Err(error) = store.record_agent(
                                        &id,
                                        &result,
                                        result.rubric_digest.as_deref(),
                                        configured_model,
                                        Some(&input.request),
                                    ) {
                                        post_reply_failure(
                                            store,
                                            &registration.run,
                                            &id,
                                            "agent-record",
                                            error.kind,
                                        );
                                    }
                                }
                                (Some(Err(_)), _) => post_reply_failure(
                                    store,
                                    &registration.run,
                                    &id,
                                    "agent-join",
                                    "door-agent-task-panicked",
                                ),
                                (None, Err(error)) => post_reply_failure(
                                    store,
                                    &registration.run,
                                    &id,
                                    "agent-input",
                                    error.kind,
                                ),
                                (None, Ok(None)) => post_reply_failure(
                                    store,
                                    &registration.run,
                                    &id,
                                    "agent-config",
                                    "door-agent-unconfigured",
                                ),
                                _ => {}
                            }
                            run
                        });
                        completed_reply = Some(outcome?);
                        drop(lease);
                        return Ok(String::new());
                    }
                    completed_reply = Some(run_claimed_workspace(
                        stream,
                        registration,
                        peer,
                        &request,
                        route,
                        admission,
                        store,
                        &wait,
                        &id,
                        effect,
                        ending,
                        started,
                        admission_deadline,
                        &context,
                        mode,
                        false,
                    )?);
                    drop(lease);
                    return Ok(String::new());
                }
                store.file(record)?;
                let finished = store.finish_request(&id, Some(effect), &ending);
                finished?;
                return Err(LaneError::input(
                    "door-request-refusal",
                    format!(
                        "{}; nothing was run",
                        would_do["reason"].as_str().unwrap_or_default()
                    ),
                ));
            }
            Err(LaneError::input(
                "door-workspace-context-differs",
                "workspace disposition was not handled; nothing was run",
            ))
        })();
        if let Some(reply) = completed_reply {
            return Ok((reply, Vec::new()));
        }
        let (reason, detail) = match answer {
            Ok(detail) => ("door-workspace-context-differs", detail),
            Err(error) => (error.kind, error.detail),
        };
        let mut reply = transport::refusal(registration, peer, reason, started);
        reply["schema"] = json!(3);
        reply["request_record_error"] = json!(detail);
        wait.report(&mut reply);
        wait.write_final(&reply, admission_deadline)?;
        return Ok((reply, Vec::new()));
    }
    let args = transport::argument_bytes(request);
    let compute_candidate = args.as_deref().is_some_and(compute::candidate);
    let maximum = if compute_candidate {
        registered_deadline_ms
    } else {
        120_000
    };
    let shape = args
        .as_ref()
        .is_some_and(|words| words.len() == 2 && words[0] == b"door-shape-probe");
    let reason = if peer != registration.worker_uid {
        Some("door-peer-refusal")
    } else if request.get("mirror_ref").is_some() {
        Some("door-changed-ref-refusal")
    } else if request.as_object().is_none_or(|object| {
        object.len() != 3
            || ["schema", "argv", "deadline_ms"]
                .iter()
                .any(|key| !object.contains_key(*key))
    }) || request["schema"] != 2
        || args.is_none()
        || request["deadline_ms"]
            .as_u64()
            .is_none_or(|ms| ms == 0 || ms > maximum)
    {
        Some("door-request-refusal")
    } else if registration.scope == Scope::Review {
        Some("door-review-compute-refusal")
    } else if shape {
        if args
            .as_ref()
            .is_some_and(|words| words[1] == registration.run.as_bytes())
        {
            Some("door-transport-pending")
        } else {
            Some("door-caller-authority-refusal")
        }
    } else {
        None
    };
    let deadline = started
        + Duration::from_millis(
            request["deadline_ms"]
                .as_u64()
                .unwrap_or(maximum)
                .min(maximum),
        );
    if let Some(reason) = reason {
        let mut reply = refuse(reason);
        if shape && let Some(document) = reply.as_object_mut() {
            document.remove("registration");
        }
        write_preflight_final(
            &wait,
            &reply,
            (owner_home, fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    }
    let Some(route) = route else {
        let reply = refuse("door-compute-unregistered");
        write_preflight_final(
            &wait,
            &reply,
            (owner_home, fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    };
    let words = if compute_candidate {
        match route.compute_words(args.as_deref().unwrap_or_default()) {
            Ok(words) => words,
            Err(reason) => {
                let reply = refuse(reason);
                write_preflight_final(
                    &wait,
                    &reply,
                    (owner_home, fixture_store, &registration.loop_name),
                    admission_deadline,
                )?;
                return Ok((reply, Vec::new()));
            }
        }
    } else {
        Vec::new()
    };
    let Some(operation) = route.allowed(args.as_deref().unwrap_or_default(), registration) else {
        let reply = refuse("door-caller-authority-refusal");
        write_preflight_final(
            &wait,
            &reply,
            (owner_home, fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    };
    let Some(runner) = runner else {
        let reply = refuse("door-compute-unregistered");
        write_preflight_final(
            &wait,
            &reply,
            (owner_home, fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    };
    let bound_runner = transport::ComputeRunner {
        inner: runner,
        words: &words,
        deadline,
        registered_deadline_ms,
        wait: Some(&wait),
    };
    let runner: &dyn transport::Runner = if compute_candidate {
        &bound_runner
    } else {
        runner
    };
    let Some(owner_home) = owner_home else {
        let reply = refuse("door-requests-unregistered");
        write_preflight_final(
            &wait,
            &reply,
            (owner_home, fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    };
    if let Some(error) = admission_error {
        return Err(error);
    }
    let opened = if fixture_store.is_none() {
        Some(
            Store::open(owner_home, &registration.loop_name, true)
                .map_err(io::Error::other)?
                .with_reader_deadline(deadline),
        )
    } else {
        None
    };
    let store = fixture_store
        .or(opened.as_ref())
        .ok_or_else(|| io::Error::other("door store is absent"))?;
    let store = store
        .for_request(deadline)
        .map_err(io::Error::other)?
        .with_wait_credit(std::sync::Arc::clone(&wait));
    let default_class = if compute_candidate { "compute" } else { "ssh" };
    let default_rubric = Rubric::decode(&json!({"schema":1,"class":default_class,
        "undecided_reason":"no registered rule for this operation","rules":[]}))
    .map_err(io::Error::other)?;
    let class = rubric.unwrap_or(&default_rubric).class();
    let setting = match store.ensure_first_mode(class) {
        Ok(setting) => setting,
        Err(error)
            if wait.stop(deadline).is_some()
                || crate::requests::store::is_lock_contention(&error) =>
        {
            let mut reply =
                transport::refusal(registration, peer, "door-request-record-refusal", started);
            reply["request_record_error"] = json!(error.line());
            wait.report(&mut reply);
            write_preflight_final(
                &wait,
                &reply,
                (Some(owner_home), fixture_store, &registration.loop_name),
                admission_deadline,
            )?;
            return Ok((reply, Vec::new()));
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    let shape_key = if compute_candidate {
        compute::shape(&words)
    } else {
        format!("{class}:{}", operation.name())
    };
    // The registered receive envelope names only this run's mirror. The first
    // Git command packet is checked against mirror_ref before forwarding bytes.
    let registered_receive = operation == transport::Operation::GitReceive;
    let (mut would_do, matched_rule, _history) = match if registered_receive {
        Ok((
            json!({"decision":"allow","reason":crate::requests::judgement::REGISTERED_RECEIVE_RULE}),
            Value::Null,
            json!([]),
        ))
    } else {
        rubric.map_or_else(
            || {
                store
                    .learned_judgement(class, operation.name(), &shape_key)
                    .or_else(|error| {
                        if wait.stop(deadline).is_some()
                            || crate::requests::store::is_lock_contention(&error)
                        {
                            return Err(error);
                        }
                        Ok((
                            json!({"decision":"undecided","reason":error.line()}),
                            Value::Null,
                            json!([]),
                        ))
                    })
            },
            |rubric| {
                Ok((
                    rubric.would_do(class, operation.name(), &shape_key),
                    Value::Null,
                    json!([]),
                ))
            },
        )
    } {
        Ok(judgement) => judgement,
        Err(error)
            if wait.stop(deadline).is_some()
                || crate::requests::store::is_lock_contention(&error) =>
        {
            let mut reply =
                transport::refusal(registration, peer, "door-request-record-refusal", started);
            reply["request_record_error"] = json!(error.line());
            wait.report(&mut reply);
            write_preflight_final(
                &wait,
                &reply,
                (Some(owner_home), fixture_store, &registration.loop_name),
                admission_deadline,
            )?;
            return Ok((reply, Vec::new()));
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    let mode = match execute_command::policy::DoorMode::from_record(setting["mode"].as_str()) {
        Ok(mode) => mode.as_str(),
        Err(error) => {
            let mut reply = refuse(error.0);
            wait.report(&mut reply);
            write_preflight_final(
                &wait,
                &reply,
                (Some(owner_home), fixture_store, &registration.loop_name),
                admission_deadline,
            )?;
            return Ok((reply, Vec::new()));
        }
    };
    let miss = would_do["decision"] == "undecided";
    let agent_words: Vec<_> = args
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|word| String::from_utf8_lossy(word))
        .collect();
    let input = execute_command::rubric::DoorInput {
        request: json!({"words":agent_words}),
        class: class.into(),
        rubric: String::new(),
    };
    let judge = |source: &Value, id: &str| {
        let mut result = agent.map_or_else(
            || agent::RunnerOutcome::referral("failure", "door-agent-unconfigured", Instant::now()),
            |runner| match input.encode() {
                Ok(bytes) => {
                    let began = Instant::now();
                    let life = wait.lifetime.as_ref();
                    let boot = life.and_then(|life| life.elapsed().ok()).unwrap_or_default();
                    let now = || began + life.and_then(|life| life.elapsed().ok()).unwrap_or(boot).saturating_sub(boot);
                    runner.judge_request_controlled(
                        &bytes,
                        wait.deadline(deadline).saturating_duration_since(Instant::now()),
                        &json!({"loop":registration.loop_name,"run":registration.run,"request_id":id}),
                        &now, &|| wait.stop(deadline).is_some(),
                    )
                },
                Err(error) => agent::RunnerOutcome::referral("failure", error.0, Instant::now()),
            },
        );
        let verdict = result.apply_judgement(source);
        if !result.observations["rubric_failure"].is_null() {
            let _logged = writeln!(
                io::stderr().lock(),
                "door-agent-failure {}",
                json!({"loop":registration.loop_name,"run":registration.run,
                    "reason":result.reason,"runner_evidence":result.observations})
            );
        }
        (result, verdict)
    };
    let initial_would_do = would_do.clone();
    let synchronous_agent = miss && mode != "allow" && agent.is_some();
    let initially_immediate = mode == "allow" || (mode == "enforce" && !miss);
    let record = request_record(
        registration,
        class,
        operation,
        &setting,
        &initial_would_do,
        !initially_immediate && !synchronous_agent,
        &words,
    )?;
    let mut value = record.into_value();
    if registered_receive {
        crate::requests::judgement::registered_receive(&mut value);
    } else {
        value["matched_rule"] = matched_rule;
    }
    let record = RequestRecord::decode(value).map_err(io::Error::other)?;
    let id = record.id().to_owned();
    let store = store.with_request_id(&id);
    let binding_source = record.value().clone();
    let activity = store.file_active(record);
    if let Err(error) = &activity {
        let _logged = writeln!(io::stderr().lock(), "door request file: {}", error.line());
        if let Err(attempt) = store.record_incomplete(&registration.run, &id, error.kind) {
            let _logged = writeln!(
                io::stderr().lock(),
                "door incomplete outcome: {}",
                attempt.line()
            );
        }
        let reason = if error.kind == "requests-store-full" {
            format!("{FULL_STORE_REASON_PREFIX}{}", error.detail)
        } else {
            "door-request-record-refusal".to_owned()
        };
        let mut reply = transport::refusal(registration, peer, &reason, started);
        reply["request_record_error"] = json!(error.line());
        wait.report(&mut reply);
        write_preflight_final(
            &wait,
            &reply,
            (Some(owner_home), fixture_store, &registration.loop_name),
            admission_deadline,
        )?;
        return Ok((reply, Vec::new()));
    }
    let _publication_activity = activity.map_err(io::Error::other)?;
    let _ending = RequestEnding {
        store: &store,
        wait: &wait,
        id: &id,
    };
    #[cfg(test)]
    REQUEST_FILED.with(|slot| {
        if let Some(sender) = slot.borrow_mut().take() {
            let _sent = sender.send(id.clone());
        }
    });
    #[cfg(test)]
    let deadline = REQUEST_READY.with(|slot| {
        slot.borrow_mut()
            .take()
            .map_or(Ok(deadline), |ready| ready(&id))
    })?;
    if (initially_immediate || synchronous_agent)
        && let Some(stop) = wait.stop(deadline)
    {
        return finish_stopped(
            &store,
            &id,
            &wait,
            registration,
            peer,
            started,
            stop,
            deadline,
        );
    }
    if synchronous_agent {
        // The intent is durable before any vendor call, including audit.
        // record_agent merges under the store lock before publishing waiting.
        let (result, _verdict) = judge(&binding_source, &id);
        let stopped = wait.stop(deadline);
        if stopped.is_some()
            && let Some(life) = &wait.lifetime
        {
            life.finish();
        }
        if let Err(error) = store.record_agent(
            &id,
            &result,
            result.rubric_digest.as_deref(),
            configured_model,
            None,
        ) {
            let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
            let mut reply =
                transport::refusal(registration, peer, "door-request-record-refusal", started);
            reply["request_record_error"] = json!(error.line());
            reply["request_id"] = json!(id);
            wait.report(&mut reply);
            wait.write_final(&reply, admission_deadline)?;
            return Ok((reply, Vec::new()));
        }
        if let Some(stop) = stopped {
            return finish_stopped(
                &store,
                &id,
                &wait,
                registration,
                peer,
                started,
                stop,
                deadline,
            );
        }
        would_do = json!({"decision":result.verdict,"reason":result.reason});
    }
    let decided_enforce = crate::requests::decided_enforce(mode, &would_do["decision"]);
    let immediate = mode == "allow" || decided_enforce;
    if decided_enforce && would_do["decision"] == "refuse" {
        let mut reply = transport::refusal(registration, peer, "door-rubric-refusal", started);
        reply["would_do"] = would_do;
        reply["request_id"] = json!(id);
        let result = store
            .record_effect(&id, observed_effect(&reply, &wait))
            .and_then(|_| store.publish_observed(&id));
        if let Err(error) = result {
            let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
            reply["reason"] = json!("door-record-incomplete");
            reply["request_record_error"] = json!(error.line());
        }
        wait.report(&mut reply);
        wait.write_final(&reply, admission_deadline)?;
        return Ok((reply, Vec::new()));
    }
    if immediate {
        if mode == "allow" && miss && agent.is_some() {
            // The intent is admitted and durable before the judgement starts.
            // Scoped ownership keeps the call attached to this service handler;
            // the transport can execute and return its final frame immediately.
            return thread::scope(|scope| {
                let agent_task = scope.spawn(|| {
                    let (result, _) = judge(&binding_source, &id);
                    store.record_agent(
                        &id,
                        &result,
                        result.rubric_digest.as_deref(),
                        configured_model,
                        None,
                    )
                });
                let complete = |reply: &Value| {
                    store
                        .record_effect(&id, observed_effect(reply, &wait))
                        .map(|_| ())
                };
                let outcome = transport::serve_compute(
                    stream,
                    registration,
                    peer,
                    operation,
                    runner,
                    started,
                    deadline,
                    "no-queue",
                    None,
                    Some(&would_do),
                    Some(&complete),
                    Some(&wait),
                );
                if outcome.is_ok() {
                    drop(request_guard.take());
                    #[cfg(test)]
                    AFTER_ALLOW_ADMISSION_RELEASE.with(|slot| {
                        if let Some(sender) = slot.borrow_mut().take() {
                            let _sent = sender.send(());
                        }
                    });
                }
                let judgement = agent_task.join();
                match outcome {
                    Ok(reply) => {
                        match judgement {
                            Err(_) => post_reply_failure(
                                &store,
                                &registration.run,
                                &id,
                                "agent-join",
                                "door-agent-task-panicked",
                            ),
                            Ok(Err(error)) => post_reply_failure(
                                &store,
                                &registration.run,
                                &id,
                                "agent-record",
                                error.kind,
                            ),
                            Ok(Ok(_)) => {
                                if let Err(error) = store.publish_after_reply(&id) {
                                    post_reply_failure(
                                        &store,
                                        &registration.run,
                                        &id,
                                        "waiting-publication",
                                        error.kind,
                                    );
                                }
                            }
                        }
                        recover_after_success(
                            &store,
                            &registration.run,
                            &reply,
                            &mut request_guard,
                        );
                        Ok((reply, Vec::new()))
                    }
                    Err(error) => {
                        let judgement =
                            judgement.map_err(|_| io::Error::other("door-agent-task-panicked"))?;
                        if let Err(error) = judgement {
                            let _recorded =
                                store.record_incomplete(&registration.run, &id, error.kind);
                            return Err(io::Error::other(error));
                        }
                        let _recorded = store.record_incomplete(
                            &registration.run,
                            &id,
                            "allow transport incomplete",
                        );
                        Err(error)
                    }
                }
            });
        }
        let complete = |reply: &Value| {
            if let Err(error) = store.record_effect(&id, observed_effect(reply, &wait)) {
                let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                return Err(error);
            }
            let publication = if decided_enforce {
                store.publish_observed(&id)
            } else {
                store.publish_waiting(&id)
            };
            if let Err(error) = publication {
                let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                return Err(error);
            }
            Ok(())
        };
        let result = transport::serve_compute(
            stream,
            registration,
            peer,
            operation,
            runner,
            started,
            deadline,
            "no-queue",
            None,
            Some(&would_do),
            Some(&complete),
            Some(&wait),
        );
        if result.is_err() {
            let _recorded =
                store.record_incomplete(&registration.run, &id, "allow transport incomplete");
        }
        return result.map(|reply| {
            recover_after_success(&store, &registration.run, &reply, &mut request_guard);
            (reply, Vec::new())
        });
    }
    let answer = wait_answer_controlled(&store, &id, stream, deadline, Some(&wait));
    match answer {
        Answer::Allow(wall) => {
            let complete = |reply: &Value| {
                if let Err(error) = store.record_effect(&id, observed_effect(reply, &wait)) {
                    let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                    return Err(error);
                }
                Ok(())
            };
            let result = transport::serve_compute(
                stream,
                registration,
                peer,
                operation,
                runner,
                started,
                deadline,
                "answered",
                Some(wall),
                Some(&would_do),
                Some(&complete),
                Some(&wait),
            );
            if result.is_err() {
                let _recorded =
                    store.record_incomplete(&registration.run, &id, "audit transport incomplete");
            }
            result.map(|reply| {
                recover_after_success(&store, &registration.run, &reply, &mut request_guard);
                (reply, Vec::new())
            })
        }
        Answer::ReadFailure(wall) => {
            let mut reply = queue_reply(
                registration,
                peer,
                "door-request-read-refusal",
                started,
                "refused",
                wall,
                &id,
            );
            if let Err(error) =
                store.record_incomplete(&registration.run, &id, "waiting read failed")
            {
                let _logged = writeln!(
                    io::stderr().lock(),
                    "door wait incomplete: {}",
                    error.line()
                );
            }
            wait.report(&mut reply);
            wait.write_final(&reply, admission_deadline)?;
            Ok((reply, Vec::new()))
        }
        Answer::Refuse(wall) | Answer::Deadline(wall) | Answer::Disconnect(wall) => {
            let (reason, state) = match answer {
                Answer::Refuse(_) => ("door-adjudicated-refusal", "refused"),
                Answer::Deadline(_) => ("door-request-deadline", "deadline"),
                Answer::Disconnect(_) => ("door-disconnect-refusal", "deadline"),
                Answer::Allow(_) | Answer::ReadFailure(_) => unreachable!(),
            };
            let mut reply = queue_reply(registration, peer, reason, started, state, wall, &id);
            if compute_candidate {
                reply["registered_deadline_ms"] = json!(registered_deadline_ms);
                reply["request_deadline_ms"] = request["deadline_ms"].clone();
            }
            if let Err(error) = store.record_effect(&id, observed_effect(&reply, &wait)) {
                let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                reply["reason"] = json!("door-record-incomplete");
                reply["request_record_error"] = json!(error.line());
            }
            wait.report(&mut reply);
            wait.write_final(&reply, admission_deadline)?;
            Ok((reply, Vec::new()))
        }
    }
}

/// Serve one bounded peer request, including its exact standard input bytes.
///
/// # Errors
///
/// Refuses malformed frames, overlong input or a broken connection.
pub fn serve_one(stream: &mut UnixStream, registration: &Registration) -> io::Result<Value> {
    serve_one_captured(stream, registration).map(|(reply, _input)| reply)
}

/// Listen only on a caller-supplied fixture socket.
///
/// # Errors
///
/// Refuses a failed bind or connection.
pub fn serve_socket(socket: &Path, registration: &Registration) -> io::Result<(Value, Vec<u8>)> {
    let listener = UnixListener::bind(socket)?;
    let (mut stream, _) = listener.accept()?;
    serve_one_captured(&mut stream, registration)
}

struct BoundSocket<'a>(&'a crate::SocketSlot);

impl Drop for BoundSocket<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.0.remove() {
            let _logged = writeln!(io::stderr().lock(), "door socket cleanup: {error}");
        }
    }
}

fn clear_stale_socket(slot: &crate::SocketSlot) -> Result<(), LaneError> {
    let Some(stat) = slot
        .metadata()
        .map_err(|error| LaneError::input("door-socket", error.to_string()))?
    else {
        return Ok(());
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || !UnixStream::connect(slot.address())
            .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
    {
        return Err(LaneError::input(
            "door-socket",
            "socket slot is occupied or changed",
        ));
    }
    slot.remove()
        .map_err(|error| LaneError::operation("door-socket", error.to_string()))
}

fn bind_socket_slot(
    slot: &crate::SocketSlot,
    finalize: impl FnOnce(&UnixListener, &nix::sys::stat::FileStat) -> Result<(), LaneError>,
) -> Result<(UnixListener, BoundSocket<'_>), LaneError> {
    clear_stale_socket(slot)?;
    let listener = UnixListener::bind(slot.address())
        .map_err(|error| LaneError::operation("door-socket", error.to_string()))?;
    let cleanup = BoundSocket(slot);
    let before = slot
        .metadata()
        .map_err(|error| LaneError::operation("door-socket", error.to_string()))?
        .filter(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFSOCK)
        .ok_or_else(|| LaneError::operation("door-socket", "bound socket is absent"))?;
    finalize(&listener, &before)?;
    let after = slot
        .metadata()
        .map_err(|error| LaneError::operation("door-socket", error.to_string()))?
        .ok_or_else(|| LaneError::operation("door-socket", "socket identity changed"))?;
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        || after.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || after.st_mode & 0o7777 != 0o660
    {
        return Err(LaneError::operation(
            "door-socket",
            "socket identity changed",
        ));
    }
    Ok((listener, cleanup))
}

fn socket_group_child(
    owner_home: &Path,
    service: &Path,
    slot: &crate::SocketSlot,
    listener: &UnixListener,
    loop_uid: u32,
    before: &nix::sys::stat::FileStat,
    block: (u32, u32),
) -> Result<PeerUidMap, LaneError> {
    let owner = nix::unistd::Uid::effective().as_raw();
    #[cfg(test)]
    if startup_tests::socket_fixture_enabled() {
        private_set_socket_group(
            nix::unistd::dup(slot.directory())
                .map_err(|error| LaneError::operation("fixture-socket", error.to_string()))?,
            &nix::unistd::dup(listener)
                .map_err(|error| LaneError::operation("fixture-socket", error.to_string()))?,
            loop_uid,
            before.st_dev,
            before.st_ino,
            0,
            Some((0, 0, loop_uid)),
        )?;
        return PeerUidMap::parse(
            &format!("0 {owner} 1\n{} 100000 {}\n", block.0, block.1),
            owner,
            block,
        );
    }
    let service_word = crate::pinned::owner_executable_word(service, owner)?;
    let args = vec![
        "unshare".into(),
        service_word,
        "_set-socket-group".into(),
        loop_uid.to_string(),
        before.st_dev.to_string(),
        before.st_ino.to_string(),
    ];
    let spec = crate::build::child(
        Path::new("/usr/bin/podman"),
        args,
        &crate::build::podman_environment(owner_home)?,
        owner_home,
        30,
        "door-socket",
    )
    .with_private_door_listener(slot.directory(), listener)?;
    let output = crate::build::checked_output(&spec, None)?;
    decode_socket_group_report(&output, owner, block)
}

fn decode_socket_group_report(
    output: &str,
    owner: u32,
    block: (u32, u32),
) -> Result<PeerUidMap, LaneError> {
    let report: Value = serde_json::from_str(output)
        .map_err(|_| LaneError::input("door-socket", "private socket report is malformed"))?;
    let value = report
        .as_object()
        .filter(|value| {
            value.len() == 3
                && value.contains_key("schema")
                && value.contains_key("status")
                && value.contains_key("uid_map")
        })
        .ok_or_else(|| LaneError::input("door-socket", "private socket report shape differs"))?;
    if value["schema"] != 1 || value["status"] != "door-socket-ready" {
        return Err(LaneError::input(
            "door-socket",
            "private socket report differs",
        ));
    }
    let source = value["uid_map"]
        .as_str()
        .filter(|source| source.len() <= 4096)
        .ok_or_else(|| {
            LaneError::input("door-socket", "private UID map is absent or over limit")
        })?;
    PeerUidMap::parse(source, owner, block)
}

/// Set the bound socket group beneath the handed directory in the owner namespace.
///
/// # Errors
///
/// Refuses malformed arguments, mismatched descriptors or a changed socket.
pub fn run_socket_group_private(args: &[String]) -> Result<String, LaneError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(LaneError::input(
            "door-socket-private",
            "namespace root is required",
        ));
    }
    socket_group_entry(args, &io::stdin(), None)?;
    crate::launch::exercise_resources::map_bytes("uid_map")
}

fn socket_group_entry(
    args: &[String],
    stream: &impl AsFd,
    fixture_view: Option<(u32, u32, u32)>,
) -> Result<(), LaneError> {
    let (group, device, inode) = parse_socket_group_args(args)?;
    let mut fds = crate::home::receive_private_descriptors(stream, 2)?;
    let listener = fds
        .pop()
        .ok_or_else(|| LaneError::input("door-socket-private", "listener descriptor is absent"))?;
    let directory = fds
        .pop()
        .ok_or_else(|| LaneError::input("door-socket-private", "directory descriptor is absent"))?;
    private_set_socket_group(directory, &listener, group, device, inode, 0, fixture_view)
}

fn parse_socket_group_args(args: &[String]) -> Result<(u32, u64, u64), LaneError> {
    let [group, device, inode] = args else {
        return Err(LaneError::input(
            "door-socket-private",
            "private form is incomplete",
        ));
    };
    let parse = |word: &str| {
        word.parse::<u64>()
            .map_err(|_| LaneError::input("door-socket-private", "private number is invalid"))
    };
    let group = u32::try_from(parse(group)?)
        .map_err(|_| LaneError::input("door-socket-private", "group is outside range"))?;
    let device = parse(device)?;
    let inode = parse(inode)?;
    Ok((group, device, inode))
}

fn private_set_socket_group(
    directory: OwnedFd,
    listener: &OwnedFd,
    group: u32,
    device: u64,
    inode: u64,
    namespace_owner: u32,
    fixture_view: Option<(u32, u32, u32)>,
) -> Result<(), LaneError> {
    let actual_owner = nix::unistd::Uid::effective().as_raw();
    let observed_effective = fixture_view.map_or(actual_owner, |view| view.0);
    if observed_effective != namespace_owner {
        return Err(LaneError::input(
            "door-socket-private",
            "namespace root is required",
        ));
    }
    let directory_stat = fstat(&directory)
        .map_err(|error| LaneError::input("door-socket-private", error.to_string()))?;
    if directory_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || fixture_view.map_or(directory_stat.st_uid, |view| view.1) != namespace_owner
        || fixture_view.map_or(directory_stat.st_gid, |view| view.2) != group
        || directory_stat.st_mode & 0o7777 != 0o750
    {
        return Err(LaneError::input(
            "door-socket-private",
            "socket directory differs",
        ));
    }
    let listener_stat = fstat(listener)
        .map_err(|error| LaneError::input("door-socket-private", error.to_string()))?;
    if listener_stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(LaneError::input(
            "door-socket-private",
            "listener descriptor is not a socket",
        ));
    }
    let slot = crate::SocketSlot::new(directory, std::ffi::OsStr::new("capability.sock"))
        .map_err(|error| LaneError::input("door-socket-private", error.to_string()))?;
    let before = slot
        .metadata()
        .map_err(|error| LaneError::input("door-socket-private", error.to_string()))?
        .ok_or_else(|| LaneError::input("door-socket-private", "socket entry is absent"))?;
    if before.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || (before.st_dev, before.st_ino) != (device, inode)
    {
        return Err(LaneError::input(
            "door-socket-private",
            "socket identity differs",
        ));
    }
    #[cfg(test)]
    let fixture_setter =
        fixture_view.is_some() && !FIXTURE_PRODUCTION_SETTER.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let fixture_setter = false;
    let setter_owner = if fixture_setter {
        actual_owner
    } else {
        namespace_owner
    };
    let setter_group = if fixture_setter {
        nix::unistd::Gid::effective().as_raw()
    } else {
        group
    };
    slot.set_owner_mode(setter_owner, setter_group, 0o660)
        .map_err(|error| LaneError::operation("door-socket-private", error.to_string()))?;
    let after = slot
        .metadata()
        .map_err(|error| LaneError::operation("door-socket-private", error.to_string()))?
        .ok_or_else(|| LaneError::operation("door-socket-private", "socket vanished"))?;
    if (after.st_dev, after.st_ino) != (device, inode)
        || fixture_view.map_or(after.st_uid, |view| view.1) != namespace_owner
        || fixture_view.map_or(after.st_gid, |view| view.2) != group
        || after.st_mode & 0o7777 != 0o660
    {
        return Err(LaneError::operation(
            "door-socket-private",
            "socket metadata differs",
        ));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FIXTURE_PRODUCTION_SETTER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn completed_door_group(generation: &Value, loop_name: &str) -> Result<u32, LaneError> {
    const KEYS: [&str; 10] = [
        "schema",
        "phase",
        "loop",
        "template_dir",
        "socket_dir",
        "stub_sha256",
        "service_sha256",
        "unit_dir",
        "registered",
        "host_door_gid",
    ];
    if generation["schema"] == 1 {
        return Err(LaneError::input(
            "door-generation-upgrade-required",
            "run install-door with valid door.toml to replace the pre-agent generation",
        ));
    }
    if generation.as_object().is_none_or(|object| {
        object.len() != KEYS.len() + 1
            || !object.contains_key("agent")
            || KEYS.iter().any(|key| !object.contains_key(*key))
    }) || generation["schema"] != 2
        || generation["phase"] != "complete"
        || generation["loop"] != loop_name
        || generation["registered"] != json!(["ssh"])
    {
        return Err(LaneError::input(
            "door-install",
            "completed door generation shape differs",
        ));
    }
    let _agent = config::runner(&generation["agent"], Path::new("/"), loop_name, None)?;
    generation["host_door_gid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("door-install", "recorded host door group is absent"))
}

/// Run the private per-loop socket service from the validated row and allocation.
///
/// # Errors
///
/// Refuses an absent installation, unprotected path, changed socket or service failure.
pub fn run_service(loop_name: &str) -> Result<(), LaneError> {
    run_service_with_snapshot(loop_name, |home, name| {
        Store::open(home, name, true)?
            .publish_snapshot()
            .map(|_| ())
    })
}

#[allow(clippy::too_many_lines)]
fn run_service_with_snapshot(
    loop_name: &str,
    publish: impl FnOnce(&Path, &str) -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("door-loop", error.message()))?;
    let owner_home = crate::caller_home()?;
    let owner = nix::unistd::Uid::effective().as_raw();
    let settings_path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("workers.toml");
    let config = settings_path
        .parent()
        .ok_or_else(|| LaneError::input("door-install", "configuration parent is absent"))?;
    let config_directory = crate::pinned::open_protected(&owner_home, config, owner)?;
    let config_stat = fstat(&config_directory)
        .map_err(|error| LaneError::input("door-compute-registration", error.to_string()))?;
    if SFlag::from_bits_truncate(config_stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || config_stat.st_uid != owner
        || config_stat.st_mode & 0o022 != 0
    {
        return Err(LaneError::input(
            "door-compute-registration",
            "configuration directory differs",
        ));
    }
    let generation_bytes = crate::pinned::read_private(
        &owner_home,
        &config.join("door-install-generation.json"),
        owner,
        0o600,
        65_536,
    )?;
    let generation: Value = serde_json::from_slice(&generation_bytes)
        .map_err(|error| LaneError::input("door-install", error.to_string()))?;
    let recorded_group = completed_door_group(&generation, loop_name)?;
    let service_path = config.join("door-service");
    let executable = std::env::current_exe()
        .map_err(|error| LaneError::input("door-install", error.to_string()))?;
    let service_bytes = crate::pinned::read_checked(
        &owner_home,
        &service_path,
        owner,
        (owner, nix::unistd::Gid::effective().as_raw(), 0o700),
        64 * 1024 * 1024,
    )?;
    if executable != service_path
        || generation["service_sha256"] != crate::build::sha256_bytes(&service_bytes, &owner_home)?
    {
        return Err(LaneError::input(
            "door-install",
            "service differs from the completed generation",
        ));
    }
    let settings = crate::settings::Settings::read(&settings_path)?;
    if let Err(error) = publish(&owner_home, loop_name) {
        Store::report_snapshot_failure(&error);
    }
    settings.validate_grant(&owner_home, loop_name)?;
    let row = crate::plan::registry(&settings, loop_name)?;
    let loop_uid = row["uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("door-registration", "row uid is absent"))?;
    let compute_deadlines = Arc::new(config::compute_deadlines(&generation["agent"])?);
    let workspace_judgement_wait_ms = config::workspace_judgement_wait_ms(&generation["agent"])?;
    let workspace_deadline_ms = config::workspace_deadline_ms(&generation["agent"])?;
    let agent_runner = Arc::new(config::runner(
        &generation["agent"],
        &owner_home,
        loop_name,
        Some(loop_uid),
    )?);
    writeln!(
        io::stderr().lock(),
        "door-agent-metadata {}",
        metadata::inspect(
            &agent_runner.entry,
            &owner_home,
            loop_name,
            &agent_runner.executable
        )
    )
    .map_err(|error| LaneError::operation("door-agent-journal", error.to_string()))?;
    let runs_root = Path::new(
        row["runs_root"]
            .as_str()
            .ok_or_else(|| LaneError::input("door-registration", "row runs root is absent"))?,
    );
    let runs =
        crate::home::verify_host_launch_root(Path::new("/"), &owner_home, runs_root, owner, 0)?;
    let block = crate::launch::worker_range(&owner_home, loop_name)?;
    let socket_dir = settings
        .socket_dir
        .as_deref()
        .ok_or_else(|| LaneError::input("door-install", "socket_dir is absent"))?;
    let socket = socket_dir.join("door/capability.sock");
    let door_directory = socket
        .parent()
        .ok_or_else(|| LaneError::input("door-socket", "socket parent is absent"))?;
    let directory = crate::home::pin_parent(door_directory, owner)?;
    let door_stat =
        fstat(&directory).map_err(|error| LaneError::input("door-install", error.to_string()))?;
    if door_stat.st_uid != owner
        || door_stat.st_gid != recorded_group
        || door_stat.st_mode & 0o7777 != 0o750
    {
        return Err(LaneError::input(
            "door-install",
            "registered socket directory differs from generation",
        ));
    }
    let slot = crate::SocketSlot::beneath(&directory, std::ffi::OsStr::new("capability.sock"))
        .map_err(|error| LaneError::input("door-socket", error.to_string()))?;
    let _lock = nix::fcntl::Flock::lock(
        File::from(directory),
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_file, error)| LaneError::input("door-socket-busy", error.to_string()))?;
    let loop_uid = row["uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("door-registration", "row uid is absent"))?;
    recover_at_start(&owner_home, loop_name);
    let mut peer_map = None;
    let (listener, _bound_socket) = bind_socket_slot(&slot, |listener, before| {
        peer_map = Some(socket_group_child(
            &owner_home,
            &service_path,
            &slot,
            listener,
            loop_uid,
            before,
            block,
        )?);
        Ok(())
    })?;
    let peer_map =
        Arc::new(peer_map.ok_or_else(|| {
            LaneError::operation("door-socket", "private UID map was not reported")
        })?);
    let active = Arc::new(AtomicUsize::new(0));
    let runs = Arc::new(runs);
    let row = Arc::new(row);
    let config = Arc::new(config.to_path_buf());
    let config_directory = Arc::new(config_directory);
    let loop_name = Arc::new(loop_name.to_owned());
    let owner_home = Arc::new(owner_home);
    for connection in listener.incoming() {
        let mut stream =
            connection.map_err(|error| LaneError::operation("door-socket", error.to_string()))?;
        let acceptance = lifetime::Start::now()
            .map_err(|error| LaneError::operation("door-clock", error.to_string()))?;
        let Some(guard) = admit_peer(&active, &mut stream) else {
            continue;
        };
        let runs = Arc::clone(&runs);
        let row = Arc::clone(&row);
        let config = Arc::clone(&config);
        let config_directory = Arc::clone(&config_directory);
        let loop_name = Arc::clone(&loop_name);
        let owner_home = Arc::clone(&owner_home);
        let peer_map = Arc::clone(&peer_map);
        let agent_runner = Arc::clone(&agent_runner);
        let compute_deadlines = Arc::clone(&compute_deadlines);
        thread::spawn(move || {
            let _guard = guard;
            let started = acceptance.awake;
            let result = (|| {
                let uid = mapped_peer_uid(&stream, &peer_map)?;
                let (request, request_wire) =
                    request_frame_read_until(&mut stream, started + PEER_DEADLINE)?;
                let probe_run = transport::argument_bytes(&request).and_then(|args| {
                    (args.len() == 2 && args[0] == b"door-shape-probe")
                        .then(|| String::from_utf8(args[1].clone()).ok())
                        .flatten()
                });
                let registration = probe_run
                    .map_or_else(
                        || {
                            crate::launch::door_registration(
                                &runs, &row, &loop_name, uid, block, owner,
                            )
                        },
                        |run| {
                            crate::launch::door_probe_registration(
                                &runs, &row, &loop_name, &run, uid, block, owner,
                            )
                        },
                    )
                    .map_err(io::Error::other)?;
                let route = match transport::HostRunner::load(
                    config_directory.as_ref(),
                    config.as_path(),
                    &loop_name,
                    owner,
                ) {
                    Ok(route) => Some(route.with_compute_deadlines(&compute_deadlines)),
                    Err(error) if error.kind == "door-compute-root-refusal" => {
                        return root_refusal_at(
                            &mut stream,
                            &registration,
                            uid,
                            &request,
                            &owner_home,
                            &error,
                            acceptance,
                        );
                    }
                    Err(error) => {
                        let _logged = writeln!(io::stderr().lock(), "door route: {}", error.line());
                        None
                    }
                };
                serve_request_with_agent_at_context(
                    &mut stream,
                    &registration,
                    uid,
                    &request,
                    route.as_ref(),
                    route.as_ref().map(|route| route as &dyn transport::Runner),
                    Some(owner_home.as_path()),
                    None,
                    None,
                    Some(agent_runner.as_ref()),
                    Some(&agent_runner.model),
                    started,
                    acceptance,
                    Some(WorkspaceSocketContext {
                        runs: runs.as_ref(),
                        config_directory: config_directory.as_ref(),
                        owner,
                        wire: &request_wire,
                        judgement_wait_ms: workspace_judgement_wait_ms,
                        deadline_ms: workspace_deadline_ms,
                    }),
                )
                .map(|_reply| ())
            })();
            if let Err(error) = result {
                let _logged = writeln!(io::stderr().lock(), "door connection: {error}");
                let _sent = frame_write(&mut stream, &connection_refusal(&error, started));
            }
        });
    }
    if slot
        .metadata()
        .map_err(|error| LaneError::operation("door-socket", error.to_string()))?
        .is_none_or(|stat| stat.st_mode & libc::S_IFMT != libc::S_IFSOCK)
    {
        return Err(LaneError::operation("door-socket", "socket changed type"));
    }
    Ok(())
}

fn connection_refusal(error: &io::Error, started: Instant) -> Value {
    let mut reply = json!({"schema":2,"type":"final","status":125,
        "reason":"door-request-refusal","ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
        "queue_state":"no-queue","queue_wall_seconds":null,"compute_exit_status":null,
        "mediation_wall_seconds":started.elapsed().as_secs_f64(),"compute_wall_seconds":0.0});
    if let Some(cause) = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<LaneError>())
        && crate::requests::store::is_lock_contention(cause)
    {
        reply["request_record_error"] = json!(cause.to_string());
    }
    reply
}

/// Send exact argument bytes to the registered socket and return its typed status.
///
/// # Errors
///
/// Refuses a failed connection, overlong argument list, or malformed response.
pub fn stub_call(socket: &Path, args: &[std::ffi::OsString], input: &[u8]) -> io::Result<Value> {
    transport::stub_call(socket, args, input)
}

/// Exercise one fixture class through the registered compute route and a private fixture socket.
///
/// # Errors
///
/// Refuses an absent route, unsafe fixture directory, failed service call or mode move.
pub(crate) fn exercise_mode_fixture(
    owner_home: &Path,
    registration: &Registration,
    case: &str,
) -> Result<Value, LaneError> {
    use crate::requests::{Mode, modes::ModeTarget};
    let store = Store::open(owner_home, &registration.loop_name, true)?
        .with_reader_budget(Duration::from_secs(120));
    let prior = store.modes()?["loop_settings"]
        .as_array()
        .and_then(|rows| rows.last())
        .and_then(|row| row["mode"].as_str())
        .and_then(Mode::parse);
    // Claims belong to the whole exercise, including a later refused call.
    let mut claims = json!({});
    #[cfg(test)]
    let result = if FIXTURE_FORCE_FLOOR_REFUSAL.with(std::cell::Cell::get) {
        store
            .set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "exercise-fixture",
                "fixture below-floor refusal",
                &now_nanos().to_string(),
                &[],
            )
            .map(|_| json!({}))
    } else if EXERCISE_CAT_RUNNER.with(std::cell::Cell::get) {
        exercise_mode_fixture_with(
            owner_home,
            registration,
            case,
            Some(Arc::new(CatRunner)),
            &mut claims,
        )
    } else {
        exercise_mode_fixture_with(owner_home, registration, case, None, &mut claims)
    };
    #[cfg(not(test))]
    let result = exercise_mode_fixture_with(owner_home, registration, case, None, &mut claims);
    let restore = (|| -> Result<Value, LaneError> {
        let current = store.modes()?["loop_settings"]
            .as_array()
            .and_then(|rows| rows.last())
            .and_then(|row| row["mode"].as_str())
            .and_then(Mode::parse);
        let target = prior.unwrap_or_else(|| store.floor());
        if current.is_some_and(|mode| mode.domain() > target.domain()) {
            #[cfg(test)]
            if FIXTURE_FAIL_RESTORE_WRITE.with(std::cell::Cell::get) {
                crate::requests::store::tests::arm_mode_write_failure();
            }
            let move_report = store.set_mode(
                &ModeTarget::Loop,
                target,
                "exercise-fixture",
                "restore loop-wide setting after door exercise",
                &now_nanos().to_string(),
                &[],
            )?;
            Ok(json!({"status":"pass","prior":prior.map(Mode::as_str),
                "restored":target.as_str(),"move":move_report}))
        } else {
            Ok(json!({"status":"pass","prior":prior.map(Mode::as_str),
                "restored":current.map(Mode::as_str),"move":null}))
        }
    })();
    let restore = match restore {
        Ok(report) => report,
        Err(error) => json!({"status":"fail","prior":prior.map(Mode::as_str),
            "reason":error.line()}),
    };
    let failed = result.is_err();
    let mut fixture = match result {
        Ok(fixture) => fixture,
        Err(error) => json!({"fixture_error":error.line(),"fixture_error_kind":error.kind,
            "mode_moves":store.modes().ok().map_or(json!([]), |modes|
                modes["loop_settings"].clone()),"claims":claims}),
    };
    fixture["claims"]["loop_restored"] = restore.clone();
    if !failed
        && !restore["move"].is_null()
        && let Some(moves) = fixture["mode_moves"].as_array_mut()
    {
        moves.push(restore["move"].clone());
    }
    Ok(fixture)
}

#[cfg(test)]
std::thread_local! {
    static EXERCISE_CAT_RUNNER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_ABORT_AFTER_BIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_ABORT_AFTER_RELAX: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_FAIL_RESTORE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_FORCE_FLOOR_REFUSAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_WRONG_FLOOR_PROBE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FIXTURE_HELPER_FAULT: std::cell::RefCell<Option<&'static str>> = const {
        std::cell::RefCell::new(None)
    };
}

struct CatRunner;

impl transport::Runner for CatRunner {
    fn spawn(
        &self,
        _registration: &Registration,
        _operation: transport::Operation,
    ) -> io::Result<std::process::Child> {
        std::process::Command::new("/usr/bin/cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    }
}

#[cfg(test)]
pub(crate) fn with_fixture_cat_runner<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            EXERCISE_CAT_RUNNER.with(|selected| selected.set(false));
        }
    }
    EXERCISE_CAT_RUNNER.with(|selected| selected.set(true));
    let _reset = Reset;
    f()
}

#[cfg(test)]
fn with_fixture_abort_after_bind<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXTURE_ABORT_AFTER_BIND.with(|selected| selected.set(false));
        }
    }
    FIXTURE_ABORT_AFTER_BIND.with(|selected| selected.set(true));
    let _reset = Reset;
    f()
}

#[cfg(test)]
fn with_fixture_flag<T>(
    flag: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
    f: impl FnOnce() -> T,
) -> T {
    struct Reset(&'static std::thread::LocalKey<std::cell::Cell<bool>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            self.0.with(|selected| selected.set(false));
        }
    }
    flag.with(|selected| selected.set(true));
    let _reset = Reset(flag);
    f()
}

#[cfg(test)]
pub(crate) fn with_fixture_floor_refusal<T>(f: impl FnOnce() -> T) -> T {
    with_fixture_flag(&FIXTURE_FORCE_FLOOR_REFUSAL, f)
}

#[cfg(test)]
pub(crate) fn with_wrong_floor_probe<T>(f: impl FnOnce() -> T) -> T {
    with_fixture_flag(&FIXTURE_WRONG_FLOOR_PROBE, f)
}

#[cfg(test)]
pub(crate) fn with_abort_after_relax<T>(f: impl FnOnce() -> T) -> T {
    with_fixture_flag(&FIXTURE_ABORT_AFTER_RELAX, f)
}

#[cfg(test)]
pub(crate) fn with_restore_write_failure<T>(f: impl FnOnce() -> T) -> T {
    with_fixture_flag(&FIXTURE_FAIL_RESTORE_WRITE, f)
}

#[cfg(test)]
fn fixture_fault_is(name: &str) -> bool {
    FIXTURE_HELPER_FAULT.with(|selected| *selected.borrow() == Some(name))
}

#[cfg(test)]
pub(crate) fn with_fixture_helper_fault<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXTURE_HELPER_FAULT.with(|selected| *selected.borrow_mut() = None);
        }
    }
    FIXTURE_HELPER_FAULT.with(|selected| *selected.borrow_mut() = Some(name));
    let _reset = Reset;
    f()
}

#[allow(clippy::too_many_lines)]
fn exercise_mode_fixture_with(
    owner_home: &Path,
    registration: &Registration,
    case: &str,
    runner_override: Option<Arc<dyn transport::Runner>>,
    claims: &mut Value,
) -> Result<Value, LaneError> {
    use crate::requests::{Mode, modes::ModeTarget};
    let class = format!(
        "fixture-{}-{}-{}",
        case.strip_prefix("door-").unwrap_or("invalid"),
        registration.run,
        now_nanos()
    );
    let store = Store::open(owner_home, &registration.loop_name, true)?
        .with_reader_budget(Duration::from_secs(120));
    let target = ModeTarget::class(&class)?;
    let mut outcomes = Vec::new();
    let mut mode_moves = Vec::new();
    let mut correction_reports = Vec::new();
    if matches!(case, "door-audit" | "door-allow") {
        let setting = store.ensure_first_mode(&class)?;
        if setting["class"]["mode"] != "audit" {
            store.set_mode(
                &target,
                Mode::Audit,
                "exercise-fixture",
                "explicit audit baseline for mode exercise",
                &now_nanos().to_string(),
                &[],
            )?;
        }
    }
    if case == "door-audit" {
        store.ensure_first_mode(&class)?;
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            Some("allow"),
            runner_override.clone(),
        )?);
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            Some("refuse"),
            runner_override.clone(),
        )?);
    } else if case == "door-allow" {
        store.ensure_first_mode(&class)?;
        let prior_loop = store.effective_mode(&class)?["loop"]["mode"]
            .as_str()
            .and_then(Mode::parse)
            .filter(|_| {
                #[cfg(test)]
                {
                    !fixture_fault_is("loop-setting")
                }
                #[cfg(not(test))]
                {
                    true
                }
            })
            .ok_or_else(|| LaneError::operation("exercise-door-allow", "loop setting is absent"))?;
        let agreeing = fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            Some("allow"),
            runner_override.clone(),
        )?;
        #[cfg(test)]
        let agreeing = if fixture_fault_is("agreeing-id") {
            let mut missing = agreeing;
            missing["request_id"] = Value::Null;
            missing
        } else {
            agreeing
        };
        let citation = vec![
            agreeing["request_id"]
                .as_str()
                .ok_or_else(|| {
                    LaneError::operation(
                        "exercise-door-allow",
                        "agreeing audit fixture id is absent",
                    )
                })?
                .to_owned(),
        ];
        outcomes.push(agreeing);
        let at = now_nanos().to_string();
        mode_moves.push(store.set_mode(
            &target,
            Mode::Allow,
            "exercise-fixture",
            "agreeing audit fixture",
            &at,
            &citation,
        )?);
        if prior_loop != Mode::Allow {
            mode_moves.push(store.set_mode(
                &ModeTarget::Loop,
                Mode::Allow,
                "exercise-fixture",
                "agreeing audit fixture",
                &now_nanos().to_string(),
                &citation,
            )?);
        }
        #[cfg(test)]
        if FIXTURE_ABORT_AFTER_RELAX.with(std::cell::Cell::get) {
            return Err(LaneError::operation(
                "exercise-door-allow",
                "fixture failure after loop relaxation",
            ));
        }
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            None,
            runner_override.clone(),
        )?);
        let id = outcomes
            .last()
            .and_then(|row| row["request_id"].as_str())
            .ok_or_else(|| {
                LaneError::operation("exercise-door-allow", "fixture request id is absent")
            })?;
        store.triage(
            &registration.run,
            &[json!({"id":id,"action":"adjudicate",
            "treatment":"allow","reason":"fixture later judgement"})],
            "exercise-fixture",
            &now_nanos().to_string(),
        )?;
    } else if case == "door-enforce" {
        let floor = store.floor();
        let prior_loop = store.modes()?["loop_settings"]
            .as_array()
            .and_then(|rows| rows.last())
            .and_then(|row| row["mode"].as_str())
            .and_then(Mode::parse);
        let desired_loop = if floor == Mode::Allow {
            Mode::Allow
        } else {
            Mode::Enforce
        };
        if prior_loop.is_none() {
            mode_moves.push(store.set_mode(
                &ModeTarget::Loop,
                desired_loop,
                "exercise-fixture",
                "fixture loop first setting",
                &now_nanos().to_string(),
                &[],
            )?);
        } else if matches!(prior_loop, Some(Mode::Audit))
            || (prior_loop == Some(Mode::Enforce) && desired_loop == Mode::Allow)
        {
            let seed_class = format!("{class}-seed");
            let setting = store.ensure_first_mode(&seed_class)?;
            if setting["class"]["mode"] != "audit" {
                store.set_mode(
                    &ModeTarget::class(&seed_class)?,
                    Mode::Audit,
                    "exercise-fixture",
                    "audit seed for cited loop move",
                    &now_nanos().to_string(),
                    &[],
                )?;
            }
            let seed = fixture_mode_call(
                owner_home,
                registration,
                &seed_class,
                Some("allow"),
                Some("allow"),
                runner_override.clone(),
            )?;
            #[cfg(test)]
            let seed = if fixture_fault_is("seed-id") {
                let mut missing = seed;
                missing["request_id"] = Value::Null;
                missing
            } else {
                seed
            };
            let citation = seed["request_id"]
                .as_str()
                .ok_or_else(|| {
                    LaneError::operation("exercise-door-enforce", "fixture seed id is absent")
                })?
                .to_owned();
            mode_moves.push(store.set_mode(
                &ModeTarget::Loop,
                desired_loop,
                "exercise-fixture",
                "agreeing fixture seed",
                &now_nanos().to_string(),
                &[citation],
            )?);
        }
        mode_moves.push(store.set_mode(
            &target,
            Mode::Enforce,
            "exercise-fixture",
            "floor-compliant fixture first enforcement",
            &now_nanos().to_string(),
            &[],
        )?);
        if floor == Mode::Enforce {
            let before = store.modes()?;
            #[cfg(test)]
            let probe_mode = if FIXTURE_WRONG_FLOOR_PROBE.with(std::cell::Cell::get) {
                Mode::Enforce
            } else {
                Mode::Allow
            };
            #[cfg(not(test))]
            let probe_mode = Mode::Allow;
            let refusal = store.set_mode(
                &target,
                probe_mode,
                "exercise-fixture",
                "below-floor probe",
                &now_nanos().to_string(),
                &[],
            );
            let unchanged = store.modes()? == before;
            let kind = refusal.as_ref().err().map(|error| error.kind);
            claims["below_floor"] = json!({"status":if kind == Some("door-mode-floor-refusal")
                && unchanged {"pass"} else {"fail"},
                "floor":"enforce","requested":probe_mode.as_str(),"refusal":kind,
                "history_unchanged":unchanged});
        } else {
            claims["below_floor"] = json!({"status":"unmeasured","floor":floor.as_str(),
                "reason":"no class mode is below the recorded row floor"});
        }
        let agreeing = fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            None,
            runner_override.clone(),
        )?;
        let agreeing_id = agreeing["request_id"].as_str().ok_or_else(|| {
            LaneError::operation("exercise-door-enforce", "agreeing fixture id is absent")
        })?;
        let reviewed = store.review(agreeing_id, &format!("fixture-{}", now_nanos()))?;
        let review_id = reviewed.value()["review"]["id"]
            .as_str()
            .unwrap_or_default();
        let (_record, reports) = store.adjudicate_with_reports(
            agreeing_id,
            review_id,
            "allow",
            "fixture rubric agreement",
            "exercise-fixture",
            &now_nanos().to_string(),
        )?;
        correction_reports.extend(reports);
        if floor == Mode::Allow {
            mode_moves.push(store.set_mode(
                &target,
                Mode::Allow,
                "exercise-fixture",
                "cited fixture agreement",
                &now_nanos().to_string(),
                &[agreeing_id.to_owned()],
            )?);
            mode_moves.push(store.set_mode(
                &target,
                Mode::Enforce,
                "exercise-fixture",
                "stricter fixture move at once",
                &now_nanos().to_string(),
                &[],
            )?);
            claims["allow_to_enforce"] = json!({"status":"pass","floor":"allow"});
        } else {
            claims["allow_to_enforce"] = json!({"status":"unmeasured","floor":floor.as_str(),
                "reason":"recorded row floor refuses an allow setting"});
        }
        outcomes.push(agreeing);
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("allow"),
            None,
            runner_override.clone(),
        )?);
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("refuse"),
            None,
            runner_override.clone(),
        )?);
        outcomes.push(fixture_mode_call(
            owner_home,
            registration,
            &class,
            None,
            Some("allow"),
            runner_override.clone(),
        )?);
        let wrong = fixture_mode_call(
            owner_home,
            registration,
            &class,
            Some("refuse"),
            None,
            runner_override,
        )?;
        let id = wrong["request_id"]
            .as_str()
            .ok_or_else(|| {
                LaneError::operation("exercise-door-enforce", "fixture correction id is absent")
            })?
            .to_owned();
        outcomes.push(wrong);
        let reviewed = store.review(&id, &format!("fixture-{}", now_nanos()))?;
        let review_id = reviewed.value()["review"]["id"]
            .as_str()
            .unwrap_or_default();
        let (_record, reports) = store.adjudicate_with_reports(
            &id,
            review_id,
            "allow",
            "fixture rubric correction",
            "exercise-fixture",
            &now_nanos().to_string(),
        )?;
        claims["correction_report"] = json!({"status":if reports.iter().any(|row|
            row["mode"] == "audit" && row["target"] == class) {"pass"} else {"fail"},
            "request_id":id,"reports":reports});
        correction_reports.extend(reports);
    } else {
        return Err(LaneError::input(
            "exercise-door-mode",
            "fixture case is invalid",
        ));
    }
    let request_ids = outcomes
        .iter()
        .filter_map(|row| row["request_id"].as_str())
        .collect::<Vec<_>>();
    Ok(
        json!({"class":class,"outcomes":outcomes,"request_ids":request_ids,
        "mode_report":store.effective_mode(&class)?,"mode_moves":mode_moves,
        "correction_reports":correction_reports,"claims":claims}),
    )
}

struct FixtureSocketGuard {
    parent: std::os::fd::OwnedFd,
    name: String,
    slot: Option<crate::SocketSlot>,
    closed: bool,
}

struct ObservedFixtureRunner {
    inner: Arc<dyn transport::Runner>,
    store: Store,
    run: String,
    prior: std::collections::HashSet<String>,
    observations: Arc<std::sync::Mutex<Vec<Value>>>,
    deadline: Instant,
    #[cfg(test)]
    force_absent: bool,
}

impl transport::Runner for ObservedFixtureRunner {
    fn spawn(
        &self,
        registration: &Registration,
        operation: transport::Operation,
    ) -> io::Result<std::process::Child> {
        #[cfg(test)]
        if self.force_absent {
            return Err(io::Error::other(
                "fixture request is absent at compute start",
            ));
        }
        let rows = self
            .store
            .list_run_until(&self.run, self.deadline)
            .map_err(io::Error::other)?;
        let row = rows
            .iter()
            .rev()
            .find(|row| !self.prior.contains(row.id()))
            .ok_or_else(|| io::Error::other("fixture request is absent at compute start"))?;
        let value = row.value();
        self.observations
            .lock()
            .map_err(|_| io::Error::other("fixture observation lock poisoned"))?
            .push(json!({"request_id":row.id(),"state":value["state"],
                "label":value["label"],"agent_status":value["agent_status"],"effect_state":value["effect"]["state"]}));
        self.inner.spawn(registration, operation)
    }

    fn owns_process_group(&self) -> bool {
        self.inner.owns_process_group()
    }
}

impl FixtureSocketGuard {
    fn close(&mut self) -> Result<(), LaneError> {
        if let Some(slot) = self.slot.take() {
            slot.remove().map_err(|error| {
                LaneError::operation("exercise-door-fixture", error.to_string())
            })?;
        }
        nix::unistd::unlinkat(
            &self.parent,
            self.name.as_str(),
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for FixtureSocketGuard {
    fn drop(&mut self) {
        if !self.closed {
            if let Some(slot) = self.slot.take() {
                let _removed = slot.remove();
            }
            let _removed = nix::unistd::unlinkat(
                &self.parent,
                self.name.as_str(),
                nix::unistd::UnlinkatFlags::RemoveDir,
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn fixture_mode_call(
    owner_home: &Path,
    registration: &Registration,
    class: &str,
    decision: Option<&str>,
    answer: Option<&str>,
    runner_override: Option<Arc<dyn transport::Runner>>,
) -> Result<Value, LaneError> {
    fixture_agent_call(
        owner_home,
        registration,
        class,
        decision,
        answer,
        runner_override,
        None,
    )
}

const EXERCISE_ADMISSION_REFUSAL: &str = "exercise-door-admission-unmeasured";

// The exercise retries a refused fixture admission for two seconds.
const EXERCISE_RETRY_WINDOW: Duration = Duration::from_secs(2);

#[cfg(test)]
thread_local! {
    static EXERCISE_RETRY_OBSERVED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    // A test that releases admission on the observed refusal widens its own window to a
    // hang bound; a test that holds admission throughout keeps the deployed window, so
    // its refusal arrives after one refused attempt.
    static EXERCISE_RETRY_HANG: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(not(test))]
const fn exercise_retry_window() -> Duration {
    EXERCISE_RETRY_WINDOW
}

#[cfg(test)]
fn exercise_retry_window() -> Duration {
    EXERCISE_RETRY_HANG.with(|hang| hang.get().unwrap_or(EXERCISE_RETRY_WINDOW))
}

pub(crate) fn exercise_admission_unmeasured(kind: &str) -> bool {
    matches!(kind, EXERCISE_ADMISSION_REFUSAL | "door-mode-floor-refusal")
}

#[allow(clippy::needless_pass_by_value)]
fn fixture_agent_call(
    owner_home: &Path,
    registration: &Registration,
    class: &str,
    decision: Option<&str>,
    answer: Option<&str>,
    runner_override: Option<Arc<dyn transport::Runner>>,
    agent: Option<Arc<dyn agent::AgentRunner>>,
) -> Result<Value, LaneError> {
    let deadline = Instant::now() + exercise_retry_window();
    loop {
        let result = fixture_agent_call_once(
            owner_home,
            registration,
            class,
            decision,
            answer,
            runner_override.clone(),
            agent.clone(),
        );
        match result {
            Err(error) if error.kind == EXERCISE_ADMISSION_REFUSAL && Instant::now() < deadline => {
                #[cfg(test)]
                EXERCISE_RETRY_OBSERVED.with(|slot| {
                    if let Some(observed) = slot.borrow_mut().take() {
                        observed();
                    }
                });
                thread::sleep(
                    Duration::from_millis(50)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn fixture_agent_call_once(
    owner_home: &Path,
    registration: &Registration,
    class: &str,
    decision: Option<&str>,
    answer: Option<&str>,
    runner_override: Option<Arc<dyn transport::Runner>>,
    agent: Option<Arc<dyn agent::AgentRunner>>,
) -> Result<Value, LaneError> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
    use nix::sys::stat::{Mode, fchmod, mkdirat};
    use std::ffi::OsString;
    #[cfg(test)]
    FIXTURE_ADMISSION_CLOCK.with(|slot| {
        if let Some(clock) = slot.borrow().as_ref() {
            clock.attempts.fetch_add(1, Ordering::Relaxed);
        }
    });
    // This fixture uses the ordinary Git/probe request's 120-second budget.
    let deadline = Instant::now() + Duration::from_secs(120);
    let owner = nix::unistd::Uid::effective().as_raw();
    let config = owner_home
        .join(".config/loops")
        .join(&registration.loop_name);
    let directory = crate::pinned::open_protected(owner_home, &config, owner)?;
    let route = transport::HostRunner::load(&directory, &config, &registration.loop_name, owner)?;
    let store =
        Store::open(owner_home, &registration.loop_name, true)?.with_reader_deadline(deadline);
    let prior = store
        .list_run(&registration.run)?
        .into_iter()
        .map(|row| row.id().to_owned())
        .collect::<std::collections::HashSet<_>>();
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let runner: Arc<dyn transport::Runner> = Arc::new(ObservedFixtureRunner {
        inner: runner_override.unwrap_or_else(|| Arc::new(route.clone())),
        store: Store::open(owner_home, &registration.loop_name, true)?,
        run: registration.run.clone(),
        prior: prior.clone(),
        observations: Arc::clone(&observations),
        deadline,
        #[cfg(test)]
        force_absent: fixture_fault_is("compute-absent"),
    });
    let rules = decision.map_or_else(Vec::new, |choice| {
        vec![json!({
        "operation":"probe-echo","shape_key":format!("{class}:probe-echo"),
        "decision":choice,"reason":"fixture exact-match rubric"})]
    });
    let rubric = Rubric::decode(&json!({"schema":1,"class":class,
        "undecided_reason":"fixture rubric has no matching row","rules":rules}))?;
    let fixture_name = format!(".door-fixture-{}-{}", std::process::id(), now_nanos());
    mkdirat(&directory, fixture_name.as_str(), Mode::S_IRWXU)
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    let mut guard = FixtureSocketGuard {
        parent: directory,
        name: fixture_name.clone(),
        slot: None,
        closed: false,
    };
    let fixture_dir = openat2(
        &guard.parent,
        Path::new(&fixture_name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    fchmod(&fixture_dir, Mode::S_IRWXU)
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    let stat = fstat(&fixture_dir)
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
        return Err(LaneError::operation(
            "exercise-door-fixture",
            "fixture directory owner or mode differs",
        ));
    }
    let slot = crate::SocketSlot::beneath(&fixture_dir, std::ffi::OsStr::new("capability.sock"))
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    let listener = UnixListener::bind(slot.address())
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    let client_socket = slot.address().to_path_buf();
    guard.slot = Some(slot);
    #[cfg(test)]
    if FIXTURE_ABORT_AFTER_BIND.with(std::cell::Cell::get) {
        return Err(LaneError::operation(
            "exercise-door-fixture",
            "fixture failure after socket bind",
        ));
    }
    let registered = registration.clone();
    let home = owner_home.to_path_buf();
    let fixture_store =
        Store::open(owner_home, &registration.loop_name, true)?.with_reader_deadline(deadline);
    #[cfg(test)]
    let fault = FIXTURE_HELPER_FAULT.with(|selected| *selected.borrow());
    #[cfg(test)]
    let admission_clock = FIXTURE_ADMISSION_CLOCK.with(|slot| slot.borrow().clone());
    let server = thread::spawn(move || -> io::Result<(Value, u32)> {
        #[cfg(test)]
        if let Some(clock) = admission_clock {
            ADMISSION_CLOCK.with(|slot| *slot.borrow_mut() = Some(std::rc::Rc::new(clock)));
        }
        let (mut stream, _) = listener.accept()?;
        let socket_peer_uid = peer_uid(&stream)?;
        if socket_peer_uid != owner {
            return Err(io::Error::other("fixture peer differs"));
        }
        #[cfg(test)]
        if fault == Some("peer-diff") {
            return Err(io::Error::other("fixture peer differs"));
        }
        let started = Instant::now();
        let request = frame_read_until(&mut stream, started + Duration::from_secs(2))?;
        let reply = serve_request_with_agent(
            &mut stream,
            &registered,
            registered.worker_uid,
            &request,
            Some(&route),
            Some(runner.as_ref()),
            Some(&home),
            Some(&rubric),
            Some(&fixture_store),
            agent.as_deref(),
            Some("fixture-configured-model"),
            started,
        )?;
        #[cfg(test)]
        assert!(
            fault != Some("service-join"),
            "fixture service join failure"
        );
        Ok((reply.0, socket_peer_uid))
    });
    let client = thread::spawn(move || {
        #[cfg(test)]
        let args = if fault == Some("unfiled") {
            vec![OsString::from("door-shape-probe"), OsString::from("other")]
        } else {
            vec![OsString::from("door-attribution-probe")]
        };
        #[cfg(not(test))]
        let args = vec![OsString::from("door-attribution-probe")];
        let reply = stub_call(&client_socket, &args, b"fixture input");
        #[cfg(test)]
        assert!(fault != Some("stub-join"), "fixture stub join failure");
        reply
    });
    let mut id = None;
    let filed_deadline = Instant::now() + ADMISSION_WAIT + Duration::from_secs(3);
    while Instant::now() < filed_deadline {
        let rows = store.list_run(&registration.run)?;
        if let Some(row) = rows.iter().find(|row| {
            !prior.contains(row.id()) && (answer.is_none() || row.value()["state"] == "waiting")
        }) {
            id = Some(row.id().to_owned());
            break;
        }
        if client.is_finished() && server.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let Some(id) = id else {
        let stub_finished = client.is_finished();
        let service_finished = server.is_finished();
        let detail = if stub_finished && service_finished {
            let client_result = client.join();
            let server_result = server.join();
            if matches!(&server_result, Ok(Ok((reply, _))) if reply["reason"] == "door-request-concurrent")
            {
                guard.close()?;
                return Err(LaneError::operation(
                    EXERCISE_ADMISSION_REFUSAL,
                    "door-request-concurrent: box admission unavailable within the bounded exercise retry; no fixture request measured",
                ));
            }
            format!(
                "fixture request was not filed: stub={client_result:?} service={server_result:?}"
            )
        } else {
            format!(
                "fixture request was not filed: stub_finished={stub_finished} service_finished={service_finished}"
            )
        };
        return Err(LaneError::operation("exercise-door-fixture", detail));
    };
    let before_answer = store.waiting_request(&id)?.into_value();
    if let Some(treatment) = answer {
        #[cfg(test)]
        let treatment = if fault == Some("triage") {
            "invalid"
        } else {
            treatment
        };
        let triage = store.triage(
            &registration.run,
            &[json!({"id":id,"action":"adjudicate",
            "treatment":treatment,"reason":"fixture answer"})],
            "exercise-fixture",
            &now_nanos().to_string(),
        );
        #[cfg(test)]
        if fault == Some("triage") && triage.is_err() {
            let _answered = store.triage(
                &registration.run,
                &[json!({"id":id,"action":"adjudicate","treatment":"allow",
                    "reason":"fixture cleanup answer"})],
                "exercise-fixture",
                &now_nanos().to_string(),
            );
            let _client = client.join();
            let _server = server.join();
            guard.close()?;
            return Err(triage.expect_err("fixture triage refusal"));
        }
        triage?;
    }
    let reply = client
        .join()
        .map_err(|_| LaneError::operation("exercise-door-fixture", "fixture stub panicked"))?
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    let (_, socket_peer_uid) = server
        .join()
        .map_err(|_| LaneError::operation("exercise-door-fixture", "fixture service panicked"))?
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    #[cfg(test)]
    if fault == Some("cleanup") {
        if let Some(slot) = guard.slot.take() {
            slot.remove().map_err(|error| {
                LaneError::operation("exercise-door-fixture", error.to_string())
            })?;
        }
        nix::unistd::unlinkat(
            &guard.parent,
            guard.name.as_str(),
            nix::unistd::UnlinkatFlags::RemoveDir,
        )
        .map_err(|error| LaneError::operation("exercise-door-fixture", error.to_string()))?;
    }
    guard.close()?;
    let spawn_observations = observations
        .lock()
        .map_err(|_| {
            LaneError::operation("exercise-door-fixture", "fixture observation lock poisoned")
        })?
        .clone();
    Ok(
        json!({"request_id":id,"final":reply,"socket_peer_uid":socket_peer_uid,
        "registered_worker_uid":registration.worker_uid,
        "authority":"recorded reservation supplied to fixture service",
        "before_answer":before_answer,"spawn_observations":spawn_observations}),
    )
}

#[cfg(test)]
mod startup_tests;

#[cfg(test)]
mod tests {
    include!("door/concurrent_tests.rs");
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::{self, Write as _};
    use std::net::Shutdown;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    use super::{
        MAX_PEERS, Registration, Scope, admit_peer, completed_door_group, frame_write, peer_uid,
        serve_one_for_peer, serve_request, serve_socket, stub_call,
    };
    use crate::door::transport::{HostRunner, Operation, Runner};
    use crate::requests::{
        Mode,
        modes::Rubric,
        store::{FixtureFault, Store, fixture_fault, fixture_file_cap, tests::Fixture},
        tests::waiting,
    };

    /// ´test:unit:door-workspace-deadline-announces-the-ordinary-bound´
    #[test]
    fn door_workspace_deadline_announces_the_ordinary_bound() {
        let started = Instant::now();
        let requested = super::compute::MAX_DEADLINE_MS;
        let registered = super::compute::DEADLINE_MS;
        let (deadline, frame) =
            super::workspace_deadline_announcement(started, requested, registered, 45_000);
        assert_eq!(
            deadline.duration_since(started).as_millis(),
            u128::from(registered)
        );
        assert_eq!(frame["type"], "compute-deadline");
        assert_eq!(frame["registered_deadline_ms"], registered);
        assert_eq!(frame["request_deadline_ms"], requested);
        assert_eq!(frame["judgement_wait_ms"], 45_000);
        assert!(
            frame["remaining_ms"]
                .as_u64()
                .is_some_and(|ms| ms <= registered)
        );
    }

    /// ´test:unit:door-workspace-waited-run-ends-inside-announced-window´
    #[test]
    fn door_workspace_waited_run_ends_inside_announced_window() {
        let request_started = Instant::now();
        let command_started = request_started + Duration::from_secs(50);
        let requested = 60_000;
        let registered = 120_000;
        let judgement = 45_000;
        let ordinary = command_started + Duration::from_millis(requested);
        let bounds = super::workspace_waited_bounds(
            request_started,
            command_started,
            requested,
            registered,
            judgement,
        );
        assert!(
            bounds.command < ordinary,
            "retaken admission consumed the window"
        );
        assert_eq!(bounds.command, request_started + Duration::from_secs(100));
        assert_eq!(
            bounds.route,
            bounds.command + super::workspace_adapter::STOP_TERMINAL_BOUND,
            "the node's stop interval stays inside the announced window"
        );
        assert_eq!(bounds.final_frame, bounds.route + Duration::from_secs(2));
        let (_peer, door) = UnixStream::pair().expect("fixture peer");
        let (start, clock) = super::lifetime::Start::controlled(request_started);
        let wait = super::RequestWait::new(&door)
            .expect("wait")
            .with_lifetime(start, true, &door)
            .expect("lifetime");
        clock.advance(100_000);
        assert_eq!(
            wait.stop(bounds.command)
                .map(super::lifetime::Cause::reason),
            Some("door-request-deadline"),
            "the retaken run ends under the door's cause inside the announced window"
        );
        let late_retake = request_started + Duration::from_secs(101);
        assert!(
            super::workspace_waited_bounds(
                request_started,
                late_retake,
                requested,
                registered,
                judgement,
            )
            .command
                < late_retake,
            "a spent window must stop before the executor call"
        );
    }

    /// ´test:unit:door-workspace-quick-rule-runs-from-stub-to-recorded-effect´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_workspace_quick_rule_runs_from_stub_to_recorded_effect() {
        quick_rule_fixture(false, false);
    }

    /// ´test:unit:door-workspace-first-mode-lock-wait-keeps-schema-three´
    #[test]
    fn door_workspace_first_mode_lock_wait_keeps_schema_three() {
        quick_rule_fixture(true, false);
    }

    /// ´test:unit:door-workspace-first-mode-wait-ends-with-its-peer´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_workspace_first_mode_wait_ends_with_its_peer() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        fixture
            .store()
            .set_mode(
                &crate::requests::modes::ModeTarget::Loop,
                Mode::Enforce,
                "fixture owner",
                "fixture mode",
                "1",
                &[],
            )
            .expect("loop setting only");
        let context = fixture.home.join("workspace-context.json");
        fs::write(
            &context,
            serde_json::to_vec(&json!({"schema":1,"run":"R",
                "worker_uid":nix::unistd::Uid::effective().as_raw(),
                "node_alias":"fixture-node","grant_digest":"a".repeat(64),
                "checkout":"/tmp/checkout","cwd":[],"shell":"/bin/sh"}))
            .expect("context bytes"),
        )
        .expect("context file");
        let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join("mode-wait.sock"));
        let listener = UnixListener::bind(&socket).expect("fixture socket");
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let home = fixture.home.clone();
        let holder = thread::spawn(move || {
            let held = Store::open(&home, "alpha", true)
                .expect("holder store")
                .fixture_exclusive_lock()
                .expect("held mode lock");
            held_tx.send(()).expect("lock held");
            release_rx.recv().expect("release holder");
            drop(held);
        });
        held_rx.recv().expect("exclusive mode lock held");
        let (retry_tx, retry_rx) = std::sync::mpsc::sync_channel(1);
        let (socket_tx, socket_rx) = std::sync::mpsc::sync_channel(1);
        let stopper = thread::spawn(move || {
            let socket: UnixStream = socket_rx.recv().expect("stub socket");
            retry_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("mode lock was retried");
            socket.shutdown(Shutdown::Both).expect("peer leaves");
        });
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let home = fixture.home;
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("stub peer");
            let request =
                super::frame_read_until(&mut peer, Instant::now() + Duration::from_secs(5))
                    .expect("workspace request");
            assert_eq!(request["schema"], 3);
            let started = Instant::now();
            let wait = Arc::new(
                super::RequestWait::new(&peer)
                    .expect("request wait")
                    .with_lifetime(
                        super::lifetime::Start::at(started).expect("lifetime start"),
                        true,
                        &peer,
                    )
                    .expect("request lifetime"),
            );
            let mut retries = 0;
            crate::requests::store::AFTER_WRITER_LOCK_RETRY.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    retries += 1;
                    if retries == 8 {
                        retry_tx.send(()).expect("close peer after retries");
                    }
                }));
            });
            let store = Store::open(&home, "alpha", true).expect("mode store");
            let result = store
                .for_request(started + Duration::from_secs(30))
                .expect("bounded store")
                .with_stop_observer(wait)
                .ensure_first_mode("compute");
            result_tx.send(result).expect("mode result");
        });
        super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = Some(context));
        super::transport::STUB_REQUEST_SENT.with(|slot| *slot.borrow_mut() = Some(socket_tx));
        let stub = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/true"),
            ],
            io::empty(),
            io::sink(),
            io::sink(),
        );
        assert!(stub.is_err(), "a closed peer cannot receive a final frame");
        let result = result_rx.recv_timeout(Duration::from_secs(5));
        release_tx.send(()).expect("release lock on every result");
        let result = result.expect("mode view ended while the lock was still held");
        assert!(
            result.is_err_and(|error| error.detail.contains("disconnect")),
            "the store wait observed the peer's close"
        );
        server.join().expect("mode handler");
        stopper.join().expect("peer stopper");
        holder.join().expect("lock holder");
        super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = None);
    }

    /// ´test:unit:door-workspace-announces-before-box-admission´
    #[test]
    fn door_workspace_announces_before_box_admission() {
        quick_rule_fixture(false, true);
    }

    #[allow(clippy::too_many_lines)]
    fn quick_rule_fixture(contend_first_mode: bool, contend_admission: bool) {
        use execute_command::workspace::{
            Blacklist, BlacklistEntry, Execution, QuickPolicy, QuickRule, canonical_digest,
        };
        use std::fmt::Write as _;

        struct AdvanceOnReady {
            clock: std::sync::mpsc::Receiver<Arc<super::lifetime::TestClock>>,
            bytes: Vec<u8>,
            advanced: bool,
        }
        impl io::Write for AdvanceOnReady {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                if !self.advanced && self.bytes.windows(5).any(|window| window == b"ready") {
                    self.clock.recv().map_err(io::Error::other)?.advance(10_000);
                    self.advanced = true;
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let node = crate::workspace_node::tests::Fixture::new();
        let execution = Execution::Argv {
            words: vec![b"/usr/bin/printf".to_vec(), b"fixture-ok".to_vec()],
        };
        let quick = QuickPolicy {
            revision: "fixture-1".into(),
            rules: vec![
                QuickRule {
                    id: "fixture-printf".into(),
                    execution,
                    path: "/usr/bin".into(),
                    programs: vec!["/usr/bin/printf".into()],
                    env_additions: Vec::new(),
                    workspace_operands: Vec::new(),
                },
                QuickRule {
                    id: "fixture-running-shell".into(),
                    execution: Execution::Argv {
                        words: vec![
                            b"/bin/sh".to_vec(),
                            b"-c".to_vec(),
                            b"printf ready; /usr/bin/sleep 60".to_vec(),
                        ],
                    },
                    path: "/usr/bin".into(),
                    programs: vec!["/bin/sh".into()],
                    env_additions: Vec::new(),
                    workspace_operands: Vec::new(),
                },
            ],
        };
        let blacklist = Blacklist {
            revision: "fixture-1".into(),
            entries: vec![BlacklistEntry {
                id: "fixture-blocked".into(),
                execution_digest: canonical_digest(&Execution::Argv {
                    words: vec![b"/usr/bin/printf".to_vec(), b"blocked".to_vec()],
                })
                .expect("blocked execution digest"),
                reason: "fixture owner denies this command".into(),
            }],
        };
        let mut grant = node.grant.clone();
        grant.quick_policy_digest = canonical_digest(&quick).expect("quick digest");
        grant.blacklist_digest = canonical_digest(&blacklist).expect("blacklist digest");
        let mut placement = node.placement.clone();
        placement["grant_digest"] = json!(grant.digest().expect("grant digest"));
        let reservation = json!({"schema":1,"phase":"started","loop":"alpha",
            "run":"R","worker_uid":3000,"door_scope":"work",
            "plan":{"loop":"alpha","run":"R",
                "compute_workspace":{"digest":grant.digest().expect("grant digest"),"grant":grant},
                "compute_placement":placement}});
        crate::launch::publish_reservation(
            &crate::launch::reservation_path(&fixture.home.join("runs"), "R"),
            &reservation,
        )
        .expect("protected workspace reservation");
        let config = fixture.home.join(".config/loops/alpha");
        for (file, value) in [
            ("workspace-quick-policy.json", json!(quick)),
            ("workspace-blacklist.json", json!(blacklist)),
        ] {
            let path = config.join(file);
            fs::write(&path, serde_json::to_vec(&value).expect("policy JSON"))
                .expect("policy file");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("policy mode");
        }
        let settings = config.join("workers.toml");
        let mut contents = fs::read_to_string(&settings).unwrap_or_default();
        let _written = write!(
            contents,
            "\n[workspace_policy]\nquick_policy_digest = \"{}\"\nblacklist_digest = \"{}\"\n",
            grant.quick_policy_digest, grant.blacklist_digest
        );
        fs::write(&settings, contents).expect("published policy digests");
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600))
            .expect("workers settings mode");
        assert_eq!(
            super::workspace_digests(&fixture.home, "alpha").expect("policy digest lines"),
            format!(
                "[workspace_policy]\nquick_policy_digest = \"{}\"\nblacklist_digest = \"{}\"",
                grant.quick_policy_digest, grant.blacklist_digest
            )
        );
        let store = fixture.store();
        for target in [
            crate::requests::modes::ModeTarget::Loop,
            crate::requests::modes::ModeTarget::class("compute").expect("class"),
        ]
        .into_iter()
        .take(if contend_first_mode { 1 } else { 2 })
        {
            store
                .set_mode(
                    &target,
                    Mode::Enforce,
                    "fixture owner",
                    "fixture mode",
                    "1",
                    &[],
                )
                .expect("enforce compute mode");
        }
        let context = fixture.home.join("workspace-context.json");
        fs::write(
            &context,
            serde_json::to_vec(&json!({"schema":1,"run":"R",
                "worker_uid":nix::unistd::Uid::effective().as_raw(),
                "node_alias":"fixture-node","grant_digest":grant.digest().expect("digest"),
                "checkout":grant.workspace,"cwd":[],"shell":"/bin/sh"}))
            .expect("context JSON"),
        )
        .expect("stub context");
        let route = route_for(&fixture.home);
        let registration = Registration {
            loop_name: "alpha".into(),
            run: "R".into(),
            worker_uid: 3000,
            loop_uid: 41001,
            scope: Scope::Work,
            mirror_ref: "refs/heads/lane/R".into(),
        };
        let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join("workspace.sock"));
        let listener = UnixListener::bind(&socket).expect("workspace service socket");
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (first_frame_tx, first_frame_rx) = std::sync::mpsc::sync_channel(1);
        let (admission_ready_tx, admission_ready_rx) = std::sync::mpsc::sync_channel(1);
        let admission_holder = contend_admission.then(|| {
            let home = fixture.home.clone();
            let registration = registration.clone();
            thread::spawn(move || {
                let held = super::RequestGuard::acquire_operation(
                    &home,
                    &registration,
                    Some(super::transport::Operation::Compute),
                )
                .expect("hold compute admission")
                .expect("compute admission free");
                admission_ready_tx.send(()).expect("admission held");
                first_frame_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("stub received the first frame while admission was held");
                drop(held);
            })
        });
        if admission_holder.is_some() {
            admission_ready_rx.recv().expect("compute guard held");
        }
        let holder = contend_first_mode.then(|| {
            let home = fixture.home.clone();
            thread::spawn(move || {
                let store = Store::open(&home, "alpha", true).expect("holder store");
                let held = store
                    .fixture_exclusive_lock()
                    .expect("held first-mode lock");
                ready_tx.send(()).expect("lock held");
                release_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("observed retries release lock");
                drop(held);
            })
        });
        if holder.is_some() {
            ready_rx.recv().expect("first-mode lock held");
        }
        let (clock_tx, clock_rx) = std::sync::mpsc::sync_channel(1);
        let home = fixture.home.clone();
        let identity = node.identity;
        let server = thread::spawn(move || {
            super::transport::WORKSPACE_FIXTURE_IDENTITY
                .with(|slot| *slot.borrow_mut() = Some(identity));
            let runs: std::os::fd::OwnedFd =
                File::open(home.join("runs")).expect("held runs").into();
            let config: std::os::fd::OwnedFd = File::open(home.join(".config/loops/alpha"))
                .expect("held config")
                .into();
            let mut replies = Vec::new();
            for ordinal in 0..7 {
                if ordinal == 0 && contend_first_mode {
                    let release = release_tx.clone();
                    let mut retries = 0;
                    crate::requests::store::AFTER_WRITER_LOCK_RETRY.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move || {
                            retries += 1;
                            if retries == 8 {
                                release.send(()).expect("release held mode lock");
                            }
                        }));
                    });
                }
                let mut peer = FixtureServer::accept(&listener).expect("stub peer");
                let request = fixture_request(&mut peer).expect("stub request");
                let wire = serde_json::to_vec(&request).expect("request wire");
                let started = Instant::now();
                let before_end_count = super::REQUEST_END_COUNT.with(std::cell::Cell::get);
                if ordinal == 5 {
                    fixture_fault(Some(FixtureFault::EffectWrite));
                }
                let lifetime_start = if ordinal == 6 {
                    let (start, clock) = super::lifetime::Start::controlled(started);
                    clock_tx.send(clock).expect("deadline clock");
                    start
                } else {
                    super::lifetime::Start::at(started).expect("lifetime")
                };
                let reply = super::serve_request_with_agent_at_context(
                    &mut peer,
                    &registration,
                    if ordinal == 4 { 3001 } else { 3000 },
                    &request,
                    Some(&route),
                    Some(&route),
                    Some(home.as_path()),
                    None,
                    Some(&store),
                    None,
                    None,
                    started,
                    lifetime_start,
                    Some(super::WorkspaceSocketContext {
                        runs: &runs,
                        config_directory: &config,
                        owner: nix::unistd::Uid::effective().as_raw(),
                        wire: &wire,
                        judgement_wait_ms: 30_000,
                        deadline_ms: super::compute::DEADLINE_MS,
                    }),
                )
                .expect("workspace service")
                .0;
                if ordinal == 0 && contend_first_mode {
                    crate::requests::store::AFTER_WRITER_LOCK_RETRY.with(|slot| {
                        slot.borrow_mut().take();
                    });
                }
                if ordinal == 2 {
                    assert_eq!(
                        super::REQUEST_END_COUNT.with(std::cell::Cell::get),
                        before_end_count + 1,
                        "a referred request emits one ending after its final write"
                    );
                }
                replies.push(reply);
            }
            super::POST_REPLY_EVENTS.with(|events| {
                assert!(events.borrow().iter().any(|event| {
                    event["phase"] == "terminal-record"
                        && event["kind"] == "requests-record-refusal"
                }));
            });
            replies
        });
        super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = Some(context));
        if contend_admission {
            super::transport::STUB_FIRST_FRAME_OBSERVED
                .with(|slot| *slot.borrow_mut() = Some(first_frame_tx));
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let reply = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf fixture-ok"),
            ],
            io::empty(),
            &mut stdout,
            &mut stderr,
        )
        .expect("real stub call");
        let mut second_stdout = Vec::new();
        let second = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf fixture-ok"),
            ],
            io::empty(),
            &mut second_stdout,
            io::sink(),
        )
        .expect("second stub call after first reply");
        let missed = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf other"),
            ],
            io::empty(),
            io::sink(),
            io::sink(),
        )
        .expect("miss referral");
        let blocked = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf blocked"),
            ],
            io::empty(),
            io::sink(),
            io::sink(),
        )
        .expect("published blacklist refusal");
        let foreign_peer = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf fixture-ok"),
            ],
            io::empty(),
            io::sink(),
            io::sink(),
        )
        .expect("foreign mapped peer refusal");
        let mut faulted_stdout = Vec::new();
        let faulted = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("fixture-node"),
                OsString::from("/usr/bin/printf fixture-ok"),
            ],
            io::empty(),
            &mut faulted_stdout,
            io::sink(),
        )
        .expect("effect-write fault still returns command status");
        let deadline_request = json!({"cwd":[],"env_additions":[],
            "execution":Execution::Argv {
                words:vec![b"/bin/sh".to_vec(),b"-c".to_vec(),
                    b"printf ready; /usr/bin/sleep 60".to_vec()]},
            "deadline_ms":10_000});
        let mut deadline_output = AdvanceOnReady {
            clock: clock_rx,
            bytes: Vec::new(),
            advanced: false,
        };
        let deadline = super::transport::stub_call_stream(
            &socket,
            &[
                OsString::from("--workspace-json"),
                OsString::from(deadline_request.to_string()),
            ],
            io::empty(),
            &mut deadline_output,
            io::sink(),
        )
        .expect("deadline reply");
        assert_eq!(deadline_output.bytes, b"ready");
        assert!(deadline_output.advanced);
        super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = None);
        let server_replies = server.join().expect("service thread");
        if let Some(holder) = holder {
            holder.join().expect("lock holder");
        }
        if let Some(holder) = admission_holder {
            holder.join().expect("admission holder");
        }
        assert_eq!(
            server_replies,
            [
                reply.clone(),
                second.clone(),
                missed.clone(),
                blocked.clone(),
                foreign_peer.clone(),
                faulted.clone(),
                deadline.clone()
            ]
        );
        assert_eq!(reply["reason"], "door-complete", "{reply}");
        assert_eq!(reply["status"], 0);
        assert_eq!(stdout, b"fixture-ok");
        assert_eq!(second["reason"], "door-complete");
        assert_eq!(second_stdout, b"fixture-ok");
        assert_eq!(faulted_stdout, b"fixture-ok");
        assert_eq!(faulted["reason"], "door-complete");
        assert_eq!(faulted["status"], 0);
        assert_eq!(deadline["reason"], "door-request-deadline", "{deadline}");
        assert_eq!(
            deadline["registered_deadline_ms"],
            super::compute::DEADLINE_MS
        );
        assert_eq!(deadline["request_deadline_ms"], 10_000);
        assert!(super::final_line(&[], &deadline).is_some_and(|line| {
            line.contains("door-request-deadline")
                && line.contains("registered_deadline_ms=1800000")
                && line.contains("request_deadline_ms=10000")
        }));
        assert!(
            faulted["request_record_error"]
                .as_str()
                .is_some_and(|text| { text.contains("fixture effect write failure") })
        );
        assert_eq!(stderr, b"");
        assert_eq!(missed["reason"], "door-workspace-referred");
        assert_eq!(missed["status"], 125);
        assert_eq!(missed["request_record_error"], "door-agent-unconfigured");
        assert!(
            missed["request_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert_eq!(
            super::final_line(
                &[
                    OsString::from("fixture-node"),
                    OsString::from("/usr/bin/printf other")
                ],
                &missed
            )
            .as_deref(),
            Some("door-workspace-referred: door-agent-unconfigured")
        );
        assert_eq!(blocked["reason"], "door-request-refusal");
        assert_eq!(foreign_peer["reason"], "door-caller-authority-refusal");
        assert!(
            blocked["request_record_error"]
                .as_str()
                .is_some_and(
                    |text| text.contains("fixture-blocked") && text.contains("nothing was run")
                )
        );
        assert!(
            super::final_line(
                &[
                    OsString::from("fixture-node"),
                    OsString::from("/usr/bin/printf blocked")
                ],
                &blocked
            )
            .is_some_and(
                |line| line.contains("fixture-blocked") && line.contains("nothing was run")
            )
        );
        let rows = fixture.store().list().expect("request rows").0;
        assert_eq!(rows.len(), 6);
        let referred = rows
            .iter()
            .find(|row| Some(row.id()) == missed["request_id"].as_str())
            .expect("filed miss");
        assert_eq!(referred.value()["state"], "waiting");
        assert_eq!(referred.value()["would_do_source"], "superloop");
        assert_eq!(
            referred.value()["would_do"]["reason"],
            "door-agent-unconfigured"
        );
        assert!(referred.value()["workspace_agent_input"].is_null());
        assert_eq!(referred.value()["effect"]["state"], "refused");
        assert_eq!(
            referred.value()["effect"]["reason"],
            "door-workspace-referred"
        );
        assert_eq!(
            referred.value()["effect"]["ending"]["local_child"],
            "not-started"
        );
        assert_eq!(
            referred.value()["effect"]["ending"]["remote"]["state"],
            "not-started"
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.value()["effect"]["state"] == "completed")
                .count(),
            3,
            "the unwind guard records the command after the injected write fault"
        );
        for row in rows
            .iter()
            .filter(|row| row.value()["effect"]["state"] == "completed")
        {
            assert_eq!(row.value()["effect"]["state"], "completed");
            assert_eq!(row.value()["matched_rule"]["rule"], "fixture-printf");
            assert_eq!(
                row.value()["matched_rule"]["policy_digest"],
                grant.quick_policy_digest
            );
        }
        let timed_out = rows
            .iter()
            .find(|row| row.value()["effect"]["reason"] == "door-request-deadline")
            .expect("deadline effect");
        assert_eq!(timed_out.value()["effect"]["state"], "interrupted");
        assert_eq!(
            timed_out.value()["effect"]["workspace_node"]["node_reason"],
            "node-stopped"
        );
        assert_eq!(timed_out.value()["effect"]["ending"]["cause"], "deadline");
        assert_eq!(
            timed_out.value()["effect"]["workspace_node"]["door_cause"],
            "deadline"
        );
        let refused = rows
            .iter()
            .find(|row| row.value()["effect"]["reason"] == "door-request-refusal")
            .expect("blacklist effect");
        assert_eq!(refused.value()["effect"]["reason"], "door-request-refusal");
        assert!(
            refused.value()["would_do"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("fixture-blocked"))
        );
    }

    /// ´test:unit:door-workspace-allow-miss-runs-before-its-agent-verdict´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_workspace_allow_miss_runs_before_its_agent_verdict() {
        use execute_command::workspace::{Blacklist, QuickPolicy, canonical_digest};
        use std::fmt::Write as _;

        for (mode, agent_enabled, stop_after_claim, retake_blocked, slot_after_claim, settings) in [
            (Mode::Allow, true, false, false, false, 1),
            (Mode::Allow, true, false, false, false, 3),
            (Mode::Allow, true, false, false, false, 0),
            (Mode::Allow, true, false, false, false, 2),
            (Mode::Enforce, true, false, false, false, 2),
            (Mode::Enforce, false, false, false, false, 2),
            (Mode::Enforce, true, true, false, false, 2),
            (Mode::Enforce, true, false, true, false, 2),
            (Mode::Enforce, true, false, false, true, 2),
        ] {
            struct Allows {
                release: Mutex<std::sync::mpsc::Receiver<()>>,
                waiting_home: Option<std::path::PathBuf>,
                registration: Registration,
                wire: Option<Vec<u8>>,
                hold_admission: bool,
                held_admission: Mutex<Option<super::RequestGuard>>,
                hold_second_slot: bool,
                held_slot: Mutex<Option<super::WorkspaceWaitSlot>>,
            }
            impl super::agent::AgentRunner for Allows {
                fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                    if let Some(home) = &self.waiting_home {
                        let git = super::RequestGuard::acquire_operation(
                            home,
                            &self.registration,
                            Some(super::transport::Operation::GitUpload),
                        )
                        .expect("Git admission while workspace waits")
                        .expect("Git is admitted");
                        drop(git);
                        let compute = super::RequestGuard::acquire_operation(
                            home,
                            &self.registration,
                            Some(super::transport::Operation::Compute),
                        )
                        .expect("legacy compute admission while workspace waits")
                        .expect("legacy compute is admitted");
                        drop(compute);
                        let route = route_for(home);
                        let store = super::Store::open(home, "alpha", true)
                            .expect("protected request store");
                        let second = super::WorkspaceWaitSlot::acquire(home, &self.registration)
                            .expect("second waiter slot")
                            .expect("second waiter may enter");
                        let runs: std::os::fd::OwnedFd =
                            File::open(home.join("runs")).expect("held runs").into();
                        let config: std::os::fd::OwnedFd =
                            File::open(home.join(".config/loops/alpha"))
                                .expect("held config")
                                .into();
                        let wire = self.wire.as_deref().expect("workspace request wire");
                        let request: Value = serde_json::from_slice(wire).expect("request JSON");
                        let (_peer, mut stream) = FixtureClient::pair().expect("third peer");
                        let started = Instant::now();
                        let third = super::serve_request_with_agent_at_context(
                            &mut stream,
                            &self.registration,
                            3000,
                            &request,
                            Some(&route),
                            Some(&route),
                            Some(home),
                            None,
                            Some(&store),
                            None,
                            None,
                            started,
                            super::lifetime::Start::at(started).expect("third lifetime"),
                            Some(super::WorkspaceSocketContext {
                                runs: &runs,
                                config_directory: &config,
                                owner: nix::unistd::Uid::effective().as_raw(),
                                wire,
                                judgement_wait_ms: 30_000,
                                deadline_ms: super::compute::DEADLINE_MS,
                            }),
                        )
                        .expect("third request answer")
                        .0;
                        assert_eq!(third["reason"], "door-request-concurrent");
                        assert_eq!(third["schema"], 3);
                        assert_eq!(third["waited_seconds"], 0.0);
                        assert_eq!(third["retry_after_seconds"], 30);
                        assert_eq!(third["admission_window"], super::admission_window());
                        assert_eq!(store.list_run("R").expect("filed records").len(), 1);
                        if self.hold_second_slot {
                            *self.held_slot.lock().expect("held waiter slot") = Some(second);
                        } else {
                            drop(second);
                        }
                        if self.hold_admission {
                            let held = super::RequestGuard::acquire_operation(
                                home,
                                &self.registration,
                                Some(super::transport::Operation::Compute),
                            )
                            .expect("retake contention fixture")
                            .expect("compute guard before retake");
                            *self.held_admission.lock().expect("held admission") = Some(held);
                        }
                    }
                    self.release
                        .lock()
                        .expect("release lock")
                        .recv_timeout(Duration::from_secs(120))
                        .expect("test released the agent after the worker reply");
                    let mut answer = super::agent::RunnerOutcome::referral(
                        "verdict",
                        "fixture permits the miss",
                        Instant::now(),
                    );
                    answer.verdict = "allow".into();
                    answer.scope = "loop".into();
                    answer
                }
            }

            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            for target in [
                crate::requests::modes::ModeTarget::Loop,
                crate::requests::modes::ModeTarget::class("compute").expect("class"),
            ]
            .into_iter()
            .skip(usize::from(settings == 3))
            .take(if settings == 3 {
                1
            } else {
                usize::try_from(settings).expect("setting count")
            }) {
                store
                    .set_mode(&target, mode, "fixture owner", "fixture mode", "1", &[])
                    .expect("allow compute mode");
            }
            let node = crate::workspace_node::tests::Fixture::new();
            let quick = QuickPolicy {
                revision: "fixture-1".into(),
                rules: vec![],
            };
            let blacklist = Blacklist {
                revision: "fixture-1".into(),
                entries: vec![],
            };
            let mut grant = node.grant.clone();
            grant.quick_policy_digest = canonical_digest(&quick).expect("quick digest");
            grant.blacklist_digest = canonical_digest(&blacklist).expect("blacklist digest");
            let mut placement = node.placement.clone();
            placement["grant_digest"] = json!(grant.digest().expect("grant digest"));
            let reservation = json!({"schema":1,"phase":"started","loop":"alpha",
            "run":"R","worker_uid":3000,"door_scope":"work",
            "plan":{"loop":"alpha","run":"R",
                "compute_workspace":{"digest":grant.digest().expect("grant digest"),
                    "grant":grant},"compute_placement":placement}});
            crate::launch::publish_reservation(
                &crate::launch::reservation_path(&fixture.home.join("runs"), "R"),
                &reservation,
            )
            .expect("protected reservation");
            let config = fixture.home.join(".config/loops/alpha");
            for (name, value) in [
                ("workspace-quick-policy.json", json!(quick)),
                ("workspace-blacklist.json", json!(blacklist)),
            ] {
                let path = config.join(name);
                fs::write(&path, serde_json::to_vec(&value).expect("policy JSON"))
                    .expect("policy file");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("policy mode");
            }
            let settings = config.join("workers.toml");
            let mut contents = fs::read_to_string(&settings).unwrap_or_default();
            let _written = write!(
                contents,
                "\n[workspace_policy]\nquick_policy_digest = \"{}\"\nblacklist_digest = \"{}\"\n",
                grant.quick_policy_digest, grant.blacklist_digest
            );
            fs::write(&settings, contents).expect("published policy digests");
            fs::set_permissions(&settings, fs::Permissions::from_mode(0o600))
                .expect("settings mode");
            let context = fixture.home.join("workspace-context.json");
            fs::write(
                &context,
                serde_json::to_vec(&json!({"schema":1,"run":"R",
                "worker_uid":nix::unistd::Uid::effective().as_raw(),
                "node_alias":"fixture-node","grant_digest":grant.digest().expect("digest"),
                "checkout":grant.workspace,"cwd":[],"shell":"/bin/sh"}))
                .expect("context JSON"),
            )
            .expect("stub context");
            let socket =
                crate::fixture_exec::fixture_socket_path(fixture.home.join("mode-miss.sock"));
            let listener = UnixListener::bind(&socket).expect("service socket");
            let route = route_for(&fixture.home);
            let (agent_release, agent_wait) = std::sync::mpsc::sync_channel(1);
            let registration = Registration {
                loop_name: "alpha".into(),
                run: "R".into(),
                worker_uid: 3000,
                loop_uid: 41001,
                scope: Scope::Work,
                mirror_ref: "refs/heads/lane/R".into(),
            };
            let home = fixture.home.clone();
            let server = thread::spawn(move || {
                super::transport::WORKSPACE_FIXTURE_IDENTITY
                    .with(|slot| *slot.borrow_mut() = Some(node.identity));
                let runs: std::os::fd::OwnedFd =
                    File::open(home.join("runs")).expect("held runs").into();
                let config: std::os::fd::OwnedFd = File::open(home.join(".config/loops/alpha"))
                    .expect("held config")
                    .into();
                let mut peer = FixtureServer::accept(&listener).expect("stub peer");
                let request = fixture_request(&mut peer).expect("stub request");
                let wire = serde_json::to_vec(&request).expect("request wire");
                let allow_agent = Allows {
                    release: Mutex::new(agent_wait),
                    waiting_home: (mode == Mode::Enforce).then(|| home.clone()),
                    registration: registration.clone(),
                    wire: (mode == Mode::Enforce).then(|| wire.clone()),
                    hold_admission: retake_blocked,
                    held_admission: Mutex::new(None),
                    hold_second_slot: slot_after_claim,
                    held_slot: Mutex::new(None),
                };
                if retake_blocked {
                    let clock = Arc::new(super::FixtureAdmissionClock {
                        now: Mutex::new(Instant::now()),
                        slept_ms: std::sync::atomic::AtomicU64::new(0),
                        attempts: AtomicUsize::new(0),
                    });
                    super::ADMISSION_CLOCK.with(|slot| {
                        *slot.borrow_mut() = Some(std::rc::Rc::new(clock));
                    });
                }
                if slot_after_claim {
                    let home = home.clone();
                    let registration = registration.clone();
                    super::AFTER_WAITING_CLAIM.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move |_| {
                            let third = super::WorkspaceWaitSlot::acquire(&home, &registration)
                                .expect("third waiter acquisition after claim")
                                .expect("a claimed request no longer occupies a waiter slot");
                            drop(third);
                        }));
                    });
                } else if stop_after_claim {
                    super::AFTER_WAITING_CLAIM.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(|wait| {
                            wait.cause.select(super::lifetime::Cause::Deadline);
                        }));
                    });
                }
                let started = Instant::now();
                super::serve_request_with_agent_at_context(
                    &mut peer,
                    &registration,
                    3000,
                    &request,
                    Some(&route),
                    Some(&route),
                    Some(home.as_path()),
                    None,
                    Some(&store),
                    agent_enabled.then_some(&allow_agent as &dyn super::agent::AgentRunner),
                    None,
                    started,
                    super::lifetime::Start::at(started).expect("lifetime"),
                    Some(super::WorkspaceSocketContext {
                        runs: &runs,
                        config_directory: &config,
                        owner: nix::unistd::Uid::effective().as_raw(),
                        wire: &wire,
                        judgement_wait_ms: 30_000,
                        deadline_ms: super::compute::DEADLINE_MS,
                    }),
                )
                .expect("workspace service")
                .0
            });
            super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = Some(context));
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if mode == Mode::Enforce && agent_enabled {
                agent_release.send(()).expect("agent may decide the wait");
            }
            let reply = super::transport::stub_call_stream(
                &socket,
                &[
                    OsString::from("fixture-node"),
                    OsString::from("/usr/bin/printf other"),
                ],
                io::empty(),
                &mut stdout,
                &mut stderr,
            )
            .expect("real stub call");
            if mode == Mode::Allow && agent_enabled {
                agent_release
                    .send(())
                    .expect("agent may finish after the worker reply");
            }
            super::transport::STUB_CONTEXT_PATH.with(|slot| *slot.borrow_mut() = None);
            assert_eq!(server.join().expect("service thread"), reply);
            assert_eq!(
                reply["reason"],
                if retake_blocked {
                    "door-request-concurrent"
                } else if stop_after_claim {
                    "door-request-deadline"
                } else if agent_enabled {
                    "door-complete"
                } else {
                    "door-workspace-referred"
                },
                "mode={mode:?} reply={reply}"
            );
            assert_eq!(
                stdout,
                if agent_enabled && !stop_after_claim && !retake_blocked {
                    b"other".as_slice()
                } else {
                    b"".as_slice()
                }
            );
            if mode == Mode::Enforce {
                assert!(
                    String::from_utf8_lossy(&stderr).contains("door-waiting request_id="),
                    "the worker sees the waiting request id: {stderr:?}"
                );
            }
            let rows = fixture.store().list_run("R").expect("request rows");
            assert_eq!(rows.len(), 1);
            let workspace = rows
                .iter()
                .find(|row| row.value()["operation"] == "compute-workspace")
                .expect("workspace record");
            assert_eq!(
                workspace.value()["effect"]["state"],
                if agent_enabled && !stop_after_claim && !retake_blocked {
                    "completed"
                } else {
                    "refused"
                }
            );
            if stop_after_claim {
                assert!(workspace.value()["state"].is_null());
            } else {
                assert_eq!(
                    workspace.value()["state"],
                    if mode == Mode::Allow || !agent_enabled || retake_blocked {
                        "waiting"
                    } else {
                        "observed"
                    }
                );
            }
            assert_eq!(
                workspace.value()["would_do_source"],
                if agent_enabled { "agent" } else { "superloop" }
            );
            if agent_enabled {
                assert_eq!(workspace.value()["agent_verdict"], "allow");
            } else {
                assert_eq!(workspace.value()["would_do"]["decision"], "undecided");
                assert_eq!(
                    workspace.value()["would_do"]["reason"],
                    "door-agent-unconfigured"
                );
                assert!(workspace.value()["workspace_agent_input"].is_null());
            }
            if stop_after_claim {
                assert_eq!(
                    workspace.value()["effect"]["reason"],
                    "door-request-deadline"
                );
                assert_eq!(workspace.value()["effect"]["ending"]["cause"], "deadline");
            }
            if retake_blocked {
                assert_eq!(reply["retry_after_seconds"], 30);
                assert_eq!(reply["admission_window"], super::admission_window());
                assert!(
                    reply["waited_seconds"]
                        .as_f64()
                        .is_some_and(|wait| wait > 0.0)
                );
                assert_eq!(
                    workspace.value()["effect"]["reason"],
                    "door-request-concurrent"
                );
            }
        }
    }

    /// ´test:unit:unrecorded-ending-retains-observed-stop-cause´
    #[test]
    fn unrecorded_ending_retains_observed_stop_cause() {
        let mut ending = crate::requests::unobserved_ending();
        let unknown = super::unrecorded_ending("R:aa", None, &ending);
        assert_eq!(unknown["cause"], "handler-failure");
        ending["cause"] = json!("deadline");
        let event = super::unrecorded_ending("R:aa", None, &ending);
        assert_eq!(event["cause"], "deadline");
        assert_eq!(event["reason"], "door-handler-ended");
        assert_eq!(event["request_id"], "R:aa");
        assert_eq!(event["recorded"], false);
    }

    /// ´test:unit:door-root-registration-refusal-reaches-worker-with-path´
    #[test]
    fn door_root_registration_refusal_reaches_worker_with_path() {
        for root in [None, Some(json!("relative")), Some(json!(null))] {
            let fixture = Fixture::new();
            let _route = route_for(&fixture.home);
            let config = fixture.home.join(".config/loops/alpha");
            let path = config.join("door-compute-registration.json");
            let mut value: Value =
                serde_json::from_slice(&fs::read(&path).expect("route")).expect("JSON");
            value.as_object_mut().expect("object").remove("node_root");
            if let Some(root) = root {
                value["node_root"] = root;
            }
            fs::write(&path, serde_json::to_vec(&value).expect("bytes")).expect("route");
            let directory = File::open(&config).expect("config");
            let error = HostRunner::load(
                &directory,
                &config,
                "alpha",
                nix::unistd::Uid::effective().as_raw(),
            )
            .err()
            .expect("invalid root");
            assert_eq!(error.kind, "door-compute-root-refusal");
            let socket =
                crate::fixture_exec::fixture_socket_path(fixture.home.join("root-refusal.sock"));
            let listener = UnixListener::bind(&socket).expect("socket");
            let home = fixture.home.clone();
            let server = thread::spawn(move || {
                let home_fd = File::open(&home).expect("inherited home");
                let runs = home.join("runs");
                let runs_fd = File::open(&runs).expect("inherited runs");
                let _namespace = crate::home::activate_private_launch(
                    &home,
                    &home_fd,
                    &runs,
                    &runs_fd,
                    None,
                    nix::unistd::Uid::effective().as_raw(),
                )
                .expect("private fixture namespace");
                let mut stream = FixtureServer::accept(&listener).expect("peer");
                let request = fixture_request(&mut stream).expect("request");
                let registration = Registration::from_row(
                    &json!({"name":"alpha","uid":41001}),
                    "alpha",
                    "R",
                    3000,
                    Scope::Work,
                )
                .expect("registration");
                super::root_refusal(
                    &mut stream,
                    &registration,
                    3000,
                    &request,
                    &home,
                    &error,
                    Instant::now(),
                )
                .expect("refusal");
            });
            let mut stderr = Vec::new();
            let reply = super::stub_call_stream(
                &socket,
                &[
                    OsString::from("fixture"),
                    OsString::from("/opt/fixture/bin/report git diff"),
                ],
                io::empty(),
                io::sink(),
                &mut stderr,
            )
            .expect("worker response");
            server.join().expect("server");
            assert_eq!(reply["reason"], "door-compute-root-refusal");
            assert_eq!(reply["status"], 125);
            let diagnostic = String::from_utf8(stderr).expect("diagnostic");
            assert!(diagnostic.contains(path.to_str().expect("path")));
            assert!(diagnostic.contains("node_root"));
            let rows = fixture.store().list_run("R").expect("refusal record");
            assert_eq!(rows[0].value()["effect"]["stderr_bytes"], diagnostic.len());
            assert_eq!(reply["stderr_bytes"], diagnostic.len());
            assert_eq!(
                rows[0].value()["effect"]["reason"],
                "door-compute-root-refusal"
            );
        }
    }

    /// ´test:unit:door-service-generation-requires-recorded-host-group´
    #[test]
    fn door_service_generation_requires_recorded_host_group() {
        let mut generation = json!({"schema":1,"phase":"complete","loop":"alpha","template_dir":"/template","socket_dir":"/sockets","stub_sha256":"stub","service_sha256":"service","unit_dir":"/units","registered":["ssh"],"host_door_gid":41001});
        assert_eq!(
            completed_door_group(&generation, "alpha")
                .expect_err("legacy generation")
                .kind,
            "door-generation-upgrade-required"
        );
        generation["schema"] = json!(2);
        generation["agent"] = json!({"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"agent_expected_tokens":16384,"entry":"/fixture/entry","loop_home":"/fixture/home"});
        assert_eq!(
            completed_door_group(&generation, "alpha").expect("group"),
            41001
        );
        let mut missing = generation.clone();
        missing
            .as_object_mut()
            .expect("generation object")
            .remove("host_door_gid");
        assert_eq!(
            completed_door_group(&missing, "alpha")
                .expect_err("old generation refuses")
                .kind,
            "door-install"
        );
        let mut malformed = generation;
        malformed["host_door_gid"] = json!("41001");
        let refusal =
            completed_door_group(&malformed, "alpha").expect_err("non-numeric group refuses");
        assert_eq!(refusal.kind, "door-install");
        assert_eq!(refusal.detail, "recorded host door group is absent");
    }

    fn refused_socket_within(
        timeout: Duration,
        mut connect: impl FnMut() -> io::Result<UnixStream>,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if matches!(connect(), Err(error) if error.kind() == io::ErrorKind::ConnectionRefused) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            thread::sleep(remaining.min(Duration::from_millis(5)));
        }
    }

    fn await_refused_socket(path: &std::path::Path) {
        assert!(
            refused_socket_within(Duration::from_secs(2), || UnixStream::connect(path)),
            "closed fixture listener did not become a refused socket"
        );
    }

    /// ´test:unit:stale-socket-wait-has-wall-bound´
    #[test]
    fn stale_socket_wait_has_wall_bound() {
        let mut attempts = 0;
        let refused = refused_socket_within(Duration::ZERO, || {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::NotFound))
        });
        assert!(!refused);
        assert_eq!(attempts, 1);
    }

    /// ´test:unit:door-socket-start-removes-failed-bind-and-recovers-stale-slot´
    #[test]
    fn door_socket_start_removes_failed_bind_and_recovers_stale_slot() {
        let fixture = Fixture::new();
        let path = fixture.home.join("door-socket-start");
        fs::create_dir(&path).expect("fixture directory");
        let directory: std::os::fd::OwnedFd = File::open(&path).expect("fixture fd").into();
        let slot = crate::SocketSlot::beneath(&directory, std::ffi::OsStr::new("capability.sock"))
            .expect("fixture slot");
        let error = super::bind_socket_slot(&slot, |_listener, _stat| {
            Err(crate::error::LaneError::operation(
                "door-socket",
                "injected after bind",
            ))
        })
        .err()
        .expect("injected failure");
        assert_eq!(error.detail, "injected after bind");
        assert!(slot.metadata().expect("empty slot").is_none());

        let error = super::bind_socket_slot(&slot, |_listener, _stat| {
            slot.set_owner_mode(
                nix::unistd::Uid::effective().as_raw(),
                nix::unistd::Gid::effective().as_raw(),
                0o600,
            )
            .map_err(|failure| {
                crate::error::LaneError::operation("door-socket", failure.to_string())
            })
        })
        .err()
        .expect("parent rejects wrong child mode");
        assert_eq!(error.detail, "socket identity changed");
        assert!(slot.metadata().expect("empty failed slot").is_none());

        let stale = UnixListener::bind(crate::fixture_exec::fixture_socket_path(slot.address()))
            .expect("stale socket");
        slot.set_owner_mode(
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
            0o600,
        )
        .expect("foreign mode");
        drop(stale);
        await_refused_socket(slot.address());
        let (listener, cleanup) = super::bind_socket_slot(&slot, |_listener, _stat| {
            slot.set_owner_mode(
                nix::unistd::Uid::effective().as_raw(),
                nix::unistd::Gid::effective().as_raw(),
                0o660,
            )
            .map_err(|error| crate::error::LaneError::operation("door-socket", error.to_string()))
        })
        .expect("replace stale foreign-mode socket");
        assert_eq!(
            slot.metadata().expect("metadata").expect("socket").st_mode & 0o7777,
            0o660
        );
        let error = super::clear_stale_socket(&slot).expect_err("live listener refuses");
        assert_eq!(error.kind, "door-socket");
        drop(listener);
        drop(cleanup);
        assert!(slot.metadata().expect("clean slot").is_none());
        fs::write(slot.address(), b"occupied").expect("non-socket entry");
        let error = super::clear_stale_socket(&slot).expect_err("non-socket refuses");
        assert_eq!(error.detail, "socket slot is occupied or changed");
        fs::remove_file(slot.address()).expect("fixture cleanup");
    }

    /// ´test:unit:door-socket-entry-requires-namespace-root´
    #[test]
    fn door_socket_entry_requires_namespace_root() {
        let words = ["41001".into(), "1".into(), "2".into()];
        let refusal = super::run_socket_group_private(&words)
            .expect_err("host uid cannot claim namespace root");
        assert_eq!(refusal.kind, "door-socket-private");
        assert_eq!(refusal.detail, "namespace root is required");
    }

    /// ´test:unit:door-socket-private-uses-handoff-and-namespace-identity´
    #[test]
    fn door_socket_private_uses_handoff_and_namespace_identity() {
        let fixture = Fixture::new();
        let path = fixture.home.join("door-socket-private");
        fs::create_dir(&path).expect("fixture directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).expect("directory mode");
        let directory: std::os::fd::OwnedFd = File::open(&path).expect("fixture fd").into();
        let slot = crate::SocketSlot::beneath(&directory, std::ffi::OsStr::new("capability.sock"))
            .expect("fixture slot");
        let listener = UnixListener::bind(crate::fixture_exec::fixture_socket_path(slot.address()))
            .expect("fixture listener");
        let stat = slot.metadata().expect("metadata").expect("socket");
        for caller in [41001, 3000] {
            let error = super::private_set_socket_group(
                nix::unistd::dup(&directory).expect("directory duplicate"),
                &nix::unistd::dup(&listener).expect("listener duplicate"),
                41001,
                stat.st_dev,
                stat.st_ino,
                0,
                Some((caller, caller, 41001)),
            )
            .expect_err("host or worker cannot claim namespace root");
            assert_eq!(error.detail, "namespace root is required");
        }
        let (parent, child) = UnixStream::pair().expect("descriptor channel");
        crate::home::send_private_descriptors(
            &parent,
            &[directory.as_raw_fd(), listener.as_raw_fd()],
        )
        .expect("send held descriptors");
        let words = [
            "41001".to_owned(),
            stat.st_dev.to_string(),
            stat.st_ino.to_string(),
        ];
        super::socket_group_entry(&words, &child, Some((0, 0, 41001)))
            .expect("handed descriptors use namespace-side identity");
        assert_eq!(
            slot.metadata().expect("metadata").expect("socket").st_mode & 0o7777,
            0o660
        );
        let error = super::private_set_socket_group(
            nix::unistd::dup(&directory).expect("directory duplicate"),
            &nix::unistd::dup(&listener).expect("listener duplicate"),
            41001,
            stat.st_dev,
            stat.st_ino + 1,
            0,
            Some((0, 0, 41001)),
        )
        .expect_err("changed socket identity");
        assert_eq!(error.detail, "socket identity differs");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("changed directory");
        let error = super::private_set_socket_group(
            nix::unistd::dup(&directory).expect("directory duplicate"),
            &nix::unistd::dup(&listener).expect("listener duplicate"),
            41001,
            stat.st_dev,
            stat.st_ino,
            0,
            Some((0, 0, 41001)),
        )
        .expect_err("changed directory mode");
        assert_eq!(error.detail, "socket directory differs");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).expect("restore directory");
        let error = super::private_set_socket_group(
            nix::unistd::dup(&directory).expect("directory duplicate"),
            &directory,
            41001,
            stat.st_dev,
            stat.st_ino,
            0,
            Some((0, 0, 41001)),
        )
        .expect_err("non-socket listener descriptor");
        assert_eq!(error.detail, "listener descriptor is not a socket");
        let (incomplete_parent, incomplete_child) = UnixStream::pair().expect("descriptor channel");
        crate::home::send_private_descriptors(&incomplete_parent, &[directory.as_raw_fd()])
            .expect("send incomplete descriptors");
        let error = super::socket_group_entry(&words, &incomplete_child, Some((0, 0, 41001)))
            .expect_err("incomplete descriptor transfer");
        assert_eq!(error.kind, "verified-prefix");
        slot.remove().expect("fixture cleanup");
        let error = super::private_set_socket_group(
            nix::unistd::dup(&directory).expect("directory duplicate"),
            &nix::unistd::dup(&listener).expect("listener duplicate"),
            41001,
            stat.st_dev,
            stat.st_ino,
            0,
            Some((0, 0, 41001)),
        )
        .expect_err("absent socket entry");
        assert_eq!(error.detail, "socket entry is absent");
        drop(listener);
    }

    /// ´test:unit:door-socket-host-setter-refuses-namespace-owner-and-loop-group´
    #[test]
    fn door_socket_host_setter_refuses_namespace_owner_and_loop_group() {
        let fixture = Fixture::new();
        let path = fixture.home.join("door-socket-host-setter");
        fs::create_dir(&path).expect("fixture directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).expect("directory mode");
        let directory: std::os::fd::OwnedFd = File::open(&path).expect("fixture fd").into();
        let slot = crate::SocketSlot::beneath(&directory, std::ffi::OsStr::new("capability.sock"))
            .expect("fixture slot");
        let listener = UnixListener::bind(crate::fixture_exec::fixture_socket_path(slot.address()))
            .expect("fixture listener");
        let stat = slot.metadata().expect("metadata").expect("socket");
        super::FIXTURE_PRODUCTION_SETTER.with(|flag| flag.set(true));
        let result = super::private_set_socket_group(
            nix::unistd::dup(&directory).expect("directory duplicate"),
            &nix::unistd::dup(&listener).expect("listener duplicate"),
            41001,
            stat.st_dev,
            stat.st_ino,
            0,
            Some((0, 0, 41001)),
        );
        super::FIXTURE_PRODUCTION_SETTER.with(|flag| flag.set(false));
        let error = result.expect_err("host cannot set namespace owner and loop group");
        assert_eq!(error.kind, "door-socket-private");
        assert_eq!(error.status, 1);
        assert!(
            error.detail.contains("Operation not permitted"),
            "{error:?}"
        );
    }

    /// ´test:unit:door-socket-private-form-refuses-each-invalid-number´
    #[test]
    fn door_socket_private_form_refuses_each_invalid_number() {
        for (words, detail) in [
            (vec![], "private form is incomplete"),
            (vec!["41001"], "private form is incomplete"),
            (vec!["x", "1", "2"], "private number is invalid"),
            (vec!["4294967296", "1", "2"], "group is outside range"),
            (vec!["41001", "x", "2"], "private number is invalid"),
            (vec!["41001", "1", "x"], "private number is invalid"),
        ] {
            let words = words.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let error = super::parse_socket_group_args(&words).expect_err("invalid private form");
            assert_eq!(error.detail, detail);
        }
    }

    /// ´test:unit:door-fixture-helper-exits-are-named-and-cleaned´
    #[test]
    fn door_fixture_helper_exits_are_named_and_cleaned() {
        for (case, fault, detail) in [
            ("door-allow", "loop-setting", "loop setting is absent"),
            (
                "door-allow",
                "agreeing-id",
                "agreeing audit fixture id is absent",
            ),
            ("door-enforce", "seed-id", "fixture seed id is absent"),
            ("door-audit", "peer-diff", "fixture peer differs"),
            ("door-audit", "unfiled", "fixture request was not filed"),
            ("door-audit", "triage", "invalid"),
            ("door-audit", "stub-join", "fixture stub panicked"),
            ("door-audit", "service-join", "fixture service panicked"),
            ("door-audit", "cleanup", "No such file"),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let _route = route_for(&fixture.home);
            if fault == "seed-id" {
                fixture
                    .store()
                    .set_mode(
                        &crate::requests::modes::ModeTarget::Loop,
                        Mode::Audit,
                        "fixture",
                        "explicit audit baseline",
                        "1",
                        &[],
                    )
                    .expect("prior loop setting");
            }
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                3000,
                Scope::Work,
            )
            .expect("registration");
            let (runner, _, _) = counting_runner(&fixture);
            let runner: Arc<dyn Runner> = Arc::new(runner);
            let error = super::with_fixture_helper_fault(fault, || {
                super::exercise_mode_fixture_with(
                    &fixture.home,
                    &registration,
                    case,
                    Some(runner),
                    &mut json!({}),
                )
            })
            .expect_err("named helper refusal");
            assert!(error.detail.contains(detail), "{fault}: {error:?}");
            let config = fixture.home.join(".config/loops/alpha");
            assert!(
                !fs::read_dir(config)
                    .expect("config entries")
                    .any(|entry| entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".door-fixture-")),
                "{fault} left fixture socket"
            );
        }
    }

    /// ´test:unit:door-fixture-compute-observation-refuses-absent-or-poisoned-state´
    #[test]
    fn door_fixture_compute_observation_refuses_absent_or_poisoned_state() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let runner = super::ObservedFixtureRunner {
            inner: Arc::new(super::CatRunner),
            store: fixture.store(),
            run: "R".into(),
            prior: HashSet::new(),
            observations: Arc::clone(&observations),
            deadline: Instant::now() + Duration::from_secs(120),
            force_absent: false,
        };
        let absent = runner
            .spawn(&registration, Operation::ProbeEcho)
            .expect_err("request absent at compute start");
        assert!(
            absent
                .to_string()
                .contains("fixture request is absent at compute start")
        );
        store
            .file(waiting("R", "1a", 3000, Mode::Audit))
            .expect("request");
        let poisoned = Arc::clone(&observations);
        let _ended = thread::spawn(move || {
            let _held = poisoned.lock().expect("fixture lock");
            panic!("poison fixture observation");
        })
        .join();
        let error = runner
            .spawn(&registration, Operation::ProbeEcho)
            .expect_err("poisoned observation lock");
        assert!(
            error
                .to_string()
                .contains("fixture observation lock poisoned")
        );
    }

    struct CountingRunner {
        calls: Arc<AtomicUsize>,
        seen_state: Arc<Mutex<Vec<String>>>,
        store: Store,
        fail_after_input: bool,
    }

    impl Runner for CountingRunner {
        fn spawn(&self, _registration: &Registration, _operation: Operation) -> io::Result<Child> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rows = self.store.list().map_err(io::Error::other)?.0;
            let state = rows.last().map_or("absent", |row| {
                row.value()["state"].as_str().unwrap_or("intent")
            });
            self.seen_state
                .lock()
                .expect("fixture states")
                .push(state.to_owned());
            let mut command = Command::new("/usr/bin/cat");
            if self.fail_after_input {
                command.args(["-", "/definitely-unavailable-door-fixture-source"]);
            }
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        }
    }

    pub(super) fn route_for(home: &std::path::Path) -> HostRunner {
        let config = home.join(".config/loops/alpha");
        let owner = nix::unistd::Uid::effective().as_raw();
        let route = json!({"schema":1,"loop":"alpha","alias":"fixture",
            "mirror_root":"~/mirrors","node_root":"/srv/loops/loop-a","key_path":config.join("door-key"),"compute_wrapper":"/opt/fixture/bin/report","compute_environment":json!({"RUSTUP_HOME":"/opt/fixture/rustup","PATH":"/opt/fixture/tools:/opt/fixture/cargo/bin:/usr/bin:/bin","PUBLIC_PACK_TEST_LINTER":"/opt/fixture/tools/superloop-lint"})});
        for (name, bytes) in [
            (
                "door-compute-registration.json",
                serde_json::to_vec(&route).expect("route bytes"),
            ),
            ("door-ssh_config", b"Host fixture\nHostName 192.0.2.1\nUser fixture\nUserKnownHostsFile /fixture/known_hosts\nStrictHostKeyChecking yes\n".to_vec()),
        ] {
            let path = config.join(name);
            fs::write(&path, bytes).expect("fixture route");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("route mode");
        }
        crate::door_node::fixture(&config);
        let held = File::open(&config).expect("held config");
        HostRunner::load(&held, &config, "alpha", owner).expect("fixture route pin")
    }

    fn rubric(decision: Option<&str>) -> Rubric {
        let rules = decision.map_or_else(Vec::new, |decision| {
            vec![json!({
            "operation":"probe-echo","shape_key":"ssh:probe-echo",
            "decision":decision,"reason":"fixture rubric decision"})]
        });
        Rubric::decode(&json!({"schema":1,"class":"ssh","undecided_reason":"fixture rubric has no row","rules":rules})).expect("fixture rubric")
    }

    fn fixture_class_rubric(decision: Option<&str>) -> Rubric {
        let rules = decision.map_or_else(Vec::new, |decision| {
            vec![
                json!({"operation":"probe-echo","shape_key":"fixture:probe-echo",
                "decision":decision,"reason":"fixture class rubric"}),
            ]
        });
        Rubric::decode(&json!({"schema":1,"class":"fixture",
            "undecided_reason":"fixture class has no matching row","rules":rules}))
        .expect("fixture class rubric")
    }

    fn fixture_service(
        fixture: &Fixture,
        runner: CountingRunner,
        rubric: Rubric,
        deadline_ms: u64,
        cap: Option<usize>,
    ) -> (
        FixtureClient,
        thread::JoinHandle<io::Result<serde_json::Value>>,
    ) {
        fixture_service_with(fixture, runner, rubric, deadline_ms, cap, None, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn fixture_service_with(
        fixture: &Fixture,
        runner: CountingRunner,
        rubric: Rubric,
        deadline_ms: u64,
        cap: Option<usize>,
        fault: Option<FixtureFault>,
        registered: bool,
    ) -> (
        FixtureClient,
        thread::JoinHandle<io::Result<serde_json::Value>>,
    ) {
        let (socket, server) =
            fixture_stub_service_with(fixture, runner, rubric, deadline_ms, cap, fault, registered);
        (
            FixtureClient::connect(socket).expect("connected fixture client"),
            server,
        )
    }

    fn fixture_stub_service(
        fixture: &Fixture,
        runner: CountingRunner,
        rubric: Rubric,
        deadline_ms: u64,
        cap: Option<usize>,
    ) -> (PathBuf, thread::JoinHandle<io::Result<serde_json::Value>>) {
        fixture_stub_service_with(fixture, runner, rubric, deadline_ms, cap, None, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn fixture_stub_service_with(
        fixture: &Fixture,
        runner: CountingRunner,
        rubric: Rubric,
        deadline_ms: u64,
        cap: Option<usize>,
        fault: Option<FixtureFault>,
        registered: bool,
    ) -> (PathBuf, thread::JoinHandle<io::Result<serde_json::Value>>) {
        let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join(format!(
            "door-fixture-{deadline_ms}-{}.sock",
            super::REQUEST_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )));
        let listener = UnixListener::bind(&socket).expect("fixture socket");
        let home = fixture.home.clone();
        let store = fixture.store();
        let filed = super::REQUEST_FILED.with(|slot| slot.borrow_mut().take());
        let ready = super::REQUEST_READY.with(|slot| slot.borrow_mut().take());
        let writer_wait = crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.get();
        let server = thread::spawn(move || {
            super::REQUEST_FILED.with(|slot| *slot.borrow_mut() = filed);
            super::REQUEST_READY.with(|slot| *slot.borrow_mut() = ready);
            crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.set(writer_wait);
            fixture_file_cap(cap);
            fixture_fault(fault);
            let mut stream = FixtureServer::accept(&listener)?;
            let started = Instant::now();
            let _socket_peer = peer_uid(&stream)?;
            let peer = 3000;
            let request = fixture_request(&mut stream)?;
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                peer,
                Scope::Work,
            )
            .map_err(io::Error::other)?;
            let route = route_for(&home);
            let reply = serve_request(
                &mut stream,
                &registration,
                peer,
                &request,
                Some(&route),
                Some(&runner),
                registered.then_some(home.as_path()),
                Some(&rubric),
                Some(&store),
                started,
            )?
            .0;
            fixture_file_cap(None);
            fixture_fault(None);
            Ok(reply)
        });
        (socket, server)
    }

    /// # Panics
    /// Panics only if fixture setup fails or observation changes a receive record's attribution.
    /// ´test:unit:door-attribution-service-receives-stay-unlabelled´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_attribution_service_receives_stay_unlabelled() {
        for (floor, mode) in [
            ("audit", Mode::Audit),
            ("allow", Mode::Allow),
            ("enforce", Mode::Enforce),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor(floor);
            let store = fixture.store();
            if mode != Mode::Audit {
                set_fixture_mode(&store, mode);
            }
            let finished = AtomicBool::new(false);
            let observed = Arc::new(std::sync::Mutex::new(HashSet::new()));
            let watched = thread::scope(|scope| {
                struct FinishWatch<'a>(&'a AtomicBool);
                impl Drop for FinishWatch<'_> {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                let watcher = scope.spawn(|| {
                    crate::launch::exercise::door_attribution::watch_requests_with_observer(
                        &store,
                        "R",
                        &HashSet::new(),
                        &finished,
                        |value| {
                            observed
                                .lock()
                                .expect("observed requests")
                                .insert(value["id"].as_str().expect("request id").to_owned());
                        },
                    )
                });
                // Drop before scope joins even when a client assertion panics.
                let _finish_watch = FinishWatch(&finished);
                let read_reply = FixtureClient::answer;
                for _ in 0..2 {
                    let observed = Arc::clone(&observed);
                    let expired = Instant::now();
                    // Keep the watcher live while the receive is waiting. Only
                    // its actual observation permits this fixture to end the wait.
                    super::REQUEST_READY.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move |id| {
                            let setup = Instant::now() + FIXTURE_HANG;
                            while !observed
                                .lock()
                                .map_err(|_| io::Error::other("observer lock"))?
                                .contains(id)
                            {
                                if Instant::now() >= setup {
                                    return Err(io::Error::other("receive observation readiness"));
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Ok(if floor == "allow" {
                                Instant::now() + FIXTURE_HANG
                            } else {
                                expired
                            })
                        }));
                    });
                    let (runner, _, _) = counting_runner(&fixture);
                    let (socket, server) =
                        fixture_service(&fixture, runner, rubric(Some("allow")), 120_000, None);
                    let mut client = socket;
                    client
                        .send(&json!({"schema":2,"argv":[b"fixture".to_vec(),
                            b"git-receive-pack '~/mirrors/R.git'".to_vec()],"deadline_ms":120_000}))
                        .expect("receive request");
                    client.shutdown(Shutdown::Write).expect("receive end");
                    let _reply = read_reply(&mut client);
                    server
                        .join()
                        .expect("service thread")
                        .expect("service reply");
                }
                let (runner, _, _) = counting_runner(&fixture);
                let (socket, server) =
                    fixture_service(&fixture, runner, rubric(None), 120_000, None);
                let mut echo = send_probe(socket, 120_000);
                let echo_frame = read_reply(&mut echo);
                assert_eq!(
                    echo_frame["queue_state"],
                    if floor == "allow" {
                        "no-queue"
                    } else {
                        "answered"
                    },
                    "{floor}"
                );
                server.join().expect("echo thread").expect("echo reply");
                finished.store(true, Ordering::Release);
                watcher
                    .join()
                    .expect("watcher thread")
                    .expect("watcher result")
            });
            assert_eq!(watched.records["git-receive"].len(), 2);
            assert_eq!(watched.records["git-receive"][0]["mode"], floor);
            assert_eq!(watched.records["probe-echo"][0]["mode"], floor);
            let rows = store.list_run("R").expect("service records");
            assert_eq!(rows.len(), 3, "{floor}");
            for row in rows {
                assert_eq!(row.value()["class"], "ssh");
                assert_eq!(row.value()["mode"], floor);
                if row.value()["operation"] == "git-receive" {
                    assert!(row.value()["label"].is_null(), "{floor}");
                    assert!(!watched.answered.iter().any(|id| id == row.id()), "{floor}");
                }
            }
            let (_, _, claims) = crate::launch::exercise::door_attribution::evaluate(
                &json!({"changed_ref_waiting":true}),
                "R",
                "refs/heads/lane/R",
                3000,
                "work",
                &watched.records,
            );
            assert!(claims["changed_ref"]["mode"].is_null());
            assert_eq!(claims["changed_ref"]["verdict"], "unmeasured");
            assert!(
                claims["changed_ref"]["reason"]
                    .as_str()
                    .expect("reason")
                    .contains("cannot be attributed")
            );
            let mut isolated = watched.records.clone();
            isolated
                .get_mut("git-receive")
                .expect("receive")
                .truncate(1);
            let (_, _, isolated_claims) = crate::launch::exercise::door_attribution::evaluate(
                &json!({"changed_ref_waiting":true}),
                "R",
                "refs/heads/lane/R",
                3000,
                "work",
                &isolated,
            );
            assert_eq!(isolated_claims["changed_ref"]["mode"], floor);
            for (slug, operation) in [
                ("complete_status", "probe-echo"),
                ("peer_registration", "probe-echo"),
                ("long_duplex", "probe-echo"),
                ("separate_walls", "probe-echo"),
                ("changed_ref", "git-receive"),
                ("caller_authority", "unregistered"),
                ("remote_exit_status", "probe-status"),
                ("whole_command_deadline", "probe-deadline"),
                ("disconnect_followup", "probe-status"),
            ] {
                let index = usize::from(slug == "disconnect_followup");
                let expected = watched
                    .records
                    .get(operation)
                    .filter(|rows| operation != "git-receive" || rows.len() == 1)
                    .and_then(|rows| rows.get(index))
                    .map_or(Value::Null, |record| record["mode"].clone());
                assert_eq!(claims[slug]["mode"], expected, "{slug}");
            }
        }
    }

    fn send_probe(mut client: FixtureClient, deadline_ms: u64) -> FixtureClient {
        client
            .send(&json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":deadline_ms}))
            .expect("fixture request");
        client.shutdown(Shutdown::Write).expect("request end");
        client
    }

    fn wait_filed(store: &Store) -> String {
        for _ in 0..100 {
            if let Some(record) = store.list().expect("fixture list").0.first() {
                return record.id().to_owned();
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("fixture request was not filed")
    }

    fn counting_runner(
        fixture: &Fixture,
    ) -> (CountingRunner, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let states = Arc::new(Mutex::new(Vec::new()));
        (
            CountingRunner {
                calls: calls.clone(),
                seen_state: states.clone(),
                store: fixture.store(),
                fail_after_input: false,
            },
            calls,
            states,
        )
    }

    fn label(store: &Store, id: &str, treatment: &str) {
        let at = super::now_nanos().to_string();
        store
            .triage(
                "R",
                &[json!({"id":id,"action":"adjudicate","treatment":treatment,
            "reason":"fixture decision"})],
                "fixture owner",
                &at,
            )
            .expect("fixture label");
    }

    fn incomplete_attempt(fixture: &Fixture) -> serde_json::Value {
        let bytes = fs::read(
            fixture
                .home
                .join(".config/loops/alpha/door-requests-attempt.json"),
        )
        .expect("incomplete attempt");
        serde_json::from_slice(&bytes).expect("attempt JSON")
    }

    fn assert_incomplete(fixture: &Fixture, id: &str) {
        let attempt = incomplete_attempt(fixture);
        assert_eq!(attempt["latest"]["incomplete"]["phase"], "incomplete");
        assert!(
            attempt["latest"]["incomplete"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(id))
        );
    }

    fn set_fixture_mode(store: &Store, mode: crate::requests::Mode) {
        for target in [
            crate::requests::modes::ModeTarget::Loop,
            crate::requests::modes::ModeTarget::class("ssh").expect("class"),
        ] {
            store
                .set_mode(
                    &target,
                    mode,
                    "fixture owner",
                    "fixture first setting",
                    "1",
                    &[],
                )
                .expect("fixture mode");
        }
    }

    /// # Panics
    /// Panics only if concurrent records lose a completed command or execute it twice.
    /// ´test:unit:door-completed-command-outlasts-sibling-record-wait´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_completed_command_outlasts_sibling_record_wait() {
        use crate::requests::store::{
            AFTER_WRITER_LOCK_TIMEOUT, BEFORE_LEAF_SYNC, WRITER_LOCK_WAIT_OVERRIDE,
        };
        struct ProbeOutput(std::sync::mpsc::Sender<Vec<u8>>);
        impl io::Write for ProbeOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.send(bytes.to_vec()).map_err(io::Error::other)?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, Mode::Allow);
        let sibling = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "S",
            3001,
            Scope::Work,
        )
        .expect("sibling registration");
        let sibling = super::request_record(
            &sibling,
            "ssh",
            Operation::ProbeEcho,
            &store.effective_mode("ssh").expect("settings"),
            &json!({"decision":"allow","reason":"fixture sibling"}),
            false,
            &[],
        )
        .expect("sibling reservation");
        let sibling_id = sibling.id().to_owned();
        let mut effect = sibling.value()["effect"].clone();
        effect["state"] = json!("completed");
        effect["reason"] = json!("door-complete");
        effect["exit_status"] = json!(0);
        effect["ref_check"] = json!("not-applicable");
        store.file(sibling).expect("sibling admitted");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        super::REQUEST_READY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_| {
                super::WAIT_CREDIT_OBSERVED.with(|slot| *slot.borrow_mut() = Some(progress_tx));
                WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(Some(Duration::from_millis(20))));
                AFTER_WRITER_LOCK_TIMEOUT.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        release_tx.send(()).expect("record wait expired once");
                    }));
                });
                Ok(Instant::now() + Duration::from_secs(5))
            }));
        });
        let (runner, calls, _) = counting_runner(&fixture);
        let (socket, server) =
            fixture_stub_service(&fixture, runner, rubric(Some("allow")), 5000, None);
        let (mut input, stub_input) = UnixStream::pair().expect("controlled input");
        let (output_tx, output_rx) = std::sync::mpsc::channel();
        let client = thread::spawn(move || {
            super::transport::STUB_TEST_BUDGET.with(|slot| slot.set(Some(5000)));
            super::transport::stub_call_stream(
                &socket,
                &[std::ffi::OsString::from("door-attribution-probe")],
                stub_input,
                ProbeOutput(output_tx),
                Vec::new(),
            )
            .expect("stub retains the completed effect after progress")
        });
        let deadline = Instant::now() + Duration::from_secs(4);
        while calls.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline, "second command never started");
            thread::sleep(Duration::from_millis(5));
        }
        // Seeing stdout proves spawn's custody read has finished; the child
        // stays live on stdin while the sibling takes the record lock.
        input.write_all(b"x").expect("running command input");
        assert_eq!(
            output_rx
                .recv_timeout(Duration::from_secs(4))
                .expect("running command output"),
            b"x"
        );
        let sibling_store = store
            .for_request(deadline)
            .expect("sibling view")
            .with_request_id(&sibling_id);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            let sibling_id = &sibling_id;
            let writer = scope.spawn(move || {
                BEFORE_LEAF_SYNC.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        held_tx.send(()).expect("sibling syncing");
                        release_rx
                            .recv_timeout(Duration::from_secs(4))
                            .expect("second record retried");
                        progress_rx
                            .recv_timeout(Duration::from_secs(4))
                            .expect("progress frame emitted before release");
                    }));
                });
                sibling_store
                    .record_effect(sibling_id, effect)
                    .expect("sibling complete")
            });
            held_rx
                .recv_timeout(Duration::from_secs(4))
                .expect("sibling holds lock");
            input
                .shutdown(Shutdown::Write)
                .expect("second command finishes");
            let reply = client.join().expect("stub client");
            assert!(
                reply["request_lock_wait_credit_ms"]
                    .as_u64()
                    .expect("measured credit")
                    >= 50
            );
            assert_eq!(reply["reason"], "door-complete");
            assert_eq!(reply["status"], 0);
            writer.join().expect("sibling writer");
        });
        server
            .join()
            .expect("service thread")
            .expect("second complete");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let records = store.list().expect("both records").0;
        assert_eq!(records.len(), 2);
        for record in records {
            assert_eq!(record.value()["effect"]["state"], "completed");
            assert_eq!(record.value()["effect"]["exit_status"], 0);
        }
    }

    /// # Panics
    /// Panics only if a connection refusal discloses a non-lock cause to the worker.
    /// ´test:unit:door-connection-refusal-withholds-non-lock-cause´
    #[test]
    fn door_connection_refusal_withholds_non_lock_cause() {
        for error in [
            std::io::Error::other("unmapped peer with private host context"),
            std::io::Error::other(crate::error::LaneError::input(
                "requests-record-refusal",
                "request lock owner or mode differs at private host path",
            )),
            std::io::Error::other("request lock: Resource temporarily unavailable (os error 11)"),
        ] {
            let reply = super::connection_refusal(&error, Instant::now());
            assert_eq!(reply["reason"], "door-request-refusal");
            assert!(reply.get("request_record_error").is_none());
            let line = super::final_line(&["fixture".into(), "git status --short".into()], &reply)
                .expect("worker diagnostic");
            assert!(!line.contains("private"));
            assert!(!line.contains("request lock:"));
        }
    }

    /// ´test:unit:door-initial-store-refusal-withholds-non-lock-cause´
    #[test]
    fn door_initial_store_refusal_withholds_non_lock_cause() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new();
        let store = fixture.store();
        store.ensure_first_mode("ssh").expect("initial custody");
        std::fs::set_permissions(
            fixture.home.join(".config/loops/alpha/door-requests.lock"),
            std::fs::Permissions::from_mode(0o777),
        )
        .expect("invalid fixture custody");
        let route = route_for(&fixture.home);
        let (runner, calls, _) = counting_runner(&fixture);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let (mut server, _worker) = UnixStream::pair().expect("worker connection");
        let started = Instant::now();
        let error = serve_request(
            &mut server,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":3000}),
            Some(&route),
            Some(&runner),
            Some(&fixture.home),
            Some(&rubric(Some("allow"))),
            Some(&store),
            started,
        )
        .expect_err("non-contention failure stays at the connection boundary");
        let reply = super::connection_refusal(&error, started);
        assert_eq!(reply["reason"], "door-request-refusal");
        assert!(reply.get("request_record_error").is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    /// # Panics
    /// Panics only if a store contention refusal loses its cause at the worker boundary.
    /// ´test:unit:door-admission-lock-refusal-retains-worker-cause´
    #[test]
    fn door_admission_lock_refusal_retains_worker_cause() {
        let fixture = Fixture::new();
        let store = fixture.store().with_request_id("S:holder");
        let route = route_for(&fixture.home);
        let (runner, calls, _) = counting_runner(&fixture);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let held = store.fixture_exclusive_lock().expect("sibling holder");
        let (mut worker, mut server) = FixtureClient::pair().expect("worker connection");
        let started = Instant::now();
        let (acceptance, clock) = super::lifetime::Start::controlled(started);
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE
            .with(|bound| bound.set(Some(FIXTURE_HANG)));
        super::WAIT_CREDIT_CAP.with(|cap| cap.set(Some(50)));
        super::BEFORE_CREDIT_WRITE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || clock.advance(120_051)));
        });
        let (reply, _) = super::serve_request_with_agent_at(
            &mut server,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
            Some(&route),
            Some(&runner),
            Some(&fixture.home),
            Some(&rubric(Some("allow"))),
            Some(&store),
            None,
            None,
            started,
            acceptance,
        )
        .expect("named admission lock deadline reply");
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(None));
        let mut observed_credit = 0;
        // Wire reads are intentional: every credited amount is part of this assertion.
        let delivered = loop {
            let frame = super::frame_read(worker.wire()).expect("worker frame");
            if frame["type"] != "request-lock-wait" {
                break frame;
            }
            let credit = frame["wait_ms"].as_u64().expect("credit milliseconds");
            assert!(credit >= observed_credit && credit <= 50);
            observed_credit = credit;
        };
        assert_eq!(observed_credit, 50);
        assert_eq!(delivered, reply);
        assert_eq!(reply["reason"], "door-request-deadline");
        assert_eq!(reply["stop_cause"], "deadline");
        assert_eq!(reply["request_lock_wait_credit_ms"], 50);
        assert_eq!(reply["request_lock_wait_credit_cap_ms"], 50);
        assert!(
            reply["request_lock_wait_ms"]
                .as_u64()
                .expect("measured contention")
                >= 50
        );
        let line = super::final_line(&["fixture".into(), "git status --short".into()], &reply)
            .expect("worker diagnostic");
        assert!(line.contains("request lock stopped:"), "{line}");
        assert!(line.contains("wait_seconds="), "{line}");
        assert!(line.contains("holder_request_id=S:holder"), "{line}");
        let mut preflight = reply;
        preflight["reason"] = json!("door-compute-words-refusal");
        let line = super::final_line(&["fixture".into(), "cargo check".into()], &preflight)
            .expect("preflight diagnostic");
        assert!(line.contains("holder_request_id=S:holder"), "{line}");
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        drop(held);
        assert!(
            store
                .list_run("R")
                .expect("no execution or reservation")
                .is_empty()
        );
    }

    /// # Panics
    /// Panics only if the concurrent refusal loses its worker-facing retry figures.
    /// ´test:unit:door-concurrent-final-line-shows-wait-and-retry´
    #[test]
    fn door_concurrent_final_line_shows_wait_and_retry() {
        let reply = json!({"reason":"door-request-concurrent","status":125,
            "waited_seconds":1.001,"retry_after_seconds":30});
        assert_eq!(
            super::final_line(&["fixture".into(), "git status --short".into()], &reply),
            Some("door-request-concurrent: waited=1.001s retry_after=30s; the door waited for admission held through the durable effect and final reply; allow-mode agent publication may finish after admission is released; retry after 30 seconds".to_owned())
        );
    }

    /// ´test:unit:door-stop-guidance-distinguishes-unstarted-and-unconfirmed´
    #[test]
    fn door_stop_guidance_distinguishes_unstarted_and_unconfirmed() {
        for cause in [
            super::lifetime::Cause::Deadline,
            super::lifetime::Cause::Disconnect,
            super::lifetime::Cause::ObservationFailure,
            super::lifetime::Cause::Transport,
        ] {
            let (server, _client) = UnixStream::pair().expect("pair");
            let wait = super::RequestWait::new(&server).expect("wait");
            wait.cause.select(cause);
            let mut reply = json!({"reason":cause.reason()});
            wait.report(&mut reply);
            assert_eq!(reply["remote"]["state"], "not-started");
            assert_eq!(reply["wall_clock"], "monotonic-awake");
            let line = super::final_line(&["fixture".into(), "git status".into()], &reply)
                .expect("notice");
            assert!(
                line.contains(
                    if matches!(
                        cause,
                        super::lifetime::Cause::Deadline | super::lifetime::Cause::Disconnect
                    ) {
                        "ask again through the ordinary door route"
                    } else {
                        "report this stop to your loop"
                    }
                ),
                "{line}"
            );
            {
                let mut ending = wait.ending.lock().expect("ending");
                ending["local_child"] = json!("reaped");
                ending["remote"]["bound_seconds"] = json!(42);
            }
            wait.report(&mut reply);
            let line = super::final_line(&["fixture".into(), "git status".into()], &reply)
                .expect("notice");
            assert!(
                line.contains("up to 42 s after it started (start not observed)"),
                "{line}"
            );
            assert!(line.contains("report this stop to your loop"), "{line}");
            assert!(line.contains("node run lock"), "{line}");
            assert!(
                line.contains("a repeat is admitted but may wait for that lock"),
                "{line}"
            );
            wait.ending.lock().expect("ending")["remote"]["bound_seconds"] = Value::Null;
            wait.report(&mut reply);
            let line = super::final_line(&["fixture".into(), "git-upload-pack".into()], &reply)
                .expect("Git notice");
            assert!(!line.contains("run lock"), "{line}");
            assert!(
                line.contains("a repeat is admitted but may duplicate remote work"),
                "{line}"
            );
        }
    }

    /// ´test:unit:door-final-credit-cannot-revive-an-observed-stop´
    #[test]
    fn door_final_credit_cannot_revive_an_observed_stop() {
        let (peer, server) = UnixStream::pair().expect("pair");
        let awake = Instant::now();
        let (start, clock) = super::lifetime::Start::controlled(awake);
        let wait = super::RequestWait::new(&server)
            .expect("wait")
            .with_lifetime(start, true, &server)
            .expect("life");
        let base = awake + Duration::from_secs(30);
        clock.advance(30_000);
        assert_eq!(wait.stop(base), Some(super::lifetime::Cause::Deadline));
        wait.credit(Duration::from_secs(120));
        assert_eq!(
            wait.final_remaining(base).expect("remaining"),
            Duration::ZERO
        );
        let held = wait.writer.lock().expect("prior writer");
        let reply =
            json!({"type":"final","schema":2,"status":125,"reason":"door-request-deadline"});
        assert!(
            wait.write_final(&reply, base).is_err(),
            "spent admission cannot wait for writer"
        );
        drop(held);
        assert!(
            super::frame_write_until(
                &mut server.try_clone().expect("fallback"),
                &reply,
                Instant::now() + FIXTURE_HANG
            )
            .is_err(),
            "a failed final closes the connection fallback too"
        );
        drop(peer);
    }

    fn final_write_record(fixture: &Fixture) -> (Store, String, Registration) {
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, crate::requests::Mode::Allow);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let record = super::request_record(
            &registration,
            "ssh",
            Operation::ProbeEcho,
            &store.effective_mode("ssh").expect("mode"),
            &json!({"decision":"undecided","reason":"fixture"}),
            false,
            &[],
        )
        .expect("record");
        let id = record.id().to_owned();
        store.file(record).expect("file");
        (store, id, registration)
    }

    #[allow(unsafe_code)]
    fn small_final_buffer(server: &UnixStream) {
        let size: libc::c_int = 1024;
        assert_eq!(
            // SAFETY: size is a live c_int and its supplied length matches its type.
            unsafe {
                libc::setsockopt(
                    server.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    std::ptr::from_ref(&size).cast(),
                    std::mem::size_of_val(&size)
                        .try_into()
                        .expect("option size"),
                )
            },
            0,
            "small output buffer"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn final_write_service(
        server: &UnixStream,
        store: &Store,
        id: &str,
        registration: &Registration,
        start: super::lifetime::Start,
        events: &std::sync::mpsc::Sender<Duration>,
        resume: std::sync::mpsc::Receiver<()>,
        expire: bool,
    ) -> Value {
        let base = start.awake + FIXTURE_HANG;
        let wait = super::RequestWait::new(server)
            .expect("wait")
            .with_lifetime(start, true, server)
            .expect("lifetime");
        let ending = super::RequestEnding {
            store,
            wait: &wait,
            id,
        };
        let mut reply =
            super::transport::refusal(registration, 3000, "door-complete", Instant::now());
        reply["status"] = json!(0);
        reply["compute_exit_status"] = json!(0);
        reply["padding"] = json!("x".repeat(50_000));
        // A complete output frame is queued before the terminal frame.
        super::frame_write_until(
            &mut server.try_clone().expect("output writer"),
            &final_fixture_output(),
            base,
        )
        .expect("queued output");
        reply["stdout_bytes"] = json!(13);
        store
            .record_effect(id, super::observed_effect(&reply, &wait))
            .expect("effect");
        let resume = Arc::new(std::sync::Mutex::new(resume));
        let continuation = Arc::clone(&resume);
        let blocked = events.clone();
        super::FINAL_BLOCKED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |left| {
                blocked.send(left).expect("blocked final event");
                continuation
                    .lock()
                    .expect("continuation")
                    .recv_timeout(FIXTURE_HANG)
                    .expect("peer resumes");
            }));
        });
        let result = wait.write_final(&reply, base);
        assert_eq!(result.is_err(), expire, "final outcome: {result:?}");
        wait.credit(Duration::from_millis(100));
        drop(ending);
        events.send(Duration::ZERO).expect("final completed");
        resume
            .lock()
            .expect("continuation")
            .recv_timeout(FIXTURE_HANG)
            .expect("peer checked while writer lives");
        reply
    }

    fn ordered_final_write(expire: bool) {
        use std::io::Read as _;
        let fixture = Fixture::new();
        let (store, id, registration) = final_write_record(&fixture);
        let (mut client, server) = FixtureClient::pair().expect("pair");
        small_final_buffer(&server);
        let (start, clock) = super::lifetime::Start::controlled(Instant::now());
        let (events, blocked) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let service = thread::spawn(move || {
            final_write_service(
                &server,
                &store,
                &id,
                &registration,
                start,
                &events,
                resume,
                expire,
            )
        });
        let left = blocked
            .recv_timeout(FIXTURE_HANG)
            .expect("final blocked on live peer");
        // This is injected-clock budget, not a wall measurement of the node.
        assert_eq!(left, FIXTURE_HANG, "final owns the request lifetime");
        clock.advance(if expire { 240_000 } else { 3_000 });
        release.send(()).expect("resume final");
        if expire {
            // This wire test deliberately receives an incomplete frame.
            assert_eq!(
                blocked
                    .recv_timeout(FIXTURE_HANG)
                    .expect("failed final completed"),
                Duration::ZERO
            );
            client
                .wire()
                .set_nonblocking(true)
                .expect("observe closed half without a wall");
            let mut partial = Vec::new();
            let read = client.wire().read_to_end(&mut partial);
            release.send(()).expect("release live writer");
            let reply = service.join().expect("service");
            read.expect("partial final closes write half while writer remains alive");
            let expected = final_fixture_bytes(&reply);
            assert!(!partial.is_empty() && partial.len() < expected.len());
            assert!(
                expected.starts_with(&partial),
                "no credit follows partial final"
            );
        } else {
            let reply = client.answer();
            assert_eq!(
                blocked.recv_timeout(FIXTURE_HANG).expect("final completed"),
                Duration::ZERO
            );
            release.send(()).expect("release live writer");
            let returned = service.join().expect("service");
            assert_eq!(reply, as_sent(&returned));
            assert_eq!(reply["stdout_bytes"], 13);
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "SLOW-FINAL status={} reason={} stdout_bytes={} stderr_bytes={} padding_bytes={}",
                    reply["status"],
                    reply["reason"],
                    reply["stdout_bytes"],
                    reply["stderr_bytes"],
                    reply["padding"].as_str().expect("padding").len()
                );
            }
        }
        let rows = fixture.store().list_run("R").expect("record");
        assert_eq!(
            rows[0].value()["effect"]["ending"]["final_write"],
            if expire {
                "failed"
            } else {
                "succeeded-locally"
            }
        );
        #[allow(clippy::print_stderr)]
        {
            eprintln!("SLOW-FINAL-RECORD {}", rows[0].value());
        }
    }

    fn final_fixture_output() -> Value {
        json!({"schema":2,"type":"stdout","bytes":b"queued output".to_vec()})
    }

    fn final_fixture_bytes(reply: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        for frame in [final_fixture_output(), reply.clone()] {
            let body = serde_json::to_vec(&frame).expect("encode");
            bytes.extend(u32::try_from(body.len()).expect("length").to_be_bytes());
            bytes.extend(body);
        }
        bytes
    }

    /// ´test:unit:door-slow-final-uses-request-lifetime´
    #[test]
    fn door_slow_final_uses_request_lifetime() {
        ordered_final_write(false);
    }

    /// ´test:unit:door-partial-final-closes-before-credit´
    #[test]
    fn door_partial_final_closes_before_credit() {
        ordered_final_write(true);
    }

    fn fixture_class_call(
        fixture: &Fixture,
        decision: Option<&str>,
        answer: Option<&str>,
    ) -> String {
        let store = fixture.store();
        let (filed, request) = std::sync::mpsc::channel();
        super::REQUEST_FILED.with(|slot| *slot.borrow_mut() = Some(filed));
        let (runner, _, _) = counting_runner(fixture);
        let (socket, server) = fixture_service(
            fixture,
            runner,
            fixture_class_rubric(decision),
            120_000,
            None,
        );
        let mut client = send_probe(socket, 120_000);
        // Rendezvous after the production store write releases its lock.
        // The common bound guards a hung fixture, not setup performance.
        let id = request
            .recv_timeout(FIXTURE_HANG)
            .expect("fixture request filed");
        if let Some(treatment) = answer {
            label(&store, &id, treatment);
        }
        let _reply = client.answer();
        server.join().expect("fixture service").expect("reply");
        id
    }

    /// ´test:unit:door-lookup-failure-files-named-miss´
    #[test]
    fn door_lookup_failure_files_named_miss() {
        let fixture = Fixture::new();
        let index = fixture.home.join(".config/loops/alpha/door-learned.json");
        fs::write(&index, b"invalid index").expect("damaged index");
        fs::set_permissions(&index, fs::Permissions::from_mode(0o600)).expect("private index");
        let store = fixture.store();
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let (mut stream, _peer) = UnixStream::pair().expect("socket pair");
        let (runner, calls, _) = counting_runner(&fixture);
        let route = route_for(&fixture.home);
        let (filed, observed) = std::sync::mpsc::channel();
        super::REQUEST_READY.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |id| {
                filed.send(id.to_owned()).expect("filed lookup miss");
                Ok(Instant::now())
            }));
        });
        // Model delayed setup without sleeping: the event, not this elapsed
        // second, selects expiry after the named miss has been filed.
        let started = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("fixture past acceptance");
        serve_request(
            &mut stream,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
            Some(&route),
            Some(&runner),
            Some(&fixture.home),
            None,
            Some(&store),
            started,
        )
        .expect("recorded deadline");
        let id = observed
            .try_recv()
            .expect("readiness followed durable filing");
        let rows = store.list_run("R").expect("record");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id(), id);
        assert_eq!(rows[0].value()["would_do"]["decision"], "undecided");
        assert!(
            rows[0].value()["would_do"]["reason"]
                .as_str()
                .expect("reason")
                .contains("requests-learned-index")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct EstateReferral(&'static str, &'static str);
    impl super::agent::AgentRunner for EstateReferral {
        fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
            super::agent::RunnerOutcome::referral(self.0, self.1, Instant::now())
        }
    }
    fn referral_client(
        fixture: &Fixture,
    ) -> (
        FixtureServer,
        serde_json::Value,
        thread::JoinHandle<serde_json::Value>,
    ) {
        let socket = crate::fixture_exec::fixture_socket_path(fixture.home.join("referral.sock"));
        let listener = UnixListener::bind(&socket).expect("listener");
        let client = thread::spawn(move || {
            super::transport::STUB_TEST_BUDGET.with(|slot| slot.set(Some(30_000)));
            super::transport::stub_call_stream(
                &socket,
                &[std::ffi::OsString::from("door-attribution-probe")],
                io::empty(),
                Vec::new(),
                Vec::new(),
            )
            .expect("stub retains the final referral refusal")
        });
        let mut stream = FixtureServer::accept(&listener).expect("client connection");
        let request = fixture_request(&mut stream).expect("stub request");
        (stream, request, client)
    }

    fn referral_contender(
        store: &crate::requests::store::Store,
        induce_wait: bool,
    ) -> Option<thread::JoinHandle<()>> {
        if induce_wait {
            let held = store.fixture_exclusive_lock().expect("competing writer");
            let (contended, observed) = std::sync::mpsc::channel();
            super::WAIT_CREDIT_OBSERVED.with(|slot| *slot.borrow_mut() = Some(contended));
            Some(thread::spawn(move || {
                observed
                    .recv_timeout(Duration::from_secs(10))
                    .expect("measured store contention");
                drop(held);
            }))
        } else {
            None
        }
    }

    /// ´test:unit:door-unprovisioned-estate-referral-has-no-effect´
    #[test]
    fn door_unprovisioned_estate_referral_has_no_effect() {
        let cases = [
            ("verdict", "estate judgement needed"),
            ("timeout", "door-agent-timeout"),
            ("failure", "door-agent-call-failed"),
            ("invalid-output", "door-agent-invalid-output"),
            ("timeout", "door-agent-no-budget"),
            ("failure", "door-rubric-unavailable"),
            ("failure", "door-agent-projection-unavailable"),
        ];
        for induce_wait in [false, true] {
            for (mode, (status, reason)) in
                [crate::requests::Mode::Audit, crate::requests::Mode::Enforce]
                    .into_iter()
                    .flat_map(|mode| cases.into_iter().map(move |case| (mode, case)))
            {
                let fixture = Fixture::new();
                fixture.set_floor("allow");
                let store = fixture.store();
                set_fixture_mode(&store, mode);
                let registration = Registration::from_row(
                    &json!({"name":"alpha","uid":41001}),
                    "alpha",
                    "R",
                    3000,
                    Scope::Work,
                )
                .expect("registration");
                let (mut stream, request, client) = referral_client(&fixture);
                let (runner, calls, _) = counting_runner(&fixture);
                let route = route_for(&fixture.home);
                let review_store = fixture.store();
                super::AFTER_WAIT_READ.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        let rows = review_store.list_run("R").expect("waiting review");
                        let row = &rows[0];
                        assert_eq!(row.value()["state"], "waiting");
                        assert_eq!(row.value()["would_do"]["decision"], "refer");
                        assert_eq!(row.value()["agent_reason"], reason);
                        assert_eq!(row.value()["effect"]["state"], "pending");
                        assert!(row.value()["label"].is_null());
                        review_store
                            .triage(
                                "R",
                                &[json!({"id":row.id(),"action":"adjudicate",
                                "treatment":"refuse","reason":"loop review answer"})],
                                "fixture-reviewer",
                                "2",
                            )
                            .expect("loop answer");
                    }));
                });
                let release = referral_contender(&store, induce_wait);
                let (reply, _) = super::serve_request_with_agent(
                    &mut stream,
                    &registration,
                    3000,
                    &request,
                    Some(&route),
                    Some(&runner),
                    Some(&fixture.home),
                    None,
                    Some(&store),
                    Some(&EstateReferral(status, reason)),
                    None,
                    Instant::now(),
                )
                .expect("loop review refusal");
                assert_eq!(reply["reason"], "door-adjudicated-refusal");
                let wire = client.join().expect("stub client");
                if let Some(release) = release {
                    release.join().expect("holder released");
                    assert!(
                        wire["request_lock_wait_credit_ms"]
                            .as_u64()
                            .expect("credit")
                            >= 50
                    );
                }
                for field in [
                    "reason",
                    "request_id",
                    "queue_state",
                    "status",
                    "request_lock_wait_ms",
                    "request_lock_wait_credit_ms",
                ] {
                    assert_eq!(wire[field], reply[field], "{field}");
                }
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                let rows = store.list_run("R").expect("retained review evidence");
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].value()["agent_scope"], "estate");
                assert_eq!(
                    rows[0].value()["effect"]["reason"],
                    "door-adjudicated-refusal"
                );
            }
        }
    }

    /// ´test:unit:door-terminal-record-retains-outcome-and-local-final-write´
    #[test]
    fn door_terminal_record_retains_outcome_and_local_final_write() {
        for (deadline, broken, cause, written) in [
            (false, false, "child-exit", "succeeded-locally"),
            (true, false, "deadline", "succeeded-locally"),
            (true, true, "deadline", "failed"),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Allow);
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                3000,
                Scope::Work,
            )
            .expect("registration");
            let (mut peer, mut stream) = FixtureClient::pair().expect("pair");
            peer.shutdown(std::net::Shutdown::Write)
                .expect("empty input");
            if deadline {
                super::transport::fixture_expire_after_spawn();
            }
            if broken {
                let peer = peer.wire().try_clone().expect("closing peer");
                super::BEFORE_TERMINAL_WRITE.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        peer.shutdown(std::net::Shutdown::Both)
                            .expect("failed final event");
                    }));
                });
            }
            let (runner, _, _) = counting_runner(&fixture);
            let route = route_for(&fixture.home);
            crate::requests::store::CHECK_ACTIVE_FILING.with(|check| check.set(true));
            let result = super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                None,
                None,
                Instant::now(),
            );
            assert!(
                !crate::requests::store::CHECK_ACTIVE_FILING.with(std::cell::Cell::get),
                "door used the lease-first filing boundary"
            );
            assert_eq!(result.is_err(), broken, "transport result {result:?}");
            if !broken {
                assert!(peer.answer()["status"].is_i64());
            }
            let rows = store.list_run("R").expect("ending");
            assert_eq!(rows.len(), 1);
            let ending = &rows[0].value()["effect"]["ending"];
            assert_eq!(ending["cause"], cause);
            assert_eq!(ending["local_child"], "reaped");
            assert_eq!(ending["final_write"], written);
            #[allow(clippy::print_stderr)] // Captured fixture evidence for the terminal record.
            {
                eprintln!("ENDING-TRANSPORT {}", rows[0].value());
            }
        }
    }

    /// ´test:unit:door-acceptance-clock-and-close-stop-admission-and-compute´
    #[test]
    fn door_acceptance_clock_and_close_stop_admission_and_compute() {
        for admission in [true, false] {
            for disconnected in [false, true] {
                let fixture = Fixture::new();
                fixture.set_floor("allow");
                let store = fixture.store();
                set_fixture_mode(&store, crate::requests::Mode::Allow);
                let registration = concurrent_registration(3000);
                let (mut peer, mut stream) = FixtureClient::pair().expect("pair");
                // EOF alone must leave the response side and the request alive.
                peer.shutdown(Shutdown::Write).expect("input EOF");
                let closed = peer.wire().try_clone().expect("close event");
                let began = Instant::now();
                let (start, clock) = super::lifetime::Start::controlled(began);
                let action = move || {
                    if disconnected {
                        closed.shutdown(Shutdown::Both).expect("full close event");
                    } else {
                        clock.advance(240_000);
                    }
                };
                let guard = admission.then(|| {
                    super::RequestGuard::acquire(&fixture.home, &registration)
                        .expect("guard")
                        .expect("uncontended")
                });
                if admission {
                    super::ADMISSION_CONTENDED
                        .with(|slot| *slot.borrow_mut() = Some(Box::new(action)));
                    super::ADMISSION_CLOCK.with(|slot| {
                        *slot.borrow_mut() =
                            Some(std::rc::Rc::new(ControlledAdmissionClock::default()));
                    });
                } else {
                    super::transport::fixture_after_spawn(move || {
                        action();
                        Instant::now() + Duration::from_secs(120)
                    });
                }
                let (runner, _, _) = counting_runner(&fixture);
                let route = route_for(&fixture.home);
                let result = super::serve_request_with_agent_at(
                    &mut stream,
                    &registration,
                    3000,
                    &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                    Some(&route),
                    Some(&runner),
                    Some(&fixture.home),
                    None,
                    Some(&store),
                    None,
                    None,
                    began,
                    start,
                );
                super::ADMISSION_CLOCK.with(|slot| *slot.borrow_mut() = None);
                drop(guard);
                let cause = if disconnected {
                    "disconnect"
                } else {
                    "deadline"
                };
                if disconnected {
                    assert!(
                        result.is_ok(),
                        "observed close is a successful stop: {result:?}"
                    );
                } else {
                    let reply = peer.answer();
                    assert_eq!(reply["stop_cause"], cause, "{reply}");
                    assert_eq!(reply["deadline_clock"], "boottime");
                    assert_eq!(reply["status"], 125);
                    assert!(result.is_ok(), "{result:?}");
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("STOP-REPLY {reply}");
                    }
                }
                let rows = store.list_run("R").expect("records");
                if admission {
                    assert!(rows.is_empty(), "admission stops before filing");
                } else {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].value()["effect"]["ending"]["cause"], cause);
                    assert_eq!(rows[0].value()["effect"]["ending"]["local_child"], "reaped");
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("STOP-RECORD {}", rows[0].value());
                    }
                }
            }
        }
    }

    /// ´test:unit:door-judgement-stop-prevents-effect-and-retains-first-cause´
    #[test]
    fn door_judgement_stop_prevents_effect_and_retains_first_cause() {
        struct Stops(std::sync::Arc<super::lifetime::TestClock>, UnixStream, bool);
        impl super::agent::AgentRunner for Stops {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                if self.2 {
                    self.1
                        .shutdown(Shutdown::Both)
                        .expect("full close during judgement");
                } else {
                    self.0.advance(240_000);
                }
                super::agent::RunnerOutcome::referral(
                    "failure",
                    "fixture stopped judgement",
                    Instant::now(),
                )
            }
        }
        for disconnected in [false, true] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Audit);
            let registration = concurrent_registration(3000);
            let (mut peer, mut stream) = FixtureClient::pair().expect("pair");
            let began = Instant::now();
            let (start, clock) = super::lifetime::Start::controlled(began);
            let agent = Stops(
                clock,
                peer.wire().try_clone().expect("close control"),
                disconnected,
            );
            let (runner, calls, _) = counting_runner(&fixture);
            let route = route_for(&fixture.home);
            let result = super::serve_request_with_agent_at(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                Some(&agent),
                None,
                began,
                start,
            );
            assert_eq!(
                calls.load(Ordering::Relaxed),
                0,
                "stopped judgement must not run an effect"
            );
            assert!(result.is_ok(), "stopped judgement: {result:?}");
            let cause = if disconnected {
                "disconnect"
            } else {
                "deadline"
            };
            if !disconnected {
                let reply = peer.answer();
                assert_eq!(reply["stop_cause"], cause);
                assert_eq!(reply["reason"], "door-request-deadline");
                assert_eq!(reply["status"], 125);
            }
            let rows = store.list_run("R").expect("terminal record");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].value()["effect"]["ending"]["cause"], cause);
            assert_eq!(
                rows[0].value()["effect"]["ending"]["local_child"],
                "not-started"
            );
            if disconnected {
                assert_eq!(
                    rows[0].value()["effect"]["ending"]["final_write"],
                    "not-attempted"
                );
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("DISCONNECT-STOPPED {}", rows[0].value());
                }
            }
        }
    }

    /// ´test:unit:door-git-routes-do-not-treat-full-close-as-cancellation´
    #[test]
    fn door_git_routes_do_not_treat_full_close_as_cancellation() {
        for operation in ["git-upload-pack", "git-receive-pack"] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Allow);
            store
                .set_mode(
                    &crate::requests::modes::ModeTarget::class("git").expect("class"),
                    crate::requests::Mode::Allow,
                    "fixture owner",
                    "fixture first setting",
                    "1",
                    &[],
                )
                .expect("git mode");
            let registration = concurrent_registration(3000);
            let (mut peer, mut stream) = FixtureClient::pair().expect("pair");
            let closed = peer.wire().try_clone().expect("close event");
            super::REQUEST_READY.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |_| {
                    closed.shutdown(Shutdown::Both).expect("full close");
                    Ok(Instant::now() + Duration::from_secs(120))
                }));
            });
            let (runner, _, _) = counting_runner(&fixture);
            let route = route_for(&fixture.home);
            let result = super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"fixture".to_vec(), format!("{operation} '~/mirrors/R.git'").into_bytes()],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                None,
                None,
                Instant::now(),
            );
            assert!(result.is_err(), "closed reply transport: {result:?}");
            let rows = store.list_run("R").expect("record");
            assert_eq!(rows.len(), 1);
            assert_ne!(
                rows[0].value()["effect"]["ending"]["cause"],
                "disconnect",
                "{operation}: close retains Git EOF/transport semantics"
            );
        }
    }

    /// ´test:unit:door-stopped-decided-enforce-outcome-remains-observed´
    #[test]
    fn door_stopped_decided_enforce_outcome_remains_observed() {
        for decision in ["allow", "refuse"] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Enforce);
            let registration = concurrent_registration(3000);
            let (mut peer, mut stream) = FixtureClient::pair().expect("pair");
            let began = Instant::now();
            let (start, clock) = super::lifetime::Start::controlled(began);
            super::REQUEST_READY.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |_| {
                    clock.advance(240_000);
                    Ok(began + Duration::from_secs(120))
                }));
            });
            let (runner, calls, _) = counting_runner(&fixture);
            let route = route_for(&fixture.home);
            super::serve_request_with_agent_at(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                Some(&rubric(Some(decision))),
                Some(&store),
                None,
                None,
                began,
                start,
            )
            .expect("stopped before effect");
            assert_eq!(peer.answer()["stop_cause"], "deadline");
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            let rows = store.list_run("R").expect("records");
            assert_eq!(
                rows[0].value()["state"],
                "observed",
                "decided {decision} is not new triage"
            );
        }
    }

    /// ´test:unit:door-restart-probe-observes-shared-and-exclusive-admission´
    #[test]
    fn door_restart_probe_observes_shared_and_exclusive_admission() {
        let fixture = Fixture::new();
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        for operation in [
            None,
            Some(super::transport::Operation::Compute),
            Some(super::transport::Operation::GitReceive),
        ] {
            let guard =
                super::RequestGuard::acquire_operation(&fixture.home, &registration, operation)
                    .expect("admission")
                    .expect("free slot");
            assert_eq!(
                super::restart_probe(&fixture.home, "alpha").expect("busy probe")["status"],
                "request-in-flight"
            );
            drop(guard);
            assert_eq!(
                super::restart_probe(&fixture.home, "alpha").expect("idle probe")["status"],
                "admission-idle"
            );
        }
    }

    /// ´test:unit:door-workspace-wait-slots-do-not-hold-admission´
    #[test]
    fn door_workspace_wait_slots_do_not_hold_admission() {
        let fixture = Fixture::new();
        let registration = concurrent_registration(3000);
        let first = super::WorkspaceWaitSlot::acquire(&fixture.home, &registration)
            .expect("first slot")
            .expect("available");
        let second = super::WorkspaceWaitSlot::acquire(&fixture.home, &registration)
            .expect("second slot")
            .expect("available");
        assert!(
            super::WorkspaceWaitSlot::acquire(&fixture.home, &registration)
                .expect("third slot")
                .is_none()
        );
        assert_eq!(
            super::restart_probe(&fixture.home, "alpha").expect("admission probe")["status"],
            "admission-idle"
        );
        let admission = super::RequestGuard::acquire_operation(
            &fixture.home,
            &registration,
            Some(super::transport::Operation::Compute),
        )
        .expect("admission")
        .expect("waiters released admission");
        drop(admission);
        drop(first);
        assert!(
            super::WorkspaceWaitSlot::acquire(&fixture.home, &registration)
                .expect("released slot")
                .is_some()
        );
        drop(second);
    }

    /// ´test:unit:door-terminal-record-survives-advisory-unwind´
    #[test]
    fn door_terminal_record_survives_advisory_unwind() {
        struct Panics;
        impl super::agent::AgentRunner for Panics {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                panic!("controlled advisory failure")
            }
        }
        let fixture = Fixture::new();
        let store = fixture.store();
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let (mut stream, _peer) = UnixStream::pair().expect("pair");
        let (runner, _, _) = counting_runner(&fixture);
        let route = route_for(&fixture.home);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                Some(&Panics),
                None,
                Instant::now(),
            )
        }));
        assert!(result.is_err(), "controlled panic reached");
        let rows = store.list_run("R").expect("terminal record");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value()["effect"]["reason"], "door-handler-panicked");
        assert_eq!(
            rows[0].value()["effect"]["ending"]["final_write"],
            "unknown"
        );
        assert_eq!(
            rows[0].value()["effect"]["ending"]["cause"],
            "handler-failure"
        );
    }

    /// ´test:unit:door-agent-merge-failure-records-incomplete´
    #[test]
    fn door_agent_merge_failure_records_incomplete() {
        struct InvalidMerge;
        impl super::agent::AgentRunner for InvalidMerge {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                let mut result = super::agent::RunnerOutcome::referral(
                    "failure",
                    "invalid merge fixture",
                    Instant::now(),
                );
                result.rubric_digest = Some("invalid digest".into());
                result
            }
        }
        for mode in [crate::requests::Mode::Audit, crate::requests::Mode::Enforce] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, mode);
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                3000,
                Scope::Work,
            )
            .expect("registration");
            let (mut peer, mut stream) = FixtureClient::pair().expect("socket pair");
            let (runner, calls, _) = counting_runner(&fixture);
            let route = route_for(&fixture.home);
            let (reply, _) = super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":30_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                Some(&InvalidMerge),
                None,
                Instant::now(),
            )
            .expect("named merge refusal");
            let rows = store.list_run("R").expect("durable intent");
            assert_eq!(rows.len(), 1);
            assert_eq!(reply["reason"], "door-request-record-refusal");
            assert_eq!(reply["request_id"], rows[0].id());
            assert_eq!(peer.answer(), as_sent(&reply));
            assert!(rows[0].value()["agent_status"].is_null());
            assert!(rows[0].value()["state"].is_null());
            assert_incomplete(&fixture, rows[0].id());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    /// # Panics
    /// Panics if a learned hit invokes the agent, changes its cited decision or repeats an effect.
    /// ´test:unit:door-repeated-learned-hits-skip-agent´
    #[test]
    fn door_repeated_learned_hits_skip_agent() {
        struct Agent(AtomicUsize);
        impl super::agent::AgentRunner for Agent {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                self.0.fetch_add(1, Ordering::SeqCst);
                panic!("learned hit invoked the agent")
            }
        }
        let fixture = Fixture::new();
        fixture.set_floor("enforce");
        let store = fixture.store();
        set_fixture_mode(&store, crate::requests::Mode::Enforce);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("registration");
        let setting = store.effective_mode("ssh").expect("setting");
        let seed = super::request_record(
            &registration,
            "ssh",
            Operation::ProbeEcho,
            &setting,
            &json!({"decision":"undecided","reason":"fixture seed"}),
            true,
            &[],
        )
        .expect("seed");
        let seed_id = seed.id().to_owned();
        store.file(seed).expect("seed filing");
        label(&store, &seed_id, "allow");
        let route = route_for(&fixture.home);
        let (runner, effects, _) = counting_runner(&fixture);
        let agent = Agent(AtomicUsize::new(0));
        let mut observed_ids = std::collections::HashSet::from([seed_id.clone()]);
        for iteration in 0..24 {
            let (mut peer, mut stream) = FixtureClient::pair().expect("socket pair");
            peer.shutdown(std::net::Shutdown::Write)
                .expect("empty input");
            let (reply, _) = super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                Some(&agent),
                None,
                Instant::now(),
            )
            .expect("learned request");
            let frame = peer.answer();
            assert_eq!(frame["would_do"], reply["would_do"]);
            assert_eq!(frame["reason"], "door-complete");
            assert_eq!(frame["status"], 0);
            let fresh: Vec<_> = store
                .list_run("R")
                .expect("durable decisions")
                .into_iter()
                .filter(|row| !observed_ids.contains(row.id()))
                .collect();
            assert_eq!(fresh.len(), 1);
            let record = &fresh[0];
            observed_ids.insert(record.id().to_owned());
            assert_eq!(record.value()["would_do"]["decision"], "allow");
            assert_eq!(
                record.value()["matched_rule"]["request_ids"],
                json!([seed_id])
            );
            assert!(record.value()["agent_status"].is_null());
            assert_eq!(record.value()["effect"]["state"], "completed");
            assert_eq!(agent.0.load(Ordering::SeqCst), 0);
            assert_eq!(effects.load(Ordering::SeqCst), iteration + 1);
        }
    }

    /// ´test:unit:door-registered-receive-rule-skips-agent-and-keeps-packet-refusal´
    #[test]
    fn door_registered_receive_rule_skips_agent_and_keeps_packet_refusal() {
        struct NoAgent;
        impl super::agent::AgentRunner for NoAgent {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                panic!("registered receive invoked agent")
            }
        }
        let old = "0".repeat(40);
        let new = "1".repeat(40);
        for (mode, reference, expected) in [
            (Mode::Allow, "refs/heads/lane/R", "door-complete"),
            (Mode::Enforce, "refs/heads/lane/R", "door-complete"),
            (Mode::Allow, "refs/heads/lane/S", "door-changed-ref-refusal"),
            (
                Mode::Enforce,
                "refs/heads/lane/S",
                "door-changed-ref-refusal",
            ),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, mode);
            let registration = concurrent_registration(3000);
            let route = route_for(&fixture.home);
            let (runner, calls, _) = counting_runner(&fixture);
            let (mut peer, mut stream) = FixtureClient::pair().expect("socket pair");
            let command = format!("{old} {new} {reference}\0 report-status\n");
            let mut packet = format!("{:04x}", command.len() + 4).into_bytes();
            packet.extend(command.as_bytes());
            packet.extend(b"0000");
            peer.wire().write_all(&packet).expect("Git command packet");
            peer.shutdown(Shutdown::Write).expect("end Git input");
            let (reply, _) = super::serve_request_with_agent(
                &mut stream,
                &registration,
                3000,
                &json!({"schema":2,"argv":[b"fixture".to_vec(),b"git-receive-pack '~/mirrors/R.git'".to_vec()],"deadline_ms":120_000}),
                Some(&route),
                Some(&runner),
                Some(&fixture.home),
                None,
                Some(&store),
                Some(&NoAgent),
                None,
                Instant::now(),
            )
            .expect("receive reply");
            assert_eq!(reply["reason"], expected, "{mode:?} {reference}");
            assert_eq!(peer.answer()["reason"], expected);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let rows = store.list_run("R").expect("receive record");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].value()["would_do_source"], "transport-rule");
            assert_eq!(
                rows[0].value()["matched_rule"]["rule"],
                "registered-receive-transport"
            );
            assert!(rows[0].value()["agent_status"].is_null());
            assert_eq!(rows[0].value()["effect"]["reason"], expected);
        }
    }

    /// ´test:unit:door-registered-receive-audit-waits-and-other-targets-refuse´
    #[test]
    fn door_registered_receive_audit_waits_and_other_targets_refuse() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, Mode::Audit);
        let registration = concurrent_registration(3000);
        let route = route_for(&fixture.home);
        let (runner, calls, _) = counting_runner(&fixture);
        let (mut peer, mut stream) = FixtureClient::pair().expect("socket pair");
        peer.shutdown(Shutdown::Write).expect("end input");
        super::REQUEST_READY.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|_| Ok(Instant::now())));
        });
        let (reply, _) = super::serve_request_with_agent(
            &mut stream,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"fixture".to_vec(),b"git-receive-pack '~/mirrors/R.git'".to_vec()],"deadline_ms":120_000}),
            Some(&route), Some(&runner), Some(&fixture.home), None, Some(&store), None, None,
            Instant::now(),
        ).expect("audit reply");
        assert_ne!(reply["reason"], "door-complete");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.list_run("R").expect("record")[0].value()["would_do_source"],
            "transport-rule"
        );
        let _answer = peer.answer();
        for scope in [Scope::Work, Scope::Review] {
            let registration = Registration::from_row(
                &json!({"name":"alpha","uid":41001}),
                "alpha",
                "R",
                3000,
                scope,
            )
            .expect("registration");
            let (mut peer, mut stream) = FixtureClient::pair().expect("socket pair");
            let target = if scope == Scope::Work { "S" } else { "R" };
            let (reply, _) = super::serve_request_with_agent(
                &mut stream, &registration, 3000,
                &json!({"schema":2,"argv":[b"fixture".to_vec(),format!("git-receive-pack '~/mirrors/{target}.git'").into_bytes()],"deadline_ms":120_000}),
                Some(&route), Some(&runner), Some(&fixture.home), None, Some(&store), None, None,
                Instant::now(),
            ).expect("preflight reply");
            assert_eq!(
                reply["reason"],
                if scope == Scope::Work {
                    "door-caller-authority-refusal"
                } else {
                    "door-review-compute-refusal"
                }
            );
            assert_eq!(peer.answer()["reason"], reply["reason"]);
        }
    }

    // Common fixture hang bound, not a scheduling/performance assertion.
    pub(super) const FIXTURE_HANG: Duration = Duration::from_secs(120);

    // Observe the credit without consuming it: the final-reader mutation must
    // still encounter this very frame after the writer is released.
    #[allow(unsafe_code)] // MSG_PEEK has no stable UnixStream wrapper.
    fn fixture_peek_frame(client: &mut FixtureClient, mut partial: impl FnMut()) -> Value {
        let client = client.wire();
        let until = Instant::now() + FIXTURE_HANG;
        let mut peek = |bytes: &mut [u8]| loop {
            client
                .set_read_timeout(Some(until.saturating_duration_since(Instant::now())))
                .expect("fixture peek deadline");
            // SAFETY: the live socket and writable slice remain borrowed for recv.
            let received = unsafe {
                libc::recv(
                    client.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_PEEK | libc::MSG_WAITALL,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("fixture credit peek: {error}");
            }
            let received = usize::try_from(received).expect("received bytes");
            assert!(received > 0, "fixture credit closed before its frame");
            if received == bytes.len() {
                break;
            }
            assert!(Instant::now() < until, "fixture partial credit deadline");
            partial();
            thread::yield_now();
        };
        let mut header = [0; 4];
        peek(&mut header);
        let length = usize::try_from(u32::from_be_bytes(header)).expect("frame length");
        assert!(length <= super::FRAME_LIMIT);
        let mut bytes = vec![0; 4 + length];
        peek(&mut bytes);
        serde_json::from_slice(&bytes[4..]).expect("fixture credit JSON")
    }

    fn fixture_fragmented_credit() {
        let (mut client, mut writer) = FixtureClient::pair().expect("fragmented frame pair");
        let body = br#"{"type":"request-lock-wait","wait_ms":50}"#;
        let (partial, observed) = std::sync::mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            writer
                .write_all(&u32::try_from(body.len()).expect("length").to_be_bytes())
                .expect("frame header");
            observed.recv_timeout(FIXTURE_HANG).expect("partial peek");
            writer.write_all(body).expect("frame body");
        });
        let mut partial = Some(partial);
        let frame = fixture_peek_frame(&mut client, || {
            if let Some(partial) = partial.take() {
                partial.send(()).expect("release fragmented body");
            }
        });
        assert_eq!(frame["type"], "request-lock-wait");
        server.join().expect("fragmented writer");
    }

    pub(super) use fixture_client::{Client as FixtureClient, Server as FixtureServer};

    // Server fixtures consume requests, never answers. Keep the raw reader here.
    pub(super) fn fixture_request(stream: &mut FixtureServer) -> io::Result<Value> {
        super::frame_read_until(stream, Instant::now() + FIXTURE_HANG)
    }

    // Own the socket: no Read, Deref, or implicit conversion to UnixStream.
    // Ordinary tests use send/answer/event; wire assertions must opt in by name.
    mod fixture_client {
        use super::{FIXTURE_HANG, Instant, UnixStream, Value, io};
        use std::io::Write;
        use std::net::Shutdown;
        use std::path::Path;

        pub struct Client {
            stream: UnixStream,
            output: [usize; 2],
        }

        #[derive(Debug)]
        pub struct Server {
            stream: UnixStream,
        }

        impl Server {
            pub(crate) fn connect_reverse(path: impl AsRef<Path>) -> io::Result<Self> {
                UnixStream::connect(path).map(|stream| Self { stream })
            }
            pub(crate) fn into_wire(self) -> UnixStream {
                self.stream
            }
            pub(crate) fn wire(&mut self) -> &mut UnixStream {
                &mut self.stream
            }
            pub(crate) fn accept(listener: &std::os::unix::net::UnixListener) -> io::Result<Self> {
                listener.accept().map(|(stream, _)| Self { stream })
            }
        }

        impl std::ops::Deref for Server {
            type Target = UnixStream;
            fn deref(&self) -> &Self::Target {
                &self.stream
            }
        }

        impl std::ops::DerefMut for Server {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.stream
            }
        }

        impl std::io::Read for Server {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                std::io::Read::read(&mut self.stream, bytes)
            }
        }

        impl Write for Server {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.stream.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.stream.flush()
            }
        }

        impl Client {
            pub(crate) fn new(stream: UnixStream) -> Self {
                Self {
                    stream,
                    output: [0, 0],
                }
            }

            pub(crate) fn pair() -> io::Result<(Self, Server)> {
                UnixStream::pair().map(|(client, stream)| (Self::new(client), Server { stream }))
            }

            pub(crate) fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
                UnixStream::connect(path).map(Self::new)
            }

            pub(crate) fn send(&mut self, request: &Value) -> io::Result<()> {
                crate::door::frame_write_until(
                    &mut self.stream,
                    request,
                    Instant::now() + FIXTURE_HANG,
                )
            }

            pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
                self.stream.shutdown(how)
            }

            pub(crate) fn answer(&mut self) -> Value {
                self.event("final")
            }

            pub(crate) fn wire(&mut self) -> &mut UnixStream {
                &mut self.stream
            }

            pub(crate) fn event(&mut self, expected: &str) -> Value {
                let until = Instant::now() + FIXTURE_HANG;
                loop {
                    let frame = crate::door::frame_read_until(&mut self.stream, until)
                        .expect("fixture protocol frame");
                    let kind = frame["type"].as_str();
                    if expected == "final" && frame.get("status").is_some() {
                        assert!(frame["status"].as_i64().is_some(), "final status: {frame}");
                        assert!(
                            kind.is_none() || kind == Some("final"),
                            "final type: {frame}"
                        );
                        assert_eq!(
                            frame["stdout_bytes"], self.output[0],
                            "stdout count: {frame}"
                        );
                        assert_eq!(
                            frame["stderr_bytes"], self.output[1],
                            "stderr count: {frame}"
                        );
                        return frame;
                    }
                    if matches!(kind, Some("stdout" | "stderr")) {
                        let bytes = frame["bytes"].as_array().expect("output bytes");
                        assert!(
                            bytes
                                .iter()
                                .all(|byte| byte.as_u64().is_some_and(|n| n <= 255)),
                            "output byte: {frame}"
                        );
                        let index = usize::from(kind == Some("stderr"));
                        self.output[index] = self.output[index]
                            .checked_add(bytes.len())
                            .expect("output count");
                    }
                    if kind == Some("request-lock-wait") {
                        assert_eq!(frame["schema"], 2);
                        assert!(frame["wait_ms"].as_u64().is_some_and(|wait| wait > 0));
                    }
                    if kind == Some(expected) {
                        assert_ne!(expected, "final", "final frame lacks status: {frame}");
                        return frame;
                    }
                    assert!(
                        kind == Some("request-lock-wait")
                            || (expected == "final"
                                && matches!(
                                    kind,
                                    Some("compute-deadline" | "stdout" | "stderr" | "limits")
                                )),
                        "expected {expected}, received {frame}"
                    );
                }
            }
        }

        impl Write for Client {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.stream.write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.stream.flush()
            }
        }
    }

    // A reply as its peer decodes it. Frames are `serde_json::to_vec`, and the default
    // parser can land one unit in the last place away from a printed float measurement.
    pub(super) fn as_sent(reply: &Value) -> Value {
        let bytes = serde_json::to_vec(reply).expect("encode reply");
        serde_json::from_slice(&bytes).expect("decode reply")
    }

    /// ´test:unit:door-final-reply-follows-lock-wait-credits´
    #[test]
    fn door_final_reply_follows_lock_wait_credits() {
        for (credits, damaged) in [
            (0, None),
            (1, None),
            (3, None),
            (1, Some("stdout_bytes")),
            (1, Some("stderr_bytes")),
        ] {
            let (mut reader, mut writer) = FixtureClient::pair().expect("reply channel");
            let request = json!({"schema":2,"argv":[],"deadline_ms":120_000});
            reader.send(&request).expect("request");
            assert_eq!(
                fixture_request(&mut writer).expect("server request"),
                request
            );
            for wait_ms in 1..=credits {
                frame_write(
                    &mut writer,
                    &json!({"schema":2,"type":"request-lock-wait","wait_ms":wait_ms}),
                )
                .expect("credit frame");
            }
            for kind in ["compute-deadline", "limits"] {
                frame_write(&mut writer, &json!({"schema":2,"type":kind})).expect("announcement");
            }
            for (kind, bytes) in [("stdout", vec![65]), ("stderr", vec![66, 67])] {
                frame_write(&mut writer, &json!({"schema":2,"type":kind,"bytes":bytes}))
                    .expect("output");
            }
            let mut reply = super::connection_refusal(
                &io::Error::other("synthetic framing case"),
                Instant::now(),
            );
            reply["stdout_bytes"] = json!(1);
            reply["stderr_bytes"] = json!(2);
            if let Some(field) = damaged {
                reply[field] = json!(99);
            }
            super::frame_write_no_drain(&mut writer, &reply).expect("final reply");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reader.answer()));
            if damaged.is_some() {
                assert!(
                    result.is_err(),
                    "answer must reject differing output counts"
                );
            } else {
                assert_eq!(result.expect("valid answer"), as_sent(&reply));
            }
        }
    }

    /// ´test:unit:door-audit-label-precedes-effect´
    #[test]
    fn door_audit_label_precedes_effect() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let (runner, calls, states) = counting_runner(&fixture);
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
        let mut client = send_probe(socket, 2000);
        let id = wait_filed(&store);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            store.request(&id).expect("request").value()["state"],
            "waiting"
        );
        let first = store.effective_mode("ssh").expect("first setting");
        assert_eq!(first["mode"], "audit");
        assert_eq!(first["class"]["setter"], "door-service");
        assert_eq!(first["class"]["floor"], "audit");
        label(&store, &id, "allow");
        let final_frame = client.answer();
        assert_eq!(final_frame["queue_state"], "answered");
        assert!(
            final_frame["queue_wall_seconds"]
                .as_f64()
                .expect("queue wall")
                > 0.0
        );
        assert_eq!(final_frame["status"], 0);
        server.join().expect("service").expect("reply");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(*states.lock().expect("states"), vec!["adjudicated"]);
        assert_eq!(
            store.request(&id).expect("request").value()["effect"]["state"],
            "completed"
        );
    }

    /// ´test:unit:door-allow-effect-precedes-waiting-and-label´
    #[test]
    fn door_allow_effect_precedes_waiting_and_label() {
        fixture_fragmented_credit();
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, crate::requests::Mode::Allow);
        let (runner, calls, states) = counting_runner(&fixture);
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.set(Some(FIXTURE_HANG));
        let (socket, server) =
            fixture_service(&fixture, runner, rubric(Some("allow")), 120_000, None);
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.set(None);
        let held = store
            .fixture_exclusive_lock()
            .expect("held admission writer");
        let mut client = send_probe(socket, 120_000);
        let progress = fixture_peek_frame(&mut client, || {});
        assert_eq!(progress["type"], "request-lock-wait");
        assert!(progress["wait_ms"].as_u64().is_some_and(|wait| wait >= 50));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "effect before admission");
        drop(held);
        let final_frame = client.answer();
        server.join().expect("service").expect("reply");
        assert_eq!(final_frame["queue_state"], "no-queue");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(*states.lock().expect("states"), vec!["intent"]);
        let id = wait_filed(&store);
        let record = store.request(&id).expect("request");
        assert_eq!(record.value()["state"], "waiting");
        assert_eq!(record.value()["effect"]["state"], "completed");
        label(&store, &id, "allow");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// ´test:unit:door-enforce-rubric-and-undecided-queue´
    #[test]
    fn door_enforce_rubric_and_undecided_queue() {
        for (decision, expected, effect) in [
            (Some("allow"), "door-complete", true),
            (Some("refuse"), "door-rubric-refusal", false),
            (None, "door-complete", true),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("enforce");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Enforce);
            let (runner, calls, _states) = counting_runner(&fixture);
            let (socket, server) = fixture_service(&fixture, runner, rubric(decision), 2000, None);
            let mut client = send_probe(socket, 2000);
            if decision.is_none() {
                let id = wait_filed(&store);
                assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
                label(&store, &id, "allow");
            }
            let final_frame = client.answer();
            server.join().expect("service").expect("reply");
            assert_eq!(final_frame["reason"], expected);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(effect)
            );
            let records = store.list().expect("records").0;
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].value()["state"],
                if decision.is_none() {
                    "adjudicated"
                } else {
                    "observed"
                }
            );
            assert_eq!(records[0].value()["class"], "ssh");
            assert_eq!(records[0].value()["shape_key"], "ssh:probe-echo");
            assert_eq!(records[0].value()["mode"], "enforce");
            assert_eq!(
                records[0].value()["would_do"]["decision"],
                decision.unwrap_or("undecided")
            );
            assert_eq!(records[0].value()["effect"]["reason"], expected);
            assert_eq!(
                records[0].value()["effect"]["ref_check"],
                if decision == Some("refuse") {
                    "not-reached"
                } else {
                    "not-applicable"
                }
            );
            if decision.is_some() {
                let id = records[0].id();
                assert_eq!(
                    store
                        .triage(
                            "R",
                            &[json!({"id":id,"action":"adjudicate",
                    "treatment":"allow","reason":"no waiting request"})],
                            "fixture",
                            "2"
                        )
                        .expect_err("observed is not waiting")
                        .kind,
                    "requests-batch-refusal"
                );
                let listed = fixture
                    .command(&["list", "alpha", "--state", "observed"], b"")
                    .expect("observed list");
                assert_eq!(listed["requests"].as_array().expect("rows").len(), 1);
            }
            if decision == Some("allow") {
                let id = records[0].id();
                let reviewed = store.review(id, "2").expect("observed review");
                assert_eq!(reviewed.value()["state"], "marked");
                let review_id = reviewed.value()["review"]["id"]
                    .as_str()
                    .expect("review id");
                store
                    .adjudicate(
                        id,
                        review_id,
                        "refuse",
                        "wrong enforced rubric",
                        "fixture owner",
                        "3",
                    )
                    .expect("correction label");
                assert_eq!(
                    store.effective_mode("ssh").expect("corrected mode")["mode"],
                    "audit"
                );
            }
        }
    }

    /// A request whose wait expires or disconnects performs no effect. (´[TOOLS-rule:workercontracts:bounded-judgement]´)
    ///
    /// ´claim:capability:expired-wait-no-effect´
    /// ´test:unit:door-wait-deadline-and-disconnect-have-no-effect´
    #[test]
    fn door_wait_deadline_and_disconnect_have_no_effect() {
        for disconnect in [false, true] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let (runner, calls, _states) = counting_runner(&fixture);
            let deadline_ms = 120_000;
            let (waiting, entered) = std::sync::mpsc::channel();
            let (release, proceed) = std::sync::mpsc::channel();
            if disconnect {
                super::REQUEST_READY.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |_| {
                        crate::requests::store::BEFORE_READER_LOCK_ATTEMPT.with(|hook| {
                            *hook.borrow_mut() = Some(Box::new(move |_| {
                                waiting.send(()).expect("owner wait entered");
                                proceed.recv_timeout(FIXTURE_HANG).expect("peer closed");
                            }));
                        });
                        Ok(Instant::now() + FIXTURE_HANG)
                    }));
                });
            } else {
                let expired = Instant::now();
                super::REQUEST_READY.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |_| Ok(expired)));
                });
            }
            let (socket, server) =
                fixture_service(&fixture, runner, rubric(None), deadline_ms, None);
            let mut client = send_probe(socket, deadline_ms);
            let id = wait_filed(&store);
            if disconnect {
                entered.recv_timeout(FIXTURE_HANG).expect("owner wait read");
                drop(client);
                release.send(()).expect("observe close in owner wait");
            } else {
                let final_frame = client.answer();
                assert_eq!(final_frame["reason"], "door-request-deadline");
                assert_eq!(final_frame["queue_state"], "deadline");
            }
            let reply = server.join().expect("service").expect("reply");
            assert_eq!(reply["queue_state"], "deadline", "{reply}");
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            let reason = if disconnect {
                "door-disconnect-refusal"
            } else {
                "door-request-deadline"
            };
            assert_eq!(
                store.request(&id).expect("request").value()["effect"]["reason"],
                reason
            );
        }
    }

    /// ´test:unit:door-full-request-store-refuses-before-effect´
    #[test]
    fn door_full_request_store_refuses_before_effect() {
        for allow in [false, true] {
            let fixture = Fixture::new();
            if allow {
                fixture.set_floor("allow");
            }
            let store = fixture.store();
            if allow {
                set_fixture_mode(&store, crate::requests::Mode::Allow);
            }
            let (runner, calls, _states) = counting_runner(&fixture);
            let (socket, server) = fixture_service(&fixture, runner, rubric(None), 2000, Some(0));
            let mut client = send_probe(socket, 2000);
            let final_frame = client.answer();
            server.join().expect("service").expect("reply");
            assert_eq!(
                final_frame["reason"],
                format!(
                    "door-requests-full-refusal: run request capacity is full; {}",
                    crate::requests::store::RUN_CAP_REMEDY
                )
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            let attempt: serde_json::Value = serde_json::from_slice(
                &fs::read(
                    fixture
                        .home
                        .join(".config/loops/alpha/door-requests-attempt.json"),
                )
                .expect("incomplete attempt"),
            )
            .expect("attempt JSON");
            assert_eq!(attempt["latest"]["incomplete"]["phase"], "incomplete");
            assert!(
                attempt["latest"]["incomplete"]["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("requests-store-full"))
            );
        }
    }

    /// ´test:unit:door-adjudicated-refusal-has-no-effect´
    #[test]
    fn door_adjudicated_refusal_has_no_effect() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let (runner, calls, _) = counting_runner(&fixture);
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
        let mut client = send_probe(socket, 2000);
        let id = wait_filed(&store);
        label(&store, &id, "refuse");
        let reply = client.answer();
        server.join().expect("service").expect("refusal");
        assert_eq!(reply["reason"], "door-adjudicated-refusal");
        assert_eq!(reply["queue_state"], "refused");
        assert!(
            reply["queue_wall_seconds"]
                .as_f64()
                .is_some_and(|wall| wall > 0.0)
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            store.request(&id).expect("request").value()["effect"]["reason"],
            "door-adjudicated-refusal"
        );
    }

    /// ´test:unit:door-compute-record-failures-keep-exit-and-incomplete-attempt´
    #[test]
    fn door_compute_record_failures_keep_exit_and_incomplete_attempt() {
        for (allow, fault) in [
            (true, FixtureFault::EffectWrite),
            (false, FixtureFault::EffectWrite),
            (true, FixtureFault::WaitingWrite),
        ] {
            let fixture = Fixture::new();
            if allow {
                fixture.set_floor("allow");
            }
            let store = fixture.store();
            if allow {
                set_fixture_mode(&store, crate::requests::Mode::Allow);
            }
            let (runner, calls, _) = counting_runner(&fixture);
            let (socket, server) = fixture_service_with(
                &fixture,
                runner,
                rubric(Some("allow")),
                2000,
                None,
                Some(fault),
                true,
            );
            let mut client = send_probe(socket, 2000);
            let id = wait_filed(&store);
            if !allow {
                label(&store, &id, "allow");
            }
            let reply = client.answer();
            server.join().expect("service").expect("incomplete reply");
            assert_eq!(reply["status"], 0);
            assert_eq!(reply["reason"], "door-record-incomplete");
            assert_eq!(reply["compute_exit_status"], 0);
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
            assert_incomplete(&fixture, &id);
        }
    }

    /// ´test:unit:door-stub-keeps-command-status-after-effect-record-failure´
    #[test]
    fn door_stub_keeps_command_status_after_effect_record_failure() {
        for exit in [0, 1] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Allow);
            let (mut runner, calls, _) = counting_runner(&fixture);
            runner.fail_after_input = exit != 0;
            let (socket, server) = fixture_stub_service_with(
                &fixture,
                runner,
                rubric(Some("allow")),
                2000,
                None,
                Some(FixtureFault::EffectWrite),
                true,
            );
            let args = [OsString::from("door-attribution-probe")];
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let reply = super::stub_call_stream(
                &socket,
                &args,
                io::Cursor::new(b"fictional output\n"),
                &mut output,
                &mut errors,
            )
            .expect("stub final reply");
            server
                .join()
                .expect("service")
                .expect("record failure reply");
            assert_eq!(output, b"fictional output\n");
            if exit == 0 {
                assert_eq!(errors, Vec::<u8>::new());
            } else {
                assert!(
                    String::from_utf8_lossy(&errors)
                        .contains("/definitely-unavailable-door-fixture-source")
                );
            }
            assert_eq!(reply["status"], exit);
            assert_eq!(reply["compute_exit_status"], exit);
            assert_eq!(reply["reason"], "door-record-incomplete");
            let line = super::final_line(&args, &reply).expect("visible record failure");
            let visible: serde_json::Value =
                serde_json::from_str(&line).expect("probe prints its final reply");
            assert_eq!(visible["reason"], "door-record-incomplete");
            assert_eq!(
                visible["request_record_error"],
                "requests-record-refusal: fixture effect write failure"
            );
            let command_line = super::final_line(&[OsString::from("git")], &reply)
                .expect("ordinary command prints its final failure");
            assert_eq!(
                command_line,
                "door-record-incomplete: requests-record-refusal: fixture effect write failure"
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
            let id = store.list().expect("filed request").0[0].id().to_owned();
            assert_incomplete(&fixture, &id);
        }
    }

    /// ´test:unit:door-decided-enforce-record-failures-remain-incomplete´
    #[test]
    fn door_decided_enforce_record_failures_remain_incomplete() {
        for (decision, fault) in [
            ("refuse", FixtureFault::EffectWrite),
            ("refuse", FixtureFault::ObservedWrite),
            ("allow", FixtureFault::EffectWrite),
            ("allow", FixtureFault::ObservedWrite),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("enforce");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Enforce);
            let (runner, calls, _) = counting_runner(&fixture);
            let (socket, server) = fixture_service_with(
                &fixture,
                runner,
                rubric(Some(decision)),
                2000,
                None,
                Some(fault),
                true,
            );
            let mut client = send_probe(socket, 2000);
            let reply = client.answer();
            server.join().expect("service").expect("reply");
            assert_eq!(reply["reason"], "door-record-incomplete");
            assert_eq!(reply["status"], if decision == "allow" { 0 } else { 125 });
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(decision == "allow")
            );
            if decision == "allow" {
                assert_eq!(reply["compute_exit_status"], 0);
            }
            let id = store.list().expect("record").0[0].id().to_owned();
            assert_incomplete(&fixture, &id);
        }
    }

    /// ´test:unit:door-file-refusals-and-absent-registration-are-typed´
    #[test]
    fn door_file_refusals_and_absent_registration_are_typed() {
        for (fault, expected) in [
            (
                Some(FixtureFault::ChangedSnapshot),
                "door-request-record-refusal",
            ),
            (
                Some(FixtureFault::LoopFull),
                "door-requests-full-refusal: loop request capacity is full; retire LOOP RUN for a finished run to free room",
            ),
            (
                Some(FixtureFault::RunsFull),
                "door-requests-full-refusal: loop request capacity is full; retire LOOP RUN for a finished run to free room",
            ),
            (
                Some(FixtureFault::InvalidIncomplete),
                "door-requests-full-refusal: run request capacity is full; this run is at its own cap; once its round ends, retire LOOP RUN and continue the work in a new run",
            ),
            (None, "door-requests-unregistered"),
        ] {
            let fixture = Fixture::new();
            fixture.set_floor("allow");
            let store = fixture.store();
            set_fixture_mode(&store, crate::requests::Mode::Allow);
            let (runner, calls, _) = counting_runner(&fixture);
            let registered = fault.is_some();
            let (socket, server) = fixture_service_with(
                &fixture,
                runner,
                rubric(None),
                2000,
                None,
                fault,
                registered,
            );
            let mut client = send_probe(socket, 2000);
            let reply = client.answer();
            server.join().expect("service").expect("refusal");
            assert_eq!(reply["reason"], expected);
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            if matches!(fault, Some(FixtureFault::InvalidIncomplete)) {
                assert!(
                    !fixture
                        .home
                        .join(".config/loops/alpha/door-requests-attempt.json")
                        .exists()
                );
            } else if registered {
                let attempt = incomplete_attempt(&fixture);
                assert_eq!(attempt["latest"]["incomplete"]["phase"], "incomplete");
            }
        }
    }

    /// ´test:unit:door-wait-errors-send-final-and-record-incomplete´
    #[test]
    fn door_wait_errors_send_final_and_record_incomplete() {
        for (fault, answer, expected_state) in [
            (FixtureFault::WaitRead, "read", "refused"),
            (FixtureFault::EffectWrite, "refuse", "refused"),
            (FixtureFault::EffectWrite, "deadline", "deadline"),
            (FixtureFault::EffectWrite, "disconnect", "deadline"),
        ] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let (runner, calls, _) = counting_runner(&fixture);
            let deadline_ms = 120_000;
            let (waiting, entered) = std::sync::mpsc::channel();
            let (release, proceed) = std::sync::mpsc::channel();
            if answer == "disconnect" {
                super::REQUEST_READY.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |_| {
                        crate::requests::store::BEFORE_READER_LOCK_ATTEMPT.with(|hook| {
                            *hook.borrow_mut() = Some(Box::new(move |_| {
                                waiting.send(()).expect("owner wait entered");
                                proceed.recv_timeout(FIXTURE_HANG).expect("peer closed");
                            }));
                        });
                        Ok(Instant::now() + FIXTURE_HANG)
                    }));
                });
            }
            if answer == "deadline" {
                let expired = Instant::now();
                super::REQUEST_READY.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |_| Ok(expired)));
                });
            }
            let (socket, server) = fixture_service_with(
                &fixture,
                runner,
                rubric(None),
                deadline_ms,
                None,
                Some(fault),
                true,
            );
            let mut client = send_probe(socket, deadline_ms);
            let id = wait_filed(&store);
            if answer == "refuse" {
                label(&store, &id, "refuse");
            }
            if answer == "disconnect" {
                entered.recv_timeout(FIXTURE_HANG).expect("owner wait read");
                // Close after the wait entered its read, then let either valid
                // observation point report the same durable disconnect.
                drop(client);
                release.send(()).expect("observe close in owner wait");
            } else {
                let reply = client.answer();
                assert_eq!(
                    reply["reason"],
                    if answer == "read" {
                        "door-request-read-refusal"
                    } else {
                        "door-record-incomplete"
                    }
                );
                assert_eq!(reply["queue_state"], expected_state);
                assert_eq!(reply["status"], 125);
            }
            let outcome = server.join().expect("service");
            assert!(outcome.is_ok(), "owner wait {answer}: {outcome:?}");
            if answer == "disconnect" {
                let reply = outcome.expect("stopped owner wait");
                assert_eq!(reply["queue_state"], "deadline", "{reply}");
                assert!(reply["request_record_error"].is_string(), "{reply}");
                let rows = store.list_run("R").expect("durable record");
                assert_eq!(
                    rows[0].value()["effect"]["reason"],
                    "door-disconnect-refusal"
                );
                assert_eq!(rows[0].value()["effect"]["ending"]["cause"], "disconnect");
                assert_eq!(
                    rows[0].value()["effect"]["ending"]["final_write"],
                    "not-attempted"
                );
            }
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_incomplete(&fixture, &id);
        }
    }

    /// ´test:unit:door-stub-accepts-answered-and-deadline-final-frames´
    #[test]
    fn door_stub_accepts_answered_and_deadline_final_frames() {
        for answered in [true, false] {
            let fixture = Fixture::new();
            let store = fixture.store();
            let (runner, calls, _) = counting_runner(&fixture);
            if !answered {
                let expired = Instant::now();
                super::REQUEST_READY.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |_| Ok(expired)));
                });
            }
            super::transport::STUB_TEST_BUDGET.with(|slot| slot.set(Some(120_000)));
            let (socket, server) =
                fixture_stub_service(&fixture, runner, rubric(None), 120_000, None);
            let labeler = answered.then(|| {
                thread::spawn(move || {
                    let id = wait_filed(&store);
                    label(&store, &id, "allow");
                })
            });
            let operation = if answered {
                "door-attribution-probe"
            } else {
                "door-attribution-deadline"
            };
            let reply = stub_call(&socket, &[OsString::from(operation)], b"")
                .expect("real stub queued final");
            if let Some(labeler) = labeler {
                labeler.join().expect("labeler");
            }
            server.join().expect("service").expect("stub reply");
            assert_eq!(
                reply["queue_state"],
                if answered { "answered" } else { "deadline" }
            );
            assert!(
                reply["queue_wall_seconds"]
                    .as_f64()
                    .is_some_and(|wall| wall >= 0.0)
            );
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                usize::from(answered)
            );
        }
    }

    /// ´test:unit:door-refused-large-input-keeps-checked-final-frame´
    #[test]
    fn door_refused_large_input_keeps_checked_final_frame() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let (runner, calls, _) = counting_runner(&fixture);
        let (socket, server) = fixture_stub_service(&fixture, runner, rubric(None), 2000, None);
        let labeler = thread::spawn(move || {
            let id = wait_filed(&store);
            label(&store, &id, "refuse");
        });
        let reply = stub_call(
            &socket,
            &[OsString::from("door-attribution-probe")],
            &vec![7; 2 * 1024 * 1024],
        )
        .expect("checked refusal wins over a closed stdin peer");
        labeler.join().expect("labeler");
        server.join().expect("service").expect("refusal");
        assert_eq!(reply["reason"], "door-adjudicated-refusal");
        assert_eq!(reply["status"], 125);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    fn finish_isolated_sized_wait() -> bool {
        const FILTER: &str = "door::tests::door_waiters_release_writer_over_sized_run";
        if std::env::var_os("DOOR_SIZED_WAIT_CHILD").is_some() {
            return false;
        }
        // Concurrent tests can fork while a reader holds its flock, inheriting
        // that open file description until exec. Isolate those unrelated lock
        // holders while retaining all sixteen polling readers and their writer.
        let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([FILTER, "--exact", "--nocapture"])
            .env("DOOR_SIZED_WAIT_CHILD", "1")
            .output()
            .expect("isolated sized reader fixture");
        assert!(
            result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        true
    }

    /// # Panics
    /// Panics only if fixture setup, reader synchronization, or the writer-release contract fails.
    ///
    /// ´test:unit:door-waiters-release-writer-over-sized-run´
    #[test]
    fn door_waiters_release_writer_over_sized_run() {
        if finish_isolated_sized_wait() {
            return;
        }
        let fixture = Fixture::new();
        let store = Arc::new(fixture.store());
        store.ensure_first_mode("git").expect("first mode");
        let setting = store.effective_mode("git").expect("effective mode");
        for size in [64_u32, 1900_u32] {
            let mut rows = Vec::new();
            for number in 1..=size {
                let mut value = crate::requests::tests::waiting(
                    "R",
                    &format!("{number:x}"),
                    3000,
                    crate::requests::Mode::Audit,
                )
                .into_value();
                value["class_setting"] = setting["class"].clone();
                value["loop_setting"] = setting["loop"].clone();
                rows.push(value);
            }
            let bytes = serde_json::to_vec(&json!({"schema":1,"run":"R","revision":size,
            "requests":rows}))
            .expect("sized run bytes");
            store
                .fixture_replace_run_bytes("R", &bytes)
                .expect("fixture custody");
            let mut peers = Vec::new();
            let mut waiters = Vec::new();
            let (read_tx, read_rx) = std::sync::mpsc::channel();
            let mut resume = Vec::new();
            for _ in 0..16 {
                let (peer, worker) = UnixStream::pair().expect("fixture pair");
                peers.push(peer);
                let store = Arc::clone(&store);
                let read_tx = read_tx.clone();
                let (resume_tx, resume_rx) = std::sync::mpsc::channel();
                resume.push(resume_tx);
                waiters.push(thread::spawn(move || {
                    super::AFTER_WAIT_READ.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            read_tx.send(()).expect("reader reached polling boundary");
                            resume_rx
                                .recv_timeout(Duration::from_secs(120))
                                .expect("writer published before readers resume");
                        }));
                    });
                    let started = Instant::now();
                    let answer = super::wait_answer(
                        &store,
                        "R:1",
                        &worker,
                        started + Duration::from_secs(120),
                    );
                    (answer, started.elapsed())
                }));
            }
            drop(read_tx);
            // All sixteen readers actually read the sized run, then rendezvous
            // outside waiting_request. Keep them parked until the writer has
            // published: none may retain a store lock across this boundary.
            for _ in 0..16 {
                read_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("every reader reached polling boundary");
            }
            let started = Instant::now();
            crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.set(Some(Duration::ZERO));
            let publication = store.triage(
                "R",
                &[json!({"id":"R:1","action":"adjudicate",
            "treatment":"allow","reason":"sized fixture answer"})],
                "fixture owner",
                &super::now_nanos().to_string(),
            );
            crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.set(None);
            publication.expect("parked readers released the writer lock");
            let writer_wall = started.elapsed();
            let longest = resume
                .into_iter()
                .zip(waiters)
                .map(|(release, waiter)| {
                    release
                        .send(())
                        .expect("answer published before reader resumes");
                    let (answer, wall) = waiter.join().expect("waiter");
                    assert!(
                        matches!(answer, super::Answer::Allow(_)),
                        "waiter returned {answer:?}"
                    );
                    wall
                })
                .max()
                .expect("waiters");
            let _reported = writeln!(
                io::stderr().lock(),
                "door wait load: rows={size} waiters=16 run_bytes={} writer_ms={} longest_wait_ms={}",
                bytes.len(),
                writer_wall.as_millis(),
                longest.as_millis()
            );
            drop(peers);
        }
    }

    /// # Panics
    /// Panics only if fixture setup fails or the observed lock timeout prevents a later answer.
    /// ´test:unit:door-wait-retries-lock-timeout-before-command-deadline´
    #[test]
    fn door_wait_retries_lock_timeout_before_command_deadline() {
        let fixture = Fixture::new();
        let store = Arc::new(fixture.store());
        store.ensure_first_mode("git").expect("first setting");
        let setting = store.effective_mode("git").expect("effective setting");
        let mut value =
            crate::requests::tests::waiting("R", "1a", 3000, crate::requests::Mode::Audit)
                .into_value();
        value["class_setting"] = setting["class"].clone();
        value["loop_setting"] = setting["loop"].clone();
        store
            .file(crate::requests::RequestRecord::decode(value).expect("request"))
            .expect("file");
        let lock = store.fixture_exclusive_lock().expect("held writer lock");
        let (peer, worker) = UnixStream::pair().expect("fixture pair");
        let waiting_store = Arc::clone(&store);
        let (timed_out, observed) = std::sync::mpsc::channel();
        let deadline = Instant::now() + Duration::from_secs(6);
        let waiter = thread::spawn(move || {
            crate::requests::store::READER_LOCK_WAIT_OVERRIDE.set(Some(Duration::from_millis(300)));
            super::AFTER_WAIT_LOCK_TIMEOUT.with(|slot| *slot.borrow_mut() = Some(timed_out));
            super::wait_answer(&waiting_store, "R:1a", &worker, deadline)
        });
        observed
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("waiter observed a lock timeout before release");
        drop(lock);
        store
            .triage(
                "R",
                &[json!({"id":"R:1a","action":"adjudicate",
            "treatment":"allow","reason":"lock released"})],
                "fixture owner",
                &super::now_nanos().to_string(),
            )
            .expect("label");
        assert!(matches!(
            waiter.join().expect("waiter"),
            super::Answer::Allow(_)
        ));
        drop(peer);
    }

    /// ´test:unit:door-wait-lock-timeout-reaches-command-deadline´
    #[test]
    fn door_wait_lock_timeout_reaches_command_deadline() {
        let fixture = Fixture::new();
        let store = Arc::new(fixture.store());
        store.ensure_first_mode("git").expect("first setting");
        let setting = store.effective_mode("git").expect("effective setting");
        let mut value =
            crate::requests::tests::waiting("R", "1b", 3000, crate::requests::Mode::Audit)
                .into_value();
        value["class_setting"] = setting["class"].clone();
        value["loop_setting"] = setting["loop"].clone();
        store
            .file(crate::requests::RequestRecord::decode(value).expect("request"))
            .expect("file");
        let lock = store.fixture_exclusive_lock().expect("held writer lock");
        let (peer, worker) = UnixStream::pair().expect("fixture pair");
        let waiting_store = Arc::clone(&store);
        let waiter = thread::spawn(move || {
            super::wait_answer(
                &waiting_store,
                "R:1b",
                &worker,
                Instant::now() + Duration::from_millis(2200),
            )
        });
        assert!(matches!(
            waiter.join().expect("waiter"),
            super::Answer::Deadline(_)
        ));
        drop(lock);
        drop(peer);
    }

    /// ´test:unit:door-mode-exercise-reads-fixture-service-outcomes´
    #[test]
    fn door_mode_exercise_reads_fixture_service_outcomes() {
        let fixture = Fixture::new();
        let store = fixture.store();
        for treatment in ["allow", "refuse"] {
            let previous = store.list().expect("prior records").0.len();
            let (runner, _, _) = counting_runner(&fixture);
            let (socket, server) =
                fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
            let mut client = send_probe(socket, 2000);
            let id = (0..100)
                .find_map(|_| {
                    let rows = store.list().expect("records").0;
                    if rows.len() > previous {
                        rows.last().map(|record| record.id().to_owned())
                    } else {
                        thread::sleep(Duration::from_millis(10));
                        None
                    }
                })
                .expect("new request");
            label(&store, &id, treatment);
            assert_eq!(
                client.answer()["status"],
                if treatment == "allow" { 0 } else { 125 }
            );
            server.join().expect("service").expect("reply");
        }
        let records = store
            .list()
            .expect("audit records")
            .0
            .into_iter()
            .map(crate::requests::RequestRecord::into_value)
            .collect::<Vec<_>>();
        let (reasons, observed) = crate::launch::exercise::door_modes::audit(&records);
        assert!(observed);
        assert!(reasons.is_empty(), "{reasons:?}");
        for (mutation, expected) in [
            ("early", "audit effect occurred before"),
            ("answer", "audit request has no adjudicated answer"),
        ] {
            let mut broken = records.clone();
            broken[0]["label"] = Value::Null;
            if mutation == "answer" {
                broken[0]["effect"]["state"] = json!("pending");
                broken[0]["state"] = json!("waiting");
            }
            let (reasons, _) = crate::launch::exercise::door_modes::audit(&broken);
            assert!(
                reasons.iter().any(|reason| reason.contains(expected)),
                "{reasons:?}"
            );
        }

        drop(store);
        drop(fixture);

        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, crate::requests::Mode::Allow);
        let (runner, _, _) = counting_runner(&fixture);
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
        let mut client = send_probe(socket, 2000);
        let _reply = client.answer();
        server.join().expect("service").expect("allow");
        let id = store.list().expect("allow record").0[0].id().to_owned();
        label(&store, &id, "allow");
        let records = store
            .list()
            .expect("labelled record")
            .0
            .into_iter()
            .map(crate::requests::RequestRecord::into_value)
            .collect::<Vec<_>>();
        let (reasons, observed) = crate::launch::exercise::door_modes::allow(&records);
        assert!(observed);
        assert!(reasons.is_empty(), "{reasons:?}");
        for (mutation, expected) in [
            ("floor", "below its recorded row floor"),
            ("wait", "confirmation wait"),
            ("effect", "effect is unrecorded"),
            ("label", "later label"),
        ] {
            let mut broken = records.clone();
            match mutation {
                "floor" => broken[0]["floor"] = json!("audit"),
                "wait" => broken[0]["effect"]["queue_wall_seconds"] = json!(1.0),
                "effect" => broken[0]["effect"]["state"] = json!("pending"),
                _ => broken[0]["label"] = Value::Null,
            }
            let (reasons, _) = crate::launch::exercise::door_modes::allow(&broken);
            assert!(
                reasons.iter().any(|reason| reason.contains(expected)),
                "{reasons:?}"
            );
        }
    }

    fn finish_isolated_enforce_exercise() -> bool {
        const FILTER: &str =
            "door::tests::door_enforce_exercise_keeps_fixture_moves_and_correction";
        if std::env::var_os("DOOR_ENFORCE_EXERCISE_CHILD").is_some() {
            return false;
        }
        // Other tests can fork while a request flock is held, retaining its
        // open description until exec. Keep those holders out of this fixture.
        let result = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([FILTER, "--exact", "--nocapture"])
            .env("DOOR_ENFORCE_EXERCISE_CHILD", "1")
            .output()
            .expect("isolated enforcement fixture");
        assert!(
            result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        true
    }

    /// ´test:unit:door-enforce-exercise-keeps-fixture-moves-and-correction´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn door_enforce_exercise_keeps_fixture_moves_and_correction() {
        use crate::requests::modes::ModeTarget;
        if finish_isolated_enforce_exercise() {
            return;
        }
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        let target = ModeTarget::class("fixture").expect("fixture class");
        store
            .set_mode(
                &ModeTarget::Loop,
                crate::requests::Mode::Allow,
                "fixture owner",
                "recorded floor admits allow",
                "1",
                &[],
            )
            .expect("loop first setting");
        store
            .set_mode(
                &target,
                crate::requests::Mode::Enforce,
                "fixture owner",
                "fixture class first enforcement",
                "1",
                &[],
            )
            .expect("class first setting");
        let agreeing = fixture_class_call(&fixture, Some("allow"), None);
        let review = store
            .review(&agreeing, "review-one")
            .expect("observed review");
        let review_id = review.value()["review"]["id"].as_str().expect("review id");
        store
            .adjudicate(
                &agreeing,
                review_id,
                "allow",
                "rubric agrees",
                "fixture owner",
                &super::now_nanos().to_string(),
            )
            .expect("agreeing label");
        store
            .set_mode(
                &target,
                crate::requests::Mode::Allow,
                "fixture owner",
                "cited agreement permits relaxation",
                &super::now_nanos().to_string(),
                &[agreeing],
            )
            .expect("cited relaxation");
        store
            .set_mode(
                &target,
                crate::requests::Mode::Enforce,
                "fixture owner",
                "stricter fixture move at once",
                &super::now_nanos().to_string(),
                &[],
            )
            .expect("strict move");
        let _decided_allow = fixture_class_call(&fixture, Some("allow"), None);
        let _decided_refuse = fixture_class_call(&fixture, Some("refuse"), None);
        let _undecided = fixture_class_call(&fixture, None, Some("allow"));
        let wrong = fixture_class_call(&fixture, Some("refuse"), None);
        let review = store.review(&wrong, "review-wrong").expect("wrong review");
        let review_id = review.value()["review"]["id"].as_str().expect("review id");
        store
            .adjudicate(
                &wrong,
                review_id,
                "allow",
                "rubric was wrong",
                "fixture owner",
                &super::now_nanos().to_string(),
            )
            .expect("correction");
        let records = store
            .list()
            .expect("fixture records")
            .0
            .into_iter()
            .map(crate::requests::RequestRecord::into_value)
            .collect::<Vec<_>>();
        let modes = store.modes().expect("mode history");
        let claims = json!({"allow_to_enforce":{"status":"pass"},
            "below_floor":{"status":"pass"},"correction_report":{"status":"pass"}});
        let (reasons, observed) =
            crate::launch::exercise::door_modes::enforce(&records, &modes, "fixture", &claims);
        assert!(observed);
        assert!(reasons.is_empty(), "{reasons:?} {modes}");
        assert_eq!(
            store.effective_mode("fixture").expect("return to audit")["mode"],
            "audit"
        );
        let mut unsupported = modes;
        unsupported["classes"][0]["settings"] = json!([]);
        let (reasons, _) = crate::launch::exercise::door_modes::enforce(
            &records,
            &unsupported,
            "fixture",
            &claims,
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("first enforce"))
        );
    }

    /// ´test:unit:door-mode-runtime-fixture-runs-stub-and-service-for-each-mode´
    #[test]
    fn door_mode_runtime_fixture_runs_stub_and_service_for_each_mode() {
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let _store = fixture.store();
        let _route = route_for(&fixture.home);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        let (runner, calls, _) = counting_runner(&fixture);
        let runner: Arc<dyn crate::door::transport::Runner> = Arc::new(runner);
        for case in ["door-audit", "door-allow", "door-enforce"] {
            let proof = super::exercise_mode_fixture_with(
                &fixture.home,
                &registration,
                case,
                Some(Arc::clone(&runner)),
                &mut json!({}),
            )
            .expect("runtime fixture");
            assert!(proof["class"].as_str().is_some());
            assert!(
                proof["outcomes"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
            );
            if case == "door-enforce" {
                assert_eq!(proof["mode_report"]["mode"], "audit");
            }
        }
        assert!(calls.load(std::sync::atomic::Ordering::Relaxed) >= 5);
    }

    /// ´test:unit:door-fixture-socket-cleans-up-after-refusal´
    #[test]
    fn door_fixture_socket_cleans_up_after_refusal() {
        let fixture = Fixture::new();
        let _route = route_for(&fixture.home);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        let (runner, _, _) = counting_runner(&fixture);
        let runner: Arc<dyn crate::door::transport::Runner> = Arc::new(runner);
        let error = super::with_fixture_abort_after_bind(|| {
            super::exercise_mode_fixture_with(
                &fixture.home,
                &registration,
                "door-audit",
                Some(runner),
                &mut json!({}),
            )
        })
        .expect_err("injected failure after bind");
        assert_eq!(error.kind, "exercise-door-fixture");
        assert!(error.detail.contains("after socket bind"));
        let config = fixture.home.join(".config/loops/alpha");
        assert!(!fs::read_dir(config).expect("config entries").any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".door-fixture-")
        }));
        assert!(
            !fs::read_dir(&fixture.home)
                .expect("home entries")
                .any(|entry| entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".door-fixture-"))
        );
    }

    /// ´test:unit:door-capacity-refuses-seventeenth-peer´
    #[test]
    fn door_capacity_refuses_seventeenth_peer() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut grants = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..MAX_PEERS {
            let (client, mut server) = FixtureClient::pair().expect("fixture peer");
            grants.push(admit_peer(&active, &mut server).expect("slot"));
            peers.push((client, server));
        }
        let (mut client, mut server) = FixtureClient::pair().expect("overflow peer");
        client
            .send(&json!({"schema":2,"argv":[],"deadline_ms":1000}))
            .expect("overflow request");
        assert!(admit_peer(&active, &mut server).is_none());
        let reply = client.answer();
        assert_eq!(reply["reason"], "door-capacity-refusal");
        assert_eq!(reply["queue_state"], "no-queue");
        assert_eq!(reply["peer_limit"], 16);
        assert_eq!(reply["retry_after_seconds"], 120);
        assert_eq!(reply["status"], 125);
        assert_eq!(reply["ref_check"], "not-reached");
        assert!(reply["compute_exit_status"].is_null());
        assert!(reply["queue_wall_seconds"].is_null());
        for key in ["stdin_bytes", "stdout_bytes", "stderr_bytes"] {
            assert_eq!(reply[key], 0);
        }
        assert_eq!(
            super::final_line(&["fixture".into(), "cargo test".into()], &reply),
            Some(
                "door-capacity-refusal: peer_limit=16 retry_after=120s; no request was dispatched"
                    .into()
            )
        );
        let old_reply = json!({"type":"final", "reason":"door-capacity-refusal"});
        assert_eq!(
            super::final_line(&["fixture".into(), "cargo test".into()], &old_reply),
            Some("door-capacity-refusal".into())
        );
        let (closed, mut overflow) = UnixStream::pair().expect("early closing peer");
        drop(closed);
        assert!(admit_peer(&active, &mut overflow).is_none());
        assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), MAX_PEERS);
        drop(grants.pop().expect("one released slot"));
        assert_eq!(active.load(Ordering::Relaxed), MAX_PEERS - 1);
        let (mut next, mut next_server) = FixtureClient::pair().expect("next peer");
        let grant = admit_peer(&active, &mut next_server).expect("released slot");
        assert_eq!(active.load(Ordering::Relaxed), MAX_PEERS);
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        next.send(&json!({"schema":2,"argv":[],"deadline_ms":1000}))
            .expect("next request");
        serve_one_for_peer(&mut next_server, &registration, 3000).expect("next answer");
        assert_eq!(next.answer()["reason"], "door-compute-unregistered");
        drop(grant);
        drop(grants);
        drop(peers);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    /// ´test:unit:door-capacity-silent-peer-does-not-hold-accept-loop´
    #[test]
    fn door_capacity_silent_peer_does_not_hold_accept_loop() {
        let temp = tempfile::tempdir().expect("socket directory");
        let socket = temp.path().join("door.sock");
        let listener = UnixListener::bind(&socket).expect("capacity listener");
        let active = Arc::new(AtomicUsize::new(MAX_PEERS));
        let (progress, observed) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("silent excess peer");
            assert!(admit_peer(&active, &mut first).is_none());
            let (mut second, _) = listener.accept().expect("next excess peer");
            assert!(admit_peer(&active, &mut second).is_none());
            progress.send(()).expect("next peer answered");
        });
        let first = UnixStream::connect(&socket).expect("silent peer connection");
        let second = UnixStream::connect(&socket).expect("next peer connection");
        let next_answered = observed.recv_timeout(Duration::from_secs(5));
        first
            .shutdown(std::net::Shutdown::Both)
            .expect("release silent peer even on failure");
        drop(second);
        server.join().expect("capacity server");
        assert!(
            next_answered.is_ok(),
            "next peer did not receive an immediate answer"
        );
    }

    fn call_fixture_socket_when_ready(
        path: &std::path::Path,
        args: &[OsString],
        server: thread::JoinHandle<io::Result<(serde_json::Value, Vec<u8>)>>,
    ) -> Result<(serde_json::Value, serde_json::Value, Vec<u8>), String> {
        let until = Instant::now() + FIXTURE_HANG;
        let reply = loop {
            match stub_call(path, args, b"") {
                Ok(reply) => break reply,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    if server.is_finished() {
                        let result = server.join().map_err(|panic| {
                            format!("fixture server panicked before listener: {panic:?}")
                        })?;
                        return Err(format!(
                            "fixture server finished before listener: {result:?}; connect: {error}"
                        ));
                    }
                    if Instant::now() >= until {
                        return Err(format!("fixture listener did not become ready: {error}"));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(format!("fixture stub call: {error}")),
            }
        };
        let (response, body) = server
            .join()
            .map_err(|panic| format!("fixture server panicked: {panic:?}"))?
            .map_err(|error| format!("fixture server: {error}"))?;
        Ok((reply, response, body))
    }

    /// # Panics
    /// Panics only if the fixture fails to expose its server's own error.
    /// ´test:unit:fixture-socket-reports-server-failure-before-listener´
    #[test]
    fn fixture_socket_reports_server_failure_before_listener() {
        let fixture = tempfile::tempdir().expect("fixture");
        let path = fixture.path().join("never-listened.sock");
        let server = thread::spawn(|| Err(io::Error::other("fixture bind failed")));
        let error =
            call_fixture_socket_when_ready(&path, &[], server).expect_err("fixture server failure");
        assert!(error.contains("fixture bind failed"), "{error}");
    }

    /// # Panics
    /// Panics only if the fixture or its server fails to start or answer.
    /// ´test:unit:fixture-socket-binds-peer-and-keeps-exact-arguments´
    #[test]
    fn fixture_socket_binds_peer_and_keeps_exact_arguments() {
        let fixture = tempfile::tempdir().expect("fixture");
        let socket =
            crate::fixture_exec::fixture_socket_path(fixture.path().join("capability.sock"));
        let peer = nix::unistd::Uid::effective().as_raw();
        let row = json!({"name":"alpha","uid":41001});
        let registration =
            Registration::from_row(&row, "alpha", "R", peer, Scope::Work).expect("registration");
        let server_registration = registration;
        let server_socket = socket.clone();
        let server = thread::spawn(move || serve_socket(&server_socket, &server_registration));
        let args = [OsString::from("door-shape-probe"), OsString::from("R")];
        let (reply, response, body) =
            call_fixture_socket_when_ready(&socket, &args, server).expect("stub reply");
        assert_eq!(reply, response);
        assert_eq!(body, Vec::<u8>::new());
        assert_eq!(reply["reason"], "door-transport-pending");
        assert!(reply.get("registration").is_none());
        assert_eq!(reply["peer_uid"], peer);
        assert_eq!(reply["status"], 125);
        let review =
            Registration::from_row(&row, "alpha", "R", peer, Scope::Review).expect("review");
        assert_eq!(review.scope.name(), "review");
        let review_socket =
            crate::fixture_exec::fixture_socket_path(fixture.path().join("review.sock"));
        let server_path = review_socket.clone();
        let server = thread::spawn(move || serve_socket(&server_path, &review));
        let (reply, _, _) =
            call_fixture_socket_when_ready(&review_socket, &args, server).expect("review probe");
        assert_eq!(reply["reason"], "door-review-compute-refusal");
    }

    /// ´test:unit:door-host-peer-maps-to-recorded-review-worker´
    #[test]
    fn door_host_peer_maps_to_recorded_review_worker() {
        let host_peer = nix::unistd::Uid::effective().as_raw();
        let host_owner = host_peer.checked_add(1).expect("fixture owner");
        let source = format!("0 {host_owner} 1\n3000 100000 1\n3001 {host_peer} 1\n");
        let report = json!({"schema":1,"status":"door-socket-ready","uid_map":source});
        let map = super::decode_socket_group_report(&report.to_string(), host_owner, (3000, 2))
            .expect("private child map");
        let fixture = tempfile::tempdir().expect("run custody");
        let runs: std::os::fd::OwnedFd = File::open(fixture.path()).expect("held runs").into();
        crate::launch::publish_reservation(
            &crate::launch::reservation_path(fixture.path(), "migration-1"),
            &json!({"schema":1,"phase":"started","loop":"alpha","run":"migration-1",
                "worker_uid":3001,"door_scope":"review","plan":{"door":{"peer_uid":3001}}}),
        )
        .expect("recorded review reservation");
        let row = json!({"name":"alpha","uid":41001});
        let old_refusal = crate::launch::door_probe_registration(
            &runs,
            &row,
            "alpha",
            "migration-1",
            host_peer,
            (3000, 2),
            host_peer,
        )
        .expect_err("host-view UID is outside the recorded block");
        assert_eq!(old_refusal.detail, "peer is outside the allocated block");
        let (mut client, mut server) = FixtureClient::pair().expect("host socket peer");
        let worker = super::mapped_peer_uid(&server, &map).expect("mapped socket peer");
        assert_ne!(host_peer, worker);
        assert_eq!(worker, 3001);
        let registration = crate::launch::door_probe_registration(
            &runs,
            &row,
            "alpha",
            "migration-1",
            worker,
            (3000, 2),
            host_peer,
        )
        .expect("recorded review grant");
        client
            .send(
                &json!({"schema":2,"argv":[b"door-shape-probe".to_vec(), b"migration-1".to_vec()],
                "deadline_ms":1000}),
            )
            .expect("probe request");
        serve_one_for_peer(&mut server, &registration, worker).expect("review refusal");
        let announced = client.event("compute-deadline");
        assert_eq!(announced["type"], "compute-deadline");
        assert_eq!(announced["request_deadline_ms"], 1000);
        let reply = client.answer();
        assert_eq!(reply["reason"], "door-review-compute-refusal");
        assert_eq!(reply["peer_uid"], 3001);
    }

    /// ´test:unit:door-peer-map-refuses-incomplete-or-changed-child-reports´
    #[test]
    fn door_peer_map_refuses_incomplete_or_changed_child_reports() {
        for (report, kind, detail) in [
            (
                "not JSON".to_owned(),
                "door-socket",
                "private socket report is malformed",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready"}).to_string(),
                "door-socket",
                "private socket report shape differs",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 1\n3000 100000 2\n","extra":true}).to_string(),
                "door-socket",
                "private socket report shape differs",
            ),
            (
                json!({"schema":2,"status":"door-socket-ready","uid_map":"0 1000 1"}).to_string(),
                "door-socket",
                "private socket report differs",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":2}).to_string(),
                "door-socket",
                "private UID map is absent or over limit",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"bad"}).to_string(),
                "door-peer-map",
                "UID map line is malformed",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 x 1"}).to_string(),
                "door-peer-map",
                "UID map number is invalid",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 0"}).to_string(),
                "door-peer-map",
                "UID map ranges differ",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 1\n3000 100000 2\n3001 200000 1\n"}).to_string(),
                "door-peer-map",
                "UID map ranges differ",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 1\n3000 100000 2\n3002 100001 1\n"}).to_string(),
                "door-peer-map",
                "UID map ranges differ",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 1"}).to_string(),
                "door-peer-map",
                "owner or worker block is absent from UID map",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"1 1000 1\n3000 100000 2\n"}).to_string(),
                "door-peer-map",
                "owner or worker block is absent from UID map",
            ),
            (
                json!({"schema":1,"status":"door-socket-ready","uid_map":"0 1000 1\n3000 100000 1\n"}).to_string(),
                "door-peer-map",
                "owner or worker block is absent from UID map",
            ),
        ] {
            let refusal = super::decode_socket_group_report(&report, 1000, (3000, 2))
                .expect_err("changed report refused");
            assert_eq!((refusal.kind, refusal.detail.as_str()), (kind, detail));
        }
    }

    /// ´test:unit:door-peer-outside-owner-map-refuses-without-fallback´
    #[test]
    fn door_peer_outside_owner_map_refuses_without_fallback() {
        let host_peer = nix::unistd::Uid::effective().as_raw();
        let different_host = host_peer.checked_add(1).expect("other fixture uid");
        let map = super::PeerUidMap(vec![(0, u64::from(different_host), 1)]);
        let (_client, server) = UnixStream::pair().expect("peer socket");
        let refusal = super::mapped_peer_uid(&server, &map).expect_err("outside peer refused");
        assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(refusal.to_string(), "peer is outside the owner UID map");
    }

    /// ´test:unit:production-frame-ref-and-other-peer-refuse´
    #[test]
    fn production_frame_ref_and_other_peer_refuse() {
        let row = json!({"name":"alpha","uid":41001});
        let registration =
            Registration::from_row(&row, "alpha", "R", 3000, Scope::Work).expect("registration");
        for (peer, request, reason) in [
            (
                3000,
                json!({"schema":1,"argv":[],"mirror_ref":"refs/heads/lane/changed"}),
                "door-changed-ref-refusal",
            ),
            (3001, json!({"schema":1,"argv":[]}), "door-peer-refusal"),
        ] {
            let (mut client, mut server) = FixtureClient::pair().expect("fixture pair");
            client.send(&request).expect("request");
            let (response, _) =
                serve_one_for_peer(&mut server, &registration, peer).expect("served");
            assert_eq!(response["reason"], reason);
            assert_eq!(response["peer_uid"], peer);
            assert_eq!(client.answer(), as_sent(&response));
        }
    }

    /// ´test:unit:door-frame-deadline-bounds-a-trickling-peer´
    #[test]
    fn door_frame_deadline_bounds_a_trickling_peer() {
        let (mut client, server) = FixtureClient::pair().expect("fixture pair");
        let (read_done, hold_writer) = std::sync::mpsc::channel();
        let writer = thread::spawn(move || {
            client
                .write_all(&32_u32.to_be_bytes())
                .expect("frame length");
            for _ in 0..5 {
                thread::sleep(std::time::Duration::from_millis(15));
                if client.write_all(b"x").is_err() {
                    break;
                }
            }
            hold_writer
                .recv_timeout(Duration::from_secs(120))
                .expect("reader returned before writer closes");
        });
        let deadline = Instant::now() + std::time::Duration::from_millis(40);
        let mut reader = server;
        let result = super::frame_read_until(reader.wire(), deadline);
        read_done.send(()).expect("release writer after read");
        writer.join().expect("bounded writer");
        let error = result.expect_err("whole frame deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    /// ´test:unit:workspace-socket-reader-preserves-wire-and-legacy-bound´
    #[test]
    fn workspace_socket_reader_preserves_wire_and_legacy_bound() {
        let payload = " ".repeat(super::FRAME_LIMIT);
        for schema in [2, 3] {
            let (mut client, mut server) = FixtureClient::pair().expect("fixture pair");
            let wire = serde_json::to_vec(&json!({"schema":schema,"padding":payload}))
                .expect("request bytes");
            let writer = thread::spawn(move || {
                client
                    .write_all(
                        &u32::try_from(wire.len())
                            .expect("bounded length")
                            .to_be_bytes(),
                    )
                    .expect("frame length");
                client.write_all(&wire).expect("frame body");
                wire
            });
            let result = super::request_frame_read_until(
                server.wire(),
                Instant::now() + Duration::from_secs(5),
            );
            let original = writer.join().expect("writer");
            if schema == 3 {
                let (value, exact) = result.expect("workspace bound");
                assert_eq!(value["schema"], 3);
                assert_eq!(exact, original);
            } else {
                assert_eq!(
                    result.expect_err("legacy bound").kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }
}
