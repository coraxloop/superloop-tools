//! The registered socket boundary for outward worker calls.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
pub mod metadata;

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
    } else if reason == "door-request-concurrent" {
        Some(format!(
            "{reason}: waited={}s retry_after={}s; {ADMISSION_WINDOW}",
            reply["waited_seconds"], reply["retry_after_seconds"]
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
const ADMISSION_WAIT: Duration = Duration::from_secs(30);
const ADMISSION_POLL: Duration = Duration::from_millis(100);
const ADMISSION_REPLY_MARGIN: Duration = Duration::from_secs(2);
pub(crate) const FULL_STORE_REASON_PREFIX: &str = "door-requests-full-refusal: ";
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// The service and host exercises share this inode; never unlink a lock on release.
struct RequestGuard {
    _held: nix::fcntl::Flock<File>,
}

impl RequestGuard {
    fn acquire_wait(
        home: &Path,
        registration: &Registration,
        request: &Value,
        started: Instant,
    ) -> io::Result<(Option<Self>, Duration)> {
        let began = Instant::now();
        let remaining = Duration::from_millis(request["deadline_ms"].as_u64().unwrap_or(0))
            .saturating_sub(started.elapsed())
            .saturating_sub(ADMISSION_REPLY_MARGIN);
        let budget = remaining.min(ADMISSION_WAIT);
        loop {
            if let Some(guard) = Self::acquire(home, registration)? {
                return Ok((Some(guard), began.elapsed()));
            }
            #[cfg(test)]
            ADMISSION_CONTENDED.with(|slot| {
                if let Some(action) = slot.borrow_mut().take() {
                    action();
                }
            });
            let remaining = budget.saturating_sub(began.elapsed());
            if remaining.is_zero() {
                return Ok((None, began.elapsed()));
            }
            #[cfg(test)]
            if remaining <= ADMISSION_POLL {
                ADMISSION_LAST_POLL.with(|slot| {
                    if let Some(action) = slot.borrow_mut().take() {
                        action();
                    }
                });
            }
            thread::sleep(remaining.min(ADMISSION_POLL));
        }
    }

    fn acquire(home: &Path, registration: &Registration) -> io::Result<Option<Self>> {
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
        let name = format!("door-admission-{}.lock", registration.worker_uid);
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
        match Flock::lock(File::from(fd), FlockArg::LockExclusiveNonblock) {
            Ok(held) => Ok(Some(Self { _held: held })),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, error)) => Err(io::Error::from(error)),
        }
    }
}

#[cfg(test)]
thread_local! {
    static ADMISSION_LAST_POLL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static ADMISSION_CONTENDED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

const RETRY_AFTER_SECONDS: u64 = 30;
const ADMISSION_WINDOW: &str = "the door waited for admission held through effect and agent publication, possibly after the final reply; retry after 30 seconds";

fn concurrent_refusal(
    stream: &mut UnixStream,
    registration: &Registration,
    peer: u32,
    started: Instant,
    waited: Duration,
) -> io::Result<(Value, Vec<u8>)> {
    let _logged = writeln!(
        io::stderr().lock(),
        "door preflight: run={} check=door-request-concurrent",
        registration.run
    );
    let mut reply = transport::refusal(registration, peer, "door-request-concurrent", started);
    reply["admission_window"] = json!(ADMISSION_WINDOW);
    reply["waited_seconds"] = json!((waited.as_secs_f64() * 1000.0).round() / 1000.0);
    reply["retry_after_seconds"] = json!(RETRY_AFTER_SECONDS);
    frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
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
                "reason":"door-capacity-refusal","ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
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
    Ok(())
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
        "shape_key":format!("{class}:{}", operation.name()),"operation":operation.name(),
        "mirror_ref":registration.mirror_ref,"mode":setting["mode"],"floor":setting["floor"],
        "class_setting":setting["class"],"loop_setting":setting["loop"],
        "would_do":would_do,"effect":{"state":"pending","reason":null,"ref_check":null,
            "exit_status":null,"stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
            "queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
        "state":if waiting {json!("waiting")} else {Value::Null},
        // filed_at is decimal Unix epoch nanoseconds since 1970-01-01T00:00:00Z.
        "mark_reason":null,"review":null,"label":null,"filed_at":at.to_string()
    });
    if operation == transport::Operation::Compute {
        value["shape_key"] = json!(compute::shape(words));
        value["effect"]["compute"] = compute::pending(words);
    }
    crate::requests::judgement::initialize(&mut value);
    RequestRecord::decode(value).map_err(io::Error::other)
}

pub(crate) fn effect_from_final(reply: &Value) -> Value {
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

#[derive(Clone, Copy)]
enum Answer {
    Allow(f64),
    Refuse(f64),
    Deadline(f64),
    Disconnect(f64),
    ReadFailure(f64),
}

#[cfg(test)]
type RequestReadiness = Box<dyn FnOnce(&str) -> io::Result<Instant> + Send>;

#[cfg(test)]
thread_local! {
    static AFTER_WAIT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_WAIT_LOCK_TIMEOUT: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> = const { std::cell::RefCell::new(None) };
    static REQUEST_FILED: std::cell::RefCell<Option<std::sync::mpsc::Sender<String>>> = const { std::cell::RefCell::new(None) };
    static REQUEST_READY: std::cell::RefCell<Option<RequestReadiness>> = const { std::cell::RefCell::new(None) };
}

fn wait_answer(store: &Store, id: &str, stream: &UnixStream, deadline: Instant) -> Answer {
    let queued = Instant::now();
    let mut interval = Duration::from_millis(10);
    loop {
        let record = match store.waiting_request_until(id, deadline) {
            Ok(record) => record,
            Err(error) => {
                if crate::requests::store::is_lock_contention(&error) {
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
        match peer_disconnected(stream) {
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
    let (_request_guard, admission_error) = if peer == registration.worker_uid {
        match RequestGuard::acquire_wait(owner_home, registration, request, started) {
            Ok((Some(guard), _)) => (Some(guard), None),
            Ok((None, waited)) => {
                return concurrent_refusal(stream, registration, peer, started, waited).map(|_| ());
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
    let deadline = Instant::now() + Duration::from_secs(2);
    for bytes in diagnostic.as_bytes().chunks(8192) {
        frame_write_until(
            stream,
            &json!({"schema":2,"type":"stderr","bytes":bytes}),
            deadline,
        )?;
    }
    frame_write_until(stream, &reply, deadline)
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
    // Claim the authenticated box before any preflight or intent record write,
    // and retain it through the final effect publication and reply.
    let (_request_guard, admission_error) =
        if let Some(home) = owner_home.filter(|_| peer == registration.worker_uid) {
            match RequestGuard::acquire_wait(home, registration, request, started) {
                Ok((Some(guard), _)) => (Some(guard), None),
                Ok((None, waited)) => {
                    return concurrent_refusal(stream, registration, peer, started, waited);
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
    let args = transport::argument_bytes(request);
    let compute_candidate = args.as_deref().is_some_and(compute::candidate);
    let maximum = if compute_candidate {
        compute::DEADLINE_MS
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
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    }
    let Some(route) = route else {
        let reply = refuse("door-compute-unregistered");
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    };
    let words = if compute_candidate {
        match route.compute_words(args.as_deref().unwrap_or_default()) {
            Ok(words) => words,
            Err(reason) => {
                let reply = refuse(reason);
                frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
                return Ok((reply, Vec::new()));
            }
        }
    } else {
        Vec::new()
    };
    let Some(operation) = route.allowed(args.as_deref().unwrap_or_default(), registration) else {
        let reply = refuse("door-caller-authority-refusal");
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    };
    let Some(runner) = runner else {
        let reply = refuse("door-compute-unregistered");
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    };
    let bound_runner = transport::ComputeRunner {
        inner: runner,
        words: &words,
        deadline,
    };
    let runner: &dyn transport::Runner = if compute_candidate {
        &bound_runner
    } else {
        runner
    };
    let Some(owner_home) = owner_home else {
        let reply = refuse("door-requests-unregistered");
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
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
    let store = store.for_request(deadline).map_err(io::Error::other)?;
    let default_class = if compute_candidate { "compute" } else { "ssh" };
    let default_rubric = Rubric::decode(&json!({"schema":1,"class":default_class,
        "undecided_reason":"no registered rule for this operation","rules":[]}))
    .map_err(io::Error::other)?;
    let class = rubric.unwrap_or(&default_rubric).class();
    let setting = store.ensure_first_mode(class).map_err(io::Error::other)?;
    let shape_key = if compute_candidate {
        compute::shape(&words)
    } else {
        format!("{class}:{}", operation.name())
    };
    let (mut would_do, matched_rule, history) = rubric
        .map_or_else(
            || {
                store
                    .learned_judgement(class, operation.name(), &shape_key)
                    .or_else(|error| {
                        if crate::requests::store::is_lock_contention(&error) {
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
        .map_err(io::Error::other)?;
    let mode = match execute_command::policy::DoorMode::from_record(setting["mode"].as_str()) {
        Ok(mode) => mode.as_str(),
        Err(error) => {
            let reply = refuse(error.0);
            frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
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
        shape_record: history,
        rubric: String::new(),
    };
    let judge = |source: &Value| {
        let mut result = agent.map_or_else(
            || agent::RunnerOutcome::referral("failure", "door-agent-unconfigured", Instant::now()),
            |runner| match input.encode() {
                Ok(bytes) => {
                    runner.judge(&bytes, deadline.saturating_duration_since(Instant::now()))
                }
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
    value["matched_rule"] = matched_rule;
    let record = RequestRecord::decode(value).map_err(io::Error::other)?;
    let id = record.id().to_owned();
    let store = store.with_request_id(&id);
    let binding_source = record.value().clone();
    if let Err(error) = store.file(record) {
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
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    }
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
    if synchronous_agent {
        // The intent is durable before any vendor call, including audit.
        // record_agent merges under the store lock before publishing waiting.
        let (result, _verdict) = judge(&binding_source);
        if let Err(error) = store.record_agent(
            &id,
            &result,
            result.rubric_digest.as_deref(),
            configured_model,
        ) {
            let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
            let mut reply =
                transport::refusal(registration, peer, "door-request-record-refusal", started);
            reply["request_record_error"] = json!(error.line());
            reply["request_id"] = json!(id);
            frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
            return Ok((reply, Vec::new()));
        }
        would_do = json!({"decision":result.verdict,"reason":result.reason});
    }
    let decided_enforce =
        mode == "enforce" && matches!(would_do["decision"].as_str(), Some("allow" | "refuse"));
    let immediate = mode == "allow" || decided_enforce;
    if decided_enforce && would_do["decision"] == "refuse" {
        let mut reply = transport::refusal(registration, peer, "door-rubric-refusal", started);
        reply["would_do"] = would_do;
        reply["request_id"] = json!(id);
        let result = store
            .record_effect(&id, effect_from_final(&reply))
            .and_then(|_| store.publish_observed(&id));
        if let Err(error) = result {
            let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
            reply["reason"] = json!("door-record-incomplete");
            reply["request_record_error"] = json!(error.line());
        }
        frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
        return Ok((reply, Vec::new()));
    }
    if immediate {
        if mode == "allow" && miss && agent.is_some() {
            // The intent is admitted and durable before the judgement starts.
            // Scoped ownership keeps the call attached to this service handler;
            // the transport can execute and return its final frame immediately.
            return thread::scope(|scope| {
                let agent_task = scope.spawn(|| {
                    let (result, _) = judge(&binding_source);
                    store.record_agent(
                        &id,
                        &result,
                        result.rubric_digest.as_deref(),
                        configured_model,
                    )
                });
                let complete = |reply: &Value| {
                    store
                        .record_effect(&id, effect_from_final(reply))
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
                );
                let judgement = agent_task
                    .join()
                    .map_err(|_| io::Error::other("door-agent-task-panicked"))?;
                if let Err(error) = judgement {
                    let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                    return Err(io::Error::other(error));
                }
                if outcome.is_ok() {
                    store.publish_waiting(&id).map_err(io::Error::other)?;
                } else {
                    let _recorded = store.record_incomplete(
                        &registration.run,
                        &id,
                        "allow transport incomplete",
                    );
                }
                outcome.map(|reply| (reply, Vec::new()))
            });
        }
        let complete = |reply: &Value| {
            if let Err(error) = store.record_effect(&id, effect_from_final(reply)) {
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
        );
        if result.is_err() {
            let _recorded =
                store.record_incomplete(&registration.run, &id, "allow transport incomplete");
        }
        return result.map(|reply| (reply, Vec::new()));
    }
    let answer = wait_answer(&store, &id, stream, deadline);
    match answer {
        Answer::Allow(wall) => {
            let complete = |reply: &Value| {
                if let Err(error) = store.record_effect(&id, effect_from_final(reply)) {
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
            );
            if result.is_err() {
                let _recorded =
                    store.record_incomplete(&registration.run, &id, "audit transport incomplete");
            }
            result.map(|reply| (reply, Vec::new()))
        }
        Answer::ReadFailure(wall) => {
            let reply = queue_reply(
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
            frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
            Ok((reply, Vec::new()))
        }
        Answer::Refuse(wall) | Answer::Deadline(wall) | Answer::Disconnect(wall) => {
            let (reason, state, disconnected) = match answer {
                Answer::Refuse(_) => ("door-adjudicated-refusal", "refused", false),
                Answer::Deadline(_) => ("door-request-deadline", "deadline", false),
                Answer::Disconnect(_) => ("door-disconnect-refusal", "deadline", true),
                Answer::Allow(_) | Answer::ReadFailure(_) => unreachable!(),
            };
            let mut reply = queue_reply(registration, peer, reason, started, state, wall, &id);
            if let Err(error) = store.record_effect(&id, effect_from_final(&reply)) {
                let _recorded = store.record_incomplete(&registration.run, &id, error.kind);
                reply["reason"] = json!("door-record-incomplete");
                reply["request_record_error"] = json!(error.line());
            }
            if !disconnected {
                frame_write_until(stream, &reply, Instant::now() + Duration::from_secs(2))?;
            }
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
    let _agent = config::runner(&generation["agent"], Path::new("/"), loop_name)?;
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
    let agent_runner = Arc::new(config::runner(
        &generation["agent"],
        &owner_home,
        loop_name,
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
    settings.validate_grant(&owner_home, loop_name)?;
    let row = crate::plan::registry(&settings, loop_name)?;
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
        thread::spawn(move || {
            let _guard = guard;
            let started = Instant::now();
            let result = (|| {
                let uid = mapped_peer_uid(&stream, &peer_map)?;
                let request = frame_read_until(&mut stream, started + PEER_DEADLINE)?;
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
                    Ok(route) => Some(route),
                    Err(error) if error.kind == "door-compute-root-refusal" => {
                        return root_refusal(
                            &mut stream,
                            &registration,
                            uid,
                            &request,
                            &owner_home,
                            &error,
                            started,
                        );
                    }
                    Err(error) => {
                        let _logged = writeln!(io::stderr().lock(), "door route: {}", error.line());
                        None
                    }
                };
                serve_request_with_agent(
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
    let deadline = Instant::now() + Duration::from_secs(2);
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
    let server = thread::spawn(move || -> io::Result<(Value, u32)> {
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
        MAX_PEERS, Registration, Scope, admit_peer, completed_door_group, frame_read,
        frame_read_until, frame_write, frame_write_until, peer_uid, serve_one_for_peer,
        serve_request, serve_socket, stub_call,
    };
    use crate::door::transport::{HostRunner, Operation, Runner};
    use crate::requests::{
        Mode,
        modes::Rubric,
        store::{FixtureFault, Store, fixture_fault, fixture_file_cap, tests::Fixture},
        tests::waiting,
    };

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
                let (mut stream, _) = listener.accept().expect("peer");
                let request = frame_read(&mut stream).expect("request");
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
        generation["agent"] = json!({"source":"/fixture/door.toml","rubric_root":"/fixture","rubric_path":"/fixture/permissions/door.md","executable":"/fixture/codex","model":"fixture","effort":"medium","cap_ms":30000,"entry":"/fixture/entry","loop_home":"/fixture/home"});
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
        let refused = refused_socket_within(Duration::from_millis(5), || {
            attempts += 1;
            thread::sleep(Duration::from_millis(20));
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
            Command::new("/usr/bin/cat")
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
    ) -> (PathBuf, thread::JoinHandle<io::Result<serde_json::Value>>) {
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
        let server = thread::spawn(move || {
            super::REQUEST_FILED.with(|slot| *slot.borrow_mut() = filed);
            super::REQUEST_READY.with(|slot| *slot.borrow_mut() = ready);
            fixture_file_cap(cap);
            fixture_fault(fault);
            let (mut stream, _) = listener.accept()?;
            let started = Instant::now();
            let _socket_peer = peer_uid(&stream)?;
            let peer = 3000;
            let request = frame_read_until(&mut stream, started + Duration::from_secs(2))?;
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
                for _ in 0..2 {
                    let observed = Arc::clone(&observed);
                    // Keep the watcher live while the receive is waiting. Only
                    // its actual observation arms the unchanged 300 ms claim.
                    super::REQUEST_READY.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move |id| {
                            let setup = Instant::now() + Duration::from_secs(2);
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
                            Ok(Instant::now() + Duration::from_millis(300))
                        }));
                    });
                    let (runner, _, _) = counting_runner(&fixture);
                    let (socket, server) =
                        fixture_service(&fixture, runner, rubric(Some("allow")), 300, None);
                    let mut client = UnixStream::connect(&socket).expect("fixture receive");
                    frame_write_until(
                        &mut client,
                        &json!({"schema":2,"argv":[b"fixture".to_vec(),
                            b"git-receive-pack '~/mirrors/R.git'".to_vec()],"deadline_ms":300}),
                        Instant::now() + Duration::from_secs(2),
                    )
                    .expect("receive request");
                    client.shutdown(Shutdown::Write).expect("receive end");
                    let _reply = frame_read(&mut client).expect("receive frame");
                    server
                        .join()
                        .expect("service thread")
                        .expect("service reply");
                }
                let (runner, _, _) = counting_runner(&fixture);
                let (socket, server) = fixture_service(&fixture, runner, rubric(None), 2000, None);
                let mut echo = send_probe(&socket, 2000);
                let echo_frame = frame_read(&mut echo).expect("echo frame");
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

    fn send_probe(socket: &std::path::Path, deadline_ms: u64) -> UnixStream {
        let mut client = UnixStream::connect(socket).expect("fixture connect");
        frame_write_until(
            &mut client,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":deadline_ms}),
            Instant::now() + Duration::from_secs(2),
        )
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
        super::REQUEST_READY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_| {
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
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 5000, None);
        let mut client = UnixStream::connect(socket).expect("second connection");
        frame_write(
            &mut client,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":5000}),
        )
        .expect("second request");
        let deadline = Instant::now() + Duration::from_secs(4);
        while calls.load(Ordering::Relaxed) == 0 {
            assert!(Instant::now() < deadline, "second command never started");
            thread::sleep(Duration::from_millis(5));
        }
        // Seeing stdout proves spawn's custody read has finished; the child
        // stays live on stdin while the sibling takes the record lock.
        client.write_all(b"x").expect("running command input");
        assert_eq!(
            frame_read(&mut client).expect("running command output")["type"],
            "stdout"
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
                    }));
                });
                sibling_store
                    .record_effect(sibling_id, effect)
                    .expect("sibling complete")
            });
            held_rx
                .recv_timeout(Duration::from_secs(4))
                .expect("sibling holds lock");
            client
                .shutdown(Shutdown::Write)
                .expect("second command finishes");
            let reply = frame_read(&mut client).expect("second final frame");
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
        let (mut server, mut worker) = UnixStream::pair().expect("worker connection");
        let started = Instant::now();
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE
            .with(|bound| bound.set(Some(Duration::from_millis(30))));
        let error = serve_request(
            &mut server,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":30}),
            Some(&route),
            Some(&runner),
            Some(&fixture.home),
            Some(&rubric(Some("allow"))),
            Some(&store),
            started,
        )
        .expect_err("admission lock deadline");
        crate::requests::store::WRITER_LOCK_WAIT_OVERRIDE.with(|bound| bound.set(None));
        let reply = super::connection_refusal(&error, started);
        frame_write(&mut server, &reply).expect("production connection refusal");
        let reply = frame_read(&mut worker).expect("worker final frame");
        assert_eq!(reply["reason"], "door-request-refusal");
        let line = super::final_line(&["fixture".into(), "git status --short".into()], &reply)
            .expect("worker diagnostic");
        assert!(line.contains("request lock:"), "{line}");
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
            Some(format!(
                "door-request-concurrent: waited=1.001s retry_after=30s; {}",
                super::ADMISSION_WINDOW
            ))
        );
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
        let (socket, server) =
            fixture_service(fixture, runner, fixture_class_rubric(decision), 2000, None);
        let mut client = send_probe(&socket, 2000);
        // Rendezvous after the production store write releases its lock. Keep
        // the former 100 x 10 ms wait bound without polling unrelated records.
        let id = request
            .recv_timeout(Duration::from_secs(1))
            .expect("fixture request filed");
        if let Some(treatment) = answer {
            label(&store, &id, treatment);
        }
        let _reply = frame_read(&mut client).expect("fixture final frame");
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
        serve_request(
            &mut stream,
            &registration,
            3000,
            &json!({"schema":2,"argv":[b"door-attribution-probe"],"deadline_ms":100}),
            Some(&route),
            Some(&runner),
            Some(&fixture.home),
            None,
            Some(&store),
            Instant::now(),
        )
        .expect("recorded deadline");
        let rows = store.list_run("R").expect("record");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value()["would_do"]["decision"], "undecided");
        assert!(
            rows[0].value()["would_do"]["reason"]
                .as_str()
                .expect("reason")
                .contains("requests-learned-index")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// ´test:unit:door-unprovisioned-estate-referral-has-no-effect´
    #[test]
    fn door_unprovisioned_estate_referral_has_no_effect() {
        struct Estate(&'static str, &'static str);
        impl super::agent::AgentRunner for Estate {
            fn judge(&self, _: &[u8], _: Duration) -> super::agent::RunnerOutcome {
                super::agent::RunnerOutcome::referral(self.0, self.1, Instant::now())
            }
        }
        let cases = [
            ("verdict", "estate judgement needed"),
            ("timeout", "door-agent-timeout"),
            ("failure", "door-agent-call-failed"),
            ("invalid-output", "door-agent-invalid-output"),
            ("timeout", "door-agent-no-budget"),
            ("failure", "door-rubric-unavailable"),
            ("failure", "door-agent-sign-in-unavailable"),
        ];
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
            let (mut stream, mut peer) = UnixStream::pair().expect("socket pair");
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
                Some(&Estate(status, reason)),
                None,
                Instant::now(),
            )
            .expect("loop review refusal");
            assert_eq!(reply["reason"], "door-adjudicated-refusal");
            let wire = frame_read(&mut peer).expect("worker reply");
            for field in ["reason", "request_id", "queue_state", "status"] {
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
            let (mut stream, mut peer) = UnixStream::pair().expect("socket pair");
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
            assert_eq!(
                frame_read(&mut peer).expect("worker receives refusal"),
                reply
            );
            assert!(rows[0].value()["agent_status"].is_null());
            assert!(rows[0].value()["state"].is_null());
            assert_incomplete(&fixture, rows[0].id());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    /// ´test:unit:door-audit-label-precedes-effect´
    #[test]
    fn door_audit_label_precedes_effect() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let (runner, calls, states) = counting_runner(&fixture);
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
        let mut client = send_probe(&socket, 2000);
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
        let final_frame = frame_read(&mut client).expect("final frame");
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
        let fixture = Fixture::new();
        fixture.set_floor("allow");
        let store = fixture.store();
        set_fixture_mode(&store, crate::requests::Mode::Allow);
        let (runner, calls, states) = counting_runner(&fixture);
        let (socket, server) = fixture_service(&fixture, runner, rubric(Some("allow")), 2000, None);
        let mut client = send_probe(&socket, 2000);
        let final_frame = frame_read(&mut client).expect("final frame");
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
            let mut client = send_probe(&socket, 2000);
            if decision.is_none() {
                let id = wait_filed(&store);
                assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
                label(&store, &id, "allow");
            }
            let final_frame = frame_read(&mut client).expect("final frame");
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
            let deadline_ms = if disconnect { 2000 } else { 120 };
            let (socket, server) =
                fixture_service(&fixture, runner, rubric(None), deadline_ms, None);
            let mut client = send_probe(&socket, deadline_ms);
            let id = wait_filed(&store);
            if disconnect {
                drop(client);
            } else {
                let final_frame = frame_read(&mut client).expect("deadline frame");
                assert_eq!(final_frame["reason"], "door-request-deadline");
                assert_eq!(final_frame["queue_state"], "deadline");
            }
            server.join().expect("service").expect("reply");
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
            let mut client = send_probe(&socket, 2000);
            let final_frame = frame_read(&mut client).expect("full store frame");
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
        let mut client = send_probe(&socket, 2000);
        let id = wait_filed(&store);
        label(&store, &id, "refuse");
        let reply = frame_read(&mut client).expect("refusal frame");
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
            let mut client = send_probe(&socket, 2000);
            let id = wait_filed(&store);
            if !allow {
                label(&store, &id, "allow");
            }
            let reply = frame_read(&mut client).expect("incomplete final frame");
            server.join().expect("service").expect("incomplete reply");
            assert_eq!(reply["status"], 125);
            assert_eq!(reply["reason"], "door-record-incomplete");
            assert_eq!(reply["compute_exit_status"], 0);
            assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
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
            let mut client = send_probe(&socket, 2000);
            let reply = frame_read(&mut client).expect("incomplete enforce frame");
            server.join().expect("service").expect("reply");
            assert_eq!(reply["reason"], "door-record-incomplete");
            assert_eq!(reply["status"], 125);
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
            let mut client = send_probe(&socket, 2000);
            let reply = frame_read(&mut client).expect("typed refusal");
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
            let deadline_ms = if answer == "deadline" { 120 } else { 2000 };
            let (socket, server) = fixture_service_with(
                &fixture,
                runner,
                rubric(None),
                deadline_ms,
                None,
                Some(fault),
                true,
            );
            let mut client = send_probe(&socket, deadline_ms);
            let id = wait_filed(&store);
            if answer == "refuse" {
                label(&store, &id, "refuse");
            }
            if answer == "disconnect" {
                drop(client);
            } else {
                let reply = frame_read(&mut client).expect("wait error frame");
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
            server.join().expect("service").expect("wait outcome");
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
            let (socket, server) = fixture_service(&fixture, runner, rubric(None), 2000, None);
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
                    .is_some_and(|wall| wall > 0.0)
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
        let (socket, server) = fixture_service(&fixture, runner, rubric(None), 2000, None);
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
                                .expect("rendezvous released readers before writer admission");
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
            // outside waiting_request. Resume them before the write so their
            // sized-run polls and backoff contend with writer admission.
            for _ in 0..16 {
                read_rx
                    .recv_timeout(Duration::from_secs(120))
                    .expect("every reader reached polling boundary");
            }
            for waiter in resume {
                waiter
                    .send(())
                    .expect("resume readers before writer admission");
            }
            let started = Instant::now();
            store
                .triage(
                    "R",
                    &[json!({"id":"R:1","action":"adjudicate",
            "treatment":"allow","reason":"sized fixture answer"})],
                    "fixture owner",
                    &super::now_nanos().to_string(),
                )
                .expect("writer admits answer");
            let writer_wall = started.elapsed();
            let longest = waiters
                .into_iter()
                .map(|waiter| {
                    let (answer, wall) = waiter.join().expect("waiter");
                    assert!(matches!(answer, super::Answer::Allow(_)));
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
            assert!(writer_wall < Duration::from_secs(15));
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
            let mut client = send_probe(&socket, 2000);
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
            let _reply = frame_read(&mut client).expect("final frame");
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
        let mut client = send_probe(&socket, 2000);
        let _reply = frame_read(&mut client).expect("allow frame");
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
            let (client, mut server) = UnixStream::pair().expect("fixture peer");
            grants.push(admit_peer(&active, &mut server).expect("slot"));
            peers.push((client, server));
        }
        let (mut client, mut server) = UnixStream::pair().expect("overflow peer");
        assert!(admit_peer(&active, &mut server).is_none());
        let reply = frame_read(&mut client).expect("typed capacity reply");
        assert_eq!(reply["reason"], "door-capacity-refusal");
        assert_eq!(reply["queue_state"], "no-queue");
        let (closed, mut overflow) = UnixStream::pair().expect("early closing peer");
        drop(closed);
        assert!(admit_peer(&active, &mut overflow).is_none());
        assert_eq!(active.load(std::sync::atomic::Ordering::Relaxed), MAX_PEERS);
        drop(grants);
        drop(peers);
        let (mut next, mut next_server) = UnixStream::pair().expect("next peer");
        let _grant = admit_peer(&active, &mut next_server).expect("released slot");
        let registration = Registration::from_row(
            &json!({"name":"alpha","uid":41001}),
            "alpha",
            "R",
            3000,
            Scope::Work,
        )
        .expect("fixture registration");
        frame_write(&mut next, &json!({"schema":2,"argv":[],"deadline_ms":1000}))
            .expect("next request");
        serve_one_for_peer(&mut next_server, &registration, 3000).expect("next answer");
        assert_eq!(
            frame_read(&mut next).expect("next final")["reason"],
            "door-compute-unregistered"
        );
    }

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
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(2));
        }
        let reply = stub_call(
            &socket,
            &[OsString::from("door-shape-probe"), OsString::from("R")],
            b"",
        )
        .expect("stub reply");
        let (response, body) = server.join().expect("server thread").expect("served");
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
        for _ in 0..100 {
            if review_socket.exists() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(2));
        }
        let reply = stub_call(
            &review_socket,
            &[OsString::from("door-shape-probe"), OsString::from("R")],
            b"",
        )
        .expect("review probe");
        assert_eq!(reply["reason"], "door-review-compute-refusal");
        server
            .join()
            .expect("review server")
            .expect("served review");
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
        let (mut client, mut server) = UnixStream::pair().expect("host socket peer");
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
        frame_write(
            &mut client,
            &json!({"schema":2,"argv":[b"door-shape-probe".to_vec(), b"migration-1".to_vec()],
                "deadline_ms":1000}),
        )
        .expect("probe request");
        serve_one_for_peer(&mut server, &registration, worker).expect("review refusal");
        let reply = frame_read(&mut client).expect("typed reply");
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
            let (mut client, mut server) = UnixStream::pair().expect("fixture pair");
            frame_write(&mut client, &request).expect("request");
            let (response, _) =
                serve_one_for_peer(&mut server, &registration, peer).expect("served");
            assert_eq!(response["reason"], reason);
            assert_eq!(response["peer_uid"], peer);
            assert_eq!(frame_read(&mut client).expect("reply"), response);
        }
    }

    /// ´test:unit:door-frame-deadline-bounds-a-trickling-peer´
    #[test]
    fn door_frame_deadline_bounds_a_trickling_peer() {
        let (mut client, mut server) = UnixStream::pair().expect("fixture pair");
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
        });
        let deadline = Instant::now() + std::time::Duration::from_millis(40);
        let error =
            super::frame_read_until(&mut server, deadline).expect_err("whole frame deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        writer.join().expect("bounded writer");
    }
}
