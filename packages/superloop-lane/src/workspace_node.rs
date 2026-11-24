//! Protocol-one node entry for an admitted workspace command.
//! The door owns admission; this entry verifies the received execution context.
use crate::workspace_executor::{ExecutionMeasurements, PreparedExecution, StartFailure};
use execute_command::workspace::{Envelope, Grant, Measurement, Outcome, canonical_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

/// An eight MiB frame accommodates the one MiB envelope after JSON byte encoding.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// The legacy door's aggregate child-output ceiling.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const OUTPUT_CHUNK: usize = 8192;
const CONTROL_SILENCE: Duration = Duration::from_secs(120);
const START_WAIT: Duration = Duration::from_secs(10);
const OUTPUT_WRITE_BOUND: Duration = Duration::from_secs(120);
const OUTPUT_DRAIN_BOUND: Duration = Duration::from_secs(2);
const OUTPUT_DRAIN_TOTAL: Duration = Duration::from_secs(120);
const OUTPUT_QUEUE: usize = 2;

const CAUSE_NONE: u8 = 0;
const CAUSE_STOP: u8 = 1;
const CAUSE_INPUT_GONE: u8 = 2;
const CAUSE_SILENCE: u8 = 3;
const CAUSE_MALFORMED: u8 = 4;
const CAUSE_OUTPUT_LIMIT: u8 = 5;

const fn end_reason(cause: u8, outcome: &Outcome, incomplete: bool) -> &'static str {
    match cause {
        CAUSE_OUTPUT_LIMIT => "node-output-limit",
        _ if incomplete => "node-output-incomplete",
        CAUSE_STOP => "node-stopped",
        CAUSE_INPUT_GONE => "node-input-closed",
        CAUSE_SILENCE => "node-heartbeat-silence",
        CAUSE_MALFORMED => "node-malformed-control",
        _ if matches!(outcome, Outcome::TimedOut) => "node-deadline",
        _ => "node-complete",
    }
}

#[derive(Clone, Copy)]
struct StreamBounds {
    start_wait: Duration,
    silence: Duration,
    output_limit: usize,
    write: Duration,
    drain: Duration,
}

impl Default for StreamBounds {
    fn default() -> Self {
        Self {
            start_wait: START_WAIT,
            silence: CONTROL_SILENCE,
            output_limit: MAX_OUTPUT_BYTES,
            write: OUTPUT_WRITE_BOUND,
            drain: OUTPUT_DRAIN_BOUND,
        }
    }
}

struct StreamState {
    cancelled: AtomicBool,
    finished: AtomicBool,
    stop_readers: AtomicBool,
    cause: AtomicU8,
    bytes_seen: AtomicUsize,
    last_byte_read: Mutex<Option<Instant>>,
    output_limit: usize,
}

impl StreamState {
    const fn new(output_limit: usize) -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            stop_readers: AtomicBool::new(false),
            cause: AtomicU8::new(CAUSE_NONE),
            bytes_seen: AtomicUsize::new(0),
            last_byte_read: Mutex::new(None),
            output_limit,
        }
    }
}

/// The one request frame. The grant and placement are snapshots, not authority
/// supplied by the worker: the door must read them from its held reservation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCall {
    pub protocol: u8,
    pub request_id: String,
    pub nonce: String,
    pub node: String,
    pub grant: Value,
    pub placement: Value,
    pub envelope: Value,
}

fn refusal(kind: &str, detail: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{kind}: {detail}"))
}

/// Write one bounded length-prefixed JSON frame.
/// # Errors
/// Refuses a frame that cannot be encoded or exceeds the protocol bound.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, frame: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "frame length differs",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

#[allow(unsafe_code)]
pub(crate) fn write_frame_before<W: AsRawFd, T: Serialize>(
    writer: &W,
    frame: &T,
    deadline: Instant,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "frame length differs",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    let mut encoded = Vec::with_capacity(bytes.len() + 4);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(&bytes);
    let fd = writer.as_raw_fd();
    // SAFETY: the held writer owns this descriptor throughout the call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: only this thread writes the held output descriptor after the acknowledgement.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    while offset < encoded.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "workspace route output stalled",
            ));
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = i32::try_from(remaining.as_millis().min(200)).unwrap_or(200);
        // SAFETY: poll observes the held output descriptor without retaining it.
        let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: encoded remains alive and the descriptor is held for this call.
        let count = unsafe {
            libc::write(
                fd,
                encoded[offset..].as_ptr().cast(),
                encoded.len() - offset,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        offset += usize::try_from(count).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Read one bounded length-prefixed JSON frame.
/// # Errors
/// Refuses an empty, oversized, truncated or malformed frame.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Value> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let size = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "frame length differs",
        ));
    }
    let mut bytes = vec![0_u8; size];
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| refusal("door-workspace-protocol-refusal", error))
}

/// Read a route frame before one outer deadline, including a trickling body.
/// # Errors
/// Refuses a closed, stalled, oversized or malformed frame.
#[allow(unsafe_code)]
pub(crate) fn read_frame_before<R: Read + AsRawFd>(
    reader: &mut R,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<Value> {
    let fd = reader.as_raw_fd();
    // SAFETY: the caller holds this descriptor through the read.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut exact = |bytes: &mut [u8]| -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            if stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "door request stopped",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "node frame deadline",
                ));
            }
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = i32::try_from(remaining.as_millis().min(200)).unwrap_or(200);
            // SAFETY: poll observes the caller-held descriptor.
            let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            match reader.read(&mut bytes[offset..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(count) => offset += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    };
    let mut length = [0_u8; 4];
    exact(&mut length)?;
    let size = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "frame length differs",
        ));
    }
    let mut bytes = vec![0_u8; size];
    exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| refusal("door-workspace-protocol-refusal", error))
}

/// Read the node registry name from its installed, regular, owner-held file.
/// # Errors
/// Refuses a link, a writable or foreign file, or a malformed name.
pub fn installed_node_name(path: &Path, owner: u32) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| refusal("door-workspace-context-differs", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| refusal("door-workspace-context-differs", error))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o004 == 0
        || metadata.nlink() != 1
    {
        return Err(refusal(
            "door-workspace-context-differs",
            "node identity metadata differs",
        ));
    }
    let mut raw = String::new();
    file.take(82)
        .read_to_string(&mut raw)
        .map_err(|error| refusal("door-workspace-context-differs", error))?;
    let name = raw.strip_suffix('\n').unwrap_or(&raw);
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(refusal(
            "door-workspace-context-differs",
            "node identity name differs",
        ));
    }
    Ok(name.to_owned())
}

fn checked_call(frame: &Value, identity: &str) -> io::Result<(NodeCall, Value, Envelope, String)> {
    let call: NodeCall = serde_json::from_value(frame.clone())
        .map_err(|error| refusal("door-workspace-protocol-refusal", error))?;
    if call.protocol != 1
        || call.request_id.is_empty()
        || call.request_id.len() > 160
        || call.nonce.is_empty()
        || call.nonce.len() > 64
        || !call
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || !call.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "version or call identifier differs",
        ));
    }
    if call.node != identity {
        return Err(refusal(
            "door-workspace-context-differs",
            "installed node identity differs",
        ));
    }
    let envelope = Envelope::decode(call.envelope.clone())
        .map_err(|error| refusal(error.kind, error.detail))?;
    let grant =
        Grant::decode(call.grant.clone()).map_err(|error| refusal(error.kind, error.detail))?;
    let digest = grant
        .digest()
        .map_err(|error| refusal(error.kind, error.detail))?;
    if grant.node != identity || envelope.grant_digest != digest {
        return Err(refusal(
            "door-workspace-context-differs",
            "node or grant digest differs",
        ));
    }
    let reservation = json!({
        "loop": grant.loop_name,
        "run": grant.run,
        "plan": {
            "loop": grant.loop_name,
            "run": grant.run,
            "compute_workspace": {"grant": grant, "digest": digest},
            "compute_placement": call.placement,
        }
    });
    let snapshot = crate::plan::workspace_snapshot(&reservation["plan"])
        .map_err(|error| refusal("door-workspace-context-differs", error.line()))?
        .ok_or_else(|| refusal("door-workspace-context-differs", "grant absent"))?;
    crate::placement::snapshot(&reservation["plan"], Some(&snapshot))
        .map_err(|error| refusal("door-workspace-context-differs", error.line()))?
        .ok_or_else(|| refusal("door-workspace-context-differs", "placement absent"))?;
    // A same-connection acknowledgement is a diagnostic identity, not a
    // cryptographic binding against the node account (proto:superlooplane:workspace-executor-call).
    let digest = canonical_digest(frame).map_err(|error| refusal(error.kind, error.detail))?;
    let frame_handle = digest
        .get(..16)
        .ok_or_else(|| refusal("door-workspace-protocol-refusal", "frame handle differs"))?
        .to_owned();
    Ok((call, reservation, envelope, frame_handle))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    schema: u8,
    #[serde(rename = "type")]
    kind: String,
}

#[allow(unsafe_code)]
fn read_control<R: Read + AsRawFd>(
    reader: &mut R,
    finished: &AtomicBool,
    deadline: Instant,
) -> io::Result<Option<Control>> {
    fn exact<R: Read + AsRawFd>(
        reader: &mut R,
        mut bytes: &mut [u8],
        finished: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<bool> {
        while !bytes.is_empty() {
            if finished.load(Ordering::Acquire) {
                return Ok(false);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "workspace heartbeat silence",
                ));
            }
            let timeout = i32::try_from(remaining.as_millis().min(200)).unwrap_or(200);
            let mut descriptor = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            // SAFETY: the held reader owns this descriptor for the duration of poll.
            let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let count = reader.read(bytes)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "workspace route closed",
                ));
            }
            bytes = &mut bytes[count..];
        }
        Ok(true)
    }
    let mut length = [0_u8; 4];
    if !exact(reader, &mut length, finished, deadline)? {
        return Ok(None);
    }
    let size = usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "control length differs",
        ));
    }
    let mut bytes = vec![0_u8; size];
    if !exact(reader, &mut bytes, finished, deadline)? {
        return Ok(None);
    }
    let control: Control = serde_json::from_slice(&bytes)
        .map_err(|error| refusal("door-workspace-protocol-refusal", error))?;
    if control.schema != 1 {
        return Err(refusal(
            "door-workspace-protocol-refusal",
            "control version differs",
        ));
    }
    Ok(Some(control))
}

enum Event {
    Output(&'static str, Vec<u8>),
    Closed(bool),
    Done(ExecutionMeasurements, Instant),
}

#[allow(clippy::too_many_arguments)] // Each argument is one distinct terminal frame observation.
fn terminal_frame(
    call: &NodeCall,
    result: &Measurement,
    steps: &[Measurement],
    output_bytes: usize,
    reason: &str,
    output_incomplete: bool,
    child_started: bool,
    start_failure: Option<&StartFailure>,
) -> Value {
    json!({
        "schema":1,"type":"terminal","request_id":call.request_id,
        "nonce":call.nonce,"result":result,"steps":steps,
        "output_bytes":output_bytes,"reason":reason,
        "output_incomplete":output_incomplete,
        "child_started":child_started,
        "start_failure":start_failure,
    })
}

fn ended_before_spawn<W: Write>(output: &mut W, call: &NodeCall, cause: u8) -> io::Result<()> {
    write_frame(
        output,
        &terminal_frame(
            call,
            &Measurement {
                outcome: Outcome::TimedOut,
                wall_seconds: Some(0.0),
                user_cpu_seconds: None,
                system_cpu_seconds: None,
            },
            &[],
            0,
            end_reason(cause, &Outcome::TimedOut, false),
            false,
            false,
            None,
        ),
    )
}

#[allow(unsafe_code)]
fn read_child_output(
    descriptor: OwnedFd,
    kind: &'static str,
    events: &mpsc::SyncSender<Event>,
    state: &StreamState,
) {
    let mut reader = File::from(descriptor);
    let mut bytes = [0_u8; OUTPUT_CHUNK];
    loop {
        if state.stop_readers.load(Ordering::Acquire) {
            let _sent = events.send(Event::Closed(true));
            return;
        }
        let mut poll = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: the reader holds the descriptor until this call returns.
        let ready = unsafe { libc::poll(&raw mut poll, 1, 100) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let _sent = events.send(Event::Closed(true));
            return;
        }
        if ready == 0 {
            continue;
        }
        match reader.read(&mut bytes) {
            Ok(0) => {
                let _sent = events.send(Event::Closed(false));
                return;
            }
            Ok(count) => {
                *state
                    .last_byte_read
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
                let total = state
                    .bytes_seen
                    .fetch_add(count, Ordering::AcqRel)
                    .saturating_add(count);
                if total > state.output_limit {
                    let _first = state.cause.compare_exchange(
                        CAUSE_NONE,
                        CAUSE_OUTPUT_LIMIT,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    state.cancelled.store(true, Ordering::Release);
                    let _sent = events.send(Event::Closed(true));
                    return;
                }
                if events
                    .send(Event::Output(kind, bytes[..count].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                let _sent = events.send(Event::Closed(true));
                return;
            }
        }
    }
}

fn monitor_control<R: Read + AsRawFd>(input: &mut R, state: &StreamState, silence: Duration) {
    let mut deadline = Instant::now() + silence;
    while !state.finished.load(Ordering::Acquire) {
        match read_control(input, &state.finished, deadline) {
            Ok(Some(Control { kind, .. })) if kind == "heartbeat" => {
                deadline = Instant::now() + silence;
            }
            Ok(None) => break,
            ending => {
                let reason = match ending {
                    Ok(Some(Control { kind, .. })) if kind == "stop" => CAUSE_STOP,
                    Err(ref error) if error.kind() == io::ErrorKind::TimedOut => CAUSE_SILENCE,
                    Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        CAUSE_INPUT_GONE
                    }
                    _ => CAUSE_MALFORMED,
                };
                let _first = state.cause.compare_exchange(
                    CAUSE_NONE,
                    reason,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                state.cancelled.store(true, Ordering::Release);
                break;
            }
        }
    }
}

fn prestart_timeout_cause(start_bound: Instant, command_deadline: Instant) -> u8 {
    if command_deadline <= start_bound {
        CAUSE_NONE
    } else {
        CAUSE_SILENCE
    }
}

fn drain_expired(
    command_ended: Instant,
    last_byte_read: Option<Instant>,
    now: Instant,
    idle_bound: Duration,
) -> bool {
    let idle_from = last_byte_read.unwrap_or(command_ended).max(command_ended);
    now.saturating_duration_since(idle_from) >= idle_bound
        || now.saturating_duration_since(command_ended) >= OUTPUT_DRAIN_TOTAL
}

fn relay_events<W: AsRawFd>(
    receiver: mpsc::Receiver<Event>,
    output: &W,
    call: &NodeCall,
    state: &StreamState,
    bounds: StreamBounds,
) -> io::Result<()> {
    let mut streams_closed = 0_u8;
    let mut result = None;
    let mut command_ended = None;
    let mut incomplete = false;
    let mut held_output = false;
    while streams_closed < 2 || result.is_none() {
        if let Some(ended) = command_ended {
            let last_byte = *state
                .last_byte_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if drain_expired(ended, last_byte, Instant::now(), bounds.drain) {
                state.stop_readers.store(true, Ordering::Release);
                incomplete = streams_closed < 2;
                held_output |= incomplete;
            }
        }
        let event = if result.is_some() {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(error) => return Err(io::Error::other(error)),
            }
        } else {
            receiver.recv().map_err(io::Error::other)?
        };
        match event {
            Event::Output(kind, bytes) => {
                if let Err(error) = write_frame_before(
                    output,
                    &json!({"schema":1,"type":kind,"bytes":bytes}),
                    Instant::now() + bounds.write,
                ) {
                    state.cancelled.store(true, Ordering::Release);
                    state.finished.store(true, Ordering::Release);
                    state.stop_readers.store(true, Ordering::Release);
                    drop(receiver);
                    return Err(error);
                }
            }
            Event::Closed(forced) => {
                streams_closed += 1;
                incomplete |= forced;
            }
            Event::Done(measured, ended) => {
                result = Some(measured);
                state.finished.store(true, Ordering::Release);
                command_ended = Some(ended);
            }
        }
    }
    let measured = result.ok_or_else(|| io::Error::other("measurements absent"))?;
    let cause = state.cause.load(Ordering::Acquire);
    let reason = if cause == CAUSE_OUTPUT_LIMIT {
        "node-output-limit"
    } else if held_output || incomplete {
        "node-output-incomplete"
    } else if measured.start_failure.is_some() {
        "node-start-failed"
    } else {
        end_reason(cause, &measured.result.outcome, incomplete)
    };
    write_frame_before(
        output,
        &terminal_frame(
            call,
            &measured.result,
            &measured.steps,
            state.bytes_seen.load(Ordering::Acquire),
            reason,
            incomplete,
            measured.child_started,
            measured.start_failure.as_ref(),
        ),
        Instant::now() + bounds.write,
    )
}

fn stream_execution<R: Read + AsRawFd + Send, W: Write + AsRawFd>(
    mut input: R,
    output: &W,
    call: &NodeCall,
    prepared: PreparedExecution,
    bounds: StreamBounds,
) -> io::Result<()> {
    let state = StreamState::new(bounds.output_limit);
    let (sender, receiver) = mpsc::sync_channel::<Event>(OUTPUT_QUEUE);
    std::thread::scope(|scope| -> io::Result<()> {
        scope.spawn(|| monitor_control(&mut input, &state, bounds.silence));
        let (out_read, out_write) = nix::unistd::pipe()?;
        let (err_read, err_write) = nix::unistd::pipe()?;
        let out_writer = File::from(out_write);
        let err_writer = File::from(err_write);
        for (kind, descriptor) in [("stdout", out_read), ("stderr", err_read)] {
            let events = sender.clone();
            let state = &state;
            scope.spawn(move || read_child_output(descriptor, kind, &events, state));
        }
        let events = sender.clone();
        let state = &state;
        scope.spawn(move || {
            let measured = prepared.run_admitted(&out_writer, &err_writer, &state.cancelled);
            let ended = Instant::now();
            drop(out_writer);
            drop(err_writer);
            let _sent = events.send(Event::Done(measured, ended));
        });
        drop(sender);
        let result = relay_events(receiver, output, call, state, bounds);
        state.finished.store(true, Ordering::Release);
        state.stop_readers.store(true, Ordering::Release);
        result
    })
}

/// Serve one call on an already connected route. The installed entry passes a
/// root-owned node identity; tests pass an identity owned by their fixture user.
/// # Errors
/// Refuses a malformed call, changed grant or placement, foreign node, or a
/// broken control route. No workspace path is opened before those checks.
pub fn serve<R: Read + AsRawFd + Send, W: Write + AsRawFd>(
    input: R,
    output: W,
    identity_path: &Path,
    owner: u32,
) -> io::Result<()> {
    serve_with_limits(input, output, identity_path, owner, StreamBounds::default())
}

fn serve_with_limits<R: Read + AsRawFd + Send, W: Write + AsRawFd>(
    mut input: R,
    mut output: W,
    identity_path: &Path,
    owner: u32,
    bounds: StreamBounds,
) -> io::Result<()> {
    let prepared_call = (|| {
        let frame = read_frame(&mut input)
            .map_err(|error| refusal("door-workspace-protocol-refusal", error))?;
        let identity = installed_node_name(identity_path, owner)?;
        let (call, reservation, envelope, digest) = checked_call(&frame, &identity)?;
        let prepared = PreparedExecution::from_reservation(&reservation, &identity, &envelope)
            .map_err(|error| refusal("door-workspace-context-differs", error.line()))?;
        Ok::<_, io::Error>((call, digest, prepared))
    })();
    let (call, digest, prepared) = match prepared_call {
        Ok(value) => value,
        Err(error) => {
            let message = error.to_string();
            let kind = message
                .split_once(':')
                .map_or("door-workspace-protocol-refusal", |(kind, _)| kind);
            let _written = write_frame(
                &mut output,
                &json!({"schema":1,"type":"refusal","reason":kind}),
            );
            return Err(error);
        }
    };
    write_frame(
        &mut output,
        &json!({
            "schema":1,"type":"ack","request_id":call.request_id,
            "nonce":call.nonce,"frame_handle":digest,
            "entry_version":env!("CARGO_PKG_VERSION"),
        }),
    )?;
    let never_finished = AtomicBool::new(false);
    let start_bound = Instant::now() + bounds.start_wait;
    let command_deadline = prepared.deadline();
    let start_deadline = start_bound.min(command_deadline);
    loop {
        let control = read_control(&mut input, &never_finished, start_deadline);
        match control {
            Ok(Some(Control { kind, .. })) if kind == "start" => break,
            Ok(Some(Control { kind, .. })) if kind == "stop" => {
                return ended_before_spawn(&mut output, &call, CAUSE_STOP);
            }
            Ok(Some(Control { kind, .. })) if kind == "heartbeat" => {}
            other => {
                let cause = match other {
                    Err(ref error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        CAUSE_INPUT_GONE
                    }
                    Err(ref error) if error.kind() == io::ErrorKind::TimedOut => {
                        prestart_timeout_cause(start_bound, command_deadline)
                    }
                    _ => CAUSE_MALFORMED,
                };
                return ended_before_spawn(&mut output, &call, cause);
            }
        }
    }
    stream_execution(input, &output, &call, prepared, bounds)
}

#[cfg(test)]
#[path = "workspace_node_tests.rs"]
pub(crate) mod tests;
