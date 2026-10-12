//! The namespace owner's fixed container start and bounded stream channel.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::unistd::Uid;
use serde_json::{Value, json};

use crate::build;
use crate::error::LaneError;
use crate::launch::{
    check_mount_roots, check_pins, image_check_with_environment, private_podman_environment,
    publish_reservation, read_reservation, reservation_path,
};
use crate::plan::protected_identifier_path;
use crate::{caller_home, load_plan, valid_run_name};

const PROMPT_LIMIT: usize = 1_048_576;
const STREAM_LIMIT: usize = 67_108_864;
const FRAME_LIMIT: usize = 8192;
const CAPACITY_EVIDENCE_LIMIT: usize = 1_048_576;
const STREAM_DRAIN_GRACE: Duration = Duration::from_secs(30);
const STREAM_STOP_GRACE: Duration = Duration::from_secs(5);

#[derive(Default)]
struct CapacityCapture {
    tail: Vec<u8>,
    thread: Option<String>,
    skipping_line: bool,
    scanned: usize,
}

impl CapacityCapture {
    fn push(&mut self, mut bytes: &[u8]) {
        if self.skipping_line {
            let Some(end) = bytes.iter().position(|byte| *byte == b'\n') else {
                return;
            };
            bytes = &bytes[end + 1..];
            self.skipping_line = false;
        }
        self.tail.extend_from_slice(bytes);
        if self.thread.is_none() {
            self.thread = self.tail[self.scanned..]
                .split_inclusive(|byte| *byte == b'\n')
                .find_map(|line| {
                    if !line.ends_with(b"\n") {
                        return None;
                    }
                    self.scanned += line.len();
                    let event: Value = serde_json::from_slice(line).ok()?;
                    let thread = event["thread_id"].as_str()?;
                    (event["type"] == "thread.started" && valid_thread(thread))
                        .then(|| thread.to_owned())
                });
        }
        if self.tail.len() > CAPACITY_EVIDENCE_LIMIT {
            let excess = self.tail.len() - CAPACITY_EVIDENCE_LIMIT;
            if let Some(end) = self.tail[excess..].iter().position(|byte| *byte == b'\n') {
                self.tail.drain(..=excess + end);
                self.scanned = self.scanned.saturating_sub(excess + end + 1);
            } else {
                self.tail.clear();
                self.skipping_line = true;
                self.scanned = 0;
            }
        }
    }
}

pub(crate) fn resume_box_vector(vector: &[String], thread: &str) -> Result<Vec<String>, LaneError> {
    if !valid_thread(thread) {
        return Err(LaneError::input(
            "round-thread",
            "request thread is malformed",
        ));
    }
    let exec = vector
        .iter()
        .position(|word| word == "exec")
        .ok_or_else(|| LaneError::input("round-thread", "saved Codex exec is absent"))?;
    if vector
        .get(exec.wrapping_sub(1))
        .is_none_or(|word| !word.ends_with("/codex"))
        || vector.last().is_none_or(|word| word != "-")
    {
        return Err(LaneError::input(
            "round-thread",
            "saved Codex prompt boundary differs",
        ));
    }
    let mut resumed = vector.to_vec();
    let position = resumed.len() - 1;
    resumed.splice(position..position, ["resume".to_owned(), thread.to_owned()]);
    Ok(resumed)
}

fn valid_thread(thread: &str) -> bool {
    !thread.is_empty()
        && thread.len() <= 128
        && thread
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(crate) fn requested_thread(run_dir: &Path, prompt: &[u8]) -> Result<Option<String>, LaneError> {
    let prompt = std::str::from_utf8(prompt)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let step = prompt
        .trim_end_matches('\n')
        .strip_prefix("Read /home/worker/.local/inbox/")
        .and_then(|word| word.strip_suffix(".md."))
        .ok_or_else(|| LaneError::input("round-thread", "round prompt does not name one letter"))?;
    crate::launch::letters::valid_step(step)?;
    if step == "dispatch" {
        return Ok(None);
    }
    let path = run_dir.join(format!("round-launch-{step}.json"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            LaneError::input("round-thread", format!("{}: {error}", path.display()))
        })?;
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let parent = std::fs::symlink_metadata(run_dir)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    validate_request_identity(
        meta.is_file(),
        meta.len(),
        meta.uid(),
        meta.mode(),
        parent.uid(),
        Uid::effective().as_raw(),
    )?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    let request: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    if request["step"] != step || request["letter"] != format!("{step}.md") {
        return Err(LaneError::input(
            "round-thread",
            "round request names another letter",
        ));
    }
    if request.get("thread_id").is_some_and(Value::is_null) {
        return Ok(None);
    }
    let thread = request["thread_id"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-thread", "round request has no thread"))?;
    if !valid_thread(thread) {
        return Err(LaneError::input(
            "round-thread",
            "round request thread is malformed",
        ));
    }
    Ok(Some(thread.to_owned()))
}

fn validate_request_identity(
    regular: bool,
    bytes: u64,
    file_uid: u32,
    mode: u32,
    directory_uid: u32,
    reader_uid: u32,
) -> Result<(), LaneError> {
    if !regular
        || bytes > 4096
        || file_uid != directory_uid
        || file_uid != reader_uid
        || mode & 0o777 != 0o600
    {
        return Err(LaneError::input(
            "round-thread",
            "round request is not bounded reader-owned evidence",
        ));
    }
    Ok(())
}

pub(crate) fn command_for_request(
    vector: &[String],
    record: &Value,
    requested: Option<&str>,
) -> Result<Vec<String>, LaneError> {
    let step = record["active_round"].as_str();
    if requested.is_none() && crate::launch::rounds::fresh_thread_round(record) {
        return Ok(vector.to_vec());
    }
    if step == Some("dispatch") || step.is_none() {
        if requested.is_some() {
            return Err(LaneError::input(
                "round-thread",
                "first round request names a thread",
            ));
        }
        return Ok(vector.to_vec());
    }
    let saved = record["thread_id"]
        .as_str()
        .ok_or_else(|| LaneError::input("round-thread", "reservation has no thread"))?;
    if requested != Some(saved) {
        return Err(LaneError::input(
            "round-thread",
            format!(
                "request thread {} differs from reservation {saved}",
                requested.unwrap_or("absent")
            ),
        ));
    }
    resume_box_vector(vector, saved)
}

fn decode_round_request(bytes: Vec<u8>) -> Result<(Option<String>, Vec<u8>), LaneError> {
    if bytes.first() != Some(&0) {
        return Ok((None, bytes));
    }
    let end = bytes[1..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| index + 1)
        .ok_or_else(|| LaneError::input("round-thread", "round request has no thread boundary"))?;
    let thread = std::str::from_utf8(&bytes[1..end])
        .map_err(|error| LaneError::input("round-thread", error.to_string()))?;
    if !valid_thread(thread) {
        return Err(LaneError::input(
            "round-thread",
            "round request thread is malformed",
        ));
    }
    Ok((Some(thread.to_owned()), bytes[end + 1..].to_vec()))
}

#[derive(Clone)]
struct AttemptOutcome {
    thread: Option<String>,
    code: i32,
    capacity: bool,
    attempt_wall: Option<lane_lifecycle::AttemptWall>,
}

struct AttemptProgress {
    code: i32,
    capacity: bool,
    attempt_wall: Option<lane_lifecycle::AttemptWall>,
    stream_bytes: usize,
    stream_errors: Vec<(&'static str, LaneError)>,
    wait_error: Option<LaneError>,
    stop_error: Option<LaneError>,
    setup_error: Option<LaneError>,
}

fn spawn_attempt_worker<T: Send + 'static>(
    name: &'static str,
    gate: &mut impl FnMut(&'static str) -> std::io::Result<()>,
    task: impl FnOnce() -> T + Send + 'static,
) -> Result<JoinHandle<T>, LaneError> {
    gate(name)
        .and_then(|()| std::thread::Builder::new().name(name.into()).spawn(task))
        .map_err(|error| LaneError::operation("container-thread", format!("{name}: {error}")))
}

fn join_attempt_worker(
    name: &'static str,
    handle: Option<JoinHandle<std::io::Result<()>>>,
) -> Option<(&'static str, LaneError)> {
    handle.and_then(|handle| {
        handle
            .join()
            .map_err(|_| LaneError::operation("container-stream", format!("{name} panicked")))
            .and_then(|result| {
                result.map_err(|error| LaneError::operation("container-stream", error.to_string()))
            })
            .err()
            .map(|error| (name, error))
    })
}

fn finish_attempt_workers(
    input: &mut Option<JoinHandle<std::io::Result<()>>>,
    output: &mut Option<JoinHandle<std::io::Result<()>>>,
    error: &mut Option<JoinHandle<std::io::Result<()>>>,
    deadline: Instant,
) -> Vec<(&'static str, LaneError)> {
    let mut workers = [("stdin", input), ("stdout", output), ("stderr", error)];
    while workers
        .iter()
        .any(|(_, handle)| handle.as_ref().is_some_and(|handle| !handle.is_finished()))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    workers
        .iter_mut()
        .filter_map(|(name, worker)| match worker.take() {
            Some(handle) if !handle.is_finished() => Some((
                *name,
                LaneError::operation(
                    "container-stream",
                    format!("{name} worker did not finish after container stop"),
                ),
            )),
            handle => join_attempt_worker(name, handle),
        })
        .collect()
}

fn reap_started_child(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

const fn retry_after(outcome: &AttemptOutcome) -> bool {
    outcome.code != 0 && outcome.capacity && outcome.attempt_wall.is_none()
}

const MAX_ATTEMPTS: u32 = 4;

/// Leave time beyond all capacity attempts for helper startup offsets, each
/// attempt's five-second stop and thirty-second drain grace, and the driver's
/// terminal report write. The host is an outer guard, not the attempt timer.
pub(crate) const HOST_LAUNCH_MARGIN_SECONDS: u64 = 300;

pub(crate) fn host_launch_bound(record: &Value) -> Result<u64, LaneError> {
    attempt_wall_bound(record)?
        .checked_mul(u64::from(MAX_ATTEMPTS))
        .and_then(|bound| bound.checked_add(HOST_LAUNCH_MARGIN_SECONDS))
        .ok_or_else(|| LaneError::input("launch-wall", "host launch bound exceeds u64 seconds"))
}

pub(crate) fn attempt_wall_bound(record: &Value) -> Result<u64, LaneError> {
    let active = record["active_round"]
        .as_str()
        .ok_or_else(|| LaneError::input("attempt-budget", "reservation active round is absent"))?;
    let budget = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.iter().find(|round| round["step"] == active))
        .and_then(|round| round["budget_seconds"].as_u64())
        .filter(|budget| *budget > 0)
        .ok_or_else(|| {
            LaneError::input(
                "attempt-budget",
                format!("active round {active} has no positive budget_seconds"),
            )
        })?;
    record["plan"].get("attempt_wall_seconds").map_or_else(
        || Ok(budget.saturating_mul(lane_lifecycle::RUNAWAY_MULTIPLIER)),
        |value| {
            value.as_u64().filter(|wall| *wall > 0).ok_or_else(|| {
                LaneError::input(
                    "attempt-wall",
                    "plan attempt_wall_seconds must be a positive integer",
                )
            })
        },
    )
}

fn attempt_wall_record(end: lane_lifecycle::AttemptWall) -> Value {
    json!({"cause":"attempt-wall","attempt_elapsed_seconds":end.wall_seconds,"bound_seconds":end.bound_seconds})
}

fn record_attempt_wall(
    reservation: &Path,
    record: &Value,
    end: lane_lifecycle::AttemptWall,
) -> Result<(), LaneError> {
    let root = reservation
        .parent()
        .ok_or_else(|| LaneError::input("helper-pin", "runs root is absent"))?;
    let run = record["run"]
        .as_str()
        .ok_or_else(|| LaneError::input("helper-pin", "run is absent"))?;
    let _mailbox = crate::launch::lock_mailbox(root, run, Uid::effective().as_raw())?;
    let mut current = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("helper-pin", "reservation is absent"))?;
    if current["active_round"] != record["active_round"] {
        return Err(LaneError::input(
            "helper-pin",
            "active round changed during attempt",
        ));
    }
    let round = current["rounds"]
        .as_array_mut()
        .and_then(|rounds| {
            rounds
                .iter_mut()
                .find(|round| round["step"] == record["active_round"])
        })
        .ok_or_else(|| LaneError::input("attempt-budget", "active round is absent"))?;
    round["attempt_end"] = attempt_wall_record(end);
    publish_reservation(reservation, &current)
}

fn capacity_event(bytes: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        let Ok(event) = serde_json::from_slice::<Value>(line) else {
            return false;
        };
        let message = match event["type"].as_str() {
            Some("error") => event["message"].as_str(),
            Some("turn.failed") => event["error"]["message"].as_str(),
            _ => None,
        };
        message.is_some_and(|message| {
            let lower = message.to_ascii_lowercase();
            lower.contains("model") && lower.contains("at capacity")
        })
    })
}

pub(crate) fn socket_path(run_dir: &Path) -> Result<PathBuf, LaneError> {
    let root = run_dir
        .parent()
        .ok_or_else(|| LaneError::input("helper-socket", "run has no protected root"))?;
    let run = run_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("helper-socket", "run name is not text"))?;
    if !valid_run_name(run) {
        return Err(LaneError::input("helper-socket", "run name is invalid"));
    }
    Ok(root.join(format!(".container-{run}.sock")))
}

#[derive(Clone, Debug)]
struct ClientSocketIdentity {
    root_dev: u64,
    root_ino: u64,
    socket_name: String,
}

impl ClientSocketIdentity {
    fn from_environment() -> Result<Self, LaneError> {
        let field = |name: &str| {
            std::env::var(name)
                .map_err(|_| LaneError::input("helper-socket", format!("{name} is absent")))
        };
        let number = |name: &str| -> Result<u64, LaneError> {
            field(name)?.parse().map_err(|_| {
                LaneError::input("helper-socket", format!("{name} is not an inode identity"))
            })
        };
        Ok(Self {
            root_dev: number("SUPERLOOP_CLIENT_ROOT_DEV")?,
            root_ino: number("SUPERLOOP_CLIENT_ROOT_INO")?,
            socket_name: field("SUPERLOOP_CLIENT_SOCKET_NAME")?,
        })
    }
}

fn open_client_runs_root_with(
    root_path: &Path,
    ancestor_stat: impl FnOnce(&Path) -> Result<(u32, u32), LaneError>,
) -> Result<std::os::fd::OwnedFd, LaneError> {
    let ancestor = root_path
        .parent()
        .ok_or_else(|| LaneError::input("helper-socket", "runs root has no ancestor"))?;
    let (mode, _owner) = ancestor_stat(ancestor)?;
    if mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(LaneError::input(
            "helper-socket",
            "runs root ancestor is not a directory",
        ));
    }
    let relative = root_path
        .strip_prefix("/")
        .map_err(|_| LaneError::input("helper-socket", "runs root is not absolute"))?;
    let filesystem_root = nix::fcntl::open(
        "/",
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|error| LaneError::input("helper-socket", error.to_string()))?;
    nix::fcntl::openat2(
        &filesystem_root,
        relative,
        nix::fcntl::OpenHow::new()
            .flags(
                nix::fcntl::OFlag::O_PATH
                    | nix::fcntl::OFlag::O_DIRECTORY
                    | nix::fcntl::OFlag::O_CLOEXEC,
            )
            .resolve(
                nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                    | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
            ),
    )
    .map_err(|error| LaneError::input("helper-socket", format!("runs root: {error}")))
}

fn attested_client_socket(
    run_dir: &Path,
    identity: &ClientSocketIdentity,
    root_owner: u32,
    socket_group: u32,
) -> Result<crate::SocketSlot, LaneError> {
    let planned = socket_path(run_dir)?;
    let name = planned
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| LaneError::input("helper-socket", "planned socket name is invalid"))?;
    if name != identity.socket_name {
        return Err(LaneError::input(
            "helper-socket",
            "client socket name differs from the owner runtime record",
        ));
    }
    let root_path = run_dir
        .parent()
        .ok_or_else(|| LaneError::input("helper-socket", "runs root is absent"))?;
    let directory = open_client_runs_root_with(root_path, |ancestor| {
        let stat = nix::sys::stat::stat(ancestor)
            .map_err(|error| LaneError::input("helper-socket", error.to_string()))?;
        Ok((stat.st_mode, stat.st_uid))
    })?;
    let root_stat = nix::sys::stat::fstat(&directory)
        .map_err(|error| LaneError::input("helper-socket", error.to_string()))?;
    if root_stat.st_dev != identity.root_dev
        || root_stat.st_ino != identity.root_ino
        || root_stat.st_uid != root_owner
        || root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || root_stat.st_mode & 0o022 != 0
    {
        return Err(LaneError::input(
            "helper-socket",
            "runs root differs from the owner-recorded inode or protection",
        ));
    }
    let slot = crate::SocketSlot::new(directory, OsStr::new(name))
        .map_err(|error| LaneError::input("helper-socket", error.to_string()))?;
    let meta = slot
        .metadata()
        .map_err(|error| LaneError::input("helper-socket", error.to_string()))?
        .ok_or_else(|| LaneError::input("helper-socket", "socket is absent"))?;
    if meta.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || meta.st_mode & 0o7777 != 0o660
        || meta.st_uid != root_owner
        || meta.st_gid != socket_group
    {
        return Err(LaneError::input(
            "helper-socket",
            "socket differs from the owner-recorded run and group",
        ));
    }
    Ok(slot)
}

pub(crate) fn control_socket_path(run_dir: &Path) -> Result<PathBuf, LaneError> {
    let root = run_dir
        .parent()
        .ok_or_else(|| LaneError::input("helper-control", "run has no protected root"))?;
    let run = run_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("helper-control", "run name is not text"))?;
    Ok(root.join(format!(".control-{run}.sock")))
}

fn control_loop(
    listener: &UnixListener,
    cancelled: &AtomicBool,
    owner_uid: u32,
) -> Result<(), LaneError> {
    listener
        .set_nonblocking(true)
        .map_err(|error| LaneError::operation("helper-control", error.to_string()))?;
    while !cancelled.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if peer_credentials(&stream)?.uid != owner_uid {
                    continue;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|error| LaneError::operation("helper-control", error.to_string()))?;
                let mut word = [0_u8];
                stream
                    .read_exact(&mut word)
                    .map_err(|error| LaneError::operation("helper-control", error.to_string()))?;
                if word == *b"C" {
                    cancelled.store(true, Ordering::Release);
                    stream.write_all(b"K").map_err(|error| {
                        LaneError::operation("helper-control", error.to_string())
                    })?;
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(LaneError::operation("helper-control", error.to_string())),
        }
    }
    Ok(())
}

fn next_client(
    listener: &UnixListener,
    cancelled: &AtomicBool,
    launcher: LauncherIdentity,
) -> Result<Option<UnixStream>, LaneError> {
    while !cancelled.load(Ordering::Acquire) {
        if !launcher_alive(launcher) {
            cancelled.store(true, Ordering::Release);
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => return Ok(Some(stream)),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(LaneError::operation("helper-channel", error.to_string())),
        }
    }
    Ok(None)
}

struct PinnedRequest {
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    loop_uid: u32,
    driver_dir: PathBuf,
    record: Value,
    launcher: LauncherIdentity,
}

#[derive(Clone, Copy)]
struct LauncherIdentity {
    pid: u32,
    start: u64,
}

fn launcher_alive(identity: LauncherIdentity) -> bool {
    process_alive(identity.pid, identity.start)
}

#[cfg(test)]
fn read_words(path: &Path) -> Result<Vec<String>, LaneError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut bytes = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| LaneError::input("helper-pin", format!("{}: {error}", path.display())))?
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("helper-pin", format!("{}: {error}", path.display())))?;
    if bytes.is_empty() || bytes.len() > 65_536 || bytes.last() != Some(&0) {
        return Err(LaneError::input(
            "helper-pin",
            format!("{} is not bounded NUL-separated data", path.display()),
        ));
    }
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|word| {
            std::str::from_utf8(word)
                .map(str::to_owned)
                .map_err(|error| {
                    LaneError::input("helper-pin", format!("{}: {error}", path.display()))
                })
        })
        .collect()
}

#[cfg(test)]
fn verify_vector(saved: &[String], expected: &[String]) -> Result<(), LaneError> {
    if saved != expected {
        return Err(LaneError::input(
            "helper-pin",
            "saved container vector differs from the plan",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_pinned_request(
    owner_home: &Path,
    run: &str,
    podman: &Path,
) -> Result<Value, LaneError> {
    pinned_request(owner_home, "alpha", run, podman).map(|request| request.record)
}

fn pinned_request(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    podman: &Path,
) -> Result<PinnedRequest, LaneError> {
    crate::pinned::owner_executable(podman, Uid::effective().as_raw())?;
    let (initial, _) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let root = initial
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("helper-pin", "run has no runs root"))?;
    let reservation = reservation_path(root, run);
    let record = read_reservation(&reservation)?.ok_or_else(|| {
        LaneError::input("helper-pin", format!("{} is absent", reservation.display()))
    })?;
    if record["loop"] != loop_name || record["run"] != run {
        return Err(LaneError::input(
            "helper-pin",
            "reservation names another run",
        ));
    }
    let launcher = LauncherIdentity {
        pid: record["launcher_pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or_else(|| LaneError::input("helper-pin", "reservation has no launcher PID"))?,
        start: record["launcher_start"].as_u64().ok_or_else(|| {
            LaneError::input("helper-pin", "reservation has no launcher start tick")
        })?,
    };
    if !launcher_alive(launcher) {
        return Err(LaneError::input(
            "helper-pin",
            "launcher's recorded process is absent",
        ));
    }
    let (plan, settings) =
        crate::launch::pinned_plan_from_record(owner_home, loop_name, run, podman, &record)
            .map_err(|error| LaneError::input("helper-pin", error.line()))?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let observing = record["plan"]["vendor_mode"].is_string();
    crate::plan::verify_box_attestation(&plan.document)?;
    let argv = plan.document["runtime_argv"]
        .as_array()
        .ok_or_else(|| LaneError::input("helper-pin", "plan has no runtime vector"))?
        .iter()
        .map(|word| {
            word.as_str()
                .map(str::to_owned)
                .ok_or_else(|| LaneError::input("helper-pin", "plan runtime word is not text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment = private_podman_environment(owner_home)?;
    check_mount_roots(&plan, &settings, owner_home)?;
    check_pins(&plan, &settings, owner_home, observing, true)?;
    image_check_with_environment(
        podman,
        settings
            .image_digest
            .as_deref()
            .ok_or_else(|| LaneError::input("helper-pin", "image ID is absent"))?,
        owner_home,
        &environment,
    )?;
    Ok(PinnedRequest {
        argv,
        environment,
        loop_uid,
        driver_dir: plan.driver_dir,
        record,
        launcher,
    })
}

fn attempt_vector(
    base: &[String],
    driver_dir: &Path,
    attempt: u32,
) -> Result<Vec<String>, LaneError> {
    if !(1..=MAX_ATTEMPTS).contains(&attempt) {
        return Err(LaneError::input(
            "helper-attempt",
            format!("attempt is outside 1..={MAX_ATTEMPTS}"),
        ));
    }
    let mut vector = base.to_vec();
    let mut names = 0;
    let mut identifiers = 0;
    for word in &mut vector {
        if let Some(name) = word.strip_prefix("--name=") {
            names += 1;
            let stem = name.strip_suffix("-attempt-1").ok_or_else(|| {
                LaneError::input("helper-pin", "planned container name lacks attempt 1")
            })?;
            *word = format!("--name={stem}-attempt-{attempt}");
        }
        if let Some(path) = word.strip_prefix("--cidfile=") {
            identifiers += 1;
            if path
                != protected_identifier_path(driver_dir, 1)?
                    .display()
                    .to_string()
            {
                return Err(LaneError::input(
                    "helper-pin",
                    "planned identifier path differs from the run",
                ));
            }
            *word = format!(
                "--cidfile={}",
                protected_identifier_path(driver_dir, attempt)?.display()
            );
        }
    }
    if names != 1 || identifiers != 1 {
        return Err(LaneError::input(
            "helper-pin",
            "planned container name or identifier is not unique",
        ));
    }
    Ok(vector)
}

fn frame(stream: &Arc<Mutex<UnixStream>>, channel: u8, bytes: &[u8]) -> std::io::Result<()> {
    let mut writer = stream
        .lock()
        .map_err(|_| std::io::Error::other("channel lock poisoned"))?;
    writer.write_all(&[channel])?;
    let length = u32::try_from(bytes.len()).map_err(std::io::Error::other)?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)
}

#[allow(clippy::too_many_arguments)]
fn forward(
    mut pipe: impl std::io::Read,
    stream: &Arc<Mutex<UnixStream>>,
    channel: u8,
    bytes: &Arc<AtomicUsize>,
    overflow: &Arc<AtomicBool>,
    capacity: &Arc<Mutex<CapacityCapture>>,
    stream_limit: usize,
) -> std::io::Result<()> {
    let mut chunk = [0_u8; FRAME_LIMIT];
    loop {
        let count = pipe.read(&mut chunk)?;
        if count == 0 {
            return Ok(());
        }
        if bytes.fetch_add(count, Ordering::AcqRel) + count > stream_limit {
            overflow.store(true, Ordering::Release);
            return Err(std::io::Error::other("container stream limit reached"));
        }
        if channel == b'O' {
            let mut evidence = capacity
                .lock()
                .map_err(|_| std::io::Error::other("capacity lock poisoned"))?;
            evidence.push(&chunk[..count]);
            drop(evidence);
        }
        if let Err(error) = frame(stream, channel, &chunk[..count]) {
            overflow.store(true, Ordering::Release);
            return Err(error);
        }
    }
}

fn start_after_reservation<T>(
    reservation: &Path,
    record: &Value,
    start: impl FnOnce() -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    let root = reservation
        .parent()
        .ok_or_else(|| LaneError::input("helper-pin", "runs root is absent"))?;
    let run = record["run"]
        .as_str()
        .ok_or_else(|| LaneError::input("helper-pin", "run is absent"))?;
    {
        let _mailbox = crate::launch::lock_mailbox(root, run, Uid::effective().as_raw())?;
        let mut current = read_reservation(reservation)?
            .ok_or_else(|| LaneError::input("helper-pin", "reservation is absent"))?;
        if current["loop"] != record["loop"]
            || current["run"] != record["run"]
            || current["worker_uid"] != record["worker_uid"]
            || current["plan"] != record["plan"]
            || !["preparing", "started"].contains(&current["phase"].as_str().unwrap_or_default())
        {
            return Err(LaneError::input(
                "helper-pin",
                "reservation changed before container start",
            ));
        }
        current["phase"] = json!("started");
        publish_reservation(reservation, &current)?;
    }
    start()
}

#[allow(unsafe_code)]
fn client_disconnected(stream: &UnixStream) -> bool {
    let mut byte = [0_u8];
    // SAFETY: recv writes at most one byte into the live local buffer and does not consume it.
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            byte.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result == 0 {
        return true;
    }
    if result < 0 {
        let error = std::io::Error::last_os_error();
        return !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        );
    }
    false
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_attempt(
    stream: &mut UnixStream,
    vector: &[String],
    environment: &BTreeMap<String, String>,
    owner_home: &Path,
    reservation: &Path,
    record: &Value,
    driver_dir: &Path,
    attempt: u32,
    cancelled: &AtomicBool,
    launcher: LauncherIdentity,
    retry_thread: Option<&str>,
) -> Result<AttemptOutcome, LaneError> {
    run_attempt_with(
        stream,
        vector,
        environment,
        owner_home,
        reservation,
        record,
        driver_dir,
        attempt,
        cancelled,
        launcher,
        STREAM_LIMIT,
        STREAM_DRAIN_GRACE,
        STREAM_STOP_GRACE,
        Child::try_wait,
        |_| Ok(()),
        |_| Ok(()),
        retry_thread,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_attempt_with(
    stream: &mut UnixStream,
    vector: &[String],
    environment: &BTreeMap<String, String>,
    owner_home: &Path,
    reservation: &Path,
    record: &Value,
    driver_dir: &Path,
    attempt: u32,
    cancelled: &AtomicBool,
    launcher: LauncherIdentity,
    stream_limit: usize,
    drain_grace: Duration,
    stop_grace: Duration,
    mut try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
    mut spawn_gate: impl FnMut(&'static str) -> std::io::Result<()>,
    mut after_start: impl FnMut(u32) -> Result<(), LaneError>,
    retry_thread: Option<&str>,
) -> Result<AttemptOutcome, LaneError> {
    let wall_bound = attempt_wall_bound(record)?;
    let mut length = [0_u8; 4];
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    stream
        .read_exact(&mut length)
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    let length = u32::from_le_bytes(length) as usize;
    if length > PROMPT_LIMIT {
        return Err(LaneError::input(
            "helper-channel",
            "prompt exceeds 1048576 bytes",
        ));
    }
    let mut prompt = vec![0_u8; length];
    stream
        .read_exact(&mut prompt)
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    stream
        .set_read_timeout(None)
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    let (requested, prompt) = decode_round_request(prompt)?;
    let resolved = command_for_request(vector, record, requested.as_deref())?;
    // The helper retained this identity from its prior stdout capture or
    // the validated round request, with its source recorded in the evidence,
    // after capacity evidence admitted another attempt. The client still
    // has to pass the original round-request validation above.
    let resolved = if let Some(thread) = retry_thread {
        resume_box_vector(vector, thread)?
    } else {
        resolved
    };
    let (program, arguments) = resolved
        .split_first()
        .ok_or_else(|| LaneError::input("helper-pin", "empty container vector"))?;
    crate::pinned::owner_executable(Path::new(program), Uid::effective().as_raw())?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .current_dir(owner_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let sender = stream
        .try_clone()
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    sender
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    let identifier_file = protected_identifier_path(driver_dir, attempt)?;
    let custody_dir = crate::plan::protected_identity_dir(driver_dir)?;
    let custody_fd = crate::home::pin_parent(&custody_dir, Uid::effective().as_raw())?;
    let custody_base = PathBuf::from(format!("/proc/self/fd/{}", custody_fd.as_raw_fd()));
    let custody_directory = std::fs::File::from(custody_fd);
    let start_path = custody_base.join(format!("container-attempt-{attempt}.start.json"));
    let start = json!({"schema":1,"attempt":attempt,"state":"started","launcher_pid":record["launcher_pid"],"launcher_start":record["launcher_start"],"container_name":vector.iter().find_map(|word| word.strip_prefix("--name="))});
    build::publish(
        &start_path,
        &serde_json::to_vec(&start)
            .map_err(|error| LaneError::operation("container-evidence", error.to_string()))?,
    )?;
    custody_directory
        .sync_all()
        .map_err(|error| LaneError::operation("container-evidence", error.to_string()))?;
    let mut child = start_after_reservation(reservation, record, || {
        crate::fixture_exec::spawn(&mut command)
            .map_err(|error| LaneError::operation("container-start", error.to_string()))
    })?;
    let writer = Arc::new(Mutex::new(sender));
    let transferred = Arc::new(AtomicUsize::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let capacity = Arc::new(Mutex::new(CapacityCapture::default()));
    let mut out_worker = None;
    let mut err_worker = None;
    let mut input_worker = None;
    let mut driver_death = None;
    let mut driver_unmeasured = None;
    let driven = (|| -> Result<AttemptProgress, LaneError> {
        after_start(child.id())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| LaneError::operation("container-start", "stdout pipe absent"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| LaneError::operation("container-start", "stderr pipe absent"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| LaneError::operation("container-start", "stdin pipe absent"))?;
        out_worker = Some(spawn_attempt_worker("stdout", &mut spawn_gate, {
            let writer = Arc::clone(&writer);
            let transferred = Arc::clone(&transferred);
            let overflow = Arc::clone(&overflow);
            let capacity = Arc::clone(&capacity);
            move || {
                forward(
                    stdout,
                    &writer,
                    b'O',
                    &transferred,
                    &overflow,
                    &capacity,
                    stream_limit,
                )
            }
        })?);
        err_worker = Some(spawn_attempt_worker("stderr", &mut spawn_gate, {
            let writer = Arc::clone(&writer);
            let transferred = Arc::clone(&transferred);
            let overflow = Arc::clone(&overflow);
            let capacity = Arc::clone(&capacity);
            move || {
                forward(
                    stderr,
                    &writer,
                    b'E',
                    &transferred,
                    &overflow,
                    &capacity,
                    stream_limit,
                )
            }
        })?);
        input_worker = Some(spawn_attempt_worker("stdin", &mut spawn_gate, move || {
            stdin.write_all(&prompt)
        })?);
        let began = Instant::now();
        let mut status = None;
        let mut stopped = false;
        let mut attempt_wall = None;
        let mut cleanup = None;
        let mut wait_error = None;
        let mut drain_error = None;
        let mut drain_deadline = None;
        let mut stop_deadline = None;
        let mut next_driver_measurement = Instant::now();
        loop {
            if !stopped && driver_death.is_none() && Instant::now() >= next_driver_measurement {
                next_driver_measurement = Instant::now() + Duration::from_secs(1);
                match measured_driver_end(reservation, record) {
                    Ok(Some(proof)) => {
                        driver_unmeasured = None;
                        driver_death = Some(proof);
                        cancelled.store(true, Ordering::Release);
                    }
                    Ok(None) => driver_unmeasured = None,
                    Err(error) => driver_unmeasured = Some(error.line()),
                }
            }
            if client_disconnected(stream) || !launcher_alive(launcher) {
                cancelled.store(true, Ordering::Release);
            }
            if !stopped
                && (cancelled.load(Ordering::Acquire)
                    || overflow.load(Ordering::Acquire)
                    || wait_error.is_some()
                    || began.elapsed() > Duration::from_secs(wall_bound))
            {
                if !cancelled.load(Ordering::Acquire)
                    && !overflow.load(Ordering::Acquire)
                    && wait_error.is_none()
                {
                    attempt_wall = Some(lane_lifecycle::AttemptWall {
                        wall_seconds: began.elapsed().as_secs(),
                        bound_seconds: wall_bound,
                    });
                }
                stopped = true;
                if let Ok(pid) = i32::try_from(child.id()) {
                    let _ignored = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                let _ignored = child.kill();
                cleanup = Some(stop_container(program, vector, environment, owner_home));
                stop_deadline = Some(Instant::now() + stop_grace);
            }
            if status.is_none() && wait_error.is_none() {
                match try_wait(&mut child) {
                    Ok(exit) => status = exit,
                    Err(error) => {
                        wait_error =
                            Some(LaneError::operation("container-wait", error.to_string()));
                    }
                }
            }
            if status.is_none() && wait_error.is_some() && stopped {
                status = child.try_wait().ok().flatten();
            }
            let workers_finished = out_worker.as_ref().is_some_and(JoinHandle::is_finished)
                && err_worker.as_ref().is_some_and(JoinHandle::is_finished)
                && input_worker.as_ref().is_some_and(JoinHandle::is_finished);
            if status.is_some() && workers_finished {
                break;
            }
            if status.is_some() {
                let deadline = drain_deadline.get_or_insert_with(|| Instant::now() + drain_grace);
                if !stopped && Instant::now() >= *deadline {
                    stopped = true;
                    drain_error = Some(LaneError::operation(
                        "container-stream",
                        format!(
                            "stream drain exceeded {:.3} seconds after child exit",
                            drain_grace.as_secs_f64()
                        ),
                    ));
                    if let Ok(pid) = i32::try_from(child.id()) {
                        let _ignored = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(pid),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                    let _ignored = child.kill();
                    cleanup = Some(stop_container(program, vector, environment, owner_home));
                    stop_deadline = Some(Instant::now() + stop_grace);
                }
            }
            if stop_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                if status.is_none() && wait_error.is_none() {
                    wait_error = Some(LaneError::operation(
                        "container-wait",
                        "child did not exit after container stop",
                    ));
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut stream_errors = finish_attempt_workers(
            &mut input_worker,
            &mut out_worker,
            &mut err_worker,
            stop_deadline.unwrap_or_else(Instant::now),
        );
        if let Some(error) = drain_error {
            stream_errors.insert(0, ("drain", error));
        }
        let stop_error = cleanup.and_then(Result::err);
        let code =
            if stopped || wait_error.is_some() || !stream_errors.is_empty() || stop_error.is_some()
            {
                1
            } else {
                status.and_then(|exit| exit.code()).unwrap_or(1)
            };
        let capacity_evidence = !stopped
            && stream_errors.is_empty()
            && wait_error.is_none()
            && code != 0
            && capacity
                .lock()
                .is_ok_and(|capture| capacity_event(&capture.tail));
        Ok(AttemptProgress {
            code,
            capacity: capacity_evidence,
            attempt_wall,
            stream_bytes: transferred.load(Ordering::Acquire),
            stream_errors,
            wait_error,
            stop_error,
            setup_error: None,
        })
    })();
    let progress = match driven {
        Ok(progress) => progress,
        Err(error) => {
            if let Ok(pid) = i32::try_from(child.id()) {
                let _ignored = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ignored = child.kill();
            let stop_error = stop_container(program, vector, environment, owner_home).err();
            let deadline = Instant::now() + stop_grace;
            let _status = reap_started_child(&mut child, deadline);
            let stream_errors = finish_attempt_workers(
                &mut input_worker,
                &mut out_worker,
                &mut err_worker,
                deadline,
            );
            AttemptProgress {
                code: 1,
                capacity: false,
                attempt_wall: None,
                stream_bytes: transferred.load(Ordering::Acquire),
                stream_errors,
                wait_error: None,
                stop_error,
                setup_error: Some(error),
            }
        }
    };
    let stream_errors = progress
        .stream_errors
        .iter()
        .map(|(stream, error)| json!({"stream":stream,"reason":error.detail}))
        .collect::<Vec<_>>();
    let mut evidence = json!({"schema":1,"attempt":attempt,"launcher_pid":record["launcher_pid"],"launcher_start":record["launcher_start"],"status":progress.code,"capacity_evidence":progress.capacity,"stream_bytes":progress.stream_bytes,"stream_errors":stream_errors,"stream_error":stream_errors.first(),"wait_error":progress.wait_error.as_ref().map(LaneError::line),"stop_error":progress.stop_error.as_ref().map(LaneError::line),"thread_error":progress.setup_error.as_ref().filter(|error| error.kind == "container-thread").map(LaneError::line),"post_start_error":progress.setup_error.as_ref().map(LaneError::line),"bounded":true,"container_name":vector.iter().find_map(|word| word.strip_prefix("--name=")),"identifier_file":identifier_file,"removal":{"state":"pending"}});
    let evidence_name = format!("container-attempt-{attempt}.status.json");
    if let Some(proof) = &driver_death {
        evidence["reaping"] = json!({"state":"pending","cause":"driver-death","driver":proof});
    } else if let Some(error) = &driver_unmeasured {
        evidence["reaping"] = json!({"state":"unmeasured","cause":"driver-presence","error":error});
    }
    evidence["attempt_end"] = progress
        .attempt_wall
        .map_or(Value::Null, attempt_wall_record);
    let captured_thread = capacity
        .lock()
        .ok()
        .and_then(|capture| capture.thread.clone());
    let thread_id_source = if captured_thread.is_some() {
        Some("captured")
    } else if requested.is_some() {
        Some("requested")
    } else {
        None
    };
    let captured_thread = captured_thread.or(requested);
    evidence["thread_id"] = json!(captured_thread);
    evidence["thread_id_source"] = json!(thread_id_source);
    evidence["resume_thread"] = json!(retry_thread);
    let evidence_path = driver_dir.join(&evidence_name);
    let custody_path = custody_base.join(&evidence_name);
    let initial_publish = serde_json::to_vec(&evidence)
        .map_err(|error| LaneError::operation("container-evidence", error.to_string()))
        .and_then(|bytes| {
            build::publish(&custody_path, &bytes)?;
            custody_directory
                .sync_all()
                .map_err(|error| LaneError::operation("container-evidence", error.to_string()))?;
            build::publish(&evidence_path, &bytes)
        });
    evidence["removal"] = match remove_container(program, vector, environment, owner_home) {
        Ok(result) => result,
        Err(error) => json!({"state":"failed","error":error.line()}),
    };
    if driver_death.is_some() {
        evidence["reaping"]["state"] = json!(if progress.stop_error.is_none()
            && matches!(
                evidence["removal"]["state"].as_str(),
                Some("absent" | "removed")
            ) {
            "survivors-reaped"
        } else {
            "unmeasured"
        });
    }
    let final_publish = serde_json::to_vec(&evidence)
        .map_err(|error| LaneError::operation("container-evidence", error.to_string()))
        .and_then(|bytes| {
            build::publish(&custody_path, &bytes)?;
            custody_directory
                .sync_all()
                .map_err(|error| LaneError::operation("container-evidence", error.to_string()))?;
            build::publish(&evidence_path, &bytes)
        });
    let end_record = progress
        .attempt_wall
        .map(|end| record_attempt_wall(reservation, record, end))
        .transpose();
    let frame_error = progress
        .attempt_wall
        .map_or(Ok(()), |end| {
            frame(&writer, b'W', end.diagnostic().as_bytes())
        })
        .and_then(|()| frame(&writer, b'X', &progress.code.to_le_bytes()))
        .err()
        .filter(|_| !cancelled.load(Ordering::Acquire))
        .map(|error| LaneError::operation("helper-channel", error.to_string()));
    if let Some(error) = progress
        .setup_error
        .or(progress.wait_error)
        .or_else(|| {
            progress
                .stream_errors
                .into_iter()
                .next()
                .map(|(_, error)| error)
        })
        .or(progress.stop_error)
        .or_else(|| initial_publish.err())
        .or_else(|| final_publish.err())
        .or_else(|| end_record.err())
        .or(frame_error)
    {
        return Err(error);
    }
    if driver_death.is_some() {
        return Err(LaneError::operation(
            if evidence["reaping"]["state"] == "survivors-reaped" {
                "survivors-reaped"
            } else {
                "run-reaping"
            },
            evidence["reaping"].to_string(),
        ));
    }
    Ok(AttemptOutcome {
        thread: captured_thread,
        code: progress.code,
        capacity: progress.capacity,
        attempt_wall: progress.attempt_wall,
    })
}

fn measured_driver_end(reservation: &Path, initial: &Value) -> Result<Option<Value>, LaneError> {
    // serve authorizes every request against this identity before starting an attempt.
    let Some(pid) = initial["driver_entry_pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
    else {
        return Ok(None);
    };
    let start = initial["driver_entry_start"]
        .as_u64()
        .ok_or_else(|| LaneError::input("helper-session", "driver start tick absent"))?;
    let current = read_reservation(reservation)?
        .ok_or_else(|| LaneError::input("helper-session", "reservation disappeared"))?;
    if ["loop", "run", "driver_entry_pid", "driver_entry_start"]
        .iter()
        .any(|key| current[*key] != initial[*key])
    {
        return Err(LaneError::input(
            "helper-session",
            "driver identity changed during attempt",
        ));
    }
    if current["driver_end"]["state"] == "completed" {
        return Ok(Some(
            json!({"pid":pid,"start":start,"state":"recorded-end","end":current["driver_end"]}),
        ));
    }
    match process_presence(pid, start) {
        ProcessPresence::Present => Ok(None),
        ProcessPresence::Absent => Ok(Some(json!({"pid":pid,"start":start,"state":"absent"}))),
        ProcessPresence::Unknown => Err(LaneError::input(
            "helper-session",
            "driver presence is unmeasured",
        )),
    }
}

fn stop_container(
    program: &str,
    vector: &[String],
    environment: &BTreeMap<String, String>,
    owner_home: &Path,
) -> Result<(), LaneError> {
    crate::pinned::owner_executable(Path::new(program), Uid::effective().as_raw())?;
    let name = vector
        .iter()
        .find_map(|word| word.strip_prefix("--name="))
        .ok_or_else(|| LaneError::input("helper-pin", "container name is absent"))?;
    build::run_checked(
        Path::new(program),
        vec![
            "stop".into(),
            "--ignore".into(),
            "--time=10".into(),
            name.into(),
        ],
        environment,
        owner_home,
        30,
        "container-stop",
    )?;
    build::run_checked(
        Path::new(program),
        vec!["wait".into(), "--ignore".into(), name.into()],
        environment,
        owner_home,
        30,
        "container-wait",
    )?;
    Ok(())
}

fn listed_container_id(
    program: &str,
    name: &str,
    environment: &BTreeMap<String, String>,
    owner_home: &Path,
) -> Result<Option<String>, LaneError> {
    let listed = build::run_checked(
        Path::new(program),
        vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.ID}} {{.Names}}".into(),
            "--filter".into(),
            format!("name={name}"),
        ],
        environment,
        owner_home,
        30,
        "container-remove",
    )?;
    let mut selected = None;
    for line in listed.lines() {
        let mut words = line.split_whitespace();
        let (Some(id), Some(found_name), None) = (words.next(), words.next(), words.next()) else {
            return Err(LaneError::input(
                "container-remove",
                "container listing has an invalid identity",
            ));
        };
        if found_name == name && selected.replace(id.to_owned()).is_some() {
            return Err(LaneError::input(
                "container-remove",
                format!("container listing repeats {name}"),
            ));
        }
    }
    if let Some(id) = &selected
        && (id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(LaneError::input(
            "container-remove",
            format!("container listing has an invalid full ID for {name}: {id}"),
        ));
    }
    Ok(selected)
}

fn remove_container(
    program: &str,
    vector: &[String],
    environment: &BTreeMap<String, String>,
    owner_home: &Path,
) -> Result<Value, LaneError> {
    crate::pinned::owner_executable(Path::new(program), Uid::effective().as_raw())?;
    let name = vector
        .iter()
        .find_map(|word| word.strip_prefix("--name="))
        .ok_or_else(|| LaneError::input("helper-pin", "container name is absent"))?;
    let labels = vector
        .iter()
        .filter_map(|word| word.strip_prefix("--label="))
        .filter(|label| {
            label.starts_with("org.superloop.loop=") || label.starts_with("org.superloop.run=")
        })
        .collect::<Vec<_>>();
    if labels.len() != 2 {
        return Err(LaneError::input(
            "helper-pin",
            "container loop and run labels are absent",
        ));
    }
    let Some(id) = listed_container_id(program, name, environment, owner_home)? else {
        return Ok(json!({"state":"absent","container_name":name}));
    };
    let inspected = build::run_checked(
        Path::new(program),
        vec![
            "container".into(),
            "inspect".into(),
            "--format".into(),
            "{{json .Config.Labels}}".into(),
            id.clone(),
        ],
        environment,
        owner_home,
        30,
        "container-remove",
    )?;
    let inspected: Value = serde_json::from_str(&inspected).map_err(|error| {
        LaneError::input(
            "container-remove",
            format!("container {id} has invalid label inspection: {error}"),
        )
    })?;
    for label in labels {
        let (key, expected) = label.split_once('=').ok_or_else(|| {
            LaneError::input("container-remove", "planned container label is invalid")
        })?;
        if inspected[key] != expected {
            return Err(LaneError::input(
                "container-remove",
                format!("container {id} named {name} differs at label {key}"),
            ));
        }
    }
    let printed = build::run_checked(
        Path::new(program),
        vec!["rm".into(), "--ignore".into(), id.clone()],
        environment,
        owner_home,
        30,
        "container-remove",
    )?;
    match printed.trim() {
        "" => Ok(json!({"state":"absent","container_name":name,"container_id":id})),
        removed if removed == id => {
            Ok(json!({"state":"removed","container_name":name,"container_id":id}))
        }
        other => Err(LaneError::input(
            "container-remove",
            format!("container removal printed {other}, expected {id} for {name}"),
        )),
    }
}

fn run_identity(run_dir: &Path) -> Result<(PathBuf, String, String, PathBuf), LaneError> {
    run_identity_at(&caller_home()?, run_dir, Uid::effective().as_raw())
}

fn run_identity_at(
    owner_home: &Path,
    run_dir: &Path,
    namespace_owner: u32,
) -> Result<(PathBuf, String, String, PathBuf), LaneError> {
    let invalid = || {
        LaneError::input(
            "helper-pin",
            "run directory is outside the planned runs root",
        )
    };
    if !run_dir.is_absolute()
        || run_dir.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    let run = run_dir
        .file_name()
        .and_then(|part| part.to_str())
        .ok_or_else(invalid)?
        .to_owned();
    let runs = run_dir.parent().ok_or_else(invalid)?;
    if !valid_run_name(&run) {
        return Err(invalid());
    }
    let _protected_root = crate::home::pin_parent(runs, namespace_owner)?;
    let record = read_reservation(&reservation_path(runs, &run))?
        .ok_or_else(|| LaneError::input("helper-pin", "protected run reservation is absent"))?;
    let loop_name = record["loop"].as_str().ok_or_else(invalid)?.to_owned();
    loop_home::validate_name(&loop_name)
        .map_err(|error| LaneError::input("helper-pin", error.message()))?;
    if record["run"] != run || record["plan"]["driver_dir"] != run_dir.display().to_string() {
        return Err(invalid());
    }
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("helper-pin", "reserved runtime program is absent"))?;
    let program = PathBuf::from(program);
    if !program.is_absolute() {
        return Err(LaneError::input(
            "helper-pin",
            "reserved runtime program is not absolute",
        ));
    }
    let (plan, _settings) =
        crate::launch::pinned_plan_from_record(owner_home, &loop_name, &run, &program, &record)
            .map_err(|error| LaneError::input("helper-pin", error.line()))?;
    if plan.driver_dir != run_dir {
        return Err(invalid());
    }
    Ok((owner_home.to_path_buf(), loop_name, run, program))
}

#[allow(unsafe_code)]
fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred, LaneError> {
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = u32::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|error| LaneError::operation("helper-peer", error.to_string()))?;
    // SAFETY: the socket is live, the output has enough space for ucred, and the kernel sets length.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if status != 0 || usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
        return Err(LaneError::operation(
            "helper-peer",
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: successful SO_PEERCRED wrote a complete ucred into the output above.
    let credential = unsafe { credential.assume_init() };
    Ok(credential)
}

fn process_info(pid: u32) -> Result<(u32, u64, u8), LaneError> {
    let path = format!("/proc/{pid}/stat");
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .and_then(|file| file.take(4097).read_to_end(&mut bytes))
        .map_err(|error| LaneError::input("helper-session", format!("{path}: {error}")))?;
    if bytes.len() > 4096 {
        return Err(LaneError::input(
            "helper-session",
            "process record exceeds 4096 bytes",
        ));
    }
    let source = std::str::from_utf8(&bytes)
        .map_err(|error| LaneError::input("helper-session", error.to_string()))?;
    let (_, fields) = source
        .rsplit_once(") ")
        .ok_or_else(|| LaneError::input("helper-session", "process record has no command end"))?;
    let fields = fields.split_whitespace().collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|state| state.as_bytes().first().copied())
        .ok_or_else(|| LaneError::input("helper-session", "process state is absent"))?;
    let parent = fields
        .get(1)
        .ok_or_else(|| LaneError::input("helper-session", "process parent is absent"))?
        .parse::<u32>()
        .map_err(|error| LaneError::input("helper-session", error.to_string()))?;
    let start = fields
        .get(19)
        .ok_or_else(|| LaneError::input("helper-session", "process start is absent"))?
        .parse::<u64>()
        .map_err(|error| LaneError::input("helper-session", error.to_string()))?;
    Ok((parent, start, state))
}

pub(crate) fn process_start(pid: u32) -> Result<u64, LaneError> {
    process_info(pid).map(|(_, start, _)| start)
}

pub(crate) fn process_alive(pid: u32, start: u64) -> bool {
    process_info(pid).is_ok_and(|(_, found, state)| found == start && !matches!(state, b'Z' | b'X'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessPresence {
    Present,
    Absent,
    Unknown,
}

pub(crate) fn process_presence(pid: u32, start: u64) -> ProcessPresence {
    process_presence_with(pid, start, process_info)
}

pub(crate) fn process_presence_with(
    pid: u32,
    start: u64,
    probe: impl FnOnce(u32) -> Result<(u32, u64, u8), LaneError>,
) -> ProcessPresence {
    match probe(pid) {
        Ok((_, found, state)) if found == start && !matches!(state, b'Z' | b'X') => {
            ProcessPresence::Present
        }
        Ok(_) => ProcessPresence::Absent,
        Err(_) => match fs::symlink_metadata(format!("/proc/{pid}")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProcessPresence::Absent,
            _ => ProcessPresence::Unknown,
        },
    }
}

fn in_driver_session(peer_pid: u32, entry_pid: u32, entry_start: u64) -> Result<bool, LaneError> {
    if process_start(entry_pid)? != entry_start {
        return Ok(false);
    }
    let mut current = peer_pid;
    for _ in 0..64 {
        if current == entry_pid {
            return Ok(true);
        }
        let (parent, _, _) = process_info(current)?;
        if parent <= 1 || parent == current {
            return Ok(false);
        }
        current = parent;
    }
    Ok(false)
}

fn authorize_peer(stream: &UnixStream, loop_uid: u32, reservation: &Path) -> Result<(), LaneError> {
    let peer = peer_credentials(stream)?;
    if peer.uid != loop_uid || peer.pid <= 0 {
        return Err(LaneError::input(
            "helper-peer",
            "request did not come from the loop identity",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let record = read_reservation(reservation)?
            .ok_or_else(|| LaneError::input("helper-session", "protected reservation is absent"))?;
        if let (Some(pid), Some(start)) = (
            record["driver_entry_pid"].as_u64(),
            record["driver_entry_start"].as_u64(),
        ) {
            let pid = u32::try_from(pid)
                .map_err(|error| LaneError::input("helper-session", error.to_string()))?;
            let peer_pid = u32::try_from(peer.pid)
                .map_err(|error| LaneError::input("helper-peer", error.to_string()))?;
            if in_driver_session(peer_pid, pid, start)? {
                return Ok(());
            }
            return Err(LaneError::input(
                "helper-peer",
                "request is outside the launched driver session",
            ));
        }
        if Instant::now() >= deadline {
            return Err(LaneError::input(
                "helper-session",
                "launched driver identity was not recorded",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Publish the round's credential before exposing the helper's ready socket.
pub(crate) fn publish_round_credential(
    owner_home: &Path,
    loop_name: &str,
    record: &mut Value,
) -> Result<(), LaneError> {
    let home = record["plan"]["home"]
        .as_str()
        .ok_or_else(|| LaneError::input("credential-publish", "run home is absent"))?;
    let uid = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("credential-publish", "worker UID is absent"))?;
    let step = record["active_round"]
        .as_str()
        .ok_or_else(|| LaneError::input("credential-publish", "active round is absent"))?
        .to_owned();
    let home = PathBuf::from(home);
    let round = record["rounds"]
        .as_array_mut()
        .and_then(|rounds| rounds.last_mut())
        .filter(|round| round["step"] == step)
        .ok_or_else(|| LaneError::input("credential-publish", "active round differs"))?;
    round["credential_publication"] =
        crate::credential::publish_round(owner_home, loop_name, &home, uid)?;
    Ok(())
}

/// Serve one run's fixed container request as the namespace owner.
///
/// # Errors
///
/// Refuses a changed saved request, a foreign peer, or a failed bounded child.
#[allow(clippy::too_many_lines)]
pub fn serve(run_dir: &Path) -> Result<(), LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "helper-identity",
            "rootless namespace owner is required",
        ));
    }
    let (owner_home, loop_name, run, podman) = run_identity(run_dir)?;
    let initial = pinned_request(&owner_home, &loop_name, &run, &podman)?;
    attempt_vector(&initial.argv, &initial.driver_dir, 1)?;
    let loop_uid = initial.loop_uid;
    let driver_dir = initial.driver_dir;
    let socket = socket_path(&driver_dir)?;
    let control = control_socket_path(&driver_dir)?;
    let socket_slot = crate::SocketSlot::pinned(&socket, 0)?;
    let control_slot = crate::SocketSlot::pinned(&control, 0)?;
    if socket_slot
        .metadata()
        .map_err(|error| LaneError::input("helper-socket", error.to_string()))?
        .is_some()
        || control_slot
            .metadata()
            .map_err(|error| LaneError::input("helper-socket", error.to_string()))?
            .is_some()
    {
        return Err(LaneError::input(
            "helper-socket",
            format!(
                "{} or {} already exists",
                socket.display(),
                control.display()
            ),
        ));
    }
    let root = driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("helper-pin", "runs root absent"))?;
    let reservation = reservation_path(root, &run);
    {
        let _lock = crate::launch::lock_runs_root(root, true, 0)?;
        let _mailbox = crate::launch::lock_mailbox(root, &run, 0)?;
        let mut record = crate::launch::read_reservation(&reservation)?
            .ok_or_else(|| LaneError::input("helper-pin", "reservation is absent"))?;
        if record["phase"] != "preparing" || record["loop"] != loop_name || record["run"] != run {
            return Err(LaneError::input(
                "helper-pin",
                "reservation names another run",
            ));
        }
        let pid = std::process::id();
        record["helper_pid"] = json!(pid);
        record["helper_start"] = json!(process_start(pid)?);
        publish_round_credential(&owner_home, &loop_name, &mut record)?;
        crate::launch::publish_reservation(&reservation, &record)?;
    }
    let listener = UnixListener::bind(socket_slot.address())
        .map_err(|error| LaneError::operation("helper-socket", error.to_string()))?;
    socket_slot
        .set_owner_mode(0, loop_uid, 0o660)
        .map_err(|error| LaneError::operation("helper-socket", error.to_string()))?;
    let control_listener = UnixListener::bind(control_slot.address())
        .map_err(|error| LaneError::operation("helper-control", error.to_string()))?;
    control_slot
        .set_owner_mode(0, 0, 0o600)
        .map_err(|error| LaneError::operation("helper-control", error.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let control_cancelled = Arc::clone(&cancelled);
    let controller =
        std::thread::spawn(move || control_loop(&control_listener, &control_cancelled, 0));
    let refresh_cancelled = Arc::clone(&cancelled);
    let refresh_home = owner_home.clone();
    let refresh_loop = loop_name.clone();
    let refresh_root = root.to_path_buf();
    let refresh_driver_dir = driver_dir.clone();
    let refresh_anchors = crate::home::snapshot_private_home()?;
    let refresher = std::thread::Builder::new()
        .name("credential-authority".into())
        .spawn(move || -> Result<(), LaneError> {
            let _verified = crate::home::activate_private_snapshot(refresh_anchors)?;
            let mut published = BTreeMap::new();
            let mut checked = false;
            while !refresh_cancelled.load(Ordering::Acquire) {
                let result = crate::credential::refresh_live(
                    &refresh_home,
                    &refresh_loop,
                    &refresh_root,
                    &mut published,
                );
                if let Some(evidence) = crate::credential::evidence_for_check(&result, !checked)
                    && let Err(error) =
                        crate::credential::publish_evidence(&refresh_driver_dir, &evidence)
                {
                    refresh_cancelled.store(true, Ordering::Release);
                    return Err(error);
                }
                checked = result.is_ok();
                for _ in 0..30 {
                    if refresh_cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Ok(())
        })
        .map_err(|error| LaneError::operation("credential-thread", error.to_string()))?;
    let result = (|| {
        let mut previous_capacity = false;
        let mut retry_thread = None;
        for attempt in 1..=MAX_ATTEMPTS {
            if attempt > 1 && !previous_capacity {
                break;
            }
            let Some(mut stream) = next_client(&listener, &cancelled, initial.launcher)? else {
                break;
            };
            stream
                .set_nonblocking(false)
                .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
            authorize_peer(&stream, loop_uid, &reservation)?;
            let socket_meta = socket_slot
                .metadata()
                .map_err(|error| LaneError::input("helper-socket", error.to_string()))?
                .ok_or_else(|| LaneError::input("helper-socket", "the socket is absent"))?;
            if socket_meta.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || socket_meta.st_mode & 0o7777 != 0o660
            {
                return Err(LaneError::input(
                    "helper-socket",
                    "the loop-group socket changed during the run",
                ));
            }
            let request = pinned_request(&owner_home, &loop_name, &run, &podman)?;
            if request.loop_uid != loop_uid || request.driver_dir != driver_dir {
                return Err(LaneError::input(
                    "helper-pin",
                    "run identity changed after helper readiness",
                ));
            }
            if request.record["driver_entry_pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .is_none()
                || request.record["driver_entry_start"].as_u64().is_none()
            {
                return Err(LaneError::input(
                    "helper-session",
                    "driver identity disappeared after peer authorization",
                ));
            }
            if attempt > 1 && retry_thread.is_none() {
                return Err(LaneError::input(
                    "round-thread",
                    "capacity attempt has no captured thread",
                ));
            }
            let vector = attempt_vector(&request.argv, &driver_dir, attempt)?;
            let outcome = run_attempt(
                &mut stream,
                &vector,
                &request.environment,
                &owner_home,
                &reservation,
                &request.record,
                &driver_dir,
                attempt,
                &cancelled,
                request.launcher,
                retry_thread.as_deref(),
            )?;
            previous_capacity = retry_after(&outcome);
            retry_thread = outcome.thread.or(retry_thread);
        }
        Ok(())
    })();
    cancelled.store(true, Ordering::Release);
    let refresh_result = refresher
        .join()
        .map_err(|_| LaneError::operation("credential-thread", "authority thread panicked"))?;
    let control_result = controller
        .join()
        .map_err(|_| LaneError::operation("helper-control", "control thread panicked"))?;
    let socket_result = socket_slot
        .remove()
        .map_err(|error| LaneError::operation("helper-socket", error.to_string()));
    let control_remove = control_slot
        .remove()
        .map_err(|error| LaneError::operation("helper-control", error.to_string()));
    refresh_result?;
    result?;
    control_result?;
    socket_result?;
    control_remove
}

/// Forward one prompt and bounded result through the fixed run socket as the loop identity.
///
/// # Errors
///
/// Refuses an oversized prompt, malformed frame, or missing final status.
pub fn client(run_dir: &Path) -> Result<i32, LaneError> {
    let identity = ClientSocketIdentity::from_environment()?;
    let slot = attested_client_socket(run_dir, &identity, 0, Uid::effective().as_raw())?;
    let mut prompt = Vec::new();
    std::io::stdin()
        .lock()
        .take((PROMPT_LIMIT + 1) as u64)
        .read_to_end(&mut prompt)
        .map_err(|error| LaneError::operation("helper-prompt", error.to_string()))?;
    if prompt.len() > PROMPT_LIMIT {
        return Err(LaneError::input(
            "helper-prompt",
            "prompt exceeds 1048576 bytes",
        ));
    }
    let thread = requested_thread(run_dir, &prompt)?;
    let prompt = if let Some(thread) = thread {
        let mut request = Vec::with_capacity(prompt.len() + thread.len() + 2);
        request.push(0);
        request.extend_from_slice(thread.as_bytes());
        request.push(0);
        request.extend_from_slice(&prompt);
        request
    } else {
        prompt
    };
    let mut stream = UnixStream::connect(slot.address())
        .map_err(|error| LaneError::operation("helper-socket", error.to_string()))?;
    let length = u32::try_from(prompt.len())
        .map_err(|error| LaneError::input("helper-prompt", error.to_string()))?;
    stream
        .write_all(&length.to_le_bytes())
        .and_then(|()| stream.write_all(&prompt))
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    let mut total = 0;
    loop {
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).map_err(|error| {
            LaneError::operation("helper-channel", format!("status absent: {error}"))
        })?;
        let length = u32::from_le_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| LaneError::operation("helper-channel", "bad frame length"))?,
        ) as usize;
        if length > FRAME_LIMIT {
            return Err(LaneError::input(
                "helper-channel",
                "frame exceeds 8192 bytes",
            ));
        }
        let mut bytes = vec![0_u8; length];
        stream
            .read_exact(&mut bytes)
            .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
        if header[0] == b'X' && length == 4 {
            return Ok(i32::from_le_bytes(bytes.try_into().map_err(|_| {
                LaneError::operation("helper-channel", "bad status")
            })?));
        }
        if header[0] == b'W' {
            let end = std::str::from_utf8(&bytes)
                .ok()
                .and_then(lane_lifecycle::AttemptWall::from_diagnostic)
                .ok_or_else(|| LaneError::input("helper-channel", "bad attempt-wall frame"))?;
            let path = std::env::var_os("LANE_ATTEMPT_END").ok_or_else(|| {
                LaneError::input("helper-channel", "driver attempt end path is absent")
            })?;
            end.publish(Path::new(&path))
                .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
            continue;
        }
        total += length;
        if total > STREAM_LIMIT {
            return Err(LaneError::input(
                "helper-channel",
                "stream exceeds 67108864 bytes",
            ));
        }
        match header[0] {
            b'O' => std::io::stdout().lock().write_all(&bytes),
            b'E' => std::io::stderr().lock().write_all(&bytes),
            _ => return Err(LaneError::input("helper-channel", "unknown frame channel")),
        }
        .map_err(|error| LaneError::operation("helper-channel", error.to_string()))?;
    }
}

#[cfg(test)]
mod tests {
    const TEST_CONTAINER_ID: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_OTHER_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    use super::{
        AttemptOutcome, ClientSocketIdentity, LauncherIdentity, STREAM_DRAIN_GRACE, STREAM_LIMIT,
        STREAM_STOP_GRACE, attempt_vector, attested_client_socket, capacity_event,
        command_for_request, control_loop, decode_round_request, in_driver_session, launcher_alive,
        open_client_runs_root_with, pinned_request, process_start, read_words, remove_container,
        retry_after, run_attempt, run_attempt_with, run_identity_at, start_after_reservation,
        stop_container, verify_vector,
    };

    /// ´test:unit:round-client-refuses-request-owned-by-another-uid´
    #[test]
    fn round_client_refuses_request_owned_by_another_uid() {
        super::validate_request_identity(true, 120, 41001, 0o600, 41001, 41001)
            .expect("loop reader owns request");
        let error = super::validate_request_identity(true, 120, 3000, 0o600, 41001, 41001)
            .expect_err("worker-owned request differs from loop reader");
        assert!(error.line().contains("round-thread"));
        assert!(error.line().contains("reader-owned"));
    }
    use crate::launch::{
        image_check_with_environment, private_podman_environment_from, publish_reservation,
        read_reservation,
    };
    use crate::plan::protected_identifier_path;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn seed_attempt_reservation(root: &Path) {
        publish_reservation(
            &root.join(".reservation-R.json"),
            &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]}),
        )
        .expect("protected attempt reservation");
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´test:unit:host-launch-guard-covers-all-helper-attempts-and-margin´
    #[test]
    fn host_launch_guard_covers_all_helper_attempts_and_margin() {
        for (plan, expected) in [
            (json!({}), 115_500),
            (json!({"attempt_wall_seconds":7}), 328),
        ] {
            let record = json!({"active_round":"review","rounds":[
                {"step":"dispatch","budget_seconds":1},
                {"step":"review","budget_seconds":7200}
            ],"plan":plan});
            let attempt = super::attempt_wall_bound(&record).expect("attempt wall");
            let host = super::host_launch_bound(&record).expect("host guard");
            assert_eq!(host, expected);
            assert!(host > attempt);
            assert_eq!(
                host,
                u64::from(super::MAX_ATTEMPTS) * attempt + super::HOST_LAUNCH_MARGIN_SECONDS
            );
        }
        let record = json!({"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":1}],"plan":{"attempt_wall_seconds":u64::MAX}});
        assert_eq!(
            super::host_launch_bound(&record)
                .expect_err("unrepresentable guard")
                .kind,
            "launch-wall"
        );
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´test:unit:attempt-wall-follows-active-budget-and-explicit-plan´
    #[test]
    fn attempt_wall_follows_active_budget_and_explicit_plan() {
        for (budget, expected) in [
            (1, 4),
            (3499, 13_996),
            (3500, 14_000),
            (3501, 14_004),
            (3600, 14_400),
            (3601, 14_404),
            (7200, 28_800),
            (u64::MAX / 4, u64::MAX - 3),
            (u64::MAX, u64::MAX),
        ] {
            let mut record = json!({"active_round":"review","rounds":[
                {"step":"dispatch","budget_seconds":2},
                {"step":"review","budget_seconds":budget},
                {"step":"later","budget_seconds":3}
            ],"plan":{}});
            assert_eq!(
                super::attempt_wall_bound(&record).expect("budget bound"),
                expected,
                "budget {budget}"
            );
            record["plan"]["attempt_wall_seconds"] = json!(7);
            assert_eq!(
                super::attempt_wall_bound(&record).expect("explicit bound"),
                7
            );
            record["rounds"][1]["budget_seconds"] = serde_json::Value::Null;
            assert_eq!(
                super::attempt_wall_bound(&record)
                    .expect_err("budget required despite override")
                    .kind,
                "attempt-budget"
            );
        }
        for wall in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            serde_json::Value::Null,
        ] {
            let record = json!({"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":1}],"plan":{"attempt_wall_seconds":wall}});
            assert_eq!(
                super::attempt_wall_bound(&record)
                    .expect_err("invalid explicit bound")
                    .kind,
                "attempt-wall"
            );
        }
    }

    /// ´test:unit:attempt-without-active-budget-refuses-before-spawn´
    #[test]
    fn attempt_without_active_budget_refuses_before_spawn() {
        let fixture = StartedAttemptFixture::new("printf started > \"$TEST_REMOVE\"");
        for plan in [json!({}), json!({"attempt_wall_seconds":1})] {
            let (mut server, _client) = UnixStream::pair().expect("channel");
            let record = json!({"active_round":"review","rounds":[{"step":"dispatch","budget_seconds":60},{"step":"review"}],"plan":plan});
            let result = run_attempt(
                &mut server,
                &fixture.vector,
                &fixture.environment,
                fixture.root.path(),
                &fixture.root.path().join(".reservation-R.json"),
                &record,
                &fixture.driver,
                1,
                &AtomicBool::new(false),
                LauncherIdentity {
                    pid: std::process::id(),
                    start: process_start(std::process::id()).expect("launcher"),
                },
                None,
            );
            assert_eq!(
                result.err().expect("missing budget refuses").kind,
                "attempt-budget"
            );
            assert!(!fixture.removal.exists());
            assert!(
                !fixture
                    .driver
                    .join("container-attempt-1.status.json")
                    .exists()
            );
        }
    }

    /// ´test:unit:helper-wall-stop-retains-cause-in-outcome-and-round´
    #[test]
    fn helper_wall_stop_retains_cause_in_outcome_and_round() {
        let fixture = StartedAttemptFixture::new("cat >/dev/null; exec sleep 30");
        let reservation = fixture.root.path().join(".reservation-R.json");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":7200}],"plan":{"attempt_wall_seconds":1}});
        publish_reservation(&reservation, &record).expect("planned wall");
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let began = Instant::now();
        let outcome = run_attempt(
            &mut server,
            &fixture.vector,
            &fixture.environment,
            fixture.root.path(),
            &reservation,
            &record,
            &fixture.driver,
            1,
            &AtomicBool::new(false),
            LauncherIdentity {
                pid: std::process::id(),
                start: process_start(std::process::id()).expect("launcher"),
            },
            None,
        )
        .expect("wall is a named outcome");
        assert!(began.elapsed() < Duration::from_secs(10));
        assert_eq!(outcome.code, 1);
        assert!(!retry_after(&outcome));
        let end = outcome.attempt_wall.expect("named wall");
        assert_eq!(end.bound_seconds, 1);
        assert!(end.wall_seconds >= 1);
        let expected = super::attempt_wall_record(end);
        assert_eq!(fixture.evidence()["attempt_end"], expected);
        assert_eq!(fixture.evidence()["removal"]["state"], "removed");
        let saved = read_reservation(&reservation)
            .expect("read round")
            .expect("round record");
        assert_eq!(saved["rounds"][0]["attempt_end"], expected);
        let mut header = [0_u8; 5];
        client
            .read_exact(&mut header)
            .expect("named completion frame");
        assert_eq!(header[0], b'W');
        let length = u32::from_le_bytes(header[1..].try_into().expect("length"));
        let mut body = vec![0; length as usize];
        client.read_exact(&mut body).expect("wall payload");
        assert_eq!(
            lane_lifecycle::AttemptWall::from_diagnostic(
                std::str::from_utf8(&body).expect("diagnostic")
            ),
            Some(end)
        );
        assert_eq!(read_attempt_status(&mut client), 1);
    }

    /// ´test:unit:client-socket-uses-recorded-root-identity-below-overflow-ancestor´
    #[test]
    fn client_socket_uses_recorded_root_identity_below_overflow_ancestor() {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture mode");
        let root = fixture.path().join("runs");
        fs::create_dir(&root).expect("runs root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let run = root.join("R");
        let socket = root.join(".container-R.sock");
        let listener = UnixListener::bind(&socket).expect("synthetic socket");
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).expect("socket mode");
        let root_meta = fs::metadata(&root).expect("recorded runs root");
        let identity = ClientSocketIdentity {
            root_dev: root_meta.dev(),
            root_ino: root_meta.ino(),
            socket_name: ".container-R.sock".into(),
        };
        let opened = open_client_runs_root_with(&root, |ancestor| {
            assert_eq!(ancestor, fixture.path());
            Ok((libc::S_IFDIR, 65_534))
        })
        .expect("client resolver accepts an overflow-owned ancestor");
        assert_eq!(
            nix::sys::stat::fstat(&opened)
                .expect("resolved root")
                .st_ino,
            root_meta.ino()
        );
        let slot = attested_client_socket(&run, &identity, root_meta.uid(), root_meta.gid())
            .expect("client opens by link-free root identity without ancestor ownership walk");
        assert!(slot.metadata().expect("socket stat").is_some());
        let _client = UnixStream::connect(slot.address()).expect("descriptor-relative connect");
        let (_accepted, _) = listener
            .accept()
            .expect("listener accepts held-root client");
        fs::rename(&root, fixture.path().join("old-runs")).expect("replace root path");
        fs::create_dir(&root).expect("replacement root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        let error = attested_client_socket(&run, &identity, root_meta.uid(), root_meta.gid())
            .err()
            .expect("replacement root has another inode");
        assert_eq!(error.kind, "helper-socket");
        assert!(error.detail.contains("owner-recorded inode"));
    }
    /// ´test:unit:helper-inspect-stop-and-wait-retain-namespace-markers´
    #[test]
    fn helper_inspect_stop_and_wait_retain_namespace_markers() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("home mode");
        let program = root.join("podman-standin");
        let log = root.join("children");
        let image = format!("sha256:{}", "a".repeat(64));
        fs::write(&program, format!("#!/bin/sh\nprintf '%s %s %s %s\\n' \"$1\" \"$2\" \"$_CONTAINERS_USERNS_CONFIGURED\" \"$_CONTAINERS_ROOTLESS_UID\" >> '{}'\nif [ \"$1\" = image ]; then printf '{}\\n'; fi\n", log.display(), image.strip_prefix("sha256:").expect("bare image"))).expect("stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        assert_eq!(
            private_podman_environment_from(root, None, Some("41001"))
                .expect_err("missing marker")
                .kind,
            "namespace-environment"
        );
        assert_eq!(
            private_podman_environment_from(root, Some("1"), None)
                .expect_err("missing uid")
                .kind,
            "namespace-environment"
        );
        let environment = private_podman_environment_from(root, Some("1"), Some("41001"))
            .expect("namespace markers");
        image_check_with_environment(&program, &image, root, &environment).expect("image inspect");
        stop_container(
            program.to_str().expect("program path"),
            &["run".into(), "--name=alpha-R-attempt-1".into()],
            &environment,
            root,
        )
        .expect("stop and wait");
        let children = fs::read_to_string(log).expect("child vectors");
        assert!(children.contains("image inspect 1 41001"));
        assert!(children.contains("stop --ignore 1 41001"));
        assert!(children.contains("wait --ignore 1 41001"));
    }

    fn custom_runs_fixture() -> (TempDir, PathBuf, PathBuf) {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("owner home");
        let custody = home.join(".config/loops/alpha");
        fs::create_dir_all(&custody).expect("custody");
        for parent in [
            home.join(".config"),
            home.join(".config/loops"),
            custody.clone(),
        ] {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .expect("protected config");
        }
        let runs = home.join("custom-runs");
        fs::create_dir(&runs).expect("custom root");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("protected root");
        fs::write(home.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display())).expect("registry");
        let allocations = home.join(".config/loops/allocations.toml");
        fs::write(&allocations, "[alpha]\nuids = { base = 3000, count = 2 }\n")
            .expect("allocation");
        fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600))
            .expect("allocation mode");
        let settings = format!(
            "runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nbackend_argv = {{ codex = [\"/usr/libexec/superloop/codex\"] }}\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
            runs.display(),
            "a".repeat(64),
            home.join("template").display(),
            home.join("sockets").display()
        );
        fs::write(custody.join("workers.toml"), settings).expect("settings");
        fs::set_permissions(
            custody.join("workers.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("settings mode");
        let run_dir = runs.join("R");
        let letter = home.join("letter");
        fs::write(&letter, "Read back.\n").expect("letter without declaration");
        let selection = json!({"model":"gpt-6-sol","effort":"high","model_source":"launch-flag","effort_source":"launch-flag"});
        let (mut plan, _) = crate::load_plan(home, "alpha", "R", (0, 0)).expect("base plan");
        plan.select_worker_uid(3000).expect("worker UID");
        plan.select_container_program(Path::new("/usr/bin/podman"))
            .expect("container program");
        plan.select_launch_model(&selection).expect("flag model");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"plan":plan.document,"model_selection":selection,"letter_source":letter});
        fs::write(
            runs.join(".reservation-R.json"),
            serde_json::to_vec(&record).expect("record"),
        )
        .expect("reservation");
        fs::set_permissions(
            runs.join(".reservation-R.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("reservation mode");
        (fixture, run_dir, letter)
    }

    /// ´test:unit:helper-accepts-a-registered-custom-runs-root´
    #[test]
    fn helper_accepts_a_registered_custom_runs_root() {
        let (fixture, run_dir, _letter) = custom_runs_fixture();
        let home = fixture.path();
        let runs = run_dir.parent().expect("runs root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let identity = run_identity_at(home, &run_dir, owner).expect("custom root accepted");
        assert_eq!(identity.0, home);
        assert_eq!(identity.1, "alpha");
        assert_eq!(identity.2, "R");
        assert_eq!(identity.3, Path::new("/usr/bin/podman"));
        let saved = read_reservation(&runs.join(".reservation-R.json"))
            .expect("read pinned record")
            .expect("present record");
        let (matched, _) = crate::launch::pinned_plan_from_record(
            home,
            "alpha",
            "R",
            Path::new("/usr/bin/podman"),
            &saved,
        )
        .expect("helper pin includes flag selection");
        assert_eq!(matched.document, saved["plan"]);
    }

    /// ´test:unit:helper-pin-refuses-letter-declaration-different-from-record´
    #[test]
    fn helper_pin_refuses_letter_declaration_different_from_record() {
        let (fixture, run_dir, letter) = custom_runs_fixture();
        fs::write(&letter, "Model: different\nEffort: high\n").expect("changed declaration");
        let error = run_identity_at(
            fixture.path(),
            &run_dir,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect_err("the helper pin must reject a different declaration");
        assert_eq!(error.kind, "helper-pin");
        assert!(error.detail.contains("letter declaration differs"));
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´test:unit:helper-retains-the-protected-attempt-wall-in-pinned-plans´
    #[test]
    fn helper_retains_the_protected_attempt_wall_in_pinned_plans() {
        let (fixture, run_dir, _letter) = custom_runs_fixture();
        let path = run_dir
            .parent()
            .expect("runs root")
            .join(".reservation-R.json");
        let mut saved = read_reservation(&path).expect("read").expect("record");
        let settings = fixture.path().join(".config/loops/alpha/workers.toml");
        let source = fs::read_to_string(&settings).expect("settings");
        fs::write(&settings, format!("{source}attempt_wall_seconds = 12\n"))
            .expect("explicit wall");
        let (produced, _) =
            crate::load_plan(fixture.path(), "alpha", "R", (0, 0)).expect("configured plan");
        assert_eq!(produced.document["attempt_wall_seconds"], 12);
        saved["plan"]["attempt_wall_seconds"] = produced.document["attempt_wall_seconds"].clone();
        fs::write(&settings, format!("{source}attempt_wall_seconds = 24\n"))
            .expect("changed settings");
        let (plan, _) = crate::launch::pinned_plan_from_record(
            fixture.path(),
            "alpha",
            "R",
            Path::new("/usr/bin/podman"),
            &saved,
        )
        .expect("explicit protected wall survives reconstruction");
        assert_eq!(plan.document, saved["plan"]);
        saved["plan"]
            .as_object_mut()
            .expect("plan")
            .remove("attempt_wall_seconds");
        let (plan, _) = crate::launch::pinned_plan_from_record(
            fixture.path(),
            "alpha",
            "R",
            Path::new("/usr/bin/podman"),
            &saved,
        )
        .expect("absent pinned wall stays absent");
        assert_eq!(plan.document, saved["plan"]);
    }

    /// # Panics
    /// Panics only if fixture setup or the asserted attempt-wall contract fails.
    ///
    /// ´test:unit:plan-load-refuses-invalid-attempt-wall-settings´
    #[test]
    fn plan_load_refuses_invalid_attempt_wall_settings() {
        let (fixture, _, _) = custom_runs_fixture();
        let settings = fixture.path().join(".config/loops/alpha/workers.toml");
        let source = fs::read_to_string(&settings).expect("settings");
        for value in ["0", "-1", "1.5", "true", "\"12\""] {
            fs::write(
                &settings,
                format!("{source}attempt_wall_seconds = {value}\n"),
            )
            .expect("invalid wall");
            let error = crate::load_plan(fixture.path(), "alpha", "R", (0, 0))
                .expect_err("invalid explicit wall");
            assert_eq!(error.kind, "attempt-wall");
            assert!(error.detail.contains("attempt_wall_seconds"));
        }
    }

    /// ´test:unit:helper-request-rechecks-a-program-replaced-after-readiness´
    #[test]
    fn helper_request_rechecks_a_program_replaced_after_readiness() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected parent");
        let program = fixture.path().join("podman");
        fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("program");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        crate::pinned::owner_executable(&program, nix::unistd::Uid::effective().as_raw())
            .expect("ready helper sees the program");
        fs::remove_file(&program).expect("replace between readiness and request");
        std::os::unix::fs::symlink("/usr/bin/true", &program).expect("replacement link");
        let refusal = pinned_request(fixture.path(), "alpha", "R", &program)
            .err()
            .expect("request checks the executable before reading the run");
        assert_eq!(refusal.kind, "owner-program");
    }

    /// ´test:unit:helper-requires-capacity-evidence-and-the-launched-session-for-retry´
    #[test]
    fn helper_requires_capacity_evidence_and_the_launched_session_for_retry() {
        assert!(capacity_event(
            b"{\"type\":\"error\",\"message\":\"The model is at capacity\"}\n"
        ));
        assert!(!capacity_event(
            b"{\"type\":\"item.completed\",\"message\":\"model at capacity\"}\n"
        ));
        assert!(!capacity_event(
            b"{\"type\":\"error\",\"message\":\"model access denied\"}\n"
        ));
        assert!(retry_after(&AttemptOutcome {
            thread: None,
            code: 1,
            capacity: true,
            attempt_wall: None,
        }));
        assert!(!retry_after(&AttemptOutcome {
            thread: None,
            code: 0,
            capacity: true,
            attempt_wall: None,
        }));
        assert!(!retry_after(&AttemptOutcome {
            thread: None,
            code: 1,
            capacity: false,
            attempt_wall: None,
        }));
        let pid = std::process::id();
        let start = process_start(pid).expect("current process start");
        assert!(in_driver_session(pid, pid, start).expect("same session"));
        assert!(!in_driver_session(pid, pid, start + 1).expect("reused pid refused"));
    }

    /// ´test:unit:helper-removes-after-status-and-records-removal-failure´
    #[test]
    fn helper_removes_after_status_and_records_removal_failure() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("protected fixture");
        seed_attempt_reservation(root);
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver directory");
        let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
        fs::create_dir(&custody).expect("custody directory");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        let evidence = driver.join("container-attempt-1.status.json");
        let calls = root.join("remove-args");
        let program = root.join("runtime-standin");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n run) exit 42;;\n ps) printf '%s %s\\n' '{TEST_CONTAINER_ID}' 'superloop-lane-alpha-R-attempt-1';;\n container) printf '%s\\n' '{{\"org.superloop.loop\":\"alpha\",\"org.superloop.run\":\"R\"}}';;\n rm) test -s '{}' || exit 97; printf '%s\\n' \"$@\" > '{}'; exit 7;;\nesac\n",
                evidence.display(),
                calls.display()
            ),
        )
        .expect("runtime stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        let vector = vec![
            program.display().to_string(),
            "run".into(),
            "--name=superloop-lane-alpha-R-attempt-1".into(),
            "--label=org.superloop.loop=alpha".into(),
            "--label=org.superloop.run=R".into(),
        ];
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let launcher = LauncherIdentity {
            pid: std::process::id(),
            start: process_start(std::process::id()).expect("launcher start"),
        };
        let outcome = run_attempt(
            &mut server,
            &vector,
            &private_podman_environment_from(root, Some("1"), Some("41001"))
                .expect("namespace environment"),
            root,
            &root.join(".reservation-R.json"),
            &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]}),
            &driver,
            1,
            &AtomicBool::new(false),
            launcher,
            None,
        )
        .expect("attempt status survives removal failure");
        assert_eq!(outcome.code, 42);
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence).expect("attempt evidence"))
                .expect("evidence JSON");
        assert_eq!(saved["status"], 42);
        assert_eq!(saved["removal"]["state"], "failed");
        let custody_evidence = custody.join("container-attempt-1.status.json");
        let protected: serde_json::Value =
            serde_json::from_slice(&fs::read(&custody_evidence).expect("owner attempt custody"))
                .expect("custody JSON");
        assert_eq!(protected, saved);
        assert_ne!(
            std::os::unix::fs::MetadataExt::uid(
                &fs::metadata(&custody_evidence).expect("custody owner")
            ),
            3000
        );
        assert!(
            saved["removal"]["error"]
                .as_str()
                .expect("removal error")
                .contains("exit status: 7")
        );
        let arguments = fs::read_to_string(calls).expect("removal after evidence");
        assert_eq!(arguments, format!("rm\n--ignore\n{TEST_CONTAINER_ID}\n"));
        let mut frame = [0_u8; 9];
        client.read_exact(&mut frame).expect("status frame");
        assert_eq!(frame[0], b'X');
        assert_eq!(
            i32::from_le_bytes(frame[5..9].try_into().expect("status bytes")),
            42
        );
    }

    /// ´test:unit:helper-removes-after-disconnected-output-and-retains-stream-error´
    #[test]
    fn helper_removes_after_disconnected_output_and_retains_stream_error() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("protected fixture");
        seed_attempt_reservation(root);
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver directory");
        let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
        fs::create_dir(&custody).expect("custody directory");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        let evidence = driver.join("container-attempt-1.status.json");
        let calls = root.join("remove-args");
        let program = root.join("runtime-standin");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n run) exec /usr/bin/yes output;;\n stop|wait) exit 0;;\n ps) printf '%s %s\\n' '{TEST_CONTAINER_ID}' 'superloop-lane-alpha-R-attempt-1';;\n container) printf '%s\\n' '{{\"org.superloop.loop\":\"alpha\",\"org.superloop.run\":\"R\"}}';;\n rm) test -s '{}' || exit 97; printf '%s\\n' \"$@\" > '{}'; printf '%s\\n' '{TEST_CONTAINER_ID}';;\nesac\n",
                evidence.display(),
                calls.display()
            ),
        )
        .expect("runtime stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        let vector = vec![
            program.display().to_string(),
            "run".into(),
            "--name=superloop-lane-alpha-R-attempt-1".into(),
            "--label=org.superloop.loop=alpha".into(),
            "--label=org.superloop.run=R".into(),
        ];
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        let reader = std::thread::spawn(move || {
            client
                .write_all(&0_u32.to_le_bytes())
                .expect("empty prompt");
            let mut header = [0_u8; 5];
            client.read_exact(&mut header).expect("first output header");
            assert_eq!(header[0], b'O');
            let length = u32::from_le_bytes(header[1..5].try_into().expect("frame length"));
            let mut body = vec![0_u8; length as usize];
            client.read_exact(&mut body).expect("first output body");
        });
        let launcher = LauncherIdentity {
            pid: std::process::id(),
            start: process_start(std::process::id()).expect("launcher start"),
        };
        let refusal = run_attempt(
            &mut server,
            &vector,
            &private_podman_environment_from(root, Some("1"), Some("41001"))
                .expect("namespace environment"),
            root,
            &root.join(".reservation-R.json"),
            &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]}),
            &driver,
            1,
            &AtomicBool::new(false),
            launcher,
            None,
        )
        .err()
        .expect("disconnected output is a stream refusal");
        reader
            .join()
            .expect("client received output before disconnect");
        assert_eq!(refusal.kind, "container-stream");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(evidence).expect("attempt evidence"))
                .expect("evidence JSON");
        assert_eq!(saved["stream_error"]["stream"], "stdout");
        assert_eq!(saved["stream_error"]["reason"], refusal.detail);
        assert_eq!(saved["removal"]["state"], "removed");
        let arguments = fs::read_to_string(calls).expect("removal after evidence");
        assert_eq!(arguments, format!("rm\n--ignore\n{TEST_CONTAINER_ID}\n"));
    }

    struct StartedAttemptFixture {
        root: TempDir,
        driver: PathBuf,
        removal: PathBuf,
        vector: Vec<String>,
        environment: BTreeMap<String, String>,
    }

    /// ´test:unit:helper-reaps-dead-driver-through-built-process´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn helper_reaps_dead_driver_through_built_process() {
        if let Some(ready) = std::env::var_os("HELPER_DRIVER_READY") {
            fs::write(ready, b"ready").expect("driver ready");
            std::thread::sleep(Duration::from_secs(60));
            return;
        }
        for recorded_end in [false, true] {
            let mut fixture = StartedAttemptFixture::new(
                "printf started > \"$TEST_STARTED\"; exec /bin/sleep 30",
            );
            let ready = fixture.root.path().join("driver-ready");
            let mut driver = crate::fixture_exec::spawn(
                Command::new(std::env::current_exe().expect("test binary"))
                    .args([
                        "--exact",
                        "container_helper::tests::helper_reaps_dead_driver_through_built_process",
                        "--nocapture",
                    ])
                    .env("HELPER_DRIVER_READY", &ready)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
            )
            .expect("built driver process");
            wait_fixture_ready(&ready).expect("driver start");
            let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,
                "driver_entry_pid":driver.id(),"driver_entry_start":process_start(driver.id()).expect("driver identity"),
                "active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]});
            let reservation = fixture.root.path().join(".reservation-R.json");
            publish_reservation(&reservation, &record).expect("record");
            let started = fixture.root.path().join("container-started");
            fixture
                .environment
                .insert("TEST_STARTED".into(), started.display().to_string());
            let stopped = fixture.root.path().join("stopped");
            fixture
                .environment
                .insert("TEST_STOP_MARKER".into(), stopped.display().to_string());
            let (mut server, mut client) = UnixStream::pair().expect("channel");
            client.write_all(&0_u32.to_le_bytes()).expect("prompt");
            let saved = record.clone();
            let reservation_copy = reservation.clone();
            let helper = std::thread::spawn(move || {
                let pid = std::process::id();
                let result = run_attempt(
                    &mut server,
                    &fixture.vector,
                    &fixture.environment,
                    fixture.root.path(),
                    &reservation_copy,
                    &saved,
                    &fixture.driver,
                    1,
                    &AtomicBool::new(false),
                    LauncherIdentity {
                        pid,
                        start: process_start(pid).expect("launcher"),
                    },
                    None,
                );
                (result, fixture.evidence(), fixture)
            });
            wait_fixture_ready(&started).expect("container started");
            publish_reservation(&reservation, &json!({"schema":1,"phase":"started"}))
                .expect("temporarily unmeasured identity");
            std::thread::sleep(Duration::from_millis(2100));
            assert!(
                !stopped.exists(),
                "unknown presence must not stop a live driver"
            );
            publish_reservation(&reservation, &record).expect("identity restored");
            let began = Instant::now();
            if recorded_end {
                let mut ended = record;
                ended["driver_end"] = json!({"state":"completed","successful":false});
                publish_reservation(&reservation, &ended).expect("recorded end");
            } else {
                driver.kill().expect("driver dies");
            }
            let (result, evidence, fixture) = helper.join().expect("helper finishes");
            if recorded_end {
                driver.kill().expect("end fixture driver");
            }
            driver.wait().expect("reap fixture driver");
            assert_eq!(result.err().expect("named reap").kind, "survivors-reaped");
            assert_eq!(
                evidence["reaping"]["driver"]["state"],
                if recorded_end {
                    "recorded-end"
                } else {
                    "absent"
                }
            );
            assert_eq!(evidence["reaping"]["state"], "survivors-reaped");
            assert_eq!(evidence["removal"]["state"], "removed");
            assert!(stopped.exists() && fixture.removal.exists());
            assert!(began.elapsed() < Duration::from_secs(10));
            drop(client);
        }
    }

    impl StartedAttemptFixture {
        fn new(run: &str) -> Self {
            let root = TempDir::new_in("/tmp").expect("fixture");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("protected fixture");
            seed_attempt_reservation(root.path());
            let driver = root.path().join("R");
            fs::create_dir(&driver).expect("driver directory");
            let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
            fs::create_dir(&custody).expect("custody directory");
            fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
            let removal = root.path().join("removed");
            let program = root.path().join("runtime-standin");
            fs::write(
                &program,
                format!(
                    "#!/bin/sh\ncase \"$1\" in\n run) {run};;\n stop) if [ -n \"$TEST_STOP_MARKER\" ]; then printf stopped > \"$TEST_STOP_MARKER\"; fi; exit 0;;\n wait) exit 0;;\n ps) if [ \"$TEST_REMOVE_CASE\" != absent ]; then printf '%s %s\\n' '{TEST_CONTAINER_ID}' 'superloop-lane-alpha-R-attempt-1'; fi; if [ \"$TEST_REMOVE_CASE\" = two ]; then printf '%s %s\\n' '{TEST_OTHER_ID}' 'superloop-lane-alpha-R-attempt-2'; fi;;\n container) printf '%s\\n' '{{\"org.superloop.loop\":\"alpha\",\"org.superloop.run\":\"R\"}}';;\n rm) printf removed > \"$TEST_REMOVE\"; if [ -n \"$TEST_REMOVED_ID\" ]; then printf '%s' \"$3\" > \"$TEST_REMOVED_ID\"; fi; if [ \"$TEST_REMOVE_CASE\" = mismatch ]; then printf '%s\\n' '{TEST_OTHER_ID}'; else printf '%s\\n' \"$3\"; fi;;\nesac\n"
                ),
            )
            .expect("runtime stand-in");
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
            let vector = vec![
                program.display().to_string(),
                "run".into(),
                "--name=superloop-lane-alpha-R-attempt-1".into(),
                "--label=org.superloop.loop=alpha".into(),
                "--label=org.superloop.run=R".into(),
            ];
            let mut environment =
                private_podman_environment_from(root.path(), Some("1"), Some("41001"))
                    .expect("namespace environment");
            environment.insert("TEST_REMOVE".into(), removal.display().to_string());
            Self {
                root,
                driver,
                removal,
                vector,
                environment,
            }
        }

        fn run(
            &self,
            server: &mut UnixStream,
            stream_limit: usize,
            try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
        ) -> Result<AttemptOutcome, crate::error::LaneError> {
            self.run_with_thread_gate(
                server,
                stream_limit,
                STREAM_DRAIN_GRACE,
                STREAM_STOP_GRACE,
                try_wait,
                |_| Ok(()),
            )
        }

        fn run_with_thread_gate(
            &self,
            server: &mut UnixStream,
            stream_limit: usize,
            drain_grace: Duration,
            stop_grace: Duration,
            try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
            spawn_gate: impl FnMut(&'static str) -> std::io::Result<()>,
        ) -> Result<AttemptOutcome, crate::error::LaneError> {
            self.run_with_seams(
                server,
                stream_limit,
                drain_grace,
                stop_grace,
                try_wait,
                spawn_gate,
                |_| Ok(()),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn run_with_seams(
            &self,
            server: &mut UnixStream,
            stream_limit: usize,
            drain_grace: Duration,
            stop_grace: Duration,
            try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
            spawn_gate: impl FnMut(&'static str) -> std::io::Result<()>,
            after_start: impl FnMut(u32) -> Result<(), crate::error::LaneError>,
        ) -> Result<AttemptOutcome, crate::error::LaneError> {
            let pid = std::process::id();
            run_attempt_with(
                server,
                &self.vector,
                &self.environment,
                self.root.path(),
                &self.root.path().join(".reservation-R.json"),
                &json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]}),
                &self.driver,
                1,
                &AtomicBool::new(false),
                LauncherIdentity {
                    pid,
                    start: process_start(pid).expect("launcher start"),
                },
                stream_limit,
                drain_grace,
                stop_grace,
                try_wait,
                spawn_gate,
                after_start,
                None,
            )
        }

        fn evidence(&self) -> serde_json::Value {
            self.attempt_evidence(1)
        }

        fn attempt_evidence(&self, attempt: u32) -> serde_json::Value {
            let name = format!("container-attempt-{attempt}.status.json");
            let bytes = fs::read(self.driver.join(name)).expect("attempt evidence");
            serde_json::from_slice(&bytes).expect("evidence JSON")
        }

        fn assert_retry_identity(&self, attempt: u32, resumed: Option<&str>) {
            let evidence = self.attempt_evidence(attempt);
            assert_eq!(evidence["thread_id"], "thread-1");
            assert_eq!(evidence["resume_thread"], json!(resumed));
            assert_eq!(evidence["thread_id_source"], "captured");
            let custody = crate::plan::protected_identity_dir(&self.driver).expect("custody");
            let protected: serde_json::Value = serde_json::from_slice(
                &fs::read(custody.join(format!("container-attempt-{attempt}.status.json")))
                    .expect("protected evidence"),
            )
            .expect("protected JSON");
            assert_eq!(protected, evidence);
        }
    }

    /// # Panics
    /// Panics only if fixture setup fails or the asserted retry contract is violated.
    /// ´test:unit:boxed-capacity-retry-resumes-captured-thread-after-large-output´
    #[test]
    fn boxed_capacity_retry_resumes_captured_thread_after_large_output() {
        for step in ["dispatch", "review"] {
            let mut fixture = StartedAttemptFixture::new(
                r#"
cat > "$TEST_HOME/input"
printf '%s\n' "$@" > "$TEST_HOME/argv"
if [ ! -f "$TEST_HOME/.codex/rollout" ]; then
    mkdir -p "$TEST_HOME/.codex"
    printf thread-1 > "$TEST_HOME/.codex/rollout"
    printf '%s\n' '{"type":"thread.started","thread_id":"thread-1"}'
    awk 'BEGIN { for (i=0; i<70000; i++) print "{\"type\":\"notice\",\"text\":\"padding\"}" }'
    printf '%s\n' '{"type":"error","message":"The selected model is at capacity"}'
    printf '%s\n' '{"type":"turn.failed","error":{"message":"The selected model is at capacity"}}'
    exit 1
fi
case " $* " in *' resume thread-1 - '*) ;; *) exit 98;; esac
test "$(cat "$TEST_HOME/.codex/rollout")" = thread-1 || exit 97
printf '%s\n' '{"type":"thread.started","thread_id":"thread-1"}'
printf '%s\n' '{"type":"turn.completed","usage":{}}'
exit 0
"#,
            );
            let retained_home = fixture.root.path().join("retained-home");
            fs::create_dir(&retained_home).expect("retained home");
            fixture
                .environment
                .insert("TEST_HOME".into(), retained_home.display().to_string());
            fixture.vector.push(format!(
                "--cidfile={}",
                protected_identifier_path(&fixture.driver, 1)
                    .expect("identifier")
                    .display()
            ));
            fixture.vector.extend([
                "/home/worker/.local/bin/codex".into(),
                "exec".into(),
                "--json".into(),
                "-".into(),
            ]);
            let prompt = format!("Read /home/worker/.local/inbox/{step}.md.");
            let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":step,"thread_id":"thread-1","rounds":[{"step":step,"budget_seconds":3600}]});
            let mut retry_thread = None;
            for attempt in 1..=2 {
                let (mut server, mut client) = UnixStream::pair().expect("channel");
                let mut request = Vec::new();
                if step == "review" {
                    request.extend_from_slice(b"\0thread-1\0");
                }
                request.extend_from_slice(prompt.as_bytes());
                let reader = std::thread::spawn(move || {
                    client
                        .write_all(&u32::try_from(request.len()).expect("length").to_le_bytes())
                        .expect("header");
                    client.write_all(&request).expect("prompt");
                    read_bounded_attempt_status(&mut client, super::STREAM_LIMIT)
                });
                let vector = attempt_vector(&fixture.vector, &fixture.driver, attempt)
                    .expect("attempt vector");
                let pid = std::process::id();
                let outcome = run_attempt(
                    &mut server,
                    &vector,
                    &fixture.environment,
                    fixture.root.path(),
                    &fixture.root.path().join(".reservation-R.json"),
                    &record,
                    &fixture.driver,
                    attempt,
                    &AtomicBool::new(false),
                    LauncherIdentity {
                        pid,
                        start: process_start(pid).expect("launcher"),
                    },
                    retry_thread.as_deref(),
                )
                .expect("attempt completed");
                assert_eq!(reader.join().expect("client drained"), outcome.code);
                assert_eq!(outcome.code, i32::from(attempt == 1));
                assert_eq!(retry_after(&outcome), attempt == 1);
                assert_eq!(outcome.thread.as_deref(), Some("thread-1"));
                fixture.assert_retry_identity(attempt, retry_thread.as_deref());
                retry_thread = outcome.thread;
                assert_eq!(
                    fs::read(retained_home.join("input")).expect("saved prompt"),
                    prompt.as_bytes()
                );
                if attempt == 1 {
                    assert!(
                        fixture.evidence()["stream_bytes"].as_u64().expect("bytes") > 2_000_000
                    );
                    assert_eq!(fixture.evidence()["capacity_evidence"], true);
                } else {
                    let argv =
                        fs::read_to_string(retained_home.join("argv")).expect("resume command");
                    assert!(argv.ends_with("resume\nthread-1\n-\n"), "{argv}");
                    assert_eq!(argv.matches("resume\n").count(), 1);
                }
            }
        }
    }

    /// # Panics
    /// Panics only if fixture setup fails or the asserted retry contract is violated.
    /// ´test:unit:helper-attempt-evidence-omits-the-constant-capture-flag´
    #[test]
    fn helper_attempt_evidence_omits_the_constant_capture_flag() {
        for setup_failure in [false, true] {
            let fixture = StartedAttemptFixture::new("cat >/dev/null; exit 0");
            let (mut server, mut client) = UnixStream::pair().expect("channel");
            let reader = std::thread::spawn(move || {
                client
                    .write_all(&0_u32.to_le_bytes())
                    .expect("empty prompt");
                read_attempt_status(&mut client)
            });
            let result = fixture.run_with_thread_gate(
                &mut server,
                STREAM_LIMIT,
                STREAM_DRAIN_GRACE,
                STREAM_STOP_GRACE,
                Child::try_wait,
                |name| {
                    if setup_failure && name == "stderr" {
                        Err(std::io::Error::other("synthetic thread limit"))
                    } else {
                        Ok(())
                    }
                },
            );
            if setup_failure {
                assert_eq!(
                    result.err().expect("setup refusal").kind,
                    "container-thread"
                );
            } else {
                assert_eq!(result.expect("completed attempt").code, 0);
            }
            assert_eq!(
                reader.join().expect("client status"),
                i32::from(setup_failure)
            );
            let evidence = fixture.evidence();
            assert!(evidence.get("capacity_capture_bounded").is_none());
            assert_eq!(evidence["status"], i32::from(setup_failure));
            let custody = crate::plan::protected_identity_dir(&fixture.driver).expect("custody");
            assert_eq!(
                fs::read(custody.join("container-attempt-1.status.json"))
                    .expect("protected evidence"),
                fs::read(fixture.driver.join("container-attempt-1.status.json"))
                    .expect("driver evidence"),
            );
        }
    }

    /// # Panics
    /// Panics only if fixture setup fails or the asserted retry contract is violated.
    /// ´test:unit:capacity-capture-discards-oversized-fragments-without-losing-later-events´
    #[test]
    fn capacity_capture_discards_oversized_fragments_without_losing_later_events() {
        let mut capture = super::CapacityCapture::default();
        capture.push(b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n");
        let padding = vec![b'x'; super::FRAME_LIMIT];
        for _ in 0..300 {
            capture.push(&padding);
            assert!(capture.tail.len() <= super::CAPACITY_EVIDENCE_LIMIT);
        }
        capture.push(b"{\"type\":\"error\",\"message\":\"model at capacity\"}\n");
        assert!(!capacity_event(&capture.tail));
        capture.push(b"{\"type\":\"error\",\"message\":\"model at capacity\"}\n");
        assert!(capacity_event(&capture.tail));
        assert_eq!(capture.thread.as_deref(), Some("thread-1"));
    }

    /// ´test:unit:helper-starts-saved-first-command-and-resumed-review-command´
    #[test]
    fn helper_starts_saved_first_command_and_resumed_review_command() {
        for (step, requested, succeeds, capacity) in [
            ("dispatch", None, true, false),
            ("review", Some("thread-1"), true, false),
            ("review", Some("thread-1"), true, true),
            ("review", Some("thread-2"), false, false),
        ] {
            let run = if capacity {
                "printf '%s\\n' \"$@\" > \"$TEST_ARGV\"; cat >/dev/null; printf '%s\\n' '{\"type\":\"error\",\"message\":\"model at capacity\"}'; exit 1"
            } else {
                "printf '%s\\n' \"$@\" > \"$TEST_ARGV\"; cat >/dev/null; exit 0"
            };
            let mut fixture = StartedAttemptFixture::new(run);
            let arguments = fixture.root.path().join("started-argv");
            fixture
                .environment
                .insert("TEST_ARGV".into(), arguments.display().to_string());
            fixture.vector.extend([
                "/home/worker/.local/bin/codex".into(),
                "exec".into(),
                "-m".into(),
                "gpt-6-sol".into(),
                "-c".into(),
                "model_reasoning_effort=high".into(),
                "--json".into(),
                "-".into(),
            ]);
            let (mut server, mut client) = UnixStream::pair().expect("channel");
            let prompt = b"Read /home/worker/.local/inbox/review.md.";
            let mut request = Vec::new();
            if let Some(thread) = requested {
                request.push(0);
                request.extend_from_slice(thread.as_bytes());
                request.push(0);
            }
            request.extend_from_slice(prompt);
            client
                .write_all(
                    &u32::try_from(request.len())
                        .expect("bounded request")
                        .to_le_bytes(),
                )
                .expect("length");
            client.write_all(&request).expect("round request");
            let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":step,"thread_id":"thread-1","rounds":[{"step":step,"budget_seconds":3600}]});
            let pid = std::process::id();
            let result = run_attempt(
                &mut server,
                &fixture.vector,
                &fixture.environment,
                fixture.root.path(),
                &fixture.root.path().join(".reservation-R.json"),
                &record,
                &fixture.driver,
                1,
                &AtomicBool::new(false),
                LauncherIdentity {
                    pid,
                    start: process_start(pid).expect("launcher start"),
                },
                None,
            );
            if succeeds {
                let outcome = result.expect("box command started");
                assert_eq!(outcome.code, i32::from(capacity));
                assert_eq!(read_attempt_status(&mut client), i32::from(capacity));
                assert_eq!(retry_after(&outcome), capacity);
                assert_eq!(outcome.thread.as_deref(), requested);
                // No thread.started is emitted, including on capacity refusal:
                // resume names its request as source; dispatch has no identity.
                let evidence = fixture.evidence();
                assert_eq!(evidence["thread_id"], json!(requested));
                if requested.is_none() {
                    assert_eq!(evidence.get("thread_id_source"), Some(&Value::Null));
                } else {
                    assert_eq!(evidence.get("thread_id_source"), Some(&json!("requested")));
                }
                let started = fs::read_to_string(&arguments).expect("started arguments");
                let expected = if step == "dispatch" {
                    fixture.vector[1..].to_vec()
                } else {
                    super::resume_box_vector(&fixture.vector, "thread-1").expect("resume vector")
                        [1..]
                        .to_vec()
                };
                assert_eq!(started, format!("{}\n", expected.join("\n")));
                if step == "review" {
                    assert!(started.ends_with("resume\nthread-1\n-\n"));
                }
            } else {
                let error = result.err().expect("wrong request thread refuses");
                assert!(error.line().contains("round-thread"));
                assert!(!arguments.exists());
            }
            let decoded = decode_round_request(request).expect("round framing");
            assert_eq!(decoded.0.as_deref(), requested);
            assert_eq!(decoded.1, prompt);
            assert_eq!(
                command_for_request(&fixture.vector, &record, requested).is_ok(),
                succeeds
            );
        }
    }

    /// ´test:unit:helper-removal-selects-only-the-recorded-attempt´
    #[test]
    fn helper_removal_selects_only_the_recorded_attempt() {
        let mut fixture = StartedAttemptFixture::new("exit 0");
        fixture
            .environment
            .insert("TEST_REMOVE_CASE".into(), "two".into());
        let removed_id = fixture.root.path().join("removed-id");
        fixture
            .environment
            .insert("TEST_REMOVED_ID".into(), removed_id.display().to_string());
        let vector = fixture
            .vector
            .iter()
            .map(|word| word.replace("-attempt-1", "-attempt-2"))
            .collect::<Vec<_>>();
        let result = remove_container(
            &fixture.vector[0],
            &vector,
            &fixture.environment,
            fixture.root.path(),
        )
        .expect("only the second attempt is selected");
        assert_eq!(result["state"], "removed");
        assert_eq!(result["container_id"], TEST_OTHER_ID);
        assert_eq!(
            fs::read_to_string(removed_id).expect("removed ID"),
            TEST_OTHER_ID
        );
    }

    /// ´test:unit:helper-records-an-absent-attempt-removal´
    #[test]
    fn helper_records_an_absent_attempt_removal() {
        let mut fixture = StartedAttemptFixture::new("exit 0");
        fixture
            .environment
            .insert("TEST_REMOVE_CASE".into(), "absent".into());
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        fixture
            .run(&mut server, STREAM_LIMIT, Child::try_wait)
            .expect("attempt status");
        let evidence = fixture.evidence();
        assert_eq!(evidence["removal"]["state"], "absent");
        assert!(!fixture.removal.exists());
    }

    /// ´test:unit:helper-records-a-mismatched-removed-identity´
    #[test]
    fn helper_records_a_mismatched_removed_identity() {
        let mut fixture = StartedAttemptFixture::new("exit 0");
        fixture
            .environment
            .insert("TEST_REMOVE_CASE".into(), "mismatch".into());
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        fixture
            .run(&mut server, STREAM_LIMIT, Child::try_wait)
            .expect("attempt status survives removal failure");
        let evidence = fixture.evidence();
        assert_eq!(evidence["removal"]["state"], "failed");
        assert!(
            evidence["removal"]["error"]
                .as_str()
                .expect("removal refusal")
                .contains(TEST_OTHER_ID)
        );
    }

    struct HolderState {
        child: Option<Child>,
        closed: bool,
    }

    struct HolderGuard(Arc<Mutex<HolderState>>);

    impl HolderGuard {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(HolderState {
                child: None,
                closed: false,
            })))
        }

        fn slot(&self) -> Arc<Mutex<HolderState>> {
            Arc::clone(&self.0)
        }

        fn close(&self) {
            let child = {
                let mut state = self.0.lock().expect("holder lock");
                state.closed = true;
                state.child.take()
            };
            if let Some(mut child) = child {
                let _ignored = child.kill();
                let _ignored = child.wait();
            }
        }
    }

    impl Drop for HolderGuard {
        fn drop(&mut self) {
            self.close();
        }
    }

    fn wait_fixture_ready(path: &Path) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if path.exists() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "fixture child did not signal readiness",
            ))
        }
    }

    fn hold_stdout(
        pid: u32,
        holder: &Arc<Mutex<HolderState>>,
        ready: &Path,
        release: &Path,
        published: &mpsc::SyncSender<()>,
    ) -> std::io::Result<()> {
        wait_fixture_ready(ready)?;
        let writer = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/fd/1"))?;
        let child = Command::new("/bin/sleep")
            .arg0("r002d23-fixture-holder")
            .arg("30")
            .process_group(0)
            .stdout(Stdio::from(writer))
            .spawn()?;
        let mut child = Some(child);
        let closed = {
            let mut state = holder.lock().expect("holder lock");
            if state.closed {
                true
            } else {
                state.child = child.take();
                false
            }
        };
        if closed && let Some(mut child) = child {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
        let _ = published.send(());
        fs::write(release, b"")
    }

    fn retained_reader_fixture() -> (StartedAttemptFixture, PathBuf, PathBuf) {
        let mut fixture = StartedAttemptFixture::new(
            "printf ready > \"$TEST_READY\"; while [ ! -e \"$TEST_RELEASE\" ]; do sleep 0.01; done; exit 0",
        );
        let ready = fixture.root.path().join("ready");
        let release = fixture.root.path().join("release");
        fixture
            .environment
            .insert("TEST_READY".into(), ready.display().to_string());
        fixture
            .environment
            .insert("TEST_RELEASE".into(), release.display().to_string());
        (fixture, ready, release)
    }

    fn finish_held_runner<T>(
        guard: &HolderGuard,
        published: &mpsc::Receiver<()>,
        runner: JoinHandle<T>,
        bound: Duration,
    ) -> T {
        let handoff = published.recv_timeout(Duration::from_secs(5)).is_ok();
        let deadline = Instant::now() + bound;
        while !runner.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let bounded = runner.is_finished();
        guard.close();
        let result = runner.join().expect("reap fixture runner");
        assert!(handoff, "holder was published before the bound began");
        assert!(bounded, "fixture runner exceeded its cleanup bound");
        result
    }

    fn read_attempt_status(stream: &mut UnixStream) -> i32 {
        read_bounded_attempt_status(stream, 32_768)
    }

    fn read_bounded_attempt_status(stream: &mut UnixStream, output_bound: usize) -> i32 {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bounded status read");
        let mut total = 0;
        loop {
            let mut header = [0_u8; 5];
            stream.read_exact(&mut header).expect("frame header");
            let length = u32::from_le_bytes(header[1..5].try_into().expect("frame length"));
            let mut body = vec![0_u8; length as usize];
            stream.read_exact(&mut body).expect("frame body");
            if header[0] == b'X' {
                assert_eq!(length, 4);
                return i32::from_le_bytes(body.try_into().expect("status bytes"));
            }
            assert!(matches!(header[0], b'O' | b'E'));
            total += length as usize;
            assert!(total < output_bound, "fixture output remains bounded");
        }
    }

    /// ´test:unit:helper-records-closed-stdin-and-unsuccessful-status´
    #[test]
    fn helper_records_closed_stdin_and_unsuccessful_status() {
        let fixture = StartedAttemptFixture::new("exec 0<&-; sleep 0.1; exit 0");
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        let reader = std::thread::spawn(move || {
            client
                .write_all(&(1_048_576_u32).to_le_bytes())
                .expect("prompt length");
            client
                .write_all(&vec![b'p'; 1_048_576])
                .expect("large prompt");
            read_attempt_status(&mut client)
        });
        let refusal = fixture
            .run(&mut server, STREAM_LIMIT, Child::try_wait)
            .err()
            .expect("closed stdin refuses");
        assert_eq!(reader.join().expect("status reader"), 1);
        assert_eq!(refusal.kind, "container-stream");
        let evidence = fixture.evidence();
        assert_eq!(evidence["status"], 1);
        assert_eq!(evidence["stream_error"]["stream"], "stdin");
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(
            fs::read_to_string(fixture.removal).expect("removal"),
            "removed"
        );
    }

    /// ´test:unit:helper-sends-unsuccessful-status-after-stream-limit´
    #[test]
    fn helper_sends_unsuccessful_status_after_stream_limit() {
        let fixture = StartedAttemptFixture::new("exec /usr/bin/yes output");
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        let reader = std::thread::spawn(move || {
            client
                .write_all(&0_u32.to_le_bytes())
                .expect("empty prompt");
            read_attempt_status(&mut client)
        });
        let refusal = fixture
            .run(&mut server, 8192, Child::try_wait)
            .err()
            .expect("stream limit refuses");
        assert_eq!(reader.join().expect("status reader"), 1);
        assert_eq!(refusal.kind, "container-stream");
        assert!(refusal.detail.contains("container stream limit reached"));
        let evidence = fixture.evidence();
        assert_eq!(evidence["stream_error"]["stream"], "stdout");
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(
            fs::read_to_string(fixture.removal).expect("removal"),
            "removed"
        );
    }

    /// ´test:unit:helper-cleans-up-after-child-wait-error´
    #[test]
    fn helper_cleans_up_after_child_wait_error() {
        let fixture = StartedAttemptFixture::new("sleep 5");
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        let reader = std::thread::spawn(move || {
            client
                .write_all(&0_u32.to_le_bytes())
                .expect("empty prompt");
            read_attempt_status(&mut client)
        });
        let refusal = fixture
            .run(&mut server, STREAM_LIMIT, |_child| {
                Err(std::io::Error::other("synthetic wait error"))
            })
            .err()
            .expect("wait error refuses");
        assert_eq!(reader.join().expect("status reader"), 1);
        assert_eq!(refusal.kind, "container-wait");
        let evidence = fixture.evidence();
        assert_eq!(evidence["status"], 1);
        assert!(
            evidence["wait_error"]
                .as_str()
                .expect("wait error")
                .contains("synthetic wait error")
        );
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(
            fs::read_to_string(fixture.removal).expect("removal"),
            "removed"
        );
    }

    /// ´test:unit:helper-cleans-up-after-stream-thread-creation-error´
    #[test]
    fn helper_cleans_up_after_stream_thread_creation_error() {
        let fixture = StartedAttemptFixture::new("sleep 5");
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        let reader = std::thread::spawn(move || {
            client
                .write_all(&0_u32.to_le_bytes())
                .expect("empty prompt");
            read_attempt_status(&mut client)
        });
        let refusal = fixture
            .run_with_thread_gate(
                &mut server,
                STREAM_LIMIT,
                STREAM_DRAIN_GRACE,
                STREAM_STOP_GRACE,
                Child::try_wait,
                |name| {
                    if name == "stderr" {
                        Err(std::io::Error::other("synthetic thread limit"))
                    } else {
                        Ok(())
                    }
                },
            )
            .err()
            .expect("thread creation refuses");
        assert_eq!(reader.join().expect("status reader"), 1);
        assert_eq!(refusal.kind, "container-thread");
        assert!(refusal.detail.contains("stderr: synthetic thread limit"));
        let evidence = fixture.evidence();
        assert_eq!(evidence["status"], 1);
        assert!(
            evidence["thread_error"]
                .as_str()
                .expect("thread error")
                .contains("stderr: synthetic thread limit")
        );
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(
            fs::read_to_string(fixture.removal).expect("removal"),
            "removed"
        );
    }

    /// ´test:unit:helper-bounds-reader-after-thread-creation-error´
    #[test]
    fn helper_bounds_reader_after_thread_creation_error() {
        let (fixture, ready, release) = retained_reader_fixture();
        let holder = HolderGuard::new();
        let runner_holder = holder.slot();
        let (published, publication) = mpsc::sync_channel(1);
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let runner = std::thread::spawn(move || {
            let refusal = fixture
                .run_with_seams(
                    &mut server,
                    STREAM_LIMIT,
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                    Child::try_wait,
                    |name| {
                        if name == "stderr" {
                            Err(std::io::Error::other("synthetic thread limit"))
                        } else {
                            Ok(())
                        }
                    },
                    |pid| {
                        hold_stdout(pid, &runner_holder, &ready, &release, &published).map_err(
                            |error| {
                                crate::error::LaneError::operation("fixture", error.to_string())
                            },
                        )
                    },
                )
                .err()
                .expect("thread creation refuses");
            let evidence = fixture.evidence();
            let removed = fs::read_to_string(fixture.removal).expect("removal");
            (refusal, evidence, removed)
        });
        let (refusal, evidence, removed) =
            finish_held_runner(&holder, &publication, runner, Duration::from_secs(2));
        assert_eq!(refusal.kind, "container-thread");
        assert_eq!(read_attempt_status(&mut client), 1);
        assert_eq!(evidence["status"], 1);
        assert_eq!(evidence["stream_error"]["stream"], "stdout");
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(removed, "removed");
    }

    /// ´test:unit:helper-bounds-reader-after-child-exit´
    #[test]
    fn helper_bounds_reader_after_child_exit() {
        let (fixture, ready, release) = retained_reader_fixture();
        let holder = HolderGuard::new();
        let runner_holder = holder.slot();
        let (published, publication) = mpsc::sync_channel(1);
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let runner = std::thread::spawn(move || {
            let refusal = fixture
                .run_with_seams(
                    &mut server,
                    STREAM_LIMIT,
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                    Child::try_wait,
                    |_| Ok(()),
                    |pid| {
                        hold_stdout(pid, &runner_holder, &ready, &release, &published).map_err(
                            |error| {
                                crate::error::LaneError::operation("fixture", error.to_string())
                            },
                        )
                    },
                )
                .err()
                .expect("retained reader refuses");
            let evidence = fixture.evidence();
            let removed = fs::read_to_string(fixture.removal).expect("removal");
            (refusal, evidence, removed)
        });
        let (refusal, evidence, removed) =
            finish_held_runner(&holder, &publication, runner, Duration::from_secs(20));
        assert_eq!(refusal.kind, "container-stream");
        assert_eq!(read_attempt_status(&mut client), 1);
        assert_eq!(evidence["status"], 1);
        assert_eq!(evidence["stream_error"]["stream"], "drain");
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(removed, "removed");
    }

    /// ´test:unit:helper-retains-drain-expiry-after-reader-finishes-during-stop´
    #[test]
    fn helper_retains_drain_expiry_after_reader_finishes_during_stop() {
        let (mut fixture, ready, release) = retained_reader_fixture();
        let marker = fixture.root.path().join("stopped");
        fixture
            .environment
            .insert("TEST_STOP_MARKER".into(), marker.display().to_string());
        let holder = HolderGuard::new();
        let runner_holder = holder.slot();
        let (published, publication) = mpsc::sync_channel(1);
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let runner = std::thread::spawn(move || {
            let refusal = fixture
                .run_with_seams(
                    &mut server,
                    STREAM_LIMIT,
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                    Child::try_wait,
                    |_| Ok(()),
                    |pid| {
                        hold_stdout(pid, &runner_holder, &ready, &release, &published).map_err(
                            |error| {
                                crate::error::LaneError::operation("fixture", error.to_string())
                            },
                        )
                    },
                )
                .err()
                .expect("expired drain refuses");
            (refusal, fixture.evidence())
        });
        let handoff = publication.recv_timeout(Duration::from_secs(5)).is_ok();
        let marker_deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < marker_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stopped = marker.exists();
        holder.close();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !runner.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let bounded = runner.is_finished();
        let (refusal, evidence) = runner.join().expect("reap fixture runner");
        assert!(handoff, "holder was published before stop");
        assert!(stopped, "stop follows drain expiry");
        assert!(bounded, "cleanup is bounded");
        assert_eq!(refusal.kind, "container-stream");
        assert!(refusal.detail.contains("stream drain exceeded"));
        assert_eq!(evidence["stream_error"]["stream"], "drain");
        assert!(
            evidence["stream_error"]["reason"]
                .as_str()
                .expect("drain reason")
                .contains("stream drain exceeded")
        );
        assert_eq!(evidence["removal"]["state"], "removed");
        assert_eq!(read_attempt_status(&mut client), 1);
    }

    /// ´test:unit:helper-detects-the-launchers-absent-process´
    #[test]
    fn helper_detects_the_launchers_absent_process() {
        let mut child = Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("launcher stand-in");
        let identity = LauncherIdentity {
            pid: child.id(),
            start: process_start(child.id()).expect("start tick"),
        };
        assert!(launcher_alive(identity));
        child.kill().expect("end launcher");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while super::process_info(child.id())
            .is_ok_and(|(_, _, state)| state != b'Z' && state != b'X')
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!launcher_alive(identity), "unreaped zombie is absent");
        child.wait().expect("reap launcher");
        assert!(!launcher_alive(identity));
    }

    /// ´test:unit:helper-cancels-a-silent-container-and-waits-for-the-named-stop´
    #[test]
    fn helper_cancels_a_silent_container_and_waits_for_the_named_stop() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protected fixture");
        let program = root.join("container-standin");
        fs::write(&program, format!("#!/bin/sh\ncase \"$1\" in\n run) printf '%s %s' \"$_CONTAINERS_USERNS_CONFIGURED\" \"$_CONTAINERS_ROOTLESS_UID\" > '{}/markers'; printf started > '{}/started'; sleep 5;;\n stop) printf stopped > '{}/stopped';;\n wait) printf waited > '{}/waited';;\nesac\n", root.display(), root.display(), root.display(), root.display())).expect("stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("stand-in mode");
        crate::pinned::owner_executable(&program, nix::unistd::Uid::effective().as_raw())
            .expect("stand-in has a protected program path");
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver directory");
        let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
        fs::create_dir(&custody).expect("custody directory");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        let reservation = root.join(".reservation-R.json");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]});
        publish_reservation(&reservation, &record).expect("attempt reservation");
        let vector = vec![
            program.display().to_string(),
            "run".into(),
            "--name=superloop-lane-alpha-R-attempt-1".into(),
            format!(
                "--cidfile={}",
                protected_identifier_path(&driver, 1)
                    .expect("identifier path")
                    .display()
            ),
        ];
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client
            .write_all(&0_u32.to_le_bytes())
            .expect("empty prompt");
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let launcher = LauncherIdentity {
            pid: std::process::id(),
            start: process_start(std::process::id()).expect("launcher start"),
        };
        let control_path = root.join("control.sock");
        let listener = UnixListener::bind(&control_path).expect("control socket");
        let control_signal = Arc::clone(&cancelled);
        let owner = nix::unistd::Uid::effective().as_raw();
        let environment = private_podman_environment_from(&root, Some("1"), Some("41001"))
            .expect("namespace environment");
        let controller =
            std::thread::spawn(move || control_loop(&listener, &control_signal, owner));
        let began = Instant::now();
        let handle = std::thread::spawn(move || {
            run_attempt(
                &mut server,
                &vector,
                &environment,
                &root,
                &reservation,
                &record,
                &driver,
                1,
                &signal,
                launcher,
                None,
            )
        });
        while !fixture.path().join("started").exists() && began.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            fixture.path().join("started").exists(),
            "silent child started"
        );
        let mut control = UnixStream::connect(&control_path).expect("supervisor control");
        control.write_all(b"C").expect("cancel request");
        let mut ack = [0_u8];
        control
            .read_exact(&mut ack)
            .expect("cancel acknowledgement");
        assert_eq!(ack, [b'K']);
        client
            .shutdown(Shutdown::Both)
            .expect("driver client disconnects");
        assert!(cancelled.load(Ordering::Acquire));
        controller
            .join()
            .expect("control thread")
            .expect("control result");
        let outcome = handle
            .join()
            .expect("helper thread")
            .expect("bounded cancellation");
        assert_eq!(outcome.code, 1);
        assert!(!outcome.capacity);
        assert!(fixture.path().join("stopped").exists());
        assert!(fixture.path().join("waited").exists());
        assert_eq!(
            fs::read_to_string(fixture.path().join("markers")).expect("run environment"),
            "1 41001"
        );
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "silent child was cancelled before its natural end"
        );
    }

    /// ´test:unit:helper-cancels-a-silent-attempt-when-its-client-disappears´
    #[test]
    fn helper_cancels_a_silent_attempt_when_its_client_disappears() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path().to_path_buf();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protected fixture");
        let program = root.join("container-standin");
        fs::write(&program, format!("#!/bin/sh\ncase \"$1\" in\n run) printf started > '{}/started'; sleep 5;;\n stop) printf stopped > '{}/stopped';;\n wait) printf waited > '{}/waited';;\nesac\n", root.display(), root.display(), root.display())).expect("stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        crate::pinned::owner_executable(&program, nix::unistd::Uid::effective().as_raw())
            .expect("stand-in has a protected program path");
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver");
        let custody = crate::plan::protected_identity_dir(&driver).expect("custody path");
        fs::create_dir(&custody).expect("custody directory");
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700)).expect("custody mode");
        let reservation = root.join(".reservation-R.json");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]});
        publish_reservation(&reservation, &record).expect("attempt reservation");
        let vector = vec![
            program.display().to_string(),
            "run".into(),
            "--name=superloop-lane-alpha-R-attempt-1".into(),
            format!(
                "--cidfile={}",
                protected_identifier_path(&driver, 1)
                    .expect("identifier")
                    .display()
            ),
        ];
        let (mut server, mut client) = UnixStream::pair().expect("channel");
        client.write_all(&0_u32.to_le_bytes()).expect("prompt");
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let launcher = LauncherIdentity {
            pid: std::process::id(),
            start: process_start(std::process::id()).expect("launcher start"),
        };
        let began = Instant::now();
        let handle = std::thread::spawn(move || {
            run_attempt(
                &mut server,
                &vector,
                &BTreeMap::new(),
                &root,
                &reservation,
                &record,
                &driver,
                1,
                &signal,
                launcher,
                None,
            )
        });
        while !fixture.path().join("started").exists() && began.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(fixture.path().join("started").exists());
        drop(client);
        let outcome = handle
            .join()
            .expect("helper thread")
            .expect("bounded cancellation");
        assert_eq!(outcome.code, 1);
        assert!(cancelled.load(Ordering::Acquire));
        assert!(fixture.path().join("stopped").exists());
        assert!(fixture.path().join("waited").exists());
        assert!(began.elapsed() < Duration::from_secs(5));
    }

    /// ´test:unit:helper-publishes-started-before-invoking-container-start´
    #[test]
    fn helper_publishes_started_before_invoking_container_start() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let path = fixture.path().join(".reservation-R.json");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"active_round":"dispatch","rounds":[{"step":"dispatch","budget_seconds":3600}]});
        publish_reservation(&path, &record).expect("seed reservation");
        start_after_reservation(&path, &record, || {
            let saved = read_reservation(&path)
                .expect("read reservation")
                .expect("present");
            assert_eq!(saved["phase"], "started");
            Ok(())
        })
        .expect("start after record");
        assert_eq!(record["phase"], "preparing");
    }

    /// ´test:unit:helper-start-preserves-letter-placed-after-its-read´
    #[test]
    fn helper_start_preserves_letter_placed_after_its_read() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let path = fixture.path().join(".reservation-R.json");
        let stale = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"plan":{"home":"~/worker"},"letters":[]});
        publish_reservation(&path, &stale).expect("seed reservation");
        let mut placed = stale.clone();
        placed["letters"] = json!([{"step":"dispatch","name":"dispatch-1.md","state":"placed","bytes":4,"sha256":"fixture","placed_at_unix_ns":1}]);
        publish_reservation(&path, &placed).expect("placement between helper read and write");
        start_after_reservation(&path, &stale, || Ok(())).expect("start from stale request");
        let saved = read_reservation(&path).expect("read").expect("present");
        assert_eq!(saved["letters"], placed["letters"]);
        assert_eq!(saved["phase"], "started");
    }

    /// ´test:unit:helper-refuses-a-request-differing-from-saved-plan´
    #[test]
    fn helper_refuses_a_request_differing_from_saved_plan() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let path = fixture.path().join("container.argv");
        fs::write(&path, b"/usr/bin/podman\0run\0--name\0changed\0").expect("changed request");
        let saved = read_words(&path).expect("saved request");
        let expected = vec![
            "/usr/bin/podman".to_owned(),
            "run".to_owned(),
            "--name=superloop-lane-alpha-R-attempt-1".to_owned(),
        ];
        let refusal = verify_vector(&saved, &expected).expect_err("changed request");
        assert_eq!(refusal.kind, "helper-pin");
    }

    /// ´test:unit:boxed-capacity-retries-use-distinct-container-names-and-identifiers´
    #[test]
    fn boxed_capacity_retries_use_distinct_container_names_and_identifiers() {
        let fixture = TempDir::new_in("/tmp").expect("fixture");
        let root = fixture.path();
        let program = root.join("container-stand-in");
        fs::write(&program, format!("#!/bin/sh\nname=\ncidfile=\nfor word in \"$@\"; do\n case \"$word\" in\n --name=*) name=${{word#--name=}};;\n --cidfile=*) cidfile=${{word#--cidfile=}};;\n esac\ndone\n[ -n \"$name\" ] && [ -n \"$cidfile\" ] || exit 99\n[ ! -e '{}/'$name ] || exit 125\nprintf '%s\\n' \"$name\" > '{}/'$name\nprintf '%s\\n' \"$name\" > \"$cidfile\"\ncase \"$name\" in *attempt-1) exit 42;; esac\nexit 0\n", root.display(), root.display())).expect("stand-in");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).expect("program mode");
        let driver = root.join("R");
        let base = vec![
            program.display().to_string(),
            "run".into(),
            "--name=superloop-lane-alpha-R-attempt-1".into(),
            format!(
                "--cidfile={}",
                protected_identifier_path(&driver, 1)
                    .expect("identifier path")
                    .display()
            ),
        ];
        let first = attempt_vector(&base, &driver, 1).expect("first");
        let second = attempt_vector(&base, &driver, 2).expect("retry");
        assert_ne!(first[2], second[2]);
        assert_ne!(first[3], second[3]);
        assert_eq!(second[2], "--name=superloop-lane-alpha-R-attempt-2");
        let first_status = Command::new("/bin/sh")
            .arg(&first[0])
            .args(&first[1..])
            .status()
            .expect("first boxed start");
        assert_eq!(first_status.code(), Some(42));
        let second_status = Command::new("/bin/sh")
            .arg(&second[0])
            .args(&second[1..])
            .status()
            .expect("retry boxed start");
        assert!(second_status.success());
        assert!(
            protected_identifier_path(&driver, 1)
                .expect("first path")
                .is_file()
        );
        assert!(
            protected_identifier_path(&driver, 2)
                .expect("second path")
                .is_file()
        );
    }
}
