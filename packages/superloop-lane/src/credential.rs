//! Owner-side credential authority and backend-specific worker encodings.

use crate::settings::BoxBackend;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
use serde_json::{Value, json};

use crate::error::LaneError;

const AUTH_HOST: &str = "auth.openai.com";
pub(crate) const AUTH_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
#[cfg(test)]
thread_local! {
    static SERVICE_ENDPOINT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Select the fixed service endpoint, with a required isolated override in test builds.
/// # Panics
/// Panics in test builds if the spawning thread has not installed a fixture endpoint.
pub(crate) fn service_endpoint() -> String {
    #[cfg(test)]
    {
        SERVICE_ENDPOINT.with(|value| {
            value
                .borrow()
                .clone()
                .expect("service fixture endpoint is required")
        })
    }
    #[cfg(not(test))]
    AUTH_ENDPOINT.to_owned()
}

#[cfg(test)]
pub(crate) struct ServiceEndpointGuard(Option<String>);
#[cfg(test)]
impl Drop for ServiceEndpointGuard {
    fn drop(&mut self) {
        SERVICE_ENDPOINT.with(|value| *value.borrow_mut() = self.0.take());
    }
}

/// Serve one synthetic refresh response on loopback for the namespace service fixture.
///
/// # Panics
/// Panics if the fixture listener or its request/response cannot be established.
#[cfg(test)]
pub(crate) fn fixture_refresh_endpoint(
    response: Value,
) -> (String, std::thread::JoinHandle<Value>) {
    tests::fixture_endpoint("200 OK", response)
}

/// Override the spawning thread's service endpoint in a test build.
#[cfg(test)]
pub(crate) fn fixture_service_endpoint(endpoint: String) -> ServiceEndpointGuard {
    ServiceEndpointGuard(SERVICE_ENDPOINT.with(|value| value.replace(Some(endpoint))))
}

const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// Complete SHA-256 of the program behind the loop's reviewed credential structure record.
/// An executable supplier cannot select the independent record; bind all program bytes
/// before authority access (´proto:superlooplane:claude-owner-program-binding´).
pub(crate) const CLAUDE_SCHEMA_PROGRAM_SHA256: &str =
    "708c77b204db30086ff6f1ed34577bda03e1be74ced80557cbf7b54249ebf0bd";
const REFRESH_AHEAD: Duration = Duration::from_secs(10 * 60);
const MAX_AUTH_BYTES: u64 = 65_536;
const MAX_EVIDENCE_BYTES: u64 = 65_536;

/// The owner-side refresh host is recorded separately from the worker proxy list.
pub const REFRESH_HOST: &str = AUTH_HOST;

fn failure(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail.into())
}

pub(crate) fn sign_in_dir(owner_home: &Path, loop_name: &str) -> PathBuf {
    owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("lanes/codex")
}

fn owner_identity() -> (u32, u32) {
    (Uid::effective().as_raw(), Gid::effective().as_raw())
}

fn now_seconds() -> Result<u64, LaneError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| failure("credential-clock", error.to_string()))
}

fn now_milliseconds() -> Result<u64, LaneError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| failure("credential-clock", error.to_string()))?;
    u64::try_from(elapsed.as_millis())
        .map_err(|error| failure("credential-clock", error.to_string()))
}

fn credential_spawn_error(
    program: &Path,
    kind: &'static str,
    message: &str,
    error: &std::io::Error,
) -> LaneError {
    let held = crate::container_entry::spawn_error(program, kind, error);
    if held.kind == "anchor-exec" {
        held
    } else {
        failure(kind, message)
    }
}

/// Drive an entered publication or refresh child through a bounded pipe.
/// The caller owns the child until it is reaped, including on a selected stop.
pub(crate) fn bounded_pipe(
    command: &mut Command,
    input: &[u8],
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
    output_limit: usize,
) -> Result<std::process::Output, &'static str> {
    use nix::fcntl::{FcntlArg, fcntl};
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    use std::os::unix::process::CommandExt as _;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = crate::fixture_exec::spawn(command).map_err(|_| "spawn")?;
    let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
    let result = (|| {
        let stdin = child.stdin.take().ok_or("stdin")?;
        let mut stdout = child.stdout.take().ok_or("stdout")?;
        for pipe in [stdin.as_fd(), stdout.as_fd()] {
            let flags = fcntl(pipe, FcntlArg::F_GETFL).map_err(|_| "pipe")?;
            fcntl(
                pipe,
                FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
            )
            .map_err(|_| "pipe")?;
        }
        let mut stdin = if input.is_empty() { None } else { Some(stdin) };
        let mut sent = 0;
        let mut bytes = Vec::new();
        let mut status = None;
        let mut eof = false;
        loop {
            if stopped() {
                return Err("cancelled");
            }
            if Instant::now() >= deadline {
                return Err("deadline");
            }
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&input[sent..]) {
                    Ok(0) => return Err("stdin"),
                    Ok(count) => sent += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err("stdin"),
                }
            }
            if sent == input.len() {
                stdin = None;
            }
            let mut buffer = [0; 8192];
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if bytes.len().saturating_add(count) > output_limit {
                        return Err("output-limit");
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err("stdout"),
            }
            if status.is_none() {
                status = child.try_wait().map_err(|_| "wait")?;
            }
            if let Some(status) = status.filter(|_| eof && stdin.is_none()) {
                return Ok(std::process::Output {
                    status,
                    stdout: bytes,
                    stderr: Vec::new(),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _killed = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    let _reaped = child.wait();
    result
}

#[cfg(test)]
fn utc_timestamp() -> Result<String, LaneError> {
    utc_timestamp_bound(None)
}

fn utc_timestamp_bound(bound: Option<(Instant, &dyn Fn() -> bool)>) -> Result<String, LaneError> {
    let program = Path::new("/usr/bin/date");
    let argv = ["-u".into(), "+%Y-%m-%dT%H:%M:%SZ".into()];
    let mut command = Command::new("/usr/bin/date");
    command.args(&argv);
    crate::container_entry::configure(&mut command, program, &argv, &std::env::vars().collect())?;
    let output = if let Some((deadline, stopped)) = bound {
        bounded_pipe(&mut command, b"", deadline, stopped, 128).map_err(|kind| {
            failure(
                if kind == "deadline" || kind == "cancelled" {
                    "credential-door-timeout"
                } else {
                    "credential-clock"
                },
                kind,
            )
        })?
    } else {
        command.output().map_err(|error| {
            credential_spawn_error(
                program,
                "credential-clock",
                "UTC date program could not start",
                &error,
            )
        })?
    };
    if !output.status.success() {
        return Err(failure("credential-clock", "UTC date program failed"));
    }
    let stamp = String::from_utf8(output.stdout)
        .map_err(|_| failure("credential-clock", "UTC timestamp is invalid"))?;
    Ok(stamp.trim_end().to_owned())
}

fn decode_base64url(source: &str) -> Result<Vec<u8>, LaneError> {
    if source.len() % 4 == 1 {
        return Err(failure(
            "credential-token",
            "token has invalid base64url length",
        ));
    }
    let mut result = Vec::with_capacity(source.len() * 3 / 4);
    let mut value = 0_u32;
    let mut bits = 0_u8;
    for byte in source.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(failure(
                    "credential-token",
                    "access token has invalid encoding",
                ));
            }
        };
        value = (value << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push(
                u8::try_from(value >> bits).map_err(|_| {
                    failure("credential-token", "access token has invalid encoding")
                })?,
            );
            value &= (1 << bits) - 1;
        }
    }
    if value != 0 {
        return Err(failure(
            "credential-token",
            "token has non-zero unused base64url bits",
        ));
    }
    Ok(result)
}

fn jwt_claims(token: &str) -> Result<Value, LaneError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(failure("credential-token", "token has invalid JWT shape"));
    }
    let payload = parts[1];
    if payload.len() > 16_384 {
        return Err(failure(
            "credential-token",
            "access token claims exceed limit",
        ));
    }
    let claims: Value = serde_json::from_slice(&decode_base64url(payload)?)
        .map_err(|_| failure("credential-token", "access token claims are invalid"))?;
    if !claims.is_object() {
        return Err(failure(
            "credential-token",
            "token claims are not an object",
        ));
    }
    Ok(claims)
}

fn expiry(access: &str) -> Result<u64, LaneError> {
    let claims = jwt_claims(access)?;
    let expires = claims["exp"]
        .as_u64()
        .ok_or_else(|| failure("credential-token", "access token expiry is absent"))?;
    if expires < REFRESH_AHEAD.as_secs() {
        return Err(failure(
            "credential-token",
            "access token expiry precedes refresh lead",
        ));
    }
    Ok(expires)
}

pub(crate) fn refresh_due_for_access(access: &str, now: u64) -> Result<bool, LaneError> {
    expiry(access).map(|expires_at| expires_at <= now.saturating_add(REFRESH_AHEAD.as_secs()))
}

fn valid_id_claims(claims: &Value) -> bool {
    let optional_string = |object: &Value, key: &str| {
        object
            .get(key)
            .is_none_or(|value| value.is_null() || value.is_string())
    };
    if !optional_string(claims, "email") {
        return false;
    }
    if let Some(profile) = claims.get("https://api.openai.com/profile")
        && !profile.is_null()
        && (!profile.is_object() || !optional_string(profile, "email"))
    {
        return false;
    }
    if let Some(auth) = claims.get("https://api.openai.com/auth") {
        if auth.is_null() {
            return true;
        }
        if !auth.is_object() {
            return false;
        }
        for key in [
            "chatgpt_plan_type",
            "chatgpt_user_id",
            "user_id",
            "chatgpt_account_id",
        ] {
            if !optional_string(auth, key) {
                return false;
            }
        }
        if auth
            .get("chatgpt_account_is_fedramp")
            .is_some_and(|value| !value.is_boolean())
        {
            return false;
        }
    }
    true
}

fn valid_timestamp(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    if bytes.len() < 20 || bytes.len() > 40 {
        return false;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let number = |start: usize, end: usize| stamp[start..end].parse::<u32>().unwrap_or_default();
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if year == 0
        || day == 0
        || day > days
        || number(11, 13) > 23
        || number(14, 16) > 59
        || number(17, 19) > 59
    {
        return false;
    }
    let mut suffix = &stamp[19..];
    if let Some(fraction) = suffix.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return false;
        }
        suffix = &fraction[digits..];
    }
    suffix == "Z"
        || (suffix.len() == 6
            && matches!(suffix.as_bytes()[0], b'+' | b'-')
            && suffix.as_bytes()[3] == b':'
            && suffix.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
            && suffix.as_bytes()[4..6].iter().all(u8::is_ascii_digit)
            && suffix[1..3].parse::<u32>().is_ok_and(|hour| hour <= 23)
            && suffix[4..6].parse::<u32>().is_ok_and(|minute| minute <= 59))
}

#[derive(Clone)]
pub struct Source {
    document: Value,
    expires_at: u64,
    stamp: Option<FileStamp>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: libc::dev_t,
    inode: libc::ino_t,
    size: libc::off_t,
    modified: libc::time_t,
    modified_nsec: libc::c_long,
}

impl FileStamp {
    const fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size,
            modified: stat.st_mtime,
            modified_nsec: stat.st_mtime_nsec,
        }
    }
}

impl Source {
    fn parse(document: Value) -> Result<Self, LaneError> {
        let tokens = &document["tokens"];
        if document["auth_mode"] != "chatgpt" && !document["auth_mode"].is_null() {
            return Err(failure("credential-sign-in", "sign-in is not ChatGPT auth"));
        }
        for field in ["id_token", "access_token", "refresh_token", "account_id"] {
            if tokens[field].as_str().is_none_or(str::is_empty) {
                return Err(failure(
                    "credential-sign-in",
                    format!("sign-in is missing {field}"),
                ));
            }
        }
        if !document["last_refresh"]
            .as_str()
            .is_some_and(valid_timestamp)
        {
            return Err(failure(
                "credential-sign-in",
                "sign-in last_refresh is not a date",
            ));
        }
        let id_claims = jwt_claims(tokens["id_token"].as_str().unwrap_or_default())
            .map_err(|_| failure("credential-sign-in", "sign-in id_token is malformed"))?;
        if !valid_id_claims(&id_claims) {
            return Err(failure(
                "credential-sign-in",
                "sign-in id_token claims have invalid types",
            ));
        }
        let expires_at = expiry(tokens["access_token"].as_str().unwrap_or_default())?;
        Ok(Self {
            document,
            expires_at,
            stamp: None,
        })
    }

    fn worker_file(&self) -> Vec<u8> {
        let tokens = &self.document["tokens"];
        let worker = json!({
            "auth_mode": "chatgptAuthTokens",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": tokens["id_token"],
                "access_token": tokens["access_token"],
                "refresh_token": "",
                "account_id": tokens["account_id"]
            },
            "last_refresh": self.document["last_refresh"]
        });
        let mut bytes = worker.to_string().into_bytes();
        bytes.push(b'\n');
        bytes
    }

    const fn needs_refresh(&self, now: u64) -> bool {
        self.expires_at <= now.saturating_add(REFRESH_AHEAD.as_secs())
    }

    const fn refresh_due_unix(&self) -> u64 {
        self.expires_at - REFRESH_AHEAD.as_secs()
    }
}

fn open_dir(
    path: &Path,
    walk_owner: u32,
    leaf_owner: u32,
    mode: u32,
) -> Result<std::os::fd::OwnedFd, LaneError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| failure("credential-path", "directory parent is absent"))?;
    let parent = crate::home::pin_parent(parent_path, walk_owner)?;
    let name = path
        .file_name()
        .ok_or_else(|| failure("credential-path", "directory name is absent"))?;
    let fd = openat2(
        &parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| failure("credential-path", format!("{}: {error}", path.display())))?;
    let stat = fstat(&fd).map_err(|error| failure("credential-path", error.to_string()))?;
    let actual_mode = stat.st_mode & 0o7777;
    if stat.st_uid != leaf_owner || actual_mode != mode {
        return Err(failure(
            "credential-path",
            format!(
                "{} has uid {} mode {actual_mode:04o}; expected uid {leaf_owner} mode {mode:04o}",
                path.display(),
                stat.st_uid
            ),
        ));
    }
    Ok(fd)
}

fn read_source(owner_home: &Path, loop_name: &str) -> Result<Source, LaneError> {
    let (document, stamp) = read_owner_document(&sign_in_dir(owner_home, loop_name), "auth.json")?;
    let mut source = Source::parse(document)?;
    source.stamp = Some(stamp);
    Ok(source)
}

fn read_owner_document(path: &Path, filename: &str) -> Result<(Value, FileStamp), LaneError> {
    let owner = owner_identity().0;
    let dir = open_dir(path, owner, owner, 0o700)?;
    read_owner_file(&dir, filename)
}

fn read_owner_file(dir: &OwnedFd, filename: &str) -> Result<(Value, FileStamp), LaneError> {
    let file = openat2(
        dir,
        filename,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|_| {
        failure(
            "credential-sign-in",
            "loop sign-in is missing or unreadable",
        )
    })?;
    let stat = fstat(&file).map_err(|_| failure("credential-sign-in", "sign-in stat failed"))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner_identity().0
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size < 0
        || stat.st_size.cast_unsigned() > MAX_AUTH_BYTES
    {
        return Err(failure(
            "credential-sign-in",
            "sign-in owner, mode, type or size is unsafe",
        ));
    }
    let mut bytes = Vec::new();
    File::from(file)
        .take(MAX_AUTH_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("credential-sign-in", "sign-in read failed"))?;
    if bytes.len() as u64 > MAX_AUTH_BYTES {
        return Err(failure("credential-sign-in", "sign-in exceeds size limit"));
    }
    let document = serde_json::from_slice(&bytes)
        .map_err(|_| failure("credential-sign-in", "sign-in JSON is invalid"))?;
    Ok((document, FileStamp::from_stat(&stat)))
}

fn atomic_file(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    dir_mode: u32,
    expected: Option<FileStamp>,
) -> Result<bool, LaneError> {
    let fd = open_dir(directory, owner_identity().0, uid, dir_mode)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| failure("credential-publish", error.to_string()))?
        .as_nanos();
    let temporary = format!(".{name}-{}-{nonce}.tmp", std::process::id());
    let write = (|| {
        let opened = openat2(
            &fd,
            temporary.as_str(),
            OpenHow::new()
                .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|_| {
            failure(
                "credential-publish",
                "credential temporary cannot be created",
            )
        })?;
        fchown(&opened, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
            .map_err(|_| failure("credential-publish", "credential owner cannot be set"))?;
        fchmod(&opened, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|_| failure("credential-publish", "credential mode cannot be set"))?;
        let mut file = File::from(opened);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| failure("credential-publish", "credential write or sync failed"))?;
        if let Some(expected) = expected {
            let actual = fstatat(&fd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| failure("credential-publish", "credential source disappeared"))?;
            if FileStamp::from_stat(&actual) != expected {
                return Ok(false);
            }
        }
        renameat(&fd, temporary.as_str(), &fd, name)
            .map_err(|_| failure("credential-publish", "credential rename failed"))?;
        File::from(
            fd.as_fd()
                .try_clone_to_owned()
                .map_err(|_| failure("credential-publish", "credential directory clone failed"))?,
        )
        .sync_all()
        .map_err(|_| failure("credential-publish", "credential directory sync failed"))?;
        Ok(true)
    })();
    let _ignored = unlinkat(&fd, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    write
}

fn write_run(home: &Path, worker_uid: u32, source: &Source) -> Result<(), LaneError> {
    atomic_file(
        &home.join(".codex"),
        "auth.json",
        &source.worker_file(),
        worker_uid,
        worker_uid,
        0o700,
        None,
    )
    .map(|_published| ())
}

/// Publish refresh evidence beneath the owner-controlled launch directory.
///
/// # Errors
///
/// Refuses an unsafe directory or failed atomic replacement.
pub(crate) fn publish_evidence(driver_dir: &Path, document: &Value) -> Result<(), LaneError> {
    publish_evidence_bound(
        driver_dir,
        document,
        &crate::runtime_admission::ReviewedProgramBinding::Schema,
    )
}

/// Publish evidence using the same binding that shaped the helper observation.
pub(crate) fn publish_evidence_bound(
    driver_dir: &Path,
    document: &Value,
    binding: &crate::runtime_admission::ReviewedProgramBinding,
) -> Result<(), LaneError> {
    validate_evidence(document, binding)?;
    let directory = crate::plan::protected_identity_dir(driver_dir)?;
    let bytes = serde_json::to_vec(document)
        .map_err(|_| failure("credential-evidence", "refresh evidence cannot be encoded"))?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(failure(
            "credential-evidence",
            "refresh evidence exceeds size limit",
        ));
    }
    let (uid, gid) = owner_identity();
    atomic_file(
        &directory,
        "credential-refresh.json",
        &bytes,
        uid,
        gid,
        0o700,
        None,
    )
    .map(|_published| ())
    .map_err(|error| failure("credential-evidence", error.detail))
}

fn evidence_provider_valid(
    document: &Value,
    binding: &crate::runtime_admission::ReviewedProgramBinding,
) -> bool {
    match document["schema"].as_u64() {
        Some(1) => {
            document["host"] == REFRESH_HOST
                && document.get("backend").is_none()
                && document.get("provider").is_none()
        }
        Some(2) => {
            document["backend"] == "claude"
                && document.get("host").is_none()
                && document["provider"]
                    == json!({
                        "kind":"owner-program", "program":"/usr/bin/claude",
                        "required_sha256":binding.required_sha256(),
                    })
        }
        _ => false,
    }
}

fn validate_evidence(
    document: &Value,
    binding: &crate::runtime_admission::ReviewedProgramBinding,
) -> Result<(), LaneError> {
    if !evidence_provider_valid(document, binding)
        || !matches!(
            document["state"].as_str(),
            Some("current" | "published" | "partial" | "refused")
        )
    {
        return Err(failure(
            "credential-evidence",
            "schema, provider or state is invalid",
        ));
    }
    let expires = document
        .get("expires_unix")
        .ok_or_else(|| failure("credential-evidence", "expires_unix is absent or invalid"))?;
    let due = document.get("refresh_due_unix").ok_or_else(|| {
        failure(
            "credential-evidence",
            "refresh_due_unix is absent or invalid",
        )
    })?;
    if expires.is_null() && due.is_null() {
        if document["state"] != "refused" || document["kind"].as_str().is_none_or(str::is_empty) {
            return Err(failure(
                "credential-evidence",
                "expires_unix is absent or invalid",
            ));
        }
    } else {
        let expires = expires
            .as_u64()
            .ok_or_else(|| failure("credential-evidence", "expires_unix is absent or invalid"))?;
        let due = due.as_u64().ok_or_else(|| {
            failure(
                "credential-evidence",
                "refresh_due_unix is absent or invalid",
            )
        })?;
        if expires.checked_sub(REFRESH_AHEAD.as_secs()) != Some(due) {
            return Err(failure(
                "credential-evidence",
                "refresh_due_unix disagrees with expires_unix",
            ));
        }
    }
    if !document["run_refusals"].is_array() || !document["run_refusals_omitted"].is_u64() {
        return Err(failure(
            "credential-evidence",
            "run refusal fields are invalid",
        ));
    }
    let pair = (document.get("kind"), document.get("detail"));
    if !matches!(
        pair,
        (Some(Value::Null), Some(Value::Null)) | (Some(Value::String(_)), Some(Value::String(_)))
    ) {
        return Err(failure(
            "credential-evidence",
            "kind or detail is absent or invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub(crate) enum EvidenceObservation {
    Current(Value),
    Historical(Value),
}

/// Read one bounded owner evidence observation beneath a held runs root.
///
/// # Errors
///
/// Refuses undecodable evidence envelopes and unsafe or unreadable existing entries.
pub(crate) fn read_evidence(
    runs: &OwnedFd,
    run: &str,
    owner: u32,
) -> Result<Option<EvidenceObservation>, LaneError> {
    let Some(bytes) = read_evidence_bytes(runs, run, owner)? else {
        return Ok(None);
    };
    let document: Value = serde_json::from_slice(&bytes).map_err(|_| {
        failure(
            "credential-evidence",
            "credential-refresh.json is malformed",
        )
    })?;
    if crate::launch::census::rewrite::historical_shape(&document) {
        return Ok(Some(EvidenceObservation::Historical(document)));
    }
    validate_evidence_envelope(&document)?;
    crate::launch::census::rewrite::validate_provenance(&document)?;
    Ok(Some(EvidenceObservation::Current(document)))
}

/// Read the original bounded bytes for an explicit evidence rewrite.
pub(crate) fn read_evidence_bytes(
    runs: &OwnedFd,
    run: &str,
    owner: u32,
) -> Result<Option<Vec<u8>>, LaneError> {
    if !crate::valid_run_name(run) {
        return Err(failure("credential-evidence", "run name is invalid"));
    }
    let directory = match openat2(
        runs,
        format!(".launch-{run}").as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(failure(
                "credential-evidence",
                format!("protected directory: {error}"),
            ));
        }
    };
    let stat =
        fstat(&directory).map_err(|error| failure("credential-evidence", error.to_string()))?;
    if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
        return Err(failure(
            "credential-evidence",
            "protected directory owner or mode is invalid",
        ));
    }
    let opened = match openat2(
        &directory,
        "credential-refresh.json",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(failure(
                "credential-evidence",
                format!("credential-refresh.json: {error}"),
            ));
        }
    };
    let stat = fstat(&opened).map_err(|error| failure("credential-evidence", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_size < 0
        || stat.st_size.cast_unsigned() > MAX_EVIDENCE_BYTES
    {
        return Err(failure(
            "credential-evidence",
            "credential-refresh.json owner, mode, type or size is invalid",
        ));
    }
    let mut bytes = Vec::new();
    File::from(opened)
        .take(MAX_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| failure("credential-evidence", error.to_string()))?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(failure(
            "credential-evidence",
            "credential-refresh.json exceeds size limit",
        ));
    }
    Ok(Some(bytes))
}

// Census observes temporal defects; publication still uses validate_evidence.
fn validate_evidence_envelope(document: &Value) -> Result<(), LaneError> {
    if !evidence_provider_valid(
        document,
        &crate::runtime_admission::ReviewedProgramBinding::Schema,
    ) || !matches!(
        document["state"].as_str(),
        Some("current" | "published" | "partial" | "refused")
    ) || !document["run_refusals"].is_array()
        || !document["run_refusals_omitted"].is_u64()
        || !matches!(
            (document.get("kind"), document.get("detail")),
            (Some(Value::Null), Some(Value::Null))
                | (Some(Value::String(_)), Some(Value::String(_)))
        )
    {
        return Err(failure(
            "credential-evidence",
            "credential evidence envelope is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn lock(owner_home: &Path, loop_name: &str) -> Result<Flock<File>, LaneError> {
    let owner = owner_identity().0;
    let dir = open_dir(&sign_in_dir(owner_home, loop_name), owner, owner, 0o700)?;
    lock_with(&dir, FlockArg::LockExclusive)
}

pub(crate) fn try_lock(owner_home: &Path, loop_name: &str) -> Result<Flock<File>, LaneError> {
    // Door calls are host-side even inside an exercise with private launch anchors.
    // Search-only ancestors are sufficient: never list an ancestor or credential.
    let path = sign_in_dir(owner_home, loop_name);
    let owner = owner_identity().0;
    if !path.is_absolute() {
        return Err(failure("credential-lock", "lock root is not absolute"));
    }
    let mut dir = nix::fcntl::open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| failure("credential-lock", error.to_string()))?;
    let mut stat = fstat(&dir).map_err(|error| failure("credential-lock", error.to_string()))?;
    let mut prefix = PathBuf::from("/");
    for component in path.components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(failure(
                "credential-lock",
                "lock root has a dotted component",
            ));
        };
        let next = openat2(
            &dir,
            name,
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| failure("credential-lock", error.to_string()))?;
        let next_stat =
            fstat(&next).map_err(|error| failure("credential-lock", error.to_string()))?;
        crate::home::trusted(&stat, &next_stat, &prefix, owner)?;
        prefix.push(name);
        dir = next;
        stat = next_stat;
    }
    if stat.st_uid != owner || stat.st_mode & 0o7777 != 0o700 {
        return Err(failure(
            "credential-lock",
            "lock root owner or mode is unsafe",
        ));
    }
    lock_with(&dir, FlockArg::LockExclusiveNonblock)
}

fn lock_with(dir: &OwnedFd, operation: FlockArg) -> Result<Flock<File>, LaneError> {
    let opened = openat2(
        dir,
        ".refresh.lock",
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC)
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|_| failure("credential-lock", "loop refresh lock cannot be opened"))?;
    let stat = fstat(&opened).map_err(|_| failure("credential-lock", "lock stat failed"))?;
    if stat.st_uid != owner_identity().0
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
    {
        return Err(failure(
            "credential-lock",
            "loop refresh lock owner, mode or type is unsafe",
        ));
    }
    let file = File::from(opened);
    Flock::lock(file, operation).map_err(|(_, error)| {
        if error == Errno::EWOULDBLOCK {
            failure("credential-lock-busy", "loop refresh lock is held")
        } else {
            failure("credential-lock", "loop refresh lock failed")
        }
    })
}

#[cfg(test)]
fn refresh_request(source: &Source, endpoint: &str) -> Result<Source, LaneError> {
    refresh_request_bound(source, endpoint, None)
}

fn refresh_request_bound(
    source: &Source,
    endpoint: &str,
    bound: Option<(Instant, &dyn Fn() -> bool)>,
) -> Result<Source, LaneError> {
    let body = json!({
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": source.document["tokens"]["refresh_token"]
    });
    let program = Path::new("/usr/bin/curl");
    let max_time = bound.map_or(20, |(deadline, _)| {
        deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .saturating_add(1)
            .clamp(1, 20)
    });
    let max_time = max_time.to_string();
    let argv = [
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--max-time",
        &max_time,
        "--max-filesize",
        "65536",
        "--noproxy",
        "*",
        "--header",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        endpoint,
    ]
    .map(str::to_owned);
    let mut command = Command::new("/usr/bin/curl");
    command
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::container_entry::configure(&mut command, program, &argv, &std::env::vars().collect())?;
    let output = if let Some((deadline, stopped)) = bound {
        bounded_pipe(
            &mut command,
            body.to_string().as_bytes(),
            deadline,
            stopped,
            65_536,
        )
        .map_err(|kind| {
            failure(
                if kind == "deadline" || kind == "cancelled" {
                    "credential-door-timeout"
                } else {
                    "credential-refresh"
                },
                kind,
            )
        })?
    } else {
        let mut child = command.spawn().map_err(|error| {
            credential_spawn_error(
                program,
                "credential-refresh",
                "token client could not start",
                &error,
            )
        })?;
        child
            .stdin
            .take()
            .ok_or_else(|| failure("credential-refresh", "token client input is absent"))?
            .write_all(body.to_string().as_bytes())
            .map_err(|_| failure("credential-refresh", "token request could not be sent"))?;
        child
            .wait_with_output()
            .map_err(|_| failure("credential-refresh", "token request could not complete"))?
    };
    if !output.status.success() || output.stdout.len() > 65_536 {
        return Err(failure(
            "credential-refresh",
            "token endpoint refused or exceeded size limit",
        ));
    }
    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| failure("credential-refresh", "token endpoint response is invalid"))?;
    let mut next = source.document.clone();
    for field in ["id_token", "access_token", "refresh_token"] {
        if let Some(value) = response[field].as_str() {
            next["tokens"][field] = json!(value);
        }
    }
    next["last_refresh"] = json!(utc_timestamp_bound(bound)?);
    Source::parse(next)
}

fn publish_owner(
    owner_home: &Path,
    loop_name: &str,
    source: &Source,
    expected: FileStamp,
) -> Result<bool, LaneError> {
    let mut bytes = source.document.to_string().into_bytes();
    bytes.push(b'\n');
    let (uid, gid) = owner_identity();
    atomic_file(
        &sign_in_dir(owner_home, loop_name),
        "auth.json",
        &bytes,
        uid,
        gid,
        0o700,
        Some(expected),
    )
}

/// Owner-only authority operations; worker file encodings do not enter this protocol.
/// A provider may return refreshed authority or let its owner-side program replace
/// the source itself. The latter is adopted by the read after refresh.
trait OwnerProvider {
    type Snapshot;
    type Identity: Copy + Eq;

    fn read(&self) -> Result<Self::Snapshot, LaneError>;
    fn due(&self, source: &Self::Snapshot, now: u64) -> bool;
    fn identity(&self, source: &Self::Snapshot) -> Result<Self::Identity, LaneError>;
    /// Some stages authority for conditional publication; None means an owner
    /// program owns publication and the helper must only reread its source.
    fn refresh(&self, source: &Self::Snapshot) -> Result<Option<Self::Snapshot>, LaneError>;
    fn publish(&self, next: &Self::Snapshot, expected: Self::Identity) -> Result<bool, LaneError>;
}

struct CodexOwnerProvider<'a> {
    owner_home: &'a Path,
    loop_name: &'a str,
    endpoint: &'a str,
    bound: Option<(Instant, &'a dyn Fn() -> bool)>,
}

impl OwnerProvider for CodexOwnerProvider<'_> {
    type Snapshot = Source;
    type Identity = FileStamp;

    fn read(&self) -> Result<Source, LaneError> {
        read_source(self.owner_home, self.loop_name)
    }

    fn due(&self, source: &Source, now: u64) -> bool {
        source.needs_refresh(now)
    }

    fn identity(&self, source: &Source) -> Result<FileStamp, LaneError> {
        source
            .stamp
            .ok_or_else(|| failure("credential-sign-in", "source identity is absent"))
    }

    fn refresh(&self, source: &Source) -> Result<Option<Source>, LaneError> {
        refresh_request_bound(source, self.endpoint, self.bound).map(Some)
    }

    fn publish(&self, next: &Source, expected: FileStamp) -> Result<bool, LaneError> {
        publish_owner(self.owner_home, self.loop_name, next, expected)
    }
}

// The structural record describes owner authority, never a worker refresh grant.
struct ClaudeSource {
    oauth: Value,
    expires_ms: u64,
    stamp: Option<FileStamp>,
}

impl ClaudeSource {
    fn parse(document: &Value) -> Result<Self, LaneError> {
        let oauth = &document["claudeAiOauth"];
        let object = oauth.as_object().ok_or_else(|| {
            failure(
                "credential-sign-in",
                "Claude claudeAiOauth object is absent",
            )
        })?;
        let fields = [
            "accessToken",
            "refreshToken",
            "expiresAt",
            "refreshTokenExpiresAt",
            "scopes",
            "subscriptionType",
            "subscriptionTypeSource",
            "rateLimitTier",
        ];
        if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
            return Err(failure(
                "credential-sign-in",
                "Claude owner credential fields differ from the recorded schema",
            ));
        }
        for field in ["accessToken", "refreshToken"] {
            if !oauth[field].as_str().is_some_and(|value| {
                value.len() == 108 && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            }) {
                return Err(failure(
                    "credential-sign-in",
                    format!("Claude {field} has an invalid opaque token shape"),
                ));
            }
        }
        for field in ["expiresAt", "refreshTokenExpiresAt"] {
            if !oauth[field]
                .as_u64()
                .is_some_and(|value| (1_000_000_000_000..10_000_000_000_000).contains(&value))
            {
                return Err(failure(
                    "credential-sign-in",
                    format!("Claude {field} is not a 13-digit millisecond epoch"),
                ));
            }
        }
        let printable = |value: &Value| {
            value.as_str().is_some_and(|text| {
                !text.is_empty()
                    && text.len() <= 256
                    && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            })
        };
        if !oauth["scopes"].as_array().is_some_and(|values| {
            !values.is_empty() && values.len() <= 64 && values.iter().all(printable)
        }) {
            return Err(failure(
                "credential-sign-in",
                "Claude scopes are not bounded printable strings",
            ));
        }
        for field in [
            "subscriptionType",
            "subscriptionTypeSource",
            "rateLimitTier",
        ] {
            if !printable(&oauth[field]) {
                return Err(failure(
                    "credential-sign-in",
                    format!("Claude {field} is not a bounded printable string"),
                ));
            }
        }
        Ok(Self {
            oauth: oauth.clone(),
            expires_ms: oauth["expiresAt"].as_u64().unwrap_or_default(),
            stamp: None,
        })
    }

    fn worker_file(&self) -> Vec<u8> {
        // Neither refresh authority nor plugin state crosses this allow-list
        // (proto:superlooplane:claude-owner-credential-encoding).
        let mut oauth = serde_json::Map::new();
        for key in [
            "accessToken",
            "expiresAt",
            "scopes",
            "subscriptionType",
            "subscriptionTypeSource",
            "rateLimitTier",
        ] {
            oauth.insert(key.into(), self.oauth[key].clone());
        }
        let mut bytes = json!({"claudeAiOauth":oauth}).to_string().into_bytes();
        bytes.push(b'\n');
        bytes
    }

    const fn needs_refresh(&self, now: u64) -> bool {
        self.expires_ms
            <= now
                .saturating_add(REFRESH_AHEAD.as_secs())
                .saturating_mul(1000)
    }
}

/// Observe the validated Claude projection beneath a held sign-in directory while holding its
/// publication lock. This does not refresh authority or expose a credential-derived digest.
/// The caller enforces the runtime gate and supplies the directory's custody; `home` only
/// names the reported source path and is never opened.
///
/// # Errors
///
/// Refuses unsafe owner custody, malformed source data, or a failed observation.
pub(crate) fn with_claude_exercise_snapshot<T>(
    directory: &OwnedFd,
    home: &Path,
    now: u64,
    observe: impl FnOnce(Value, Value, bool) -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    let _guard = lock_with(directory, FlockArg::LockExclusive)?;
    let (document, stamp) = read_owner_file(directory, ".credentials.json")?;
    let source = ClaudeSource::parse(&document)?;
    let projection = serde_json::from_slice(&source.worker_file())
        .map_err(|_| failure("credential-sign-in", "Claude projection cannot be encoded"))?;
    let owner = owner_identity().0;
    let identity = json!({"path":home.join(".credentials.json"),"device":stamp.device,
        "inode":stamp.inode,"uid":owner,"mode":600,
        "modified_wall_unix_seconds":stamp.modified,"modified_nanoseconds":stamp.modified_nsec});
    observe(identity, projection, source.needs_refresh(now))
}

pub(crate) fn claude_sign_in_dir(owner_home: &Path, loop_name: &str) -> PathBuf {
    owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("claude")
}

/// Check the Claude source's custody for a launch preview without opening its
/// contents or creating the refresh lock. Expiry is checked at publication.
pub(crate) fn claude_source_custody_preview(
    owner_home: &Path,
    loop_name: &str,
) -> Result<Value, LaneError> {
    let source_home = claude_sign_in_dir(owner_home, loop_name);
    admitted_claude_mode(&source_home)?;
    let owner = owner_identity().0;
    let dir = open_dir(&source_home, owner, owner, 0o700)?;
    match fstatat(&dir, ".refresh.lock", AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(lock)
            if lock.st_uid == owner
                && lock.st_mode & 0o7777 == 0o600
                && lock.st_mode & libc::S_IFMT == libc::S_IFREG
                && lock.st_nlink == 1 => {}
        Err(Errno::ENOENT) => {}
        _ => {
            return Err(failure(
                "credential-lock",
                "loop refresh lock owner, mode or type is unsafe",
            ));
        }
    }
    let file = openat2(
        &dir,
        ".credentials.json",
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|_| failure("credential-sign-in", "Claude source is missing or unsafe"))?;
    let stat = fstat(&file).map_err(|_| failure("credential-sign-in", "source stat failed"))?;
    if stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size < 0
        || stat.st_size.cast_unsigned() > MAX_AUTH_BYTES
    {
        return Err(failure(
            "credential-sign-in",
            "Claude source owner, mode, type or size is unsafe",
        ));
    }
    Ok(json!({"owner_uid":stat.st_uid,"mode":"0600","regular":true,
        "hard_links":stat.st_nlink,"size_bytes":stat.st_size,
        "expiry":"checked at the act"}))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaudeMode {
    Read,
    Refresh,
}

// The owner holds this 0600 file in the unmounted Claude home. An absent file
// selects read-only publication. A requested cutover cannot activate until the
// carrier gate covers other UIDs, unreadable environments and host-client starts.
fn claude_mode(home: &Path) -> Result<ClaudeMode, LaneError> {
    let path = home.join(".boxed-refresh-mode");
    let anchor = home
        .parent()
        .ok_or_else(|| failure("credential-mode", "Claude home has no parent"))?;
    let bytes = crate::pinned::read_private_optional(anchor, &path, owner_identity().0, 0o600, 16)
        .map_err(|_| failure("credential-mode", "Claude mode custody is unsafe"))?;
    match bytes.as_deref() {
        None => Ok(ClaudeMode::Read),
        Some(b"refresh\n") => Ok(ClaudeMode::Refresh),
        Some(_) => Err(failure("credential-mode", "Claude mode is invalid")),
    }
}

fn admitted_claude_mode(home: &Path) -> Result<ClaudeMode, LaneError> {
    let mode = claude_mode(home)?;
    if mode == ClaudeMode::Refresh {
        return Err(failure(
            "credential-cutover-gate",
            "Claude refresh cannot start until all home carriers can be excluded",
        ));
    }
    Ok(mode)
}

fn read_claude_source(home: &Path) -> Result<ClaudeSource, LaneError> {
    let (document, stamp) = read_owner_document(home, ".credentials.json")?;
    let mut source = ClaudeSource::parse(&document)?;
    source.stamp = Some(stamp);
    Ok(source)
}

struct ClaudeOwnerProvider<'a, F> {
    home: &'a Path,
    refresh_program: F,
}

impl<F: Fn() -> Result<(), LaneError>> OwnerProvider for ClaudeOwnerProvider<'_, F> {
    type Snapshot = ClaudeSource;
    type Identity = FileStamp;

    fn read(&self) -> Result<ClaudeSource, LaneError> {
        read_claude_source(self.home)
    }
    fn due(&self, source: &ClaudeSource, now: u64) -> bool {
        source.needs_refresh(now)
    }
    fn identity(&self, source: &ClaudeSource) -> Result<FileStamp, LaneError> {
        source
            .stamp
            .ok_or_else(|| failure("credential-sign-in", "Claude source identity is absent"))
    }
    fn refresh(&self, _source: &ClaudeSource) -> Result<Option<ClaudeSource>, LaneError> {
        (self.refresh_program)()?;
        Ok(None)
    }
    fn publish(&self, _next: &ClaudeSource, _expected: FileStamp) -> Result<bool, LaneError> {
        Err(failure(
            "credential-publish",
            "Claude owner publication belongs to the vendor program",
        ))
    }
}

fn claude_refresh_program(home: &Path, expected_program: &str) -> Result<(), LaneError> {
    use std::os::unix::process::CommandExt as _;
    #[cfg(test)]
    if home.join(".fixture-refresh-sentinel-arm").exists() {
        fs::write(home.join(".fixture-refresh-sentinel"), b"entered")
            .map_err(|_| failure("credential-refresh", "fixture sentinel write failed"))?;
    }
    let program = Path::new("/usr/bin/claude");
    // Never fall back to an ambient program from the namespace/helper thread.
    crate::container_entry::check(program).ok_or_else(|| {
        failure(
            "credential-refresh",
            "Claude refresh requires its held owner program",
        )
    })??;
    crate::container_entry::verify_program_digest(program, expected_program)?;
    let argv = vec!["--print".into(), "Reply with OK.".into()];
    let environment = BTreeMap::from([
        ("HOME".into(), home.to_string_lossy().into_owned()),
        (
            "CLAUDE_CONFIG_DIR".into(),
            home.to_string_lossy().into_owned(),
        ),
        ("TMPDIR".into(), home.to_string_lossy().into_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
    ]);
    let mut command = Command::new("/usr/bin/claude");
    command
        .args(&argv)
        .env_clear()
        .envs(&environment)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    crate::container_entry::configure(&mut command, program, &argv, &environment)?;
    let mut child = command.spawn().map_err(|error| {
        credential_spawn_error(
            program,
            "credential-refresh",
            "Claude owner refresh could not start",
            &error,
        )
    })?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(failure(
                        "credential-refresh",
                        "Claude owner print-mode refresh failed",
                    ))
                };
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            state => {
                if let Ok(pid) = i32::try_from(child.id()) {
                    let _ignored = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(failure(
                    "credential-refresh",
                    if state.is_err() {
                        "Claude owner refresh wait failed"
                    } else {
                        "Claude owner refresh timed out"
                    },
                ));
            }
        }
    }
}

// Check the reviewed executable before opening any sign-in or publishing a worker
// file, even when the current access token does not need a refresh.
fn claude_program_pin(owner_home: &Path, loop_name: &str) -> Result<String, LaneError> {
    let expected = crate::launch::reviewed_claude_program_digest(owner_home, loop_name)?;
    crate::container_entry::verify_program_digest(Path::new("/usr/bin/claude"), &expected)?;
    Ok(expected)
}

fn claude_program_pin_bound(
    owner_home: &Path,
    loop_name: &str,
    binding: &crate::runtime_admission::ReviewedProgramBinding,
) -> Result<String, LaneError> {
    let expected =
        crate::launch::reviewed_claude_program_digest_bound(owner_home, loop_name, binding)?;
    crate::container_entry::verify_program_digest(Path::new("/usr/bin/claude"), &expected)?;
    Ok(expected)
}

fn prepare_claude_run(
    owner_home: &Path,
    loop_name: &str,
    run_home: &Path,
    worker_uid: u32,
    now: u64,
) -> Result<(), LaneError> {
    let home = claude_sign_in_dir(owner_home, loop_name);
    let expected_program = claude_program_pin(owner_home, loop_name)?;
    let mode = admitted_claude_mode(&home)?;
    with_claude_authority_mode(
        mode,
        &home,
        now,
        || claude_refresh_program(&home, &expected_program),
        now_milliseconds,
        |source| write_claude_run(run_home, worker_uid, source),
    )
}

#[cfg(test)]
fn prepare_claude_run_at(
    home: &Path,
    run_home: &Path,
    worker_uid: u32,
    now: u64,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
) -> Result<(), LaneError> {
    with_claude_authority(home, now, refresh_program, publication_time_ms, |source| {
        write_claude_run(run_home, worker_uid, source)
    })
}

#[cfg(test)]
fn with_claude_authority<T>(
    home: &Path,
    now: u64,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
    action: impl FnOnce(&ClaudeSource) -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    with_claude_authority_mode(
        ClaudeMode::Refresh,
        home,
        now,
        refresh_program,
        publication_time_ms,
        action,
    )
}

fn with_claude_authority_mode<T>(
    mode: ClaudeMode,
    home: &Path,
    now: u64,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
    action: impl FnOnce(&ClaudeSource) -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    with_claude_authority_mode_observed(
        mode,
        home,
        now,
        refresh_program,
        publication_time_ms,
        |_| {},
        action,
    )
}

fn with_claude_authority_mode_observed<T>(
    mode: ClaudeMode,
    home: &Path,
    now: u64,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
    observed: impl FnOnce(&ClaudeSource),
    action: impl FnOnce(&ClaudeSource) -> Result<T, LaneError>,
) -> Result<T, LaneError> {
    let owner = owner_identity().0;
    let directory = open_dir(home, owner, owner, 0o700)?;
    let _guard = lock_with(&directory, FlockArg::LockExclusive)?;
    let source = match mode {
        ClaudeMode::Read => {
            let source = read_claude_source(home)?;
            observed(&source);
            if source.expires_ms <= now.saturating_mul(1000) {
                return Err(failure(
                    "credential-read-expired",
                    "Claude access authority expired",
                ));
            }
            if source.needs_refresh(now) {
                return Err(failure(
                    "credential-read-due",
                    "Claude access authority is due",
                ));
            }
            source
        }
        ClaudeMode::Refresh => refresh_provider(
            &ClaudeOwnerProvider {
                home,
                refresh_program,
            },
            now,
            || {},
        )?,
    };
    let publication_time = publication_time_ms()?;
    if mode == ClaudeMode::Read
        && source.expires_ms
            <= publication_time.saturating_add(REFRESH_AHEAD.as_secs().saturating_mul(1000))
    {
        return Err(failure(
            if source.expires_ms <= publication_time {
                "credential-read-expired"
            } else {
                "credential-read-due"
            },
            "Claude access authority became due before publication",
        ));
    }
    if source.expires_ms <= publication_time {
        return Err(failure(
            if mode == ClaudeMode::Read {
                "credential-read-expired"
            } else {
                "credential-refresh"
            },
            if mode == ClaudeMode::Read {
                "Claude access authority expired before publication"
            } else {
                "Claude owner program left expired access authority"
            },
        ));
    }
    action(&source)
}

#[cfg(test)]
fn publish_claude_round_at(
    home: &Path,
    run_home: &Path,
    worker_uid: u32,
    now: u64,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
) -> Result<Value, LaneError> {
    with_claude_authority(home, now, refresh_program, publication_time_ms, |source| {
        claude_round_receipt(run_home, worker_uid, source)
    })
}

fn claude_round_receipt(
    run_home: &Path,
    worker_uid: u32,
    source: &ClaudeSource,
) -> Result<Value, LaneError> {
    let stamp = source
        .stamp
        .ok_or_else(|| failure("credential-publish", "Claude source inode is absent"))?;
    write_claude_run(run_home, worker_uid, source)?;
    publication_receipt(stamp)
}

fn write_claude_run(home: &Path, worker_uid: u32, source: &ClaudeSource) -> Result<(), LaneError> {
    atomic_file(
        &home.join(".claude"),
        ".credentials.json",
        &source.worker_file(),
        worker_uid,
        worker_uid,
        0o700,
        None,
    )
    .map(|_published| ())
}

/// Remove only the selected backend's worker projection after its service ends.
/// The entry is inspected beneath the held directory without opening its contents.
pub(crate) fn withdraw_worker_projection(
    home: &Path,
    worker_uid: u32,
    backend: BoxBackend,
) -> Result<(), LaneError> {
    let directory = home.join(backend.state_leaf());
    let name = backend.worker_projection_name();
    let fd = open_dir(&directory, owner_identity().0, worker_uid, 0o700)?;
    let stat = match fstatat(&fd, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(failure("credential-withdraw", error.to_string())),
    };
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != worker_uid
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err(failure(
            "credential-withdraw",
            "worker projection changed type, owner or mode",
        ));
    }
    unlinkat(&fd, name, UnlinkatFlags::NoRemoveDir)
        .or_else(|error| {
            if error == Errno::ENOENT {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| failure("credential-withdraw", error.to_string()))?;
    File::from(fd)
        .sync_all()
        .map_err(|error| failure("credential-withdraw", error.to_string()))
}

/// Callers hold the loop refresh lock through this operation and worker publication.
/// This preserves the identity check followed by rename; it is not an atomic CAS.
fn refresh_provider<P: OwnerProvider>(
    provider: &P,
    now: u64,
    before_publish: impl FnOnce(),
) -> Result<P::Snapshot, LaneError> {
    let source = provider.read()?;
    if !provider.due(&source, now) {
        return Ok(source);
    }
    let expected = provider.identity(&source)?;
    let next = provider.refresh(&source)?;
    let current = provider.read()?;
    if provider.identity(&current)? != expected {
        return Ok(current);
    }
    let Some(next) = next else {
        return Ok(current);
    };
    before_publish();
    if provider.publish(&next, expected)? {
        Ok(next)
    } else {
        provider.read()
    }
}

fn refresh_if_due(
    owner_home: &Path,
    loop_name: &str,
    endpoint: &str,
    now: u64,
) -> Result<Source, LaneError> {
    refresh_if_due_with(owner_home, loop_name, endpoint, now, || {})
}

fn refresh_if_due_with(
    owner_home: &Path,
    loop_name: &str,
    endpoint: &str,
    now: u64,
    before_publish: impl FnOnce(),
) -> Result<Source, LaneError> {
    refresh_provider(
        &CodexOwnerProvider {
            owner_home,
            loop_name,
            endpoint,
            bound: None,
        },
        now,
        before_publish,
    )
}

/// Access-only authority selected under the caller's loop refresh guard.
pub(crate) struct DoorAuthority {
    pub(crate) bytes: Vec<u8>,
    pub(crate) expires_unix: u64,
    pub(crate) refresh_due_unix: u64,
    pub(crate) refreshed: bool,
}

/// Select and, when due, renew owner authority without taking a second lock.
///
/// # Errors
/// Refuses an unusable source, failed renewal, stop, or insufficient access lifetime.
pub(crate) fn door_authority_under_lock(
    owner_home: &Path,
    loop_name: &str,
    endpoint: &str,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<DoorAuthority, LaneError> {
    if stopped() || Instant::now() >= deadline {
        return Err(failure(
            "credential-door-timeout",
            "publication time exhausted",
        ));
    }
    let now = now_seconds()?;
    let provider = CodexOwnerProvider {
        owner_home,
        loop_name,
        endpoint,
        bound: Some((deadline, stopped)),
    };
    let before = provider.read()?;
    let source = refresh_provider(&provider, now, || {})?;
    door_lifetime(source.expires_at, deadline, stopped)?;
    Ok(DoorAuthority {
        bytes: source.worker_file(),
        expires_unix: source.expires_at,
        refresh_due_unix: source.refresh_due_unix(),
        refreshed: before.stamp != source.stamp && before.needs_refresh(now),
    })
}

fn door_lifetime(
    expires_unix: u64,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<(), LaneError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let margin = remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0) + 2;
    if stopped() || remaining.is_zero() {
        return Err(failure(
            "credential-door-timeout",
            "publication time exhausted",
        ));
    }
    if expires_unix <= now_seconds()?.saturating_add(margin) {
        return Err(failure(
            "credential-door-lifetime",
            "access authority ends before the admitted call",
        ));
    }
    Ok(())
}

/// Publish one access-only projection through the registered loop entry.
/// The caller holds the loop refresh guard and must drop it before vendor spawn.
///
/// # Errors
/// Refuses missing authority, stop, insufficient lifetime, or unconfirmed publication.
pub(crate) fn publish_door_under_lock(
    owner_home: &Path,
    loop_name: &str,
    entry: &Path,
    private_home: &Path,
    loop_uid: u32,
    deadline: Instant,
    stopped: &dyn Fn() -> bool,
) -> Result<Value, LaneError> {
    let authority =
        door_authority_under_lock(owner_home, loop_name, AUTH_ENDPOINT, deadline, stopped)?;
    if authority.bytes.len() > 65_536 {
        return Err(failure(
            "credential-door-publication",
            "projection exceeds limit",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || stopped() {
        return Err(failure(
            "credential-door-timeout",
            "publication time exhausted",
        ));
    }
    crate::pinned::owner_executable(entry, Uid::effective().as_raw())?;
    let mut command = Command::new(entry);
    command
        .args([
            "enter",
            loop_name,
            "--",
            "/usr/bin/python3",
            "-I",
            "-c",
            include_str!("door_sign_in_private.py"),
        ])
        .arg(loop_uid.to_string())
        .arg(private_home)
        .arg(remaining.as_millis().to_string())
        .env_clear()
        .env("HOME", owner_home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", format!("/run/user/{}", Uid::effective()))
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{}/bus", Uid::effective()),
        );
    let output =
        bounded_pipe(&mut command, &authority.bytes, deadline, stopped, 8192).map_err(|kind| {
            failure(
                if kind == "deadline" || kind == "cancelled" {
                    "credential-door-timeout"
                } else {
                    "credential-door-publication"
                },
                kind,
            )
        })?;
    if !output.status.success() {
        return Err(failure("credential-door-publication", "receiver refused"));
    }
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| failure("credential-door-publication", "receiver report invalid"))?;
    if receipt["published"] != true
        || receipt["path"].as_str() != private_home.join(".codex/auth.json").to_str()
        || receipt["loop_uid"] != loop_uid
    {
        return Err(failure(
            "credential-door-publication",
            "receiver report unconfirmed",
        ));
    }
    door_lifetime(authority.expires_unix, deadline, stopped)?;
    Ok(json!({"expires_unix":authority.expires_unix,
        "refresh_due_unix":authority.refresh_due_unix,
        "refreshed":authority.refreshed}))
}

/// Hold the loop-wide refresh lock through the initial run-home credential publication.
///
/// # Errors
///
/// Refuses missing source auth, a failed vendor refresh, or a failed atomic publication.
pub fn prepare_run(
    owner_home: &Path,
    loop_name: &str,
    run_home: &Path,
    worker_uid: u32,
    backend: BoxBackend,
) -> Result<(), LaneError> {
    backend.require_runtime()?;
    if backend == BoxBackend::Claude {
        return prepare_claude_run(owner_home, loop_name, run_home, worker_uid, now_seconds()?);
    }
    let _guard = lock(owner_home, loop_name)?;
    let source = refresh_if_due(owner_home, loop_name, AUTH_ENDPOINT, now_seconds()?)?;
    write_run(run_home, worker_uid, &source)
}

/// Republish the current owner source synchronously before a round can start.
///
/// # Errors
///
/// Refuses unavailable authority, unsafe custody or failed publication and clock evidence.
pub(crate) fn publish_round_admitted(
    owner_home: &Path,
    loop_name: &str,
    run_home: &Path,
    worker_uid: u32,
    backend: BoxBackend,
    admission: &crate::runtime_admission::RuntimeAdmission,
) -> Result<Value, LaneError> {
    admission.check(backend)?;
    let binding = admission.round_binding(owner_home, loop_name, run_home, worker_uid)?;
    if backend == BoxBackend::Claude {
        let home = claude_sign_in_dir(owner_home, loop_name);
        let expected_program = claude_program_pin_bound(owner_home, loop_name, binding)?;
        let mode = admitted_claude_mode(&home)?;
        return with_claude_authority_mode(
            mode,
            &home,
            now_seconds()?,
            || claude_refresh_program(&home, &expected_program),
            now_milliseconds,
            |source| claude_round_receipt(run_home, worker_uid, source),
        );
    }
    let _guard = lock(owner_home, loop_name)?;
    let _refreshed = refresh_if_due(owner_home, loop_name, AUTH_ENDPOINT, now_seconds()?)?;
    // Reopen after a refresh so the evidence identifies the published owner inode.
    let source = read_source(owner_home, loop_name)?;
    let stamp = source
        .stamp
        .ok_or_else(|| failure("credential-publish", "source inode is absent"))?;
    write_run(run_home, worker_uid, &source)?;
    publication_receipt(stamp)
}

fn publication_receipt(stamp: FileStamp) -> Result<Value, LaneError> {
    let published = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| failure("credential-clock", error.to_string()))?;
    let instant = u64::try_from(published.as_nanos())
        .map_err(|error| failure("credential-clock", error.to_string()))?;
    Ok(json!({"source_inode":stamp.inode,"published_unix_ns":instant}))
}

/// Check owner credentials before any run destination is created.
///
/// # Errors
///
/// Refuses absent, unreadable or malformed sign-in data.
pub fn preflight(owner_home: &Path, loop_name: &str, backend: BoxBackend) -> Result<(), LaneError> {
    backend.require_runtime()?;
    if backend == BoxBackend::Claude {
        let home = claude_sign_in_dir(owner_home, loop_name);
        let expected_program = claude_program_pin(owner_home, loop_name)?;
        let mode = admitted_claude_mode(&home)?;
        return with_claude_authority_mode(
            mode,
            &home,
            now_seconds()?,
            || claude_refresh_program(&home, &expected_program),
            now_milliseconds,
            |_| Ok(()),
        );
    }
    preflight_at(owner_home, loop_name, AUTH_ENDPOINT, now_seconds()?)
}

fn preflight_at(
    owner_home: &Path,
    loop_name: &str,
    endpoint: &str,
    now: u64,
) -> Result<(), LaneError> {
    let _guard = lock(owner_home, loop_name)?;
    let _source = refresh_if_due(owner_home, loop_name, endpoint, now)?;
    Ok(())
}

/// Refresh and publish one loop's token to each live run while the helper serves it.
#[derive(Debug)]
pub(crate) struct RefreshReport {
    pub changed: bool,
    pub refusals: Vec<Value>,
    pub refusals_omitted: usize,
    pub expires_unix: u64,
    pub refresh_due_unix: u64,
    pub authority_failure: Option<LaneError>,
}

/// Shape evidence under the compiled schema binding for regressions.
#[cfg(test)]
pub(crate) fn evidence_for_check(
    result: &Result<RefreshReport, LaneError>,
    first_check: bool,
    backend: BoxBackend,
) -> Option<Value> {
    evidence_for_check_bound(
        result,
        first_check,
        backend,
        &crate::runtime_admission::ReviewedProgramBinding::Schema,
    )
}

/// Shape the result of one helper check for protected owner evidence.
pub(crate) fn evidence_for_check_bound(
    result: &Result<RefreshReport, LaneError>,
    first_check: bool,
    backend: BoxBackend,
    binding: &crate::runtime_admission::ReviewedProgramBinding,
) -> Option<Value> {
    let mut evidence = match result {
        Err(error) => Some(json!({
            "schema":1,"host":REFRESH_HOST,"state":"refused",
            "run_refusals":[],"run_refusals_omitted":0,
            "expires_unix":null,"refresh_due_unix":null,
            "kind":error.kind,"detail":error.detail,
        })),
        Ok(report)
            if first_check
                || report.changed
                || !report.refusals.is_empty()
                || report.refusals_omitted > 0
                || report.authority_failure.is_some() =>
        {
            let state = if report.authority_failure.is_some() {
                "refused"
            } else if report.changed && report.refusals.is_empty() && report.refusals_omitted == 0 {
                "published"
            } else if report.changed {
                "partial"
            } else if report.refusals.is_empty() && report.refusals_omitted == 0 {
                "current"
            } else {
                "refused"
            };
            let authority = report.authority_failure.as_ref();
            Some(json!({
                "schema":1,"host":REFRESH_HOST,"state":state,
                "run_refusals":report.refusals,"run_refusals_omitted":report.refusals_omitted,
                "expires_unix":report.expires_unix,"refresh_due_unix":report.refresh_due_unix,
                "kind":authority.map(|error| error.kind),
                "detail":authority.map(|error| error.detail.as_str()),
            }))
        }
        Ok(_) => None,
    }?;
    if backend == BoxBackend::Claude {
        evidence.as_object_mut()?.remove("host");
        evidence["schema"] = json!(2);
        evidence["backend"] = json!("claude");
        evidence["provider"] = json!({
            "kind":"owner-program", "program":"/usr/bin/claude",
            "required_sha256":binding.required_sha256(),
        });
    }
    Some(evidence)
}

#[cfg(test)]
pub(crate) const fn fixture_report(expires_unix: u64) -> RefreshReport {
    RefreshReport {
        changed: false,
        refusals: Vec::new(),
        refusals_omitted: 0,
        expires_unix,
        refresh_due_unix: expires_unix - REFRESH_AHEAD.as_secs(),
        authority_failure: None,
    }
}

/// Refresh the owner source and attempt every live run publication.
///
/// # Errors
///
/// Reports a failed authority request or publication without exposing token bytes.
pub(crate) fn refresh_live_admitted(
    owner_home: &Path,
    loop_name: &str,
    runs_root: &Path,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
    backend: BoxBackend,
    endpoint: &str,
    admission: &crate::runtime_admission::RuntimeAdmission,
) -> Result<RefreshReport, LaneError> {
    admission.check(backend)?;
    let binding = admission.periodic_binding(owner_home, loop_name, runs_root)?;
    if backend == BoxBackend::Claude {
        let home = claude_sign_in_dir(owner_home, loop_name);
        let expected_program = claude_program_pin_bound(owner_home, loop_name, binding)?;
        let mode = admitted_claude_mode(&home)?;
        return refresh_claude_live_admitted_at(
            &home,
            loop_name,
            runs_root,
            now_seconds()?,
            published,
            (
                mode,
                || claude_refresh_program(&home, &expected_program),
                now_milliseconds,
                admission,
            ),
        );
    }
    refresh_live_at(
        owner_home,
        loop_name,
        runs_root,
        endpoint,
        now_seconds()?,
        published,
        write_run,
    )
}

fn refresh_live_at(
    owner_home: &Path,
    loop_name: &str,
    runs_root: &Path,
    endpoint: &str,
    now: u64,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
    mut publish: impl FnMut(&Path, u32, &Source) -> Result<(), LaneError>,
) -> Result<RefreshReport, LaneError> {
    let _guard = lock(owner_home, loop_name)?;
    let source = read_source(owner_home, loop_name)?;
    let next = if source.needs_refresh(now) {
        match refresh_if_due(owner_home, loop_name, endpoint, now) {
            Ok(next) => next,
            Err(error) => {
                return Ok(RefreshReport {
                    changed: false,
                    refusals: Vec::new(),
                    refusals_omitted: 0,
                    expires_unix: source.expires_at,
                    refresh_due_unix: source.refresh_due_unix(),
                    authority_failure: Some(error),
                });
            }
        }
    } else {
        source
    };
    publish_live_snapshot(
        runs_root,
        loop_name,
        BoxBackend::Codex,
        published,
        &next.worker_file(),
        next.expires_at,
        |home, uid| publish(home, uid, &next),
    )
}

#[cfg(test)]
fn refresh_claude_live_at(
    home: &Path,
    loop_name: &str,
    runs_root: &Path,
    now: u64,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
    refresh_program: impl Fn() -> Result<(), LaneError>,
    publication_time_ms: impl FnOnce() -> Result<u64, LaneError>,
) -> Result<RefreshReport, LaneError> {
    refresh_claude_live_admitted_at(
        home,
        loop_name,
        runs_root,
        now,
        published,
        (
            ClaudeMode::Refresh,
            refresh_program,
            publication_time_ms,
            &crate::runtime_admission::RuntimeAdmission::Gate,
        ),
    )
}

fn refresh_claude_live_admitted_at(
    home: &Path,
    loop_name: &str,
    runs_root: &Path,
    now: u64,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
    provider: (
        ClaudeMode,
        impl Fn() -> Result<(), LaneError>,
        impl FnOnce() -> Result<u64, LaneError>,
        &crate::runtime_admission::RuntimeAdmission,
    ),
) -> Result<RefreshReport, LaneError> {
    let (mode, refresh_program, publication_time_ms, admission) = provider;
    #[cfg(not(test))]
    let _ = admission;
    let mut measured_expiry = None;
    let result = with_claude_authority_mode_observed(
        mode,
        home,
        now,
        refresh_program,
        publication_time_ms,
        |source| measured_expiry = Some(source.expires_ms / 1000),
        |source| {
            publish_live_snapshot(
                runs_root,
                loop_name,
                BoxBackend::Claude,
                published,
                &source.worker_file(),
                source.expires_ms / 1000,
                |home, uid| {
                    #[cfg(test)]
                    admission.scope_recipient(home)?;
                    write_claude_run(home, uid, source)
                },
            )
        },
    );
    match (result, measured_expiry) {
        (Err(error), Some(expires_unix))
            if matches!(
                error.kind,
                "credential-read-due" | "credential-read-expired"
            ) =>
        {
            Ok(RefreshReport {
                changed: false,
                refusals: Vec::new(),
                refusals_omitted: 0,
                expires_unix,
                refresh_due_unix: expires_unix.saturating_sub(REFRESH_AHEAD.as_secs()),
                authority_failure: Some(error),
            })
        }
        (result, _) => result,
    }
}

fn publish_live_snapshot(
    runs_root: &Path,
    loop_name: &str,
    backend: BoxBackend,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
    snapshot: &[u8],
    expires_unix: u64,
    mut publish: impl FnMut(&Path, u32) -> Result<(), LaneError>,
) -> Result<RefreshReport, LaneError> {
    let mut changed = false;
    let mut refusals = Vec::new();
    let mut refusal_bytes = 2_usize;
    let mut refusals_omitted = 0_usize;
    let held_runs = crate::home::pin_parent(runs_root, owner_identity().0)?;
    let held_path = format!("/proc/self/fd/{}", held_runs.as_raw_fd());
    for entry in fs::read_dir(&held_path)
        .map_err(|_| failure("credential-publish", "runs root cannot be listed"))?
    {
        let entry = entry.map_err(|_| failure("credential-publish", "run entry cannot be read"))?;
        let run = entry.file_name();
        let Some(run) = run.to_str() else { continue };
        if !crate::valid_run_name(run) {
            continue;
        }
        let Some(record) =
            crate::launch::read_reservation(&crate::launch::reservation_path(runs_root, run))?
        else {
            continue;
        };
        if record["loop"] != loop_name || record["phase"] != "started" {
            continue;
        }
        let (Some(pid), Some(start)) = (
            record["helper_pid"].as_u64(),
            record["helper_start"].as_u64(),
        ) else {
            continue;
        };
        let Ok(pid) = u32::try_from(pid) else {
            continue;
        };
        if crate::container_helper::process_presence(pid, start)
            != crate::container_helper::ProcessPresence::Present
        {
            continue;
        }
        // The protected backend confines publication to its own vendor homes.
        if BoxBackend::from_plan(&record["plan"])? != backend {
            continue;
        }
        let Some(home) = record["plan"]["home"].as_str() else {
            return Err(failure("credential-publish", "live run home is absent"));
        };
        let uid = record["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| failure("credential-publish", "live worker uid is absent"))?;
        let home = PathBuf::from(home);
        if published.get(&home).map(Vec::as_slice) == Some(snapshot) {
            continue;
        }
        if let Err(error) = publish(&home, uid) {
            let refusal = json!({"run": run, "kind": error.kind, "detail": error.detail});
            let entry_bytes = serde_json::to_vec(&refusal)
                .map_err(|_| failure("credential-evidence", "run refusal cannot be encoded"))?
                .len();
            if refusal_bytes + entry_bytes + usize::from(!refusals.is_empty())
                <= (MAX_EVIDENCE_BYTES / 2) as usize
            {
                refusal_bytes += entry_bytes + usize::from(!refusals.is_empty());
                refusals.push(refusal);
            } else {
                refusals_omitted += 1;
            }
            continue;
        }
        published.insert(home, snapshot.to_vec());
        changed = true;
    }
    Ok(RefreshReport {
        changed,
        refusals,
        refusals_omitted,
        expires_unix,
        refresh_due_unix: expires_unix.saturating_sub(REFRESH_AHEAD.as_secs()),
        authority_failure: None,
    })
}

#[cfg(test)]
mod tests {
    mod transaction;
    use crate::runtime_admission::RuntimeAdmission::Gate;

    /// # Panics
    /// Panics if a fixture can select a vendor endpoint without its thread-local guard.
    /// ´claim:superlooplane:service-fixture-endpoint-required´
    /// ´test:unit:service-fixture-endpoint-is-required-on-each-thread´
    #[test]
    fn service_fixture_endpoint_is_required_on_each_thread() {
        std::thread::spawn(|| {
            let refused = || {
                let error = std::panic::catch_unwind(service_endpoint)
                    .expect_err("missing fixture hook must refuse before spawning authority");
                let message = error
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| error.downcast_ref::<&str>().copied());
                assert!(
                    message
                        .is_some_and(|text| text.contains("service fixture endpoint is required"))
                );
            };
            refused();
            let endpoint = "http://127.0.0.1:1/fixture";
            let guard = fixture_service_endpoint(endpoint.into());
            assert_eq!(service_endpoint(), endpoint);
            {
                let _nested = fixture_service_endpoint("http://127.0.0.1:2/nested".into());
                assert_eq!(service_endpoint(), "http://127.0.0.1:2/nested");
            }
            assert_eq!(service_endpoint(), endpoint);
            std::thread::spawn(refused)
                .join()
                .expect("new thread refuses inherited hook");
            drop(guard);
            refused();
        })
        .join()
        .expect("isolated endpoint policy");
    }
    use super::*;
    use std::net::TcpListener;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::sync::{Arc, Mutex};

    fn fixture_root() -> tempfile::TempDir {
        let root = tempfile::Builder::new()
            .prefix("lane-credential-")
            .tempdir_in("/var/tmp")
            .expect("trusted fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
        root
    }

    fn claude_fixture_root() -> tempfile::TempDir {
        let root = tempfile::Builder::new()
            .prefix("lane-claude-credential-")
            .tempdir()
            .expect("private TMPDIR fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
        root
    }

    /// # Panics
    /// Panics if withdrawal touches another entry, reads a projection, or a later
    /// publication cannot restore the selected worker file.
    /// ´test:unit:codex-worker-projection-withdraws-and-republishes´
    #[test]
    fn codex_worker_projection_withdraws_and_republishes() {
        let root = claude_fixture_root();
        let uid = owner_identity().0;
        let directory = root.path().join(".codex");
        fs::create_dir(&directory).expect("worker state");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("worker state mode");
        let other = directory.join("config.toml");
        fs::write(&other, b"other worker state").expect("other entry");
        atomic_file(
            &directory,
            "auth.json",
            b"fictional access",
            uid,
            uid,
            0o700,
            None,
        )
        .expect("first publication");
        withdraw_worker_projection(root.path(), uid, BoxBackend::Codex)
            .expect("service withdrawal");
        assert!(!directory.join("auth.json").exists());
        assert_eq!(
            fs::read(&other).expect("other entry remains"),
            b"other worker state"
        );
        withdraw_worker_projection(root.path(), uid, BoxBackend::Codex)
            .expect("absent projection is harmless");
        atomic_file(
            &directory,
            "auth.json",
            b"next fictional access",
            uid,
            uid,
            0o700,
            None,
        )
        .expect("next round publication");
        assert_eq!(
            fs::read(directory.join("auth.json")).expect("next round file"),
            b"next fictional access"
        );
    }

    /// ´test:unit:worker-projection-withdrawal-refuses-changed-entry´
    #[test]
    fn worker_projection_withdrawal_refuses_changed_entry() {
        use std::os::unix::fs::symlink;
        let root = claude_fixture_root();
        let uid = owner_identity().0;
        let directory = root.path().join(".codex");
        fs::create_dir(&directory).expect("worker state");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("worker state mode");
        let projection = directory.join("auth.json");
        let expect_refusal = || {
            let error = withdraw_worker_projection(root.path(), uid, BoxBackend::Codex)
                .expect_err("changed entry refuses withdrawal");
            assert_eq!(error.kind, "credential-withdraw", "{error:?}");
            assert!(
                error.detail.contains("changed type, owner or mode"),
                "{error:?}"
            );
            assert!(projection.exists() || projection.symlink_metadata().is_ok());
        };
        fs::write(&projection, b"fictional access").expect("projection");
        fs::set_permissions(&projection, fs::Permissions::from_mode(0o640)).expect("wrong mode");
        expect_refusal();
        fs::remove_file(&projection).expect("remove wrong mode");
        symlink("config.toml", &projection).expect("link projection");
        expect_refusal();
        fs::remove_file(&projection).expect("remove link");
        fs::create_dir(&projection).expect("directory projection");
        fs::set_permissions(&projection, fs::Permissions::from_mode(0o600))
            .expect("directory has the expected file mode");
        expect_refusal();
        fs::remove_dir(&projection).expect("remove directory");
        fs::write(&projection, b"fictional access").expect("projection");
        fs::set_permissions(&projection, fs::Permissions::from_mode(0o600)).expect("correct mode");
        let error =
            withdraw_worker_projection(root.path(), uid.saturating_add(1), BoxBackend::Codex)
                .expect_err("wrong worker owner refuses withdrawal");
        assert!(error.line().contains("credential"), "{error:?}");
        assert_eq!(
            fs::read(&projection).expect("unchanged projection"),
            b"fictional access"
        );
    }

    /// # Panics
    /// Panics if unheld executable custody can read authority or replace a worker file.
    /// ´test:unit:claude-program-pin-precedes-owner-authority´
    #[test]
    fn claude_program_pin_precedes_owner_authority() {
        let root = claude_fixture_root();
        let loop_root = root.path().join(".config/loops/alpha");
        fs::create_dir_all(&loop_root).expect("configuration fixture");
        let record = json!({"schema":1,"phase":"complete", "image_digest":format!("sha256:{}", "b".repeat(64)),
            "claude_sha256":CLAUDE_SCHEMA_PROGRAM_SHA256, "claude_image_program":"/opt/claude/bin/claude",
            "claude_template_dir":format!("/owner/runner-templates/claude/{}", "b".repeat(64))});
        fs::write(
            loop_root.join("install-generation.json"),
            serde_json::to_vec(&record).expect("record"),
        )
        .expect("configuration");
        fs::set_permissions(
            loop_root.join("install-generation.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private generation");
        let _configuration = crate::runtime_entry::fixture_configuration(root.path());
        let worker = root.path().join("worker");
        fs::create_dir_all(worker.join(".claude")).expect("worker directory");
        let prior = worker.join(".claude/.credentials.json");
        fs::write(&prior, b"synthetic prior worker file").expect("prior file");
        let error = prepare_claude_run(
            root.path(),
            "alpha",
            &worker,
            owner_identity().0,
            1_800_000_000,
        )
        .expect_err("unheld program precedes absent owner authority");
        assert_eq!(error.kind, "credential-program-pin");
        assert_eq!(error.detail, "Claude program has no held executable");
        assert!(!claude_sign_in_dir(root.path(), "alpha").exists());
        assert_eq!(
            fs::read(prior).expect("prior worker"),
            b"synthetic prior worker file"
        );
    }

    /// # Panics
    /// Panics only if an unheld owner program is admitted for refresh.
    /// ´test:unit:claude-refresh-refuses-unheld-program´
    #[test]
    fn claude_refresh_refuses_unheld_program() {
        let error = claude_refresh_program(Path::new("/unopened-helper-home"), &"a".repeat(64))
            .expect_err("no ambient executable fallback");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(
            error.detail,
            "Claude refresh requires its held owner program"
        );
    }

    /// # Panics
    /// Panics only if stale authority is published or the owner refresh loses its lock.
    /// ´test:unit:claude-preparation-refuses-expired-program-result´
    #[test]
    fn claude_preparation_refuses_expired_program_result() {
        for (start, published) in [
            (1_800_000_000, 1_800_000_000_000),
            (1_799_999_990, 1_800_000_000_000),
            (1_799_999_990, 1_800_000_000_001),
        ] {
            let fixture = claude_fixture_root();
            let document = claude_document(1_800_000_000_000);
            let home = fixture_claude(fixture.path(), &document);
            let run = fixture.path().join("run");
            fs::create_dir_all(run.join(".claude")).expect("worker home");
            for path in [&run, &run.join(".claude")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("private worker home");
            }
            let calls = std::cell::Cell::new(0);
            let error = prepare_claude_run_at(
                &home,
                &run,
                owner_identity().0,
                start,
                || {
                    calls.set(calls.get() + 1);
                    let directory = open_dir(&home, owner_identity().0, owner_identity().0, 0o700)
                        .expect("owner home");
                    assert!(
                        lock_with(&directory, FlockArg::LockExclusiveNonblock).is_err(),
                        "refresh must hold the owner lock"
                    );
                    Ok(())
                },
                || {
                    assert_eq!(calls.get(), 1, "publication clock must follow the program");
                    Ok(published)
                },
            )
            .expect_err("successful program did not supply unexpired authority");
            assert_eq!(calls.get(), 1);
            assert_eq!(error.kind, "credential-refresh");
            assert_eq!(
                error.detail,
                "Claude owner program left expired access authority"
            );
            assert!(!run.join(".claude/.credentials.json").exists());
            assert_eq!(
                fs::read_to_string(home.join(".credentials.json")).expect("owner source"),
                document.to_string()
            );
        }
    }

    /// # Panics
    /// Panics if preflight publishes a worker file or admits expired owner authority.
    /// ´test:unit:claude-preflight-checks-without-worker-publication´
    #[test]
    fn claude_preflight_checks_without_worker_publication() {
        let fixture = claude_fixture_root();
        let document = claude_document(1_800_000_000_000);
        let home = fixture_claude(fixture.path(), &document);
        with_claude_authority(
            &home,
            1_700_000_000,
            || panic!("current source must not refresh"),
            || Ok(1_700_000_000_000),
            |_| Ok(()),
        )
        .expect("preflight");
        assert!(!fixture.path().join("worker").exists());
        assert_eq!(
            fs::read_to_string(home.join(".credentials.json")).expect("source"),
            document.to_string()
        );
        let error = with_claude_authority(
            &home,
            1_800_000_000,
            || Ok(()),
            || Ok(1_800_000_000_000),
            |_| Ok(()),
        )
        .expect_err("expired authority");
        assert_eq!(error.kind, "credential-refresh");
        let absent = fixture.path().join("absent");
        let backend = BoxBackend::Claude;
        for result in [
            preflight(&absent, "alpha", backend),
            prepare_run(&absent, "alpha", &absent, owner_identity().0, backend),
            publish_round_admitted(
                &absent,
                "alpha",
                &absent,
                owner_identity().0,
                backend,
                &Gate,
            )
            .map(|_| ()),
        ] {
            assert_eq!(
                result.expect_err("trial gate precedes custody").kind,
                "backend-unavailable"
            );
        }
        assert!(!absent.exists());
    }

    /// # Panics
    /// Panics if a resumed round uses stale authority, leaks host state or publishes on refusal.
    /// ´test:unit:claude-round-publication-reloads-owner-authority´
    #[test]
    fn claude_round_publication_reloads_owner_authority() {
        let fixture = claude_fixture_root();
        let old = claude_document(1_700_000_010_000);
        let home = fixture_claude(fixture.path(), &old);
        let prior_source_inode = fs::metadata(home.join(".credentials.json"))
            .expect("prior source")
            .ino();
        let run = fixture.path().join("worker");
        fs::create_dir_all(run.join(".claude")).expect("worker");
        for path in [&run, &run.join(".claude")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let mut next = claude_document(1_800_000_000_000);
        next["claudeAiOauth"]["accessToken"] = json!("N".repeat(108));
        let calls = std::cell::Cell::new(0);
        let receipt = publish_claude_round_at(
            &home,
            &run,
            owner_identity().0,
            1_700_000_000,
            || {
                calls.set(calls.get() + 1);
                let directory = open_dir(&home, owner_identity().0, owner_identity().0, 0o700)?;
                assert!(lock_with(&directory, FlockArg::LockExclusiveNonblock).is_err());
                let replacement = home.join("owner-program-next");
                fs::write(&replacement, next.to_string()).expect("stand-in owner program");
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
                    .expect("owner mode");
                fs::rename(replacement, home.join(".credentials.json")).expect("owner publication");
                Ok(())
            },
            || Ok(1_700_000_001_000),
        )
        .expect("round publication");
        assert_eq!(calls.get(), 1);
        assert_ne!(
            fs::metadata(home.join(".credentials.json"))
                .expect("new source")
                .ino(),
            prior_source_inode
        );
        let worker_path = run.join(".claude/.credentials.json");
        let bytes = fs::read(&worker_path).expect("worker bytes");
        assert_eq!(
            bytes,
            ClaudeSource::parse(&next).expect("shape").worker_file()
        );
        let encoded: Value = serde_json::from_slice(&bytes).expect("worker JSON");
        assert_eq!(encoded["claudeAiOauth"]["accessToken"], "N".repeat(108));
        assert_eq!(encoded.as_object().expect("worker object").len(), 1);
        assert!(encoded["claudeAiOauth"].get("refreshToken").is_none());
        assert!(
            encoded["claudeAiOauth"]
                .get("refreshTokenExpiresAt")
                .is_none()
        );
        let worker_inode = fs::metadata(&worker_path).expect("worker inode").ino();
        assert_eq!(
            fs::metadata(&worker_path)
                .expect("mode")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            receipt["source_inode"],
            fs::metadata(home.join(".credentials.json"))
                .expect("source inode")
                .ino()
        );
        assert!(receipt["published_unix_ns"].as_u64().is_some_and(|n| n > 0));
        assert_eq!(receipt.as_object().expect("publication receipt").len(), 2);
        let error = publish_claude_round_at(
            &home,
            &run,
            owner_identity().0,
            1_800_000_000,
            || Ok(()),
            || Ok(1_800_000_000_000),
        )
        .expect_err("expired resumed source");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(fs::read(&worker_path).expect("unchanged worker"), bytes);
        assert_eq!(
            fs::metadata(&worker_path).expect("unchanged inode").ino(),
            worker_inode
        );
        assert_eq!(
            fs::read_to_string(home.join(".credentials.json")).expect("unchanged owner"),
            next.to_string()
        );
    }

    /// # Panics
    /// Panics if a failed refresh alters the prior worker's bytes or inode.
    /// ´test:unit:claude-failed-round-refresh-preserves-worker-file´
    #[test]
    fn claude_failed_round_refresh_preserves_worker_file() {
        let fixture = claude_fixture_root();
        let home = fixture_claude(fixture.path(), &claude_document(1_800_000_000_000));
        let run = fixture.path().join("worker");
        fs::create_dir_all(run.join(".claude")).expect("worker leaf");
        for path in [&run, &run.join(".claude")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("worker mode");
        }
        let worker_path = run.join(".claude/.credentials.json");
        let bytes = b"synthetic prior worker file";
        fs::write(&worker_path, bytes).expect("prior worker");
        fs::set_permissions(&worker_path, fs::Permissions::from_mode(0o600)).expect("worker mode");
        let worker_inode = fs::metadata(&worker_path).expect("prior inode").ino();
        let error = publish_claude_round_at(
            &home,
            &run,
            owner_identity().0,
            1_800_000_000,
            || Err(failure("credential-refresh", "synthetic refusal")),
            || panic!("a failed refresh must not reach the publication clock"),
        )
        .expect_err("failed resumed refresh");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(error.detail, "synthetic refusal");
        assert_eq!(fs::read(&worker_path).expect("unchanged worker"), bytes);
        assert_eq!(
            fs::metadata(&worker_path).expect("unchanged inode").ino(),
            worker_inode
        );
    }

    fn claude_document(expires_ms: u64) -> Value {
        json!({
            "claudeAiOauth": {
                "accessToken": "A".repeat(108), "refreshToken": "R".repeat(108),
                "expiresAt": expires_ms, "refreshTokenExpiresAt": 1_900_000_000_000_u64,
                "scopes": ["a".repeat(16), "b".repeat(14), "c".repeat(16), "d".repeat(12), "e".repeat(12), "f".repeat(25)],
                "subscriptionType": "abc", "subscriptionTypeSource": "fixture", "rateLimitTier": "t".repeat(22)
            },
            "mcpOAuth": {"fixture-plugin": {"accessToken": "", "discoveryState": {"oauthMetadataFound": true}}}
        })
    }

    /// ´test:unit:claude-exercise-snapshot-holds-publication-lock´
    #[test]
    fn claude_exercise_snapshot_holds_publication_lock() {
        let root = tempfile::tempdir().expect("fixture");
        let document = claude_document(1_800_000_000_000);
        let home = fixture_claude(root.path(), &document);
        let owner = owner_identity().0;
        let held = open_dir(&home, owner, owner, 0o700).expect("held sign-in");
        let result = with_claude_exercise_snapshot(
            &held,
            &home,
            1_799_999_400,
            |identity, projection, due| {
                let directory = open_dir(&home, owner, owner, 0o700)?;
                let Err(error) = lock_with(&directory, FlockArg::LockExclusiveNonblock) else {
                    panic!("publication lock is not held");
                };
                assert_eq!(error.kind, "credential-lock-busy");
                assert!(due);
                assert_eq!(projection["claudeAiOauth"]["accessToken"], "A".repeat(108));
                assert!(projection["claudeAiOauth"].get("refreshToken").is_none());
                assert!(projection.get("mcpOAuth").is_none());
                assert!(identity.get("digest").is_none());
                assert!(!identity.to_string().contains(&"A".repeat(108)));
                Ok(())
            },
        );
        result.expect("locked read-only observation");
        assert_eq!(
            read_claude_source(&home).expect("unchanged").oauth,
            document["claudeAiOauth"]
        );
        let due = with_claude_exercise_snapshot(&held, &home, 1_799_999_399, |_, _, due| Ok(due));
        assert!(!due.expect("before margin"));
        fs::rename(&home, root.path().join("retained")).expect("replace pathname");
        let due = with_claude_exercise_snapshot(&held, &home, 1_799_999_400, |_, _, due| Ok(due));
        assert!(due.expect("held directory supplies the source"));
    }

    /// # Panics
    /// Panics if mapped owner publication loses worker ownership or exposes refresh authority.
    /// ´test:unit:claude-namespace-publication-keeps-worker-authority-separate´
    #[test]
    fn claude_namespace_publication_keeps_worker_authority_separate() {
        claude_namespace_case(
            "claude_namespace_publication_keeps_worker_authority_separate",
            "CLAUDE-NAMESPACE-PUBLICATION-MEASURED",
            claude_namespace_publication,
        );
    }

    /// # Panics
    /// Panics if held stand-in execution or transferred publication loses its boundary.
    /// ´test:unit:claude-namespace-held-program-standin´
    #[test]
    fn claude_namespace_held_program_standin() {
        claude_namespace_case(
            "claude_namespace_held_program_standin",
            "CLAUDE-NAMESPACE-HELD-STANDIN-MEASURED",
            claude_namespace_standin,
        );
    }

    fn claude_namespace_case(name: &str, marker: &str, body: fn()) {
        assert!(
            !claude_namespace_run(name, marker, body, None, None),
            "{name} exceeded its 60-second namespace watchdog"
        );
    }

    fn claude_namespace_run(
        name: &str,
        marker: &str,
        body: fn(),
        probe: Option<&Path>,
        observation: Option<&std::sync::Mutex<Option<ClaudeFixtureIdentity>>>,
    ) -> bool {
        use std::os::unix::process::CommandExt as _;
        if std::env::var_os("SUPERLOOP_CLAUDE_NAMESPACE_PROOF").is_some() {
            if std::env::var_os("CLAUDE_NAMESPACE_INIT").is_some() {
                claude_record_namespace_init();
                body();
                writeln!(std::io::stdout().lock(), "{marker}").expect("namespace marker");
            } else {
                claude_pid_namespace(name);
            }
            return false;
        }
        let standin = matches!(
            name,
            "claude_namespace_held_program_standin"
                | "claude_namespace_fixture_cleanup_survives_timeout_and_panic"
        )
        .then(claude_standin_host);
        let publication = (name == "claude_namespace_publication_keeps_worker_authority_separate")
            .then(claude_fixture_root);
        let fixture_root = standin
            .as_ref()
            .map(|(root, _)| root.path())
            .or_else(|| publication.as_ref().map(tempfile::TempDir::path));
        claude_retain_fixture(observation, fixture_root);
        let identity = fixture_root
            .or(probe)
            .map(|root| root.join("namespace-init"));
        let mut command = Command::new("/usr/bin/podman");
        if let Some(root) = &publication {
            command.env("CLAUDE_PUBLICATION_ROOT", root.path());
        }
        if let Some(path) = &identity {
            command.env("CLAUDE_NAMESPACE_IDENTITY", path);
        }
        command.stdin(Stdio::null());
        let channel = standin.as_ref().map(|(root, bundle)| {
            let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights channel");
            command
                .env("CLAUDE_STANDIN_ROOT", root.path())
                .env("CLAUDE_STANDIN_MANIFEST", &bundle.manifest)
                .stdin(Stdio::from(OwnedFd::from(input)));
            sender
        });
        if let Some(root) = probe {
            command.env("CLAUDE_WATCHDOG_ROOT", root);
        }
        let child = command
            .arg("unshare")
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                &format!("credential::tests::{name}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env_remove("_CONTAINERS_USERNS_CONFIGURED")
            .env_remove("_CONTAINERS_ROOTLESS_UID")
            .env("SUPERLOOP_CLAUDE_NAMESPACE_PROOF", "1")
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("mapped namespace");
        let mut child = ClaudeNamespaceChild {
            child: Some(child),
            root: fixture_root.map(Path::to_owned),
            identity,
            stopped: None,
        };
        claude_namespace_probe(probe, &child);
        if let (Some(channel), Some((_, bundle))) = (channel, standin.as_ref()) {
            loop_home::anchor::transport::send(&channel, &bundle.descriptors)
                .expect("complete helper capability frame");
        }
        if claude_namespace_wait(&mut child, probe) {
            return true;
        }
        let output = child.wait_with_output().expect("namespace output");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(marker) && stdout.contains("1 passed"),
            "{stdout}"
        );
        claude_namespace_output(name, &stdout);
        false
    }

    fn claude_namespace_wait(child: &mut ClaudeNamespaceChild, probe: Option<&Path>) -> bool {
        let began = std::time::Instant::now();
        while child.try_wait().expect("namespace status").is_none() {
            assert!(
                !probe.is_some_and(|root| {
                    root.join("ready").exists() && root.join("panic").exists()
                }),
                "injected host panic after namespace readiness"
            );
            if began.elapsed() > Duration::from_secs(60)
                || probe.is_some_and(|root| root.join("ready").exists())
            {
                assert!(child.stop(), "namespace fixture did not terminate");
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    struct ClaudeNamespaceChild {
        child: Option<std::process::Child>,
        root: Option<PathBuf>,
        identity: Option<PathBuf>,
        stopped: Option<bool>,
    }

    impl std::ops::Deref for ClaudeNamespaceChild {
        type Target = std::process::Child;
        fn deref(&self) -> &Self::Target {
            self.child.as_ref().expect("owned namespace child")
        }
    }

    impl std::ops::DerefMut for ClaudeNamespaceChild {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.child.as_mut().expect("owned namespace child")
        }
    }

    impl ClaudeNamespaceChild {
        fn stop(&mut self) -> bool {
            if let Some(stopped) = self.stopped {
                return stopped;
            }
            if let Some(child) = &mut self.child {
                if let Ok(group) = i32::try_from(child.id()) {
                    let _ignored = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(group),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                drop(child.kill());
                drop(child.wait());
            }
            let stopped = claude_namespace_exited(self.identity.as_deref());
            self.stopped = Some(stopped);
            stopped
        }

        fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
            let output = self
                .child
                .take()
                .expect("owned namespace child")
                .wait_with_output()?;
            self.stopped = Some(true);
            if let Some(root) = self.root.take() {
                claude_cleanup_fixture(&root)?;
            }
            Ok(output)
        }
    }

    impl Drop for ClaudeNamespaceChild {
        fn drop(&mut self) {
            if !self.stop() {
                let _ignored = writeln!(
                    std::io::stderr().lock(),
                    "namespace fixture termination unconfirmed; mapped storage retained"
                );
                return;
            }
            if let Some(root) = self.root.take()
                && let Err(error) = claude_cleanup_fixture(&root)
            {
                let _ignored = writeln!(
                    std::io::stderr().lock(),
                    "namespace fixture cleanup failed: {error}"
                );
            }
        }
    }

    fn claude_namespace_exited(identity: Option<&Path>) -> bool {
        use crate::container_helper::{ProcessPresence, process_presence};
        let Some(path) = identity else {
            return true;
        };
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        };
        let Ok(record) = serde_json::from_slice::<Value>(&bytes) else {
            return false;
        };
        let Some(pid) = record["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            return false;
        };
        let Some(start) = record["start"].as_u64() else {
            return false;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match process_presence(pid, start) {
                ProcessPresence::Absent => return true,
                ProcessPresence::Unknown => return false,
                ProcessPresence::Present => {}
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn claude_record_namespace_init() {
        if let Some(path) = std::env::var_os("CLAUDE_NAMESPACE_IDENTITY") {
            let path = PathBuf::from(path);
            let (pid, start) = claude_host_identity();
            let record = serde_json::json!({"pid": pid, "start": start});
            let pending = path.with_extension("pending");
            fs::write(&pending, record.to_string()).expect("namespace identity");
            fs::rename(pending, path).expect("namespace ready before fixture work");
        }
    }

    fn claude_cleanup_fixture(root: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        if !root.is_absolute() {
            return Err(std::io::Error::other("mapped fixture root is not absolute"));
        }
        let directory = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        claude_cleanup_fixture_at(&directory)
    }

    fn claude_cleanup_fixture_at(directory: &fs::File) -> std::io::Result<()> {
        claude_cleanup_contents_at(directory, false)
    }

    fn claude_cleanup_contents_at(directory: &fs::File, all: bool) -> std::io::Result<()> {
        let held = directory.metadata()?;
        claude_cleanup_identity_at(directory, all, (held.dev(), held.ino()))
    }

    fn claude_cleanup_identity_at(
        directory: &fs::File,
        all: bool,
        expected: (u64, u64),
    ) -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        // Enter the held directory before execution; no namespace-written path is followed.
        let child = Command::new("/usr/bin/podman")
            .args(["unshare", "/usr/bin/python3", "-I", "-c"])
            .arg(format!("{}{}", concat!(
                "import os,sys\n",
                "root=os.open('.',os.O_RDONLY|os.O_DIRECTORY)\n",
                "held=os.fstat(root)\n",
                "if (held.st_dev,held.st_ino)!=(int(sys.argv[1]),int(sys.argv[2])):\n",
                " raise RuntimeError('mapped fixture cleanup identity differs')\n",
            ), if all {
                concat!(
                    "import os,shutil,stat\n",
                    "for name in os.listdir(root):\n",
                    " if stat.S_ISDIR(os.stat(name,dir_fd=root,follow_symlinks=False).st_mode):\n",
                    "  shutil.rmtree(name,dir_fd=root)\n",
                    " else: os.unlink(name,dir_fd=root)\n",
                )
            } else {
                concat!(
                    "import os,shutil\n",
                    "try:\n",
                    " r=os.open('runs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)\n",
                    "except FileNotFoundError: pass\n",
                    "else:\n",
                    " try: shutil.rmtree('worker',dir_fd=r)\n",
                    " except FileNotFoundError: pass\n",
                    " finally: os.close(r)\n",
                )
            }))
            .args([expected.0.to_string(), expected.1.to_string()])
            .env_remove("_CONTAINERS_USERNS_CONFIGURED")
            .env_remove("_CONTAINERS_ROOTLESS_UID")
            .current_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        let mut child = ClaudeNamespaceChild {
            child: Some(child),
            root: None,
            identity: None,
            stopped: None,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while child.try_wait()?.is_none() {
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::other("mapped fixture cleanup timed out"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.stopped = Some(true);
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "mapped fixture cleanup refused: {}",
                String::from_utf8_lossy(&output.stderr),
            )));
        }
        Ok(())
    }

    fn claude_namespace_probe(probe: Option<&Path>, child: &ClaudeNamespaceChild) {
        if let Some(root) = probe {
            let pid = child.id();
            let start = crate::container_helper::process_start(pid).expect("supervisor start");
            let record = serde_json::json!({"pid": pid, "start": start});
            fs::write(root.join("supervisor"), record.to_string()).expect("supervisor record");
            if let Some(fixture) = &child.root {
                fs::write(root.join("fixture"), fixture.as_os_str().as_encoded_bytes())
                    .expect("fixture location");
            }
        }
    }

    /// # Panics
    /// Panics if timeout or host unwind retains a supervisor or mapped fixture storage.
    /// ´test:unit:claude-namespace-fixture-cleanup-survives-timeout-and-panic´
    #[test]
    fn claude_namespace_fixture_cleanup_survives_timeout_and_panic() {
        let name = "claude_namespace_fixture_cleanup_survives_timeout_and_panic";
        if std::env::var_os("SUPERLOOP_CLAUDE_NAMESPACE_PROOF").is_some() {
            claude_namespace_run(name, "CLEANUP-UNREACHABLE", claude_cleanup_body, None, None);
            return;
        }
        for panic in [false, true] {
            let probe = claude_fixture_root();
            let outside = claude_fixture_root();
            let sentinel = outside.path().join("sentinel");
            fs::write(&sentinel, b"outside fixture").expect("outside sentinel");
            let inode = fs::metadata(&sentinel).expect("sentinel identity").ino();
            let observation = std::sync::Mutex::new(None);
            if panic {
                fs::write(probe.path().join("panic"), b"inject").expect("panic trigger");
            }
            let result = std::panic::catch_unwind(|| {
                claude_namespace_run(
                    name,
                    "CLEANUP-UNREACHABLE",
                    claude_cleanup_body,
                    Some(probe.path()),
                    Some(&observation),
                )
            });
            let ready = probe.path().join("ready").exists();
            fs::write(
                probe.path().join("fixture"),
                outside.path().as_os_str().as_encoded_bytes(),
            )
            .expect("namespace-writable target replaced");
            let fixture = observation
                .lock()
                .expect("host observation")
                .take()
                .expect("fixture");
            claude_cleanup_observation(probe.path(), &fixture);
            assert_eq!(
                fs::read(&sentinel).expect("outside retained"),
                b"outside fixture"
            );
            assert_eq!(fs::metadata(&sentinel).expect("same sentinel").ino(), inode);
            assert!(ready, "mapped worker existed before interruption");
            if panic {
                assert!(result.is_err(), "host panic reached");
            } else {
                assert!(
                    result.expect("timeout without host panic"),
                    "watchdog reached"
                );
            }
        }
    }

    fn claude_cleanup_body() {
        let root = PathBuf::from(std::env::var_os("CLAUDE_STANDIN_ROOT").expect("fixture root"));
        let run = claude_standin_worker(&root.join("runs"));
        fs::write(run.join(".claude/synthetic"), b"fixture storage").expect("worker storage");
        let probe = PathBuf::from(std::env::var_os("CLAUDE_WATCHDOG_ROOT").expect("probe root"));
        fs::write(probe.join("ready"), b"ready").expect("worker ready");
        // A host killed without unwinding leaves this body for at most two minutes.
        std::thread::sleep(Duration::from_secs(120));
        panic!("cleanup body outlived its 120-second bound");
    }

    struct ClaudeFixtureIdentity {
        path: PathBuf,
        directory: fs::File,
    }

    fn claude_retain_fixture(
        observation: Option<&std::sync::Mutex<Option<ClaudeFixtureIdentity>>>,
        root: Option<&Path>,
    ) {
        if let Some(observation) = observation {
            let path = root.expect("host-created fixture").to_owned();
            let directory = fs::File::open(&path).expect("retain host-created directory");
            *observation.lock().expect("host observation") =
                Some(ClaudeFixtureIdentity { path, directory });
        }
    }

    fn claude_fixture_identity_matches(fixture: &ClaudeFixtureIdentity) -> bool {
        let current = match fs::symlink_metadata(&fixture.path) {
            Ok(current) => current,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Err(error) => panic!("fixture identity: {error}"),
        };
        let held = fixture.directory.metadata().expect("held fixture identity");
        assert!(
            current.is_dir() && (current.dev(), current.ino()) == (held.dev(), held.ino()),
            "fixture root replaced"
        );
        true
    }

    fn claude_remove_retained_fixture(fixture: &ClaudeFixtureIdentity) -> bool {
        claude_remove_retained_fixture_with(fixture, |directory| {
            claude_cleanup_fixture_at(directory).expect("negative-control mapped cleanup");
        })
    }

    fn claude_remove_retained_fixture_with(
        fixture: &ClaudeFixtureIdentity,
        cleanup: impl FnOnce(&fs::File),
    ) -> bool {
        if !claude_fixture_identity_matches(fixture) {
            return false;
        }
        cleanup(&fixture.directory);
        if !claude_fixture_identity_matches(fixture) {
            return false;
        }
        fs::remove_dir_all(&fixture.path).expect("negative-control host cleanup");
        true
    }

    fn claude_assert_replaced(result: std::thread::Result<bool>) {
        let panic = result.expect_err("replacement must refuse");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"fixture root replaced"));
    }

    /// # Panics
    /// Panics if a replaced host fixture pathname authorizes removal of another directory.
    /// ´test:unit:claude-cleanup-retains-host-fixture-identity´
    #[test]
    fn claude_cleanup_retains_host_fixture_identity() {
        let parent = claude_fixture_root();
        let path = parent.path().join("fixture");
        fs::create_dir(&path).expect("fixture directory");
        let fixture = ClaudeFixtureIdentity {
            directory: fs::File::open(&path).expect("held fixture"),
            path: path.clone(),
        };
        fs::rename(&path, parent.path().join("retained")).expect("move original");
        fs::create_dir(&path).expect("foreign replacement");
        let sentinel = path.join("sentinel");
        fs::write(&sentinel, b"foreign directory").expect("sentinel");
        let inode = fs::metadata(&sentinel).expect("sentinel identity").ino();
        claude_assert_replaced(std::panic::catch_unwind(|| {
            claude_remove_retained_fixture(&fixture)
        }));
        assert_eq!(
            fs::read(&sentinel).expect("retained sentinel"),
            b"foreign directory"
        );
        assert_eq!(fs::metadata(&sentinel).expect("same sentinel").ino(), inode);
    }

    /// # Panics
    /// Panics if a non-directory replacement or a replacement during cleanup is removed.
    /// ´test:unit:claude-cleanup-rechecks-host-identity-after-mapped-removal´
    #[test]
    fn claude_cleanup_rechecks_host_identity_after_mapped_removal() {
        for (during, directory) in [(false, false), (true, false), (true, true)] {
            let parent = claude_fixture_root();
            let path = parent.path().join("fixture");
            fs::create_dir(&path).expect("fixture");
            let fixture = ClaudeFixtureIdentity {
                directory: fs::File::open(&path).expect("held directory"),
                path: path.clone(),
            };
            let replace = || {
                fs::rename(&path, parent.path().join("retained")).expect("retain original");
                if directory {
                    fs::create_dir(&path).expect("foreign directory");
                    fs::write(path.join("sentinel"), b"foreign file").expect("sentinel");
                } else {
                    fs::write(&path, b"foreign file").expect("non-directory replacement");
                }
            };
            if !during {
                replace();
            }
            claude_assert_replaced(std::panic::catch_unwind(|| {
                claude_remove_retained_fixture_with(&fixture, |_| {
                    assert!(during, "initial replacement must refuse before cleanup");
                    replace();
                })
            }));
            let sentinel = if directory {
                path.join("sentinel")
            } else {
                path
            };
            assert_eq!(
                fs::read(sentinel).expect("replacement retained"),
                b"foreign file"
            );
        }
    }

    /// # Panics
    /// Panics if a mapped cleanup can remove entries after a changed cwd identity.
    /// ´test:unit:claude-cleanup-checks-mapped-enclosing-identity´
    #[test]
    fn claude_cleanup_checks_mapped_enclosing_identity() {
        for all in [false, true] {
            let root = claude_fixture_root();
            fs::create_dir_all(root.path().join("runs/worker")).expect("worker");
            let sentinel = root.path().join("runs/worker/sentinel");
            fs::write(&sentinel, b"retained fixture").expect("sentinel");
            let inode = fs::metadata(&sentinel).expect("sentinel identity").ino();
            let held = fs::File::open(root.path()).expect("held root");
            let identity = held.metadata().expect("identity");
            let error = claude_cleanup_identity_at(
                &held,
                all,
                (
                    identity.dev(),
                    identity.ino().checked_add(1).expect("foreign inode"),
                ),
            )
            .expect_err("mapped cwd must match held identity");
            assert!(
                error
                    .to_string()
                    .contains("mapped fixture cleanup identity differs"),
                "cleanup stderr: {error}"
            );
            assert_eq!(fs::read(&sentinel).expect("retained"), b"retained fixture");
            assert_eq!(fs::metadata(&sentinel).expect("same inode").ino(), inode);
            claude_cleanup_contents_at(&held, all).expect("matching mapped cwd");
            assert!(!sentinel.exists());
        }
    }

    /// # Panics
    /// Panics if Podman's mapped cleanup loses the renamed held directory.
    /// ´test:unit:claude-cleanup-measures-renamed-cwd-custody´
    #[test]
    fn claude_cleanup_measures_renamed_cwd_custody() {
        let parent = claude_fixture_root();
        let original = parent.path().join("enclosure");
        let retained = parent.path().join("retained");
        fs::create_dir(&original).expect("enclosure");
        fs::write(original.join("synthetic"), b"fixture").expect("fixture file");
        let held = fs::File::open(&original).expect("held enclosure");
        fs::rename(&original, &retained).expect("rename before re-exec");
        fs::create_dir(&original).expect("replacement");
        fs::write(original.join("sentinel"), b"outside held enclosure").expect("sentinel");
        claude_cleanup_contents_at(&held, true).expect("re-exec retains cwd identity");
        assert_eq!(
            fs::read_dir(&retained).expect("retained directory").count(),
            0
        );
        assert_eq!(
            fs::read(original.join("sentinel")).expect("replacement retained"),
            b"outside held enclosure"
        );
    }

    /// # Panics
    /// Panics if mapped cleanup follows a namespace-written runs symlink.
    /// ´test:unit:claude-cleanup-refuses-a-linked-runs-directory´
    #[test]
    fn claude_cleanup_refuses_a_linked_runs_directory() {
        let root = claude_fixture_root();
        let outside = claude_fixture_root();
        fs::create_dir(outside.path().join("worker")).expect("outside worker");
        let sentinel = outside.path().join("worker/sentinel");
        fs::write(&sentinel, b"outside worker").expect("sentinel");
        let inode = fs::metadata(&sentinel).expect("identity").ino();
        symlink(outside.path(), root.path().join("runs")).expect("namespace link");
        let error = claude_cleanup_fixture(root.path()).expect_err("linked runs must refuse");
        assert!(
            error
                .to_string()
                .contains("mapped fixture cleanup refused:")
        );
        assert!(
            error.to_string().contains("'runs'"),
            "cleanup stderr: {error}"
        );
        assert_eq!(
            fs::read(&sentinel).expect("outside retained"),
            b"outside worker"
        );
        assert_eq!(fs::metadata(&sentinel).expect("same inode").ino(), inode);
    }

    fn claude_cleanup_observation(probe: &Path, fixture: &ClaudeFixtureIdentity) {
        let record: Value =
            serde_json::from_slice(&fs::read(probe.join("supervisor")).expect("supervisor"))
                .expect("identity");
        let pid = u32::try_from(record["pid"].as_u64().expect("pid")).expect("u32 pid");
        let start = record["start"].as_u64().expect("start");
        let alive = crate::container_helper::process_alive(pid, start);
        if alive {
            let _ignored = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(i32::try_from(pid).expect("group")),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while crate::container_helper::process_alive(pid, start)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !crate::container_helper::process_alive(pid, start),
            "negative-control supervisor cleanup"
        );
        let _ignored = nix::sys::wait::waitpid(
            nix::unistd::Pid::from_raw(i32::try_from(pid).expect("supervisor")),
            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
        );
        assert!(
            claude_namespace_exited(Some(&fixture.path.join("namespace-init"))),
            "negative-control namespace cleanup"
        );
        let retained = claude_remove_retained_fixture(fixture);
        assert!(!alive, "fixture supervisor survived host unwind");
        assert!(!retained, "mapped fixture home survived wrapper cleanup");
    }

    fn claude_namespace_output(name: &str, stdout: &str) {
        if name == "claude_namespace_held_program_standin" {
            let record = stdout
                .lines()
                .find_map(|line| {
                    line.find("CLAUDE-STANDIN-PROGRAM ")
                        .map(|index| &line[index..])
                })
                .expect("stand-in digest record");
            writeln!(std::io::stdout().lock(), "{record}").expect("record fixture digest");
        }
    }

    fn claude_pid_namespace(name: &str) {
        let mut command = Command::new("/usr/bin/unshare");
        // Every PID fixture gets a private mount namespace, including a future
        // mounting case outside the transaction tests.
        command.args(["--mount", "--propagation", "private"]);
        command.env(
            "CLAUDE_PARENT_MOUNT_NAMESPACE",
            fs::read_link("/proc/self/ns/mnt").expect("parent mount namespace"),
        );
        let status = command
            .args(["--pid", "--fork", "--kill-child"])
            .arg(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                &format!("credential::tests::{name}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CLAUDE_NAMESPACE_INIT", "1")
            .status()
            .expect("fixture PID namespace");
        assert!(status.success(), "fixture PID namespace: {status}");
    }

    /// # Panics
    /// Panics if the wrapper watchdog leaves a separate-group descendant alive.
    /// ´test:unit:claude-namespace-watchdog-contains-detached-descendant´
    #[test]
    fn claude_namespace_watchdog_contains_detached_descendant() {
        if std::env::var_os("CLAUDE_WATCHDOG_DESCENDANT").is_some() {
            claude_watchdog_descendant();
        }
        if std::env::var_os("SUPERLOOP_CLAUDE_NAMESPACE_PROOF").is_some() {
            claude_namespace_run(
                "claude_namespace_watchdog_contains_detached_descendant",
                "WATCHDOG-UNREACHABLE",
                claude_watchdog_body,
                None,
                None,
            );
            return;
        }
        let root = claude_fixture_root();
        assert!(claude_namespace_run(
            "claude_namespace_watchdog_contains_detached_descendant",
            "WATCHDOG-UNREACHABLE",
            claude_watchdog_body,
            Some(root.path()),
            None,
        ));
        let record: Value = serde_json::from_slice(
            &fs::read(root.path().join("ready")).expect("descendant readiness"),
        )
        .expect("synthetic process identity");
        let pid = u32::try_from(record["pid"].as_u64().expect("pid")).expect("u32 pid");
        let start = record["start"].as_u64().expect("start");
        let cleanup = ClaudeWatchdogDescendant(pid, start);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while crate::container_helper::process_alive(pid, start)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let survived = crate::container_helper::process_alive(pid, start);
        drop(cleanup);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while crate::container_helper::process_alive(pid, start)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !crate::container_helper::process_alive(pid, start),
            "negative-control descendant cleanup"
        );
        assert!(
            !survived,
            "separate-group descendant survived the wrapper watchdog"
        );
    }

    struct ClaudeWatchdogDescendant(u32, u64);
    impl Drop for ClaudeWatchdogDescendant {
        fn drop(&mut self) {
            if crate::container_helper::process_alive(self.0, self.1) {
                let pid = i32::try_from(self.0).expect("fixture pid");
                let _ignored = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }

    fn claude_watchdog_body() {
        use std::os::unix::process::CommandExt as _;
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "credential::tests::claude_namespace_watchdog_contains_detached_descendant",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CLAUDE_WATCHDOG_DESCENDANT", "1")
            .process_group(0)
            .spawn()
            .expect("separate-group descendant");
        let status = child.wait().expect("descendant wait");
        panic!("watchdog descendant exited early: {status}");
    }

    fn claude_watchdog_descendant() -> ! {
        let root = PathBuf::from(std::env::var_os("CLAUDE_WATCHDOG_ROOT").expect("probe root"));
        assert_eq!(
            nix::unistd::getpgrp().as_raw().unsigned_abs(),
            std::process::id()
        );
        let (pid, start) = claude_host_identity();
        let record = serde_json::json!({"pid": pid, "start": start});
        fs::write(root.join("pending"), record.to_string()).expect("process record");
        fs::rename(root.join("pending"), root.join("ready")).expect("ready publication");
        // A host killed without unwinding leaves this descendant for at most two minutes.
        std::thread::sleep(Duration::from_secs(120));
        panic!("synthetic descendant outlived its 120-second bound");
    }

    fn claude_host_identity() -> (u32, u64) {
        // The retained host proc mount names the identity the host observer can check.
        let pid: u32 = fs::read_link("/proc/self")
            .expect("host proc identity")
            .to_str()
            .expect("numeric identity")
            .parse()
            .expect("pid");
        let start = crate::container_helper::process_start(pid).expect("process start");
        (pid, start)
    }

    struct ClaudeStandinWorker(PathBuf);
    impl Drop for ClaudeStandinWorker {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn claude_standin_host() -> (tempfile::TempDir, crate::container_entry::Bundle) {
        claude_standin_host_with_root(claude_fixture_root(), None)
    }

    fn claude_standin_host_with_root(
        root: tempfile::TempDir,
        podman: Option<&Path>,
    ) -> (tempfile::TempDir, crate::container_entry::Bundle) {
        let owner = root.path().join("owner");
        let runs = root.path().join("runs");
        for path in [&owner, &runs] {
            fs::create_dir(path).expect("fixture directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        fixture_claude(&owner, &claude_document(1_800_000_000_000));
        let config = owner.join(".config/loops");
        for (name, text) in [
            (
                "registry.toml",
                concat!(
                    "namespace='org.superloop-tools.loophome.registry'\n",
                    "version=[1,0,0]\n",
                    "loops=[{name='alpha',uid=64000,launch='dev/alpha'}]\n"
                ),
            ),
            (
                "allocations.toml",
                concat!(
                    "mail_uid=64001\n[alpha]\n",
                    "uids={base=64010,count=2}\n",
                    "mail_gids={base=64020,count=3}\n"
                ),
            ),
        ] {
            fs::write(config.join(name), text).expect("synthetic configuration");
            fs::set_permissions(config.join(name), fs::Permissions::from_mode(0o600))
                .expect("private configuration");
        }
        let bundle = podman.map_or_else(
            || crate::container_entry::fixture_claude_helper_bundle(&owner, &runs),
            |program| {
                crate::container_entry::fixture_claude_helper_bundle_with_podman(
                    &owner, &runs, program,
                )
            },
        );
        (root, bundle)
    }

    // Native true returns success without rotating the synthetic authority.
    // No vendor response or refresh behavior is emulated.
    fn claude_namespace_standin() {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;
        assert_eq!(owner_identity(), (0, 0));
        let root = PathBuf::from(std::env::var_os("CLAUDE_STANDIN_ROOT").expect("host root"));
        let owner = root.join("owner");
        let runs = root.join("runs");
        let source = std::env::var("CLAUDE_STANDIN_MANIFEST").expect("host manifest");
        let (_, mut anchors) = crate::container_entry::receive_for(
            &source,
            &std::io::stdin(),
            "container-helper",
            Some("alpha"),
        )
        .expect("production eight-role receiver");
        loop_home::anchor::transport::replace_stdin("container-helper").expect("close setup input");
        let _configuration = crate::container_entry::configuration(
            &owner,
            "alpha",
            "container-helper",
            anchors.pop().expect("configuration"),
        )
        .expect("held configuration");
        let (_runtime, programs) =
            crate::container_entry::take_support_programs(&mut anchors, BoxBackend::Claude)
                .expect("selected credential roles");
        let _home =
            crate::home::activate_private_launch(&owner, &anchors[0], &runs, &anchors[1], None, 0)
                .expect("received roots");
        let _programs = crate::container_entry::activate_program_map("container-helper", programs);
        let home = claude_sign_in_dir(&owner, "alpha");
        let run = claude_standin_worker(&runs);
        let _cleanup = ClaudeStandinWorker(run.clone());
        let mut digest = String::with_capacity(64);
        for byte in Sha256::digest(fs::read("/usr/bin/true").expect("public root-owned stand-in")) {
            write!(&mut digest, "{byte:02x}").expect("hex digest");
        }
        let custody = crate::container_helper::CredentialThreadCustody::capture_admitted(
            BoxBackend::Claude,
            &Gate,
        )
        .expect("production transfer");
        writeln!(
            std::io::stdout().lock(),
            "CLAUDE-STANDIN-PROGRAM sha256={digest}"
        )
        .expect("public fixture digest");
        std::thread::spawn(move || {
            let _custody = custody.activate().expect("authority thread activation");
            assert!(
                crate::container_entry::check(Path::new("/usr/bin/sha256sum"))
                    .expect("active credential map")
                    .is_err()
            );
            claude_standin_publication(&home, &run, &digest);
            let configuration = crate::runtime_entry::snapshot_configuration().expect("snapshot");
            let held = configuration
                .open_private_directory(Path::new("alpha/claude"))
                .expect("production configuration opener");
            with_claude_exercise_snapshot(&held, &home, 1_799_999_990, |_, projection, due| {
                assert!(due);
                assert_eq!(
                    fs::read(run.join(".claude/.credentials.json")).expect("worker"),
                    format!("{projection}\n").as_bytes()
                );
                Ok(())
            })
            .expect("held exercise read");
        })
        .join()
        .expect("namespace authority thread");
        assert_eq!(
            preflight(&owner, "alpha", BoxBackend::Claude)
                .expect_err("public gate remains closed")
                .kind,
            "backend-unavailable"
        );
    }

    fn claude_standin_worker(runs: &Path) -> PathBuf {
        let run = runs.join("worker");
        fs::create_dir(&run).expect("worker home");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o750)).expect("home mode");
        fs::create_dir(run.join(".claude")).expect("worker state");
        fs::set_permissions(run.join(".claude"), fs::Permissions::from_mode(0o700))
            .expect("state mode");
        nix::unistd::chown(
            &run.join(".claude"),
            Some(Uid::from_raw(3000)),
            Some(Gid::from_raw(3000)),
        )
        .expect("distinct worker");
        run
    }

    fn claude_standin_publication(home: &Path, run: &Path, digest: &str) {
        let refresh = || {
            let held = open_dir(home, 0, 0, 0o700)?;
            let error = lock_with(&held, FlockArg::LockExclusiveNonblock)
                .expect_err("owner lock stays held across program execution");
            assert_eq!(error.kind, "credential-lock-busy");
            claude_refresh_program(home, digest)
        };
        prepare_claude_run_at(home, run, 3000, 1_799_999_990, refresh, || {
            Ok(1_799_999_990_000)
        })
        .expect("real held print and publication");
        let path = run.join(".claude/.credentials.json");
        let bytes = fs::read(&path).expect("projection");
        let metadata = fs::metadata(&path).expect("worker identity");
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (3000, 3000, 0o600)
        );
        let projection: Value = serde_json::from_slice(&bytes).expect("projection JSON");
        assert!(projection.get("mcpOAuth").is_none());
        for field in ["refreshToken", "refreshTokenExpiresAt"] {
            assert!(projection["claudeAiOauth"].get(field).is_none());
        }
        let error = publish_claude_round_at(
            home,
            run,
            3000,
            1_799_999_991,
            || claude_refresh_program(home, &"0".repeat(64)),
            || Ok(1_799_999_991_000),
        )
        .expect_err("wrong digest during due round publication");
        assert_eq!(error.status, 2);
        assert_eq!(error.kind, "credential-program-pin");
        assert_eq!(
            error.detail,
            "held Claude program differs from the reviewed SHA-256"
        );
        assert_eq!(fs::read(&path).expect("wrong-pin retained bytes"), bytes);
        assert_eq!(
            fs::metadata(&path).expect("wrong-pin retained inode").ino(),
            metadata.ino()
        );
        let error = publish_claude_round_at(home, run, 3000, 1_800_000_000, refresh, || {
            Ok(1_800_000_000_000)
        })
        .expect_err("successful stand-in is not refreshed authority");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(
            error.detail,
            "Claude owner program left expired access authority"
        );
        assert_eq!(fs::read(&path).expect("retained bytes"), bytes);
        assert_eq!(
            fs::metadata(path).expect("retained identity").ino(),
            metadata.ino()
        );
    }

    fn claude_publication_root() -> PathBuf {
        PathBuf::from(
            std::env::var_os("CLAUDE_PUBLICATION_ROOT").expect("host-owned publication fixture"),
        )
    }

    /// # Panics
    /// Panics if the real provider and publisher violate custody in the mapped namespace.
    fn claude_namespace_publication() {
        assert_eq!(owner_identity(), (0, 0));
        let root = claude_publication_root();
        let owner_home = root.join("owner");
        let runs = root.join("runs");
        for path in [&owner_home, &runs] {
            fs::create_dir(path).expect("fixture directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let _custody = crate::home::activate_private_launch(
            &owner_home,
            &File::open(&owner_home).expect("owner"),
            &runs,
            &File::open(&runs).expect("runs"),
            None,
            0,
        )
        .expect("received namespace roots");
        let expiry = 1_800_000_000_u64;
        let home = fixture_claude(&owner_home, &claude_document(expiry * 1000));
        let run = runs.join("worker");
        fs::create_dir(&run).expect("worker home");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o750)).expect("home mode");
        let state = run.join(".claude");
        fs::create_dir(&state).expect("worker state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state mode");
        nix::unistd::chown(&state, Some(Uid::from_raw(3000)), Some(Gid::from_raw(3000)))
            .expect("distinct mapped worker");
        prepare_claude_run_at(
            &home,
            &run,
            3000,
            expiry - 3600,
            || panic!("current fixture authority must not refresh"),
            || Ok((expiry - 3600) * 1000),
        )
        .expect("mapped preparation");
        let path = state.join(".credentials.json");
        let before = fs::metadata(&path).expect("prepared worker");
        assert_eq!(
            (before.uid(), before.gid(), before.mode() & 0o777),
            (3000, 3000, 0o600)
        );
        let receipt = publish_claude_round_at(
            &home,
            &run,
            3000,
            expiry - 10,
            || claude_namespace_refresh(&home, expiry),
            || Ok((expiry - 9) * 1000),
        )
        .expect("mapped round publication");
        assert_eq!(receipt.as_object().expect("receipt").len(), 2);
        let bytes = fs::read(&path).expect("published worker");
        let metadata = fs::metadata(&path).expect("published identity");
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (3000, 3000, 0o600)
        );
        assert_ne!(metadata.ino(), before.ino());
        let held = open_dir(&home, 0, 0, 0o700).expect("held sign-in");
        with_claude_exercise_snapshot(&held, &home, expiry, |identity, projection, due| {
            assert!(!due);
            assert_ne!(identity["inode"], json!(metadata.ino()));
            assert_eq!(bytes, format!("{projection}\n").as_bytes());
            assert!(projection.get("mcpOAuth").is_none());
            assert!(projection["claudeAiOauth"].get("refreshToken").is_none());
            assert!(
                projection["claudeAiOauth"]
                    .get("refreshTokenExpiresAt")
                    .is_none()
            );
            Ok(())
        })
        .expect("mapped exercise observation");
        let error = publish_claude_round_at(
            &home,
            &run,
            3000,
            expiry + 3600,
            || Ok(()),
            || Ok((expiry + 3600) * 1000),
        )
        .expect_err("expired stand-in");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(
            error.detail,
            "Claude owner program left expired access authority"
        );
        assert_eq!(fs::read(&path).expect("unchanged worker"), bytes);
        assert_eq!(
            fs::metadata(&path).expect("unchanged inode").ino(),
            metadata.ino()
        );
        assert_eq!(
            preflight(&owner_home, "alpha", BoxBackend::Claude)
                .expect_err("public gate remains closed")
                .kind,
            "backend-unavailable"
        );
    }

    /// # Panics
    /// Panics if the synthetic owner replacement loses the production refresh lock.
    fn claude_namespace_refresh(home: &Path, expiry: u64) -> Result<(), LaneError> {
        let directory = open_dir(home, 0, 0, 0o700)?;
        let Err(error) = lock_with(&directory, FlockArg::LockExclusiveNonblock) else {
            panic!("owner refresh lost the lock");
        };
        assert_eq!(error.kind, "credential-lock-busy");
        // Stand-in for the owner's program; no vendor program or live sign-in is used.
        let mut next = claude_document((expiry + 3600) * 1000);
        next["claudeAiOauth"]["accessToken"] = json!("B".repeat(108));
        let staged = home.join(".synthetic-replacement");
        fs::write(&staged, next.to_string()).expect("synthetic replacement");
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).expect("source mode");
        fs::rename(staged, home.join(".credentials.json")).expect("owner publication");
        Ok(())
    }

    fn fixture_claude(home: &Path, document: &Value) -> PathBuf {
        fixture_sign_in(home, &source(1_900_000_000, "unused-codex"));
        let dir = claude_sign_in_dir(home, "alpha");
        fs::create_dir_all(&dir).expect("Claude fixture home");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("private home");
        let path = dir.join(".credentials.json");
        fs::write(&path, document.to_string()).expect("synthetic Claude source");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private source");
        dir
    }

    /// # Panics
    /// Panics only if read mode starts the synthetic program or fails to publish current access authority.
    /// ´test:unit:claude-reader-mode-never-spawns-the-program´
    #[test]
    fn claude_reader_mode_never_spawns_the_program() {
        let fixture = claude_fixture_root();
        let home = fixture_claude(fixture.path(), &claude_document(1_800_000_000_000));
        let run = fixture.path().join("reader-run");
        fs::create_dir_all(run.join(".claude")).expect("worker state");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("run mode");
        fs::set_permissions(run.join(".claude"), fs::Permissions::from_mode(0o700))
            .expect("state mode");
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            admitted_claude_mode(&home).expect("default read mode"),
            ClaudeMode::Read
        );
        with_claude_authority_mode(
            ClaudeMode::Read,
            &home,
            1_700_000_000,
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || Ok(1_700_000_000_000),
            |source| write_claude_run(&run, owner_identity().0, source),
        )
        .expect("read-only publication");
        assert_eq!(calls.get(), 0);
        assert!(run.join(".claude/.credentials.json").is_file());
    }

    /// # Panics
    /// Panics only if due or expired access authority reaches publication or starts a refresher.
    /// ´test:unit:claude-reader-refuses-due-and-expired-authority´
    #[test]
    fn claude_reader_refuses_due_and_expired_authority() {
        let fixture = claude_fixture_root();
        let home = fixture_claude(fixture.path(), &claude_document(1_800_000_000_000));
        for (now, expected) in [
            (1_799_999_500, "credential-read-due"),
            (1_800_000_000, "credential-read-expired"),
        ] {
            let error = with_claude_authority_mode(
                ClaudeMode::Read,
                &home,
                now,
                || panic!("reader must not start vendor program"),
                || Ok(now * 1000),
                |_| -> Result<(), LaneError> { panic!("reader must not publish due authority") },
            )
            .expect_err("read refusal");
            assert_eq!(error.kind, expected);
        }
        let crossing = with_claude_authority_mode(
            ClaudeMode::Read,
            &home,
            1_799_999_399,
            || panic!("reader must not start vendor program"),
            || Ok(1_799_999_400_000),
            |_| -> Result<(), LaneError> { panic!("due authority must not publish") },
        )
        .expect_err("publication crossed the due boundary");
        assert_eq!(crossing.kind, "credential-read-due");
    }

    /// # Panics
    /// Panics if a refused Claude read loses expiry already measured from the source.
    /// ´test:unit:claude-read-refusal-evidence-keeps-measured-expiry´
    #[test]
    fn claude_read_refusal_evidence_keeps_measured_expiry() {
        let fixture = claude_fixture_root();
        let expires = 1_800_000_000_u64;
        let home = fixture_claude(fixture.path(), &claude_document(expires * 1000));
        let mut published = BTreeMap::new();
        for (now, kind) in [
            (expires - 300, "credential-read-due"),
            (expires, "credential-read-expired"),
        ] {
            let result = refresh_claude_live_admitted_at(
                &home,
                "alpha",
                &fixture.path().join("runs"),
                now,
                &mut published,
                (
                    ClaudeMode::Read,
                    || panic!("reader must not start the program"),
                    || Ok(now * 1000),
                    &Gate,
                ),
            );
            let report = result.as_ref().expect("measured refusal report");
            assert_eq!(
                report.authority_failure.as_ref().expect("refusal").kind,
                kind
            );
            let evidence =
                evidence_for_check(&result, true, BoxBackend::Claude).expect("periodic evidence");
            assert_eq!(evidence["expires_unix"], expires);
            assert_eq!(evidence["refresh_due_unix"], expires - 600);
            assert_eq!(evidence["kind"], kind);
        }
    }

    /// # Panics
    /// Panics only if an owner cutover request can reach refresh before the carrier gate exists.
    /// ´test:unit:claude-cutover-mark-refuses-before-carrier-gate´
    #[test]
    fn claude_cutover_mark_refuses_before_carrier_gate() {
        let fixture = claude_fixture_root();
        let home = fixture_claude(fixture.path(), &claude_document(1_800_000_000_000));
        let path = home.join(".boxed-refresh-mode");
        fs::write(&path, b"refresh\n").expect("owner cutover mark");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("marker mode");
        assert_eq!(
            claude_mode(&home).expect("parsed mark"),
            ClaudeMode::Refresh
        );
        assert_eq!(
            admitted_claude_mode(&home)
                .expect_err("carrier gate absent")
                .kind,
            "credential-cutover-gate"
        );
    }

    /// # Panics
    /// Panics only if the synthetic structural fixture leaks refresh authority or host state.
    /// ´test:unit:claude-worker-encoding-excludes-owner-authority´
    #[test]
    fn claude_worker_encoding_excludes_owner_authority() {
        let document = claude_document(1_800_000_000_001);
        let source = ClaudeSource::parse(&document).expect("recorded structural shape");
        let encoded = source.worker_file();
        let worker: Value = serde_json::from_slice(&encoded).expect("worker JSON");
        assert_eq!(worker.as_object().expect("object").len(), 1);
        assert_eq!(
            ClaudeSource::parse(&worker)
                .err()
                .expect("worker is not owner authority")
                .kind,
            "credential-sign-in"
        );
        let oauth = worker["claudeAiOauth"].as_object().expect("OAuth object");
        assert_eq!(oauth.len(), 6);
        assert!(!oauth.contains_key("refreshToken"));
        assert!(!oauth.contains_key("refreshTokenExpiresAt"));
        for field in [
            "accessToken",
            "expiresAt",
            "scopes",
            "subscriptionType",
            "subscriptionTypeSource",
            "rateLimitTier",
        ] {
            assert_eq!(oauth[field], document["claudeAiOauth"][field]);
        }
        assert_eq!(document["claudeAiOauth"]["refreshToken"], "R".repeat(108));
        assert!(!source.needs_refresh(1_799_999_400));
        assert!(source.needs_refresh(1_799_999_401));
        assert!(source.needs_refresh(u64::MAX));
    }

    /// # Panics
    /// Panics only if malformed owner inputs pass validation or appear in diagnostics.
    /// ´test:unit:claude-owner-schema-refuses-malformed-fields´
    #[test]
    fn claude_owner_schema_refuses_malformed_fields() {
        for (field, value) in [
            ("accessToken", json!("A".repeat(107))),
            ("refreshToken", json!("\n".repeat(108))),
            ("accessToken", json!("é".repeat(54))),
            ("expiresAt", json!(1_800_000_000)),
            ("expiresAt", json!("1800000000000")),
            ("expiresAt", json!(1_800_000_000_000.5)),
            ("refreshTokenExpiresAt", json!(-1)),
            ("scopes", json!([])),
            ("scopes", json!([false])),
            ("subscriptionType", json!(null)),
            ("subscriptionTypeSource", json!("\u{7f}")),
            ("rateLimitTier", json!("x".repeat(257))),
        ] {
            let mut document = claude_document(1_800_000_000_000);
            document["claudeAiOauth"][field] = value;
            let error = ClaudeSource::parse(&document)
                .err()
                .expect("malformed refusal");
            assert_eq!(error.kind, "credential-sign-in");
            assert!(!error.detail.contains(&"A".repeat(108)));
            assert!(!error.detail.contains(&"R".repeat(108)));
        }
        let mut document = claude_document(1_800_000_000_000);
        document["claudeAiOauth"]["futureAuthority"] = json!(true);
        assert!(ClaudeSource::parse(&document).is_err());
        assert!(ClaudeSource::parse(&json!({})).is_err());
    }

    /// # Panics
    /// Panics only if the provider fails to adopt its owner program's synthetic replacement.
    /// ´test:unit:claude-provider-adopts-owner-program-publication´
    #[test]
    fn claude_provider_adopts_owner_program_publication() {
        let fixture = claude_fixture_root();
        let old = claude_document(1_800_000_000_000);
        let home = fixture_claude(fixture.path(), &old);
        let mut next = claude_document(1_800_000_003_000);
        next["claudeAiOauth"]["accessToken"] = json!("B".repeat(108));
        next["mcpOAuth"]["fixture-plugin"]["hostOnly"] = json!(true);
        let owner_bytes = next.to_string();
        let calls = std::cell::Cell::new(0);
        let provider = ClaudeOwnerProvider {
            home: &home,
            refresh_program: || {
                calls.set(calls.get() + 1);
                let staged = home.join(".owner-login.tmp");
                fs::write(&staged, &owner_bytes).expect("owner program output");
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))
                    .expect("owner program mode");
                fs::rename(staged, home.join(".credentials.json"))
                    .expect("owner program publication");
                Ok(())
            },
        };
        let directory =
            open_dir(&home, owner_identity().0, owner_identity().0, 0o700).expect("home");
        let refresh_lock = lock_with(&directory, FlockArg::LockExclusive).expect("refresh lock");
        let result = refresh_provider(&provider, 1_800_000_000, || {
            panic!("helper must not publish owner source")
        })
        .expect("provider refresh");
        assert_eq!(calls.get(), 1);
        assert_eq!(
            result.oauth["accessToken"],
            next["claudeAiOauth"]["accessToken"]
        );
        assert_eq!(
            fs::read_to_string(home.join(".credentials.json")).expect("owner source"),
            owner_bytes
        );
        let run = fixture.path().join("run");
        fs::create_dir_all(run.join(".claude")).expect("worker home");
        for path in [&run, &run.join(".claude")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("worker home mode");
        }
        write_claude_run(&run, owner_identity().0, &result).expect("worker publication");
        let worker_path = run.join(".claude/.credentials.json");
        assert_eq!(
            fs::read(&worker_path).expect("worker bytes"),
            result.worker_file()
        );
        assert_eq!(
            fs::metadata(&worker_path)
                .expect("worker metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(refresh_lock);
        prepare_claude_run_at(
            &home,
            &run,
            owner_identity().0,
            1_700_000_000,
            || panic!("current authority must not refresh"),
            || Ok(1_700_000_000_000),
        )
        .expect("production preparation with current owner authority");
        assert_eq!(
            fs::read(worker_path).expect("prepared worker bytes"),
            result.worker_file()
        );
        assert_eq!(
            fs::read_to_string(home.join(".credentials.json")).expect("owner source preserved"),
            owner_bytes
        );
    }

    /// # Panics
    /// Panics only if unsafe source custody is accepted or a refusal changes authority.
    /// ´test:unit:claude-provider-refuses-unsafe-source-and-refresh´
    #[test]
    fn claude_provider_refuses_unsafe_source_and_refresh() {
        let fixture = claude_fixture_root();
        let document = claude_document(1_800_000_000_000);
        let home = fixture_claude(fixture.path(), &document);
        let provider = ClaudeOwnerProvider {
            home: &home,
            refresh_program: || Err(failure("credential-refresh", "synthetic refusal")),
        };
        assert_eq!(
            refresh_provider(&provider, 1_800_000_000, || {})
                .err()
                .expect("refresh refusal")
                .kind,
            "credential-refresh"
        );
        assert_eq!(
            fs::read_to_string(home.join(".credentials.json")).expect("unchanged source"),
            document.to_string()
        );
        let source =
            refresh_provider(&provider, 1_700_000_000, || {}).expect("not due, no program call");
        assert_eq!(source.expires_ms, 1_800_000_000_000);
        let path = home.join(".credentials.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("bad mode");
        assert_eq!(
            read_claude_source(&home).err().expect("mode refusal").kind,
            "credential-sign-in"
        );
        fs::remove_file(&path).expect("remove fixture");
        std::os::unix::fs::symlink(home.join("absent"), &path).expect("source symlink");
        assert_eq!(
            read_claude_source(&home)
                .err()
                .expect("symlink refusal")
                .kind,
            "credential-sign-in"
        );
    }

    fn encoded(bytes: &[u8]) -> String {
        const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::new();
        for part in bytes.chunks(3) {
            let first = part[0];
            result.push(char::from(DIGITS[usize::from(first >> 2)]));
            let second = part.get(1).copied().unwrap_or_default();
            result.push(char::from(
                DIGITS[usize::from(((first & 3) << 4) | (second >> 4))],
            ));
            if part.len() > 1 {
                let third = part.get(2).copied().unwrap_or_default();
                result.push(char::from(
                    DIGITS[usize::from(((second & 15) << 2) | (third >> 6))],
                ));
                if part.len() > 2 {
                    result.push(char::from(DIGITS[usize::from(third & 63)]));
                }
            }
        }
        result
    }

    fn token(exp: u64) -> String {
        format!(
            "header.{}.signature",
            encoded(json!({"exp":exp}).to_string().as_bytes())
        )
    }

    fn source(exp: u64, label: &str) -> Value {
        json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": token(exp),
                "access_token": token(exp),
                "refresh_token": format!("fixture-refresh-{label}"),
                "account_id": "fixture-account"
            },
            "last_refresh": "2026-10-05T00:00:00Z"
        })
    }

    fn fixture_sign_in(home: &Path, document: &Value) {
        let dir = sign_in_dir(home, "alpha");
        fs::create_dir_all(&dir).expect("synthetic sign-in directory");
        for path in [
            home.to_path_buf(),
            home.join(".config"),
            home.join(".config/loops"),
            home.join(".config/loops/alpha"),
            home.join(".config/loops/alpha/lanes"),
            dir.clone(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("owner-only directory");
        }
        let file = dir.join("auth.json");
        fs::write(&file, document.to_string()).expect("synthetic sign-in");
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).expect("owner-only file");
    }

    fn replace_sign_in(home: &Path, document: &Value) {
        let directory = sign_in_dir(home, "alpha");
        let staged = directory.join(".owner-login.tmp");
        fs::write(&staged, document.to_string()).expect("synthetic owner login");
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))
            .expect("private owner login");
        fs::rename(staged, directory.join("auth.json")).expect("owner login replaces source");
    }

    /// # Panics
    /// Panics only if synthetic round publication or its recorded evidence differs.
    /// ´test:unit:round-launch-republishes-owner-login-before-agent-start´
    #[test]
    fn round_launch_republishes_owner_login_before_agent_start() {
        use std::os::unix::fs::MetadataExt as _;
        let fixture = fixture_root();
        let home = fixture.path();
        let run_home = home.join("run-R");
        fs::create_dir(&run_home).expect("run home");
        fs::set_permissions(&run_home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::create_dir(run_home.join(".codex")).expect("Codex home");
        fs::set_permissions(run_home.join(".codex"), fs::Permissions::from_mode(0o700))
            .expect("Codex home mode");
        let initial = source(1_900_000_000, "initial");
        let replacement = source(1_900_000_100, "replacement");
        fixture_sign_in(home, &initial);
        let source_path = sign_in_dir(home, "alpha").join("auth.json");
        let first_inode = fs::metadata(&source_path)
            .expect("synthetic metadata")
            .ino();
        let mut record = json!({"worker_uid":Uid::effective().as_raw(),"plan":{"backend":"codex","home":run_home},"active_round":"dispatch","rounds":[{"step":"dispatch"}]});
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        crate::container_helper::publish_round_credential_admitted(
            home,
            "alpha",
            &mut record,
            &Gate,
        )
        .expect("first round barrier");
        let first =
            crate::launch::report::credential_publication(&record).expect("first report evidence");
        let published: Value = serde_json::from_slice(
            &fs::read(run_home.join(".codex/auth.json")).expect("synthetic published token"),
        )
        .expect("token JSON");
        assert_eq!(
            published["tokens"]["access_token"],
            initial["tokens"]["access_token"]
        );
        assert_eq!(first["source_inode"], first_inode);
        assert!(u128::from(first["published_unix_ns"].as_u64().expect("instant")) >= before);
        replace_sign_in(home, &replacement);
        let second_inode = fs::metadata(&source_path)
            .expect("replacement metadata")
            .ino();
        assert_ne!(first_inode, second_inode);
        record["active_round"] = json!("resume");
        record["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"resume"}));
        crate::container_helper::publish_round_credential_admitted(
            home,
            "alpha",
            &mut record,
            &Gate,
        )
        .expect("resumed round barrier");
        let second =
            crate::launch::report::credential_publication(&record).expect("second report evidence");
        let published: Value = serde_json::from_slice(
            &fs::read(run_home.join(".codex/auth.json")).expect("synthetic republished token"),
        )
        .expect("token JSON");
        assert_eq!(
            published["tokens"]["access_token"],
            replacement["tokens"]["access_token"]
        );
        assert_eq!(published["tokens"]["refresh_token"], "");
        assert_eq!(second["source_inode"], second_inode);
        assert!(second["published_unix_ns"].as_u64() >= first["published_unix_ns"].as_u64());
        assert!(
            u128::from(second["published_unix_ns"].as_u64().expect("instant"))
                <= SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
        );
        assert_eq!(record["rounds"][0]["credential_publication"], first);
        assert_eq!(
            fs::metadata(run_home.join(".codex/auth.json"))
                .expect("token mode")
                .mode()
                & 0o777,
            0o600
        );
    }

    pub(super) fn fixture_endpoint(
        status: &str,
        response: Value,
    ) -> (String, std::thread::JoinHandle<Value>) {
        fixture_endpoint_with(status, response, || {})
    }

    fn fixture_endpoint_with(
        status: &str,
        response: Value,
        on_request: impl FnOnce() + Send + 'static,
    ) -> (String, std::thread::JoinHandle<Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture endpoint");
        let url = format!("http://{}/token", listener.local_addr().expect("address"));
        let status = status.to_owned();
        let handle = std::thread::spawn(move || {
            let (mut client, _) = listener.accept().expect("fixture request");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bounded fixture");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            let body_start = loop {
                let count = client.read(&mut chunk).expect("read fixture request");
                assert!(count > 0, "request ended before headers");
                request.extend_from_slice(&chunk[..count]);
                if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
                assert!(request.len() < 8192, "fixture headers exceeded bound");
            };
            let headers = String::from_utf8_lossy(&request[..body_start]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .expect("content length");
            while request.len() - body_start < length {
                let count = client.read(&mut chunk).expect("read fixture body");
                assert!(count > 0, "request body ended early");
                request.extend_from_slice(&chunk[..count]);
            }
            let received: Value = serde_json::from_slice(&request[body_start..body_start + length])
                .expect("JSON request");
            on_request();
            let body = response.to_string();
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            client.write_all(reply.as_bytes()).expect("fixture reply");
            received
        });
        (url, handle)
    }

    fn fixture_run(runs: &Path, run: &str, uid: u32) {
        fs::set_permissions(runs, fs::Permissions::from_mode(0o700)).expect("protected runs root");
        fs::create_dir(runs.join(run)).expect("synthetic live run");
        let pid = std::process::id();
        let record = json!({
            "schema": 1,
            "phase": "started",
            "loop": "alpha",
            "run": run,
            "worker_uid": uid,
            "helper_pid": pid,
            "helper_start": crate::container_helper::process_start(pid).expect("fixture process start"),
            "plan": {"backend":"codex","home": runs.join(format!("home-{run}"))}
        });
        crate::launch::publish_reservation(&crate::launch::reservation_path(runs, run), &record)
            .expect("synthetic reservation");
    }

    /// ´test:unit:credential-write-run-walks-ancestors-at-owner-and-checks-leaf-at-worker´
    #[test]
    fn credential_write_run_walks_ancestors_at_owner_and_checks_leaf_at_worker() {
        let temp = fixture_root();
        let run_home = temp.path().join("run-home");
        fs::create_dir(&run_home).expect("owner run home");
        fs::set_permissions(&run_home, fs::Permissions::from_mode(0o700))
            .expect("private run home");
        let codex = run_home.join(".codex");
        fs::create_dir(&codex).expect("caller-owned Codex home");
        fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).expect("private Codex home");
        let worker = Uid::effective()
            .as_raw()
            .checked_add(1)
            .expect("distinct fixture worker uid");
        let source = Source::parse(source(1_900_000_000, "initial")).expect("synthetic source");
        let error = write_run(&run_home, worker, &source)
            .expect_err("caller-owned leaf cannot stand in for worker-owned leaf");
        assert_eq!(error.kind, "credential-path");
        assert!(error.detail.contains(&codex.display().to_string()));
        assert!(error.detail.contains(&format!("expected uid {worker}")));
        assert!(!error.detail.contains("verified prefix"));
    }

    /// ´test:unit:credential-missing-or-invalid-sign-in-refuses-before-run-home´
    #[test]
    fn credential_missing_or_invalid_sign_in_refuses_before_run_home() {
        let temp = fixture_root();
        fixture_sign_in(temp.path(), &source(1_900_000_000, "initial"));
        fs::remove_file(sign_in_dir(temp.path(), "alpha").join("auth.json"))
            .expect("remove synthetic sign-in");
        let missing = preflight_at(temp.path(), "alpha", "http://127.0.0.1:1", 1_800_000_000)
            .expect_err("missing sign-in");
        assert_eq!(missing.kind, "credential-sign-in");
        fs::write(sign_in_dir(temp.path(), "alpha").join("auth.json"), b"{")
            .expect("malformed synthetic sign-in");
        fs::set_permissions(
            sign_in_dir(temp.path(), "alpha").join("auth.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private synthetic sign-in");
        let invalid = preflight_at(temp.path(), "alpha", "http://127.0.0.1:1", 1_800_000_000)
            .expect_err("invalid sign-in");
        assert_eq!(invalid.kind, "credential-sign-in");
    }

    /// ´test:unit:credential-mid-run-refresh-publishes-before-margin-and-reloads-on-rejection´
    #[test]
    fn credential_mid_run_refresh_publishes_before_margin_and_reloads_on_rejection() {
        let temp = fixture_root();
        let now = 1_800_000_000;
        fixture_sign_in(temp.path(), &source(now + 540, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        let file = runs.join("worker-auth.json");
        let (endpoint, server) = fixture_endpoint(
            "200 OK",
            json!({"id_token":token(now + 3600),"access_token":token(now + 3600),"refresh_token":"fixture-rotated"}),
        );
        let mut published = BTreeMap::new();
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            &endpoint,
            now,
            &mut published,
            |_home, _uid, source| {
                fs::write(&file, source.worker_file())
                    .map_err(|error| failure("fixture", error.to_string()))
            },
        )
        .expect("refresh and publish");
        let request = server.join().expect("endpoint joined");
        assert_eq!(request["grant_type"], "refresh_token");
        assert_eq!(request["client_id"], CLIENT_ID);
        let reloaded: Value = serde_json::from_slice(&fs::read(file).expect("published file"))
            .expect("worker reload");
        assert_eq!(reloaded["auth_mode"], "chatgptAuthTokens");
        assert_eq!(reloaded["tokens"]["refresh_token"], "");
        assert_eq!(reloaded["tokens"]["access_token"], token(now + 3600));
    }

    /// ´test:unit:boxed-backend-codex-refresh-skips-claude-run´
    #[test]
    fn boxed_backend_codex_refresh_skips_claude_run() {
        let temp = fixture_root();
        let now = 1_800_000_000;
        fixture_sign_in(temp.path(), &source(now + 3600, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "codex-run", 3001);
        fixture_run(&runs, "claude-run", 3002);
        let path = crate::launch::reservation_path(&runs, "claude-run");
        let mut record = crate::launch::read_reservation(&path)
            .expect("read")
            .expect("record");
        record["plan"]["backend"] = json!("claude");
        crate::launch::publish_reservation(&path, &record).expect("Claude fixture");
        let mut recipients = Vec::new();
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            now,
            &mut BTreeMap::new(),
            |_home, uid, _source| {
                recipients.push(uid);
                Ok(())
            },
        )
        .expect("valid source needs no refresh request");
        assert_eq!(recipients, [3001]);
    }

    fn claude_live_fixture(runs: &Path, name: &str) -> PathBuf {
        fixture_run(runs, name, owner_identity().0);
        let path = crate::launch::reservation_path(runs, name);
        let mut record = crate::launch::read_reservation(&path)
            .expect("read")
            .expect("record");
        record["plan"]["backend"] = json!("claude");
        crate::launch::publish_reservation(&path, &record).expect("Claude reservation");
        let home = PathBuf::from(record["plan"]["home"].as_str().expect("home"));
        fs::create_dir_all(home.join(".claude")).expect("worker leaf");
        for path in [&home, &home.join(".claude")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("worker mode");
        }
        home
    }

    /// # Panics
    /// Panics if periodic publication crosses vendors, repeats unchanged writes or loses retries.
    /// ´test:unit:claude-live-refresh-selects-live-homes-and-retries-publication´
    #[test]
    fn claude_live_refresh_selects_live_homes_and_retries_publication() {
        let root = claude_fixture_root();
        let now = 1_800_000_000;
        let home = fixture_claude(root.path(), &claude_document((now + 500) * 1000));
        let runs = root.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        let first = claude_live_fixture(&runs, "claude-first");
        let second = claude_live_fixture(&runs, "claude-second");
        fixture_run(&runs, "codex-control", owner_identity().0);
        let retired = claude_live_fixture(&runs, "claude-retired");
        let path = crate::launch::reservation_path(&runs, "claude-retired");
        let mut record = crate::launch::read_reservation(&path)
            .expect("read")
            .expect("record");
        record["phase"] = json!("retired");
        crate::launch::publish_reservation(&path, &record).expect("retirement");
        fs::set_permissions(second.join(".claude"), fs::Permissions::from_mode(0o755))
            .expect("bad mode");
        let calls = std::cell::Cell::new(0);
        let mut cache = BTreeMap::new();
        let report = refresh_claude_live_at(
            &home,
            "alpha",
            &runs,
            now,
            &mut cache,
            || {
                calls.set(calls.get() + 1);
                let dir = open_dir(&home, owner_identity().0, owner_identity().0, 0o700)?;
                assert!(lock_with(&dir, FlockArg::LockExclusiveNonblock).is_err());
                let mut next = claude_document((now + 3600) * 1000);
                next["claudeAiOauth"]["accessToken"] = json!("N".repeat(108));
                fs::write(home.join(".credentials.json"), next.to_string())
                    .expect("synthetic owner refresh");
                Ok(())
            },
            || Ok(now * 1000),
        )
        .expect("partial publication");
        assert_eq!(calls.get(), 1);
        assert!(report.changed);
        assert_eq!(report.refusals.len(), 1);
        assert_eq!(report.refusals[0]["run"], "claude-second");
        assert_eq!(cache.len(), 1);
        let bytes = fs::read(first.join(".claude/.credentials.json")).expect("first worker");
        let worker: Value = serde_json::from_slice(&bytes).expect("encoding");
        assert_eq!(worker.as_object().expect("object").len(), 1);
        assert_eq!(worker["claudeAiOauth"].as_object().expect("OAuth").len(), 6);
        assert_eq!(worker["claudeAiOauth"]["accessToken"], "N".repeat(108));
        assert!(!retired.join(".claude/.credentials.json").exists());
        assert!(!runs.join("home-codex-control").exists());
        fs::set_permissions(second.join(".claude"), fs::Permissions::from_mode(0o700))
            .expect("repair mode");
        let prior = fs::metadata(first.join(".claude/.credentials.json"))
            .expect("first inode")
            .ino();
        let report = refresh_claude_live_at(
            &home,
            "alpha",
            &runs,
            now,
            &mut cache,
            || panic!("current authority must not refresh"),
            || Ok(now * 1000),
        )
        .expect("retry");
        assert!(report.changed);
        assert_eq!(report.refusals, [] as [Value; 0]);
        assert_eq!(cache.len(), 2);
        assert_eq!(
            fs::read(second.join(".claude/.credentials.json")).expect("retry worker"),
            bytes
        );
        assert_eq!(
            fs::metadata(first.join(".claude/.credentials.json"))
                .expect("retained inode")
                .ino(),
            prior
        );
        let report = refresh_claude_live_at(
            &home,
            "alpha",
            &runs,
            now,
            &mut cache,
            || panic!("current authority"),
            || Ok(now * 1000),
        )
        .expect("unchanged");
        assert!(!report.changed);
    }

    /// # Panics
    /// Panics if unrotated authority hides repeated owner calls or crosses expiry.
    /// ´test:unit:claude-periodic-unrotated-authority-keeps-the-refresh-window-visible´
    #[test]
    fn claude_periodic_unrotated_authority_keeps_the_refresh_window_visible() {
        let root = claude_fixture_root();
        let now = 1_800_000_000;
        let expiry = now + REFRESH_AHEAD.as_secs();
        let home = fixture_claude(root.path(), &claude_document(expiry * 1000));
        let runs = root.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        let worker = claude_live_fixture(&runs, "claude-live").join(".claude/.credentials.json");
        let calls = std::cell::Cell::new(0);
        let mut helpers = [BTreeMap::new(), BTreeMap::new()];
        // Stand-in calls leave the synthetic token unchanged. Injected samples
        // model two helpers; no vendor margin or real elapsed cadence is measured.
        for tick in 0..20 {
            let sampled = now + tick * 30;
            for published in &mut helpers {
                let report = refresh_claude_live_at(
                    &home,
                    "alpha",
                    &runs,
                    sampled,
                    published,
                    || {
                        let owner = owner_identity().0;
                        let directory = open_dir(&home, owner, owner, 0o700).expect("owner home");
                        assert!(lock_with(&directory, FlockArg::LockExclusiveNonblock).is_err());
                        calls.set(calls.get() + 1);
                        Ok(())
                    },
                    || Ok(sampled * 1000),
                )
                .expect("unrotated but unexpired authority");
                assert_eq!(report.expires_unix, expiry);
                assert_eq!(report.changed, tick == 0);
            }
        }
        assert_eq!(calls.get(), 40);
        let bytes = fs::read(&worker).expect("prior worker");
        let inode = fs::metadata(&worker).expect("prior inode").ino();
        let error = refresh_claude_live_at(
            &home,
            "alpha",
            &runs,
            expiry,
            &mut helpers[0],
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            || Ok(expiry * 1000),
        )
        .expect_err("expired authority cannot be published");
        assert_eq!(error.kind, "credential-refresh");
        assert_eq!(calls.get(), 41);
        assert_eq!(fs::read(&worker).expect("unchanged bytes"), bytes);
        assert_eq!(fs::metadata(&worker).expect("unchanged inode").ino(), inode);
    }

    /// # Panics
    /// Panics if failed or expired owner refresh publishes any worker or cache entry.
    /// ´test:unit:claude-live-refresh-refusal-preserves-workers´
    #[test]
    fn claude_live_refresh_refusal_preserves_workers() {
        let root = claude_fixture_root();
        let now = 1_800_000_000;
        let home = fixture_claude(root.path(), &claude_document(now * 1000));
        let runs = root.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        let worker = claude_live_fixture(&runs, "claude-live").join(".claude/.credentials.json");
        fs::write(&worker, b"synthetic prior worker").expect("prior file");
        let inode = fs::metadata(&worker).expect("inode").ino();
        let mut cache = BTreeMap::new();
        for refuse in [true, false] {
            let error = refresh_claude_live_at(
                &home,
                "alpha",
                &runs,
                now,
                &mut cache,
                || {
                    if refuse {
                        Err(failure("credential-refresh", "synthetic refusal"))
                    } else {
                        Ok(())
                    }
                },
                || Ok(now * 1000),
            )
            .expect_err("owner refusal or expired result");
            assert_eq!(error.kind, "credential-refresh");
            assert!(cache.is_empty());
            assert_eq!(
                fs::read(&worker).expect("prior bytes"),
                b"synthetic prior worker"
            );
            assert_eq!(fs::metadata(&worker).expect("prior inode").ino(), inode);
        }
        let absent = root.path().join("absent-owner");
        assert_eq!(
            refresh_live_admitted(
                &absent,
                "alpha",
                &runs,
                &mut cache,
                BoxBackend::Claude,
                AUTH_ENDPOINT,
                &Gate
            )
            .expect_err("closed gate")
            .kind,
            "backend-unavailable"
        );
        assert!(!absent.exists());
    }

    /// # Panics
    /// Panics if either evidence boundary accepts mixed schemas or a foreign backend.
    /// ´test:unit:credential-evidence-refuses-cross-schema-provider-fields´
    #[test]
    fn credential_evidence_refuses_cross_schema_provider_fields() {
        let root = claude_fixture_root();
        let runs = root.path().join("runs");
        let driver = runs.join("pilot");
        fs::create_dir_all(&driver).expect("driver");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected path");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("private evidence");
        let file = protected.join("credential-refresh.json");
        let owner = owner_identity().0;
        let held = open_dir(&runs, owner, owner, 0o700).expect("held runs");
        for (backend, field, value) in [
            (BoxBackend::Codex, "backend", Value::Null),
            (BoxBackend::Codex, "backend", json!("codex")),
            (BoxBackend::Codex, "provider", Value::Null),
            (
                BoxBackend::Codex,
                "provider",
                json!({"kind":"owner-program"}),
            ),
            (BoxBackend::Claude, "backend", json!("codex")),
            (BoxBackend::Claude, "backend", json!("unknown")),
            (BoxBackend::Claude, "backend", Value::Null),
        ] {
            let valid = evidence_for_check(&Ok(fixture_report(1_900_000_000)), true, backend)
                .expect("valid evidence");
            publish_evidence(&driver, &valid).expect("valid writer control");
            assert_eq!(
                read_evidence(&held, "pilot", owner).expect("valid reader control"),
                Some(EvidenceObservation::Current(valid.clone()))
            );
            let bytes = fs::read(&file).expect("prior evidence");
            let inode = fs::metadata(&file).expect("prior identity").ino();
            let mut invalid = valid;
            invalid[field] = value;
            let error = publish_evidence(&driver, &invalid).expect_err("mixed provider writer");
            assert_eq!(error.kind, "credential-evidence");
            assert_eq!(error.detail, "schema, provider or state is invalid");
            assert_eq!(fs::read(&file).expect("evidence retained"), bytes);
            assert_eq!(fs::metadata(&file).expect("identity retained").ino(), inode);
            fs::write(&file, invalid.to_string()).expect("synthetic invalid persisted evidence");
            let error = read_evidence(&held, "pilot", owner).expect_err("mixed provider reader");
            assert_eq!(error.kind, "credential-evidence");
            assert_eq!(error.detail, "credential evidence envelope is invalid");
        }
    }

    /// # Panics
    /// Panics if either backend's credential evidence changes from its pinned schema bytes.
    /// ´test:unit:credential-evidence-schemas-are-byte-pinned´
    #[test]
    fn credential_evidence_schemas_are_byte_pinned() {
        let report = Ok(fixture_report(1_900_000_000));
        for (backend, path, expected) in [
            (
                BoxBackend::Codex,
                "tests/fixtures/credential-evidence-codex.json",
                include_str!("../tests/fixtures/credential-evidence-codex.json"),
            ),
            (
                BoxBackend::Claude,
                "tests/fixtures/credential-evidence-claude.json",
                include_str!("../tests/fixtures/credential-evidence-claude.json"),
            ),
        ] {
            let actual = serde_json::to_string(
                &evidence_for_check(&report, true, backend).expect("fictional credential evidence"),
            )
            .expect("evidence JSON");
            if std::env::var_os("UPDATE_LANE_PLAN").is_some() {
                fs::write(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join(path),
                    format!("{actual}\n"),
                )
                .expect("write evidence fixture");
            } else {
                assert_eq!(actual, expected.trim_end());
            }
        }
    }

    /// # Panics
    /// Panics if production evidence differs from its reviewed program binding.
    /// ´test:unit:claude-reviewed-binding-keeps-schema-evidence´
    #[test]
    fn claude_reviewed_binding_keeps_schema_evidence() {
        let root = claude_fixture_root();
        let runs = root.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let driver = runs.join("pilot");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected path");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("mode");
        let held =
            open_dir(&runs, owner_identity().0, owner_identity().0, 0o700).expect("held runs");
        let binding = &crate::runtime_admission::ReviewedProgramBinding::Schema;
        for backend in [BoxBackend::Codex, BoxBackend::Claude] {
            for result in [
                Ok(fixture_report(1_900_000_000)),
                Err(failure("credential-refresh", "synthetic refusal")),
            ] {
                let evidence = evidence_for_check_bound(&result, true, backend, binding)
                    .expect("production evidence");
                if backend == BoxBackend::Claude {
                    assert_eq!(
                        evidence["provider"]["required_sha256"],
                        CLAUDE_SCHEMA_PROGRAM_SHA256
                    );
                }
                let mut expected = match &result {
                    Ok(_) => json!({
                        "schema":1, "host":REFRESH_HOST, "state":"current",
                        "run_refusals":[], "run_refusals_omitted":0,
                        "expires_unix":1_900_000_000_u64, "refresh_due_unix":1_899_999_400_u64,
                        "kind":null, "detail":null,
                    }),
                    Err(_) => json!({
                        "schema":1, "host":REFRESH_HOST, "state":"refused",
                        "run_refusals":[], "run_refusals_omitted":0,
                        "expires_unix":null, "refresh_due_unix":null,
                        "kind":"credential-refresh", "detail":"synthetic refusal",
                    }),
                };
                if backend == BoxBackend::Claude {
                    expected.as_object_mut().expect("object").remove("host");
                    expected["schema"] = json!(2);
                    expected["backend"] = json!("claude");
                    expected["provider"] = json!({
                        "kind":"owner-program", "program":"/usr/bin/claude",
                        "required_sha256":CLAUDE_SCHEMA_PROGRAM_SHA256,
                    });
                }
                assert_eq!(
                    serde_json::to_vec(&evidence).expect("evidence bytes"),
                    serde_json::to_vec(&expected).expect("expected bytes")
                );
                let original = evidence_for_check(&result, true, backend).expect("original form");
                publish_evidence(&driver, &original).expect("compiled writer");
                let original_bytes =
                    fs::read(protected.join("credential-refresh.json")).expect("original bytes");
                publish_evidence_bound(&driver, &evidence, binding).expect("bound writer");
                assert_eq!(
                    fs::read(protected.join("credential-refresh.json")).expect("bound bytes"),
                    original_bytes
                );
                assert_eq!(
                    serde_json::to_vec(&evidence).expect("encoding"),
                    original_bytes
                );
                assert_eq!(
                    read_evidence(&held, "pilot", owner_identity().0).expect("census"),
                    Some(EvidenceObservation::Current(evidence))
                );
            }
        }
        let mut foreign = evidence_for_check_bound(
            &Ok(fixture_report(1_900_000_000)),
            true,
            BoxBackend::Claude,
            binding,
        )
        .expect("production evidence");
        let retained = fs::read(protected.join("credential-refresh.json")).expect("retained");
        foreign["provider"]["required_sha256"] = json!("0".repeat(64));
        let error = publish_evidence_bound(&driver, &foreign, binding)
            .expect_err("bound writer validates before writing");
        assert_eq!(error.kind, "credential-evidence");
        assert_eq!(error.detail, "schema, provider or state is invalid");
        assert_eq!(
            fs::read(protected.join("credential-refresh.json")).expect("evidence retained"),
            retained
        );
    }

    /// # Panics
    /// Panics if Claude evidence fabricates an endpoint or cannot be read by census.
    /// ´test:unit:claude-refresh-evidence-names-owner-program-without-host´
    #[test]
    fn claude_refresh_evidence_names_owner_program_without_host() {
        let backend = BoxBackend::Claude;
        let root = claude_fixture_root();
        let runs = root.path().join("runs");
        let driver = runs.join("pilot");
        fs::create_dir_all(&driver).expect("driver");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected path");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("protected mode");
        let held =
            open_dir(&runs, owner_identity().0, owner_identity().0, 0o700).expect("held runs");
        for result in [
            Ok(fixture_report(1_900_000_000)),
            Err(failure("credential-refresh", "synthetic refusal")),
        ] {
            let evidence = evidence_for_check(&result, true, backend).expect("evidence");
            assert_eq!(evidence["schema"], 2);
            assert_eq!(evidence["backend"], "claude");
            assert!(evidence.get("host").is_none());
            assert_eq!(evidence["provider"]["kind"], "owner-program");
            assert_eq!(
                evidence["provider"]["required_sha256"],
                CLAUDE_SCHEMA_PROGRAM_SHA256
            );
            publish_evidence(&driver, &evidence).expect("publish");
            assert_eq!(
                read_evidence(&held, "pilot", owner_identity().0).expect("census"),
                Some(EvidenceObservation::Current(evidence.clone()))
            );
            let mut foreign = evidence;
            foreign["host"] = json!(REFRESH_HOST);
            assert_eq!(
                publish_evidence(&driver, &foreign)
                    .expect_err("foreign host")
                    .kind,
                "credential-evidence"
            );
            foreign.as_object_mut().expect("object").remove("host");
            foreign["provider"]["required_sha256"] = json!("0".repeat(64));
            assert_eq!(
                publish_evidence(&driver, &foreign)
                    .expect_err("foreign program")
                    .kind,
                "credential-evidence"
            );
        }
    }

    #[derive(Clone, Copy)]
    enum StandInRefresh {
        Unchanged,
        Staged,
        OwnerProgram,
        OwnerProgramUnchanged,
        OwnerLogin,
        Refused,
    }

    // These counters stand in for opaque authority and file identity. They are
    // neither a Claude credential schema nor a fixture of vendor output.
    struct StandInProvider {
        current: std::cell::Cell<u64>,
        mode: StandInRefresh,
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl OwnerProvider for StandInProvider {
        type Snapshot = u64;
        type Identity = u64;

        fn read(&self) -> Result<u64, LaneError> {
            self.calls.borrow_mut().push("read");
            Ok(self.current.get())
        }

        fn due(&self, _source: &u64, _now: u64) -> bool {
            !matches!(self.mode, StandInRefresh::Unchanged)
        }

        fn identity(&self, source: &u64) -> Result<u64, LaneError> {
            Ok(*source)
        }

        fn refresh(&self, _source: &u64) -> Result<Option<u64>, LaneError> {
            self.calls.borrow_mut().push("owner-refresh");
            match self.mode {
                StandInRefresh::Refused => Err(failure("credential-refresh", "stand-in refused")),
                StandInRefresh::OwnerProgram => {
                    self.current.set(2);
                    Ok(None)
                }
                StandInRefresh::OwnerProgramUnchanged => Ok(None),
                StandInRefresh::OwnerLogin => {
                    self.current.set(3);
                    Ok(Some(2))
                }
                StandInRefresh::Staged => Ok(Some(2)),
                StandInRefresh::Unchanged => panic!("unneeded refresh"),
            }
        }

        fn publish(&self, next: &u64, expected: u64) -> Result<bool, LaneError> {
            self.calls.borrow_mut().push("publish");
            if self.current.get() != expected {
                return Ok(false);
            }
            self.current.set(*next);
            Ok(true)
        }
    }

    /// ´test:unit:credential-provider-preserves-owner-refresh-boundaries´
    #[test]
    fn credential_provider_preserves_owner_refresh_boundaries() {
        for (mode, replace_before_publish, expected, calls) in [
            (StandInRefresh::Unchanged, false, Some(1), vec!["read"]),
            (
                StandInRefresh::Staged,
                false,
                Some(2),
                vec!["read", "owner-refresh", "read", "publish"],
            ),
            (
                StandInRefresh::OwnerProgram,
                false,
                Some(2),
                vec!["read", "owner-refresh", "read"],
            ),
            (
                StandInRefresh::OwnerProgramUnchanged,
                false,
                Some(1),
                vec!["read", "owner-refresh", "read"],
            ),
            (
                StandInRefresh::OwnerLogin,
                false,
                Some(3),
                vec!["read", "owner-refresh", "read"],
            ),
            (
                StandInRefresh::Staged,
                true,
                Some(3),
                vec!["read", "owner-refresh", "read", "publish", "read"],
            ),
            (
                StandInRefresh::Refused,
                false,
                None,
                vec!["read", "owner-refresh"],
            ),
        ] {
            let provider = StandInProvider {
                current: std::cell::Cell::new(1),
                mode,
                calls: std::cell::RefCell::new(Vec::new()),
            };
            let result = refresh_provider(&provider, 0, || {
                if replace_before_publish {
                    provider.current.set(3);
                }
            });
            if let Some(value) = expected {
                assert_eq!(result.expect("provider result"), value);
            } else {
                let error = result.expect_err("owner refresh refusal");
                assert_eq!(error.kind, "credential-refresh");
                assert_eq!(provider.current.get(), 1);
            }
            assert_eq!(*provider.calls.borrow(), calls);
        }
    }

    /// ´test:unit:credential-two-distinct-workers-receive-one-refresh´
    #[test]
    fn credential_two_distinct_workers_receive_one_refresh() {
        let temp = fixture_root();
        let now = 1_800_000_000;
        fixture_sign_in(temp.path(), &source(now + 500, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        fixture_run(&runs, "pilot-2", 3002);
        let (endpoint, server) = fixture_endpoint(
            "200 OK",
            json!({"access_token":token(now + 3600),"refresh_token":"fixture-rotated"}),
        );
        let published = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&published);
        let mut published_runs = BTreeMap::new();
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            &endpoint,
            now,
            &mut published_runs,
            move |_home, uid, source| {
                captured
                    .lock()
                    .expect("capture")
                    .push((uid, source.worker_file()));
                Ok(())
            },
        )
        .expect("one refresh for both runs");
        server.join().expect("endpoint joined");
        let mut published = published.lock().expect("capture").clone();
        published.sort_by_key(|(uid, _)| *uid);
        assert_eq!(published.len(), 2);
        assert_eq!((published[0].0, published[1].0), (3001, 3002));
        assert_eq!(published[0].1, published[1].1);
    }

    /// ´test:unit:credential-owner-login-replacement-reaches-live-run´
    #[test]
    fn credential_owner_login_replacement_reaches_live_run() {
        let temp = fixture_root();
        let now = 1_800_000_000;
        fixture_sign_in(temp.path(), &source(now + 3600, "first"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        let mut published_runs = BTreeMap::new();
        let mut published = Vec::new();
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            now,
            &mut published_runs,
            |_home, uid, source| {
                published.push((uid, source.worker_file()));
                Ok(())
            },
        )
        .expect("first publication");
        fixture_sign_in(temp.path(), &source(now + 7200, "owner-login"));
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            now + 30,
            &mut published_runs,
            |_home, uid, source| {
                published.push((uid, source.worker_file()));
                Ok(())
            },
        )
        .expect("replacement publication");
        assert_eq!(published.len(), 2);
        assert_ne!(published[0].1, published[1].1);
    }

    /// ´test:unit:credential-vendor-refusal-keeps-live-token-and-refuses-new-run´
    #[test]
    fn credential_vendor_refusal_keeps_live_token_and_refuses_new_run() {
        let temp = fixture_root();
        let now = 1_800_000_000;
        let original = source(now + 400, "initial");
        fixture_sign_in(temp.path(), &original);
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        let live_file = runs.join("live-auth.json");
        let mut published = BTreeMap::new();
        refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            now - 1000,
            &mut published,
            |_home, _uid, source| {
                fs::write(&live_file, source.worker_file())
                    .map_err(|error| failure("fixture", error.to_string()))
            },
        )
        .expect("live run begins with valid token");
        let before = fs::read(&live_file).expect("live token");
        let before_count = published.len();
        let (endpoint, server) =
            fixture_endpoint("400 Bad Request", json!({"error":"invalid_grant"}));
        let live_report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            &endpoint,
            now,
            &mut published,
            |_home, _uid, _source| panic!("refused refresh must not publish"),
        )
        .expect("live refresh refusal is reported with its due instant");
        assert_eq!(live_report.expires_unix, now + 400);
        assert_eq!(live_report.refresh_due_unix, now - 200);
        let live_error = live_report.authority_failure.expect("authority refusal");
        assert_eq!(live_error.kind, "credential-refresh");
        assert_eq!(published.len(), before_count);
        assert_eq!(fs::read(&live_file).expect("live token retained"), before);
        server.join().expect("endpoint joined");
        let (endpoint, server) =
            fixture_endpoint("400 Bad Request", json!({"error":"invalid_grant"}));
        let error = preflight_at(temp.path(), "alpha", &endpoint, now)
            .expect_err("new run refuses vendor failure");
        assert_eq!(error.kind, "credential-refresh");
        server.join().expect("endpoint joined");
        let after: Value = serde_json::from_slice(
            &fs::read(sign_in_dir(temp.path(), "alpha").join("auth.json"))
                .expect("synthetic source"),
        )
        .expect("still parseable");
        assert_eq!(after, original);
    }

    /// ´test:unit:credential-evidence-replaces-only-the-protected-name´
    #[test]
    fn credential_evidence_replaces_only_the_protected_name() {
        let temp = fixture_root();
        let root = temp.path().join("runs");
        let driver = root.join("pilot-1");
        let old_launch = driver.join("launch");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected path");
        fs::create_dir_all(&old_launch).expect("loop-controlled directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protected runs root");
        fs::create_dir(&protected).expect("owner-controlled directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("protected mode");
        let target = temp.path().join("owner-target");
        fs::write(&target, b"unchanged").expect("synthetic owner target");
        symlink(&target, old_launch.join("credential-refresh.json")).expect("loop-created symlink");
        let evidence =
            evidence_for_check(&Ok(fixture_report(1_900_000_000)), true, BoxBackend::Codex)
                .expect("first check evidence");
        publish_evidence(&driver, &evidence).expect("protected evidence publication");
        assert_eq!(fs::read(&target).expect("target"), b"unchanged");
        let written: Value = serde_json::from_slice(
            &fs::read(protected.join("credential-refresh.json")).expect("protected evidence"),
        )
        .expect("evidence JSON");
        assert_eq!(written, evidence);
        fs::remove_dir_all(protected).expect("remove protected directory");
        assert_eq!(
            publish_evidence(&driver, &evidence)
                .expect_err("publication failure propagates")
                .kind,
            "credential-evidence"
        );
    }

    fn assert_temporal_evidence_refusals(
        evidence: &Value,
        protected: &Path,
        held: &OwnedFd,
        driver: &Path,
        owner: u32,
    ) {
        for (field, invalid, named) in [
            ("expires_unix", Value::Null, "expires_unix"),
            ("expires_unix", json!("1900000000"), "expires_unix"),
            ("expires_unix", json!(1_900_000_000.5_f64), "expires_unix"),
            ("refresh_due_unix", Value::Null, "refresh_due_unix"),
            ("refresh_due_unix", json!("1899999400"), "refresh_due_unix"),
            (
                "refresh_due_unix",
                json!(1_899_999_400.5_f64),
                "refresh_due_unix",
            ),
            ("refresh_due_unix", json!(1_899_999_401_u64), "disagrees"),
        ] {
            let mut malformed = evidence.clone();
            malformed[field] = invalid;
            fs::write(
                protected.join("credential-refresh.json"),
                malformed.to_string(),
            )
            .expect("malformed fixture");
            assert_eq!(
                read_evidence(held, "R", owner).expect("temporal defect is observable"),
                Some(EvidenceObservation::Current(malformed.clone()))
            );
            let error = publish_evidence(driver, &malformed)
                .expect_err("writer still refuses malformed instant");
            assert_eq!(error.status, 2);
            assert!(error.detail.contains(named), "{}", error.line());
        }
    }

    /// ´test:unit:credential-evidence-instants-follow-fixture-exp-and-refuse-missing-fields´
    #[test]
    fn credential_evidence_instants_follow_fixture_exp_and_refuse_missing_fields() {
        let temp = fixture_root();
        let expires = 1_900_000_000_u64;
        fixture_sign_in(temp.path(), &source(expires, "known-exp"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs root");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let mut published = BTreeMap::new();
        let report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            1_800_000_000,
            &mut published,
            |_home, _uid, _source| panic!("no run is present"),
        )
        .expect("first helper check");
        assert!(!report.changed);
        assert_eq!(report.expires_unix, expires);
        assert_eq!(report.refresh_due_unix, expires - 600);
        let driver = runs.join("R");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected name");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("protected mode");
        let evidence = evidence_for_check(&Ok(report), true, BoxBackend::Codex)
            .expect("first check publishes");
        assert_eq!(evidence["state"], "current");
        publish_evidence(&driver, &evidence).expect("evidence publication");
        let held: OwnedFd = File::open(&runs).expect("held runs root").into();
        let owner = Uid::effective().as_raw();
        assert_eq!(
            read_evidence(&held, "R", owner).expect("evidence"),
            Some(EvidenceObservation::Current(evidence.clone()))
        );
        assert_eq!(read_evidence(&held, "S", owner).expect("absent"), None);
        fs::write(
            protected.join("credential-refresh.json"),
            json!({"schema":1,"host":REFRESH_HOST,"state":"published","run_refusals":[]})
                .to_string(),
        )
        .expect("older shape");
        assert_eq!(
            read_evidence(&held, "R", owner).expect("historical observation"),
            Some(EvidenceObservation::Historical(
                json!({"schema":1,"host":REFRESH_HOST,"state":"published","run_refusals":[]})
            ))
        );
        assert_temporal_evidence_refusals(&evidence, &protected, &held, &driver, owner);
        let refusal = failure("credential-sign-in", "source cannot be read");
        let failed_check: Result<RefreshReport, LaneError> = Err(refusal);
        let refused =
            evidence_for_check(&failed_check, false, BoxBackend::Codex).expect("error evidence");
        assert_eq!(refused["expires_unix"], Value::Null);
        assert_eq!(refused["refresh_due_unix"], Value::Null);
        publish_evidence(&driver, &refused).expect("refusal replaces prior measurement");
        assert_eq!(
            read_evidence(&held, "R", owner).expect("refused evidence"),
            Some(EvidenceObservation::Current(refused))
        );
        let recovered_check = Ok(fixture_report(expires));
        let recovered =
            evidence_for_check(&recovered_check, failed_check.is_err(), BoxBackend::Codex)
                .expect("healthy check after refusal republishes");
        assert_eq!(recovered["state"], "current");
        publish_evidence(&driver, &recovered).expect("recovered evidence publication");
        let EvidenceObservation::Current(measured) = read_evidence(&held, "R", owner)
            .expect("recovered evidence")
            .expect("measured record")
        else {
            panic!("current evidence expected");
        };
        assert_eq!(measured["expires_unix"], expires);
        assert_eq!(measured["refresh_due_unix"], expires - 600);
    }

    /// ´test:unit:credential-run-refusals-stay-below-evidence-reader-bound´
    #[test]
    fn credential_run_refusals_stay_below_evidence_reader_bound() {
        let temp = fixture_root();
        fixture_sign_in(temp.path(), &source(1_900_000_000, "bounded"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs root");
        for index in 0..20 {
            fixture_run(&runs, &format!("R{index}"), 3000 + index % 2);
        }
        let mut published = BTreeMap::new();
        let report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            1_800_000_000,
            &mut published,
            |_home, _uid, _source| Err(failure("fixture", "x".repeat(4096))),
        )
        .expect("bounded refusals");
        assert!(report.refusals_omitted > 0);
        let driver = runs.join("R0");
        let protected = crate::plan::protected_identity_dir(&driver).expect("protected name");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("protected mode");
        let evidence = evidence_for_check(&Ok(report), false, BoxBackend::Codex)
            .expect("run refusals publish");
        publish_evidence(&driver, &evidence).expect("bounded evidence publication");
        let held: OwnedFd = File::open(&runs).expect("held runs root").into();
        assert_eq!(
            read_evidence(&held, "R0", Uid::effective().as_raw()).expect("bounded reader"),
            Some(EvidenceObservation::Current(evidence))
        );
    }

    /// # Panics
    /// Panics if the fixture cannot pin and validate the selected real executable files.
    fn credential_test_programs(
        client: &str,
        clock: &str,
    ) -> BTreeMap<PathBuf, std::sync::Arc<loop_home::anchor::Anchor>> {
        use loop_home::anchor::{
            HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Receiver, Requirement,
            Transport,
        };
        let host = HostVerifier::current().expect("host map");
        let policy = Policy {
            kind: Kind::File,
            owner: Owner::RootFile,
            mode: ModePolicy::Executable,
        };
        let mut pins = Vec::new();
        let mut requirements = Vec::new();
        for (slot, purpose, path) in [
            (0, "credential-client", client),
            (1, "credential-clock", clock),
        ] {
            pins.push(
                host.pin(Path::new(path), purpose, slot, policy)
                    .expect("host executable"),
            );
            requirements.push(Requirement {
                purpose: purpose.into(),
                policy,
                alias_group: None,
            });
        }
        let manifest = Manifest {
            version: 1,
            transport: Transport::Rights,
            operation: "credential-test".into(),
            loop_name: "alpha".into(),
            records: pins
                .iter()
                .map(loop_home::anchor::HostPin::record)
                .collect(),
        };
        let anchors = Receiver::current()
            .expect("receiver")
            .validate(
                &manifest,
                pins.into_iter()
                    .map(loop_home::anchor::HostPin::into_fd)
                    .collect(),
                "credential-test",
                "alpha",
                Transport::Rights,
                &requirements,
            )
            .expect("validated programs");
        ["/usr/bin/curl", "/usr/bin/date"]
            .into_iter()
            .zip(anchors)
            .map(|(path, anchor)| (PathBuf::from(path), std::sync::Arc::new(anchor)))
            .collect()
    }

    /// # Panics
    /// Panics if the production helper composer, receiver or support extraction disagrees.
    fn helper_custody_fixture(
        client: &str,
    ) -> (
        tempfile::TempDir,
        crate::home::PrivateHomeGuard,
        crate::container_entry::ExecutableGuard,
    ) {
        let home = fixture_root();
        let runs = home.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let held_home = File::open(home.path()).expect("home").into();
        let held_runs = File::open(&runs).expect("runs").into();
        for path in [
            home.path().join(".config"),
            home.path().join(".config/loops"),
        ] {
            fs::create_dir_all(&path).expect("configuration directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let mut bundle = crate::container_entry::pin(
            "alpha",
            (home.path(), &held_home),
            (&runs, &held_runs),
            &std::env::current_exe().expect("entry image"),
            Path::new("/usr/bin/podman"),
            BoxBackend::Codex,
        )
        .expect("production helper composer");
        if client != "/usr/bin/curl" {
            use loop_home::anchor::{HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy};
            let pin = HostVerifier::current()
                .expect("host map")
                .for_operation("container-helper")
                .pin(
                    Path::new(client),
                    "credential-client",
                    5,
                    Policy {
                        kind: Kind::File,
                        owner: Owner::RootFile,
                        mode: ModePolicy::Executable,
                    },
                )
                .expect("substitute root-owned client capability");
            let mut manifest = Manifest::parse(&bundle.manifest).expect("manifest");
            manifest.records[5] = pin.record();
            bundle.descriptors[5] = pin.into_fd();
            bundle.manifest = serde_json::to_string(&manifest).expect("client declaration");
        }
        let (sender, input) = std::os::unix::net::UnixStream::pair().expect("rights channel");
        loop_home::anchor::transport::send(&sender, &bundle.descriptors).expect("complete frame");
        let (_, mut anchors) = crate::container_entry::receive_for(
            &bundle.manifest,
            &input,
            "container-helper",
            Some("alpha"),
        )
        .expect("production helper receiver");
        let _configuration = anchors.pop().expect("configuration role");
        let (runtime, mut support) =
            crate::container_entry::take_support_programs(&mut anchors, BoxBackend::Codex)
                .expect("production helper support roles");
        support.insert(PathBuf::from("/usr/bin/podman"), Arc::new(runtime));
        let guard = crate::home::activate_private_launch(
            home.path(),
            &anchors[0],
            &runs,
            &anchors[1],
            None,
            Uid::effective().as_raw(),
        )
        .expect("held home and runs");
        let programs = crate::container_entry::activate_program_map("container-helper", support);
        (home, guard, programs)
    }

    /// # Panics
    /// Panics if the credential thread loses held executables or changes the refresh exchange.
    /// ´claim:superlooplane:credential-thread-refreshes-through-held-executables´
    /// ´test:unit:credential-thread-refreshes-through-held-executables´
    #[test]
    fn credential_thread_refreshes_through_held_executables() {
        let (_home, _private, _guard) = helper_custody_fixture("/usr/bin/curl");
        let custody = crate::container_helper::CredentialThreadCustody::capture_admitted(
            BoxBackend::Codex,
            &Gate,
        )
        .expect("production helper thread handoff");
        let (endpoint, server) = fixture_endpoint(
            "200 OK",
            json!({"id_token":token(1_900_000_000),"access_token":token(1_900_000_000),"refresh_token":"fixture-rotated"}),
        );
        let refreshed = std::thread::spawn(move || {
            let _guard = custody
                .activate()
                .expect("production helper thread activation");
            assert!(
                crate::container_entry::check(Path::new("/usr/bin/curl"))
                    .expect("held client")
                    .is_ok()
            );
            assert!(
                crate::container_entry::check(Path::new("/usr/bin/date"))
                    .expect("held clock")
                    .is_ok()
            );
            assert!(
                crate::container_entry::check(Path::new("/usr/bin/sha256sum"))
                    .expect("scoped map")
                    .is_err(),
                "hashing authority is not transferred"
            );
            assert!(
                crate::container_entry::check(Path::new("/usr/bin/podman"))
                    .expect("scoped map")
                    .is_err(),
                "container authority is not transferred"
            );
            refresh_request(
                &Source::parse(source(1_800_000_000, "initial")).expect("source"),
                &endpoint,
            )
            .expect("held refresh exchange")
        })
        .join()
        .expect("credential thread");
        let request = server.join().expect("endpoint");
        assert_eq!(request["grant_type"], "refresh_token");
        assert_eq!(
            refreshed.document["tokens"]["refresh_token"],
            "fixture-rotated"
        );
        assert!(
            refreshed.document["last_refresh"]
                .as_str()
                .expect("clock output")
                .ends_with('Z')
        );
        let _clock = crate::container_entry::activate_program_map(
            "credential-test",
            credential_test_programs("/usr/bin/curl", "/usr/bin/false"),
        );
        let refusal = utc_timestamp().expect_err("held false image replaces the date program key");
        assert_eq!(refusal.kind, "credential-clock");
        assert_eq!(refusal.detail, "UTC date program failed");
    }

    /// # Panics
    /// Panics if the service authority loses held roots, its first evidence or cancellation.
    /// ´claim:superlooplane:service-credential-authority-retains-custody´
    /// ´test:unit:service-credential-authority-retains-custody´
    #[test]
    fn service_credential_authority_retains_custody() {
        for case in ["current", "absent", "client", "exchange"] {
            service_authority_case(case);
        }
    }

    /// # Panics
    /// Panics if a service authority check escapes its capabilities or loses its evidence.
    fn service_authority_case(case: &str) {
        use std::sync::atomic::{AtomicBool, Ordering};

        let present = case != "absent";
        let due = matches!(case, "client" | "exchange");
        let (home, private, programs) = helper_custody_fixture(if case == "client" {
            "/usr/bin/true"
        } else {
            "/usr/bin/curl"
        });
        let expires = now_seconds().expect("current instant") + if due { 300 } else { 86_400 };
        fixture_sign_in(home.path(), &source(expires, "service"));
        if !present {
            fs::remove_file(sign_in_dir(home.path(), "alpha").join("auth.json"))
                .expect("absent authority source");
        }
        let runs = home.path().join("runs");
        let driver = runs.join("R");
        fs::create_dir(&driver).expect("driver");
        let protected = crate::plan::protected_identity_dir(&driver).expect("evidence path");
        fs::create_dir(&protected).expect("protected evidence directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).expect("evidence mode");
        let lock = lock(home.path(), "alpha").expect("order the first authority check");
        let retained = ReplacedAuthorityHome::new(home.path());
        let cancelled = Arc::new(AtomicBool::new(false));
        let exchange = (case == "exchange").then(|| fixture_endpoint(
            "200 OK",
            json!({"id_token":token(expires + 86_400),"access_token":token(expires + 86_400),"refresh_token":"service-rotated"}),
        ));
        // Retain the unserved listener so a lost program map can contact only loopback.
        let refusal = TcpListener::bind("127.0.0.1:0").expect("closed fixture boundary");
        let endpoint = exchange.as_ref().map_or_else(
            || {
                format!(
                    "http://{}/token",
                    refusal.local_addr().expect("local endpoint")
                )
            },
            |(endpoint, _)| endpoint.clone(),
        );
        let _endpoint = fixture_service_endpoint(endpoint);
        let (pass, observed) = std::sync::mpsc::sync_channel(1);
        let authority = crate::container_helper::fixture_authority_with_wait(
            (home.path(), &runs, &driver),
            Arc::clone(&cancelled),
            &Gate,
            BoxBackend::Codex,
            move |cancelled| {
                pass.send(()).expect("pass observer");
                cancelled.store(true, Ordering::Release);
            },
        )
        .expect("service authority spawn");
        drop(programs);
        drop(private);
        // The blocking lock orders both guard releases before refresh_live_at can read.
        drop(lock);
        let result = finish_service_authority(authority);
        assert!(
            !home.path().join(".config").exists(),
            "replacement home is untouched"
        );
        retained.restore();
        result.expect("service authority result");
        observed
            .try_recv()
            .expect("authority reached its post-publication wait");
        assert!(
            cancelled.load(Ordering::Acquire),
            "first pass cancels the loop"
        );
        assert_service_authority_evidence(case, home.path(), &protected, expires, exchange);
    }

    struct ReplacedAuthorityHome {
        original: PathBuf,
        retained: tempfile::TempDir,
    }
    impl ReplacedAuthorityHome {
        /// # Panics
        /// Panics if the fixture home cannot be retained and replaced.
        fn new(home: &Path) -> Self {
            let retained = tempfile::tempdir_in(home.parent().expect("home parent"))
                .expect("owned retention directory");
            fs::rename(home, retained.path().join("home")).expect("retain original home inode");
            fs::create_dir(home).expect("replacement home");
            fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("replacement mode");
            Self {
                original: home.to_path_buf(),
                retained,
            }
        }
        fn path(&self) -> PathBuf {
            self.retained.path().join("home")
        }
        /// # Panics
        /// Panics if the empty replacement cannot be removed and the retained home restored.
        fn restore(self) {
            fs::remove_dir(&self.original).expect("remove empty replacement");
            fs::rename(self.path(), &self.original).expect("restore fixture for cleanup");
        }
    }

    /// # Panics
    /// Panics if the authority or join waiter panics; an unproved exit stops this process.
    #[allow(clippy::exit)]
    fn finish_service_authority(
        authority: std::thread::JoinHandle<Result<(), LaneError>>,
    ) -> Result<(), LaneError> {
        let (finished, completion) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let _sent = finished.send(authority.join());
        });
        let joined = completion.recv_timeout(Duration::from_secs(180));
        if joined.is_err() {
            // Do not drop retained custody beneath an authority whose exit is unproved.
            let _reported = writeln!(
                std::io::stderr(),
                "service authority completion exceeded distant hang guard"
            );
            std::process::exit(125);
        }
        waiter.join().expect("authority waiter join");
        joined
            .expect("authority completion event")
            .expect("service authority join")
    }

    /// # Panics
    /// Panics if an already cancelled authority reaches its blocked first check.
    /// ´claim:superlooplane:service-authority-cancellation-prevents-first-check´
    /// ´test:unit:service-authority-cancellation-prevents-first-check´
    #[test]
    fn service_authority_cancellation_prevents_first_check() {
        let (home, _private, _programs) = helper_custody_fixture("/usr/bin/true");
        fixture_sign_in(
            home.path(),
            &source(now_seconds().expect("clock") + 300, "cancelled"),
        );
        let _lock = lock(home.path(), "alpha").expect("block every first check");
        let original =
            fs::read(sign_in_dir(home.path(), "alpha").join("auth.json")).expect("source");
        let refusal = TcpListener::bind("127.0.0.1:0").expect("local boundary");
        let _endpoint = fixture_service_endpoint(format!(
            "http://{}/token",
            refusal.local_addr().expect("address")
        ));
        let driver = home.path().join("runs/R");
        let authority = crate::container_helper::spawn_credential_authority_admitted(
            home.path().to_path_buf(),
            "alpha".into(),
            home.path().join("runs"),
            driver.clone(),
            BoxBackend::Codex,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            &Gate,
        )
        .expect("cancelled service spawn");
        finish_service_authority(authority).expect("cancelled before first check");
        assert!(
            !driver.exists(),
            "cancelled authority publishes no evidence"
        );
        assert_eq!(
            fs::read(sign_in_dir(home.path(), "alpha").join("auth.json"))
                .expect("unchanged source"),
            original
        );
    }

    /// # Panics
    /// Panics if unwinding leaks the owned retention directory or its contents.
    /// ´claim:superlooplane:service-authority-retention-cleans-up-on-panic´
    /// ´test:unit:service-authority-retention-cleans-up-on-panic´
    #[test]
    fn service_authority_retention_cleans_up_on_panic() {
        let home = tempfile::tempdir().expect("home");
        let retained = std::cell::RefCell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let moved = ReplacedAuthorityHome::new(home.path());
            *retained.borrow_mut() = Some(moved.retained.path().to_path_buf());
            fs::write(moved.path().join("sentinel"), b"fictional").expect("retained contents");
            panic!("fixture panic after home replacement");
        }));
        assert!(result.is_err());
        assert!(!retained.borrow().as_ref().expect("retained path").exists());
        assert!(home.path().exists());
    }

    /// # Panics
    /// Panics if the service exchange or its persisted evidence differs from the check.
    fn assert_service_authority_evidence(
        case: &str,
        home: &Path,
        protected: &Path,
        expires: u64,
        exchange: Option<(String, std::thread::JoinHandle<Value>)>,
    ) {
        let present = case != "absent";
        let due = matches!(case, "client" | "exchange");
        let evidence: Value = serde_json::from_slice(
            &fs::read(protected.join("credential-refresh.json"))
                .expect("first service check publishes evidence"),
        )
        .expect("evidence JSON");
        if let Some((_, server)) = exchange {
            // A refused exchange must fail before joining an endpoint that saw no request.
            assert_eq!(evidence["state"], "current");
            assert_eq!(evidence["expires_unix"], expires + 86_400);
            let request = server.join().expect("service refresh exchange");
            assert_eq!(request["grant_type"], "refresh_token");
            assert_eq!(request["refresh_token"], "fixture-refresh-service");
            let refreshed: Value = serde_json::from_slice(
                &fs::read(sign_in_dir(home, "alpha").join("auth.json")).expect("refreshed source"),
            )
            .expect("source JSON");
            assert_eq!(refreshed["tokens"]["refresh_token"], "service-rotated");
            assert!(
                refreshed["last_refresh"]
                    .as_str()
                    .expect("held clock result")
                    .ends_with('Z')
            );
            assert_eq!(evidence["run_refusals"], json!([]));
        } else {
            assert_eq!(
                evidence["state"],
                if present && !due {
                    "current"
                } else {
                    "refused"
                }
            );
            if due {
                assert_eq!(evidence["kind"], "credential-refresh");
                assert!(
                    matches!(
                        evidence["detail"].as_str(),
                        Some(
                            "token endpoint response is invalid"
                                | "token request could not be sent"
                        )
                    ),
                    "{evidence}"
                );
                assert_eq!(evidence["expires_unix"], expires);
            } else if present {
                assert_eq!(evidence["expires_unix"], expires);
                assert_eq!(evidence["refresh_due_unix"], expires - 600);
                assert_eq!(evidence["run_refusals"], json!([]));
            } else {
                assert_eq!(evidence["kind"], "credential-sign-in");
                assert!(evidence["expires_unix"].is_null());
            }
        }
    }

    /// # Panics
    /// Panics if the refresh client executes its pathname instead of the received capability.
    /// ´claim:superlooplane:credential-client-executes-the-received-file´
    /// ´test:unit:credential-client-executes-the-received-file´
    #[test]
    fn credential_client_executes_the_received_file() {
        let (_home, _private, _programs) = helper_custody_fixture("/usr/bin/true");
        let custody = crate::container_helper::CredentialThreadCustody::capture_admitted(
            BoxBackend::Codex,
            &Gate,
        )
        .expect("production handoff");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("endpoint");
        listener.set_nonblocking(true).expect("bounded observation");
        let endpoint = format!("http://{}/refresh", listener.local_addr().expect("address"));
        let error = std::thread::spawn(move || {
            let _guard = custody.activate().expect("production thread activation");
            let output = crate::build::run_checked(
                Path::new("/usr/bin/curl"),
                Vec::new(),
                &std::env::vars().collect(),
                Path::new("/"),
                10,
                "credential-client-test",
            )
            .expect("held true client");
            assert!(
                output.is_empty(),
                "the argument-free held client emits nothing"
            );
            let Err(error) = refresh_request(
                &Source::parse(source(1_800_000_000, "initial")).expect("source"),
                &endpoint,
            ) else {
                panic!("the held client produces no token response");
            };
            error
        })
        .join()
        .expect("credential thread");
        assert_eq!(error.kind, "credential-refresh");
        assert!(
            matches!(
                error.detail.as_str(),
                "token endpoint response is invalid" | "token request could not be sent"
            ),
            "{error:?}"
        );
        assert_eq!(
            listener
                .accept()
                .expect_err("no pathname client connects")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// ´test:unit:credential-helper-thread-retains-verified-anchors´
    #[test]
    fn credential_helper_thread_retains_verified_anchors() {
        let temp = fixture_root();
        let writable = temp.path().join("writable-ancestor");
        let home = writable.join("home");
        fs::create_dir(&writable).expect("ancestor");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o770))
            .expect("replaceable ancestor");
        fs::create_dir(&home).expect("home");
        fixture_sign_in(&home, &source(1_900_000_000, "initial"));
        let runs = home.join("runs");
        fs::create_dir(&runs).expect("runs");
        fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("protected runs root");
        fixture_run(&runs, "pilot-1", 3001);
        let owner = Uid::effective().as_raw();
        assert_eq!(
            crate::home::pin_parent(&sign_in_dir(&home, "alpha"), owner)
                .expect_err("full walk sees replaceable ancestor")
                .kind,
            "unsafe-path"
        );
        let home_fd = File::open(&home).expect("held home");
        let runs_fd = File::open(&runs).expect("held runs root");
        let mut overflow = fstat(&home_fd).expect("synthetic ancestor stat");
        overflow.st_uid = 65_534;
        let child = fstat(&runs_fd).expect("synthetic child stat");
        assert_eq!(
            crate::home::trusted(&overflow, &child, Path::new("/"), owner)
                .expect_err("overflow-owned ancestor is refused by a full walk")
                .kind,
            "unsafe-path"
        );
        let _active =
            crate::home::activate_private_launch(&home, &home_fd, &runs, &runs_fd, None, owner)
                .expect("verified descriptors");
        let snapshot = crate::home::snapshot_private_home().expect("held anchors");
        let result = std::thread::spawn(move || {
            let _thread_anchors =
                crate::home::activate_private_snapshot(snapshot).expect("thread anchors");
            let mut published = BTreeMap::new();
            let mut recipients = Vec::new();
            let report = refresh_live_at(
                &home,
                "alpha",
                &runs,
                "http://127.0.0.1:1",
                1_800_000_000,
                &mut published,
                |_home, uid, _source| {
                    recipients.push(uid);
                    Ok(())
                },
            )
            .expect("anchored refresh thread");
            (report.changed, recipients)
        })
        .join()
        .expect("refresh thread joined");
        assert_eq!(result, (true, vec![3001]));
    }

    /// ´test:unit:credential-refresh-enumerates-held-runs-root-after-replacement´
    #[test]
    fn credential_refresh_enumerates_held_runs_root_after_replacement() {
        let temp = fixture_root();
        fixture_sign_in(temp.path(), &source(1_900_000_000, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        let home_fd = File::open(temp.path()).expect("held home");
        let runs_fd = File::open(&runs).expect("held runs root");
        let _active = crate::home::activate_private_launch(
            temp.path(),
            &home_fd,
            &runs,
            &runs_fd,
            None,
            Uid::effective().as_raw(),
        )
        .expect("verified descriptors");
        fs::rename(&runs, temp.path().join("retired-runs")).expect("rename held root");
        fs::create_dir(&runs).expect("replacement root");
        let mut published = BTreeMap::new();
        let mut recipients = Vec::new();
        let report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            1_800_000_000,
            &mut published,
            |_home, uid, _source| {
                recipients.push(uid);
                Ok(())
            },
        )
        .expect("held generation is enumerated");
        assert!(report.changed);
        assert_eq!(recipients, vec![3001]);
    }

    /// ´test:unit:credential-refresh-skips-driver-run-without-reservation´
    #[test]
    fn credential_refresh_skips_driver_run_without_reservation() {
        let temp = fixture_root();
        fixture_sign_in(temp.path(), &source(1_900_000_000, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs root");
        fs::create_dir(runs.join("20260101T000000Z-driver-run")).expect("driver run");
        fixture_run(&runs, "pilot-1", 3001);
        let mut published = BTreeMap::new();
        let mut recipients = Vec::new();
        let report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            1_800_000_000,
            &mut published,
            |_home, uid, _source| {
                recipients.push(uid);
                Ok(())
            },
        )
        .expect("driver run skipped");
        assert!(report.changed);
        assert_eq!(recipients, vec![3001]);
    }

    /// ´test:unit:credential-owner-login-wins-both-refresh-windows´
    #[test]
    fn credential_owner_login_wins_both_refresh_windows() {
        let now = 1_800_000_000;
        for during_request in [true, false] {
            let temp = fixture_root();
            fixture_sign_in(temp.path(), &source(now + 300, "old"));
            let replacement = source(now + 7200, "owner-login");
            let home = temp.path().to_path_buf();
            let (endpoint, server) = if during_request {
                let replacement = replacement.clone();
                fixture_endpoint_with(
                    "200 OK",
                    json!({"access_token":token(now + 3600),"refresh_token":"fixture-rotated"}),
                    move || replace_sign_in(&home, &replacement),
                )
            } else {
                fixture_endpoint(
                    "200 OK",
                    json!({"access_token":token(now + 3600),"refresh_token":"fixture-rotated"}),
                )
            };
            let adopted = refresh_if_due_with(temp.path(), "alpha", &endpoint, now, || {
                if !during_request {
                    replace_sign_in(temp.path(), &replacement);
                }
            })
            .expect("adopt owner login");
            server.join().expect("fixture endpoint joined");
            assert_eq!(
                adopted.document["tokens"]["refresh_token"],
                "fixture-refresh-owner-login"
            );
            assert_eq!(
                read_source(temp.path(), "alpha")
                    .expect("owner sign-in")
                    .document,
                replacement
            );
        }
    }

    /// ´test:unit:owner-refresh-serializes-box-and-door-consumers´
    #[test]
    fn owner_refresh_serializes_box_and_door_consumers() {
        let home = fixture_root();
        let now = now_seconds().expect("fixture clock");
        fixture_sign_in(home.path(), &source(now + 300, "due"));
        let peer_home = home.path().to_path_buf();
        let (endpoint, server) = fixture_endpoint_with(
            "200 OK",
            json!({"access_token":token(now + 3600),"refresh_token":"fixture-next"}),
            move || {
                let refused = try_lock(&peer_home, "alpha").expect_err("door holds lock");
                assert_eq!(refused.kind, "credential-lock-busy");
            },
        );
        let guard = try_lock(home.path(), "alpha").expect("door publication guard");
        let selected = door_authority_under_lock(
            home.path(),
            "alpha",
            &endpoint,
            Instant::now() + Duration::from_secs(30),
            &|| false,
        )
        .expect("renewed projection");
        assert!(selected.refreshed);
        assert_eq!(selected.expires_unix, now + 3600);
        assert_eq!(
            server.join().expect("one synthetic refresh")["refresh_token"],
            "fixture-refresh-due"
        );
        drop(guard);
        let box_source = refresh_if_due(home.path(), "alpha", "http://127.0.0.1:1/unused", now)
            .expect("box adopts committed generation without another refresh");
        assert_eq!(
            box_source.document["tokens"]["refresh_token"],
            "fixture-next"
        );
        assert_eq!(box_source.worker_file(), selected.bytes);
    }

    /// ´test:unit:door-refresh-cancellation-reaps-owned-child´
    #[test]
    fn door_refresh_cancellation_reaps_owned_child() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let home = fixture_root();
        let now = now_seconds().expect("fixture clock");
        fixture_sign_in(home.path(), &source(now + 300, "due"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("fixture endpoint");
        let endpoint = format!("http://{}/token", listener.local_addr().expect("address"));
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (client, _) = listener.accept().expect("bounded refresh reached fixture");
            accepted_tx.send(()).expect("accepted event");
            release_rx.recv().expect("release fixture");
            drop(client);
        });
        let stopped = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&stopped);
        let stop_thread = std::thread::spawn(move || {
            accepted_rx
                .recv_timeout(Duration::from_secs(120))
                .expect("refresh start event");
            signal.store(true, Ordering::Release);
        });
        let guard = try_lock(home.path(), "alpha").expect("door guard");
        let error = door_authority_under_lock(
            home.path(),
            "alpha",
            &endpoint,
            Instant::now() + Duration::from_secs(30),
            &|| stopped.load(Ordering::Acquire),
        )
        .err()
        .expect("controlled stop refuses refresh");
        assert_eq!(error.kind, "credential-door-timeout");
        stop_thread.join().expect("stop event delivered");
        drop(guard);
        let next = try_lock(home.path(), "alpha").expect("owned child reaped before release");
        drop(next);
        release_tx.send(()).expect("release peer");
        server.join().expect("held peer exited");
        assert_eq!(
            read_source(home.path(), "alpha")
                .expect("old source")
                .document,
            source(now + 300, "due")
        );
    }

    /// ´test:unit:door-projection-refuses-insufficient-access-lifetime´
    #[test]
    fn door_projection_refuses_insufficient_access_lifetime() {
        let now = now_seconds().expect("fixture clock");
        let refused = door_lifetime(now + 10, Instant::now() + Duration::from_secs(30), &|| {
            false
        })
        .expect_err("call could outlive access authority");
        assert_eq!(refused.kind, "credential-door-lifetime");
    }

    /// ´test:unit:credential-one-refusing-run-does-not-starve-peer´
    #[test]
    fn credential_one_refusing_run_does_not_starve_peer() {
        let temp = fixture_root();
        fixture_sign_in(temp.path(), &source(1_900_000_000, "initial"));
        let runs = temp.path().join("runs");
        fs::create_dir(&runs).expect("runs");
        fixture_run(&runs, "pilot-1", 3001);
        fixture_run(&runs, "pilot-2", 3002);
        let mut published = BTreeMap::new();
        let mut recipients = Vec::new();
        let report = refresh_live_at(
            temp.path(),
            "alpha",
            &runs,
            "http://127.0.0.1:1",
            1_800_000_000,
            &mut published,
            |_home, uid, _source| {
                if uid == 3001 {
                    return Err(failure("credential-publish", "worker home mode changed"));
                }
                recipients.push(uid);
                Ok(())
            },
        )
        .expect("peer still receives publication");
        assert!(report.changed);
        assert_eq!(recipients, vec![3002]);
        assert_eq!(report.refusals.len(), 1);
        assert_eq!(report.refusals[0]["run"], "pilot-1");
        assert_eq!(report.refusals[0]["kind"], "credential-publish");
    }

    /// ´test:unit:credential-preflight-rejects-malformed-pinned-fields´
    #[test]
    fn credential_preflight_rejects_malformed_pinned_fields() {
        let temp = fixture_root();
        for (field, value) in [
            ("last_refresh", json!("yesterday")),
            ("last_refresh", json!("2026-02-30T00:00:00Z")),
            ("id_token", json!("not-a-jwt")),
            ("id_token", json!("header.bad-payload.signature")),
        ] {
            let mut malformed = source(1_900_000_000, "initial");
            if field == "id_token" {
                malformed["tokens"][field] = value;
            } else {
                malformed[field] = value;
            }
            fixture_sign_in(temp.path(), &malformed);
            assert_eq!(
                preflight_at(temp.path(), "alpha", "http://127.0.0.1:1", 1_800_000_000)
                    .expect_err("pinned parser rejects malformed field")
                    .kind,
                "credential-sign-in"
            );
        }
    }

    /// ´test:unit:credential-preflight-rejects-pinned-id-claim-types´
    #[test]
    fn credential_preflight_rejects_pinned_id_claim_types() {
        let temp = fixture_root();
        for claims in [
            json!({"email": 7}),
            json!({"https://api.openai.com/profile": {"email": false}}),
            json!({"https://api.openai.com/auth": {"chatgpt_plan_type": 7}}),
            json!({"https://api.openai.com/auth": {"chatgpt_user_id": false}}),
            json!({"https://api.openai.com/auth": {"user_id": 7}}),
            json!({"https://api.openai.com/auth": {"chatgpt_account_id": 7}}),
            json!({"https://api.openai.com/auth": {"chatgpt_account_is_fedramp": "false"}}),
        ] {
            let mut malformed = source(1_900_000_000, "initial");
            malformed["tokens"]["id_token"] = json!(format!(
                "header.{}.signature",
                encoded(claims.to_string().as_bytes())
            ));
            fixture_sign_in(temp.path(), &malformed);
            assert_eq!(
                preflight_at(temp.path(), "alpha", "http://127.0.0.1:1", 1_800_000_000)
                    .expect_err("typed claim preflight")
                    .kind,
                "credential-sign-in"
            );
        }
    }

    /// ´test:unit:credential-preflight-rejects-malformed-token-encoding´
    #[test]
    fn credential_preflight_rejects_malformed_token_encoding() {
        let temp = fixture_root();
        for payload in [
            format!("{}A", encoded(b"{ }")),
            "e31".to_owned(),
            "e30=".to_owned(),
        ] {
            let mut malformed = source(1_900_000_000, "initial");
            malformed["tokens"]["id_token"] = json!(format!("header.{payload}.signature"));
            fixture_sign_in(temp.path(), &malformed);
            assert_eq!(
                preflight_at(temp.path(), "alpha", "http://127.0.0.1:1", 1_800_000_000)
                    .expect_err("pinned base64url decoder rejects malformed token")
                    .kind,
                "credential-sign-in"
            );
        }
    }
}
