//! Owner-side authority for one loop's Codex access credentials.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat};
use serde_json::{Value, json};

use crate::error::LaneError;

const AUTH_HOST: &str = "auth.openai.com";
const AUTH_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
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

fn utc_timestamp() -> Result<String, LaneError> {
    let output = Command::new("/usr/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .map_err(|_| failure("credential-clock", "UTC date program could not start"))?;
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
    let path = sign_in_dir(owner_home, loop_name);
    let owner = owner_identity().0;
    let dir = open_dir(&path, owner, owner, 0o700)?;
    let file = openat2(
        &dir,
        "auth.json",
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
    let mut source = Source::parse(document)?;
    source.stamp = Some(FileStamp::from_stat(&stat));
    Ok(source)
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
    validate_evidence(document)?;
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

fn validate_evidence(document: &Value) -> Result<(), LaneError> {
    if document["schema"] != 1
        || document["host"] != REFRESH_HOST
        || !matches!(
            document["state"].as_str(),
            Some("current" | "published" | "partial" | "refused")
        )
    {
        return Err(failure(
            "credential-evidence",
            "schema, host or state is invalid",
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
    if document["schema"] != 1
        || document["host"] != REFRESH_HOST
        || !matches!(
            document["state"].as_str(),
            Some("current" | "published" | "partial" | "refused")
        )
        || !document["run_refusals"].is_array()
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

fn refresh_request(source: &Source, endpoint: &str) -> Result<Source, LaneError> {
    let body = json!({
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": source.document["tokens"]["refresh_token"]
    });
    let mut child = Command::new("/usr/bin/curl")
        .args([
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            "20",
            "--max-filesize",
            "65536",
            "--noproxy",
            "*",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure("credential-refresh", "token client could not start"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| failure("credential-refresh", "token client input is absent"))?
        .write_all(body.to_string().as_bytes())
        .map_err(|_| failure("credential-refresh", "token request could not be sent"))?;
    let output = child
        .wait_with_output()
        .map_err(|_| failure("credential-refresh", "token request could not complete"))?;
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
    next["last_refresh"] = json!(utc_timestamp()?);
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
    let source = read_source(owner_home, loop_name)?;
    if !source.needs_refresh(now) {
        return Ok(source);
    }
    let expected = source
        .stamp
        .ok_or_else(|| failure("credential-sign-in", "source identity is absent"))?;
    let next = refresh_request(&source, endpoint)?;
    let current = read_source(owner_home, loop_name)?;
    if current.stamp != Some(expected) {
        return Ok(current);
    }
    before_publish();
    if publish_owner(owner_home, loop_name, &next, expected)? {
        Ok(next)
    } else {
        read_source(owner_home, loop_name)
    }
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
) -> Result<(), LaneError> {
    let _guard = lock(owner_home, loop_name)?;
    let source = refresh_if_due(owner_home, loop_name, AUTH_ENDPOINT, now_seconds()?)?;
    write_run(run_home, worker_uid, &source)
}

/// Republish the current owner source synchronously before a round can start.
///
/// # Errors
///
/// Refuses unavailable authority, unsafe custody or failed publication and clock evidence.
pub(crate) fn publish_round(
    owner_home: &Path,
    loop_name: &str,
    run_home: &Path,
    worker_uid: u32,
) -> Result<Value, LaneError> {
    let _guard = lock(owner_home, loop_name)?;
    let _refreshed = refresh_if_due(owner_home, loop_name, AUTH_ENDPOINT, now_seconds()?)?;
    // Reopen after a refresh so the evidence identifies the published owner inode.
    let source = read_source(owner_home, loop_name)?;
    let stamp = source
        .stamp
        .ok_or_else(|| failure("credential-publish", "source inode is absent"))?;
    write_run(run_home, worker_uid, &source)?;
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
pub fn preflight(owner_home: &Path, loop_name: &str) -> Result<(), LaneError> {
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

/// Shape the result of one helper check for protected owner evidence.
pub(crate) fn evidence_for_check(
    result: &Result<RefreshReport, LaneError>,
    first_check: bool,
) -> Option<Value> {
    match result {
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
    }
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
pub(crate) fn refresh_live(
    owner_home: &Path,
    loop_name: &str,
    runs_root: &Path,
    published: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<RefreshReport, LaneError> {
    refresh_live_at(
        owner_home,
        loop_name,
        runs_root,
        AUTH_ENDPOINT,
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
    let snapshot = next.worker_file();
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
        let Some(home) = record["plan"]["home"].as_str() else {
            return Err(failure("credential-publish", "live run home is absent"));
        };
        let uid = record["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| failure("credential-publish", "live worker uid is absent"))?;
        let home = PathBuf::from(home);
        if published.get(&home) == Some(&snapshot) {
            continue;
        }
        if let Err(error) = publish(&home, uid, &next) {
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
        published.insert(home, snapshot.clone());
        changed = true;
    }
    Ok(RefreshReport {
        changed,
        refusals,
        refusals_omitted,
        expires_unix: next.expires_at,
        refresh_due_unix: next.refresh_due_unix(),
        authority_failure: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
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
        let mut record = json!({"worker_uid":Uid::effective().as_raw(),"plan":{"home":run_home},"active_round":"dispatch","rounds":[{"step":"dispatch"}]});
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        crate::container_helper::publish_round_credential(home, "alpha", &mut record)
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
        crate::container_helper::publish_round_credential(home, "alpha", &mut record)
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

    fn fixture_endpoint(status: &str, response: Value) -> (String, std::thread::JoinHandle<Value>) {
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
            "plan": {"home": runs.join(format!("home-{run}"))}
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
        let evidence = evidence_for_check(&Ok(fixture_report(1_900_000_000)), true)
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
        let evidence = evidence_for_check(&Ok(report), true).expect("first check publishes");
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
                read_evidence(&held, "R", owner).expect("temporal defect is observable"),
                Some(EvidenceObservation::Current(malformed.clone()))
            );
            let error = publish_evidence(&driver, &malformed)
                .expect_err("writer still refuses malformed instant");
            assert_eq!(error.status, 2);
            assert!(error.detail.contains(named), "{}", error.line());
        }
        let refusal = failure("credential-sign-in", "source cannot be read");
        let failed_check: Result<RefreshReport, LaneError> = Err(refusal);
        let refused = evidence_for_check(&failed_check, false).expect("error evidence");
        assert_eq!(refused["expires_unix"], Value::Null);
        assert_eq!(refused["refresh_due_unix"], Value::Null);
        publish_evidence(&driver, &refused).expect("refusal replaces prior measurement");
        assert_eq!(
            read_evidence(&held, "R", owner).expect("refused evidence"),
            Some(EvidenceObservation::Current(refused))
        );
        let checked = failed_check.is_ok();
        let recovered_check = Ok(fixture_report(expires));
        let recovered = evidence_for_check(&recovered_check, !checked)
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
        let evidence = evidence_for_check(&Ok(report), false).expect("run refusals publish");
        publish_evidence(&driver, &evidence).expect("bounded evidence publication");
        let held: OwnedFd = File::open(&runs).expect("held runs root").into();
        assert_eq!(
            read_evidence(&held, "R0", Uid::effective().as_raw()).expect("bounded reader"),
            Some(EvidenceObservation::Current(evidence))
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
