//! Carry settled replies through a fresh letter when the old worker yields.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{Uid, UnlinkatFlags, dup, unlinkat};
use serde_json::{Value, json};

use super::checkout;
use super::{LaunchRequest, MAX_RESERVATION_BYTES};
#[cfg(test)]
use super::{lock_mailbox, publish_reservation, read_reservation, reservation_path};
use crate::{build, error::LaneError, home, load_plan, valid_run_name};

const MAX_ROTATION_ATTEMPTS: usize = 8;
static NEXT_INTENT_PUBLICATION: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static FAIL_INTENT_SYNC_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REPLACE_INTENT_AFTER_PUBLICATION_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_SOURCE_UNLINK_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug)]
struct IntentPublication {
    intent: Value,
    identity: String,
    sync_error: Option<LaneError>,
}

struct PreparedIntent {
    intent: Value,
    attempt_instant: u64,
}

fn intent_stage_failure(
    root: &OwnedFd,
    temporary: &str,
    step: &str,
    error: impl std::fmt::Display,
) -> LaneError {
    match unlinkat(root, temporary, UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => {
            LaneError::operation("rotate-record", format!("{step}: {error}"))
        }
        Err(cleanup) => LaneError::operation(
            "rotate-record",
            format!("{step}: {error}; temporary-residue={temporary} cleanup={cleanup}"),
        ),
    }
}

struct RotationStore<'a> {
    runs: &'a OwnedFd,
    owner: u32,
}

impl RotationStore<'_> {
    #[cfg(test)]
    fn identity(&self, run: &str) -> Result<String, LaneError> {
        checkout::read_record_bound(self.runs, run, self.owner).map(|(_, identity)| identity)
    }

    fn read(&self, run: &str) -> Result<Option<Value>, LaneError> {
        let name = format!(".reservation-{run}.json");
        match openat2(
            self.runs,
            name.as_str(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(error) => Err(LaneError::input(
                "rotate-record",
                format!("{name}: {error}"),
            )),
            Ok(fd) => {
                drop(fd);
                checkout::read_record(self.runs, run, self.owner).map(Some)
            }
        }
    }

    fn required(&self, run: &str) -> Result<Value, LaneError> {
        self.read(run)?.ok_or_else(|| {
            LaneError::input("rotate-record", format!("{run} reservation is absent"))
        })
    }

    fn bound(&self, run: &str, expected_identity: &str) -> Result<Value, LaneError> {
        let (record, identity) = checkout::read_record_bound(self.runs, run, self.owner)?;
        if identity != expected_identity {
            return Err(LaneError::input(
                "rotate-record",
                "reservation identity differs from the handover read",
            ));
        }
        validate_rotation_attempts(&record)?;
        Ok(record)
    }

    fn publish(&self, run: &str, record: &Value) -> Result<(), LaneError> {
        checkout::publish_record(self.runs, run, record, "rotation")
    }

    // The held temporary file supplies the identity of the inode actually renamed.
    fn publish_intent(
        &self,
        run: &str,
        record: &Value,
    ) -> Result<(String, Option<LaneError>), LaneError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| LaneError::input("rotate-record", error.to_string()))?;
        if bytes.len() as u64 > MAX_RESERVATION_BYTES {
            return Err(LaneError::input(
                "rotate-record",
                "reservation exceeds reader bound",
            ));
        }
        let (temporary, fd) = loop {
            let number = NEXT_INTENT_PUBLICATION.fetch_add(1, Ordering::Relaxed);
            let temporary = format!(
                ".reservation-{run}-rotation-{}-{number}.tmp",
                std::process::id()
            );
            match openat2(
                self.runs,
                temporary.as_str(),
                OpenHow::new()
                    .flags(
                        OFlag::O_WRONLY
                            | OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                    )
                    .mode(nix::sys::stat::Mode::from_bits_truncate(0o600))
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            ) {
                Ok(fd) => break (temporary, fd),
                Err(nix::errno::Errno::EEXIST) => {}
                Err(error) => return Err(LaneError::operation("rotate-record", error.to_string())),
            }
        };
        let mut file: File = fd.into();
        file.write_all(&bytes)
            .map_err(|error| intent_stage_failure(self.runs, &temporary, "write", error))?;
        file.sync_all()
            .map_err(|error| intent_stage_failure(self.runs, &temporary, "sync", error))?;
        let stat = fstat(&file)
            .map_err(|error| intent_stage_failure(self.runs, &temporary, "stat", error))?;
        if stat.st_uid != self.owner
            || stat.st_mode & 0o7777 != 0o600
            || SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
            || usize::try_from(stat.st_size).ok() != Some(bytes.len())
        {
            return Err(intent_stage_failure(
                self.runs,
                &temporary,
                "stat",
                "temporary owner, mode, size, or type differs",
            ));
        }
        let digest = build::sha256_bytes(&bytes, Path::new("/"))
            .map_err(|error| intent_stage_failure(self.runs, &temporary, "digest", error))?;
        let identity = format!("{}:{}:{digest}", stat.st_dev, stat.st_ino);
        renameat2(
            self.runs,
            temporary.as_str(),
            self.runs,
            format!(".reservation-{run}.json").as_str(),
            RenameFlags::empty(),
        )
        .map_err(|error| intent_stage_failure(self.runs, &temporary, "rename", error))?;
        #[cfg(test)]
        let injected_sync = FAIL_INTENT_SYNC_ONCE.with(|flag| flag.replace(false));
        #[cfg(not(test))]
        let injected_sync = false;
        let sync_error = if injected_sync {
            Some(LaneError::operation(
                "rotate-record",
                "intent directory sync injected failure",
            ))
        } else {
            match dup(self.runs) {
                Ok(directory) => File::from(directory).sync_all().err().map(|error| {
                    LaneError::operation("rotate-record", format!("intent directory sync: {error}"))
                }),
                Err(error) => Some(LaneError::operation(
                    "rotate-record",
                    format!("intent directory descriptor: {error}"),
                )),
            }
        };
        #[cfg(test)]
        if REPLACE_INTENT_AFTER_PUBLICATION_ONCE.with(|flag| flag.replace(false))
            && let Err(error) = checkout::publish_record(self.runs, run, record, "fixture-rotation")
        {
            return Ok((identity, Some(error)));
        }
        Ok((identity, sync_error))
    }

    fn lock(&self, run: &str) -> Result<nix::fcntl::Flock<File>, LaneError> {
        super::lock_mailbox_at(self.runs, run, self.owner)
    }
}

#[cfg(test)]
fn with_test_store<T>(root: &Path, action: impl FnOnce(&RotationStore<'_>) -> T) -> T {
    let runs: OwnedFd = File::open(root).expect("fixture runs root").into();
    action(&RotationStore {
        runs: &runs,
        owner: Uid::effective().as_raw(),
    })
}

#[derive(Debug)]
pub struct RotateRequest {
    pub loop_name: String,
    pub run: String,
    pub dry_run: bool,
    pub force: Option<String>,
    pub expect_digest: Option<String>,
    pub next: Option<PathBuf>,
}

impl RotateRequest {
    /// Parse a rotation that binds its handover digest or records a force reason.
    ///
    /// # Errors
    ///
    /// Refuses repeated options, malformed digests and an empty force reason.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "rotate-usage",
                "rotate LOOP RUN [--dry-run] [--expect-digest HEX] [--force REASON] [--next FILE]",
            ));
        };
        if !valid_run_name(run) {
            return Err(LaneError::input(
                "rotate-run",
                "run name is not a plain word",
            ));
        }
        let mut dry_run = false;
        let mut force = None;
        let mut expect_digest = None;
        let mut next = None;
        let mut index = 0;
        while index < rest.len() {
            match rest[index].as_str() {
                "--dry-run" if !dry_run => dry_run = true,
                "--force" if force.is_none() => {
                    let reason = rest.get(index + 1).ok_or_else(|| {
                        LaneError::input("rotate-usage", "--force needs a reason")
                    })?;
                    if reason.trim().is_empty() || reason.len() > 256 {
                        return Err(LaneError::input(
                            "rotate-force",
                            "force reason must have 1 through 256 bytes",
                        ));
                    }
                    force = Some(reason.clone());
                    index += 1;
                }
                "--expect-digest" if expect_digest.is_none() => {
                    let digest = rest.get(index + 1).ok_or_else(|| {
                        LaneError::input("rotate-usage", "--expect-digest needs a SHA-256 digest")
                    })?;
                    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(LaneError::input(
                            "rotate-handover",
                            "expected digest must be 64 hexadecimal digits",
                        ));
                    }
                    expect_digest = Some(digest.to_ascii_lowercase());
                    index += 1;
                }
                "--next" if next.is_none() => {
                    let path = rest
                        .get(index + 1)
                        .ok_or_else(|| LaneError::input("rotate-usage", "--next needs a file"))?;
                    next = Some(PathBuf::from(path));
                    index += 1;
                }
                _ => {
                    return Err(LaneError::input(
                        "rotate-usage",
                        "unexpected or repeated option",
                    ));
                }
            }
            index += 1;
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            dry_run,
            force,
            expect_digest,
            next,
        })
    }
}

/// Build the exact private handover form consumed by the binary entry.
///
/// # Errors
///
/// Refuses an owner home or runs root that cannot be passed as a path word.
pub fn private_handover_argv(
    loop_name: &str,
    run: &str,
    owner_home: &Path,
    runs_root: &Path,
    record_identity: &str,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_rotation-handover".into(),
        loop_name.into(),
        run.into(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--runs-root".into(),
        crate::pinned::path_word(runs_root, "runs-root")?,
        "--record-identity".into(),
        record_identity.into(),
    ])
}

/// Parse the private handover form before namespace entry and at dispatch.
///
/// # Errors
///
/// Refuses a changed word order, missing field, or non-absolute directory.
pub fn parse_private_handover_argv(
    args: &[String],
) -> Result<(&str, &str, &Path, &Path, &str), LaneError> {
    let [
        command,
        loop_name,
        run,
        home_flag,
        owner_home,
        root_flag,
        runs_root,
        identity_flag,
        identity,
    ] = args
    else {
        return Err(LaneError::input(
            "rotate-private",
            "private handover form is incomplete",
        ));
    };
    if command != "_rotation-handover"
        || home_flag != "--owner-home"
        || root_flag != "--runs-root"
        || identity_flag != "--record-identity"
        || !Path::new(owner_home).is_absolute()
        || !Path::new(runs_root).is_absolute()
        || identity.is_empty()
    {
        return Err(LaneError::input(
            "rotate-private",
            "private handover form is malformed",
        ));
    }
    Ok((
        loop_name,
        run,
        Path::new(owner_home),
        Path::new(runs_root),
        identity,
    ))
}

fn next_name(store: &RotationStore<'_>, old: &str) -> Result<(u64, String), LaneError> {
    for index in 1..=10_000 {
        let candidate = format!("{old}-rotation-{index}");
        if !valid_run_name(&candidate) {
            return Err(LaneError::input(
                "rotate-name",
                "rotation name exceeds the run name bound",
            ));
        }
        if store.read(&candidate)?.is_none() {
            return Ok((index, candidate));
        }
    }
    Err(LaneError::input(
        "rotate-name",
        "rotation indexes are exhausted",
    ))
}

fn stop_for_last_round(record: &Value) -> Result<Value, LaneError> {
    let last = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("rotate-stop", "last settled round is absent"))?;
    if last["phase"] != "settled" || last["ended_by"] != "by-report-after-stop" {
        return Err(LaneError::input(
            "rotate-stop",
            "last round did not report after stop",
        ));
    }
    last["step"]
        .as_str()
        .and_then(|step| super::steering::stop_brief(record, step))
        .cloned()
        .ok_or_else(|| LaneError::input("rotate-stop", "last round has no verified stop brief"))
}

fn pending_message(intent: &Value) -> String {
    format!(
        "rotation intent index={} new_run={} reason={} at_unix_ns={} handover_sha256={} has no run reservation",
        intent["index"],
        intent["new_run"],
        intent["reason"],
        intent["at_unix_ns"],
        intent["letter_sha256"]
    )
}

fn validate_old_snapshot(old: &Value, intent: &Value) -> Result<(), LaneError> {
    let rounds = old["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-record", "old rounds are absent"))?;
    let last = rounds
        .last()
        .ok_or_else(|| LaneError::input("rotate-record", "old settled round is absent"))?;
    if old["phase"] != "settled"
        || last["phase"] != "settled"
        || json!(rounds.len()) != intent["round_count"]
        || last["step"] != intent["settled_step"]
        || last["reply"]["sha256"] != intent["reply_sha256"]
    {
        return Err(LaneError::input(
            "rotate-record",
            "old settled step or reply digest changed after intent",
        ));
    }
    Ok(())
}

fn validate_new_handover(
    old: &Value,
    new: &Value,
    intent: &Value,
    name: &str,
) -> Result<(), LaneError> {
    if new["schema"] != 1
        || new["run"] != name
        || new["loop"] != old["loop"]
        || new["letter_source"] != intent["letter_source"]
        || new["worker_uid"].as_u64().is_none()
        || old["worker_uid"].as_u64().is_none()
        || new["worker_uid"] == old["worker_uid"]
    {
        return Err(LaneError::input(
            "rotate-record",
            "new reservation differs from rotation intent",
        ));
    }
    if new["initial_brief"]["name"] != "brief.txt"
        || new["initial_brief"]["step"] != "dispatch"
        || new["initial_brief"]["state"] != "placed"
        || new["initial_brief"]["sha256"] != intent["letter_sha256"]
    {
        return Err(LaneError::input(
            "rotate-pending",
            format!("{name} handover letter is not placed with the intent digest"),
        ));
    }
    if new["phase"] != "settled"
        || new["rounds"][0]["step"] != "dispatch"
        || new["rounds"][0]["phase"] != "settled"
        || !new["rounds"][0]["reply"]["sha256"].is_string()
    {
        return Err(LaneError::input(
            "rotate-pending",
            format!("{name} dispatch is not settled; phase={}", new["phase"]),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_rotation_record(rotation: &Value) -> Result<(), LaneError> {
    let fields = rotation
        .as_object()
        .ok_or_else(|| LaneError::input("rotate-record", "rotation record is not an object"))?;
    for key in [
        "old_run",
        "new_run",
        "context",
        "threshold",
        "force_reason",
        "digest_override_reason",
        "stop_letter",
        "replies",
        "inbox_letters",
        "next_task",
    ] {
        if !fields.contains_key(key) {
            return Err(LaneError::input(
                "rotate-record",
                format!("rotation key {key} is absent; record predates it"),
            ));
        }
    }
    if !rotation["old_run"].is_string()
        || !rotation["new_run"].is_string()
        || !rotation["context"].is_object()
        || !(rotation["threshold"].is_null() || rotation["threshold"].is_number())
        || !(rotation["force_reason"].is_null() || rotation["force_reason"].is_string())
        || !(rotation["digest_override_reason"].is_null()
            || rotation["digest_override_reason"].is_string())
    {
        return Err(LaneError::input(
            "rotate-record",
            "rotation identity or option type differs",
        ));
    }
    let stop = rotation["stop_letter"]
        .as_object()
        .ok_or_else(|| LaneError::input("rotate-record", "stop letter is not an object"))?;
    if !stop.contains_key("name")
        || !stop.contains_key("placed_at_unix_ns")
        || !rotation["stop_letter"]["name"].is_string()
        || !rotation["stop_letter"]["placed_at_unix_ns"].is_u64()
    {
        return Err(LaneError::input(
            "rotate-record",
            "stop letter fields are absent or malformed",
        ));
    }
    let replies = rotation["replies"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-record", "reply list is not an array"))?;
    let mut expected_inbox = Vec::new();
    for reply in replies {
        let Some(row) = reply.as_object() else {
            return Err(LaneError::input(
                "rotate-record",
                "reply row is not an object",
            ));
        };
        if ["step", "outbox", "sha256", "inbox"]
            .iter()
            .any(|key| !row.contains_key(*key))
            || !reply["step"].is_string()
            || !reply["outbox"].is_string()
            || !reply["sha256"].is_string()
            || !reply["inbox"].is_array()
        {
            return Err(LaneError::input(
                "rotate-record",
                "reply row fields are absent or malformed",
            ));
        }
        for name in reply["inbox"]
            .as_array()
            .ok_or_else(|| LaneError::input("rotate-record", "reply inbox names are absent"))?
        {
            let name = name
                .as_str()
                .ok_or_else(|| LaneError::input("rotate-record", "reply inbox name is not text"))?;
            expected_inbox.push((
                reply["step"].as_str().unwrap_or_default().to_owned(),
                name.to_owned(),
            ));
        }
    }
    let carried = rotation["inbox_letters"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-record", "carried inbox list is not an array"))?;
    let mut actual_inbox = Vec::new();
    for entry in carried {
        let Some(row) = entry.as_object() else {
            return Err(LaneError::input(
                "rotate-record",
                "carried inbox row is not an object",
            ));
        };
        if ["step", "name", "sha256"]
            .iter()
            .any(|key| !row.contains_key(*key))
            || !entry["step"].is_string()
            || !entry["name"].is_string()
            || !entry["sha256"].is_string()
        {
            return Err(LaneError::input(
                "rotate-record",
                "carried inbox fields are absent or malformed",
            ));
        }
        actual_inbox.push((
            entry["step"].as_str().unwrap_or_default().to_owned(),
            entry["name"].as_str().unwrap_or_default().to_owned(),
        ));
    }
    expected_inbox.sort();
    actual_inbox.sort();
    if expected_inbox != actual_inbox {
        return Err(LaneError::input(
            "rotate-record",
            "carried inbox list differs from reply names",
        ));
    }
    let next = rotation["next_task"]
        .as_object()
        .ok_or_else(|| LaneError::input("rotate-record", "next task is not an object"))?;
    if !next.contains_key("state") || !next.contains_key("sha256") {
        return Err(LaneError::input(
            "rotate-record",
            "next task fields are absent; record predates them",
        ));
    }
    match next["state"].as_str() {
        Some("absent") if next["sha256"].is_null() => Ok(()),
        Some("present") if next["sha256"].is_string() => Ok(()),
        _ => Err(LaneError::input(
            "rotate-record",
            "next task state and digest contradict",
        )),
    }
}

fn validate_links(old: &Value, new: &Value, intent: &Value) -> Result<(), LaneError> {
    let rotation = &intent["rotation"];
    validate_rotation_record(rotation)?;
    if old["rotation"].is_object() {
        validate_rotation_record(&old["rotation"])?;
    }
    if new["rotation"].is_object() {
        validate_rotation_record(&new["rotation"])?;
    }
    if (new["rotation"].is_object() && new["rotation"] != *rotation)
        || (old["rotation"].is_object() && old["rotation"] != *rotation)
    {
        return Err(LaneError::input(
            "rotate-record",
            "existing rotation link differs from intent",
        ));
    }
    Ok(())
}

fn intent_name<'a>(old_run: &str, intent: &'a Value) -> Result<&'a str, LaneError> {
    validate_rotation_record(&intent["rotation"])?;
    let name = intent["new_run"]
        .as_str()
        .filter(|name| valid_run_name(name))
        .ok_or_else(|| LaneError::input("rotate-pending", "intent has no valid new run name"))?;
    if intent["index"].as_u64().is_none()
        || intent["rotation"]["old_run"] != old_run
        || intent["rotation"]["new_run"] != name
    {
        return Err(LaneError::input(
            "rotate-pending",
            "intent link identity is malformed",
        ));
    }
    Ok(name)
}

fn preview_intent(
    root: &Path,
    store: &RotationStore<'_>,
    old_run: &str,
    expected_identity: &str,
    intent: &Value,
    owner: u32,
) -> Result<Value, LaneError> {
    let name = intent_name(old_run, intent)?;
    let old = store.bound(old_run, expected_identity)?;
    if old["rotation_intent"] != *intent {
        return Err(LaneError::input(
            "rotate-pending",
            "rotation intent changed",
        ));
    }
    validate_old_snapshot(&old, intent)?;
    let new = store
        .read(name)?
        .ok_or_else(|| LaneError::input("rotate-pending", pending_message(intent)))?;
    validate_new_handover(&old, &new, intent, name)?;
    validate_links(&old, &new, intent)?;
    let source = Path::new(intent["letter_source"].as_str().ok_or_else(|| {
        LaneError::input("rotate-pending", "intent handover letter path is absent")
    })?);
    let letter_matches_intent = match std::fs::symlink_metadata(source) {
        Ok(_) => {
            let bytes = home::read_letter(source, owner)?;
            build::sha256_bytes(&bytes, root)? == intent["letter_sha256"]
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(LaneError::input("rotate-pending", error.to_string())),
    };
    Ok(
        json!({"schema":1,"command":"rotate","dry_run":true,"old_run":old_run,"new_run":name,"intent":intent,"handover_sha256":intent["letter_sha256"],"handover_letter_matches_intent":letter_matches_intent,"new_run_exists":true,"new_run_complete":true,"would_link_old":!old["rotation"].is_object(),"would_link_new":!new["rotation"].is_object(),"changed":false}),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn publish_intent(
    root: &Path,
    old_run: &str,
    expected: &Value,
    reason: Option<&str>,
    rotation: &Value,
    config: &Path,
    letter_digest: &str,
    _owner: u32,
) -> Result<Value, LaneError> {
    with_test_store(root, |store| {
        let mailbox = store.lock(old_run)?;
        let identity = store.identity(old_run)?;
        publish_intent_locked(
            root,
            store,
            &identity,
            old_run,
            expected,
            reason,
            rotation,
            config,
            None,
            letter_digest,
            &mailbox,
        )
        .map(|published| published.intent)
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_intent_locked(
    store: &RotationStore<'_>,
    expected_identity: &str,
    old_run: &str,
    expected: &Value,
    reason: Option<&str>,
    rotation: &Value,
    config: &Path,
    letter_digest: &str,
    instant: u64,
    _mailbox: &nix::fcntl::Flock<File>,
) -> Result<PreparedIntent, LaneError> {
    validate_rotation_record(rotation)?;
    let current = store.bound(old_run, expected_identity)?;
    if current["rotation_intent"].is_object() {
        return Err(LaneError::input(
            "rotate-pending",
            format!(
                "rotation intent already names {}",
                current["rotation_intent"]["new_run"]
            ),
        ));
    }
    if current != *expected
        || current["rotation"].is_object()
        || current["phase"] != "settled"
        || current["rounds"] != expected["rounds"]
    {
        return Err(LaneError::input(
            "rotate-record",
            "old round or rotation changed before intent",
        ));
    }
    let rounds = current["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-record", "old rounds are absent"))?;
    let last = rounds
        .last()
        .ok_or_else(|| LaneError::input("rotate-record", "old settled round is absent"))?;
    let step = last["step"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-record", "old settled step is absent"))?;
    let reply_digest = last["reply"]["sha256"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-record", "old reply digest is absent"))?;
    let (index, new_run) = next_name(store, old_run)?;
    let source = config.join(format!("handover-{new_run}.md"));
    let mut linked = rotation.clone();
    linked["new_run"] = json!(new_run);
    let intent = json!({"index":index,"new_run":new_run,"reason":reason,"at_unix_ns":instant,"letter_source":source,"letter_sha256":letter_digest,"round_count":rounds.len(),"settled_step":step,"reply_sha256":reply_digest,"rotation":linked});
    // A control byte expands to six JSON bytes. Reserve the largest serialized
    // attempt the bounded writer can produce, including a staged source name.
    let worst_case = json!({"new_run":new_run,"refusal":"x".repeat(256),"detail":"\u{0000}".repeat(256),"at_unix_ns":u64::MAX,"expected_sha256":letter_digest,"actual_sha256":"f".repeat(64),"source_residue":{"name":"x".repeat(128),"step":"x".repeat(256),"errno":i32::MIN}});
    for with_intent in [false, true] {
        let mut reserved = current.clone();
        if with_intent {
            reserved["rotation_intent"] = intent.clone();
        }
        // A source created after this check can reuse an absent residue name.
        // Reserve using only entries with no residue, whose status cannot change.
        append_attempt_value(&mut reserved, worst_case.clone(), None).map_err(|error| {
            if matches!(
                error.kind,
                "rotation-attempt-size" | "rotation-attempt-residue"
            ) {
                LaneError::input("rotate-intent-reserve", error.detail)
            } else {
                error
            }
        })?;
    }
    Ok(PreparedIntent {
        intent,
        attempt_instant: instant,
    })
}

fn publish_prepared_intent_locked(
    store: &RotationStore<'_>,
    expected_identity: &str,
    old_run: &str,
    expected: &Value,
    prepared: &PreparedIntent,
) -> Result<IntentPublication, LaneError> {
    let mut current = store.bound(old_run, expected_identity)?;
    if current != *expected || current["rotation_intent"].is_object() {
        return Err(LaneError::input(
            "rotate-record",
            "old reservation changed before prepared intent publication",
        ));
    }
    current["rotation_intent"] = prepared.intent.clone();
    let (identity, sync_error) = store.publish_intent(old_run, &current)?;
    Ok(IntentPublication {
        intent: prepared.intent.clone(),
        identity,
        sync_error,
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn publish_intent_locked(
    _root: &Path,
    store: &RotationStore<'_>,
    expected_identity: &str,
    old_run: &str,
    expected: &Value,
    reason: Option<&str>,
    rotation: &Value,
    config: &Path,
    _source_directory: Option<&dyn AsFd>,
    letter_digest: &str,
    mailbox: &nix::fcntl::Flock<File>,
) -> Result<IntentPublication, LaneError> {
    let instant = super::letters::unix_ns()?;
    let prepared = prepare_intent_locked(
        store,
        expected_identity,
        old_run,
        expected,
        reason,
        rotation,
        config,
        letter_digest,
        instant,
        mailbox,
    )?;
    publish_prepared_intent_locked(store, expected_identity, old_run, expected, &prepared)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn publish_checked_intent(
    root: &Path,
    old_run: &str,
    expected_record: &Value,
    reason: Option<&str>,
    expected_digest: Option<&str>,
    rotation: &Value,
    config: &Path,
    rendered_digest: &str,
    mailbox: &nix::fcntl::Flock<File>,
) -> Result<Value, LaneError> {
    require_handover_digest(rendered_digest, expected_digest, reason)?;
    with_test_store(root, |store| {
        let identity = store.identity(old_run)?;
        publish_intent_locked(
            root,
            store,
            &identity,
            old_run,
            expected_record,
            reason,
            rotation,
            config,
            None,
            rendered_digest,
            mailbox,
        )
        .map(|published| published.intent)
    })
}

fn require_handover_digest(
    rendered: &str,
    expected: Option<&str>,
    force: Option<&str>,
) -> Result<(), LaneError> {
    match expected {
        Some(expected) if expected != rendered => Err(LaneError::input(
            "rotate-handover",
            format!("expected digest {expected} differs from rendered digest {rendered}"),
        )),
        Some(_) => Ok(()),
        None if force.is_some() => Ok(()),
        None => Err(LaneError::input(
            "rotate-handover",
            format!("expected digest is required; rendered digest {rendered}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_rotation_failure_locked_at(
    store: &RotationStore<'_>,
    expected_identity: Option<&str>,
    old_run: &str,
    intent: Option<&Value>,
    new_run: &str,
    expected_digest: &str,
    error: &LaneError,
    residue: Option<&SourceResidue>,
    source_directory: Option<&dyn AsFd>,
    attempt_instant: u64,
    _mailbox: &nix::fcntl::Flock<File>,
) -> Result<(), LaneError> {
    if let Some(intent) = intent {
        validate_rotation_record(&intent["rotation"])?;
    }
    let mut old = if let Some(identity) = expected_identity {
        store.bound(old_run, identity)?
    } else {
        store.required(old_run)?
    };
    if let Some(intent) = intent {
        if old["rotation_intent"] != *intent {
            return Err(LaneError::input(
                "rotate-record",
                "rotation intent changed during refusal",
            ));
        }
        if let Some(new) = store.read(new_run)?
            && new["phase"] != "failed"
        {
            return Err(LaneError::input(
                "rotate-pending",
                format!(
                    "{new_run} has phase {}; rotation intent remains",
                    new["phase"]
                ),
            ));
        }
        old.as_object_mut()
            .ok_or_else(|| LaneError::input("rotate-record", "old reservation is not an object"))?
            .remove("rotation_intent");
    } else if old["rotation_intent"].is_object() {
        return Err(LaneError::input(
            "rotate-pending",
            "rotation intent appeared during refusal",
        ));
    }
    append_rotation_attempt(
        &mut old,
        new_run,
        expected_digest,
        error,
        residue,
        source_directory,
        attempt_instant,
    )?;
    store.publish(old_run, &old)
}

fn validate_rotation_attempts(old: &Value) -> Result<(), LaneError> {
    if let Some(prior) = old.get("rotation_attempts") {
        let prior = prior.as_array().ok_or_else(|| {
            LaneError::input("rotation-attempts", "attempt journal is not an array")
        })?;
        for entry in prior {
            let row = entry.as_object().ok_or_else(|| {
                LaneError::input("rotation-attempts", "attempt row is not an object")
            })?;
            for key in [
                "new_run",
                "refusal",
                "detail",
                "at_unix_ns",
                "expected_sha256",
                "actual_sha256",
                "source_residue",
            ] {
                if !row.contains_key(key) {
                    return Err(LaneError::input(
                        "rotation-attempts",
                        format!("attempt key {key} is absent; record predates it"),
                    ));
                }
            }
            if !entry["new_run"].is_string()
                || !entry["refusal"].is_string()
                || !entry["detail"].is_string()
                || !entry["at_unix_ns"].is_u64()
                || !entry["expected_sha256"].is_string()
                || !(entry["actual_sha256"].is_null() || entry["actual_sha256"].is_string())
            {
                return Err(LaneError::input(
                    "rotation-attempts",
                    "attempt field type differs",
                ));
            }
            if let Some(residue) = entry["source_residue"].as_object() {
                if ["name", "step", "errno"]
                    .iter()
                    .any(|key| !residue.contains_key(*key))
                    || !entry["source_residue"]["name"].is_string()
                    || !entry["source_residue"]["step"].is_string()
                    || !entry["source_residue"]["errno"].is_i64()
                    || !entry["source_residue"]["name"]
                        .as_str()
                        .is_some_and(|name| {
                            !name.is_empty()
                                && name.len() <= 128
                                && name.bytes().all(|byte| {
                                    byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)
                                })
                        })
                {
                    return Err(LaneError::input(
                        "rotation-attempts",
                        "source residue fields differ",
                    ));
                }
            } else if !entry["source_residue"].is_null() {
                return Err(LaneError::input(
                    "rotation-attempts",
                    "source residue is malformed",
                ));
            }
        }
    }
    Ok(())
}

fn append_rotation_attempt(
    old: &mut Value,
    new_run: &str,
    expected_digest: &str,
    error: &LaneError,
    residue: Option<&SourceResidue>,
    source_directory: Option<&dyn AsFd>,
    attempt_instant: u64,
) -> Result<(), LaneError> {
    validate_rotation_attempts(old)?;
    let actual_digest = error
        .detail
        .rsplit_once(" digest ")
        .map(|(_, digest)| digest)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let mut detail = String::new();
    for character in error.detail.chars() {
        detail.push(character);
        let escaped = serde_json::to_vec(&detail)
            .map_err(|error| LaneError::input("rotation-attempts", error.to_string()))?;
        if escaped.len() > 258 {
            detail.pop();
            break;
        }
    }
    let source_residue =
        residue.map(|entry| json!({"name":entry.name,"step":entry.step,"errno":entry.errno}));
    let attempt = json!({"new_run":new_run,"refusal":error.kind,"detail":detail,"at_unix_ns":attempt_instant,"expected_sha256":expected_digest,"actual_sha256":actual_digest,"source_residue":source_residue});
    append_attempt_value(old, attempt, source_directory)
}

fn residue_present(entry: &Value, source_directory: Option<&dyn AsFd>) -> Result<bool, LaneError> {
    let Some(residue) = entry["source_residue"].as_object() else {
        return Ok(false);
    };
    let Some(directory) = source_directory else {
        return Ok(true);
    };
    let name = residue["name"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotation-attempts", "source residue name is absent"))?;
    let opened = openat2(
        directory,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    );
    match opened {
        Ok(fd) => {
            fstat(&fd).map_err(|error| LaneError::input("rotation-attempts", error.to_string()))?;
            Ok(true)
        }
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(LaneError::input(
            "rotation-attempts",
            format!("source residue {name} cannot be observed: {error}"),
        )),
    }
}

fn evict_clear_attempt(
    old: &mut Value,
    source_directory: Option<&dyn AsFd>,
) -> Result<(), LaneError> {
    let attempts = old["rotation_attempts"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotation-attempts", "attempt journal is not an array"))?;
    let mut removable = None;
    for (index, entry) in attempts
        .iter()
        .enumerate()
        .take(attempts.len().saturating_sub(1))
    {
        if !residue_present(entry, source_directory)? {
            removable = Some(index);
            break;
        }
    }
    let index = removable.ok_or_else(|| {
        LaneError::input(
            "rotation-attempt-residue",
            "every older attempt still names an observed or unmeasured source residue",
        )
    })?;
    old["rotation_attempts"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("rotation-attempts", "attempt journal is not an array"))?
        .remove(index);
    let omitted = old["attempts_omitted"]
        .as_u64()
        .ok_or_else(|| LaneError::input("rotation-attempts", "omitted count is not an integer"))?
        .checked_add(1)
        .ok_or_else(|| LaneError::input("rotation-attempts", "omitted count overflowed"))?;
    old["attempts_omitted"] = json!(omitted);
    Ok(())
}

fn append_attempt_value(
    old: &mut Value,
    attempt: Value,
    source_directory: Option<&dyn AsFd>,
) -> Result<(), LaneError> {
    validate_rotation_attempts(old)?;
    // Measure the escaped attempt before inserting it; a retained residue is never trimmed.
    let attempt_size = serde_json::to_vec(&attempt)
        .map_err(|error| LaneError::input("rotation-attempts", error.to_string()))?
        .len();
    if attempt_size as u64 >= MAX_RESERVATION_BYTES {
        return Err(LaneError::input(
            "rotation-attempt-size",
            "serialized attempt exceeds reservation bound",
        ));
    }
    if old.get("rotation_attempts").is_none() {
        old["rotation_attempts"] = json!([]);
    }
    let attempts = old["rotation_attempts"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("rotation-attempts", "attempt journal is not an array"))?;
    attempts.push(attempt);
    let omitted = match old.get("attempts_omitted") {
        None => 0,
        Some(value) => value.as_u64().ok_or_else(|| {
            LaneError::input("rotation-attempts", "omitted count is not an integer")
        })?,
    };
    old["attempts_omitted"] = json!(omitted);
    while old["rotation_attempts"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotation-attempts", "attempt journal is not an array"))?
        .len()
        > MAX_ROTATION_ATTEMPTS
    {
        evict_clear_attempt(old, source_directory)?;
    }
    while u64::try_from(
        serde_json::to_vec(&old)
            .map_err(|error| LaneError::input("rotation-attempts", error.to_string()))?
            .len(),
    )
    .map_err(|error| LaneError::input("rotation-attempts", error.to_string()))?
        > MAX_RESERVATION_BYTES
    {
        let attempts = old["rotation_attempts"].as_array().ok_or_else(|| {
            LaneError::input("rotation-attempts", "attempt journal is not an array")
        })?;
        if attempts.len() <= 1 {
            return Err(LaneError::input(
                "rotation-attempt-size",
                "serialized attempt and reservation cannot fit together",
            ));
        }
        evict_clear_attempt(old, source_directory)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_pending_intent_sync_failure(
    store: &RotationStore<'_>,
    identity: &str,
    old_run: &str,
    intent: &Value,
    new_run: &str,
    expected_digest: &str,
    error: &LaneError,
    source_directory: &dyn AsFd,
    attempt_instant: u64,
    _mailbox: &nix::fcntl::Flock<File>,
) -> Result<(), LaneError> {
    let mut old = store.bound(old_run, identity)?;
    if old["rotation_intent"] != *intent {
        return Err(LaneError::input(
            "rotate-record",
            "published intent changed after rename",
        ));
    }
    append_rotation_attempt(
        &mut old,
        new_run,
        expected_digest,
        error,
        None,
        Some(source_directory),
        attempt_instant,
    )?;
    store.publish(old_run, &old)
}

#[cfg(test)]
fn record_rotation_failure_locked(
    root: &Path,
    old_run: &str,
    intent: Option<&Value>,
    new_run: &str,
    expected_digest: &str,
    error: &LaneError,
    mailbox: &nix::fcntl::Flock<File>,
) -> Result<(), LaneError> {
    let instant = super::letters::unix_ns()?;
    with_test_store(root, |store| {
        let identity = store.identity(old_run)?;
        record_rotation_failure_locked_at(
            store,
            Some(&identity),
            old_run,
            intent,
            new_run,
            expected_digest,
            error,
            None,
            None,
            instant,
            mailbox,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn record_rotation_failure(
    store: &RotationStore<'_>,
    expected_identity: &str,
    old_run: &str,
    intent: &Value,
    new_run: &str,
    expected_digest: &str,
    error: &LaneError,
    source_directory: &dyn AsFd,
    attempt_instant: u64,
) -> Result<(), LaneError> {
    let mailbox = store.lock(old_run)?;
    record_rotation_failure_locked_at(
        store,
        Some(expected_identity),
        old_run,
        Some(intent),
        new_run,
        expected_digest,
        error,
        None,
        Some(source_directory),
        attempt_instant,
        &mailbox,
    )
}

fn link_intent_at(
    store: &RotationStore<'_>,
    expected_identity: &str,
    old_run: &str,
    intent: &Value,
) -> Result<Value, LaneError> {
    let name = intent_name(old_run, intent)?;
    let _old_lock = store.lock(old_run)?;
    let mut old = store.bound(old_run, expected_identity)?;
    if old["rotation_intent"] != *intent {
        return Err(LaneError::input(
            "rotate-pending",
            "rotation intent changed during recovery",
        ));
    }
    validate_old_snapshot(&old, intent)?;
    if store.read(name)?.is_none() {
        return Err(LaneError::input("rotate-pending", pending_message(intent)));
    }
    let _new_lock = store.lock(name)?;
    let mut new = store
        .read(name)?
        .ok_or_else(|| LaneError::input("rotate-pending", pending_message(intent)))?;
    validate_new_handover(&old, &new, intent, name)?;
    let rotation = &intent["rotation"];
    validate_links(&old, &new, intent)?;
    if !new["rotation"].is_object() {
        new["rotation"] = rotation.clone();
        store.publish(name, &new)?;
    }
    old["rotation"] = rotation.clone();
    old.as_object_mut()
        .ok_or_else(|| LaneError::input("rotate-record", "old reservation is not an object"))?
        .remove("rotation_intent");
    store.publish(old_run, &old)?;
    Ok(rotation.clone())
}

#[cfg(test)]
fn link_intent(
    root: &Path,
    old_run: &str,
    intent: &Value,
    _owner: u32,
) -> Result<Value, LaneError> {
    with_test_store(root, |store| {
        let identity = store.identity(old_run)?;
        link_intent_at(store, &identity, old_run, intent)
    })
}

fn recover_pending_rotation_at(
    root: &Path,
    store: &RotationStore<'_>,
    old_run: &str,
    expected_identity: &str,
    intent: &Value,
    dry_run: bool,
) -> Result<Value, LaneError> {
    if dry_run {
        return preview_intent(root, store, old_run, expected_identity, intent, store.owner);
    }
    let rotation = link_intent_at(store, expected_identity, old_run, intent)?;
    Ok(
        json!({"schema":1,"command":"rotate","dry_run":false,"old_run":old_run,"new_run":rotation["new_run"],"rotation":rotation,"reconciled":true,"changed":true}),
    )
}

#[cfg(test)]
fn recover_pending_rotation(
    root: &Path,
    old_run: &str,
    intent: &Value,
    dry_run: bool,
    _owner: u32,
) -> Result<Value, LaneError> {
    with_test_store(root, |store| {
        let identity = store.identity(old_run)?;
        recover_pending_rotation_at(root, store, old_run, &identity, intent, dry_run)
    })
}

fn check_rotation(
    record: &Value,
    context: &Value,
    threshold: Option<f64>,
    force: Option<&str>,
) -> Result<(), LaneError> {
    require_rotation_replies(record)?;
    if record["phase"] != "settled"
        || record["rounds"].as_array().is_none_or(|rounds| {
            rounds.is_empty() || rounds.iter().any(|round| round["phase"] != "settled")
        })
    {
        return Err(LaneError::input(
            "rotate-live",
            "old run has no complete settled round sequence",
        ));
    }
    let last = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .ok_or_else(|| LaneError::input("rotate-live", "last round is absent"))?;
    if last["ended_by"] != "by-report-after-stop"
        || last["step"]
            .as_str()
            .is_none_or(|step| super::steering::stop_brief(record, step).is_none())
    {
        return Err(LaneError::input(
            "rotate-stop",
            "old run has no settled stop letter and report",
        ));
    }
    if record["rotation"].is_object() {
        validate_rotation_record(&record["rotation"])?;
        return Err(LaneError::input(
            "rotate-record",
            "old run already names a rotation",
        ));
    }
    if force.is_some() {
        return Ok(());
    }
    if context["state"] != "measured" {
        return Err(LaneError::input(
            "rotate-context",
            format!("context is {}", context["state"]),
        ));
    }
    let limit = threshold
        .ok_or_else(|| LaneError::input("rotate-threshold", "context_threshold is absent"))?;
    let fraction = context["fraction"]
        .as_f64()
        .ok_or_else(|| LaneError::input("rotate-context", "measured fraction is absent"))?;
    if fraction < limit {
        return Err(LaneError::input(
            "rotate-threshold",
            format!("context fraction {fraction} is below threshold {limit}"),
        ));
    }
    Ok(())
}

fn require_rotation_replies(record: &Value) -> Result<(), LaneError> {
    let reply_absent = |round: &Value| {
        round["phase"] == "failed"
            && round.get("reply").is_some_and(Value::is_null)
            && round["settle_attempts"]
                .as_array()
                .and_then(|attempts| attempts.last())
                .is_some_and(|attempt| attempt["phase"] == "complete")
    };
    if record["phase"] == "settled"
        && record["rounds"]
            .as_array()
            .is_some_and(|rounds| rounds.iter().any(reply_absent))
    {
        if !record["rounds"]
            .as_array()
            .and_then(|rounds| rounds.last())
            .is_some_and(reply_absent)
        {
            return Err(LaneError::input(
                "rotate-reply-absent",
                "run holds an earlier reply-less failed round and cannot hand over; a later settled round does not supply that missing reply",
            ));
        }
        return Err(LaneError::input(
            "rotate-reply-absent",
            format!(
                "settlement completed but a failed round has no reply for handover; use bind-mail {} {} --step NEW --delivery UTC_INSTANT then launch {} {} --round NEW to continue in the same home",
                record["loop"].as_str().unwrap_or("LOOP"),
                record["run"].as_str().unwrap_or("RUN"),
                record["loop"].as_str().unwrap_or("LOOP"),
                record["run"].as_str().unwrap_or("RUN")
            ),
        ));
    }
    Ok(())
}

fn read_reply(
    outbox: &File,
    name: &str,
    worker: u32,
    saved: &Value,
    owner_home: &Path,
) -> Result<String, LaneError> {
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
    let mut file = File::from(
        openat2(outbox, name, how)
            .map_err(|error| LaneError::input("rotate-reply", format!("{name}: {error}")))?,
    );
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("rotate-reply", error.to_string()))?;
    if !meta.is_file()
        || meta.uid() != worker
        || meta.permissions().mode() & 0o7777 != 0o600
        || meta.len() > home::MAX_LETTER
    {
        return Err(LaneError::input(
            "rotate-reply",
            format!("{name} is not a bounded private worker reply"),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(home::MAX_LETTER + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("rotate-reply", error.to_string()))?;
    if saved["bytes"] != bytes.len() || saved["sha256"] != build::sha256_bytes(&bytes, owner_home)?
    {
        return Err(LaneError::input(
            "rotate-reply",
            format!("{name} differs from its saved size or digest"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| LaneError::input("rotate-reply", format!("{name} is not UTF-8")))
}

fn next_task(
    path: Option<&Path>,
    owner_home: &Path,
    loop_name: &str,
    owner: u32,
) -> Result<Value, LaneError> {
    let Some(path) = path else {
        return Ok(
            json!({"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}),
        );
    };
    if path.starts_with(crate::credential::sign_in_dir(owner_home, loop_name))
        || path.file_name().is_some_and(|name| name == "auth.json")
    {
        return Err(LaneError::input(
            "rotate-next",
            "next task cannot name sign-in input",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::input("rotate-next", "next task parent is absent"))?;
    let directory = home::pin_parent(parent, owner)?;
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("rotate-next", "next task name is absent"))?;
    let file = File::from(
        openat2(
            &directory,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("rotate-next", format!("{}: {error}", path.display())))?,
    );
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("rotate-next", error.to_string()))?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.permissions().mode() & 0o022 != 0
        || meta.len() > home::MAX_LETTER
    {
        return Err(LaneError::input(
            "rotate-next",
            "next task is not a bounded owner-controlled regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(home::MAX_LETTER + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("rotate-next", error.to_string()))?;
    if bytes.len() as u64 > home::MAX_LETTER {
        return Err(LaneError::input(
            "rotate-next",
            "next task exceeds letter size bound",
        ));
    }
    let digest = build::sha256_bytes(&bytes, owner_home)?;
    let size = bytes.len();
    let body = String::from_utf8(bytes)
        .map_err(|_| LaneError::input("rotate-next", "next task is not UTF-8"))?;
    Ok(json!({"state":"present","sha256":digest,"bytes":size,"body":body,"body_truncated":false}))
}

#[derive(Clone, Copy)]
enum BodySlot {
    Reply(usize),
    Inbox(usize, usize),
    Next,
}

fn trim_longest_body(handover: &mut Value, excess: usize) -> Result<(), LaneError> {
    let replies = handover["replies"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-handover", "reply list is absent"))?;
    let mut largest = None;
    for (round_index, reply) in replies.iter().enumerate() {
        let reply_len = reply["body"].as_str().map_or(0, str::len);
        if largest.is_none_or(|(length, _)| reply_len > length) {
            largest = Some((reply_len, BodySlot::Reply(round_index)));
        }
        if let Some(entries) = reply["inbox_letters"].as_array() {
            for (entry_index, entry) in entries.iter().enumerate() {
                let length = entry["body"].as_str().map_or(0, str::len);
                if largest.is_none_or(|(current, _)| length > current) {
                    largest = Some((length, BodySlot::Inbox(round_index, entry_index)));
                }
            }
        }
    }
    let next_len = handover["next_task"]["body"].as_str().map_or(0, str::len);
    if largest.is_none_or(|(length, _)| next_len > length) {
        largest = Some((next_len, BodySlot::Next));
    }
    let Some((length, slot)) = largest.filter(|(length, _)| *length > 0) else {
        return Err(LaneError::input(
            "rotate-handover",
            "handover metadata exceeds letter size bound",
        ));
    };
    let target = match slot {
        BodySlot::Reply(index) => &mut handover["replies"][index],
        BodySlot::Inbox(round, index) => &mut handover["replies"][round]["inbox_letters"][index],
        BodySlot::Next => &mut handover["next_task"],
    };
    let body = target["body"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-handover", "body is absent"))?;
    let mut retained = length.saturating_sub(excess.max(1));
    while !body.is_char_boundary(retained) {
        retained -= 1;
    }
    target["body"] = json!(&body[..retained]);
    target["body_truncated"] = json!(true);
    Ok(())
}

fn bound_handover_output(handover: &mut Value) -> Result<(), LaneError> {
    let limit = usize::try_from(home::MAX_LETTER)
        .map_err(|_| LaneError::input("rotate-handover", "letter bound exceeds process width"))?;
    loop {
        let serialized = serde_json::to_vec(handover)
            .map_err(|error| LaneError::input("rotate-handover", error.to_string()))?;
        if serialized.len() <= limit {
            return Ok(());
        }
        trim_longest_body(handover, serialized.len() - limit)?;
    }
}

fn bound_private_record(
    runs: &OwnedFd,
    run: &str,
    owner: u32,
    expected_identity: &str,
) -> Result<Value, LaneError> {
    let (record, identity) = checkout::read_record_bound(runs, run, owner)?;
    if identity != expected_identity {
        return Err(LaneError::input(
            "rotate-private-record",
            "private reservation identity differs from the public read",
        ));
    }
    Ok(record)
}

/// Read replies and context in the private namespace from their recorded custody.
///
/// # Errors
///
/// Refuses a changed reservation, outbox, reply or context record.
#[allow(clippy::too_many_lines)]
pub fn private_handover(
    owner_home: &Path,
    loop_name: &str,
    run: &str,
    runs_root: &Path,
    expected_identity: &str,
) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let runs = home::pin_parent(runs_root, 0)?;
    let record = bound_private_record(&runs, run, 0, expected_identity)?;
    let (plan, _) = load_plan(owner_home, loop_name, run, (0, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("rotate-record", "runs root is absent"))?;
    if root != runs_root {
        return Err(LaneError::input(
            "rotate-private-record",
            "private runs root differs from the public read",
        ));
    }
    if record["loop"] != loop_name
        || record["run"] != run
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "rotate-record",
            "old reservation names another home",
        ));
    }
    let loop_uid = super::recorded_loop_uid(&record)?;
    let evidence = File::from(home::pin_loop_round(root, &plan.driver_dir, 0, loop_uid)?);
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-record", "rounds are absent"))?;
    let mut handover = json!({"schema":1,"loop":loop_name,"run":run,"context":null,"replies":[]});
    require_rotation_replies(&record)?;
    for round in rounds {
        if round["phase"] != "settled" {
            return Err(LaneError::input("rotate-live", "old round is not settled"));
        }
        let step = round["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("rotate-record", "round step is absent"))?;
        super::letters::valid_step(step)?;
        let name = format!("{step}.md");
        let reply = read_reply(
            &evidence,
            &format!("reply-{step}.txt"),
            loop_uid,
            &round["reply"],
            owner_home,
        )?;
        handover["replies"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("rotate-handover", "replies are absent"))?
            .push(json!({"step":step,"outbox":name,"sha256":round["reply"]["sha256"],"bytes":round["reply"]["bytes"],"inbox":[],"inbox_letters":[],"body":reply,"body_truncated":false}));
        bound_handover_output(&mut handover)?;
        let index = handover["replies"]
            .as_array()
            .ok_or_else(|| LaneError::input("rotate-handover", "replies are absent"))?
            .len()
            - 1;
        let binding = if step == "dispatch" {
            &record["initial_brief"]
        } else {
            record["mail"]
                .as_array()
                .and_then(|bindings| bindings.iter().find(|binding| binding["step"] == step))
                .ok_or_else(|| {
                    LaneError::input("rotate-evidence", "round has no delivery binding")
                })?
        };
        let directory = round["driver_dir"].as_str().ok_or_else(|| {
            LaneError::input("rotate-evidence", "round evidence directory absent")
        })?;
        let held = File::from(home::pin_loop_round(
            root,
            Path::new(directory),
            0,
            loop_uid,
        )?);
        let name = format!("step-{step}.txt");
        let expected = if step == "dispatch" {
            &binding["sha256"]
        } else {
            &binding["evidence_digest"]
        };
        let saved = json!({"bytes":binding["bytes"],"sha256":expected});
        let body = read_reply(&held, &name, loop_uid, &saved, owner_home)?;
        handover["replies"][index]["inbox"]
            .as_array_mut()
            .ok_or_else(|| LaneError::input("rotate-evidence", "brief list absent"))?
            .push(json!(name));
        handover["replies"][index]["inbox_letters"].as_array_mut().ok_or_else(||LaneError::input("rotate-evidence","brief evidence list absent"))?.push(json!({"step":step,"name":name,"sha256":expected,"bytes":binding["bytes"],"body":body,"body_truncated":false}));
        bound_handover_output(&mut handover)?;
    }
    let last = rounds
        .last()
        .ok_or_else(|| LaneError::input("rotate-record", "rounds are empty"))?;
    let directory = last["driver_dir"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-context", "last driver directory is absent"))?;
    let pinned = File::from(home::pin_loop_round(
        root,
        Path::new(directory),
        0,
        loop_uid,
    )?);
    let context = super::follow::open_regular_at(&pinned, "context.jsonl", "rotate-context", true)?
        .map_or_else(|| Ok(None), |file| {
            let bytes = super::follow::read_regular(file, "rotate-context")?;
            let last = bytes.split(|byte| *byte == b'\n').rfind(|line| !line.is_empty());
            last.map_or(Ok(None), |line| serde_json::from_slice::<Value>(line)
                .map(Some).map_err(|error| LaneError::input("rotate-context", error.to_string())))
        })?
        .unwrap_or_else(|| json!({"state":"unknown","used":null,"window":null,"fraction":null,"source":"event-stream","reason":"context-record-absent","turn":0,"at":null}));
    handover["context"] = context;
    bound_handover_output(&mut handover)?;
    Ok(handover)
}

fn marked_body(entry: &Value, kind: &str) -> Result<String, LaneError> {
    let body = entry
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| LaneError::input("rotate-letter", format!("{kind} body is absent")))?;
    let truncated = entry
        .get("body_truncated")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            LaneError::input(
                "rotate-letter",
                format!("{kind} truncation state is absent"),
            )
        })?;
    if !truncated {
        return Ok(body.to_owned());
    }
    let digest = entry.get("sha256").and_then(Value::as_str).ok_or_else(|| {
        LaneError::input("rotate-letter", format!("{kind} whole digest is absent"))
    })?;
    let bytes = entry
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| LaneError::input("rotate-letter", format!("{kind} whole size is absent")))?;
    let mut marked = body.to_owned();
    if !marked.ends_with('\n') {
        marked.push('\n');
    }
    write!(
        &mut marked,
        "[TRUNCATED {kind} BODY: shown {} of {bytes} bytes; whole SHA-256 {digest}]",
        body.len()
    )
    .map_err(|error| LaneError::operation("rotate-letter", error.to_string()))?;
    Ok(marked)
}

fn render_handover_once(record: &Value, handover: &Value, old: &str) -> Result<String, LaneError> {
    let model = record["model_selection"]["model"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-letter", "model is absent"))?;
    let effort = record["model_selection"]["effort"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-letter", "effort is absent"))?;
    let replies = handover["replies"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-letter", "replies are absent"))?;
    let mut letter = format!(
        "Model: {model}\nEffort: {effort}\n\nHandover from run {old}. Continue from these replies of record in round order.\n\n"
    );
    let mut added_section = false;
    for reply in replies {
        let step = reply["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("rotate-letter", "step is absent"))?;
        let name = reply["outbox"]
            .as_str()
            .ok_or_else(|| LaneError::input("rotate-letter", "outbox name is absent"))?;
        let digest = reply["sha256"]
            .as_str()
            .ok_or_else(|| LaneError::input("rotate-letter", "digest is absent"))?;
        let body = marked_body(reply, "REPLY")?;
        writeln!(
            &mut letter,
            "## {step}: {name}\nDigest: {digest}\nInbox letters answered: {}\n\n{body}\n",
            reply["inbox"]
        )
        .map_err(|error| LaneError::operation("rotate-letter", error.to_string()))?;
        let inbox = reply
            .get("inbox_letters")
            .and_then(Value::as_array)
            .ok_or_else(|| LaneError::input("rotate-letter", "inbox letter bodies are absent"))?;
        for entry in inbox {
            added_section = true;
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| LaneError::input("rotate-letter", "inbox name is absent"))?;
            let digest = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| LaneError::input("rotate-letter", "inbox digest is absent"))?;
            let body = marked_body(entry, "INBOX")?;
            writeln!(
                &mut letter,
                "### Inbox letter {step}: {name}\nDigest: {digest}\n\n{body}\n"
            )
            .map_err(|error| LaneError::operation("rotate-letter", error.to_string()))?;
        }
    }
    let next = handover
        .get("next_task")
        .and_then(Value::as_object)
        .ok_or_else(|| LaneError::input("rotate-letter", "next task state is absent"))?;
    match next.get("state").and_then(Value::as_str) {
        Some("absent")
            if next.get("sha256") == Some(&Value::Null)
                && next.get("body") == Some(&Value::Null) => {}
        Some("present") => {
            added_section = true;
            let digest = next
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| LaneError::input("rotate-letter", "next task digest is absent"))?;
            let body = marked_body(&handover["next_task"], "NEXT TASK")?;
            writeln!(&mut letter, "## Next task\nDigest: {digest}\n\n{body}\n")
                .map_err(|error| LaneError::operation("rotate-letter", error.to_string()))?;
        }
        _ => {
            return Err(LaneError::input(
                "rotate-letter",
                "next task state is malformed",
            ));
        }
    }
    if added_section && letter.ends_with("\n\n") {
        letter.pop();
    }
    Ok(letter)
}

fn handover_letter(record: &Value, handover: &Value, old: &str) -> Result<String, LaneError> {
    let mut bounded = handover.clone();
    let limit = usize::try_from(home::MAX_LETTER)
        .map_err(|_| LaneError::input("rotate-letter", "letter bound exceeds process width"))?;
    loop {
        let letter = render_handover_once(record, &bounded, old)?;
        if letter.len() <= limit {
            return Ok(letter);
        }
        trim_longest_body(&mut bounded, letter.len() - limit)?;
    }
}

fn render_handover(
    record: &Value,
    handover: &Value,
    old: &str,
    owner_home: &Path,
) -> Result<(String, String), LaneError> {
    let letter = handover_letter(record, handover, old)?;
    let digest = build::sha256_bytes(letter.as_bytes(), owner_home)?;
    Ok((letter, digest))
}

fn preview_worker_uid_at(
    store: &RotationStore<'_>,
    root: &Path,
    run: &str,
    base: u32,
    count: u32,
) -> Result<u32, LaneError> {
    let duplicate = nix::unistd::dup(store.runs)
        .map_err(|error| LaneError::input("uid-lock", error.to_string()))?;
    let _lock = nix::fcntl::Flock::lock(duplicate, nix::fcntl::FlockArg::LockShared)
        .map_err(|(_, error)| LaneError::operation("uid-lock", error.to_string()))?;
    let names = super::checkpoint::directory_names(store.runs, root)?;
    let mut used = std::collections::BTreeSet::new();
    for name in names {
        if name == run
            || name == format!(".launch-{run}")
            || (1..=4).any(|attempt| name == format!(".container-{run}-attempt-{attempt}.id"))
        {
            return Err(LaneError::input(
                "already-exists",
                format!("{run} has protected inputs"),
            ));
        }
        let Some(saved_run) = name
            .strip_prefix(".reservation-")
            .and_then(|rest| rest.strip_suffix(".json"))
        else {
            continue;
        };
        let record = store.read(saved_run)?.ok_or_else(|| {
            LaneError::input(
                "launch-reservation",
                "reservation disappeared during census",
            )
        })?;
        let uid = record["worker_uid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| LaneError::input("uid-table", "reservation has no worker UID"))?;
        used.insert(uid);
    }
    (base..base + count)
        .find(|uid| !used.contains(uid))
        .ok_or_else(|| LaneError::input("uid-range", "no free worker identity"))
}

#[cfg(test)]
fn preview_worker_uid(
    root: &Path,
    run: &str,
    base: u32,
    count: u32,
    _owner: u32,
) -> Result<u32, LaneError> {
    with_test_store(root, |store| {
        preview_worker_uid_at(store, root, run, base, count)
    })
}

fn handover_preview_fields(
    letter: &str,
    digest: &str,
    worker_uid: u32,
    sign_in_source: &Path,
) -> Value {
    json!({"handover_letter":letter,"handover_bytes":letter.len(),"handover_sha256":digest,"worker_uid":worker_uid,"sign_in_source":sign_in_source})
}

struct PublishedHandover {
    path: PathBuf,
    directory: File,
    name: String,
    device: u64,
    inode: u64,
}

#[derive(Clone)]
struct SourceResidue {
    name: String,
    step: &'static str,
    errno: i32,
}

struct SourceFault {
    error: LaneError,
    residue: Option<SourceResidue>,
}

fn unlink_source(directory: &File, name: &str) -> Result<(), nix::errno::Errno> {
    #[cfg(test)]
    if FAIL_SOURCE_UNLINK_ONCE.with(|flag| flag.replace(false)) {
        return Err(nix::errno::Errno::EPERM);
    }
    unlinkat(directory, name, UnlinkatFlags::NoRemoveDir)
}

impl SourceFault {
    const fn plain(error: LaneError) -> Self {
        Self {
            error,
            residue: None,
        }
    }
}

fn source_directory(home_fd: &OwnedFd, loop_name: &str, owner: u32) -> Result<OwnedFd, LaneError> {
    let mut current =
        dup(home_fd).map_err(|error| LaneError::input("rotate-letter", error.to_string()))?;
    for component in [".config", "loops", loop_name] {
        let next = openat2(
            &current,
            component,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("rotate-letter", format!("{component}: {error}")))?;
        let stat =
            fstat(&next).map_err(|error| LaneError::input("rotate-letter", error.to_string()))?;
        if stat.st_uid != owner
            || stat.st_mode & 0o022 != 0
            || SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        {
            return Err(LaneError::input(
                "rotate-letter",
                format!("{component} owner, mode, or type differs"),
            ));
        }
        current = next;
    }
    Ok(current)
}

fn withdraw_source(
    source: &PublishedHandover,
    step: &'static str,
    error: LaneError,
) -> SourceFault {
    match unlink_source(&source.directory, source.name.as_str()) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => SourceFault::plain(error),
        Err(cleanup) => SourceFault {
            error,
            residue: Some(SourceResidue {
                name: source.name.clone(),
                step,
                errno: cleanup as i32,
            }),
        },
    }
}

fn source_failure(
    directory: &File,
    name: &str,
    step: &'static str,
    cause: impl std::fmt::Display,
) -> SourceFault {
    match unlink_source(directory, name) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => SourceFault::plain(LaneError::operation(
            "rotate-letter",
            format!("{step}: {cause}"),
        )),
        Err(cleanup) => SourceFault {
            error: LaneError::operation("rotate-letter", format!("{step}: {cause}")),
            residue: Some(SourceResidue {
                name: name.to_owned(),
                step,
                errno: cleanup as i32,
            }),
        },
    }
}

fn publish_handover_source_at(
    directory_fd: &OwnedFd,
    config: &Path,
    new_run: &str,
    letter: &str,
) -> Result<PublishedHandover, SourceFault> {
    let stage = format!(".handover-{new_run}-{}.md", std::process::id());
    let name = format!("handover-{new_run}.md");
    let directory = File::from(dup(directory_fd).map_err(|error| {
        SourceFault::plain(LaneError::operation("rotate-letter", error.to_string()))
    })?);
    let opened = openat2(
        &directory,
        stage.as_str(),
        OpenHow::new()
            .flags(
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
            )
            .mode(nix::sys::stat::Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| {
        SourceFault::plain(LaneError::operation("rotate-letter", error.to_string()))
    })?;
    let mut file: File = opened.into();
    let staged =
        fstat(&file).map_err(|error| source_failure(&directory, &stage, "stage-stat", error))?;
    if staged.st_uid != Uid::effective().as_raw()
        || staged.st_mode & 0o7777 != 0o600
        || SFlag::from_bits_truncate(staged.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
    {
        return Err(source_failure(
            &directory,
            &stage,
            "stage-stat",
            "owner, mode, or type differs",
        ));
    }
    if let Err(error) = file.write_all(letter.as_bytes()) {
        return Err(source_failure(&directory, &stage, "write", error));
    }
    if let Err(error) = file.sync_all() {
        return Err(source_failure(&directory, &stage, "sync", error));
    }
    renameat2(
        &directory,
        stage.as_str(),
        &directory,
        name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| source_failure(&directory, &stage, "rename", error))?;
    let renamed = openat2(
        &directory,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| source_failure(&directory, &name, "renamed-open", error))?;
    let observed = fstat(&renamed)
        .map_err(|error| source_failure(&directory, &name, "renamed-stat", error))?;
    if observed.st_dev != staged.st_dev || observed.st_ino != staged.st_ino {
        return Err(source_failure(
            &directory,
            &name,
            "renamed-stat",
            "staged inode differs",
        ));
    }
    directory
        .sync_all()
        .map_err(|error| source_failure(&directory, &name, "directory-sync", error))?;
    Ok(PublishedHandover {
        path: config.join(&name),
        directory,
        name,
        device: staged.st_dev,
        inode: staged.st_ino,
    })
}

#[cfg(test)]
fn publish_handover_source(
    config: &Path,
    new_run: &str,
    letter: &str,
) -> Result<PathBuf, LaneError> {
    let directory: OwnedFd = File::open(config)
        .map_err(|error| LaneError::operation("rotate-letter", error.to_string()))?
        .into();
    publish_handover_source_at(&directory, config, new_run, letter)
        .map(|source| source.path)
        .map_err(|fault| fault.error)
}

/// Preview or launch a fresh worker with the replaced worker's replies.
///
/// # Errors
///
/// Refuses an unsettled run, unmeasured threshold without force or changed reply evidence.
#[allow(clippy::too_many_lines)]
pub fn run(owner_home: &Path, request: &RotateRequest) -> Result<Value, LaneError> {
    run_with_host_root(owner_home, request, Path::new("/"), 0)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with_host_root(
    owner_home: &Path,
    request: &RotateRequest,
    host_root: &Path,
    root_uid: u32,
) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let (plan, settings) = load_plan(owner_home, &request.loop_name, &request.run, (caller, 0))?;
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("rotate-record", "runs root is absent"))?;
    let verified_home = home::verify_host_prefix_from(host_root, owner_home, caller, root_uid)?;
    let verified_runs =
        home::verify_host_launch_root(host_root, owner_home, root, caller, root_uid)?;
    let store = RotationStore {
        runs: &verified_runs,
        owner: caller,
    };
    let mailbox = if request.dry_run {
        None
    } else {
        Some(store.lock(&request.run)?)
    };
    let (old, record_identity) = checkout::read_record_bound(store.runs, &request.run, caller)?;
    validate_rotation_attempts(&old)?;
    if old["loop"] != request.loop_name
        || old["run"] != request.run
        || old["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "rotate-record",
            "old reservation names another home",
        ));
    }
    if old["rotation_intent"].is_object() {
        validate_rotation_record(&old["rotation_intent"]["rotation"])?;
        if !request.dry_run {
            let pending_digest = old["rotation_intent"]["letter_sha256"]
                .as_str()
                .ok_or_else(|| LaneError::input("rotate-pending", "intent digest is absent"))?;
            let recorded_override =
                old["rotation_intent"]["rotation"]["digest_override_reason"].as_str();
            let force = request.force.as_deref().filter(|reason| {
                request.expect_digest.is_some() || recorded_override == Some(*reason)
            });
            require_handover_digest(pending_digest, request.expect_digest.as_deref(), force)?;
        }
        drop(mailbox);
        return recover_pending_rotation_at(
            root,
            &store,
            &request.run,
            &record_identity,
            &old["rotation_intent"],
            request.dry_run,
        );
    }
    if old["phase"] != "settled" {
        return Err(LaneError::input(
            "rotate-live",
            "old run has a live or failed round",
        ));
    }
    require_rotation_replies(&old)?;
    let podman = PathBuf::from(
        old["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| LaneError::input("rotate-record", "container program is absent"))?,
    );
    crate::pinned::owner_executable(&podman, caller)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("rotate-program", error.to_string()))?;
    let exe_word = crate::pinned::owner_executable_word(&exe, caller)?;
    let mut argv = vec!["unshare".into(), exe_word];
    argv.extend(private_handover_argv(
        &request.loop_name,
        &request.run,
        owner_home,
        root,
        &record_identity,
    )?);
    let output = build::run_checked_with_private_launch(
        &podman,
        argv,
        &super::launch_environment(owner_home)?,
        owner_home,
        60,
        "rotation-handover",
        &verified_home,
        root,
        &verified_runs,
        None,
    )?;
    let handover: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::input("rotate-handover", error.to_string()))?;
    execute_rotation_at(
        owner_home,
        &verified_home,
        &store,
        &record_identity,
        request,
        old,
        handover,
        settings.context_threshold,
        podman,
        mailbox,
        |name| {
            let (base, count) = super::worker_range(owner_home, &request.loop_name)?;
            preview_worker_uid_at(&store, root, name, base, count)
        },
        |_| Ok(()),
        super::run,
    )
}

// The entry owns the reservation and handover snapshots while the mailbox lock is held.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]
fn execute_rotation_at(
    owner_home: &Path,
    verified_home: &OwnedFd,
    store: &RotationStore<'_>,
    record_identity: &str,
    request: &RotateRequest,
    old: Value,
    mut handover: Value,
    threshold: Option<f64>,
    podman: PathBuf,
    mailbox: Option<nix::fcntl::Flock<File>>,
    preview_uid: impl FnOnce(&str) -> Result<u32, LaneError>,
    after_publication: impl FnOnce(&Path) -> Result<(), LaneError>,
    provision: impl FnOnce(&Path, &LaunchRequest) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    let caller = Uid::effective().as_raw();
    let door_scope = match old["door_scope"].as_str() {
        Some("work") => crate::door::Scope::Work,
        Some("review") => crate::door::Scope::Review,
        _ => {
            return Err(LaneError::input(
                "rotate-record",
                "door scope is absent or invalid",
            ));
        }
    };
    validate_rotation_attempts(&old)?;
    let (_, preview_name) = next_name(store, &request.run)?;
    let context = handover["context"].clone();
    check_rotation(&old, &context, threshold, request.force.as_deref())?;
    let next = next_task(
        request.next.as_deref(),
        owner_home,
        &request.loop_name,
        caller,
    )?;
    handover
        .as_object_mut()
        .ok_or_else(|| LaneError::input("rotate-handover", "private handover is not an object"))?
        .insert(String::from("next_task"), next.clone());
    let (letter, digest) = render_handover(&old, &handover, &request.run, owner_home)?;
    let stop = stop_for_last_round(&old)?;
    let digest_override_reason = if request.expect_digest.is_none() && !request.dry_run {
        request.force.as_deref()
    } else {
        None
    };
    let replies = handover["replies"]
        .as_array()
        .ok_or_else(|| LaneError::input("rotate-handover", "replies are absent"))?;
    let mut inbox_letters = Vec::new();
    for reply in replies {
        let entries = reply["inbox_letters"]
            .as_array()
            .ok_or_else(|| LaneError::input("rotate-handover", "inbox entries are absent"))?;
        for entry in entries {
            inbox_letters
                .push(json!({"step":reply["step"],"name":entry["name"],"sha256":entry["sha256"]}));
        }
    }
    let rotation = json!({"old_run":request.run,"new_run":preview_name,"context":context,"threshold":threshold,"force_reason":request.force,"digest_override_reason":digest_override_reason,"stop_letter":{"name":stop["name"],"placed_at_unix_ns":stop["placed_at_unix_ns"]},"replies":replies.iter().map(|reply| json!({"step":reply["step"],"outbox":reply["outbox"],"sha256":reply["sha256"],"inbox":reply["inbox"]})).collect::<Vec<_>>(),"inbox_letters":inbox_letters,"next_task":{"state":next["state"],"sha256":next["sha256"]}});
    validate_rotation_record(&rotation)?;
    let sign_in_source =
        crate::credential::sign_in_dir(owner_home, &request.loop_name).join("auth.json");
    if request.dry_run {
        let worker_uid = preview_uid(&preview_name)?;
        let handover = handover_preview_fields(&letter, &digest, worker_uid, &sign_in_source);
        return Ok(
            json!({"schema":1,"command":"rotate","dry_run":true,"old_run":request.run,"new_run":preview_name,"context":context,"threshold":threshold,"handover_letter":handover["handover_letter"],"handover_bytes":handover["handover_bytes"],"handover_sha256":handover["handover_sha256"],"worker_uid":handover["worker_uid"],"sign_in_source":handover["sign_in_source"],"rotation":rotation,"changed":false}),
        );
    }
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    require_handover_digest(
        &digest,
        request.expect_digest.as_deref(),
        request.force.as_deref(),
    )?;
    let mailbox_lock = mailbox.as_ref().ok_or_else(|| {
        LaneError::operation("rotate-record", "changing rotation has no mailbox lock")
    })?;
    let config_fd = source_directory(verified_home, &request.loop_name, caller)?;
    let attempt_instant = super::letters::unix_ns()?;
    let prepared = prepare_intent_locked(
        store,
        record_identity,
        &request.run,
        &old,
        request.force.as_deref(),
        &rotation,
        &config,
        &digest,
        attempt_instant,
        mailbox_lock,
    )?;
    if prepared.intent["new_run"] != preview_name {
        return Err(LaneError::input(
            "rotate-record",
            "prepared intent names another run",
        ));
    }
    let source = match publish_handover_source_at(&config_fd, &config, &preview_name, &letter) {
        Ok(source) => source,
        Err(fault) => {
            record_rotation_failure_locked_at(
                store,
                Some(record_identity),
                &request.run,
                None,
                &preview_name,
                &digest,
                &fault.error,
                fault.residue.as_ref(),
                Some(&config_fd),
                prepared.attempt_instant,
                mailbox_lock,
            )?;
            return Err(fault.error);
        }
    };
    let pinned_source = match after_publication(&source.path)
        .and_then(|()| {
            super::pin_rotation_source_at(
                &source.directory,
                &source.name,
                &digest,
                owner_home,
                caller,
            )
        })
        .and_then(|pinned| {
            let stat = fstat(&pinned.descriptor)
                .map_err(|error| LaneError::input("rotate-source", error.to_string()))?;
            if stat.st_dev != source.device || stat.st_ino != source.inode {
                return Err(LaneError::input(
                    "rotate-source",
                    "published source inode differs from the staged inode",
                ));
            }
            Ok(pinned)
        }) {
        Ok(source) => source,
        Err(error) => {
            let fault = withdraw_source(&source, "source-pin", error);
            record_rotation_failure_locked_at(
                store,
                Some(record_identity),
                &request.run,
                None,
                &preview_name,
                &digest,
                &fault.error,
                fault.residue.as_ref(),
                Some(&source.directory),
                prepared.attempt_instant,
                mailbox_lock,
            )?;
            return Err(fault.error);
        }
    };
    let intent =
        match publish_prepared_intent_locked(store, record_identity, &request.run, &old, &prepared)
        {
            Ok(intent) => intent,
            Err(error) => {
                let fault = withdraw_source(&source, "intent", error);
                record_rotation_failure_locked_at(
                    store,
                    Some(record_identity),
                    &request.run,
                    None,
                    &preview_name,
                    &digest,
                    &fault.error,
                    fault.residue.as_ref(),
                    Some(&source.directory),
                    prepared.attempt_instant,
                    mailbox_lock,
                )?;
                return Err(fault.error);
            }
        };
    let IntentPublication {
        intent,
        identity: intent_identity,
        sync_error,
    } = intent;
    let mut expected_intent_record = old;
    expected_intent_record["rotation_intent"] = intent.clone();
    if store.bound(&request.run, &intent_identity)? != expected_intent_record {
        return Err(LaneError::input(
            "rotate-record",
            "published intent reservation differs before continuation",
        ));
    }
    if let Some(error) = sync_error {
        record_pending_intent_sync_failure(
            store,
            &intent_identity,
            &request.run,
            &intent,
            &preview_name,
            &digest,
            &error,
            &source.directory,
            prepared.attempt_instant,
            mailbox_lock,
        )?;
        return Err(error);
    }
    let new_run = intent["new_run"]
        .as_str()
        .ok_or_else(|| LaneError::input("rotate-pending", "intent new run is absent"))?
        .to_owned();
    if new_run != preview_name || intent["letter_source"] != source.path.display().to_string() {
        let error = LaneError::input(
            "rotate-record",
            "intent differs from pinned handover source",
        );
        record_rotation_failure_locked_at(
            store,
            Some(&intent_identity),
            &request.run,
            Some(&intent),
            &new_run,
            &digest,
            &error,
            None,
            Some(&source.directory),
            prepared.attempt_instant,
            mailbox_lock,
        )?;
        return Err(error);
    }
    drop(mailbox);
    let launch = provision(
        owner_home,
        &LaunchRequest {
            loop_name: request.loop_name.clone(),
            run: new_run.clone(),
            letter: source.path,
            round: None,
            budget: 3600,
            dry_run: false,
            expect_digest: None,
            observe: false,
            podman_bin: podman,
            proxy_bin: None,
            model: None,
            effort: None,
            door_scope,
            rotation_source: Some(pinned_source),
        },
    );
    let launch = match launch {
        Ok(launch) => launch,
        Err(error) => {
            record_rotation_failure(
                store,
                &intent_identity,
                &request.run,
                &intent,
                &new_run,
                &digest,
                &error,
                &source.directory,
                prepared.attempt_instant,
            )?;
            return Err(error);
        }
    };
    let rotation = link_intent_at(store, &intent_identity, &request.run, &intent)?;
    Ok(
        json!({"schema":1,"command":"rotate","dry_run":false,"old_run":request.run,"new_run":new_run,"handover_bytes":letter.len(),"handover_sha256":digest,"sign_in_source":sign_in_source,"rotation":rotation,"launch":launch,"changed":true}),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn execute_rotation(
    owner_home: &Path,
    root: &Path,
    request: &RotateRequest,
    old: Value,
    handover: Value,
    threshold: Option<f64>,
    podman: PathBuf,
    mailbox: Option<nix::fcntl::Flock<File>>,
    preview_uid: impl FnOnce(&str) -> Result<u32, LaneError>,
    after_publication: impl FnOnce(&Path) -> Result<(), LaneError>,
    provision: impl FnOnce(&Path, &LaunchRequest) -> Result<Value, LaneError>,
) -> Result<Value, LaneError> {
    with_test_store(root, |store| {
        let identity = store.identity(&request.run)?;
        let verified_home: OwnedFd = File::open(owner_home)
            .map_err(|error| LaneError::input("rotate-letter", error.to_string()))?
            .into();
        execute_rotation_at(
            owner_home,
            &verified_home,
            store,
            &identity,
            request,
            old,
            handover,
            threshold,
            podman,
            mailbox,
            preview_uid,
            after_publication,
            provision,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        RotateRequest, check_rotation, execute_rotation, handover_letter, handover_preview_fields,
        link_intent, preview_worker_uid, publish_checked_intent, publish_handover_source,
        publish_intent, recover_pending_rotation, render_handover, stop_for_last_round,
    };
    use serde_json::json;
    use std::cell::Cell;
    use std::fs;
    use std::os::fd::OwnedFd;

    /// ´test:unit:rotation-private-handover-refuses-replaced-reservation´
    #[test]
    fn rotation_private_handover_refuses_replaced_reservation() {
        let root = tempfile::TempDir::new().expect("runs root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("runs root mode");
        let path = super::reservation_path(root.path(), "R");
        let first =
            json!({"schema":1,"loop":"alpha","run":"R","worker_uid":3000,"phase":"settled"});
        super::publish_reservation(&path, &first).expect("first reservation");
        let held: OwnedFd = fs::File::open(root.path()).expect("runs descriptor").into();
        let owner = nix::unistd::Uid::effective().as_raw();
        let (_, identity) = super::checkout::read_record_bound(&held, "R", owner)
            .expect("public reservation identity");
        let mut replacement = first;
        replacement["worker_uid"] = json!(3001);
        super::publish_reservation(&path, &replacement).expect("replacement reservation");
        let error = super::bound_private_record(&held, "R", owner, &identity)
            .expect_err("private handover refuses replacement before evidence");
        assert_eq!(error.kind, "rotate-private-record");
        assert_eq!(error.status, 2);
    }

    /// ´test:unit:rotation-post-handover-stages-refuse-replaced-reservation´
    #[test]
    fn rotation_post_handover_stages_refuse_replaced_reservation() {
        let root = tempfile::TempDir::new().expect("runs root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("runs root mode");
        let path = super::reservation_path(root.path(), "R");
        let original = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"rounds":[{"step":"review","phase":"settled","reply":{"sha256":"old-digest"}}]});
        super::publish_reservation(&path, &original).expect("original reservation");
        let held: OwnedFd = fs::File::open(root.path()).expect("held runs root").into();
        let owner = nix::unistd::Uid::effective().as_raw();
        let store = super::RotationStore { runs: &held, owner };
        let identity = store.identity("R").expect("public identity");
        super::bound_private_record(&held, "R", owner, &identity)
            .expect("private handover read before replacement");
        let mut replaced = original.clone();
        replaced["worker_uid"] = json!(3001);
        super::publish_reservation(&path, &replaced).expect("replacement after handover");
        let mailbox = store.lock("R").expect("mailbox lock");
        let rotation = rotation_shape("R-rotation-1");
        let intent_error = super::publish_intent_locked(
            root.path(),
            &store,
            &identity,
            "R",
            &original,
            None,
            &rotation,
            root.path(),
            None,
            "digest",
            &mailbox,
        )
        .expect_err("intent refuses replaced reservation");
        assert_eq!(intent_error.kind, "rotate-record");
        assert_eq!(intent_error.status, 2);
        let refusal = crate::error::LaneError::input("rotate-source", "fixture refusal");
        let failure_error = super::record_rotation_failure_locked_at(
            &store,
            Some(&identity),
            "R",
            None,
            "R-rotation-1",
            "digest",
            &refusal,
            None,
            None,
            1,
            &mailbox,
        )
        .expect_err("refusal writer refuses replaced reservation");
        assert_eq!(failure_error.kind, "rotate-record");
        assert_eq!(failure_error.status, 2);
        assert_eq!(
            super::read_reservation(&path).expect("read replaced"),
            Some(replaced)
        );
    }

    /// ´test:unit:rotation-post-intent-stages-refuse-replaced-reservation´
    #[test]
    fn rotation_post_intent_stages_refuse_replaced_reservation() {
        let (root, intent) = intent_fixture(true);
        let path = super::reservation_path(root.path(), "R");
        let held: OwnedFd = fs::File::open(root.path()).expect("runs descriptor").into();
        let owner = nix::unistd::Uid::effective().as_raw();
        let store = super::RotationStore { runs: &held, owner };
        let identity = store.identity("R").expect("published intent identity");
        let original = super::read_reservation(&path)
            .expect("read intent")
            .expect("intent reservation");
        super::publish_reservation(&path, &original).expect("replace same bytes after intent");
        let refusal = crate::error::LaneError::input("rotate-source", "fixture refusal");
        let mailbox = store.lock("R").expect("mailbox lock");
        let error = super::record_rotation_failure_locked_at(
            &store,
            Some(&identity),
            "R",
            Some(&intent),
            "R-rotation-1",
            "digest",
            &refusal,
            None,
            None,
            1,
            &mailbox,
        )
        .expect_err("refusal cannot write replacement");
        assert_eq!(error.kind, "rotate-record");
        drop(mailbox);
        let error = super::link_intent_at(&store, &identity, "R", &intent)
            .expect_err("link cannot write replacement");
        assert_eq!(error.kind, "rotate-record");
        let error =
            super::recover_pending_rotation_at(root.path(), &store, "R", &identity, &intent, false)
                .expect_err("recovery cannot write replacement");
        assert_eq!(error.kind, "rotate-record");
        assert_eq!(
            super::read_reservation(&path).expect("read replacement"),
            Some(original)
        );
    }

    /// ´test:unit:rotation-entry-post-intent-replacement-refuses-failure-and-link-stages´
    #[test]
    fn rotation_entry_post_intent_replacement_refuses_failure_and_link_stages() {
        for fail_provision in [true, false] {
            let (home, root, old, handover) = rotation_entry_fixture();
            let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
            let path = super::reservation_path(&root, "R");
            let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
                .expect("changing mailbox lock");
            let error = execute_rotation(
                home.path(),
                &root,
                &rotate_form(false, preview["handover_sha256"].as_str()),
                old,
                handover,
                None,
                PathBuf::from("/usr/bin/podman"),
                Some(mailbox),
                |_| Ok(3001),
                |_| Ok(()),
                |_, _| {
                    let published = super::read_reservation(&path)
                        .expect("read published intent")
                        .expect("intent reservation");
                    assert!(published["rotation_intent"].is_object());
                    super::publish_reservation(&path, &published)
                        .expect("replace after intent with same bytes");
                    if fail_provision {
                        Err(crate::error::LaneError::input("fixture-provision", "stop"))
                    } else {
                        Ok(json!({"changed":true}))
                    }
                },
            )
            .expect_err("post-intent stage refuses replacement");
            assert_eq!(error.kind, "rotate-record");
            let saved = super::read_reservation(&path)
                .expect("read replacement")
                .expect("reservation");
            assert!(saved["rotation_intent"].is_object());
            assert!(saved.get("rotation_attempts").is_none());
        }
    }

    /// ´test:unit:rotation-intent-sync-failure-retains-source-and-records-pending-attempt´
    #[test]
    fn rotation_intent_sync_failure_retains_source_and_records_pending_attempt() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let digest = preview["handover_sha256"].as_str().expect("digest");
        let config = home.path().join(".config/loops/alpha");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        publish_checked_intent(
            &root,
            "R",
            &old,
            None,
            Some(digest),
            &preview["rotation"],
            &config,
            digest,
            &mailbox,
        )
        .expect("roomy intent");
        let path = super::reservation_path(&root, "R");
        let published = super::read_reservation(&path)
            .expect("read roomy intent")
            .expect("intent reservation");
        let size = serde_json::to_vec(&published).expect("intent bytes").len();
        let padding = usize::try_from(super::MAX_RESERVATION_BYTES).expect("bound") - size - 3_200;
        old["padding"] = json!("x".repeat(padding));
        super::publish_reservation(&path, &old).expect("near-bound settled record");
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        super::FAIL_INTENT_SYNC_ONCE.with(|flag| flag.set(true));
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| Ok(()),
            |_, _| panic!("sync refusal launched a worker"),
        )
        .expect_err("directory sync after intent rename refuses");
        assert_eq!(error.kind, "rotate-record");
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read pending intent")
            .expect("reservation");
        assert!(saved["rotation_intent"].is_object());
        assert_eq!(saved["rotation_attempts"][0]["refusal"], "rotate-record");
        assert!(
            home.path()
                .join(".config/loops/alpha/handover-R-rotation-1.md")
                .exists()
        );
    }

    /// ´test:unit:rotation-entry-refuses-same-bytes-replacement-after-intent-publication´
    #[test]
    fn rotation_entry_refuses_same_bytes_replacement_after_intent_publication() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        super::REPLACE_INTENT_AFTER_PUBLICATION_ONCE.with(|flag| flag.set(true));
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| Ok(()),
            |_, _| panic!("replacement launched a worker"),
        )
        .expect_err("returned renamed identity refuses same-bytes replacement");
        assert_eq!(error.kind, "rotate-record");
        assert!(error.detail.contains("identity differs"));
    }

    /// ´test:unit:rotation-attempt-journal-keeps-recent-refusals-below-reader-bound´
    #[test]
    fn rotation_attempt_journal_keeps_recent_refusals_below_reader_bound() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = super::reservation_path(root.path(), "R");
        super::publish_reservation(
            &path,
            &json!({"schema":1,"phase":"settled","run":"R","worker_uid":3000}),
        )
        .expect("old reservation");
        let mailbox = super::lock_mailbox(root.path(), "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        let expected = "a".repeat(64);
        let actual = "b".repeat(64);
        for index in 1..=300 {
            let error = crate::error::LaneError::input(
                "rotate-source",
                format!(
                    "attempt {index}: expected digest {expected} differs from source digest {actual}"
                ),
            );
            super::record_rotation_failure_locked(
                root.path(),
                "R",
                None,
                &format!("R-rotation-{index}"),
                &expected,
                &error,
                &mailbox,
            )
            .expect("bounded attempt publication");
        }
        let saved = super::read_reservation(&path)
            .expect("bounded reservation read")
            .expect("reservation present");
        let attempts = saved["rotation_attempts"]
            .as_array()
            .expect("attempt journal");
        assert_eq!(attempts.len(), 8);
        assert_eq!(saved["attempts_omitted"], 292);
        for (offset, attempt) in attempts.iter().enumerate() {
            assert_eq!(attempt["new_run"], format!("R-rotation-{}", 293 + offset));
            assert_eq!(attempt["refusal"], "rotate-source");
        }
        assert!(fs::metadata(&path).expect("reservation metadata").len() <= 65_536);
    }

    /// ´test:unit:rotation-attempt-journal-trims-oldest-for-reservation-byte-bound´
    #[test]
    fn rotation_attempt_journal_trims_oldest_for_reservation_byte_bound() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = super::reservation_path(root.path(), "R");
        let mut old =
            json!({"schema":1,"phase":"settled","run":"R","worker_uid":3000,"padding":""});
        let baseline = serde_json::to_vec(&old).expect("baseline size").len();
        let padding = usize::try_from(super::MAX_RESERVATION_BYTES)
            .expect("reservation bound fits usize")
            - baseline
            - 550;
        old["padding"] = json!("x".repeat(padding));
        super::publish_reservation(&path, &old).expect("near-bound reservation");
        let mailbox = super::lock_mailbox(root.path(), "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        let expected = "a".repeat(64);
        let actual = "b".repeat(64);
        for index in 1..=2 {
            let error = crate::error::LaneError::input(
                "rotate-source",
                format!("expected digest {expected} differs from source digest {actual}"),
            );
            super::record_rotation_failure_locked(
                root.path(),
                "R",
                None,
                &format!("R-rotation-{index}"),
                &expected,
                &error,
                &mailbox,
            )
            .expect("byte-bound publication");
        }
        let saved = super::read_reservation(&path)
            .expect("read after trim")
            .expect("reservation");
        let attempts = saved["rotation_attempts"].as_array().expect("journal");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0]["new_run"], "R-rotation-2");
        assert_eq!(saved["attempts_omitted"], 1);
    }
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    fn rotation_entry_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        serde_json::Value,
        serde_json::Value,
    ) {
        let home = tempfile::TempDir::new_in("/tmp").expect("fixture home");
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).expect("home mode");
        let root = home.path().join("runs");
        let config = home.path().join(".config/loops/alpha");
        fs::create_dir(&root).expect("runs root");
        fs::create_dir_all(&config).expect("config");
        for directory in [
            home.path().join(".config"),
            home.path().join(".config/loops"),
            config,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("config mode");
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let old = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"door_scope":"review","model_selection":{"model":"gpt-6-sol","effort":"high"},"rounds":[{"step":"review","phase":"settled","ended_by":"by-report-after-stop","reply":{"sha256":"first"}}],"mail":[{"step":"review","name":"review-1.md","stop":true,"state":"placed","placed_at_unix_ns":1}]});
        super::publish_reservation(&super::reservation_path(&root, "R"), &old).expect("old run");
        let handover = json!({"context":{"state":"unknown","reason":"window-unreported"},"replies":[{"step":"review","outbox":"review.md","sha256":"first","bytes":12,"inbox":["review.md","review-1.md"],"inbox_letters":[{"step":"review","name":"review.md","sha256":"round","bytes":13,"body":"Round letter.","body_truncated":false},{"step":"review","name":"review-1.md","sha256":"later","bytes":14,"body":"In-round note.","body_truncated":false}],"body":"First reply.","body_truncated":false}]});
        (home, root, old, handover)
    }

    fn rotate_form(dry_run: bool, expected: Option<&str>) -> RotateRequest {
        RotateRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            dry_run,
            force: Some("host measurement".into()),
            expect_digest: expected.map(str::to_owned),
            next: None,
        }
    }

    fn entry_preview(
        home: &Path,
        root: &Path,
        old: serde_json::Value,
        handover: serde_json::Value,
    ) -> serde_json::Value {
        execute_rotation(
            home,
            root,
            &rotate_form(true, None),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            None,
            |_| Ok(3001),
            |_| panic!("dry run published a source"),
            |_, _| panic!("dry run provisioned a worker"),
        )
        .expect("dry rotation entry")
    }

    /// ´test:unit:rotation-intent-preflight-refuses-changed-record-before-source´
    #[test]
    fn rotation_intent_preflight_refuses_changed_record_before_source() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let mut stale = old;
        stale["worker_uid"] = json!(3001);
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            stale,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| Ok(()),
            |_, _| panic!("intent refusal provisioned a worker"),
        )
        .expect_err("intent differs from public record");
        assert_eq!(error.kind, "rotate-record");
        let source = home
            .path()
            .join(".config/loops/alpha/handover-R-rotation-1.md");
        assert!(!source.exists());
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read refusal")
            .expect("reservation");
        assert!(saved.get("rotation_attempts").is_none());
        assert!(saved.get("rotation_intent").is_none());
    }

    /// ´test:unit:rotation-source-rename-refusal-cleans-stage-and-records-attempt´
    #[test]
    fn rotation_source_rename_refusal_cleans_stage_and_records_attempt() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let config = home.path().join(".config/loops/alpha");
        let source = config.join("handover-R-rotation-1.md");
        fs::write(&source, b"existing").expect("force no-replace rename refusal");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| panic!("failed source reached pin"),
            |_, _| panic!("failed source provisioned worker"),
        )
        .expect_err("rename refuses existing target");
        assert_eq!(error.kind, "rotate-letter");
        assert_eq!(fs::read(&source).expect("original source"), b"existing");
        assert!(
            !config
                .join(format!(".handover-R-rotation-1-{}.md", std::process::id()))
                .exists()
        );
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read refusal")
            .expect("reservation");
        assert_eq!(saved["rotation_attempts"][0]["refusal"], "rotate-letter");
    }

    /// ´test:unit:rotation-source-parent-link-refuses-beneath-held-home´
    #[test]
    fn rotation_source_parent_link_refuses_beneath_held_home() {
        let (home, _, _, _) = rotation_entry_fixture();
        let config = home.path().join(".config/loops/alpha");
        let replacement = home.path().join("replacement");
        fs::create_dir(&replacement).expect("replacement directory");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
            .expect("replacement mode");
        fs::remove_dir(&config).expect("remove empty config directory");
        std::os::unix::fs::symlink(&replacement, &config).expect("linked config component");
        let held: OwnedFd = fs::File::open(home.path()).expect("held home").into();
        let error = super::source_directory(&held, "alpha", nix::unistd::Uid::effective().as_raw())
            .expect_err("link below held home refuses");
        assert_eq!(error.kind, "rotate-letter");
        assert_eq!(error.status, 2);
        assert!(
            fs::read_dir(&replacement)
                .expect("replacement contents")
                .next()
                .is_none()
        );
    }

    /// ´test:unit:rotation-intent-reserves-escaped-refusal-before-publication´
    #[test]
    fn rotation_intent_reserves_escaped_refusal_before_publication() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let digest = preview["handover_sha256"]
            .as_str()
            .expect("handover digest");
        let config = home.path().join(".config/loops/alpha");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        publish_checked_intent(
            &root,
            "R",
            &old,
            None,
            Some(digest),
            &preview["rotation"],
            &config,
            digest,
            &mailbox,
        )
        .expect("roomy intent");
        let path = super::reservation_path(&root, "R");
        let published = super::read_reservation(&path)
            .expect("read roomy intent")
            .expect("intent reservation");
        let size = serde_json::to_vec(&published).expect("intent bytes").len();
        let padding = usize::try_from(super::MAX_RESERVATION_BYTES).expect("bound") - size - 128;
        old["padding"] = json!("x".repeat(padding));
        super::publish_reservation(&path, &old).expect("near-bound settled record");
        let before = fs::read(&path).expect("protected bytes before refusal");
        let error = publish_checked_intent(
            &root,
            "R",
            &old,
            None,
            Some(digest),
            &preview["rotation"],
            &config,
            digest,
            &mailbox,
        )
        .expect_err("intent must reserve its refusal attempt");
        assert_eq!(error.kind, "rotate-intent-reserve");
        assert_eq!(error.status, 2);
        assert_eq!(fs::read(&path).expect("unchanged refusal record"), before);
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(digest)),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| panic!("capacity refusal published a source"),
            |_, _| panic!("capacity refusal launched a worker"),
        )
        .expect_err("entry reserves before creating a source");
        assert_eq!(error.kind, "rotate-intent-reserve");
        assert_eq!(fs::read(&path).expect("unchanged entry refusal"), before);
        assert!(
            fs::read_dir(home.path().join(".config/loops/alpha"))
                .expect("source directory")
                .next()
                .is_none()
        );
    }

    /// ´test:unit:rotation-cleanup-failure-records-prepared-attempt-after-source-creation´
    #[test]
    fn rotation_cleanup_failure_records_prepared_attempt_after_source_creation() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        super::FAIL_SOURCE_UNLINK_ONCE.with(|flag| flag.set(true));
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| {
                Err(crate::error::LaneError::input(
                    "fixture-source",
                    "stop after source",
                ))
            },
            |_, _| panic!("source failure launched a worker"),
        )
        .expect_err("failed source cleanup refuses");
        assert_eq!(error.kind, "fixture-source");
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read refusal")
            .expect("old reservation");
        let attempt = &saved["rotation_attempts"][0];
        assert_eq!(attempt["refusal"], "fixture-source");
        assert!(attempt["at_unix_ns"].as_u64().is_some());
        assert_eq!(
            attempt["source_residue"]["name"],
            "handover-R-rotation-1.md"
        );
        assert!(
            home.path()
                .join(".config/loops/alpha/handover-R-rotation-1.md")
                .exists()
        );
    }

    /// ´test:unit:rotation-provision-refusal-observes-residue-removed-after-reserve´
    #[test]
    fn rotation_provision_refusal_observes_residue_removed_after_reserve() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        let config = home.path().join(".config/loops/alpha");
        let attempts: Vec<_> = (1..=8)
            .map(|index| {
                let name = format!("handover-residue-{index}.md");
                if index != 1 {
                    fs::write(config.join(&name), b"residue").expect("initial residue");
                }
                let residue = if index == 1 {
                    json!(null)
                } else {
                    json!({"name":name,"step":"cleanup","errno":libc::EPERM})
                };
                json!({"new_run":format!("R-old-{index}"),"refusal":"rotate-letter","detail":"cleanup refused","at_unix_ns":1,"expected_sha256":"a","actual_sha256":null,"source_residue":residue})
            })
            .collect();
        old["rotation_attempts"] = json!(attempts);
        old["attempts_omitted"] = json!(0);
        super::publish_reservation(&super::reservation_path(&root, "R"), &old)
            .expect("old reservation with residues");
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| {
                fs::write(config.join("handover-residue-1.md"), b"new residue")
                    .expect("first residue appears after reserve");
                fs::remove_file(config.join("handover-residue-2.md"))
                    .expect("second residue disappears after reserve");
                Ok(())
            },
            |_, _| Err(crate::error::LaneError::input("fixture-provision", "stop")),
        )
        .expect_err("provision failure refuses");
        assert_eq!(error.kind, "fixture-provision");
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read refusal")
            .expect("old reservation");
        assert_eq!(
            saved["rotation_attempts"][7]["refusal"],
            "fixture-provision"
        );
        assert_eq!(
            saved["rotation_attempts"][0]["source_residue"]["name"],
            "handover-residue-2.md"
        );
        assert_eq!(saved["attempts_omitted"], 1);
    }

    /// ´test:unit:rotation-reserve-refuses-when-new-source-reuses-last-clear-residue´
    #[test]
    fn rotation_reserve_refuses_when_new_source_reuses_last_clear_residue() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        let config = home.path().join(".config/loops/alpha");
        let attempts: Vec<_> = (1..=8)
            .map(|index| {
                let name = if index == 8 {
                    "handover-R-rotation-1.md".to_owned()
                } else {
                    format!("handover-residue-{index}.md")
                };
                if index != 8 {
                    fs::write(config.join(&name), b"residue").expect("initial residue");
                }
                json!({"new_run":format!("R-old-{index}"),"refusal":"rotate-letter","detail":"cleanup refused","at_unix_ns":1,"expected_sha256":"a","actual_sha256":null,"source_residue":{"name":name,"step":"cleanup","errno":libc::EPERM}})
            })
            .collect();
        old["rotation_attempts"] = json!(attempts);
        old["attempts_omitted"] = json!(0);
        let path = super::reservation_path(&root, "R");
        super::publish_reservation(&path, &old).expect("old reservation with residues");
        let before = fs::read(&path).expect("journal before refusal");
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("reserve refusal provisioned a worker"),
            |_| panic!("reserve refusal published a source"),
            |_, _| panic!("reserve refusal launched a worker"),
        )
        .expect_err("last clear residue must not be evicted before creation");
        assert_eq!(error.kind, "rotate-intent-reserve");
        assert_eq!(fs::read(path).expect("journal after refusal"), before);
        assert!(!config.join("handover-R-rotation-1.md").exists());
    }

    /// ´test:unit:rotation-malformed-attempt-refuses-before-source-creation´
    #[test]
    fn rotation_malformed_attempt_refuses_before_source_creation() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        old["rotation_attempts"] = json!([{"new_run":"R-rotation-1"}]);
        let path = super::reservation_path(&root, "R");
        super::publish_reservation(&path, &old).expect("malformed protected journal");
        let before = fs::read(&path).expect("journal bytes before refusal");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, None),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("malformed attempts reached uid preview"),
            |_| panic!("malformed attempts published a source"),
            |_, _| panic!("malformed attempts provisioned a worker"),
        )
        .expect_err("malformed attempt must refuse first");
        assert_eq!(error.kind, "rotation-attempts");
        assert_eq!(error.status, 2);
        assert_eq!(fs::read(&path).expect("unchanged journal"), before);
        assert!(
            fs::read_dir(home.path().join(".config/loops/alpha"))
                .expect("source directory")
                .next()
                .is_none()
        );
    }

    /// ´test:unit:rotation-source-pin-stays-under-held-parent-after-replacement´
    #[test]
    fn rotation_source_pin_stays_under_held_parent_after_replacement() {
        let (home, _, _, _) = rotation_entry_fixture();
        let config = home.path().join(".config/loops/alpha");
        let name = "handover-R-rotation-1.md";
        let source = config.join(name);
        fs::write(&source, b"Question and answer.\n").expect("source bytes");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
        let home_fd: OwnedFd = fs::File::open(home.path()).expect("held home").into();
        let owner = nix::unistd::Uid::effective().as_raw();
        let directory: fs::File = super::source_directory(&home_fd, "alpha", owner)
            .expect("held source parent")
            .into();
        let digest = crate::build::sha256_bytes(b"Question and answer.\n", Path::new("/"))
            .expect("source digest");
        let original = fs::metadata(&source).expect("original inode");
        let moved = home.path().join("moved-config");
        fs::rename(&config, &moved).expect("move published parent");
        let replacement = home.path().join("replacement");
        fs::create_dir(&replacement).expect("replacement parent");
        std::os::unix::fs::symlink(&replacement, &config).expect("linked pathname");
        let pinned =
            super::super::pin_rotation_source_at(&directory, name, &digest, home.path(), owner)
                .expect("held parent still supplies source");
        let actual = nix::sys::stat::fstat(&pinned.descriptor).expect("pinned inode");
        assert_eq!(
            (actual.st_dev, actual.st_ino),
            (original.dev(), original.ino())
        );
        assert!(
            fs::read_dir(replacement)
                .expect("replacement contents")
                .next()
                .is_none()
        );
    }

    /// ´test:unit:rotation-retry-retains-observed-source-residue-until-absent´
    #[test]
    fn rotation_retry_retains_observed_source_residue_until_absent() {
        let fixture = tempfile::tempdir().expect("source directory");
        let directory = fs::File::open(fixture.path()).expect("held directory");
        let name = "handover-R-rotation-1.md";
        fs::write(fixture.path().join(name), b"residue").expect("failed cleanup residue");
        let mut old = json!({"schema":1});
        let refusal = crate::error::LaneError::input("rotate-source", "cleanup refused");
        let residue = super::SourceResidue {
            name: name.into(),
            step: "source-pin",
            errno: libc::EPERM,
        };
        super::append_rotation_attempt(
            &mut old,
            "R-rotation-1",
            "a",
            &refusal,
            Some(&residue),
            Some(&directory),
            1,
        )
        .expect("first residue attempt");
        for index in 2..=9 {
            super::append_rotation_attempt(
                &mut old,
                &format!("R-rotation-{index}"),
                "a",
                &refusal,
                None,
                Some(&directory),
                1,
            )
            .expect("retry attempt");
        }
        assert_eq!(
            old["rotation_attempts"].as_array().expect("attempts").len(),
            8
        );
        assert_eq!(old["rotation_attempts"][0]["source_residue"]["name"], name);
        assert_eq!(old["attempts_omitted"], 1);
        nix::unistd::unlinkat(&directory, name, nix::unistd::UnlinkatFlags::NoRemoveDir)
            .expect("residue cleared");
        super::append_rotation_attempt(
            &mut old,
            "R-rotation-10",
            "a",
            &refusal,
            None,
            Some(&directory),
            1,
        )
        .expect("absent residue may be omitted");
        assert_eq!(old["rotation_attempts"][0]["new_run"], "R-rotation-3");
        assert_eq!(old["attempts_omitted"], 2);
    }

    /// ´test:unit:rotation-attempt-bound-refuses-when-all-residues-remain´
    #[test]
    fn rotation_attempt_bound_refuses_when_all_residues_remain() {
        let fixture = tempfile::tempdir().expect("source directory");
        let directory = fs::File::open(fixture.path()).expect("held directory");
        let mut old = json!({"schema":1});
        let refusal = crate::error::LaneError::input("rotate-source", "cleanup refused");
        for index in 1..=8 {
            let name = format!("handover-R-rotation-{index}.md");
            fs::write(fixture.path().join(&name), b"residue").expect("remaining source");
            let residue = super::SourceResidue {
                name,
                step: "source-pin",
                errno: libc::EPERM,
            };
            super::append_rotation_attempt(
                &mut old,
                &format!("R-rotation-{index}"),
                "a",
                &refusal,
                Some(&residue),
                Some(&directory),
                1,
            )
            .expect("retained residue attempt");
        }
        let error = super::append_rotation_attempt(
            &mut old,
            "R-rotation-9",
            "a",
            &refusal,
            None,
            Some(&directory),
            1,
        )
        .expect_err("no explainable attempt can be evicted");
        assert_eq!(error.kind, "rotation-attempt-residue");
        assert_eq!(
            old["rotation_attempts"][0]["source_residue"]["name"],
            "handover-R-rotation-1.md"
        );
    }

    /// ´test:unit:rotation-cleanup-residue-survives-escaped-detail-near-reservation-limit´
    #[test]
    fn rotation_cleanup_residue_survives_escaped_detail_near_reservation_limit() {
        let (home, root, mut old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let baseline = serde_json::to_vec(&old).expect("baseline").len();
        let padding =
            usize::try_from(super::MAX_RESERVATION_BYTES).expect("bound") - baseline - 4_000;
        old["padding"] = json!("x".repeat(padding));
        super::publish_reservation(&super::reservation_path(&root, "R"), &old)
            .expect("near-bound reservation");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, preview["handover_sha256"].as_str()),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| Ok(3001),
            |_| {
                super::FAIL_SOURCE_UNLINK_ONCE.with(|flag| flag.set(true));
                Err(crate::error::LaneError::input(
                    "rotate-source",
                    "\u{0001}".repeat(256),
                ))
            },
            |_, _| panic!("failed pin launched a worker"),
        )
        .expect_err("source pin refusal with failed cleanup");
        assert_eq!(error.kind, "rotate-source");
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read bounded attempt")
            .expect("reservation");
        let attempt = &saved["rotation_attempts"][0];
        assert_eq!(attempt["refusal"], "rotate-source");
        assert_eq!(
            attempt["source_residue"]["name"],
            "handover-R-rotation-1.md"
        );
        assert_eq!(attempt["source_residue"]["step"], "source-pin");
        assert_eq!(attempt["source_residue"]["errno"], libc::EPERM);
        assert!(
            serde_json::to_vec(&saved).expect("saved bytes").len() as u64
                <= super::MAX_RESERVATION_BYTES
        );
        assert!(
            home.path()
                .join(".config/loops/alpha/handover-R-rotation-1.md")
                .exists()
        );
    }

    /// ´test:unit:rotation-attempt-reader-refuses-missing-residue-key-without-rewrite´
    #[test]
    fn rotation_attempt_reader_refuses_missing_residue_key_without_rewrite() {
        let root = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = super::reservation_path(root.path(), "R");
        let old = json!({"schema":1,"phase":"settled","run":"R","worker_uid":3000,"rotation_attempts":[{"new_run":"R-rotation-1","refusal":"rotate-source","detail":"old","at_unix_ns":1,"expected_sha256":"digest","actual_sha256":null}]});
        super::publish_reservation(&path, &old).expect("malformed protected journal");
        let before = fs::read(&path).expect("record bytes");
        let mailbox = super::lock_mailbox(root.path(), "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        let error = super::record_rotation_failure_locked(
            root.path(),
            "R",
            None,
            "R-rotation-2",
            "digest",
            &crate::error::LaneError::input("rotate-source", "new refusal"),
            &mailbox,
        )
        .expect_err("missing required residue key refuses");
        assert_eq!(error.kind, "rotation-attempts");
        assert_eq!(error.status, 2);
        assert_eq!(fs::read(&path).expect("unchanged record"), before);
    }

    /// ´test:unit:rotation-entry-refuses-changed-handover-before-intent-or-worker´
    #[test]
    fn rotation_entry_refuses_changed_handover_before_intent_or_worker() {
        let (home, root, mut old, mut handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let digest = preview["handover_sha256"].as_str().expect("digest");
        old["rounds"].as_array_mut().expect("rounds").push(json!({"step":"later","phase":"settled","ended_by":"by-report-after-stop","reply":{"sha256":"second"}}));
        old["mail"].as_array_mut().expect("letters").push(json!({"step":"later","name":"later-1.md","stop":true,"state":"placed","placed_at_unix_ns":2}));
        handover["replies"].as_array_mut().expect("replies").push(json!({"step":"later","outbox":"later.md","sha256":"second","bytes":13,"inbox":["later.md","later-1.md"],"inbox_letters":[{"step":"later","name":"later.md","sha256":"round","bytes":3,"body":"abc","body_truncated":false},{"step":"later","name":"later-1.md","sha256":"extra","bytes":3,"body":"abc","body_truncated":false}],"body":"Second reply.","body_truncated":false}));
        super::publish_reservation(&super::reservation_path(&root, "R"), &old)
            .expect("intervening settled round");
        let allocation = Cell::new(false);
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(digest)),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| {
                allocation.set(true);
                Ok(3001)
            },
            |_| panic!("mismatched digest published a source"),
            |_, _| panic!("mismatched digest provisioned a worker"),
        )
        .expect_err("changed handover");
        assert_eq!(error.kind, "rotate-handover");
        assert!(error.detail.contains(digest));
        assert!(!allocation.get());
        let saved = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("read old")
            .expect("old run");
        assert!(saved.get("rotation_intent").is_none());
        assert!(
            super::read_reservation(&super::reservation_path(&root, "R-rotation-1"))
                .expect("read new")
                .is_none()
        );
        assert!(!root.join("R-rotation-1").exists());
    }

    /// ´test:unit:rotation-entry-preview-pair-stops-at-provisioning-verification´
    #[test]
    fn rotation_entry_preview_pair_stops_at_provisioning_verification() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        assert_eq!(
            preview["rotation"]["next_task"],
            json!({"state":"absent","sha256":null})
        );
        assert_eq!(
            preview["rotation"]["inbox_letters"]
                .as_array()
                .expect("carried inbox")
                .len(),
            2
        );
        let digest = preview["handover_sha256"].as_str().expect("digest");
        let expected = preview["handover_letter"]
            .as_str()
            .expect("letter")
            .as_bytes();
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(digest)),
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("changing rotation previewed an allocation"),
            |_| Ok(()),
            |owner_home, launch| {
                assert_eq!(launch.door_scope, crate::door::Scope::Review);
                let source = launch.rotation_source.as_ref().expect("pinned source");
                let bytes = super::super::rotation_source_bytes(
                    &source.descriptor,
                    &source.digest,
                    owner_home,
                    nix::unistd::Uid::effective().as_raw(),
                )?;
                let inbox = owner_home.join("synthetic-inbox");
                fs::create_dir(&inbox).expect("synthetic inbox");
                fs::write(inbox.join("dispatch.md"), &bytes).expect("provisioning bytes");
                Err(crate::error::LaneError::input(
                    "fixture-provisioning-stop",
                    "worker was not started",
                ))
            },
        )
        .expect_err("stop at verified provisioning");
        assert_eq!(error.kind, "fixture-provisioning-stop");
        assert_eq!(
            fs::read(home.path().join("synthetic-inbox/dispatch.md")).expect("inbox"),
            expected
        );
        let source = home
            .path()
            .join(".config/loops/alpha/handover-R-rotation-1.md");
        assert_eq!(fs::read(source).expect("published source"), expected);
        let old = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("old read")
            .expect("old reservation");
        assert!(old.get("rotation_intent").is_none());
        assert_eq!(
            old["rotation_attempts"][0]["refusal"],
            "fixture-provisioning-stop"
        );
    }

    /// ´test:unit:rotation-next-task-digest-binds-changing-call´
    #[test]
    fn rotation_next_task_digest_binds_changing_call() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let path = home.path().join("next.md");
        fs::write(&path, b"abc").expect("next task");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("next mode");
        let mut request = rotate_form(true, None);
        request.next = Some(path.clone());
        let preview = execute_rotation(
            home.path(),
            &root,
            &request,
            old.clone(),
            handover.clone(),
            None,
            PathBuf::from("/usr/bin/podman"),
            None,
            |_| Ok(3001),
            |_| panic!("dry run published source"),
            |_, _| panic!("dry run provisioned worker"),
        )
        .expect("next preview");
        assert!(
            preview["handover_letter"]
                .as_str()
                .expect("letter")
                .contains("## Next task")
        );
        assert_eq!(preview["rotation"]["next_task"]["state"], "present");
        assert_eq!(
            preview["rotation"]["next_task"]["sha256"],
            crate::build::sha256_bytes(b"abc", home.path()).expect("next digest")
        );
        fs::write(&path, b"abd").expect("changed next task");
        request.dry_run = false;
        request.expect_digest = preview["handover_sha256"].as_str().map(str::to_owned);
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &request,
            old,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("changing call allocated worker"),
            |_| panic!("mismatched next task published source"),
            |_, _| panic!("mismatched next task provisioned worker"),
        )
        .expect_err("changed next task refuses");
        assert_eq!(error.kind, "rotate-handover");
    }

    /// ´test:unit:rotation-entry-replacement-refuses-before-worker-provisioning´
    #[test]
    fn rotation_entry_replacement_refuses_before_worker_provisioning() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let digest = preview["handover_sha256"].as_str().expect("digest");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(digest)),
            old,
            handover.clone(),
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("changing rotation previewed an allocation"),
            |source| {
                let replacement = source.with_extension("replacement");
                fs::write(&replacement, b"Different handover.\n").expect("replacement bytes");
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
                fs::rename(replacement, source).expect("replace published name");
                Ok(())
            },
            |_, _| panic!("changed source provisioned a worker"),
        )
        .expect_err("replaced source");
        assert_eq!(error.kind, "rotate-source");
        assert!(error.detail.contains(digest));
        assert!(error.detail.contains("source digest"));
        assert!(
            super::read_reservation(&super::reservation_path(&root, "R-rotation-1"))
                .expect("read new")
                .is_none()
        );
        assert!(!root.join("R-rotation-1").exists());
        let current = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("old after replacement")
            .expect("old reservation");
        assert!(current.get("rotation_intent").is_none());
        assert_eq!(current["rotation_attempts"][0]["refusal"], "rotate-source");
        assert_eq!(current["rotation_attempts"][0]["new_run"], "R-rotation-1");
        assert_eq!(current["rotation_attempts"][0]["expected_sha256"], digest);
        assert!(current["rotation_attempts"][0]["actual_sha256"].is_string());
        let fresh = entry_preview(home.path(), &root, current.clone(), handover.clone());
        let fresh_digest = fresh["handover_sha256"].as_str().expect("fresh digest");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("retry mailbox lock");
        let reached = Cell::new(false);
        let retry = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(fresh_digest)),
            current,
            handover,
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("retry previewed allocation"),
            |_| Ok(()),
            |owner_home, launch| {
                reached.set(true);
                let source = launch
                    .rotation_source
                    .as_ref()
                    .expect("retry pinned source");
                super::super::rotation_source_bytes(
                    &source.descriptor,
                    &source.digest,
                    owner_home,
                    nix::unistd::Uid::effective().as_raw(),
                )?;
                Err(crate::error::LaneError::input(
                    "fixture-provisioning-stop",
                    "no worker started",
                ))
            },
        )
        .expect_err("retry reached provisioning");
        assert_eq!(retry.kind, "fixture-provisioning-stop");
        assert!(reached.get());
    }

    /// ´test:unit:rotation-entry-reconciles-failed-private-inbox-refusal-before-retry´
    #[test]
    fn rotation_entry_reconciles_failed_private_inbox_refusal_before_retry() {
        let (home, root, old, handover) = rotation_entry_fixture();
        let preview = entry_preview(home.path(), &root, old.clone(), handover.clone());
        let digest = preview["handover_sha256"].as_str().expect("digest");
        let actual = crate::build::sha256_bytes(b"changed inbox", home.path()).expect("actual");
        let mailbox = super::lock_mailbox(&root, "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing mailbox lock");
        let error = execute_rotation(
            home.path(),
            &root,
            &rotate_form(false, Some(digest)),
            old,
            handover.clone(),
            None,
            PathBuf::from("/usr/bin/podman"),
            Some(mailbox),
            |_| panic!("changing rotation previewed allocation"),
            |_| Ok(()),
            |_, launch| {
                let new_path = super::reservation_path(&root, &launch.run);
                let refusal = format!("rotate-source: expected digest {digest} differs from inbox digest {actual}");
                super::publish_reservation(
                    &new_path,
                    &json!({"schema":1,"phase":"failed","run":launch.run,"worker_uid":3001,"pre_driver_failure":refusal}),
                )?;
                Err(crate::error::LaneError::input(
                    "rotate-source",
                    format!("expected digest {digest} differs from inbox digest {actual}"),
                ))
            },
        )
        .expect_err("private inbox refused before worker");
        assert_eq!(error.kind, "rotate-source");
        let new = super::read_reservation(&super::reservation_path(&root, "R-rotation-1"))
            .expect("new read")
            .expect("failed new reservation");
        assert_eq!(new["phase"], "failed");
        assert!(
            new["pre_driver_failure"]
                .as_str()
                .expect("refusal")
                .contains("rotate-source")
        );
        let current = super::read_reservation(&super::reservation_path(&root, "R"))
            .expect("old read")
            .expect("old reservation");
        assert!(current.get("rotation_intent").is_none());
        assert_eq!(current["rotation_attempts"][0]["refusal"], "rotate-source");
        assert_eq!(current["rotation_attempts"][0]["expected_sha256"], digest);
        assert_eq!(current["rotation_attempts"][0]["actual_sha256"], actual);
        let retry = entry_preview(home.path(), &root, current, handover);
        assert_eq!(retry["new_run"], "R-rotation-2");
    }

    fn rotation_shape(new_run: &str) -> serde_json::Value {
        json!({"old_run":"R","new_run":new_run,"context":{"state":"unknown"},"threshold":null,"force_reason":"host measurement","digest_override_reason":null,"stop_letter":{"name":"review-1.md","placed_at_unix_ns":1},"replies":[{"step":"review","outbox":"review.md","sha256":"old-digest","inbox":["review.md","review-1.md"]}],"inbox_letters":[{"step":"review","name":"review.md","sha256":"round"},{"step":"review","name":"review-1.md","sha256":"later"}],"next_task":{"state":"absent","sha256":null}})
    }

    /// ´test:unit:rotation-record-requires-carried-letters-and-explicit-next-state´
    #[test]
    fn rotation_record_requires_carried_letters_and_explicit_next_state() {
        let intact = rotation_shape("R-rotation-1");
        super::validate_rotation_record(&intact).expect("one rotation shape");
        for key in ["inbox_letters", "next_task"] {
            let mut missing = intact.clone();
            missing
                .as_object_mut()
                .expect("rotation object")
                .remove(key);
            let error = super::validate_rotation_record(&missing).expect_err("missing key");
            assert_eq!(error.kind, "rotate-record");
            assert!(error.detail.contains(key));
        }
        let mut omitted_letter = intact.clone();
        omitted_letter["inbox_letters"]
            .as_array_mut()
            .expect("carried")
            .pop();
        assert_eq!(
            super::validate_rotation_record(&omitted_letter)
                .expect_err("omitted carried letter")
                .kind,
            "rotate-record"
        );
        let mut absent_digest = intact;
        absent_digest["next_task"]["sha256"] = json!("unexpected");
        assert_eq!(
            super::validate_rotation_record(&absent_digest)
                .expect_err("absent task cannot carry digest")
                .kind,
            "rotate-record"
        );
    }

    fn intent_fixture(with_new: bool) -> (tempfile::TempDir, serde_json::Value) {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let rotation = rotation_shape("R-rotation-1");
        let intent = json!({"index":1,"new_run":"R-rotation-1","reason":"host measurement","at_unix_ns":123,"letter_source":"/synthetic/handover.md","letter_sha256":"digest","round_count":1,"settled_step":"review","reply_sha256":"old-digest","rotation":rotation});
        let old = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"rounds":[{"step":"review","phase":"settled","reply":{"sha256":"old-digest"},"ended_by":"by-report-after-stop"}],"rotation_intent":intent});
        super::publish_reservation(&super::reservation_path(root.path(), "R"), &old)
            .expect("old reservation");
        if with_new {
            let new = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R-rotation-1","worker_uid":3001,"letter_source":"/synthetic/handover.md","initial_brief":{"step":"dispatch","name":"brief.txt","state":"placed","sha256":"digest"},"mail":[],"rounds":[{"step":"dispatch","phase":"settled","reply":{"sha256":"new-digest"}}]});
            super::publish_reservation(&super::reservation_path(root.path(), "R-rotation-1"), &new)
                .expect("new reservation");
        }
        (root, intent)
    }

    /// ´test:unit:rotation-intent-with-run-completes-both-links-on-retry´
    #[test]
    fn rotation_intent_with_run_completes_both_links_on_retry() {
        let (root, intent) = intent_fixture(true);
        let linked = link_intent(
            root.path(),
            "R",
            &intent,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("recover link");
        for run in ["R", "R-rotation-1"] {
            let record = super::read_reservation(&super::reservation_path(root.path(), run))
                .expect("read")
                .expect("reservation");
            assert_eq!(record["rotation"], linked);
            if run == "R" {
                assert!(record.get("rotation_intent").is_none());
            }
        }
    }

    /// ´test:unit:pending-rotation-dry-run-keeps-both-reservations-byte-identical´
    #[test]
    fn pending_rotation_dry_run_keeps_both_reservations_byte_identical() {
        let (root, intent) = intent_fixture(true);
        let old_path = super::reservation_path(root.path(), "R");
        let new_path = super::reservation_path(root.path(), "R-rotation-1");
        let before_old = fs::read(&old_path).expect("old bytes");
        let before_new = fs::read(&new_path).expect("new bytes");
        let preview = recover_pending_rotation(
            root.path(),
            "R",
            &intent,
            true,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("read-only preview");
        assert_eq!(preview["dry_run"], true);
        assert_eq!(preview["changed"], false);
        assert_eq!(preview["new_run_exists"], true);
        assert_eq!(preview["new_run_complete"], true);
        assert_eq!(preview["handover_sha256"], intent["letter_sha256"]);
        assert_eq!(preview["handover_letter_matches_intent"], false);
        assert_eq!(preview["would_link_old"], true);
        assert_eq!(preview["would_link_new"], true);
        assert_eq!(fs::read(&old_path).expect("old after"), before_old);
        assert_eq!(fs::read(&new_path).expect("new after"), before_new);
    }

    /// ´test:unit:pending-rotation-preview-verifies-the-published-handover-digest´
    #[test]
    fn pending_rotation_preview_verifies_the_published_handover_digest() {
        let (root, mut intent) = intent_fixture(true);
        let config = root.path().join("config");
        fs::create_dir(&config).expect("config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("owner-only config");
        let source =
            publish_handover_source(&config, "R-rotation-1", "Handover.\n").expect("source");
        let digest = crate::build::sha256_bytes(b"Handover.\n", root.path()).expect("digest");
        intent["letter_source"] = json!(source);
        intent["letter_sha256"] = json!(digest);
        let old_path = super::reservation_path(root.path(), "R");
        let new_path = super::reservation_path(root.path(), "R-rotation-1");
        let mut old = super::read_reservation(&old_path)
            .expect("read")
            .expect("old");
        old["rotation_intent"] = intent.clone();
        super::publish_reservation(&old_path, &old).expect("updated intent");
        let mut new = super::read_reservation(&new_path)
            .expect("read")
            .expect("new");
        new["letter_source"] = json!(source);
        new["initial_brief"]["sha256"] = json!(digest);
        super::publish_reservation(&new_path, &new).expect("updated new");
        let preview = recover_pending_rotation(
            root.path(),
            "R",
            &intent,
            true,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("matching source");
        assert_eq!(preview["handover_letter_matches_intent"], true);
    }

    /// ´test:unit:rotation-preparation-and-unsettled-dispatch-cannot-link´
    #[test]
    fn rotation_preparation_and_unsettled_dispatch_cannot_link() {
        let (root, intent) = intent_fixture(true);
        let path = super::reservation_path(root.path(), "R-rotation-1");
        let mut new = super::read_reservation(&path).expect("read").expect("new");
        new["phase"] = json!("preparing");
        new["mail"] = json!([]);
        super::publish_reservation(&path, &new).expect("preparation before letter");
        let link = || {
            link_intent(
                root.path(),
                "R",
                &intent,
                nix::unistd::Uid::effective().as_raw(),
            )
        };
        assert_eq!(link().expect_err("letter absent").kind, "rotate-pending");
        new["mail"] =
            json!([{"step":"dispatch","name":"dispatch.md","state":"placed","sha256":"digest"}]);
        new["phase"] = json!("started");
        new["rounds"][0]["phase"] = json!("running");
        super::publish_reservation(&path, &new).expect("letter placed, dispatch running");
        assert_eq!(link().expect_err("dispatch running").kind, "rotate-pending");
        new["phase"] = json!("settled");
        new["rounds"][0]["phase"] = json!("settled");
        super::publish_reservation(&path, &new).expect("dispatch settled");
        assert!(link().is_ok());
    }

    /// ´test:unit:rotation-link-refuses-old-round-after-intent-snapshot´
    #[test]
    fn rotation_link_refuses_old_round_after_intent_snapshot() {
        let (root, intent) = intent_fixture(true);
        let path = super::reservation_path(root.path(), "R");
        let mut old = super::read_reservation(&path).expect("read").expect("old");
        old["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"later","phase":"settled","reply":{"sha256":"later-digest"}}));
        super::publish_reservation(&path, &old).expect("later round");
        let error = link_intent(
            root.path(),
            "R",
            &intent,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect_err("snapshot changed");
        assert_eq!(error.kind, "rotate-record");
        old["rounds"].as_array_mut().expect("rounds").truncate(1);
        old["rounds"][0]["reply"]["sha256"] = json!("changed-digest");
        super::publish_reservation(&path, &old).expect("changed reply");
        assert_eq!(
            link_intent(
                root.path(),
                "R",
                &intent,
                nix::unistd::Uid::effective().as_raw(),
            )
            .expect_err("reply digest changed")
            .kind,
            "rotate-record"
        );
        let new = super::read_reservation(&super::reservation_path(root.path(), "R-rotation-1"))
            .expect("read")
            .expect("new");
        assert!(new.get("rotation").is_none());
    }

    /// ´test:unit:rotation-recovers-after-new-link-before-old-link´
    #[test]
    fn rotation_recovers_after_new_link_before_old_link() {
        let (root, intent) = intent_fixture(true);
        let new_path = super::reservation_path(root.path(), "R-rotation-1");
        let mut new = super::read_reservation(&new_path)
            .expect("read")
            .expect("new");
        new["rotation"] = intent["rotation"].clone();
        super::publish_reservation(&new_path, &new).expect("new link before interruption");
        let linked = link_intent(
            root.path(),
            "R",
            &intent,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("finish old link");
        let old = super::read_reservation(&super::reservation_path(root.path(), "R"))
            .expect("read")
            .expect("old");
        assert_eq!(old["rotation"], linked);
        assert!(old.get("rotation_intent").is_none());
    }

    /// ´test:unit:rotation-publishes-intent-before-new-reservation´
    #[test]
    fn rotation_publishes_intent_before_new_reservation() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let old = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"rounds":[{"step":"review","phase":"settled","reply":{"sha256":"old-digest"}}]});
        super::publish_reservation(&super::reservation_path(root.path(), "R"), &old).expect("old");
        let intent = publish_intent(
            root.path(),
            "R",
            &old,
            Some("host measurement"),
            &rotation_shape("R-rotation-1"),
            root.path(),
            "digest",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("durable intent");
        assert_eq!(intent["index"], 1);
        assert_eq!(intent["new_run"], "R-rotation-1");
        assert!(intent["at_unix_ns"].as_u64().is_some());
        let saved = super::read_reservation(&super::reservation_path(root.path(), "R"))
            .expect("read")
            .expect("old");
        assert_eq!(saved["rotation_intent"], intent);
        assert!(
            super::read_reservation(&super::reservation_path(root.path(), "R-rotation-1"))
                .expect("check new")
                .is_none()
        );
    }

    /// ´test:unit:rotation-intent-without-run-refuses-and-preserves-intent´
    #[test]
    fn rotation_intent_without_run_refuses_and_preserves_intent() {
        let (root, intent) = intent_fixture(false);
        let old_path = super::reservation_path(root.path(), "R");
        let before = fs::read(&old_path).expect("old bytes");
        let preview = recover_pending_rotation(
            root.path(),
            "R",
            &intent,
            true,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect_err("absent run dry-run refusal");
        assert_eq!(preview.kind, "rotate-pending");
        assert_eq!(fs::read(&old_path).expect("old after preview"), before);
        let error = link_intent(
            root.path(),
            "R",
            &intent,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect_err("absent run");
        assert_eq!(error.kind, "rotate-pending");
        assert!(error.detail.contains("R-rotation-1"));
        let old = super::read_reservation(&super::reservation_path(root.path(), "R"))
            .expect("read")
            .expect("old");
        assert_eq!(old["rotation_intent"], intent);
    }

    /// ´test:unit:second-rotation-refuses-pending-intent-under-mailbox-lock´
    #[test]
    fn second_rotation_refuses_pending_intent_under_mailbox_lock() {
        let (root, _intent) = intent_fixture(false);
        let old = super::read_reservation(&super::reservation_path(root.path(), "R"))
            .expect("read")
            .expect("old");
        let error = publish_intent(
            root.path(),
            "R",
            &old,
            Some("second"),
            &rotation_shape("R-rotation-2"),
            root.path(),
            "digest",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect_err("pending rotation");
        assert_eq!(error.kind, "rotate-pending");
    }

    /// ´test:unit:rotation-selects-stop-of-final-settled-step´
    #[test]
    fn rotation_selects_stop_of_final_settled_step() {
        let record = json!({"rounds":[{"step":"review","phase":"settled","ended_by":"by-report-after-stop"}],"mail":[
            {"step":"review","name":"review-1.md","stop":true,"state":"placed","placed_at_unix_ns":1},
            {"step":"later","name":"later.md","stop":true,"state":"placed","placed_at_unix_ns":2}]});
        assert_eq!(
            stop_for_last_round(&record).expect("last round stop")["name"],
            "review-1.md"
        );
        let missing = json!({"rounds":record["rounds"],"mail":[record["mail"][1]]});
        assert_eq!(
            stop_for_last_round(&missing)
                .expect_err("later step is unrelated")
                .kind,
            "rotate-stop"
        );
    }

    /// ´test:unit:rotation-requires-settlement-and-measured-threshold-or-force´
    #[test]
    fn rotation_requires_settlement_and_measured_threshold_or_force() {
        let record = json!({"phase":"settled","rounds":[{"step":"review","phase":"settled","ended_by":"by-report-after-stop"}],"mail":[{"step":"review","stop":true,"state":"placed"}]});
        assert_eq!(
            check_rotation(&record, &json!({"state":"unknown"}), Some(0.8), None)
                .expect_err("unknown")
                .kind,
            "rotate-context"
        );
        check_rotation(
            &record,
            &json!({"state":"unknown"}),
            Some(0.8),
            Some("host measurement"),
        )
        .expect("forced unknown");
        assert_eq!(
            check_rotation(
                &record,
                &json!({"state":"measured","fraction":0.7}),
                Some(0.8),
                None
            )
            .expect_err("below limit")
            .kind,
            "rotate-threshold"
        );
        check_rotation(
            &record,
            &json!({"state":"measured","fraction":0.8}),
            Some(0.8),
            None,
        )
        .expect("crossed limit");
        let live = json!({"phase":"started","rounds":[{"phase":"running"}]});
        assert_eq!(
            check_rotation(&live, &json!({"state":"unknown"}), None, Some("force"))
                .expect_err("live refuses force")
                .kind,
            "rotate-live"
        );
    }

    /// ´test:unit:handover-names-inbox-and-carries-reply-body´
    #[test]
    fn handover_names_inbox_and_carries_reply_body() {
        let letter = handover_letter(
            &json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}}),
            &json!({"replies":[{"step":"dispatch","outbox":"dispatch.md","sha256":"digest","bytes":8,"inbox":["dispatch.md","dispatch-1.md"],"inbox_letters":[{"step":"dispatch","name":"dispatch.md","sha256":"round","bytes":7,"body":"Question","body_truncated":false},{"step":"dispatch","name":"dispatch-1.md","sha256":"extra","bytes":6,"body":"Follow","body_truncated":false}],"body":"A reply.","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}}),
            "R",
        ).expect("handover");
        assert!(letter.contains("Model: gpt-6-sol\nEffort: high"));
        assert!(letter.contains("dispatch-1.md"));
        assert!(letter.contains("A reply."));
    }

    /// ´test:unit:handover-byte-snapshots-carry-inbox-cut-marker-and-next-task´
    #[test]
    fn handover_byte_snapshots_carry_inbox_cut_marker_and_next_task() {
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(
            crate::build::sha256_bytes(b"abc", Path::new("/")).expect("whole digest"),
            digest
        );
        let record = json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}});
        let reply = json!({"step":"dispatch","outbox":"dispatch.md","sha256":digest,"bytes":3,"inbox":["dispatch.md","dispatch-1.md"],"inbox_letters":[{"step":"dispatch","name":"dispatch.md","sha256":digest,"bytes":3,"body":"abc","body_truncated":false},{"step":"dispatch","name":"dispatch-1.md","sha256":digest,"bytes":3,"body":"abc","body_truncated":false}],"body":"abc","body_truncated":false});
        let absent = json!({"replies":[reply],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}});
        let no_next = handover_letter(&record, &absent, "R").expect("without next");
        assert_eq!(
            no_next,
            include_str!("../../tests/fixtures/handover-no-next.txt")
        );
        let legacy = format!(
            "Model: gpt-6-sol\nEffort: high\n\nHandover from run R. Continue from these replies of record in round order.\n\n## dispatch: dispatch.md\nDigest: {digest}\nInbox letters answered: [\"dispatch.md\",\"dispatch-1.md\"]\n\nabc\n\n"
        );
        assert!(no_next.starts_with(&legacy));
        let mut cut = reply;
        cut["inbox_letters"][1]["body"] = json!("a");
        cut["inbox_letters"][1]["body_truncated"] = json!(true);
        let with_next = json!({"replies":[cut],"next_task":{"state":"present","sha256":digest,"bytes":3,"body":"abc","body_truncated":false}});
        let next_letter = handover_letter(&record, &with_next, "R").expect("with next");
        assert_eq!(
            next_letter,
            include_str!("../../tests/fixtures/handover-next.txt")
        );
        assert_ne!(
            crate::build::sha256_bytes(no_next.as_bytes(), Path::new("/")).expect("first digest"),
            crate::build::sha256_bytes(next_letter.as_bytes(), Path::new("/"))
                .expect("next digest")
        );
    }

    /// ´test:unit:handover-size-bound-marks-the-whole-cut-body´
    #[test]
    fn handover_size_bound_marks_the_whole_cut_body() {
        let whole = "x".repeat(usize::try_from(crate::home::MAX_LETTER).expect("bound fits"));
        let digest = crate::build::sha256_bytes(whole.as_bytes(), Path::new("/"))
            .expect("whole body digest");
        let record = json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}});
        let handover = json!({"replies":[{"step":"dispatch","outbox":"dispatch.md","sha256":digest,"bytes":whole.len(),"inbox":["dispatch.md"],"inbox_letters":[{"step":"dispatch","name":"dispatch.md","sha256":digest,"bytes":whole.len(),"body":whole,"body_truncated":false}],"body":"ok","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}});
        let letter = handover_letter(&record, &handover, "R").expect("bounded handover");
        assert!(letter.len() as u64 <= crate::home::MAX_LETTER);
        assert!(letter.contains("[TRUNCATED INBOX BODY:"));
        assert!(letter.contains(&format!("whole SHA-256 {digest}]")));
    }

    /// ´test:unit:rotation-step-evidence-checks-whole-delivery-digest´
    #[test]
    fn rotation_step_evidence_checks_whole_delivery_digest() {
        let fixture = tempfile::tempdir().expect("evidence fixture");
        let path = fixture.path().join("step-review.txt");
        fs::write(&path, b"abc").expect("retained bytes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("custody");
        let saved = json!({"bytes":3,"sha256":crate::build::sha256_bytes(b"abc",fixture.path()).expect("digest")});
        let held = fs::File::open(fixture.path()).expect("held evidence directory");
        assert_eq!(
            super::read_reply(
                &held,
                "step-review.txt",
                nix::unistd::Uid::effective().as_raw(),
                &saved,
                fixture.path()
            )
            .expect("exact evidence"),
            "abc"
        );
        fs::write(&path, b"abd").expect("changed bytes");
        assert!(
            super::read_reply(
                &held,
                "step-review.txt",
                nix::unistd::Uid::effective().as_raw(),
                &saved,
                fixture.path()
            )
            .is_err()
        );
    }

    /// ´test:unit:rotation-next-task-uses-one-held-file-read´
    #[test]
    fn rotation_next_task_uses_one_held_file_read() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("next fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("owner directory");
        let path = fixture.path().join("next.md");
        fs::write(&path, b"abc").expect("next body");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("next mode");
        let first = super::next_task(
            Some(&path),
            fixture.path(),
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("first held read");
        fs::write(&path, b"abd").expect("replacement body");
        assert_eq!(first["body"], "abc");
        assert_eq!(
            first["sha256"],
            crate::build::sha256_bytes(b"abc", fixture.path()).expect("first digest")
        );
        let second = super::next_task(
            Some(&path),
            fixture.path(),
            "alpha",
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("second held read");
        assert_ne!(first["sha256"], second["sha256"]);
    }

    /// ´test:unit:rotation-preview-letter-equals-published-source-and-leaves-root-unchanged´
    #[test]
    fn rotation_preview_letter_equals_published_source_and_leaves_root_unchanged() {
        let (root, _intent) = intent_fixture(false);
        let config = root.path().join("config");
        fs::create_dir(&config).expect("synthetic config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("owner-only config");
        let old_path = super::reservation_path(root.path(), "R");
        let old_bytes = fs::read(&old_path).expect("old reservation");
        let before = fs::read_dir(root.path())
            .expect("runs root")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<std::collections::BTreeSet<_>>();
        let letter = handover_letter(
            &json!({"model_selection":{"model":"gpt-6-sol","effort":"high"}}),
            &json!({"replies":[{"step":"dispatch","outbox":"dispatch.md","sha256":"digest","bytes":9,"inbox":["dispatch.md"],"inbox_letters":[],"body":"A reply.\n","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}}),
            "R",
        )
        .expect("preview letter");
        let digest = crate::build::sha256_bytes(letter.as_bytes(), root.path()).expect("digest");
        let uid = preview_worker_uid(
            root.path(),
            "R-rotation-1",
            3000,
            2,
            nix::unistd::Uid::effective().as_raw(),
        )
        .expect("read-only UID selection");
        let sign_in = root.path().join("config/lanes/codex/auth.json");
        let preview = handover_preview_fields(&letter, &digest, uid, &sign_in);
        assert_eq!(preview["worker_uid"], 3001);
        assert_eq!(preview["sign_in_source"], json!(sign_in));
        assert_eq!(preview["handover_bytes"], letter.len());
        assert_eq!(preview["handover_sha256"], digest);
        assert_eq!(preview["handover_letter"], letter);
        assert_eq!(fs::read(&old_path).expect("old after preview"), old_bytes);
        let after = fs::read_dir(root.path())
            .expect("runs root after preview")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(after, before);
        assert_eq!(
            fs::read_dir(&config).expect("config after preview").count(),
            0
        );
        let published = publish_handover_source(&config, "R-rotation-1", &letter)
            .expect("changing publication");
        assert_eq!(
            fs::read(&published).expect("published bytes"),
            letter.as_bytes()
        );
        assert_eq!(
            crate::build::sha256_bytes(&fs::read(published).expect("published"), root.path())
                .expect("published digest"),
            digest
        );
    }

    /// ´test:unit:rotation-expected-digest-refuses-a-round-settled-between-calls´
    #[test]
    fn rotation_expected_digest_refuses_a_round_settled_between_calls() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = super::reservation_path(root.path(), "R");
        let mut old = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"model_selection":{"model":"gpt-6-sol","effort":"high"},"rounds":[{"step":"dispatch","phase":"settled","reply":{"sha256":"first"}}]});
        super::publish_reservation(&path, &old).expect("first settled round");
        let first = json!({"replies":[{"step":"dispatch","outbox":"dispatch.md","sha256":"first","bytes":12,"inbox":["dispatch.md"],"inbox_letters":[],"body":"First reply.","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}});
        let (_, preview_digest) = render_handover(&old, &first, "R", root.path()).expect("dry run");
        let owner = nix::unistd::Uid::effective().as_raw();
        {
            let _mailbox = super::lock_mailbox(root.path(), "R", owner).expect("mailbox lock");
            old["rounds"]
                .as_array_mut()
                .expect("rounds")
                .push(json!({"step":"review","phase":"settled","reply":{"sha256":"second"}}));
            super::publish_reservation(&path, &old).expect("second settled round");
        }
        let mailbox = super::lock_mailbox(root.path(), "R", owner).expect("changing lock");
        let current = super::read_reservation(&path)
            .expect("read")
            .expect("old run");
        assert_eq!(current["rounds"].as_array().expect("rounds").len(), 2);
        let second = json!({"replies":[first["replies"][0],{"step":"review","outbox":"review.md","sha256":"second","bytes":13,"inbox":["review.md"],"inbox_letters":[],"body":"Second reply.","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}});
        let (_, rendered_digest) =
            render_handover(&current, &second, "R", root.path()).expect("changing render");
        let error = publish_checked_intent(
            root.path(),
            "R",
            &current,
            None,
            Some(&preview_digest),
            &rotation_shape("R-rotation-1"),
            root.path(),
            &rendered_digest,
            &mailbox,
        )
        .expect_err("changed handover");
        assert_eq!(error.kind, "rotate-handover");
        assert!(error.detail.contains(&preview_digest));
        assert!(error.detail.contains(&rendered_digest));
        let after = super::read_reservation(&path)
            .expect("read after")
            .expect("old run");
        assert!(after.get("rotation_intent").is_none());
    }

    /// ´test:unit:rotation-expected-digest-publishes-preview-bytes´
    #[test]
    fn rotation_expected_digest_publishes_preview_bytes() {
        let root = tempfile::TempDir::new_in("/tmp").expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let config = root.path().join("config");
        fs::create_dir(&config).expect("config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("config mode");
        let old = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,"model_selection":{"model":"gpt-6-sol","effort":"high"},"rounds":[{"step":"dispatch","phase":"settled","reply":{"sha256":"digest"}}]});
        super::publish_reservation(&super::reservation_path(root.path(), "R"), &old)
            .expect("old reservation");
        let replies = json!({"replies":[{"step":"dispatch","outbox":"dispatch.md","sha256":"digest","bytes":8,"inbox":["dispatch.md"],"inbox_letters":[],"body":"A reply.","body_truncated":false}],"next_task":{"state":"absent","sha256":null,"bytes":null,"body":null,"body_truncated":false}});
        let (preview, digest) = render_handover(&old, &replies, "R", root.path()).expect("dry run");
        let mailbox = super::lock_mailbox(root.path(), "R", nix::unistd::Uid::effective().as_raw())
            .expect("changing lock");
        let (changing, rendered) =
            render_handover(&old, &replies, "R", root.path()).expect("changing render");
        let intent = publish_checked_intent(
            root.path(),
            "R",
            &old,
            None,
            Some(&digest),
            &rotation_shape("R-rotation-1"),
            &config,
            &rendered,
            &mailbox,
        )
        .expect("expected digest and intent");
        assert_eq!(intent["letter_sha256"], digest);
        drop(mailbox);
        let source = publish_handover_source(&config, "R-rotation-1", &changing).expect("publish");
        assert_eq!(fs::read(source).expect("letter bytes"), preview.as_bytes());
        assert_eq!(rendered, digest);
    }

    /// ´test:unit:rotation-form-requires-a-reason-for-force´
    #[test]
    fn rotation_form_requires_a_reason_for_force() {
        let args = ["alpha", "R", "--force", "host measured"].map(str::to_owned);
        assert_eq!(
            RotateRequest::parse(&args).expect("force").force.as_deref(),
            Some("host measured")
        );
        assert_eq!(
            RotateRequest::parse(&["alpha", "R", "--force", ""].map(str::to_owned))
                .expect_err("empty reason")
                .kind,
            "rotate-force"
        );
        let digest = "ab".repeat(32);
        let with_digest = ["alpha", "R", "--expect-digest", &digest].map(str::to_owned);
        assert_eq!(
            RotateRequest::parse(&with_digest)
                .expect("expected digest")
                .expect_digest,
            Some(digest)
        );
        assert_eq!(
            RotateRequest::parse(&["alpha", "R", "--expect-digest", "short"].map(str::to_owned))
                .expect_err("invalid digest")
                .kind,
            "rotate-handover"
        );
    }
}
