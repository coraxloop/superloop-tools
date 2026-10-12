//! Prepare a clean owner-controlled checkout from one complete preserved checkpoint.

use super::*;
use std::os::unix::process::CommandExt;
use std::path::Component;
use std::process::Stdio;

const LANE_GIT_NAME: &str = "Lane Worker";
const LANE_GIT_EMAIL: &str = "worker@invalid";
static NEXT_PUBLICATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static FAIL_PUBLICATION_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_OPEN_ONCE: std::cell::Cell<Option<PublicationFault>> = const { std::cell::Cell::new(None) };
    static FAIL_UNLINK_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationFault {
    Write,
    Rename,
}

#[derive(Debug)]
pub struct CheckoutRequest {
    pub loop_name: String,
    pub run: String,
    pub repo: String,
    pub into: PathBuf,
    pub dry_run: bool,
    pub invocation_token: Option<String>,
}

/// Build the private checkout words used by the public command.
///
/// # Errors
///
/// Refuses a destination or owner home that cannot be passed as a path word.
pub fn private_checkout_argv(
    request: &CheckoutRequest,
    owner_home: &Path,
    token: Option<&str>,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec![
        "_checkout".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--into".into(),
        crate::pinned::path_word(&request.into, "checkout-destination")?,
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "checkout-home")?,
        "--repo".into(),
        request.repo.clone(),
    ];
    if let Some(token) = token {
        argv.extend(["--token".into(), token.into()]);
    } else if request.dry_run {
        argv.push("--dry-run".into());
    }
    Ok(argv)
}

impl CheckoutRequest {
    /// Parse one checkout request.
    ///
    /// # Errors
    ///
    /// Refuses missing, repeated, or malformed arguments.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "checkout-usage",
                "checkout LOOP RUN --repo REPO --into DIR [--dry-run]",
            ));
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !valid_run_name(run) {
            return Err(LaneError::input("run-name", "run is not a plain lane word"));
        }
        let (mut repo, mut into, mut dry_run) = (None, None, false);
        let mut index = 0;
        while index < rest.len() {
            match rest[index].as_str() {
                "--repo" if repo.is_none() => {
                    index += 1;
                    repo = rest.get(index).cloned();
                }
                "--into" if into.is_none() => {
                    index += 1;
                    into = rest.get(index).map(PathBuf::from);
                }
                "--dry-run" if !dry_run => dry_run = true,
                _ => {
                    return Err(LaneError::input(
                        "checkout-usage",
                        "checkout LOOP RUN --repo REPO --into DIR [--dry-run]",
                    ));
                }
            }
            index += 1;
        }
        let repo = repo.ok_or_else(|| LaneError::input("checkout-usage", "--repo is absent"))?;
        let into = into.ok_or_else(|| LaneError::input("checkout-usage", "--into is absent"))?;
        if !valid_run_name(&repo) || !plain_absolute(&into) {
            return Err(LaneError::input(
                "checkout-usage",
                "repo must be plain and DIR must be absolute without dotted components",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            repo,
            into,
            dry_run,
            invocation_token: None,
        })
    }
}

fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|value| !value.split('/').any(|part| part == "." || part == ".."))
        && path
            .components()
            .skip(1)
            .all(|component| matches!(component, Component::Normal(_)))
}

fn destination_allowed(into: &Path, home: &Path, runs_root: &Path) -> Result<(), LaneError> {
    let homes_root = home
        .parent()
        .ok_or_else(|| LaneError::input("checkout-destination", "run home has no parent"))?;
    if into.starts_with(homes_root) || into.starts_with(runs_root) {
        return Err(LaneError::input(
            "checkout-destination",
            format!(
                "{} is beneath the owner's temporary home root or the runs root",
                into.display()
            ),
        ));
    }
    Ok(())
}

fn checked_directory(fd: &OwnedFd, path: &Path, owner: u32) -> Result<(), LaneError> {
    let stat = fstat(fd).map_err(|error| {
        LaneError::input(
            "checkout-destination",
            format!("{}: {error}", path.display()),
        )
    })?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    let mode = stat.st_mode & 0o7777;
    if kind != SFlag::S_IFDIR || stat.st_uid != owner || mode & 0o700 != 0o700 || mode & 0o7022 != 0
    {
        return Err(LaneError::input(
            "checkout-destination",
            format!(
                "{} must be an owner-controlled directory without group or other write access",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn target_at(parent: &OwnedFd, into: &Path, owner: u32) -> Result<Option<OwnedFd>, LaneError> {
    let name = into.file_name().ok_or_else(|| {
        LaneError::input("checkout-destination", "destination basename is absent")
    })?;
    let opened = match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => Some(fd),
        Err(nix::errno::Errno::ENOENT) => None,
        Err(error) => {
            return Err(LaneError::input(
                "checkout-destination",
                format!("{}: {error}", into.display()),
            ));
        }
    };
    if let Some(fd) = &opened {
        checked_directory(fd, into, owner)?;
        if !checkpoint::directory_names(fd, into)?.is_empty() {
            return Err(LaneError::input(
                "checkout-destination",
                format!("{} is not empty", into.display()),
            ));
        }
    }
    Ok(opened)
}

pub(super) fn read_record(root: &OwnedFd, run: &str, owner: u32) -> Result<Value, LaneError> {
    read_record_bound(root, run, owner).map(|(record, _)| record)
}

pub(super) fn read_record_bound(
    root: &OwnedFd,
    run: &str,
    owner: u32,
) -> Result<(Value, String), LaneError> {
    let name = format!(".reservation-{run}.json");
    let fd = openat2(
        root,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("checkout-record", format!("{name}: {error}")))?;
    let stat =
        fstat(&fd).map_err(|error| LaneError::input("checkout-record", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
        || u64::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > MAX_RESERVATION_BYTES)
    {
        return Err(LaneError::input(
            "checkout-record",
            "reservation owner, mode, size, or type differs",
        ));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take(MAX_RESERVATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("checkout-record", error.to_string()))?;
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| LaneError::input("checkout-record", error.to_string()))?;
    if record["schema"] != 1 || record["worker_uid"].as_u64().is_none() {
        return Err(LaneError::input(
            "checkout-record",
            "reservation shape differs",
        ));
    }
    super::repin_door::validate(&record)?;
    let digest = crate::build::sha256_bytes(&bytes, Path::new("/"))?;
    Ok((record, format!("{}:{}:{digest}", stat.st_dev, stat.st_ino)))
}

fn publication_failure(root: &OwnedFd, temporary: &str, step: &str, cause: &str) -> LaneError {
    #[cfg(test)]
    let forced = FAIL_UNLINK_ONCE.with(|fail| fail.replace(false));
    #[cfg(not(test))]
    let forced = false;
    let cleanup = if forced {
        Err(nix::errno::Errno::EPERM)
    } else {
        nix::unistd::unlinkat(root, temporary, nix::unistd::UnlinkatFlags::NoRemoveDir)
    };
    match cleanup {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => {
            LaneError::operation("checkout-record", format!("{step}: {cause}"))
        }
        Err(error) => LaneError::operation(
            "checkout-record",
            format!("temporary-residue={temporary} step={step} cleanup={error}; {cause}"),
        ),
    }
}

pub(super) fn publish_record(
    root: &OwnedFd,
    run: &str,
    record: &Value,
    token: &str,
) -> Result<(), LaneError> {
    #[cfg(test)]
    if FAIL_PUBLICATION_ONCE.with(|fail| fail.replace(false)) {
        return Err(LaneError::operation(
            "checkout-record",
            "injected publication failure",
        ));
    }
    let bytes = serde_json::to_vec(record)
        .map_err(|error| LaneError::input("checkout-record", error.to_string()))?;
    if bytes.len() as u64 > MAX_RESERVATION_BYTES {
        return Err(LaneError::input(
            "checkout-record",
            "reservation exceeds reader bound",
        ));
    }
    let (temporary, fd) = loop {
        let sequence = NEXT_PUBLICATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = format!(
            ".reservation-{run}-checkout-{}-{token}-{sequence}.tmp",
            std::process::id()
        );
        let opened = openat2(
            root,
            temporary.as_str(),
            OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                )
                .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        );
        match opened {
            Ok(fd) => break (temporary, fd),
            Err(nix::errno::Errno::EEXIST) => {}
            Err(error) => return Err(LaneError::operation("checkout-record", error.to_string())),
        }
    };
    let mut file = File::from(fd);
    #[cfg(test)]
    let injected = FAIL_AFTER_OPEN_ONCE.with(|fail| fail.replace(None));
    #[cfg(test)]
    if injected == Some(PublicationFault::Write) {
        return Err(publication_failure(
            root,
            &temporary,
            "write",
            "injected write failure",
        ));
    }
    file.write_all(&bytes)
        .map_err(|error| publication_failure(root, &temporary, "write", &error.to_string()))?;
    file.sync_all()
        .map_err(|error| publication_failure(root, &temporary, "sync", &error.to_string()))?;
    #[cfg(test)]
    if injected == Some(PublicationFault::Rename) {
        return Err(publication_failure(
            root,
            &temporary,
            "rename",
            "injected rename failure",
        ));
    }
    renameat(
        root,
        temporary.as_str(),
        root,
        format!(".reservation-{run}.json").as_str(),
    )
    .map_err(|error| publication_failure(root, &temporary, "rename", &error.to_string()))?;
    File::from(
        nix::unistd::dup(root)
            .map_err(|error| LaneError::operation("checkout-record", error.to_string()))?,
    )
    .sync_all()
    .map_err(|error| LaneError::operation("checkout-record", error.to_string()))
}

fn checkout_fields(record: &Value) -> Result<(Vec<Value>, u64, Vec<Value>, u64), LaneError> {
    let fields = [
        "checkouts",
        "checkouts_omitted",
        "checkout_attempts",
        "checkout_next_index",
    ];
    if fields.iter().any(|key| record.get(*key).is_none()) {
        return Err(LaneError::input(
            "checkout-record",
            "checkout fields are absent from this reservation",
        ));
    }
    let checkouts = record["checkouts"]
        .as_array()
        .ok_or_else(|| LaneError::input("checkout-record", "checkout list is malformed"))?;
    let omitted = record["checkouts_omitted"].as_u64().ok_or_else(|| {
        LaneError::input("checkout-record", "checkout omission count is malformed")
    })?;
    let attempts = record["checkout_attempts"]
        .as_array()
        .ok_or_else(|| LaneError::input("checkout-record", "checkout attempts are malformed"))?;
    let next = record["checkout_next_index"]
        .as_u64()
        .filter(|index| *index > 0)
        .ok_or_else(|| LaneError::input("checkout-record", "checkout next index is malformed"))?;
    if checkouts.len() > 64
        || attempts.len() > 64
        || checkouts.iter().any(|entry| {
            entry.as_object().is_none_or(|fields| {
                fields.len() != 5
                    || fields
                        .get("checkpoint_index")
                        .and_then(Value::as_u64)
                        .is_none()
                    || fields.get("object").and_then(Value::as_str).is_none()
                    || fields.get("directory").and_then(Value::as_str).is_none()
                    || fields.get("repo").and_then(Value::as_str).is_none()
                    || fields
                        .get("instant_unix_ns")
                        .and_then(Value::as_u64)
                        .is_none()
            })
        })
        || attempts.iter().any(|entry| {
            entry.as_object().is_none_or(|fields| {
                fields.len() != 13
                    || fields.get("index").and_then(Value::as_u64).is_none()
                    || fields.get("token").and_then(Value::as_str).is_none()
                    || fields
                        .get("checkpoint_index")
                        .and_then(Value::as_u64)
                        .is_none()
                    || fields.get("repo").and_then(Value::as_str).is_none()
                    || fields.get("directory").and_then(Value::as_str).is_none()
                    || fields.get("refusal").and_then(Value::as_str).is_none()
                    || fields.get("detail").and_then(Value::as_str).is_none()
                    || fields
                        .get("residue")
                        .is_none_or(|value| !value.is_null() && !value.is_boolean())
                    || fields.get("path_valid").and_then(Value::as_bool).is_none()
                    || fields.get("path_error").and_then(Value::as_str).is_none()
                    || !matches!(
                        fields.get("created_observed").and_then(Value::as_str),
                        Some("yes" | "no" | "unknown")
                    )
                    || fields
                        .get("instant_unix_ns")
                        .and_then(Value::as_u64)
                        .is_none()
                    || fields.get("disposition").and_then(Value::as_str) != Some("left-for-owner")
                    || (fields.get("residue").is_some_and(Value::is_null)
                        && fields.get("path_valid") == Some(&Value::Bool(true)))
                    || (fields.get("residue") == Some(&Value::Bool(false))
                        && fields.get("path_valid") != Some(&Value::Bool(true)))
                    || (fields.get("created_observed").and_then(Value::as_str) == Some("yes")
                        && fields.get("residue") != Some(&Value::Bool(true)))
            })
        })
    {
        return Err(LaneError::input(
            "checkout-record",
            "checkout journal shape differs",
        ));
    }
    Ok((checkouts.clone(), omitted, attempts.clone(), next))
}

fn pending(record: &Value) -> Result<Option<&Value>, LaneError> {
    let Some(value) = record.get("checkout_pending") else {
        return Ok(None);
    };
    let Some(fields) = value.as_object() else {
        return Err(LaneError::input(
            "checkout-record",
            "pending checkout is malformed",
        ));
    };
    if fields.len() != 8
        || fields.get("index").and_then(Value::as_u64).is_none()
        || fields
            .get("token")
            .and_then(Value::as_str)
            .is_none_or(|token| {
                token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || fields
            .get("checkpoint_index")
            .and_then(Value::as_u64)
            .is_none()
        || fields.get("repo").and_then(Value::as_str).is_none()
        || fields.get("directory").and_then(Value::as_str).is_none()
        || fields.get("object").and_then(Value::as_str).is_none()
        || fields.get("preexisting").and_then(Value::as_bool).is_none()
        || fields
            .get("attempt_instant_unix_ns")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(LaneError::input(
            "checkout-record",
            "pending checkout shape differs",
        ));
    }
    Ok(Some(value))
}

fn instant() -> Result<u128, LaneError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| LaneError::operation("checkout-clock", error.to_string()))
}

fn detail_bytes(detail: &str) -> String {
    let mut bounded = String::new();
    for letter in detail.chars() {
        bounded.push(letter);
        if serde_json::to_string(&bounded).is_ok_and(|serialized| serialized.len() <= 256) {
            continue;
        }
        bounded.pop();
        break;
    }
    bounded
}

fn refusal_kind(kind: &'static str) -> &'static str {
    if serde_json::to_string(kind).is_ok_and(|serialized| serialized.len() <= 256) {
        kind
    } else {
        "checkout-private"
    }
}

fn attempt_bound(record: &Value) -> Result<usize, LaneError> {
    let marker = pending(record)?
        .ok_or_else(|| LaneError::input("checkout-record", "pending checkout is absent"))?;
    let mut failure = record.clone();
    failure
        .as_object_mut()
        .ok_or_else(|| LaneError::input("checkout-record", "reservation is not an object"))?
        .remove("checkout_pending");
    let attempts = failure["checkout_attempts"]
        .as_array_mut()
        .ok_or_else(|| LaneError::input("checkout-record", "checkout attempts are malformed"))?;
    attempts.push(json!({"index":marker["index"],"token":marker["token"],"checkpoint_index":marker["checkpoint_index"],"repo":marker["repo"],"directory":marker["directory"],"refusal":"x".repeat(254),"detail":"x".repeat(254),"residue":false,"path_valid":true,"path_error":"x".repeat(254),"created_observed":"unknown","instant_unix_ns":marker["attempt_instant_unix_ns"],"disposition":"left-for-owner"}));
    serde_json::to_vec(&failure)
        .map(|bytes| bytes.len())
        .map_err(|error| LaneError::input("checkout-record", error.to_string()))
}

fn pending_fits(record: &Value) -> Result<(), LaneError> {
    let pending_size = serde_json::to_vec(record)
        .map_err(|error| LaneError::input("checkout-record", error.to_string()))?
        .len();
    if pending_size as u64 > MAX_RESERVATION_BYTES
        || attempt_bound(record)? as u64 > MAX_RESERVATION_BYTES
    {
        return Err(LaneError::input(
            "checkout-size",
            "reservation has no room for a refusal attempt",
        ));
    }
    Ok(())
}

fn residue(parent: Option<&OwnedFd>, directory: &Path, owner: u32) -> (Option<bool>, bool, String) {
    let Some(parent) = parent else {
        return (None, false, "parent could not be pinned".into());
    };
    let Some(name) = directory.file_name() else {
        return (None, false, "basename is absent".into());
    };
    match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Err(nix::errno::Errno::ENOENT) => (Some(false), true, String::new()),
        Err(error) => (None, false, error.to_string()),
        Ok(fd) => match fstat(&fd) {
            Err(error) => (Some(true), false, error.to_string()),
            Ok(stat) => {
                let mode = stat.st_mode & 0o7777;
                let valid = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
                    == SFlag::S_IFDIR
                    && stat.st_uid == owner
                    && mode & 0o700 == 0o700
                    && mode & 0o7022 == 0;
                (Some(true), valid, String::new())
            }
        },
    }
}

fn record_failure(
    root: &OwnedFd,
    run: &str,
    record: &mut Value,
    token: &str,
    error: &LaneError,
    observed: &(Option<bool>, bool, String),
    created_observed: &str,
) -> Result<(), LaneError> {
    let marker = pending(record)?
        .ok_or_else(|| LaneError::input("checkout-record", "pending checkout is absent"))?
        .clone();
    if marker["token"] != token {
        return Err(LaneError::input(
            "checkout-record",
            "another checkout token is pending",
        ));
    }
    let (checkouts, omitted, mut attempts, next) = checkout_fields(record)?;
    if attempts.len() >= 64 {
        return Err(LaneError::input(
            "checkout-size",
            "checkout attempt journal is full",
        ));
    }
    attempts.push(json!({"index":marker["index"],"token":token,"checkpoint_index":marker["checkpoint_index"],"repo":marker["repo"],"directory":marker["directory"],"refusal":refusal_kind(error.kind),"detail":detail_bytes(&error.detail),"residue":observed.0,"path_valid":observed.1,"path_error":detail_bytes(&observed.2),"created_observed":created_observed,"instant_unix_ns":marker["attempt_instant_unix_ns"],"disposition":"left-for-owner"}));
    record["checkouts"] = json!(checkouts);
    record["checkouts_omitted"] = json!(omitted);
    record["checkout_attempts"] = json!(attempts);
    record["checkout_next_index"] = json!(next);
    checkout_fields(record)?;
    record
        .as_object_mut()
        .ok_or_else(|| LaneError::input("checkout-record", "reservation is not an object"))?
        .remove("checkout_pending");
    publish_record(root, run, record, token)
}

fn append_checkout(
    record: &mut Value,
    index: u64,
    repo: &str,
    object: &str,
    directory: &Path,
    read_instant: impl FnOnce() -> Result<u128, LaneError>,
) -> Result<(), LaneError> {
    let (mut checkouts, mut omitted, attempts, next) = checkout_fields(record)?;
    let imports = super::imports::validated(record)?;
    if checkouts
        .iter()
        .any(|entry| entry["repo"] == repo && entry["checkpoint_index"] == index)
    {
        return Err(LaneError::input(
            "checkout-duplicate",
            "repo and checkpoint already have an external checkout",
        ));
    }
    checkouts.push(json!({"checkpoint_index":index,"object":object,"directory":directory,"repo":repo,"instant_unix_ns":read_instant()?}));
    if checkouts.len() > 16
        && let Some(position) = checkouts[..checkouts.len() - 1].iter().position(|entry| {
            !imports.iter().any(|mark| {
                mark["checkpoint_index"] == entry["checkpoint_index"]
                    && mark["repo"] == entry["repo"]
                    && mark["object"] == entry["object"]
            })
        })
    {
        checkouts.remove(position);
        omitted = omitted
            .checked_add(1)
            .ok_or_else(|| LaneError::input("checkout-size", "omission count overflow"))?;
    }
    if checkouts.len() > 64 {
        return Err(LaneError::input(
            "checkout-size",
            "all retained checkout tuples explain marked imports",
        ));
    }
    record["checkouts"] = json!(checkouts);
    record["checkouts_omitted"] = json!(omitted);
    record["checkout_attempts"] = json!(attempts);
    record["checkout_next_index"] = json!(next);
    record
        .as_object_mut()
        .ok_or_else(|| LaneError::input("checkout-record", "reservation is not an object"))?
        .remove("checkout_pending");
    Ok(())
}

fn recover_pending(
    owner_home: &Path,
    root: &Path,
    run: &str,
    token: Option<&str>,
    reason: &str,
) -> Result<(), LaneError> {
    let owner = Uid::effective().as_raw();
    let root_fd = home::pin_parent(root, owner)?;
    let _mailbox = lock_mailbox(root, run, owner)?;
    let mut record = read_record(&root_fd, run, owner)?;
    checkout_fields(&record)?;
    let Some(marker) = pending(&record)?.cloned() else {
        return Ok(());
    };
    let found = marker["token"].as_str().unwrap_or_default();
    if token.is_some_and(|token| token != found) {
        return Err(LaneError::input(
            "checkout-record",
            "another checkout token is pending",
        ));
    }
    let directory = PathBuf::from(marker["directory"].as_str().unwrap_or_default());
    let parent = directory.parent().and_then(|path| {
        home::verify_host_launch_root(Path::new("/"), owner_home, path, owner, 0).ok()
    });
    let observed = residue(parent.as_ref(), &directory, owner);
    let error = LaneError::input("checkout-private", reason);
    let created = if marker["preexisting"] == true {
        "no"
    } else {
        "unknown"
    };
    record_failure(
        &root_fd,
        run,
        &mut record,
        found,
        &error,
        &observed,
        created,
    )
}

#[allow(unsafe_code)]
fn bind_git(command: &mut Command, directory: &OwnedFd) {
    let raw = directory.as_raw_fd();
    // SAFETY: the held descriptor stays open through spawn and binds the child's cwd.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(raw) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

fn git(mut command: Command, directory: &OwnedFd, step: &str) -> Result<Vec<u8>, LaneError> {
    bind_git(&mut command, directory);
    let output = command
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| LaneError::operation("checkout-git", format!("{step}: {error}")))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(LaneError::input(
            "checkout-git",
            format!("{step}: {}", detail.chars().take(512).collect::<String>()),
        ));
    }
    Ok(output.stdout)
}

#[allow(clippy::too_many_lines)]
fn clone_checkout(
    bare: &OwnedFd,
    target: &OwnedFd,
    run: &str,
    expected: &str,
) -> Result<(), LaneError> {
    let mut init = Command::new("/usr/bin/git");
    init.args(["init", "-q"]);
    git(init, target, "initialize external checkout")?;
    let mut pack = Command::new("/usr/bin/git");
    pack.args([
        "-c",
        "safe.directory=*",
        "--git-dir=.",
        "pack-objects",
        "--stdout",
        "--all",
    ])
    .env_clear()
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    bind_git(&mut pack, bare);
    let mut source = pack.spawn().map_err(|error| {
        LaneError::operation("checkout-git", format!("pack preserved bare: {error}"))
    })?;
    let mut index = Command::new("/usr/bin/git");
    index
        .args(["index-pack", "--stdin"])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    bind_git(&mut index, target);
    let mut receiver = index.spawn().map_err(|error| {
        drop(source.kill());
        drop(source.wait());
        LaneError::operation("checkout-git", format!("index preserved pack: {error}"))
    })?;
    let copied = std::io::copy(
        source
            .stdout
            .as_mut()
            .ok_or_else(|| LaneError::operation("checkout-git", "pack stream is absent"))?,
        receiver
            .stdin
            .as_mut()
            .ok_or_else(|| LaneError::operation("checkout-git", "index stream is absent"))?,
    );
    drop(receiver.stdin.take());
    if copied.is_err() {
        drop(source.kill());
        drop(receiver.kill());
    }
    let source_status = source
        .wait()
        .map_err(|error| LaneError::operation("checkout-git", format!("pack wait: {error}")))?;
    let receiver_status = receiver
        .wait()
        .map_err(|error| LaneError::operation("checkout-git", format!("index wait: {error}")))?;
    if copied.is_err() || !source_status.success() || !receiver_status.success() {
        return Err(LaneError::input(
            "checkout-git",
            "preserved pack transfer failed",
        ));
    }
    let mut checkout = Command::new("/usr/bin/git");
    checkout
        .args(["checkout", "-q", "-B"])
        .arg(format!("lane/{run}"))
        .arg(expected);
    git(checkout, target, "check out recorded object")?;
    for (key, value) in [
        ("user.name", LANE_GIT_NAME),
        ("user.email", LANE_GIT_EMAIL),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
    ] {
        let mut config = Command::new("/usr/bin/git");
        config.args(["config", "--local", key, value]);
        git(config, target, "set lane identity")?;
    }
    let mut rev = Command::new("/usr/bin/git");
    rev.args(["rev-parse", "HEAD"]);
    let actual = git(rev, target, "read checked-out object")?;
    if std::str::from_utf8(&actual).unwrap_or_default().trim() != expected {
        return Err(LaneError::input(
            "checkout-object",
            "checked-out object differs from preserved ref",
        ));
    }
    let mut branch = Command::new("/usr/bin/git");
    branch.args(["symbolic-ref", "HEAD"]);
    let actual_branch = git(branch, target, "read checked-out branch")?;
    if std::str::from_utf8(&actual_branch)
        .unwrap_or_default()
        .trim()
        != format!("refs/heads/lane/{run}")
    {
        return Err(LaneError::input(
            "checkout-object",
            "checkout is not on the lane branch",
        ));
    }
    let mut status = Command::new("/usr/bin/git");
    status.args(["status", "--porcelain=v1", "--untracked-files=all"]);
    if !git(status, target, "inspect checkout cleanliness")?.is_empty() {
        return Err(LaneError::input(
            "checkout-dirty",
            "external checkout is not clean",
        ));
    }
    Ok(())
}

/// Enter the owner namespace with held home, runs-root, and destination descriptors.
///
/// # Errors
/// Refuses an unsafe destination or private checkout failure.
#[allow(clippy::too_many_lines)]
pub fn run(owner_home: &Path, request: &CheckoutRequest) -> Result<Value, LaneError> {
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("checkout-grant", "runs_root is absent"))?;
    destination_allowed(&request.into, &plan.home, root)?;
    let owner = Uid::effective().as_raw();
    let podman = plan.document["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("checkout-record", "container program is absent"))?;
    crate::pinned::owner_executable(Path::new(podman), owner)?;
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let parent_path = request
        .into
        .parent()
        .ok_or_else(|| LaneError::input("checkout-destination", "destination parent is absent"))?;
    let parent = home::verify_host_launch_root(Path::new("/"), owner_home, parent_path, owner, 0)?;
    if !request.dry_run {
        recover_pending(
            owner_home,
            root,
            &request.run,
            None,
            "interrupted checkout recovered by the next invocation",
        )?;
    }
    target_at(&parent, &request.into, owner)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("checkout-program", error.to_string()))?;
    crate::pinned::owner_executable(&exe, owner)?;
    let mut argv = vec![
        "unshare".into(),
        crate::pinned::path_word(&exe, "checkout-program")?,
    ];
    let token = if request.dry_run {
        None
    } else {
        let token = checkpoint::random_token()?;
        Some(token)
    };
    argv.extend(private_checkout_argv(
        request,
        owner_home,
        token.as_deref(),
    )?);
    let output = build::run_checked_with_private_launch(
        Path::new(podman),
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        300,
        "checkout-private",
        &home_fd,
        root,
        &runs_fd,
        Some((parent_path, &parent)),
    )
    .map_err(|error| {
        if let Some(token) = token.as_deref()
            && let Err(recovery) = recover_pending(
                owner_home,
                root,
                &request.run,
                Some(token),
                "private checkout failed or reached its 300 second limit",
            )
        {
            return LaneError::operation(
                "checkout-private",
                format!("{}; recovery: {}", error.line(), recovery.line()),
            );
        }
        for kind in [
            "checkout-destination",
            "checkout-checkpoint",
            "checkout-record",
            "checkout-repo",
            "checkout-object",
            "checkout-dirty",
            "checkout-git",
        ] {
            if error.detail.contains(&format!("{kind}:")) {
                return LaneError::input(kind, error.detail);
            }
        }
        error
    })?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::operation("checkout-private", error.to_string()))
}

/// Clone from one verified preserved bare while holding the mailbox lock.
///
/// # Errors
/// Refuses an unsafe destination, absent checkpoint, or changed preserved content.
#[allow(clippy::too_many_lines)]
pub fn private_run(owner_home: &Path, request: &CheckoutRequest) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("checkout-grant", "runs_root is absent"))?;
    private_run_with_plan(&plan, root, request, Uid::effective().as_raw())
}

#[allow(clippy::too_many_lines)]
pub(super) fn private_run_with_plan(
    plan: &crate::plan::Plan,
    root: &Path,
    request: &CheckoutRequest,
    owner: u32,
) -> Result<Value, LaneError> {
    destination_allowed(&request.into, &plan.home, root)?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let root_fd = home::pin_parent(root, owner)?;
    let _mailbox = if request.dry_run {
        checkpoint::existing_checkpoint_lock(root, &request.run, owner, "letter", false)
            .map_err(|error| LaneError::input("checkout-record", error.line()))?
    } else {
        lock_mailbox(root, &request.run, owner)?
    };
    let mut record = read_record(&root_fd, &request.run, owner)?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || record["phase"] != "settled"
        || record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "checkout-record",
            "reservation is not this settled run",
        ));
    }
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(&record)
        .map_err(|error| LaneError::input("checkout-checkpoint", error.line()))?;
    let checkpoint = checkpoints
        .last()
        .ok_or_else(|| LaneError::input("checkout-checkpoint", "complete checkpoint is absent"))?;
    let index = checkpoint["index"]
        .as_u64()
        .ok_or_else(|| LaneError::input("checkout-checkpoint", "checkpoint index is malformed"))?;
    let bares = checkpoint["bares"]
        .as_array()
        .ok_or_else(|| LaneError::input("checkout-checkpoint", "checkpoint bare list is absent"))?;
    let selected = bares
        .iter()
        .filter(|bare| bare["name"] == request.repo)
        .collect::<Vec<_>>();
    let [bare] = selected.as_slice() else {
        return Err(LaneError::input(
            "checkout-repo",
            "repo is absent or repeated in checkpoint",
        ));
    };
    let object = bare["object"]
        .as_str()
        .ok_or_else(|| LaneError::input("checkout-checkpoint", "recorded object is absent"))?;
    let files = checkpoint["files"]
        .as_array()
        .ok_or_else(|| LaneError::input("checkout-checkpoint", "checkpoint file list is absent"))?;
    let run_fd = home::pin_loop_round(root, &plan.driver_dir, owner, loop_uid)?;
    let verified = checkpoint::verify_preserved_copy(
        &run_fd,
        &plan.driver_dir,
        index,
        files,
        &request.repo,
        &request.run,
        object,
        loop_uid,
    )
    .map_err(|error| LaneError::input("checkout-checkpoint", error.line()))?;
    let (checkouts, omitted, attempts, next) = checkout_fields(&record)?;
    if pending(&record)?.is_some() {
        return Err(LaneError::input(
            "checkout-record",
            "pending checkout requires owner recovery",
        ));
    }
    if record.get("checkout").is_some() {
        return Err(LaneError::input(
            "checkout-record",
            "singular checkout field is not this record shape",
        ));
    }
    if checkouts
        .iter()
        .any(|entry| entry["repo"] == request.repo && entry["checkpoint_index"] == index)
    {
        return Err(LaneError::input(
            "checkout-duplicate",
            "repo and checkpoint already have an external checkout",
        ));
    }
    let parent_path = request
        .into
        .parent()
        .ok_or_else(|| LaneError::input("checkout-destination", "destination parent is absent"))?;
    let parent = home::pin_parent(parent_path, owner)?;
    let existing = target_at(&parent, &request.into, owner)?;
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"checkout","loop":request.loop_name,"run":request.run,"repo":request.repo,"dry_run":true,"checkpoint_index":index,"object":object,"preserved_bare":verified.path,"directory":request.into,"directory_exists":existing.is_some()}),
        );
    }
    let name = request.into.file_name().ok_or_else(|| {
        LaneError::input("checkout-destination", "destination basename is absent")
    })?;
    let token = request
        .invocation_token
        .as_deref()
        .ok_or_else(|| LaneError::input("checkout-record", "invocation token is absent"))?;
    if attempts.len() >= 64 {
        return Err(LaneError::input(
            "checkout-size",
            "checkout attempt journal is full",
        ));
    }
    let next_index = next
        .checked_add(1)
        .ok_or_else(|| LaneError::input("checkout-size", "checkout index overflow"))?;
    record["checkouts"] = json!(checkouts);
    record["checkouts_omitted"] = json!(omitted);
    record["checkout_attempts"] = json!(attempts);
    record["checkout_next_index"] = json!(next_index);
    let attempt_instant = instant()?;
    record["checkout_pending"] = json!({"index":next,"token":token,"checkpoint_index":index,"repo":request.repo,"directory":request.into,"object":object,"preexisting":existing.is_some(),"attempt_instant_unix_ns":attempt_instant});
    pending_fits(&record)?;
    publish_record(&root_fd, &request.run, &record, token)?;
    let mut completed = record.clone();
    let mut created = false;
    let result = (|| -> Result<(), LaneError> {
        let target = if let Some(existing) = existing {
            existing
        } else {
            nix::sys::stat::mkdirat(&parent, name, nix::sys::stat::Mode::S_IRWXU).map_err(
                |error| {
                    LaneError::input(
                        "checkout-destination",
                        format!("{}: {error}", request.into.display()),
                    )
                },
            )?;
            created = true;
            target_at(&parent, &request.into, owner)?.ok_or_else(|| {
                LaneError::input("checkout-destination", "created destination disappeared")
            })?
        };
        let target_stat = fstat(&target)
            .map_err(|error| LaneError::input("checkout-destination", error.to_string()))?;
        clone_checkout(&verified.fd, &target, &request.run, object)?;
        let reopened = openat2(
            &parent,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| LaneError::input("checkout-destination", error.to_string()))?;
        checked_directory(&reopened, &request.into, owner)?;
        let fresh_stat = fstat(&reopened)
            .map_err(|error| LaneError::input("checkout-destination", error.to_string()))?;
        if fresh_stat.st_dev != target_stat.st_dev || fresh_stat.st_ino != target_stat.st_ino {
            return Err(LaneError::input(
                "checkout-destination",
                "destination inode changed during clone",
            ));
        }
        append_checkout(
            &mut completed,
            index,
            &request.repo,
            object,
            &request.into,
            instant,
        )?;
        publish_record(&root_fd, &request.run, &completed, token)
    })();
    if let Err(error) = result {
        let observed = residue(Some(&parent), &request.into, owner);
        let created_observed = if created {
            if observed.0 == Some(true) {
                "yes"
            } else {
                "unknown"
            }
        } else {
            "no"
        };
        if let Err(refusal) = record_failure(
            &root_fd,
            &request.run,
            &mut record,
            token,
            &error,
            &observed,
            created_observed,
        ) {
            return Err(LaneError::operation(
                "checkout-private",
                format!("{}; disposition: {}", error.line(), refusal.line()),
            ));
        }
        return Err(error);
    }
    Ok(
        json!({"schema":1,"command":"checkout","loop":request.loop_name,"run":request.run,"repo":request.repo,"dry_run":false,"checkpoint_index":index,"object":object,"preserved_bare":verified.path,"directory":request.into}),
    )
}

#[cfg(test)]
mod tests {
    use super::{CheckoutRequest, clone_checkout, destination_allowed, target_at};
    use crate::launch::checkpoint::verify_preserved_copy;
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::Path;
    use std::process::Command;

    fn mode(path: &Path, value: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(value)).expect("fixture mode");
    }

    fn secure_tree(path: &Path) {
        if path.is_dir() {
            mode(path, 0o700);
            for entry in fs::read_dir(path).expect("fixture directory") {
                secure_tree(&entry.expect("fixture entry").path());
            }
        } else {
            mode(path, 0o600);
        }
    }

    fn git(command: &mut Command) -> Vec<u8> {
        let output = command.output().expect("fixture Git");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn manifest(root: &Path, directory: &Path, result: &mut Vec<Value>) {
        for entry in fs::read_dir(directory).expect("fixture directory") {
            let entry = entry.expect("fixture entry");
            let path = entry.path();
            if entry.file_type().expect("fixture type").is_dir() {
                manifest(root, &path, result);
            } else {
                let output = git(Command::new("/usr/bin/sha256sum").arg(&path));
                let sha256 = std::str::from_utf8(&output[..64]).expect("digest");
                result.push(json!({
                    "path":path.strip_prefix(root).expect("relative").to_str().expect("UTF-8"),
                    "size":entry.metadata().expect("fixture metadata").len(),
                    "sha256":sha256,
                }));
            }
        }
    }

    /// ´test:unit:checkout-request-and-destination-refuse-home-runs-and-unsafe-words´
    #[test]
    fn checkout_request_and_destination_refuse_home_runs_and_unsafe_words() {
        let request = CheckoutRequest::parse(&[
            "alpha".into(),
            "R".into(),
            "--repo".into(),
            "tools".into(),
            "--into".into(),
            "/srv/external/R".into(),
            "--dry-run".into(),
        ])
        .expect("request");
        assert!(request.dry_run);
        for into in [
            "/srv/owner/.cache/tmp/lane-alpha-R/gate",
            "/srv/owner/.cache/tmp/external-gate",
            "/srv/runs/R/gate",
        ] {
            let error = destination_allowed(
                Path::new(into),
                Path::new("/srv/owner/.cache/tmp/lane-alpha-R"),
                Path::new("/srv/runs"),
            )
            .expect_err("inside protected roots");
            assert_eq!(error.kind, "checkout-destination");
            assert!(
                error
                    .detail
                    .contains("temporary home root or the runs root")
            );
        }
        assert_eq!(
            CheckoutRequest::parse(&[
                "alpha".into(),
                "R".into(),
                "--repo".into(),
                "bad/name".into(),
                "--into".into(),
                "/srv/external/R".into(),
            ])
            .expect_err("bad repo")
            .kind,
            "checkout-usage"
        );
    }

    /// ´test:unit:checkout-target-refuses-nonempty-and-linked-destinations´
    #[test]
    fn checkout_target_refuses_nonempty_and_linked_destinations() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let parent =
            crate::home::pin_parent(fixture.path(), nix::unistd::Uid::effective().as_raw())
                .expect("pinned parent");
        let target = fixture.path().join("external");
        assert!(
            target_at(&parent, &target, nix::unistd::Uid::effective().as_raw())
                .expect("absent preview")
                .is_none()
        );
        assert!(!target.exists());
        fs::create_dir(&target).expect("target");
        mode(&target, 0o700);
        fs::write(target.join("untracked"), b"content").expect("untracked");
        assert_eq!(
            target_at(&parent, &target, nix::unistd::Uid::effective().as_raw())
                .expect_err("nonempty")
                .kind,
            "checkout-destination"
        );
        fs::remove_file(target.join("untracked")).expect("remove fixture file");
        fs::remove_dir(&target).expect("remove fixture directory");
        symlink("other", &target).expect("linked target");
        assert_eq!(
            target_at(&parent, &target, nix::unistd::Uid::effective().as_raw())
                .expect_err("link")
                .kind,
            "checkout-destination"
        );
    }

    /// ´test:unit:checkout-clones-only-verified-preserved-objects´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn checkout_clones_only_verified_preserved_objects() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let driver = fixture.path().join("driver");
        let preserved = driver.join("preserved/1");
        let sources = preserved.join("sources");
        fs::create_dir_all(&sources).expect("preserved sources");
        fs::create_dir(preserved.join("inbox")).expect("inbox");
        fs::create_dir(preserved.join("outbox")).expect("outbox");
        for path in [
            &driver,
            &driver.join("preserved"),
            &preserved,
            &sources,
            &preserved.join("inbox"),
            &preserved.join("outbox"),
        ] {
            mode(path, 0o700);
        }
        let bare = sources.join("tools.git");
        git(Command::new("/usr/bin/git")
            .args(["init", "-q", "--bare"])
            .arg(&bare));
        mode(&bare, 0o700);
        mode(&bare.join("config"), 0o600);
        let work = fixture.path().join("work");
        git(Command::new("/usr/bin/git").args(["init", "-q"]).arg(&work));
        fs::write(work.join("note"), b"preserved commit\n").expect("note");
        git(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&work)
            .args(["add", "note"]));
        git(Command::new("/usr/bin/git").arg("-C").arg(&work).args([
            "-c",
            "user.name=Worker",
            "-c",
            "user.email=worker@invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ]));
        git(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&work)
            .arg("push")
            .arg(&bare)
            .arg("HEAD:refs/heads/lane/R"));
        secure_tree(&bare);
        let object = String::from_utf8(git(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&work)
            .args(["rev-parse", "HEAD"])))
        .expect("object");
        let object = object.trim();
        let mut files = Vec::new();
        manifest(&preserved, &preserved, &mut files);
        let driver_fd = nix::fcntl::open(
            &driver,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("driver descriptor");
        let uid = nix::unistd::Uid::effective().as_raw();
        let source =
            verify_preserved_copy(&driver_fd, &driver, 1, &files, "tools", "R", object, uid)
                .expect("preserved source verified");
        assert_eq!(source.path, bare);
        let external = fixture.path().join("external");
        fs::create_dir(&external).expect("external checkout directory");
        mode(&external, 0o700);
        let target = nix::fcntl::open(
            &external,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("target descriptor");
        clone_checkout(&source.fd, &target, "R", object).expect("external checkout");
        let checked = String::from_utf8(git(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&external)
            .args(["rev-parse", "HEAD"])))
        .expect("checked object");
        assert_eq!(checked.trim(), object);
        let identity = String::from_utf8(git(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&external)
            .args(["config", "--local", "--get", "user.name"])))
        .expect("identity");
        assert_eq!(identity.trim(), "Lane Worker");
        fs::write(bare.join("description"), b"changed after checkpoint\n")
            .expect("change preserved file");
        assert_eq!(
            verify_preserved_copy(&driver_fd, &driver, 1, &files, "tools", "R", object, uid)
                .expect_err("changed preservation")
                .kind,
            "checkout-checkpoint"
        );
    }

    /// ´test:unit:checkout-record-retains-two-source-checkouts´
    #[test]
    fn checkout_record_retains_two_source_checkouts() {
        assert_eq!(
            super::checkout_fields(&json!({"schema":1,"worker_uid":3000}))
                .expect_err("older record shape")
                .kind,
            "checkout-record"
        );
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":1,"imports":[]});
        super::append_checkout(
            &mut record,
            1,
            "tools",
            &"1".repeat(40),
            Path::new("/external/tools"),
            super::instant,
        )
        .expect("first source");
        super::append_checkout(
            &mut record,
            1,
            "notes",
            &"2".repeat(40),
            Path::new("/external/notes"),
            super::instant,
        )
        .expect("second source");
        assert_eq!(record["checkouts"].as_array().expect("checkouts").len(), 2);
        assert_eq!(record["checkouts_omitted"], 0);
        assert_eq!(
            super::append_checkout(
                &mut record,
                1,
                "tools",
                &"1".repeat(40),
                Path::new("/external/again"),
                super::instant,
            )
            .expect_err("duplicate source and checkpoint")
            .kind,
            "checkout-duplicate"
        );
        assert_eq!(record["checkouts"].as_array().expect("checkouts").len(), 2);
    }

    /// ´test:unit:marked-import-checkout-tuple-survives-bounded-retention´
    #[test]
    fn marked_import_checkout_tuple_survives_bounded_retention() {
        let object = "a".repeat(40);
        let other_object = "b".repeat(40);
        let checkpoint = json!({"index":1,"instant_unix_ns":1,"round_after":"a","files":[],"bares":[{"name":"repo0","declared":true,"seed":null,"lane_ref":"present","object":object}]});
        let mut record = json!({"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":1,"imports":[{"checkpoint_index":1,"repo":"repo0","object":object,"instant_unix_ns":2}],"checkpoints":[checkpoint]});
        for index in 0..17 {
            let repo = format!("repo{index}");
            super::append_checkout(
                &mut record,
                1,
                &repo,
                if index == 0 { &object } else { &other_object },
                Path::new("/external/checkout"),
                || Ok(3),
            )
            .expect("bounded checkout");
        }
        let checkouts = record["checkouts"].as_array().expect("checkouts");
        assert_eq!(checkouts.len(), 16);
        assert_eq!(record["checkouts_omitted"], 1);
        assert!(checkouts.iter().any(|entry| entry["repo"] == "repo0"));
        assert!(!checkouts.iter().any(|entry| entry["repo"] == "repo1"));
    }

    /// ´test:unit:checkout-failed-clone-and-recovery-explain-left-directory´
    #[test]
    fn checkout_failed_clone_and_recovery_explain_left_directory() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let root = fixture.path().join("runs");
        let outside = fixture.path().join("outside");
        let bad_source = fixture.path().join("bad-source");
        for path in [&root, &outside, &bad_source] {
            fs::create_dir(path).expect("directory");
            mode(path, 0o700);
        }
        let destination = outside.join("R");
        fs::create_dir(&destination).expect("destination");
        mode(&destination, 0o700);
        let owner = nix::unistd::Uid::effective().as_raw();
        let root_fd = crate::home::pin_parent(&root, owner).expect("runs descriptor");
        let parent = crate::home::pin_parent(&outside, owner).expect("outside descriptor");
        let source = crate::home::pin_parent(&bad_source, owner).expect("source descriptor");
        let target = crate::home::pin_parent(&destination, owner).expect("target descriptor");
        let first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"checkout_pending":{"index":1,"token":first,"checkpoint_index":1,"repo":"tools","directory":destination,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":super::instant().expect("attempt instant")}});
        super::publish_record(&root_fd, "R", &record, first).expect("pending before clone");
        let error = super::clone_checkout(&source, &target, "R", &"1".repeat(40))
            .expect_err("bad source interrupts clone");
        assert!(destination.join(".git").exists());
        super::record_failure(
            &root_fd,
            "R",
            &mut record,
            first,
            &error,
            &super::residue(Some(&parent), &destination, owner),
            "yes",
        )
        .expect("failure disposition");
        assert!(record.get("checkout_pending").is_none());
        assert_eq!(record["checkout_attempts"][0]["residue"], true);
        assert_eq!(record["checkout_attempts"][0]["created_observed"], "yes");
        assert_eq!(
            record["checkout_attempts"][0]["disposition"],
            "left-for-owner"
        );
        let second = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        record["checkout_pending"] = json!({"index":2,"token":second,"checkpoint_index":1,"repo":"notes","directory":destination,"object":"2".repeat(40),"preexisting":false,"attempt_instant_unix_ns":super::instant().expect("attempt instant")});
        record["checkout_next_index"] = json!(3);
        super::publish_record(&root_fd, "R", &record, second).expect("interrupted marker");
        super::recover_pending(fixture.path(), &root, "R", None, "interrupted clone")
            .expect("owner recovery");
        let saved = super::read_record(&root_fd, "R", owner).expect("saved record");
        assert!(saved.get("checkout_pending").is_none());
        assert_eq!(
            saved["checkout_attempts"]
                .as_array()
                .expect("attempts")
                .len(),
            2
        );
        assert_eq!(saved["checkout_attempts"][1]["token"], second);
        assert_eq!(saved["checkout_attempts"][1]["created_observed"], "unknown");
        assert!(destination.join(".git").exists());
    }

    /// ´test:unit:checkout-clock-refusal-publishes-premeasured-attempt´
    #[test]
    fn checkout_clock_refusal_publishes_premeasured_attempt() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let root = fixture.path().join("runs");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).expect("runs");
        fs::create_dir(&outside).expect("outside");
        mode(&root, 0o700);
        mode(&outside, 0o700);
        let destination = outside.join("R");
        fs::create_dir(&destination).expect("created destination");
        mode(&destination, 0o700);
        let owner = nix::unistd::Uid::effective().as_raw();
        let root_fd = crate::home::pin_parent(&root, owner).expect("runs descriptor");
        let parent = crate::home::pin_parent(&outside, owner).expect("outside descriptor");
        let token = "cccccccccccccccccccccccccccccccc";
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"imports":[],"checkout_pending":{"index":1,"token":token,"checkpoint_index":1,"repo":"tools","directory":destination,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":123}});
        super::publish_record(&root_fd, "R", &record, token).expect("pending marker");
        let error = super::append_checkout(
            &mut record,
            1,
            "tools",
            &"1".repeat(40),
            &destination,
            || {
                Err(crate::error::LaneError::operation(
                    "checkout-clock",
                    "clock refused",
                ))
            },
        )
        .expect_err("clock refusal");
        assert_eq!(error.kind, "checkout-clock");
        super::record_failure(
            &root_fd,
            "R",
            &mut record,
            token,
            &error,
            &super::residue(Some(&parent), &destination, owner),
            "yes",
        )
        .expect("attempt published without another clock read");
        let saved = super::read_record(&root_fd, "R", owner).expect("saved record");
        assert!(saved.get("checkout_pending").is_none());
        assert_eq!(saved["checkout_attempts"][0]["refusal"], "checkout-clock");
        assert_eq!(saved["checkout_attempts"][0]["instant_unix_ns"], 123);
    }

    /// ´test:unit:checkout-completion-publication-failure-records-attempt´
    #[test]
    fn checkout_completion_publication_failure_records_attempt() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let root = fixture.path().join("runs");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).expect("runs");
        fs::create_dir(&outside).expect("outside");
        mode(&root, 0o700);
        mode(&outside, 0o700);
        let destination = outside.join("R");
        let owner = nix::unistd::Uid::effective().as_raw();
        let root_fd = crate::home::pin_parent(&root, owner).expect("runs descriptor");
        let parent = crate::home::pin_parent(&outside, owner).expect("outside descriptor");
        let token = "abababababababababababababababab";
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"checkout_pending":{"index":1,"token":token,"checkpoint_index":1,"repo":"tools","directory":destination,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":123}});
        super::publish_record(&root_fd, "R", &record, token).expect("pending marker");
        nix::sys::stat::mkdirat(&parent, "R", nix::sys::stat::Mode::S_IRWXU)
            .expect("destination created after marker");
        let mut completed = record.clone();
        completed
            .as_object_mut()
            .expect("record object")
            .remove("checkout_pending");
        completed["checkouts"] = json!([{"checkpoint_index":1,"object":"1".repeat(40),"directory":destination,"repo":"tools","instant_unix_ns":124}]);
        super::FAIL_PUBLICATION_ONCE.with(|fail| fail.set(true));
        let error = super::publish_record(&root_fd, "R", &completed, token)
            .expect_err("injected completion publication failure");
        assert_eq!(error.kind, "checkout-record");
        super::record_failure(
            &root_fd,
            "R",
            &mut record,
            token,
            &error,
            &super::residue(Some(&parent), &destination, owner),
            "yes",
        )
        .expect("attempt published after completion refusal");
        let saved = super::read_record(&root_fd, "R", owner).expect("saved refusal");
        assert!(saved.get("checkout_pending").is_none());
        assert_eq!(saved["checkout_attempts"][0]["refusal"], "checkout-record");
        assert_eq!(saved["checkout_attempts"][0]["created_observed"], "yes");
        assert!(destination.is_dir());
    }

    /// ´test:unit:checkout-open-temporary-failures-clean-or-name-residue´
    #[test]
    fn checkout_open_temporary_failures_clean_or_name_residue() {
        for (stage, fail_cleanup) in [
            (super::PublicationFault::Write, false),
            (super::PublicationFault::Rename, false),
            (super::PublicationFault::Write, true),
        ] {
            let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
            mode(fixture.path(), 0o700);
            let root = fixture.path().join("runs");
            let outside = fixture.path().join("outside");
            fs::create_dir(&root).expect("runs");
            fs::create_dir(&outside).expect("outside");
            mode(&root, 0o700);
            mode(&outside, 0o700);
            let destination = outside.join("R");
            let owner = nix::unistd::Uid::effective().as_raw();
            let root_fd = crate::home::pin_parent(&root, owner).expect("runs descriptor");
            let parent = crate::home::pin_parent(&outside, owner).expect("outside descriptor");
            let token = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
            let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"checkout_pending":{"index":1,"token":token,"checkpoint_index":1,"repo":"tools","directory":destination,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":123}});
            super::publish_record(&root_fd, "R", &record, token).expect("pending marker");
            nix::sys::stat::mkdirat(&parent, "R", nix::sys::stat::Mode::S_IRWXU)
                .expect("destination created after marker");
            let mut completed = record.clone();
            completed
                .as_object_mut()
                .expect("record object")
                .remove("checkout_pending");
            completed["checkouts"] = json!([{"checkpoint_index":1,"object":"1".repeat(40),"directory":destination,"repo":"tools","instant_unix_ns":124}]);
            super::FAIL_AFTER_OPEN_ONCE.with(|fail| fail.set(Some(stage)));
            if fail_cleanup {
                super::FAIL_UNLINK_ONCE.with(|fail| fail.set(true));
            }
            let error = super::publish_record(&root_fd, "R", &completed, token)
                .expect_err("injected failure after temporary open");
            assert_eq!(error.kind, "checkout-record");
            super::record_failure(
                &root_fd,
                "R",
                &mut record,
                token,
                &error,
                &super::residue(Some(&parent), &destination, owner),
                "yes",
            )
            .expect("indexed refusal");
            let saved = super::read_record(&root_fd, "R", owner).expect("saved refusal");
            assert!(saved.get("checkout_pending").is_none());
            assert_eq!(saved["checkout_attempts"][0]["refusal"], "checkout-record");
            let temporaries = fs::read_dir(&root)
                .expect("runs root")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .filter(|name| {
                    std::path::Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext == "tmp")
                })
                .collect::<Vec<_>>();
            if fail_cleanup {
                let [temporary] = temporaries.as_slice() else {
                    panic!("one named residue is required")
                };
                let detail = saved["checkout_attempts"][0]["detail"]
                    .as_str()
                    .expect("detail");
                assert!(detail.contains(temporary));
                assert!(detail.contains("step=write"));
            } else {
                assert!(
                    temporaries.is_empty(),
                    "temporary publication file remained"
                );
            }
            assert!(destination.is_dir());
        }
    }

    /// ´test:unit:checkout-mkdir-exists-never-claims-invocation-created-directory´
    #[test]
    fn checkout_mkdir_exists_never_claims_invocation_created_directory() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        mode(fixture.path(), 0o700);
        let root = fixture.path().join("runs");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).expect("runs");
        fs::create_dir(&outside).expect("outside");
        mode(&root, 0o700);
        mode(&outside, 0o700);
        let destination = outside.join("R");
        fs::create_dir(&destination).expect("other process created destination");
        mode(&destination, 0o700);
        let owner = nix::unistd::Uid::effective().as_raw();
        let root_fd = crate::home::pin_parent(&root, owner).expect("runs descriptor");
        let parent = crate::home::pin_parent(&outside, owner).expect("outside descriptor");
        let token = "dddddddddddddddddddddddddddddddd";
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"checkout_pending":{"index":1,"token":token,"checkpoint_index":1,"repo":"tools","directory":destination,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":123}});
        super::publish_record(&root_fd, "R", &record, token).expect("pending marker");
        let mkdir = nix::sys::stat::mkdirat(&parent, "R", nix::sys::stat::Mode::S_IRWXU);
        assert_eq!(mkdir, Err(nix::errno::Errno::EEXIST));
        let error = crate::error::LaneError::input("checkout-destination", "R: EEXIST");
        super::record_failure(
            &root_fd,
            "R",
            &mut record,
            token,
            &error,
            &super::residue(Some(&parent), &destination, owner),
            "no",
        )
        .expect("failed mkdir attempt");
        assert_eq!(record["checkout_attempts"][0]["residue"], true);
        assert_eq!(record["checkout_attempts"][0]["created_observed"], "no");
    }

    /// ´test:unit:checkout-attempt-reserve-measures-escaped-path-at-reader-limit´
    #[test]
    fn checkout_attempt_reserve_measures_escaped_path_at_reader_limit() {
        let directory = format!("/external/{}", "\u{0001}".repeat(160));
        let mut record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[],"checkout_next_index":2,"checkout_pending":{"index":1,"token":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","checkpoint_index":1,"repo":"tools","directory":directory,"object":"1".repeat(40),"preexisting":false,"attempt_instant_unix_ns":123}});
        let base = super::attempt_bound(&record).expect("attempt bound");
        let padding = usize::try_from(super::MAX_RESERVATION_BYTES).expect("reader bound") - base;
        record["padding"] = json!("x".repeat(padding));
        let pending_size = serde_json::to_vec(&record).expect("pending bytes").len();
        assert!(pending_size as u64 <= super::MAX_RESERVATION_BYTES);
        assert!(
            super::attempt_bound(&record).expect("expanded attempt") as u64
                > super::MAX_RESERVATION_BYTES
        );
        assert_eq!(
            super::pending_fits(&record)
                .expect_err("attempt exceeds bound before creation")
                .kind,
            "checkout-size"
        );
        assert!(
            serde_json::to_string(&super::detail_bytes(&"\u{0001}".repeat(256)))
                .expect("encoded detail")
                .len()
                <= 256
        );
    }

    /// ´test:unit:checkout-attempt-reader-refuses-contradictory-observations´
    #[test]
    fn checkout_attempt_reader_refuses_contradictory_observations() {
        let attempt = json!({"index":1,"token":"ffffffffffffffffffffffffffffffff","checkpoint_index":1,"repo":"tools","directory":"/external/R","refusal":"checkout-git","detail":"failed","residue":true,"path_valid":true,"path_error":"","created_observed":"yes","instant_unix_ns":123,"disposition":"left-for-owner"});
        let record = json!({"schema":1,"worker_uid":3000,"checkouts":[],"checkouts_omitted":0,"checkout_attempts":[attempt],"checkout_next_index":2});
        super::checkout_fields(&record).expect("valid observation");
        for (residue, path_valid, created) in [
            (Value::Null, true, "unknown"),
            (Value::Bool(false), true, "yes"),
            (Value::Bool(false), false, "no"),
        ] {
            let mut malformed = record.clone();
            malformed["checkout_attempts"][0]["residue"] = residue;
            malformed["checkout_attempts"][0]["path_valid"] = json!(path_valid);
            malformed["checkout_attempts"][0]["created_observed"] = json!(created);
            let original = serde_json::to_vec(&malformed).expect("original bytes");
            assert_eq!(
                super::checkout_fields(&malformed)
                    .expect_err("contradictory attempt")
                    .kind,
                "checkout-record"
            );
            assert_eq!(
                serde_json::to_vec(&malformed).expect("retained bytes"),
                original
            );
        }
    }
}
