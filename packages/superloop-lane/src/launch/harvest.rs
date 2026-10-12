//! Compare a preserved lane object with gate evidence before collecting its disposable home.

use super::*;
use nix::unistd::{UnlinkatFlags, unlinkat};

const MAX_PRESERVED_ENTRIES: usize = 8192;
const MAX_REMOVALS: usize = 65_536;
const MAX_COLLECTION_BYTES: usize = 4_194_304;
const MAX_DEPTH: usize = 32;

#[derive(Debug)]
pub struct HarvestRequest {
    pub loop_name: String,
    pub run: String,
    pub gate_object: String,
    pub dry_run: bool,
}

/// Build the private harvest or recovery words used by the public command.
///
/// # Errors
///
/// Refuses an owner home that cannot be passed as a path word.
pub fn private_harvest_argv(
    request: &HarvestRequest,
    owner_home: &Path,
    recovery: bool,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec![
        if recovery {
            "_harvest-recover"
        } else {
            "_harvest"
        }
        .into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--gate-object".into(),
        request.gate_object.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "harvest-home")?,
    ];
    if request.dry_run {
        argv.push("--dry-run".into());
    }
    Ok(argv)
}

fn valid_object(object: &str) -> bool {
    [40, 64].contains(&object.len())
        && object
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl HarvestRequest {
    /// Parse one gate-bound harvest request.
    ///
    /// # Errors
    ///
    /// Refuses missing or extra arguments and malformed names or object IDs.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, flag, object, rest @ ..] = args else {
            return Err(LaneError::input(
                "harvest-usage",
                "harvest LOOP RUN --gate-object HEX [--dry-run]",
            ));
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !valid_run_name(run)
            || flag != "--gate-object"
            || !valid_object(object)
            || !(rest.is_empty() || rest == ["--dry-run"])
        {
            return Err(LaneError::input(
                "harvest-usage",
                "harvest LOOP RUN --gate-object HEX [--dry-run]",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            gate_object: object.clone(),
            dry_run: !rest.is_empty(),
        })
    }
}

fn exact_fields(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key))
    })
}

pub(super) fn valid_planned(paths: &[Value]) -> bool {
    if paths.is_empty()
        || paths.len() > MAX_REMOVALS
        || paths.last().and_then(Value::as_str) != Some(".")
    {
        return false;
    }
    let mut seen = BTreeSet::new();
    for path in paths {
        let Some(name) = path.as_str() else {
            return false;
        };
        if !seen.insert(name)
            || (name != "."
                && (name.is_empty()
                    || Path::new(name)
                        .components()
                        .any(|part| !matches!(part, std::path::Component::Normal(_)))))
        {
            return false;
        }
    }
    true
}

pub(super) fn valid_remaining(remaining: &[Value], planned: &[Value]) -> bool {
    let mut position = 0;
    for path in remaining {
        let Some(found) = planned[position..]
            .iter()
            .position(|candidate| candidate == path)
        else {
            return false;
        };
        position += found + 1;
    }
    true
}

/// Read the one agreement and collection shape without accepting absent required keys.
///
/// # Errors
///
/// Refuses an old, malformed, or contradictory harvest record.
pub(super) fn harvest_fields(record: &Value) -> Result<(Option<Value>, Option<Value>), LaneError> {
    let agreement = record
        .get("harvest_agreement")
        .ok_or_else(|| LaneError::input("harvest-record", "agreement field is absent"))?;
    let collection = record
        .get("collection")
        .ok_or_else(|| LaneError::input("harvest-record", "collection field is absent"))?;
    if !agreement.is_null()
        && (!exact_fields(
            agreement,
            &[
                "checkpoint_index",
                "preserved_object",
                "gate_object",
                "instant_unix_ns",
            ],
        ) || agreement["checkpoint_index"].as_u64().is_none()
            || agreement["instant_unix_ns"].as_u64().is_none()
            || agreement["preserved_object"]
                .as_str()
                .is_none_or(|object| !valid_object(object))
            || agreement["gate_object"]
                .as_str()
                .is_none_or(|object| !valid_object(object))
            || agreement["preserved_object"] != agreement["gate_object"])
    {
        return Err(LaneError::input(
            "harvest-record",
            "agreement shape or object equality differs",
        ));
    }
    if !collection.is_null() {
        if agreement.is_null()
            || !exact_fields(
                collection,
                &[
                    "checkpoint_index",
                    "state",
                    "instant_unix_ns",
                    "planned",
                    "writable_collected_first",
                    "remaining",
                    "refusal",
                    "component",
                    "token",
                    "parent_identity",
                    "home_identity",
                ],
            )
            || collection["checkpoint_index"] != agreement["checkpoint_index"]
            || collection["instant_unix_ns"].as_u64().is_none()
            || collection["planned"]
                .as_array()
                .is_none_or(|paths| !valid_planned(paths))
            || !valid_writable_collected_first(collection)
            || collection["token"].as_str().is_none_or(|token| {
                token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || !valid_identity(&collection["parent_identity"])
            || !valid_identity(&collection["home_identity"])
        {
            return Err(LaneError::input(
                "harvest-record",
                "collection shape differs",
            ));
        }
        match collection["state"].as_str() {
            Some("removing")
                if collection["remaining"].is_null()
                    && collection["refusal"].is_null()
                    && collection["component"].is_null() => {}
            Some("collected")
                if collection["remaining"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                    && collection["refusal"].is_null()
                    && collection["component"].is_null() => {}
            Some("refused")
                if (collection["remaining"].as_array().is_some_and(|paths| {
                    collection["planned"]
                        .as_array()
                        .is_some_and(|planned| valid_remaining(paths, planned))
                }) || collection["remaining"].is_null())
                    && collection["refusal"].as_str().is_some()
                    && collection["component"].as_str().is_some() => {}
            _ => {
                return Err(LaneError::input(
                    "harvest-record",
                    "collection state contradicts its disposition",
                ));
            }
        }
    }
    Ok((
        (!agreement.is_null()).then(|| agreement.clone()),
        (!collection.is_null()).then(|| collection.clone()),
    ))
}

fn valid_identity(value: &Value) -> bool {
    exact_fields(value, &["device", "inode"])
        && value["device"].as_u64().is_some()
        && value["inode"].as_u64().is_some()
}

fn descriptor_identity(fd: &OwnedFd) -> Result<Value, LaneError> {
    let stat = fstat(fd).map_err(|error| LaneError::input("harvest-path", error.to_string()))?;
    Ok(json!({"device":stat.st_dev,"inode":stat.st_ino}))
}

pub(super) fn checkpoint_object(checkpoint: &Value, gate: &str) -> Result<String, LaneError> {
    let bares = checkpoint["bares"]
        .as_array()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare list is malformed"))?;
    let objects = bares
        .iter()
        .filter(|bare| bare["lane_ref"] != "absent")
        .map(|bare| bare["object"].as_str())
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare object is absent"))?;
    if objects.is_empty() {
        return Err(LaneError::input(
            "harvest-checkpoint",
            "latest checkpoint has no shipped bare",
        ));
    }
    if objects.iter().any(|object| !valid_object(object)) {
        return Err(LaneError::input(
            "harvest-checkpoint",
            "bare object is malformed",
        ));
    }
    if objects.contains(gate) {
        return Ok(gate.to_owned());
    }
    if objects.len() == 1 {
        return Ok(objects
            .iter()
            .next()
            .copied()
            .unwrap_or_default()
            .to_owned());
    }
    Err(LaneError::input(
        "harvest-mismatch",
        format!("preserved objects {objects:?} differ from gate object {gate}"),
    ))
}

fn compare_object(preserved: &str, gate: &str) -> Result<(), LaneError> {
    if preserved != gate {
        return Err(LaneError::input(
            "harvest-mismatch",
            format!("preserved object {preserved} differs from gate object {gate}"),
        ));
    }
    Ok(())
}

fn instant() -> Result<u128, LaneError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| LaneError::operation("harvest-clock", error.to_string()))
}

/// Enter the owner namespace with held home and runs-root descriptors.
///
/// # Errors
///
/// Refuses an unsafe root, private failure, or malformed report.
pub fn run(owner_home: &Path, request: &HarvestRequest) -> Result<Value, LaneError> {
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("harvest-grant", "runs_root is absent"))?;
    let program = plan.document["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("harvest-record", "container program is absent"))?;
    let owner = Uid::effective().as_raw();
    crate::pinned::owner_executable(Path::new(program), owner)?;
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("harvest-program", error.to_string()))?;
    crate::pinned::owner_executable(&exe, owner)?;
    let prefix = [
        "unshare".to_owned(),
        crate::pinned::path_word(&exe, "harvest-program")?,
    ];
    let mut argv = prefix.to_vec();
    argv.extend(private_harvest_argv(request, owner_home, false)?);
    let mut recovery_argv = prefix.to_vec();
    recovery_argv.extend(private_harvest_argv(request, owner_home, true)?);
    let environment = launch_environment(owner_home)?;
    let output = build::run_checked_with_private_launch(
        Path::new(program),
        argv,
        &environment,
        owner_home,
        300,
        "harvest-private",
        &home_fd,
        root,
        &runs_fd,
        None,
    );
    let output = output.map_err(|error| {
        if !request.dry_run {
            let recovered = build::run_checked_with_private_launch(
                Path::new(program),
                recovery_argv,
                &environment,
                owner_home,
                300,
                "harvest-recovery",
                &home_fd,
                root,
                &runs_fd,
                None,
            );
            if let Err(recovery_error) = recovered {
                return LaneError::operation(
                    "harvest-recovery",
                    format!("{}; recovery: {}", error.line(), recovery_error.line()),
                );
            }
        }
        for kind in [
            "harvest-record",
            "harvest-checkpoint",
            "harvest-mismatch",
            "harvest-unpreserved",
            "harvest-path",
            "harvest-collection",
            "harvest-size",
            "harvest-clock",
        ] {
            if error.detail.contains(&format!("{kind}:")) {
                return LaneError::input(kind, error.detail);
            }
        }
        error
    })?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::operation("harvest-private", error.to_string()))
}

fn entry(parent: &OwnedFd, name: &str, path: &Path) -> Result<OwnedFd, LaneError> {
    openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("harvest-path", format!("{}: {error}", path.display())))
}

fn stat_entry(
    fd: &OwnedFd,
    path: &Path,
    expected_uid: u32,
) -> Result<nix::sys::stat::FileStat, LaneError> {
    let stat = fstat(fd).map_err(|error| {
        LaneError::input("harvest-path", format!("{}: {error}", path.display()))
    })?;
    let mode = stat.st_mode & 0o7777;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    let collected_only = collected_only(path);
    if stat.st_uid != expected_uid
        || mode & 0o7000 != 0
        || (kind != SFlag::S_IFLNK && !collected_only && mode & 0o022 != 0)
    {
        let mode_rule = if collected_only {
            "without special bits"
        } else {
            "without writable or special owner bits"
        };
        return Err(LaneError::input(
            "harvest-path",
            format!(
                "{}: uid {} mode {mode:04o}; expected uid {expected_uid} {mode_rule}",
                path.display(),
                stat.st_uid
            ),
        ));
    }
    Ok(stat)
}

/// These worker-owned roots are inventoried for removal but not read as harvest evidence.
fn collected_only(relative: &Path) -> bool {
    relative.starts_with(".codex") || relative.starts_with(".cache")
}

fn valid_writable_collected_first(collection: &Value) -> bool {
    let first = &collection["writable_collected_first"];
    first.is_null()
        || first.as_str().is_some_and(|path| {
            collected_only(Path::new(path))
                && collection["planned"]
                    .as_array()
                    .is_some_and(|paths| paths.iter().any(|row| row.as_str() == Some(path)))
        })
}

fn directory(parent: &OwnedFd, name: &str, path: &Path, owner: u32) -> Result<OwnedFd, LaneError> {
    let observed = entry(parent, name, path)?;
    let prior = stat_entry(&observed, path, owner)?;
    if SFlag::from_bits_truncate(prior.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(LaneError::input(
            "harvest-path",
            format!("{} is not a directory", path.display()),
        ));
    }
    let opened = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("harvest-path", format!("{}: {error}", path.display())))?;
    let current = stat_entry(&opened, path, owner)?;
    if prior.st_dev != current.st_dev || prior.st_ino != current.st_ino {
        return Err(LaneError::input(
            "harvest-path",
            format!("{} changed inode during descriptor opening", path.display()),
        ));
    }
    Ok(opened)
}

fn owner_map(
    record: &Value,
    home: &Path,
    owner: u32,
    worker: u32,
) -> Result<BTreeMap<PathBuf, u32>, LaneError> {
    let rows = record["plan"]["paths"]
        .as_array()
        .ok_or_else(|| LaneError::input("harvest-plan", "plan paths are absent"))?;
    let mut owners = BTreeMap::new();
    for row in rows {
        let name = row["path"]
            .as_str()
            .ok_or_else(|| LaneError::input("harvest-plan", "plan path is absent"))?;
        if let Ok(relative) = Path::new(name).strip_prefix(home) {
            let uid = row["uid"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| LaneError::input("harvest-plan", format!("{name} has no owner")))?;
            if uid != owner && uid != worker || owners.insert(relative.to_path_buf(), uid).is_some()
            {
                return Err(LaneError::input(
                    "harvest-plan",
                    format!("{name} has an unexpected or duplicate owner"),
                ));
            }
        }
    }
    if owners.get(Path::new("")) != Some(&owner) {
        return Err(LaneError::input(
            "harvest-plan",
            "home owner is absent from plan",
        ));
    }
    for root in [".codex", ".cache"] {
        if owners.get(Path::new(root)) != Some(&worker) {
            return Err(LaneError::input(
                "harvest-plan",
                format!("{root} worker owner is absent from plan"),
            ));
        }
    }
    Ok(owners)
}

fn planned_uid(relative: &Path, owners: &BTreeMap<PathBuf, u32>) -> Result<u32, LaneError> {
    if let Some(uid) = owners.get(relative) {
        return Ok(*uid);
    }
    for root in [
        ".codex",
        ".cache",
        ".local/outbox",
        ".local/sources",
        ".local/inbox",
    ] {
        if relative.starts_with(root) && relative != Path::new(root) {
            return owners.get(Path::new(root)).copied().ok_or_else(|| {
                LaneError::input("harvest-plan", format!("{root} has no plan row"))
            });
        }
    }
    Err(LaneError::input(
        "harvest-plan",
        format!("{} has no plan row", relative.display()),
    ))
}

fn fixed_child(relative: &Path) -> bool {
    let word = relative.to_string_lossy();
    if relative.components().count() == 1 {
        return [".ssh", ".gitconfig", ".codex", ".cache", ".local"].contains(&word.as_ref());
    }
    if relative.components().count() == 2 && word.starts_with(".local/") {
        return [
            "bin", "door", "vendor", "outbox", "sources", "libexec", "inbox",
        ]
        .iter()
        .any(|name| word.as_ref() == format!(".local/{name}"));
    }
    true
}

fn walk_mailbox(
    fd: &OwnedFd,
    relative: &Path,
    uid: u32,
    expected: &mut BTreeMap<String, (u64, String)>,
    depth: usize,
) -> Result<(), LaneError> {
    if depth > MAX_DEPTH {
        return Err(LaneError::input(
            "harvest-unpreserved",
            "mailbox depth exceeds bound",
        ));
    }
    let names = checkpoint::directory_names(fd, relative)
        .map_err(|error| LaneError::input("harvest-unpreserved", error.line()))?;
    for name in names {
        let path = relative.join(&name);
        let opened = entry(fd, &name, &path)
            .map_err(|error| LaneError::input("harvest-unpreserved", error.line()))?;
        let stat = stat_entry(&opened, &path, uid)?;
        let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        if kind == SFlag::S_IFDIR {
            let child = directory(fd, &name, &path, uid)?;
            walk_mailbox(&child, &path, uid, expected, depth + 1)?;
        } else if kind == SFlag::S_IFREG {
            let word = path.to_str().ok_or_else(|| {
                LaneError::input("harvest-unpreserved", "mailbox name is not UTF-8")
            })?;
            let Some((size, digest)) = expected.remove(word) else {
                return Err(LaneError::input(
                    "harvest-unpreserved",
                    format!("added file {word}"),
                ));
            };
            let actual_size = u64::try_from(stat.st_size).map_err(|_| {
                LaneError::input("harvest-unpreserved", format!("{word}: negative size"))
            })?;
            let file = openat2(
                fd,
                name.as_str(),
                OpenHow::new()
                    .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )
            .map_err(|error| LaneError::input("harvest-unpreserved", format!("{word}: {error}")))?;
            let fresh = stat_entry(&file, &path, uid)?;
            if fresh.st_dev != stat.st_dev || fresh.st_ino != stat.st_ino {
                return Err(LaneError::input(
                    "harvest-unpreserved",
                    format!("{word}: inode changed during read"),
                ));
            }
            let actual_digest = checkpoint::digest(&file, &path)
                .map_err(|error| LaneError::input("harvest-unpreserved", error.line()))?;
            let after = stat_entry(&file, &path, uid)?;
            if actual_size != size
                || after.st_size != fresh.st_size
                || after.st_mtime != fresh.st_mtime
                || after.st_mtime_nsec != fresh.st_mtime_nsec
                || actual_digest != digest
            {
                return Err(LaneError::input(
                    "harvest-unpreserved",
                    format!("changed file {word}"),
                ));
            }
        } else {
            return Err(LaneError::input(
                "harvest-unpreserved",
                format!("{} is not a regular file or directory", path.display()),
            ));
        }
    }
    Ok(())
}

fn measure_home(
    home_fd: &OwnedFd,
    home_path: &Path,
    worker: u32,
    checkpoint: &Value,
) -> Result<(), LaneError> {
    let local_path = home_path.join(".local");
    let local = directory(home_fd, ".local", &local_path, 0)?;
    let files = checkpoint["files"]
        .as_array()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "file list is malformed"))?;
    let mut expected = BTreeMap::new();
    for file in files {
        let name = file["path"].as_str().ok_or_else(|| {
            LaneError::input("harvest-checkpoint", "preserved file path is malformed")
        })?;
        let size = file["size"].as_u64().ok_or_else(|| {
            LaneError::input("harvest-checkpoint", "preserved file size is malformed")
        })?;
        let digest = file["sha256"].as_str().ok_or_else(|| {
            LaneError::input("harvest-checkpoint", "preserved file digest is malformed")
        })?;
        if expected
            .insert(name.to_owned(), (size, digest.to_owned()))
            .is_some()
        {
            return Err(LaneError::input(
                "harvest-checkpoint",
                "preserved file is repeated",
            ));
        }
    }
    for (name, uid) in [("inbox", 0), ("outbox", worker), ("sources", worker)] {
        let path = Path::new(name);
        let source = directory(&local, name, &local_path.join(name), uid)?;
        if name == "sources" {
            let actual = checkpoint::directory_names(&source, path)
                .map_err(|error| LaneError::input("harvest-unpreserved", error.line()))?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let recorded = checkpoint["bares"]
                .as_array()
                .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare list is absent"))?
                .iter()
                .map(|bare| bare["name"].as_str().map(|name| format!("{name}.git")))
                .collect::<Option<BTreeSet<_>>>()
                .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare name is absent"))?;
            if actual != recorded {
                return Err(LaneError::input(
                    "harvest-unpreserved",
                    format!(
                        "source bare directory changed: recorded {recorded:?}, present {actual:?}"
                    ),
                ));
            }
        }
        walk_mailbox(&source, path, uid, &mut expected, 0)?;
    }
    if let Some(name) = expected.keys().next() {
        return Err(LaneError::input(
            "harvest-unpreserved",
            format!("missing file {name}"),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Inventory {
    removals: Vec<String>,
    writable_collected_first: Option<String>,
    entries: usize,
    preserved: usize,
    contributors: BTreeMap<String, usize>,
    preserved_contributors: BTreeMap<String, usize>,
}

fn largest(contributors: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut rows: Vec<_> = contributors
        .iter()
        .map(|(path, count)| (path.as_str(), *count))
        .collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    rows.truncate(5);
    rows
}

fn size_refusal(
    bound: &str,
    count: usize,
    limit: usize,
    contributors: &BTreeMap<String, usize>,
) -> LaneError {
    LaneError::input(
        "harvest-size",
        format!(
            "bound={bound} count={count} limit={limit} largest={:?}",
            largest(contributors)
        ),
    )
}

impl Inventory {
    fn observe(&mut self, path: &Path) {
        let group: PathBuf = path
            .components()
            .take(if path.starts_with(".local") { 2 } else { 1 })
            .collect();
        let group = group.to_string_lossy().into_owned();
        self.entries += 1;
        *self.contributors.entry(group.clone()).or_default() += 1;
        if [".local/inbox", ".local/outbox", ".local/sources"]
            .iter()
            .any(|root| path.starts_with(root))
        {
            self.preserved += 1;
            *self.preserved_contributors.entry(group).or_default() += 1;
        }
        // Continue measuring after the limit without retaining an unbounded plan.
        if self.removals.len() < MAX_REMOVALS {
            self.removals.push(path.to_string_lossy().into_owned());
        }
    }
}

fn plan_entries(
    fd: &OwnedFd,
    relative: &Path,
    owners: &BTreeMap<PathBuf, u32>,
    worker: u32,
    inventory: &mut Inventory,
    depth: usize,
) -> Result<(), LaneError> {
    if depth > MAX_DEPTH {
        return Err(LaneError::input(
            "harvest-collection",
            "home depth exceeds bound",
        ));
    }
    for name in checkpoint::directory_names(fd, relative)
        .map_err(|error| LaneError::input("harvest-collection", error.line()))?
    {
        let path = relative.join(&name);
        if !fixed_child(&path) {
            return Err(LaneError::input(
                "harvest-collection",
                format!("{} is an unexpected fixed input", path.display()),
            ));
        }
        let uid = planned_uid(&path, owners)?;
        let observed = entry(fd, &name, &path)?;
        let stat = stat_entry(&observed, &path, uid)?;
        if collected_only(&path) && stat.st_mode & 0o022 != 0 {
            inventory
                .writable_collected_first
                .get_or_insert_with(|| path.to_string_lossy().into_owned());
        }
        let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
        if kind == SFlag::S_IFDIR {
            let child = directory(fd, &name, &path, uid)?;
            plan_entries(&child, &path, owners, worker, inventory, depth + 1)?;
        } else if kind == SFlag::S_IFLNK && uid != worker {
            return Err(LaneError::input(
                "harvest-collection",
                format!("{} replaces a protected input with a link", path.display()),
            ));
        }
        inventory.observe(&path);
    }
    Ok(())
}

fn planned_removals(
    home_fd: &OwnedFd,
    owners: &BTreeMap<PathBuf, u32>,
    worker: u32,
) -> Result<(Vec<String>, Option<String>), LaneError> {
    let mut inventory = Inventory::default();
    plan_entries(home_fd, Path::new(""), owners, worker, &mut inventory, 0)?;
    inventory.observe(Path::new("."));
    if inventory.preserved > MAX_PRESERVED_ENTRIES {
        return Err(size_refusal(
            "preservation-entries",
            inventory.preserved,
            MAX_PRESERVED_ENTRIES,
            &inventory.preserved_contributors,
        ));
    }
    if inventory.entries > MAX_REMOVALS {
        return Err(size_refusal(
            "collection-entries",
            inventory.entries,
            MAX_REMOVALS,
            &inventory.contributors,
        ));
    }
    Ok((inventory.removals, inventory.writable_collected_first))
}

fn parent_for(
    home_fd: &OwnedFd,
    relative: &Path,
    owners: &BTreeMap<PathBuf, u32>,
) -> Result<OwnedFd, LaneError> {
    let mut current = nix::unistd::dup(home_fd)
        .map_err(|error| LaneError::operation("harvest-collection", error.to_string()))?;
    let mut path = PathBuf::new();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(LaneError::input(
                "harvest-collection",
                "removal parent has a non-normal component",
            ));
        };
        let word = name.to_str().ok_or_else(|| {
            LaneError::input("harvest-collection", "removal parent name is not UTF-8")
        })?;
        path.push(name);
        current = directory(&current, word, &path, planned_uid(&path, owners)?)?;
    }
    Ok(current)
}

fn present_relative(
    home_fd: &OwnedFd,
    relative: &str,
    owners: &BTreeMap<PathBuf, u32>,
) -> Option<bool> {
    if relative == "." {
        return Some(true);
    }
    let path = Path::new(relative);
    let mut parent = nix::unistd::dup(home_fd).ok()?;
    let mut walked = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        let word = name.to_str()?;
        walked.push(name);
        let opened = match openat2(
            &parent,
            word,
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Some(false),
            Err(_) => return None,
        };
        stat_entry(&opened, &walked, planned_uid(&walked, owners).ok()?).ok()?;
        if components.peek().is_none() {
            return Some(true);
        }
        parent = directory(&parent, word, &walked, planned_uid(&walked, owners).ok()?).ok()?;
    }
    None
}

fn remaining_after_interruption(
    parent: &OwnedFd,
    home: &Path,
    owner: u32,
    owners: &BTreeMap<PathBuf, u32>,
    planned: &[Value],
) -> Option<Vec<String>> {
    let name = home.file_name()?.to_str()?;
    remaining_from_parent(parent, name, home, owner, owners, planned)
}

fn checked_remaining(
    parent: Option<&OwnedFd>,
    home: &Path,
    owner: u32,
    owners: &BTreeMap<PathBuf, u32>,
    collection: &Value,
) -> (Option<Vec<String>>, &'static str) {
    let Some(parent) = parent else {
        return (None, "harvest-parent");
    };
    if descriptor_identity(parent).ok().as_ref() != Some(&collection["parent_identity"]) {
        return (None, "harvest-parent");
    }
    let Some(name) = home.file_name() else {
        return (None, "harvest-home");
    };
    match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) if descriptor_identity(&fd).ok().as_ref() != Some(&collection["home_identity"]) => {
            return (None, "harvest-home");
        }
        Ok(_) | Err(nix::errno::Errno::ENOENT) => {}
        Err(_) => return (None, "harvest-home"),
    }
    let Some(planned) = collection["planned"].as_array() else {
        return (None, "harvest-record");
    };
    (
        remaining_after_interruption(parent, home, owner, owners, planned),
        "harvest-private",
    )
}

fn remaining_from_parent(
    parent: &OwnedFd,
    name: &str,
    home: &Path,
    owner: u32,
    owners: &BTreeMap<PathBuf, u32>,
    planned: &[Value],
) -> Option<Vec<String>> {
    let held = match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Some(Vec::new()),
        Err(_) => return None,
    };
    stat_entry(&held, home, owner).ok()?;
    let mut remaining = Vec::new();
    for relative in planned {
        let path = relative.as_str()?;
        match present_relative(&held, path, owners) {
            Some(true) => remaining.push(path.to_owned()),
            Some(false) => {}
            None => return None,
        }
    }
    Some(remaining)
}

fn remove_entry(
    home_fd: &OwnedFd,
    home_parent: &OwnedFd,
    home_name: &str,
    relative: &str,
    owner: u32,
    worker: u32,
    owners: &BTreeMap<PathBuf, u32>,
) -> Result<(), LaneError> {
    if relative == "." {
        let found = entry(home_parent, home_name, Path::new(home_name))?;
        let stat = stat_entry(&found, Path::new(home_name), owner)?;
        let held = fstat(home_fd)
            .map_err(|error| LaneError::operation("harvest-collection", error.to_string()))?;
        if stat.st_dev != held.st_dev || stat.st_ino != held.st_ino {
            return Err(LaneError::input(
                "harvest-collection",
                "home inode changed before removal",
            ));
        }
        return unlinkat(home_parent, home_name, UnlinkatFlags::RemoveDir)
            .map_err(|error| LaneError::operation("harvest-collection", format!(".: {error}")));
    }
    let path = Path::new(relative);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("harvest-collection", "removal name is invalid"))?;
    let parent = parent_for(
        home_fd,
        path.parent().unwrap_or_else(|| Path::new("")),
        owners,
    )?;
    let found = entry(&parent, name, path)?;
    let uid = planned_uid(path, owners)?;
    let stat = stat_entry(&found, path, uid)?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind == SFlag::S_IFLNK && uid != worker {
        return Err(LaneError::input(
            "harvest-collection",
            format!("{relative}: protected link appeared before removal"),
        ));
    }
    let flag = if kind == SFlag::S_IFDIR {
        UnlinkatFlags::RemoveDir
    } else {
        UnlinkatFlags::NoRemoveDir
    };
    unlinkat(&parent, name, flag)
        .map_err(|error| LaneError::operation("harvest-collection", format!("{relative}: {error}")))
}

fn checked_size(record: &Value) -> Result<(), LaneError> {
    let size = serde_json::to_vec(record)
        .map_err(|error| LaneError::input("harvest-size", error.to_string()))?
        .len();
    if size > MAX_COLLECTION_BYTES {
        let contributors = record
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, value)| serde_json::to_vec(value).map(|bytes| (name.clone(), bytes.len())))
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|error| LaneError::input("harvest-size", error.to_string()))?;
        return Err(size_refusal(
            "collection-bytes",
            size,
            MAX_COLLECTION_BYTES,
            &contributors,
        ));
    }
    Ok(())
}

fn publish_collection(
    root_fd: &OwnedFd,
    run: &str,
    record: &Value,
    token: &str,
) -> Result<(), LaneError> {
    checkout::publish_record(root_fd, run, record, token)
        .map_err(|error| LaneError::operation("harvest-record", error.line()))
}

#[allow(clippy::too_many_arguments)]
fn finish_pending(
    record: &mut Value,
    collection: &Value,
    root_fd: &OwnedFd,
    run: &str,
    home: &Path,
    home_parent: Option<&OwnedFd>,
    owner: u32,
    owners: &BTreeMap<PathBuf, u32>,
) -> Result<Value, LaneError> {
    let (remaining, refusal) = checked_remaining(home_parent, home, owner, owners, collection);
    let complete = remaining.as_ref().is_some_and(Vec::is_empty);
    record["collection"]["state"] = json!(if complete { "collected" } else { "refused" });
    record["collection"]["remaining"] = remaining.map_or(Value::Null, |paths| json!(paths));
    record["collection"]["refusal"] = if complete {
        Value::Null
    } else {
        json!(refusal)
    };
    record["collection"]["component"] = if complete { Value::Null } else { json!(".") };
    checked_size(record)?;
    let token = collection["token"]
        .as_str()
        .ok_or_else(|| LaneError::input("harvest-record", "pending token is absent"))?;
    publish_collection(root_fd, run, record, token)?;
    Ok(record["collection"].clone())
}

// Settlement retains the final step as active_round; the driver directory comes from the verified plan.
fn settled_reservation(
    record: &Value,
    plan: &Plan,
    loop_name: &str,
    run: &str,
) -> Result<(), LaneError> {
    let text = |value: &Value, key: &str| -> Result<String, LaneError> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                LaneError::input("harvest-record", format!("{key} is absent or not text"))
            })
    };
    for (key, wanted) in [("loop", loop_name), ("run", run)] {
        let actual = text(record, key)?;
        if actual != wanted {
            return Err(LaneError::input(
                "harvest-record",
                format!("{key} is {actual}; expected {wanted}"),
            ));
        }
    }
    let phase = text(record, "phase")?;
    if phase != "settled" {
        return Err(LaneError::input(
            "harvest-record",
            format!("phase is {phase}; expected settled"),
        ));
    }
    let saved_plan = record
        .get("plan")
        .and_then(Value::as_object)
        .ok_or_else(|| LaneError::input("harvest-record", "plan is absent or not an object"))?;
    let home = saved_plan
        .get("home")
        .and_then(Value::as_str)
        .ok_or_else(|| LaneError::input("harvest-record", "plan.home is absent or not text"))?;
    if home != plan.home.to_string_lossy() {
        return Err(LaneError::input("harvest-record", "plan.home differs"));
    }
    let driver_dir = saved_plan
        .get("driver_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LaneError::input("harvest-record", "plan.driver_dir is absent or not text")
        })?;
    if driver_dir != plan.driver_dir.to_string_lossy() {
        return Err(LaneError::input(
            "harvest-record",
            "plan.driver_dir differs",
        ));
    }
    let rounds = record
        .get("rounds")
        .and_then(Value::as_array)
        .ok_or_else(|| LaneError::input("harvest-record", "rounds is absent or not an array"))?;
    let last = rounds.last().and_then(Value::as_object).ok_or_else(|| {
        LaneError::input("harvest-record", "last round is absent or not an object")
    })?;
    let step = last.get("step").and_then(Value::as_str).ok_or_else(|| {
        LaneError::input("harvest-record", "last round step is absent or not text")
    })?;
    let round_phase = last.get("phase").and_then(Value::as_str).ok_or_else(|| {
        LaneError::input("harvest-record", "last round phase is absent or not text")
    })?;
    if !super::settle::final_round_ready(record) {
        return Err(LaneError::input(
            "harvest-record",
            format!("last round phase is {round_phase}; expected settled"),
        ));
    }
    if super::reaping::recovery_verdict(record).is_ok() {
        let active = text(record, "active_round")?;
        if active != step {
            return Err(LaneError::input(
                "harvest-record",
                "active round differs from recovered final round",
            ));
        }
        return Ok(());
    }
    let ended_by = last
        .get("ended_by")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LaneError::input(
                "harvest-record",
                "last round ended_by is absent or not text",
            )
        })?;
    if !matches!(ended_by, "by-report" | "by-report-after-stop" | "by-budget") {
        return Err(LaneError::input(
            "harvest-record",
            format!("last round ended_by is {ended_by}"),
        ));
    }
    let active = text(record, "active_round")?;
    if active != step {
        return Err(LaneError::input(
            "harvest-record",
            format!("active_round is {active}; last settled step is {step}"),
        ));
    }
    Ok(())
}

/// Reconcile a pending removal after a private failure while holding owner locks.
///
/// # Errors
///
/// Refuses an unsafe or malformed reservation or a failed disposition publication.
pub fn private_recover(owner_home: &Path, request: &HarvestRequest) -> Result<Value, LaneError> {
    if request.dry_run {
        return Err(LaneError::input(
            "harvest-recovery",
            "dry run cannot publish a recovery",
        ));
    }
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
        .ok_or_else(|| LaneError::input("harvest-grant", "runs_root is absent"))?;
    let owner = Uid::effective().as_raw();
    let root_fd = home::pin_parent(root, owner)?;
    let (_lease, _mailbox) = checkpoint::checkpoint_locks_at(&root_fd, &request.run, owner, false)?;
    let mut record = checkout::read_record(&root_fd, &request.run, owner)
        .map_err(|error| LaneError::input("harvest-record", error.line()))?;
    settled_reservation(&record, &plan, &request.loop_name, &request.run)?;
    let (agreement, collection) = harvest_fields(&record)?;
    let Some(collection) = collection.filter(|collection| collection["state"] == "removing") else {
        return Ok(
            json!({"schema":1,"command":"harvest-recovery","run":request.run,"changed":false,"pending":false}),
        );
    };
    if agreement
        .as_ref()
        .is_none_or(|agreement| agreement["gate_object"] != request.gate_object)
    {
        return Err(LaneError::input(
            "harvest-record",
            "pending agreement names another gate object",
        ));
    }
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("harvest-record", "worker UID is absent"))?;
    let owners = owner_map(&record, &plan.home, owner, worker)?;
    let home_parent = plan
        .home
        .parent()
        .and_then(|parent| home::pin_parent(parent, owner).ok());
    let disposition = finish_pending(
        &mut record,
        &collection,
        &root_fd,
        &request.run,
        &plan.home,
        home_parent.as_ref(),
        owner,
        &owners,
    )?;
    Ok(
        json!({"schema":1,"command":"harvest-recovery","run":request.run,"changed":true,"pending":false,"collection":disposition}),
    )
}

#[cfg(test)]
thread_local! {
    static PRIVATE_RUN_FIXTURE: std::cell::RefCell<Option<(Plan, Settings)>> = const { std::cell::RefCell::new(None) };
}

fn private_inputs(
    owner_home: &Path,
    request: &HarvestRequest,
) -> Result<(Plan, Settings), LaneError> {
    #[cfg(test)]
    if let Some(inputs) = PRIVATE_RUN_FIXTURE.with(|slot| slot.borrow_mut().take()) {
        return Ok(inputs);
    }
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))
}

#[allow(clippy::too_many_arguments)]
fn verify_checkpoint_bares(
    run_fd: &OwnedFd,
    driver_dir: &Path,
    index: u64,
    files: &[Value],
    bares: &[Value],
    run: &str,
    loop_uid: u32,
) -> Result<(), LaneError> {
    for bare in bares {
        let repo = bare["name"]
            .as_str()
            .filter(|repo| valid_run_name(repo))
            .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare name is malformed"))?;
        let bare_object = if bare["lane_ref"] == "absent" {
            None
        } else {
            Some(
                bare["object"]
                    .as_str()
                    .filter(|object| valid_object(object))
                    .ok_or_else(|| {
                        LaneError::input("harvest-checkpoint", "bare object is malformed")
                    })?,
            )
        };
        checkpoint::verify_preserved_copy_state(
            run_fd,
            driver_dir,
            index,
            files,
            repo,
            run,
            bare_object,
            loop_uid,
        )
        .map_err(|error| LaneError::input("harvest-checkpoint", error.line()))?;
    }
    Ok(())
}

/// Compare preserved objects, record agreement, re-measure outputs, then collect through descriptors.
///
/// # Errors
///
/// Refuses mismatched gate evidence, incomplete preservation, changed outputs, or unsafe removal.
#[allow(clippy::too_many_lines)]
pub fn private_run(owner_home: &Path, request: &HarvestRequest) -> Result<Value, LaneError> {
    let (mut plan, settings) = private_inputs(owner_home, request)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("harvest-grant", "runs_root is absent"))?;
    let owner = Uid::effective().as_raw();
    let root_fd = home::pin_parent(root, owner)?;
    let (_lease, _mailbox) =
        checkpoint::checkpoint_locks_at(&root_fd, &request.run, owner, request.dry_run)?;
    let mut record = checkout::read_record(&root_fd, &request.run, owner)
        .map_err(|error| LaneError::input("harvest-record", error.line()))?;
    settled_reservation(&record, &plan, &request.loop_name, &request.run)?;
    let (prior_agreement, prior_collection) = harvest_fields(&record)?;
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(&record)?;
    let checkpoint = checkpoints
        .last()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "run has no complete checkpoint"))?;
    let index = checkpoint["index"]
        .as_u64()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "checkpoint index is malformed"))?;
    let preserved_object = checkpoint_object(checkpoint, &request.gate_object)?;
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| LaneError::input("harvest-record", "worker UID is absent"))?;
    plan.select_worker_uid(worker)?;
    let owners = owner_map(&record, &plan.home, owner, worker)?;
    let home_parent_path = plan
        .home
        .parent()
        .ok_or_else(|| LaneError::input("harvest-path", "home parent is absent"))?;
    if home_parent_path != owner_home.join(".cache/tmp") {
        return Err(LaneError::input(
            "harvest-path",
            "disposable home is outside the temporary home root",
        ));
    }
    let home_parent = home::pin_parent(home_parent_path, owner)?;
    let loop_uid = super::recorded_loop_uid(&record)?;
    let run_fd = home::pin_loop_round_at(&root_fd, root, &plan.driver_dir, loop_uid)?;
    let files = checkpoint["files"]
        .as_array()
        .ok_or_else(|| LaneError::input("harvest-checkpoint", "file list is malformed"))?;
    verify_checkpoint_bares(
        &run_fd,
        &plan.driver_dir,
        index,
        files,
        checkpoint["bares"]
            .as_array()
            .ok_or_else(|| LaneError::input("harvest-checkpoint", "bare list is malformed"))?,
        &request.run,
        loop_uid,
    )?;
    compare_object(&preserved_object, &request.gate_object)?;
    if let Some(agreement) = &prior_agreement
        && (agreement["checkpoint_index"] != index
            || agreement["preserved_object"] != preserved_object
            || agreement["gate_object"] != request.gate_object)
    {
        return Err(LaneError::input(
            "harvest-record",
            "prior agreement names another checkpoint or gate object",
        ));
    }
    if let Some(collection) = &prior_collection {
        if collection["state"] == "collected" {
            let (remaining, _) =
                checked_remaining(Some(&home_parent), &plan.home, owner, &owners, collection);
            if remaining.as_ref().is_none_or(|paths| !paths.is_empty()) {
                return Err(LaneError::input(
                    "harvest-collection",
                    format!("collected home has remaining components {remaining:?}"),
                ));
            }
            return Ok(
                json!({"schema":1,"command":"harvest","loop":request.loop_name,"run":request.run,"dry_run":request.dry_run,"checkpoint_index":index,"preserved_object":preserved_object,"gate_object":request.gate_object,"collection":collection,"changed":false}),
            );
        }
        if collection["state"] == "removing" {
            if request.dry_run {
                return Ok(
                    json!({"schema":1,"command":"harvest","loop":request.loop_name,"run":request.run,"dry_run":true,"checkpoint_index":index,"preserved_object":preserved_object,"gate_object":request.gate_object,"pending_collection":collection,"disposition":"would-recover-interrupted-removal","changed":false}),
                );
            }
            let disposition = finish_pending(
                &mut record,
                collection,
                &root_fd,
                &request.run,
                &plan.home,
                Some(&home_parent),
                owner,
                &owners,
            )?;
            return Err(LaneError::input(
                "harvest-collection",
                format!(
                    "interrupted removal reconciled as {} with remaining {}",
                    disposition["state"], disposition["remaining"]
                ),
            ));
        }
        return Err(LaneError::input(
            "harvest-collection",
            format!("prior collection disposition is {}", collection["state"]),
        ));
    }
    if !request.dry_run && prior_agreement.is_none() {
        let agreement_instant = instant()?;
        record["harvest_agreement"] = json!({"checkpoint_index":index,"preserved_object":preserved_object,"gate_object":request.gate_object,"instant_unix_ns":agreement_instant});
        checked_size(&record)?;
        let agreement_token = checkpoint::random_token()?;
        checkout::publish_record(&root_fd, &request.run, &record, &agreement_token)
            .map_err(|error| LaneError::operation("harvest-record", error.line()))?;
    }
    let home_name = plan
        .home
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LaneError::input("harvest-path", "home name is invalid"))?;
    let home_fd = directory(&home_parent, home_name, &plan.home, owner)?;
    let home_stat =
        fstat(&home_fd).map_err(|error| LaneError::input("harvest-path", error.to_string()))?;
    if home_stat.st_mode & 0o7777 != 0o750 {
        return Err(LaneError::input(
            "harvest-path",
            "home mode differs from 0750",
        ));
    }
    let (removals, writable_collected_first) = planned_removals(&home_fd, &owners, worker)?;
    measure_home(&home_fd, &plan.home, worker, checkpoint)?;
    let removal_instant = instant()?;
    let token = checkpoint::random_token()?;
    let parent_identity = descriptor_identity(&home_parent)?;
    let home_identity = descriptor_identity(&home_fd)?;
    let mut pending = record.clone();
    pending["collection"] = json!({"checkpoint_index":index,"state":"removing","instant_unix_ns":removal_instant,"planned":removals,"writable_collected_first":writable_collected_first,"remaining":null,"refusal":null,"component":null,"token":token,"parent_identity":parent_identity,"home_identity":home_identity});
    let mut worst = pending.clone();
    worst["collection"]["state"] = json!("refused");
    worst["collection"]["remaining"] = json!(removals);
    worst["collection"]["refusal"] = json!("x".repeat(256));
    worst["collection"]["component"] = json!(
        removals
            .iter()
            .max_by_key(|path| path.len())
            .cloned()
            .unwrap_or_default()
    );
    checked_size(&worst)?;
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"harvest","loop":request.loop_name,"run":request.run,"dry_run":true,"checkpoint_index":index,"preserved_object":preserved_object,"gate_object":request.gate_object,"would_remove":removals,"writable_collected_first":writable_collected_first,"agreement":"would-record","changed":false}),
        );
    }
    publish_collection(&root_fd, &request.run, &pending, &token)?;
    for relative in &removals {
        if let Err(error) = remove_entry(
            &home_fd,
            &home_parent,
            home_name,
            relative,
            owner,
            worker,
            &owners,
        ) {
            pending["collection"]["state"] = json!("refused");
            let (remaining, path_refusal) = checked_remaining(
                Some(&home_parent),
                &plan.home,
                owner,
                &owners,
                &pending["collection"],
            );
            pending["collection"]["remaining"] =
                remaining.map_or(Value::Null, |paths| json!(paths));
            pending["collection"]["refusal"] = json!(if path_refusal == "harvest-private" {
                error.kind
            } else {
                path_refusal
            });
            pending["collection"]["component"] = json!(relative);
            publish_collection(&root_fd, &request.run, &pending, &token)?;
            return Err(LaneError::operation(
                "harvest-collection",
                format!("{relative}: {}", error.line()),
            ));
        }
    }
    pending["collection"]["state"] = json!("collected");
    pending["collection"]["remaining"] = json!([]);
    publish_collection(&root_fd, &request.run, &pending, &token)?;
    Ok(
        json!({"schema":1,"command":"harvest","loop":request.loop_name,"run":request.run,"dry_run":false,"checkpoint_index":index,"preserved_object":preserved_object,"gate_object":request.gate_object,"collection":pending["collection"],"changed":true}),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// # Panics
    /// Panics only if fixture construction or the production refusal contract fails.
    ///
    /// ´test:unit:harvest-entry-reports-preservation-count-bound-and-contributors´
    #[test]
    fn harvest_entry_reports_preservation_count_bound_and_contributors() {
        let (fixture, mut plan, settings, mut record, _bare) =
            super::super::exercise::cases::tests::mixed_preserved_fixture();
        let owner = Uid::effective().as_raw();
        let worker = 3000;
        let owner_home = fixture.path();
        let home_parent = owner_home.join(".cache/tmp");
        std::fs::create_dir_all(&home_parent).expect("home parent");
        for path in [owner_home.join(".cache"), home_parent.clone()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("parent mode");
        }
        plan.home = home_parent.join("lane-alpha-R");
        plan.document =
            serde_json::from_str(include_str!("../../tests/fixtures/plan.json")).expect("plan");
        let inbox = plan.home.join(".local/inbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        for path in [plan.home.join(".local"), inbox.clone()] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("preserved directory mode");
        }
        std::fs::set_permissions(&plan.home, std::fs::Permissions::from_mode(0o750))
            .expect("home mode");
        // Empty copied directories count too; each directory listing stays below
        // the independent checkpoint directory-listing bound.
        for group in 0..3 {
            let group = inbox.join(format!("group-{group}"));
            std::fs::create_dir(&group).expect("group");
            std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o700))
                .expect("group mode");
            for entry in 0..2800 {
                let path = group.join(entry.to_string());
                std::fs::create_dir(&path).expect("entry");
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .expect("entry mode");
            }
        }
        record["plan"]["home"] = json!(plan.home);
        record["plan"]["paths"] = json!([
            {"path":plan.home,"uid":owner,"gid":owner},
            {"path":plan.driver_dir,"uid":owner,"gid":owner,"kind":"directory"},
            {"path":plan.home.join(".codex"),"uid":worker,"gid":worker},
            {"path":plan.home.join(".cache"),"uid":worker,"gid":worker},
            {"path":plan.home.join(".local"),"uid":owner,"gid":owner},
            {"path":inbox,"uid":owner,"gid":owner}
        ]);
        record["worker_uid"] = json!(worker);
        record["schema"] = json!(1);
        record["rounds"] = json!([{"step":"dispatch","phase":"settled","ended_by":"by-report"}]);
        record["active_round"] = json!("dispatch");
        record["collection"] = Value::Null;
        let root = settings.runs_root.as_deref().expect("runs root");
        for name in [".prepare-R.lock", ".letter-R.lock"] {
            let path = root.join(name);
            std::fs::write(&path, b"").expect("lock");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("lock mode");
        }
        publish_reservation(&reservation_path(root, "R"), &record).expect("reservation");
        let gate_object = record["checkpoints"][0]["bares"][0]["object"]
            .as_str()
            .expect("object")
            .to_owned();
        assert_preservation_refusal(owner_home, &plan, &settings, &gate_object);
    }

    fn assert_preservation_refusal(
        owner_home: &Path,
        plan: &Plan,
        settings: &Settings,
        gate_object: &str,
    ) {
        for dry_run in [true, false] {
            PRIVATE_RUN_FIXTURE.with(|slot| {
                *slot.borrow_mut() = Some((
                    Plan {
                        home: plan.home.clone(),
                        driver_dir: plan.driver_dir.clone(),
                        letter: plan.letter.clone(),
                        document: plan.document.clone(),
                    },
                    settings.clone(),
                ));
            });
            let error = private_run(
                owner_home,
                &HarvestRequest {
                    loop_name: "alpha".into(),
                    run: "R".into(),
                    gate_object: gate_object.to_owned(),
                    dry_run,
                },
            )
            .expect_err("oversized preservation");
            assert_eq!(error.kind, "harvest-size", "{}", error.line());
            let fields: BTreeMap<_, _> = error
                .detail
                .split_whitespace()
                .filter_map(|word| word.split_once('='))
                .collect();
            assert_eq!(fields["bound"], "preservation-entries");
            assert_eq!(
                fields["count"].parse::<usize>().expect("measured count"),
                8404
            );
            assert_eq!(
                fields["limit"].parse::<usize>().expect("bound"),
                MAX_PRESERVED_ENTRIES
            );
            assert!(error.detail.contains(".local/inbox"));
            assert!(plan.home.join(".local/inbox").exists());
        }
    }

    /// ´test:unit:harvest-private-dry-run-verifies-unborn-copy´
    #[test]
    fn harvest_private_dry_run_verifies_unborn_copy() {
        let (fixture, mut plan, settings, mut record, _bare) =
            super::super::exercise::cases::tests::mixed_preserved_fixture();
        let owner = Uid::effective().as_raw();
        let worker = 3000;
        assert_ne!(owner, worker);
        let owner_home = fixture.path();
        let home_parent = owner_home.join(".cache/tmp");
        std::fs::create_dir_all(&home_parent).expect("temporary home root");
        std::fs::set_permissions(
            owner_home.join(".cache"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("cache mode");
        std::fs::set_permissions(&home_parent, std::fs::Permissions::from_mode(0o700))
            .expect("temporary root mode");
        plan.home = home_parent.join("lane-alpha-R");
        plan.document = serde_json::from_str(include_str!("../../tests/fixtures/plan.json"))
            .expect("fixture plan document");
        record["plan"]["home"] = json!(plan.home);
        record["plan"]["paths"] = json!([
            {"path":plan.home,"uid":owner,"gid":owner},
            {"path":plan.driver_dir,"uid":owner,"gid":owner,"kind":"directory"},
            {"path":plan.home.join(".codex"),"uid":worker,"gid":worker},
            {"path":plan.home.join(".cache"),"uid":worker,"gid":worker}
        ]);
        record["worker_uid"] = json!(worker);
        record["schema"] = json!(1);
        record["rounds"] = json!([{"step":"dispatch","phase":"settled","ended_by":"by-report"}]);
        record["active_round"] = json!("dispatch");
        record["collection"] = json!({"checkpoint_index":1,"state":"removing","instant_unix_ns":3,"planned":["."],"writable_collected_first":null,"remaining":null,"refusal":null,"component":null,"token":"a".repeat(32),"parent_identity":{"device":1,"inode":1},"home_identity":{"device":1,"inode":2}});
        let root = settings.runs_root.as_deref().expect("runs root");
        for name in [".prepare-R.lock", ".letter-R.lock"] {
            let path = root.join(name);
            std::fs::write(&path, b"").expect("existing dry-run lock");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("lock mode");
        }
        super::super::publish_reservation(&super::super::reservation_path(root, "R"), &record)
            .expect("mixed reservation");
        let gate_object = record["checkpoints"][0]["bares"][0]["object"]
            .as_str()
            .expect("shipped object")
            .to_owned();
        let request = HarvestRequest {
            loop_name: "alpha".into(),
            run: "R".into(),
            gate_object,
            dry_run: true,
        };
        PRIVATE_RUN_FIXTURE.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some((plan, settings));
        });
        let report = private_run(owner_home, &request).expect("mixed-bare dry run");
        assert_eq!(report["disposition"], "would-recover-interrupted-removal");
        assert_eq!(report["changed"], false);
    }

    /// ´test:unit:harvest-refuses-a-missing-unborn-preserved-copy´
    #[test]
    fn harvest_refuses_a_missing_unborn_preserved_copy() {
        let (_fixture, plan, _settings, record, _shipped) =
            super::super::exercise::cases::tests::mixed_preserved_fixture();
        let checkpoint = &record["checkpoints"][0];
        let unborn = checkpoint["bares"][1].clone();
        let fd: OwnedFd = std::fs::File::open(&plan.driver_dir)
            .expect("held driver directory")
            .into();
        let uid = Uid::effective().as_raw();
        verify_checkpoint_bares(
            &fd,
            &plan.driver_dir,
            1,
            checkpoint["files"].as_array().expect("file list"),
            std::slice::from_ref(&unborn),
            "R",
            uid,
        )
        .expect("unborn copy remains intact");
        std::fs::remove_dir_all(plan.driver_dir.join("preserved/1/sources/unborn.git"))
            .expect("remove unborn copy");
        let refusal = verify_checkpoint_bares(
            &fd,
            &plan.driver_dir,
            1,
            checkpoint["files"].as_array().expect("file list"),
            &[unborn],
            "R",
            uid,
        )
        .expect_err("missing unborn copy must refuse");
        assert_eq!(refusal.kind, "harvest-checkpoint");
    }

    #[allow(clippy::too_many_lines)]
    pub fn production_settled_reservation() -> (tempfile::TempDir, Plan, Value) {
        let fixture = tempfile::tempdir_in("/tmp").expect("fixture");
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runs root mode");
        let owner = Uid::effective().as_raw();
        let settings = crate::settings::Settings {
            sandbox_mode: String::from("danger-full-access"),
            runs_root: None,
            backend_argv: std::collections::BTreeMap::from([(
                "codex".into(),
                vec!["/usr/libexec/superloop/codex".into()],
            )]),
            driver_argv: Vec::new(),
            entry_bin: Some(fixture.path().join("entry")),
            driver_bin: Some(fixture.path().join("driver")),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            template_dir: Some(fixture.path().join("templates")),
            resources: Some(crate::settings::Resources {
                memory_bytes: 2_147_483_648,
                pids_max: 128,
                cpu_shares: 512,
            }),
            socket_dir: Some(fixture.path().join("sockets")),
            vendor_hosts: std::collections::BTreeMap::new(),
            context_threshold: None,
            retention: String::from("keep"),
            source: String::new(),
        };
        let row = json!({"name":"alpha","uid":41001,"runs_root":fixture.path()});
        let mut plan = Plan::build(
            fixture.path(),
            "alpha",
            "R",
            &settings,
            &row,
            loop_home::registry::WorkerBlock {
                base: 3000,
                count: 2,
            },
            (owner, owner),
        )
        .expect("production launch planner");
        plan.select_worker_uid(3000).expect("worker selection");
        let selection = json!({"model":"gpt-6-sol","effort":"high","model_source":"launch-flag","effort_source":"launch-flag"});
        plan.select_launch_model(&selection)
            .expect("model selection");
        std::fs::create_dir_all(plan.home.parent().expect("home parent"))
            .expect("planned home ancestry");
        for directory in [
            fixture.path().join(".cache"),
            fixture.path().join(".cache/tmp"),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("planned home ancestor mode");
        }
        let step_dir = plan.driver_dir.join("20261007T043545Z-dispatch");
        std::fs::create_dir_all(&step_dir).expect("step directory");
        std::fs::set_permissions(&plan.driver_dir, std::fs::Permissions::from_mode(0o700))
            .expect("driver mode");
        std::fs::write(
            step_dir.join("events.jsonl"),
            b"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n",
        )
        .expect("events");
        std::fs::write(step_dir.join(".event-start"), b"0\n").expect("event boundary");
        let report = format!(
            "RUN-REPORT lane=dispatch exit=0 verdict=ok dir={}\n",
            step_dir.display()
        );
        std::fs::write(step_dir.join("run-report.txt"), report).expect("terminal report");
        let mut record = super::initial_reservation(
            &plan,
            "alpha",
            "R",
            3000,
            &selection,
            &[],
            &plan.letter,
            None,
            &[],
            crate::door::Scope::Work,
        );
        let reservation = super::reservation_path(fixture.path(), "R");
        super::publish_reservation(&reservation, &record).expect("production launch reservation");
        record["phase"] = json!("started");
        super::record_dispatch_letter(
            &mut record,
            3600,
            b"ask",
            false,
            1,
            fixture.path(),
            &step_dir,
        )
        .expect("production dispatch row");
        super::publish_reservation(&reservation, &record).expect("placed dispatch");
        super::rounds::record_step_directory(
            &plan,
            "R",
            "dispatch",
            &format!(
                "RUN-REPORT lane=dispatch exit=0 verdict=ok dir={}\n",
                step_dir.display()
            ),
        )
        .expect("production step directory writer");
        let reply = json!({"path":fixture.path().join("reply.md"),"bytes":5,"sha256":"digest","worker_uid":3000});
        super::rounds::record_settlement(&plan, "alpha", "R", &reply).expect("settlement writer");
        let settled_round = super::read_reservation(&reservation)
            .expect("read settled round")
            .expect("reservation");
        super::publish_interrupted_phase(
            &reservation,
            &settled_round,
            true,
            &json!({"state":"complete"}),
            Uid::effective().as_raw(),
        )
        .expect("launch phase writer");
        let settled = super::read_reservation(&reservation)
            .expect("read settled run")
            .expect("reservation");
        (fixture, plan, settled)
    }

    /// ´test:unit:harvest-accepts-production-settled-reservation-and-names-drift´
    #[test]
    fn harvest_accepts_production_settled_reservation_and_names_drift() {
        let (fixture, plan, settled) = production_settled_reservation();
        assert_eq!(settled["phase"], "settled");
        assert_eq!(settled["active_round"], "dispatch");
        assert_eq!(settled["rounds"][0]["ended_by"], "by-report");
        assert_eq!(settled["plan"]["driver_dir"], json!(plan.driver_dir));
        settled_reservation(&settled, &plan, "alpha", "R")
            .expect("production settled reservation is accepted");
        let mut historical = settled.clone();
        historical["rounds"][0]["ended_by"] = json!("by-budget");
        settled_reservation(&historical, &plan, "alpha", "R")
            .expect("historical budget end remains readable");
        let root_fd: OwnedFd = std::fs::File::open(fixture.path())
            .expect("runs root descriptor")
            .into();
        let (checkout_record, _) =
            super::checkout::read_record_bound(&root_fd, "R", Uid::effective().as_raw())
                .expect("checkout's bound reservation reader");
        assert_eq!(
            checkout_record["plan"]["driver_dir"],
            json!(plan.driver_dir)
        );
        let (_, checkpoints, _) = super::checkpoint::checkpoint_fields(&checkout_record)
            .expect("checkpoint record reader");
        assert_eq!(checkpoints, Vec::<Value>::new());
        // Copying worker-owned home data and cloning its preserved bare require the private namespace.
        let mut without_driver_dir = settled.clone();
        without_driver_dir["plan"]
            .as_object_mut()
            .expect("plan")
            .remove("driver_dir");
        let error = settled_reservation(&without_driver_dir, &plan, "alpha", "R")
            .expect_err("missing recorded driver directory");
        assert_eq!(error.detail, "plan.driver_dir is absent or not text");
        let mut changed_driver_dir = settled.clone();
        changed_driver_dir["plan"]["driver_dir"] = json!("/another/driver");
        let error = settled_reservation(&changed_driver_dir, &plan, "alpha", "R")
            .expect_err("changed driver directory");
        assert_eq!(error.detail, "plan.driver_dir differs");
        let mut phase = settled.clone();
        phase["phase"] = json!("running");
        let error = settled_reservation(&phase, &plan, "alpha", "R").expect_err("phase drift");
        assert_eq!(error.kind, "harvest-record");
        assert_eq!(error.detail, "phase is running; expected settled");
        let mut home = settled.clone();
        home["plan"]["home"] = json!("/another/home");
        let error = settled_reservation(&home, &plan, "alpha", "R").expect_err("home drift");
        assert_eq!(error.detail, "plan.home differs");
        let mut step = settled;
        step["active_round"] = json!("review");
        let error = settled_reservation(&step, &plan, "alpha", "R").expect_err("step drift");
        assert_eq!(
            error.detail,
            "active_round is review; last settled step is dispatch"
        );
        let mut missing = step;
        missing
            .as_object_mut()
            .expect("record")
            .remove("active_round");
        let error =
            settled_reservation(&missing, &plan, "alpha", "R").expect_err("missing active round");
        assert_eq!(error.detail, "active_round is absent or not text");
        missing["active_round"] = json!("dispatch");
        missing["rounds"][0]["ended_by"] = Value::Null;
        let error =
            settled_reservation(&missing, &plan, "alpha", "R").expect_err("missing round end");
        assert_eq!(error.detail, "last round ended_by is absent or not text");
    }

    /// ´test:unit:harvest-and-rotation-cases-read-production-settled-reservation´
    #[test]
    fn harvest_and_rotation_cases_read_production_settled_reservation() {
        let (fixture, plan, settled) = production_settled_reservation();
        let settings = Settings {
            runs_root: Some(fixture.path().to_path_buf()),
            backend_argv: BTreeMap::new(),
            driver_argv: Vec::new(),
            entry_bin: None,
            driver_bin: None,
            image_digest: None,
            template_dir: None,
            resources: None,
            socket_dir: None,
            vendor_hosts: BTreeMap::new(),
            sandbox_mode: String::new(),
            context_threshold: None,
            retention: String::from("keep"),
            source: String::new(),
        };
        let root_fd: OwnedFd = std::fs::File::open(fixture.path())
            .expect("runs root descriptor")
            .into();
        let harvest_case = super::super::exercise::cases::measure(
            fixture.path(),
            &plan,
            &settings,
            &settled,
            "alpha",
            "R",
            "harvest",
            None,
            &root_fd,
        )
        .expect("harvest case");
        assert_eq!(harvest_case["verdict"], "fail");
        assert_eq!(
            harvest_case["claims"]["preserved_byte_audit"]["reason"],
            "complete checkpoint is absent"
        );
        let rotation_case = super::super::exercise::cases::measure(
            fixture.path(),
            &plan,
            &settings,
            &settled,
            "alpha",
            "R",
            "rotation",
            None,
            &root_fd,
        )
        .expect("rotation case");
        assert_eq!(rotation_case["verdict"], "unmeasured");
        assert_eq!(rotation_case["claims"]["default_keep"]["verdict"], "pass");
    }

    fn object() -> String {
        "a".repeat(40)
    }

    fn agreement() -> Value {
        json!({"checkpoint_index":1,"preserved_object":object(),"gate_object":object(),"instant_unix_ns":1})
    }

    fn collection() -> Value {
        json!({"checkpoint_index":1,"state":"removing","instant_unix_ns":2,"planned":[".local/inbox/dispatch.md",".local/inbox",".local","."],"writable_collected_first":null,"remaining":null,"refusal":null,"component":null,"token":"a".repeat(32),"parent_identity":{"device":1,"inode":2},"home_identity":{"device":1,"inode":3}})
    }

    /// ´test:unit:harvest-record-requires-present-keys-and-consistent-disposition´
    #[test]
    fn harvest_record_requires_present_keys_and_consistent_disposition() {
        let base = json!({"harvest_agreement":agreement(),"collection":collection()});
        assert!(harvest_fields(&base).is_ok());
        let mut missing = base.clone();
        missing["collection"]
            .as_object_mut()
            .expect("object")
            .remove("remaining");
        assert_eq!(
            harvest_fields(&missing).expect_err("missing key").kind,
            "harvest-record"
        );
        let mut contradictory = base.clone();
        contradictory["collection"]["state"] = json!("collected");
        assert_eq!(
            harvest_fields(&contradictory)
                .expect_err("contradiction")
                .kind,
            "harvest-record"
        );
        let mut repeated = base.clone();
        repeated["collection"]["planned"] = json!([".local", ".local", "."]);
        assert_eq!(
            harvest_fields(&repeated)
                .expect_err("repeated removal")
                .kind,
            "harvest-record"
        );
        let mut wrong_order = base;
        wrong_order["collection"]["state"] = json!("refused");
        wrong_order["collection"]["remaining"] = json!([".", ".local"]);
        wrong_order["collection"]["refusal"] = json!("harvest-collection");
        wrong_order["collection"]["component"] = json!(".");
        assert_eq!(
            harvest_fields(&wrong_order)
                .expect_err("remaining order")
                .kind,
            "harvest-record"
        );
    }

    /// ´test:unit:harvest-selects-gate-object-from-preserved-bares´
    #[test]
    fn harvest_selects_gate_object_from_preserved_bares() {
        let one = json!({"bares":[{"name":"tools","object":object()}]});
        assert_eq!(
            checkpoint_object(&one, &object()).expect("one object"),
            object()
        );
        let mixed = json!({"bares":[{"name":"tools","object":object()},{"name":"other","object":"b".repeat(40)}]});
        assert_eq!(
            checkpoint_object(&mixed, &"b".repeat(40)).expect("selected second source"),
            "b".repeat(40)
        );
        assert_eq!(
            checkpoint_object(&mixed, &"c".repeat(40))
                .expect_err("gate object absent")
                .kind,
            "harvest-mismatch"
        );
        assert_eq!(
            checkpoint_object(&json!({"bares":[]}), &object())
                .expect_err("no bare")
                .kind,
            "harvest-checkpoint"
        );
        let mismatch = compare_object(&object(), &"b".repeat(40)).expect_err("mismatch");
        assert_eq!(mismatch.kind, "harvest-mismatch");
        assert!(mismatch.detail.contains(&object()));
        assert!(mismatch.detail.contains(&"b".repeat(40)));
    }

    /// ´test:unit:harvest-interrupted-removal-observes-remaining-components´
    #[test]
    fn harvest_interrupted_removal_observes_remaining_components() {
        let temp = tempfile::tempdir().expect("fixture root");
        let home = temp.path().join("lane-alpha-R");
        std::fs::create_dir(&home).expect("fixture home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o750)).expect("mode");
        std::fs::write(home.join("note"), b"example").expect("fixture file");
        std::fs::set_permissions(home.join("note"), std::fs::Permissions::from_mode(0o640))
            .expect("file mode");
        let owner = Uid::effective().as_raw();
        let owners = BTreeMap::from([(PathBuf::new(), owner), (PathBuf::from("note"), owner)]);
        let planned = vec![json!("note"), json!(".")];
        let parent: OwnedFd = std::fs::File::open(temp.path())
            .expect("fixture parent")
            .into();
        assert_eq!(
            remaining_from_parent(&parent, "lane-alpha-R", &home, owner, &owners, &planned),
            Some(vec![String::from("note"), String::from(".")])
        );
        std::fs::remove_file(home.join("note")).expect("remove fixture file");
        assert_eq!(
            remaining_from_parent(&parent, "lane-alpha-R", &home, owner, &owners, &planned),
            Some(vec![String::from(".")])
        );
        std::fs::remove_dir(&home).expect("remove fixture home");
        assert_eq!(
            remaining_from_parent(&parent, "lane-alpha-R", &home, owner, &owners, &planned),
            Some(Vec::new())
        );
    }

    /// ´test:unit:harvest-recovery-refuses-replaced-parent-with-unknown-inventory´
    #[test]
    fn harvest_recovery_refuses_replaced_parent_with_unknown_inventory() {
        let temp = tempfile::tempdir().expect("fixture");
        let parent_path = temp.path().join("current");
        std::fs::create_dir(&parent_path).expect("parent");
        let home_path = parent_path.join("lane-alpha-R");
        std::fs::create_dir(&home_path).expect("home");
        let old_parent: OwnedFd = std::fs::File::open(&parent_path)
            .expect("old parent")
            .into();
        let old_home: OwnedFd = std::fs::File::open(&home_path).expect("old home").into();
        let mut pending = collection();
        pending["parent_identity"] = descriptor_identity(&old_parent).expect("identity");
        pending["home_identity"] = descriptor_identity(&old_home).expect("identity");
        std::fs::rename(&parent_path, temp.path().join("aside")).expect("move parent");
        std::fs::create_dir(&parent_path).expect("replacement");
        let replacement: OwnedFd = std::fs::File::open(&parent_path)
            .expect("new parent")
            .into();
        let (remaining, refusal) = checked_remaining(
            Some(&replacement),
            &home_path,
            Uid::effective().as_raw(),
            &BTreeMap::new(),
            &pending,
        );
        assert!(remaining.is_none());
        assert_eq!(refusal, "harvest-parent");
        let root_fd: OwnedFd = std::fs::File::open(temp.path())
            .expect("record root")
            .into();
        let mut record = json!({"collection":pending.clone()});
        let disposition = finish_pending(
            &mut record,
            &pending,
            &root_fd,
            "R",
            &home_path,
            Some(&replacement),
            Uid::effective().as_raw(),
            &BTreeMap::new(),
        )
        .expect("publish refusal");
        assert_eq!(disposition["state"], "refused");
        assert_eq!(disposition["refusal"], "harvest-parent");
        assert!(disposition["remaining"].is_null());
    }

    /// ´test:unit:harvest-refuses-added-and-changed-mailbox-files´
    #[test]
    fn harvest_refuses_added_and_changed_mailbox_files() {
        let temp = tempfile::tempdir().expect("fixture root");
        let inbox = temp.path().join("inbox");
        std::fs::create_dir(&inbox).expect("inbox");
        std::fs::write(inbox.join("dispatch.md"), b"letter").expect("letter");
        std::fs::set_permissions(
            inbox.join("dispatch.md"),
            std::fs::Permissions::from_mode(0o640),
        )
        .expect("mode");
        let fd: OwnedFd = std::fs::File::open(&inbox)
            .expect("inbox descriptor")
            .into();
        let file = openat2(
            &fd,
            "dispatch.md",
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .expect("file descriptor");
        let digest = checkpoint::digest(&file, Path::new("inbox/dispatch.md")).expect("digest");
        let uid = Uid::effective().as_raw();
        let expected =
            || BTreeMap::from([(String::from("inbox/dispatch.md"), (6, digest.clone()))]);
        walk_mailbox(&fd, Path::new("inbox"), uid, &mut expected(), 0).expect("unchanged letter");
        std::fs::write(inbox.join("dispatch.md"), b"changed").expect("changed letter");
        assert_eq!(
            walk_mailbox(&fd, Path::new("inbox"), uid, &mut expected(), 0)
                .expect_err("changed letter refused")
                .kind,
            "harvest-unpreserved"
        );
        std::fs::write(inbox.join("dispatch.md"), b"letter").expect("restore letter");
        std::fs::write(inbox.join("added.md"), b"extra").expect("added letter");
        std::fs::set_permissions(
            inbox.join("added.md"),
            std::fs::Permissions::from_mode(0o640),
        )
        .expect("added mode");
        assert_eq!(
            walk_mailbox(&fd, Path::new("inbox"), uid, &mut expected(), 0)
                .expect_err("added file refused")
                .kind,
            "harvest-unpreserved"
        );
    }

    /// ´test:unit:harvest-unlink-stays-beneath-pinned-home-and-refuses-fixed-link´
    #[test]
    fn harvest_unlink_stays_beneath_pinned_home_and_refuses_fixed_link() {
        let temp = tempfile::tempdir().expect("fixture root");
        let home = temp.path().join("lane-alpha-R");
        std::fs::create_dir(&home).expect("home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o750)).expect("mode");
        std::fs::write(home.join("note"), b"inside").expect("note");
        std::fs::set_permissions(home.join("note"), std::fs::Permissions::from_mode(0o640))
            .expect("file mode");
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"outside").expect("outside");
        std::os::unix::fs::symlink(&outside, home.join("link")).expect("link");
        let parent: OwnedFd = std::fs::File::open(temp.path())
            .expect("parent descriptor")
            .into();
        let held = directory(&parent, "lane-alpha-R", &home, Uid::effective().as_raw())
            .expect("home descriptor");
        let owner = Uid::effective().as_raw();
        let worker = owner.checked_add(1).expect("distinct worker");
        let owners = BTreeMap::from([
            (PathBuf::new(), owner),
            (PathBuf::from("note"), owner),
            (PathBuf::from("link"), owner),
        ]);
        assert_eq!(
            remove_entry(
                &held,
                &parent,
                "lane-alpha-R",
                "link",
                owner,
                worker,
                &owners
            )
            .expect_err("fixed link refused")
            .kind,
            "harvest-collection"
        );
        remove_entry(
            &held,
            &parent,
            "lane-alpha-R",
            "note",
            owner,
            worker,
            &owners,
        )
        .expect("remove note");
        assert!(home.join("note").symlink_metadata().is_err());
        assert_eq!(
            std::fs::read(&outside).expect("outside remains"),
            b"outside"
        );
    }

    /// ´test:unit:harvest-owner-class-comes-from-plan-and-unplanned-input-refuses´
    #[test]
    fn harvest_owner_class_comes_from_plan_and_unplanned_input_refuses() {
        let home = Path::new("~/lane-alpha-R");
        let record = json!({"plan":{"paths":[{"path":home,"uid":41001},{"path":home.join(".codex"),"uid":3000},{"path":home.join(".cache"),"uid":3000},{"path":home.join(".local"),"uid":41001},{"path":home.join(".local/inbox"),"uid":41001},{"path":home.join(".local/outbox"),"uid":3000}]}});
        let owners = owner_map(&record, home, 41001, 3000).expect("plan owners");
        assert_eq!(
            planned_uid(Path::new(".local/inbox/letter.md"), &owners).expect("inbox owner"),
            41001
        );
        assert_eq!(
            planned_uid(Path::new(".local/outbox/reply.md"), &owners).expect("outbox owner"),
            3000
        );
        assert_eq!(
            planned_uid(Path::new(".local/bin/unplanned"), &owners)
                .expect_err("unplanned protected input")
                .kind,
            "harvest-plan"
        );
    }

    /// ´test:unit:harvest-removes-writable-collected-only-file-and-records-its-path´
    #[test]
    fn harvest_removes_writable_collected_only_file_and_records_its_path() {
        let fixture = tempfile::tempdir().expect("fixture");
        let home = fixture.path().join("lane-alpha-R");
        let cache = home.join(".codex/plugins/cache");
        std::fs::create_dir_all(&cache).expect("worker cache");
        for directory in [
            home.join(".codex"),
            home.join(".codex/plugins"),
            cache.clone(),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("worker cache directory mode");
        }
        let writable = cache.join(".app.json");
        std::fs::write(&writable, b"fixture\n").expect("worker cache file");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o664))
            .expect("worker cache mode");
        let writable_directory = cache.join("downloads");
        std::fs::create_dir(&writable_directory).expect("worker cache directory");
        std::fs::set_permissions(&writable_directory, std::fs::Permissions::from_mode(0o775))
            .expect("worker cache directory mode");
        // A disposable cache larger than the preservation bound remains
        // collectable, and every descendant still passes descriptor removal.
        for group in 0..3 {
            for entry in 0..2800 {
                std::fs::create_dir_all(writable_directory.join(format!("group-{group}/{entry}")))
                    .expect("disposable cache entry");
            }
        }
        let worker = Uid::effective().as_raw();
        let owner = if worker == 41001 { 41002 } else { 41001 };
        let cache_fd: OwnedFd = std::fs::File::open(&cache)
            .expect("worker cache descriptor")
            .into();
        let cache_path = Path::new(".codex/plugins/cache/.app.json");
        let file = entry(&cache_fd, ".app.json", cache_path).expect("cache file descriptor");
        assert_eq!(
            stat_entry(&file, cache_path, owner)
                .expect_err("foreign owner")
                .kind,
            "harvest-path"
        );
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o4664))
            .expect("special cache mode");
        assert_eq!(
            stat_entry(&file, cache_path, worker)
                .expect_err("special mode")
                .kind,
            "harvest-path"
        );
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o664))
            .expect("restore cache mode");
        let owners = BTreeMap::from([(PathBuf::new(), owner), (PathBuf::from(".codex"), worker)]);
        let parent: OwnedFd = std::fs::File::open(fixture.path())
            .expect("home parent")
            .into();
        let held: OwnedFd = std::fs::File::open(&home).expect("home descriptor").into();
        let (planned, first) = planned_removals(&held, &owners, worker).expect("dry plan");
        assert!(planned.len() > MAX_PRESERVED_ENTRIES);
        assert_eq!(first.as_deref(), Some(".codex/plugins/cache/.app.json"));
        assert!(
            planned
                .iter()
                .any(|path| path == ".codex/plugins/cache/.app.json")
        );
        assert!(
            planned
                .iter()
                .any(|path| path == ".codex/plugins/cache/downloads")
        );
        let mut collection = collection();
        collection["planned"] = json!(planned);
        collection["writable_collected_first"] = json!(first);
        let record = json!({"harvest_agreement":agreement(),"collection":collection});
        harvest_fields(&record).expect("writable path in collection record");
        for path in planned.iter().filter(|path| path.as_str() != ".") {
            remove_entry(&held, &parent, "lane-alpha-R", path, owner, worker, &owners)
                .expect("changing removal");
        }
        assert!(!writable.exists());
        assert!(!home.join(".codex").exists());
    }

    /// ´test:unit:harvest-preserved-writable-file-still-refuses-by-name´
    #[test]
    fn harvest_preserved_writable_file_still_refuses_by_name() {
        let fixture = tempfile::tempdir().expect("fixture");
        std::fs::write(fixture.path().join("reply.md"), b"reply\n").expect("preserved reply");
        std::fs::set_permissions(
            fixture.path().join("reply.md"),
            std::fs::Permissions::from_mode(0o664),
        )
        .expect("writable reply mode");
        let parent: OwnedFd = std::fs::File::open(fixture.path())
            .expect("preserved parent")
            .into();
        let path = Path::new(".local/outbox/reply.md");
        let file = entry(&parent, "reply.md", path).expect("preserved file descriptor");
        let worker = Uid::effective().as_raw();
        assert_eq!(
            stat_entry(&file, path, worker)
                .expect_err("writable preserved file")
                .kind,
            "harvest-path"
        );
        assert_eq!(
            walk_mailbox(
                &parent,
                Path::new("outbox"),
                worker,
                &mut BTreeMap::new(),
                0,
            )
            .expect_err("writable evidence walk")
            .kind,
            "harvest-path"
        );
    }
}
