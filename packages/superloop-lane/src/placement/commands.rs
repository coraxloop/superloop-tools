//! Owner-invoked own-path preparation and read-only placement inventory.
use super::{Placement, RootIdentity, read_identity, refusal};
use crate::error::LaneError;
use execute_command::workspace::canonical_digest;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, mkdirat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::File;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path};

pub const USAGE: &str = "placement prepare --parent DIR --declaration JSON {--dry-run|--expect-digest HEX}; placement inventory --parent DIR; placement census --parent DIR --inventory FILE --loop LOOP";
const MAX_INPUT: u64 = 8 * 1024 * 1024;

fn path_check(path: &Path) -> Result<(), LaneError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(refusal("placement parent must be an absolute normal path"));
    }
    Ok(())
}
fn open_beneath(root: &File, path: &str) -> Result<File, LaneError> {
    openat2(
        root,
        path,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map(File::from)
    .map_err(|e| refusal(format!("placement directory open: {e}")))
}
fn private(file: &File) -> Result<(), LaneError> {
    private_for(file, nix::unistd::Uid::effective().as_raw())
}
fn private_for(file: &File, owner: u32) -> Result<(), LaneError> {
    let m = file.metadata().map_err(|e| refusal(e.to_string()))?;
    if !m.is_dir() || m.uid() != owner || m.mode() & 0o7777 != 0o700 {
        return Err(refusal(
            "placement directory must be owned by the entered owner and mode 0700",
        ));
    }
    Ok(())
}
fn parent(path: &Path) -> Result<File, LaneError> {
    path_check(path)?;
    let root = File::open("/").map_err(|e| refusal(e.to_string()))?;
    let text = path
        .to_str()
        .ok_or_else(|| refusal("placement parent must be UTF-8"))?;
    let file = open_beneath(&root, text.trim_start_matches('/'))?;
    private(&file)?;
    Ok(file)
}
fn digest(value: &Value) -> Result<String, LaneError> {
    canonical_digest(value).map_err(|e| refusal(e.to_string()))
}

/// Prepare one exclusive root; receipt loss leaves an enumerable immediate entry.
/// # Errors
/// Refuses a foreign/nonprivate parent, existing root, unsupported identity or stale preview.
pub fn prepare(
    path: &Path,
    declaration: &str,
    expected: Option<&str>,
    dry: bool,
) -> Result<Value, LaneError> {
    let snapshot = crate::launch::workspace::declaration(declaration)?;
    if crate::launch::workspace::placement(declaration, &snapshot)?.is_some() {
        return Err(refusal(
            "placement preparation requires an unplaced declaration",
        ));
    }
    let held = parent(path)?;
    let name = &snapshot.grant.run;
    if !crate::valid_run_name(name)
        || path.join(name).to_str() != Some(snapshot.grant.workspace.as_str())
    {
        return Err(refusal(
            "workspace must be the named run directly beneath the placement parent",
        ));
    }
    for (key, child) in [
        ("CARGO_TARGET_DIR", "target"),
        ("CARGO_HOME", "cargo"),
        ("TMPDIR", "tmp"),
    ] {
        let wanted = Path::new(&snapshot.grant.workspace).join(child);
        if !snapshot
            .grant
            .baseline_env
            .iter()
            .any(|(k, v)| k == key && Path::new(v) == wanted)
        {
            return Err(refusal(
                "placement baseline must name its own target, cargo and tmp directories",
            ));
        }
    }
    let slot = format!("/proc/self/fd/{}/{name}", held.as_raw_fd());
    match std::fs::symlink_metadata(&slot) {
        Ok(_) => {
            return Err(refusal(
                "placement destination already exists; never reuse it",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(refusal(e.to_string())),
    }
    let mut preview = json!({"schema":1,"command":"placement-prepare","parent":path,
        "parent_identity":read_identity(&held)?,"compute_workspace":snapshot,"root":snapshot.grant.workspace});
    let sha = digest(&preview)?;
    preview["preview_sha256"] = json!(sha);
    preview["changed"] = json!(false);
    if dry {
        return Ok(preview);
    }
    if expected != Some(sha.as_str()) {
        return Err(refusal("placement preview digest differs; repeat dry run"));
    }
    mkdirat(&held, name.as_str(), Mode::S_IRWXU)
        .map_err(|e| refusal(format!("exclusive placement creation: {e}")))?;
    // From here on every failure leaves the named root for the census. Never
    // infer absence of activity or remove a path after an uncertain interruption.
    let root = open_beneath(&held, name)?;
    private(&root)?;
    let identity = read_identity(&root)?;
    for name in ["source", "target", "build", "cargo", "tmp"] {
        mkdirat(&root, name, Mode::S_IRWXU)
            .map_err(|e| refusal(format!("placement layout: {e}")))?;
    }
    root.sync_all().map_err(|e| refusal(e.to_string()))?;
    held.sync_all().map_err(|e| refusal(e.to_string()))?;
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .map_err(|e| refusal(e.to_string()))?;
    let placement = Placement {
        schema: 1,
        placement: super::encode(&random),
        loop_name: snapshot.grant.loop_name.clone(),
        run: name.clone(),
        node: snapshot.grant.node.clone(),
        grant_digest: snapshot.digest.clone(),
        mode: "own-path".into(),
        root: snapshot.grant.workspace.clone(),
        root_identity: identity,
        seed: None,
    };
    let placement = Placement::decode(json!(placement), &snapshot)?;
    let declaration = json!({"grant":snapshot.grant,"baseline_environment_is_public":true,"compute_placement":placement});
    let launch_digest = crate::launch::workspace::declaration_digest(&declaration.to_string())?;
    Ok(
        json!({"schema":1,"command":"placement-prepare","changed":true,"declaration":declaration,
        "workspace_declaration_digest":launch_digest,"preview_sha256":sha}),
    )
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    identity: Option<RootIdentity>,
    observation: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: u8,
    parent: String,
    parent_identity: RootIdentity,
    entries: Vec<Entry>,
}

/// Enumerate only the parent's immediate entries, never workspace contents.
/// # Errors
/// Refuses an invalid parent or an incomplete enumeration; no entry is removed.
pub fn inventory(path: &Path) -> Result<Value, LaneError> {
    let held = parent(path)?;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .map_err(|e| refusal(e.to_string()))?
    {
        let entry = entry.map_err(|e| refusal(e.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|n| crate::valid_run_name(n)) else {
            entries.push(Entry {
                name: format!(
                    "bytes:{}",
                    super::encode(std::os::unix::ffi::OsStrExt::as_bytes(name.as_os_str()))
                ),
                identity: None,
                observation: "unrecognised-name".into(),
            });
            continue;
        };
        let result = open_beneath(&held, name).and_then(|f| {
            private(&f)?;
            read_identity(&f)
        });
        entries.push(Entry {
            name: name.into(),
            identity: result.ok(),
            observation: "directory-candidate".into(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    serde_json::to_value(Inventory {
        schema: 1,
        parent: path.to_string_lossy().into(),
        parent_identity: read_identity(&held)?,
        entries,
    })
    .map_err(|e| refusal(e.to_string()))
}

/// Join an owner-transported inventory to exact protected reservation names.
/// # Errors
/// Refuses malformed inventory. Per-entry read failures remain explicit, never orphans safe to delete.
pub fn census(path: &Path, bytes: &[u8], loop_name: &str, runs: &Path) -> Result<Value, LaneError> {
    path_check(path)?;
    if bytes.len() > usize::try_from(MAX_INPUT).unwrap_or(0) {
        return Err(refusal("placement inventory exceeds bound"));
    }
    let input: Inventory = serde_json::from_slice(bytes).map_err(|e| refusal(e.to_string()))?;
    if input.schema != 1 || Path::new(&input.parent) != path {
        return Err(refusal("placement inventory context differs"));
    }
    input.parent_identity.validate()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for entry in input.entries {
        if !seen.insert(entry.name.clone()) {
            return Err(refusal("placement inventory repeats an entry"));
        }
        let state = classify_entry(path, loop_name, runs, &entry);
        rows.push(json!({"name":entry.name,"state":state,"identity":entry.identity,
            "removal":"not authorised: refresh census, reconcile live and retired custody, verify root identity and prove activity ended before owner removal"}));
    }
    Ok(
        json!({"schema":1,"command":"placement-census","parent":path,"loop":loop_name,
        "point_in_time":true,"changed":false,"entries":rows}),
    )
}
fn classify_entry(path: &Path, loop_name: &str, runs: &Path, entry: &Entry) -> &'static str {
    if entry.observation != "directory-candidate" || !crate::valid_run_name(&entry.name) {
        return "unrecognised";
    }
    let Some(identity) = &entry.identity else {
        return "unreadable-or-unrecognised";
    };
    if identity.validate().is_err() {
        return "unreadable-or-unrecognised";
    }
    let record = match crate::launch::read_reservation(
        &runs.join(format!(".reservation-{}.json", entry.name)),
    ) {
        Ok(Some(record)) => record,
        Ok(None) => return "orphan-candidate",
        Err(_) => return "reservation-unreadable",
    };
    let Some(grant) = crate::plan::workspace_snapshot(&record["plan"])
        .ok()
        .flatten()
    else {
        return "reservation-unbound";
    };
    let Some(placement) = super::snapshot(&record["plan"], Some(&grant))
        .ok()
        .flatten()
    else {
        return "reservation-unbound";
    };
    if placement.loop_name != loop_name
        || placement.run != entry.name
        || Path::new(&placement.root) != path.join(&entry.name)
    {
        return "reservation-context-differs";
    }
    if placement.bind(Ok(identity.clone())).is_err() {
        return "root-replaced";
    }
    if record["phase"] == "retired" {
        "retired-binding"
    } else {
        "live-binding"
    }
}

fn census_owner(path: &Path, source: &Path, loop_name: &str) -> Result<Value, LaneError> {
    loop_home::validate_name(loop_name).map_err(|e| refusal(e.message()))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)
        .map_err(|e| refusal(e.to_string()))?;
    let metadata = file.metadata().map_err(|e| refusal(e.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT {
        return Err(refusal(
            "placement inventory must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refusal(e.to_string()))?;
    let home = crate::caller_home()?;
    let config = home.join(".config/loops").join(loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let settings = crate::settings::Settings::read_beneath(&config.join("workers.toml"), &home)?;
    settings.validate_grant(&home, loop_name)?;
    let runs = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| refusal("placement census requires the loop's runs_root"))?;
    let _runs = crate::launch::lock_runs_root(runs, false, nix::unistd::Uid::effective().as_raw())?;
    census(path, &bytes, loop_name, runs)
}

/// Owner CLI, with explicit node inventory transport; no SSH or door dispatch.
/// # Errors
/// Refuses unknown arguments, invalid owner inputs or filesystem observations.
pub fn run(args: &[String]) -> Result<Value, LaneError> {
    match args {
        [op, flag, path, declaration_flag, text, dry]
            if op == "prepare"
                && flag == "--parent"
                && declaration_flag == "--declaration"
                && dry == "--dry-run" =>
        {
            prepare(Path::new(path), text, None, true)
        }
        [op, flag, path, declaration_flag, text, expect, sha]
            if op == "prepare"
                && flag == "--parent"
                && declaration_flag == "--declaration"
                && expect == "--expect-digest" =>
        {
            prepare(Path::new(path), text, Some(sha), false)
        }
        [op, flag, path] if op == "inventory" && flag == "--parent" => inventory(Path::new(path)),
        [op, flag, path, source_flag, source, loop_flag, loop_name]
            if op == "census"
                && flag == "--parent"
                && source_flag == "--inventory"
                && loop_flag == "--loop" =>
        {
            census_owner(Path::new(path), Path::new(source), loop_name)
        }
        _ => Err(refusal(USAGE)),
    }
}

#[cfg(test)]
#[path = "commands_tests.rs"]
mod tests;
