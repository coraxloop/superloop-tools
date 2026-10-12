//! The shared grammar and runs-root grant check for a loop's workers settings.

use std::path::{Component, Path, PathBuf};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::fstat;

use crate::{LoopError, LoopRecord};

const RETIRED_SETTINGS: &[(&str, &str)] = &[(
    "driver_bin",
    "set driver_argv = [PATH, \"driver\", \"start\", \"--backend\", \"codex\"]",
)];

fn retired_setting(table: &toml::Table) -> Option<LoopError> {
    RETIRED_SETTINGS.iter().find_map(|(name, replacement)| {
        table.contains_key(*name).then(|| {
            let path = std::env::current_exe()
                .ok()
                .and_then(|entry| {
                    let owner = nix::unistd::Uid::effective().as_raw();
                    owner_executable(&entry, owner).ok()?;
                    let driver = entry.with_file_name("superloop-lane");
                    owner_executable(&driver, owner).ok()?;
                    driver.to_str().map(str::to_owned)
                })
                .map_or_else(
                    || "PATH".to_owned(),
                    |path| toml::Value::String(path).to_string(),
                );
            refusal(
                "retired-setting",
                format!("{name}; {}", replacement.replace("PATH", &path)),
            )
        })
    })
}

/// Check an executable through held, link-free path components immediately before an owner act.
///
/// # Errors
///
/// Refuses a path whose parent or inode the loop identity could replace.
pub fn owner_executable(path: &Path, owner_uid: u32) -> Result<(), LoopError> {
    let relative = path.strip_prefix("/").map_err(|_| {
        refusal(
            "owner-program",
            format!("{} is not absolute", path.display()),
        )
    })?;
    let parts = relative.components().collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(refusal(
            "owner-program",
            format!("{} is not a plain absolute path", path.display()),
        ));
    }
    let mut parent = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|error| refusal("owner-program", error.to_string()))?;
    for (index, part) in parts.iter().enumerate() {
        let stat = fstat(&parent).map_err(|error| refusal("owner-program", error.to_string()))?;
        let trusted_owner = stat.st_uid == owner_uid || stat.st_uid == 0 || stat.st_uid == 65534;
        let sticky_root =
            (stat.st_uid == 0 || stat.st_uid == 65534) && stat.st_mode & 0o1777 == 0o1777;
        if !trusted_owner || (stat.st_mode & 0o022 != 0 && !sticky_root) {
            return Err(refusal(
                "owner-program",
                format!(
                    "{} has a replaceable parent at component {index}: uid {} mode {:04o}, owner uid {owner_uid}",
                    path.display(),
                    stat.st_uid,
                    stat.st_mode & 0o7777
                ),
            ));
        }
        let last = index + 1 == parts.len();
        parent = openat2(
            &parent,
            Path::new(part.as_os_str()),
            OpenHow::new()
                .flags(
                    OFlag::O_PATH
                        | OFlag::O_CLOEXEC
                        | if last {
                            OFlag::empty()
                        } else {
                            OFlag::O_DIRECTORY
                        },
                )
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| refusal("owner-program", format!("{}: {error}", path.display())))?;
    }
    let stat = fstat(&parent).map_err(|error| refusal("owner-program", error.to_string()))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o111 == 0
        || stat.st_mode & 0o022 != 0
        || !(stat.st_uid == owner_uid || stat.st_uid == 0 || stat.st_uid == 65534)
    {
        return Err(refusal(
            "owner-program",
            format!("{} is not an owner-controlled executable", path.display()),
        ));
    }
    Ok(())
}

/// Read the durable runs root from the session owner's trusted workers file.
///
/// The registered loop UID is deliberately not the settings owner. The registry
/// grants the root; this setting selects it without widening that grant.
///
/// # Errors
///
/// Refuses an absent setting, unsafe source, malformed value or registry mismatch.
pub fn read_runs_root(
    caller_home: &Path,
    row: &LoopRecord,
    granted_root: Option<&Path>,
) -> Result<PathBuf, LoopError> {
    read_runs_root_for_owner(
        caller_home,
        row,
        granted_root,
        nix::unistd::Uid::effective().as_raw(),
    )
}

pub(crate) fn read_runs_root_for_owner(
    caller_home: &Path,
    row: &LoopRecord,
    granted_root: Option<&Path>,
    owner: u32,
) -> Result<PathBuf, LoopError> {
    crate::validate_name(&row.name)?;
    let path = crate::driver_launch::settings_path(caller_home, &row.name);
    let source = crate::driver_launch::read_driver_setting(&path, owner)?;
    let table = validate_workers_settings(&source, &path)?;
    required_runs_root(&table, row, granted_root)
}

pub(crate) fn required_runs_root(
    table: &toml::Table,
    row: &LoopRecord,
    granted_root: Option<&Path>,
) -> Result<PathBuf, LoopError> {
    let root = table
        .get("runs_root")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            refusal(
                "runs_root_required",
                "runs_root is absent from workers settings",
            )
        })?;
    validate_workers_grant(table, row, granted_root)?;
    Ok(PathBuf::from(root))
}

fn refusal(kind: &str, detail: impl AsRef<str>) -> LoopError {
    LoopError::refusal(format!("{kind}: {}", detail.as_ref()))
}

fn absolute(value: &str) -> bool {
    Path::new(value).is_absolute()
        && !value.contains(',')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && !value.split('/').any(|part| part == "." || part == "..")
}

/// Decode one configured executable vector without shell interpretation.
///
/// # Errors
///
/// Refuses a missing vector, a nonabsolute program, or invalid argument bytes.
pub fn executable_argv(value: Option<&toml::Value>, key: &str) -> Result<Vec<String>, LoopError> {
    let list = value.and_then(toml::Value::as_array).ok_or_else(|| {
        refusal(
            "missing-setting",
            format!("{key} must be a nonempty argument array"),
        )
    })?;
    let words = list
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|word| !word.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| {
                    refusal(
                        "bad-setting",
                        format!("{key} must contain strings without NUL"),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if words.first().is_none_or(|program| !absolute(program)) {
        return Err(refusal(
            "bad-setting",
            format!("{key} must start with an absolute path without dotted components or commas"),
        ));
    }
    Ok(words)
}

/// Executable selectors read from an owner-controlled workers settings file.
#[derive(Clone, Debug)]
pub struct ExecutionSettings {
    /// Exact driver program and fixed arguments.
    pub driver_argv: Vec<String>,
    /// Exact backend program and fixed arguments for each configured backend.
    pub backend_argv: std::collections::BTreeMap<String, Vec<String>>,
    /// The trusted file that supplied these values.
    pub path: PathBuf,
}

impl ExecutionSettings {
    /// Carry selected values across the entry's clean environment boundary.
    #[must_use]
    pub fn environment(&self) -> Vec<String> {
        vec![
            format!("LANE_DRIVER_ARGV={}", serde_json::json!(self.driver_argv)),
            format!("LANE_BACKEND_ARGV={}", serde_json::json!(self.backend_argv)),
            format!(
                "LANE_SETTINGS_EVIDENCE={}",
                serde_json::json!({"path": self.path, "driver_argv": self.driver_argv, "backend_argv": self.backend_argv})
            ),
        ]
    }
}

/// Read executable selectors through the entry's pinned settings reader.
/// Ordinary entry may carry an empty backend map; a selected backend requires its vector.
///
/// # Errors
///
/// Refuses unsafe settings, a changed runs-root grant, or missing selectors.
pub fn read_execution_settings(
    caller_home: &Path,
    row: &LoopRecord,
    granted_root: Option<&Path>,
    backend: Option<&str>,
) -> Result<ExecutionSettings, LoopError> {
    let path = crate::driver_launch::settings_path(caller_home, &row.name);
    let source =
        crate::driver_launch::read_driver_setting(&path, nix::unistd::Uid::effective().as_raw())?;
    let table = validate_workers_settings(&source, &path)?;
    validate_workers_grant(&table, row, granted_root)?;
    let driver_argv = executable_argv(table.get("driver_argv"), "driver_argv")?;
    let empty = toml::Table::new();
    let vendors = match table.get("backend_argv").and_then(toml::Value::as_table) {
        Some(vendors) => vendors,
        None if backend.is_none() => &empty,
        None => {
            return Err(refusal(
                "missing-setting",
                "backend_argv is absent from workers settings",
            ));
        }
    };
    if let Some(backend) = backend {
        executable_argv(vendors.get(backend), &format!("backend_argv.{backend}"))?;
    }
    let backend_argv = vendors
        .iter()
        .map(|(name, value)| {
            executable_argv(Some(value), &format!("backend_argv.{name}"))
                .map(|argv| (name.clone(), argv))
        })
        .collect::<Result<_, _>>()?;
    Ok(ExecutionSettings {
        driver_argv,
        backend_argv,
        path,
    })
}

fn positive(table: &toml::Table, key: &str) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .is_some_and(|value| value > 0)
}

fn valid_host(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_lowercase()
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// Validate the complete settings grammar used by both the entry and the lane.
///
/// # Errors
///
/// Refuses malformed values and names every unknown setting.
#[allow(clippy::too_many_lines)]
pub fn validate_workers_settings(source: &str, path: &Path) -> Result<toml::Table, LoopError> {
    let value: toml::Value = toml::from_str(source).map_err(|_| {
        refusal(
            "settings-toml",
            format!("{}: malformed TOML", path.display()),
        )
    })?;
    let table = value.as_table().ok_or_else(|| {
        refusal(
            "settings-toml",
            format!("{}: expected a table", path.display()),
        )
    })?;
    let allowed = [
        "runs_root",
        "backend_argv",
        "driver_argv",
        "entry_bin",
        "image_digest",
        "template_dir",
        "resources",
        "socket_dir",
        "vendor_hosts",
        "sandbox_mode",
        "retention",
        "attempt_wall_seconds",
        "context_threshold",
    ];
    if let Some(error) = retired_setting(table) {
        return Err(error);
    }
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(refusal(
            "unknown-setting",
            format!("{}: {key}", path.display()),
        ));
    }
    for key in ["runs_root", "entry_bin", "template_dir", "socket_dir"] {
        if let Some(value) = table.get(key) {
            let text = value
                .as_str()
                .ok_or_else(|| refusal("bad-setting", format!("{key} must be a string")))?;
            if !absolute(text) {
                return Err(refusal(
                    "bad-setting",
                    format!(
                        "{key} must be an absolute path without dotted components or commas: {text}"
                    ),
                ));
            }
        }
    }
    if let Some(value) = table.get("driver_argv") {
        executable_argv(Some(value), "driver_argv")?;
    }
    if let Some(value) = table.get("image_digest") {
        let text = value
            .as_str()
            .ok_or_else(|| refusal("bad-setting", "image_digest must be a string"))?;
        if text.len() != 71
            || !text.starts_with("sha256:")
            || !text[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refusal(
                "bad-setting",
                "image_digest must be sha256: followed by 64 lowercase hex digits",
            ));
        }
    }
    if let Some(value) = table.get("sandbox_mode")
        && !matches!(
            value.as_str(),
            Some("workspace-write" | "danger-full-access")
        )
    {
        return Err(refusal(
            "bad-setting",
            "sandbox_mode must be workspace-write or danger-full-access",
        ));
    }
    if let Some(value) = table.get("retention")
        && value.as_str() != Some("keep")
    {
        return Err(refusal("retention-policy", "retention must be keep"));
    }
    if let Some(value) = table.get("attempt_wall_seconds")
        && value
            .as_integer()
            .and_then(|seconds| u64::try_from(seconds).ok())
            .is_none_or(|seconds| seconds == 0)
    {
        return Err(refusal(
            "attempt-wall",
            "attempt_wall_seconds must be a positive integer",
        ));
    }
    if let Some(value) = table.get("context_threshold")
        && value
            .as_float()
            .is_none_or(|fraction| !fraction.is_finite() || fraction <= 0.0 || fraction >= 1.0)
    {
        return Err(refusal(
            "context-threshold",
            "context_threshold must be a finite fraction above zero and below one",
        ));
    }
    if let Some(value) = table.get("resources") {
        let resources = value
            .as_table()
            .ok_or_else(|| refusal("bad-setting", "resources must be an inline table"))?;
        if let Some(key) = resources
            .keys()
            .find(|key| !["memory_bytes", "pids_max", "cpu_shares"].contains(&key.as_str()))
        {
            return Err(refusal("unknown-setting", format!("resources.{key}")));
        }
        if resources
            .get("memory_bytes")
            .and_then(toml::Value::as_integer)
            .and_then(|value| u64::try_from(value).ok())
            .is_none_or(|value| value == 0)
        {
            return Err(refusal(
                "bad-setting",
                "missing or invalid resources.memory_bytes",
            ));
        }
        for key in ["pids_max", "cpu_shares"] {
            if !positive(resources, key) {
                return Err(refusal("bad-setting", format!("missing or invalid {key}")));
            }
        }
    }
    for key in ["backend_argv", "vendor_hosts"] {
        let Some(value) = table.get(key) else {
            continue;
        };
        let vendors = value
            .as_table()
            .ok_or_else(|| refusal("bad-setting", format!("{key} must be an inline table")))?;
        for (vendor, values) in vendors {
            if !["codex", "claude"].contains(&vendor.as_str()) {
                return Err(refusal(
                    "bad-setting",
                    format!("{key} has unknown vendor {vendor}"),
                ));
            }
            if key == "backend_argv" {
                executable_argv(Some(values), &format!("backend_argv.{vendor}"))?;
            }
            let list = values.as_array().ok_or_else(|| {
                refusal("bad-setting", format!("{key}.{vendor} must be an array"))
            })?;
            let mut seen = std::collections::BTreeSet::new();
            for (index, item) in list.iter().enumerate() {
                let text = item.as_str().ok_or_else(|| {
                    refusal(
                        "bad-setting",
                        format!("{key}.{vendor} must contain strings"),
                    )
                })?;
                if key == "backend_argv" && index == 0 && !absolute(text) {
                    return Err(refusal(
                        "bad-setting",
                        format!(
                            "{key} must be an absolute path without dotted components or commas: {text}"
                        ),
                    ));
                }
                if key == "vendor_hosts" && (!valid_host(text) || !seen.insert(text)) {
                    return Err(refusal(
                        "bad-setting",
                        format!("{key}.{vendor} has an invalid or repeated hostname: {text}"),
                    ));
                }
            }
            if key == "backend_argv" && list.is_empty() {
                return Err(refusal(
                    "bad-setting",
                    format!("{key}.{vendor} must be nonempty"),
                ));
            }
        }
    }
    Ok(table.clone())
}

/// Refuse settings that widen the registry's runs root.
///
/// # Errors
///
/// Refuses a widened root.
pub fn validate_workers_grant(
    table: &toml::Table,
    _row: &LoopRecord,
    runs_root: Option<&Path>,
) -> Result<(), LoopError> {
    if table
        .get("runs_root")
        .and_then(toml::Value::as_str)
        .is_some_and(|root| Some(Path::new(root)) != runs_root)
    {
        return Err(refusal(
            "settings-grant",
            "runs_root differs from the registry row",
        ));
    }
    Ok(())
}
