//! Resolve an owner-side launch from the registered effective runs root.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

pub(super) fn option_value(arguments: &[OsString], selected: u8) -> Option<&OsStr> {
    let mut words = arguments.iter();
    let mut found = None;
    while let Some(word) = words.next() {
        let bytes = word.as_bytes();
        match bytes {
            b"--ignore-pool" => continue,
            b"--pool-threshold" | b"--gateway-lane" => {
                words.next()?;
                continue;
            }
            b"--" | b"-" => break,
            _ if !bytes.starts_with(b"-") => break,
            _ => {}
        }
        let Some(index) = bytes
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, byte)| (*byte != b'P').then_some(index))
        else {
            continue;
        };
        if !matches!(
            bytes[index],
            b't' | b'C' | b's' | b'm' | b'e' | b'n' | b'r' | b'd'
        ) {
            return None;
        }
        let value = if index + 1 < bytes.len() {
            OsStr::from_bytes(&bytes[index + 1..])
        } else {
            words.next()?.as_os_str()
        };
        if bytes[index] == selected {
            found = Some(value);
        }
    }
    found
}

fn previous(selected: &Path) -> bool {
    selected
        .file_name()
        .is_some_and(|name| name.as_encoded_bytes().starts_with(b".claude-"))
}

pub(super) fn resolve(arguments: &[OsString]) -> Result<PathBuf, String> {
    let explicit = std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from);
    if explicit.as_ref().is_some_and(|path| previous(path)) {
        return Err("claude-home-previous-layout".into());
    }
    if std::env::var_os("LANE_RUN_DIR").is_some() {
        return explicit.filter(|path| path.is_absolute()).ok_or_else(|| {
            "claude-home-mismatch: boxed form requires explicit configuration".into()
        });
    }
    let runs = std::env::var_os("LANE_RUNS_ROOT").map(PathBuf::from);
    if option_value(arguments, b'r').is_none()
        && runs.as_ref().is_none_or(|path| !path.is_absolute())
    {
        return Err("runs_root_required: LANE_RUNS_ROOT must be an absolute path".into());
    }
    let home = registered_home(runs.as_deref(), arguments)?;
    if explicit.is_some_and(|path| path != home) {
        return Err("claude-home-mismatch".into());
    }
    if !std::fs::symlink_metadata(&home).is_ok_and(|metadata| metadata.is_dir()) {
        return Err("claude-home-absent".into());
    }
    Ok(home)
}

fn registered_home(runs: Option<&Path>, arguments: &[OsString]) -> Result<PathBuf, String> {
    let owner = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("claude-home-unregistered-loop")?;
    let resume_root = option_value(arguments, b'd').and_then(|value| Path::new(value).parent());
    let selected = resume_root
        .or(runs)
        .filter(|path| path.is_absolute())
        .ok_or("claude-home-unregistered-loop")?;
    let path = loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), &owner);
    let registry = loop_home::load_registry(&path)
        .map_err(|error| format!("claude-home-unregistered-loop: {}", error.message()))?;
    let rows = registry
        .rows(&owner)
        .into_iter()
        .filter(|row| {
            let default = owner.join(".var/loops").join(&row.name).join("runs");
            registry.runs_root(&row.name).unwrap_or(&default) == selected
        })
        .collect::<Vec<_>>();
    let row = match rows.as_slice() {
        [] => return Err("claude-home-unregistered-loop".into()),
        [row] => row,
        _ => return Err("claude-home-ambiguous-loop".into()),
    };
    if let Some(root) = runs.filter(|root| resume_root.is_some() && *root != selected) {
        return Err(format!(
            "claude-home-runs-root-mismatch: LANE_RUNS_ROOT={} run_root={}",
            root.display(),
            selected.display()
        ));
    }
    Ok(crate::signin_home::claude_home(&owner, &row.name))
}
