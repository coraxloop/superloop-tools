//! Preserve lifetime history across legacy rollback without restoring stale bindings.
//!
//! The coordinator parks the post-cutover namespace before restoring legacy paths;
//! a later attempt must restore this exact history before allocating another name.
use super::{
    io,
    journal::{MailError, Result, digest},
    migration_tree,
};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Implementation bound for a whole-estate history projection, not a mail-name bound.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Witness {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    digest: String,
    directory: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    path: PathBuf,
    witness: Option<Witness>,
    parked: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    restoring: bool,
    restored: bool,
    slots: Vec<Slot>,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn custody(state: &File) -> Result<Flock<File>> {
    let info = state.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw()
        || info.mode() & 0o7777 != 0o700
        || !info.is_dir()
    {
        return Err(invalid(
            "unsafe-storage: history vault requires private custody",
        ));
    }
    Flock::lock(
        io::child(state, Path::new("."), true)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|_| invalid("changed-source: history vault busy"))
}
fn witness(file: &File) -> Result<Witness> {
    let info = file.metadata()?;
    let directory = info.is_dir();
    if !directory && (!info.is_file() || info.nlink() != 1) {
        return Err(invalid("unsafe-storage: history object type"));
    }
    let content = if directory {
        migration_tree::fingerprint(file)?
    } else {
        digest(&super::migration_control::bounded(
            file,
            MAX_MANIFEST_BYTES,
        )?)
    };
    Ok(Witness {
        device: info.dev(),
        inode: info.ino(),
        uid: info.uid(),
        gid: info.gid(),
        mode: info.mode(),
        digest: content,
        directory,
    })
}
fn optional(parent: &File, name: &Path) -> Result<Option<File>> {
    match io::child(parent, name, false) {
        Ok(file) => Ok(Some(file)),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn parent(path: &Path) -> Result<(File, &std::ffi::OsStr)> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid(
            "unsafe-storage: history path is not canonical absolute",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid("unsafe-storage: history path has no leaf"))?;
    Ok((
        io::absolute(
            path.parent()
                .ok_or_else(|| invalid("unsafe-storage: history parent absent"))?,
            true,
        )?,
        name,
    ))
}
fn save(state: &File, record: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| invalid("invalid-directory: history manifest encoding"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid(
            "invalid-directory: history manifest exceeds implementation bound",
        ));
    }
    let name = ".history-next";
    let mut file = File::from(openat2(
        state,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    let info = file.metadata()?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != nix::unistd::Uid::effective().as_raw()
        || info.mode() & 0o7777 != 0o600
    {
        return Err(invalid("unsafe-storage: history scratch custody"));
    }
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    renameat2(state, name, state, "history.json", RenameFlags::empty())?;
    state.sync_all()?;
    Ok(())
}
fn load(state: &File) -> Result<Manifest> {
    let file = io::child(state, Path::new("history.json"), false)?;
    let info = file.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw() || info.mode() & 0o7777 != 0o600 {
        return Err(invalid("unsafe-storage: history manifest custody"));
    }
    let record: Manifest = serde_json::from_slice(&super::migration_control::bounded(
        &file,
        MAX_MANIFEST_BYTES,
    )?)
    .map_err(|_| invalid("invalid-directory: history manifest schema"))?;
    if record.version != 1 {
        return Err(invalid("invalid-directory: history manifest version"));
    }
    Ok(record)
}
/// Freeze every post-cutover binding and namespace before any legacy restoration.
/// Missing paths are explicit witnesses; a source cannot overlap the vault or another source.
///
/// # Errors
/// Refuses replacement, aliasing, unsafe custody and incomplete existing history.
pub fn prepare(state: &File, paths: &[PathBuf]) -> Result<()> {
    let _lock = custody(state)?;
    if optional(state, Path::new("history.json"))?.is_some() {
        let record = load(state)?;
        if record.slots.iter().map(|slot| &slot.path).ne(paths.iter()) {
            return Err(invalid("changed-source: history inventory differs"));
        }
        return Ok(());
    }
    if !io::names(state)?.is_empty() {
        return Err(invalid("unsafe-storage: unrecorded history vault"));
    }
    let mut slots = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for path in paths {
        let (parent, name) = parent(path)?;
        if migration_tree::is_ancestor(state, &parent)? {
            return Err(invalid("unsafe-storage: history source inside vault"));
        }
        for prior in paths {
            if path != prior && path.starts_with(prior) {
                return Err(invalid("unsafe-storage: overlapping history sources"));
            }
        }
        let observed = optional(&parent, Path::new(name))?;
        let observed = if let Some(file) = observed {
            if file.metadata()?.is_dir() && migration_tree::is_ancestor(&file, state)? {
                return Err(invalid("unsafe-storage: vault inside history source"));
            }
            let value = witness(&file)?;
            if !seen.insert((value.device, value.inode)) {
                return Err(invalid("unsafe-storage: aliased history source"));
            }
            Some(value)
        } else {
            None
        };
        slots.push(Slot {
            path: path.clone(),
            witness: observed,
            parked: false,
        });
    }
    save(
        state,
        &Manifest {
            version: 1,
            restoring: false,
            restored: false,
            slots,
        },
    )
}
fn check(file: &File, expected: &Witness) -> Result<()> {
    if witness(file)? != *expected {
        return Err(invalid(
            "changed-source: lifetime history differs from its witness",
        ));
    }
    Ok(())
}
/// Read the exact namespace projection retained by this vault.
///
/// # Errors
/// Requires the original protected manifest and private custody.
pub fn paths(state: &File) -> Result<Vec<PathBuf>> {
    let _lock = custody(state)?;
    Ok(load(state)?
        .slots
        .into_iter()
        .map(|slot| slot.path)
        .collect())
}
/// Move frozen lifetime history into the private vault without copying or deleting it.
///
/// # Errors
/// Refuses collisions and changed history; a surviving named inode resumes the move.
pub fn park(state: &File) -> Result<()> {
    transfer(state, false, |_| Ok(()))
}
/// Verify the vault after legacy paths and processes are restored.
///
/// # Errors
/// Missing, modified or unexpectedly restored lifetime records block rollback completion.
pub fn verify_parked(state: &File) -> Result<()> {
    let _lock = custody(state)?;
    let record = load(state)?;
    if record.restoring || record.restored {
        return Err(invalid(
            "changed-source: lifetime vault is no longer parked",
        ));
    }
    for (index, slot) in record.slots.iter().enumerate() {
        let name = format!("object-{index:08}");
        let archived = optional(state, Path::new(&name))?;
        match (&slot.witness, archived) {
            (Some(expected), Some(file)) if slot.parked => check(&file, expected)?,
            (None, None) => (),
            _ => {
                return Err(invalid(
                    "changed-source: retained lifetime history is incomplete",
                ));
            }
        }
    }
    Ok(())
}
/// Restore retained history only into absent original paths, before new birth.
///
/// # Errors
/// Legacy paths must be reconciled first. No existing configuration is overwritten.
pub fn restore(state: &File) -> Result<()> {
    transfer(state, true, |_| Ok(()))
}
fn transfer(state: &File, restore: bool, mut stop: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let _lock = custody(state)?;
    let mut record = load(state)?;
    if !restore && (record.restoring || record.restored) {
        return Err(invalid(
            "changed-source: history restoration already begins",
        ));
    }
    if restore && !record.restoring {
        record.restoring = true;
        save(state, &record)?;
        stop("restore-intent")?;
    }
    for index in 0..record.slots.len() {
        let slot = &record.slots[index];
        let (source, name) = parent(&slot.path)?;
        let saved = format!("object-{index:08}");
        let original = optional(&source, Path::new(name))?;
        let archived = optional(state, Path::new(&saved))?;
        let Some(expected) = &slot.witness else {
            if original.is_some() || archived.is_some() {
                return Err(invalid(
                    "changed-source: absent history path acquired an object",
                ));
            }
            continue;
        };
        match (&original, &archived) {
            (Some(original), None) => {
                check(original, expected)?;
                if !restore {
                    renameat2(
                        &source,
                        name,
                        state,
                        saved.as_str(),
                        RenameFlags::RENAME_NOREPLACE,
                    )?;
                    source.sync_all()?;
                    state.sync_all()?;
                    stop("park-rename")?;
                }
            }
            (None, Some(archived)) => {
                check(archived, expected)?;
                if restore {
                    renameat2(
                        state,
                        saved.as_str(),
                        &source,
                        name,
                        RenameFlags::RENAME_NOREPLACE,
                    )?;
                    state.sync_all()?;
                    source.sync_all()?;
                    stop("restore-rename")?;
                }
            }
            _ => {
                return Err(invalid(
                    "changed-source: history needs exactly one matching inode",
                ));
            }
        }
        record.slots[index].parked = !restore;
        save(state, &record)?;
        stop("history-recorded")?;
    }
    if restore {
        record.restored = true;
        save(state, &record)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    fn fixture(tag: &str) -> (PathBuf, File, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("migration-history-{tag}-{}", std::process::id()));
        fs::create_dir(&root).expect("root");
        let vault = root.join("vault");
        fs::create_dir(&vault).expect("vault");
        fs::set_permissions(&vault, fs::Permissions::from_mode(0o700)).expect("custody");
        let history = root.join("workers");
        fs::create_dir(&history).expect("history");
        fs::write(history.join("receipt"), b"retired name, reused uid").expect("receipt");
        let file = File::open(vault).expect("vault descriptor");
        (root, file, history)
    }
    /// ´claim:loophome:migration-history-retains-lifetime-names-through-interrupted-rollback´
    /// ´test:unit:migration-history-retains-lifetime-names-through-interrupted-rollback´
    #[test]
    fn migration_history_retains_lifetime_names_through_interrupted_rollback() {
        for point in ["park-rename", "history-recorded"] {
            let (root, state, path) = fixture(point);
            prepare(&state, std::slice::from_ref(&path)).expect("freeze");
            assert!(
                transfer(&state, false, |at| if at == point {
                    Err(invalid("fixture interruption"))
                } else {
                    Ok(())
                })
                .is_err()
            );
            park(&state).expect("recover park");
            assert!(!path.exists());
            fs::create_dir(&path).expect("legacy layout");
            assert!(restore(&state).is_err());
            fs::remove_dir(&path).expect("reconciled legacy layout");
            restore(&state).expect("restore lifetime history");
            assert_eq!(
                fs::read(path.join("receipt")).expect("receipt"),
                b"retired name, reused uid"
            );
            fs::remove_dir_all(root).expect("cleanup");
        }
        for point in ["restore-intent", "restore-rename", "history-recorded"] {
            let (root, state, path) = fixture(point);
            prepare(&state, std::slice::from_ref(&path)).expect("freeze");
            park(&state).expect("park");
            assert!(
                transfer(&state, true, |at| if at == point {
                    Err(invalid("fixture interruption"))
                } else {
                    Ok(())
                })
                .is_err()
            );
            restore(&state).expect("resume restore");
            assert_eq!(
                fs::read(path.join("receipt")).expect("receipt"),
                b"retired name, reused uid"
            );
            fs::remove_dir_all(root).expect("cleanup");
        }
    }
    /// ´claim:loophome:migration-history-refuses-forged-replacement-and-aliasing´
    /// ´test:unit:migration-history-refuses-forged-replacement-and-aliasing´
    #[test]
    fn migration_history_refuses_forged_replacement_and_aliasing() {
        let (root, state, path) = fixture("changed");
        assert!(prepare(&state, &[path.clone(), path.clone()]).is_err());
        prepare(&state, std::slice::from_ref(&path)).expect("freeze");
        fs::write(path.join("receipt"), b"different history").expect("tamper");
        assert!(park(&state).is_err());
        assert!(path.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
