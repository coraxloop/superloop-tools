//! Exact, non-following tree snapshots protect worker-home relocation rollback.
use super::{
    io,
    journal::{MailError, Result, digest},
    migration_metadata,
};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, mkdirat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize)]
struct Entry {
    path: Vec<Vec<u8>>,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: (i64, i64),
    attributes: migration_metadata::Attributes,
    content: Option<String>,
    link: Option<Vec<u8>>,
    hard_link: Option<Vec<Vec<u8>>>,
}
/// A durable backup proof; the source inode is distinct from its content digest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub source_device: u64,
    pub source_inode: u64,
    pub digest: String,
    pub copied: bool,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
fn file_hash(file: &mut File) -> Result<String> {
    let before = file.metadata()?;
    let mut block = [0_u8; 16384];
    let mut hash = Sha256::new();
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        hash.update(&block[..count]);
    }
    if !unchanged(&before, &file.metadata()?) {
        return Err(invalid("changed-source: migration tree file changed"));
    }
    Ok(hash
        .finalize()
        .iter()
        .flat_map(|byte| {
            let hex = b"0123456789abcdef";
            [
                char::from(hex[usize::from(byte >> 4)]),
                char::from(hex[usize::from(byte & 15)]),
            ]
        })
        .collect())
}
fn row(
    path: Vec<Vec<u8>>,
    info: &fs::Metadata,
    attributes: migration_metadata::Attributes,
) -> Entry {
    Entry {
        path,
        uid: info.uid(),
        gid: info.gid(),
        mode: info.mode(),
        mtime: (info.mtime(), info.mtime_nsec()),
        attributes,
        content: None,
        link: None,
        hard_link: None,
    }
}
type HardLinks = std::collections::BTreeMap<(u64, u64), Vec<Vec<u8>>>;
fn walk(
    directory: &File,
    path: &[Vec<u8>],
    rows: &mut Vec<Entry>,
    hard_links: &mut HardLinks,
) -> Result<()> {
    let before = directory.metadata()?;
    rows.push(row(
        path.to_vec(),
        &before,
        migration_metadata::read(directory)?,
    ));
    let mut names = io::names(directory)?;
    names.sort();
    for name in names {
        let pinned = Path::new("/proc/self/fd")
            .join(directory.as_raw_fd().to_string())
            .join(&name);
        let info = fs::symlink_metadata(&pinned)?;
        let mut relative = path.to_vec();
        relative.push(name.as_bytes().to_vec());
        if info.is_dir() {
            let child = io::child(directory, Path::new(&name), true)?;
            if (child.metadata()?.dev(), child.metadata()?.ino()) != (info.dev(), info.ino()) {
                return Err(invalid("changed-source: migration tree directory replaced"));
            }
            walk(&child, &relative, rows, hard_links)?;
        } else {
            let mut entry = row(
                relative,
                &info,
                migration_metadata::read_child(directory, &name)?,
            );
            if info.is_file() {
                let mut file = io::child(directory, Path::new(&name), false)?;
                if (file.metadata()?.dev(), file.metadata()?.ino()) != (info.dev(), info.ino()) {
                    return Err(invalid("changed-source: migration tree file replaced"));
                }
                entry.content = Some(file_hash(&mut file)?);
                entry.hard_link = Some(
                    hard_links
                        .entry((info.dev(), info.ino()))
                        .or_insert_with(|| entry.path.clone())
                        .clone(),
                );
            } else if info.file_type().is_symlink() {
                entry.link = Some(fs::read_link(&pinned)?.as_os_str().as_bytes().to_vec());
            }
            rows.push(entry);
        }
        if !unchanged(&info, &fs::symlink_metadata(&pinned)?) {
            return Err(invalid("changed-source: migration tree entry changed"));
        }
    }
    if !unchanged(&before, &directory.metadata()?) {
        return Err(invalid("changed-source: migration tree changed"));
    }
    Ok(())
}
/// Fingerprint names, opaque bytes, link targets, ownership, modes, times and attributes.
///
/// # Errors
/// Refuses changed or unreadable entries; never follows a descendant symbolic link.
pub fn fingerprint(root: &File) -> Result<String> {
    let mut rows = Vec::new();
    walk(root, &[], &mut rows, &mut HardLinks::new())?;
    Ok(digest(&serde_json::to_vec(&rows).map_err(|_| {
        invalid("invalid-directory: migration tree serialization")
    })?))
}
fn save(state: &File, proof: &Proof) -> Result<()> {
    let mut file = File::from(openat2(
        state,
        ".tree-next",
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
        return Err(invalid("unsafe-storage: tree proof scratch custody"));
    }
    file.set_len(0)?;
    serde_json::to_writer(&mut file, proof)
        .map_err(|_| invalid("invalid-directory: tree proof serialization"))?;
    file.flush()?;
    file.sync_all()?;
    nix::fcntl::renameat(state, ".tree-next", state, "tree.json")?;
    state.sync_all()?;
    Ok(())
}
fn load(state: &File) -> Result<Proof> {
    let file = io::child(state, Path::new("tree.json"), false)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != nix::unistd::Uid::effective().as_raw()
        || info.mode() & 0o7777 != 0o600
    {
        return Err(invalid("unsafe-storage: tree proof custody"));
    }
    serde_json::from_reader(file).map_err(|_| invalid("invalid-directory: tree proof schema"))
}
fn sync_tree(directory: &File) -> Result<()> {
    for name in io::names(directory)? {
        let path = Path::new("/proc/self/fd")
            .join(directory.as_raw_fd().to_string())
            .join(&name);
        let info = fs::symlink_metadata(path)?;
        if info.is_dir() {
            sync_tree(&io::child(directory, Path::new(&name), true)?)?;
        } else if info.is_file() {
            io::child(directory, Path::new(&name), false)?.sync_all()?;
        }
    }
    directory.sync_all()?;
    Ok(())
}
pub(super) fn is_ancestor(ancestor: &File, descendant: &File) -> Result<bool> {
    let wanted = ancestor.metadata()?;
    let wanted = (wanted.dev(), wanted.ino());
    let mut current = descendant.try_clone()?;
    loop {
        let info = current.metadata()?;
        let identity = (info.dev(), info.ino());
        if identity == wanted {
            return Ok(true);
        }
        let parent = File::from(openat2(
            &current,
            "..",
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS),
        )?);
        let info = parent.metadata()?;
        if (info.dev(), info.ino()) == identity {
            return Ok(false);
        }
        current = parent;
    }
}
/// Create an independent archive copy before a legacy execution tree can move.
///
/// # Errors
/// Refuses conflicting state, changed source or a copy that loses any recorded attribute.
pub fn backup(source: &File, state: &File) -> Result<Proof> {
    if is_ancestor(source, state)? || is_ancestor(state, source)? {
        return Err(invalid("unsafe-storage: backup and source trees overlap"));
    }
    let info = state.metadata()?;
    if info.uid() != nix::unistd::Uid::effective().as_raw() || info.mode() & 0o7777 != 0o700 {
        return Err(invalid("unsafe-storage: tree backup state custody"));
    }
    let _lock = Flock::lock(
        io::child(state, Path::new("."), true)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|_| invalid("changed-source: tree backup busy"))?;
    if io::names(state)?.iter().any(|name| {
        !["tree.json", ".tree-next", "tree"]
            .iter()
            .any(|expected| name == expected)
    }) {
        return Err(invalid("unsafe-storage: tree backup has unrelated entries"));
    }
    let source_info = source.metadata()?;
    let wanted = fingerprint(source)?;
    let mut proof = match load(state) {
        Ok(proof) => {
            if proof.source_device != source_info.dev()
                || proof.source_inode != source_info.ino()
                || proof.digest != wanted
            {
                return Err(invalid("changed-source: tree backup source differs"));
            }
            proof
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let proof = Proof {
                source_device: source_info.dev(),
                source_inode: source_info.ino(),
                digest: wanted,
                copied: false,
            };
            save(state, &proof)?;
            proof
        }
        Err(error) => return Err(error),
    };
    match mkdirat(state, "tree", Mode::from_bits_truncate(0o700)) {
        Ok(()) => state.sync_all()?,
        Err(nix::errno::Errno::EEXIST) => (),
        Err(error) => return Err(error.into()),
    }
    let target = io::child(state, Path::new("tree"), true)?;
    if !proof.copied {
        let parent = std::process::id();
        let status = Command::new("/usr/bin/cp")
            .env_clear()
            .env("LC_ALL", "C")
            .args(["--archive", "--reflink=auto", "--"])
            .arg(format!("/proc/{parent}/fd/{}/.", source.as_raw_fd()))
            .arg(format!("/proc/{parent}/fd/{}/.", target.as_raw_fd()))
            .status()?;
        if !status.success() {
            return Err(invalid("io-failure: independent legacy tree backup failed"));
        }
        sync_tree(&target)?;
        state.sync_all()?;
    }
    if fingerprint(source)? != proof.digest {
        return Err(invalid("changed-source: legacy tree changed during backup"));
    }
    if fingerprint(&target)? != proof.digest {
        return Err(invalid("unsafe-storage: legacy tree backup is not exact"));
    }
    proof.copied = true;
    save(state, &proof)?;
    Ok(proof)
}
/// Re-measure the retained backup independently of the relocated live tree.
///
/// # Errors
/// Refuses missing, unfinished or modified backup evidence.
pub fn verify_backup(state: &File) -> Result<Proof> {
    let proof = load(state)?;
    if !proof.copied || fingerprint(&io::child(state, Path::new("tree"), true)?)? != proof.digest {
        return Err(invalid(
            "unsafe-storage: legacy tree backup is not verified",
        ));
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    /// ´claim:loophome:migration-tree-backup-preserves-links-and-refuses-changed-history´
    /// ´test:unit:migration-tree-backup-preserves-links-and-refuses-changed-history´
    #[test]
    fn migration_tree_backup_preserves_links_and_refuses_changed_history() {
        let root = std::env::temp_dir().join(format!("migration-tree-{}", std::process::id()));
        fs::create_dir(&root).expect("fixture");
        let source = root.join("source");
        let state = root.join("state");
        fs::create_dir(&source).expect("source");
        fs::create_dir(&state).expect("state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("custody");
        fs::write(source.join("body"), [0, 1, 255]).expect("opaque bytes");
        fs::hard_link(source.join("body"), source.join("hard-link")).expect("hard link");
        symlink("../outside", source.join("link")).expect("link");
        fs::write(root.join("outside"), b"not followed").expect("outside");
        let source = File::open(&source).expect("source descriptor");
        let state_fd = File::open(&state).expect("state descriptor");
        let proof = backup(&source, &state_fd).expect("copy");
        assert!(proof.copied);
        assert_eq!(
            fs::metadata(state.join("tree/body"))
                .expect("body identity")
                .ino(),
            fs::metadata(state.join("tree/hard-link"))
                .expect("hard-link identity")
                .ino()
        );
        verify_backup(&state_fd).expect("independent proof");
        backup(&source, &state_fd).expect("idempotent backup");
        fs::write(root.join("outside"), b"different outside bytes").expect("outside mutation");
        verify_backup(&state_fd).expect("link target was never followed");
        fs::write(state.join("tree/body"), b"different").expect("tampered backup");
        assert!(verify_backup(&state_fd).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
