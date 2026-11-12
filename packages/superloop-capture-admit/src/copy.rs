use crate::{Result, manifest::Manifest};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

pub fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC).bits())
        .open(path)?)
}
pub fn pinned(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
pub fn child(parent: &File, path: &Path, dir: bool) -> Result<File> {
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let fd = openat(
        parent,
        path,
        flags
            | if dir {
                OFlag::O_DIRECTORY
            } else {
                OFlag::empty()
            },
        Mode::empty(),
    )?;
    Ok(File::from(fd))
}
fn source_file(root: &File, path: &Path) -> Result<File> {
    let mut dir = root.try_clone()?;
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        let file = child(&dir, Path::new(part.as_os_str()), parts.peek().is_some())?;
        if parts.peek().is_none() {
            if !file.metadata()?.is_file() {
                return Err("source-not-regular".into());
            }
            return Ok(file);
        }
        dir = file;
    }
    Err("source-empty-path".into())
}
pub fn verified(source: &Path, destination: &Path, manifest: &Manifest) -> Result<()> {
    let root = directory(source)?;
    for entry in &manifest.entries {
        let mut input = source_file(&root, &entry.path)?;
        let target = destination.join(&entry.path);
        fs::create_dir_all(target.parent().ok_or("missing-parent")?)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)?;
        let mut hash = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = vec![0_u8; 65536].into_boxed_slice();
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(u64::try_from(n)?)
                .ok_or("source-size-overflow")?;
            if count > entry.size {
                return Err("size-mismatch".into());
            }
            output.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
        }
        if count != entry.size {
            return Err("size-mismatch".into());
        }
        if crate::manifest::hex(&hash.finalize()) != entry.digest {
            return Err("digest-mismatch".into());
        }
        output.set_permissions(Permissions::from_mode(0o644))?;
        output.sync_all()?;
    }
    let mut paths = manifest.entries.iter().map(|e| e.path.clone()).collect();
    walk(&root, Path::new(""), &mut paths)?;
    if !paths.is_empty() {
        return Err("missing-source-entry-after-copy".into());
    }
    seal(destination)
}
fn walk(dir: &File, prefix: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(pinned(dir))? {
        let entry = entry?;
        let relative = prefix.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if !paths.iter().any(|p| p.starts_with(&relative)) {
                return Err("unlisted-source-directory".into());
            }
            walk(
                &child(dir, Path::new(&entry.file_name()), true)?,
                &relative,
                paths,
            )?;
        } else if !kind.is_file() || !paths.remove(&relative) {
            return Err("unlisted-or-nonregular-source-entry".into());
        }
    }
    Ok(())
}
fn seal(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            seal(&entry.path())?;
        }
    }
    fs::set_permissions(path, Permissions::from_mode(0o755))?;
    directory(path)?.sync_all()?;
    Ok(())
}
