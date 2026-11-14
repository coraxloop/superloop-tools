//! Pinned regular-file reads and exclusive receipt publication.
use crate::record::Result;
use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::fs::{File, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path};

pub fn open(path: &Path, directory: bool) -> Result<File> {
    walk(path, directory, false)
}

fn walk(path: &Path, directory: bool, protected: bool) -> Result<File> {
    if !crate::record::path(path, true) {
        return Err("unsafe-path");
    }
    let mut current = File::open("/").map_err(|_| "path-root")?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    for (index, part) in parts.iter().enumerate() {
        if protected {
            let meta = current.metadata().map_err(|_| "directory-metadata")?;
            let trusted_owner = meta.uid() == 0 || meta.uid() == nix::unistd::geteuid().as_raw();
            if !trusted_owner || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0) {
                return Err("directory-ancestor-custody");
            }
        }
        let flags = OFlag::O_RDONLY
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK
            | if directory || index + 1 < parts.len() {
                OFlag::O_DIRECTORY
            } else {
                OFlag::empty()
            };
        current = File::from(
            openat(&current, Path::new(part), flags, Mode::empty()).map_err(|_| "path-open")?,
        );
    }
    Ok(current)
}

/// Private directories may have filesystem-dependent link counts. A live
/// directory needs a nonzero count, not the regular-file single-link rule.
pub fn sealed_directory(path: &Path) -> Result<File> {
    let dir = walk(path, true, true)?;
    let meta = dir.metadata().map_err(|_| "directory-metadata")?;
    if meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
        || meta.nlink() == 0
    {
        return Err("sealed-directory-custody");
    }
    Ok(dir)
}

pub fn parameters(path: &Path) -> Result<Vec<u8>> {
    let file = walk(path, false, true)?;
    read_file(file, crate::record::RECORD_LIMIT as u64, true).map_err(|class| {
        if class == "file-custody" {
            "parameter-custody"
        } else {
            class
        }
    })
}

pub fn read(path: &Path, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    read_file(open(path, false)?, limit, immutable)
}

pub fn read_file(mut file: File, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|_| "file-metadata")?;
    if !before.is_file()
        || (immutable && before.nlink() != 1)
        || before.len() > limit
        || (immutable
            && (before.mode() & 0o7777 != 0o400 || before.uid() != nix::unistd::geteuid().as_raw()))
    {
        return Err("file-custody");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file-read")?;
    let after = file.metadata().map_err(|_| "file-metadata")?;
    if bytes.len() as u64 > limit
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("file-changed");
    }
    Ok(bytes)
}

pub fn publish(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let dir = open(root, true)?;
    let meta = dir.metadata().map_err(|_| "receipt-root")?;
    if meta.uid() != nix::unistd::geteuid().as_raw() || meta.mode() & 0o777 != 0o700 {
        return Err("receipt-root-custody");
    }
    let temporary = format!(".{name}.partial");
    let fd = openat(
        &dir,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| "receipt-exclusive-create")?;
    let mut file = File::from(fd);
    let result = (|| {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| "receipt-mode")?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|_| "receipt-write")?;
        file.sync_all().map_err(|_| "receipt-sync")?;
        file.set_permissions(Permissions::from_mode(0o400))
            .map_err(|_| "receipt-mode")?;
        file.sync_all().map_err(|_| "receipt-sync")?;
        renameat2(
            &dir,
            temporary.as_str(),
            &dir,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(|_| "receipt-no-replace")?;
        dir.sync_all().map_err(|_| "receipt-directory-sync")
    })();
    if result.is_err() {
        let _ignored = unlinkat(&dir, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}
