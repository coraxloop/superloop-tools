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

pub fn walk(path: &Path, directory: bool, protected: bool) -> Result<File> {
    walk_owner(path, directory, protected, false)
}

const fn ancestor_owner(owner: u32, effective: u32, root_only: bool) -> bool {
    owner == 0 || (!root_only && owner == effective)
}

fn walk_owner(path: &Path, directory: bool, protected: bool, root_only: bool) -> Result<File> {
    if !crate::record::path(path, true) {
        return Err("unsafe-path");
    }
    let mut current =
        File::open("/").map_err(|error| crate::process::io_failure("path-root", error))?;
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
            let trusted_owner =
                ancestor_owner(meta.uid(), nix::unistd::geteuid().as_raw(), root_only);
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
            openat(&current, Path::new(part), flags, Mode::empty())
                .map_err(|error| crate::process::io_failure("path-open", error))?,
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

pub fn repository(path: &Path) -> Result<File> {
    let dir = walk(path, true, true)?;
    let meta = dir.metadata().map_err(|_| "repository-custody")?;
    if (meta.uid() != 0 && meta.uid() != nix::unistd::geteuid().as_raw())
        || meta.mode() & 0o7022 != 0
        || meta.nlink() == 0
    {
        return Err("repository-custody");
    }
    Ok(dir)
}

pub fn protected_read(path: &Path, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    read_file(walk(path, false, true)?, limit, immutable)
}

pub fn parameters(path: &Path) -> Result<Vec<u8>> {
    parameter_bytes(path, false)
}

// Only the separately tagged fixture schema consumes this public-data class.
pub fn fixture_parameters(path: &Path) -> Result<Vec<u8>> {
    parameter_bytes(path, true)
}

fn parameter_bytes(path: &Path, public_case: bool) -> Result<Vec<u8>> {
    let mut file = walk(path, false, true)?;
    let metadata = file.metadata().map_err(|_| "file-metadata")?;
    if public_case && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o444 {
        // A DynamicUser may read this class, but must not control its path.
        // Re-walk with root-only ancestors and read only that retained file.
        file = walk_owner(path, false, true, true)?;
    }
    read_with_custody(file, crate::record::RECORD_LIMIT as u64, true, public_case).map_err(
        |class| {
            if class == "file-custody" {
                "parameter-custody"
            } else {
                class
            }
        },
    )
}

pub fn read(path: &Path, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    read_file(open(path, false)?, limit, immutable)
}

pub fn read_file(file: File, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    read_with_custody(file, limit, immutable, false)
}

const fn immutable_owner_mode(owner: u32, mode: u32, effective: u32, public_case: bool) -> bool {
    (mode & 0o7777 == 0o400 && owner == effective)
        || (public_case && owner == 0 && mode & 0o7777 == 0o444)
}

fn read_with_custody(
    mut file: File,
    limit: u64,
    immutable: bool,
    public_case: bool,
) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|_| "file-metadata")?;
    if !before.is_file()
        || (immutable && before.nlink() != 1)
        || before.len() > limit
        || (immutable
            && !immutable_owner_mode(
                before.uid(),
                before.mode(),
                nix::unistd::geteuid().as_raw(),
                public_case,
            ))
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
    publish_held(&walk(root, true, true)?, name, bytes)
}

pub fn publish_held(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
    if !crate::record::name(name) || name.starts_with('.') || name.ends_with(".partial") {
        return Err("receipt-name");
    }
    let meta = dir.metadata().map_err(|_| "receipt-root")?;
    if !meta.is_dir()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o700
    {
        return Err("receipt-root-custody");
    }
    let temporary = format!(".{name}.partial");
    let fd = openat(
        dir,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| crate::process::io_failure("receipt-exclusive-create", error))?;
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
            dir,
            temporary.as_str(),
            dir,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(|_| "receipt-no-replace")?;
        dir.sync_all().map_err(|_| "receipt-directory-sync")
    })();
    if result.is_err() {
        let _ignored = unlinkat(dir, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:public-case-custody-is-a-distinct-class´
    #[test]
    fn public_case_custody_is_a_distinct_class() {
        // Root ownership cannot be manufactured by an ordinary host uid. Test
        // its exact predicate with explicit metadata; exercise the same reader
        // and real protected walk below. DynamicUser delivery is rehearsal-only.
        assert!(ancestor_owner(0, 1234, true));
        assert!(!ancestor_owner(1234, 1234, true));
        assert!(ancestor_owner(1234, 1234, false));
        assert!(!ancestor_owner(2345, 1234, false));
        for public in [false, true] {
            for owner in [0, 1234, 2345] {
                for mode in [0o400, 0o444, 0o440, 0o644, 0o4444] {
                    let expected =
                        (owner == 1234 && mode == 0o400) || (public && owner == 0 && mode == 0o444);
                    assert_eq!(immutable_owner_mode(owner, mode, 1234, public), expected);
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("case.json");
        std::fs::write(&file, b"public metadata").unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o400)).unwrap();
        assert_eq!(fixture_parameters(&file).unwrap(), b"public metadata");
        std::fs::hard_link(&file, dir.path().join("alias")).unwrap();
        assert_eq!(fixture_parameters(&file).unwrap_err(), "parameter-custody");
        std::fs::remove_file(dir.path().join("alias")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("link")).unwrap();
        assert_eq!(
            fixture_parameters(&dir.path().join("link/case.json")).unwrap_err(),
            "path-open"
        );
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            fixture_parameters(&file).unwrap_err(),
            "directory-ancestor-custody"
        );
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, vec![b' '; crate::record::RECORD_LIMIT + 1]).unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o400)).unwrap();
        assert_eq!(fixture_parameters(&file).unwrap_err(), "parameter-custody");
        assert_eq!(
            fixture_parameters(dir.path()).unwrap_err(),
            "parameter-custody"
        );
    }
}
