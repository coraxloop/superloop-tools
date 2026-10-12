//! Descriptor-pinned metadata changes below directories the namespace owner controls.

use std::io::Read as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::Path;

use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{Gid, Uid, fchownat};

use crate::error::LaneError;

fn open_component(
    parent: &OwnedFd,
    name: &Path,
    directory: bool,
    readable: bool,
) -> Result<OwnedFd, LaneError> {
    let mut flags = (if readable {
        OFlag::O_RDONLY
    } else {
        OFlag::O_PATH
    }) | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW;
    if directory {
        flags |= OFlag::O_DIRECTORY;
    }
    let fd = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(flags)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("protected-path", format!("{}: {error}", name.display())))?;
    let stat = fstat(&fd).map_err(|error| LaneError::input("protected-path", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFLNK {
        return Err(LaneError::input(
            "protected-path",
            "symbolic link is refused",
        ));
    }
    Ok(fd)
}

/// Open an inode through protected parents without following any symbolic link.
///
/// # Errors
///
/// Refuses a link, a path outside the anchor, or a parent writable by another identity.
fn open_protected_with(
    anchor: &Path,
    path: &Path,
    owner_uid: u32,
    readable: bool,
) -> Result<OwnedFd, LaneError> {
    let relative = path.strip_prefix(anchor).map_err(|_| {
        LaneError::input(
            "protected-path",
            format!("{} is outside {}", path.display(), anchor.display()),
        )
    })?;
    if !anchor.is_absolute() || relative.as_os_str().is_empty() {
        return Err(LaneError::input(
            "protected-path",
            "anchor or target is not a child path",
        ));
    }
    let mut parent = if crate::home::private_is_active() {
        crate::home::pin_parent(anchor, owner_uid)?
    } else {
        let root = open(
            "/",
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|error| LaneError::input("protected-path", error.to_string()))?;
        let anchor_relative = anchor
            .strip_prefix("/")
            .map_err(|_| LaneError::input("protected-path", "anchor is not absolute"))?;
        open_component(&root, anchor_relative, true, false)?
    };
    let mut parts = relative.components().peekable();
    let mut reached = anchor.to_path_buf();
    while let Some(part) = parts.next() {
        let stat = fstat(&parent)
            .map_err(|error| LaneError::input("protected-path", error.to_string()))?;
        if stat.st_uid != owner_uid || stat.st_mode & 0o022 != 0 {
            return Err(LaneError::input(
                "protected-path",
                format!(
                    "{} has uid {} mode {:04o}; expected owner uid {owner_uid} and no group or other write",
                    reached.display(),
                    stat.st_uid,
                    stat.st_mode & 0o7777
                ),
            ));
        }
        let directory = parts.peek().is_some();
        parent = open_component(
            &parent,
            Path::new(part.as_os_str()),
            directory,
            readable && !directory,
        )?;
        reached.push(part.as_os_str());
    }
    Ok(parent)
}

pub fn open_protected(anchor: &Path, path: &Path, owner_uid: u32) -> Result<OwnedFd, LaneError> {
    open_protected_with(anchor, path, owner_uid, false)
}

/// Check an executable with the same verifier used for settings replacements.
///
/// # Errors
///
/// Refuses a path whose parent or inode the loop identity could replace.
pub fn owner_executable(path: &Path, owner_uid: u32) -> Result<(), LaneError> {
    loop_home::workers_settings::owner_executable(path, owner_uid).map_err(|error| {
        LaneError::input(
            "owner-program",
            error
                .message()
                .strip_prefix("owner-program: ")
                .unwrap_or_else(|| error.message()),
        )
    })
}

/// Turn a path into one child argument without changing its spelling.
///
/// # Errors
///
/// Refuses a path that cannot be represented by the child's string argument grammar.
pub fn path_word(path: &Path, kind: &'static str) -> Result<String, LaneError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| LaneError::input(kind, format!("{} is not UTF-8", path.display())))
}

/// Check the exact spelling that an owner-executed child receives.
///
/// # Errors
///
/// Refuses a non-UTF-8 or replaceable executable path.
pub fn owner_executable_word(path: &Path, owner_uid: u32) -> Result<String, LaneError> {
    let word = path_word(path, "owner-program")?;
    owner_executable(Path::new(&word), owner_uid)?;
    Ok(word)
}

/// Read a bounded, owner-owned regular file through protected parent descriptors.
///
/// # Errors
///
/// Refuses a linked, foreign, oversized or differently moded file.
pub fn read_private(
    anchor: &Path,
    path: &Path,
    owner_uid: u32,
    mode: u32,
    limit: usize,
) -> Result<Vec<u8>, LaneError> {
    let fd = open_protected_with(anchor, path, owner_uid, true)?;
    let stat = fstat(&fd).map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner_uid
        || stat.st_mode & 0o7777 != mode
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(LaneError::input(
            "protected-file",
            format!(
                "{} differs from owner uid {owner_uid}, mode {mode:04o}, or {limit} byte bound",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LaneError::input("protected-file", format!("{}: {error}", path.display()))
        })?;
    if bytes.len() > limit {
        return Err(LaneError::input(
            "protected-file",
            format!("{} exceeds {limit} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

/// Read a bounded file of a specific owner, group, and mode below an anchor.
///
/// # Errors
///
/// Refuses a changed component, link, foreign inode, mode, or excess bytes.
pub fn read_checked(
    anchor: &Path,
    path: &Path,
    parent_owner: u32,
    identity: (u32, u32, u32),
    limit: usize,
) -> Result<Vec<u8>, LaneError> {
    let fd = open_protected_with(anchor, path, parent_owner, true)?;
    let stat = fstat(&fd).map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777) != identity
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(LaneError::input(
            "protected-file",
            format!(
                "{} differs from its pinned owner, mode or byte limit",
                path.display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if bytes.len() > limit {
        return Err(LaneError::input(
            "protected-file",
            "read exceeds byte limit",
        ));
    }
    Ok(bytes)
}

/// Read an optional private file through a held parent descriptor.
///
/// # Errors
///
/// Refuses an unsafe parent, linked file, foreign owner, mode, or size.
pub fn read_private_optional(
    anchor: &Path,
    path: &Path,
    owner_uid: u32,
    mode: u32,
    limit: usize,
) -> Result<Option<Vec<u8>>, LaneError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| LaneError::input("protected-file", "optional file has no parent"))?;
    let parent = open_protected_with(anchor, parent_path, owner_uid, false)?;
    let parent_stat =
        fstat(&parent).map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if SFlag::from_bits_truncate(parent_stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || parent_stat.st_uid != owner_uid
        || parent_stat.st_mode & 0o022 != 0
    {
        return Err(LaneError::input(
            "protected-file",
            "optional file parent is unsafe",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::input("protected-file", "optional file has no name"))?;
    let fd = match openat2(
        &parent,
        Path::new(name),
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "protected-file",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let stat = fstat(&fd).map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner_uid
        || stat.st_mode & 0o7777 != mode
        || usize::try_from(stat.st_size)
            .ok()
            .is_none_or(|size| size > limit)
    {
        return Err(LaneError::input(
            "protected-file",
            format!("{} differs from owner, mode, or byte bound", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("protected-file", error.to_string()))?;
    if bytes.len() > limit {
        return Err(LaneError::input(
            "protected-file",
            "optional file exceeds byte bound",
        ));
    }
    Ok(Some(bytes))
}

/// Set ownership and mode on the opened inode, never on a later pathname lookup.
///
/// # Errors
///
/// Refuses an unprotected parent or a failed metadata change.
#[allow(unsafe_code)]
pub fn set_metadata(
    anchor: &Path,
    path: &Path,
    owner_uid: u32,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), LaneError> {
    let fd = open_protected(anchor, path, owner_uid)?;
    fchownat(
        &fd,
        "",
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        AtFlags::AT_EMPTY_PATH,
    )
    .map_err(|error| LaneError::operation("inode-owner", format!("{}: {error}", path.display())))?;
    // SAFETY: Linux fchmodat2 with AT_EMPTY_PATH changes the held inode.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            fd.as_raw_fd(),
            c"".as_ptr(),
            mode as libc::mode_t,
            libc::AT_EMPTY_PATH,
        )
    };
    if result == -1 {
        return Err(LaneError::operation(
            "inode-mode",
            format!("{}: {}", path.display(), std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{owner_executable, owner_executable_word, read_private};
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    /// ´test:unit:owner-executable-word-refuses-an-invalid-byte-path´
    #[test]
    fn owner_executable_word_refuses_an_invalid_byte_path() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let name = std::ffi::OsString::from_vec(b"lane-\xff".to_vec());
        let path = fixture.path().join(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("program mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        owner_executable(&path, owner).expect("raw path is owner controlled");
        let error = owner_executable_word(&path, owner).expect_err("invalid byte refuses vector");
        assert_eq!(error.kind, "owner-program");
    }

    /// ´test:unit:helper-request-refuses-a-replaced-container-program-after-readiness´
    #[test]
    fn helper_request_refuses_a_replaced_container_program_after_readiness() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("protected fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let path = fixture.path().join("podman");
        fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("program mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        owner_executable(&path, owner).expect("helper readiness sees protected program");
        fs::remove_file(&path).expect("replace after readiness");
        symlink("/usr/bin/true", &path).expect("replacement link");
        let refusal = owner_executable(&path, owner).expect_err("helper request rechecks");
        assert_eq!(refusal.kind, "owner-program");
    }

    /// ´test:unit:private-protected-read-retains-bound-home-after-path-replacement´
    #[test]
    fn private_protected_read_retains_bound_home_after_path_replacement() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let file = home.join("private.txt");
        fs::write(&file, b"held inode").expect("private file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("private file mode");
        let inherited = fs::File::open(&home).expect("home descriptor");
        let guard =
            crate::home::activate_private_home(&home, &inherited, owner).expect("bound home");
        fs::rename(&home, fixture.path().join("retired")).expect("retire home pathname");
        fs::create_dir(&home).expect("replacement home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        assert_eq!(
            read_private(&home, &file, owner, 0o600, 32).expect("read bound inode"),
            b"held inode"
        );
        drop(guard);
    }

    /// ´test:unit:protected-observation-refuses-links-wrong-mode-and-excess-bytes´
    #[test]
    fn protected_observation_refuses_links_wrong_mode_and_excess_bytes() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let path = fixture.path().join(".observed-R.txt");
        fs::write(&path, b"mode=observing run=R enforcing=false\n").expect("observation");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
        assert!(read_private(fixture.path(), &path, owner, 0o600, 32_768).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("loop-writable mode");
        assert_eq!(
            read_private(fixture.path(), &path, owner, 0o600, 32_768)
                .expect_err("writable observation refused")
                .kind,
            "protected-file"
        );
        fs::remove_file(&path).expect("replace record");
        symlink(fixture.path().join("foreign"), &path).expect("linked record");
        assert_eq!(
            read_private(fixture.path(), &path, owner, 0o600, 32_768)
                .expect_err("link refused")
                .kind,
            "protected-path"
        );
        fs::remove_file(&path).expect("remove link");
        fs::write(&path, vec![b'a'; 32_769]).expect("large record");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
        assert_eq!(
            read_private(fixture.path(), &path, owner, 0o600, 32_768)
                .expect_err("large record refused")
                .kind,
            "protected-file"
        );
    }
}
