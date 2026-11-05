//! Opened-object operations shared by service resolution and provisioning.
use super::journal::{MailError, Result};
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

pub(super) fn child(parent: &File, name: &Path, directory: bool) -> Result<File> {
    Ok(File::from(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(
                OFlag::O_RDONLY
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NONBLOCK
                    | if directory {
                        OFlag::O_DIRECTORY
                    } else {
                        OFlag::empty()
                    },
            )
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
pub(super) fn absolute(path: &Path, directory: bool) -> Result<File> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| MailError::Invalid("unsafe-storage: absolute path required"))?;
    child(&File::open("/")?, relative, directory)
}
pub(super) fn search_directory(path: &Path) -> Result<File> {
    let relative = path
        .strip_prefix("/")
        .map_err(|_| MailError::Invalid("unsafe-storage: absolute path required"))?;
    Ok(File::from(openat2(
        &File::open("/")?,
        relative,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
pub(super) fn names(directory: &File) -> Result<Vec<OsString>> {
    let descriptor = child(directory, Path::new("."), true)?;
    let mut stream = nix::dir::Dir::from_fd(descriptor.into())?;
    let mut names = Vec::new();
    for entry in stream.iter() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            use std::os::unix::ffi::OsStrExt as _;
            names.push(OsStr::from_bytes(name).to_owned());
        }
    }
    Ok(names)
}
pub(super) fn bounded(file: &File, limit: u64) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(MailError::Invalid(
            "invalid-file: single-link regular file required",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(MailError::Invalid("oversize: bounded metadata"));
    }
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(MailError::Invalid("changed-source: opened file changed"));
    }
    Ok(bytes)
}
