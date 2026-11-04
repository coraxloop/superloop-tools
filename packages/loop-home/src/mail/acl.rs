//! Linux descriptor ACLs keep service access scoped to one configuration file.

use super::journal::{MailError, Result};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;

const XATTR: &[u8] = b"system.posix_acl_access\0";
const UNDEFINED: u32 = u32::MAX;

#[allow(unsafe_code)]
fn read_attribute(file: &impl std::os::fd::AsRawFd, attribute: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; 4096];
    // The descriptor remains live; both slices cover the supplied lengths.
    let mut length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            attribute.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
        // O_PATH permits search-only ancestor inspection. Linux rejects fgetxattr
        // on it; the live proc descriptor link resolves the pinned inode instead.
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| MailError::Invalid("descriptor spelling"))?;
        length = unsafe {
            libc::getxattr(
                path.as_ptr(),
                attribute.as_ptr().cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
    }
    let length = usize::try_from(length).map_err(|_| MailError::Io(io::Error::last_os_error()))?;
    bytes.truncate(length);
    Ok(bytes)
}

fn read(file: &impl std::os::fd::AsRawFd) -> Result<Vec<u8>> {
    read_attribute(file, XATTR)
}

fn entries(owner: u16, service: u32, access: u16) -> Vec<u8> {
    let mut bytes = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1_u16, owner, UNDEFINED),
        (2, access, service),
        (4, 0, UNDEFINED),
        (16, access, UNDEFINED),
        (32, 0, UNDEFINED),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permissions.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

/// Verify the exact file-only read or directory-only search grant, including mask.
///
/// # Errors
/// Refuses an absent grant, widened access, peers, or an ineffective ACL mask.
pub fn verify(file: &File, service: u32, directory: bool) -> Result<()> {
    let expected = entries(
        if directory { 7 } else { 6 },
        service,
        if directory { 1 } else { 4 },
    );
    if read(file)? != expected {
        return Err(MailError::Invalid(
            "unsafe-storage: exact service ACL required",
        ));
    }
    Ok(())
}

/// Install a named ACL without sharing private siblings or future files.
///
/// # Errors
/// Refuses an unsupported filesystem or insufficient ownership privileges.
#[allow(unsafe_code)]
pub fn install(file: &File, service: u32, directory: bool) -> Result<()> {
    let bytes = entries(
        if directory { 7 } else { 6 },
        service,
        if directory { 1 } else { 4 },
    );
    // The file descriptor and both buffers remain live for the syscall.
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            XATTR.as_ptr().cast(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    file.sync_all()?;
    verify(file, service, directory)
}

/// Reject extended grants on a service-owned transport directory.
///
/// # Errors
/// Refuses peer ACLs; the actor-specific owning group is the sole reader grant.
pub(super) fn transport(file: &File) -> Result<()> {
    match read(file) {
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => Ok(()),
        Ok(_) => Err(MailError::Invalid(
            "unsafe-storage: transport directory has extra ACL grants",
        )),
        Err(error) => Err(error),
    }
}

pub(super) fn outbox(file: &File, service: u32) -> Result<()> {
    if read(file)? != entries(7, service, 7) {
        return Err(MailError::Invalid(
            "unsafe-storage: outbox service ACL or peer grant",
        ));
    }
    Ok(())
}
/// Preserve a named read/search grant's mask across a nominal mode correction.
///
/// The descriptor's owner supplies the grant; service activation separately
/// verifies its mapped identity. Copying raw ACL IDs preserves namespace mapping.
pub fn preserved_mode(file: &impl std::os::fd::AsRawFd, nominal: u32) -> u32 {
    let Ok(bytes) = read(file) else {
        return nominal;
    };
    if bytes.len() != 44 {
        return nominal;
    }
    let service = u32::from_le_bytes(bytes[16..20].try_into().unwrap_or_default());
    let access = u16::from_le_bytes(bytes[14..16].try_into().unwrap_or_default());
    if ![1, 4, 5].contains(&access) {
        return nominal;
    }
    let mut expected = entries((nominal >> 6 & 7) as u16, service, access);
    expected[22..24].copy_from_slice(&((nominal >> 3 & 7) as u16).to_le_bytes());
    expected[38..40].copy_from_slice(&((nominal & 7) as u16).to_le_bytes());
    let mut observed = bytes;
    observed[6..8].copy_from_slice(&expected[6..8]);
    observed[38..40].copy_from_slice(&expected[38..40]);
    observed[30..32].copy_from_slice(&access.to_le_bytes());
    if observed != expected {
        return nominal;
    }
    nominal | (u32::from(access) << 3)
}

/// Grant only service search on private ancestors or read on the one mail file.
///
/// # Errors
/// Refuses unrelated named grants or widened base permissions instead of erasing them.
pub fn ensure_private(file: &File, service: u32, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let access = if directory { 1_u16 } else { 4_u16 };
    let expected = entries(if directory { 7 } else { 6 }, service, access);
    match read(file) {
        Ok(mut observed) => {
            if observed.len() != expected.len() {
                return Err(MailError::Invalid(
                    "unsafe-storage: extra private ACL grants",
                ));
            }
            observed[30..32].copy_from_slice(&access.to_le_bytes());
            if observed != expected {
                return Err(MailError::Invalid(
                    "unsafe-storage: private ACL identity or permissions",
                ));
            }
        }
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => {
            if file.metadata()?.mode() & 0o777 != if directory { 0o700 } else { 0o600 } {
                return Err(MailError::Invalid(
                    "unsafe-storage: private configuration mode",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    install(file, service, directory)
}

/// Retain an existing owner-authorized service read grant on atomic replacement.
///
/// # Errors
/// Refuses unexpected ACLs instead of widening a replacement's readers.
pub fn copy_private_read(previous: &File, replacement: &File) -> Result<()> {
    match read(previous) {
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => Ok(()),
        Err(error) => Err(error),
        Ok(bytes) => {
            if preserved_mode(previous, 0o600) != 0o640 {
                return Err(MailError::Invalid("unsafe-storage: allocation read ACL"));
            }
            write_acl(replacement, XATTR, &bytes)
        }
    }
}

#[allow(unsafe_code)]
fn write_acl(file: &File, attribute: &[u8], bytes: &[u8]) -> Result<()> {
    // Both buffers are live and attribute is a NUL-terminated constant.
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            attribute.as_ptr().cast(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    file.sync_all()?;
    Ok(())
}

pub(super) fn grant_outbox(file: &File, service: u32) -> Result<()> {
    write_acl(file, XATTR, &entries(7, service, 7))
}
pub(super) fn grant_draft_default(file: &File, service: u32) -> Result<()> {
    let attribute = b"system.posix_acl_default\0";
    let expected = entries(7, service, 4);
    match read_attribute(file, attribute) {
        Ok(bytes) if bytes == expected => Ok(()),
        Ok(_) => Err(MailError::Invalid(
            "unsafe-storage: draft default ACL differs",
        )),
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => {
            write_acl(file, attribute, &expected)
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn grant_ancestor(file: &File, service: u32, access: u16, nominal: u32) -> Result<()> {
    let mut bytes = entries((nominal >> 6 & 7) as u16, service, access);
    bytes[22..24].copy_from_slice(&((nominal >> 3 & 7) as u16).to_le_bytes());
    bytes[38..40].copy_from_slice(&((nominal & 7) as u16).to_le_bytes());
    bytes[30..32].copy_from_slice(&(access | ((nominal >> 3 & 7) as u16)).to_le_bytes());
    match read(file) {
        Ok(mut previous) => {
            if previous == bytes {
                return Ok(());
            }
            if previous.len() != bytes.len() {
                return Err(MailError::Invalid(
                    "unsafe-storage: unrelated ancestor ACL grants",
                ));
            }
            previous[30..32].copy_from_slice(&bytes[30..32]);
            if previous != bytes {
                return Err(MailError::Invalid("unsafe-storage: ancestor ACL differs"));
            }
        }
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => {}
        Err(error) => return Err(error),
    }
    write_acl(file, XATTR, &bytes)
}

pub(crate) fn root_mode(path: &std::path::Path, nominal: u32) -> u32 {
    super::io::search_directory(path).map_or(nominal, |file| preserved_mode(&file, nominal))
}

pub(super) fn base_mode(file: &File) -> Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    let mode = file.metadata()?.mode() & 0o777;
    match read(file) {
        Err(MailError::Io(error)) if error.raw_os_error() == Some(libc::ENODATA) => Ok(mode),
        Err(error) => Err(error),
        Ok(bytes) if bytes.len() == 44 => {
            let group = u16::from_le_bytes(bytes[22..24].try_into().unwrap_or_default());
            Ok((mode & !0o070) | (u32::from(group) << 3))
        }
        Ok(_) => Err(MailError::Invalid(
            "unsafe-storage: unrelated ancestor ACL grants",
        )),
    }
}

/// Remove inherited and named grants before terminal service custody.
#[allow(unsafe_code)]
pub(super) fn remove_grants(file: &File) -> Result<()> {
    for attribute in [XATTR, b"system.posix_acl_default\0".as_slice()] {
        // The live descriptor and NUL-terminated attribute survive the syscall.
        if unsafe { libc::fremovexattr(file.as_raw_fd(), attribute.as_ptr().cast()) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENODATA) {
                return Err(error.into());
            }
        }
    }
    Ok(())
}
