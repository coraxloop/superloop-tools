//! Descriptor-based metadata retained by preactivation migration backups.
use super::journal::{MailError, Result};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd as _;

/// Linux bounds one extended attribute and its name list at 64 KiB.
const ATTRIBUTE_BYTES: usize = 65_536;
pub(super) type Attributes = Vec<(Vec<u8>, Vec<u8>)>;

#[allow(unsafe_code)]
pub(super) fn read(file: &File) -> Result<Attributes> {
    let mut names = vec![0_u8; ATTRIBUTE_BYTES];
    // The opened descriptor and writable name buffer remain live for the syscall.
    let count =
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    let count =
        usize::try_from(count).map_err(|_| MailError::Io(std::io::Error::last_os_error()))?;
    names.truncate(count);
    let mut result = Vec::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let key = CString::new(name)
            .map_err(|_| MailError::Invalid("invalid-directory: migration attribute name"))?;
        let mut bytes = vec![0_u8; ATTRIBUTE_BYTES];
        // The terminated key and writable value buffer cover the supplied lengths.
        let length = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                key.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        let length =
            usize::try_from(length).map_err(|_| MailError::Io(std::io::Error::last_os_error()))?;
        bytes.truncate(length);
        result.push((name.to_vec(), bytes));
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(result)
}

#[allow(unsafe_code)]
pub(super) fn restore(file: &File, expected: &Attributes) -> Result<()> {
    for (name, _) in read(file)? {
        if !expected.iter().any(|(wanted, _)| *wanted == name) {
            let key = CString::new(name)
                .map_err(|_| MailError::Invalid("invalid-directory: migration attribute name"))?;
            // The file and terminated key remain live; only the staged file changes.
            if unsafe { libc::fremovexattr(file.as_raw_fd(), key.as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    for (name, value) in expected {
        let key = CString::new(name.as_slice())
            .map_err(|_| MailError::Invalid("invalid-directory: migration attribute name"))?;
        // The file, terminated key and immutable value remain live for the syscall.
        if unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                key.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if read(file)? != *expected {
        return Err(MailError::Invalid(
            "unsafe-storage: restored migration attributes differ",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn read_child(parent: &File, name: &std::ffi::OsStr) -> Result<Attributes> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut path = format!("/proc/self/fd/{}/", parent.as_raw_fd()).into_bytes();
    path.extend(name.as_bytes());
    let path = CString::new(path)
        .map_err(|_| MailError::Invalid("invalid-directory: migration child name"))?;
    let mut names = vec![0_u8; ATTRIBUTE_BYTES];
    // The ancestor descriptor is held; llistxattr does not follow the final symlink.
    let count = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    let count =
        usize::try_from(count).map_err(|_| MailError::Io(std::io::Error::last_os_error()))?;
    names.truncate(count);
    let mut result = Vec::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let key = CString::new(name)
            .map_err(|_| MailError::Invalid("invalid-directory: migration attribute name"))?;
        let mut bytes = vec![0_u8; ATTRIBUTE_BYTES];
        // The pinned ancestor path, terminated key and value buffer remain live.
        let count = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                key.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        let count =
            usize::try_from(count).map_err(|_| MailError::Io(std::io::Error::last_os_error()))?;
        bytes.truncate(count);
        result.push((name.to_vec(), bytes));
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(result)
}
