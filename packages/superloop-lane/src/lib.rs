#![doc = include_str!("../README.md")]

pub mod build;
pub mod container_helper;
pub mod credential;
pub mod door;
pub mod door_node;
pub mod door_sign_in;
pub mod driver;
pub mod error;
mod fixture_exec;
pub mod gateway_dispatch;
pub mod home;
pub mod install;
pub mod install_door;
pub mod install_private;
pub mod launch;
mod pinned;
pub mod plan;
pub mod prepare;
pub mod repair;
pub mod requests;
pub mod routes;
pub mod settings;
pub mod sign_in;
pub mod signin_home;
pub mod vendor_net;
pub mod worker_launch;

use std::path::{Path, PathBuf};

use error::LaneError;
use plan::Plan;
use settings::Settings;

/// Match the entry's portable run-name grammar.
#[must_use]
pub fn valid_run_name(run: &str) -> bool {
    let bytes = run.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte))
}

/// Upper bound for a socket address through a directory descriptor, including
/// the widest possible descriptor number.
#[must_use]
pub(crate) fn socket_address_length(name: &str) -> usize {
    format!("/proc/self/fd/{}/{}", i32::MAX, name).len()
}

/// A socket name whose address, checks, metadata changes and removal all use
/// one verified directory descriptor.
pub struct SocketSlot {
    directory: std::os::fd::OwnedFd,
    name: std::ffi::OsString,
    address: PathBuf,
}

impl SocketSlot {
    /// Reuse a verified directory for another socket name.
    ///
    /// # Errors
    ///
    /// Refuses a failed descriptor duplication or invalid name.
    pub fn beneath(
        directory: &std::os::fd::OwnedFd,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Self> {
        let copy = nix::unistd::dup(directory)
            .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        Self::new(copy, name)
    }
    /// Pin a socket directory through the active private anchor, or through
    /// the owner's protected host walk before crossing the namespace.
    ///
    /// # Errors
    ///
    /// Refuses an unsafe parent or invalid socket name.
    pub fn pinned(path: &Path, owner: u32) -> Result<Self, LaneError> {
        let parent = path
            .parent()
            .ok_or_else(|| LaneError::input("socket-path", "socket parent is absent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| LaneError::input("socket-path", "socket name is absent"))?;
        let directory = home::pin_parent(parent, owner)?;
        Self::new(directory, name)
            .map_err(|error| LaneError::input("socket-path", error.to_string()))
    }

    /// Build a short address beneath a directory verified by the caller.
    ///
    /// # Errors
    ///
    /// Refuses an invalid name or an address beyond the Linux socket limit.
    pub fn new(directory: std::os::fd::OwnedFd, name: &std::ffi::OsStr) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;
        if name.as_bytes().is_empty()
            || name.as_bytes().contains(&b'/')
            || name.as_bytes() == b"."
            || name.as_bytes() == b".."
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket name is invalid",
            ));
        }
        let address = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
        let length = address.as_os_str().as_bytes().len();
        if length > 107 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("socket-path: address length {length} exceeds 107"),
            ));
        }
        Ok(Self {
            directory,
            name: name.to_owned(),
            address,
        })
    }

    /// Descriptor-relative address for bind or connect.
    #[must_use]
    pub fn address(&self) -> &Path {
        &self.address
    }

    /// Descriptor number for the private child handoff.
    #[must_use]
    pub fn directory_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.directory)
    }

    pub(crate) const fn directory(&self) -> &std::os::fd::OwnedFd {
        &self.directory
    }

    /// Metadata of the named entry, without following a link.
    ///
    /// # Errors
    ///
    /// Reports an unreadable directory entry.
    pub fn metadata(&self) -> std::io::Result<Option<nix::sys::stat::FileStat>> {
        use nix::fcntl::AtFlags;
        match nix::sys::stat::fstatat(
            &self.directory,
            self.name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => Ok(Some(stat)),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
        }
    }

    /// Remove the named socket from the held directory.
    ///
    /// # Errors
    ///
    /// Reports a failed unlink.
    pub fn remove(&self) -> std::io::Result<()> {
        nix::unistd::unlinkat(
            &self.directory,
            self.name.as_os_str(),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))
    }

    /// Finalize ownership and mode relative to the held directory.
    ///
    /// # Errors
    ///
    /// Reports a failed owner or mode update.
    pub fn set_owner_mode(&self, uid: u32, gid: u32, mode: u32) -> std::io::Result<()> {
        use nix::fcntl::AtFlags;
        nix::unistd::fchownat(
            &self.directory,
            self.name.as_os_str(),
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            self.name.as_os_str(),
        ))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        #[allow(unsafe_code)]
        // SAFETY: the descriptor and NUL-terminated name are held for this call.
        let result = unsafe {
            libc::fchmodat(
                std::os::fd::AsRawFd::as_raw_fd(&self.directory),
                name.as_ptr(),
                mode,
                0,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Load settings and the entry's registry row to plan one run.
///
/// # Errors
///
/// Refuses an invalid name, unsafe settings path, setting, or registry row.
pub fn load_plan(
    home: &Path,
    loop_name: &str,
    run: &str,
    caller: (u32, u32),
) -> Result<(Plan, Settings), LaneError> {
    load_plan_with_door(home, loop_name, run, caller, true)
}

/// Load a protected run's paths without consulting a current door generation.
///
/// # Errors
///
/// Refuses invalid settings, registry fields, or other plan inputs.
pub(crate) fn load_plan_for_record(
    home: &Path,
    loop_name: &str,
    run: &str,
    caller: (u32, u32),
) -> Result<(Plan, Settings), LaneError> {
    load_plan_with_door(home, loop_name, run, caller, false)
}

fn load_plan_with_door(
    home: &Path,
    loop_name: &str,
    run: &str,
    caller: (u32, u32),
    include_door: bool,
) -> Result<(Plan, Settings), LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    if !valid_run_name(run) {
        return Err(LaneError::input("run-name", format!("bad run name: {run}")));
    }
    let settings_path = home
        .join(".config/loops")
        .join(loop_name)
        .join("workers.toml");
    let settings = Settings::read(&settings_path)?;
    settings.validate_grant(home, loop_name)?;
    let registry_path =
        loop_home::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
    let registry_file = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let row = registry_file
        .row(loop_name, home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let registry: serde_json::Value = serde_json::from_str(
        &row.to_registry_json_with_runs_root(registry_file.runs_root(loop_name)),
    )
    .map_err(|error| LaneError::input("registry-row", error.to_string()))?;
    let worker_block = home::read_allocations(home)?
        .require(loop_name)
        .map_err(|error| LaneError::input("allocations", error.message()))?;
    let plan = if include_door {
        Plan::build(
            home,
            loop_name,
            run,
            &settings,
            &registry,
            worker_block,
            caller,
        )?
    } else {
        Plan::build_for_record(
            home,
            loop_name,
            run,
            &settings,
            &registry,
            worker_block,
            caller,
        )?
    };
    Ok((plan, settings))
}

/// Read the calling identity's absolute home path.
///
/// # Errors
///
/// Refuses an absent or nonabsolute home.
pub fn caller_home() -> Result<PathBuf, LaneError> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| LaneError::input("home", "HOME is absent"))?;
    let path = PathBuf::from(home);
    if !path.is_absolute() {
        return Err(LaneError::input("home", "HOME must be absolute"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../tests/support/registry_entry.rs"]
mod registry_fixture;
