//! Child-only confinement: no new filesystem write opens and no socket creation.
use super::{Result, measure::Admission, policy::ArtifactRole, require};
use crate::receipt;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::Command;

pub(super) const ABI_FLOOR: i32 = 5;
// ABI 5 handles every filesystem right through IOCTL_DEV, including REFER and
// TRUNCATE. Never mask this policy down for an older kernel.
const HANDLED: u64 = (1 << 16) - 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const EXECUTE: u64 = 1;
#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}
#[repr(C, packed)]
struct Beneath {
    allowed_access: u64,
    parent_fd: i32,
}
pub(super) struct Confinement {
    ruleset: OwnedFd,
}
impl Confinement {
    pub fn prepare(admission: &Admission) -> Result<Self> {
        Self::require_abi(abi()?)?;
        let ruleset = create()?;
        let key_directory = admission
            .policy()
            .host_key
            .parent()
            .ok_or("sealer-key-directory")?;
        let key = receipt::sealed_directory(key_directory).map_err(|_| "sealer-key-directory")?;
        add(&ruleset, &key, READ_FILE | READ_DIR)?;
        for artifact in admission
            .artifacts()
            .iter()
            .filter(|a| matches!(a.role, ArtifactRole::Sealer | ArtifactRole::Library))
        {
            artifact.unchanged()?;
            add(&ruleset, &artifact.file, READ_FILE | EXECUTE)?;
        }
        Ok(Self { ruleset })
    }
    const fn require_abi(version: i32) -> Result<()> {
        require(version >= ABI_FLOOR, "sealer-landlock-abi")
    }
    #[allow(unsafe_code)]
    pub fn configure(&self, command: &mut Command) -> Result<()> {
        let ruleset = self
            .ruleset
            .try_clone()
            .map_err(|_| "sealer-landlock-duplicate")?;
        let filter = socket_filter()?;
        // SAFETY: the child callback only uses owned descriptors, immutable
        // arrays and Linux syscalls. The descriptor stays live until exec/drop.
        unsafe {
            command.pre_exec(move || {
                if nix::libc::syscall(
                    nix::libc::SYS_landlock_restrict_self,
                    ruleset.as_raw_fd(),
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let program = nix::libc::sock_fprog {
                    len: u16::try_from(filter.len()).unwrap_or(0),
                    filter: filter.as_ptr().cast_mut(),
                };
                if nix::libc::prctl(nix::libc::PR_SET_SECCOMP, 2, &raw const program) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}
#[allow(unsafe_code)]
fn abi() -> Result<i32> {
    // SAFETY: VERSION is a scalar query; no pointer is dereferenced.
    let version = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            std::ptr::null::<Ruleset>(),
            0,
            1,
        )
    };
    i32::try_from(version)
        .ok()
        .filter(|v| *v >= 0)
        .ok_or("sealer-landlock-unavailable")
}
#[allow(unsafe_code)]
fn create() -> Result<OwnedFd> {
    let rules = Ruleset {
        handled_access_fs: HANDLED,
    };
    // SAFETY: one correctly sized stack structure; a successful fd is newly owned.
    let fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            &raw const rules,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    require(fd >= 0, "sealer-landlock-create")?;
    let fd =
        unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).map_err(|_| "sealer-landlock-create")?) };
    nix::fcntl::fcntl(
        &fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map_err(|_| "sealer-landlock-create")?;
    Ok(fd)
}
#[allow(unsafe_code)]
fn add(rules: &OwnedFd, path: &File, access: u64) -> Result<()> {
    let beneath = Beneath {
        allowed_access: access,
        parent_fd: path.as_raw_fd(),
    };
    // SAFETY: packed kernel ABI structure has the declared size and live fd.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_add_rule,
            rules.as_raw_fd(),
            1,
            &raw const beneath,
            0,
        )
    };
    require(result == 0, "sealer-landlock-rule")
}
const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> nix::libc::sock_filter {
    nix::libc::sock_filter { code, jt, jf, k }
}
fn socket_filter() -> Result<Vec<nix::libc::sock_filter>> {
    let architecture = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else if cfg!(target_arch = "aarch64") {
        0xc000_00b7
    } else {
        return Err("sealer-seccomp-architecture");
    };
    // Validate seccomp_data.arch before interpreting syscall numbers. Reject x32
    // numbers too; a second syscall ABI must not bypass the native-number checks.
    let mut filter = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, architecture),
        instruction(0x06, 0, 0, 0x8000_0000),
        instruction(0x20, 0, 0, 0),
        instruction(0x45, 0, 1, 0x4000_0000),
        instruction(0x06, 0, 0, 0x8000_0000),
    ];
    // io_uring can create sockets without SYS_socket; deny that alternate route
    // as well. No ring descriptor is admitted across this child exec.
    let mut denied = vec![
        nix::libc::SYS_socket,
        nix::libc::SYS_socketpair,
        nix::libc::SYS_io_uring_setup,
        nix::libc::SYS_io_uring_enter,
        nix::libc::SYS_io_uring_register,
        // Landlock does not mediate these metadata changes. A root-owned
        // receipt must not become writable to an unconfined second account.
        nix::libc::SYS_fchmod,
        nix::libc::SYS_fchmodat,
        nix::libc::SYS_fchmodat2,
        nix::libc::SYS_fchown,
        nix::libc::SYS_fchownat,
        nix::libc::SYS_utimensat,
        nix::libc::SYS_setxattr,
        nix::libc::SYS_lsetxattr,
        nix::libc::SYS_fsetxattr,
        nix::libc::SYS_removexattr,
        nix::libc::SYS_lremovexattr,
        nix::libc::SYS_fremovexattr,
    ];
    #[cfg(target_arch = "x86_64")]
    denied.extend([
        nix::libc::SYS_chmod,
        nix::libc::SYS_chown,
        nix::libc::SYS_lchown,
        nix::libc::SYS_utime,
        nix::libc::SYS_utimes,
        nix::libc::SYS_futimesat,
    ]);
    for syscall in denied {
        filter.push(instruction(
            0x15,
            0,
            1,
            u32::try_from(syscall).map_err(|_| "sealer-seccomp-architecture")?,
        ));
        filter.push(instruction(0x06, 0, 0, 0x0005_0001));
    }
    filter.push(instruction(0x06, 0, 0, 0x7fff_0000));
    Ok(filter)
}
#[cfg(test)]
mod tests {
    use super::*;
    /// ´test:unit:sealer-landlock-floor-never-degrades´
    #[test]
    fn sealer_landlock_floor_never_degrades() {
        for version in [-1, 0, 1, 2, 3, 4] {
            assert_eq!(
                Confinement::require_abi(version),
                Err("sealer-landlock-abi")
            );
        }
        assert_eq!(Confinement::require_abi(5), Ok(()));
        assert_eq!(Confinement::require_abi(10), Ok(()));
        assert_eq!(HANDLED & (1 << 14), 1 << 14); // TRUNCATE
        assert_eq!(HANDLED & (1 << 15), 1 << 15); // IOCTL_DEV
    }
}
