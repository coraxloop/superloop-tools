//! Child-only confinement: no new filesystem write opens and no socket creation.
use super::{Result, measure::Admission, policy::ArtifactRole, require};
use crate::receipt;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

pub(super) const ABI_FLOOR: i32 = 6;
// ABI 5 handles every filesystem right through IOCTL_DEV, including REFER and
// TRUNCATE. Never mask this policy down for an older kernel.
const HANDLED: u64 = (1 << 16) - 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const EXECUTE: u64 = 1;
#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
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
        let (directory, key) = key_handles(&admission.policy().host_key, admission.owner())?;
        add(&ruleset, &directory, READ_DIR)?;
        add(&ruleset, &key, READ_FILE)?;
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
fn key_handles(path: &std::path::Path, owner: u32) -> Result<(File, File)> {
    let parent = path.parent().ok_or("sealer-key-directory")?;
    let directory = receipt::walk(parent, true, true).map_err(|_| "sealer-key-directory")?;
    let meta = directory.metadata().map_err(|_| "sealer-key-directory")?;
    require(
        meta.is_dir() && meta.uid() == owner && meta.mode() & 0o7022 == 0 && meta.nlink() != 0,
        "sealer-key-directory",
    )?;
    // O_PATH retains identity without reading a key byte. Open beneath the held
    // parent, and never follow a leaf link. Only this file receives READ_FILE.
    let key = File::from(
        nix::fcntl::openat(
            &directory,
            path.file_name().ok_or("sealer-key-file")?,
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|_| "sealer-key-file")?,
    );
    key_custody(&key, owner)?;
    Ok((directory, key))
}
fn key_custody(key: &File, owner: u32) -> Result<()> {
    let meta = key.metadata().map_err(|_| "sealer-key-file")?;
    require(
        meta.is_file() && meta.uid() == owner && meta.mode() & 0o7777 == 0o400 && meta.nlink() == 1,
        "sealer-key-file",
    )
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
        handled_access_net: 0,
        scoped: 3, // ABI 6: abstract UNIX sockets and signals stay within the domain.
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
    // prlimit64(pid=0) is needed by libc for the child's own limits. Every
    // nonzero pid is refused, including its explicit own pid. Inspect both
    // halves so a noncanonical argument cannot bypass the filter.
    filter.extend([
        instruction(
            0x15,
            0,
            6,
            u32::try_from(nix::libc::SYS_prlimit64).map_err(|_| "sealer-seccomp-architecture")?,
        ),
        instruction(0x20, 0, 0, 16),
        instruction(0x15, 0, 3, 0),
        instruction(0x20, 0, 0, 20),
        instruction(0x15, 0, 1, 0),
        instruction(0x06, 0, 0, 0x7fff_0000),
        instruction(0x06, 0, 0, 0x0005_0001),
    ]);
    for syscall in denied_syscalls() {
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
fn denied_syscalls() -> Vec<nix::libc::c_long> {
    // io_uring can create sockets without SYS_socket; deny that alternate route
    // as well. No ring descriptor is admitted across this child exec.
    let mut denied = vec![
        // No kernel keyring or SysV/POSIX message-queue authority is needed.
        nix::libc::SYS_setpgid,
        nix::libc::SYS_setsid,
        nix::libc::SYS_keyctl,
        nix::libc::SYS_add_key,
        nix::libc::SYS_request_key,
        nix::libc::SYS_semget,
        nix::libc::SYS_semop,
        nix::libc::SYS_semtimedop,
        nix::libc::SYS_semctl,
        nix::libc::SYS_shmget,
        nix::libc::SYS_shmat,
        nix::libc::SYS_shmdt,
        nix::libc::SYS_shmctl,
        nix::libc::SYS_msgget,
        nix::libc::SYS_msgsnd,
        nix::libc::SYS_msgrcv,
        nix::libc::SYS_msgctl,
        nix::libc::SYS_mq_open,
        nix::libc::SYS_mq_unlink,
        nix::libc::SYS_mq_timedsend,
        nix::libc::SYS_mq_timedreceive,
        nix::libc::SYS_mq_notify,
        nix::libc::SYS_mq_getsetattr,
        // No scheduling or IO-priority mutation is needed, even for self.
        nix::libc::SYS_setpriority,
        nix::libc::SYS_sched_setparam,
        nix::libc::SYS_sched_setscheduler,
        nix::libc::SYS_sched_setattr,
        nix::libc::SYS_sched_setaffinity,
        nix::libc::SYS_ioprio_set,
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
    denied
}
#[cfg(test)]
mod tests {
    use super::*;
    /// ´test:unit:sealer-landlock-floor-never-degrades´
    #[test]
    fn sealer_landlock_floor_never_degrades() {
        let _case = crate::launch::test_support::case_guard();
        for version in [-1, 0, 1, 2, 3, 4, 5] {
            assert_eq!(
                Confinement::require_abi(version),
                Err("sealer-landlock-abi")
            );
        }
        assert_eq!(Confinement::require_abi(6), Ok(()));
        assert_eq!(Confinement::require_abi(10), Ok(()));
        assert_eq!(HANDLED & (1 << 14), 1 << 14); // TRUNCATE
        assert_eq!(HANDLED & (1 << 15), 1 << 15); // IOCTL_DEV
    }
    /// ´test:unit:sealer-key-owner-is-exact´
    #[test]
    fn sealer_key_owner_is_exact() {
        use std::os::unix::fs::PermissionsExt as _;
        let _case = crate::launch::test_support::case_guard();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("synthetic");
        std::fs::write(&path, b"public control").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        let (_, key) = key_handles(&path, owner).unwrap();
        assert_eq!(
            key_custody(&key, owner.wrapping_add(1)),
            Err("sealer-key-file")
        );
        assert_eq!(
            key_handles(&path, owner.wrapping_add(1)).err(),
            Some("sealer-key-directory")
        );
    }
}
