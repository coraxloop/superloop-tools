#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, mkdirat};
use nix::unistd::{Gid, Uid, chown};
use serde_json::json;

use crate::error::LaneError;
use crate::plan::{Plan, protected_identity_dir};
use crate::settings::Settings;

pub const MAX_LETTER: u64 = 1_048_576;

/// Transfer verified directory handles over the standard-input socket that Podman forwards.
#[allow(clippy::borrow_as_ptr, clippy::cast_possible_truncation)]
pub(crate) fn send_private_descriptors(
    stream: &UnixStream,
    fds: &[RawFd],
) -> Result<(), LaneError> {
    let mut byte = [1_u8];
    let mut data = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let bytes = std::mem::size_of_val(fds);
    let mut control = [0_usize; 16];
    #[allow(unsafe_code)]
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(bytes as u32) as usize;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(bytes as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        if libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(LaneError::operation(
                "verified-prefix",
                std::io::Error::last_os_error().to_string(),
            ));
        }
    }
    Ok(())
}

/// Receive exactly the handles named by a private launch vector.
///
/// # Errors
///
/// Refuses an absent, truncated or malformed descriptor transfer.
#[allow(clippy::borrow_as_ptr, clippy::cast_possible_truncation)]
pub fn receive_private_descriptors(
    socket: &impl AsFd,
    count: usize,
) -> Result<Vec<OwnedFd>, LaneError> {
    let mut byte = [0_u8];
    let mut data = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 16];
    #[allow(unsafe_code)]
    unsafe {
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut data;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        if libc::recvmsg(
            socket.as_fd().as_raw_fd(),
            &mut message,
            libc::MSG_CMSG_CLOEXEC,
        ) != 1
            || byte[0] != 1
            || message.msg_flags & libc::MSG_CTRUNC != 0
        {
            return Err(LaneError::input(
                "verified-prefix",
                "private descriptor transfer is incomplete",
            ));
        }
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
            || (*header).cmsg_len
                != libc::CMSG_LEN((count * std::mem::size_of::<RawFd>()) as u32) as usize
        {
            return Err(LaneError::input(
                "verified-prefix",
                "private descriptor transfer is invalid",
            ));
        }
        let first = libc::CMSG_DATA(header).cast::<RawFd>();
        Ok((0..count)
            .map(|index| OwnedFd::from_raw_fd(*first.add(index)))
            .collect())
    }
}

type PrivateAnchor = (PathBuf, Arc<OwnedFd>);

#[derive(Clone)]
struct PrivateAnchors {
    home: PrivateAnchor,
    runs: PrivateAnchor,
    letter: Option<PrivateAnchor>,
    rotation_source: Option<Arc<OwnedFd>>,
}

thread_local! {
    static PRIVATE_HOME: RefCell<Option<PrivateAnchors>> = const { RefCell::new(None) };
    #[cfg(test)]
    static FIXTURE_ROOT_UID: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Override the observed root identity for a private-entry fixture only.
#[cfg(test)]
pub fn with_fixture_root_identity<T>(uid: u32, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<u32>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FIXTURE_ROOT_UID.with(|active| active.set(self.0));
        }
    }
    let previous = FIXTURE_ROOT_UID.with(|active| active.replace(Some(uid)));
    let _restore = Restore(previous);
    run()
}

#[cfg(test)]
fn observed_root_uid(actual: u32) -> u32 {
    if let Some(uid) = FIXTURE_ROOT_UID.with(Cell::get) {
        return uid;
    }
    actual
}

#[cfg(not(test))]
const fn observed_root_uid(actual: u32) -> u32 {
    actual
}

/// Keep one verified private home active for a single private entry.
pub struct PrivateHomeGuard {
    _opened: PrivateAnchors,
}

/// Held private descriptors that may be activated on another thread.
pub(crate) struct PrivateHomeSnapshot(PrivateAnchors);

/// Copy the verified descriptors without reopening their paths.
pub(crate) fn snapshot_private_home() -> Result<PrivateHomeSnapshot, LaneError> {
    PRIVATE_HOME.with(|active| {
        active
            .borrow()
            .as_ref()
            .cloned()
            .map(PrivateHomeSnapshot)
            .ok_or_else(|| LaneError::input("verified-prefix", "private anchors are absent"))
    })
}

/// Activate inherited verified descriptors on one worker thread.
pub(crate) fn activate_private_snapshot(
    snapshot: PrivateHomeSnapshot,
) -> Result<PrivateHomeGuard, LaneError> {
    install_private_anchors(snapshot.0)
}

impl Drop for PrivateHomeGuard {
    fn drop(&mut self) {
        PRIVATE_HOME.with(|active| *active.borrow_mut() = None);
    }
}

/// Bind and activate the inherited home descriptor for a private command.
///
/// # Errors
///
/// Refuses a missing, mismatched, or nested private home binding.
pub fn activate_private_home(
    owner_home: &Path,
    inherited: &impl AsFd,
    owner: u32,
) -> Result<PrivateHomeGuard, LaneError> {
    let opened = Arc::new(bind_private_home(owner_home, inherited, owner)?);
    let anchors = PrivateAnchors {
        home: (owner_home.to_path_buf(), Arc::clone(&opened)),
        runs: (owner_home.to_path_buf(), opened),
        letter: None,
        rotation_source: None,
    };
    install_private_anchors(anchors)
}

/// Activate a home whose host ancestry was verified before descriptor transfer.
///
/// # Errors
///
/// Refuses a foreign, writable or non-directory descriptor.
pub fn activate_handed_home(
    owner_home: &Path,
    inherited: &impl AsFd,
    owner: u32,
) -> Result<PrivateHomeGuard, LaneError> {
    let stat =
        fstat(inherited).map_err(|error| LaneError::input("verified-prefix", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || stat.st_uid != owner
        || stat.st_mode & 0o022 != 0
    {
        return Err(LaneError::input(
            "verified-prefix",
            "handed owner home differs",
        ));
    }
    let opened = Arc::new(
        nix::unistd::dup(inherited)
            .map_err(|error| LaneError::input("verified-prefix", error.to_string()))?,
    );
    let anchors = PrivateAnchors {
        home: (owner_home.to_path_buf(), Arc::clone(&opened)),
        runs: (owner_home.to_path_buf(), opened),
        letter: None,
        rotation_source: None,
    };
    install_private_anchors(anchors)
}

/// Bind the inherited home, runs root and optional letter directory for a private launch.
///
/// # Errors
///
/// Refuses a missing or mismatched descriptor or a nested private binding.
pub fn activate_private_launch(
    owner_home: &Path,
    inherited_home: &dyn AsFd,
    runs_root: &Path,
    inherited_runs: &dyn AsFd,
    letter: Option<(&Path, &dyn AsFd)>,
    owner: u32,
) -> Result<PrivateHomeGuard, LaneError> {
    let home = Arc::new(bind_private_home(owner_home, inherited_home, owner)?);
    let runs_prefix = if runs_root.starts_with(owner_home) {
        owner_home
    } else {
        runs_root
    };
    let runs = Arc::new(bind_socket_directory(
        runs_root,
        runs_prefix,
        inherited_runs.as_fd().as_raw_fd(),
        owner,
    )?);
    let letter = letter
        .map(|(path, fd)| {
            bind_private_directory(path, fd, owner, "letter directory")
                .map(|opened| (path.to_path_buf(), Arc::new(opened)))
        })
        .transpose()?;
    install_private_anchors(PrivateAnchors {
        home: (owner_home.to_path_buf(), home),
        runs: (runs_root.to_path_buf(), runs),
        letter,
        rotation_source: None,
    })
}

fn install_private_anchors(anchors: PrivateAnchors) -> Result<PrivateHomeGuard, LaneError> {
    PRIVATE_HOME.with(|active| {
        let mut active = active.borrow_mut();
        if active.is_some() {
            return Err(LaneError::input(
                "verified-prefix",
                "a private home is already active",
            ));
        }
        *active = Some(PrivateAnchors {
            home: (anchors.home.0.clone(), Arc::clone(&anchors.home.1)),
            runs: (anchors.runs.0.clone(), Arc::clone(&anchors.runs.1)),
            letter: anchors
                .letter
                .as_ref()
                .map(|(path, fd)| (path.clone(), Arc::clone(fd))),
            rotation_source: anchors.rotation_source.as_ref().map(Arc::clone),
        });
        Ok(PrivateHomeGuard { _opened: anchors })
    })
}

/// Retain the pinned handover file received with a private launch.
///
/// # Errors
///
/// Refuses a missing private launch or a descriptor with foreign type, owner or mode.
pub fn attach_private_rotation_source(inherited: &dyn AsFd, owner: u32) -> Result<(), LaneError> {
    let stat =
        fstat(inherited).map_err(|error| LaneError::input("rotate-source", error.to_string()))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err(LaneError::input(
            "rotate-source",
            "inherited source has foreign type, owner or mode",
        ));
    }
    let descriptor = Arc::new(
        nix::unistd::dup(inherited.as_fd())
            .map_err(|error| LaneError::input("rotate-source", error.to_string()))?,
    );
    PRIVATE_HOME.with(|active| {
        let mut active = active.borrow_mut();
        let anchors = active
            .as_mut()
            .ok_or_else(|| LaneError::input("rotate-source", "private launch is absent"))?;
        if anchors.rotation_source.replace(descriptor).is_some() {
            return Err(LaneError::input(
                "rotate-source",
                "source is already attached",
            ));
        }
        Ok(())
    })
}

/// Duplicate the handover descriptor bound to this private invocation.
///
/// # Errors
///
/// Refuses an absent source or failed descriptor duplication.
pub fn private_rotation_source() -> Result<OwnedFd, LaneError> {
    PRIVATE_HOME.with(|active| {
        let active = active.borrow();
        let source = active
            .as_ref()
            .and_then(|anchors| anchors.rotation_source.as_ref())
            .ok_or_else(|| LaneError::input("rotate-source", "inherited source is absent"))?;
        nix::unistd::dup(source.as_ref())
            .map_err(|error| LaneError::input("rotate-source", error.to_string()))
    })
}

pub(crate) fn private_home() -> Option<PathBuf> {
    PRIVATE_HOME.with(|active| {
        active
            .borrow()
            .as_ref()
            .map(|anchors| anchors.home.0.clone())
    })
}

pub(crate) fn private_is_active() -> bool {
    PRIVATE_HOME.with(|active| active.borrow().is_some())
}

pub(crate) fn private_runs() -> Result<(PathBuf, OwnedFd), LaneError> {
    PRIVATE_HOME.with(|active| {
        let active = active.borrow();
        let anchors = active
            .as_ref()
            .ok_or_else(|| LaneError::input("verified-prefix", "private runs anchor is absent"))?;
        let fd = nix::unistd::dup(anchors.runs.1.as_ref())
            .map_err(|error| LaneError::input("verified-prefix", error.to_string()))?;
        Ok((anchors.runs.0.clone(), fd))
    })
}

/// Read allocations through the active private home or the full host walk.
///
/// # Errors
///
/// Refuses an unsafe private anchor or invalid allocation ledger.
pub fn read_allocations(home: &Path) -> Result<loop_home::allocations::Allocations, LaneError> {
    let path = loop_home::allocations::allocations_path(home);
    let result = if let Some(prefix) = private_home() {
        if prefix != home {
            return Err(LaneError::input(
                "verified-prefix",
                "allocation home differs from the verified private home",
            ));
        }
        let root = home.join(".config/loops");
        let pinned = pin_parent_beneath(&root, home, nix::unistd::Uid::effective().as_raw())?;
        loop_home::allocations::Allocations::read_beneath(&path, &root, &pinned)
    } else {
        loop_home::allocations::Allocations::read(&path)
    };
    result.map_err(|error| LaneError::input("allocations", error.message()))
}

fn reason(path: &Path, error: impl std::fmt::Display) -> LaneError {
    LaneError::input("unsafe-path", format!("{}: {error}", path.display()))
}

fn directory(fd: &OwnedFd, path: &Path) -> Result<nix::sys::stat::FileStat, LaneError> {
    let stat = fstat(fd).map_err(|error| reason(path, error))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(reason(path, "not a directory"));
    }
    Ok(stat)
}

fn child(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd, LaneError> {
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    openat2(parent, name, how).map_err(|error| reason(path, error))
}

fn require_absent(parent: &OwnedFd, path: &Path) -> Result<(), LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| reason(path, "missing name"))?;
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    match openat2(parent, name, how) {
        Ok(_) => Err(LaneError::input(
            "already-exists",
            format!("{} already exists", path.display()),
        )),
        Err(Errno::ENOENT) => Ok(()),
        Err(error) => Err(reason(path, error)),
    }
}

pub(crate) fn trusted(
    parent: &nix::sys::stat::FileStat,
    next: &nix::sys::stat::FileStat,
    path: &Path,
    owner: u32,
) -> Result<(), LaneError> {
    let mode = parent.st_mode & 0o7777;
    if parent.st_uid != 0 && parent.st_uid != 65534 && parent.st_uid != owner {
        return Err(reason(
            path,
            format!("replaceable ancestor uid {}", parent.st_uid),
        ));
    }
    if mode & 0o022 != 0 && (mode & 0o1000 == 0 || (next.st_uid != 0 && next.st_uid != 65534 && next.st_uid != owner)) {
        return Err(reason(
            path,
            format!("replaceable ancestor mode {mode:04o}"),
        ));
    }
    Ok(())
}

/// Open an owner-controlled directory through pinned, link-free ancestors.
///
/// # Errors
///
/// Refuses a linked, missing, replaceable, or wrongly owned component.
pub fn pin_parent(path: &Path, owner: u32) -> Result<OwnedFd, LaneError> {
    if let Some(prefix) = PRIVATE_HOME.with(|active| {
        active.borrow().as_ref().map(|anchors| {
            if let Some((letter, _)) = &anchors.letter
                && path == letter
            {
                return letter.clone();
            }
            if path.starts_with(&anchors.runs.0) {
                anchors.runs.0.clone()
            } else {
                anchors.home.0.clone()
            }
        })
    }) {
        return pin_parent_beneath(path, &prefix, owner);
    }
    if !path.is_absolute() {
        return Err(reason(path, "not absolute"));
    }
    let prefix = PathBuf::from("/");
    let fd = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| reason(Path::new("/"), error))?;
    let mut stat = directory(&fd, &prefix)?;
    stat.st_uid = observed_root_uid(stat.st_uid);
    let (fd, stat) = loop_home::custody::walk_directories(
        fd,
        stat,
        &prefix,
        path.strip_prefix("/")
            .map_err(|error| reason(path, error))?,
        OFlag::O_RDONLY,
        |parent, next, path| trusted(parent, next, path, owner),
        reason,
    )?;
    let mode = stat.st_mode & 0o7777;
    if stat.st_uid != owner || mode & 0o022 != 0 {
        return Err(reason(
            path,
            format!(
                "parent uid {} mode {mode:04o}; expected uid {owner} without group or other write",
                stat.st_uid
            ),
        ));
    }
    Ok(fd)
}

/// Cross from the pinned owner-controlled runs root into loop-owned round directories.
///
/// # Errors
///
/// Refuses a linked, writable, or foreign-owned component.
pub(crate) fn pin_loop_round(
    runs_root: &Path,
    path: &Path,
    namespace_owner: u32,
    loop_uid: u32,
) -> Result<OwnedFd, LaneError> {
    pin_loop_round_with(
        runs_root,
        path,
        namespace_owner,
        loop_uid,
        |fd, component| {
            let stat = directory(fd, component)?;
            Ok((stat.st_uid, stat.st_mode & 0o7777))
        },
    )
}

/// Descend from the caller's held runs root into one loop-owned round directory.
///
/// # Errors
///
/// Refuses a path outside that root or a linked, writable, or foreign-owned component.
pub(crate) fn pin_loop_round_at(
    runs_fd: &OwnedFd,
    runs_root: &Path,
    path: &Path,
    loop_uid: u32,
) -> Result<OwnedFd, LaneError> {
    pin_loop_round_at_with(runs_fd, runs_root, path, loop_uid, |fd, path| {
        let stat = directory(fd, path)?;
        Ok((stat.st_uid, stat.st_mode & 0o7777))
    })
}

pub(crate) fn pin_loop_round_at_with(
    runs_fd: &OwnedFd,
    runs_root: &Path,
    path: &Path,
    loop_uid: u32,
    mut metadata: impl FnMut(&OwnedFd, &Path) -> Result<(u32, u32), LaneError>,
) -> Result<OwnedFd, LaneError> {
    let relative = path
        .strip_prefix(runs_root)
        .map_err(|_| reason(path, "round is outside the runs root"))?;
    if relative.as_os_str().is_empty() {
        return Err(reason(path, "round directory is absent"));
    }
    let mut fd = nix::unistd::dup(runs_fd).map_err(|error| reason(runs_root, error))?;
    let mut current = runs_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(reason(path, "dotted component"));
        };
        current.push(name);
        let next = child(&fd, name, &current)?;
        let (uid, mode) = metadata(&next, &current)?;
        loop_round_owner(uid, mode, loop_uid, &current)?;
        fd = next;
    }
    Ok(fd)
}

fn pin_loop_round_with(
    runs_root: &Path,
    path: &Path,
    namespace_owner: u32,
    loop_uid: u32,
    mut metadata: impl FnMut(&OwnedFd, &Path) -> Result<(u32, u32), LaneError>,
) -> Result<OwnedFd, LaneError> {
    let relative = path
        .strip_prefix(runs_root)
        .map_err(|_| reason(path, "round is outside the runs root"))?;
    if relative.as_os_str().is_empty() {
        return Err(reason(path, "round directory is absent"));
    }
    let mut fd = pin_parent(runs_root, namespace_owner)?;
    let mut current = runs_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(reason(path, "dotted component"));
        };
        current.push(name);
        let next = child(&fd, name, &current)?;
        let (uid, mode) = metadata(&next, &current)?;
        loop_round_owner(uid, mode, loop_uid, &current)?;
        fd = next;
    }
    Ok(fd)
}

fn loop_round_owner(actual: u32, mode: u32, expected: u32, path: &Path) -> Result<(), LaneError> {
    if actual != expected || mode & 0o022 != 0 {
        return Err(reason(
            path,
            format!("loop directory uid {actual} mode {mode:04o}; expected uid {expected}"),
        ));
    }
    Ok(())
}

fn host_ancestor(
    stat: &nix::sys::stat::FileStat,
    path: &Path,
    root_uid: u32,
) -> Result<(), LaneError> {
    let mode = stat.st_mode & 0o7777;
    if stat.st_uid != root_uid || mode & 0o022 != 0 {
        return Err(reason(
            path,
            format!(
                "host ancestor uid {} mode {mode:04o}; expected uid {root_uid} without group or other write",
                stat.st_uid
            ),
        ));
    }
    Ok(())
}

/// Pin the owner home after checking each host ancestor from a trusted root.
///
/// # Errors
///
/// Refuses a linked, writable, or wrongly owned host ancestor or owner home.
pub(crate) fn verify_host_prefix_from(
    root: &Path,
    owner_home: &Path,
    owner: u32,
    root_uid: u32,
) -> Result<OwnedFd, LaneError> {
    let relative = owner_home
        .strip_prefix(root)
        .map_err(|_| reason(owner_home, "owner home is outside the host root"))?;
    let mut prefix = root.to_path_buf();
    let mut fd = open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| reason(root, error))?;
    let mut stat = directory(&fd, root)?;
    if root == Path::new("/") {
        stat.st_uid = observed_root_uid(stat.st_uid);
    }
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(reason(owner_home, "dotted component"));
        };
        host_ancestor(&stat, &prefix, root_uid)?;
        prefix.push(name);
        let next = child(&fd, name, &prefix)?;
        stat = directory(&next, &prefix)?;
        fd = next;
    }
    let mode = stat.st_mode & 0o7777;
    if stat.st_uid != owner || mode & 0o022 != 0 {
        return Err(reason(
            owner_home,
            format!(
                "owner home uid {} mode {mode:04o}; expected uid {owner} without group or other write",
                stat.st_uid
            ),
        ));
    }
    Ok(fd)
}

/// Verify an owner-controlled launch root from its host ancestry or the verified home.
///
/// # Errors
///
/// Refuses a linked, writable, or wrongly owned ancestor or launch root.
pub(crate) fn verify_host_launch_root(
    host_root: &Path,
    owner_home: &Path,
    target: &Path,
    owner: u32,
    root_uid: u32,
) -> Result<OwnedFd, LaneError> {
    if target.starts_with(owner_home) {
        verify_host_prefix_from(owner_home, target, owner, owner)
    } else {
        verify_host_prefix_from(host_root, target, owner, root_uid)
    }
}

/// Pin an owner path beneath a host-verified prefix inside a rootless namespace.
///
/// # Errors
///
/// Refuses a linked or replaceable component beneath the verified prefix.
pub fn pin_parent_beneath(
    path: &Path,
    verified_prefix: &Path,
    owner: u32,
) -> Result<OwnedFd, LaneError> {
    let relative = path
        .strip_prefix(verified_prefix)
        .map_err(|_| reason(path, "path is outside the verified owner home"))?;
    let prefix_relative = verified_prefix
        .strip_prefix("/")
        .map_err(|_| reason(verified_prefix, "verified owner home is not absolute"))?;
    if prefix_relative.as_os_str().is_empty() {
        return Err(reason(
            verified_prefix,
            "verified owner home is the filesystem root",
        ));
    }
    if verified_prefix
        .components()
        .skip(1)
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(reason(verified_prefix, "dotted component"));
    }
    let active_fd = PRIVATE_HOME.with(|active| {
        active.borrow().as_ref().and_then(|anchors| {
            [&anchors.home, &anchors.runs]
                .into_iter()
                .chain(anchors.letter.as_ref())
                .find(|(path, _)| path == verified_prefix)
                .map(|(_, fd)| nix::unistd::dup(fd.as_ref()))
        })
    });
    let fd = if let Some(duplicate) = active_fd {
        duplicate.map_err(|error| reason(verified_prefix, error))?
    } else {
        let root = open(
            "/",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| reason(Path::new("/"), error))?;
        #[cfg(test)]
        if FIXTURE_ROOT_UID.with(|active| active.get().is_some()) {
            let mut stat = fstat(&root).map_err(|error| reason(Path::new("/"), error))?;
            stat.st_uid = observed_root_uid(stat.st_uid);
            host_ancestor(&stat, Path::new("/"), 0)?;
        }
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        openat2(&root, prefix_relative, how).map_err(|error| reason(verified_prefix, error))?
    };
    let prefix = verified_prefix.to_path_buf();
    let stat = directory(&fd, &prefix)?;
    let mode = stat.st_mode & 0o7777;
    if stat.st_uid != owner || mode & 0o022 != 0 {
        return Err(reason(
            verified_prefix,
            format!(
                "verified prefix uid {} mode {mode:04o}; expected uid {owner} without group or other write",
                stat.st_uid
            ),
        ));
    }
    let (fd, stat) = loop_home::custody::walk_directories(
        fd,
        stat,
        &prefix,
        relative,
        OFlag::O_RDONLY,
        |parent, next, path| trusted(parent, next, path, owner),
        reason,
    )?;
    let mode = stat.st_mode & 0o7777;
    if stat.st_uid != owner || mode & 0o022 != 0 {
        return Err(reason(
            path,
            format!(
                "parent uid {} mode {mode:04o}; expected uid {owner} without group or other write",
                stat.st_uid
            ),
        ));
    }
    Ok(fd)
}

/// Match the private home reopen to the owner-verified inherited directory.
///
/// # Errors
///
/// Refuses a missing descriptor or a different home inode.
pub fn bind_private_home(
    owner_home: &Path,
    inherited: &dyn AsFd,
    owner: u32,
) -> Result<OwnedFd, LaneError> {
    let reopened = pin_parent_beneath(owner_home, owner_home, owner)?;
    let bound = fstat(inherited).map_err(|error| {
        LaneError::input(
            "verified-prefix",
            format!("inherited home descriptor: {error}"),
        )
    })?;
    let actual =
        fstat(&reopened).map_err(|error| LaneError::input("verified-prefix", error.to_string()))?;
    if bound.st_dev != actual.st_dev || bound.st_ino != actual.st_ino {
        return Err(LaneError::input(
            "verified-prefix",
            "owner home differs from the inherited verified descriptor",
        ));
    }
    Ok(reopened)
}

/// Match a private directory reopen to its owner-verified inherited descriptor.
///
/// # Errors
///
/// Refuses a missing or different directory inode.
pub fn bind_private_directory(
    path: &Path,
    inherited: &dyn AsFd,
    owner: u32,
    role: &str,
) -> Result<OwnedFd, LaneError> {
    let reopened = pin_parent_beneath(path, path, owner)?;
    let bound = fstat(inherited).map_err(|error| {
        LaneError::input("verified-prefix", format!("{role} descriptor: {error}"))
    })?;
    let actual =
        fstat(&reopened).map_err(|error| LaneError::input("verified-prefix", error.to_string()))?;
    if bound.st_dev != actual.st_dev || bound.st_ino != actual.st_ino {
        return Err(LaneError::input(
            "verified-prefix",
            format!("{role} differs from the inherited verified descriptor"),
        ));
    }
    Ok(reopened)
}

/// Reopen an expected socket directory from an independent verified anchor and
/// compare it with a descriptor received across the namespace boundary.
///
/// # Errors
///
/// Refuses an unsafe walk, closed descriptor, non-directory, or differing inode.
pub fn bind_socket_directory(
    path: &Path,
    prefix: &Path,
    received_fd: RawFd,
    owner: u32,
) -> Result<OwnedFd, LaneError> {
    #[allow(unsafe_code)]
    // SAFETY: fcntl duplicates an open descriptor before any pathname reopen can reuse its number.
    let copied = unsafe { libc::fcntl(received_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if copied < 0 {
        let received_error = std::io::Error::last_os_error();
        let expected = pin_parent_beneath(path, prefix, owner).map_err(|error| {
            LaneError::input(
                "socket-dir-handoff",
                format!("expected directory walk: {}", error.detail),
            )
        })?;
        let expected = fstat(&expected)
            .map_err(|error| LaneError::input("socket-dir-handoff", error.to_string()))?;
        return Err(LaneError::input(
            "socket-dir-handoff",
            format!(
                "expected {}:{} directory; received closed: {received_error}",
                expected.st_dev, expected.st_ino
            ),
        ));
    }
    #[allow(unsafe_code)]
    // SAFETY: successful F_DUPFD_CLOEXEC returned a new owned descriptor.
    let received_fd = unsafe { OwnedFd::from_raw_fd(copied) };
    let reopened = pin_parent_beneath(path, prefix, owner).map_err(|error| {
        LaneError::input(
            "socket-dir-handoff",
            format!("expected directory walk: {}", error.detail),
        )
    })?;
    let expected = fstat(&reopened)
        .map_err(|error| LaneError::input("socket-dir-handoff", error.to_string()))?;
    let received = fstat(&received_fd)
        .map_err(|error| LaneError::input("socket-dir-handoff", error.to_string()))?;
    if received.st_mode & libc::S_IFMT != libc::S_IFDIR
        || received.st_dev != expected.st_dev
        || received.st_ino != expected.st_ino
    {
        return Err(LaneError::input(
            "socket-dir-handoff",
            format!(
                "expected {}:{} directory; received {}:{} mode {:o}",
                expected.st_dev,
                expected.st_ino,
                received.st_dev,
                received.st_ino,
                received.st_mode & libc::S_IFMT
            ),
        ));
    }
    Ok(reopened)
}

fn make_dir(parent: &OwnedFd, path: &Path, mode: u32) -> Result<OwnedFd, LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| reason(path, "missing name"))?;
    mkdirat(parent, name, Mode::from_bits_truncate(0o700)).map_err(|error| reason(path, error))?;
    let fd = child(parent, name, path)?;
    fchmod(&fd, Mode::from_bits_truncate(mode)).map_err(|error| reason(path, error))?;
    Ok(fd)
}

fn make_file(parent: &OwnedFd, path: &Path, bytes: &[u8], mode: u32) -> Result<File, LaneError> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| reason(path, "non-UTF-8 name"))?;
    let fd = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| reason(path, error))?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|error| reason(path, error))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|error| reason(path, error))?;
    Ok(file)
}

/// Read one bounded regular-file letter without following its final link.
///
/// # Errors
///
/// Refuses an unreadable, linked, nonregular, or oversized letter.
pub fn read_letter(path: &Path, owner: u32) -> Result<Vec<u8>, LaneError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| reason(path, "missing parent"))?;
    let parent = pin_parent(parent_path, owner)?;
    let name = path
        .file_name()
        .ok_or_else(|| reason(path, "missing name"))?;
    read_letter_at(&parent, name, path)
}

/// Read a bounded letter beneath a previously verified directory descriptor.
///
/// # Errors
///
/// Refuses an unreadable, linked, nonregular, or oversized letter.
pub fn read_letter_at(parent: &impl AsFd, name: &OsStr, path: &Path) -> Result<Vec<u8>, LaneError> {
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    let fd = openat2(parent, name, how)
        .map_err(|error| LaneError::input("letter-read", format!("{}: {error}", path.display())))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|error| LaneError::input("letter-read", format!("{}: {error}", path.display())))?;
    if !meta.is_file() {
        return Err(LaneError::input(
            "letter-kind",
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.len() > MAX_LETTER {
        return Err(LaneError::input(
            "letter-size",
            format!("{} exceeds {MAX_LETTER} bytes", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_LETTER + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| LaneError::input("letter-read", format!("{}: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_LETTER {
        return Err(LaneError::input(
            "letter-size",
            format!("{} exceeds {MAX_LETTER} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

fn report(
    reports: &mut Vec<serde_json::Value>,
    path: &Path,
    meta: &std::fs::Metadata,
    expected_owner: u32,
    expected_group: u32,
    want_mode: u32,
) {
    reports.push(json!({"actual": {"gid": meta.gid(), "mode": format!("{:04o}", meta.mode() & 0o7777), "uid": meta.uid()}, "path": path.to_string_lossy(), "wanted": {"gid": expected_group, "mode": format!("{want_mode:04o}"), "uid": expected_owner}}));
}

fn report_dir(
    reports: &mut Vec<serde_json::Value>,
    fd: &OwnedFd,
    path: &Path,
    expected_owner: u32,
    expected_group: u32,
    want_mode: u32,
) -> Result<(), LaneError> {
    let meta = File::from(fd.try_clone().map_err(|error| reason(path, error))?)
        .metadata()
        .map_err(|error| reason(path, error))?;
    report(
        reports,
        path,
        &meta,
        expected_owner,
        expected_group,
        want_mode,
    );
    Ok(())
}

fn report_file(
    reports: &mut Vec<serde_json::Value>,
    file: &File,
    path: &Path,
    expected_owner: u32,
    expected_group: u32,
    want_mode: u32,
) -> Result<(), LaneError> {
    report(
        reports,
        path,
        &file.metadata().map_err(|error| reason(path, error))?,
        expected_owner,
        expected_group,
        want_mode,
    );
    Ok(())
}

fn make_empty_bare(
    sources: &OwnedFd,
    path: &Path,
    worker: u32,
    reports: &mut Vec<serde_json::Value>,
) -> Result<(), LaneError> {
    make_empty_bare_with(sources, path, worker, reports, |_| Ok(()))
}

fn make_empty_bare_with(
    sources: &OwnedFd,
    path: &Path,
    worker: u32,
    reports: &mut Vec<serde_json::Value>,
    after_root: impl FnOnce(&OwnedFd) -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    let bare = make_dir(sources, path, 0o700)?;
    report_dir(reports, &bare, path, worker, worker, 0o700)?;
    after_root(&bare)?;
    for name in ["objects", "refs", "hooks", "info"] {
        let child_path = path.join(name);
        let child = make_dir(&bare, &child_path, 0o700)?;
        report_dir(reports, &child, &child_path, worker, worker, 0o700)?;
        for nested in match name {
            "objects" => &["info", "pack"][..],
            "refs" => &["heads", "tags"][..],
            _ => &[][..],
        } {
            let nested_path = child_path.join(nested);
            let nested_fd = make_dir(&child, &nested_path, 0o700)?;
            report_dir(reports, &nested_fd, &nested_path, worker, worker, 0o700)?;
        }
    }
    for (name, bytes) in [
        ("HEAD", b"ref: refs/heads/main\n".as_slice()),
        (
            "config",
            b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n".as_slice(),
        ),
        ("description", b"Unnamed repository\n".as_slice()),
    ] {
        let child_path = path.join(name);
        let file = make_file(&bare, &child_path, bytes, 0o600)?;
        report_file(reports, &file, &child_path, worker, worker, 0o600)?;
    }
    Ok(())
}

fn make_declared_bares_with(
    sources: &OwnedFd,
    root: &Path,
    worker: u32,
    declarations: &[crate::launch::DeclaredSource],
    reports: &mut Vec<serde_json::Value>,
    mut make: impl FnMut(&OwnedFd, &Path, u32, &mut Vec<serde_json::Value>) -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    for source in declarations {
        if let Err(error) = make(
            sources,
            &root.join(format!("{}.git", source.name)),
            worker,
            reports,
        ) {
            let original = LaneError::operation(
                "source-seed-create",
                format!("{}: {}", source.name, error.line()),
            );
            return Err(cleanup_created_after(sources, root, declarations, original));
        }
    }
    Ok(())
}

fn cleanup_created_after(
    sources: &OwnedFd,
    root: &Path,
    declarations: &[crate::launch::DeclaredSource],
    original: LaneError,
) -> LaneError {
    match crate::launch::seed::cleanup_created(sources, root, declarations) {
        Ok(()) => original,
        Err(cleanup) => LaneError::input(
            "source-seed-cleanup",
            format!("sources: {}; after {}", cleanup.detail, original.line()),
        ),
    }
}

/// Create the home, driver directory, and identity directory beneath pinned parents.
///
/// # Errors
///
/// Refuses unsafe parents, an existing root, or a failed creation.
#[allow(clippy::too_many_lines)]
pub fn make_home(
    plan: &Plan,
    settings: &Settings,
    letter_bytes: &[u8],
    caller: (u32, u32),
) -> Result<serde_json::Value, LaneError> {
    let home_parent_path = plan
        .home
        .parent()
        .ok_or_else(|| reason(&plan.home, "missing parent"))?;
    let driver_parent_path = plan
        .driver_dir
        .parent()
        .ok_or_else(|| reason(&plan.driver_dir, "missing parent"))?;
    let home_parent = pin_parent(home_parent_path, caller.0)?;
    let driver_parent = pin_parent(driver_parent_path, caller.0)?;
    make_home_pinned(
        plan,
        settings,
        letter_bytes,
        caller,
        &home_parent,
        &driver_parent,
    )
}

/// Create a run from the rootless namespace root and assign every planned owner.
///
/// # Errors
///
/// Refuses an unsafe parent, an existing run, or any failed ownership assignment.
#[allow(clippy::too_many_lines)]
pub fn make_home_in_namespace(
    plan: &Plan,
    settings: &Settings,
    letter_bytes: &[u8],
    owner_home: &Path,
    loop_name: &str,
) -> Result<serde_json::Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let home_parent_path = plan
        .home
        .parent()
        .ok_or_else(|| reason(&plan.home, "missing parent"))?;
    let driver_parent_path = plan
        .driver_dir
        .parent()
        .ok_or_else(|| reason(&plan.driver_dir, "missing parent"))?;
    let home_parent = pin_parent(home_parent_path, 0)?;
    let driver_parent = pin_parent(driver_parent_path, 0)?;
    let worker = plan.document["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| reason(&plan.home, "missing worker uid"))?;
    let loop_uid = plan.document["paths"][0]["gid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| reason(&plan.home, "missing loop uid"))?;
    let declarations = crate::launch::declared_sources(letter_bytes)?;
    let mut held_sources = None;
    let attempt = (|| -> Result<serde_json::Value, LaneError> {
        let mut report = make_home_pinned_with_sources(
            plan,
            settings,
            letter_bytes,
            (0, 0),
            &home_parent,
            &driver_parent,
            &mut held_sources,
        )?;
        let sources_parent = nix::unistd::dup(
            held_sources
                .as_ref()
                .ok_or_else(|| reason(&plan.home, "sources descriptor is absent"))?,
        )
        .map_err(|error| reason(&plan.home, error))?;
        let seeds = crate::launch::seed::seed_sources_from_parent(
            sources_parent,
            plan,
            owner_home,
            loop_name,
            loop_uid,
            0,
            &declarations,
        )?;
        crate::launch::seed::handover_or_cleanup(&seeds, || -> Result<(), LaneError> {
            let paths = plan.document["paths"]
                .as_array()
                .ok_or_else(|| LaneError::operation("plan-paths", "planned paths are absent"))?;
            let mut ordered = paths.iter().collect::<Vec<_>>();
            ordered.sort_by_key(|entry| {
                std::cmp::Reverse(
                    entry["path"]
                        .as_str()
                        .unwrap_or_default()
                        .matches('/')
                        .count(),
                )
            });
            for entry in ordered {
                let name = entry["path"]
                    .as_str()
                    .ok_or_else(|| LaneError::operation("plan-paths", "path is absent"))?;
                let uid = entry["uid"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| {
                        LaneError::operation("plan-paths", format!("{name}: uid is absent"))
                    })?;
                let gid = entry["gid"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| {
                        LaneError::operation("plan-paths", format!("{name}: gid is absent"))
                    })?;
                let path = Path::new(name);
                chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(
                    |error| LaneError::operation("home-owner", format!("{name}: {error}")),
                )?;
                let meta = std::fs::symlink_metadata(path).map_err(|error| {
                    LaneError::operation("home-owner", format!("{name}: {error}"))
                })?;
                if meta.uid() != uid || meta.gid() != gid {
                    return Err(LaneError::operation(
                        "home-owner",
                        format!("{name}: ownership differs"),
                    ));
                }
            }
            if let Some(created) = report["created"].as_array() {
                let source_root = plan.home.join(".local/sources");
                let mut source_entries = created
                    .iter()
                    .filter(|entry| {
                        entry["path"].as_str().is_some_and(|path| {
                            Path::new(path).starts_with(&source_root)
                                && Path::new(path) != source_root
                        })
                    })
                    .collect::<Vec<_>>();
                source_entries.sort_by_key(|entry| {
                    std::cmp::Reverse(
                        entry["path"]
                            .as_str()
                            .unwrap_or_default()
                            .matches('/')
                            .count(),
                    )
                });
                for entry in source_entries {
                    let name = entry["path"]
                        .as_str()
                        .ok_or_else(|| reason(&source_root, "source path is absent"))?;
                    let path = Path::new(name);
                    chown(
                        path,
                        Some(Uid::from_raw(worker)),
                        Some(Gid::from_raw(worker)),
                    )
                    .map_err(|error| {
                        LaneError::operation("home-owner", format!("{name}: {error}"))
                    })?;
                    let meta = std::fs::symlink_metadata(path).map_err(|error| {
                        LaneError::operation("home-owner", format!("{name}: {error}"))
                    })?;
                    if meta.uid() != worker || meta.gid() != worker {
                        return Err(LaneError::operation(
                            "home-owner",
                            format!("{name}: ownership differs"),
                        ));
                    }
                }
            }
            crate::launch::seed::assign_source_ownership(&seeds, worker)?;
            Ok(())
        })?;
        if let Some(created) = report["created"].as_array_mut() {
            for entry in created {
                entry["actual"] = entry["wanted"].clone();
            }
        }
        report["remaining"] =
            json!("fixed bind sources and the worker process remain to be started");
        report["declared_sources"] = json!(seeds.records);
        Ok(report)
    })();
    match attempt {
        Ok(report) => Ok(report),
        Err(error) => {
            if let Some(parent) = held_sources.as_ref() {
                return Err(cleanup_created_after(
                    parent,
                    &plan.home.join(".local/sources"),
                    &declarations,
                    error,
                ));
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn make_home_pinned(
    plan: &Plan,
    settings: &Settings,
    letter_bytes: &[u8],
    caller: (u32, u32),
    home_parent: &OwnedFd,
    driver_parent: &OwnedFd,
) -> Result<serde_json::Value, LaneError> {
    let mut held_sources = None;
    let created = make_home_pinned_with_sources(
        plan,
        settings,
        letter_bytes,
        caller,
        home_parent,
        driver_parent,
        &mut held_sources,
    );
    if let Err(error) = created {
        if let Some(parent) = held_sources.as_ref() {
            let declarations = crate::launch::declared_sources(letter_bytes)?;
            return Err(cleanup_created_after(
                parent,
                &plan.home.join(".local/sources"),
                &declarations,
                error,
            ));
        }
        return Err(error);
    }
    created
}

#[allow(clippy::too_many_lines)]
fn make_home_pinned_with_sources(
    plan: &Plan,
    settings: &Settings,
    letter_bytes: &[u8],
    caller: (u32, u32),
    home_parent: &OwnedFd,
    driver_parent: &OwnedFd,
    held_sources: &mut Option<OwnedFd>,
) -> Result<serde_json::Value, LaneError> {
    let declared_sources = crate::launch::declared_sources(letter_bytes)?;
    require_absent(home_parent, &plan.home)?;
    require_absent(driver_parent, &plan.driver_dir)?;
    let identity_dir = protected_identity_dir(&plan.driver_dir)?;
    require_absent(driver_parent, &identity_dir)?;
    let worker = plan.document["worker_uid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| reason(&plan.home, "missing worker uid"))?;
    let loop_uid = crate::plan::loop_uid(&plan.document)?;
    let mut reports = Vec::new();
    let d = make_dir(driver_parent, &plan.driver_dir, 0o700)?;
    report_dir(
        &mut reports,
        &d,
        &plan.driver_dir,
        loop_uid,
        loop_uid,
        0o700,
    )?;
    let runtime_path = plan.driver_dir.join("launch");
    let runtime = make_dir(&d, &runtime_path, 0o700)?;
    report_dir(
        &mut reports,
        &runtime,
        &runtime_path,
        loop_uid,
        loop_uid,
        0o700,
    )?;
    let launch_path = identity_dir;
    let launch = make_dir(driver_parent, &launch_path, 0o700)?;
    report_dir(
        &mut reports,
        &launch,
        &launch_path,
        caller.0,
        caller.1,
        0o700,
    )?;
    let passwd_path = launch_path.join("passwd");
    let passwd = format!("worker:x:{worker}:{worker}::/home/worker:/bin/sh\n");
    let file = make_file(&launch, &passwd_path, passwd.as_bytes(), 0o440)?;
    report_file(&mut reports, &file, &passwd_path, caller.0, loop_uid, 0o440)?;
    let group_path = launch_path.join("group");
    let group = format!("worker:x:{worker}:\nloop:x:{loop_uid}:worker\n");
    let file = make_file(&launch, &group_path, group.as_bytes(), 0o440)?;
    report_file(&mut reports, &file, &group_path, caller.0, loop_uid, 0o440)?;
    let settings_path = plan.driver_dir.join("settings.toml");
    let file = make_file(&d, &settings_path, settings.source.as_bytes(), 0o600)?;
    report_file(
        &mut reports,
        &file,
        &settings_path,
        loop_uid,
        loop_uid,
        0o600,
    )?;
    let plan_path = plan.driver_dir.join("plan.json");
    let mut plan_bytes = plan.json()?.into_bytes();
    plan_bytes.push(b'\n');
    let file = make_file(&d, &plan_path, &plan_bytes, 0o600)?;
    report_file(&mut reports, &file, &plan_path, loop_uid, loop_uid, 0o600)?;
    let h = make_dir(home_parent, &plan.home, 0o750)?;
    report_dir(&mut reports, &h, &plan.home, caller.0, loop_uid, 0o750)?;
    let ssh_path = plan.home.join(".ssh");
    let ssh = make_dir(&h, &ssh_path, 0o750)?;
    report_dir(&mut reports, &ssh, &ssh_path, caller.0, loop_uid, 0o750)?;
    let routing_path = ssh_path.join("config");
    let file = make_file(&ssh, &routing_path, b"Host *\n  BatchMode yes\n", 0o640)?;
    report_file(
        &mut reports,
        &file,
        &routing_path,
        caller.0,
        loop_uid,
        0o640,
    )?;
    let git_path = plan.home.join(".gitconfig");
    let file = make_file(
        &h,
        &git_path,
        b"[commit]\n\tgpgsign = false\n[user]\n\tname = Lane Worker\n\temail = worker@invalid\n",
        0o640,
    )?;
    report_file(&mut reports, &file, &git_path, caller.0, loop_uid, 0o640)?;
    let codex_path = plan.home.join(".codex");
    let codex = make_dir(&h, &codex_path, 0o700)?;
    report_dir(&mut reports, &codex, &codex_path, worker, worker, 0o700)?;
    for name in ["config.toml", "AGENTS.md"] {
        let path = codex_path.join(name);
        let file = make_file(&codex, &path, b"", 0o600)?;
        report_file(&mut reports, &file, &path, worker, worker, 0o600)?;
    }
    let credential_path = codex_path.join("auth.json");
    let credential = make_file(&codex, &credential_path, b"", 0o600)?;
    report_file(
        &mut reports,
        &credential,
        &credential_path,
        worker,
        worker,
        0o600,
    )?;
    let cache_path = plan.home.join(".cache");
    let cache = make_dir(&h, &cache_path, 0o700)?;
    report_dir(&mut reports, &cache, &cache_path, worker, worker, 0o700)?;
    let work_path = cache_path.join("work");
    let work = make_dir(&cache, &work_path, 0o700)?;
    report_dir(&mut reports, &work, &work_path, worker, worker, 0o700)?;
    let local_path = plan.home.join(".local");
    let local = make_dir(&h, &local_path, 0o750)?;
    report_dir(&mut reports, &local, &local_path, caller.0, loop_uid, 0o750)?;
    for (name, mode, uid, gid) in [
        ("bin", 0o550, caller.0, loop_uid),
        ("door", 0o750, caller.0, loop_uid),
        ("vendor", 0o750, caller.0, loop_uid),
        ("outbox", 0o750, worker, loop_uid),
        ("sources", 0o700, worker, worker),
    ] {
        let path = local_path.join(name);
        let fd = make_dir(&local, &path, mode)?;
        report_dir(&mut reports, &fd, &path, uid, gid, mode)?;
        if name == "sources" {
            *held_sources = Some(nix::unistd::dup(&fd).map_err(|error| reason(&path, error))?);
            make_declared_bares_with(
                &fd,
                &path,
                worker,
                &declared_sources,
                &mut reports,
                make_empty_bare,
            )?;
        }
    }
    let libexec_path = local_path.join("libexec");
    let libexec = make_dir(&local, &libexec_path, 0o750)?;
    report_dir(
        &mut reports,
        &libexec,
        &libexec_path,
        caller.0,
        loop_uid,
        0o750,
    )?;
    let helpers_path = libexec_path.join("superloop");
    let helpers = make_dir(&libexec, &helpers_path, 0o550)?;
    report_dir(
        &mut reports,
        &helpers,
        &helpers_path,
        caller.0,
        loop_uid,
        0o550,
    )?;
    let inbox_path = local_path.join("inbox");
    let inbox = make_dir(&local, &inbox_path, 0o750)?;
    report_dir(&mut reports, &inbox, &inbox_path, caller.0, loop_uid, 0o750)?;
    let file = make_file(&h, &plan.letter, letter_bytes, 0o640)?;
    report_file(&mut reports, &file, &plan.letter, caller.0, loop_uid, 0o640)?;
    reports.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(
        json!({"created": reports, "driver_dir": plan.driver_dir, "home": plan.home, "remaining": "launch must assign loop and worker ownership and bind fixed sources"}),
    )
}

#[cfg(test)]
mod prefix_tests {
    use super::{
        activate_private_launch, bind_private_directory, bind_private_home, bind_socket_directory,
        directory, pin_parent, pin_parent_beneath, read_letter, trusted, verify_host_launch_root,
        verify_host_prefix_from,
    };
    use std::fs;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::FileExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::process::Command;

    /// ´test:unit:second-source-creation-failure-cleans-every-created-bare´
    #[test]
    fn second_source_creation_failure_cleans_every_created_bare() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("sources");
        fs::create_dir(&root).expect("sources root");
        let parent = nix::fcntl::open(
            &root,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("held sources descriptor");
        let declarations = [
            crate::launch::DeclaredSource {
                name: "one".into(),
                seed: None,
            },
            crate::launch::DeclaredSource {
                name: "two".into(),
                seed: None,
            },
        ];
        let mut reports = Vec::new();
        let mut count = 0;
        let failure = super::make_declared_bares_with(
            &parent,
            &root,
            nix::unistd::Uid::effective().as_raw(),
            &declarations,
            &mut reports,
            |parent, path, worker, reports| {
                count += 1;
                super::make_empty_bare_with(parent, path, worker, reports, |_| {
                    if count == 2 {
                        return Err(crate::error::LaneError::operation(
                            "fixture-create",
                            "second bare failed after its root was created",
                        ));
                    }
                    Ok(())
                })
            },
        )
        .expect_err("second creation refuses");
        assert_eq!(failure.kind, "source-seed-create");
        assert!(failure.detail.contains("two"), "{}", failure.line());
        assert!(
            failure.detail.contains("fixture-create"),
            "{}",
            failure.line()
        );
        assert!(!root.join("one.git").exists());
        assert!(!root.join("two.git").exists());
    }

    /// ´test:unit:failed-bare-cleanup-retains-the-creation-refusal´
    #[test]
    fn failed_bare_cleanup_retains_the_creation_refusal() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("sources");
        fs::create_dir(&root).expect("sources root");
        let parent = nix::fcntl::open(
            &root,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("held sources descriptor");
        let declarations = [
            crate::launch::DeclaredSource {
                name: "one".into(),
                seed: None,
            },
            crate::launch::DeclaredSource {
                name: "two".into(),
                seed: None,
            },
        ];
        let mut count = 0;
        let failure = super::make_declared_bares_with(
            &parent,
            &root,
            nix::unistd::Uid::effective().as_raw(),
            &declarations,
            &mut Vec::new(),
            |_, path, _, _| {
                count += 1;
                if count == 1 {
                    std::os::unix::fs::symlink("outside", path).expect("unremovable source entry");
                    Ok(())
                } else {
                    Err(crate::error::LaneError::operation(
                        "fixture-create",
                        "two failed",
                    ))
                }
            },
        )
        .expect_err("cleanup refuses a symlink");
        assert_eq!(failure.kind, "source-seed-cleanup");
        assert_eq!(failure.status, 2);
        assert!(
            failure.detail.starts_with("sources: "),
            "{}",
            failure.line()
        );
        assert!(failure.detail.contains("one.git"), "{}", failure.line());
        assert!(failure.detail.contains("two"), "{}", failure.line());
        assert!(
            failure.detail.contains("fixture-create"),
            "{}",
            failure.line()
        );
        assert!(root.join("one.git").is_symlink());
    }

    /// ´test:unit:declared-bare-accepts-ordinary-local-git-push´
    #[test]
    fn declared_bare_accepts_ordinary_local_git_push() {
        let fixture = tempfile::tempdir().expect("fixture");
        let sources = fixture.path().join("sources");
        fs::create_dir(&sources).expect("sources");
        let source_fd = nix::fcntl::open(
            &sources,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("sources descriptor");
        let bare = sources.join("tools.git");
        let uid = nix::unistd::Uid::effective().as_raw();
        super::make_empty_bare(&source_fd, &bare, uid, &mut Vec::new()).expect("empty bare");
        let work = fixture.path().join("work");
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .arg(&work)
                .status()
                .expect("init")
                .success()
        );
        fs::write(work.join("note"), b"checkpoint\n").expect("work file");
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .args(["add", "note"])
                .status()
                .expect("add")
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .args([
                    "-c",
                    "user.name=Worker",
                    "-c",
                    "user.email=worker@invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "checkpoint"
                ])
                .status()
                .expect("commit")
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&work)
                .arg("push")
                .arg(&bare)
                .arg("HEAD:refs/heads/lane/R")
                .status()
                .expect("push")
                .success()
        );
        let object = Command::new("git")
            .arg(format!("--git-dir={}", bare.display()))
            .args(["rev-parse", "refs/heads/lane/R"])
            .output()
            .expect("ref");
        assert!(object.status.success());
        assert_eq!(
            String::from_utf8(object.stdout)
                .expect("object")
                .trim()
                .len(),
            40
        );
    }

    /// ´test:unit:private-rotation-source-keeps-the-transferred-inode-after-replacement´
    #[test]
    fn private_rotation_source_keeps_the_transferred_inode_after_replacement() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        let sources = fixture.path().join("sources");
        for directory in [&home, &runs, &sources] {
            fs::create_dir(directory).expect("directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let source = sources.join("handover.md");
        fs::write(&source, b"First letter.\n").expect("first letter");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("source mode");
        let held = fs::File::open(&source).expect("source descriptor");
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let owner = nix::unistd::Uid::effective().as_raw();
        let _private = activate_private_launch(&home, &home_fd, &runs, &runs_fd, None, owner)
            .expect("private anchors");
        super::attach_private_rotation_source(&held, owner).expect("source handoff");
        let replacement = sources.join("replacement.md");
        fs::write(&replacement, b"Different letter.\n").expect("replacement");
        fs::rename(replacement, &source).expect("replace name");
        let inherited = super::private_rotation_source().expect("inherited source");
        let file = fs::File::from(inherited);
        let mut bytes = [0_u8; 14];
        assert_eq!(file.read_at(&mut bytes, 0).expect("read pinned"), 14);
        assert_eq!(&bytes, b"First letter.\n");
    }

    /// ´test:unit:loop-round-owner-refuses-a-foreign-component´
    #[test]
    fn loop_round_owner_refuses_a_foreign_component() {
        super::loop_round_owner(41001, 0o755, 41001, std::path::Path::new("~/runs/R"))
            .expect("loop-owned component");
        let error = super::loop_round_owner(
            3000,
            0o755,
            41001,
            std::path::Path::new("~/runs/R/steps/review"),
        )
        .expect_err("foreign-owned component");
        assert_eq!(error.kind, "unsafe-path");
        assert!(error.detail.contains("uid 3000"));
        assert!(error.detail.contains("expected uid 41001"));
    }

    /// ´test:unit:private-follow-walk-uses-two-synthetic-uids´
    #[test]
    fn private_follow_walk_uses_two_synthetic_uids() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let runs = fixture.path().join("runs");
        let step = runs.join("R/steps/review");
        fs::create_dir_all(&step).expect("round chain");
        let home = fixture.path().join("home");
        fs::create_dir(&home).expect("private home");
        for directory in [fixture.path(), home.as_path(), runs.as_path()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private directory mode");
        }
        let namespace_owner = nix::unistd::Uid::effective().as_raw();
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = fs::File::open(&runs).expect("runs descriptor");
        let _private =
            activate_private_launch(&home, &home_fd, &runs, &runs_fd, None, namespace_owner)
                .expect("private entry anchors");
        let pinned = super::pin_loop_round_with(&runs, &step, namespace_owner, 41001, |_, _| {
            Ok((41001, 0o755))
        })
        .expect("loop-owned chain is pinned");
        assert_eq!(
            nix::sys::stat::fstat(&pinned).expect("pinned step").st_ino,
            fs::metadata(&step).expect("step metadata").ino()
        );
        let error = super::pin_loop_round_with(&runs, &step, namespace_owner, 41001, |_, path| {
            Ok((if path.ends_with("steps") { 3000 } else { 41001 }, 0o755))
        })
        .expect_err("foreign-owned middle component refuses");
        assert_eq!(error.kind, "unsafe-path");
        assert!(error.detail.contains("uid 3000"));
        assert!(error.detail.contains("expected uid 41001"));
    }

    /// ´test:unit:helper-runs-root-handoff-checks-identity-and-descriptor-type´
    #[test]
    fn helper_runs_root_handoff_checks_identity_and_descriptor_type() {
        let fixture = tempfile::TempDir::new().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        let other = fixture.path().join("other");
        for path in [&home, &runs, &other] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let wrong = fs::File::open(&other).expect("wrong runs descriptor");
        let error = activate_private_launch(&home, &home_fd, &runs, &wrong, None, owner)
            .err()
            .expect("different runs root refused");
        assert_eq!(error.kind, "socket-dir-handoff");
        assert!(error.detail.contains("expected"));
        assert!(error.detail.contains("received"));
        let regular = fixture.path().join("regular");
        fs::write(&regular, b"synthetic").expect("regular file");
        let file = fs::File::open(&regular).expect("regular descriptor");
        assert_eq!(
            bind_socket_directory(&runs, &runs, file.as_raw_fd(), owner)
                .expect_err("non-directory refused")
                .kind,
            "socket-dir-handoff"
        );
        let closed = file.as_raw_fd();
        drop(file);
        assert_eq!(
            bind_socket_directory(&runs, &runs, closed, owner)
                .expect_err("closed descriptor refused")
                .kind,
            "socket-dir-handoff"
        );
        let matching = fs::File::open(&runs).expect("matching runs descriptor");
        let _guard = activate_private_launch(&home, &home_fd, &runs, &matching, None, owner)
            .expect("matching runs root accepted");
    }

    /// ´test:unit:private-launch-uses-external-runs-and-letter-anchors´
    #[test]
    fn private_launch_uses_external_runs_and_letter_anchors() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("host ancestor mode");
        let home = fixture.path().join("home");
        let runs = fixture.path().join("runs");
        let letters = fixture.path().join("letters");
        for path in [&home, &runs, &letters] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let run = runs.join("R");
        fs::create_dir(&run).expect("driver directory");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("driver mode");
        let letter = letters.join("first.md");
        fs::write(&letter, b"first letter").expect("letter");
        let home_fd = fs::File::open(&home).expect("home descriptor");
        let runs_fd = verify_host_launch_root(fixture.path(), &home, &runs, owner, owner)
            .expect("outside runs root checked by host owner");
        let letter_fd = verify_host_launch_root(fixture.path(), &home, &letters, owner, owner)
            .expect("outside letter directory checked by host owner");
        let _guard = activate_private_launch(
            &home,
            &home_fd,
            &runs,
            &runs_fd,
            Some((&letters, &letter_fd)),
            owner,
        )
        .expect("bound private anchors");
        let pinned = pin_parent(&run, owner).expect("changing run pins external root");
        assert_eq!(
            nix::sys::stat::fstat(&pinned).expect("driver inode").st_ino,
            fs::metadata(&run).expect("driver metadata").ino()
        );
        assert_eq!(
            read_letter(&letter, owner).expect("external letter"),
            b"first letter"
        );
    }

    /// ´test:unit:private-launch-refuses-mismatched-external-anchors´
    #[test]
    fn private_launch_refuses_mismatched_external_anchors() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let runs = fixture.path().join("runs");
        let other = fixture.path().join("other");
        for path in [&runs, &other] {
            fs::create_dir(path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let other_fd = fs::File::open(&other).expect("wrong descriptor");
        assert_eq!(
            bind_private_directory(&runs, &other_fd, owner, "runs root")
                .expect_err("mismatched runs descriptor")
                .kind,
            "verified-prefix"
        );
        assert_eq!(
            bind_private_directory(&runs, &other_fd, owner, "letter directory")
                .expect_err("mismatched letter descriptor")
                .kind,
            "verified-prefix"
        );
    }

    /// ´test:unit:host-prefix-refuses-group-writable-ancestor´
    #[test]
    fn host_prefix_refuses_group_writable_ancestor() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let ancestor = fixture.path().join("var");
        fs::create_dir(&ancestor).expect("ancestor");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o770))
            .expect("group writable ancestor");
        let home = ancestor.join("home");
        fs::create_dir(&home).expect("home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let error = verify_host_prefix_from(fixture.path(), &home, owner, owner)
            .expect_err("group writable ancestor");
        assert_eq!(error.kind, "unsafe-path");
        assert!(error.detail.contains("host ancestor"));
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o750)).expect("safe ancestor");
        verify_host_prefix_from(fixture.path(), &home, owner, owner)
            .expect("protected host prefix");
    }

    /// ´test:unit:pin-parent-refuses-overflow-root-without-anchor´
    #[test]
    fn pin_parent_refuses_overflow_root_without_anchor() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let refusal = super::with_fixture_root_identity(65_534, || {
            pin_parent(fixture.path(), owner).expect_err("overflow root must refuse")
        });
        assert_eq!(refusal.kind, "unsafe-path");
        assert!(
            refusal.detail.contains("/: replaceable ancestor uid 65534"),
            "{}",
            refusal.detail
        );
    }

    /// ´test:unit:bind-private-home-refuses-overflow-root-without-anchor´
    #[test]
    fn bind_private_home_refuses_overflow_root_without_anchor() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let inherited = fs::File::open(fixture.path()).expect("held home");
        let refusal = super::with_fixture_root_identity(65_534, || {
            bind_private_home(fixture.path(), &inherited, owner)
                .expect_err("overflow root must refuse unanchored home")
        });
        assert_eq!(refusal.kind, "unsafe-path");
        assert!(
            refusal.detail.contains("/: host ancestor uid 65534"),
            "{}",
            refusal.detail
        );
    }

    /// ´test:unit:private-prefix-skips-overflow-ancestors-above-home´
    #[test]
    fn private_prefix_skips_overflow_ancestors_above_home() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let config = home.join(".config");
        let loops = config.join("loops");
        let settings = loops.join("alpha");
        fs::create_dir_all(&settings).expect("settings tree");
        for path in [
            fixture.path(),
            home.as_path(),
            config.as_path(),
            loops.as_path(),
            settings.as_path(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let ancestor = nix::fcntl::open(
            fixture.path(),
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("ancestor descriptor");
        let mut overflow = directory(&ancestor, fixture.path()).expect("ancestor stat");
        overflow.st_uid = 65_534;
        let home_fd = nix::fcntl::open(
            &home,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("home descriptor");
        let home_stat = directory(&home_fd, &home).expect("home stat");
        assert_eq!(
            trusted(&overflow, &home_stat, fixture.path(), owner)
                .expect_err("old root walk sees overflow uid")
                .kind,
            "unsafe-path"
        );
        pin_parent_beneath(&settings, &home, owner).expect("private walk starts at verified home");
        fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o770))
            .expect("replaceable descendant");
        assert_eq!(
            pin_parent_beneath(&settings, &home, owner)
                .expect_err("descendant remains checked")
                .kind,
            "unsafe-path"
        );
    }

    /// ´test:unit:private-prefix-refuses-a-different-inherited-inode´
    #[test]
    fn private_prefix_refuses_a_different_inherited_inode() {
        let fixture = tempfile::TempDir::new().expect("fixture root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let home = fixture.path().join("home");
        let other = fixture.path().join("other");
        fs::create_dir(&home).expect("home");
        fs::create_dir(&other).expect("other");
        for path in [&home, &other] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private mode");
        }
        let other_fd = fs::File::open(&other).expect("other descriptor");
        assert_eq!(
            bind_private_home(&home, &other_fd, owner)
                .expect_err("different descriptor")
                .kind,
            "verified-prefix"
        );
        let home_fd = fs::File::open(&home).expect("home descriptor");
        bind_private_home(&home, &home_fd, owner).expect("matching descriptor");
    }
}
