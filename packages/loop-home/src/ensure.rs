//! Descriptor-pinned creation and checking of the standard loop roots.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fstat, mkdirat};
use nix::unistd::{Gid, Uid, fchownat};

use crate::registry::validate_name;

#[cfg(test)]
thread_local! {
    pub(crate) static OBSERVED_GROUP: std::cell::Cell<Option<(u64, u64, u32)>> = const { std::cell::Cell::new(None) };
    static SYSCALL_COUNTS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
    static DENY_INSPECTION_NOATIME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PREPARE_TRACE: std::cell::RefCell<Option<Vec<(String, PathBuf)>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn begin_prepare_trace() {
    PREPARE_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
}

#[cfg(test)]
pub(crate) fn end_prepare_trace() -> Vec<(String, PathBuf)> {
    PREPARE_TRACE.with(|trace| trace.borrow_mut().take().expect("prepare trace was begun"))
}

#[cfg(test)]
fn trace_prepare(operation: &str, path: &Path) {
    PREPARE_TRACE.with(|trace| {
        if let Some(events) = trace.borrow_mut().as_mut() {
            events.push((operation.to_owned(), path.to_path_buf()));
        }
    });
}

#[cfg(test)]
pub(crate) fn deny_inspection_noatime(denied: bool) {
    DENY_INSPECTION_NOATIME.with(|value| value.set(denied));
}

#[cfg(test)]
pub(crate) fn reset_syscall_counts() {
    SYSCALL_COUNTS.with(|counts| counts.set((0, 0)));
}

#[cfg(test)]
pub(crate) fn syscall_counts() -> (usize, usize) {
    SYSCALL_COUNTS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn count_open() {
    SYSCALL_COUNTS.with(|counts| {
        let (opens, stats) = counts.get();
        counts.set((opens + 1, stats));
    });
}

#[cfg(test)]
fn count_stat() {
    SYSCALL_COUNTS.with(|counts| {
        let (opens, stats) = counts.get();
        counts.set((opens, stats + 1));
    });
}

const USAGE: &str = "usage: superloop ensure-roots UID NAME HOME REPORT";

/// The principal expected to own a standard root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootOwner {
    /// The caller, represented by namespace root in the private step.
    Owner,
    /// Owner-published policy readable by the loop's primary group.
    Policy,
    /// The loop's subordinate uid.
    Loop,
    /// Loop-owned directory traversed using the correspondence group.
    Shared(u32),
}

/// How the ensure step treats an absent row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnsureClass {
    /// Create an absent row and check an existing row.
    Created,
    /// Require the class root, but never create or change it.
    Checked,
    /// Check and correct when present, but never create it.
    WhenPresent,
    /// Create an absent child only when its optional parent already exists.
    CreatedWhenParentPresent,
}

/// One row of the estate layout's loop roots table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardRoot {
    /// Absolute path derived from the caller's home and loop name.
    pub path: PathBuf,
    /// Principal that owns the directory.
    pub owner: RootOwner,
    /// Required mode, written as an octal permission value.
    pub mode: u32,
    /// Creation and checking policy.
    pub ensure: EnsureClass,
}

/// Number of rows created and corrected by one step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnsureCounts {
    /// Rows made by this invocation.
    pub created: usize,
    /// Existing rows whose mode was corrected.
    pub corrected: usize,
}

/// A named path and the reason the step refused it.
#[derive(Debug, PartialEq, Eq)]
pub struct EnsureFailure {
    /// The path refused.
    pub path: PathBuf,
    /// What was found or which operating-system operation failed.
    pub reason: String,
}

impl fmt::Display for EnsureFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ensure refused: {}: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for EnsureFailure {}

fn refused(path: &Path, reason: impl Into<String>) -> EnsureFailure {
    EnsureFailure {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// Derive the table rows in table order; absent custody rows remain optional.
#[must_use]
pub fn standard_roots(caller_home: &Path, name: &str) -> Vec<StandardRoot> {
    use EnsureClass::{Checked, Created, CreatedWhenParentPresent, WhenPresent};
    use RootOwner::{Loop, Owner};

    let var = caller_home.join(".var");
    let cache = caller_home.join(".cache");
    let durable = var.join("loops");
    let loop_home = durable.join(name);
    let private = loop_home.join("private");
    let custody = caller_home.join(".config/loops");
    let custody_home = custody.join(name);
    let cache_partition = cache.join("loops");
    let loop_cache = cache_partition.join(name);
    let rows = [
        (var, Owner, 0o711, Checked),
        (cache, Owner, 0o711, Checked),
        (durable, Owner, 0o711, Created),
        (loop_home.clone(), Owner, 0o711, Created),
        (private.clone(), Loop, 0o700, Created),
        (private.join(".run"), Loop, 0o700, Created),
        (private.join(".config"), Loop, 0o700, Created),
        (private.join(".config/custody"), Loop, 0o700, Created),
        (private.join(".ssh"), Loop, 0o700, Created),
        (private.join(".local"), Loop, 0o700, Created),
        (private.join(".local/bin"), Loop, 0o700, Created),
        (private.join(".local/share"), Loop, 0o700, Created),
        (private.join(".local/state"), Loop, 0o700, Created),
        (loop_home.join("shared"), Loop, 0o750, Created),
        (loop_home.join("src"), Loop, 0o700, Created),
        (loop_home.join("direct"), Loop, 0o700, Created),
        (loop_home.join("policy"), RootOwner::Policy, 0o2750, Created),
        (loop_home.join("runs"), Owner, 0o711, Created),
        (custody, Owner, 0o700, Created),
        (custody_home.clone(), Owner, 0o700, Created),
        (custody_home.join("lanes"), Owner, 0o700, Created),
        (custody_home.join("lanes/keys"), Owner, 0o700, Created),
        (custody_home.join("private"), Loop, 0o700, WhenPresent),
        (custody_home.join("private/ssh"), Loop, 0o700, WhenPresent),
        (custody_home.join("private/gpg"), Loop, 0o700, WhenPresent),
        (
            custody_home.join("private/gh"),
            Loop,
            0o700,
            CreatedWhenParentPresent,
        ),
        (cache_partition, Owner, 0o711, Created),
        (loop_cache.clone(), Loop, 0o700, Created),
        (loop_cache.join("tmp"), Loop, 0o700, Created),
    ];
    rows.into_iter()
        .map(|(path, owner, mode, ensure)| StandardRoot {
            path,
            owner,
            mode,
            ensure,
        })
        .collect()
}

fn path_flags(readable: bool) -> OFlag {
    let access = if readable {
        OFlag::O_RDONLY
    } else {
        OFlag::O_PATH
    };
    access | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC
}

#[derive(Clone, Copy)]
struct StatInfo {
    uid: u32,
    gid: u32,
    mode: u32,
}

fn stat_info(fd: &OwnedFd, path: &Path) -> Result<StatInfo, EnsureFailure> {
    #[cfg(test)]
    count_stat();
    #[cfg(test)]
    trace_prepare("fstat", path);
    let stat = fstat(fd).map_err(|error| refused(path, error.to_string()))?;
    #[cfg(test)]
    let stat = {
        let mut stat = stat;
        OBSERVED_GROUP.with(|observed| {
            if let Some((device, inode, gid)) = observed.get()
                && (stat.st_dev, stat.st_ino) == (device, inode)
            {
                stat.st_gid = gid;
            }
        });
        stat
    };
    Ok(StatInfo {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode,
    })
}

fn open_class(path: &Path) -> Result<(OwnedFd, StatInfo), EnsureFailure> {
    #[cfg(test)]
    trace_prepare("open O_PATH|O_CLOEXEC|O_NOFOLLOW", path);
    let fd = open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| refused(path, open_reason(error)))?;
    #[cfg(test)]
    count_open();
    let stat = stat_info(&fd, path)?;
    match SFlag::from_bits_truncate(stat.mode) & SFlag::S_IFMT {
        SFlag::S_IFDIR => Ok((fd, stat)),
        SFlag::S_IFLNK => Err(refused(path, "a symbolic link")),
        _ => Err(refused(path, "not a directory")),
    }
}

fn open_reason(error: Errno) -> String {
    match error {
        Errno::ELOOP => String::from("a symbolic link"),
        Errno::ENOTDIR => String::from("not a directory"),
        _ => error.to_string(),
    }
}

fn beneath(parent: &OwnedFd, path: &Path, readable: bool) -> Result<OwnedFd, Errno> {
    #[cfg(test)]
    trace_prepare(
        if readable {
            "openat2 O_RDONLY"
        } else {
            "openat2 O_PATH"
        },
        path,
    );
    let name = path.file_name().ok_or(Errno::EINVAL)?;
    let how = OpenHow::new()
        .flags(path_flags(readable))
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    let fd = openat2(parent, name, how)?;
    #[cfg(test)]
    count_open();
    Ok(fd)
}

fn beneath_inspect(
    parent: &OwnedFd,
    path: &Path,
    readable: bool,
) -> Result<(OwnedFd, bool), Errno> {
    if !readable {
        return beneath(parent, path, false).map(|fd| (fd, false));
    }
    let name = path.file_name().ok_or(Errno::EINVAL)?;
    let how = OpenHow::new()
        .flags(path_flags(true) | OFlag::O_NOATIME)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    #[cfg(test)]
    let forced_denial = DENY_INSPECTION_NOATIME.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let forced_denial = false;
    let opened = if forced_denial {
        Err(Errno::EPERM)
    } else {
        openat2(parent, name, how)
    };
    match opened {
        Ok(fd) => {
            #[cfg(test)]
            count_open();
            Ok((fd, false))
        }
        Err(Errno::EPERM | Errno::EACCES) => beneath(parent, path, true).map(|fd| (fd, true)),
        Err(error) => Err(error),
    }
}

fn check(
    stat: StatInfo,
    row: &StandardRoot,
    owner: (u32, u32),
    loop_id: (u32, u32),
) -> Result<u32, EnsureFailure> {
    match decision(Some(stat), row, owner, loop_id) {
        RootAction::Refuse(reason) => Err(refused(&row.path, reason)),
        _ => Ok(stat.mode & 0o7777),
    }
}

fn decision(
    stat: Option<StatInfo>,
    row: &StandardRoot,
    owner: (u32, u32),
    loop_id: (u32, u32),
) -> RootAction {
    let Some(stat) = stat else {
        return if matches!(
            row.ensure,
            EnsureClass::Created | EnsureClass::CreatedWhenParentPresent
        ) {
            RootAction::Create
        } else {
            RootAction::Nothing
        };
    };
    if SFlag::from_bits_truncate(stat.mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return RootAction::Refuse(String::from("not a directory"));
    }
    let expected = match row.owner {
        RootOwner::Owner => owner,
        RootOwner::Policy => (owner.0, loop_id.1),
        RootOwner::Loop => loop_id,
        RootOwner::Shared(gid) => (loop_id.0, gid),
    };
    if stat.uid != expected.0 {
        return RootAction::Refuse(format!(
            "owned by uid {}, expected uid {}",
            stat.uid, expected.0
        ));
    }
    if stat.gid != expected.1 {
        if matches!(row.owner, RootOwner::Shared(_)) && stat.gid == loop_id.1 {
            return RootAction::Correct;
        }
        return RootAction::Refuse(format!(
            "owned by gid {}, expected gid {}",
            stat.gid, expected.1
        ));
    }
    let mode = stat.mode & 0o7777;
    if row.ensure == EnsureClass::Checked && mode & 0o001 == 0 {
        return RootAction::Refuse(format!("mode {mode:04o}, no search permission for others"));
    }
    if row.ensure == EnsureClass::Checked && row.path.ends_with(".var") && mode & 0o022 != 0 {
        return RootAction::Refuse(format!("mode {mode:04o}, group or other write permission"));
    }
    if row.ensure != EnsureClass::Checked && mode != row.mode {
        RootAction::Correct
    } else {
        RootAction::Nothing
    }
}

fn config_decision(stat: StatInfo, path: &Path, owner: (u32, u32)) -> RootAction {
    let declaration = StandardRoot {
        path: path.to_path_buf(),
        owner: RootOwner::Owner,
        mode: stat.mode & 0o7777,
        ensure: EnsureClass::WhenPresent,
    };
    decision(Some(stat), &declaration, owner, owner)
}

#[allow(unsafe_code)]
fn chmod(fd: &OwnedFd, path: &Path, mode: u32) -> Result<(), EnsureFailure> {
    // SAFETY: the descriptor is held open, the empty path is NUL terminated, and Linux
    // fchmodat2 applies AT_EMPTY_PATH to that descriptor rather than resolving a path.
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
        Err(refused(path, io::Error::last_os_error().to_string()))
    } else {
        Ok(())
    }
}

fn created_row(
    row: &StandardRoot,
    parent: &OwnedFd,
    owner: (u32, u32),
    loop_id: (u32, u32),
) -> Result<(OwnedFd, bool), EnsureFailure> {
    let name = row
        .path
        .file_name()
        .ok_or_else(|| refused(&row.path, "no final component"))?;
    let made = match mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
        Ok(()) => true,
        Err(Errno::EEXIST) => false,
        Err(error) => return Err(refused(&row.path, error.to_string())),
    };
    let readable = row
        .path
        .parent()
        .is_some_and(|path| path.ends_with(".var/loops"));
    let fd = beneath(parent, &row.path, readable)
        .map_err(|error| refused(&row.path, open_reason(error)))?;
    if made {
        let stat = stat_info(&fd, &row.path)?;
        if SFlag::from_bits_truncate(stat.mode) & SFlag::S_IFMT != SFlag::S_IFDIR
            || stat.mode & 0o7777 != 0o700
            || stat.uid != owner.0
            || stat.gid != owner.1
        {
            return Err(refused(
                &row.path,
                "new directory is not owned by namespace root at mode 0700",
            ));
        }
        let expected = match row.owner {
            RootOwner::Owner => owner,
            RootOwner::Policy => (owner.0, loop_id.1),
            RootOwner::Loop => loop_id,
            RootOwner::Shared(gid) => (loop_id.0, gid),
        };
        fchownat(
            &fd,
            "",
            Some(Uid::from_raw(expected.0)),
            Some(Gid::from_raw(expected.1)),
            AtFlags::AT_EMPTY_PATH,
        )
        .map_err(|error| refused(&row.path, error.to_string()))?;
    } else {
        check(stat_info(&fd, &row.path)?, row, owner, loop_id)?;
    }
    Ok((fd, made))
}

#[allow(unsafe_code)]
fn refuse_root_entries_inspect(fd: &OwnedFd, path: &Path) -> Result<(), EnsureFailure> {
    use std::os::fd::IntoRawFd as _;

    // SAFETY: fdopendir owns the duplicate, closedir releases it, and readdir's
    // returned entry is used only before the next call or closedir.
    unsafe {
        let duplicate = nix::unistd::dup(fd).map_err(|error| refused(path, error.to_string()))?;
        let raw = duplicate.into_raw_fd();
        let directory = libc::fdopendir(raw);
        if directory.is_null() {
            let error = io::Error::last_os_error();
            libc::close(raw);
            return Err(refused(path, error.to_string()));
        }
        loop {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(directory);
            if entry.is_null() {
                let error = io::Error::last_os_error();
                libc::closedir(directory);
                return if error.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(refused(path, error.to_string()))
                };
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr());
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                libc::closedir(directory);
                return Err(refused(path, "holds entries without private/"));
            }
        }
    }
}

fn refuse_root_entries(fd: &OwnedFd, path: &Path) -> Result<(), EnsureFailure> {
    #[cfg(test)]
    trace_prepare("read_dir /proc/self/fd", path);
    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|error| refused(path, error.to_string()))?;
    if entries.into_iter().next().is_some() {
        Err(refused(path, "holds entries without private/"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootAction {
    Nothing,
    Create,
    Correct,
    Refuse(String),
    Unseen(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootObservation {
    pub path: PathBuf,
    pub kind: &'static str,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub action: RootAction,
    pub atime_may_have_changed: bool,
}

impl RootObservation {
    fn from_stat(path: PathBuf, stat: StatInfo, action: RootAction) -> Self {
        let kind = match SFlag::from_bits_truncate(stat.mode) & SFlag::S_IFMT {
            SFlag::S_IFDIR => "directory",
            SFlag::S_IFLNK => "symlink",
            SFlag::S_IFREG => "file",
            _ => "other",
        };
        Self {
            path,
            kind,
            uid: Some(stat.uid),
            gid: Some(stat.gid),
            mode: Some(stat.mode & 0o7777),
            action,
            atime_may_have_changed: false,
        }
    }

    const fn missing(path: PathBuf, action: RootAction) -> Self {
        Self {
            path,
            kind: "missing",
            uid: None,
            gid: None,
            mode: None,
            action,
            atime_may_have_changed: false,
        }
    }

    const fn unseen(path: PathBuf, reason: String) -> Self {
        Self {
            path,
            kind: "unseen",
            uid: None,
            gid: None,
            mode: None,
            action: RootAction::Unseen(reason),
            atime_may_have_changed: false,
        }
    }
}

pub(crate) struct RootInspection {
    pub observations: Vec<RootObservation>,
}

impl RootInspection {
    pub fn status(&self) -> u8 {
        if self
            .observations
            .iter()
            .any(|row| matches!(row.action, RootAction::Refuse(_) | RootAction::Unseen(_)))
        {
            4
        } else if self
            .observations
            .iter()
            .any(|row| matches!(row.action, RootAction::Create | RootAction::Correct))
        {
            3
        } else {
            0
        }
    }

    pub fn would_counts(&self) -> EnsureCounts {
        EnsureCounts {
            created: self
                .observations
                .iter()
                .filter(|row| row.action == RootAction::Create)
                .count(),
            corrected: self
                .observations
                .iter()
                .filter(|row| row.action == RootAction::Correct)
                .count(),
        }
    }

    pub fn to_json(&self) -> String {
        use crate::verify::push_json_string;

        let mut output = String::from("[");
        for (index, row) in self.observations.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str("{\"action\":");
            let (action, reason) = match &row.action {
                RootAction::Nothing => ("nothing", None),
                RootAction::Create => ("create", None),
                RootAction::Correct => ("correct", None),
                RootAction::Refuse(reason) => ("refuse", Some(reason)),
                RootAction::Unseen(reason) => ("unseen", Some(reason)),
            };
            push_json_string(&mut output, action);
            let _written = write!(
                &mut output,
                ",\"atime_may_have_changed\":{}",
                row.atime_may_have_changed
            );
            output.push_str(",\"gid\":");
            if let Some(gid) = row.gid {
                let _written = write!(&mut output, "{gid}");
            } else {
                output.push_str("null");
            }
            output.push_str(",\"kind\":");
            push_json_string(&mut output, row.kind);
            output.push_str(",\"mode\":");
            if let Some(mode) = row.mode {
                push_json_string(&mut output, &format!("{mode:04o}"));
            } else {
                output.push_str("null");
            }
            output.push_str(",\"path\":");
            push_json_string(&mut output, &row.path.to_string_lossy());
            if let Some(reason) = reason {
                output.push_str(",\"reason\":");
                push_json_string(&mut output, reason);
            }
            output.push_str(",\"uid\":");
            if let Some(uid) = row.uid {
                let _written = write!(&mut output, "{uid}");
            } else {
                output.push_str("null");
            }
            output.push('}');
        }
        output.push(']');
        output
    }
}

fn failed_observation(path: &Path, failure: EnsureFailure) -> RootObservation {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => RootObservation::from_stat(
            path.to_path_buf(),
            StatInfo {
                uid: std::os::unix::fs::MetadataExt::uid(&metadata),
                gid: std::os::unix::fs::MetadataExt::gid(&metadata),
                mode: std::os::unix::fs::MetadataExt::mode(&metadata),
            },
            RootAction::Refuse(failure.reason),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            RootObservation::missing(path.to_path_buf(), RootAction::Refuse(failure.reason))
        }
        Err(_) => RootObservation::unseen(path.to_path_buf(), failure.reason),
    }
}

/// Inspect declared rows independently of the preparing walk.
#[must_use]
#[allow(clippy::too_many_lines)]
pub(crate) fn inspect_roots(
    rows: &[StandardRoot],
    owner: (u32, u32),
    loop_id: (u32, u32),
) -> RootInspection {
    let mut opened = BTreeMap::<PathBuf, OwnedFd>::new();
    let mut observations = Vec::with_capacity(rows.len() + 1);
    let home = rows.first().and_then(|row| row.path.parent());
    let config = home.map(|path| path.join(".config"));
    for row in rows.iter().filter(|row| row.ensure == EnsureClass::Checked) {
        match open_class(&row.path) {
            Ok((fd, stat)) => {
                let action = decision(Some(stat), row, owner, loop_id);
                observations.push(RootObservation::from_stat(row.path.clone(), stat, action));
                opened.insert(row.path.clone(), fd);
            }
            Err(failure) => {
                observations.push(failed_observation(&row.path, failure));
            }
        }
    }
    if let Some(config) = &config {
        match open_class(config) {
            Ok((fd, stat)) => {
                let action = config_decision(stat, config, owner);
                observations.push(RootObservation::from_stat(config.clone(), stat, action));
                opened.insert(config.clone(), fd);
            }
            Err(failure) => {
                observations.push(failed_observation(config, failure));
            }
        }
    }
    for row in rows {
        if row.ensure == EnsureClass::Checked {
            continue;
        }
        let Some(parent_path) = row.path.parent() else {
            observations.push(RootObservation::unseen(
                row.path.clone(),
                String::from("no parent"),
            ));
            continue;
        };
        let Some(parent) = opened.get(parent_path) else {
            let parent_missing = observations.iter().any(|seen| {
                seen.path == parent_path
                    && seen.kind == "missing"
                    && matches!(seen.action, RootAction::Create | RootAction::Nothing)
            });
            let action = if row.ensure == EnsureClass::CreatedWhenParentPresent {
                RootAction::Nothing
            } else {
                decision(None, row, owner, loop_id)
            };
            if parent_missing {
                observations.push(RootObservation::missing(row.path.clone(), action));
            } else {
                observations.push(RootObservation::unseen(
                    row.path.clone(),
                    format!("parent {} cannot be inspected", parent_path.display()),
                ));
            }
            continue;
        };
        let readable = parent_path.ends_with(".var/loops");
        match beneath_inspect(parent, &row.path, readable) {
            Ok((fd, atime_may_have_changed)) => match stat_info(&fd, &row.path) {
                Ok(stat) => {
                    let action = decision(Some(stat), row, owner, loop_id);
                    let mut observation =
                        RootObservation::from_stat(row.path.clone(), stat, action);
                    observation.atime_may_have_changed = atime_may_have_changed;
                    observations.push(observation);
                    opened.insert(row.path.clone(), fd);
                }
                Err(failure) => {
                    let mut observation = failed_observation(&row.path, failure);
                    observation.atime_may_have_changed = atime_may_have_changed;
                    observations.push(observation);
                }
            },
            Err(Errno::ENOENT) => {
                let action = decision(None, row, owner, loop_id);
                observations.push(RootObservation::missing(row.path.clone(), action));
            }
            Err(error) => {
                let failure = refused(&row.path, open_reason(error));
                observations.push(failed_observation(&row.path, failure));
            }
        }
    }
    if let (Some(loop_row), Some(private_row)) = (rows.get(3), rows.get(4))
        && let Some(fd) = opened.get(&loop_row.path)
        && !opened.contains_key(&private_row.path)
        && let Err(failure) = refuse_root_entries_inspect(fd, &loop_row.path)
        && let Some(observation) = observations
            .iter_mut()
            .find(|row| row.path == loop_row.path)
    {
        observation.action = RootAction::Refuse(failure.reason);
    }
    RootInspection { observations }
}

/// Open and check all existing rows, then create missing rows and correct modes.
///
/// # Errors
///
/// Returns one named refusal when a row or an operating-system operation fails.
#[allow(clippy::too_many_lines)]
pub fn ensure_roots<W: io::Write>(
    rows: &[StandardRoot],
    owner: (u32, u32),
    loop_id: (u32, u32),
    report: &mut W,
) -> Result<EnsureCounts, EnsureFailure> {
    let home = rows
        .first()
        .and_then(|row| row.path.parent())
        .ok_or_else(|| refused(Path::new("/"), "no class roots"))?;
    let config = home.join(".config");
    let mut opened = BTreeMap::<PathBuf, OwnedFd>::new();
    let mut class_stats = BTreeMap::<PathBuf, StatInfo>::new();
    for row in rows.iter().filter(|row| row.ensure == EnsureClass::Checked) {
        let (fd, stat) = open_class(&row.path)?;
        class_stats.insert(row.path.clone(), stat);
        opened.insert(row.path.clone(), fd);
    }
    let (config_fd, config_stat) = open_class(&config)?;
    opened.insert(config.clone(), config_fd);
    let mut missing = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.ensure == EnsureClass::Checked {
            continue;
        }
        let parent_path = row
            .path
            .parent()
            .ok_or_else(|| refused(&row.path, "no parent"))?;
        let Some(parent) = opened.get(parent_path) else {
            missing.push(index);
            continue;
        };
        let readable = row
            .path
            .parent()
            .is_some_and(|path| path.ends_with(".var/loops"));
        match beneath(parent, &row.path, readable) {
            Ok(fd) => {
                opened.insert(row.path.clone(), fd);
            }
            Err(Errno::ENOENT) => missing.push(index),
            Err(error) => return Err(refused(&row.path, open_reason(error))),
        }
    }
    let mut original_modes = BTreeMap::new();
    for row in rows {
        if let Some(fd) = opened.get(&row.path) {
            let stat = if let Some(stat) = class_stats.get(&row.path) {
                *stat
            } else {
                stat_info(fd, &row.path)?
            };
            original_modes.insert(row.path.clone(), check(stat, row, owner, loop_id)?);
        }
    }
    if let RootAction::Refuse(reason) = config_decision(config_stat, &config, owner) {
        return Err(refused(&config, reason));
    }
    let loop_row = rows
        .get(3)
        .ok_or_else(|| refused(home, "loop root row absent"))?;
    let loop_home = &loop_row.path;
    let private = &rows
        .get(4)
        .ok_or_else(|| refused(home, "private row absent"))?
        .path;
    if let Some(fd) = opened.get(loop_home)
        && !opened.contains_key(private)
    {
        refuse_root_entries(fd, loop_home)?;
    }
    let mut counts = EnsureCounts::default();
    for index in missing {
        let row = &rows[index];
        if !matches!(
            row.ensure,
            EnsureClass::Created | EnsureClass::CreatedWhenParentPresent
        ) {
            continue;
        }
        let parent_path = row
            .path
            .parent()
            .ok_or_else(|| refused(&row.path, "no parent"))?;
        if row.ensure == EnsureClass::CreatedWhenParentPresent && !opened.contains_key(parent_path)
        {
            continue;
        }
        let parent = opened
            .get(parent_path)
            .ok_or_else(|| refused(&row.path, "parent absent"))?;
        let (fd, made) = created_row(row, parent, owner, loop_id)?;
        if !made && row.path == *loop_home && !opened.contains_key(private) {
            match beneath(&fd, private, false) {
                Ok(_private_fd) => {}
                Err(Errno::ENOENT) => refuse_root_entries(&fd, loop_home)?,
                Err(error) => return Err(refused(private, open_reason(error))),
            }
        }
        if made {
            if row.path != *loop_home {
                chmod(&fd, &row.path, row.mode)?;
            }
            writeln!(report, "created {} {:04o}", row.path.display(), row.mode)
                .map_err(|error| refused(&row.path, error.to_string()))?;
            counts.created += 1;
        } else {
            let existing_mode = check(stat_info(&fd, &row.path)?, row, owner, loop_id)?;
            original_modes.insert(row.path.clone(), existing_mode);
        }
        opened.insert(row.path.clone(), fd);
    }
    if !original_modes.contains_key(loop_home) && opened.contains_key(private) {
        let fd = opened
            .get(loop_home)
            .ok_or_else(|| refused(loop_home, "loop root absent"))?;
        chmod(fd, loop_home, loop_row.mode)?;
    }
    for row in rows {
        let Some(&old) = original_modes.get(&row.path) else {
            continue;
        };
        let fd = opened
            .get(&row.path)
            .ok_or_else(|| refused(&row.path, "row absent"))?;
        let group_correction = if let RootOwner::Shared(gid) = row.owner {
            let old_gid = stat_info(fd, &row.path)?.gid;
            (old_gid != gid).then_some((old_gid, gid))
        } else {
            None
        };
        if row.ensure == EnsureClass::Checked || (old == row.mode && group_correction.is_none()) {
            continue;
        }
        if row.path == *loop_home && !opened.contains_key(private) {
            continue;
        }
        let fd = opened
            .get(&row.path)
            .ok_or_else(|| refused(&row.path, "row absent"))?;
        if let RootOwner::Shared(gid) = row.owner {
            fchownat(
                fd,
                "",
                None,
                Some(Gid::from_raw(gid)),
                AtFlags::AT_EMPTY_PATH,
            )
            .map_err(|error| refused(&row.path, error.to_string()))?;
        }
        chmod(fd, &row.path, row.mode)?;
        writeln!(
            report,
            "{}",
            correction_line(&row.path, old, row.mode, group_correction)
        )
        .map_err(|error| refused(&row.path, error.to_string()))?;
        counts.corrected += 1;
    }
    Ok(counts)
}

pub(crate) fn correction_line(path: &Path, old: u32, new: u32, gids: Option<(u32, u32)>) -> String {
    let mut line = format!("corrected {} {old:04o} {new:04o}", path.display());
    if let Some((old_gid, new_gid)) = gids {
        let _written = write!(line, " gid {old_gid} {new_gid}");
    }
    line
}

/// Run the private step from exactly four validated arguments.
///
/// # Errors
///
/// Writes one usage or named refusal line on failure.
pub fn ensure_roots_entry<I, A, E>(arguments: I, error: &mut E) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
    E: io::Write,
{
    let arguments: Vec<String> = if let Ok(arguments) = arguments
        .into_iter()
        .map(|value| value.into().into_string())
        .collect()
    {
        arguments
    } else {
        let _written = writeln!(error, "{USAGE}");
        return 2;
    };
    let [uid, name, home, report_path] = arguments.as_slice() else {
        let _written = writeln!(error, "{USAGE}");
        return 2;
    };
    let parsed = uid
        .parse::<u32>()
        .ok()
        .filter(|uid| (1000..=65_535).contains(uid));
    if parsed.is_none()
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || validate_name(name).is_err()
        || !Path::new(home).is_absolute()
        || !Path::new(report_path).is_absolute()
    {
        let _written = writeln!(error, "{USAGE}");
        return 2;
    }
    let started = Instant::now();
    let mut report = match OpenOptions::new().append(true).open(report_path) {
        Ok(report) => report,
        Err(failure) => {
            let _written = writeln!(
                error,
                "{}",
                refused(Path::new(report_path), failure.to_string())
            );
            return 2;
        }
    };
    let uid = parsed.unwrap_or_default();
    match crate::letters::ensure_layout(Path::new(home), name, uid, &mut report) {
        Ok(()) => {
            if let Err(failure) = writeln!(report, "wall {}", started.elapsed().as_micros()) {
                let _written = writeln!(
                    error,
                    "{}",
                    refused(Path::new(report_path), failure.to_string())
                );
                2
            } else {
                0
            }
        }
        Err(failure) => {
            let _written = writeln!(error, "{failure}");
            2
        }
    }
}

/// Run the read-only root inspection in the owner's user namespace.
pub(crate) fn inspect_roots_entry<I, A, E>(arguments: I, error: &mut E) -> u8
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
    E: io::Write,
{
    let arguments: Vec<String> = if let Ok(arguments) = arguments
        .into_iter()
        .map(|value| value.into().into_string())
        .collect()
    {
        arguments
    } else {
        let _written = writeln!(error, "usage: superloop inspect-roots UID NAME HOME REPORT");
        return 2;
    };
    let [uid, name, home, report_path] = arguments.as_slice() else {
        let _written = writeln!(error, "usage: superloop inspect-roots UID NAME HOME REPORT");
        return 2;
    };
    let valid_uid = uid
        .parse::<u32>()
        .ok()
        .filter(|uid| (1000..=65_535).contains(uid));
    if valid_uid.is_none()
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || validate_name(name).is_err()
        || !Path::new(home).is_absolute()
        || !Path::new(report_path).is_absolute()
    {
        let _written = writeln!(error, "usage: superloop inspect-roots UID NAME HOME REPORT");
        return 2;
    }
    let mut rows = standard_roots(Path::new(home), name);
    let grant_path = Path::new(home).join(".config/loops/allocations.toml:letters_gid");
    let grant = match crate::letters::group(Path::new(home), false) {
        Ok(Some(gid)) => {
            crate::letters::add_roots(&mut rows, Path::new(home), name, gid);
            RootObservation {
                path: grant_path,
                kind: "grant",
                uid: Some(0),
                gid: Some(gid),
                mode: None,
                action: RootAction::Nothing,
                atime_may_have_changed: false,
            }
        }
        Ok(None) => match crate::letters::planned_group(Path::new(home)) {
            Ok(gid) => {
                let gid = gid.unwrap_or_else(|| {
                    if valid_uid == Some(65_535) {
                        65_533
                    } else {
                        65_535
                    }
                });
                crate::letters::add_roots(&mut rows, Path::new(home), name, gid);
                RootObservation::missing(grant_path, RootAction::Create)
            }
            Err(failure) => RootObservation::unseen(grant_path, failure.message().to_owned()),
        },
        Err(failure) => RootObservation::unseen(grant_path, failure.message().to_owned()),
    };
    let uid = valid_uid.unwrap_or_default();
    let mut inspection = inspect_roots(&rows, (0, 0), (uid, uid));
    inspection.observations.push(grant);
    let counts = inspection.would_counts();
    let status = inspection.status();
    let result = OpenOptions::new()
        .append(true)
        .open(report_path)
        .and_then(|mut report| {
            writeln!(
                report,
                "inspection {status} {} {}",
                counts.created, counts.corrected
            )?;
            writeln!(report, "{}", inspection.to_json())
        });
    if let Err(failure) = result {
        let _written = writeln!(error, "inspect refused: {report_path}: {failure}");
        1
    } else {
        status
    }
}
