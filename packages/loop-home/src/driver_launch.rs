use std::fs::{self, File};
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, fstat};

use self::run_paths::{PinnedRunPath, pin_run_directory, pin_runs_root};
use crate::{LoopError, LoopRecord};

fn one_line_path(path: &Path) -> String {
    path.to_string_lossy().escape_debug().to_string()
}

fn run_directory_reason(reason: &str) -> &str {
    match reason {
        "is reached through a link" => "reached through a link",
        "has a nondirectory component" => "component is not a directory",
        other => other,
    }
}

/// A run name is 1–64 ASCII bytes, starts with a letter or digit, and then
/// contains only letters, digits, hyphens, underscores, or dots.
pub fn valid_run_name(run: &str) -> bool {
    let bytes = run.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte))
}

pub fn settings_path(caller_home: &Path, name: &str) -> PathBuf {
    caller_home
        .join(".config/loops")
        .join(name)
        .join("workers.toml")
}

fn pin_settings_parent(path: &Path, owner: u32) -> Result<OwnedFd, LoopError> {
    if !path.is_absolute() {
        return Err(LoopError::refusal(format!(
            "workers settings directory is not absolute: {}",
            one_line_path(path)
        )));
    }
    let mut fd = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        LoopError::refusal(format!("could not open workers settings root: {error}"))
    })?;
    let mut previous = fstat(&fd).map_err(|error| {
        LoopError::refusal(format!("could not inspect workers settings root: {error}"))
    })?;
    let mut prefix = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(LoopError::refusal(format!(
                "workers settings directory has a dotted component: {}",
                one_line_path(path)
            )));
        };
        prefix.push(name);
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        let next = openat2(&fd, name, how).map_err(|error| {
            LoopError::refusal(format!(
                "could not open workers settings directory {}: {error}",
                one_line_path(&prefix)
            ))
        })?;
        let stat = fstat(&next).map_err(|error| {
            LoopError::refusal(format!(
                "could not inspect workers settings directory {}: {error}",
                one_line_path(&prefix)
            ))
        })?;
        let parent_mode = previous.st_mode & 0o7777;
        if (previous.st_uid != 0 && previous.st_uid != 65534 && previous.st_uid != owner)
            || (parent_mode & 0o022 != 0
                && (parent_mode & 0o1000 == 0
                    || (stat.st_uid != 0 && stat.st_uid != 65534 && stat.st_uid != owner)))
        {
            return Err(LoopError::refusal(format!(
                "workers settings have a replaceable ancestor: {}",
                one_line_path(&prefix)
            )));
        }
        previous = stat;
        fd = next;
    }
    if previous.st_uid != owner || previous.st_mode & 0o7777 != 0o700 {
        return Err(LoopError::refusal(format!(
            "workers settings directory must be owner-owned at mode 0700: {}",
            one_line_path(path)
        )));
    }
    Ok(fd)
}

pub fn read_driver_setting(path: &Path, owner: u32) -> Result<String, LoopError> {
    let parent = path
        .parent()
        .ok_or_else(|| LoopError::refusal("workers settings has no parent"))?;
    let pinned_parent = pin_settings_parent(parent, owner)?;
    let name = path
        .file_name()
        .ok_or_else(|| LoopError::refusal("workers settings has no name"))?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    let file = File::from(openat2(&pinned_parent, name, how).map_err(|error| {
        if error == nix::errno::Errno::ENOENT
            && fs::symlink_metadata(parent.join("box.toml")).is_ok()
        {
            return LoopError::refusal(format!(
                "workers settings {} is missing; rename box.toml to workers.toml",
                one_line_path(path)
            ));
        }
        LoopError::refusal(format!(
            "could not read workers settings {}: {}",
            one_line_path(path),
            std::io::Error::from_raw_os_error(error as i32)
        ))
    })?);
    let metadata = file.metadata().map_err(|error| {
        LoopError::refusal(format!(
            "could not inspect workers settings {}: {error}",
            one_line_path(path)
        ))
    })?;
    if !metadata.is_file() {
        return Err(LoopError::refusal(format!(
            "workers settings is not a regular file: {}",
            one_line_path(path)
        )));
    }
    if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o600 {
        return Err(LoopError::refusal(format!(
            "workers settings must be owner-owned at mode 0600: {}",
            one_line_path(path)
        )));
    }
    if metadata.len() > 65_536 {
        return Err(LoopError::refusal(format!(
            "workers settings exceeds 65536 bytes: {}",
            one_line_path(path)
        )));
    }
    let mut source = String::new();
    file.take(65_537)
        .read_to_string(&mut source)
        .map_err(|error| {
            LoopError::refusal(format!(
                "could not read workers settings {}: {error}",
                one_line_path(path)
            ))
        })?;
    if source.len() > 65_536 {
        return Err(LoopError::refusal(format!(
            "workers settings exceeds 65536 bytes: {}",
            one_line_path(path)
        )));
    }
    Ok(source)
}

fn parse_driver_setting(
    source: &str,
    path: &Path,
    record: &LoopRecord,
    runs_root: Option<&Path>,
) -> Result<(PathBuf, PathBuf), LoopError> {
    let settings = crate::workers_settings::validate_workers_settings(source, path)?;
    crate::workers_settings::validate_workers_grant(&settings, record, runs_root)?;
    let argv =
        crate::workers_settings::executable_argv(settings.get("driver_argv"), "driver_argv")?;
    let driver = PathBuf::from(&argv[0]);
    crate::workers_settings::executable_argv(
        settings
            .get("backend_argv")
            .and_then(toml::Value::as_table)
            .and_then(|vendors| vendors.get("codex")),
        "backend_argv.codex",
    )?;
    let runs_root = crate::workers_settings::required_runs_root(&settings, record, runs_root)?;
    Ok((driver, runs_root))
}

/// Check the settings, driver executable, and loop-owned run directory before launch.
///
/// # Errors
///
/// Returns a status-two refusal naming the first invalid input.
pub fn validate_driver_launch(
    caller_home: &Path,
    record: &LoopRecord,
    runs_root: Option<&Path>,
    run: &str,
    driver_bin: &Path,
    run_dir: &Path,
) -> Result<PinnedRunPath, LoopError> {
    let owner = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    validate_driver_launch_for_owner(
        caller_home,
        record,
        runs_root,
        run,
        driver_bin,
        run_dir,
        owner,
    )
}

pub fn validate_driver_launch_for_owner(
    caller_home: &Path,
    record: &LoopRecord,
    runs_root: Option<&Path>,
    run: &str,
    driver_bin: &Path,
    run_dir: &Path,
    owner: (u32, u32),
) -> Result<PinnedRunPath, LoopError> {
    if !valid_run_name(run) {
        return Err(LoopError::refusal(format!(
            "bad run name: {}",
            run.escape_debug()
        )));
    }
    if !driver_bin.is_absolute() {
        return Err(LoopError::refusal(format!(
            "driver path is not absolute: {}",
            one_line_path(driver_bin)
        )));
    }
    crate::allocations::Allocations::read(&crate::allocations::allocations_path(caller_home))?
        .require(&record.name)?;
    let settings = settings_path(caller_home, &record.name);
    let source = read_driver_setting(&settings, nix::unistd::Uid::effective().as_raw())?;
    let (configured, configured_root) =
        parse_driver_setting(&source, &settings, record, runs_root)?;
    if driver_bin.as_os_str() != configured.as_os_str() {
        return Err(LoopError::refusal(format!(
            "driver path differs from workers settings: {}",
            one_line_path(&settings)
        )));
    }
    let metadata = fs::metadata(driver_bin).map_err(|error| {
        LoopError::refusal(format!(
            "could not inspect driver {}: {error}",
            one_line_path(driver_bin)
        ))
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LoopError::refusal(format!(
            "driver is not a regular executable file: {}",
            one_line_path(driver_bin)
        )));
    }
    let expected = configured_root.join(run);
    if run_dir.as_os_str() != expected.as_os_str() || !run_dir.is_absolute() {
        return Err(LoopError::refusal(format!(
            "run directory is outside the loop runs root or has the wrong name: {}",
            one_line_path(run_dir)
        )));
    }
    let pinned = pin_runs_root(&configured_root, owner, true).map_err(|failure| {
        LoopError::refusal(format!(
            "runs_root for loop {} {}: {}",
            record.name,
            failure.reason,
            one_line_path(&failure.path)
        ))
    })?;
    pin_run_directory(pinned, run).map_err(|failure| {
        LoopError::refusal(format!(
            "run directory {}: {}",
            run_directory_reason(&failure.reason),
            one_line_path(&failure.path)
        ))
    })
}

pub mod run_paths {
    //! Descriptor-pinned checks for durable run paths.

    use std::os::fd::OwnedFd;
    use std::path::{Component, Path, PathBuf};

    use nix::errno::Errno;
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
    use nix::sys::stat::{FileStat, Mode, SFlag, fstat};

    /// A failed component and the reason it cannot be trusted.
    #[derive(Debug)]
    pub struct RunPathFailure {
        pub path: PathBuf,
        pub reason: String,
    }

    fn refused(path: &Path, reason: impl Into<String>) -> RunPathFailure {
        RunPathFailure {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    }

    fn flags() -> OFlag {
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
    }

    fn open_reason(error: Errno) -> String {
        match error {
            Errno::ELOOP => String::from("is reached through a link"),
            Errno::ENOTDIR => String::from("has a nondirectory component"),
            _ => format!(
                "cannot inspect: {}",
                std::io::Error::from_raw_os_error(error as i32)
            ),
        }
    }

    fn checked_stat(fd: &OwnedFd, path: &Path) -> Result<FileStat, RunPathFailure> {
        let stat = fstat(fd).map_err(|error| {
            refused(
                path,
                format!(
                    "cannot inspect: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                ),
            )
        })?;
        match SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT {
            SFlag::S_IFDIR => Ok(stat),
            SFlag::S_IFLNK => Err(refused(path, "is reached through a link")),
            _ => Err(refused(path, "has a nondirectory component")),
        }
    }

    fn child(
        parent: &OwnedFd,
        component: &std::ffi::OsStr,
        path: &Path,
    ) -> Result<OwnedFd, RunPathFailure> {
        let how = OpenHow::new()
            .flags(flags())
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        openat2(parent, component, how).map_err(|error| refused(path, open_reason(error)))
    }

    fn trusted_ancestor(
        stat: &FileStat,
        child_stat: &FileStat,
        path: &Path,
        owner_uid: u32,
    ) -> Result<(), RunPathFailure> {
        let mode = stat.st_mode & 0o7777;
        let rule = format!(
            "expected ancestor uid 0 or {owner_uid} with no group/other write; a sticky writable ancestor requires a child owned by uid 0 or {owner_uid}"
        );
        if stat.st_uid != 0 && stat.st_uid != 65534 && stat.st_uid != owner_uid {
            return Err(refused(
                path,
                format!(
                    "has a replaceable ancestor owned by uid {}; {rule}",
                    stat.st_uid
                ),
            ));
        }
        if mode & 0o022 != 0
            && (mode & 0o1000 == 0 || ![0, 65534, owner_uid].contains(&child_stat.st_uid))
        {
            return Err(refused(
                path,
                format!("has a replaceable ancestor at mode {mode:04o}; {rule}"),
            ));
        }
        Ok(())
    }

    /// An opened durable runs root and its checked metadata.
    #[derive(Debug)]
    pub struct PinnedRunsRoot {
        fd: OwnedFd,
        path: PathBuf,
        pub uid: u32,
        pub gid: u32,
        pub mode: u32,
    }

    fn pin_with_hook(
        path: &Path,
        owner: (u32, u32),
        declared: bool,
        mut after_open: impl FnMut(&Path),
    ) -> Result<PinnedRunsRoot, RunPathFailure> {
        if !path.is_absolute() {
            return Err(refused(path, "is not absolute"));
        }
        let mut prefix = PathBuf::from("/");
        let mut fd = open("/", flags(), Mode::empty())
            .map_err(|error| refused(&prefix, open_reason(error)))?;
        let mut stat = checked_stat(&fd, &prefix)?;
        after_open(&prefix);
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(refused(path, "has a dotted component"));
            };
            let parent_stat = stat;
            let parent_path = prefix.clone();
            prefix.push(name);
            let next = child(&fd, name, &prefix)?;
            stat = checked_stat(&next, &prefix)?;
            if declared {
                trusted_ancestor(
                    &parent_stat,
                    &stat,
                    &parent_path,
                    nix::unistd::Uid::effective().as_raw(),
                )?;
            }
            fd = next;
            after_open(&prefix);
        }
        let mode = stat.st_mode & 0o7777;
        if declared {
            if stat.st_uid != owner.0 {
                return Err(refused(
                    path,
                    format!("owned by uid {}, expected uid {}", stat.st_uid, owner.0),
                ));
            }
            if stat.st_gid != owner.1 {
                return Err(refused(
                    path,
                    format!("owned by gid {}, expected gid {}", stat.st_gid, owner.1),
                ));
            }
            if mode != 0o711 {
                return Err(refused(
                    path,
                    format!("mode {mode:04o}, expected mode 0711"),
                ));
            }
        }
        Ok(PinnedRunsRoot {
            fd,
            path: path.to_path_buf(),
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode,
        })
    }

    /// Open a root component by component, pinning every ancestor until the check ends.
    pub fn pin_runs_root(
        path: &Path,
        owner: (u32, u32),
        declared: bool,
    ) -> Result<PinnedRunsRoot, RunPathFailure> {
        pin_with_hook(path, owner, declared, |_| {})
    }

    /// Exercise an ancestor substitution immediately after a selected descriptor opens.
    #[cfg(test)]
    pub fn pin_runs_root_with_hook(
        path: &Path,
        owner: (u32, u32),
        declared: bool,
        after_open: impl FnMut(&Path),
    ) -> Result<PinnedRunsRoot, RunPathFailure> {
        pin_with_hook(path, owner, declared, after_open)
    }

    /// The opened root and its opened run directory, held through launch dispatch.
    #[derive(Debug)]
    pub struct PinnedRunPath {
        pub root: PinnedRunsRoot,
        pub run: OwnedFd,
    }

    pub fn pin_run_directory(
        root: PinnedRunsRoot,
        run: &str,
    ) -> Result<PinnedRunPath, RunPathFailure> {
        let path = root.path.join(run);
        let run_fd = child(&root.fd, std::ffi::OsStr::new(run), &path)?;
        checked_stat(&run_fd, &path)?;
        Ok(PinnedRunPath { root, run: run_fd })
    }
}
