use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use nix::fcntl::{Flock, FlockArg, RenameFlags, renameat2};
use serde_json::{Value, json};

use crate::build::{
    ChildSpec, checked_output, child, executable, hash_preview, podman_environment, publish, sha256,
};
use crate::error::LaneError;
use crate::settings::Settings;

pub(crate) static NEXT_ALLOCATION_TEMP: AtomicU64 = AtomicU64::new(0);

/// The loop configuration directory held under its install lock.
pub struct InstallGuard {
    lock: InstallLock,
    writable: bool,
}

enum InstallLock {
    Public(Flock<fs::File>),
    Transferred(OwnedFd),
}

impl std::fmt::Debug for InstallGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallGuard")
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

impl AsFd for InstallGuard {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.lock {
            InstallLock::Public(lock) => lock.as_fd(),
            InstallLock::Transferred(fd) => fd.as_fd(),
        }
    }
}

impl InstallGuard {
    /// Bind a transferred directory descriptor to the loop and hold its flock.
    ///
    /// # Errors
    ///
    /// Refuses a different directory, unsafe metadata or a contended lock.
    #[allow(unsafe_code)]
    pub fn from_transferred(path: &Path, fd: OwnedFd) -> Result<Self, LaneError> {
        validate_install_descriptor(path, &fd)?;
        // SAFETY: this takes or retains the exclusive lock on the transferred open file
        // description; a competing holder makes the nonblocking acquisition fail.
        if unsafe { libc::flock(fd.as_fd().as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(LaneError::input(
                "install-lock",
                format!("{}: {}", path.display(), std::io::Error::last_os_error()),
            ));
        }
        Ok(Self {
            lock: InstallLock::Transferred(fd),
            writable: true,
        })
    }

    /// Bind an install lock below the already handed owner home without resolving from root.
    ///
    /// # Errors
    ///
    /// Refuses a changed directory, unsafe metadata or a contended lock.
    #[allow(unsafe_code)]
    pub fn from_handed(
        path: &Path,
        owner_home: &Path,
        owner: u32,
        fd: OwnedFd,
    ) -> Result<Self, LaneError> {
        Self::from_handed_mode(path, owner_home, owner, fd, false)
    }

    /// Keep a handed preview lock shared, while changing work remains exclusive.
    ///
    /// # Errors
    ///
    /// Refuses a changed directory, unsafe metadata or a contended lock.
    #[allow(unsafe_code)]
    pub fn from_handed_mode(
        path: &Path,
        owner_home: &Path,
        owner: u32,
        fd: OwnedFd,
        dry_run: bool,
    ) -> Result<Self, LaneError> {
        let named = crate::home::pin_parent_beneath(path, owner_home, owner)?;
        let actual = nix::sys::stat::fstat(&named)
            .map_err(|error| LaneError::input("install-lock", error.to_string()))?;
        let held = nix::sys::stat::fstat(&fd)
            .map_err(|error| LaneError::input("install-lock", error.to_string()))?;
        if actual.st_mode & libc::S_IFMT != libc::S_IFDIR
            || actual.st_uid != owner
            || actual.st_mode & 0o7777 != 0o700
            || (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino)
        {
            return Err(LaneError::input(
                "install-lock",
                "handed loop configuration differs",
            ));
        }
        // SAFETY: the descriptor is a checked directory open file description.
        let operation = if dry_run {
            libc::LOCK_SH
        } else {
            libc::LOCK_EX
        } | libc::LOCK_NB;
        if unsafe { libc::flock(fd.as_fd().as_raw_fd(), operation) } != 0 {
            return Err(LaneError::input(
                "install-lock",
                format!("{}: {}", path.display(), std::io::Error::last_os_error()),
            ));
        }
        Ok(Self {
            lock: InstallLock::Transferred(fd),
            writable: !dry_run,
        })
    }

    pub(crate) const fn is_writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn verify(&self, path: &Path, dry_run: bool) -> Result<(), LaneError> {
        validate_install_descriptor(path, self)?;
        if !dry_run && !self.writable {
            return Err(LaneError::input(
                "install-lock",
                "changing install needs an exclusive lock",
            ));
        }
        Ok(())
    }
}

fn validate_install_descriptor(path: &Path, fd: &impl AsFd) -> Result<(), LaneError> {
    let named = fs::symlink_metadata(path).map_err(|error| {
        LaneError::input("install-lock", format!("{}: {error}", path.display()))
    })?;
    let held = nix::sys::stat::fstat(fd)
        .map_err(|error| LaneError::input("install-lock", error.to_string()))?;
    if !named.is_dir()
        || named.uid() != nix::unistd::Uid::effective().as_raw()
        || named.mode() & 0o7777 != 0o700
        || named.dev() != held.st_dev
        || named.ino() != held.st_ino
    {
        return Err(LaneError::input(
            "install-lock",
            format!("{} differs from the held owner directory", path.display()),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InstallScope {
    Full,
    ProxyRecord,
}

#[derive(Clone)]
pub struct InstallRequest {
    pub loop_name: String,
    pub pilot: bool,
    pub scope: InstallScope,
    pub dry_run: bool,
    pub repair: bool,
    pub podman_bin: Option<PathBuf>,
    /// Empty until the build report supplies the runtime default.
    pub data_dir: PathBuf,
    /// Empty until runtime sibling or installed defaults are resolved.
    pub proxy_bin: PathBuf,
    pub unit_dir: Option<PathBuf>,
}

fn default_proxy_bin(lane_bin: &Path, config: &Path) -> Result<PathBuf, LaneError> {
    let sibling = lane_bin.with_file_name("superloop-lane-vendor-proxy");
    match fs::symlink_metadata(&sibling) {
        Ok(_) => {
            verify_proxy_provenance(&sibling)?;
            return Ok(sibling);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(LaneError::input(
                "proxy-program",
                format!("{}: {error}", sibling.display()),
            ));
        }
    }
    if let Some(generation) = read_generation(&config.join("install-generation.json"))?
        && let Some(path) = generation["proxy_bin"]
            .as_str()
            .filter(|path| !path.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    option_env!("SUPERLOOP_LANE_PROXY_BIN").filter(|path| !path.is_empty()).map(PathBuf::from)
        .ok_or_else(|| LaneError::input("proxy-program", "no verified runtime sibling, recorded proxy, or configured default; supply --proxy-bin"))
}

fn verify_proxy_provenance(proxy: &Path) -> Result<(), LaneError> {
    use std::io::Read as _;
    let provenance = proxy.with_file_name("superloop-lane-vendor-proxy.provenance");
    let refusal = |detail: String| {
        LaneError::input(
            "proxy-provenance",
            format!("{}: {detail}", provenance.display()),
        )
    };
    crate::pinned::owner_executable_word(proxy, nix::unistd::Uid::effective().as_raw())
        .map_err(|error| refusal(format!("{}: {}", error.kind, error.detail)))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&provenance)
        .map_err(|error| refusal(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| refusal(error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 65_536
    {
        return Err(refusal(
            "must be a bounded owner-controlled regular provenance file".into(),
        ));
    }
    let mut text = String::new();
    std::io::Read::by_ref(&mut file)
        .take(65_537)
        .read_to_string(&mut text)
        .map_err(|error| refusal(error.to_string()))?;
    if text.len() > 65_536 {
        return Err(refusal("provenance exceeds 65536 bytes".into()));
    }
    let mut prefixes = text
        .lines()
        .filter_map(|line| line.strip_prefix("sha256-prefix: "));
    let prefix = prefixes
        .next()
        .filter(|value| value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| refusal("expected one 16-hex sha256-prefix".into()))?;
    if prefixes.next().is_some() || !sha256(proxy)?.starts_with(&prefix.to_ascii_lowercase()) {
        return Err(refusal(
            "sha256-prefix differs from the runtime proxy sibling".into(),
        ));
    }
    Ok(())
}

pub(crate) fn lock_loop_config(path: &Path, dry_run: bool) -> Result<InstallGuard, LaneError> {
    let config_meta = fs::symlink_metadata(path).map_err(|error| {
        LaneError::input("install-lock", format!("{}: {error}", path.display()))
    })?;
    let caller_uid = nix::unistd::Uid::effective().as_raw();
    if !config_meta.is_dir() || config_meta.uid() != caller_uid {
        return Err(LaneError::input(
            "install-lock",
            format!("{} is not a directory owned by the caller", path.display()),
        ));
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|error| {
            LaneError::input("install-lock", format!("{}: {error}", path.display()))
        })?;
    let opened = lock_file
        .metadata()
        .map_err(|error| LaneError::input("install-lock", error.to_string()))?;
    if opened.dev() != config_meta.dev()
        || opened.ino() != config_meta.ino()
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(LaneError::input(
            "install-lock",
            format!("{} changed or differs from mode 0700", path.display()),
        ));
    }
    let lock_mode = if dry_run {
        FlockArg::LockSharedNonblock
    } else {
        FlockArg::LockExclusiveNonblock
    };
    let lock = Flock::lock(lock_file, lock_mode).map_err(|(_file, error)| {
        LaneError::input("install-busy", format!("{}: {error}", path.display()))
    })?;
    Ok(InstallGuard {
        lock: InstallLock::Public(lock),
        writable: !dry_run,
    })
}

/// Serialize generation publication on an inode that is never replaced.
pub(crate) fn lock_generation(
    config: &Path,
    exclusive: bool,
    create: bool,
) -> Result<Option<Flock<fs::File>>, LaneError> {
    let path = config.join(".install-generation.lock");
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "install-generation-lock",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("install-generation-lock", error.to_string()))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(LaneError::input(
            "install-generation-lock",
            "generation lock must be an owner-private regular file at mode 0600",
        ));
    }
    let mode = if exclusive {
        FlockArg::LockExclusiveNonblock
    } else {
        FlockArg::LockSharedNonblock
    };
    let lock = Flock::lock(file, mode).map_err(|(_, error)| {
        LaneError::input(
            "install-busy",
            format!(
                "{}: generation publication or launch preparation: {error}",
                path.display()
            ),
        )
    })?;
    let named = fs::symlink_metadata(&path)
        .map_err(|error| LaneError::input("install-generation-lock", error.to_string()))?;
    if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(LaneError::input(
            "install-generation-lock",
            "generation lock changed during acquisition",
        ));
    }
    Ok(Some(lock))
}

/// Hold one generation across launch preparation without creating files in a preview.
pub(crate) fn lock_launch_generation(
    config: &Path,
    dry_run: bool,
) -> Result<(InstallGuard, Option<Flock<fs::File>>), LaneError> {
    let configuration = lock_loop_config(config, true)?;
    let generation = lock_generation(config, false, !dry_run)?;
    if generation.is_some() {
        return Ok((configuration, generation));
    }
    // Before the first changing install/launch creates the sidecar, an exclusive
    // configuration hold prevents a refresh from creating it behind a preview.
    drop(configuration);
    let configuration = lock_loop_config(config, false)?;
    let generation = lock_generation(config, false, false)?;
    Ok((configuration, generation))
}

pub(crate) fn lock_allocations(
    path: &Path,
    create: bool,
    dry_run: bool,
) -> Result<Option<Flock<fs::File>>, LaneError> {
    if create && !dry_run && !allocation_file_present(path)? {
        let parent = path
            .parent()
            .ok_or_else(|| LaneError::input("allocations-read", "allocation path has no parent"))?;
        let (temporary, file) = create_allocation_temporary(parent)?;
        drop(file);
        let directory = fs::File::open(parent).map_err(|error| {
            let _removed = fs::remove_file(&temporary);
            LaneError::input("allocations-read", format!("{}: {error}", parent.display()))
        })?;
        if let Err(error) = renameat2(
            &directory,
            temporary.file_name().expect("temporary name"),
            &directory,
            path.file_name().expect("allocation name"),
            RenameFlags::RENAME_NOREPLACE,
        ) {
            let _removed = fs::remove_file(&temporary);
            return Err(LaneError::input(
                "allocations-read",
                format!("{}: {error}", path.display()),
            ));
        }
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if dry_run && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(LaneError::input(
                "allocations-read",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        LaneError::input("allocations-read", format!("{}: {error}", path.display()))
    })?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LaneError::input(
            "allocations-read",
            format!(
                "{} must be an owner-owned regular file at mode 0600",
                path.display()
            ),
        ));
    }
    let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, error)| {
        LaneError::input("install-busy", format!("{}: {error}", path.display()))
    })?;
    let canonical = fs::symlink_metadata(path).map_err(|error| {
        LaneError::input("allocations-read", format!("{}: {error}", path.display()))
    })?;
    if canonical.dev() != metadata.dev() || canonical.ino() != metadata.ino() {
        return Err(LaneError::input(
            "install-busy",
            format!("{} changed before allocation", path.display()),
        ));
    }
    Ok(Some(lock))
}

fn allocation_file_present(path: &Path) -> Result<bool, LaneError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_other) => Err(LaneError::input(
            "allocations-read",
            format!("{} is not a regular allocation file", path.display()),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LaneError::input(
            "allocations-read",
            format!("{}: {error}", path.display()),
        )),
    }
}

pub(crate) fn install_allocation(
    owner_home: &Path,
    loop_name: &str,
    pilot: bool,
    dry_run: bool,
) -> Result<Value, LaneError> {
    use loop_home::allocations::{Allocations, MAX_ALLOCATIONS, allocations_path};
    let path = allocations_path(owner_home);
    if !pilot && !allocation_file_present(&path)? {
        return Err(LaneError::input(
            "allocations",
            format!("missing worker uid allocation for loop: {loop_name}"),
        ));
    }
    let _lock = lock_allocations(&path, pilot, dry_run)?;
    let mut allocations = Allocations::read_or_empty(&path)
        .map_err(|error| LaneError::input("allocations-read", error.message()))?;
    let (block, changed) = if let Some(block) = allocations.get(loop_name) {
        (block, false)
    } else {
        if !pilot {
            return Err(LaneError::input(
                "allocations",
                format!("missing worker uid allocation for loop: {loop_name}"),
            ));
        }
        let block = allocations.next_block().ok_or_else(|| {
            LaneError::input(
                "allocations-exhausted",
                "no free block of 64 worker UIDs at or above 3000",
            )
        })?;
        (block, true)
    };
    if changed && !dry_run {
        allocations
            .insert(loop_name, block)
            .map_err(|error| LaneError::input("allocations", error.message()))?;
        let source = allocations.to_toml();
        if source.len() as u64 > MAX_ALLOCATIONS {
            return Err(LaneError::input(
                "allocations-write",
                "allocations.toml exceeds 65536 bytes",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            LaneError::input("allocations-write", "allocations path has no parent")
        })?;
        let (temporary, mut file) = create_allocation_temporary(parent)?;
        let result = file
            .write_all(source.as_bytes())
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&temporary, &path));
        if let Err(error) = result {
            let _removed = fs::remove_file(&temporary);
            return Err(LaneError::input(
                "allocations-write",
                format!("{}: {error}", path.display()),
            ));
        }
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|error| {
                LaneError::operation("allocations-sync", format!("{}: {error}", parent.display()))
            })?;
        directory.sync_all().map_err(|error| {
            LaneError::operation("allocations-sync", format!("{}: {error}", parent.display()))
        })?;
    }
    Ok(
        json!({"base":block.base,"count":block.count,"would_allocate":dry_run && changed,"allocated":!dry_run && changed}),
    )
}

fn create_allocation_temporary(parent: &Path) -> Result<(PathBuf, fs::File), LaneError> {
    let (temporary, file) = loop {
        let suffix = NEXT_ALLOCATION_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".allocations-{}-{suffix}.tmp", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LaneError::input(
                    "allocations-write",
                    format!("{}: {error}", temporary.display()),
                ));
            }
        }
    };
    let checked = file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| file.metadata())
        .map_err(|error| {
            LaneError::input(
                "allocations-write",
                format!("{}: {error}", temporary.display()),
            )
        });
    match checked {
        Ok(metadata) if metadata.mode() & 0o7777 == 0o600 => Ok((temporary, file)),
        Ok(_) => {
            let _removed = fs::remove_file(&temporary);
            Err(LaneError::input(
                "allocations-write",
                "temporary ledger mode differs from 0600",
            ))
        }
        Err(error) => {
            let _removed = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

impl InstallRequest {
    /// Parse the loop-scoped install form.
    ///
    /// # Errors
    ///
    /// Refuses an absent, repeated or unknown option.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let mut loop_name = None;
        let mut pilot = false;
        let mut refresh_proxy = false;
        let mut dry_run = false;
        let mut podman_bin = None;
        let mut data_dir = None;
        let mut proxy_bin = None;
        let mut unit_dir = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--pilot" if !pilot => pilot = true,
                "--refresh-proxy" if !refresh_proxy => refresh_proxy = true,
                "--dry-run" if !dry_run => dry_run = true,
                "--podman-bin" | "--data-dir" | "--proxy-bin" | "--unit-dir" => {
                    let option = args[index].as_str();
                    let value = args.get(index + 1).ok_or_else(|| {
                        LaneError::input("usage", format!("{option} needs a value"))
                    })?;
                    if value.is_empty() {
                        return Err(LaneError::input(
                            "usage",
                            format!("{option} needs a nonempty value"),
                        ));
                    }
                    let slot = match option {
                        "--podman-bin" => &mut podman_bin,
                        "--data-dir" => &mut data_dir,
                        "--unit-dir" => &mut unit_dir,
                        _ => &mut proxy_bin,
                    };
                    if slot.replace(value.clone()).is_some() {
                        return Err(LaneError::input("usage", format!("{option} repeated")));
                    }
                    index += 1;
                }
                word if !word.starts_with('-') && loop_name.is_none() => {
                    loop_name = Some(word.to_owned());
                }
                other => {
                    return Err(LaneError::input(
                        "usage",
                        format!("unexpected install argument {other}"),
                    ));
                }
            }
            index += 1;
        }
        if refresh_proxy && !pilot {
            return Err(LaneError::input(
                "usage",
                "--refresh-proxy requires --pilot",
            ));
        }
        Ok(Self {
            loop_name: loop_name.ok_or_else(|| LaneError::input("usage", "install [--pilot [--refresh-proxy]] LOOP [--dry-run] [--podman-bin FILE] [--data-dir DIR] [--proxy-bin FILE]"))?,
            pilot,
            scope: if refresh_proxy { InstallScope::ProxyRecord } else { InstallScope::Full },
            dry_run,
            repair: false,
            podman_bin: podman_bin.map(PathBuf::from),
            data_dir: data_dir.map(PathBuf::from).unwrap_or_default(),
            proxy_bin: proxy_bin.map(PathBuf::from).unwrap_or_default(),
            unit_dir: unit_dir.map(PathBuf::from),
        })
    }
}

struct FileDestination {
    path: PathBuf,
    bytes: Vec<u8>,
    mode: u32,
}

fn checked_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<bool, LaneError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LaneError::input(
                "install-destination",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    if !meta.is_dir() || meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o7777 != mode {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} differs: expected directory uid={uid} gid={gid} mode={mode:04o}",
                path.display()
            ),
        ));
    }
    Ok(true)
}

fn checked_file(file: &FileDestination, uid: u32, gid: u32) -> Result<bool, LaneError> {
    checked_file_mode(file, uid, gid, false)
}

fn checked_file_mode(
    file: &FileDestination,
    uid: u32,
    gid: u32,
    repair: bool,
) -> Result<bool, LaneError> {
    let meta = match fs::symlink_metadata(&file.path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LaneError::input(
                "install-destination",
                format!("{}: {error}", file.path.display()),
            ));
        }
    };
    if !meta.is_file()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o7777 != file.mode
        || meta.len() > 65_536
    {
        return Err(LaneError::input(
            if repair {
                "repair-unit"
            } else {
                "install-conflict"
            },
            format!(
                "{} has unsafe type, owner, mode or size",
                file.path.display()
            ),
        ));
    }
    let bytes = if repair {
        let parent = file
            .path
            .parent()
            .ok_or_else(|| LaneError::input("repair-unit", "unit has no parent"))?;
        crate::pinned::read_private(parent, &file.path, uid, file.mode, 65_536)
            .map_err(|error| LaneError::input("repair-unit", error.detail))?
    } else {
        fs::read(&file.path).map_err(|error| {
            LaneError::input(
                "install-conflict",
                format!("{}: {error}", file.path.display()),
            )
        })?
    };
    let matches = bytes == file.bytes;
    if !matches && !repair {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "{} differs from its pinned unit or report",
                file.path.display()
            ),
        ));
    }
    Ok(matches)
}

fn source_text(path: &Path) -> Result<String, LaneError> {
    let meta = fs::symlink_metadata(path).map_err(|error| {
        LaneError::input("install-source", format!("{}: {error}", path.display()))
    })?;
    if !meta.is_file() || meta.len() > 65_536 {
        return Err(LaneError::input(
            "install-source",
            format!("{} is not a bounded regular file", path.display()),
        ));
    }
    fs::read_to_string(path)
        .map_err(|error| LaneError::input("install-source", format!("{}: {error}", path.display())))
}

fn unit_text(source: &Path, replacements: &[(&str, &Path)]) -> Result<Vec<u8>, LaneError> {
    let mut text = source_text(source)?;
    for (token, path) in replacements {
        let value = path.to_str().ok_or_else(|| {
            LaneError::input("unit-path", format!("{} is not UTF-8", path.display()))
        })?;
        if !path.is_absolute()
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !b"_./-".contains(&byte))
        {
            return Err(LaneError::input(
                "unit-path",
                format!(
                    "{} cannot be represented in a unit argument",
                    path.display()
                ),
            ));
        }
        if !text.contains(token) {
            return Err(LaneError::input(
                "install-source",
                format!("{} lacks {token}", source.display()),
            ));
        }
        text = text.replace(token, value);
    }
    if text.contains("@ENTRY_BIN@") || text.contains("@PROXY_BIN@") || text.contains("@LANE_BIN@") {
        return Err(LaneError::input(
            "install-source",
            format!("{} has an unfilled program path", source.display()),
        ));
    }
    Ok(text.into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn private_spec(
    request: &InstallRequest,
    program: &Path,
    owner_home: &Path,
    entry_bin: &Path,
    lane_bin: &Path,
    codex_bin: &Path,
    codex_host_bin: &Path,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    dry_run: bool,
    expected_source: Option<&str>,
) -> Result<ChildSpec, LaneError> {
    let mut args = vec![
        "unshare".to_owned(),
        crate::pinned::path_word(entry_bin, "owner-program")?,
        "lane-install-private".to_owned(),
        request.loop_name.clone(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        crate::pinned::path_word(lane_bin, "owner-program")?,
        crate::pinned::path_word(&request.data_dir, "install-source")?,
        if codex_bin.as_os_str().is_empty() {
            String::new()
        } else {
            crate::pinned::path_word(codex_bin, "codex-program")?
        },
        if codex_host_bin.as_os_str().is_empty() {
            String::new()
        } else {
            crate::pinned::path_word(codex_host_bin, "codex-host-program")?
        },
        image_digest.to_owned(),
        codex_sha256.to_owned(),
        tools_commit.to_owned(),
    ];
    if dry_run {
        args.push("--dry-run".into());
        if request.dry_run || request.scope == InstallScope::ProxyRecord {
            args.push("--shared-install-lock".into());
        }
    } else {
        let source = expected_source.ok_or_else(|| {
            LaneError::operation(
                "install-source",
                "changing install needs a preflight source digest",
            )
        })?;
        args.extend(["--expected-source-sha256".into(), source.into()]);
    }
    if request.repair {
        args.push("--repair".into());
    }
    Ok(child(
        program,
        args,
        &podman_environment(owner_home)?,
        owner_home,
        120,
        "install-private",
    ))
}

fn blocked_install(request: &InstallRequest, holder: &[String], started: Instant) -> Value {
    json!({"schema":1,"command":"install","pilot":request.pilot,"loop":request.loop_name,"dry_run":true,"blocked":true,"busy":holder,"actions":[],"changed":0,"wall_seconds":started.elapsed().as_secs_f64()})
}

fn refresh_refusal(detail: &str) -> LaneError {
    LaneError::input("install-proxy-refresh", detail)
}

#[allow(clippy::too_many_arguments)]
fn refresh_proxy_generation(
    request: &InstallRequest,
    path: &Path,
    prior: Option<&Value>,
    candidate: &serde_json::Map<String, Value>,
    private: &Value,
    settings_change: bool,
    remedy_proxy: &Path,
    started: Instant,
    admit_install: impl FnOnce() -> Result<(), LaneError>,
) -> Result<Value, LaneError> {
    let mut differing: Vec<_> = candidate
        .iter()
        .filter(|(key, value)| {
            key.as_str() != "proxy_sha256" && prior.is_some_and(|prior| prior[*key] != **value)
        })
        .map(|(key, _)| key.as_str())
        .collect();
    if settings_change {
        differing.push("installed settings");
    }
    let destinations = private["destinations"].as_array().ok_or_else(|| {
        LaneError::operation("install-private", "private report lacks destinations")
    })?;
    let sign_in_changes = private["sign_in"]["changes"].as_array().ok_or_else(|| {
        LaneError::operation("install-private", "private report lacks sign-in changes")
    })?;
    if destinations.iter().any(|row| !row["complete"].is_boolean())
        || (!private["charter_refresh"].is_null() && !private["charter_refresh"].is_boolean())
    {
        return Err(LaneError::operation(
            "install-private",
            "private report has invalid completion fields",
        ));
    }
    if private["charter_refresh"] == true {
        differing.push("charter");
    }
    if destinations.iter().any(|row| row["complete"] == false) {
        differing.push("private destinations");
    }
    if !sign_in_changes.is_empty() {
        differing.push("sign-in metadata");
    }
    let quoted = remedy_proxy.to_string_lossy().replace('\'', "'\\''");
    let complete = prior.filter(|record| record["phase"] == "complete");
    let non_proxy: Vec<_> = differing
        .iter()
        .copied()
        .filter(|key| *key != "proxy_bin")
        .collect();
    let Some(prior) = complete.filter(|_| non_proxy.is_empty()) else {
        admit_install()?;
        let detail = if complete.is_none() {
            "completed pilot generation is absent".to_owned()
        } else {
            format!(
                "{} {} from the installed generation",
                non_proxy.join(", "),
                if non_proxy.len() == 1 {
                    "differs"
                } else {
                    "differ"
                }
            )
        };
        return Err(refresh_refusal(&format!(
            "{detail}; when the loop is idle, run superloop-lane install --pilot {} --proxy-bin '{quoted}' without --refresh-proxy, keeping the same explicit source, runtime and unit-directory options; then run superloop-lane install --pilot {} --refresh-proxy --proxy-bin '{quoted}' with those same options. Both commands retain the selected proxy path; moving an installed path requires separate vendor-unit replacement",
            request.loop_name, request.loop_name
        )));
    };
    if differing.as_slice() == ["proxy_bin"] {
        return Err(refresh_refusal(&format!(
            "proxy_bin differs from the installed generation; run superloop-lane install --pilot {} --refresh-proxy --proxy-bin '{quoted}', keeping the same explicit source, runtime and unit-directory options; moving the proxy path requires separate vendor-unit replacement at an idle loop",
            request.loop_name
        )));
    }
    let mut next = prior.clone();
    next["proxy_sha256"] = candidate["proxy_sha256"].clone();
    let changed = next != *prior;
    if changed && !request.dry_run {
        publish_generation(path, &next).map_err(|error| refresh_refusal(&format!(
            "{}: {}; restore writable and durable custody of the named generation path; then retry the refresh",
            error.kind, error.detail
        )))?;
    }
    Ok(
        json!({"schema":1,"command":"install","pilot":true,"loop":request.loop_name,"refresh_proxy":true,"dry_run":request.dry_run,"blocked":false,"exclusive_configuration_lock_required":false,"changed":u8::from(changed),"proxy_bin":next["proxy_bin"],"proxy_sha256":next["proxy_sha256"],"private_preflight":private,"unit_activation_performed":false,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

fn publish_generation(path: &Path, generation: &Value) -> Result<(), LaneError> {
    let bytes = serde_json::to_vec_pretty(generation)
        .map_err(|error| LaneError::operation("install-generation", error.to_string()))?;
    publish(path, &bytes)?;
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::operation("install-generation", "record has no parent"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            LaneError::operation(
                "install-generation",
                format!("{}: {error}", parent.display()),
            )
        })
}

fn private_report(spec: &ChildSpec, entry_bin: &Path, lane_bin: &Path) -> Result<Value, LaneError> {
    crate::pinned::owner_executable_word(entry_bin, nix::unistd::Uid::effective().as_raw())?;
    crate::pinned::owner_executable_word(lane_bin, nix::unistd::Uid::effective().as_raw())?;
    let output = checked_output(spec, None)?;
    if output.len() > 65_536 {
        return Err(LaneError::operation(
            "install-private",
            "private report exceeds 65536 bytes",
        ));
    }
    serde_json::from_str(&output).map_err(|error| {
        LaneError::operation(
            "install-private",
            format!("invalid private report: {error}"),
        )
    })
}

fn ensure_directory(path: &Path) -> Result<(), LaneError> {
    DirBuilder::new().mode(0o700).create(path).map_err(|error| {
        LaneError::operation("install-create", format!("{}: {error}", path.display()))
    })
}

fn sync_unit_directory_with(
    path: &Path,
    sync: &mut impl FnMut(&Path, &fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    let directory = fs::File::open(path).map_err(|error| {
        LaneError::operation("install-sync", format!("{}: {error}", path.display()))
    })?;
    sync(path, &directory).map_err(|error| {
        LaneError::operation("install-sync", format!("{}: {error}", path.display()))
    })
}

fn ensure_directory_with_sync(
    path: &Path,
    sync: &mut impl FnMut(&Path, &fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    ensure_directory(path)?;
    let parent = path.parent().ok_or_else(|| {
        LaneError::operation("install-sync", format!("{} has no parent", path.display()))
    })?;
    sync_unit_directory_with(parent, sync)
}

fn retire_worker_unit_with_sync(
    source: &Path,
    retired: &Path,
    sync: &mut impl FnMut(&Path, &fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    fs::rename(source, retired).map_err(|error| {
        LaneError::operation("install-retire", format!("{}: {error}", source.display()))
    })?;
    let source_parent = source.parent().ok_or_else(|| {
        LaneError::operation(
            "install-sync",
            format!("{} has no parent", source.display()),
        )
    })?;
    let retired_parent = retired.parent().ok_or_else(|| {
        LaneError::operation(
            "install-sync",
            format!("{} has no parent", retired.display()),
        )
    })?;
    sync_unit_directory_with(source_parent, sync)?;
    sync_unit_directory_with(retired_parent, sync)
}

fn sync_pending_unit_directories_with(
    unit_parent: &Path,
    unit_dir: &Path,
    retired_dir: Option<&Path>,
    sync: &mut impl FnMut(&Path, &fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    let ancestor = unit_parent.parent().ok_or_else(|| {
        LaneError::operation(
            "install-sync",
            format!("{} has no parent", unit_parent.display()),
        )
    })?;
    sync_unit_directory_with(ancestor, sync)?;
    sync_unit_directory_with(unit_parent, sync)?;
    sync_unit_directory_with(unit_dir, sync)?;
    if let Some(retired_dir) = retired_dir {
        sync_unit_directory_with(retired_dir, sync)?;
    }
    Ok(())
}

fn complete_generation_after_unit_sync_with(
    generation_path: &Path,
    generation: &mut Value,
    unit_parent: &Path,
    unit_dir: &Path,
    retired_dir: Option<&Path>,
    sync: &mut impl FnMut(&Path, &fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    sync_pending_unit_directories_with(unit_parent, unit_dir, retired_dir, sync)?;
    generation["phase"] = json!("complete");
    publish_generation(generation_path, generation)
}

fn write_unit(file: &FileDestination, lane_bin: &Path) -> Result<(), LaneError> {
    let mut sync = fs::File::sync_all;
    write_unit_with_sync(file, lane_bin, false, &mut sync)
}

fn replace_unit(file: &FileDestination, lane_bin: &Path) -> Result<(), LaneError> {
    let mut sync = fs::File::sync_all;
    write_unit_with_sync(file, lane_bin, true, &mut sync)
}

fn write_unit_with_sync(
    file: &FileDestination,
    lane_bin: &Path,
    replace: bool,
    sync: &mut impl FnMut(&fs::File) -> std::io::Result<()>,
) -> Result<(), LaneError> {
    crate::pinned::owner_executable_word(lane_bin, nix::unistd::Uid::effective().as_raw())?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| LaneError::operation("install-create", error.to_string()))?
        .as_nanos();
    let staged = file
        .path
        .with_extension(format!("staged-{}-{nonce}", std::process::id()));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(file.mode)
        .open(&staged)
        .map_err(|error| {
            LaneError::operation("install-create", format!("{}: {error}", staged.display()))
        })?;
    output
        .write_all(&file.bytes)
        .and_then(|()| sync(&output))
        .map_err(|error| {
            LaneError::operation("install-create", format!("{}: {error}", staged.display()))
        })?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(file.mode)).map_err(|error| {
        LaneError::operation("install-mode", format!("{}: {error}", staged.display()))
    })?;
    sync(&output).map_err(|error| {
        LaneError::operation("install-sync", format!("{}: {error}", staged.display()))
    })?;
    if replace {
        fs::rename(&staged, &file.path).map_err(|error| {
            LaneError::operation("repair-unit", format!("{}: {error}", file.path.display()))
        })?;
    } else {
        fs::hard_link(&staged, &file.path).map_err(|error| {
            LaneError::operation(
                "install-create",
                format!("{}: {error}", file.path.display()),
            )
        })?;
        fs::remove_file(&staged).map_err(|error| {
            LaneError::operation("install-create", format!("{}: {error}", staged.display()))
        })?;
    }
    let parent = file
        .path
        .parent()
        .ok_or_else(|| LaneError::operation("install-sync", "unit has no parent"))?;
    fs::File::open(parent)
        .and_then(|directory| sync(&directory))
        .map_err(|error| {
            LaneError::operation("install-sync", format!("{}: {error}", parent.display()))
        })
}

pub(crate) fn read_generation(path: &Path) -> Result<Option<Value>, LaneError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "install-generation",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    validate_generation(path, &bytes).map(Some)
}

pub(crate) fn validate_generation(path: &Path, bytes: &[u8]) -> Result<Value, LaneError> {
    if bytes.len() > 65_536 {
        return Err(LaneError::input(
            "install-generation",
            format!("{} exceeds 65536 bytes", path.display()),
        ));
    }
    let record: Value = serde_json::from_slice(bytes).map_err(|error| {
        LaneError::input("install-generation", format!("{}: {error}", path.display()))
    })?;
    if record["schema"] != 1 || !matches!(record["phase"].as_str(), Some("preparing" | "complete"))
    {
        return Err(LaneError::input(
            "install-generation",
            format!("{} has an unknown form", path.display()),
        ));
    }
    crate::build::payload::check_claude_generation(&record)?;
    Ok(record)
}

fn vendor_generation_fields(
    record: &mut Value,
    payloads: &[crate::build::payload::InstallPayload],
    loop_root: &Path,
    hash: &str,
) -> Result<(), LaneError> {
    let object = record
        .as_object_mut()
        .ok_or_else(|| LaneError::operation("install-generation", "generation is not an object"))?;
    if !payloads
        .iter()
        .any(|payload| payload.vendor == crate::build::payload::CODEX)
    {
        for key in ["codex_sha256", "codex_host_sha256", "codex_image_program"] {
            object.remove(key);
        }
    }
    for payload in payloads {
        object.insert(payload.vendor.hash_key.into(), json!(payload.sha256));
        object.insert(
            payload.vendor.program_key.into(),
            json!(payload.image_program),
        );
        if payload.vendor == crate::build::payload::CLAUDE {
            object.insert(
                "claude_template_dir".into(),
                json!(payload.template(loop_root, hash)),
            );
        }
    }
    Ok(())
}

fn generation_matches(
    record: &Value,
    image_digest: &str,
    codex_sha256: &str,
    tools_commit: &str,
    template_dir: &Path,
    socket_dir: &Path,
) -> bool {
    record["image_digest"] == image_digest
        && if codex_sha256.is_empty() {
            record.get("codex_sha256").is_none()
        } else {
            record["codex_sha256"] == codex_sha256
        }
        && record["tools_commit"] == tools_commit
        && record["template_dir"] == template_dir.display().to_string()
        && record["socket_dir"] == socket_dir.display().to_string()
}

/// Inspect or prepare the loop's first launch inputs without activating a unit.
///
/// # Errors
///
/// Refuses an absent grant, missing installed program, or conflicting destination before mutation.
pub fn run(owner_home: &Path, request: &InstallRequest) -> Result<Value, LaneError> {
    let lane_bin = std::env::current_exe()
        .map_err(|error| LaneError::operation("install-program", error.to_string()))?;
    run_with_lane_bin(owner_home, request, &lane_bin, Path::new("/"), 0)
}

/// Reconcile using the build report and generation already read through pinned descriptors.
///
/// # Errors
///
/// Refuses unsafe or changed installed inputs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_repair_with_lane_bin(
    owner_home: &Path,
    request: &InstallRequest,
    report: &Value,
    generation: &Value,
    lane_bin: &Path,
    host_root: &Path,
    host_root_uid: u32,
) -> Result<Value, LaneError> {
    run_with_lane_bin_inner(
        owner_home,
        request,
        lane_bin,
        host_root,
        host_root_uid,
        Some((report, generation)),
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn run_with_lane_bin(
    owner_home: &Path,
    request: &InstallRequest,
    lane_bin: &Path,
    host_root: &Path,
    host_root_uid: u32,
) -> Result<Value, LaneError> {
    let result = run_with_lane_bin_inner(
        owner_home,
        request,
        lane_bin,
        host_root,
        host_root_uid,
        None,
    );
    result.map_err(|error| {
        if request.scope == InstallScope::ProxyRecord
            && !matches!(
                error.kind,
                "install-busy" | "install-proxy-refresh" | "proxy-provenance" | "proxy-program" | "usage"
            )
        {
            let remedy = match error.kind {
                "install-source" | "codex-program" | "codex-host-program" =>
                    "restore the named source to the bytes and executable custody pinned by image-build.json; then retry the refresh with the same explicit options",
                "install-private" =>
                    "restore the private source, destination or runtime prerequisite reported above, including a working private preflight returning the required measured fingerprint, destinations and sign-in changes; then retry the refresh with the same explicit options",
                "install-generation" =>
                    "restore valid generation custody and the inputs of any pending generation; when the loop is idle, complete that pilot installation before retrying the refresh",
                "install-conflict" | "install-destination" =>
                    "restore the named path's required type, owner, group, mode and pinned contents or derived settings shown above; then retry the refresh with the same explicit options",
                _ => "restore the named prerequisite reported above; then retry the refresh with the same explicit options",
            };
            refresh_refusal(&format!("{}: {}; {remedy}", error.kind, error.detail))
        } else {
            error
        }
    })
}

#[allow(clippy::too_many_lines)]
fn run_with_lane_bin_inner(
    owner_home: &Path,
    request: &InstallRequest,
    lane_bin: &Path,
    host_root: &Path,
    host_root_uid: u32,
    pinned: Option<(&Value, &Value)>,
) -> Result<Value, LaneError> {
    let started = Instant::now();
    let default_program = if let Some((report, _)) = pinned {
        Path::new(
            report["build_environment"]["podman_bin"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    LaneError::input(
                        "repair-build-report",
                        "build environment podman_bin is absent",
                    )
                })?,
        )
    } else {
        Path::new("/usr/bin/podman")
    };
    let program = request.podman_bin.as_deref().unwrap_or(default_program);
    crate::pinned::owner_executable_word(lane_bin, nix::unistd::Uid::effective().as_raw())?;
    loop_home::validate_name(&request.loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let loop_config = owner_home.join(".config/loops").join(&request.loop_name);
    if request.dry_run
        && request.scope != InstallScope::ProxyRecord
        && let Some(holder) = crate::install_door::configuration_blocked_with_program(
            owner_home,
            &request.loop_name,
            &loop_config,
            request.podman_bin.as_deref(),
            default_program,
        )?
    {
        return Ok(blocked_install(request, &holder, started));
    }
    let install_guard = match lock_loop_config(
        &loop_config,
        request.dry_run || request.scope == InstallScope::ProxyRecord,
    ) {
        Ok(guard) => guard,
        Err(error) if error.kind == "install-busy" => {
            let holder = crate::install_door::busy_holder_with_program(
                owner_home,
                &request.loop_name,
                &loop_config,
                request.podman_bin.as_deref(),
                default_program,
            );
            if request.dry_run {
                return Ok(blocked_install(request, &holder, started));
            }
            return Err(LaneError::input("install-busy", holder.join(", ")));
        }
        Err(error) => return Err(error),
    };
    let generation_guard = || {
        if request.dry_run {
            drop(lock_generation(&loop_config, true, false)?);
            lock_generation(&loop_config, false, false)
        } else {
            lock_generation(&loop_config, true, true)
        }
    };
    let _generation_guard = match generation_guard() {
        Ok(guard) => guard,
        Err(error) if error.kind == "install-busy" => {
            let mut holders: Vec<String> = crate::install_door::busy_holder_with_program(
                owner_home,
                &request.loop_name,
                &loop_config,
                request.podman_bin.as_deref(),
                default_program,
            )
            .into_iter()
            .filter_map(|holder| {
                holder
                    .strip_suffix(" (preparing)")
                    .map(|run| format!("{run} (preparing-or-starting)"))
            })
            .collect();
            holders.push("preparing-or-starting names are candidates whose generation hold may already be released; a possible unnamed holder has an unpublished reservation or launcher identity, or is another install, refresh or repair, including a preview, holding the generation lock".into());
            if request.dry_run {
                return Ok(blocked_install(request, &holders, started));
            }
            return Err(LaneError::input("install-busy", holders.join(", ")));
        }
        Err(error) => return Err(error),
    };
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let row = registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let settings_path = owner_home
        .join(".config/loops")
        .join(&request.loop_name)
        .join("workers.toml");
    let settings = Settings::read(&settings_path)?;
    settings.validate_grant(owner_home, &request.loop_name)?;
    let allocation_path = loop_home::allocations::allocations_path(owner_home);
    let block = loop_home::allocations::Allocations::read(&allocation_path)
        .and_then(|allocations| allocations.require(&request.loop_name))
        .map_err(|error| LaneError::input("allocations", error.message()))?;
    let allocation =
        json!({"base":block.base,"count":block.count,"would_allocate":false,"allocated":false});
    let report_path = settings_path.with_file_name("image-build.json");
    let report: Value = if let Some((report, _)) = pinned {
        report.clone()
    } else {
        serde_json::from_slice(&fs::read(&report_path).map_err(|error| {
            LaneError::input(
                "build-report",
                format!("{}: {error}", report_path.display()),
            )
        })?)
        .map_err(|error| {
            LaneError::input(
                "build-report",
                format!("{}: {error}", report_path.display()),
            )
        })?
    };
    let mut resolved = request.clone();
    if resolved.data_dir.as_os_str().is_empty() {
        resolved.data_dir = PathBuf::from(report["build_environment"]["template_dir"].as_str()
            .filter(|path| !path.is_empty()).ok_or_else(|| LaneError::input("build-report", "image-build.json build_environment.template_dir is absent; supply --data-dir"))?);
    }
    if resolved.proxy_bin.as_os_str().is_empty() {
        resolved.proxy_bin = default_proxy_bin(lane_bin, &loop_config)?;
    }
    let request = &resolved;
    let payloads = crate::build::payload::install_payloads(&report, &settings)?;
    let primary = payloads
        .first()
        .ok_or_else(|| LaneError::input("missing-setting", "no configured vendor"))?;
    let image_program = &primary.image_program;
    let installed_backends: Vec<_> = payloads.iter().map(|payload| payload.vendor.name).collect();
    let image_digest = if request.repair && request.dry_run {
        report["image_digest"].as_str().ok_or_else(|| {
            LaneError::input("build-report", "image-build.json image ID is absent")
        })?
    } else {
        settings.image_digest.as_deref().ok_or_else(|| {
            LaneError::input("missing-setting", "image_digest is absent; run build first")
        })?
    };
    if report["image_digest"] != image_digest {
        return Err(LaneError::input(
            "build-report",
            "image-build.json image ID differs from workers.toml",
        ));
    }
    let codex = payloads
        .iter()
        .find(|payload| payload.vendor == crate::build::payload::CODEX);
    let codex_bin = codex.map_or_else(|| Path::new(""), |payload| payload.bin.as_path());
    let codex_sha256 = codex.map_or("", |payload| payload.sha256.as_str());
    let host = codex.and_then(|payload| payload.companion.as_ref());
    let codex_host_bin = host.map_or_else(|| Path::new(""), |(path, _)| path.as_path());
    let codex_host_sha256 = host.map_or("", |(_, hash)| hash.as_str());
    let tools_commit = report["tools_commit"]
        .as_str()
        .ok_or_else(|| LaneError::input("build-report", "tools commit is absent"))?;
    for payload in &payloads {
        executable(&payload.bin, payload.vendor.name)?;
        if sha256(&payload.bin)? != payload.sha256 {
            let name = if payload.vendor == crate::build::payload::CODEX {
                "Codex"
            } else {
                "Claude"
            };
            return Err(LaneError::input(
                "install-source",
                format!(
                    "{}: {name} executable differs from image-build.json",
                    payload.bin.display()
                ),
            ));
        }
        if let Some((path, hash)) = &payload.companion {
            executable(path, "Codex code-mode host")?;
            if sha256(path)? != *hash {
                return Err(LaneError::input(
                    "install-source",
                    format!(
                        "{}: Codex code-mode host differs from image-build.json",
                        path.display()
                    ),
                ));
            }
        }
    }
    let hash = image_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| LaneError::input("build-report", "image ID is not a sha256 value"))?;
    let template_dir = primary.template(&row.home, hash);
    let socket_dir = row.home.join("sockets");
    crate::pinned::owner_executable_word(
        &request.proxy_bin,
        nix::unistd::Uid::effective().as_raw(),
    )?;
    let proxy_sha256 = sha256(&request.proxy_bin)?;
    let init_sha256 = report["init_sha256"]
        .as_str()
        .ok_or_else(|| LaneError::input("build-report", "private init sha256 is absent"))?;
    if sha256(&request.data_dir.join("box-init"))? != init_sha256 {
        return Err(LaneError::input(
            "install-source",
            format!(
                "{}: box-init differs from image-build.json",
                request.data_dir.join("box-init").display()
            ),
        ));
    }
    let unit_dir = request
        .unit_dir
        .clone()
        .unwrap_or_else(|| owner_home.join(".config/systemd/user"));
    let generation_path = settings_path.with_file_name("install-generation.json");
    let prior_generation = if let Some((_, generation)) = pinned {
        Some(generation.clone())
    } else {
        read_generation(&generation_path)?
    };
    let same_generation = prior_generation.as_ref().is_some_and(|record| {
        generation_matches(
            record,
            image_digest,
            codex_sha256,
            tools_commit,
            &template_dir,
            &socket_dir,
        ) && record["proxy_bin"] == request.proxy_bin.display().to_string()
            && record["unit_dir"] == unit_dir.display().to_string()
            && record["proxy_sha256"] == proxy_sha256
            && record["init_sha256"] == init_sha256
            && (codex.is_none()
                || (record["codex_image_program"] == *image_program
                    && record["codex_host_sha256"] == codex_host_sha256))
            && payloads.iter().all(|payload| {
                record[payload.vendor.hash_key] == payload.sha256
                    && record[payload.vendor.program_key] == payload.image_program
                    && (payload.vendor != crate::build::payload::CLAUDE
                        || record["claude_template_dir"]
                            == payload.template(&row.home, hash).display().to_string())
            })
            && (record.get("claude_sha256").is_some() == settings.configures("claude"))
    });
    if prior_generation
        .as_ref()
        .is_some_and(|record| record["phase"] == "preparing")
        && !same_generation
    {
        return Err(LaneError::input(
            "install-generation",
            format!(
                "{} has an unfinished different generation",
                generation_path.display()
            ),
        ));
    }
    let previous_complete = prior_generation.as_ref().is_some_and(|record| {
        record["phase"] == "complete"
            && !same_generation
            && settings
                .template_dir
                .as_ref()
                .is_some_and(|path| record["template_dir"] == path.display().to_string())
    });
    if settings
        .template_dir
        .as_ref()
        .is_some_and(|path| path != &template_dir)
        && !previous_complete
    {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "template_dir differs from {}; restore '{}' so template_dir is '{}'",
                template_dir.display(),
                settings_path.display(),
                template_dir.display()
            ),
        ));
    }
    if settings
        .socket_dir
        .as_ref()
        .is_some_and(|path| path != &socket_dir)
    {
        return Err(LaneError::input(
            "install-conflict",
            format!(
                "socket_dir differs from {}; restore '{}' so socket_dir is '{}'",
                socket_dir.display(),
                settings_path.display(),
                socket_dir.display()
            ),
        ));
    }
    let entry_bin = settings
        .entry_bin
        .as_deref()
        .ok_or_else(|| LaneError::input("missing-setting", "entry_bin is absent"))?;
    crate::pinned::owner_executable_word(entry_bin, nix::unistd::Uid::effective().as_raw())?;
    crate::pinned::owner_executable(program, nix::unistd::Uid::effective().as_raw())?;
    // Inspect the same installation prerequisites before recommending that operation.
    // Refresh retains the unit's recorded proxy, even when the requested path differs.
    let remedy_proxy = if request.scope == InstallScope::ProxyRecord {
        if let Some(record) = &prior_generation {
            let recorded = record["proxy_bin"].as_str().filter(|path| !path.is_empty())
                .ok_or_else(|| LaneError::input("install-generation", "recorded proxy_bin is absent; restore the installed proxy path in generation custody"))?;
            let path = Path::new(recorded);
            crate::pinned::owner_executable_word(path, nix::unistd::Uid::effective().as_raw())?;
            path
        } else {
            request.proxy_bin.as_path()
        }
    } else {
        request.proxy_bin.as_path()
    };
    let owner = nix::unistd::Uid::effective().as_raw();
    let group = nix::unistd::Gid::effective().as_raw();
    let verified_owner_home =
        crate::home::verify_host_prefix_from(host_root, owner_home, owner, host_root_uid)?;
    let inspect_install = || {
        if !unit_dir.is_absolute()
            || !unit_dir.starts_with(owner_home.join(".config"))
            || unit_dir.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(LaneError::input(
                "unit-dir",
                format!(
                    "{} must be an absolute path under the owner's config tree without dotted components",
                    unit_dir.display()
                ),
            ));
        }
        let unit_parent = unit_dir
            .parent()
            .ok_or_else(|| LaneError::input("unit-dir", "unit directory has no parent"))?
            .to_path_buf();
        let unit_ancestor = unit_parent.parent().ok_or_else(|| {
            LaneError::input("unit-dir", "unit directory has no existing ancestor")
        })?;
        let pinned_ancestor = crate::home::pin_parent(unit_ancestor, owner)?;
        let parent_exists = checked_directory(&unit_parent, owner, group, 0o700)?;
        let dir_exists = checked_directory(&unit_dir, owner, group, 0o700)?;
        let unit_source = |name: &str, replacements: &[(&str, &Path)]| {
            unit_text(&request.data_dir.join(name), replacements).map_err(|error| {
            if request.scope == InstallScope::ProxyRecord && error.kind == "install-source" {
                refresh_refusal(&format!(
                    "{}: {}; restore the named unit source template in the selected data directory; then retry the refresh with the same explicit options",
                    error.kind, error.detail
                ))
            } else {
                error
            }
        })
        };
        let vendor_unit = FileDestination {
            path: unit_dir.join(format!(
                "superloop-lane-vendor@{}.service",
                request.loop_name
            )),
            bytes: unit_source(
                "vendor-proxy.service.in",
                &[("@LANE_BIN@", lane_bin), ("@PROXY_BIN@", remedy_proxy)],
            )?,
            mode: 0o644,
        };
        let worker_unit = FileDestination {
            path: unit_dir.join(format!(
                "superloop-lane-worker@{}.service",
                request.loop_name
            )),
            bytes: unit_source("worker.service.in", &[("@LANE_BIN@", lane_bin)])?,
            mode: 0o644,
        };
        let worker_unit_present = checked_file(&worker_unit, owner, group)?;
        let retired_dir = unit_dir.join("retired");
        let retired_dir_exists = checked_directory(&retired_dir, owner, group, 0o700)?;
        let unit_files = [&vendor_unit];
        let existing = unit_files
        .iter()
        .map(|file| {
            checked_file_mode(file, owner, group, request.repair).map_err(|error| {
                if request.scope == InstallScope::ProxyRecord {
                    let remedy = if error.detail.ends_with("differs from its pinned unit or report")
                        && prior_generation.as_ref().is_some_and(|record| record["phase"] == "complete") {
                        format!("when the loop is idle, run superloop-lane repair {} to restore the vendor unit at the recorded proxy path", request.loop_name)
                    } else if error.detail.contains("unsafe type, owner, mode or size") {
                        "restore safe custody of the named vendor unit (regular file, owner and group of the installing account, mode 0644, at most 65536 bytes)".to_owned()
                    } else {
                        "restore the named vendor unit or remove the conflicting unit while the loop is idle; an absent or preparing generation cannot be repaired".to_owned()
                    };
                    refresh_refusal(&format!("{}: {}; {remedy}, then retry the refresh; moving the proxy path requires separate vendor-unit replacement", error.kind, error.detail))
                } else {
                    error
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
        Ok((
            unit_parent,
            pinned_ancestor,
            parent_exists,
            dir_exists,
            vendor_unit,
            worker_unit,
            worker_unit_present,
            retired_dir,
            retired_dir_exists,
            existing,
        ))
    };
    let early_install = if request.scope == InstallScope::Full {
        Some(inspect_install()?)
    } else {
        None
    };
    let preflight_spec = private_spec(
        request,
        program,
        owner_home,
        entry_bin,
        lane_bin,
        codex_bin,
        codex_host_bin,
        image_digest,
        codex_sha256,
        tools_commit,
        true,
        None,
    )?
    .with_private_install(&verified_owner_home, &install_guard)?;
    let private = private_report(&preflight_spec, entry_bin, lane_bin)?;
    let init_source = request.data_dir.join("box-init");
    let mut source_checks = vec![("init", init_source.as_path(), init_sha256)];
    for payload in &payloads {
        source_checks.push((
            payload.vendor.name,
            payload.bin.as_path(),
            payload.sha256.as_str(),
        ));
        if let Some((path, hash)) = &payload.companion {
            source_checks.push(("codex_host", path.as_path(), hash.as_str()));
        }
    }
    for (key, source, expected) in source_checks {
        if private["source_sha256"][key] != expected {
            return Err(LaneError::input(
                "install-source",
                format!(
                    "private source snapshot {key} for '{}' differs from pinned hash {expected}",
                    source.display()
                ),
            ));
        }
    }
    let measured_source = private["source_fingerprint"]
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            LaneError::operation(
                "install-private",
                "private preflight lacks a measured source fingerprint",
            )
        })?;
    if prior_generation.as_ref().is_some_and(|record| {
        record["phase"] == "preparing" && record["source_fingerprint"] != measured_source
    }) {
        return Err(LaneError::input(
            "install-generation",
            format!(
                "{} names another source snapshot",
                generation_path.display()
            ),
        ));
    }
    let same_generation = same_generation
        && prior_generation
            .as_ref()
            .is_some_and(|record| record["source_fingerprint"] == measured_source);
    let mut parsed: toml::Value = toml::from_str(&settings.source)
        .map_err(|error| LaneError::operation("settings-write", error.to_string()))?;
    let table = parsed
        .as_table_mut()
        .ok_or_else(|| LaneError::operation("settings-write", "settings root is not a table"))?;
    table.insert(
        "template_dir".into(),
        toml::Value::String(template_dir.display().to_string()),
    );
    table.insert(
        "socket_dir".into(),
        toml::Value::String(socket_dir.display().to_string()),
    );
    let updated = toml::to_string_pretty(&parsed)
        .map_err(|error| LaneError::operation("settings-write", error.to_string()))?;
    let settings_change = settings.template_dir.as_deref() != Some(template_dir.as_path())
        || settings.socket_dir.is_none();
    let mut destinations = private["destinations"].as_array().cloned().ok_or_else(|| {
        LaneError::operation("install-private", "private report lacks destinations")
    })?;
    let resumable = prior_generation
        .as_ref()
        .is_some_and(|record| record["phase"] == "preparing" && same_generation);
    let check_derived_paths = |existing: &[bool]| {
        if settings_change
            && !resumable
            && !previous_complete
            && (existing.iter().any(|exists| *exists)
                || destinations.iter().any(|destination| {
                    destination["path"].as_str() == template_dir.to_str()
                        && destination["exists"] == true
                }))
        {
            return Err(LaneError::input(
                "install-conflict",
                format!(
                    "{} lacks derived paths while installed inputs exist; restore template_dir={} and socket_dir={}",
                    settings_path.display(),
                    template_dir.display(),
                    socket_dir.display()
                ),
            ));
        }
        Ok(())
    };
    if request.scope == InstallScope::ProxyRecord {
        let mut candidate = Value::Object(serde_json::Map::from_iter([
            ("schema".into(), json!(1)),
            ("phase".into(), json!("complete")),
            ("image_digest".into(), json!(image_digest)),
            ("codex_sha256".into(), json!(codex_sha256)),
            ("codex_host_sha256".into(), json!(codex_host_sha256)),
            ("tools_commit".into(), json!(tools_commit)),
            ("template_dir".into(), json!(template_dir)),
            ("socket_dir".into(), json!(socket_dir)),
            ("unit_dir".into(), json!(unit_dir)),
            ("proxy_bin".into(), json!(request.proxy_bin)),
            ("proxy_sha256".into(), json!(proxy_sha256)),
            ("init_sha256".into(), json!(init_sha256)),
            ("codex_image_program".into(), json!(image_program)),
            ("source_fingerprint".into(), json!(measured_source)),
        ]));
        vendor_generation_fields(&mut candidate, &payloads, &row.home, hash)?;
        let candidate = candidate.as_object().ok_or_else(|| {
            LaneError::operation("install-generation", "candidate is not an object")
        })?;
        return refresh_proxy_generation(
            request,
            &generation_path,
            prior_generation.as_ref(),
            candidate,
            &private,
            settings_change,
            remedy_proxy,
            started,
            || {
                let inspected = inspect_install()?;
                check_derived_paths(&inspected.9)
            },
        );
    }
    let (
        unit_parent,
        _pinned_ancestor,
        parent_exists,
        dir_exists,
        vendor_unit,
        worker_unit,
        worker_unit_present,
        retired_dir,
        mut retired_dir_exists,
        existing,
    ) = early_install.ok_or_else(|| {
        LaneError::operation("install-private", "full installation inspection is absent")
    })?;
    check_derived_paths(&existing)?;
    let unit_files = [&vendor_unit];
    let install_spec = private_spec(
        request,
        program,
        owner_home,
        entry_bin,
        lane_bin,
        codex_bin,
        codex_host_bin,
        image_digest,
        codex_sha256,
        tools_commit,
        false,
        Some(measured_source),
    )?
    .with_private_install(&verified_owner_home, &install_guard)?;
    destinations.push(json!({"path":unit_parent,"owner_uid":owner,"group_gid":group,"mode":"0700","exists":parent_exists}));
    destinations.push(json!({"path":unit_dir,"owner_uid":owner,"group_gid":group,"mode":"0700","exists":dir_exists}));
    for (file, exists) in unit_files.iter().zip(&existing) {
        destinations.push(json!({"path":file.path,"owner_uid":owner,"group_gid":group,"mode":"0644","exists":exists}));
    }
    destinations.push(json!({"path":worker_unit.path,"owner_uid":owner,"group_gid":group,"mode":"0644","exists":worker_unit_present,"action":if worker_unit_present { "retire" } else { "deferred" }}));
    destinations.push(json!({"path":settings_path,"owner_uid":owner,"group_gid":group,"mode":"0600","exists":true,"would_update":settings_change}));
    destinations.push(json!({"path":allocation_path,"owner_uid":owner,"group_gid":group,"mode":"0600","exists":true,"would_update":false}));
    let generation_changed = !same_generation || prior_generation.is_none();
    let private_changed = private["changed"].as_u64().ok_or_else(|| {
        LaneError::operation(
            "install-private",
            "private report lacks an unsigned changed count",
        )
    })?;
    let public_changed = u64::from(!parent_exists)
        + u64::from(!dir_exists)
        + existing.iter().filter(|exists| !**exists).count() as u64
        + u64::from(worker_unit_present)
        + u64::from(generation_changed)
        + u64::from(settings_change);
    let changed = private_changed.checked_add(public_changed).ok_or_else(|| {
        LaneError::operation(
            "install-private",
            "private change count exceeds the report range",
        )
    })?;
    let change_counts = json!({"private_destination_and_sign_in_operations":private_changed,"public_destination_updates":public_changed});
    if request.dry_run {
        let mut hash_checks: Vec<_> = payloads.iter().map(|payload| {
            json!({"input":payload.bin,"spec":hash_preview(payload.bin.parent().unwrap_or_else(|| Path::new("/")))})
        }).collect();
        hash_checks.push(json!({"input":request.proxy_bin,"spec":hash_preview(request.proxy_bin.parent().unwrap_or_else(|| Path::new("/")))}));
        return Ok(
            json!({"schema":1,"command":"install","pilot":request.pilot,"installed_backends":installed_backends,"dry_run":true,"changed":changed,"change_counts":change_counts,"allocation":allocation,"unit_dir":unit_dir,"destinations":destinations,"sign_in_metadata":private["sign_in"],"proxy_bin":request.proxy_bin,"proxy_sha256":proxy_sha256,"hash_checks":hash_checks,"private_hash_checks":private["hash_checks"],"private_preflight":preflight_spec.preview(),"private_install":install_spec.preview(),"activation":["systemctl --user daemon-reload",format!("systemctl --user start superloop-lane-vendor@{}.service", request.loop_name)],"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let mut generation = json!({"schema":1,"phase":"preparing","image_digest":image_digest,"codex_sha256":codex_sha256,"codex_host_sha256":codex_host_sha256,"tools_commit":tools_commit,"template_dir":template_dir,"socket_dir":socket_dir,"unit_dir":unit_dir,"proxy_bin":request.proxy_bin,"proxy_sha256":proxy_sha256,"init_sha256":init_sha256,"codex_image_program":image_program,"source_fingerprint":measured_source});
    vendor_generation_fields(&mut generation, &payloads, &row.home, hash)?;
    let refresh_needed = private["charter_refresh"] == true;
    let private_mutation = private["destinations"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|row| row["complete"] == false));
    let unit_mutation = !parent_exists
        || !dir_exists
        || existing.iter().any(|exists| !exists)
        || worker_unit_present;
    let pending_needed =
        generation_changed || resumable || refresh_needed || private_mutation || unit_mutation;
    if pending_needed {
        publish_generation(&generation_path, &generation)?;
    }
    let private_done = private_report(&install_spec, entry_bin, lane_bin)?;
    if private_done["changed"].as_u64() != Some(private_changed) {
        return Err(LaneError::operation(
            "install-private",
            "private change count differs from preview; inspect partial installation before repeating the preview",
        ));
    }
    let mut sync_unit_dir = |_: &Path, directory: &fs::File| directory.sync_all();
    if !parent_exists {
        ensure_directory_with_sync(&unit_parent, &mut sync_unit_dir)?;
    }
    if !dir_exists {
        ensure_directory_with_sync(&unit_dir, &mut sync_unit_dir)?;
    }
    for (file, exists) in unit_files.iter().zip(&existing) {
        if !exists {
            if request.repair && file.path.exists() {
                if checked_file_mode(file, owner, group, true)? {
                    return Err(LaneError::input(
                        "repair-unit",
                        format!("{} changed after preflight", file.path.display()),
                    ));
                }
                replace_unit(file, lane_bin)?;
            } else {
                write_unit(file, lane_bin)?;
            }
        }
    }
    if worker_unit_present {
        if !retired_dir_exists {
            ensure_directory_with_sync(&retired_dir, &mut sync_unit_dir)?;
            retired_dir_exists = true;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| LaneError::operation("install-retire", error.to_string()))?
            .as_nanos();
        let retired = retired_dir.join(format!(
            "superloop-lane-worker@{}.service-{nonce}",
            request.loop_name
        ));
        retire_worker_unit_with_sync(&worker_unit.path, &retired, &mut sync_unit_dir)?;
    }
    if settings_change {
        publish(&settings_path, updated.as_bytes())?;
    }
    checked_directory(&unit_parent, owner, group, 0o700)?;
    checked_directory(&unit_dir, owner, group, 0o700)?;
    for file in unit_files {
        checked_file(file, owner, group)?;
    }
    if pending_needed {
        complete_generation_after_unit_sync_with(
            &generation_path,
            &mut generation,
            &unit_parent,
            &unit_dir,
            retired_dir_exists.then_some(retired_dir.as_path()),
            &mut sync_unit_dir,
        )?;
    }
    let mut result = json!({"schema":1,"command":"install","pilot":request.pilot,"installed_backends":installed_backends,"dry_run":false,"changed":changed,"allocation":allocation,"unit_dir":unit_dir,"destinations":destinations,"proxy_bin":request.proxy_bin,"proxy_sha256":proxy_sha256,"template_dir":template_dir,"socket_dir":socket_dir,"sign_in_dir":owner_home.join(".config/loops").join(&request.loop_name).join("lanes/codex"),"sign_in_metadata":private_done["sign_in"],"unit_activation_performed":false,"activation":["systemctl --user daemon-reload",format!("systemctl --user start superloop-lane-vendor@{}.service", request.loop_name)],"wall_seconds":started.elapsed().as_secs_f64()});
    result["change_counts"] = change_counts;
    if codex.is_none() {
        result["sign_in_dir"] = Value::Null;
    }
    if settings.configures("claude") {
        result["claude_template_dir"] = json!(row.home.join("runner-templates/claude").join(hash));
    }
    Ok(result)
}

/// Run the installed private proxy in the rootless namespace for a loop.
///
/// # Errors
///
/// Refuses an absent or widened grant, missing helper, or failed proxy process.
#[allow(clippy::too_many_lines)]
pub fn run_proxy(owner_home: &Path, args: &[String]) -> Result<(), LaneError> {
    let [loop_name, option, proxy_bin] = args else {
        return Err(LaneError::input(
            "proxy-usage",
            "_proxy LOOP --proxy-bin FILE",
        ));
    };
    if option != "--proxy-bin" {
        return Err(LaneError::input(
            "proxy-usage",
            "_proxy LOOP --proxy-bin FILE",
        ));
    }
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let row = registry
        .row(loop_name, owner_home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let settings = Settings::read(
        &owner_home
            .join(".config/loops")
            .join(loop_name)
            .join("workers.toml"),
    )?;
    settings.validate_grant(owner_home, loop_name)?;
    if !settings.configures("codex") {
        return Err(LaneError::input(
            "missing-setting",
            "Codex is absent from backend_argv and vendor_hosts",
        ));
    }
    loop_home::allocations::Allocations::read(&loop_home::allocations::allocations_path(
        owner_home,
    ))
    .and_then(|allocations| allocations.require(loop_name))
    .map_err(|error| LaneError::input("allocations", error.message()))?;
    let socket_dir = row.home.join("sockets");
    if settings.socket_dir.as_deref() != Some(socket_dir.as_path()) {
        return Err(LaneError::input(
            "missing-setting",
            "socket_dir does not match the registry row",
        ));
    }
    let hosts = settings
        .vendor_hosts
        .get("codex")
        .filter(|hosts| !hosts.is_empty())
        .ok_or_else(|| {
            LaneError::input(
                "missing-setting",
                "vendor_hosts.codex has no observed hostnames",
            )
        })?;
    let podman_bin = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman_bin, nix::unistd::Uid::effective().as_raw())?;
    let proxy_bin = Path::new(proxy_bin);
    let proxy_word =
        crate::pinned::owner_executable_word(proxy_bin, nix::unistd::Uid::effective().as_raw())?;
    let socket_parent = socket_dir.join("vendor");
    let verified_socket =
        crate::home::pin_parent(&socket_parent, nix::unistd::Uid::effective().as_raw())?;
    let socket_fd = verified_socket.as_raw_fd();
    let mut command = Command::new(podman_bin);
    command
        .args(["unshare", proxy_word.as_str(), "--socket"])
        .arg(socket_dir.join("vendor/proxy.sock"))
        .args([
            "--group",
            &row.uid.to_string(),
            "--verified-socket-dir-fd",
            &socket_fd.to_string(),
        ])
        .arg("--owner-home")
        .arg(owner_home);
    #[allow(unsafe_code)]
    // SAFETY: only the async-signal-safe fcntl syscall runs before exec.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(socket_fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(socket_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    for host in hosts {
        command.arg("--host").arg(host);
    }
    let status = command
        .status()
        .map_err(|error| LaneError::operation("proxy-start", error.to_string()))?;
    if !status.success() {
        return Err(LaneError::operation(
            "proxy-exit",
            format!("private proxy exited {status}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FileDestination, InstallRequest, checked_file, checked_file_mode,
        complete_generation_after_unit_sync_with, ensure_directory_with_sync, private_report,
        publish_generation, read_generation, retire_worker_unit_with_sync, write_unit,
        write_unit_with_sync,
    };
    use crate::build::child;
    use crate::pinned::owner_executable;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::Path;

    /// ´test:unit:repair-unit-accepts-safe-byte-drift-and-refuses-unsafe-mode´
    #[test]
    fn repair_unit_accepts_safe_byte_drift_and_refuses_unsafe_mode() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let unit = FileDestination {
            path: fixture.path().join("vendor.service"),
            bytes: b"[Service]\n".to_vec(),
            mode: 0o644,
        };
        fs::write(&unit.path, b"drift").expect("drifted unit");
        fs::set_permissions(&unit.path, fs::Permissions::from_mode(0o644)).expect("safe mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        assert!(!checked_file_mode(&unit, owner, group, true).expect("repairable unit"));
        assert_eq!(
            checked_file_mode(&unit, owner, group, false)
                .expect_err("ordinary install refuses drift")
                .kind,
            "install-conflict"
        );
        fs::set_permissions(&unit.path, fs::Permissions::from_mode(0o600)).expect("unsafe mode");
        assert_eq!(
            checked_file_mode(&unit, owner, group, true)
                .expect_err("unsafe unit")
                .kind,
            "repair-unit"
        );
    }

    /// ´test:unit:fresh-owner-unit-directories-and-retirement-sync-in-order´
    #[test]
    fn fresh_owner_unit_directories_and_retirement_sync_in_order() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let unit_parent = fixture.path().join("systemd");
        let unit_dir = unit_parent.join("user");
        let retired_dir = unit_dir.join("retired");
        let worker_unit = unit_dir.join("superloop-lane-worker@alpha.service");
        let retired = retired_dir.join("superloop-lane-worker@alpha.service-old");
        let mut synced = Vec::new();
        let mut sync = |path: &Path, directory: &fs::File| {
            assert!(directory.metadata()?.is_dir());
            synced.push(path.to_path_buf());
            directory.sync_all()
        };
        ensure_directory_with_sync(&unit_parent, &mut sync).expect("unit parent");
        ensure_directory_with_sync(&unit_dir, &mut sync).expect("unit directory");
        fs::write(&worker_unit, b"[Unit]\n").expect("legacy worker unit");
        ensure_directory_with_sync(&retired_dir, &mut sync).expect("retired directory");
        retire_worker_unit_with_sync(&worker_unit, &retired, &mut sync)
            .expect("durable retirement");
        assert_eq!(
            synced,
            [
                fixture.path().to_path_buf(),
                unit_parent,
                unit_dir.clone(),
                unit_dir,
                retired_dir,
            ]
        );
        assert!(!worker_unit.exists());
        assert_eq!(fs::read(retired).expect("retired unit"), b"[Unit]\n");
    }

    /// ´test:unit:fresh-owner-directory-retry-syncs-existing-entry´
    #[test]
    fn fresh_owner_directory_retry_syncs_existing_entry() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let generation_path = fixture.path().join("install-generation.json");
        let mut generation = serde_json::json!({"schema":1,"phase":"preparing"});
        publish_generation(&generation_path, &generation).expect("pending record");
        let unit_parent = fixture.path().join("systemd");
        let unit_dir = unit_parent.join("user");
        let mut fail = |_: &Path, _: &fs::File| Err(std::io::Error::other("interrupted sync"));
        ensure_directory_with_sync(&unit_parent, &mut fail).expect_err("parent sync interrupted");
        assert!(unit_parent.is_dir());
        assert_eq!(
            read_generation(&generation_path)
                .expect("record")
                .expect("pending")["phase"],
            "preparing"
        );
        fs::create_dir(&unit_dir).expect("retry creates unit directory");
        let vendor = unit_dir.join("superloop-lane-vendor@alpha.service");
        fs::write(&vendor, b"[Unit]\n").expect("published unit before interrupted sync");
        let mut synced = Vec::new();
        let mut sync = |path: &Path, directory: &fs::File| {
            assert_eq!(
                read_generation(&generation_path)
                    .expect("record")
                    .expect("pending")["phase"],
                "preparing"
            );
            synced.push(path.to_path_buf());
            directory.sync_all()
        };
        complete_generation_after_unit_sync_with(
            &generation_path,
            &mut generation,
            &unit_parent,
            &unit_dir,
            None,
            &mut sync,
        )
        .expect("retry syncs entries before completion");
        assert_eq!(
            synced,
            [fixture.path().to_path_buf(), unit_parent, unit_dir]
        );
        assert_eq!(
            read_generation(&generation_path)
                .expect("record")
                .expect("complete")["phase"],
            "complete"
        );
        assert_eq!(fs::read(vendor).expect("unit survives"), b"[Unit]\n");
    }

    /// ´test:unit:retired-worker-unit-retry-syncs-both-directories´
    #[test]
    fn retired_worker_unit_retry_syncs_both_directories() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let generation_path = fixture.path().join("install-generation.json");
        let mut generation = serde_json::json!({"schema":1,"phase":"preparing"});
        publish_generation(&generation_path, &generation).expect("pending record");
        let unit_parent = fixture.path().join("systemd");
        let unit_dir = unit_parent.join("user");
        let retired_dir = unit_dir.join("retired");
        fs::create_dir_all(&retired_dir).expect("unit directories");
        let worker = unit_dir.join("superloop-lane-worker@alpha.service");
        let retired = retired_dir.join("superloop-lane-worker@alpha.service-old");
        fs::write(&worker, b"[Unit]\n").expect("legacy worker unit");
        let mut fail = |_: &Path, _: &fs::File| Err(std::io::Error::other("interrupted sync"));
        retire_worker_unit_with_sync(&worker, &retired, &mut fail)
            .expect_err("sync interrupted after rename");
        assert!(!worker.exists());
        assert!(retired.exists());
        assert_eq!(
            read_generation(&generation_path)
                .expect("record")
                .expect("pending")["phase"],
            "preparing"
        );
        let mut synced = Vec::new();
        let mut sync = |path: &Path, directory: &fs::File| {
            assert_eq!(
                read_generation(&generation_path)
                    .expect("record")
                    .expect("pending")["phase"],
                "preparing"
            );
            synced.push(path.to_path_buf());
            directory.sync_all()
        };
        complete_generation_after_unit_sync_with(
            &generation_path,
            &mut generation,
            &unit_parent,
            &unit_dir,
            Some(&retired_dir),
            &mut sync,
        )
        .expect("retry syncs both sides before completion");
        assert_eq!(
            synced,
            [
                fixture.path().to_path_buf(),
                unit_parent,
                unit_dir,
                retired_dir,
            ]
        );
        assert_eq!(
            read_generation(&generation_path)
                .expect("record")
                .expect("complete")["phase"],
            "complete"
        );
        assert_eq!(fs::read(retired).expect("retired unit"), b"[Unit]\n");
    }

    /// ´test:unit:fresh-unit-publication-syncs-final-mode-and-directory´
    #[test]
    fn fresh_unit_publication_syncs_final_mode_and_directory() {
        if let Some(home) = std::env::var_os("UNIT_UMASK_TEST_HOME") {
            let home = Path::new(&home);
            let lane_bin = home.join("lane");
            fs::write(&lane_bin, b"#!/bin/sh\nexit 0\n").expect("lane fixture");
            fs::set_permissions(&lane_bin, fs::Permissions::from_mode(0o700)).expect("lane mode");
            let unit = FileDestination {
                path: home.join("vendor.service"),
                bytes: b"[Service]\nExecStart=/fixture/lane\n".to_vec(),
                mode: 0o644,
            };
            let mut syncs = Vec::new();
            let mut sync = |opened: &fs::File| {
                let metadata = opened.metadata()?;
                syncs.push((metadata.is_dir(), metadata.permissions().mode() & 0o7777));
                opened.sync_all()
            };
            write_unit_with_sync(&unit, &lane_bin, false, &mut sync)
                .expect("fresh unit publication");
            assert_eq!(syncs, [(false, 0o000), (false, 0o644), (true, 0o700)]);
            assert_eq!(
                fs::metadata(&unit.path)
                    .expect("published unit")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o644
            );
            assert!(
                checked_file(
                    &unit,
                    nix::unistd::Uid::effective().as_raw(),
                    nix::unistd::Gid::effective().as_raw(),
                )
                .expect("repeat check")
            );
            assert_eq!(fs::read_dir(home).expect("unit directory").count(), 2);
            return;
        }
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let output = std::process::Command::new("sh")
            .args(["-c", "umask 0777; exec \"$1\" \"$2\"", "sh"])
            .arg(std::env::current_exe().expect("test binary"))
            .arg("fresh_unit_publication_syncs_final_mode_and_directory")
            .env("UNIT_UMASK_TEST_HOME", fixture.path())
            .output()
            .expect("child test");
        assert!(
            output.status.success(),
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// ´test:unit:install-defaults-are-resolved-after-parse´
    #[test]
    fn install_defaults_are_resolved_after_parse() {
        let request =
            InstallRequest::parse(&["--pilot".into(), "alpha".into()]).expect("runtime defaults");
        assert_eq!(request.podman_bin, None);
        let explicit = InstallRequest::parse(&[
            "alpha".into(),
            "--podman-bin".into(),
            "/usr/bin/podman".into(),
        ])
        .expect("explicit default program");
        assert_eq!(
            explicit.podman_bin.as_deref(),
            Some(Path::new("/usr/bin/podman"))
        );
        assert!(request.proxy_bin.as_os_str().is_empty());
        assert!(request.data_dir.as_os_str().is_empty());
        assert!(
            InstallRequest::parse(&["alpha".into(), "--proxy-bin".into(), String::new()]).is_err()
        );
    }

    /// ´test:unit:runtime-proxy-default-verifies-sibling-before-fallback´
    #[test]
    fn runtime_proxy_default_verifies_sibling_before_fallback() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let lane = home.join("superloop-lane");
        let sibling = home.join("superloop-lane-vendor-proxy");
        let provenance = home.join("superloop-lane-vendor-proxy.provenance");
        if let Some(configured) = option_env!("SUPERLOOP_LANE_PROXY_BIN") {
            assert_eq!(
                super::default_proxy_bin(&lane, home).expect("Meson fallback"),
                std::path::PathBuf::from(configured)
            );
        } else {
            let error = super::default_proxy_bin(&lane, home)
                .expect_err("first installation without any source");
            assert_eq!(error.kind, "proxy-program");
            assert!(error.detail.contains("--proxy-bin"));
        }
        fs::write(
            home.join("install-generation.json"),
            br#"{"schema":1,"phase":"complete","proxy_bin":"/recorded/proxy"}"#,
        )
        .expect("recorded fallback");
        assert_eq!(
            super::default_proxy_bin(&lane, home).expect("recorded fallback"),
            std::path::Path::new("/recorded/proxy")
        );
        crate::fixture_exec::write_executable(&sibling, b"#!/bin/sh\nexit 0\n").expect("sibling");
        assert_eq!(
            super::default_proxy_bin(&lane, home)
                .expect_err("missing provenance never falls through")
                .kind,
            "proxy-provenance"
        );
        let digest = crate::build::sha256(&sibling).expect("digest");
        fs::write(
            &provenance,
            format!("source-commit: fixture\nsha256-prefix: {}\n", &digest[..16]),
        )
        .expect("provenance");
        fs::set_permissions(&provenance, fs::Permissions::from_mode(0o644))
            .expect("provenance mode");
        assert_eq!(
            super::default_proxy_bin(&lane, home).expect("verified sibling"),
            sibling
        );
        for source in [
            "sha256-prefix: bad\n",
            "sha256-prefix: 0000000000000000\n",
            "sha256-prefix: 0000000000000000\nsha256-prefix: 0000000000000000\n",
        ] {
            fs::write(&provenance, source).expect("invalid provenance");
            let error =
                super::default_proxy_bin(&lane, home).expect_err("present invalid sibling refuses");
            assert_eq!(error.kind, "proxy-provenance");
            assert!(
                error
                    .detail
                    .contains("superloop-lane-vendor-proxy.provenance")
            );
        }
        fs::remove_file(&sibling).expect("remove sibling");
        assert_eq!(
            super::default_proxy_bin(&lane, home).expect("absent sibling uses record"),
            std::path::Path::new("/recorded/proxy")
        );
    }

    /// ´test:unit:install-refuses-a-loop-writable-entry-before-private-preflight´
    #[test]
    fn install_refuses_a_loop_writable_entry_before_private_preflight() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let writable = fixture.path().join("loop-writable");
        fs::create_dir(&writable).expect("writable parent");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).expect("parent mode");
        let entry = writable.join("entry");
        fs::write(&entry, b"#!/bin/sh\nexit 0\n").expect("entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
        let spec = child(
            Path::new("/usr/bin/true"),
            Vec::new(),
            &BTreeMap::new(),
            fixture.path(),
            1,
            "install-private",
        );
        let error = private_report(&spec, &entry, Path::new("/usr/bin/true"))
            .expect_err("loop can replace entry");
        assert_eq!(error.kind, "owner-program");
    }

    /// ´test:unit:install-rechecks-entry-replaced-after-private-preflight´
    #[test]
    fn install_rechecks_entry_replaced_after_private_preflight() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let entry = fixture.path().join("entry");
        fs::write(&entry, b"#!/bin/sh\nexit 0\n").expect("entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        owner_executable(&entry, owner).expect("initial preflight");
        fs::remove_file(&entry).expect("remove checked inode");
        symlink("/usr/bin/true", &entry).expect("replace with link");
        let spec = child(
            Path::new("/usr/bin/true"),
            Vec::new(),
            &BTreeMap::new(),
            fixture.path(),
            1,
            "install-private",
        );
        let error = private_report(&spec, &entry, Path::new("/usr/bin/true"))
            .expect_err("entry changed after preflight");
        assert_eq!(error.kind, "owner-program");
    }

    /// ´test:unit:install-rechecks-lane-binary-replaced-before-private-execution´
    #[test]
    fn install_rechecks_lane_binary_replaced_before_private_execution() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let lane_bin = fixture.path().join("lane");
        fs::write(&lane_bin, b"#!/bin/sh\nexit 0\n").expect("lane binary");
        fs::set_permissions(&lane_bin, fs::Permissions::from_mode(0o700))
            .expect("lane binary mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        owner_executable(&lane_bin, owner).expect("initial invocation");
        fs::remove_file(&lane_bin).expect("remove measured pathname");
        symlink("/usr/bin/true", &lane_bin).expect("replace with link");
        let spec = child(
            Path::new("/usr/bin/true"),
            Vec::new(),
            &BTreeMap::new(),
            fixture.path(),
            1,
            "install-private",
        );
        let error = private_report(&spec, Path::new("/usr/bin/true"), &lane_bin)
            .expect_err("replacement refused before private execution");
        assert_eq!(error.kind, "owner-program");
    }

    /// ´test:unit:install-refuses-replaced-lane-binary-before-unit-publication´
    #[test]
    fn install_refuses_replaced_lane_binary_before_unit_publication() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let lane_bin = fixture.path().join("lane");
        symlink("/usr/bin/true", &lane_bin).expect("replace with link");
        let destination = fixture.path().join("vendor.service");
        let unit = FileDestination {
            path: destination.clone(),
            bytes: b"[Service]\nExecStart=/fixture/lane\n".to_vec(),
            mode: 0o644,
        };
        let error = write_unit(&unit, &lane_bin).expect_err("unit publication refused");
        assert_eq!(error.kind, "owner-program");
        assert!(!destination.exists());
    }
}

#[cfg(test)]
mod generation_tests {
    use super::generation_matches;
    use serde_json::json;
    use std::path::Path;

    /// ´test:unit:install-generation-rejects-a-changed-socket-directory´
    #[test]
    fn install_generation_rejects_a_changed_socket_directory() {
        let record = json!({"image_digest":"sha256:abc","codex_sha256":"def","tools_commit":"ghi","template_dir":"/fixture/template","socket_dir":"/fixture/sockets"});
        let template = Path::new("/fixture/template");
        assert!(generation_matches(
            &record,
            "sha256:abc",
            "def",
            "ghi",
            template,
            Path::new("/fixture/sockets")
        ));
        assert!(!generation_matches(
            &record,
            "sha256:abc",
            "def",
            "ghi",
            template,
            Path::new("/fixture/other-sockets")
        ));
    }
}
