//! Loop correspondence: owner UID is provenance; letter bytes are untrusted data.

mod follow;
mod metadata;
mod record;
mod store;
#[cfg(test)]
mod tests;
mod wake;

pub use metadata::{LetterMetadata, letter_metadata, parse_letter_metadata};

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::Path;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{Gid, Uid};

use crate::allocations::Allocations;
use crate::ensure::{
    EnsureClass, EnsureFailure, RootOwner, StandardRoot, ensure_roots, standard_roots,
};
use crate::{LoopError, Registry};

#[cfg(test)]
thread_local! {
    static HOME_ANCHOR: std::cell::RefCell<Option<(std::path::PathBuf, OwnedFd)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct NamespaceFixture;

#[cfg(test)]
impl Drop for NamespaceFixture {
    fn drop(&mut self) {
        HOME_ANCHOR.with(|anchor| {
            anchor.borrow_mut().take();
        });
    }
}

#[cfg(test)]
fn activate_fixture(home: &Path, inherited: &OwnedFd) -> Result<NamespaceFixture, LoopError> {
    check_dir(
        inherited,
        home,
        Uid::effective().as_raw(),
        None,
        DirectoryMode::Exact(0o700),
    )?;
    let held = nix::unistd::dup(inherited).map_err(io_error)?;
    HOME_ANCHOR.with(|anchor| {
        *anchor.borrow_mut() = Some((home.to_path_buf(), held));
    });
    Ok(NamespaceFixture)
}

fn io_error(error: impl std::fmt::Display) -> LoopError {
    LoopError::runtime(format!("letters IO failure: {error}"))
}

fn unsafe_path(error: impl std::fmt::Display) -> LoopError {
    LoopError::refusal(format!("letters unsafe path: {error}"))
}

fn path_error(name: &Path, error: nix::errno::Errno) -> LoopError {
    use nix::errno::Errno;
    let message = format!("{}: {error}", name.display());
    match error {
        Errno::ELOOP | Errno::EXDEV | Errno::ENOTDIR => unsafe_path(message),
        _ => io_error(message),
    }
}

fn open_beneath(fd: &OwnedFd, name: &Path, flags: OFlag, mode: u32) -> nix::Result<OwnedFd> {
    openat2(
        fd,
        name,
        OpenHow::new()
            .flags(flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .mode(Mode::from_bits_truncate(mode))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
}

fn beneath(fd: &OwnedFd, name: &Path, flags: OFlag, mode: u32) -> Result<OwnedFd, LoopError> {
    open_beneath(fd, name, flags, mode).map_err(|error| path_error(name, error))
}

fn pin_home(home: &Path) -> Result<OwnedFd, LoopError> {
    pin_owner_path(home, None)
}

fn pin_owner_path(home: &Path, owner_uid: Option<u32>) -> Result<OwnedFd, LoopError> {
    #[cfg(test)]
    if let Some(held) = HOME_ANCHOR.with(|anchor| {
        anchor
            .borrow()
            .as_ref()
            .filter(|(path, _)| path == home)
            .map(|(_, fd)| nix::unistd::dup(fd))
    }) {
        return held.map_err(io_error);
    }
    if !home.is_absolute() {
        return Err(unsafe_path("owner home must be absolute"));
    }
    let fd = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;
    walk_owner_path(fd, home.strip_prefix("/").map_err(io_error)?, owner_uid)
}

fn walk_owner_path(
    mut fd: OwnedFd,
    relative: &Path,
    owner_uid: Option<u32>,
) -> Result<OwnedFd, LoopError> {
    let root = store::stat(&fd)?;
    let system_uid = root.st_uid;
    let mut ancestors = vec![(std::ffi::OsString::from("/"), root)];
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(unsafe_path("dotted owner home"));
        };
        fd = beneath(&fd, Path::new(name), OFlag::O_PATH | OFlag::O_DIRECTORY, 0)?;
        ancestors.push((name.to_owned(), store::stat(&fd)?));
    }
    let owner = owner_uid.unwrap_or(store::stat(&fd)?.st_uid);
    for (name, stat) in ancestors {
        if stat.st_uid != system_uid && stat.st_uid != owner
            || stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0
        {
            return Err(unsafe_path(format!(
                "unsafe owner-home ancestor: {}",
                name.to_string_lossy()
            )));
        }
    }
    Ok(fd)
}

struct OwnerRoots {
    home: OwnedFd,
    config: OwnedFd,
    uid: u32,
    gid: u32,
}

fn config(home_path: &Path) -> Result<Option<OwnerRoots>, LoopError> {
    let home = pin_home(home_path)?;
    let identity = store::stat(&home)?;
    let uid = identity.st_uid;
    let gid = identity.st_gid;
    let mut fd = nix::unistd::dup(&home).map_err(io_error)?;
    for (name, access, mode) in [
        (".config", OFlag::O_PATH, DirectoryMode::CheckedConfig),
        ("loops", OFlag::O_RDONLY, DirectoryMode::Exact(0o700)),
    ] {
        let next = match openat2(
            &fd,
            name,
            OpenHow::new()
                .flags(access | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(path_error(Path::new(name), error)),
        };
        let path = home_path.join(if name == ".config" {
            ".config"
        } else {
            ".config/loops"
        });
        check_dir(&next, &path, uid, Some(gid), mode)?;
        fd = next;
    }
    Ok(Some(OwnerRoots {
        home,
        config: fd,
        uid,
        gid,
    }))
}

#[derive(Clone, Copy)]
enum DirectoryMode {
    Exact(u32),
    CheckedDurable,
    CheckedConfig,
}

impl DirectoryMode {
    const fn accepts(self, mode: u32) -> bool {
        match self {
            Self::Exact(expected) => mode & 0o7777 == expected,
            Self::CheckedDurable => mode & 0o001 != 0 && mode & 0o022 == 0,
            Self::CheckedConfig => true,
        }
    }

    fn expected(self) -> String {
        match self {
            Self::Exact(mode) => format!("{mode:04o}"),
            Self::CheckedDurable => "search for others; no group or other write".to_owned(),
            Self::CheckedConfig => "any (checked configuration root)".to_owned(),
        }
    }
}

fn check_dir(
    fd: &OwnedFd,
    path: &Path,
    uid: u32,
    gid: Option<u32>,
    mode: DirectoryMode,
) -> Result<(), LoopError> {
    let stat = store::stat(fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || stat.st_uid != uid
        || gid.is_some_and(|gid| stat.st_gid != gid)
        || !mode.accepts(stat.st_mode)
    {
        return Err(LoopError::refusal(format!(
            "letters directory mismatch: \"{}\"; observed uid={} gid={} mode={:04o}; expected directory uid={uid} gid={} mode={}",
            path.to_string_lossy().escape_debug(),
            stat.st_uid,
            stat.st_gid,
            stat.st_mode & 0o7777,
            gid.map_or_else(|| "any".to_owned(), |gid| gid.to_string()),
            mode.expected()
        )));
    }
    Ok(())
}

fn read_registry(config: &OwnerRoots) -> Result<Registry, LoopError> {
    let fd = if let Some(path) = std::env::var_os("ENTER_LOOP_REGISTRY") {
        let path = Path::new(&path);
        let parent = path
            .parent()
            .ok_or_else(|| io_error("registry has no parent"))?;
        let parent = pin_owner_path(parent, Some(config.uid))?;
        let name = path
            .file_name()
            .ok_or_else(|| io_error("registry has no filename"))?;
        beneath(
            &parent,
            Path::new(name),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            0,
        )?
    } else {
        beneath(
            &config.config,
            Path::new("registry.toml"),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK,
            0,
        )?
    };
    let stat = store::stat(&fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != config.uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(unsafe_path("unsafe registry"));
    }
    crate::registry::load_registry_from_file(&mut File::from(fd))
}

#[allow(unsafe_code)]
fn lock(fd: &OwnedFd, name: &str) -> Result<(), LoopError> {
    // SAFETY: flock only operates on the held directory descriptor.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io_error(format!(
            "{name} lock: {}",
            std::io::Error::last_os_error()
        )))
    }
}

pub fn group(home: &Path, create: bool) -> Result<Option<u32>, LoopError> {
    group_inner(home, create, false)
}

pub fn planned_group(home: &Path) -> Result<Option<u32>, LoopError> {
    group_inner(home, false, true)
}

fn ledger_file(config: &OwnerRoots, create: bool) -> Result<Option<OwnedFd>, LoopError> {
    let flags = if create {
        OFlag::O_RDWR | OFlag::O_CREAT
    } else {
        OFlag::O_RDONLY
    };
    let fd = match open_beneath(
        &config.config,
        Path::new("allocations.toml"),
        flags | OFlag::O_NONBLOCK,
        if create { 0o600 } else { 0 },
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) if !create => return Ok(None),
        Err(error) => return Err(path_error(Path::new("allocations.toml"), error)),
    };
    let stat = store::stat(&fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || stat.st_uid != config.uid
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(unsafe_path("unsafe allocations.toml"));
    }
    Ok(Some(fd))
}

fn read_ledger(config: &OwnerRoots) -> Result<(Allocations, Option<OwnedFd>), LoopError> {
    let Some(fd) = ledger_file(config, false)? else {
        return Ok((Allocations::default(), None));
    };
    let mut source = Vec::new();
    File::from(nix::unistd::dup(&fd).map_err(io_error)?)
        .take(crate::allocations::MAX_ALLOCATIONS + 1)
        .read_to_end(&mut source)
        .map_err(io_error)?;
    if source.len() as u64 > crate::allocations::MAX_ALLOCATIONS {
        return Err(LoopError::refusal("letters oversized allocations.toml"));
    }
    let source = std::str::from_utf8(&source)
        .map_err(|_| LoopError::refusal("letters malformed allocations.toml"))?;
    Ok((Allocations::parse(source)?, Some(fd)))
}

fn select_group(
    ledger: &mut Allocations,
    config: &OwnerRoots,
    home: &Path,
) -> Result<u32, LoopError> {
    let registry = read_registry(config)?;
    let uids = registry
        .rows(home)
        .iter()
        .map(|row| row.uid)
        .collect::<Vec<_>>();
    ledger.ensure_letters_gid(&uids)
}

fn group_inner(home: &Path, create: bool, planning: bool) -> Result<Option<u32>, LoopError> {
    let config = match config(home)? {
        Some(fd) => fd,
        None if !create => return Ok(None),
        None => return Err(LoopError::refusal("letters missing owner configuration")),
    };
    group_from_roots(&config, home, create, planning)
}

fn group_from_roots(
    config: &OwnerRoots,
    home: &Path,
    create: bool,
    planning: bool,
) -> Result<Option<u32>, LoopError> {
    let (mut ledger, _) = read_ledger(config)?;
    let present = ledger.letters_gid().is_some();
    let gid = select_group(&mut ledger, config, home)?;
    if present || !create {
        return Ok((present || planning).then_some(gid));
    }
    #[cfg(test)]
    store::race("grant-absent");
    // Match the allocator: configuration root first, then the current ledger inode.
    // Existing grants take neither lock, even during another entry or assembly.
    lock(&config.config, "configuration root")?;
    let locked = ledger_file(config, true)?
        .ok_or_else(|| io_error("allocation ledger disappeared before locking"))?;
    lock(&locked, "allocations.toml")?;
    #[cfg(test)]
    store::race("grant-locked");
    let (mut ledger, named) = read_ledger(config)?;
    let named = named.ok_or_else(|| io_error("allocation ledger disappeared under lock"))?;
    let held = fstat(&locked).map_err(io_error)?;
    let current = fstat(&named).map_err(io_error)?;
    if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino) {
        return Err(unsafe_path("allocations.toml replaced before allocation"));
    }
    let present = ledger.letters_gid().is_some();
    let gid = select_group(&mut ledger, config, home)?;
    if present {
        return Ok(Some(gid));
    }
    let source = ledger.to_toml();
    if source.len() as u64 > crate::allocations::MAX_ALLOCATIONS {
        return Err(LoopError::refusal("letters oversized allocations.toml"));
    }
    let name = format!(".allocations-{}", store::random_suffix()?);
    let fd = beneath(
        &config.config,
        Path::new(&name),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
        0o600,
    )?;
    let mut file = File::from(fd);
    let result = (|| {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
        file.write_all(source.as_bytes()).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        nix::fcntl::renameat(
            &config.config,
            name.as_str(),
            &config.config,
            "allocations.toml",
        )
        .map_err(io_error)?;
        nix::unistd::fsync(&config.config).map_err(io_error)
    })();
    if result.is_err() {
        let _removed = nix::unistd::unlinkat(
            &config.config,
            name.as_str(),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        );
    }
    result?;
    Ok(Some(gid))
}

pub fn add_roots(rows: &mut Vec<StandardRoot>, home: &Path, name: &str, gid: u32) {
    let root = home.join(".var/loops").join(name);
    for (suffix, owner, mode) in [
        ("inbox", RootOwner::Shared(gid), 0o710),
        ("inbox/new", RootOwner::Shared(gid), 0o1730),
        ("inbox/cur", RootOwner::Loop, 0o700),
    ] {
        rows.push(StandardRoot {
            path: root.join(suffix),
            owner,
            mode,
            ensure: EnsureClass::Created,
        });
    }
}

pub fn ensure_layout(
    home: &Path,
    name: &str,
    uid: u32,
    report: &mut File,
) -> Result<(), EnsureFailure> {
    let failure = |error: LoopError| EnsureFailure {
        path: home.to_path_buf(),
        reason: error.message().to_owned(),
    };
    let mut rows = standard_roots(home, name);
    // Retain the preparing step's original first-owner refusal outside its namespace.
    if Uid::effective().as_raw() != 0 {
        return ensure_roots(&rows, (0, 0), (uid, uid), report).map(|_| ());
    }
    let previous = group(home, false).map_err(failure)?;
    if let Some(gid) = previous {
        add_roots(&mut rows, home, name, gid);
    }
    ensure_roots(&rows, (0, 0), (uid, uid), report)?;
    let gid = group(home, true)
        .map_err(failure)?
        .ok_or_else(|| failure(io_error("missing group")))?;
    if previous.is_none() {
        writeln!(
            report,
            "created {}:letters_gid 0600",
            home.join(".config/loops/allocations.toml").display()
        )
        .map_err(|error| failure(io_error(error)))?;
    }
    let mut rows = standard_roots(home, name);
    add_roots(&mut rows, home, name, gid);
    ensure_roots(&rows, (0, 0), (uid, uid), report)?;
    Ok(())
}

fn build_context(name: &str, home: &Path) -> Result<store::Context, LoopError> {
    let config =
        config(home)?.ok_or_else(|| LoopError::refusal("letters missing owner configuration"))?;
    let registry = read_registry(&config)?;
    let row = registry.row(name, home)?;
    let gid = group_from_roots(&config, home, false, false)?
        .ok_or_else(|| LoopError::refusal("letters missing letters group"))?;
    let durable = beneath(
        &config.home,
        Path::new(".var"),
        OFlag::O_PATH | OFlag::O_DIRECTORY,
        0,
    )?;
    check_dir(
        &durable,
        &home.join(".var"),
        config.uid,
        Some(config.gid),
        DirectoryMode::CheckedDurable,
    )?;
    let loops = beneath(
        &durable,
        Path::new("loops"),
        OFlag::O_PATH | OFlag::O_DIRECTORY,
        0,
    )?;
    check_dir(
        &loops,
        &home.join(".var/loops"),
        config.uid,
        Some(config.gid),
        DirectoryMode::Exact(0o711),
    )?;
    drop(durable);
    Ok(store::Context {
        loops,
        rows: registry.rows(home),
        uid: row.uid,
        gid,
        root_uid: config.uid,
    })
}

pub fn private_entry(
    arguments: &[String],
    output: &mut impl std::io::Write,
    report: &mut impl std::io::Write,
) -> Result<(), LoopError> {
    let [name, home, command @ ..] = arguments else {
        return Err(LoopError::refusal(
            "letters private entry needs loop and owner home",
        ));
    };
    #[cfg(test)]
    let fixture = HOME_ANCHOR.with(|anchor| anchor.borrow().is_some());
    #[cfg(not(test))]
    let fixture = false;
    if Uid::effective().as_raw() != 0 && !fixture {
        return Err(LoopError::refusal(
            "letters private entry requires namespace root",
        ));
    }
    let context = build_context(name, Path::new(home))?;
    if !fixture {
        enter_identity(&context)?;
    }
    let actions = store::command_with_report(
        &context,
        command,
        &mut std::io::stdin().lock(),
        output,
        report,
    )?;
    writeln!(report, "LETTERS actions={actions}").map_err(io_error)
}

fn enter_identity(context: &store::Context) -> Result<(), LoopError> {
    nix::unistd::setgroups(&[Gid::from_raw(context.gid)]).map_err(io_error)?;
    nix::unistd::setresgid(
        Gid::from_raw(context.uid),
        Gid::from_raw(context.uid),
        Gid::from_raw(context.uid),
    )
    .map_err(io_error)?;
    nix::unistd::setresuid(
        Uid::from_raw(context.uid),
        Uid::from_raw(context.uid),
        Uid::from_raw(context.uid),
    )
    .map_err(io_error)?;
    nix::sys::prctl::set_no_new_privs().map_err(io_error)?;
    Ok(())
}
