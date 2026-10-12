//! Descriptor-pinned custody binds in the entry's nested mount namespace.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::mount::{MsFlags, mount};
use nix::sys::stat::{Mode, SFlag, fstat};

const USAGE: &str = "usage: superloop bind-custody UID LOOP_HOME ENTERED TIER";

/// A refused custody path and its reason.
#[derive(Debug, PartialEq, Eq)]
pub struct CustodyFailure {
    /// Path whose open, check or bind was refused.
    pub path: PathBuf,
    /// The reason for the refusal.
    pub reason: String,
}

impl fmt::Display for CustodyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "custody bind refused: {}: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for CustodyFailure {}

fn refused(path: &Path, reason: impl Into<String>) -> CustodyFailure {
    CustodyFailure {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn flags() -> OFlag {
    OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC
}

/// Walk normal directory components beneath a held descriptor.
///
/// The caller supplies its already checked anchor and its custody policy. No
/// identity is inferred from ambient paths or translated between namespaces.
///
/// # Errors
///
/// Returns the caller's error for a non-normal component, failed descriptor
/// open or metadata read, or rejected parent-to-child custody check.
pub fn walk_directories<E>(
    mut parent: OwnedFd,
    mut stat: nix::sys::stat::FileStat,
    prefix: &Path,
    relative: &Path,
    flags: OFlag,
    mut verify: impl FnMut(&nix::sys::stat::FileStat, &nix::sys::stat::FileStat, &Path) -> Result<(), E>,
    error: impl Fn(&Path, String) -> E,
) -> Result<(OwnedFd, nix::sys::stat::FileStat), E> {
    let mut path = prefix.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(error(&path, "dotted component".into()));
        };
        let parent_path = path.clone();
        path.push(name);
        let how = OpenHow::new()
            .flags(flags | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        let next = openat2(&parent, Path::new(name), how)
            .map_err(|failure| error(&path, failure.to_string()))?;
        let next_stat = fstat(&next).map_err(|failure| error(&path, failure.to_string()))?;
        verify(&stat, &next_stat, &parent_path)?;
        parent = next;
        stat = next_stat;
    }
    Ok((parent, stat))
}

fn beneath(parent: &OwnedFd, component: &str, path: &Path) -> Result<OwnedFd, CustodyFailure> {
    let how = OpenHow::new()
        .flags(flags())
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
    openat2(parent, component, how).map_err(|error| refused(path, format!("{error:?}")))
}

/// The four checked endpoints kept open until both binds complete.
#[derive(Debug)]
pub struct PinnedCustody {
    /// Custody tier source.
    pub tier: OwnedFd,
    /// Entered home's custody target.
    pub custody_target: OwnedFd,
    /// Custody SSH source.
    pub ssh_source: OwnedFd,
    /// Entered home's SSH target.
    pub ssh_target: OwnedFd,
    custody_path: PathBuf,
    ssh_target_path: PathBuf,
}

/// Open every component before checking any, then require loop-owned directories.
///
/// # Errors
///
/// Returns the first path that fails its open or ownership check.
pub fn pin_custody(
    uid: u32,
    home: &Path,
    entered: &Path,
    tier: &Path,
) -> Result<PinnedCustody, CustodyFailure> {
    let mut private_text = home.as_os_str().to_os_string();
    private_text.push("/private");
    let private = PathBuf::from(private_text);
    let entered_is_home = entered.as_os_str() == home.as_os_str();
    if !entered_is_home && entered.as_os_str() != private.as_os_str() {
        return Err(refused(
            entered,
            "not the registry home or its private tier",
        ));
    }
    let custody_path = entered.join(".config/custody");
    let ssh_target_path = entered.join(".ssh");
    let ssh_source_path = tier.join("ssh");

    let home_fd =
        open(home, flags(), Mode::empty()).map_err(|error| refused(home, format!("{error:?}")))?;
    let entered_fd = beneath(
        &home_fd,
        if entered_is_home { "." } else { "private" },
        entered,
    )?;
    let custody_target = beneath(&entered_fd, ".config/custody", &custody_path)?;
    let ssh_target = beneath(&entered_fd, ".ssh", &ssh_target_path)?;
    let tier_fd =
        open(tier, flags(), Mode::empty()).map_err(|error| refused(tier, format!("{error:?}")))?;
    let ssh_source = beneath(&tier_fd, "ssh", &ssh_source_path)?;

    for (fd, path) in [
        (&home_fd, home),
        (&entered_fd, entered),
        (&custody_target, custody_path.as_path()),
        (&ssh_target, ssh_target_path.as_path()),
        (&tier_fd, tier),
        (&ssh_source, ssh_source_path.as_path()),
    ] {
        let stat = fstat(fd).map_err(|error| refused(path, format!("{error:?}")))?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
            || stat.st_uid != uid
        {
            return Err(refused(path, format!("not a directory owned by uid {uid}")));
        }
    }
    Ok(PinnedCustody {
        tier: tier_fd,
        custody_target,
        ssh_source,
        ssh_target,
        custody_path,
        ssh_target_path,
    })
}

fn fd_path(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

fn bind(source: &OwnedFd, target: &OwnedFd, path: &Path) -> Result<(), CustodyFailure> {
    mount(
        Some(fd_path(source).as_str()),
        fd_path(target).as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|error| refused(path, format!("{error:?}")))
}

/// Bind both checked sources onto the checked targets.
///
/// # Errors
///
/// Returns the target path and kernel errno when a bind fails.
pub fn mount_pinned(pinned: &PinnedCustody) -> Result<(), CustodyFailure> {
    bind(&pinned.tier, &pinned.custody_target, &pinned.custody_path)?;
    bind(
        &pinned.ssh_source,
        &pinned.ssh_target,
        &pinned.ssh_target_path,
    )
}

/// Run the entry's private custody step from exactly four arguments.
///
/// # Errors
///
/// Writes a refusal line when arguments or a pinned bind fail.
pub fn bind_custody_entry<I, A, E>(arguments: I, error: &mut E) -> u8
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
    let [uid, home, entered, tier] = arguments.as_slice() else {
        let _written = writeln!(error, "{USAGE}");
        return 2;
    };
    let uid = uid
        .parse::<u32>()
        .ok()
        .filter(|value| (1000..=65_535).contains(value));
    let paths = [home, entered, tier].map(Path::new);
    if uid.is_none()
        || !arguments[0].bytes().all(|byte| byte.is_ascii_digit())
        || paths.iter().any(|path| !path.is_absolute())
    {
        let _written = writeln!(error, "{USAGE}");
        return 2;
    }
    let result = pin_custody(uid.unwrap_or_default(), paths[0], paths[1], paths[2])
        .and_then(|pinned| mount_pinned(&pinned));
    match result {
        Ok(()) => 0,
        Err(failure) => {
            let _written = writeln!(error, "{failure}");
            1
        }
    }
}
