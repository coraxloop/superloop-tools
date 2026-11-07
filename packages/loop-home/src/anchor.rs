//! Operation-bound file and directory capabilities for namespace entry.
//!
//! Callers supply trusted requirements; a manifest is evidence, never authority.
//! Legacy readers are not switched by this module.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};
use std::sync::Arc;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use serde::{Deserialize, Serialize};

use crate::ancestor::Owners;

pub mod transport;

#[cfg(test)]
mod tests;

/// Maximum records in a single private manifest.
pub const MAX_ANCHORS: usize = 64;
/// Maximum encoded manifest size.
pub const MAX_MANIFEST: usize = 65_536;

/// A named refusal with operation, purpose and the failed custody check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Stable refusal class.
    pub kind: &'static str,
    operation: String,
    purpose: String,
    detail: String,
}

impl Error {
    fn new(kind: &'static str, operation: &str, purpose: &str) -> Self {
        Self {
            kind,
            operation: operation.into(),
            purpose: purpose.into(),
            detail: kind.strip_prefix("anchor-").unwrap_or(kind).into(),
        }
    }
    pub(crate) fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Attach the trusted caller's operation and purpose without discarding the cause.
    #[must_use]
    pub fn context(mut self, operation: &str, purpose: &str) -> Self {
        self.operation = operation.into();
        self.purpose = purpose.into();
        self
    }

    fn because(mut self, check: &str, cause: impl fmt::Display) -> Self {
        self.detail = format!("{check}: {cause}");
        self
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: operation={} purpose={} check={}",
            self.kind, self.operation, self.purpose, self.detail
        )
    }
}
impl std::error::Error for Error {}
/// Result of a capability validation or confined open.
pub type Result<T> = std::result::Result<T, Error>;

/// Private bundle transport, selected by the operation's launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Rights,
    Inherit,
}
/// Object kinds admitted by a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Directory,
    File,
}

/// Identity measured on a held host descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub purpose: String,
    pub slot: u32,
    pub kind: Kind,
    pub device: u64,
    pub inode: u64,
    pub verifier_uid: u32,
    pub owner_uid: u32,
}

/// The bounded declaration on the private command vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub transport: Transport,
    pub operation: String,
    pub loop_name: String,
    pub records: Vec<Record>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl Manifest {
    /// Decode the private declaration without treating its fields as grants.
    ///
    /// # Errors
    /// Refuses oversized, malformed, duplicate-field or inconsistent declarations.
    pub fn parse(source: &str) -> Result<Self> {
        let error = || Error::new("anchor-declaration", "manifest", "manifest");
        if source.len() > MAX_MANIFEST {
            return Err(error());
        }
        let manifest: Self = serde_json::from_str(source).map_err(|_| error())?;
        manifest.check()?;
        Ok(manifest)
    }

    fn check(&self) -> Result<()> {
        let error = || Error::new("anchor-declaration", "manifest", "manifest");
        if self.version != 1
            || self.records.len() > MAX_ANCHORS
            || !identifier(&self.operation)
            || (!self.loop_name.is_empty() && !identifier(&self.loop_name))
            || serde_json::to_vec(self).map_err(|_| error())?.len() > MAX_MANIFEST
        {
            return Err(error());
        }
        let mut purposes = BTreeSet::new();
        let mut slots = BTreeSet::new();
        for r in &self.records {
            if !identifier(&r.purpose)
                || !purposes.insert(&r.purpose)
                || !slots.insert(r.slot)
                || (self.transport == Transport::Rights && r.slot as usize >= self.records.len())
                || (self.transport == Transport::Inherit && r.slot < 3)
            {
                return Err(error());
            }
        }
        Ok(())
    }
}

/// Ownership selected by the receiver's operation and protected grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// The initial owner whose UID is namespace uid zero after entry.
    Host,
    /// A namespace UID obtained independently from a validated registry grant.
    Mapped(u32),
    /// A system file verified as initial root on the host; never a directory.
    RootFile,
}
/// Mode policy selected by the operation, not by the declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModePolicy {
    /// Complete mode including any exact named read/search ACL mask.
    Exact(u32),
    /// Regular executable with no group/world write or special permission bits.
    Executable,
}
/// Kind, owner and mode required for one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub kind: Kind,
    pub owner: Owner,
    pub mode: ModePolicy,
}
/// Required purpose and an optional operation-authorized alias group.
#[derive(Debug, Clone)]
pub struct Requirement {
    pub purpose: String,
    pub policy: Policy,
    pub alias_group: Option<String>,
}

#[derive(Debug)]
struct View {
    owners: Owners,
    host_uid: u32,
}
impl View {
    fn current() -> Result<Self> {
        let uid = nix::unistd::Uid::effective().as_raw();
        let error = || Error::new("anchor-uid-map", "entry", "map");
        let owners =
            Owners::current(uid).map_err(|cause| error().because("uid-map-read", cause))?;
        let host_uid = if owners.is_initial() {
            uid
        } else {
            u32::try_from(
                owners
                    .parent_uid(0)
                    .map_err(|cause| error().because("namespace-root-map", cause))?,
            )
            .map_err(|_| error())?
        };
        Ok(Self { owners, host_uid })
    }
    fn initial_owner(&self, owner: Owner, operation: &str, purpose: &str) -> Result<u32> {
        match owner {
            Owner::Host => Ok(self.host_uid),
            Owner::RootFile => Ok(0),
            Owner::Mapped(uid) => u32::try_from(
                self.owners
                    .parent_uid(uid)
                    .map_err(|_| Error::new("anchor-owner", operation, purpose))?,
            )
            .map_err(|_| Error::new("anchor-owner", operation, purpose)),
        }
    }
}

fn inspect_kind(
    fd: &OwnedFd,
    policy: Policy,
    operation: &str,
    purpose: &str,
) -> Result<nix::sys::stat::FileStat> {
    if policy.mode == ModePolicy::Executable && matches!(policy.owner, Owner::Mapped(_)) {
        return Err(Error::new("anchor-owner", operation, purpose).because(
            "executable-owner-policy",
            "loop-owned executable is not admitted",
        ));
    }
    if policy.owner == Owner::RootFile && policy.kind != Kind::File {
        return Err(Error::new("anchor-kind", operation, purpose).because(
            "root-file-policy",
            "root file proof cannot authorize a directory",
        ));
    }
    let access = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)
        .map_err(|cause| system_error(cause, operation, purpose, "fcntl-getfl"))?;
    let access = OFlag::from_bits_truncate(access);
    let path_only = policy.kind == Kind::Directory || policy.mode == ModePolicy::Executable;
    if access.contains(OFlag::O_PATH) != path_only
        || (!path_only && access.intersection(OFlag::O_ACCMODE) != OFlag::O_RDONLY)
    {
        return Err(Error::new("anchor-kind", operation, purpose).because(
            "descriptor-access",
            format_args!("path_only={path_only} flags={access:?}"),
        ));
    }
    let stat = fstat(fd).map_err(|cause| system_error(cause, operation, purpose, "fstat"))?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind == SFlag::S_IFLNK {
        return Err(Error::new("anchor-escape", operation, purpose));
    }
    if kind
        != match policy.kind {
            Kind::Directory => SFlag::S_IFDIR,
            Kind::File => SFlag::S_IFREG,
        }
    {
        return Err(Error::new("anchor-kind", operation, purpose).because(
            "descriptor-kind",
            format_args!("expected={:?} observed={kind:?}", policy.kind),
        ));
    }
    Ok(stat)
}

fn check_mode(
    fd: &OwnedFd,
    stat: &nix::sys::stat::FileStat,
    policy: Policy,
    operation: &str,
    purpose: &str,
) -> Result<()> {
    let valid = match policy.mode {
        ModePolicy::Exact(mode) => {
            mode <= 0o777
                && mode & 0o022 == 0
                && stat.st_mode & 0o7777 == crate::mail::acl::preserved_mode(fd, mode)
        }
        ModePolicy::Executable => {
            policy.kind == Kind::File && stat.st_mode & 0o111 != 0 && stat.st_mode & 0o7022 == 0
        }
    };
    if !valid {
        return Err(Error::new("anchor-mode", operation, purpose).because(
            "mode-policy",
            format_args!(
                "policy={:?} observed={:04o}",
                policy.mode,
                stat.st_mode & 0o7777
            ),
        ));
    }
    Ok(())
}
fn check_kind_mode(
    fd: &OwnedFd,
    policy: Policy,
    operation: &str,
    purpose: &str,
) -> Result<nix::sys::stat::FileStat> {
    let stat = inspect_kind(fd, policy, operation, purpose)?;
    check_mode(fd, &stat, policy, operation, purpose)?;
    Ok(stat)
}

fn check_owner(
    view: &View,
    stat: &nix::sys::stat::FileStat,
    policy: Policy,
    recorded: u32,
    held_file: bool,
    operation: &str,
    purpose: &str,
) -> Result<()> {
    let expected = view.initial_owner(policy.owner, operation, purpose)?;
    let observed = view.owners.inside_uid(expected);
    let accepted = recorded == expected
        && observed.map_or_else(
            || {
                held_file
                    && policy.owner == Owner::RootFile
                    && policy.kind == Kind::File
                    && stat.st_uid == view.owners.overflow_uid()
            },
            |uid| stat.st_uid == uid,
        );
    if !accepted {
        return Err(Error::new("anchor-owner", operation, purpose).because(
            "owner-binding",
            format_args!(
                "expected initial uid {expected}, declared {recorded}, observed {}",
                stat.st_uid
            ),
        ));
    }
    Ok(())
}

fn flags(policy: Policy) -> OFlag {
    let access = if policy.kind == Kind::Directory || policy.mode == ModePolicy::Executable {
        OFlag::O_PATH
    } else {
        OFlag::O_RDONLY | OFlag::O_NONBLOCK
    };
    access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW
}

fn system_error(cause: nix::errno::Errno, operation: &str, purpose: &str, check: &str) -> Error {
    let kind = match cause {
        nix::errno::Errno::ENOENT | nix::errno::Errno::EBADF => "anchor-missing",
        nix::errno::Errno::ELOOP | nix::errno::Errno::EXDEV | nix::errno::Errno::ENOTDIR => {
            "anchor-escape"
        }
        _ => "anchor-io",
    };
    Error::new(kind, operation, purpose).because(check, cause)
}

fn open_component(
    parent: &OwnedFd,
    name: &Path,
    policy: Policy,
    operation: &str,
    purpose: &str,
) -> Result<OwnedFd> {
    openat2(
        parent,
        name,
        OpenHow::new().flags(flags(policy)).resolve(
            ResolveFlag::RESOLVE_BENEATH
                | ResolveFlag::RESOLVE_NO_SYMLINKS
                | ResolveFlag::RESOLVE_NO_MAGICLINKS,
        ),
    )
    .map_err(|cause| system_error(cause, operation, purpose, "openat2"))
}

fn relative_parts(path: &Path, operation: &str, purpose: &str) -> Result<Vec<std::ffi::OsString>> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return Err(Error::new("anchor-escape", operation, purpose));
    }
    path.components()
        .map(|part| match part {
            Component::Normal(name) => Ok(name.to_owned()),
            _ => Err(Error::new("anchor-escape", operation, purpose)),
        })
        .collect()
}

/// Host verifier admitted only under the verified initial identity map.
#[derive(Debug)]
pub struct HostVerifier {
    view: View,
    operation: String,
}
/// Held host object and its measured declaration record.
#[derive(Debug)]
pub struct HostPin {
    record: Record,
    fd: OwnedFd,
}
impl HostPin {
    #[must_use]
    pub fn record(&self) -> Record {
        self.record.clone()
    }
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}
impl AsFd for HostPin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl HostVerifier {
    /// Establish the verifier's map through verified procfs.
    ///
    /// # Errors
    /// Refuses any map other than one complete identity range.
    pub fn current() -> Result<Self> {
        let view = View::current()?;
        Self::from_view(view)
    }

    fn from_view(view: View) -> Result<Self> {
        if !view.owners.is_initial() {
            return Err(Error::new("anchor-uid-map", "host", "map")
                .because("initial-map", "one complete identity range required"));
        }
        Ok(Self {
            view,
            operation: "host".into(),
        })
    }

    /// Bind subsequent pins to the trusted launcher's operation.
    #[must_use]
    pub fn for_operation(mut self, operation: &str) -> Self {
        self.operation = operation.into();
        self
    }

    /// Pin an absolute object after checking every host ancestor.
    ///
    /// Mapped leaf ownership is recorded here and authorized only by the receiver.
    /// # Errors
    /// Refuses links, untrusted ancestors and unsafe kind, owner or mode.
    pub fn pin(&self, path: &Path, purpose: &str, slot: u32, policy: Policy) -> Result<HostPin> {
        let operation = self.operation.as_str();
        if !identifier(purpose) {
            return Err(Error::new("anchor-declaration", operation, "purpose"));
        }
        let relative = path
            .strip_prefix("/")
            .map_err(|_| Error::new("anchor-escape", operation, purpose))?;
        let parts = relative_parts(relative, operation, purpose)?;
        let mut fd = open(
            Path::new("/"),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|cause| system_error(cause, operation, purpose, "host-descriptor"))?;
        for (index, name) in parts.iter().enumerate() {
            let parent = fstat(&fd)
                .map_err(|cause| system_error(cause, operation, purpose, "host-descriptor"))?;
            self.view.owners.check(parent.st_uid).map_err(|cause| {
                Error::new("anchor-owner", operation, purpose).because("ancestor-owner", cause)
            })?;
            if parent.st_mode & 0o022 != 0
                && !(parent.st_uid == 0 && parent.st_mode & 0o1777 == 0o1777)
            {
                return Err(Error::new("anchor-mode", operation, purpose).because(
                    "ancestor-mode",
                    format_args!("observed={:04o}", parent.st_mode & 0o7777),
                ));
            }
            let leaf = index + 1 == parts.len();
            let next = if leaf {
                policy
            } else {
                Policy {
                    kind: Kind::Directory,
                    owner: Owner::Host,
                    mode: ModePolicy::Exact(0o755),
                }
            };
            fd = open_component(&fd, Path::new(name), next, operation, purpose)?;
            if !leaf {
                let kind = fstat(&fd)
                    .map_err(|_| Error::new("anchor-missing", operation, purpose))?
                    .st_mode
                    & libc::S_IFMT;
                if kind == libc::S_IFLNK {
                    return Err(Error::new("anchor-escape", operation, purpose));
                }
                if kind != libc::S_IFDIR {
                    return Err(Error::new("anchor-kind", operation, purpose));
                }
            }
        }
        let stat = check_kind_mode(&fd, policy, operation, purpose)?;
        if !matches!(policy.owner, Owner::Mapped(_)) {
            check_owner(
                &self.view,
                &stat,
                policy,
                stat.st_uid,
                false,
                operation,
                purpose,
            )?;
        }
        Ok(HostPin {
            record: Record {
                purpose: purpose.into(),
                slot,
                kind: policy.kind,
                device: stat.st_dev,
                inode: stat.st_ino,
                verifier_uid: self.view.host_uid,
                owner_uid: stat.st_uid,
            },
            fd,
        })
    }
}

/// Operation context supplied by the trusted private dispatcher.
#[derive(Clone, Copy)]
pub struct Entry<'a> {
    pub operation: &'a str,
    pub loop_name: &'a str,
    pub transport: Transport,
}

/// Protected registry and ledger snapshot used to derive subsequent grants.
#[derive(Debug)]
pub struct Configuration {
    pub registry: crate::registry::Registry,
    pub allocations: crate::allocations::Allocations,
    pub ledger_source: String,
}

/// Receiver map snapshot; a declaration cannot select this map.
#[derive(Debug)]
pub struct Receiver {
    view: Arc<View>,
}
impl Receiver {
    /// Read and validate this receiver's own procfs map.
    ///
    /// # Errors
    /// Refuses unreadable or ambiguous namespace metadata.
    pub fn current() -> Result<Self> {
        Ok(Self {
            view: Arc::new(View::current()?),
        })
    }

    /// Read the bootstrap configuration before deriving loop-owned requirements.
    ///
    /// This performs only the bounded grant reads; the original entire bundle
    /// must then pass validate before any operation uses its other objects.
    /// # Errors
    /// Refuses missing or unsafe configuration and inconsistent bundle framing.
    pub fn configuration(
        &self,
        manifest: &Manifest,
        descriptors: &[OwnedFd],
        entry: Entry<'_>,
        home: &Path,
        optional_ledger: bool,
    ) -> Result<Configuration> {
        manifest.check()?;
        let error = |kind| Error::new(kind, entry.operation, "configuration");
        if manifest.operation != entry.operation
            || manifest.loop_name != entry.loop_name
            || manifest.transport != entry.transport
        {
            return Err(error("anchor-declaration"));
        }
        if descriptors.len() < manifest.records.len() {
            return Err(error("anchor-missing"));
        }
        if descriptors.len() != manifest.records.len() {
            return Err(error("anchor-transport"));
        }
        let record = manifest
            .records
            .iter()
            .find(|r| r.purpose == "configuration")
            .ok_or_else(|| error("anchor-missing"))?;
        let index = match entry.transport {
            Transport::Rights => record.slot as usize,
            Transport::Inherit => descriptors
                .iter()
                .position(|fd| u32::try_from(fd.as_raw_fd()).ok() == Some(record.slot))
                .ok_or_else(|| error("anchor-missing"))?,
        };
        let fd = descriptors
            .get(index)
            .ok_or_else(|| error("anchor-missing"))?
            .try_clone()
            .map_err(|_| error("anchor-missing"))?;
        let mut record = record.clone();
        record.slot = 0;
        let bootstrap = Manifest {
            version: 1,
            transport: Transport::Rights,
            operation: entry.operation.into(),
            loop_name: entry.loop_name.into(),
            records: vec![record],
        };
        let required = Requirement {
            purpose: "configuration".into(),
            policy: Policy {
                kind: Kind::Directory,
                owner: Owner::Host,
                mode: ModePolicy::Exact(0o700),
            },
            alias_group: None,
        };
        let mut validated = self.validate(
            &bootstrap,
            vec![fd],
            entry.operation,
            entry.loop_name,
            Transport::Rights,
            &[required],
        )?;
        let anchor = validated.pop().ok_or_else(|| error("anchor-missing"))?;
        anchor.read_configuration(home, optional_ledger)
    }

    /// Validate the complete owned bundle before returning any usable object.
    ///
    /// # Errors
    /// Refuses inconsistent declarations, missing/extra slots and every custody mismatch.
    pub fn validate(
        &self,
        manifest: &Manifest,
        descriptors: Vec<OwnedFd>,
        operation: &str,
        loop_name: &str,
        transport: Transport,
        required: &[Requirement],
    ) -> Result<Vec<Anchor>> {
        manifest.check()?;
        let error = |kind| Error::new(kind, operation, "bundle");
        if manifest.operation != operation
            || manifest.loop_name != loop_name
            || manifest.transport != transport
            || required.len() != manifest.records.len()
        {
            return Err(error("anchor-declaration"));
        }
        if descriptors.len() < manifest.records.len() {
            return Err(error("anchor-missing"));
        }
        if descriptors.len() != manifest.records.len() {
            return Err(error("anchor-transport"));
        }
        let mut named = BTreeSet::new();
        if required.iter().any(|r| {
            !named.insert(&r.purpose) || !manifest.records.iter().any(|m| m.purpose == r.purpose)
        }) {
            return Err(error("anchor-declaration"));
        }
        let mut remaining: Vec<Option<OwnedFd>> = descriptors.into_iter().map(Some).collect();
        let mut anchors: Vec<Anchor> = Vec::new();
        for record in &manifest.records {
            let requirement = required
                .iter()
                .find(|r| r.purpose == record.purpose)
                .ok_or_else(|| error("anchor-declaration"))?;
            let index = match transport {
                Transport::Rights => record.slot as usize,
                Transport::Inherit => remaining
                    .iter()
                    .position(|fd| {
                        fd.as_ref().is_some_and(|fd| {
                            u32::try_from(fd.as_raw_fd()).ok() == Some(record.slot)
                        })
                    })
                    .ok_or_else(|| error("anchor-missing"))?,
            };
            let fd = remaining
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| error("anchor-missing"))?;
            nix::fcntl::fcntl(
                &fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .map_err(|_| error("anchor-transport"))?;
            if record.kind != requirement.policy.kind || record.verifier_uid != self.view.host_uid {
                return Err(Error::new("anchor-declaration", operation, &record.purpose));
            }
            let anchor = Anchor {
                fd,
                record: record.clone(),
                policy: requirement.policy,
                operation: operation.into(),
                view: Arc::clone(&self.view),
            };
            anchor.revalidate()?;
            for other in &anchors {
                if (other.record.device, other.record.inode) == (record.device, record.inode) {
                    let previous = required
                        .iter()
                        .find(|r| r.purpose == other.record.purpose)
                        .ok_or_else(|| error("anchor-declaration"))?;
                    if requirement.alias_group.is_none()
                        || requirement.alias_group != previous.alias_group
                    {
                        return Err(error("anchor-declaration"));
                    }
                }
            }
            anchors.push(anchor);
        }
        Ok(anchors)
    }
}

/// A validated capability; dropping it closes the held descriptor.
#[derive(Debug)]
pub struct Anchor {
    fd: OwnedFd,
    record: Record,
    policy: Policy,
    operation: String,
    view: Arc<View>,
}
impl AsFd for Anchor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl Anchor {
    fn revalidate(&self) -> Result<()> {
        let stat = inspect_kind(&self.fd, self.policy, &self.operation, &self.record.purpose)?;
        if (stat.st_dev, stat.st_ino) != (self.record.device, self.record.inode) {
            return Err(Error::new(
                "anchor-identity",
                &self.operation,
                &self.record.purpose,
            ));
        }
        check_owner(
            &self.view,
            &stat,
            self.policy,
            self.record.owner_uid,
            true,
            &self.operation,
            &self.record.purpose,
        )?;
        check_mode(
            &self.fd,
            &stat,
            self.policy,
            &self.operation,
            &self.record.purpose,
        )
    }

    /// Execute this held file in the child without a namespace-side pathname lookup.
    /// Arguments include argv zero; the environment is the caller's complete selection.
    /// # Errors
    /// Refuses non-executable custody, NUL bytes, excessive vectors or a failed duplication.
    /// An execveat refusal reaches the caller through the command's spawn error.
    #[allow(unsafe_code)]
    pub fn configure_exec(
        &self,
        command: &mut std::process::Command,
        arguments: &[std::ffi::OsString],
        environment: &[(std::ffi::OsString, std::ffi::OsString)],
    ) -> Result<()> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::process::CommandExt as _;
        const WORDS: usize = 1024;
        let refusal = || Error::new("anchor-exec", &self.operation, &self.record.purpose);
        if self.policy.kind != Kind::File
            || self.policy.mode != ModePolicy::Executable
            || arguments.is_empty()
            || arguments.len() >= WORDS
            || environment.len() >= WORDS
        {
            return Err(refusal());
        }
        self.revalidate()?;
        let image = self
            .fd
            .try_clone()
            .map_err(|cause| refusal().because("exec-duplicate", cause))?;
        let argv = arguments
            .iter()
            .map(|word| std::ffi::CString::new(word.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|cause| refusal().because("exec-arguments", cause))?;
        let env = environment
            .iter()
            .map(|(key, value)| {
                let mut word = key.clone();
                word.push("=");
                word.push(value);
                std::ffi::CString::new(word.as_bytes())
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|cause| refusal().because("exec-environment", cause))?;
        // SAFETY: all C strings and the executable descriptor are owned by this
        // closure. After fork it fills bounded stack arrays and calls execveat;
        // it neither allocates nor acquires locks, and failure never falls back.
        unsafe {
            command.pre_exec(move || {
                let mut arguments = [std::ptr::null_mut(); WORDS];
                let mut environment = [std::ptr::null_mut(); WORDS];
                for (word, slot) in argv.iter().zip(arguments.iter_mut()) {
                    *slot = word.as_ptr().cast_mut();
                }
                for (word, slot) in env.iter().zip(environment.iter_mut()) {
                    *slot = word.as_ptr().cast_mut();
                }
                libc::execveat(
                    image.as_raw_fd(),
                    c"".as_ptr(),
                    arguments.as_ptr(),
                    environment.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                Err(std::io::Error::last_os_error())
            });
        }
        Ok(())
    }

    /// Duplicate this validated capability for an explicit inherited-descriptor relay.
    /// The declaration retains the verified identity and uses the new held number.
    /// # Errors
    /// Refuses changed custody or a failed descriptor duplication.
    pub fn relay(&self) -> Result<(Record, OwnedFd)> {
        self.revalidate()?;
        let fd = self.fd.try_clone().map_err(|cause| {
            Error::new("anchor-missing", &self.operation, &self.record.purpose)
                .because("relay-duplicate", cause)
        })?;
        let mut record = self.record.clone();
        record.slot = u32::try_from(fd.as_raw_fd())
            .map_err(|_| Error::new("anchor-declaration", &self.operation, &self.record.purpose))?;
        Ok((record, fd))
    }

    /// Open and validate each child without reopening the absolute ancestor chain.
    ///
    /// # Errors
    /// Refuses non-normal paths, links and unsafe custody at any component.
    pub fn open_beneath(&self, path: &Path, policy: Policy, parent_mode: u32) -> Result<OwnedFd> {
        self.revalidate()?;
        if self.policy.kind != Kind::Directory {
            return Err(Error::new(
                "anchor-kind",
                &self.operation,
                &self.record.purpose,
            ));
        }
        let parts = relative_parts(path, &self.operation, &self.record.purpose)?;
        let mut fd = self
            .fd
            .try_clone()
            .map_err(|_| Error::new("anchor-missing", &self.operation, &self.record.purpose))?;
        for (index, part) in parts.iter().enumerate() {
            let next = if index + 1 == parts.len() {
                policy
            } else {
                Policy {
                    kind: Kind::Directory,
                    owner: self.policy.owner,
                    mode: ModePolicy::Exact(parent_mode),
                }
            };
            fd = open_component(
                &fd,
                Path::new(part),
                next,
                &self.operation,
                &self.record.purpose,
            )?;
            let stat = inspect_kind(&fd, next, &self.operation, &self.record.purpose)?;
            let expected =
                self.view
                    .initial_owner(next.owner, &self.operation, &self.record.purpose)?;
            check_owner(
                &self.view,
                &stat,
                next,
                expected,
                false,
                &self.operation,
                &self.record.purpose,
            )?;
            check_mode(&fd, &stat, next, &self.operation, &self.record.purpose)?;
        }
        Ok(fd)
    }

    /// Read ledger and registry through the same owner-private configuration capability.
    ///
    /// The home argument is used only for pure registry row expansion, never an open.
    /// # Errors
    /// Refuses unsafe or malformed files; optional absence applies only to the ledger.
    pub fn read_configuration(&self, home: &Path, optional_ledger: bool) -> Result<Configuration> {
        let error = || Error::new("anchor-declaration", &self.operation, "configuration");
        let directory = Policy {
            kind: Kind::Directory,
            owner: Owner::Host,
            mode: ModePolicy::Exact(0o700),
        };
        if self.record.purpose != "configuration" || self.policy != directory {
            return Err(error());
        }
        let file = Policy {
            kind: Kind::File,
            owner: Owner::Host,
            mode: ModePolicy::Exact(0o600),
        };
        let mut registry =
            File::from(self.open_beneath(Path::new("registry.toml"), file, 0o700)?);
        let registry = crate::registry::load_registry_from_file(&mut registry)
            .map_err(|cause| error().because("registry-parse", cause))?;
        let mut source = String::new();
        match self.open_beneath(Path::new("allocations.toml"), file, 0o700) {
            Ok(fd) => {
                File::from(fd)
                    .take(crate::allocations::MAX_ALLOCATIONS + 1)
                    .read_to_string(&mut source)
                    .map_err(|cause| {
                        Error::new("anchor-io", &self.operation, "configuration")
                            .because("ledger-read", cause)
                    })?;
            }
            Err(e) if optional_ledger && e.kind == "anchor-missing" => {}
            Err(e) => return Err(e),
        }
        if source.len() as u64 > crate::allocations::MAX_ALLOCATIONS {
            return Err(error().because("ledger-bound", "allocations exceeds its byte bound"));
        }
        let ledger = crate::allocations::Allocations::parse(&source)
            .map_err(|cause| error().because("ledger-parse", cause))?
            .with_registry(&registry, home)
            .map_err(|cause| error().because("registry-ledger-binding", cause))?;
        Ok(Configuration {
            registry,
            allocations: ledger,
            ledger_source: source,
        })
    }
}
