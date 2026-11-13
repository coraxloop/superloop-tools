//! Contracts for the door's local identity entry; consumer: `door_entry`.
//! The entered D0 rubric reader remains the only door rubric reader.
use crate::anchor::{
    HostPin, HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Requirement, Transport,
};
use crate::error::LoopError;
use nix::fcntl::{FcntlArg, OFlag, SealFlag, fcntl};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::stat::{Mode, fchmod, fstat};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;

/// Maximum invocation bytes, independently enforced by sender and receiver.
pub const INVOCATION_LIMIT: usize = 262_144;
/// Ordered roles; no owner-home, Python or rubric-snapshot capability is granted.
pub const PURPOSES: [&str; 7] = [
    "configuration",
    "entry-executable",
    "loop-storage",
    "private-storage",
    "identity-executable",
    "namespace-entry",
    "invocation",
];

/// Selected by the trusted private word, never by an untrusted manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Rubric,
    Agent,
    Metadata,
}
impl Operation {
    /// Decode the private dispatcher word without consulting a declaration.
    /// # Errors
    /// Refuses every word outside the three door operations.
    pub fn from_private(word: &str) -> Result<Self, LoopError> {
        match word {
            "_door-rubric" => Ok(Self::Rubric),
            "_door-agent" => Ok(Self::Agent),
            "_door-metadata" => Ok(Self::Metadata),
            _ => Err(LoopError::refusal(
                "anchor-declaration: operation=door-entry purpose=operation",
            )),
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rubric => "door-rubric",
            Self::Agent => "door-agent",
            Self::Metadata => "door-metadata",
        }
    }
    fn refuse(self, purpose: &str, check: &str) -> LoopError {
        LoopError::refusal(format!(
            "anchor-declaration: operation={} purpose={purpose} check={check}",
            self.name()
        ))
    }
    /// Refuse even an empty override before loading configuration or a frame.
    /// # Errors
    /// Refuses any presence of `ENTER_LOOP_REGISTRY`.
    pub fn check_override(self) -> Result<(), LoopError> {
        if std::env::var_os("ENTER_LOOP_REGISTRY").is_some() {
            return Err(self.refuse("registry-override", "environment"));
        }
        Ok(())
    }

    /// Validate the operation, role order and count before receiving usable custody.
    /// The receiving dispatcher supplies the loop name independently.
    /// # Errors
    /// Refuses overrides and declarations that differ from this operation's fixed frame.
    pub fn check_frame(self, loop_name: &str, frame: &Manifest) -> Result<(), LoopError> {
        self.check_override()?;
        crate::registry::validate_name(loop_name)
            .map_err(|_| self.refuse("manifest", "loop-name"))?;
        Manifest::parse(
            &serde_json::to_string(frame).map_err(|_| self.refuse("manifest", "encode"))?,
        )
        .map_err(|error| LoopError::refusal(error.context(self.name(), "manifest").to_string()))?;
        if frame.operation != self.name()
            || frame.loop_name != loop_name
            || frame.transport != Transport::Rights
            || frame.records.len() != PURPOSES.len()
        {
            return Err(self.refuse("manifest", "frame"));
        }
        for (index, record) in frame.records.iter().enumerate() {
            let directory = matches!(index, 0 | 2 | 3);
            if record.purpose != PURPOSES[index]
                || usize::try_from(record.slot).ok() != Some(index)
                || record.kind
                    != if directory {
                        Kind::Directory
                    } else {
                        Kind::File
                    }
            {
                return Err(self.refuse(PURPOSES[index], "role"));
            }
        }
        Ok(())
    }

    /// Receiver-owned policies, using the uid from received configuration's registry row.
    /// Entry and namespace programs admit host or proven initial-root files only.
    /// `RootFile` uses anchor's UID-map proof; observed uid 65534 is never a root test here.
    /// # Errors
    /// Refuses a program owner policy outside `Host` and `RootFile`.
    pub fn requirements(
        self,
        loop_uid: u32,
        entry: Owner,
        namespace: Owner,
    ) -> Result<[Requirement; 7], LoopError> {
        if !matches!(entry, Owner::Host | Owner::RootFile)
            || !matches!(namespace, Owner::Host | Owner::RootFile)
        {
            return Err(self.refuse("program-owner", "policy"));
        }
        // slot | purpose             | kind      | owner             | mode
        // 0    | configuration       | directory | Host              | 0700
        // 1    | entry-executable    | file      | Host / RootFile   | executable
        // 2    | loop-storage        | directory | Host              | 0711
        // 3    | private-storage     | directory | Mapped(row.uid)   | 0700
        // 4    | identity-executable | file      | RootFile(setpriv) | executable
        // 5    | namespace-entry     | file      | Host / RootFile   | executable
        // 6    | invocation          | file      | Host              | 0400 + seals
        let directory = |owner, mode| Policy {
            kind: Kind::Directory,
            owner,
            mode: ModePolicy::Exact(mode),
        };
        let executable = |owner| Policy {
            kind: Kind::File,
            owner,
            mode: ModePolicy::Executable,
        };
        let policies = [
            directory(Owner::Host, 0o700),
            executable(entry),
            directory(Owner::Host, 0o711),
            directory(Owner::Mapped(loop_uid), 0o700),
            executable(Owner::RootFile),
            executable(namespace),
            Policy {
                kind: Kind::File,
                owner: Owner::Host,
                mode: ModePolicy::Exact(crate::anchor::READONLY_PRIVATE_MODE),
            },
        ];
        Ok(std::array::from_fn(|index| Requirement {
            purpose: PURPOSES[index].into(),
            policy: policies[index],
            alias_group: None,
        }))
    }
}

fn seals() -> SealFlag {
    SealFlag::F_SEAL_SEAL | SealFlag::F_SEAL_WRITE | SealFlag::F_SEAL_GROW | SealFlag::F_SEAL_SHRINK
}
fn invocation_error(operation: Operation, check: &str, error: impl std::fmt::Display) -> LoopError {
    LoopError::refusal(format!(
        "anchor-io: operation={} purpose=invocation check={check}: {error}",
        operation.name()
    ))
}

/// Make the immutable invocation, reopening read-only before handing it to the composer.
/// The composer retains normal anchor identity/owner declarations for this descriptor.
/// # Errors
/// Refuses an oversized invocation or inability to establish every seal and mode.
pub fn invocation(operation: Operation, bytes: &[u8]) -> Result<OwnedFd, LoopError> {
    if bytes.len() > INVOCATION_LIMIT {
        return Err(operation.refuse("invocation", "byte-bound"));
    }
    let fd = memfd_create(
        "door-invocation",
        MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
    )
    .map_err(|error| invocation_error(operation, "create", error))?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .map_err(|error| invocation_error(operation, "write", error))?;
    fchmod(
        &file,
        Mode::from_bits_truncate(crate::anchor::READONLY_PRIVATE_MODE),
    )
    .map_err(|error| invocation_error(operation, "mode", error))?;
    fcntl(&file, FcntlArg::F_ADD_SEALS(seals()))
        .map_err(|error| invocation_error(operation, "seal", error))?;
    // This is the process's own held descriptor, not an authority-bearing pathname.
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map(OwnedFd::from)
        .map_err(|error| invocation_error(operation, "readonly", error))
}

/// Pin a newly sealed invocation under the host verifier's existing owner/map proof.
///
/// # Errors
/// Refuses a non-host verifier, changed invocation custody or an invalid invocation.
pub fn pin_invocation(
    verifier: &HostVerifier,
    operation: Operation,
    bytes: &[u8],
) -> Result<HostPin, LoopError> {
    let fd = invocation(operation, bytes)?;
    verifier
        .retain_readonly_file(&fd, "invocation", 6)
        .map_err(|error| {
            LoopError::refusal(error.context(operation.name(), "invocation").to_string())
        })
}

/// Read invocation bytes after the ordinary anchor receiver has validated the role's owner
/// and descriptor identity. This adds seal, access-mode and byte-bound admission at receipt.
/// # Errors
/// Refuses writable descriptors, unsealed or oversized files and a mode other than 0400.
pub fn read_invocation(operation: Operation, fd: &impl AsFd) -> Result<Vec<u8>, LoopError> {
    // Seals first: once all four are present, the size and bytes stat and read observe are final.
    let observed = fcntl(fd, FcntlArg::F_GET_SEALS)
        .map_err(|error| invocation_error(operation, "seals", error))?;
    let flags = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|error| invocation_error(operation, "access", error))?;
    let info = fstat(fd).map_err(|error| invocation_error(operation, "stat", error))?;
    if info.st_mode & libc::S_IFMT != libc::S_IFREG
        || info.st_mode & 0o7777 != crate::anchor::READONLY_PRIVATE_MODE
        || flags & OFlag::O_ACCMODE.bits() != OFlag::O_RDONLY.bits()
        || observed & seals().bits() != seals().bits()
    {
        return Err(operation.refuse("invocation", "sealed-readonly-0400"));
    }
    if u64::try_from(info.st_size).map_or(true, |size| size > INVOCATION_LIMIT as u64) {
        return Err(operation.refuse("invocation", "byte-bound"));
    }
    let length = usize::try_from(info.st_size)
        .map_err(|error| invocation_error(operation, "size", error))?;
    let mut bytes = vec![0; length];
    File::from(
        fd.as_fd()
            .try_clone_to_owned()
            .map_err(|error| invocation_error(operation, "duplicate", error))?,
    )
    .read_exact_at(&mut bytes, 0)
    .map_err(|error| invocation_error(operation, "read", error))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
