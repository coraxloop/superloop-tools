//! The single lexical identity production from ``reg:mail:identity-names``.

use std::fmt;
use std::fs::File;
use std::io;
use std::path::PathBuf;

use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};

/// Admit exactly a lowercase ASCII letter or digit followed by letters, digits
/// or hyphens. Filesystem limits are checked when opening the complete endpoint.
#[must_use]
pub fn valid_identity_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Lexical refusal, separate from an unavailable backing endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NameError;

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid-name: expected the mail identity production")
    }
}

impl std::error::Error for NameError {}

/// A qualified address; sender authority is never inferred from this syntax.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Address {
    loop_name: String,
    worker: Option<String>,
}

impl Address {
    /// Parse an exact loop or loop-plus-worker address without normalization.
    ///
    /// # Errors
    /// Returns `NameError` for an address outside ``lang:mail:names``.
    pub fn parse(value: &str) -> Result<Self, NameError> {
        let (loop_name, worker) = value
            .split_once('+')
            .map_or((value, None), |(name, worker)| (name, Some(worker)));
        if !valid_identity_name(loop_name) || worker.is_some_and(|name| !valid_identity_name(name))
        {
            return Err(NameError);
        }
        Ok(Self {
            loop_name: loop_name.to_owned(),
            worker: worker.map(str::to_owned),
        })
    }

    /// Registered loop component.
    #[must_use]
    pub fn loop_name(&self) -> &str {
        &self.loop_name
    }

    /// Worker birth name, when qualified.
    #[must_use]
    pub fn worker(&self) -> Option<&str> {
        self.worker.as_deref()
    }

    /// Derive the endpoint relative to the already opened host loops root.
    #[must_use]
    pub fn relative_mailbox(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.loop_name);
        if let Some(worker) = &self.worker {
            path = path.join("workers").join(worker);
        }
        path.join("mail")
    }

    /// Open the complete endpoint beneath a pinned root without symlink traversal.
    /// This establishes path reachability only; provisioning and delivery must
    /// separately verify ownership, identity isolation and registry membership.
    ///
    /// # Errors
    /// Reports an unavailable endpoint, retaining the filesystem error (including
    /// an unrepresentable component or path); it never reclassifies a valid name.
    pub fn open_mailbox(&self, loops_root: &File) -> io::Result<File> {
        openat2(
            loops_root,
            &self.relative_mailbox(),
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map(File::from)
        .map_err(|error| {
            io::Error::new(
                io::Error::from_raw_os_error(error as i32).kind(),
                format!("unavailable endpoint {self}: {error}"),
            )
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.loop_name)?;
        if let Some(worker) = &self.worker {
            write!(formatter, "+{worker}")?;
        }
        Ok(())
    }
}

/// A submitted filename, with the bounded slug separate from unbounded identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outgoing {
    /// Exact destination address.
    pub recipient: Address,
    /// Sender-selected ASCII ordering key.
    pub slug: String,
}

impl Outgoing {
    /// Parse the outgoing filename from ``lang:mail:names``.
    ///
    /// # Errors
    /// Refuses any excluded byte, missing component or slug outside 1 to 64 bytes.
    pub fn parse(filename: &str) -> Result<Self, NameError> {
        let (address, slug) = filename
            .strip_suffix(".letter")
            .and_then(|stem| stem.split_once('.'))
            .ok_or(NameError)?;
        if !(1..=64).contains(&slug.len())
            || !slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(NameError);
        }
        Ok(Self {
            recipient: Address::parse(address)?,
            slug: slug.to_owned(),
        })
    }
}
