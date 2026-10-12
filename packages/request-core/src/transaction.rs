//! Descriptor-relative transaction primitives; the caller supplies directory custody.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};

use crate::Error;

const MAX_BYTES: u64 = 64 * 1024 * 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn failure(error: impl std::fmt::Display) -> Error {
    Error::new("requests-storage", error.to_string())
}

fn filename(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        Err(Error::new(
            "requests-storage",
            "transaction name is not a basename",
        ))
    } else {
        Ok(())
    }
}

fn validate_file(file: &File, directory: &File) -> Result<(), Error> {
    let metadata = file.metadata().map_err(failure)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != directory.metadata().map_err(failure)?.uid()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Error::new(
            "requests-storage",
            "transaction file custody differs",
        ));
    }
    Ok(())
}

/// Read one atomic snapshot without creating a file or lock.
///
/// # Errors
/// Refuses a non-basename, symlink, unsafe file, oversized or unreadable snapshot.
pub fn read(directory: &File, name: &str) -> Result<Option<Vec<u8>>, Error> {
    Ok(snapshot(directory, name)?.map(|snapshot| snapshot.bytes))
}

/// A descriptor-pinned file identity and its observed bytes.
pub struct Snapshot {
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
    _file: File,
}

impl Snapshot {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.bytes == other.bytes
    }
}

impl Eq for Snapshot {}

/// Read without mutation, retaining the file descriptor for identity comparison.
///
/// # Errors
/// Refuses the same unsafe custody and read failures as [`read`].
pub fn snapshot(directory: &File, name: &str) -> Result<Option<Snapshot>, Error> {
    filename(name)?;
    let descriptor = match openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(failure(error)),
    };
    let file = File::from(descriptor);
    validate_file(&file, directory)?;
    let metadata = file.metadata().map_err(failure)?;
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(Error::new("requests-storage", "snapshot exceeds cap"));
    }
    Ok(Some(Snapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes,
        _file: file,
    }))
}

/// A stable exclusive lock and the snapshot it guards.
pub struct Transaction<'a> {
    directory: &'a File,
    name: String,
    lock_name: String,
    before: Option<Snapshot>,
    lock: Flock<File>,
}

impl<'a> Transaction<'a> {
    /// Lock one domain transaction and read its current bytes.
    ///
    /// # Errors
    /// Refuses unsafe names, lock custody, lock failure or invalid snapshot custody.
    pub fn open(directory: &'a File, name: &str, lock_name: &str) -> Result<Self, Error> {
        filename(name)?;
        filename(lock_name)?;
        if name == lock_name {
            return Err(Error::new(
                "requests-storage",
                "data and lock names coincide",
            ));
        }
        let descriptor = openat(
            directory,
            lock_name,
            OFlag::O_RDWR
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(failure)?;
        let file = File::from(descriptor);
        validate_file(&file, directory)?;
        let lock =
            Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| failure(error))?;
        let before = snapshot(directory, name)?;
        Ok(Self {
            directory,
            name: name.to_owned(),
            lock_name: lock_name.to_owned(),
            before,
            lock,
        })
    }

    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.before
            .as_ref()
            .map(|snapshot| snapshot.bytes.as_slice())
    }

    /// Compare the locked file with a prior held snapshot, including its identity.
    #[must_use]
    pub fn matches_snapshot(&self, before: &Option<Snapshot>) -> bool {
        self.before == *before
    }

    /// Atomically publish a fully validated transaction while retaining the lock.
    ///
    /// # Errors
    /// Refuses changed preconditions and staging errors before rename. A directory
    /// sync failure after rename is explicitly `requests-commit-uncertain` and
    /// requires reading the durable snapshot before retrying a service effect.
    pub fn replace(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err(Error::new("requests-storage", "snapshot exceeds cap"));
        }
        let held = self.lock.metadata().map_err(failure)?;
        let named = nix::sys::stat::fstatat(
            self.directory,
            self.lock_name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(failure)?;
        if held.dev() != named.st_dev || held.ino() != named.st_ino {
            return Err(Error::new(
                "requests-conflict",
                "transaction lock identity changed",
            ));
        }
        if snapshot(self.directory, &self.name)? != self.before {
            return Err(Error::new(
                "requests-conflict",
                "snapshot changed under transaction lock",
            ));
        }
        let temporary = format!(
            ".request-transaction-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let descriptor = openat(
            self.directory,
            temporary.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(failure)?;
        let mut staged = File::from(descriptor);
        let result = staged
            .write_all(bytes)
            .and_then(|()| staged.sync_all())
            .map_err(failure)
            .and_then(|()| {
                renameat(
                    self.directory,
                    temporary.as_str(),
                    self.directory,
                    self.name.as_str(),
                )
                .map_err(failure)
            });
        if result.is_err() {
            let _removed = unlinkat(
                self.directory,
                temporary.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
            return result;
        }
        let metadata = staged
            .metadata()
            .map_err(|error| Error::new("requests-commit-uncertain", error.to_string()))?;
        self.before = Some(Snapshot {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: bytes.to_vec(),
            _file: staged,
        });
        self.directory
            .sync_all()
            .map_err(|error| Error::new("requests-commit-uncertain", error.to_string()))
    }
}
