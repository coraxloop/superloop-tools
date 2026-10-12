//! A folder the program writes into, reached without following links.
//!
//! The folder is opened as a directory that is not a symbolic link, and every
//! path inside it is reached component by component from that directory, each
//! directory opened with no-follow and each file created exclusively or
//! opened with no-follow, so a link placed anywhere below the folder, before
//! or during a run, redirects nothing. A write goes to a temporary file in the
//! folder's staging folder, a private directory the folder makes at its first
//! write, exclusively and with owner-only mode, and removes when it is
//! dropped; the file is created exclusively there and renamed from the staging
//! folder's descriptor over the destination, and a failed write removes it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, fchmodat, fstat, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use sha2::{Digest, Sha256};

/// The most bytes the program reads back from a manifest or a journal.
pub const MAX_RECORD_FILE: u64 = 64 << 20;

/// The flags every directory is opened with.
const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// Numbers the staging folders and the temporary files of this process.
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// The only mode a staging folder has: its owner's alone.
const STAGING_MODE: u32 = 0o700;

/// What stands at a path inside a folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    /// A symbolic link, a device, a socket or a pipe: never the program's.
    Other,
}

/// One entry found under a folder, by its `/`-separated path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
}

/// A directory the program writes into.
#[derive(Debug)]
pub struct Folder {
    directory: OwnedFd,
    /// The staging folder, once the first write has made it.
    staging: Mutex<Option<Staging>>,
}

/// A folder's private staging directory: its descriptor and its name in the
/// folder.
#[derive(Debug)]
struct Staging {
    directory: OwnedFd,
    name: String,
}

fn refused(what: &str, path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{what} {path:?} is a symbolic link or not a directory"),
    )
}

const fn kind_of(mode: u32) -> Kind {
    let format = mode & SFlag::S_IFMT.bits();
    if format == SFlag::S_IFREG.bits() {
        Kind::File
    } else if format == SFlag::S_IFDIR.bits() {
        Kind::Directory
    } else {
        Kind::Other
    }
}

/// Opens the directory `name` inside `parent` with no-follow, creating it
/// first when `create` is set; a symbolic link or a file there is refused.
fn descend(parent: &OwnedFd, name: &str, create: bool) -> io::Result<OwnedFd> {
    if create {
        match mkdirat(parent, name, Mode::from_bits_truncate(0o755)) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(errno) => return Err(errno.into()),
        }
    }
    openat(parent, name, DIRECTORY, Mode::empty()).map_err(|errno| {
        if matches!(errno, Errno::ELOOP | Errno::ENOTDIR) {
            refused("folder", name)
        } else {
            io::Error::from(errno)
        }
    })
}

impl Folder {
    /// Opens `path` as a folder; a symbolic link or anything but a directory
    /// there is refused.
    ///
    /// # Errors
    ///
    /// Returns the error of a path that cannot be opened as a directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        let directory = nix::fcntl::open(path, DIRECTORY, Mode::empty()).map_err(|errno| {
            if matches!(errno, Errno::ELOOP | Errno::ENOTDIR) {
                refused("output folder", &path.display().to_string())
            } else {
                io::Error::from(errno)
            }
        })?;
        Ok(Self::at(directory))
    }

    const fn at(directory: OwnedFd) -> Self {
        Self {
            directory,
            staging: Mutex::new(None),
        }
    }

    /// Opens the directory `name` inside this folder, creating it when absent;
    /// a symbolic link or a file there is refused.
    ///
    /// # Errors
    ///
    /// Returns the error of a directory that cannot be created or opened.
    pub fn child(&self, name: &str) -> io::Result<Self> {
        Ok(Self::at(descend(&self.directory, name, true)?))
    }

    /// The staging folder's descriptor, making the folder at the first call.
    fn staging(&self) -> io::Result<OwnedFd> {
        let mut slot = self.staging.lock().unwrap_or_else(PoisonError::into_inner);
        let staging = match slot.take() {
            Some(staging) => staging,
            None => self.make_staging()?,
        };
        let directory = staging.directory.try_clone();
        *slot = Some(staging);
        drop(slot);
        directory
    }

    /// Makes a staging folder under a name no entry of the folder has, with
    /// owner-only mode, and settles it; a folder that cannot be settled is
    /// removed again, so a failed setup leaves nothing behind.
    fn make_staging(&self) -> io::Result<Staging> {
        loop {
            let name = staging_name(TEMPORARY.fetch_add(1, Ordering::Relaxed));
            match mkdirat(
                &self.directory,
                name.as_str(),
                Mode::from_bits_truncate(STAGING_MODE),
            ) {
                Ok(()) => {}
                Err(Errno::EEXIST) => continue,
                Err(errno) => return Err(errno.into()),
            }
            return self.settle_staging(&name).inspect_err(|_| {
                let _removed = unlinkat(&self.directory, name.as_str(), UnlinkatFlags::RemoveDir);
            });
        }
    }

    /// Opens the staging folder just made at `name`: pinned without following
    /// a link, given owner-only mode through the pinned descriptor when the
    /// process's umask took any of it away, then opened from that descriptor
    /// and checked to be this user's directory of that mode, so no other user
    /// can place or replace an entry in it.
    fn settle_staging(&self, name: &str) -> io::Result<Staging> {
        let not_own = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("staging folder {name:?} is not this user's own"),
            )
        };
        let pinned_flags =
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let pinned = openat(&self.directory, name, pinned_flags, Mode::empty())?;
        let stat = fstat(&pinned)?;
        if stat.st_uid != geteuid().as_raw() {
            return Err(not_own());
        }
        if stat.st_mode & 0o7777 != STAGING_MODE {
            let entry = format!("/proc/self/fd/{}", pinned.as_raw_fd());
            fchmodat(
                &pinned,
                entry.as_str(),
                Mode::from_bits_truncate(STAGING_MODE),
                FchmodatFlags::FollowSymlink,
            )?;
        }
        let directory = openat(&pinned, ".", DIRECTORY, Mode::empty())?;
        let stat = fstat(&directory)?;
        if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != STAGING_MODE {
            return Err(not_own());
        }
        Ok(Staging {
            directory,
            name: name.to_owned(),
        })
    }

    /// The directory holding `path` and the file name within it, each
    /// directory reached with no-follow and created when `create` is set.
    fn parent<'p>(&self, path: &'p str, create: bool) -> io::Result<(OwnedFd, &'p str)> {
        let mut directory = self.directory.try_clone()?;
        let mut parts = path.split('/').peekable();
        loop {
            let part = parts.next().unwrap_or_default();
            if parts.peek().is_none() {
                return Ok((directory, part));
            }
            directory = descend(&directory, part, create)?;
        }
    }

    /// Every file, directory and other entry under the folder, found without
    /// following links; with `deep` unset, only the folder's own entries.
    ///
    /// # Errors
    ///
    /// Returns the error of a directory that cannot be listed.
    pub fn list(&self, deep: bool) -> io::Result<Vec<Entry>> {
        let mut found = Vec::new();
        let mut pending = vec![(self.directory.try_clone()?, String::new())];
        while let Some((directory, prefix)) = pending.pop() {
            let mut listing = Dir::openat(&directory, ".", DIRECTORY, Mode::empty())?;
            let mut names = Vec::new();
            for entry in listing.iter() {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name != "." && name != ".." {
                    names.push((name, entry.file_type()));
                }
            }
            for (name, known) in names {
                let kind = match known {
                    Some(Type::File) => Kind::File,
                    Some(Type::Directory) => Kind::Directory,
                    Some(_) => Kind::Other,
                    None => kind_of(
                        fstatat(&directory, name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?.st_mode,
                    ),
                };
                let path = format!("{prefix}{name}");
                if kind == Kind::Directory && deep {
                    let inner = descend(&directory, &name, false)?;
                    pending.push((inner, format!("{path}/")));
                }
                found.push(Entry { path, kind });
            }
        }
        found.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(found)
    }

    /// Opens the regular file at `path` for reading without following a link
    /// anywhere on the way; none when something else stands there.
    fn open_file(&self, path: &str) -> io::Result<Option<File>> {
        let (directory, name) = match self.parent(path, false) {
            Ok(found) => found,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => return Ok(None),
            Err(error) => return Err(error),
        };
        match fstatat(&directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) if kind_of(stat.st_mode) == Kind::File => {}
            Ok(_) | Err(Errno::ENOENT | Errno::ENOTDIR) => return Ok(None),
            Err(errno) => return Err(errno.into()),
        }
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let file = match openat(&directory, name, flags, Mode::empty()) {
            Ok(file) => file,
            Err(Errno::ENOENT | Errno::ELOOP | Errno::ENOTDIR | Errno::ENXIO) => return Ok(None),
            Err(errno) => return Err(errno.into()),
        };
        if kind_of(fstat(&file)?.st_mode) != Kind::File {
            return Ok(None);
        }
        Ok(Some(File::from(file)))
    }

    /// The SHA-256 digest of the regular file at `path`, as lower-case hex;
    /// none when no regular file is reached there without a link.
    ///
    /// # Errors
    ///
    /// Returns the error of a file that cannot be read.
    pub fn digest(&self, path: &str) -> io::Result<Option<String>> {
        let Some(mut file) = self.open_file(path)? else {
            return Ok(None);
        };
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1 << 16];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Some(hex(&hasher.finalize())))
    }

    /// The bytes of the regular file at `path`, when one is reached without a
    /// link and holds at most [`MAX_RECORD_FILE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns the error of a file that cannot be read.
    pub fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(file) = self.open_file(path)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_FILE + 1).read_to_end(&mut bytes)?;
        let within = u64::try_from(bytes.len()).is_ok_and(|len| len <= MAX_RECORD_FILE);
        Ok(within.then_some(bytes))
    }

    /// Writes `bytes` to `path`: to a temporary file created exclusively in the
    /// staging folder, then renamed from there over the destination. A
    /// failure removes the temporary file.
    ///
    /// # Errors
    ///
    /// Returns the error of a directory, a temporary file or a rename.
    pub fn write(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        let (directory, name) = self.parent(path, true)?;
        let staging = self.staging()?;
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let temporary = format!("{}.tmp", TEMPORARY.fetch_add(1, Ordering::Relaxed));
        let file = openat(
            &staging,
            temporary.as_str(),
            flags,
            Mode::from_bits_truncate(0o644),
        )?;
        let written = write_all(File::from(file), bytes).and_then(|()| {
            renameat(&staging, temporary.as_str(), &directory, name).map_err(io::Error::from)
        });
        if written.is_err() {
            let _removed = unlinkat(&staging, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
        }
        written
    }

    /// Opens `path` for appending, creating it when absent, without following
    /// a link.
    ///
    /// # Errors
    ///
    /// Returns the error of a file that cannot be opened.
    pub fn append(&self, path: &str) -> io::Result<File> {
        let (directory, name) = self.parent(path, true)?;
        let flags = OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_APPEND
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC;
        let file = openat(&directory, name, flags, Mode::from_bits_truncate(0o644))?;
        Ok(File::from(file))
    }

    /// Removes the file at `path`, a link itself and not its target.
    ///
    /// # Errors
    ///
    /// Returns the error of an entry that cannot be removed.
    pub fn remove(&self, path: &str) -> io::Result<()> {
        let (directory, name) = self.parent(path, false)?;
        unlinkat(&directory, name, UnlinkatFlags::NoRemoveDir).map_err(io::Error::from)
    }
}

impl Drop for Folder {
    /// Removes the staging folder, which every write has emptied; one that
    /// cannot be removed stays behind as a folder the next run does not own.
    fn drop(&mut self) {
        let staging = self
            .staging
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(staging) = staging {
            drop(staging.directory);
            let _removed = unlinkat(
                &self.directory,
                staging.name.as_str(),
                UnlinkatFlags::RemoveDir,
            );
        }
    }
}

/// Creates the new file `path` through its folder's descriptor, refusing a
/// folder that is or lies under one of the named directories in `apart`.
///
/// The folder the operator named is opened once; its ancestors are reached
/// from that descriptor by `..` up to the root, each compared with every
/// directory of `apart` by device and inode, and the file is created
/// exclusively, without following a link, in the folder so checked.
///
/// # Errors
///
/// Returns an `InvalidInput` error naming the role of the directory the
/// folder lies under, and the error of a folder that cannot be opened or a
/// file that exists or cannot be created.
pub fn create_apart(path: &Path, apart: &[(&Path, &str)]) -> io::Result<File> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "it names no file"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let followed = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let folder = nix::fcntl::open(parent, followed, Mode::empty())?;
    let fenced: Vec<_> = apart
        .iter()
        .filter_map(|(tree, role)| {
            let stat = nix::sys::stat::stat(*tree).ok()?;
            Some(((stat.st_dev, stat.st_ino), *role))
        })
        .collect();
    let mut at = folder.try_clone()?;
    loop {
        let stat = fstat(&at)?;
        let here = (stat.st_dev, stat.st_ino);
        if let Some((_, role)) = fenced.iter().find(|(tree, _)| *tree == here) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("it lies under the {role} directory"),
            ));
        }
        let up = openat(&at, "..", followed, Mode::empty())?;
        let above = fstat(&up)?;
        if (above.st_dev, above.st_ino) == here {
            break;
        }
        at = up;
    }
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let file = openat(&folder, name, flags, Mode::from_bits_truncate(0o644))?;
    Ok(File::from(file))
}

/// The name of this process's staging folder number `number`: hidden, and
/// outside the grammar of the files the program writes.
#[must_use]
pub fn staging_name(number: u64) -> String {
    format!(".chat-export-{}-{number}", std::process::id())
}

/// How many staging and temporary names this process has drawn so far.
#[must_use]
pub fn temporaries_drawn() -> u64 {
    TEMPORARY.load(Ordering::Relaxed)
}

fn write_all(mut file: File, bytes: &[u8]) -> io::Result<()> {
    file.write_all(bytes)?;
    file.flush()
}

/// Lower-case hexadecimal of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    text
}

/// The SHA-256 digest of `bytes`, as lower-case hex.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The SHA-256 digest of a stated sequence of fields, the kind of key that
/// decides whether something on disk may be kept.
///
/// Each field is written after its length as eight little-endian bytes, a list
/// after its count and a field that may be absent after a mark of whether it
/// is there, so two different sequences of fields never write the same bytes;
/// the first field names what the digest keys, so keys of different things
/// never meet.
pub struct Fields(Sha256);

impl Fields {
    /// A digest of the fields of `what`.
    #[must_use]
    pub fn new(what: &str) -> Self {
        let mut fields = Self(Sha256::new());
        fields.field(what.as_bytes());
        fields
    }

    /// Writes one field.
    pub fn field(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.0.update(bytes);
    }

    /// Writes how many fields or groups of fields follow.
    pub fn count(&mut self, count: usize) {
        self.0
            .update(u64::try_from(count).unwrap_or(u64::MAX).to_le_bytes());
    }

    /// Writes a field that may be absent.
    pub fn optional(&mut self, bytes: Option<&[u8]>) {
        match bytes {
            Some(bytes) => {
                self.count(1);
                self.field(bytes);
            }
            None => self.count(0),
        }
    }

    /// The digest of the fields written.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
