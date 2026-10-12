//! The input tree a loop is read from, reached without following links.
//!
//! The projects folder and its ancestors are the operator's and are resolved
//! as the system resolves them. Below it, the loop's project folder, each
//! session folder and its agents' folder, and every transcript and meta file
//! are opened relative to their folder's descriptor with no-follow, and a file
//! is read only when the opened descriptor is a regular file. A file is
//! reached again the same way each time it is read, so a link or a pipe
//! placed in the tree, before or during a run, is never followed or read.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstat, fstatat};

/// The flags every folder below the projects folder is opened with.
const FOLDER: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// What stands at a name of the input tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    /// A symbolic link, never followed.
    Link,
    /// A pipe, a socket or a device, never read.
    Other,
}

/// What reaching a name of the input tree found.
#[derive(Debug)]
pub enum Reached<T> {
    Found(T),
    /// Nothing stands at the name.
    Absent,
    /// A link, a pipe or anything but the kind the program reads there.
    Refused,
}

const fn kind_of(mode: u32) -> EntryKind {
    let format = mode & SFlag::S_IFMT.bits();
    if format == SFlag::S_IFREG.bits() {
        EntryKind::File
    } else if format == SFlag::S_IFDIR.bits() {
        EntryKind::Directory
    } else if format == SFlag::S_IFLNK.bits() {
        EntryKind::Link
    } else {
        EntryKind::Other
    }
}

/// Opens the folder `name` in `parent` without following a link.
fn descend(parent: &OwnedFd, name: &OsStr) -> io::Result<Reached<OwnedFd>> {
    match openat(parent, name, FOLDER, Mode::empty()) {
        Ok(folder) => Ok(Reached::Found(folder)),
        Err(Errno::ENOENT) => Ok(Reached::Absent),
        Err(Errno::ELOOP | Errno::ENOTDIR) => Ok(Reached::Refused),
        Err(errno) => Err(errno.into()),
    }
}

/// Descends `names` from `folder`, each a folder reached without following a
/// link.
fn walk(folder: &OwnedFd, names: &[OsString]) -> io::Result<Reached<OwnedFd>> {
    let mut at = folder.try_clone()?;
    for name in names {
        match descend(&at, name)? {
            Reached::Found(next) => at = next,
            Reached::Absent => return Ok(Reached::Absent),
            Reached::Refused => return Ok(Reached::Refused),
        }
    }
    Ok(Reached::Found(at))
}

/// A loop's project folder, held open by its descriptor.
#[derive(Clone, Debug)]
pub struct Project {
    folder: Arc<OwnedFd>,
    /// The folder's path, for messages and the manifest's sources.
    pub path: PathBuf,
}

impl Project {
    /// Opens the project folder `name` in the operator's `projects` folder:
    /// the projects folder resolved as the system resolves it, the project
    /// folder without following a link.
    ///
    /// # Errors
    ///
    /// Returns the error of a projects folder that cannot be opened.
    pub fn open(projects: &Path, name: &OsStr) -> io::Result<Reached<Self>> {
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let parent = nix::fcntl::open(projects, flags, Mode::empty())?;
        Ok(match descend(&parent, name)? {
            Reached::Found(folder) => Reached::Found(Self {
                folder: Arc::new(folder),
                path: projects.join(name),
            }),
            Reached::Absent => Reached::Absent,
            Reached::Refused => Reached::Refused,
        })
    }

    /// Opens the folder at `path` as a project folder, its last component
    /// without following a link.
    ///
    /// # Errors
    ///
    /// Returns a `NotFound` error for nothing at `path`, an `InvalidInput`
    /// error for a link or anything but a folder there, and the error of a
    /// parent that cannot be opened.
    pub fn at(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no folder name"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        match Self::open(parent, name)? {
            Reached::Found(project) => Ok(project),
            Reached::Absent => Err(io::ErrorKind::NotFound.into()),
            Reached::Refused => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is a link or not a folder", path.display()),
            )),
        }
    }

    /// The file reached from this folder through `names`.
    #[must_use]
    pub fn file(&self, names: Vec<OsString>) -> InputFile {
        let path = names
            .iter()
            .fold(self.path.clone(), |path, name| path.join(name));
        InputFile {
            folder: Arc::clone(&self.folder),
            names,
            path,
        }
    }

    /// The entries of the folder reached through `names`, in name order, each
    /// with its kind found without following a link.
    ///
    /// # Errors
    ///
    /// Returns the error of a folder that cannot be opened or listed.
    pub fn list(&self, names: &[OsString]) -> io::Result<Reached<Vec<(OsString, EntryKind)>>> {
        let folder = match walk(&self.folder, names)? {
            Reached::Found(folder) => folder,
            Reached::Absent => return Ok(Reached::Absent),
            Reached::Refused => return Ok(Reached::Refused),
        };
        let mut listing = Dir::openat(&folder, ".", FOLDER, Mode::empty())?;
        let mut entries = Vec::new();
        for entry in listing.iter() {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = OsStr::from_bytes(name).to_owned();
            let kind = match entry.file_type() {
                Some(Type::File) => EntryKind::File,
                Some(Type::Directory) => EntryKind::Directory,
                Some(Type::Symlink) => EntryKind::Link,
                Some(_) => EntryKind::Other,
                None => match fstatat(&folder, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Ok(stat) => kind_of(stat.st_mode),
                    Err(Errno::ENOENT) => continue,
                    Err(errno) => return Err(errno.into()),
                },
            };
            entries.push((name, kind));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Reached::Found(entries))
    }
}

/// A file of the input tree: its project folder, held open, and the names
/// that lead from it to the file.
#[derive(Clone, Debug)]
pub struct InputFile {
    folder: Arc<OwnedFd>,
    names: Vec<OsString>,
    /// The file's path, for messages and the manifest's sources.
    pub path: PathBuf,
}

impl InputFile {
    /// Opens the file for reading when it is a regular file, every folder on
    /// the way and the file itself reached without following a link.
    ///
    /// # Errors
    ///
    /// Returns the error of a folder or a file that cannot be opened.
    pub fn open(&self) -> io::Result<Reached<File>> {
        let Some((name, folders)) = self.names.split_last() else {
            return Ok(Reached::Absent);
        };
        let folder = match walk(&self.folder, folders)? {
            Reached::Found(folder) => folder,
            Reached::Absent => return Ok(Reached::Absent),
            Reached::Refused => return Ok(Reached::Refused),
        };
        match fstatat(&folder, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) if kind_of(stat.st_mode) == EntryKind::File => {}
            Ok(_) => return Ok(Reached::Refused),
            Err(Errno::ENOENT) => return Ok(Reached::Absent),
            Err(errno) => return Err(errno.into()),
        }
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let file = match openat(&folder, name.as_os_str(), flags, Mode::empty()) {
            Ok(file) => file,
            Err(Errno::ENOENT) => return Ok(Reached::Absent),
            Err(Errno::ELOOP | Errno::ENXIO | Errno::ENOTDIR) => return Ok(Reached::Refused),
            Err(errno) => return Err(errno.into()),
        };
        if kind_of(fstat(&file)?.st_mode) != EntryKind::File {
            return Ok(Reached::Refused);
        }
        Ok(Reached::Found(File::from(file)))
    }

    /// The file named `name` in this file's folder.
    #[must_use]
    pub fn beside(&self, name: &str) -> Self {
        let mut names = self.names.clone();
        names.pop();
        names.push(OsString::from(name));
        Self {
            folder: Arc::clone(&self.folder),
            names,
            path: self.path.with_file_name(name),
        }
    }

    /// The file's name without its extension.
    #[must_use]
    pub fn stem(&self) -> String {
        self.path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}
