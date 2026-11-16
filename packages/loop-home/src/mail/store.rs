//! Descriptor-relative, service-private durable metadata storage.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;

use nix::fcntl::{OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::journal::{JOURNAL_MAX_BYTES, MailError, Result, SUMMARY_MAX_BYTES};

pub(super) fn private(file: &File, directory: bool) -> Result<()> {
    let info = file.metadata()?;
    if info.uid() != geteuid().as_raw()
        || info.mode() & 0o077 != 0
        || info.is_dir() != directory
        || (!directory && (!info.is_file() || info.nlink() != 1))
    {
        return Err(MailError::Invalid(
            "unsafe-storage: service-private object required",
        ));
    }
    Ok(())
}

pub(super) fn open(parent: &File, name: &str, directory: bool) -> Result<File> {
    let flags = OFlag::O_RDONLY
        | OFlag::O_CLOEXEC
        | OFlag::O_NONBLOCK
        | if directory {
            OFlag::O_DIRECTORY
        } else {
            OFlag::empty()
        };
    let file = File::from(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(flags)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    private(&file, directory)?;
    Ok(file)
}

pub(super) fn directory(parent: &File, name: &str) -> Result<File> {
    mkdirat(parent, name, Mode::S_IRWXU)?;
    parent.sync_all()?;
    open(parent, name, true)
}

pub(super) fn bytes(parent: &File, name: &str, limit: u64) -> Result<Vec<u8>> {
    let file = open(parent, name, false)?;
    if file.metadata()?.len() > limit {
        return Err(MailError::Invalid("oversize journal object"));
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(MailError::Invalid("growing journal object"));
    }
    Ok(data)
}

pub(super) fn read<T: DeserializeOwned>(parent: &File, name: &str, limit: u64) -> Result<T> {
    let data = bytes(parent, name, limit)?;
    let text = std::str::from_utf8(&data).map_err(|_| MailError::Invalid("journal encoding"))?;
    toml::from_str(text).map_err(|_| MailError::Invalid("journal schema"))
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    toml::to_string(value)
        .map(String::into_bytes)
        .map_err(|_| MailError::Invalid("journal serialization"))
}

pub(super) fn remove(parent: &File, name: &str) -> Result<()> {
    unlinkat(parent, name, UnlinkatFlags::NoRemoveDir)?;
    parent.sync_all()?;
    Ok(())
}

pub(super) fn names(parent: &File) -> Result<Vec<String>> {
    let mut directory = nix::dir::Dir::from_fd(openat2(
        parent,
        ".",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?)?;
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| MailError::Invalid("journal filename"))?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

pub(super) fn size(parent: &File) -> Result<u64> {
    #[cfg(test)]
    SIZE_SCANS.with(|count| count.set(count.get() + 1));
    let mut total = 0u64;
    for name in names(parent)? {
        let file = open(parent, &name, name == "deliveries")?;
        let length = if name == "deliveries" {
            size(&file)?
        } else {
            file.metadata()?.len()
        };
        total = total.checked_add(length).ok_or(MailError::Capacity)?;
    }
    Ok(total)
}

pub(super) fn write<T: Serialize>(
    root: &File,
    parent: &File,
    name: &str,
    value: &T,
    replace: bool,
) -> Result<()> {
    write_at_size(size(root)?, parent, name, value, replace)
}
fn write_at_size<T: Serialize>(
    total: u64,
    parent: &File,
    name: &str,
    value: &T,
    replace: bool,
) -> Result<()> {
    let data = encode(value)?;
    // Record growth must leave enough space to compact safely even at capacity.
    // State and checkpoint writes consume that reserved metadata scratch.
    let compaction_scratch =
        if name != "state.toml" && name != "checkpoint.toml" && name != "writer.lock" {
            2 * SUMMARY_MAX_BYTES
        } else {
            0
        };
    if total
        .checked_add(data.len() as u64 + compaction_scratch)
        .is_none_or(|n| n > JOURNAL_MAX_BYTES)
    {
        return Err(MailError::Capacity);
    }
    let temp = format!(".{name}.replace");
    // A prior interrupted replacement is unpublished. Recovery validates the
    // committed object before removing this exact scratch name.
    let mut file = File::from(openat2(
        parent,
        temp.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    file.write_all(&data)?;
    file.sync_all()?;
    #[cfg(test)]
    interruption(1)?;
    parent.sync_all()?;
    #[cfg(test)]
    interruption(2)?;
    renameat2(
        parent,
        temp.as_str(),
        parent,
        name,
        if replace {
            RenameFlags::empty()
        } else {
            RenameFlags::RENAME_NOREPLACE
        },
    )?;
    #[cfg(test)]
    interruption(3)?;
    parent.sync_all()?;
    #[cfg(test)]
    interruption(4)?;
    Ok(())
}

#[cfg(test)]
thread_local! { pub(super) static INTERRUPT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
fn interruption(boundary: u8) -> Result<()> {
    #[cfg(test)]
    if INTERRUPT.with(|selected| selected.get() == boundary && selected.replace(0) != 0) {
        return Err(MailError::Invalid("injected metadata interruption"));
    }
    Ok(())
}

#[cfg(test)]
thread_local! { pub(super) static SIZE_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

/// Running byte accounting belongs to the exclusive journal writer. The root
/// admission lock additionally serializes outside reservation updates.
#[derive(Default)]
pub(super) struct Usage {
    total: std::cell::Cell<Option<u64>>,
    external: std::cell::Cell<u64>,
    admission: std::rc::Rc<std::cell::RefCell<Option<nix::fcntl::Flock<File>>>>,
}
pub(super) struct Admission(
    Option<std::rc::Rc<std::cell::RefCell<Option<nix::fcntl::Flock<File>>>>>,
);
impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(held) = &self.0 {
            held.borrow_mut().take();
        }
    }
}
impl Usage {
    pub fn admit(&self, root: &File) -> Result<Admission> {
        if self.admission.borrow().is_some() {
            return Ok(Admission(None));
        }
        let lock =
            nix::fcntl::Flock::lock(open(root, ".", true)?, nix::fcntl::FlockArg::LockExclusive)
                .map_err(|(_, error)| MailError::from(error))?;
        *self.admission.borrow_mut() = Some(lock);
        Ok(Admission(Some(std::rc::Rc::clone(&self.admission))))
    }
    pub fn remeasure(&self, root: &File) -> Result<()> {
        let _admission = self.admit(root)?;
        self.total.set(None);
        let total = size(root)?;
        self.external.set(external_size(root)?);
        self.total.set(Some(total));
        Ok(())
    }
    pub fn total(&self, root: &File) -> Result<u64> {
        let _admission = self.admit(root)?;
        if self.total.get().is_none() {
            self.remeasure(root)?;
        }
        let external = external_size(root)?;
        let total = self
            .total
            .get()
            .ok_or(MailError::Capacity)?
            .checked_sub(self.external.get())
            .and_then(|n| n.checked_add(external))
            .ok_or(MailError::Capacity)?;
        self.external.set(external);
        self.total.set(Some(total));
        Ok(total)
    }
    pub fn write<T: Serialize>(
        &self,
        root: &File,
        parent: &File,
        name: &str,
        value: &T,
        replace: bool,
    ) -> Result<()> {
        let _admission = self.admit(root)?;
        let total = self.total(root)?;
        let before = replacement_size(parent, name)?;
        let result = write_at_size(total, parent, name, value, replace);
        let accounted = self.changed(root, parent, name, before);
        result.and(accounted)
    }
    pub fn remove(&self, root: &File, parent: &File, name: &str) -> Result<()> {
        let _admission = self.admit(root)?;
        self.total(root)?;
        let before = replacement_size(parent, name)?;
        let result = remove(parent, name);
        let accounted = self.changed(root, parent, name, before);
        result.and(accounted)
    }
    fn changed(&self, root: &File, parent: &File, name: &str, before: u64) -> Result<()> {
        let previous = self.total.take().ok_or(MailError::Capacity)?;
        let after = replacement_size(parent, name)?;
        let total = previous
            .checked_sub(before)
            .and_then(|n| n.checked_add(after))
            .ok_or(MailError::Capacity)?;
        if name == "reservation-pins.toml" || name == ".reservation-pins.toml.replace" {
            self.external.set(external_size(root)?);
        }
        self.total.set(Some(total));
        Ok(())
    }
}
fn object_size(parent: &File, name: &str) -> Result<u64> {
    match open(parent, name, false) {
        Ok(file) => Ok(file.metadata()?.len()),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}
fn replacement_size(parent: &File, name: &str) -> Result<u64> {
    object_size(parent, name)?
        .checked_add(object_size(parent, &format!(".{name}.replace"))?)
        .ok_or(MailError::Capacity)
}
fn external_size(root: &File) -> Result<u64> {
    replacement_size(root, "reservation-pins.toml")
}
