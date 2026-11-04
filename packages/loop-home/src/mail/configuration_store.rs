//! Loop-identity configuration replacement, serialized against delivery decisions.
use super::directory::MAX_CONFIGURATION_BYTES;
use super::journal::{MailError, Result};
use super::{acl, configuration::Configuration, io};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, mkdirat};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

pub struct ConfigurationStore {
    directory: File,
    private: PathBuf,
    _writer: Flock<File>,
    current: Option<Flock<File>>,
    pub configuration: Configuration,
    service: u32,
    failed: bool,
}
fn owned(file: &File) -> Result<()> {
    if file.metadata()?.uid() != nix::unistd::geteuid().as_raw() {
        return Err(MailError::Invalid(
            "unsafe-storage: configuration requires the loop identity",
        ));
    }
    Ok(())
}
fn private_root(path: &Path) -> Result<File> {
    if path == Path::new(".") {
        return Ok(File::from(nix::fcntl::open(
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?));
    }
    io::absolute(path, true)
}

fn create(parent: &File, name: &str) -> Result<File> {
    Ok(File::from(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
fn temporary(parent: &File, prefix: &str) -> Result<(String, File)> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    loop {
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!(".{prefix}-{}-{nonce}", std::process::id());
        match create(parent, &name) {
            Ok(file) => return Ok((name, file)),
            Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

fn lock(parent: &File) -> Result<Flock<File>> {
    let file = match create(parent, "loop.lock") {
        Ok(file) => {
            file.sync_all()?;
            parent.sync_all()?;
            file
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            io::child(parent, Path::new("loop.lock"), false)?
        }
        Err(error) => return Err(error),
    };
    owned(&file)?;
    let info = file.metadata()?;
    if !info.is_file() || info.nlink() != 1 || info.mode() & 0o777 != 0o600 {
        return Err(MailError::Invalid(
            "unsafe-storage: configuration writer lock",
        ));
    }
    Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| error.into())
}
impl ConfigurationStore {
    /// Open only as the owning loop; a missing configuration is initialized only
    /// when neither worker history nor a configuration backup indicates prior state.
    ///
    /// # Errors
    /// Refuses wrong ownership, unexpected grants, corrupt or missing prior state.
    pub fn open(private: &Path, service: u32) -> Result<Self> {
        let mut directory = private_root(private)?;
        owned(&directory)?;
        acl::ensure_private(&directory, service, true)?;
        for name in [".config", "mail"] {
            match mkdirat(&directory, name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => directory.sync_all()?,
                Err(nix::errno::Errno::EEXIST) => {}
                Err(error) => return Err(error.into()),
            }
            directory = io::child(&directory, Path::new(name), true)?;
            owned(&directory)?;
            acl::ensure_private(&directory, service, true)?;
        }
        let writer = lock(&directory)?;
        let current = match io::child(&directory, Path::new("loop.toml"), false) {
            Ok(file) => {
                owned(&file)?;
                Some(
                    Flock::lock(file, FlockArg::LockExclusive)
                        .map_err(|(_, error)| MailError::from(error))?,
                )
            }
            Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let configuration = if let Some(file) = &current {
            let configuration = Configuration::parse(&io::bounded(file, MAX_CONFIGURATION_BYTES)?)?;
            acl::ensure_private(file, service, false)?;
            configuration
        } else {
            let loop_root = if private == Path::new(".") {
                PathBuf::from("..")
            } else {
                private
                    .parent()
                    .ok_or(MailError::Invalid("private home parent"))?
                    .to_path_buf()
            };
            let backup = match io::child(&directory, Path::new("loop.toml.backup"), false) {
                Ok(_) => true,
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
            let mut history = false;
            for name in ["workers", ".mail-births", ".mail-worker-staging"] {
                match std::fs::symlink_metadata(loop_root.join(name)) {
                    Ok(_) => history = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if history || backup {
                return Err(MailError::Invalid(
                    "invalid-directory: missing configuration requires backup reconciliation",
                ));
            }
            Configuration::parse(b"workers=[]\n[mail]\nversion=1\nallow=[]\n")?
        };
        let mut store = Self {
            directory,
            private: private.to_path_buf(),
            _writer: writer,
            current,
            configuration,
            service,
            failed: false,
        };
        if store.current.is_none() {
            store.publish()?;
        }
        Ok(store)
    }
    /// Prevent an in-memory mutation from standing in for an uncertain durable write.
    pub(crate) const fn available(&self) -> Result<()> {
        if self.failed {
            return Err(MailError::Invalid(
                "invalid-directory: reopen configuration after an uncertain write",
            ));
        }
        Ok(())
    }
    /// Atomically replace the complete validated configuration.
    ///
    /// # Errors
    /// Refuses changed custody or any write failure; an uncertain write requires a fresh handle.
    pub fn publish(&mut self) -> Result<()> {
        self.available()?;
        self.failed = true;
        let result = self.publish_checked();
        self.failed = result.is_err();
        result
    }
    fn publish_checked(&mut self) -> Result<()> {
        self.configuration.validate()?;
        let bytes = toml::to_string(&self.configuration)
            .map_err(|_| MailError::Invalid("invalid-directory: configuration serialization"))?
            .into_bytes();
        let mut ancestor = private_root(&self.private)?;
        owned(&ancestor)?;
        acl::verify(&ancestor, self.service, true)?;
        for name in [".config", "mail"] {
            ancestor = io::child(&ancestor, Path::new(name), true)?;
            owned(&ancestor)?;
            acl::verify(&ancestor, self.service, true)?;
        }
        let current = ancestor.metadata()?;
        let held = self.directory.metadata()?;
        if (current.dev(), current.ino()) != (held.dev(), held.ino()) {
            return Err(MailError::Invalid(
                "changed-source: configuration directory replaced",
            ));
        }
        let (name, mut file) = temporary(&self.directory, "loop.toml")?;
        file.write_all(&bytes)?;
        acl::install(&file, self.service, false)?;
        file.sync_all()?;
        if let Some(previous) = &self.current {
            // Read from a new descriptor because bounded reads consume offsets.
            let old = io::child(&self.directory, Path::new("loop.toml"), false)?;
            let info = old.metadata()?;
            let held = previous.metadata()?;
            if (info.dev(), info.ino()) != (held.dev(), held.ino()) {
                return Err(MailError::Invalid(
                    "changed-source: configuration replaced outside its writer lock",
                ));
            }
            let (backup_name, mut backup) = temporary(&self.directory, "loop.backup")?;
            backup.write_all(&io::bounded(&old, MAX_CONFIGURATION_BYTES)?)?;
            backup.sync_all()?;
            renameat(
                &self.directory,
                backup_name.as_str(),
                &self.directory,
                "loop.toml.backup",
            )?;
            self.directory.sync_all()?;
        }
        renameat(&self.directory, name.as_str(), &self.directory, "loop.toml")?;
        self.directory.sync_all()?;
        self.current = Some(
            Flock::lock(file, FlockArg::LockExclusive)
                .map_err(|(_, error)| MailError::from(error))?,
        );
        Ok(())
    }
    #[must_use]
    pub fn path(private: &Path) -> PathBuf {
        private.join(".config/mail/loop.toml")
    }
}

#[cfg(test)]
#[path = "configuration_store_tests.rs"]
mod tests;
