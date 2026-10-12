//! Descriptor-relative access to the non-credential files managed in a Claude home.

use super::Result;
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, OpenHow, ResolveFlag, open, openat2, renameat};
use nix::sys::stat::{Mode, fstat, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) struct Directory {
    pub file: Flock<File>,
    path: PathBuf,
}

fn lock(mut file: File, path: &Path) -> Result<Flock<File>> {
    let started = Instant::now();
    let limit = Duration::from_secs(5);
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(locked) => return Ok(locked),
            Err((returned, nix::errno::Errno::EWOULDBLOCK)) => file = returned,
            Err((_, error)) => return Err(error.to_string()),
        }
        let remaining = limit.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(format!("claude-home-locked: {}", path.display()));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn directory_at(parent: &impl std::os::fd::AsFd, name: &Path) -> Result<OwnedFd> {
    openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| format!("claude-home-path: {}: {error}", name.display()))
}

fn protected(fd: &impl std::os::fd::AsFd, exact: bool) -> Result<()> {
    let stat = fstat(fd).map_err(|error| error.to_string())?;
    if stat.st_uid != super::owner_uid()
        || stat.st_mode & 0o022 != 0
        || (exact && stat.st_mode & 0o7777 != 0o700)
    {
        return Err(format!(
            "claude-home-owner-mode: owner={} mode={:o} expected_owner={} exact_home={exact}",
            stat.st_uid,
            stat.st_mode & 0o7777,
            super::owner_uid()
        ));
    }
    Ok(())
}

impl Directory {
    pub fn open(owner: &Path, path: &Path, create: bool) -> Result<Self> {
        let relative = path
            .strip_prefix(owner)
            .map_err(|_| "claude-home-path: outside owner home")?;
        let canonical = std::fs::canonicalize(owner).map_err(|error| error.to_string())?;
        let mut fd = open(
            &canonical,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| error.to_string())?;
        protected(&fd, false)?;
        for part in relative.components() {
            let Component::Normal(name) = part else {
                return Err("claude-home-path: invalid component".into());
            };
            if create {
                match mkdirat(&fd, name, Mode::S_IRWXU) {
                    Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
            fd = directory_at(&fd, Path::new(name))?;
            protected(&fd, false)?;
        }
        let file = lock(File::from(fd), path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn child(&self, name: &str) -> Result<Self> {
        let fd = directory_at(&*self.file, Path::new(name))?;
        protected(&fd, true)?;
        let path = self.path.join(name);
        let file = lock(File::from(fd), &path)?;
        Ok(Self { file, path })
    }

    pub fn check_home(&self) -> Result<()> {
        protected(&*self.file, true)
    }

    pub fn identity(&self) -> Result<serde_json::Value> {
        let stat = fstat(&*self.file).map_err(|error| error.to_string())?;
        Ok(
            serde_json::json!({"device":stat.st_dev,"inode":stat.st_ino,"owner":stat.st_uid,"mode":stat.st_mode & 0o7777}),
        )
    }

    pub fn metadata(&self, name: &str) -> Result<Option<serde_json::Value>> {
        match fstatat(&*self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(
                serde_json::json!({"owner":stat.st_uid,"mode":stat.st_mode & 0o7777,"kind":stat.st_mode & libc::S_IFMT,"device":stat.st_dev,"inode":stat.st_ino}),
            )),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(error) => Err(format!("claude-home-metadata: {name}: {error}")),
        }
    }

    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if !matches!(
            name,
            "ssh_config"
                | "known_hosts.routes"
                | "settings.json"
                | ".claude.json"
                | "move-record.json"
        ) {
            return Err("claude-home-read: unmanaged file".into());
        }
        let fd = match openat2(
            &*self.file,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(format!("claude-home-read: {name}: {error}")),
        };
        let stat = fstat(&fd).map_err(|error| error.to_string())?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_uid != super::owner_uid()
            || stat.st_mode & 0o022 != 0
            || stat.st_size > 4_194_304
        {
            return Err(format!(
                "claude-home-file: {name}: owner, type, links, mode or size"
            ));
        }
        let mut bytes = Vec::new();
        File::from(fd)
            .take(4_194_305)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 4_194_304 {
            return Err(format!("claude-home-file: {name}: size"));
        }
        Ok(Some(bytes))
    }

    pub fn replace(&self, name: &str, bytes: &[u8]) -> Result<()> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staged = format!(".{name}.{}.{}", std::process::id(), sequence);
        let fd = openat2(
            &*self.file,
            staged.as_str(),
            OpenHow::new()
                .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| error.to_string())?;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| error.to_string())?;
            renameat(&*self.file, staged.as_str(), &*self.file, name)
                .map_err(|error| error.to_string())?;
            self.file.sync_all().map_err(|error| error.to_string())
        })();
        let _removed = unlinkat(&*self.file, staged.as_str(), UnlinkatFlags::NoRemoveDir);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics only if fixture setup or the bounded directory lock contract fails.
    /// ´test:unit:claude-directory-lock-refuses-with-path-within-bound´
    #[test]
    fn claude_directory_lock_refuses_with_path_within_bound() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().expect("fixture");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protected fixture");
        let held = Directory::open(root.path(), root.path(), false).expect("first handle");
        let started = Instant::now();
        let error = Directory::open(root.path(), root.path(), false)
            .err()
            .expect("contending handle refuses");
        assert_eq!(
            error,
            format!("claude-home-locked: {}", root.path().display())
        );
        // Allow scheduler overhead beyond the five-second retry budget.
        assert!(started.elapsed() < Duration::from_secs(6));
        drop(held);
        assert!(Directory::open(root.path(), root.path(), false).is_ok());
    }
}
