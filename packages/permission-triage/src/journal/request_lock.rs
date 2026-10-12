//! The legacy PID lock protocol, resolved only through the held root descriptor.
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, Instant, SystemTime};

use nix::errno::Errno;
use nix::fcntl::{OFlag, RenameFlags, openat, renameat, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use request_core::Error;

use crate::requests::failure;

pub(super) struct Lock<'a> {
    directory: &'a File,
    name: &'static str,
    file: File,
    release_wait: Duration,
}

fn open(directory: &File, name: &str, flags: OFlag) -> Result<File, Errno> {
    openat(
        directory,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::from_bits_truncate(0o600),
    )
    .map(File::from)
}

fn same(first: &File, second: &File) -> bool {
    match (first.metadata(), second.metadata()) {
        (Ok(first), Ok(second)) => first.dev() == second.dev() && first.ino() == second.ino(),
        _ => false,
    }
}

fn owns(directory: &File, name: &str, file: &File) -> bool {
    open(directory, name, OFlag::O_RDONLY).is_ok_and(|current| same(file, &current))
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        let started = Instant::now();
        loop {
            if owns(self.directory, self.name, &self.file) {
                let _removed = unlinkat(self.directory, self.name, UnlinkatFlags::NoRemoveDir);
                return;
            }
            if !matches!(
                open(self.directory, self.name, OFlag::O_RDONLY),
                Err(Errno::ENOENT)
            ) {
                return;
            }
            let Some(delay) = super::lock_retry_delay(started.elapsed(), self.release_wait) else {
                return;
            };
            std::thread::sleep(delay);
        }
    }
}

fn stale(file: &File) -> Result<bool, Error> {
    super::verify_private_file(file).map_err(failure)?;
    let metadata = file.metadata().map_err(failure)?;
    if metadata.nlink() != 1 {
        return Err(failure("journal lock link count differs"));
    }
    let mut bytes = Vec::new();
    file.take(64).read_to_end(&mut bytes).map_err(failure)?;
    let dead = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .and_then(|value| value.parse::<u32>().ok())
        .is_none_or(|pid| !super::pid_is_live(pid));
    let old = SystemTime::now()
        .duration_since(metadata.modified().map_err(failure)?)
        .is_ok_and(|age| age >= super::LOCK_STALE_AFTER);
    Ok(dead && old)
}

fn recover(directory: &File, name: &str) -> Result<(), Error> {
    let first = match open(directory, name, OFlag::O_RDONLY) {
        Ok(file) => file,
        Err(Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(failure(error)),
    };
    if !stale(&first)? {
        return Ok(());
    }
    let claim = format!(
        "{name}.steal.{}.{}-{}",
        std::process::id(),
        request_core::now_ns()?,
        super::LOCK_CLAIM_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    match renameat(directory, name, directory, claim.as_str()) {
        Ok(()) => {}
        Err(Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(failure(error)),
    }
    let claimed = open(directory, &claim, OFlag::O_RDONLY).map_err(failure)?;
    if !same(&first, &claimed) || !stale(&claimed)? {
        // Match the retained PID-lock protocol: restore a displaced live lock
        // only while the public name is absent; never unlink a successor.
        if renameat2(
            directory,
            claim.as_str(),
            directory,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    unlinkat(directory, claim.as_str(), UnlinkatFlags::NoRemoveDir).map_err(failure)?;
    Ok(())
}

pub(super) fn acquire<'a>(
    directory: &'a File,
    journal: &super::Journal,
) -> Result<Lock<'a>, Error> {
    let name = super::lock_filename(journal.scope);
    let started = Instant::now();
    loop {
        match open(
            directory,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
        ) {
            Ok(file) => {
                let mut lock = Lock {
                    directory,
                    name,
                    file,
                    release_wait: super::lock_release_window(
                        journal.lock_wait.saturating_sub(started.elapsed()),
                    ),
                };
                writeln!(lock.file, "{}", std::process::id()).map_err(failure)?;
                lock.file.sync_all().map_err(failure)?;
                super::verify_private_file(&lock.file).map_err(failure)?;
                if !owns(directory, name, &lock.file) {
                    return Err(failure("journal lock identity changed"));
                }
                directory.sync_all().map_err(failure)?;
                return Ok(lock);
            }
            Err(Errno::EEXIST) => recover(directory, name)?,
            Err(error) => return Err(failure(error)),
        }
        let Some(delay) = super::lock_retry_delay(started.elapsed(), journal.lock_wait) else {
            return Err(failure("journal lock wait elapsed"));
        };
        std::thread::sleep(delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    /// ´test:unit:request-lock-follows-held-directory-and-preserves-successor-inode´
    #[test]
    fn request_lock_follows_held_directory_and_preserves_successor_inode() {
        let root = std::env::temp_dir().join(format!(
            "request-lock-{}-{}",
            std::process::id(),
            request_core::now_ns().expect("clock")
        ));
        fs::create_dir(&root).expect("fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let directory = File::open(&root).expect("held root");
        let journal = super::super::Journal::from_state_root(&root);
        let moved = root.with_extension("moved");
        fs::rename(&root, &moved).expect("rename root");
        fs::create_dir(&root).expect("replacement root");
        let name = super::super::lock_filename(journal.scope);
        let guard = acquire(&directory, &journal).expect("descriptor lock");
        assert!(moved.join(name).exists());
        assert!(!root.join(name).exists());
        let old = moved.join("held-old");
        fs::rename(moved.join(name), &old).expect("displace lock");
        fs::write(moved.join(name), b"successor").expect("new inode");
        drop(guard);
        assert_eq!(
            fs::read(moved.join(name)).expect("successor retained"),
            b"successor"
        );
        fs::remove_dir_all(&root).expect("remove replacement");
        fs::remove_dir_all(&moved).expect("remove held root");
    }

    /// ´test:unit:request-lock-recovers-only-dead-and-old-legacy-locks´
    #[test]
    fn request_lock_recovers_only_dead_and_old_legacy_locks() {
        let root = std::env::temp_dir().join(format!(
            "request-lock-stale-{}-{}",
            std::process::id(),
            request_core::now_ns().expect("clock")
        ));
        fs::create_dir(&root).expect("fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
        let directory = File::open(&root).expect("held root");
        let journal = super::super::Journal::from_state_root(&root);
        let name = super::super::lock_filename(journal.scope);
        let path = root.join(name);
        fs::write(&path, format!("{}\n", std::process::id())).expect("live lock");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private lock");
        File::open(&path)
            .expect("lock")
            .set_modified(SystemTime::UNIX_EPOCH)
            .expect("old lock");
        recover(&directory, name).expect("live recovery check");
        assert!(path.exists());
        fs::write(&path, b"garbage\n").expect("dead owner");
        recover(&directory, name).expect("fresh recovery check");
        assert!(path.exists());
        File::open(&path)
            .expect("lock")
            .set_modified(SystemTime::UNIX_EPOCH)
            .expect("old dead lock");
        let lock = acquire(&directory, &journal).expect("recover stale lock");
        assert_eq!(
            fs::read_to_string(&path).expect("new owner"),
            format!("{}\n", std::process::id())
        );
        drop(lock);
        assert!(!path.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
