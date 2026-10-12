use nix::fcntl::{Flock, FlockArg};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

pub fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("cursor is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(io::Error::other("cursor exceeds limit"));
    }
    if bytes.is_empty() {
        return Err(io::Error::other(format!(
            "empty cursor: {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

pub fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if read(path)?.as_deref() == Some(bytes) {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("cursor parent"))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}

pub struct Guard {
    _held: Flock<File>,
}

impl Guard {
    pub fn acquire(root: &Path, name: &str) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let path = root.join(format!(".cursor-{name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other(format!(
                "lock is not regular: {}",
                path.display()
            )));
        }
        let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
            io::Error::other(format!("cursor lock {}: {error}", path.display()))
        })?;
        // Keep the lock inode: unlinking lets a concurrent opener lock a second inode.
        Ok(Self { _held: held })
    }
}
