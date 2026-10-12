use nix::dir::Dir;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::stat::Mode;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let file = open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("input is not regular"));
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other("input exceeds 64 MiB"));
    }
    Ok(bytes)
}

pub fn list(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut directory = match Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_NOATIME,
        Mode::empty(),
    ) {
        Ok(directory) => directory,
        Err(nix::errno::Errno::ENOENT) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut paths = Vec::new();
    for entry in directory.iter() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let path = path.join(OsStr::from_bytes(name));
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(io::Error::other("application-state symlink refused"));
        }
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

pub fn app_running(path: &Path) -> io::Result<bool> {
    let file = match open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut lock = libc::flock {
        l_type: i16::try_from(libc::F_WRLCK).map_err(io::Error::other)?,
        l_whence: 0,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(&file, FcntlArg::F_GETLK(&mut lock))?;
    Ok(i32::from(lock.l_type) != libc::F_UNLCK)
}

pub fn backup(root: &Path, prefix: &str) -> io::Result<PathBuf> {
    let root = std::path::absolute(root)?;
    let parent = root
        .parent()
        .ok_or_else(|| io::Error::other("backup parent"))?;
    let name = root
        .file_name()
        .ok_or_else(|| io::Error::other("backup basename"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let path = parent.join(format!("{prefix}-{stamp}.tar.gz"));
    let status = Command::new("tar")
        .arg("czf")
        .arg(&path)
        .arg("--")
        .arg(name)
        .current_dir(parent)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("backup failed"));
    }
    Ok(path)
}

pub fn json(path: &Path) -> io::Result<serde_json::Value> {
    serde_json::from_slice(&read(path)?).map_err(io::Error::other)
}

pub fn stores(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut stores = Vec::new();
    for account in list(root)? {
        if !account.is_dir() {
            continue;
        }
        for org in list(&account)? {
            if org.is_dir() && !sessions(&org)?.is_empty() {
                stores.push(org);
            }
        }
    }
    Ok(stores)
}

pub fn sessions(root: &Path) -> io::Result<Vec<PathBuf>> {
    Ok(list(root)?
        .into_iter()
        .filter(|path| {
            path.is_file()
                && path.extension().is_some_and(|ext| ext == "json")
                && path
                    .file_name()
                    .is_some_and(|name| name.as_encoded_bytes().starts_with(b"local_"))
        })
        .collect())
}
