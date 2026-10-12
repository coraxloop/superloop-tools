use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::{Mode, fstatat, mkdirat};
use nix::unistd::{Uid, UnlinkatFlags, dup, unlinkat};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{Entry, Result};

pub(super) fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!(
            "path must be absolute and normalized: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "destination must be a normalized relative path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn error(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

fn directory_child(parent: &File, name: &Path) -> std::result::Result<File, Errno> {
    openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn owned_directory(file: &File) -> Result<Metadata> {
    let info = file
        .metadata()
        .map_err(|cause| error("inspect directory", cause))?;
    if !info.is_dir() || info.uid() != Uid::effective().as_raw() || info.mode() & 0o022 != 0 {
        return Err("directory must be caller-owned and not writable by another account".into());
    }
    Ok(info)
}

pub(super) fn directory(path: &Path) -> Result<File> {
    absolute(path)?;
    let mut current = File::open("/").map_err(|cause| error("open filesystem root", cause))?;
    for part in path.components() {
        if let Component::Normal(name) = part {
            current = directory_child(&current, Path::new(name))
                .map_err(|cause| error(&format!("open directory {}", path.display()), cause))?;
        }
    }
    owned_directory(&current)?;
    Ok(current)
}

pub(super) fn optional_parent(root: &File, path: &Path) -> Result<Option<File>> {
    relative(path)?;
    let parent = path.parent().ok_or("destination parent missing")?;
    let mut current = root
        .try_clone()
        .map_err(|cause| error("clone prefix descriptor", cause))?;
    for part in parent.components() {
        if let Component::Normal(name) = part {
            current = match directory_child(&current, Path::new(name)) {
                Ok(file) => file,
                Err(Errno::ENOENT) => return Ok(None),
                Err(cause) => return Err(error("open destination parent", cause)),
            };
            owned_directory(&current)?;
        }
    }
    Ok(Some(current))
}

pub(super) fn optional_file(parent: &File, name: &Path) -> Result<Option<File>> {
    match openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(Errno::ENOENT) => Ok(None),
        Err(cause) => Err(error(&format!("open file {}", name.display()), cause)),
    }
}

fn owned_file(file: &File) -> Result<Metadata> {
    let info = file
        .metadata()
        .map_err(|cause| error("inspect file", cause))?;
    if !info.is_file()
        || info.uid() != Uid::effective().as_raw()
        || info.nlink() != 1
        || info.mode() & 0o7022 != 0
    {
        return Err("file must be regular, caller-owned, exclusively linked and not writable by another account".into());
    }
    Ok(info)
}

fn stable(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(super) fn digest(bytes: &[u8]) -> String {
    crate::hex_digest(bytes)
}

fn encode_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn file_digest(file: &File) -> Result<String> {
    let before = owned_file(file)?;
    let mut reader = file
        .try_clone()
        .map_err(|cause| error("clone file descriptor", cause))?;
    reader
        .rewind()
        .map_err(|cause| error("rewind file", cause))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 65_536].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|cause| error("read file", cause))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if !stable(&before, &owned_file(file)?) {
        return Err("file changed while its reviewed digest was checked".into());
    }
    Ok(encode_digest(&hash.finalize()))
}

pub(super) fn read_file(path: &Path) -> Result<File> {
    absolute(path)?;
    let parent = directory(path.parent().ok_or("inventory parent missing")?)?;
    let file = optional_file(
        &parent,
        Path::new(path.file_name().ok_or("inventory filename missing")?),
    )?
    .ok_or_else(|| format!("inventory absent: {}", path.display()))?;
    owned_file(&file)?;
    Ok(file)
}

pub(super) fn inventory(root: &File, relative_root: &Path) -> Result<Vec<Entry>> {
    let before = owned_directory(root)?;
    let descriptor = dup(root).map_err(|cause| error("duplicate inventory directory", cause))?;
    let mut directory = nix::dir::Dir::from_fd(descriptor)
        .map_err(|cause| error("enumerate staged directory", cause))?;
    let mut entries = directory
        .iter()
        .map(|entry| {
            entry.map(|entry| {
                std::ffi::OsStr::from_bytes(entry.file_name().to_bytes()).to_os_string()
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|cause| error("read staged directory entry", cause))?;
    entries.retain(|name| name != "." && name != "..");
    entries.sort();
    let mut result = Vec::new();
    for name in entries {
        let info = fstatat(root, Path::new(&name), AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|cause| error("inspect staged entry", cause))?;
        let kind = nix::sys::stat::SFlag::from_bits_truncate(info.st_mode);
        let destination = relative_root.join(&name);
        if kind.contains(nix::sys::stat::SFlag::S_IFDIR) {
            let child = directory_child(root, Path::new(&name))
                .map_err(|cause| error("open staged subdirectory", cause))?;
            result.extend(inventory(&child, &destination)?);
        } else if kind.contains(nix::sys::stat::SFlag::S_IFREG) {
            let file = optional_file(root, Path::new(&name))?.ok_or("staged file disappeared")?;
            let sha256 = file_digest(&file)?;
            result.push(Entry {
                destination,
                sha256,
                mode: owned_file(&file)?.mode() & 0o777,
            });
        } else {
            return Err(format!(
                "staged inventory refuses links or special files: {}",
                destination.display()
            ));
        }
    }
    if !stable(&before, &owned_directory(root)?) {
        return Err("staged directory changed during inventory".into());
    }
    Ok(result)
}

pub(super) fn recovery(path: &Path) -> Result<File> {
    absolute(path)?;
    let parent = directory(path.parent().ok_or("recovery parent missing")?)?;
    let leaf = Path::new(path.file_name().ok_or("recovery filename missing")?);
    match mkdirat(&parent, leaf, Mode::S_IRWXU) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(cause) => return Err(error("create recovery directory", cause)),
    }
    let recovery =
        directory_child(&parent, leaf).map_err(|cause| error("open recovery directory", cause))?;
    if owned_directory(&recovery)?.mode() & 0o7777 != 0o700 {
        return Err("recovery directory must have caller-only mode 0700".into());
    }
    parent
        .sync_all()
        .map_err(|cause| error("sync recovery parent", cause))?;
    Ok(recovery)
}

pub(super) fn verify(file: &File, entry: &Entry) -> Result<()> {
    if owned_file(file)?.mode() & 0o777 != entry.mode || file_digest(file)? != entry.sha256 {
        return Err(format!(
            "reviewed digest or mode differs: {}",
            entry.destination.display()
        ));
    }
    Ok(())
}

pub(super) fn move_verified(
    parent: &File,
    leaf: &Path,
    source: &File,
    recovery: &File,
    destination: &Path,
    entry: &Entry,
) -> Result<()> {
    verify(source, entry)?;
    let opened = owned_file(source)?;
    let named = fstatat(parent, leaf, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|cause| error("inspect retirement source name", cause))?;
    if named.st_dev != opened.dev() || named.st_ino != opened.ino() {
        return Err(format!(
            "source identity changed before retirement: {}",
            entry.destination.display()
        ));
    }
    renameat2(
        parent,
        leaf,
        recovery,
        destination,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|cause| error("exclusive retirement move", cause))?;
    let moved =
        optional_file(recovery, destination)?.ok_or("retired file disappeared from recovery")?;
    let observed = owned_file(&moved)?;
    if observed.dev() != opened.dev() || observed.ino() != opened.ino() {
        return Err("moved recovery entry differs from the verified source identity".into());
    }
    verify(&moved, entry)?;
    moved
        .sync_all()
        .map_err(|cause| error("sync retired bytes", cause))?;
    recovery
        .sync_all()
        .map_err(|cause| error("sync recovery directory", cause))?;
    parent
        .sync_all()
        .map_err(|cause| error("sync retired source parent", cause))?;
    Ok(())
}

pub(super) fn publish(path: &Path, value: &impl Serialize) -> Result<()> {
    absolute(path)?;
    let parent = directory(path.parent().ok_or("report parent missing")?)?;
    let leaf = Path::new(path.file_name().ok_or("report filename missing")?);
    publish_at(&parent, leaf, value)
}

fn publish_at(parent: &File, leaf: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(existing) = optional_file(parent, leaf)? {
        owned_file(&existing)?;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|cause| error("report timestamp", cause))?
        .as_nanos();
    let temporary = format!(".retirement-report-{}-{stamp}", std::process::id());
    let descriptor = openat(
        parent,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|cause| error("stage report", cause))?;
    let mut staged = File::from(descriptor);
    let result = (|| {
        serde_json::to_writer_pretty(&mut staged, value)
            .map_err(|cause| error("serialize report", cause))?;
        staged
            .write_all(b"\n")
            .map_err(|cause| error("finish report", cause))?;
        staged
            .sync_all()
            .map_err(|cause| error("sync report", cause))?;
        renameat2(
            parent,
            temporary.as_str(),
            parent,
            leaf,
            RenameFlags::empty(),
        )
        .map_err(|cause| error("publish report", cause))
    })();
    if result.is_err() {
        let _cleanup = unlinkat(parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result?;
    parent
        .sync_all()
        .map_err(|cause| error("sync report parent", cause))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// # Panics
    /// Panics only if fixture setup fails or enumeration follows a replacement path.
    /// ´test:unit:inventory-enumerates-the-held-directory-after-rename´
    #[test]
    fn inventory_enumerates_the_held_directory_after_rename() {
        let temp = tempfile::tempdir().expect("fixture");
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&original).expect("directory");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        std::fs::write(original.join("owned"), b"held bytes").expect("file");
        std::fs::set_permissions(
            original.join("owned"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("private file");
        let held = directory(&original).expect("held directory");
        std::fs::rename(&original, &moved).expect("rename");
        std::fs::create_dir(&original).expect("replacement");
        std::fs::write(original.join("replacement"), b"other bytes").expect("replacement file");
        let rows = inventory(&held, Path::new("")).expect("inventory");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].destination, Path::new("owned"));
        assert_eq!(rows[0].sha256, digest(b"held bytes"));
    }

    /// # Panics
    /// Panics only if fixture setup fails or report publication follows a replacement path.
    /// ´test:unit:retirement-report-publishes-beneath-the-held-parent´
    #[test]
    fn retirement_report_publishes_beneath_the_held_parent() {
        let temp = tempfile::tempdir().expect("fixture");
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&original).expect("directory");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let held = directory(&original).expect("held directory");
        std::fs::rename(&original, &moved).expect("rename");
        std::fs::create_dir(&original).expect("replacement");
        std::fs::write(original.join("report.json"), b"replacement").expect("replacement report");
        publish_at(
            &held,
            Path::new("report.json"),
            &serde_json::json!({"changes":[]}),
        )
        .expect("publish");
        assert_eq!(
            std::fs::read(original.join("report.json")).expect("replacement"),
            b"replacement"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(moved.join("report.json")).expect("held report"))
                .expect("JSON");
        assert_eq!(report["changes"], serde_json::json!([]));
    }
}
