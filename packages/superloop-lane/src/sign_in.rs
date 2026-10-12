//! Metadata-only repair of the worker's shared Codex sign-in tree.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
#[cfg(test)]
use std::process::Command;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::AtFlags;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{fstat, fstatat};
use nix::unistd::{Gid, Uid, fchownat};
use serde_json::{Value, json};

use crate::error::LaneError;

#[cfg(test)]
thread_local! {
    static SYNC_OPEN_FLAGS: std::cell::RefCell<Vec<i32>> = const { std::cell::RefCell::new(Vec::new()) };
}

const fn mode_for(directory: bool) -> u32 {
    if directory { 0o700 } else { 0o600 }
}

fn loop_host_gid(loop_gid: u32) -> Result<u32, LaneError> {
    #[cfg(debug_assertions)]
    if let Ok(source) = std::env::var("SUPERLOOP_SIGNIN_TEST_GID_MAP") {
        return mapped_gid(&source, loop_gid);
    }
    let program = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(program, Uid::effective().as_raw())
        .map_err(|error| LaneError::input("sign-in-group-map", error.line()))?;
    let output = std::process::Command::new("/usr/bin/timeout")
        .args(["--kill-after=1", "5"])
        .arg(program)
        .args(["unshare", "/usr/bin/cat", "/proc/self/gid_map"])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| LaneError::input("sign-in-group-map", error.to_string()))?;
    if !output.status.success() || output.stdout.len() > 65_536 {
        return Err(LaneError::input(
            "sign-in-group-map",
            "rootless GID map could not be measured",
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| LaneError::input("sign-in-group-map", "rootless GID map is not UTF-8"))?;
    mapped_gid(source, loop_gid)
}

fn mapped_gid(source: &str, loop_gid: u32) -> Result<u32, LaneError> {
    let invalid = || {
        LaneError::input(
            "sign-in-group-map",
            "rootless GID map is invalid or does not map the loop group",
        )
    };
    let mut found = None;
    for line in source.lines() {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        let [inside, outside, count] = fields.as_slice() else {
            return Err(invalid());
        };
        if *count == 0
            || u64::from(*inside) + u64::from(*count) > 1_u64 << 32
            || u64::from(*outside) + u64::from(*count) > 1_u64 << 32
        {
            return Err(invalid());
        }
        if let Some(offset) = loop_gid
            .checked_sub(*inside)
            .filter(|offset| offset < count)
        {
            if found.is_some() {
                return Err(invalid());
            }
            found = Some(outside.checked_add(offset).ok_or_else(invalid)?);
        }
    }
    found.ok_or_else(invalid)
}

fn prepare_generation(
    owner_home: &Path,
    loop_name: &str,
    uid: u32,
) -> Result<Option<Value>, LaneError> {
    let config = owner_home.join(".config/loops");
    let parent = crate::pinned::open_protected(owner_home, &config, uid)?;
    let stat = fstat(&parent)
        .map_err(|error| LaneError::input("install-generation", error.to_string()))?;
    if stat.st_uid != uid
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o022 != 0
    {
        return Err(LaneError::input(
            "install-generation",
            "loop configuration parent is unsafe",
        ));
    }
    // A fresh-loop preview has no loop directory yet. Measure that absence
    // below the protected parent without following even a dangling link.
    match fstatat(&parent, loop_name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(LaneError::input("install-generation", error.to_string())),
        Ok(_) => {}
    }
    let path = config.join(loop_name).join("install-generation.json");
    crate::pinned::read_private_optional(owner_home, &path, uid, 0o600, 65_536)?
        .map(|bytes| crate::install::validate_generation(&path, &bytes))
        .transpose()
}

/// Tighten modes and report group custody without changing a host-side group.
pub(crate) fn prepare_metadata(
    owner_home: &Path,
    loop_name: &str,
    gid: u32,
    dry_run: bool,
) -> Value {
    let uid = Uid::effective().as_raw();
    let root = crate::credential::sign_in_dir(owner_home, loop_name);
    let host_gid = prepare_generation(owner_home, loop_name, uid)
        .map_err(|error| LaneError::input("install-generation", error.detail))
        .and_then(|record| record.map(|_| loop_host_gid(gid)).transpose());
    let group_repair = match &host_gid {
        Ok(None) => None,
        _ => Some("install private convergence"),
    };
    let mut entries = Vec::new();
    let mut changed = 0_u64;
    for (path, directory) in [(root.clone(), true), (root.join("auth.json"), false)] {
        let result = prepare_entry(owner_home, &path, uid, &host_gid, directory, dry_run);
        match result {
            Ok((entry, count)) => {
                entries.push(entry);
                changed += count;
            }
            Err(error) => {
                entries.push(json!({"path":path,"finding":error.kind,"detail":error.detail}));
            }
        }
    }
    json!({"entries":entries,"changed":changed,"group_view":"host","wanted_namespace_gid":gid,"group_repair":group_repair})
}

#[allow(unsafe_code)]
fn prepare_entry(
    owner_home: &Path,
    path: &Path,
    uid: u32,
    gid: &Result<Option<u32>, LaneError>,
    directory: bool,
    dry_run: bool,
) -> Result<(Value, u64), LaneError> {
    let fd = crate::pinned::open_protected(owner_home, path, uid)?;
    let before = nix::sys::stat::fstat(&fd)
        .map_err(|error| LaneError::operation("sign-in-metadata", error.to_string()))?;
    let expected_type = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if before.st_uid != uid
        || before.st_mode & libc::S_IFMT != expected_type
        || (!directory && before.st_nlink != 1)
    {
        return Err(LaneError::input(
            "sign-in-owner-type",
            path.display().to_string(),
        ));
    }
    let mode = mode_for(directory);
    let group_required = directory && !matches!(gid, Ok(None));
    let mut findings = Vec::new();
    match gid {
        _ if !directory => {}
        Ok(Some(expected)) if before.st_gid != *expected => findings.push(json!({"name":"sign-in-group","observed_host_gid":before.st_gid,"wanted_host_gid":expected,"remedy":"run install to converge the loop group inside the rootless namespace"})),
        Err(error) => findings.push(json!({"name":error.kind,"detail":error.detail})),
        Ok(_) => {}
    }
    if !dry_run && before.st_mode & 0o7777 != mode {
        // SAFETY: fchmodat2 changes only the inode pinned by this no-follow descriptor.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fchmodat2,
                fd.as_raw_fd(),
                c"".as_ptr(),
                mode as libc::mode_t,
                libc::AT_EMPTY_PATH,
            )
        };
        if result == -1 {
            findings.push(
                json!({"name":"sign-in-mode","detail":io::Error::last_os_error().to_string()}),
            );
        }
    }
    let after = nix::sys::stat::fstat(&fd)
        .map_err(|error| LaneError::operation("sign-in-metadata", error.to_string()))?;
    let changed = u64::from(before.st_mode != after.st_mode);
    let wanted_gid = directory
        .then(|| gid.as_ref().ok().copied().flatten())
        .flatten();
    let group_complete =
        !group_required || wanted_gid.is_some_and(|expected| after.st_gid == expected);
    let mut entry = json!({"path":path,"gid":after.st_gid,"group_required":group_required,"mode":format!("{:04o}", after.st_mode & 0o7777),"wanted_gid":wanted_gid,"wanted_mode":format!("{mode:04o}"),"complete":group_complete && after.st_mode & 0o7777 == mode,"would_change":dry_run && before.st_mode & 0o7777 != mode,"findings":findings});
    if !group_required {
        entry["group_reason"] = json!(if directory {
            "no installed box: install-generation.json is absent; owner-only mode grants no group access"
        } else {
            "file replacements retain the writer's group; owner-only mode grants no group access"
        });
    }
    Ok((entry, changed))
}

fn probe_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(".worker-mode-probe-") else {
        return false;
    };
    let Some((pid, nonce)) = suffix.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !nonce.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.bytes().all(|byte| byte.is_ascii_digit())
}

fn sync_directory(fd: &OwnedFd, path: &Path) -> Result<(), LaneError> {
    #[cfg(test)]
    SYNC_OPEN_FLAGS.with(|flags| {
        flags
            .borrow_mut()
            .push((OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC).bits());
    });
    let directory = openat2(
        fd,
        ".",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })?;
    File::from(directory).sync_all().map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })
}

fn sync_file(fd: &OwnedFd, parent: &OwnedFd, path: &Path) -> Result<(), LaneError> {
    let name = path
        .file_name()
        .ok_or_else(|| LaneError::operation("sign-in-sync", "file has no name"))?;
    let flags = OFlag::O_WRONLY | OFlag::O_NOCTTY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    #[cfg(test)]
    SYNC_OPEN_FLAGS.with(|opens| opens.borrow_mut().push(flags.bits()));
    let writable = openat2(
        parent,
        Path::new(name),
        OpenHow::new()
            .flags(flags)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })?;
    let held = fstat(fd).map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })?;
    let reopened = fstat(&writable).map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })?;
    if held.st_dev != reopened.st_dev || held.st_ino != reopened.st_ino {
        return Err(LaneError::operation(
            "sign-in-sync",
            format!("{} changed while reopening", path.display()),
        ));
    }
    File::from(writable).sync_all().map_err(|error| {
        LaneError::operation("sign-in-sync", format!("{}: {error}", path.display()))
    })
}

#[allow(unsafe_code)]
fn unlink_at(parent: &OwnedFd, name: &OsStr) -> io::Result<()> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "probe name contains NUL"))?;
    // SAFETY: the name is a single component beneath the held sign-in directory.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unlink_name(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<(), LaneError> {
    unlink_at(parent, name).map_err(|error| {
        LaneError::operation(
            "sign-in-probe-cleanup",
            format!("{}: {error}", path.display()),
        )
    })
}

#[cfg(test)]
struct ProbeGuard<'a> {
    root: &'a OwnedFd,
    root_path: &'a Path,
    name: String,
    armed: bool,
}

#[cfg(test)]
impl ProbeGuard<'_> {
    fn finish(&mut self) -> Result<(), LaneError> {
        match unlink_at(self.root, OsStr::new(&self.name)) {
            Ok(()) => {
                self.armed = false;
                sync_directory(self.root, self.root_path)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(error) => Err(LaneError::operation(
                "sign-in-probe-cleanup",
                format!("{}: {error}", self.root_path.join(&self.name).display()),
            )),
        }
    }
}

#[cfg(test)]
impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            drop(unlink_at(self.root, OsStr::new(&self.name)));
        }
    }
}

fn opened(parent: &OwnedFd, name: &Path) -> Result<OwnedFd, LaneError> {
    openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| LaneError::input("sign-in-path", format!("{}: {error}", name.display())))
}

#[allow(unsafe_code)]
fn set_opened(fd: &OwnedFd, path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), LaneError> {
    fchownat(
        fd,
        "",
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        AtFlags::AT_EMPTY_PATH,
    )
    .map_err(|error| {
        LaneError::operation("sign-in-owner", format!("{}: {error}", path.display()))
    })?;
    // SAFETY: fchmodat2 changes the inode held by this no-follow descriptor.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fchmodat2,
            fd.as_raw_fd(),
            c"".as_ptr(),
            mode as libc::mode_t,
            libc::AT_EMPTY_PATH,
        )
    };
    if result == -1 {
        return Err(LaneError::operation(
            "sign-in-mode",
            format!("{}: {}", path.display(), std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn visit(
    fd: &OwnedFd,
    path: &Path,
    root: &Path,
    parent: &OwnedFd,
    uid: u32,
    gid: u32,
    dry_run: bool,
    changes: &mut Vec<Value>,
) -> Result<(), LaneError> {
    let stat = fstat(fd).map_err(|error| {
        LaneError::input("sign-in-path", format!("{}: {error}", path.display()))
    })?;
    let directory = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let regular = (stat.st_mode & libc::S_IFMT) == libc::S_IFREG;
    let dispatch_scratch = path
        .strip_prefix(root)
        .is_ok_and(|path| path == Path::new("tmp/arg0"));
    if dispatch_scratch && !directory {
        return Err(LaneError::input(
            "sign-in-path",
            format!("{} is not a dispatch scratch directory", path.display()),
        ));
    }
    if !directory && !regular {
        return Err(LaneError::input(
            "sign-in-path",
            format!(
                "{} is neither a directory nor a regular file",
                path.display()
            ),
        ));
    }
    // The CLI owns dispatch locks and executable links inside this directory.
    // Its ancestors and its own inode still receive the ordinary custody checks.
    if directory && !dispatch_scratch {
        let entries =
            fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|error| {
                LaneError::input("sign-in-path", format!("{}: {error}", path.display()))
            })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                LaneError::input("sign-in-path", format!("{}: {error}", path.display()))
            })?;
            let name = entry.file_name();
            let child = opened(fd, Path::new(&name))?;
            let child_path = path.join(&name);
            if path == root && probe_name(&name) {
                let child_stat = fstat(&child).map_err(|error| {
                    LaneError::input(
                        "sign-in-probe",
                        format!("{}: {error}", child_path.display()),
                    )
                })?;
                if (child_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
                    return Err(LaneError::input(
                        "sign-in-probe",
                        format!("{} is not a regular stale probe", child_path.display()),
                    ));
                }
                changes.push(json!({"path":child_path,"action":"remove-stale-probe","from":{"uid":child_stat.st_uid,"gid":child_stat.st_gid,"mode":format!("{:04o}", child_stat.st_mode & 0o7777)},"to":null}));
                if !dry_run {
                    unlink_name(fd, &name, &child_path)?;
                    sync_directory(fd, path)?;
                }
                continue;
            }
            visit(&child, &child_path, root, fd, uid, gid, dry_run, changes)?;
        }
    }
    let mode = mode_for(directory);
    // Only the canonical root has a required group; replaced files retain the
    // writer's group, which grants no access through their owner-only modes.
    let gid = if path == root { gid } else { stat.st_gid };
    if stat.st_uid != uid || stat.st_gid != gid || stat.st_mode & 0o7777 != mode {
        changes.push(json!({"path":path,"action":"repair","from":{"uid":stat.st_uid,"gid":stat.st_gid,"mode":format!("{:04o}",stat.st_mode & 0o7777)},"to":{"uid":uid,"gid":gid,"mode":format!("{mode:04o}")}}));
        if !dry_run {
            set_opened(fd, path, uid, gid, mode)?;
            if directory {
                sync_directory(fd, path)?;
            } else {
                sync_file(fd, parent, path)?;
            }
            let parent_path = path.parent().ok_or_else(|| {
                LaneError::operation("sign-in-sync", "repaired path has no parent")
            })?;
            sync_directory(parent, parent_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)]
fn probe(root: &OwnedFd, path: &Path, worker_uid: u32, loop_gid: u32) -> Result<(), LaneError> {
    probe_with_script(
        root,
        path,
        worker_uid,
        loop_gid,
        "umask 007; set -C; : > \"/proc/self/fd/3/$1\"",
    )
}

#[cfg(test)]
#[allow(unsafe_code)]
fn probe_with_script(
    root: &OwnedFd,
    path: &Path,
    worker_uid: u32,
    loop_gid: u32,
    script: &str,
) -> Result<(), LaneError> {
    use std::os::unix::process::CommandExt as _;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| LaneError::operation("sign-in-probe", error.to_string()))?
        .as_nanos();
    let name = format!(".worker-mode-probe-{}-{nonce}", std::process::id());
    let target = path.join(&name);
    let mut guard = ProbeGuard {
        root,
        root_path: path,
        name: name.clone(),
        armed: true,
    };
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .arg("--")
        .arg(&name)
        .uid(worker_uid)
        .gid(loop_gid);
    let held = root.as_raw_fd();
    // SAFETY: only the already verified directory descriptor is duplicated into the child.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(held, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = (|| {
        let status = command.status().map_err(|error| {
            LaneError::operation("sign-in-probe", format!("{}: {error}", target.display()))
        })?;
        if !status.success() {
            return Err(LaneError::operation(
                "sign-in-probe",
                format!("worker could not create {}: {status}", target.display()),
            ));
        }
        let child = opened(root, Path::new(&name))?;
        let stat = fstat(&child).map_err(|error| {
            LaneError::operation("sign-in-probe", format!("{}: {error}", target.display()))
        })?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || stat.st_uid != worker_uid
            || stat.st_gid != loop_gid
            || stat.st_mode & 0o7777 != 0o660
        {
            return Err(LaneError::operation(
                "sign-in-probe",
                format!("{} was not worker-owned at mode 0660", target.display()),
            ));
        }
        Ok(())
    })();
    let cleanup = guard.finish();
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(LaneError::operation(
            "sign-in-probe-cleanup",
            format!("{}; {}", error.detail, cleanup.detail),
        )),
    }
}

/// Converge names and metadata only; never open a sign-in file for reading.
/// Dispatch scratch contents beneath the validated `tmp/arg0` directory are not visited.
///
/// # Errors
///
/// Refuses links or special files outside dispatch scratch, a non-directory scratch
/// root, or failed metadata operations.
pub fn converge(
    owner_home: &Path,
    loop_name: &str,
    uid: u32,
    gid: u32,
    _worker_uid: u32,
    dry_run: bool,
) -> Result<Value, LaneError> {
    let path = owner_home
        .join(".config/loops")
        .join(loop_name)
        .join("lanes/codex");
    let mut changes = Vec::new();
    let root = match crate::pinned::open_protected(owner_home, &path, uid) {
        Ok(fd) => fd,
        Err(error) if error.detail.contains("ENOENT") && dry_run => {
            changes.push(json!({"path":path,"action":"create-directory","from":null,"to":{"uid":uid,"gid":gid,"mode":"0700"}}));
            return Ok(
                json!({"changes":changes,"was_complete":false,"complete":false,"worker_probe":"not_applicable"}),
            );
        }
        Err(error) => return Err(error),
    };
    let parent = path
        .parent()
        .ok_or_else(|| LaneError::operation("sign-in-sync", "sign-in root has no parent"))?;
    let parent_fd = crate::pinned::open_protected(owner_home, parent, uid)?;
    visit(
        &root,
        &path,
        &path,
        &parent_fd,
        uid,
        gid,
        dry_run,
        &mut changes,
    )?;
    let was_complete = changes.is_empty();
    Ok(
        json!({"changes":changes,"was_complete":was_complete,"complete":!dry_run || was_complete,"worker_probe":"not_applicable"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// ´test:unit:sign-in-converges-owner-only-files-and-worker-leftovers´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn sign_in_converges_owner_only_files_and_worker_leftovers() {
        let temp = tempfile::tempdir().expect("fixture");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let path = temp.path().join(".config/loops/alpha/lanes/codex");
        fs::create_dir_all(path.join("state")).expect("directory");
        for ancestor in [
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
        ] {
            fs::set_permissions(
                temp.path().join(ancestor),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private ancestor");
        }
        fs::write(path.join("auth.json"), b"").expect("owner-only file");
        fs::write(path.join("unreadable.db"), b"").expect("unreadable fixture");
        fs::set_permissions(
            path.join("unreadable.db"),
            fs::Permissions::from_mode(0o000),
        )
        .expect("unreadable mode");
        fs::write(path.join("state/foreign.sqlite-wal"), b"").expect("worker leftover");
        fs::write(path.join("state/config.toml"), b"").expect("nested state file");
        fs::set_permissions(path.join("auth.json"), fs::Permissions::from_mode(0o644))
            .expect("mode");
        fs::set_permissions(path.join("state"), fs::Permissions::from_mode(0o755)).expect("mode");
        let preview = converge(temp.path(), "alpha", owner, group, owner, true).expect("preview");
        assert_eq!(preview["complete"], false);
        assert!(
            preview["changes"]
                .as_array()
                .expect("changes")
                .iter()
                .any(
                    |row| row["path"] == path.join("auth.json").display().to_string()
                        && row["from"]["mode"] == "0644"
                        && row["to"]["mode"] == "0600"
                )
        );
        assert_eq!(
            fs::symlink_metadata(path.join("auth.json"))
                .expect("metadata")
                .mode()
                & 0o7777,
            0o644
        );
        SYNC_OPEN_FLAGS.with(|flags| flags.borrow_mut().clear());
        let first = converge(temp.path(), "alpha", owner, group, owner, false).expect("converge");
        SYNC_OPEN_FLAGS.with(|flags| {
            let flags = flags.borrow();
            assert!(
                flags
                    .iter()
                    .any(|flags| flags & libc::O_ACCMODE == libc::O_WRONLY),
                "metadata repair synced a file with a write-only handle"
            );
            assert!(
                flags.iter().all(|flags| flags & libc::O_DIRECTORY != 0
                    || flags & libc::O_ACCMODE == libc::O_WRONLY),
                "no sign-in file was opened readably for sync"
            );
            assert!(
                flags
                    .iter()
                    .all(|flags| flags & (libc::O_TRUNC | libc::O_CREAT) == 0),
                "sync opens neither truncate nor create files"
            );
        });
        assert!(first["changes"].as_array().expect("changes").len() >= 3);
        assert_eq!(
            fs::symlink_metadata(path.join("auth.json"))
                .expect("metadata")
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::symlink_metadata(path.join("state"))
                .expect("metadata")
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::symlink_metadata(path.join("state/config.toml"))
                .expect("metadata")
                .mode()
                & 0o7777,
            0o600
        );
        assert!(!path.join("config.toml").exists());
        let second = converge(temp.path(), "alpha", owner, group, owner, false).expect("repeat");
        assert_eq!(second["changes"].as_array().expect("changes").len(), 0);
        assert_eq!(second["worker_probe"], "not_applicable");
    }

    /// ´test:unit:sign-in-worker-probe-checks-created-file-mode´
    #[test]
    fn sign_in_worker_probe_checks_created_file_mode() {
        let temp = tempfile::tempdir().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let path = temp.path().join(".config/loops/alpha/lanes/codex");
        fs::create_dir_all(&path).expect("directory");
        for ancestor in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
        ] {
            fs::set_permissions(
                temp.path().join(ancestor),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private ancestor");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o2770)).expect("mode");
        let root = crate::pinned::open_protected(temp.path(), &path, owner).expect("pinned root");
        fs::set_permissions(
            path.parent().expect("lanes"),
            fs::Permissions::from_mode(0o000),
        )
        .expect("inaccessible absolute ancestor");
        assert!(fs::symlink_metadata(&path).is_err());
        probe(&root, &path, owner, group).expect("worker probe through held directory");
        let failed = probe_with_script(
            &root,
            &path,
            owner,
            group,
            "umask 007; set -C; : > \"/proc/self/fd/3/$1\"; exit 1",
        )
        .expect_err("failed child");
        assert_eq!(failed.kind, "sign-in-probe");
        fs::set_permissions(
            path.parent().expect("lanes"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore ancestor");
        assert!(
            !fs::read_dir(&path)
                .expect("names")
                .any(|entry| probe_name(&entry.expect("entry").file_name()))
        );
    }

    /// ´test:unit:sign-in-retires-a-stale-probe-before-repeating´
    #[test]
    fn sign_in_retires_a_stale_probe_before_repeating() {
        let temp = tempfile::tempdir().expect("fixture");
        let owner = nix::unistd::Uid::effective().as_raw();
        let group = nix::unistd::Gid::effective().as_raw();
        let path = temp.path().join(".config/loops/alpha/lanes/codex");
        fs::create_dir_all(&path).expect("directory");
        for ancestor in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
        ] {
            fs::set_permissions(
                temp.path().join(ancestor),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private ancestor");
        }
        fs::write(path.join(".worker-mode-probe-41001-17"), b"").expect("stale probe");
        let first = converge(temp.path(), "alpha", owner, group, owner, false).expect("converge");
        assert!(
            first["changes"]
                .as_array()
                .expect("changes")
                .iter()
                .any(|row| row["action"] == "remove-stale-probe")
        );
        assert!(!path.join(".worker-mode-probe-41001-17").exists());
        let repeat = converge(temp.path(), "alpha", owner, group, owner, false).expect("repeat");
        assert_eq!(repeat["changes"].as_array().expect("changes").len(), 0);
        assert_eq!(repeat["worker_probe"], "not_applicable");
    }

    /// ´test:unit:sign-in-distinct-worker-uid-uses-pinned-directory´
    #[test]
    #[ignore = "requires namespace root to switch to fixture worker uid 41001"]
    fn sign_in_distinct_worker_uid_uses_pinned_directory() {
        let temp = tempfile::tempdir().expect("fixture");
        let path = temp.path().join(".config/loops/alpha/lanes/codex");
        fs::create_dir_all(&path).expect("directory");
        for ancestor in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
        ] {
            fs::set_permissions(
                temp.path().join(ancestor),
                fs::Permissions::from_mode(0o700),
            )
            .expect("private ancestor");
        }
        let root = crate::pinned::open_protected(temp.path(), &path, 0).expect("pinned root");
        set_opened(&root, &path, 0, 41001, 0o2770).expect("loop group");
        probe(&root, &path, 41001, 41001).expect("different worker uid through held directory");
    }
}
