//! Read policy through held custody descriptors without opening owner-private state.

use super::*;
use execute_command::snapshot::PolicySnapshot;
use nix::fcntl::{OpenHow, ResolveFlag, openat2};
use nix::sys::stat::fstat;
use std::os::fd::OwnedFd;

fn custody(detail: impl std::fmt::Display) -> Error {
    Error::named("execute-command-snapshot-custody", &detail.to_string())
}

fn beneath(parent: &OwnedFd, name: &Path, flags: OFlag) -> Result<OwnedFd, Error> {
    openat2(parent, name, OpenHow::new().flags(flags | OFlag::O_CLOEXEC).resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS))
        .map_err(|error| if error == nix::errno::Errno::ENOENT {
            Error::named("execute-command-snapshot-absent", "run superloop-lane requests publish-snapshot LOOP under the owner after loop-home ensure")
        } else { custody(error) })
}

fn validate_file(file: &File, owner: u32, uid: u32) -> Result<(), Error> {
    let metadata = file.metadata().map_err(custody)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.gid() != uid
        || metadata.mode() & 0o7777 != 0o640
    {
        return Err(custody(
            "snapshot must be an owner-owned loop-group regular file at mode 0640",
        ));
    }
    Ok(())
}

fn entered_root(loop_name: &str) -> Result<PathBuf, Error> {
    loop_home::validate_name(loop_name).map_err(custody)?;
    // HOME locates the entered tier; only held custody and the snapshot authenticate it.
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| custody("entered home is absent"))?;
    if !home.ends_with("private") {
        return Err(custody("enter LOOP before using command"));
    }
    let root = home
        .parent()
        .ok_or_else(|| custody("entered home parent absent"))?;
    if root.file_name().is_none_or(|name| name != loop_name)
        || root
            .parent()
            .is_none_or(|path| !path.ends_with(".var/loops"))
    {
        return Err(custody("entered home does not name the standard loop root"));
    }
    Ok(root.to_path_buf())
}

fn pin_root(root: &Path, loop_name: &str) -> Result<(OwnedFd, u32), Error> {
    let anchor = root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| custody("class root is absent"))?;
    let flags = OFlag::O_PATH | OFlag::O_DIRECTORY;
    let anchor_fd = open(anchor, flags | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW, Mode::empty())
        .map_err(|error| if error == nix::errno::Errno::ENOENT {
            Error::named("execute-command-snapshot-absent", "run superloop-lane requests publish-snapshot LOOP under the owner after loop-home ensure")
        } else { custody(error) })?;
    let observed = fstat(&anchor_fd).map_err(custody)?;
    let owner = observed.st_uid;
    let uid = nix::unistd::geteuid().as_raw();
    if owner == uid || observed.st_mode & 0o7777 != 0o711 {
        return Err(custody(
            "class root must be independent owner custody at mode 0711",
        ));
    }
    let (root_fd, _) = loop_home::custody::walk_directories(
        anchor_fd,
        observed,
        anchor,
        &Path::new("loops").join(loop_name),
        flags,
        |parent, next, _| {
            if parent.st_uid != owner
                || next.st_uid != owner
                || parent.st_mode & 0o022 != 0
                || next.st_mode & 0o022 != 0
            {
                Err(custody("replaceable policy ancestor"))
            } else {
                Ok(())
            }
        },
        |_, error| custody(error),
    )?;
    Ok((root_fd, owner))
}

pub(super) fn read(loop_name: &str) -> Result<(Authority, PolicySnapshot, File), Error> {
    let root = entered_root(loop_name)?;
    let (root_fd, owner) = pin_root(&root, loop_name)?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let policy = beneath(
        &root_fd,
        Path::new("policy"),
        OFlag::O_PATH | OFlag::O_DIRECTORY,
    )?;
    let metadata = fstat(&policy).map_err(custody)?;
    if metadata.st_uid != owner || metadata.st_gid != gid || metadata.st_mode & 0o7777 != 0o2750 {
        return Err(custody(
            "policy tier must be owner-owned, loop-group, mode 02750",
        ));
    }
    let file = File::from(beneath(
        &policy,
        Path::new("snapshot.json"),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
    )?);
    validate_file(&file, owner, gid)?;
    let mut bytes = Vec::new();
    file.take(8 * 1_048_576 + 1)
        .read_to_end(&mut bytes)
        .map_err(custody)?;
    if bytes.len() > 8 * 1_048_576 {
        return Err(custody("snapshot exceeds bound"));
    }
    let snapshot = PolicySnapshot::decode(&bytes)
        .map_err(|error| Error::named(error.0, "republish the current policy snapshot"))?;
    if snapshot.loop_uid != uid
        || snapshot.loop_name != loop_name
        || snapshot.registry.value["root"].as_str() != root.to_str()
    {
        return Err(Error::named(
            "execute-command-snapshot-identity",
            "snapshot identity differs from the authenticated loop uid",
        ));
    }
    let journal = beneath(
        &root_fd,
        Path::new("direct"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY,
    )?;
    let metadata = fstat(&journal).map_err(custody)?;
    if metadata.st_uid != uid || metadata.st_gid != gid || metadata.st_mode & 0o7777 != 0o700 {
        return Err(custody(
            "run loop-home ensure for the loop-owned direct tier at mode 0700",
        ));
    }
    for name in ["shared", "private"] {
        let tier = beneath(
            &root_fd,
            Path::new(name),
            OFlag::O_PATH | OFlag::O_DIRECTORY,
        )?;
        let stat = fstat(&tier).map_err(custody)?;
        if stat.st_uid != uid
            || stat.st_gid != gid
            || stat.st_mode & 0o022 != 0
            || name == "private" && stat.st_mode & 0o7777 != 0o700
        {
            return Err(custody(
                "shared and private must agree with the loop-owned direct tier",
            ));
        }
    }
    let authority = Authority {
        schema: 1,
        loop_name: loop_name.into(),
        root: root.join("direct"),
        device: metadata.st_dev,
        inode: metadata.st_ino,
        principal: format!("loop:{loop_name}:uid:{uid}"),
        registration: digest(&json!({"loop":loop_name,"uid":uid,"owner":owner,"root":root}))?,
        snapshot_digest: execute_command::rubric::sha256_digest(&bytes),
        role: "orchestrator".into(),
        cwd: std::env::current_dir()
            .map_err(Error::storage)?
            .to_string_lossy()
            .into_owned(),
        scope: Some("estate".into()),
    };
    Ok((authority, snapshot, File::from(journal)))
}
