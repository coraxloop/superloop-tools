//! Seed only declared local bares while their new destination remains loop controlled.

use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
use nix::unistd::{Gid, Uid, UnlinkatFlags, dup, fchown, unlinkat};
use serde_json::{Value, json};

use super::DeclaredSource;
use crate::error::LaneError;
use crate::home;
use crate::plan::Plan;

fn refused(kind: &'static str, name: &str, reason: impl std::fmt::Display) -> LaneError {
    LaneError::input(kind, format!("{name}: {reason}"))
}

fn opened(parent: &OwnedFd, name: &OsStr, path: &Path) -> Result<OwnedFd, LaneError> {
    openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| refused("source-seed-path", &path.display().to_string(), error))
}

fn directory(parent: &OwnedFd, name: &str, path: &Path) -> Result<OwnedFd, LaneError> {
    let fd = opened(parent, OsStr::new(name), path)?;
    let stat = fstat(&fd).map_err(|error| refused("source-seed-path", name, error))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR {
        return Err(refused("source-seed-path", name, "is not a directory"));
    }
    Ok(fd)
}

#[derive(Clone, Copy)]
enum IdentityMode {
    Exact(u32),
    Unwritable,
}

fn identity(fd: &OwnedFd, name: &str, owner: u32, mode: IdentityMode) -> Result<Value, LaneError> {
    let stat = fstat(fd).map_err(|error| refused("source-seed-path", name, error))?;
    let actual_mode = stat.st_mode & 0o7777;
    let mode_matches = match mode {
        IdentityMode::Exact(expected) => actual_mode == expected,
        IdentityMode::Unwritable => actual_mode & 0o022 == 0,
    };
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFDIR
        || stat.st_uid != owner
        || stat.st_gid != owner
        || !mode_matches
    {
        let expected_mode = match mode {
            IdentityMode::Exact(expected) => format!("mode {expected:04o}"),
            IdentityMode::Unwritable => "without group or other write".to_owned(),
        };
        return Err(refused(
            "source-seed-owner",
            name,
            format!(
                "bare uid {} gid {} mode {actual_mode:04o}; expected uid and gid {owner} {expected_mode}",
                stat.st_uid, stat.st_gid
            ),
        ));
    }
    Ok(
        json!({"device":stat.st_dev,"inode":stat.st_ino,"uid":stat.st_uid,"gid":stat.st_gid,"mode":actual_mode}),
    )
}

fn same_identity(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
    held: &OwnedFd,
    expected: &Value,
    owner: u32,
    mode: IdentityMode,
) -> Result<(), LaneError> {
    let current = directory(parent, name, path)?;
    if identity(&current, name, owner, mode)? != *expected
        || identity(held, name, owner, mode)? != *expected
    {
        return Err(refused(
            "source-seed-identity",
            name,
            "pinned bare changed during fetch",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn git_at(bare: &OwnedFd, args: &[&str]) -> Result<std::process::Output, LaneError> {
    let raw = bare.as_raw_fd();
    let mut command = Command::new("/usr/bin/git");
    command
        .args(["-c", "safe.directory=*", "-c", "gc.auto=0", "--git-dir=."])
        .args(args)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
    // SAFETY: the directory descriptor remains held until the child starts.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(raw) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command
        .output()
        .map_err(|error| refused("source-seed-git", "git", error))
}

fn require_commit(bare: &OwnedFd, name: &str, seed: &str) -> Result<(), LaneError> {
    let kind = git_at(bare, &["cat-file", "-t", seed])?;
    if !kind.status.success() {
        return Err(refused(
            "source-seed-object",
            name,
            format!("{seed} is absent"),
        ));
    }
    if kind.stdout != b"commit\n" {
        return Err(refused(
            "source-seed-type",
            name,
            format!("{seed} is not a commit"),
        ));
    }
    Ok(())
}

// The session owner controls the loop root; only src beneath it is loop-owned.
fn check_loop_root(
    stat: &nix::sys::stat::FileStat,
    name: &str,
    namespace_uid: u32,
) -> Result<(), LaneError> {
    if stat.st_uid != namespace_uid || stat.st_mode & 0o022 != 0 {
        return Err(refused(
            "source-seed-owner",
            name,
            "loop root owner or mode differs",
        ));
    }
    Ok(())
}

fn source_bare(
    owner_home: &Path,
    loop_name: &str,
    name: &str,
    loop_uid: u32,
    namespace_uid: u32,
) -> Result<(OwnedFd, OwnedFd, PathBuf, Value), LaneError> {
    let loops = owner_home.join(".var/loops");
    let owner_loops = home::pin_parent(&loops, namespace_uid)
        .map_err(|error| refused("source-seed-path", name, error.detail))?;
    let loop_path = loops.join(loop_name);
    let loop_fd = directory(&owner_loops, loop_name, &loop_path)?;
    let loop_stat = fstat(&loop_fd).map_err(|error| refused("source-seed-path", name, error))?;
    check_loop_root(&loop_stat, name, namespace_uid)?;
    let src_path = loop_path.join("src");
    let src = directory(&loop_fd, "src", &src_path)?;
    let src_stat = fstat(&src).map_err(|error| refused("source-seed-path", name, error))?;
    if src_stat.st_uid != loop_uid || src_stat.st_mode & 0o7777 != 0o700 {
        return Err(refused(
            "source-seed-owner",
            name,
            "source directory owner or mode differs",
        ));
    }
    let bare_name = format!("{name}.git");
    let path = src_path.join(&bare_name);
    let bare = directory(&src, &bare_name, &path)?;
    let recorded = identity(&bare, name, loop_uid, IdentityMode::Unwritable)?;
    for forbidden in [
        "commondir",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        match openat2(
            &bare,
            forbidden,
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Err(Errno::ENOENT) => {}
            Ok(_) => {
                return Err(refused(
                    "source-seed-path",
                    name,
                    format!("{forbidden} is forbidden"),
                ));
            }
            Err(error) => return Err(refused("source-seed-path", name, error)),
        }
    }
    let config = opened(&bare, OsStr::new("config"), &path.join("config"))?;
    let config_stat = fstat(&config).map_err(|error| refused("source-seed-path", name, error))?;
    if SFlag::from_bits_truncate(config_stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || config_stat.st_size > 65_536
    {
        return Err(refused(
            "source-seed-path",
            name,
            "config is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    File::from(config)
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| refused("source-seed-path", name, error))?;
    if bytes.len() > 65_536 {
        return Err(refused("source-seed-path", name, "config exceeds bound"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refused("source-seed-path", name, "config is not UTF-8"))?;
    for line in text.lines() {
        let section = line.trim().to_ascii_lowercase();
        let section = section
            .strip_prefix('[')
            .map(str::trim_start)
            .unwrap_or_default();
        if section.starts_with("remote")
            || section.starts_with("include")
            || section.starts_with("url")
        {
            return Err(refused(
                "source-seed-path",
                name,
                "source config names a remote or include",
            ));
        }
    }
    Ok((src, bare, path, recorded))
}

fn names(fd: &OwnedFd, path: &Path) -> Result<Vec<String>, LaneError> {
    let duplicate =
        dup(fd).map_err(|error| refused("source-seed-path", &path.display().to_string(), error))?;
    #[allow(unsafe_code)]
    unsafe {
        let raw = duplicate.into_raw_fd();
        let stream = libc::fdopendir(raw);
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            libc::close(raw);
            return Err(refused(
                "source-seed-path",
                &path.display().to_string(),
                error,
            ));
        }
        let mut result = Vec::new();
        loop {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(stream);
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                libc::closedir(stream);
                if error.raw_os_error() != Some(0) {
                    return Err(refused(
                        "source-seed-path",
                        &path.display().to_string(),
                        error,
                    ));
                }
                break;
            }
            let bytes = CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = std::str::from_utf8(bytes).map_err(|_| {
                refused(
                    "source-seed-path",
                    &path.display().to_string(),
                    "non-UTF-8 entry",
                )
            })?;
            if result.len() >= 4096 {
                libc::closedir(stream);
                return Err(refused(
                    "source-seed-size",
                    &path.display().to_string(),
                    "entry count exceeds checkpoint bound",
                ));
            }
            result.push(name.to_owned());
        }
        Ok(result)
    }
}

fn remove_tree(parent: &OwnedFd, name: &str, path: &Path, depth: usize) -> Result<(), LaneError> {
    if depth > 16 {
        return Err(refused(
            "source-seed-cleanup",
            name,
            "directory depth exceeds bound",
        ));
    }
    let fd = opened(parent, OsStr::new(name), path)?;
    let stat = fstat(&fd).map_err(|error| refused("source-seed-cleanup", name, error))?;
    let directory = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR;
    if directory {
        for child in names(&fd, path)? {
            remove_tree(&fd, &child, &path.join(&child), depth + 1)?;
        }
    }
    unlinkat(
        parent,
        name,
        if directory {
            UnlinkatFlags::RemoveDir
        } else {
            UnlinkatFlags::NoRemoveDir
        },
    )
    .map_err(|error| refused("source-seed-cleanup", name, error))
}

fn assign_tree(fd: &OwnedFd, path: &Path, worker: u32, depth: usize) -> Result<(), LaneError> {
    if depth > 16 {
        return Err(refused(
            "source-seed-size",
            &path.display().to_string(),
            "directory depth exceeds bound",
        ));
    }
    let stat = fstat(fd)
        .map_err(|error| refused("source-seed-owner", &path.display().to_string(), error))?;
    if stat.st_uid != 0 && stat.st_uid != worker {
        return Err(refused(
            "source-seed-owner",
            &path.display().to_string(),
            "foreign owner appeared",
        ));
    }
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR {
        for name in names(fd, path)? {
            let child_path = path.join(&name);
            let child = opened(fd, OsStr::new(&name), &child_path)?;
            assign_tree(&child, &child_path, worker, depth + 1)?;
        }
    } else if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(refused(
            "source-seed-path",
            &path.display().to_string(),
            "unexpected entry kind",
        ));
    }
    fchown(fd, Some(Uid::from_raw(worker)), Some(Gid::from_raw(worker)))
        .map_err(|error| refused("source-seed-owner", &path.display().to_string(), error))
}

pub fn assign_source_ownership(seeded: &SeededSources, worker: u32) -> Result<(), LaneError> {
    for source in &seeded.names {
        let bare_name = format!("{source}.git");
        let path = seeded.root.join(&bare_name);
        let bare = directory(&seeded.parent, &bare_name, &path)?;
        assign_tree(&bare, &path, worker, 0)?;
    }
    fchown(
        &seeded.parent,
        Some(Uid::from_raw(worker)),
        Some(Gid::from_raw(worker)),
    )
    .map_err(|error| refused("source-seed-owner", "sources", error))?;
    fchmod(&seeded.parent, Mode::from_bits_truncate(0o700))
        .map_err(|error| refused("source-seed-owner", "sources", error))?;
    identity(
        &seeded.parent,
        "sources",
        worker,
        IdentityMode::Exact(0o700),
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn seed_one(
    destination_parent: &OwnedFd,
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_uid: u32,
    source: &DeclaredSource,
    plan: &Plan,
) -> Result<Value, LaneError> {
    let Some(seed) = &source.seed else {
        return Ok(
            json!({"name":source.name,"seed":null,"source_identity":null,"seeded_at_unix_ns":null}),
        );
    };
    let run = plan
        .document
        .get("run")
        .and_then(Value::as_str)
        .filter(|run| crate::valid_run_name(run))
        .ok_or_else(|| {
            refused(
                "source-seed-head",
                &source.name,
                "run is absent or malformed",
            )
        })?;
    let destination_root = plan.home.join(".local/sources");
    let (source_parent, source_bare, source_path, source_identity) =
        source_bare(owner_home, loop_name, &source.name, loop_uid, namespace_uid)?;
    let bare_name = format!("{}.git", source.name);
    let destination_path = destination_root.join(&bare_name);
    let destination = directory(destination_parent, &bare_name, &destination_path)?;
    let destination_identity = identity(
        &destination,
        &source.name,
        namespace_uid,
        IdentityMode::Exact(0o700),
    )?;
    require_commit(&source_bare, &source.name, seed)?;
    let source_text = source_path
        .to_str()
        .ok_or_else(|| refused("source-seed-path", &source.name, "source path is not UTF-8"))?;
    let refspec = format!("{seed}:refs/seeds/{}", source.name);
    let fetched = git_at(
        &destination,
        &[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            source_text,
            &refspec,
        ],
    )?;
    same_identity(
        &source_parent,
        &bare_name,
        &source_path,
        &source_bare,
        &source_identity,
        loop_uid,
        IdentityMode::Unwritable,
    )?;
    let (_, reopened_source, _, reopened_identity) =
        self::source_bare(owner_home, loop_name, &source.name, loop_uid, namespace_uid)?;
    if reopened_identity != source_identity
        || identity(
            &reopened_source,
            &source.name,
            loop_uid,
            IdentityMode::Unwritable,
        )? != source_identity
    {
        return Err(refused(
            "source-seed-identity",
            &source.name,
            "source path changed during fetch",
        ));
    }
    let reopened_parent = home::pin_parent(&destination_root, namespace_uid)
        .map_err(|error| refused("source-seed-identity", &source.name, error.detail))?;
    let held_parent = fstat(destination_parent)
        .map_err(|error| refused("source-seed-identity", &source.name, error))?;
    let path_parent = fstat(&reopened_parent)
        .map_err(|error| refused("source-seed-identity", &source.name, error))?;
    if held_parent.st_dev != path_parent.st_dev || held_parent.st_ino != path_parent.st_ino {
        return Err(refused(
            "source-seed-identity",
            &source.name,
            "destination parent path changed during fetch",
        ));
    }
    same_identity(
        &reopened_parent,
        &bare_name,
        &destination_path,
        &destination,
        &destination_identity,
        namespace_uid,
        IdentityMode::Exact(0o700),
    )?;
    if !fetched.status.success() {
        return Err(refused(
            "source-seed-fetch",
            &source.name,
            format!("local fetch exited {}", fetched.status),
        ));
    }
    let actual = git_at(
        &destination,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/seeds/{}", source.name),
        ],
    )?;
    if !actual.status.success() || actual.stdout != format!("{seed}\n").as_bytes() {
        return Err(refused(
            "source-seed-ref",
            &source.name,
            "seed ref differs from requested object",
        ));
    }
    let refs = git_at(&destination, &["for-each-ref", "--format=%(refname)"])?;
    if !refs.status.success() || refs.stdout != format!("refs/seeds/{}\n", source.name).as_bytes() {
        return Err(refused(
            "source-seed-ref",
            &source.name,
            "destination has another ref",
        ));
    }
    let reference = format!("refs/heads/lane/{run}");
    let changed = git_at(&destination, &["symbolic-ref", "HEAD", &reference])?;
    if !changed.status.success() {
        return Err(refused(
            "source-seed-head",
            &source.name,
            "HEAD was not set to lane branch",
        ));
    }
    let head = git_at(&destination, &["symbolic-ref", "HEAD"])?;
    if !head.status.success() || head.stdout != format!("{reference}\n").as_bytes() {
        return Err(refused(
            "source-seed-head",
            &source.name,
            "HEAD differs from lane branch",
        ));
    }
    let instant = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| refused("source-seed-time", &source.name, error))?
        .as_nanos();
    Ok(
        json!({"name":source.name,"seed":seed,"source_identity":source_identity,"seeded_at_unix_ns":instant}),
    )
}

#[derive(Debug)]
pub struct SeededSources {
    pub records: Vec<Value>,
    parent: OwnedFd,
    root: PathBuf,
    names: Vec<String>,
}

impl SeededSources {
    /// Remove each declared bare through the descriptor held from before ownership changed.
    ///
    /// # Errors
    ///
    /// Refuses a changed or unreadable entry by its declared name.
    pub fn cleanup(&self) -> Result<(), LaneError> {
        for name in &self.names {
            let bare_name = format!("{name}.git");
            remove_tree(&self.parent, &bare_name, &self.root.join(&bare_name), 0)
                .map_err(|error| refused("source-seed-cleanup", name, error.detail))?;
        }
        Ok(())
    }
}

/// Keep the seeded bares only when the complete ownership handover succeeds.
///
/// # Errors
///
/// Returns the handover refusal after removing every declared bare, or names cleanup failure.
pub fn handover_or_cleanup(
    seeded: &SeededSources,
    handover: impl FnOnce() -> Result<(), LaneError>,
) -> Result<(), LaneError> {
    if let Err(error) = handover() {
        seeded.cleanup().map_err(|cleanup| {
            refused(
                "source-seed-cleanup",
                "sources",
                format!("{}; after {}", cleanup.detail, error.line()),
            )
        })?;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
pub fn seed_sources(
    plan: &Plan,
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_uid: u32,
    sources: &[DeclaredSource],
) -> Result<SeededSources, LaneError> {
    let root = plan.home.join(".local/sources");
    let parent = home::pin_parent(&root, namespace_uid)?;
    seed_sources_from_parent(
        parent,
        plan,
        owner_home,
        loop_name,
        loop_uid,
        namespace_uid,
        sources,
    )
}

pub fn seed_sources_from_parent(
    parent: OwnedFd,
    plan: &Plan,
    owner_home: &Path,
    loop_name: &str,
    loop_uid: u32,
    namespace_uid: u32,
    sources: &[DeclaredSource],
) -> Result<SeededSources, LaneError> {
    let root = plan.home.join(".local/sources");
    identity(
        &parent,
        "sources",
        namespace_uid,
        IdentityMode::Exact(0o700),
    )?;
    let attempt = sources
        .iter()
        .map(|source| {
            seed_one(
                &parent,
                owner_home,
                loop_name,
                loop_uid,
                namespace_uid,
                source,
                plan,
            )
        })
        .collect::<Result<Vec<_>, _>>();
    let names = sources.iter().map(|source| source.name.clone()).collect();
    match attempt {
        Ok(records) => Ok(SeededSources {
            records,
            parent,
            root,
            names,
        }),
        Err(error) => {
            let seeded = SeededSources {
                records: Vec::new(),
                parent,
                root,
                names,
            };
            seeded.cleanup().map_err(|cleanup| {
                refused(
                    "source-seed-cleanup",
                    "sources",
                    format!("{}; after {}", cleanup.detail, error.line()),
                )
            })?;
            Err(error)
        }
    }
}

pub fn cleanup_created(
    parent: &OwnedFd,
    root: &Path,
    sources: &[DeclaredSource],
) -> Result<(), LaneError> {
    for source in sources {
        let bare_name = format!("{}.git", source.name);
        let path = root.join(&bare_name);
        match openat2(
            parent,
            bare_name.as_str(),
            OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Err(Errno::ENOENT) => {}
            Err(error) => return Err(refused("source-seed-cleanup", &source.name, error)),
            Ok(_) => remove_tree(parent, &bare_name, &path, 0)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DeclaredSource, IdentityMode, check_loop_root, git_at, handover_or_cleanup, identity,
        remove_tree, require_commit, seed_sources,
    };
    use crate::plan::Plan;
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, fstat};
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::{Command, Output};

    fn git(path: &Path, args: &[&str]) -> Output {
        // Give Git the estate's creation mode independently of the test runner's umask.
        let output = Command::new("/bin/sh")
            .args(["-c", "umask 022; exec /usr/bin/git \"$@\"", "git"])
            .arg("-C")
            .arg(path)
            .args(args)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
            .output()
            .expect("git fixture command starts");
        assert!(
            output.status.success(),
            "git fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn oid(output: &Output) -> String {
        String::from_utf8(output.stdout.clone())
            .expect("object ID is UTF-8")
            .trim()
            .to_owned()
    }

    /// ´test:unit:seed-fetch-copies-only-the-requested-commit-history-and-one-ref´
    #[test]
    #[allow(clippy::too_many_lines, clippy::literal_string_with_formatting_args)]
    fn seed_fetch_copies_only_the_requested_commit_history_and_one_ref() {
        let temp = tempfile::tempdir().expect("fixture root");
        let source = temp.path().join("source.git");
        let work = temp.path().join("work");
        let destination = temp.path().join("destination.git");
        git(
            temp.path(),
            &["init", "--bare", source.to_str().expect("source path")],
        );
        git(temp.path(), &["init", work.to_str().expect("work path")]);
        fs::write(work.join("file"), "one\n").expect("first file");
        git(&work, &["add", "file"]);
        git(&work, &["commit", "-m", "first"]);
        let first = oid(&git(&work, &["rev-parse", "HEAD"]));
        fs::write(work.join("file"), "two\n").expect("second file");
        git(&work, &["commit", "-am", "second"]);
        let second = oid(&git(&work, &["rev-parse", "HEAD"]));
        let tree = oid(&git(&work, &["rev-parse", "HEAD^{tree}"]));
        let foreign = oid(&git(&work, &["commit-tree", &tree, "-m", "foreign"]));
        git(
            &work,
            &[
                "push",
                source.to_str().expect("source path"),
                "HEAD:refs/heads/main",
            ],
        );
        git(
            &work,
            &[
                "push",
                source.to_str().expect("source path"),
                &format!("{foreign}:refs/heads/foreign"),
            ],
        );
        git(
            temp.path(),
            &[
                "init",
                "--bare",
                destination.to_str().expect("destination path"),
            ],
        );
        let source_fd = open(
            &source,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("source descriptor");
        let destination_fd = open(
            &destination,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("destination descriptor");
        require_commit(&source_fd, "tools", &second).expect("seed commit");
        let missing = "f".repeat(40);
        let absent = require_commit(&source_fd, "tools", &missing).expect_err("absent object");
        assert_eq!(absent.kind, "source-seed-object");
        assert_eq!(
            absent.line(),
            format!("source-seed-object: tools: {missing} is absent")
        );
        let blob = oid(&git(&work, &["rev-parse", "HEAD:file"]));
        let not_commit = require_commit(&source_fd, "tools", &blob).expect_err("blob seed");
        assert_eq!(not_commit.kind, "source-seed-type");
        assert_eq!(
            not_commit.line(),
            format!("source-seed-type: tools: {blob} is not a commit")
        );
        let fetched = git_at(
            &destination_fd,
            &[
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                source.to_str().expect("source path"),
                &format!("{second}:refs/seeds/tools"),
            ],
        )
        .expect("local fetch");
        assert!(
            fetched.status.success(),
            "local fetch failed: {}",
            String::from_utf8_lossy(&fetched.stderr)
        );
        let refs = git_at(&destination_fd, &["for-each-ref", "--format=%(refname)"]).expect("refs");
        assert_eq!(refs.stdout, b"refs/seeds/tools\n");
        assert!(
            git_at(
                &destination_fd,
                &["merge-base", "--is-ancestor", &first, &second]
            )
            .expect("descent check")
            .status
            .success()
        );
        assert!(
            !git_at(&destination_fd, &["cat-file", "-e", &foreign])
                .expect("foreign check")
                .status
                .success()
        );
        let older_destination = temp.path().join("older.git");
        git(
            temp.path(),
            &[
                "init",
                "--bare",
                older_destination.to_str().expect("older path"),
            ],
        );
        let older_fd = open(
            &older_destination,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("older descriptor");
        let older_fetch = git_at(
            &older_fd,
            &[
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                source.to_str().expect("source path"),
                &format!("{first}:refs/seeds/tools"),
            ],
        )
        .expect("older local fetch");
        assert!(
            older_fetch.status.success(),
            "older local fetch failed: {}",
            String::from_utf8_lossy(&older_fetch.stderr)
        );
        assert!(
            !git_at(&older_fd, &["cat-file", "-e", &second])
                .expect("newer object check")
                .status
                .success()
        );
    }

    /// ´test:unit:seed-owner-refusal-and-cleanup-name-the-bare´
    #[test]
    fn seed_owner_refusal_and_cleanup_name_the_bare() {
        let temp = tempfile::tempdir().expect("fixture root");
        let bare = temp.path().join("tools.git");
        fs::create_dir(&bare).expect("bare directory");
        fs::set_permissions(&bare, fs::Permissions::from_mode(0o700)).expect("bare mode");
        fs::create_dir(bare.join("objects")).expect("objects");
        fs::write(bare.join("objects/object"), b"fixture").expect("object");
        let parent = open(
            temp.path(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("parent descriptor");
        let held = open(
            &bare,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("bare descriptor");
        let owner = nix::unistd::Uid::effective().as_raw();
        assert!(identity(&held, "tools", owner, IdentityMode::Exact(0o700)).is_ok());
        let wrong_owner = owner.checked_add(1).expect("fixture owner differs");
        let foreign_owner = identity(&held, "tools", wrong_owner, IdentityMode::Exact(0o700))
            .expect_err("foreign owner");
        assert_eq!(foreign_owner.kind, "source-seed-owner");
        assert!(
            foreign_owner
                .line()
                .starts_with("source-seed-owner: tools:")
        );
        fs::set_permissions(&bare, fs::Permissions::from_mode(0o755)).expect("foreign mode");
        let foreign_mode =
            identity(&held, "tools", owner, IdentityMode::Exact(0o700)).expect_err("foreign mode");
        assert_eq!(foreign_mode.kind, "source-seed-owner");
        assert!(foreign_mode.line().starts_with("source-seed-owner: tools:"));
        remove_tree(&parent, "tools.git", &bare, 0).expect("clean created bare");
        assert!(!bare.exists());
    }

    /// ´test:unit:seed-sources-pins-private-bare-and-cleans-failed-handover´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn seed_sources_pins_private_bare_and_cleans_failed_handover() {
        let temp = tempfile::tempdir_in("/tmp").expect("fixture root beneath sticky parent");
        let owner_home = temp.path().join("owner");
        let src = owner_home.join(".var/loops/alpha/src");
        fs::create_dir_all(&src).expect("private source root");
        let source = src.join("tools.git");
        git(
            temp.path(),
            &["init", "--bare", source.to_str().expect("source path")],
        );
        let git_mode = fs::symlink_metadata(&source)
            .expect("Git-created source bare")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(git_mode, 0o755);
        let work = temp.path().join("work");
        git(temp.path(), &["init", work.to_str().expect("work path")]);
        fs::write(work.join("file"), "seed\n").expect("seed file");
        git(&work, &["add", "file"]);
        git(&work, &["commit", "-m", "seed"]);
        let seed = oid(&git(&work, &["rev-parse", "HEAD"]));
        let blob = oid(&git(&work, &["rev-parse", "HEAD:file"]));
        git(
            &work,
            &[
                "push",
                source.to_str().expect("source path"),
                "HEAD:refs/heads/main",
            ],
        );
        let run_home = temp.path().join("run-home");
        let sources = run_home.join(".local/sources");
        fs::create_dir_all(&sources).expect("destination root");
        for path in [
            temp.path().to_path_buf(),
            owner_home.clone(),
            owner_home.join(".var"),
            src,
            run_home.clone(),
            run_home.join(".local"),
            sources.clone(),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private fixture component");
        }
        for path in [
            owner_home.join(".var/loops"),
            owner_home.join(".var/loops/alpha"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o711))
                .expect("session-owned traversal directory");
        }
        let destination = sources.join("tools.git");
        let make_destination = || {
            git(
                temp.path(),
                &[
                    "init",
                    "--bare",
                    destination.to_str().expect("destination path"),
                ],
            );
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
                .expect("destination mode");
        };
        let plan = Plan {
            home: run_home,
            driver_dir: temp.path().join("driver"),
            letter: temp.path().join("letter"),
            document: json!({"run":"R"}),
        };
        let owner = nix::unistd::Uid::effective().as_raw();
        let loop_root = owner_home.join(".var/loops/alpha");
        let loop_fd = open(
            &loop_root,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .expect("loop root descriptor");
        let loop_stat = fstat(&loop_fd).expect("loop root metadata");
        check_loop_root(&loop_stat, "tools", owner).expect("session-owned loop root");
        fs::set_permissions(&loop_root, fs::Permissions::from_mode(0o700))
            .expect("private session-owned loop root");
        check_loop_root(
            &fstat(&loop_fd).expect("private loop root metadata"),
            "tools",
            owner,
        )
        .expect("private session-owned loop root");
        fs::set_permissions(&loop_root, fs::Permissions::from_mode(0o711))
            .expect("restore traversal mode");
        let mut foreign_stat = fstat(&loop_fd).expect("foreign loop root metadata");
        foreign_stat.st_uid = owner.checked_add(1).expect("distinct fixture uid");
        let foreign_root =
            check_loop_root(&foreign_stat, "tools", owner).expect_err("foreign loop root refuses");
        assert_eq!(foreign_root.kind, "source-seed-owner");
        assert_eq!(
            foreign_root.line(),
            "source-seed-owner: tools: loop root owner or mode differs"
        );
        fs::set_permissions(&loop_root, fs::Permissions::from_mode(0o731))
            .expect("group-writable loop root");
        let writable_stat = fstat(&loop_fd).expect("writable loop root metadata");
        let writable_root = check_loop_root(&writable_stat, "tools", owner)
            .expect_err("group-writable loop root refuses");
        assert_eq!(writable_root.kind, "source-seed-owner");
        assert_eq!(
            writable_root.line(),
            "source-seed-owner: tools: loop root owner or mode differs"
        );
        let declared = |object: &str| {
            [DeclaredSource {
                name: "tools".to_owned(),
                seed: Some(object.to_owned()),
            }]
        };
        make_destination();
        let writable_step =
            seed_sources(&plan, &owner_home, "alpha", owner, owner, &declared(&seed))
                .expect_err("group-writable loop root refuses in seed step");
        assert_eq!(writable_step.kind, "source-seed-owner");
        assert_eq!(
            writable_step.line(),
            "source-seed-owner: tools: loop root owner or mode differs"
        );
        assert!(!destination.exists());
        fs::set_permissions(&loop_root, fs::Permissions::from_mode(0o711))
            .expect("restore loop root mode");
        make_destination();
        let seeded = seed_sources(&plan, &owner_home, "alpha", owner, owner, &declared(&seed))
            .expect("seed from pinned private bare");
        assert_eq!(seeded.records[0]["name"], "tools");
        assert_eq!(seeded.records[0]["seed"], seed);
        assert!(seeded.records[0]["source_identity"].is_object());
        assert_eq!(seeded.records[0]["source_identity"]["mode"], git_mode);
        assert!(seeded.records[0]["seeded_at_unix_ns"].as_u64().is_some());
        assert_eq!(
            oid(&git(&destination, &["symbolic-ref", "HEAD"])),
            "refs/heads/lane/R"
        );
        assert_eq!(
            oid(&git(&destination, &["for-each-ref", "--format=%(refname)"])),
            "refs/seeds/tools"
        );
        git(
            &destination,
            &["fsck", "--connectivity-only", "--no-reflogs", &seed],
        );
        let clone = temp.path().join("clone");
        git(
            temp.path(),
            &[
                "clone",
                destination.to_str().expect("destination path"),
                clone.to_str().expect("clone path"),
            ],
        );
        git(
            &clone,
            &["fetch", "origin", "refs/seeds/tools:refs/seeds/tools"],
        );
        git(&clone, &["switch", "-c", "lane/R", "refs/seeds/tools"]);
        assert_eq!(oid(&git(&clone, &["rev-parse", "HEAD"])), seed);
        assert_eq!(
            oid(&git(&clone, &["symbolic-ref", "HEAD"])),
            "refs/heads/lane/R"
        );
        let worker = owner.checked_add(1).expect("distinct worker uid");
        let refusal =
            handover_or_cleanup(&seeded, || super::assign_source_ownership(&seeded, worker))
                .expect_err("worker handover requires a different owner");
        assert_eq!(refusal.kind, "source-seed-owner");
        assert!(!destination.exists());
        for mode in [0o755, 0o750, 0o700] {
            fs::set_permissions(&source, fs::Permissions::from_mode(mode))
                .expect("unwritable source mode");
            make_destination();
            let accepted =
                seed_sources(&plan, &owner_home, "alpha", owner, owner, &declared(&seed))
                    .expect("unwritable source bare seeds");
            assert_eq!(accepted.records[0]["source_identity"]["mode"], mode);
            accepted.cleanup().expect("remove accepted destination");
            assert!(!destination.exists());
        }
        fs::set_permissions(&source, fs::Permissions::from_mode(git_mode))
            .expect("restore Git-created source mode");
        for (object, kind) in [
            ("f".repeat(40), "source-seed-object"),
            (blob, "source-seed-type"),
        ] {
            make_destination();
            let failure = seed_sources(
                &plan,
                &owner_home,
                "alpha",
                owner,
                owner,
                &declared(&object),
            )
            .expect_err("invalid seed refuses");
            assert_eq!(failure.kind, kind);
            assert!(!destination.exists());
        }
        fs::set_permissions(&source, fs::Permissions::from_mode(0o775))
            .expect("group-writable source mode");
        make_destination();
        let wrong_mode = seed_sources(&plan, &owner_home, "alpha", owner, owner, &declared(&seed))
            .expect_err("group-writable source refuses");
        assert_eq!(wrong_mode.kind, "source-seed-owner");
        assert_eq!(
            wrong_mode.line(),
            format!(
                "source-seed-owner: tools: bare uid {owner} gid {owner} mode 0775; expected uid and gid {owner} without group or other write"
            )
        );
        assert!(!destination.exists());
        fs::set_permissions(&source, fs::Permissions::from_mode(git_mode))
            .expect("restore source mode");
        make_destination();
        let wrong_owner =
            seed_sources(&plan, &owner_home, "alpha", worker, owner, &declared(&seed))
                .expect_err("wrong owner refuses");
        assert_eq!(wrong_owner.kind, "source-seed-owner");
        assert_eq!(
            wrong_owner.line(),
            "source-seed-owner: tools: source directory owner or mode differs"
        );
        assert!(!destination.exists());
        fs::remove_dir_all(&source).expect("remove source");
        make_destination();
        let absent = seed_sources(&plan, &owner_home, "alpha", owner, owner, &declared(&seed))
            .expect_err("absent bare refuses");
        assert_eq!(absent.kind, "source-seed-path");
        assert!(!destination.exists());
    }
}
