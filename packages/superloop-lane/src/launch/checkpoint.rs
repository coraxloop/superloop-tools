//! Preserve settled mailboxes and local Git objects under the run's driver custody.

use super::*;
use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::fd::{AsFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILES: usize = 4096;
const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingMarker {
    index: u64,
    token: String,
}

#[derive(Clone, Debug)]
struct ResidueObservation {
    // None means the parent exists but cannot safely be traversed to establish the index.
    present: Option<bool>,
    valid: bool,
    path_error: Option<String>,
}

impl ResidueObservation {
    const fn absent() -> Self {
        Self {
            present: Some(false),
            valid: true,
            path_error: None,
        }
    }
}

#[derive(Debug)]
pub struct CheckpointRequest {
    pub loop_name: String,
    pub run: String,
    pub dry_run: bool,
    pub invocation_token: Option<String>,
}

/// Build the private checkpoint words used by the public command.
///
/// # Errors
///
/// Refuses an owner home that cannot be passed as a path word.
pub fn private_checkpoint_argv(
    request: &CheckpointRequest,
    owner_home: &Path,
    token: Option<&str>,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec![
        "_checkpoint".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "checkpoint-home")?,
    ];
    if let Some(token) = token {
        argv.extend(["--token".to_owned(), token.to_owned()]);
    }
    if request.dry_run {
        argv.push("--dry-run".into());
    }
    Ok(argv)
}

impl CheckpointRequest {
    /// Parse one checkpoint request.
    ///
    /// # Errors
    ///
    /// Refuses missing or extra arguments and invalid names.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, rest @ ..] = args else {
            return Err(LaneError::input(
                "checkpoint-usage",
                "checkpoint LOOP RUN [--dry-run]",
            ));
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !valid_run_name(run) || !(rest.is_empty() || rest == ["--dry-run"]) {
            return Err(LaneError::input(
                "checkpoint-usage",
                "checkpoint LOOP RUN [--dry-run]",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            dry_run: !rest.is_empty(),
            invocation_token: None,
        })
    }
}

fn refused(kind: &'static str, path: &Path, detail: impl std::fmt::Display) -> LaneError {
    LaneError::input(kind, format!("{}: {detail}", path.display()))
}

fn stat(fd: &OwnedFd, path: &Path) -> Result<nix::sys::stat::FileStat, LaneError> {
    fstat(fd).map_err(|error| refused("checkpoint-path", path, error))
}

fn checked(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    directory: bool,
    mode: Option<u32>,
) -> Result<(), LaneError> {
    checked_mode(fd, path, owner, directory, mode, false)
}

fn checked_source(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    mode: Option<u32>,
) -> Result<(), LaneError> {
    checked_mode(fd, path, owner, true, mode, true)
}

fn checked_mode(
    fd: &OwnedFd,
    path: &Path,
    owner: u32,
    directory: bool,
    mode: Option<u32>,
    source: bool,
) -> Result<(), LaneError> {
    let found = stat(fd, path)?;
    let kind = SFlag::from_bits_truncate(found.st_mode) & SFlag::S_IFMT;
    let expected = if directory {
        SFlag::S_IFDIR
    } else {
        SFlag::S_IFREG
    };
    let permissions = found.st_mode & 0o7777;
    if kind != expected
        || found.st_uid != owner
        || permissions & 0o022 != 0
        // Setgid only controls the group inherited by new children. Ownership,
        // owner access and the absence of group/other write remain pinned.
        || permissions & (if source { 0o5000 } else { 0o7000 }) != 0
        || (directory && permissions & 0o700 != 0o700)
        || (!directory && permissions & 0o400 == 0)
        || mode.is_some_and(|mode| mode != permissions & if source { 0o5777 } else { 0o7777 })
    {
        return Err(refused(
            "checkpoint-path",
            path,
            format!(
                "uid {} mode {permissions:04o} kind {kind:?}; expected uid {owner} {}{}",
                found.st_uid,
                if directory {
                    "directory"
                } else {
                    "regular file"
                },
                mode.map_or(String::new(), |mode| format!(" mode {mode:04o}"))
            ),
        ));
    }
    Ok(())
}

fn child(parent: &OwnedFd, name: &str, path: &Path) -> Result<OwnedFd, LaneError> {
    openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| refused("checkpoint-path", path, error))
}

fn optional_child(parent: &OwnedFd, name: &str, path: &Path) -> Result<Option<OwnedFd>, LaneError> {
    match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(refused("checkpoint-path", path, error)),
    }
}

fn probe_child(parent: &OwnedFd, name: &str, path: &Path) -> Result<Option<OwnedFd>, LaneError> {
    match openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(refused("checkpoint-path", path, error)),
    }
}

#[allow(unsafe_code)]
pub(super) fn directory_names(fd: &OwnedFd, path: &Path) -> Result<Vec<String>, LaneError> {
    // SAFETY: fdopendir owns the duplicate; each name is copied before readdir advances.
    unsafe {
        let duplicate =
            nix::unistd::dup(fd).map_err(|error| refused("checkpoint-path", path, error))?;
        let raw = duplicate.into_raw_fd();
        let stream = libc::fdopendir(raw);
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            libc::close(raw);
            return Err(refused("checkpoint-path", path, error));
        }
        libc::rewinddir(stream);
        let mut result = Vec::new();
        loop {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(stream);
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                libc::closedir(stream);
                if error.raw_os_error() != Some(0) {
                    return Err(refused("checkpoint-path", path, error));
                }
                break;
            }
            let bytes = CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = std::str::from_utf8(bytes)
                .map_err(|_| refused("checkpoint-path", path, "non-UTF-8 entry"))?;
            if result.len() >= MAX_FILES {
                libc::closedir(stream);
                return Err(refused(
                    "checkpoint-size",
                    path,
                    "file count exceeds reader bound",
                ));
            }
            result.push(name.to_owned());
        }
        result.sort();
        Ok(result)
    }
}

fn make_directory(
    parent: &OwnedFd,
    name: &str,
    path: &Path,
    owner: u32,
) -> Result<OwnedFd, LaneError> {
    nix::sys::stat::mkdirat(parent, name, nix::sys::stat::Mode::S_IRWXU)
        .map_err(|error| refused("checkpoint-copy", path, error))?;
    let fd = child(parent, name, path)?;
    nix::unistd::fchown(&fd, Some(Uid::from_raw(owner)), Some(Gid::from_raw(owner)))
        .map_err(|error| refused("checkpoint-copy", path, error))?;
    checked(&fd, path, owner, true, Some(0o700))?;
    Ok(fd)
}

pub(super) fn digest(fd: &OwnedFd, path: &Path) -> Result<String, LaneError> {
    let mut child = Command::new("/usr/bin/sha256sum")
        .arg("-")
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| refused("checkpoint-digest", path, error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| refused("checkpoint-digest", path, "hasher input is absent"))?;
    let file = File::from(
        nix::unistd::dup(fd).map_err(|error| refused("checkpoint-digest", path, error))?,
    );
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 65_536].into_boxed_slice();
    loop {
        let count = file
            .read_at(&mut buffer, offset)
            .map_err(|error| refused("checkpoint-digest", path, error))?;
        if count == 0 {
            break;
        }
        stdin
            .write_all(&buffer[..count])
            .map_err(|error| refused("checkpoint-digest", path, error))?;
        offset += count as u64;
    }
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| refused("checkpoint-digest", path, error))?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| refused("checkpoint-digest", path, "hasher output is not UTF-8"))?;
    let hash = text
        .strip_suffix("  -\n")
        .ok_or_else(|| refused("checkpoint-digest", path, "hasher output is malformed"))?;
    if !output.status.success()
        || hash.len() != 64
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(refused("checkpoint-digest", path, "hasher failed"));
    }
    Ok(hash.to_owned())
}

fn copy_file(
    source: &OwnedFd,
    target: &OwnedFd,
    name: &str,
    path: &Path,
    owner: u32,
) -> Result<(u64, String), LaneError> {
    let output = openat2(
        target,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| refused("checkpoint-copy", path, error))?;
    nix::unistd::fchown(
        &output,
        Some(Uid::from_raw(owner)),
        Some(Gid::from_raw(owner)),
    )
    .map_err(|error| refused("checkpoint-copy", path, error))?;
    let input = File::from(
        nix::unistd::dup(source).map_err(|error| refused("checkpoint-copy", path, error))?,
    );
    let mut destination = File::from(output);
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 65_536].into_boxed_slice();
    loop {
        let count = input
            .read_at(&mut buffer, offset)
            .map_err(|error| refused("checkpoint-copy", path, error))?;
        if count == 0 {
            break;
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|error| refused("checkpoint-copy", path, error))?;
        offset += count as u64;
    }
    destination
        .sync_all()
        .map_err(|error| refused("checkpoint-copy", path, error))?;
    let source_size = stat(source, path)?.st_size;
    let copied_size = destination
        .metadata()
        .map_err(|error| refused("checkpoint-copy", path, error))?
        .len();
    if u64::try_from(source_size).ok() != Some(offset) || copied_size != offset {
        return Err(refused(
            "checkpoint-copy",
            path,
            "source or copied size changed",
        ));
    }
    let copied = nix::unistd::dup(destination.as_fd())
        .map_err(|error| refused("checkpoint-copy", path, error))?;
    let copied_digest = digest(&copied, path)?;
    if digest(source, path)? != copied_digest {
        return Err(refused("checkpoint-copy", path, "copied digest differs"));
    }
    Ok((copied_size, copied_digest))
}

fn walk(
    source: &OwnedFd,
    target: Option<&OwnedFd>,
    relative: &Path,
    owner: u32,
    loop_uid: u32,
    files: &mut Vec<Value>,
    depth: usize,
) -> Result<(), LaneError> {
    if depth > MAX_DEPTH {
        return Err(refused(
            "checkpoint-size",
            relative,
            "directory depth exceeds bound",
        ));
    }
    for name in directory_names(source, relative)? {
        let path = relative.join(&name);
        let opened = child(source, &name, &path)?;
        let info = stat(&opened, &path)?;
        let kind = SFlag::from_bits_truncate(info.st_mode) & SFlag::S_IFMT;
        if kind == SFlag::S_IFDIR {
            if relative.starts_with("sources") {
                checked_source(&opened, &path, owner, None)?;
            } else {
                checked(&opened, &path, owner, true, None)?;
            }
            let copied = target
                .map(|target| make_directory(target, &name, &path, loop_uid))
                .transpose()?;
            walk(
                &opened,
                copied.as_ref(),
                &path,
                owner,
                loop_uid,
                files,
                depth + 1,
            )?;
        } else if kind == SFlag::S_IFREG {
            checked(&opened, &path, owner, false, None)?;
            if files.len() >= MAX_FILES {
                return Err(refused(
                    "checkpoint-size",
                    &path,
                    "file count exceeds reader bound",
                ));
            }
            let (size, hash) = if let Some(target) = target {
                let (size, hash) = copy_file(&opened, target, &name, &path, loop_uid)?;
                (size, Some(hash))
            } else {
                (
                    u64::try_from(info.st_size)
                        .map_err(|_| refused("checkpoint-size", &path, "negative size"))?,
                    None,
                )
            };
            files.push(json!({"path":path,"size":size,"sha256":hash}));
        } else {
            return Err(refused(
                "checkpoint-path",
                &path,
                "entry is neither a directory nor a regular file",
            ));
        }
    }
    Ok(())
}

fn read_ref(
    bare: &OwnedFd,
    run: &str,
    path: &Path,
    worker: u32,
) -> Result<Option<String>, LaneError> {
    let refs = child(bare, "refs", &path.join("refs"))?;
    checked_source(&refs, &path.join("refs"), worker, None)?;
    let heads = child(&refs, "heads", &path.join("refs/heads"))?;
    checked_source(&heads, &path.join("refs/heads"), worker, None)?;
    let lane = optional_child(&heads, "lane", &path.join("refs/heads/lane"))?;
    let loose = if let Some(lane) = lane {
        checked_source(&lane, &path.join("refs/heads/lane"), worker, None)?;
        let ref_path = path.join("refs/heads/lane").join(run);
        optional_child(&lane, run, &ref_path)?
            .map(|reference| {
                checked(&reference, &ref_path, worker, false, None)?;
                let mut value = String::new();
                File::from(reference)
                    .take(129)
                    .read_to_string(&mut value)
                    .map_err(|error| refused("checkpoint-ref", &ref_path, error))?;
                Ok(value)
            })
            .transpose()?
    } else {
        None
    };
    let packed = if loose.is_none() {
        let packed_path = path.join("packed-refs");
        optional_child(bare, "packed-refs", &packed_path)?
            .map(|reference| {
                checked(&reference, &packed_path, worker, false, None)?;
                let mut value = String::new();
                File::from(reference)
                    .take(1_048_577)
                    .read_to_string(&mut value)
                    .map_err(|error| refused("checkpoint-ref", &packed_path, error))?;
                if value.len() > 1_048_576 {
                    return Err(refused(
                        "checkpoint-ref",
                        &packed_path,
                        "packed refs exceed bound",
                    ));
                }
                let wanted = format!("refs/heads/lane/{run}");
                Ok(value.lines().find_map(|line| {
                    line.split_once(' ')
                        .filter(|(_, name)| *name == wanted.as_str())
                        .map(|(oid, _)| oid.to_owned())
                }))
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let Some(value) = loose.or(packed) else {
        return Ok(None);
    };
    let hex = value.trim_end_matches('\n');
    if ![40, 64].contains(&hex.len()) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused("checkpoint-ref", path, "ref is not an object ID"));
    }
    Ok(Some(hex.to_owned()))
}

fn refuse_withdrawn_ref(
    checkpoints: &[Value],
    repo: &str,
    current: Option<&str>,
    path: &Path,
) -> Result<(), LaneError> {
    if current.is_none()
        && checkpoints.last().is_some_and(|checkpoint| {
            checkpoint["bares"].as_array().is_some_and(|bares| {
                bares
                    .iter()
                    .any(|bare| bare["name"] == repo && bare["lane_ref"] == "present")
            })
        })
    {
        return Err(refused(
            "checkpoint-ref",
            path,
            format!("recorded refs/heads/lane for {repo} is absent"),
        ));
    }
    Ok(())
}

fn checkpoint_ref(
    bare: &OwnedFd,
    run: &str,
    path: &Path,
    worker: u32,
    checkpoints: &[Value],
    repo: &str,
) -> Result<Option<String>, LaneError> {
    let object = read_ref(bare, run, path, worker)?;
    refuse_withdrawn_ref(checkpoints, repo, object.as_deref(), path)?;
    Ok(object)
}

fn bare_ref_row(repo: &str, declared: bool, seed: Option<&Value>, object: Option<&str>) -> Value {
    json!({"name":repo,"declared":declared,"seed":seed,"lane_ref":if object.is_some() {"present"} else {"absent"},"object":object})
}

fn refuse_missing_previous_bares(
    checkpoints: &[Value],
    bares: &[Value],
    path: &Path,
) -> Result<(), LaneError> {
    if let Some(previous) = checkpoints
        .last()
        .and_then(|entry| entry["bares"].as_array())
    {
        for bare in previous {
            if bare["lane_ref"] == "present"
                && !bares.iter().any(|current| current["name"] == bare["name"])
            {
                return Err(refused(
                    "checkpoint-ref",
                    path,
                    format!(
                        "recorded source {} is absent",
                        bare["name"].as_str().unwrap_or_default()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn git_from_bare(bare: &OwnedFd, args: &[&str]) -> std::io::Result<std::process::Output> {
    let raw = bare.as_raw_fd();
    let mut command = Command::new("/usr/bin/git");
    command
        .args(["-c", "safe.directory=*", "--git-dir=."])
        .args(args)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    // SAFETY: the held directory descriptor remains open until the child is spawned.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(raw) == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    command.output()
}

fn verify_bare(
    bare: &OwnedFd,
    path: &Path,
    run: &str,
    expected: Option<&str>,
    loop_uid: u32,
) -> Result<(), LaneError> {
    let config_path = path.join("config");
    let config = child(bare, "config", &config_path)?;
    checked(&config, &config_path, loop_uid, false, Some(0o600))?;
    let mut bytes = Vec::new();
    File::from(config)
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|error| refused("checkpoint-bare", &config_path, error))?;
    if bytes.len() > 65_536 {
        return Err(refused(
            "checkpoint-bare",
            &config_path,
            "bare config exceeds bound",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refused("checkpoint-bare", &config_path, "bare config is not UTF-8"))?;
    for line in text.lines() {
        let line = line.trim().to_ascii_lowercase();
        let section = line
            .strip_prefix('[')
            .map(str::trim_start)
            .unwrap_or_default();
        if section.starts_with("remote") || section.starts_with("include") {
            return Err(refused(
                "checkpoint-bare",
                &config_path,
                "bare config names a remote or external include",
            ));
        }
    }
    let observed = read_ref(bare, run, path, loop_uid)?;
    if observed.as_deref() != expected {
        return Err(refused(
            "checkpoint-ref",
            path,
            format!("copied ref {observed:?} differs from {expected:?}"),
        ));
    }
    let Some(expected) = expected else {
        return Ok(());
    };
    let reference = format!("refs/heads/lane/{run}");
    let output = git_from_bare(bare, &["rev-parse", "--verify", &reference])
        .map_err(|error| refused("checkpoint-ref", path, error))?;
    let actual = std::str::from_utf8(&output.stdout)
        .unwrap_or_default()
        .trim();
    if !output.status.success() || actual != expected {
        return Err(refused(
            "checkpoint-ref",
            path,
            format!("copied ref {actual} differs from {expected}"),
        ));
    }
    let output = git_from_bare(
        bare,
        &["fsck", "--connectivity-only", "--no-reflogs", expected],
    )
    .map_err(|error| refused("checkpoint-objects", path, error))?;
    if !output.status.success() {
        return Err(refused(
            "checkpoint-objects",
            path,
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

/// Recheck the recorded preservation through held descriptors before an external checkout.
#[derive(Debug)]
pub(super) struct VerifiedBare {
    pub fd: OwnedFd,
    pub path: PathBuf,
}

/// Check the seed against the preserved lane object through the held bare.
///
/// # Errors
///
/// Refuses a Git invocation that cannot decide ancestry.
pub(super) fn seed_descends(
    bare: &VerifiedBare,
    seed: &str,
    lane_object: &str,
) -> Result<bool, LaneError> {
    let output = git_from_bare(
        &bare.fd,
        &["merge-base", "--is-ancestor", seed, lane_object],
    )
    .map_err(|error| refused("checkpoint-seed", &bare.path, error))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(refused(
            "checkpoint-seed",
            &bare.path,
            "Git could not decide ancestry",
        )),
    }
}

pub(super) fn verify_seed_ref(
    bare: &OwnedFd,
    path: &Path,
    name: &str,
    run: &str,
    seed: &str,
) -> Result<(), LaneError> {
    let reference = format!("refs/seeds/{name}");
    let output = git_from_bare(bare, &["rev-parse", "--verify", &reference])
        .map_err(|error| refused("checkpoint-seed", path, error))?;
    if !output.status.success() || output.stdout != format!("{seed}\n").as_bytes() {
        return Err(refused(
            "checkpoint-seed",
            path,
            format!("{reference} differs from recorded seed {seed}"),
        ));
    }
    let head = git_from_bare(bare, &["symbolic-ref", "HEAD"])
        .map_err(|error| refused("checkpoint-seed", path, error))?;
    let branch = format!("refs/heads/lane/{run}");
    if !head.status.success() || head.stdout != format!("{branch}\n").as_bytes() {
        return Err(refused(
            "checkpoint-seed",
            path,
            "HEAD differs from lane branch",
        ));
    }
    let kind = git_from_bare(bare, &["cat-file", "-t", seed])
        .map_err(|error| refused("checkpoint-seed", path, error))?;
    if !kind.status.success() || kind.stdout != b"commit\n" {
        return Err(refused(
            "checkpoint-seed",
            path,
            format!("{seed} is not a present commit"),
        ));
    }
    Ok(())
}

///
/// # Errors
///
/// Refuses missing, linked, changed, or incomplete preserved content.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn verify_preserved_copy(
    run_fd: &OwnedFd,
    driver_dir: &Path,
    index: u64,
    files: &[Value],
    repo: &str,
    run: &str,
    expected: &str,
    loop_uid: u32,
) -> Result<VerifiedBare, LaneError> {
    verify_preserved_copy_state(
        run_fd,
        driver_dir,
        index,
        files,
        repo,
        run,
        Some(expected),
        loop_uid,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn verify_preserved_copy_state(
    run_fd: &OwnedFd,
    driver_dir: &Path,
    index: u64,
    files: &[Value],
    repo: &str,
    run: &str,
    expected: Option<&str>,
    loop_uid: u32,
) -> Result<VerifiedBare, LaneError> {
    let preserved_path = driver_dir.join("preserved");
    let preserved = child(run_fd, "preserved", &preserved_path)?;
    checked(&preserved, &preserved_path, loop_uid, true, Some(0o700))?;
    let snapshot_path = preserved_path.join(index.to_string());
    let snapshot = child(&preserved, &index.to_string(), &snapshot_path)?;
    checked(&snapshot, &snapshot_path, loop_uid, true, Some(0o700))?;
    let mut observed = Vec::new();
    walk(
        &snapshot,
        None,
        Path::new(""),
        loop_uid,
        loop_uid,
        &mut observed,
        0,
    )?;
    let mut recorded = files.to_vec();
    observed.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    recorded.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    if observed.len() != recorded.len()
        || observed
            .iter()
            .zip(&recorded)
            .any(|(found, saved)| found["path"] != saved["path"] || found["size"] != saved["size"])
    {
        return Err(refused(
            "checkout-checkpoint",
            &snapshot_path,
            "preserved file list or size differs from checkpoint",
        ));
    }
    for saved in &recorded {
        let relative = saved["path"].as_str().ok_or_else(|| {
            refused(
                "checkout-checkpoint",
                &snapshot_path,
                "file path is malformed",
            )
        })?;
        let mut components = Path::new(relative).components().peekable();
        if components.peek().is_none() {
            return Err(refused(
                "checkout-checkpoint",
                &snapshot_path,
                "file path is empty",
            ));
        }
        let mut current = nix::unistd::dup(&snapshot)
            .map_err(|error| refused("checkout-checkpoint", &snapshot_path, error))?;
        let mut path = snapshot_path.clone();
        while let Some(component) = components.next() {
            let std::path::Component::Normal(name) = component else {
                return Err(refused(
                    "checkout-checkpoint",
                    &snapshot_path,
                    "file path has a dotted component",
                ));
            };
            let word = name.to_str().ok_or_else(|| {
                refused(
                    "checkout-checkpoint",
                    &snapshot_path,
                    "file path is not UTF-8",
                )
            })?;
            path.push(name);
            let next = child(&current, word, &path)?;
            checked(&next, &path, loop_uid, components.peek().is_some(), None)?;
            current = next;
        }
        let expected_digest = saved["sha256"]
            .as_str()
            .ok_or_else(|| refused("checkout-checkpoint", &path, "file digest is absent"))?;
        if digest(&current, &path)? != expected_digest {
            return Err(refused(
                "checkout-checkpoint",
                &path,
                "preserved file digest differs from checkpoint",
            ));
        }
    }
    let sources_path = snapshot_path.join("sources");
    let sources = child(&snapshot, "sources", &sources_path)?;
    checked(&sources, &sources_path, loop_uid, true, Some(0o700))?;
    let bare_name = format!("{repo}.git");
    let bare_path = sources_path.join(&bare_name);
    let bare = child(&sources, &bare_name, &bare_path)?;
    checked(&bare, &bare_path, loop_uid, true, Some(0o700))?;
    verify_bare(&bare, &bare_path, run, expected, loop_uid)?;
    Ok(VerifiedBare {
        fd: bare,
        path: bare_path,
    })
}

fn instant() -> Result<u128, LaneError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .map_err(|error| LaneError::operation("checkpoint-clock", error.to_string()))
}

#[allow(unsafe_code)]
pub(crate) fn random_token() -> Result<String, LaneError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining slice is writable for exactly the supplied length.
        let count = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LaneError::operation("checkpoint-token", error.to_string()));
        }
        if count == 0 {
            return Err(LaneError::operation(
                "checkpoint-token",
                "random source returned no bytes",
            ));
        }
        filled += usize::try_from(count)
            .map_err(|error| LaneError::operation("checkpoint-token", error.to_string()))?;
    }
    let mut token = String::with_capacity(32);
    for byte in bytes {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

pub(super) fn existing_checkpoint_lock(
    root: &Path,
    run: &str,
    owner: u32,
    prefix: &str,
    nonblock: bool,
) -> Result<Flock<File>, LaneError> {
    let parent = home::pin_parent(root, owner)?;
    let name = format!(".{prefix}-{run}.lock");
    let path = root.join(&name);
    let opened = match openat2(
        &parent,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(opened) => opened,
        Err(nix::errno::Errno::ENOENT) => {
            return Err(LaneError::input(
                "checkpoint-record",
                format!("{prefix} lock is absent: {}", path.display()),
            ));
        }
        Err(error) => return Err(refused("checkpoint-path", &path, error)),
    };
    checked(&opened, &path, owner, false, Some(0o600))?;
    let operation = if nonblock {
        FlockArg::LockExclusiveNonblock
    } else {
        FlockArg::LockExclusive
    };
    Flock::lock(File::from(opened), operation)
        .map_err(|(_file, error)| refused("checkpoint-round", &path, error))
}

pub(super) fn checkpoint_locks(
    root: &Path,
    run: &str,
    owner: u32,
    dry_run: bool,
) -> Result<(Flock<File>, Flock<File>), LaneError> {
    if dry_run {
        let preparation = existing_checkpoint_lock(root, run, owner, "prepare", true)?;
        let mailbox = existing_checkpoint_lock(root, run, owner, "letter", false)?;
        Ok((preparation, mailbox))
    } else {
        let preparation = super::lock_run_preparation(root, run, owner)?;
        let mailbox = super::lock_mailbox(root, run, owner)?;
        Ok((preparation, mailbox))
    }
}

pub(super) fn checkpoint_locks_at(
    root: &OwnedFd,
    run: &str,
    owner: u32,
    dry_run: bool,
) -> Result<(Flock<File>, Flock<File>), LaneError> {
    let lock = |prefix: &str, nonblock: bool| -> Result<Flock<File>, LaneError> {
        let name = format!(".{prefix}-{run}.lock");
        let flags = if dry_run {
            OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW
        } else {
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW
        };
        let how = OpenHow::new()
            .flags(flags)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
        let how = if dry_run {
            how
        } else {
            how.mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
        };
        let fd = openat2(root, name.as_str(), how)
            .map_err(|error| LaneError::input("checkpoint-record", format!("{name}: {error}")))?;
        checked(&fd, Path::new(&name), owner, false, Some(0o600))?;
        Flock::lock(
            File::from(fd),
            if nonblock {
                FlockArg::LockExclusiveNonblock
            } else {
                FlockArg::LockExclusive
            },
        )
        .map_err(|(_file, error)| LaneError::input("checkpoint-round", format!("{name}: {error}")))
    };
    let preparation = lock("prepare", true)?;
    let mailbox = lock("letter", false)?;
    Ok((preparation, mailbox))
}

fn append_attempt(
    record: &mut Value,
    index: Option<u64>,
    token: &str,
    refusal: &str,
    detail: &str,
    residue: &ResidueObservation,
) -> Result<(), LaneError> {
    let (mut entries, _, mut omitted) = checkpoint_fields(record)?;
    let mut bounded = String::new();
    for character in detail.chars() {
        bounded.push(character);
        if serde_json::to_string(&bounded)
            .map_err(|error| LaneError::input("checkpoint-record", error.to_string()))?
            .len()
            > 258
        {
            bounded.pop();
            break;
        }
    }
    let detail = bounded;
    entries.push(json!({"index":index,"token":token,"instant_unix_ns":instant()?,"state":"refused","refusal":refusal,"detail":detail,"residue":residue.present,"path_valid":residue.valid}));
    while entries
        .iter()
        .filter(|entry| entry["residue"] == false && entry["path_valid"] == true)
        .count()
        > 16
    {
        let position = entries
            .iter()
            .position(|entry| entry["residue"] == false && entry["path_valid"] == true)
            .ok_or_else(|| LaneError::input("checkpoint-record", "attempt residue is malformed"))?;
        entries.remove(position);
        omitted = omitted
            .checked_add(1)
            .ok_or_else(|| LaneError::input("checkpoint-record", "omitted count overflowed"))?;
    }
    record["checkpoint_attempts"] = json!(entries);
    record["attempts_omitted"] = json!(omitted);
    Ok(())
}

fn declared_sources(record: &Value) -> Result<Vec<Value>, LaneError> {
    record["declared_sources"]
        .as_array()
        .filter(|sources| {
            sources.iter().all(|source| {
                source.as_object().is_some_and(|fields| {
                    fields.len() == 4
                        && ["name", "seed", "source_identity", "seeded_at_unix_ns"]
                            .iter()
                            .all(|key| fields.contains_key(*key))
                }) && source["name"].as_str().is_some_and(valid_run_name)
                    && (source["seed"].is_null()
                        || source["seed"].as_str().is_some_and(|seed| {
                            seed.len() == 40 && seed.bytes().all(|byte| byte.is_ascii_hexdigit())
                        }))
                    && if source["seed"].is_null() {
                        source["source_identity"].is_null() && source["seeded_at_unix_ns"].is_null()
                    } else {
                        source["source_identity"].as_object().is_some_and(|fields| {
                            fields.len() == 5
                                && ["device", "inode", "uid", "gid", "mode"]
                                    .iter()
                                    .all(|key| fields.get(*key).and_then(Value::as_u64).is_some())
                        }) && source["seeded_at_unix_ns"].as_u64().is_some()
                    }
            })
        })
        .cloned()
        .ok_or_else(|| LaneError::input("checkpoint-record", "declared sources are malformed"))
}

pub(super) fn checkpoint_fields(
    record: &Value,
) -> Result<(Vec<Value>, Vec<Value>, u64), LaneError> {
    let attempts = match record.get("checkpoint_attempts") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .filter(|entries| {
                entries.iter().all(|entry| {
                    entry.as_object().is_some_and(|fields| {
                        fields.len() == 8
                            && fields
                                .get("index")
                                .is_some_and(|index| index.is_null() || index.as_u64().is_some())
                            && fields
                                .get("instant_unix_ns")
                                .and_then(Value::as_u64)
                                .is_some()
                            && fields
                                .get("token")
                                .and_then(Value::as_str)
                                .is_some_and(valid_token)
                            && fields.get("state").and_then(Value::as_str) == Some("refused")
                            && fields.get("refusal").and_then(Value::as_str).is_some()
                            && fields.get("detail").and_then(Value::as_str).is_some()
                            && fields.get("path_valid").and_then(Value::as_bool).is_some()
                            && fields.get("residue").is_some_and(|residue| {
                                residue.as_bool().is_some()
                                    || (residue.is_null()
                                        && fields.get("path_valid").and_then(Value::as_bool)
                                            == Some(false))
                            })
                    })
                })
            })
            .cloned()
            .ok_or_else(|| {
                LaneError::input("checkpoint-record", "checkpoint attempts are malformed")
            })?,
    };
    let checkpoints = match record.get("checkpoints") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .filter(|entries| {
                entries.iter().all(|entry| {
                    entry.as_object().is_some_and(|fields| fields.len() == 5)
                        && entry["index"].as_u64().is_some()
                        && entry["instant_unix_ns"].as_u64().is_some()
                        && entry["round_after"].as_str().is_some()
                        && entry["files"].as_array().is_some_and(|files| {
                            files.iter().all(|file| {
                                file.as_object().is_some_and(|fields| fields.len() == 3)
                                    && file["path"].as_str().is_some()
                                    && file["size"].as_u64().is_some()
                                    && file["sha256"].as_str().is_some()
                            })
                        })
                        && entry["bares"].as_array().is_some_and(|bares| {
                            bares.iter().all(|bare| {
                                bare.as_object().is_some_and(|fields| fields.len() == 5)
                                    && bare["name"].as_str().is_some()
                                    && bare["declared"].as_bool().is_some()
                                    && bare.get("seed").is_some()
                                    && bare.get("object").is_some()
                                    && (bare["seed"].is_null()
                                        || bare["seed"].as_str().is_some_and(|seed| {
                                            seed.len() == 40
                                                && seed.bytes().all(|byte| byte.is_ascii_hexdigit())
                                        }))
                                    && match bare.get("lane_ref") {
                                        Some(state) if state == "absent" => {
                                            bare["object"].is_null()
                                        }
                                        Some(state) if state == "present" => {
                                            bare["object"].as_str().is_some()
                                        }
                                        _ => false,
                                    }
                            })
                        })
                })
            })
            .cloned()
            .ok_or_else(|| LaneError::input("checkpoint-record", "checkpoints are malformed"))?,
    };
    let omitted = match record.get("attempts_omitted") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| LaneError::input("checkpoint-record", "omitted count is malformed"))?,
    };
    Ok((attempts, checkpoints, omitted))
}

fn checkpoints_with_new_row(record: &Value, row: Value) -> Vec<Value> {
    let mut entries = record["checkpoints"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    entries.push(row);
    entries
}

fn pending_marker(record: &Value) -> Result<Option<PendingMarker>, LaneError> {
    match record.get("checkpoint_pending") {
        None => Ok(None),
        Some(value) => {
            if value.as_object().is_none_or(|fields| fields.len() != 2) {
                return Err(LaneError::input(
                    "checkpoint-record",
                    "pending marker is malformed",
                ));
            }
            let index = value["index"]
                .as_u64()
                .filter(|index| (1..=1024).contains(index))
                .ok_or_else(|| {
                    LaneError::input("checkpoint-record", "pending index is malformed")
                })?;
            let token = value["token"]
                .as_str()
                .filter(|token| valid_token(token))
                .ok_or_else(|| {
                    LaneError::input("checkpoint-record", "pending token is malformed")
                })?;
            Ok(Some(PendingMarker {
                index,
                token: token.to_owned(),
            }))
        }
    }
}

fn valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn residue_at(
    run_fd: &OwnedFd,
    driver_dir: &Path,
    index: u64,
    loop_uid: u32,
) -> Result<ResidueObservation, LaneError> {
    let preserved_path = driver_dir.join("preserved");
    let Some(preserved) = probe_child(run_fd, "preserved", &preserved_path)? else {
        return Ok(ResidueObservation::absent());
    };
    if let Err(error) = checked(&preserved, &preserved_path, loop_uid, true, Some(0o700)) {
        return Ok(ResidueObservation {
            present: None,
            valid: false,
            path_error: Some(error.line()),
        });
    }
    let target_path = preserved_path.join(index.to_string());
    let Some(target) = probe_child(&preserved, &index.to_string(), &target_path)? else {
        return Ok(ResidueObservation {
            present: Some(false),
            valid: true,
            path_error: None,
        });
    };
    let target_error = checked(&target, &target_path, loop_uid, true, Some(0o700)).err();
    let path_error = target_error.map(|error| error.line());
    Ok(ResidueObservation {
        present: Some(true),
        valid: path_error.is_none(),
        path_error,
    })
}

fn pending_preview(
    record: &Value,
    run_fd: &OwnedFd,
    driver_dir: &Path,
    loop_uid: u32,
) -> Result<Option<Value>, LaneError> {
    pending_marker(record)?
        .map(|marker| {
            let residue = residue_at(run_fd, driver_dir, marker.index, loop_uid)?;
            Ok(json!({"index":marker.index,"token":marker.token,"residue":residue.present,"path_valid":residue.valid,"path_error":residue.path_error}))
        })
        .transpose()
}

fn record_failure(
    reservation: &Path,
    record: &Value,
    marker: &PendingMarker,
    error: &LaneError,
    residue: &ResidueObservation,
) -> Result<(), LaneError> {
    if pending_marker(record)?.as_ref() != Some(marker) {
        return Err(LaneError::input(
            "checkpoint-record",
            "pending token changed before refusal record",
        ));
    }
    let mut failed = record.clone();
    failed
        .as_object_mut()
        .ok_or_else(|| LaneError::input("checkpoint-record", "reservation is not an object"))?
        .remove("checkpoint_pending");
    let (refusal, detail) = residue.path_error.as_ref().map_or_else(
        || (error.kind, error.line()),
        |path_error| ("checkpoint-path", format!("{path_error}; {}", error.line())),
    );
    append_attempt(
        &mut failed,
        Some(marker.index),
        &marker.token,
        refusal,
        &detail,
        residue,
    )?;
    publish_reservation(reservation, &failed)
}

fn recover_private_failure(
    root: &Path,
    run: &str,
    expected_token: &str,
    error: &LaneError,
    inspect: impl FnOnce() -> Result<Value, LaneError>,
) -> Result<(), LaneError> {
    let reservation = reservation_path(root, run);
    let marker = {
        let _lease = super::lock_run_preparation(root, run, Uid::effective().as_raw())?;
        let _mailbox = super::lock_mailbox(root, run, Uid::effective().as_raw())?;
        let record = read_reservation(&reservation)?
            .ok_or_else(|| LaneError::input("checkpoint-record", "reservation is absent"))?;
        pending_marker(&record)?
    };
    let Some(marker) = marker else {
        return Ok(());
    };
    if marker.token != expected_token {
        return Err(LaneError::input(
            "checkpoint-record",
            format!(
                "pending token changed from {expected_token} to {} before recovery",
                marker.token
            ),
        ));
    }
    let preview = inspect()?;
    if preview["pending"]["index"].as_u64() != Some(marker.index)
        || preview["pending"]["token"].as_str() != Some(marker.token.as_str())
    {
        return Err(LaneError::input(
            "checkpoint-record",
            "private pending preview names another token or index",
        ));
    }
    let present = match preview["pending"].get("residue") {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Null) => None,
        _ => {
            return Err(LaneError::input(
                "checkpoint-record",
                "private residue preview is absent or malformed",
            ));
        }
    };
    let valid = preview["pending"]["path_valid"].as_bool().ok_or_else(|| {
        LaneError::input(
            "checkpoint-record",
            "private path validity preview is absent",
        )
    })?;
    let path_error = match preview["pending"].get("path_error") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        _ => {
            return Err(LaneError::input(
                "checkpoint-record",
                "private path error preview is malformed",
            ));
        }
    };
    if valid != path_error.is_none() {
        return Err(LaneError::input(
            "checkpoint-record",
            "private path preview disagrees",
        ));
    }
    if present.is_none() && valid {
        return Err(LaneError::input(
            "checkpoint-record",
            "unknown residue cannot have a valid path",
        ));
    }
    let residue = ResidueObservation {
        present,
        valid,
        path_error,
    };
    let _lease = super::lock_run_preparation(root, run, Uid::effective().as_raw())?;
    let _mailbox = super::lock_mailbox(root, run, Uid::effective().as_raw())?;
    let record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("checkpoint-record", "reservation is absent"))?;
    let actual = pending_marker(&record)?;
    if actual.as_ref() != Some(&marker) {
        return Err(LaneError::input(
            "checkpoint-record",
            format!(
                "pending token changed from {} to {} before recovery",
                marker.token,
                actual
                    .as_ref()
                    .map_or("absent", |value| value.token.as_str())
            ),
        ));
    }
    let limit = if error.detail.contains("time limit") {
        "300 second time limit"
    } else if error.detail.contains("output limit") {
        "private output limit"
    } else {
        "private process failure"
    };
    let refusal = LaneError::input("checkpoint-private", limit);
    record_failure(&reservation, &record, &marker, &refusal, &residue)
}

/// Enter the owner namespace with held home and runs-root descriptors.
///
/// # Errors
///
/// Refuses unsafe roots or a failed private checkpoint.
#[allow(clippy::too_many_lines)]
pub fn run(owner_home: &Path, request: &CheckpointRequest) -> Result<Value, LaneError> {
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("checkpoint-grant", "runs_root is absent"))?;
    let podman = plan.document["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("checkpoint-record", "container program is absent"))?;
    let owner = Uid::effective().as_raw();
    crate::pinned::owner_executable(Path::new(podman), owner)?;
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("checkpoint-program", error.to_string()))?;
    crate::pinned::owner_executable(&exe, owner)?;
    let mut argv = vec![
        "unshare".into(),
        crate::pinned::path_word(&exe, "checkpoint-program")?,
    ];
    let invocation_token = if request.dry_run {
        None
    } else {
        Some(random_token()?)
    };
    argv.extend(private_checkpoint_argv(
        request,
        owner_home,
        invocation_token.as_deref(),
    )?);
    let mut preview_argv = argv.clone();
    if !request.dry_run {
        preview_argv.push("--dry-run".into());
    }
    let environment = launch_environment(owner_home)?;
    let output = build::run_checked_with_private_launch(
        Path::new(podman),
        argv,
        &environment,
        owner_home,
        300,
        "checkpoint-private",
        &home_fd,
        root,
        &runs_fd,
        None,
    );
    let output = output.map_err(|error| {
        if !request.dry_run {
            let recovery = recover_private_failure(
                root,
                &request.run,
                invocation_token.as_deref().unwrap_or_default(),
                &error,
                || {
                    let preview = build::run_checked_with_private_launch(
                        Path::new(podman),
                        preview_argv,
                        &environment,
                        owner_home,
                        30,
                        "checkpoint-preview",
                        &home_fd,
                        root,
                        &runs_fd,
                        None,
                    )?;
                    serde_json::from_str(&preview).map_err(|failure| {
                        LaneError::input("checkpoint-record", failure.to_string())
                    })
                },
            );
            if let Err(recovery) = recovery {
                return LaneError::operation(
                    "checkpoint-private",
                    format!("{}; recovery: {}", error.line(), recovery.line()),
                );
            }
        }
        for kind in [
            "checkpoint-round",
            "checkpoint-record",
            "checkpoint-path",
            "checkpoint-ref",
            "checkpoint-objects",
            "checkpoint-copy",
            "checkpoint-size",
            "checkpoint-bare",
            "checkpoint-digest",
        ] {
            if error.detail.contains(&format!("{kind}:")) {
                return LaneError::input(kind, error.detail);
            }
        }
        error
    })?;
    let mut report: Value = serde_json::from_str(&output)
        .map_err(|error| LaneError::operation("checkpoint-private", error.to_string()))?;
    report["driver_dir"] = json!(plan.driver_dir);
    Ok(report)
}

/// Copy one settled run while holding its owner locks in the rootless namespace.
///
/// # Errors
///
/// Refuses a live round, unsafe source, absent ref, failed copy or unreachable object.
#[allow(clippy::too_many_lines)]
pub fn private_run(owner_home: &Path, request: &CheckpointRequest) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    if request
        .invocation_token
        .as_deref()
        .is_some_and(|token| !valid_token(token))
        || (!request.dry_run && request.invocation_token.is_none())
    {
        return Err(LaneError::input(
            "checkpoint-record",
            "invocation token is absent or malformed",
        ));
    }
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("checkpoint-grant", "runs_root is absent"))?;
    private_run_with_plan(plan, root, request, 0)
}

#[allow(clippy::too_many_lines)]
pub(super) fn private_run_with_plan(
    mut plan: crate::plan::Plan,
    root: &Path,
    request: &CheckpointRequest,
    namespace_owner: u32,
) -> Result<Value, LaneError> {
    let reservation = reservation_path(root, &request.run);
    let (_lease, _mailbox) =
        checkpoint_locks(root, &request.run, namespace_owner, request.dry_run)?;
    let record = read_reservation(&reservation)?
        .ok_or_else(|| LaneError::input("checkpoint-record", "reservation is absent"))?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || record["phase"] != "settled"
        || !super::settle::final_round_ready(&record)
    {
        return Err(LaneError::input(
            "checkpoint-round",
            "run has no settled final round",
        ));
    }
    let pending = pending_marker(&record)?;
    if pending.is_some() && !request.dry_run {
        return Err(LaneError::input(
            "checkpoint-record",
            "checkpoint pending index is unresolved",
        ));
    }
    let (_, checkpoints, _) = checkpoint_fields(&record)?;
    let round = record["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round["step"].as_str())
        .ok_or_else(|| LaneError::input("checkpoint-record", "settled round step is absent"))?
        .to_owned();
    let declared = declared_sources(&record)?;
    if checkpoints.len() >= 16 && !request.dry_run {
        return Err(LaneError::input(
            "checkpoint-size",
            "checkpoint count exceeds reservation bound",
        ));
    }
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| LaneError::input("checkpoint-record", "worker UID is absent"))?;
    plan.select_worker_uid(worker)?;
    if record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "checkpoint-record",
            "recorded paths differ from run",
        ));
    }
    let loop_uid = super::recorded_loop_uid(&record)?;
    let held_root = home::pin_parent(root, namespace_owner)?;
    let run_fd = home::pin_loop_round_at(&held_root, root, &plan.driver_dir, loop_uid)?;
    checked(&run_fd, &plan.driver_dir, loop_uid, true, Some(0o700))?;
    if pending.is_some() {
        let preview = pending_preview(&record, &run_fd, &plan.driver_dir, loop_uid)?;
        return Ok(
            json!({"schema":1,"command":"checkpoint","loop":request.loop_name,"run":request.run,"dry_run":true,"pending":preview}),
        );
    }
    let home_parent = home::pin_parent(
        plan.home
            .parent()
            .ok_or_else(|| LaneError::input("checkpoint-path", "home parent is absent"))?,
        namespace_owner,
    )?;
    let home_fd = child(
        &home_parent,
        plan.home
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| LaneError::input("checkpoint-path", "home name is invalid"))?,
        &plan.home,
    )?;
    checked(&home_fd, &plan.home, namespace_owner, true, Some(0o750))?;
    let local_path = plan.home.join(".local");
    let local = child(&home_fd, ".local", &local_path)?;
    checked(&local, &local_path, namespace_owner, true, Some(0o750))?;
    let preserved_path = plan.driver_dir.join("preserved");
    let prior_preserved = optional_child(&run_fd, "preserved", &preserved_path)?;
    if let Some(fd) = &prior_preserved {
        checked(fd, &preserved_path, loop_uid, true, Some(0o700))?;
    }
    let mut index = 1_u64;
    if let Some(fd) = &prior_preserved {
        while index <= 1024
            && optional_child(
                fd,
                &index.to_string(),
                &preserved_path.join(index.to_string()),
            )?
            .is_some()
        {
            index += 1;
        }
    }
    if index > 1024 {
        return Err(LaneError::input(
            "checkpoint-size",
            "preserved indices are exhausted",
        ));
    }
    let target_path = preserved_path.join(index.to_string());
    let checkpoint_instant = if request.dry_run {
        None
    } else {
        Some(instant()?)
    };
    let marker = if request.dry_run {
        None
    } else {
        Some(PendingMarker {
            index,
            token: request.invocation_token.clone().ok_or_else(|| {
                LaneError::input("checkpoint-record", "invocation token is absent")
            })?,
        })
    };
    let mut pending_record = record.clone();
    if let Some(marker) = &marker {
        let mut capacity = record.clone();
        append_attempt(
            &mut capacity,
            Some(index),
            &marker.token,
            &"x".repeat(256),
            &"x".repeat(256),
            &ResidueObservation {
                present: Some(true),
                valid: false,
                path_error: Some("x".repeat(256)),
            },
        )?;
        capacity["checkpoint_pending"] = json!({"index":index,"token":marker.token});
        if u64::try_from(
            serde_json::to_vec(&capacity)
                .map_err(|error| LaneError::input("checkpoint-size", error.to_string()))?
                .len(),
        )
        .map_err(|error| LaneError::input("checkpoint-size", error.to_string()))?
            > MAX_RESERVATION_BYTES
        {
            return Err(LaneError::input(
                "checkpoint-size",
                "reservation has no room for a refusal record",
            ));
        }
        pending_record["checkpoint_pending"] = json!({"index":index,"token":marker.token});
        publish_reservation(&reservation, &pending_record)?;
    }
    let mut target_created = false;
    let result = (|| -> Result<Value, LaneError> {
        let preserved = if let Some(fd) = prior_preserved {
            Some(fd)
        } else if request.dry_run {
            None
        } else {
            Some(make_directory(
                &run_fd,
                "preserved",
                &preserved_path,
                loop_uid,
            )?)
        };
        let target = if request.dry_run {
            None
        } else {
            let made = make_directory(
                preserved.as_ref().ok_or_else(|| {
                    LaneError::operation("checkpoint-copy", "preserved directory is absent")
                })?,
                &index.to_string(),
                &target_path,
                loop_uid,
            )?;
            target_created = true;
            Some(made)
        };
        let mut files = Vec::new();
        let mut bares = Vec::new();
        for (name, owner, mode) in [
            ("inbox", namespace_owner, 0o750),
            ("outbox", worker, 0o750),
            ("sources", worker, 0o700),
        ] {
            let path = local_path.join(name);
            let source = child(&local, name, &path)?;
            if name == "sources" {
                checked_source(&source, &path, worker, Some(mode))?;
            } else {
                checked(&source, &path, owner, true, Some(mode))?;
            }
            let destination = target
                .as_ref()
                .map(|target| make_directory(target, name, &target_path.join(name), loop_uid))
                .transpose()?;
            if name == "sources" {
                for bare_name in directory_names(&source, &path)? {
                    let Some(repo) = bare_name.strip_suffix(".git") else {
                        return Err(refused(
                            "checkpoint-bare",
                            &path.join(bare_name),
                            "source is not a bare name",
                        ));
                    };
                    if !valid_run_name(repo) {
                        return Err(refused(
                            "checkpoint-bare",
                            &path.join(bare_name),
                            "bare name is invalid",
                        ));
                    }
                    let bare_path = path.join(&bare_name);
                    let bare = child(&source, &bare_name, &bare_path)?;
                    checked_source(&bare, &bare_path, worker, Some(0o700))?;
                    let object = checkpoint_ref(
                        &bare,
                        &request.run,
                        &bare_path,
                        worker,
                        &checkpoints,
                        repo,
                    )?;
                    let bare_target = destination
                        .as_ref()
                        .map(|destination| {
                            make_directory(
                                destination,
                                &bare_name,
                                &target_path.join(name).join(&bare_name),
                                loop_uid,
                            )
                        })
                        .transpose()?;
                    walk(
                        &bare,
                        bare_target.as_ref(),
                        &PathBuf::from(name).join(&bare_name),
                        worker,
                        loop_uid,
                        &mut files,
                        0,
                    )?;
                    for forbidden in [
                        "commondir",
                        "objects/info/alternates",
                        "objects/info/http-alternates",
                    ] {
                        let name = PathBuf::from("sources").join(&bare_name).join(forbidden);
                        if files
                            .iter()
                            .any(|file| file["path"].as_str() == name.to_str())
                        {
                            return Err(refused(
                                "checkpoint-bare",
                                &bare_path.join(forbidden),
                                "external object path is forbidden",
                            ));
                        }
                    }
                    let source = declared.iter().find(|item| item["name"] == repo);
                    if let Some(seed) = source.and_then(|item| item["seed"].as_str()) {
                        verify_seed_ref(&bare, &bare_path, repo, &request.run, seed)?;
                    }
                    if let Some(copy) = &bare_target {
                        verify_bare(
                            copy,
                            &target_path.join(name).join(&bare_name),
                            &request.run,
                            object.as_deref(),
                            loop_uid,
                        )?;
                        if let Some(seed) = source.and_then(|item| item["seed"].as_str()) {
                            verify_seed_ref(
                                copy,
                                &target_path.join(name).join(&bare_name),
                                repo,
                                &request.run,
                                seed,
                            )?;
                        }
                    }
                    bares.push(bare_ref_row(
                        repo,
                        source.is_some(),
                        source.map(|item| &item["seed"]),
                        object.as_deref(),
                    ));
                }
                refuse_missing_previous_bares(&checkpoints, &bares, &path)?;
                for declared_source in &declared {
                    if !declared_source["seed"].is_null()
                        && !bares
                            .iter()
                            .any(|bare| bare["name"] == declared_source["name"])
                    {
                        let name = declared_source["name"].as_str().ok_or_else(|| {
                            LaneError::input("checkpoint-record", "source name is absent")
                        })?;
                        return Err(refused(
                            "checkpoint-seed",
                            &path.join(format!("{name}.git")),
                            "declared seeded bare is absent",
                        ));
                    }
                }
            } else {
                walk(
                    &source,
                    destination.as_ref(),
                    Path::new(name),
                    owner,
                    loop_uid,
                    &mut files,
                    0,
                )?;
            }
        }
        let report = json!({"schema":1,"command":"checkpoint","loop":request.loop_name,"run":request.run,"dry_run":request.dry_run,"index":index,"preserved":target_path,"round_after":round,"files":files,"bares":bares});
        let report_size = serde_json::to_vec(&report)
            .map_err(|error| LaneError::operation("checkpoint-size", error.to_string()))?
            .len();
        if report_size > 1_500_000 {
            return Err(LaneError::input(
                "checkpoint-size",
                "checkpoint report exceeds private output bound",
            ));
        }
        if !request.dry_run {
            let mut completed = record.clone();
            let next_checkpoints = checkpoints_with_new_row(
                &record,
                json!({"index":index,"instant_unix_ns":checkpoint_instant,"round_after":round,"files":files,"bares":bares}),
            );
            completed["checkpoints"] = json!(next_checkpoints);
            publish_reservation(&reservation, &completed)?;
        }
        Ok(report)
    })();
    if let Err(error) = &result
        && !request.dry_run
    {
        let mut residue = residue_at(&run_fd, &plan.driver_dir, index, loop_uid)?;
        if target_created && residue.present == Some(false) {
            residue.valid = false;
            residue.path_error = Some(format!(
                "checkpoint-path: {}: preserved target disappeared before refusal record",
                target_path.display()
            ));
        }
        let marker = marker
            .as_ref()
            .ok_or_else(|| LaneError::input("checkpoint-record", "pending marker is absent"))?;
        record_failure(&reservation, &pending_record, marker, error, &residue)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        CheckpointRequest, PendingMarker, ResidueObservation, append_attempt, bare_ref_row,
        checked, checked_source, checkpoint_fields, checkpoint_locks, checkpoint_locks_at,
        checkpoint_ref, copy_file, declared_sources, digest, git_from_bare, pending_preview,
        record_failure, recover_private_failure, refuse_missing_previous_bares, residue_at,
        verify_bare, verify_seed_ref, walk,
    };
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::Path;
    use std::process::Command;

    /// ´test:unit:checkpoint-bare-record-carries-seed-and-refuses-malformed-shape´
    #[test]
    fn checkpoint_bare_record_carries_seed_and_refuses_malformed_shape() {
        let mut record = json!({"checkpoints":[{"index":1,"instant_unix_ns":2,"round_after":"dispatch","files":[],"bares":[{"name":"tools","declared":true,"seed":"a".repeat(40),"lane_ref":"present","object":"b".repeat(40)}]}]});
        assert_eq!(checkpoint_fields(&record).expect("seed record").1.len(), 1);
        record["checkpoints"][0]["bares"][0]["seed"] = Value::Null;
        assert_eq!(
            checkpoint_fields(&record).expect("explicit null").1.len(),
            1
        );
        for key in ["name", "declared", "seed", "object"] {
            let mut malformed = record.clone();
            malformed["checkpoints"][0]["bares"][0]
                .as_object_mut()
                .expect("bare row")
                .remove(key);
            assert_eq!(
                checkpoint_fields(&malformed).expect_err(key).kind,
                "checkpoint-record"
            );
        }
        let mut malformed = record;
        malformed["checkpoints"][0]["bares"][0]
            .as_object_mut()
            .expect("bare row")
            .remove("lane_ref");
        malformed["checkpoints"][0]["bares"][0]["unexpected"] = json!(true);
        assert_eq!(
            checkpoint_fields(&malformed)
                .expect_err("extra key does not make an old row")
                .kind,
            "checkpoint-record"
        );
    }

    /// ´test:unit:old-row-without-lane-ref-refuses-without-mutation´
    #[test]
    fn old_row_without_lane_ref_refuses_without_mutation() {
        let old = json!({"checkpoints":[{"index":1,"instant_unix_ns":2,"round_after":"dispatch","files":[],"bares":[{"name":"tools","declared":true,"seed":null,"object":"a".repeat(40)}]}]});
        let before = old.clone();
        let refusal = checkpoint_fields(&old).expect_err("four-field row is not version one");
        assert_eq!(refusal.kind, "checkpoint-record");
        assert_eq!(refusal.status, 2);
        assert_eq!(old, before);
        assert!(old["checkpoints"][0]["bares"][0].get("lane_ref").is_none());
        let mut absent_object = old;
        absent_object["checkpoints"][0]["bares"][0]["object"] = Value::Null;
        assert_eq!(
            checkpoint_fields(&absent_object)
                .expect_err("four-field row with absent object also refuses")
                .kind,
            "checkpoint-record"
        );
    }

    /// ´test:unit:checkpoint-readback-preserves-absent-ref´
    #[test]
    fn checkpoint_readback_preserves_absent_ref() {
        let (fixture, bare, _work) = readback_bare_fixture();
        let owner = nix::unistd::Uid::effective().as_raw();
        let held = directory(&bare);
        assert_eq!(
            checkpoint_ref(&held, "R", &bare, owner, &[], "tools").expect("unborn lane"),
            None
        );
        let copy = fixture.path().join("preserved.git");
        fs::create_dir(&copy).expect("preserved root");
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).expect("preserved mode");
        walk(
            &held,
            Some(&directory(&copy)),
            Path::new("sources/tools.git"),
            owner,
            owner,
            &mut Vec::new(),
            0,
        )
        .expect("preserve unborn bare");
        verify_bare(&directory(&copy), &copy, "R", None, owner)
            .expect("preserved bare has no lane ref");
        let row = bare_ref_row("tools", true, None, None);
        let record = json!({"checkpoints":[{"index":1,"instant_unix_ns":2,"round_after":"readback","files":[],"bares":[row]}]});
        assert_eq!(
            checkpoint_fields(&record)
                .expect("absent ref record")
                .1
                .len(),
            1
        );
        for (state, object) in [
            ("present", Value::Null),
            ("absent", json!("a".repeat(40))),
            ("unknown", Value::Null),
        ] {
            let mut malformed = record.clone();
            malformed["checkpoints"][0]["bares"][0]["lane_ref"] = json!(state);
            malformed["checkpoints"][0]["bares"][0]["object"] = object;
            assert_eq!(
                checkpoint_fields(&malformed).expect_err(state).kind,
                "checkpoint-record"
            );
        }
    }

    /// ´test:unit:checkpoint-later-ref-records-object´
    #[test]
    fn checkpoint_later_ref_records_object() {
        let (_fixture, bare, work) = readback_bare_fixture();
        let owner = nix::unistd::Uid::effective().as_raw();
        let absent = checkpoint_ref(&directory(&bare), "R", &bare, owner, &[], "tools")
            .expect("first readback");
        let previous = json!({"bares":[bare_ref_row("tools", true, None, absent.as_deref())]});
        let object = ship_fixture_ref(&bare, &work);
        assert_eq!(
            checkpoint_ref(&directory(&bare), "R", &bare, owner, &[previous], "tools")
                .expect("shipped ref"),
            Some(object.clone())
        );
        verify_bare(&directory(&bare), &bare, "R", Some(&object), owner)
            .expect("shipped object is connected");
        let row = bare_ref_row("tools", true, None, Some(&object));
        let record = json!({"checkpoints":[{"index":2,"instant_unix_ns":3,"round_after":"shipped","files":[],"bares":[row]}]});
        assert_eq!(
            checkpoint_fields(&record)
                .expect("present ref record")
                .1
                .len(),
            1
        );
    }

    /// ´test:unit:checkpoint-copy-changed-ref-refuses-before-connectivity´
    #[test]
    fn checkpoint_copy_changed_ref_refuses_before_connectivity() {
        let (fixture, bare, work) = readback_bare_fixture();
        let owner = nix::unistd::Uid::effective().as_raw();
        let object = ship_fixture_ref(&bare, &work);
        let copy = fixture.path().join("changed-copy.git");
        fs::create_dir(&copy).expect("copy root");
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o700)).expect("copy mode");
        walk(
            &directory(&bare),
            Some(&directory(&copy)),
            Path::new("sources/tools.git"),
            owner,
            owner,
            &mut Vec::new(),
            0,
        )
        .expect("copy shipped bare");
        fs::write(
            copy.join("refs/heads/lane/R"),
            format!("{}\n", "b".repeat(40)),
        )
        .expect("inject changed ref into copy");
        let refused = verify_bare(&directory(&copy), &copy, "R", Some(&object), owner)
            .expect_err("copied ref differs");
        assert_eq!(refused.kind, "checkpoint-ref");
        assert!(refused.detail.contains("copied ref"));
        assert!(refused.detail.contains("differs from"));
    }

    /// ´test:unit:checkpoint-old-record-refusal´
    #[test]
    fn checkpoint_old_record_refusal() {
        let (_fixture, bare, work) = readback_bare_fixture();
        let object = ship_fixture_ref(&bare, &work);
        let previous = json!({"bares":[bare_ref_row("tools", true, None, Some(&object))]});
        fs::remove_file(bare.join("refs/heads/lane/R")).expect("withdraw ref");
        let owner = nix::unistd::Uid::effective().as_raw();
        let refused = checkpoint_ref(&directory(&bare), "R", &bare, owner, &[previous], "tools")
            .expect_err("recorded ref disappeared");
        assert_eq!(refused.kind, "checkpoint-ref");
        assert!(refused.detail.contains("is absent"));
        let previous = json!({"bares":[bare_ref_row("tools", true, None, Some(&object))]});
        let missing_bare = refuse_missing_previous_bares(&[previous], &[], &bare)
            .expect_err("recorded bare disappeared");
        assert_eq!(missing_bare.kind, "checkpoint-ref");
    }

    /// ´test:unit:declared-source-row-requires-present-seed-fields´
    #[test]
    fn declared_source_row_requires_present_seed_fields() {
        let row =
            json!({"name":"tools","seed":null,"source_identity":null,"seeded_at_unix_ns":null});
        let record = json!({"declared_sources":[row]});
        assert_eq!(
            declared_sources(&record).expect("explicit nulls"),
            vec![row]
        );
        for key in ["seed", "source_identity", "seeded_at_unix_ns"] {
            let mut malformed = record.clone();
            malformed["declared_sources"][0]
                .as_object_mut()
                .expect("source row")
                .remove(key);
            assert_eq!(
                declared_sources(&malformed).expect_err(key).kind,
                "checkpoint-record"
            );
        }
        let mut extra = record;
        extra["declared_sources"][0]["legacy"] = json!(true);
        assert_eq!(
            declared_sources(&extra).expect_err("extra key").kind,
            "checkpoint-record"
        );
    }

    fn directory(path: &std::path::Path) -> std::os::fd::OwnedFd {
        nix::fcntl::open(
            path,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("directory descriptor")
    }

    fn fixture_git(path: &Path, args: &[&str]) -> String {
        let output = Command::new("/bin/sh")
            .args(["-c", "umask 022; exec /usr/bin/git \"$@\"", "git", "-C"])
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
            .expect("fixture Git starts");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("fixture Git output")
            .trim()
            .to_owned()
    }

    fn readback_bare_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let fixture = tempfile::tempdir().expect("fixture");
        let bare = fixture.path().join("tools.git");
        let work = fixture.path().join("work");
        fixture_git(
            fixture.path(),
            &["init", "--bare", bare.to_str().expect("bare path")],
        );
        fixture_git(&bare, &["symbolic-ref", "HEAD", "refs/heads/lane/R"]);
        fs::set_permissions(&bare, fs::Permissions::from_mode(0o700)).expect("bare mode");
        fs::set_permissions(bare.join("config"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
        fixture_git(fixture.path(), &["init", work.to_str().expect("work path")]);
        (fixture, bare, work)
    }

    fn ship_fixture_ref(bare: &Path, work: &Path) -> String {
        fs::write(work.join("letter"), b"shipped round\n").expect("fixture letter");
        fixture_git(work, &["add", "letter"]);
        fixture_git(work, &["commit", "-m", "shipped round"]);
        let object = fixture_git(work, &["rev-parse", "HEAD"]);
        fixture_git(
            work,
            &[
                "push",
                bare.to_str().expect("bare path"),
                "HEAD:refs/heads/lane/R",
            ],
        );
        object
    }

    fn marker(index: u64, token: &str) -> PendingMarker {
        PendingMarker {
            index,
            token: token.to_owned(),
        }
    }

    fn observation(present: bool) -> ResidueObservation {
        ResidueObservation {
            present: Some(present),
            valid: true,
            path_error: None,
        }
    }

    /// ´test:unit:checkpoint-request-needs-one-plain-run-and-optional-dry-run´
    #[test]
    fn checkpoint_request_needs_one_plain_run_and_optional_dry_run() {
        let request = CheckpointRequest::parse(&["alpha".into(), "R".into(), "--dry-run".into()])
            .expect("request");
        assert!(request.dry_run);
        for args in [
            vec!["alpha".into(), "../R".into()],
            vec![
                "alpha".into(),
                "R".into(),
                "--dry-run".into(),
                "--dry-run".into(),
            ],
        ] {
            assert_eq!(
                CheckpointRequest::parse(&args)
                    .expect_err("invalid request")
                    .kind,
                "checkpoint-usage"
            );
        }
    }

    /// ´test:unit:checkpoint-source-setgid-retains-owner-and-mode-pins´
    #[test]
    fn checkpoint_source_setgid_retains_owner_and_mode_pins() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("source");
        fs::create_dir(&source).expect("source");
        let source_fd = directory(&source);
        let source_owner = nix::unistd::Uid::effective().as_raw();
        for mode in [0o2700, 0o2750] {
            fs::set_permissions(&source, fs::Permissions::from_mode(mode)).expect("setgid source");
            checked_source(&source_fd, &source, source_owner, None).expect("setgid directory");
        }
        for mode in [0o2770, 0o4750, 0o1750] {
            fs::set_permissions(&source, fs::Permissions::from_mode(mode)).expect("unsafe source");
            assert_eq!(
                checked_source(&source_fd, &source, source_owner, None)
                    .expect_err("unsafe mode")
                    .kind,
                "checkpoint-path"
            );
        }
        fs::set_permissions(&source, fs::Permissions::from_mode(0o2750)).expect("safe source");
        let foreign = if source_owner == 3000 { 3001 } else { 3000 };
        let error = checked_source(&source_fd, &source, foreign, None)
            .expect_err("setgid does not relax owner");
        assert_eq!(error.kind, "checkpoint-path");
        assert!(
            error
                .detail
                .contains(&format!("uid {source_owner} mode 2750"))
        );
        assert!(error.detail.contains(&format!("expected uid {foreign}")));
        assert_eq!(
            checked(&source_fd, &source, source_owner, true, Some(0o750))
                .expect_err("home remains pinned")
                .kind,
            "checkpoint-path"
        );
        assert_eq!(
            checked(&source_fd, &source, source_owner, true, Some(0o700))
                .expect_err("loop directory remains pinned")
                .kind,
            "checkpoint-path"
        );
    }

    /// ´test:unit:checkpoint-source-walk-keeps-worker-and-loop-identities-distinct´
    #[test]
    fn checkpoint_source_walk_keeps_worker_and_loop_identities_distinct() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("source");
        fs::create_dir(&source).expect("source");
        let source_fd = directory(&source);
        let source_owner = nix::unistd::Uid::effective().as_raw();
        let foreign = if source_owner == 3000 { 3001 } else { 3000 };
        fs::create_dir(source.join("refs")).expect("source child");
        fs::set_permissions(source.join("refs"), fs::Permissions::from_mode(0o2750))
            .expect("setgid child");
        fs::write(source.join("refs/main"), b"source ref").expect("source content");
        fs::set_permissions(source.join("refs/main"), fs::Permissions::from_mode(0o600))
            .expect("source mode");
        let mut source_rows = Vec::new();
        walk(
            &source_fd,
            None,
            std::path::Path::new("sources/repo.git"),
            source_owner,
            foreign,
            &mut source_rows,
            0,
        )
        .expect("worker source walk");
        assert_eq!(
            source_rows,
            vec![serde_json::json!({"path":"sources/repo.git/refs/main","size":10,"sha256":null})]
        );
        assert_eq!(
            walk(
                &source_fd,
                None,
                std::path::Path::new("inbox"),
                source_owner,
                foreign,
                &mut Vec::new(),
                0
            )
            .expect_err("non-source walk remains strict")
            .kind,
            "checkpoint-path"
        );
        assert_eq!(
            walk(
                &source_fd,
                None,
                std::path::Path::new("sources/repo.git"),
                foreign,
                source_owner,
                &mut Vec::new(),
                0
            )
            .expect_err("foreign source owner")
            .kind,
            "checkpoint-path"
        );
    }

    /// ´test:unit:checkpoint-copy-checks-content-and-refuses-a-linked-entry´
    #[test]
    fn checkpoint_copy_checks_content_and_refuses_a_linked_entry() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("source");
        let target = fixture.path().join("target");
        fs::create_dir(&source).expect("source");
        fs::create_dir(&target).expect("target");
        fs::write(source.join("letter.md"), b"checkpoint letter\n").expect("letter");
        fs::set_permissions(source.join("letter.md"), fs::Permissions::from_mode(0o600))
            .expect("letter mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let mut files = Vec::new();
        walk(
            &directory(&source),
            Some(&directory(&target)),
            std::path::Path::new("inbox"),
            owner,
            owner,
            &mut files,
            0,
        )
        .expect("copy");
        assert_eq!(
            fs::read(target.join("letter.md")).expect("copied letter"),
            b"checkpoint letter\n"
        );
        assert_eq!(files[0]["size"], 18);
        assert_eq!(files[0]["sha256"].as_str().expect("digest").len(), 64);
        let letter_fd = nix::fcntl::open(
            &source.join("letter.md"),
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("letter descriptor");
        let sibling = if owner == 3000 { 3001 } else { 3000 };
        assert_eq!(
            checked(
                &letter_fd,
                &source.join("letter.md"),
                sibling,
                false,
                Some(0o600)
            )
            .expect_err("foreign owner")
            .kind,
            "checkpoint-path"
        );
        symlink(source.join("letter.md"), source.join("linked.md")).expect("link");
        assert_eq!(
            walk(
                &directory(&source),
                None,
                std::path::Path::new("inbox"),
                owner,
                owner,
                &mut Vec::new(),
                0
            )
            .expect_err("linked entry")
            .kind,
            "checkpoint-path"
        );
    }

    /// ´test:unit:copied-bare-refuses-a-remote-before-git-verification´
    #[test]
    fn copied_bare_refuses_a_remote_before_git_verification() {
        let fixture = tempfile::tempdir().expect("fixture");
        let bare = fixture.path().join("tools.git");
        fs::create_dir(&bare).expect("bare");
        fs::write(bare.join("config"), b"[remote \"origin\"]\n").expect("config");
        fs::set_permissions(bare.join("config"), fs::Permissions::from_mode(0o600))
            .expect("config mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        assert_eq!(
            verify_bare(&directory(&bare), &bare, "R", Some(&"a".repeat(40)), owner)
                .expect_err("remote")
                .kind,
            "checkpoint-bare"
        );
    }

    /// ´test:unit:seeded-bare-copy-keeps-lane-head-and-passes-object-check´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn seeded_bare_copy_keeps_lane_head_and_passes_object_check() {
        let fixture = tempfile::tempdir().expect("fixture");
        let bare = fixture.path().join("tools.git");
        let work = fixture.path().join("work");
        let copied = fixture.path().join("copy.git");
        let git = |path: &Path, args: &[&str]| {
            let output = Command::new("/bin/sh")
                .args(["-c", "umask 022; exec /usr/bin/git \"$@\"", "git", "-C"])
                .arg(path)
                .args(args)
                .env_clear()
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_ALLOW_PROTOCOL", "file")
                .env("GIT_AUTHOR_NAME", "Fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
                .env("GIT_COMMITTER_NAME", "Fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
                .output()
                .expect("fixture Git starts");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout)
                .expect("fixture Git output")
                .trim()
                .to_owned()
        };
        git(
            fixture.path(),
            &["init", "--bare", bare.to_str().expect("bare path")],
        );
        git(fixture.path(), &["init", work.to_str().expect("work path")]);
        fs::write(work.join("file"), b"seed\n").expect("seed file");
        git(&work, &["add", "file"]);
        git(&work, &["commit", "-m", "seed"]);
        let seed = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &[
                "push",
                bare.to_str().expect("bare path"),
                "HEAD:refs/seeds/tools",
            ],
        );
        git(&bare, &["symbolic-ref", "HEAD", "refs/heads/lane/R"]);
        let held = directory(&bare);
        let valid = git_from_bare(
            &held,
            &["fsck", "--connectivity-only", "--no-reflogs", &seed],
        )
        .expect("seed fsck starts");
        assert!(
            valid.status.success(),
            "{}",
            String::from_utf8_lossy(&valid.stderr)
        );
        fs::write(work.join("file"), b"lane\n").expect("lane file");
        git(&work, &["commit", "-am", "lane"]);
        let lane = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &[
                "push",
                bare.to_str().expect("bare path"),
                "HEAD:refs/heads/lane/R",
            ],
        );
        fs::create_dir(&copied).expect("preserved bare root");
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o700))
            .expect("preserved bare mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let mut files = Vec::new();
        walk(
            &held,
            Some(&directory(&copied)),
            Path::new("sources/tools.git"),
            owner,
            owner,
            &mut files,
            0,
        )
        .expect("preserve bare through held descriptors");
        assert!(
            files
                .iter()
                .any(|row| row["path"] == "sources/tools.git/HEAD")
        );
        assert_eq!(
            fs::read(copied.join("HEAD")).expect("preserved HEAD"),
            b"ref: refs/heads/lane/R\n"
        );
        let copy_fd = directory(&copied);
        git(&copied, &["symbolic-ref", "HEAD", "refs/seeds/tools"]);
        assert_eq!(git(&copied, &["symbolic-ref", "HEAD"]), "refs/seeds/tools");
        let invalid = git_from_bare(
            &copy_fd,
            &["fsck", "--connectivity-only", "--no-reflogs", &lane],
        )
        .expect("non-branch HEAD fsck starts");
        if invalid.status.success() {
            assert_eq!(
                verify_seed_ref(&copy_fd, &copied, "tools", "R", &seed)
                    .expect_err("non-branch HEAD")
                    .kind,
                "checkpoint-seed"
            );
        } else {
            assert!(String::from_utf8_lossy(&invalid.stderr).contains("badHeadTarget"));
        }
        git(&copied, &["symbolic-ref", "HEAD", "refs/heads/lane/R"]);
        verify_bare(&copy_fd, &copied, "R", Some(&lane), owner).expect("preserved object check");
        verify_seed_ref(&copy_fd, &copied, "tools", "R", &seed).expect("preserved seed and HEAD");
    }

    /// ´test:unit:checkpoint-record-measures-the-preserved-descriptor´
    #[test]
    fn checkpoint_record_measures_the_preserved_descriptor() {
        let fixture = tempfile::tempdir().expect("fixture");
        let source = fixture.path().join("source");
        let target = fixture.path().join("target");
        fs::create_dir(&source).expect("source");
        fs::create_dir(&target).expect("target");
        fs::write(source.join("letter.md"), b"first\n").expect("source letter");
        let owner = nix::unistd::Uid::effective().as_raw();
        let source_fd = nix::fcntl::open(
            source.join("letter.md").as_path(),
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("source descriptor");
        let (size, hash) = copy_file(
            &source_fd,
            &directory(&target),
            "letter.md",
            std::path::Path::new("inbox/letter.md"),
            owner,
        )
        .expect("copy");
        fs::write(source.join("letter.md"), b"a later, longer home letter\n")
            .expect("change source after copy");
        let copied_fd = nix::fcntl::open(
            target.join("letter.md").as_path(),
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("copied descriptor");
        assert_eq!(
            size,
            fs::metadata(target.join("letter.md"))
                .expect("copied metadata")
                .len()
        );
        assert_eq!(
            hash,
            digest(&copied_fd, std::path::Path::new("inbox/letter.md")).expect("copied digest")
        );
    }

    /// ´test:unit:checkpoint-seventeen-residues-retain-seventeen-attempts´
    #[test]
    fn checkpoint_seventeen_residues_retain_seventeen_attempts() {
        let mut record = json!({});
        for index in 1..=17 {
            append_attempt(
                &mut record,
                Some(index),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "checkpoint-copy",
                "copy failed",
                &observation(true),
            )
            .expect("attempt");
        }
        assert_eq!(
            record["checkpoint_attempts"]
                .as_array()
                .expect("attempts")
                .len(),
            17
        );
        assert_eq!(record["attempts_omitted"], 0);
        for index in 18..=35 {
            append_attempt(
                &mut record,
                Some(index),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "checkpoint-copy",
                "before copy",
                &observation(false),
            )
            .expect("attempt without residue");
        }
        assert_eq!(
            record["checkpoint_attempts"]
                .as_array()
                .expect("attempts")
                .len(),
            33
        );
        assert_eq!(record["attempts_omitted"], 2);
    }

    /// ´test:unit:checkpoint-malformed-protected-arrays-refuse-before-write´
    #[test]
    fn checkpoint_malformed_protected_arrays_refuse_before_write() {
        let fixture = tempfile::tempdir().expect("fixture");
        let reservation = fixture.path().join("reservation.json");
        fs::write(&reservation, b"unchanged protected record").expect("old record");
        for mut record in [
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoints":"bad"}),
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoint_attempts":"bad"}),
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoint_attempts":[{"instant_unix_ns":1,"state":"refused","refusal":"checkpoint-copy","detail":"bad","residue":false,"path_valid":true}]}),
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoint_attempts":[{"index":1,"instant_unix_ns":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"refused","refusal":"checkpoint-copy","detail":"bad","path_valid":false,"unexpected":null}]}),
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoint_attempts":[{"index":1,"instant_unix_ns":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"refused","refusal":"checkpoint-copy","detail":"bad","residue":null,"path_valid":true}]}),
            json!({"checkpoint_pending":{"index":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"checkpoint_attempts":[{"index":1,"instant_unix_ns":1,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"refused","refusal":"checkpoint-copy","detail":"bad","residue":"unknown","path_valid":false}]}),
        ] {
            let before = serde_json::to_vec(&record).expect("before");
            assert_eq!(
                checkpoint_fields(&record).expect_err("malformed").kind,
                "checkpoint-record"
            );
            assert_eq!(
                append_attempt(
                    &mut record,
                    Some(1),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "checkpoint-copy",
                    "test",
                    &observation(true)
                )
                .expect_err("malformed")
                .kind,
                "checkpoint-record"
            );
            assert_eq!(serde_json::to_vec(&record).expect("after"), before);
            assert_eq!(
                record_failure(
                    &reservation,
                    &record,
                    &marker(1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    &super::LaneError::input("checkpoint-copy", "test"),
                    &observation(true),
                )
                .expect_err("malformed write")
                .kind,
                "checkpoint-record"
            );
            assert_eq!(
                fs::read(&reservation).expect("reservation"),
                b"unchanged protected record"
            );
        }
    }

    /// ´test:unit:checkpoint-private-limit-records-index-refusal-and-limit´
    #[test]
    fn checkpoint_private_limit_records_index_refusal_and_limit() {
        let fixture = tempfile::tempdir().expect("fixture");
        let reservation = fixture.path().join("reservation.json");
        let run = fixture.path().join("driver");
        fs::create_dir(&run).expect("run");
        fs::create_dir(run.join("preserved")).expect("preserved");
        fs::create_dir(run.join("preserved/4")).expect("target");
        fs::set_permissions(run.join("preserved"), fs::Permissions::from_mode(0o700))
            .expect("preserved mode");
        fs::set_permissions(run.join("preserved/4"), fs::Permissions::from_mode(0o700))
            .expect("target mode");
        let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let record = json!({"checkpoint_pending":{"index":4,"token":token}});
        let error = super::LaneError::input("checkpoint-private", "300 second time limit");
        let owner = nix::unistd::Uid::effective().as_raw();
        let observed = residue_at(&directory(&run), &run, 4, owner).expect("residue");
        record_failure(&reservation, &record, &marker(4, token), &error, &observed)
            .expect("timeout attempt");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(&reservation).expect("reservation"))
                .expect("saved record");
        assert!(saved.get("checkpoint_pending").is_none());
        let attempt = &saved["checkpoint_attempts"][0];
        assert_eq!(attempt["index"], 4);
        assert_eq!(attempt["refusal"], "checkpoint-private");
        assert!(
            attempt["detail"]
                .as_str()
                .expect("detail")
                .contains("300 second time limit")
        );
        assert_eq!(attempt["residue"], true);
        let absent_record = json!({"checkpoint_pending":{"index":5,"token":token}});
        let absent = residue_at(&directory(&run), &run, 5, owner).expect("residue");
        assert_eq!(absent.present, Some(false));
        record_failure(
            &reservation,
            &absent_record,
            &marker(5, token),
            &error,
            &absent,
        )
        .expect("attempt without residue");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(&reservation).expect("reservation"))
                .expect("saved record");
        assert_eq!(saved["checkpoint_attempts"][0]["residue"], false);
    }

    /// ´test:unit:checkpoint-attempt-detail-fits-reserved-json-bytes´
    #[test]
    fn checkpoint_attempt_detail_fits_reserved_json_bytes() {
        for detail in ["é".repeat(200), "\"".repeat(200), "line\n".repeat(100)] {
            let mut record = json!({});
            append_attempt(
                &mut record,
                Some(1),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "checkpoint-copy",
                &detail,
                &observation(false),
            )
            .expect("attempt");
            let saved = record["checkpoint_attempts"][0]["detail"]
                .as_str()
                .expect("bounded detail");
            assert!(serde_json::to_string(saved).expect("JSON string").len() <= 258);
            assert!(detail.starts_with(saved));
        }
    }

    /// ´test:unit:checkpoint-pending-dry-preview-measures-residue-without-write´
    #[test]
    fn checkpoint_pending_dry_preview_measures_residue_without_write() {
        let fixture = tempfile::tempdir().expect("fixture");
        let run = fixture.path().join("driver");
        fs::create_dir(&run).expect("run");
        let reservation = fixture.path().join("reservation.json");
        let record =
            json!({"checkpoint_pending":{"index":4,"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}});
        let original = serde_json::to_vec(&record).expect("record");
        fs::write(&reservation, &original).expect("reservation");
        let owner = nix::unistd::Uid::effective().as_raw();
        let absent = pending_preview(&record, &directory(&run), &run, owner)
            .expect("preview")
            .expect("pending");
        assert_eq!(absent["index"], 4);
        assert_eq!(absent["token"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(absent["residue"], false);
        assert_eq!(absent["path_valid"], true);
        fs::create_dir(run.join("preserved")).expect("preserved");
        fs::create_dir(run.join("preserved/4")).expect("target");
        fs::set_permissions(run.join("preserved"), fs::Permissions::from_mode(0o700))
            .expect("preserved mode");
        fs::set_permissions(run.join("preserved/4"), fs::Permissions::from_mode(0o700))
            .expect("target mode");
        let present = pending_preview(&record, &directory(&run), &run, owner)
            .expect("preview")
            .expect("pending");
        assert_eq!(present["residue"], true);
        assert_eq!(fs::read(&reservation).expect("reservation"), original);
    }

    /// ´test:unit:checkpoint-recovery-refuses-an-interleaved-pending-token´
    #[test]
    fn checkpoint_recovery_refuses_an_interleaved_pending_token() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let reservation = super::reservation_path(fixture.path(), "R");
        let first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let second = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let record = json!({"schema":1,"phase":"settled","worker_uid":3000,"checkpoint_pending":{"index":4,"token":first}});
        super::publish_reservation(&reservation, &record).expect("first marker");
        let error = super::LaneError::input("checkpoint-private", "300 second time limit");
        let refused = recover_private_failure(fixture.path(), "R", first, &error, || {
            let (_preparation, _mailbox) =
                checkpoint_locks(fixture.path(), "R", owner, false)?;
            let mut newer = record.clone();
            newer["checkpoint_pending"]["token"] = json!(second);
            super::publish_reservation(&reservation, &newer)?;
            Ok(json!({"pending":{"index":4,"token":first,"residue":false,"path_valid":true,"path_error":null}}))
        })
        .expect_err("interleaved marker");
        assert_eq!(refused.kind, "checkpoint-record");
        assert!(refused.detail.contains(first));
        assert!(refused.detail.contains(second));
        let saved = super::read_reservation(&reservation)
            .expect("read")
            .expect("reservation");
        assert_eq!(saved["checkpoint_pending"]["token"], second);
        assert!(saved.get("checkpoint_attempts").is_none());
        let refused = recover_private_failure(fixture.path(), "R", first, &error, || {
            panic!("another invocation must not inspect the marker");
        })
        .expect_err("new marker already present");
        assert_eq!(refused.kind, "checkpoint-record");
        assert!(refused.detail.contains(first));
        assert!(refused.detail.contains(second));
        recover_private_failure(fixture.path(), "R", second, &error, || {
            Ok(json!({"pending":{"index":4,"token":second,"residue":false,"path_valid":true,"path_error":null}}))
        })
        .expect("second marker recovered");
        let saved = super::read_reservation(&reservation)
            .expect("read")
            .expect("reservation");
        assert!(saved.get("checkpoint_pending").is_none());
        assert_eq!(saved["checkpoint_attempts"][0]["token"], second);
    }

    /// ´test:unit:checkpoint-recovery-records-an-untraversable-preserved-parent´
    #[test]
    fn checkpoint_recovery_records_an_untraversable_preserved_parent() {
        for kind in ["file", "link"] {
            let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
                .expect("root mode");
            let run = fixture.path().join("driver");
            fs::create_dir(&run).expect("driver");
            fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("driver mode");
            let preserved = run.join("preserved");
            if kind == "file" {
                fs::write(&preserved, b"not a directory").expect("regular parent");
            } else {
                symlink("elsewhere", &preserved).expect("linked parent");
            }
            let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            let reservation = super::reservation_path(fixture.path(), "R");
            let record = json!({"schema":1,"phase":"settled","worker_uid":3000,"checkpoint_pending":{"index":4,"token":token}});
            super::publish_reservation(&reservation, &record).expect("pending marker");
            let owner = nix::unistd::Uid::effective().as_raw();
            let preview = pending_preview(&record, &directory(&run), &run, owner)
                .expect("path preview")
                .expect("pending preview");
            assert_eq!(preview["residue"], serde_json::Value::Null);
            assert_eq!(preview["path_valid"], false);
            let error = super::LaneError::input("checkpoint-private", "300 second time limit");
            recover_private_failure(fixture.path(), "R", token, &error, || {
                let preview = pending_preview(&record, &directory(&run), &run, owner)?;
                Ok(json!({"pending":preview}))
            })
            .expect("indexed refusal");
            let saved = super::read_reservation(&reservation)
                .expect("read")
                .expect("reservation");
            assert!(saved.get("checkpoint_pending").is_none());
            let attempt = &saved["checkpoint_attempts"][0];
            assert_eq!(attempt["index"], 4);
            assert_eq!(attempt["residue"], serde_json::Value::Null);
            assert_eq!(attempt["path_valid"], false);
            assert_eq!(attempt["refusal"], "checkpoint-path");
            assert!(
                attempt["detail"]
                    .as_str()
                    .expect("detail")
                    .contains("preserved")
            );
            checkpoint_fields(&saved).expect("uncertain residue remains readable");
        }
    }

    /// ´test:unit:checkpoint-rejected-directory-remains-an-explained-residue´
    #[test]
    fn checkpoint_rejected_directory_remains_an_explained_residue() {
        let fixture = tempfile::tempdir().expect("fixture");
        let run = fixture.path().join("driver");
        fs::create_dir(&run).expect("run");
        fs::create_dir(run.join("preserved")).expect("preserved");
        fs::create_dir(run.join("preserved/4")).expect("target");
        fs::set_permissions(run.join("preserved"), fs::Permissions::from_mode(0o700))
            .expect("preserved mode");
        fs::set_permissions(run.join("preserved/4"), fs::Permissions::from_mode(0o755))
            .expect("rejected mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let observed = residue_at(&directory(&run), &run, 4, owner).expect("observed path");
        assert_eq!(observed.present, Some(true));
        assert!(!observed.valid);
        let token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let record = json!({"checkpoint_pending":{"index":4,"token":token}});
        let reservation = fixture.path().join("reservation.json");
        record_failure(
            &reservation,
            &record,
            &marker(4, token),
            &super::LaneError::input("checkpoint-copy", "post-create check failed"),
            &observed,
        )
        .expect("record invalid residue");
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(reservation).expect("reservation"))
                .expect("saved record");
        let attempt = &saved["checkpoint_attempts"][0];
        assert_eq!(attempt["residue"], true);
        assert_eq!(attempt["path_valid"], false);
        assert_eq!(attempt["refusal"], "checkpoint-path");
        fs::remove_dir(run.join("preserved/4")).expect("remove fixture target");
        fs::set_permissions(run.join("preserved"), fs::Permissions::from_mode(0o755))
            .expect("rejected parent mode");
        let parent_observed =
            residue_at(&directory(&run), &run, 5, owner).expect("observed rejected parent");
        assert_eq!(parent_observed.present, None);
        assert!(!parent_observed.valid);
        let mut journal = json!({});
        for index in 1..=17 {
            append_attempt(
                &mut journal,
                Some(index),
                token,
                "checkpoint-path",
                "rejected preserved directory",
                &parent_observed,
            )
            .expect("retained invalid path");
        }
        assert_eq!(
            journal["checkpoint_attempts"]
                .as_array()
                .expect("attempts")
                .len(),
            17
        );
        assert_eq!(journal["attempts_omitted"], 0);
    }

    /// ´test:unit:checkpoint-dry-locks-refuse-absent-files-without-creating-them´
    #[test]
    fn checkpoint_dry_locks_refuse_absent_files_without_creating_them() {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("runs root");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let owner = nix::unistd::Uid::effective().as_raw();
        let reservation = super::reservation_path(fixture.path(), "R");
        let bytes = serde_json::to_vec(&json!({"schema":1,"phase":"settled","worker_uid":3000}))
            .expect("protected record");
        fs::write(&reservation, &bytes).expect("reservation");
        fs::set_permissions(&reservation, fs::Permissions::from_mode(0o600))
            .expect("reservation mode");
        assert!(
            super::read_reservation(&reservation)
                .expect("read")
                .is_some()
        );
        assert_eq!(
            checkpoint_locks(fixture.path(), "R", owner, true)
                .expect_err("missing preparation lock")
                .kind,
            "checkpoint-record"
        );
        assert!(!fixture.path().join(".prepare-R.lock").exists());
        assert!(!fixture.path().join(".letter-R.lock").exists());
        let preparation = fixture.path().join(".prepare-R.lock");
        fs::write(&preparation, b"").expect("preparation lock");
        fs::set_permissions(&preparation, fs::Permissions::from_mode(0o600)).expect("lock mode");
        assert_eq!(
            checkpoint_locks(fixture.path(), "R", owner, true)
                .expect_err("missing mailbox lock")
                .kind,
            "checkpoint-record"
        );
        assert!(!fixture.path().join(".letter-R.lock").exists());
        assert_eq!(fs::read(reservation).expect("reservation"), bytes);
        let root = directory(fixture.path());
        assert_eq!(
            checkpoint_locks_at(&root, "R", owner, true)
                .expect_err("mailbox remains absent")
                .kind,
            "checkpoint-record"
        );
        assert!(!fixture.path().join(".letter-R.lock").exists());
        let mailbox = fixture.path().join(".letter-R.lock");
        fs::write(&mailbox, b"").expect("mailbox lock");
        fs::set_permissions(&mailbox, fs::Permissions::from_mode(0o600)).expect("mailbox mode");
        let _locks = checkpoint_locks_at(&root, "R", owner, true).expect("dry descriptor locks");
    }
}
