use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::gateway::Gateway;
use crate::types::{Operation, OperationResult, Refusal, RefusalRule, Registration};

static TEMP_INDEX_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl Gateway {
    pub(crate) fn push_registration(
        &self,
        registration: &Registration,
        seq: u64,
        started: Instant,
    ) -> OperationResult {
        match self.try_push(registration) {
            Ok(success) => OperationResult::success(
                seq,
                Operation::Push,
                elapsed_millis(started),
                Some(success.commit_id),
                success.stdout,
                success.stderr,
            ),
            Err(failure) => {
                let refusal = Refusal::new(failure.rule)
                    .with_seq(seq)
                    .with_paths(failure.paths);
                let mut result = OperationResult::refused(
                    Some(seq),
                    Some(Operation::Push),
                    elapsed_millis(started),
                    refusal,
                    failure.stdout,
                    failure.stderr,
                );
                result.exit_code = failure.exit_code;
                result
            }
        }
    }

    fn try_push(&self, registration: &Registration) -> Result<PushSuccess, PushFailure> {
        let mut work = PushWork::default();
        let snapshot =
            match snapshot_worktree(&mut work, registration, &self.state_dir().join("tmp")) {
                Ok(snapshot) => snapshot,
                Err(exit_code) => {
                    return Err(work.failure(RefusalRule::SnapshotFailed, exit_code, Vec::new()));
                }
            };

        // Entry 23: resolve the registered package allowlist against the
        // snapshot that a roster command actually runs against, not the
        // registered base commit. A lane whose deliverable is a brand-new
        // package would otherwise never resolve: the package cannot exist at
        // the base commit that predates it.
        let package_paths = match resolve_package_paths(&mut work, registration, &snapshot) {
            Ok(paths) => paths,
            Err(exit_code) => {
                return Err(work.failure(
                    RefusalRule::PackageAllowlistUnresolved,
                    exit_code,
                    Vec::new(),
                ));
            }
        };

        // Entry 24: push always admits the whole worktree — the ratified
        // contract makes push unbudgeted and unscoped, rate limiting aside.
        // Scope enforcement belongs to run admission and the orchestrator's
        // own diff audit, not to transport. The registered base is kept only
        // to annotate, not block, snapshot changes outside the allowlist.
        match changed_paths(&mut work, registration, &snapshot) {
            Ok(diff_paths) => {
                let offending: Vec<_> = diff_paths
                    .into_iter()
                    .filter(|path| !path_is_allowed(path, &package_paths))
                    .collect();
                if !offending.is_empty() {
                    let mut note = String::new();
                    let _ = write!(
                        note,
                        "note: snapshot changes {} path(s) outside the registered package \
                         allowlist (informational only, not enforced at push): {}",
                        offending.len(),
                        offending.join(", ")
                    );
                    work.note_stdout(&note);
                }
            }
            Err(exit_code) => {
                return Err(work.failure(RefusalRule::SnapshotFailed, exit_code, Vec::new()));
            }
        }

        let mut refspec = OsString::from(snapshot.as_str());
        refspec.push(":refs/lanes/gateway/");
        refspec.push(registration.lane.as_str());
        let push_arguments = vec![
            OsString::from("push"),
            OsString::from("--quiet"),
            OsString::from("--force"),
            OsString::from("--"),
            OsString::from(registration.mirror_remote.as_str()),
            refspec,
        ];
        if let Err(command) = work.git(&registration.worktree, push_arguments, None, false) {
            return Err(work.failure(RefusalRule::MirrorPushFailed, command.exit_code, Vec::new()));
        }

        let (stdout, stderr) = work.transcript.into_strings();
        Ok(PushSuccess {
            commit_id: snapshot,
            stdout,
            stderr,
        })
    }
}

fn snapshot_worktree(
    work: &mut PushWork,
    registration: &Registration,
    temporary_directory: &Path,
) -> Result<String, i32> {
    let git_dir_output = work
        .git(
            &registration.worktree,
            arguments(["rev-parse", "--absolute-git-dir"]),
            None,
            false,
        )
        .map_err(|command| command.exit_code)?;
    let git_dir = output_line(&git_dir_output.stdout)
        .map(PathBuf::from)
        .map_err(|message| {
            work.note_error(message);
            1
        })?;
    let head = git_object_id(
        work,
        &registration.worktree,
        arguments(["rev-parse", "--verify", "HEAD"]),
        None,
        false,
    )?;

    let temporary = TemporaryIndex::new(temporary_directory).map_err(|error| {
        work.note_io_error(&error);
        1
    })?;
    fs::copy(git_dir.join("index"), temporary.path()).map_err(|error| {
        work.note_io_error(&error);
        1
    })?;
    let placeholders = placeholder_paths(work, &registration.worktree)?;
    let mut add_arguments = arguments(["add", "--all", "--", "."]);
    for path in &placeholders {
        add_arguments.push(OsString::from(format!(":(exclude,literal){path}")));
    }
    let _staged = work
        .git(
            &registration.worktree,
            add_arguments,
            Some(temporary.path()),
            false,
        )
        .map_err(|command| command.exit_code)?;
    if !placeholders.is_empty() {
        let mut note = String::new();
        let _ = write!(
            note,
            "note: omitted {} sandbox placeholder path(s) from snapshot",
            placeholders.len()
        );
        work.note_stdout(&note);
    }
    let _transport_excluded = work
        .git(
            &registration.worktree,
            arguments([
                "rm",
                "--cached",
                "--quiet",
                "--ignore-unmatch",
                "-r",
                "--",
                ".lane",
            ]),
            Some(temporary.path()),
            false,
        )
        .map_err(|command| command.exit_code)?;
    let tree = git_object_id(
        work,
        &registration.worktree,
        arguments(["write-tree"]),
        Some(temporary.path()),
        false,
    )?;

    let mut message = String::from("lane-gateway snapshot: ");
    message.push_str(&registration.lane);
    git_object_id(
        work,
        &registration.worktree,
        vec![
            OsString::from("commit-tree"),
            OsString::from(tree),
            OsString::from("-p"),
            OsString::from(head),
            OsString::from("-m"),
            OsString::from(message),
        ],
        None,
        true,
    )
}

/// Find paths that a sandbox may have mounted over its temporary worktree.
///
/// Git cannot stage device nodes, FIFOs, or sockets. An untracked zero-byte
/// regular file below a hidden top-level path component is the regular-file placeholder
/// a masked mount leaves, while a tracked empty dotfile remains intentional.
fn placeholder_paths(work: &mut PushWork, worktree: &Path) -> Result<Vec<String>, i32> {
    let tracked = listed_paths(work, worktree, arguments(["ls-files", "--cached", "-z"]))?;
    let tracked: BTreeSet<_> = tracked.into_iter().collect();
    let mut candidates = listed_paths(
        work,
        worktree,
        arguments([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ]),
    )?;
    candidates.extend(special_paths(work, worktree)?);
    candidates.sort();
    candidates.dedup();
    let mut placeholders = Vec::new();
    for path in candidates {
        if Path::new(&path).starts_with(".lane") {
            continue;
        }
        let metadata = match fs::symlink_metadata(worktree.join(&path)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                work.note_io_error(&error);
                return Err(1);
            }
        };
        let kind = metadata.file_type();
        let special = is_special_file(kind);
        let masked_dotfile = kind.is_file()
            && metadata.len() == 0
            && !tracked.contains(&path)
            && Path::new(&path).components().next().is_some_and(|component| {
                matches!(component, Component::Normal(name) if name.as_encoded_bytes().starts_with(b"."))
            });
        if special || masked_dotfile {
            placeholders.push(path);
        }
    }
    Ok(placeholders)
}

/// Git's untracked listing omits special nodes, so inspect directory entries
/// for that rare case before invoking `git add` on the whole worktree.
fn special_paths(work: &mut PushWork, worktree: &Path) -> Result<Vec<String>, i32> {
    let mut directories = vec![worktree.to_path_buf()];
    let mut special = Vec::new();
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(directory).map_err(|error| {
            work.note_io_error(&error);
            1
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                work.note_io_error(&error);
                1
            })?;
            let path = entry.path();
            let relative = path.strip_prefix(worktree).map_err(|_error| 1)?;
            if relative.starts_with(".git")
                || relative.starts_with(".lane")
                || relative == Path::new("target")
            {
                continue;
            }
            let kind = entry.file_type().map_err(|error| {
                work.note_io_error(&error);
                1
            })?;
            if kind.is_dir() {
                directories.push(path);
            } else if is_special_file(kind) {
                let name = relative.to_str().ok_or_else(|| {
                    work.note_error("sandbox placeholder path is not valid UTF-8");
                    1
                })?;
                special.push(name.to_owned());
            }
        }
    }
    Ok(special)
}

pub fn is_special_file(kind: fs::FileType) -> bool {
    kind.is_char_device() || kind.is_fifo() || kind.is_socket()
}

fn listed_paths(
    work: &mut PushWork,
    worktree: &Path,
    arguments: Vec<OsString>,
) -> Result<Vec<String>, i32> {
    let output = git_output(worktree, arguments, None, false).map_err(|error| {
        work.note_io_error(&error);
        1
    })?;
    if !output.status.success() {
        work.transcript.record(&output);
        return Err(output.status.code().unwrap_or(1));
    }
    nul_strings(&output.stdout).map_err(|message| {
        work.note_error(message);
        1
    })
}

fn git_object_id(
    work: &mut PushWork,
    worktree: &Path,
    arguments: Vec<OsString>,
    temporary_index: Option<&Path>,
    identity: bool,
) -> Result<String, i32> {
    let output = work
        .git(worktree, arguments, temporary_index, identity)
        .map_err(|command| command.exit_code)?;
    object_id(&output.stdout).map_err(|message| {
        work.note_error(message);
        1
    })
}

fn resolve_package_paths(
    work: &mut PushWork,
    registration: &Registration,
    treeish: &str,
) -> Result<Vec<PathBuf>, i32> {
    let list_arguments = vec![
        OsString::from("ls-tree"),
        OsString::from("-r"),
        OsString::from("-z"),
        OsString::from("--name-only"),
        OsString::from(treeish),
        OsString::from("--"),
    ];
    let listing = work
        .git(&registration.worktree, list_arguments, None, false)
        .map_err(|command| command.exit_code)?;
    let manifest_paths = nul_strings(&listing.stdout).map_err(|message| {
        work.note_error(message);
        1
    })?;
    let wanted: BTreeSet<_> = registration.packages.iter().map(String::as_str).collect();
    let mut matches: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    let mut discovered: Vec<(String, PathBuf)> = Vec::new();

    for manifest_path in manifest_paths
        .iter()
        .filter(|path| Path::new(path).file_name() == Some(OsStr::new("Cargo.toml")))
    {
        let mut object = OsString::from(treeish);
        object.push(":");
        object.push(manifest_path.as_str());
        let show_arguments = vec![OsString::from("cat-file"), OsString::from("blob"), object];
        let manifest = work
            .git(&registration.worktree, show_arguments, None, false)
            .map_err(|command| command.exit_code)?;
        let Ok(source) = std::str::from_utf8(&manifest.stdout) else {
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(source) else {
            continue;
        };
        let Some(name) = value
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        let parent = Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        discovered.push((name.to_owned(), parent.to_path_buf()));
        if wanted.contains(name) {
            matches
                .entry(name.to_owned())
                .or_default()
                .push(parent.to_path_buf());
        }
    }

    let mut paths = Vec::with_capacity(registration.packages.len());
    for package in &registration.packages {
        let Some(found) = matches.get(package.as_str()) else {
            work.note_error(&absent_package_message(package, &discovered));
            return Err(1);
        };
        let [path] = found.as_slice() else {
            work.note_error("registered package name is not unique in the pushed snapshot");
            return Err(1);
        };
        paths.push(path.clone());
    }
    Ok(paths)
}

/// Diagnostic for a registered package absent from the resolved tree.
///
/// Entry 23 (near-miss): a registration can name a package by its directory
/// name where the actual Cargo package name differs, and a bare "absent"
/// refusal gives no hint of the mistake. This names the cargo package names
/// actually found under directories whose basename matches the registered
/// name, or whose own package name contains it, so a typo like `project-a`
/// versus `example-project-a` is diagnosed in the same round trip.
fn absent_package_message(missing: &str, discovered: &[(String, PathBuf)]) -> String {
    let mut candidates: BTreeSet<&str> = BTreeSet::new();
    for (name, directory) in discovered {
        let basename_matches = directory
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|basename| basename == missing);
        let name_is_a_near_miss = name != missing && name.contains(missing);
        if basename_matches || name_is_a_near_miss {
            candidates.insert(name.as_str());
        }
    }

    let mut message = String::from("registered package is absent from the pushed snapshot");
    if !candidates.is_empty() {
        let names = candidates.into_iter().collect::<Vec<_>>().join(", ");
        let _ = write!(
            message,
            "; closest-matching directories carry cargo package name(s): {names}"
        );
    }
    message
}

fn changed_paths(
    work: &mut PushWork,
    registration: &Registration,
    snapshot: &str,
) -> Result<Vec<String>, i32> {
    let arguments = vec![
        OsString::from("diff"),
        OsString::from("--name-only"),
        OsString::from("--no-renames"),
        OsString::from("-z"),
        OsString::from(registration.base_commit.as_str()),
        OsString::from(snapshot),
        OsString::from("--"),
    ];
    let output = work
        .git(&registration.worktree, arguments, None, false)
        .map_err(|command| command.exit_code)?;
    nul_strings(&output.stdout).map_err(|message| {
        work.note_error(message);
        1
    })
}

fn path_is_allowed(path: &str, package_paths: &[PathBuf]) -> bool {
    let path = Path::new(path);
    let is_repo_relative = !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::CurDir | Component::Normal(_)));
    is_repo_relative
        && (path.starts_with(Path::new(".lane"))
            || package_paths.iter().any(|prefix| path.starts_with(prefix)))
}

fn arguments<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.into_iter().map(OsString::from).collect()
}

fn output_line(bytes: &[u8]) -> Result<&str, &'static str> {
    let value = std::str::from_utf8(bytes).map_err(|_error| "Git output is not valid UTF-8")?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        Err("Git returned an empty output value")
    } else {
        Ok(value)
    }
}

fn object_id(bytes: &[u8]) -> Result<String, &'static str> {
    let value = output_line(bytes)?;
    if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(value.to_owned())
    } else {
        Err("Git returned an invalid object identifier")
    }
}

fn nul_strings(bytes: &[u8]) -> Result<Vec<String>, &'static str> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_error| "Git returned a non-UTF-8 repository path")
        })
        .collect()
}

#[derive(Default)]
struct PushWork {
    transcript: GitTranscript,
}

impl PushWork {
    fn git(
        &mut self,
        worktree: &Path,
        arguments: Vec<OsString>,
        temporary_index: Option<&Path>,
        identity: bool,
    ) -> Result<Output, FailedCommand> {
        let output = git_output(worktree, arguments, temporary_index, identity);
        match output {
            Ok(output) => {
                self.transcript.record(&output);
                if output.status.success() {
                    Ok(output)
                } else {
                    Err(FailedCommand {
                        exit_code: output.status.code().unwrap_or(1),
                    })
                }
            }
            Err(error) => {
                self.note_io_error(&error);
                Err(FailedCommand { exit_code: 1 })
            }
        }
    }

    fn note_error(&mut self, message: &str) {
        self.transcript.stderr.extend_from_slice(message.as_bytes());
        self.transcript.stderr.push(b'\n');
    }

    fn note_stdout(&mut self, message: &str) {
        self.transcript.stdout.extend_from_slice(message.as_bytes());
        self.transcript.stdout.push(b'\n');
    }

    fn note_io_error(&mut self, error: &io::Error) {
        self.note_error(&error.to_string());
    }

    fn failure(self, rule: RefusalRule, exit_code: i32, paths: Vec<String>) -> PushFailure {
        let (stdout, stderr) = self.transcript.into_strings();
        PushFailure {
            rule,
            paths,
            exit_code,
            stdout,
            stderr,
        }
    }
}

fn git_output(
    worktree: &Path,
    arguments: Vec<OsString>,
    temporary_index: Option<&Path>,
    identity: bool,
) -> io::Result<Output> {
    let mut command = Command::new("git");
    command.arg("-C").arg(worktree).args(arguments);
    for variable in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ] {
        command.env_remove(variable);
    }
    command.env("LC_ALL", "C");
    if let Some(index) = temporary_index {
        command.env("GIT_INDEX_FILE", index);
    }
    if identity {
        command
            .env("GIT_AUTHOR_NAME", "lane-gateway")
            .env("GIT_AUTHOR_EMAIL", "lane-gateway@localhost")
            .env("GIT_COMMITTER_NAME", "lane-gateway")
            .env("GIT_COMMITTER_EMAIL", "lane-gateway@localhost");
    }
    command.output()
}

#[derive(Default)]
struct GitTranscript {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl GitTranscript {
    fn record(&mut self, output: &Output) {
        self.stdout.extend_from_slice(&output.stdout);
        self.stderr.extend_from_slice(&output.stderr);
    }

    fn into_strings(self) -> (String, String) {
        (
            String::from_utf8_lossy(&self.stdout).into_owned(),
            String::from_utf8_lossy(&self.stderr).into_owned(),
        )
    }
}

struct TemporaryIndex {
    path: PathBuf,
}

impl TemporaryIndex {
    fn new(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let sequence = TEMP_INDEX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("index-{}-{sequence}", std::process::id()));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryIndex {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.path));
    }
}

struct FailedCommand {
    exit_code: i32,
}

struct PushSuccess {
    commit_id: String,
    stdout: String,
    stderr: String,
}

struct PushFailure {
    rule: RefusalRule,
    paths: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

pub fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
