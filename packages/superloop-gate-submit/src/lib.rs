#![doc = include_str!("../README.md")]

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_REMOTE: &str = "shared";
const REPORT_FALLBACK_NAME: &str = "unknown";
const TAIL_LINES: usize = 60;

/// Process status for green gates followed by one or more failed branch pushes.
pub const VERIFIED_PUSH_FAILURE_STATUS: u8 = 3;

static NEXT_TEMP_INDEX: AtomicU64 = AtomicU64::new(0);

/// Fixed usage diagnostic for invalid arguments or unsafe report/script tokens.
pub const USAGE_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: invalid command-line arguments\n";

/// Fixed usage diagnostic when the server profile has no SSH alias.
pub const MISSING_SSH_ALIAS_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: LANE_VERIFY_SSH is required\n";

/// Fixed usage diagnostic when the server profile has no clone path.
pub const MISSING_CLONE_PATH_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: LANE_VERIFY_CLONE is required\n";

/// Fixed usage diagnostic when the server profile has no remote runner.
pub const MISSING_REMOTE_RUNNER_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: LANE_VERIFY_REMOTE_RUNNER is required\n";

/// Fixed usage diagnostic when the server profile has no Rust environment path.
pub const MISSING_RUST_ENV_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: LANE_VERIFY_RUST_ENV is required\n";

/// Fixed usage diagnostic when a requested post-gate push has no source branch.
pub const DETACHED_HEAD_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: usage_error: --push-remote requires an attached HEAD\n";

/// Fixed status-two refusal for a committed-head checkout with local changes.
pub const DIRTY_CHECKOUT_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: dirty_checkout: committed-head checkout is dirty\n";

/// Fixed status-two refusal when HEAD is not the requested lane ref.
pub const HEAD_MISMATCH_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: head_mismatch: HEAD is not the committed-head ref\n";

/// Fixed status-two refusal when Git cannot inspect the committed checkout.
pub const COMMITTED_HEAD_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: committed_head: checkout inspection failed\n";

/// Fixed failure diagnostic for temporary-index or Git object creation errors.
pub const SNAPSHOT_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: snapshot_failure: worktree snapshot failed\n";

/// Fixed failure diagnostic for hub transport errors.
pub const PUSH_DIAGNOSTIC: &[u8] = b"superloop-gate-submit: push_failure: snapshot push failed\n";

/// Fixed failure diagnostic for a committed object push.
pub const COMMITTED_PUSH_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: push_failure: committed head push failed\n";

/// Fixed failure diagnostic when the committed head does not descend from its seed, in the external checkout or in the server's bound seed result.
pub const SEED_ANCESTRY_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: seed_ancestry: checked-out lane commit does not descend from seed\n";

/// Fixed failure diagnostic when the server seed result cannot be classified.
pub const SEED_RESULT_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: seed_result_failure: server seed result could not be verified\n";

/// Fixed failure diagnostic when local Git cannot perform the seed check.
pub const SEED_CHECK_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: seed_check_failure: local Git ancestry check failed\n";

/// Fixed failure diagnostic for SSH execution or undeclared remote statuses.
pub const REMOTE_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: remote_failure: remote verification failed\n";

/// Fixed failure diagnostic emitted after a suppressed panic.
pub const INTERNAL_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: internal_failure: unexpected internal failure\n";

/// Fixed fallback diagnostic when the owned standard-output stream rejects data.
pub const PUBLICATION_DIAGNOSTIC: &[u8] =
    b"superloop-gate-submit: publication_failure: agent-text publication failed\n";

/// Fully parsed verifier configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    packages: Vec<String>,
    name: String,
    worktree: PathBuf,
    all_features: bool,
    doc_check: bool,
    release_build: bool,
    server: ServerProfile,
    hub_remote: OsString,
    target_dir: Option<String>,
    push_remotes: Vec<String>,
    branch: Option<OsString>,
    committed_head: Option<CommittedHead>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedHead {
    ref_name: String,
    object: String,
    seed_object: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ServerProfile {
    ssh_alias: OsString,
    clone_path: String,
    remote_runner: OsString,
    rust_env: String,
}

impl Config {
    /// Report identity selected by `-n` or the canonical worktree basename.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Stable argument-rejection class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentError {
    /// The command-line shape or one of its governed tokens is invalid.
    Invalid,
    /// The required SSH alias is absent.
    MissingSshAlias,
    /// The required server clone path is absent.
    MissingClonePath,
    /// The required remote runner invocation is absent.
    MissingRemoteRunner,
    /// The required Rust environment setup path is absent.
    MissingRustEnv,
    /// A post-gate push was requested from a detached worktree.
    DetachedHead,
    /// A committed checkout contains staged, tracked, or nonignored untracked changes.
    DirtyCheckout,
    /// HEAD does not name the requested lane branch.
    HeadMismatch,
    /// Git could not inspect the committed checkout.
    CommittedHead,
}

impl ArgumentError {
    /// Fixed, classed, path-free diagnostic for this rejection.
    #[must_use]
    pub const fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::Invalid => USAGE_DIAGNOSTIC,
            Self::MissingSshAlias => MISSING_SSH_ALIAS_DIAGNOSTIC,
            Self::MissingClonePath => MISSING_CLONE_PATH_DIAGNOSTIC,
            Self::MissingRemoteRunner => MISSING_REMOTE_RUNNER_DIAGNOSTIC,
            Self::MissingRustEnv => MISSING_RUST_ENV_DIAGNOSTIC,
            Self::DetachedHead => DETACHED_HEAD_DIAGNOSTIC,
            Self::DirtyCheckout => DIRTY_CHECKOUT_DIAGNOSTIC,
            Self::HeadMismatch => HEAD_MISMATCH_DIAGNOSTIC,
            Self::CommittedHead => COMMITTED_HEAD_DIAGNOSTIC,
        }
    }
}

/// Stable failure stage for one attempted verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// The temporary-index snapshot could not be created.
    Snapshot,
    /// The snapshot could not be pushed to the configured hub remote.
    Push,
    /// The committed head could not be pushed to the configured hub remote.
    CommittedPush,
    /// The committed head does not descend from its recorded seed, in the external checkout or in the server's bound seed result.
    SeedAncestry,
    /// Local Git could not complete the seed check.
    SeedCheck,
    /// SSH could not be run or returned an undeclared status.
    Remote,
}

impl FailureKind {
    /// Fixed, classed, path-free diagnostic for this stage; evidence may carry a path.
    #[must_use]
    pub const fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::Snapshot => SNAPSHOT_DIAGNOSTIC,
            Self::Push => PUSH_DIAGNOSTIC,
            Self::CommittedPush => COMMITTED_PUSH_DIAGNOSTIC,
            Self::SeedAncestry => SEED_ANCESTRY_DIAGNOSTIC,
            Self::SeedCheck => SEED_CHECK_DIAGNOSTIC,
            Self::Remote => REMOTE_DIAGNOSTIC,
        }
    }
}

/// Successful remote execution and the governed status it returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteResult {
    evidence: Vec<u8>,
    status: u8,
    object: Option<String>,
}

impl RemoteResult {
    /// Tail-selected merged remote evidence.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Declared verifier status: gate status 0, 1, or 2, or post-gate push
    /// failure status 3.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Server-reported checked-out object in committed-head mode.
    #[must_use]
    pub fn object(&self) -> Option<&str> {
        self.object.as_deref()
    }
}

/// A classed verifier failure retaining local command or I/O evidence, or remote
/// evidence received before the failure was classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyFailure {
    kind: FailureKind,
    evidence: Vec<u8>,
}

impl VerifyFailure {
    /// Stable failure class.
    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    /// The tool's own words: a local command's stderr or exit status, an I/O error's text, or
    /// remote evidence; it may carry a path, unlike the fixed diagnostic.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
}

/// Parse command arguments, excluding the program name, and the governed
/// environment configuration.
///
/// Invalid report tokens, package tokens, clone paths, worktree identities, and
/// non-Unicode script fields are rejected as usage errors. When post-gate pushes
/// are requested, the worktree branch is resolved before snapshot construction.
///
/// # Errors
///
/// Returns a named missing-profile error when any required server field is
/// absent, [`ArgumentError::Invalid`] for invalid input, and
/// [`ArgumentError::DetachedHead`] when a post-gate push has no source branch.
pub fn parse_args<I, A>(arguments: I) -> Result<Config, ArgumentError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let server = server_profile_from_environment()?;
    let mut config = parse_config(arguments, server).ok_or(ArgumentError::Invalid)?;
    if let Some(committed) = &mut config.committed_head {
        committed.object = inspect_committed_head(&config.worktree, &committed.ref_name)?;
    }
    if !config.push_remotes.is_empty() {
        config.branch = Some(current_branch(&config.worktree).ok_or(ArgumentError::DetachedHead)?);
    }
    Ok(config)
}

fn parse_config<I, A>(arguments: I, server: ServerProfile) -> Option<Config>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    let ParsedOptions {
        packages,
        name,
        all_features,
        doc_check,
        release_build,
        push_remotes,
        committed_head,
        seed_object,
        positional,
    } = parse_options(&arguments)?;

    let package_text = packages?.into_string().ok()?;
    let packages = package_text
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if packages.is_empty() || packages.iter().any(|package| !valid_token(package)) {
        return None;
    }

    let worktree = fs::canonicalize(positional?).ok()?;
    if !worktree.is_dir() {
        return None;
    }
    let name = match name {
        Some(name) => name.into_string().ok()?,
        None => worktree.file_name()?.to_str()?.to_owned(),
    };
    if !valid_token(&name) {
        return None;
    }

    let hub_remote = environment_or_default("LANE_VERIFY_REMOTE", DEFAULT_REMOTE);
    let target_dir = match std::env::var_os("LANE_VERIFY_TARGET_DIR") {
        Some(value) if !value.is_empty() => Some(value.into_string().ok()?),
        Some(_) | None => None,
    };
    if target_dir
        .as_deref()
        .is_some_and(|path| !valid_clone_path(path))
    {
        return None;
    }

    Some(Config {
        packages,
        name,
        worktree,
        all_features,
        doc_check,
        release_build,
        server,
        hub_remote,
        target_dir,
        push_remotes,
        branch: None,
        committed_head: committed_head.map(|ref_name| CommittedHead {
            ref_name,
            object: String::new(),
            seed_object,
        }),
    })
}

fn server_profile_from_environment() -> Result<ServerProfile, ArgumentError> {
    let ssh_alias = required_environment("LANE_VERIFY_SSH", ArgumentError::MissingSshAlias)?;
    let clone_path = required_environment("LANE_VERIFY_CLONE", ArgumentError::MissingClonePath)?
        .into_string()
        .map_err(|_value| ArgumentError::Invalid)?;
    let remote_runner = required_environment(
        "LANE_VERIFY_REMOTE_RUNNER",
        ArgumentError::MissingRemoteRunner,
    )?;
    let rust_env = required_environment("LANE_VERIFY_RUST_ENV", ArgumentError::MissingRustEnv)?
        .into_string()
        .map_err(|_value| ArgumentError::Invalid)?;

    if !ssh_alias.to_str().is_some_and(valid_token)
        || !valid_clone_path(&clone_path)
        || !remote_runner.to_str().is_some_and(valid_remote_runner)
        || !valid_clone_path(&rust_env)
    {
        return Err(ArgumentError::Invalid);
    }

    Ok(ServerProfile {
        ssh_alias,
        clone_path,
        remote_runner,
        rust_env,
    })
}

fn required_environment(variable: &str, missing: ArgumentError) -> Result<OsString, ArgumentError> {
    match std::env::var_os(variable) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) | None => Err(missing),
    }
}

/// Snapshot, push, and remotely verify the parsed worktree.
///
/// # Errors
///
/// Returns a stable [`VerifyFailure`] when snapshot construction, hub transport,
/// SSH execution, or remote-status validation fails. Temporary-index cleanup is
/// completed by an owning guard on every return and unwind path.
pub fn execute(config: &Config) -> Result<RemoteResult, VerifyFailure> {
    check_seed_ancestor(config)?;
    let object = match &config.committed_head {
        Some(committed) => OsString::from(&committed.object),
        None => snapshot(config)?,
    };
    push_snapshot(config, &object)?;
    let mut result = run_remote(config)?;
    if result.status != 0 || config.push_remotes.is_empty() {
        return Ok(result);
    }
    push_verified_branches(config, &mut result);
    Ok(result)
}

fn check_seed_ancestor(config: &Config) -> Result<(), VerifyFailure> {
    let Some(committed) = &config.committed_head else {
        return Ok(());
    };
    let Some(seed) = committed.seed_object.as_deref() else {
        return Ok(());
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(&config.worktree)
        .args(["merge-base", "--is-ancestor", seed, &committed.object])
        .output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) if output.status.code() == Some(1) => Err(VerifyFailure {
            kind: FailureKind::SeedAncestry,
            evidence: Vec::new(),
        }),
        Ok(output) => {
            let object = format!("{seed}^{{commit}}");
            let probe = Command::new("git")
                .arg("-C")
                .arg(&config.worktree)
                .args(["rev-parse", "--verify", "--quiet", &object])
                .output();
            if probe
                .as_ref()
                .is_ok_and(|probe| probe.status.code() == Some(1))
            {
                return Err(VerifyFailure {
                    kind: FailureKind::SeedAncestry,
                    evidence: Vec::new(),
                });
            }
            Err(command_failure(
                FailureKind::SeedCheck,
                "merge-base",
                &output,
            ))
        }
        Err(error) => Err(classed_failure(
            FailureKind::SeedCheck,
            "merge-base",
            error.to_string().as_bytes(),
        )),
    }
}

/// Publish evidence, an optional fixed diagnostic, and the verifier's final
/// report to one agent-text stream.
///
/// An unterminated evidence tail receives one separating LF so the report remains
/// one physical line. No byte is authored after the report's terminating LF.
///
/// # Errors
///
/// Returns an I/O error if any output byte or the final flush is rejected.
pub fn publish<W: io::Write>(
    output: &mut W,
    evidence: &[u8],
    diagnostic: Option<&[u8]>,
    name: &str,
    status: u8,
    wall: Duration,
) -> io::Result<()> {
    publish_with_object(output, evidence, diagnostic, name, status, wall, None)
}

/// Publish one committed-head report with the object reported by the server.
///
/// # Errors
///
/// Returns an I/O error if publication or flush fails.
pub fn publish_with_object<W: io::Write>(
    output: &mut W,
    evidence: &[u8],
    diagnostic: Option<&[u8]>,
    name: &str,
    status: u8,
    wall: Duration,
    object: Option<&str>,
) -> io::Result<()> {
    output.write_all(evidence)?;
    if !evidence.is_empty() && !evidence.ends_with(b"\n") {
        output.write_all(b"\n")?;
    }
    if let Some(diagnostic) = diagnostic {
        output.write_all(diagnostic)?;
    }
    let verdict = match status {
        0 => "ok",
        VERIFIED_PUSH_FAILURE_STATUS => "PUSH-FAILED",
        _ => "FAILED",
    };
    if let Some(object) = object {
        writeln!(
            output,
            "RUN-REPORT lane=verify-{name} exit={status} wall={}s verdict={verdict} ref=refs/lanes/verify-{name} object={object}",
            wall.as_secs()
        )?;
    } else {
        writeln!(
            output,
            "RUN-REPORT lane=verify-{name} exit={status} wall={}s verdict={verdict} ref=refs/lanes/verify-{name}",
            wall.as_secs()
        )?;
    }
    output.flush()
}

/// Fallback report identity for failures before valid arguments exist.
#[must_use]
pub const fn fallback_name() -> &'static str {
    REPORT_FALLBACK_NAME
}

#[derive(Debug)]
struct ParsedOptions {
    packages: Option<OsString>,
    name: Option<OsString>,
    all_features: bool,
    doc_check: bool,
    release_build: bool,
    push_remotes: Vec<String>,
    committed_head: Option<String>,
    seed_object: Option<String>,
    positional: Option<OsString>,
}

#[allow(clippy::too_many_lines)]
fn parse_options(arguments: &[OsString]) -> Option<ParsedOptions> {
    let mut packages = None;
    let mut name = None;
    let mut all_features = false;
    let mut doc_check = false;
    let mut release_build = false;
    let mut push_remotes = Vec::new();
    let mut committed_head = None;
    let mut seed_object = None;
    let mut index = 0_usize;

    while let Some(argument) = arguments.get(index) {
        let text = argument.to_str()?;
        if text == "--" {
            index += 1;
            break;
        }
        if text == "--release-build" {
            release_build = true;
            index += 1;
            continue;
        }
        if text == "--committed-head" {
            index += 1;
            let ref_name = arguments.get(index)?.to_str()?;
            if !valid_committed_ref(ref_name)
                || committed_head.replace(ref_name.to_owned()).is_some()
            {
                return None;
            }
            index += 1;
            continue;
        }
        if text == "--seed-object" {
            index += 1;
            let seed = arguments.get(index)?.to_str()?;
            if seed.len() != 40
                || !seed.bytes().all(|byte| byte.is_ascii_hexdigit())
                || seed_object.replace(seed.to_ascii_lowercase()).is_some()
            {
                return None;
            }
            index += 1;
            continue;
        }
        if text == "--push-remote" {
            index += 1;
            let remote = arguments.get(index)?.to_str()?;
            if !valid_remote_name(remote) {
                return None;
            }
            push_remotes.push(remote.to_owned());
            index += 1;
            continue;
        }
        if text == "-" || !text.starts_with('-') {
            break;
        }
        if text[1..].is_empty() {
            break;
        }
        for (offset, option) in text[1..].char_indices() {
            match option {
                'A' => all_features = true,
                'D' => doc_check = true,
                'p' | 'n' => {
                    let remainder_start = 1 + offset + option.len_utf8();
                    let value = if remainder_start < text.len() {
                        OsString::from(&text[remainder_start..])
                    } else {
                        index += 1;
                        arguments.get(index)?.clone()
                    };
                    if option == 'p' {
                        packages = Some(value);
                    } else {
                        name = Some(value);
                    }
                    break;
                }
                _ => return None,
            }
        }
        index += 1;
    }

    if seed_object.is_some() && committed_head.is_none() {
        return None;
    }
    let positional = match arguments.get(index..) {
        Some([only]) => Some(only.clone()),
        _ => return None,
    };
    Some(ParsedOptions {
        packages,
        name,
        all_features,
        doc_check,
        release_build,
        push_remotes,
        committed_head,
        seed_object,
        positional,
    })
}

fn valid_committed_ref(ref_name: &str) -> bool {
    ref_name
        .strip_prefix("refs/heads/lane/")
        .is_some_and(valid_token)
}

fn inspect_committed_head(worktree: &Path, ref_name: &str) -> Result<String, ArgumentError> {
    let status = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .map_err(|_error| ArgumentError::CommittedHead)?;
    if !status.status.success() {
        return Err(ArgumentError::CommittedHead);
    }
    if !status.stdout.is_empty() {
        return Err(ArgumentError::DirtyCheckout);
    }
    let head_ref = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()
        .map_err(|_error| ArgumentError::CommittedHead)?;
    if !head_ref.status.success() || trim_line_end(&head_ref.stdout) != ref_name.as_bytes() {
        return Err(ArgumentError::HeadMismatch);
    }
    let object = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|_error| ArgumentError::CommittedHead)?;
    if !object.status.success() {
        return Err(ArgumentError::CommittedHead);
    }
    let object = std::str::from_utf8(trim_line_end(&object.stdout))
        .map_err(|_error| ArgumentError::CommittedHead)?;
    if !valid_object(object) {
        return Err(ArgumentError::CommittedHead);
    }
    Ok(object.to_owned())
}

fn valid_object(object: &str) -> bool {
    matches!(object.len(), 40 | 64) && object.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn environment_or_default(variable: &str, default: &str) -> OsString {
    match std::env::var_os(variable) {
        Some(value) if !value.is_empty() => value,
        _ => OsString::from(default),
    }
}

fn valid_token(token: &str) -> bool {
    let mut bytes = token.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_clone_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
}

fn valid_remote_runner(runner: &str) -> bool {
    !runner.is_empty()
        && !runner.starts_with(' ')
        && !runner.ends_with(' ')
        && runner.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_' | b' ')
        })
}

fn valid_remote_name(remote: &str) -> bool {
    let mut bytes = remote.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn current_branch(worktree: &Path) -> Option<OsString> {
    let output = Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let branch = trim_line_end(&output.stdout);
    if branch.is_empty() {
        return None;
    }
    Some(OsString::from_vec(branch.to_vec()))
}

fn snapshot(config: &Config) -> Result<OsString, VerifyFailure> {
    let head = git_value(
        Command::new("git")
            .arg("-C")
            .arg(&config.worktree)
            .args(["rev-parse", "HEAD"]),
        "git rev-parse HEAD",
    )?;
    let git_dir = git_value(
        Command::new("git")
            .arg("-C")
            .arg(&config.worktree)
            .args(["rev-parse", "--absolute-git-dir"]),
        "git rev-parse --absolute-git-dir",
    )?;
    let mut temporary_index = TempIndex::create().map_err(|error| {
        classed_failure(
            FailureKind::Snapshot,
            "temporary index",
            error.to_string().as_bytes(),
        )
    })?;
    temporary_index
        .copy_from(Path::new(&git_dir).join("index"))
        .map_err(|error| {
            classed_failure(
                FailureKind::Snapshot,
                "temporary index",
                error.to_string().as_bytes(),
            )
        })?;

    require_success(
        Command::new("git")
            .current_dir(&config.worktree)
            .env("GIT_INDEX_FILE", temporary_index.path())
            .args(["add", "-A", "."]),
        FailureKind::Snapshot,
        "git add -A .",
    )?;
    let tree = git_value(
        Command::new("git")
            .current_dir(&config.worktree)
            .env("GIT_INDEX_FILE", temporary_index.path())
            .arg("write-tree"),
        "git write-tree",
    )?;
    let snapshot = git_value(
        Command::new("git")
            .current_dir(&config.worktree)
            .arg("commit-tree")
            .arg(tree)
            .arg("-p")
            .arg(head)
            .arg("-m")
            .arg(format!("superloop-gate-submit snapshot: {}", config.name)),
        "git commit-tree",
    )?;
    Ok(snapshot)
}

fn git_value(command: &mut Command, step: &str) -> Result<OsString, VerifyFailure> {
    let output = command.output().map_err(|error| {
        classed_failure(FailureKind::Snapshot, step, error.to_string().as_bytes())
    })?;
    if !output.status.success() {
        return Err(command_failure(FailureKind::Snapshot, step, &output));
    }
    let value = trim_line_end(&output.stdout);
    if value.is_empty() {
        return Err(classed_failure(
            FailureKind::Snapshot,
            step,
            b"empty output",
        ));
    }
    Ok(OsString::from_vec(value.to_vec()))
}

fn push_snapshot(config: &Config, snapshot: &OsStr) -> Result<(), VerifyFailure> {
    let ref_name = format!("refs/lanes/verify-{}", config.name);
    let refspec = {
        let mut refspec = snapshot.to_os_string();
        refspec.push(":");
        refspec.push(ref_name);
        refspec
    };
    require_success(
        Command::new("git")
            .arg("-C")
            .arg(&config.worktree)
            .args(["push", "-q", "-f"])
            .arg(&config.hub_remote)
            .arg(refspec),
        if config.committed_head.is_some() {
            FailureKind::CommittedPush
        } else {
            FailureKind::Push
        },
        "git push",
    )
}

fn push_verified_branches(config: &Config, result: &mut RemoteResult) {
    let Some(branch) = config.branch.as_deref() else {
        return;
    };
    let mut refspec = OsString::from("HEAD:");
    refspec.push(branch);
    let mut any_failed = false;
    for remote in &config.push_remotes {
        let started = Instant::now();
        let success = Command::new("git")
            .current_dir(&config.worktree)
            .arg("push")
            .arg(remote)
            .arg(&refspec)
            .output()
            .is_ok_and(|output| output.status.success());
        let wall = started.elapsed();
        append_push_report(&mut result.evidence, remote, success, wall);
        any_failed |= !success;
    }
    if any_failed {
        result.status = VERIFIED_PUSH_FAILURE_STATUS;
    }
}

fn append_push_report(evidence: &mut Vec<u8>, remote: &str, success: bool, wall: Duration) {
    if !evidence.is_empty() && !evidence.ends_with(b"\n") {
        evidence.push(b'\n');
    }
    let verdict = if success { "ok" } else { "FAILED" };
    writeln!(
        evidence,
        "PUSH-REPORT remote={remote} wall={}.{:03}s verdict={verdict}",
        wall.as_secs(),
        wall.subsec_millis()
    )
    .expect("writing to a byte vector cannot fail");
}

fn require_success(
    command: &mut Command,
    kind: FailureKind,
    step: &str,
) -> Result<(), VerifyFailure> {
    match command.output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(command_failure(kind, step, &output)),
        Err(error) => Err(classed_failure(kind, step, error.to_string().as_bytes())),
    }
}

fn command_failure(kind: FailureKind, step: &str, output: &Output) -> VerifyFailure {
    let reason = if output.stderr.is_empty() {
        output.status.to_string().into_bytes()
    } else {
        tail_lines(&output.stderr, TAIL_LINES)
    };
    classed_failure(kind, step, &reason)
}

fn run_remote(config: &Config) -> Result<RemoteResult, VerifyFailure> {
    let probe = config
        .committed_head
        .as_ref()
        .map(|_| probe_token())
        .transpose()?;
    let script = remote_script(config, probe.as_deref());
    let (mut reader, writer) = UnixStream::pair().map_err(|_error| remote_failure(Vec::new()))?;
    let stderr_writer = writer
        .try_clone()
        .map_err(|_error| remote_failure(Vec::new()))?;
    let stdout_fd: OwnedFd = writer.into();
    let stderr_fd: OwnedFd = stderr_writer.into();
    let mut child = Command::new("ssh")
        .arg(&config.server.ssh_alias)
        .arg(&config.server.remote_runner)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_fd))
        .stderr(Stdio::from(stderr_fd))
        .spawn()
        .map_err(|_error| remote_failure(Vec::new()))?;

    let stdin_result = child
        .stdin
        .take()
        .ok_or_else(|| remote_failure(Vec::new()))
        .and_then(|mut stdin| {
            stdin
                .write_all(script.as_bytes())
                .map_err(|_error| remote_failure(Vec::new()))
        });
    let mut output = Vec::new();
    let read_result = reader.read_to_end(&mut output);
    let status_result = child.wait();
    if stdin_result.is_err() || read_result.is_err() || status_result.is_err() {
        return Err(remote_failure(tail_lines(&output, TAIL_LINES)));
    }

    let evidence = tail_lines(&output, TAIL_LINES);
    match status_result.ok().and_then(|status| status.code()) {
        Some(status @ 0..=2) => {
            let object = config
                .committed_head
                .as_ref()
                .map(|committed| {
                    checked_out_object(&evidence, committed, probe.as_deref().unwrap_or_default())
                })
                .transpose();
            if object
                .as_ref()
                .is_err_and(|reason| *reason == "checked_out_drift")
            {
                let mut drift_evidence = evidence;
                if !drift_evidence.ends_with(b"\n") {
                    drift_evidence.push(b'\n');
                }
                drift_evidence.extend_from_slice(
                    b"superloop-gate-submit: checked_out_drift: server checkout changed during the gate\n",
                );
                return Ok(RemoteResult {
                    evidence: tail_lines(&drift_evidence, TAIL_LINES),
                    status: u8::try_from(status.max(1)).unwrap_or(1),
                    object: None,
                });
            }
            let object = object.map_err(|reason| checked_out_failure(evidence.clone(), reason))?;
            Ok(classified_remote_result(
                config
                    .committed_head
                    .as_ref()
                    .and_then(|committed| committed.seed_object.as_deref()),
                evidence,
                u8::try_from(status).unwrap_or(1),
                object,
                probe.as_deref().unwrap_or_default(),
            ))
        }
        _ => Err(remote_failure(evidence)),
    }
}

fn classified_remote_result(
    seed: Option<&str>,
    mut evidence: Vec<u8>,
    status: u8,
    object: Option<String>,
    token: &str,
) -> RemoteResult {
    let Some(seed) = seed else {
        return RemoteResult {
            evidence,
            status,
            object,
        };
    };
    let ancestry = seed_ancestry_result(
        &evidence,
        seed,
        object.as_deref().unwrap_or_default(),
        token,
    );
    if ancestry == Ok(true) {
        return RemoteResult {
            evidence,
            status,
            object,
        };
    }
    if !evidence.ends_with(b"\n") {
        evidence.push(b'\n');
    }
    match ancestry {
        Ok(false) => evidence.extend_from_slice(FailureKind::SeedAncestry.diagnostic()),
        Err(reason) => {
            writeln!(
                evidence,
                "superloop-gate-submit: {reason}: {}",
                seed_reason_detail(reason)
            )
            .expect("writing to a byte vector cannot fail");
            evidence.extend_from_slice(SEED_RESULT_DIAGNOSTIC);
        }
        Ok(true) => unreachable!("successful seed result returned above"),
    }
    RemoteResult {
        evidence,
        status: 1,
        object,
    }
}

fn seed_reason_detail(reason: &str) -> &'static str {
    match reason {
        "seed_ancestry_missing" => "server seed result line is absent",
        "seed_ancestry_unbound" => "server seed result has another invocation token",
        "seed_ancestry_mismatch" => "server seed result names another object or seed",
        "seed_ancestry_malformed" => "server seed result is malformed or duplicated",
        "seed_ancestry_server_error" => "server Git could not check ancestry",
        "seed_ancestry_server_missing" => "server did not measure seed ancestry",
        _ => "server seed result is unclassified",
    }
}

fn checked_out_object(
    evidence: &[u8],
    committed: &CommittedHead,
    token: &str,
) -> Result<String, &'static str> {
    for line in evidence.split(|byte| *byte == b'\n') {
        if let Some(reported) = line.strip_prefix(b"CHECKED-OUT-DRIFT token=") {
            if reported != token.as_bytes() {
                return Err("checked_out_unbound");
            }
            return Err("checked_out_drift");
        }
    }
    let lines = evidence
        .split(|byte| *byte == b'\n')
        .filter(|line| line.starts_with(b"CHECKED-OUT "))
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Err("checked_out_missing");
    }
    let mut found = None;
    for line in lines {
        let line = std::str::from_utf8(line).map_err(|_error| "checked_out_malformed")?;
        let (object, remainder) = line
            .strip_prefix("CHECKED-OUT object=")
            .and_then(|line| line.split_once(" ref="))
            .ok_or("checked_out_malformed")?;
        let (ref_name, reported_token) = remainder
            .split_once(" token=")
            .ok_or("checked_out_unbound")?;
        if reported_token != token {
            return Err("checked_out_unbound");
        }
        if !valid_object(object) || ref_name != committed.ref_name {
            return Err("checked_out_malformed");
        }
        if object != committed.object {
            return Err("checked_out_mismatch");
        }
        if found.replace(object.to_owned()).is_some() {
            return Err("checked_out_malformed");
        }
    }
    found.ok_or("checked_out_missing")
}

fn checked_out_failure(mut evidence: Vec<u8>, reason: &str) -> VerifyFailure {
    if !evidence.is_empty() && !evidence.ends_with(b"\n") {
        evidence.push(b'\n');
    }
    writeln!(
        evidence,
        "superloop-gate-submit: {reason}: server object did not match the pushed head"
    )
    .expect("writing to a byte vector cannot fail");
    remote_failure(tail_lines(&evidence, TAIL_LINES))
}

fn seed_ancestry_result(
    evidence: &[u8],
    seed: &str,
    object: &str,
    token: &str,
) -> Result<bool, &'static str> {
    let mut found = None;
    for line in evidence
        .split(|byte| *byte == b'\n')
        .filter(|line| line.starts_with(b"SEED-ANCESTRY "))
    {
        let line = std::str::from_utf8(line).map_err(|_| "seed_ancestry_malformed")?;
        let (reported_object, remainder) = line
            .strip_prefix("SEED-ANCESTRY object=")
            .and_then(|line| line.split_once(" seed="))
            .ok_or("seed_ancestry_malformed")?;
        let (reported_seed, remainder) = remainder
            .split_once(" token=")
            .ok_or("seed_ancestry_malformed")?;
        let (reported_token, result) = remainder
            .split_once(" result=")
            .ok_or("seed_ancestry_unbound")?;
        if reported_token != token {
            return Err("seed_ancestry_unbound");
        }
        if reported_object != object || reported_seed != seed {
            return Err("seed_ancestry_mismatch");
        }
        let descends = match result {
            "descendant" => true,
            "foreign" => false,
            "error" => return Err("seed_ancestry_server_error"),
            "missing" => return Err("seed_ancestry_server_missing"),
            _ => return Err("seed_ancestry_malformed"),
        };
        if found.replace(descends).is_some() {
            return Err("seed_ancestry_malformed");
        }
    }
    found.ok_or("seed_ancestry_missing")
}

fn seed_check_script(seed: &str) -> String {
    let mut script = String::from("echo '== seed =='\n");
    writeln!(&mut script, "if git merge-base --is-ancestor '{seed}' \"$checked_out\"; then seed_result=descendant; else seed_status=$?; if [ \"$seed_status\" -eq 1 ]; then seed_result=foreign; else seed_result=error; fi; exit 1; fi")
        .expect("writing to a String cannot fail");
    script
}

fn remote_script(config: &Config, probe: Option<&str>) -> String {
    let ref_name = format!("refs/lanes/verify-{}", config.name);
    let mut package_arguments = String::new();
    for package in &config.packages {
        write!(&mut package_arguments, " -p {package}").expect("writing to a String cannot fail");
    }
    let all_features = if config.all_features {
        "--all-features"
    } else {
        ""
    };

    let mut script = String::new();
    writeln!(
        &mut script,
        "set -e; . {}; cd {}",
        config.server.rust_env, config.server.clone_path
    )
    .expect("writing to a String cannot fail");
    script.push_str("# gate sampler begin\n");
    script.push_str(
        include_str!("../../../infra/gate/run-slot.sh")
            .split("# END GATE SAMPLER")
            .next()
            .unwrap_or_default(),
    );
    script.push_str("samp_init\nsamp gate start\ntrap 'status=$?; samp_finish; exit \"$status\"' EXIT\n# gate sampler end\n");
    writeln!(&mut script, "git fetch -q origin '+{ref_name}:{ref_name}'")
        .expect("writing to a String cannot fail");
    writeln!(
        &mut script,
        "git checkout -qf --detach {ref_name} && git clean -qfdx"
    )
    .expect("writing to a String cannot fail");
    script.push_str("locked_flag=\n");
    script.push_str(
        "if git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1; then locked_flag=--locked; fi\n",
    );
    script.push_str("# superloop-gate-submit target-dir begin\n");
    if let Some(target_dir) = &config.target_dir {
        writeln!(&mut script, "export CARGO_TARGET_DIR='{target_dir}'")
            .expect("writing to a String cannot fail");
    } else {
        script.push_str("checkout_path=$(pwd -P)\n");
        script.push_str("checkout_digest=$(printf '%s' \"$checkout_path\" | sha256sum)\n");
        script.push_str("checkout_digest=${checkout_digest%% *}\n");
        script.push_str("target_root=${CARGO_TARGET_DIR:-$checkout_path/target}\n");
        script.push_str(
            "export CARGO_TARGET_DIR=\"$target_root/superloop-gate-submit-${checkout_digest:0:16}\"\n",
        );
    }
    script.push_str("# superloop-gate-submit target-dir end\n");
    if let Some(committed) = &config.committed_head {
        let token = probe.unwrap_or_default();
        writeln!(&mut script, "# superloop-gate-submit probe token={token}")
            .expect("writing to a String cannot fail");
        if let Some(seed) = committed.seed_object.as_deref() {
            script.push_str("seed_result=missing\n");
            writeln!(
                &mut script,
                "checked_out=$(git rev-parse HEAD); checked_status=$(git status --porcelain --untracked-files=normal); trap 'status=$?; samp_finish; final_head=$(git rev-parse HEAD 2>/dev/null) || final_head=missing; final_status=$(git status --porcelain --untracked-files=normal 2>/dev/null) || final_status=unreadable; if [ \"$final_head\" != \"$checked_out\" ] || [ \"$final_status\" != \"$checked_status\" ] || [ -n \"$final_status\" ]; then printf \"CHECKED-OUT-DRIFT token=%s\\n\" \"{}\"; if [ \"$status\" -eq 0 ]; then status=1; fi; fi; printf \"SEED-ANCESTRY object=%s seed=%s token=%s result=%s\\n\" \"$final_head\" \"{}\" \"{}\" \"$seed_result\"; printf \"CHECKED-OUT object=%s ref=%s token=%s\\n\" \"$final_head\" \"{}\" \"{}\"; exit \"$status\"' EXIT",
                token, seed, token, committed.ref_name, token
            )
            .expect("writing to a String cannot fail");
        } else {
            writeln!(
                &mut script,
                "checked_out=$(git rev-parse HEAD); checked_status=$(git status --porcelain --untracked-files=normal); trap 'status=$?; samp_finish; final_head=$(git rev-parse HEAD 2>/dev/null) || final_head=missing; final_status=$(git status --porcelain --untracked-files=normal 2>/dev/null) || final_status=unreadable; if [ \"$final_head\" != \"$checked_out\" ] || [ \"$final_status\" != \"$checked_status\" ] || [ -n \"$final_status\" ]; then printf \"CHECKED-OUT-DRIFT token=%s\\n\" \"{}\"; if [ \"$status\" -eq 0 ]; then status=1; fi; fi; printf \"CHECKED-OUT object=%s ref=%s token=%s\\n\" \"$final_head\" \"{}\" \"{}\"; exit \"$status\"' EXIT",
                token, committed.ref_name, token
            )
            .expect("writing to a String cannot fail");
        }
        if let Some(seed) = committed.seed_object.as_deref() {
            script.push_str(&seed_check_script(seed));
        }
    }
    script.push_str("sec fmt; time nice -n19 cargo fmt --all -- --check\n");
    script.push_str(
        "sec clippy; time nice -n19 cargo clippy --workspace --all-targets $locked_flag -- -D warnings\n",
    );
    writeln!(
        &mut script,
        "sec test; time nice -n19 cargo test {package_arguments} {all_features} $locked_flag"
    )
    .expect("writing to a String cannot fail");
    if config.doc_check {
        writeln!(
            &mut script,
            "sec doc; time nice -n19 env RUSTDOCFLAGS='-D warnings' cargo doc --no-deps {package_arguments} $locked_flag"
        )
        .expect("writing to a String cannot fail");
    }
    if config.release_build {
        script.push_str(
            "sec release-build; time nice -n19 cargo build --release $locked_flag --workspace\n",
        );
    } else if !config.doc_check {
        script.push('\n');
    }
    script
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod seed_tests {
    use super::{
        FailureKind, NEXT_TEMP_INDEX, Ordering, ServerProfile, check_seed_ancestor, parse_config,
        seed_check_script,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    struct Fixture(PathBuf);

    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
            .output()
            .expect("fixture Git starts");
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Git object ID")
            .trim()
            .to_owned()
    }

    /// ´test:unit:seed-ancestry-script-accepts-descendant-and-refuses-foreign-commit´
    #[test]
    fn seed_ancestry_script_accepts_descendant_and_refuses_foreign_commit() {
        let sequence = NEXT_TEMP_INDEX.fetch_add(1, Ordering::Relaxed);
        let repo = std::env::temp_dir().join(format!(
            "superloop-gate-submit-seed-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&repo).expect("fixture directory");
        let _fixture = Fixture(repo.clone());
        git(&repo, &["init", "-q"]);
        let tree = git(&repo, &["mktree"]);
        let seed = git(&repo, &["commit-tree", &tree, "-m", "seed"]);
        let lane = git(&repo, &["commit-tree", &tree, "-p", &seed, "-m", "lane"]);
        let foreign = git(&repo, &["commit-tree", &tree, "-m", "foreign"]);
        let script = seed_check_script(&seed);
        let server = ServerProfile {
            ssh_alias: "fixture".into(),
            clone_path: "/fixture/checkout".to_owned(),
            remote_runner: "fixture-runner".into(),
            rust_env: "/fixture/rust".to_owned(),
        };
        let mut config = parse_config(
            [
                "-p".into(),
                "alpha".into(),
                "--committed-head".into(),
                "refs/heads/lane/R".into(),
                "--seed-object".into(),
                seed.into(),
                repo.clone().into_os_string(),
            ],
            server,
        )
        .expect("seeded config");
        config
            .committed_head
            .as_mut()
            .expect("committed head")
            .object = lane.clone();
        check_seed_ancestor(&config).expect("external descendant");
        config
            .committed_head
            .as_mut()
            .expect("committed head")
            .object = foreign.clone();
        assert_eq!(
            check_seed_ancestor(&config)
                .expect_err("external foreign head")
                .kind(),
            FailureKind::SeedAncestry
        );
        config
            .committed_head
            .as_mut()
            .expect("committed head")
            .seed_object = Some("f".repeat(40));
        assert_eq!(
            check_seed_ancestor(&config)
                .expect_err("seed object absent from external checkout")
                .kind(),
            FailureKind::SeedAncestry
        );
        config.worktree = repo.join("absent-checkout");
        let broken = check_seed_ancestor(&config).expect_err("Git cannot open external checkout");
        assert_eq!(broken.kind(), FailureKind::SeedCheck);
        assert_ne!(broken.evidence(), []);
        let descendant = Command::new("/bin/bash")
            .args(["--noprofile", "--norc"])
            .env_remove("BASH_ENV")
            .arg("-c")
            .arg(&script)
            .current_dir(&repo)
            .env("checked_out", &lane)
            .output()
            .expect("descendant check");
        assert!(descendant.status.success());
        let unrelated = Command::new("/bin/bash")
            .args(["--noprofile", "--norc"])
            .env_remove("BASH_ENV")
            .arg("-c")
            .arg(&script)
            .current_dir(&repo)
            .env("checked_out", &foreign)
            .output()
            .expect("foreign check");
        assert_eq!(unrelated.status.code(), Some(1));
        assert_eq!(unrelated.stdout, b"== seed ==\n");
    }
}

fn probe_token() -> Result<String, VerifyFailure> {
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|_error| remote_failure(Vec::new()))?;
    let mut token = String::with_capacity(32);
    for byte in bytes {
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(token)
}

fn tail_lines(bytes: &[u8], maximum: usize) -> Vec<u8> {
    if maximum == 0 || bytes.is_empty() {
        return Vec::new();
    }
    let complete = bytes
        .iter()
        .map(|byte| usize::from(*byte == b'\n'))
        .sum::<usize>();
    let total = complete + usize::from(!bytes.ends_with(b"\n"));
    if total <= maximum {
        return bytes.to_vec();
    }
    let skip = total - maximum;
    let mut seen = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            seen += 1;
            if seen == skip {
                return bytes[index + 1..].to_vec();
            }
        }
    }
    Vec::new()
}

const fn trim_line_end(mut bytes: &[u8]) -> &[u8] {
    while let Some((last, rest)) = bytes.split_last()
        && matches!(*last, b'\n' | b'\r')
    {
        bytes = rest;
    }
    bytes
}

/// Build local failure evidence from the step and the tool or I/O reason; publication adds the fixed diagnostic afterward.
fn classed_failure(kind: FailureKind, step: &str, reason: &[u8]) -> VerifyFailure {
    let mut evidence = Vec::new();
    evidence.extend_from_slice(b"superloop-gate-submit: ");
    evidence.extend_from_slice(step.as_bytes());
    evidence.extend_from_slice(b" failed\n");
    evidence.extend_from_slice(trim_line_end(reason));
    evidence.push(b'\n');
    VerifyFailure { kind, evidence }
}

const fn remote_failure(evidence: Vec<u8>) -> VerifyFailure {
    VerifyFailure {
        kind: FailureKind::Remote,
        evidence,
    }
}

struct TempIndex {
    path: PathBuf,
    file: File,
}

impl TempIndex {
    fn create() -> io::Result<Self> {
        let temporary_directory = std::env::temp_dir();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _attempt in 0..128 {
            let sequence = NEXT_TEMP_INDEX.fetch_add(1, Ordering::Relaxed);
            let path = temporary_directory.join(format!(
                ".superloop-gate-submit-index-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary index collision limit reached",
        ))
    }

    fn copy_from(&mut self, source: impl AsRef<Path>) -> io::Result<()> {
        let mut source = File::open(source)?;
        io::copy(&mut source, &mut self.file)?;
        self.file.flush()
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempIndex {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.path);
    }
}
