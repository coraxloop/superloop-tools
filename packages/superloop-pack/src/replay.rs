//! Linear, metadata-preserving replay of commit-bound public projections.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use superloop_cli_common::burn_match::burn_offsets;
use superloop_cli_common::public_set::Manifest;

use crate::cut::{self, Projection};

/// Explicit inputs to an unsigned replay into an existing development branch.
#[derive(Clone, Copy, Debug)]
pub struct ReplayRequest<'a> {
    pub repository_root: &'a Path,
    pub since: &'a str,
    pub tag: &'a str,
    pub manifest: &'a Path,
    pub out: &'a Path,
    pub previous: &'a Path,
    pub public_root: &'a str,
    pub burn_register: &'a Path,
    pub linter: &'a Path,
    pub accept_generated_drift: bool,
}

/// A refusal never includes a matched burn value.
#[derive(Debug, thiserror::Error)]
#[error("replay refused: {0}")]
pub struct ReplayError(String);

impl From<io::Error> for ReplayError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<cut::CutError> for ReplayError {
    fn from(error: cut::CutError) -> Self {
        Self(error.to_string())
    }
}

fn refuse(reason: impl Into<String>) -> ReplayError {
    ReplayError(reason.into())
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Identity {
    name: String,
    email: String,
    timestamp: String,
    timezone: String,
}

#[derive(Debug)]
struct SourceCommit {
    oid: String,
    parent: String,
    author: Identity,
    committer: Identity,
    message: Vec<u8>,
    signature_omitted: bool,
}

#[derive(Debug, Serialize)]
struct Mapping {
    ordinal: usize,
    source: String,
    source_parent: String,
    subject: String,
    public_commit: String,
    mapped_parent: String,
    public_tree: String,
    outcome: &'static str,
    old_author: Identity,
    old_committer: Identity,
    new_author: Option<Identity>,
    new_committer: Option<Identity>,
    message_sha256: String,
    signature_omitted: bool,
    selected_paths: usize,
    omitted_paths: usize,
    readme_fallback: bool,
}

#[derive(Debug, Serialize)]
struct Check {
    name: String,
    exit: i32,
    wall_seconds: f64,
}

/// Private replay evidence, including metadata that must not become public notes.
#[derive(Debug, Serialize)]
pub struct ReplayReport {
    since: String,
    tag: String,
    public_root: String,
    final_tip: String,
    final_tree: String,
    files: usize,
    scratch_root: PathBuf,
    generated_drift: Vec<String>,
    readme_fallback_commits: usize,
    projection_version: String,
    projection_sha256: String,
    policy_sha256: String,
    linter_version: serde_json::Value,
    linter_sha256: String,
    register_sha256: String,
    register_schema: &'static str,
    mapping: Vec<Mapping>,
    checks: Vec<Check>,
}

fn command(root: &Path) -> Command {
    let mut command = crate::git_command(root);
    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
    ]);
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    command
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, ReplayError> {
    let output = command(root).args(args).output()?;
    if !output.status.success() {
        return Err(refuse("git operation failed"));
    }
    Ok(output.stdout)
}

fn line(root: &Path, args: &[&str]) -> Result<String, ReplayError> {
    crate::one_line(&git(root, args)?).ok_or_else(|| refuse("invalid git response"))
}

fn resolve(root: &Path, name: &str) -> Result<String, ReplayError> {
    line(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{name}^{{commit}}"),
        ],
    )
}

fn identity(bytes: &[u8]) -> Result<Identity, ReplayError> {
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("unsupported identity encoding"))?;
    let (identity, timezone) = text
        .rsplit_once(' ')
        .ok_or_else(|| refuse("invalid identity timezone"))?;
    let (identity, timestamp) = identity
        .rsplit_once(' ')
        .ok_or_else(|| refuse("invalid identity timestamp"))?;
    let (name, email) = identity
        .rsplit_once(" <")
        .ok_or_else(|| refuse("invalid identity"))?;
    let email = email
        .strip_suffix('>')
        .ok_or_else(|| refuse("invalid identity"))?;
    if name.trim() != name
        || name.is_empty()
        || email.is_empty()
        || name.contains(['<', '>', '\0', '\r', '\n'])
        || email
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '\0'))
        || timestamp.parse::<u64>().is_err()
        || timezone.len() != 5
        || !matches!(timezone.as_bytes()[0], b'+' | b'-')
        || !timezone.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        || timezone[1..3].parse::<u8>().unwrap_or(255) > 23
        || timezone[3..].parse::<u8>().unwrap_or(255) > 59
    {
        return Err(refuse("unsupported identity or date"));
    }
    Ok(Identity {
        name: name.into(),
        email: email.into(),
        timestamp: timestamp.into(),
        timezone: timezone.into(),
    })
}

fn source_commit(root: &Path, oid: &str) -> Result<SourceCommit, ReplayError> {
    let bytes = git(root, &["cat-file", "commit", oid])?;
    let boundary = bytes
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(|| refuse("invalid commit header"))?;
    let mut parents = Vec::new();
    let mut authors = Vec::new();
    let mut committers = Vec::new();
    let mut signature_omitted = false;
    for header in bytes[..boundary].split(|byte| *byte == b'\n') {
        if let Some(parent) = header.strip_prefix(b"parent ") {
            parents.push(
                std::str::from_utf8(parent)
                    .map_err(|_| refuse("invalid parent"))?
                    .to_owned(),
            );
        } else if let Some(author) = header.strip_prefix(b"author ") {
            authors.push(identity(author)?);
        } else if let Some(committer) = header.strip_prefix(b"committer ") {
            committers.push(identity(committer)?);
        } else if header.starts_with(b"gpgsig ") || header.starts_with(b"gpgsig-sha256 ") {
            signature_omitted = true;
        } else if !header.starts_with(b"tree ") && !header.starts_with(b" ") {
            return Err(refuse("unsupported commit header"));
        }
    }
    if parents.len() != 1 {
        return Err(refuse("merge or root commit in replay range"));
    }
    if authors.len() != 1 || committers.len() != 1 {
        return Err(refuse("commit requires one author and one committer"));
    }
    let message = bytes[boundary + 2..].to_vec();
    if message.contains(&0) || (!message.is_empty() && !message.ends_with(b"\n")) {
        return Err(refuse("unsupported commit message framing"));
    }
    Ok(SourceCommit {
        oid: oid.into(),
        parent: parents.remove(0),
        author: authors.remove(0),
        committer: committers.remove(0),
        message,
        signature_omitted,
    })
}

fn scan(
    burn: &crate::BurnDocument,
    ordinal: usize,
    field: &str,
    bytes: &[u8],
) -> Result<(), ReplayError> {
    let folded = String::from_utf8_lossy(bytes).to_lowercase();
    for value in &burn.values {
        let identifier = matches!(value.mode, crate::BurnMatch::Identifier);
        if burn_offsets(
            folded.as_bytes(),
            value.value.to_lowercase().as_bytes(),
            identifier,
        )
        .next()
        .is_some()
        {
            let kind = if identifier {
                "identifier"
            } else {
                "substring"
            };
            return Err(refuse(format!(
                "source ordinal {ordinal} field {field} match kind {kind}"
            )));
        }
    }
    Ok(())
}

fn scan_metadata(
    burn: &crate::BurnDocument,
    ordinal: usize,
    source: &SourceCommit,
) -> Result<(), ReplayError> {
    scan(burn, ordinal, "message", &source.message)?;
    for (field, value) in [
        ("author.name", &source.author.name),
        ("author.email", &source.author.email),
        ("committer.name", &source.committer.name),
        ("committer.email", &source.committer.email),
    ] {
        scan(burn, ordinal, field, value.as_bytes())?;
    }
    Ok(())
}

fn validate_git_identity(root: &Path, source: &SourceCommit) -> Result<(), ReplayError> {
    for (prefix, identity) in [("AUTHOR", &source.author), ("COMMITTER", &source.committer)] {
        let output = command(root)
            .args(["var", &format!("GIT_{prefix}_IDENT")])
            .env(format!("GIT_{prefix}_NAME"), &identity.name)
            .env(format!("GIT_{prefix}_EMAIL"), &identity.email)
            .env(
                format!("GIT_{prefix}_DATE"),
                format!("{} {}", identity.timestamp, identity.timezone),
            )
            .output()?;
        let expected = format!(
            "{} <{}> {} {}\n",
            identity.name, identity.email, identity.timestamp, identity.timezone
        );
        if !output.status.success() || output.stdout != expected.as_bytes() {
            return Err(refuse(
                "Git cannot preserve the source identity and date verbatim",
            ));
        }
    }
    Ok(())
}

const fn cut_request<'a>(request: &'a ReplayRequest<'a>) -> cut::CutRequest<'a> {
    cut::CutRequest {
        repository_root: request.repository_root,
        tag: request.tag,
        manifest: request.manifest,
        out: request.out,
        previous: Some(request.previous),
        author: "",
        date: None,
        public_tag: None,
        message: None,
        tag_message: None,
        burn_register: Some(request.burn_register),
        linter: Some(request.linter),
    }
}

struct Policy {
    manifest: Manifest,
    bytes: Vec<u8>,
}

struct PlannedCommit {
    tree: Projection,
    omitted: usize,
    readme_fallback: bool,
}

fn read_policy(request: &ReplayRequest<'_>, tag: &str) -> Result<(Policy, String), ReplayError> {
    let manifest_path = request
        .manifest
        .to_str()
        .filter(|path| superloop_cli_common::public_set::safe_path(path))
        .ok_or_else(|| refuse("manifest must be source-relative"))?;
    let bytes = git(
        request.repository_root,
        &["show", &format!("{tag}:{manifest_path}")],
    )?;
    let policy_sha256 = crate::sha256_bytes(&bytes);
    let manifest = Manifest::parse(
        std::str::from_utf8(&bytes).map_err(|_| refuse("final manifest encoding"))?,
    )
    .map_err(|_| refuse("invalid final manifest"))?;
    if [&manifest.public.licence_code, &manifest.public.licence_docs]
        .contains(&&manifest.public.readme)
        || manifest.public.readme == manifest_path
    {
        return Err(refuse(
            "public README source must differ from manifest and licence paths",
        ));
    }
    Ok((Policy { manifest, bytes }, policy_sha256))
}

fn project(
    request: &ReplayRequest<'_>,
    oid: &str,
    policy: &Policy,
) -> Result<PlannedCommit, ReplayError> {
    let entries = cut::tree_entries(request.repository_root, oid)?;
    let manifest = &policy.manifest;
    let paths = entries.keys().cloned().collect::<Vec<_>>();
    let mut selected = manifest.select(&paths);
    // Final rows may name files introduced later in the range.
    if selected
        .issues
        .iter()
        .any(|issue| !issue.starts_with("dead manifest row:"))
    {
        return Err(refuse("final policy cannot classify historical tree"));
    }
    for path in [&manifest.public.licence_code, &manifest.public.licence_docs] {
        if !selected.included.contains(path)
            || !entries
                .get(path)
                .is_some_and(|(mode, _)| matches!(mode.as_str(), "100644" | "100755"))
        {
            return Err(refuse(format!(
                "commit {oid}: required licence absent or not regular"
            )));
        }
    }
    let readme_fallback = !entries.contains_key(&manifest.public.readme);
    if readme_fallback && !selected.included.iter().any(|path| path == "README.md") {
        selected.included.push("README.md".into());
    }
    let omitted = selected.tracked.saturating_sub(selected.included.len());
    let mut projected = cut::project_tree_with_policy(
        &cut_request(request),
        oid,
        manifest,
        selected.included,
        Some(&policy.bytes),
        readme_fallback,
    )?;
    // Cut retains historical reservations for archive reproduction. Replay consumes
    // them, just as it consumes exclusions, rather than publishing private selectors.
    let path = request
        .manifest
        .to_str()
        .ok_or_else(|| refuse("manifest must be UTF-8"))?;
    let (_, content) = projected
        .get_mut(path)
        .ok_or_else(|| refuse("manifest excluded by final policy"))?;
    let mut document: toml::Value =
        toml::from_str(std::str::from_utf8(content).map_err(|_| refuse("manifest encoding"))?)
            .map_err(|_| refuse("manifest encoding"))?;
    if let Some(table) = document.as_table_mut() {
        table.remove("reserved");
    }
    *content = format!(
        "# Exclusion is a source-side matter; the cut has consumed those rows.\n{}",
        toml::to_string(&document).map_err(|_| refuse("manifest encoding"))?
    )
    .into_bytes();
    Ok(PlannedCommit {
        tree: projected,
        omitted,
        readme_fallback,
    })
}

fn output_ready(request: &ReplayRequest<'_>, expected: &str) -> Result<PathBuf, ReplayError> {
    let out = fs::canonicalize(request.out)?;
    if out != fs::canonicalize(request.previous)? {
        return Err(refuse("previous must name the same directory as out"));
    }
    crate::validate_repository(&out).map_err(|_| refuse("out must be a repository root"))?;
    let source = fs::canonicalize(request.repository_root)?;
    if out.starts_with(&source) || source.starts_with(&out) {
        return Err(refuse("source and output overlap"));
    }
    if line(&out, &["symbolic-ref", "-q", "HEAD"])? != "refs/heads/development" {
        return Err(refuse("out must be checked out on development"));
    }
    let actual = resolve(&out, "HEAD")?;
    if actual != expected {
        return Err(refuse(format!(
            "public-root mismatch: expected {expected}, development {actual}"
        )));
    }
    if !git(
        &out,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored",
        ],
    )?
    .is_empty()
    {
        return Err(refuse("out must be clean, including ignored files"));
    }
    Ok(out)
}

fn read_projection(root: &Path, oid: &str) -> Result<Projection, ReplayError> {
    cut::tree_entries(root, oid)?
        .into_iter()
        .map(|(path, (mode, object))| {
            Ok((path, (mode, git(root, &["cat-file", "blob", &object])?)))
        })
        .collect()
}

fn write_commit(
    stage: &Path,
    tree: &str,
    parent: &str,
    source: &SourceCommit,
) -> Result<String, ReplayError> {
    let mut cmd = command(stage);
    cmd.args(["commit-tree", tree, "-p", parent, "-F", "-"]);
    for (prefix, identity) in [("AUTHOR", &source.author), ("COMMITTER", &source.committer)] {
        cmd.env(format!("GIT_{prefix}_NAME"), &identity.name)
            .env(format!("GIT_{prefix}_EMAIL"), &identity.email)
            .env(
                format!("GIT_{prefix}_DATE"),
                format!("{} {}", identity.timestamp, identity.timezone),
            );
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| refuse("commit input"))?
        .write_all(&source.message)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(refuse("commit-tree failed"));
    }
    let oid = crate::one_line(&output.stdout).ok_or_else(|| refuse("commit-tree response"))?;
    let written = source_commit(stage, &oid)?;
    if written.author != source.author
        || written.committer != source.committer
        || written.message != source.message
    {
        return Err(refuse("commit-tree changed source metadata"));
    }
    Ok(oid)
}

fn clear_stage(stage: &Path) -> Result<(), ReplayError> {
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        if entry.file_name() == ".git" {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    git(stage, &["read-tree", "--empty"])?;
    Ok(())
}

/// Replay a wholly preflighted linear range without importing private parents.
///
/// # Errors
/// Refuses unsafe inputs, private values, drift without acceptance, non-linear
/// history, metadata loss, linter failures or a concurrently changed destination.
pub fn replay(request: ReplayRequest<'_>) -> Result<ReplayReport, ReplayError> {
    crate::validate_repository(request.repository_root).map_err(|_| refuse("source repository"))?;
    let since = resolve(request.repository_root, request.since)?;
    let tag = resolve(request.repository_root, request.tag)?;
    let public_root = resolve(request.out, request.public_root)?;
    let context = format!("since={since} tag={tag} public_root={public_root}");
    replay_resolved(request, since, tag, public_root)
        .map_err(|error| refuse(format!("{context}: {}", error.0)))
}

fn replay_resolved(
    request: ReplayRequest<'_>,
    since: String,
    tag: String,
    public_root: String,
) -> Result<ReplayReport, ReplayError> {
    let started = Instant::now();
    crate::validate_checkout(request.repository_root, &tag)
        .map_err(|_| refuse("clean checkout of tag required"))?;
    if since == tag {
        return Err(refuse("nothing to replay"));
    }
    let out = output_ready(&request, &public_root)?;
    let scratch_root = fs::canonicalize(std::env::temp_dir())?;
    if scratch_root.starts_with(&out)
        || scratch_root.starts_with(fs::canonicalize(request.repository_root)?)
    {
        return Err(refuse("TMPDIR must be outside source and output"));
    }
    let burn = cut::cut_burn_register(request.repository_root, Some(request.burn_register))?;
    let register = fs::canonicalize(request.burn_register)?;
    if register.starts_with(&out) {
        return Err(refuse("burn register must be outside output"));
    }
    let register_sha256 = crate::sha256_file(&register)?;
    let linter = fs::canonicalize(request.linter)?;
    let linter_sha256 = crate::sha256_file(&linter)?;
    let version = Command::new(&linter).arg("--version").output()?;
    if !version.status.success() {
        return Err(refuse("linter version failed"));
    }
    let linter_version =
        serde_json::from_slice(&version.stderr).map_err(|_| refuse("linter version protocol"))?;
    let projection_sha256 = crate::sha256_file(&std::env::current_exe()?)?;
    let (policy, policy_sha256) = read_policy(&request, &tag)?;
    let sources = linear_sources(&request, &since, &tag, &burn)?;
    let (public, planned, generated_drift) =
        plan_trees(&request, &since, &public_root, &policy, &burn, &sources)?;
    let checks = vec![Check {
        name: "whole-range-preflight".into(),
        exit: 0,
        wall_seconds: started.elapsed().as_secs_f64(),
    }];
    // No output write occurred above. Only input snapshots lived in TMPDIR.
    let temporary = staging_repository(&scratch_root, &out, &public_root)?;
    let stage = temporary.path();
    let parent = public_root.clone();
    let parent_tree = public;
    let mapping = Vec::new();
    let mut writer = Writer {
        parent,
        parent_tree,
        mapping,
        checks,
    };
    replay_commits(stage, &linter, &register, &sources, planned, &mut writer)?;
    if resolve(request.repository_root, request.since)? != since
        || resolve(request.repository_root, request.tag)? != tag
        || crate::sha256_file(&register)? != register_sha256
        || crate::sha256_file(&linter)? != linter_sha256
    {
        return Err(refuse("replay inputs changed"));
    }
    output_ready(&request, &public_root)?;
    publish(stage, &out, &public_root, &mut writer)?;
    let Writer {
        parent,
        parent_tree,
        mapping,
        checks,
    } = writer;
    let final_tree = line(&out, &["rev-parse", &format!("{parent}^{{tree}}")])?;
    Ok(ReplayReport {
        since,
        tag,
        public_root,
        final_tip: parent,
        final_tree,
        files: parent_tree.len(),
        scratch_root,
        generated_drift,
        readme_fallback_commits: mapping.iter().filter(|row| row.readme_fallback).count(),
        projection_version: env!("CARGO_PKG_VERSION").into(),
        projection_sha256,
        policy_sha256,
        linter_version,
        linter_sha256,
        register_sha256,
        register_schema: "unversioned-values",
        mapping,
        checks,
    })
}

fn staging_repository(
    scratch_root: &Path,
    out: &Path,
    public_root: &str,
) -> Result<tempfile::TempDir, ReplayError> {
    let temporary = tempfile::Builder::new()
        .prefix("pack-replay-")
        .tempdir_in(scratch_root)?;
    git(
        temporary.path(),
        &["init", "-q", "--template=", "--initial-branch=development"],
    )?;
    git(
        temporary.path(),
        &[
            "fetch",
            "--no-tags",
            "--",
            out.to_str().ok_or_else(|| refuse("output encoding"))?,
            public_root,
        ],
    )?;
    Ok(temporary)
}

/// Write private JSON evidence and the pack command's terminal summary.
///
/// # Errors
/// Returns an error when evidence cannot be serialized or written.
pub fn write_replay_report<W: io::Write>(
    result: &Result<ReplayReport, ReplayError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    match result {
        Ok(report) => {
            serde_json::to_writer(&mut *output, report)?;
            writeln!(output)?;
            writeln!(
                output,
                "replay since={} tag={} public_root={} tip={} files={} replayed={} skipped={} signatures=omitted",
                report.since,
                report.tag,
                report.public_root,
                report.final_tip,
                report.files,
                report
                    .mapping
                    .iter()
                    .filter(|row| row.outcome == "replayed")
                    .count(),
                report
                    .mapping
                    .iter()
                    .filter(|row| row.outcome == "skipped")
                    .count()
            )?;
            crate::write_terminal_report(output, "replay", 0, wall, "ok")
        }
        Err(error) => {
            serde_json::to_writer(
                &mut *output,
                &serde_json::json!({
                    "outcome": "refused", "scratch_root": std::env::temp_dir(),
                    "reason": error.0, "exit": 3, "wall_seconds": wall.as_secs_f64()
                }),
            )?;
            writeln!(output)?;
            writeln!(
                output,
                "replay outcome=refused status=3 reason={}",
                error.0.replace(['\n', '\r'], " ")
            )?;
            crate::write_terminal_report(output, "replay", 3, wall, "refused")
        }
    }
}

fn linear_sources(
    request: &ReplayRequest<'_>,
    since: &str,
    tag: &str,
    burn: &crate::BurnDocument,
) -> Result<Vec<SourceCommit>, ReplayError> {
    let range = git(
        request.repository_root,
        &[
            "rev-list",
            "--first-parent",
            "--reverse",
            &format!("{since}..{tag}"),
        ],
    )?;
    let range = std::str::from_utf8(&range).map_err(|_| refuse("range encoding"))?;
    if range.is_empty() {
        return Err(refuse("nothing to replay"));
    }
    let mut sources = Vec::new();
    let mut previous = since.to_owned();
    for (index, oid) in range.lines().enumerate() {
        let source = source_commit(request.repository_root, oid)
            .map_err(|error| refuse(format!("source ordinal {}: {error}", index + 1)))?;
        if source.parent != previous {
            return Err(refuse(format!(
                "source ordinal {}: disconnected first-parent range",
                index + 1
            )));
        }
        scan_metadata(burn, index + 1, &source)?;
        validate_git_identity(request.repository_root, &source)
            .map_err(|error| refuse(format!("source ordinal {}: {error}", index + 1)))?;
        previous = oid.into();
        sources.push(source);
    }
    Ok(sources)
}

struct Writer {
    parent: String,
    parent_tree: Projection,
    mapping: Vec<Mapping>,
    checks: Vec<Check>,
}

fn replay_commits(
    stage: &Path,
    linter: &Path,
    register: &Path,
    sources: &[SourceCommit],
    planned: Vec<PlannedCommit>,
    writer: &mut Writer,
) -> Result<(), ReplayError> {
    for (
        index,
        (
            source,
            PlannedCommit {
                tree,
                omitted,
                readme_fallback,
            },
        ),
    ) in sources.iter().zip(planned).enumerate()
    {
        let mapped_parent = writer.parent.clone();
        let skipped = tree == writer.parent_tree;
        clear_stage(stage)?;
        cut::write_projection(stage, &tree)?;
        let tree_oid = line(stage, &["write-tree"])?;
        if read_projection(stage, &tree_oid)? != tree {
            return Err(refuse("written tree differs from preflight projection"));
        }
        let check_start = Instant::now();
        let observation = crate::run_linter(linter, stage, register).map_err(|_| {
            refuse(format!(
                "source ordinal {}: linter protocol failed",
                index + 1
            ))
        })?;
        if crate::validate_linter_verdict(&observation, register).is_err() {
            return Err(refuse(format!(
                "source ordinal {}: public tree lint failed",
                index + 1
            )));
        }
        writer.checks.push(Check {
            name: format!("source-{}-lint", index + 1),
            exit: 0,
            wall_seconds: check_start.elapsed().as_secs_f64(),
        });
        if !skipped {
            writer.parent = write_commit(stage, &tree_oid, &writer.parent, source)?;
        }
        writer.mapping.push(Mapping {
            ordinal: index + 1,
            source: source.oid.clone(),
            source_parent: source.parent.clone(),
            subject: String::from_utf8_lossy(&source.message)
                .lines()
                .next()
                .unwrap_or("")
                .into(),
            public_commit: writer.parent.clone(),
            mapped_parent,
            public_tree: tree_oid,
            outcome: if skipped { "skipped" } else { "replayed" },
            old_author: source.author.clone(),
            old_committer: source.committer.clone(),
            new_author: (!skipped).then(|| source.author.clone()),
            new_committer: (!skipped).then(|| source.committer.clone()),
            message_sha256: crate::sha256_bytes(&source.message),
            signature_omitted: source.signature_omitted,
            selected_paths: tree.len(),
            omitted_paths: omitted,
            readme_fallback,
        });
        writer.parent_tree = tree;
    }
    Ok(())
}

type PlannedTrees = (Projection, Vec<PlannedCommit>, Vec<String>);

fn plan_trees(
    request: &ReplayRequest<'_>,
    since: &str,
    public_root: &str,
    policy: &Policy,
    burn: &crate::BurnDocument,
    sources: &[SourceCommit],
) -> Result<PlannedTrees, ReplayError> {
    let base = project(request, since, policy).map_err(|error| projection_refusal(0, &error))?;
    let public = read_projection(request.out, public_root)?;
    let paths: BTreeSet<_> = base.tree.keys().chain(public.keys()).cloned().collect();
    let generated_drift: Vec<_> = paths
        .into_iter()
        .filter(|path| base.tree.get(path) != public.get(path))
        .collect();
    let mut planned = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        let projection = project(request, &source.oid, policy)
            .map_err(|error| projection_refusal(index + 1, &error))?;
        for path in projection.tree.keys() {
            scan(burn, index + 1, "path", path.as_bytes())?;
        }
        for (_, bytes) in projection.tree.values() {
            scan(burn, index + 1, "blob", bytes)?;
        }
        planned.push(projection);
    }
    if !generated_drift.is_empty() && !request.accept_generated_drift {
        for path in &generated_drift {
            scan(burn, 0, "generated-drift path", path.as_bytes())?;
        }
        return Err(refuse(format!(
            "generated drift: {}",
            generated_drift.join(", ")
        )));
    }
    Ok((public, planned, generated_drift))
}

fn projection_refusal(ordinal: usize, error: &ReplayError) -> ReplayError {
    if error.0.starts_with("commit ")
        && error
            .0
            .ends_with(": required licence absent or not regular")
    {
        return refuse(format!("source ordinal {ordinal}: {}", error.0));
    }
    // Cut's audit diagnostic contains only the fixed field and matcher vocabulary
    // after this delimiter. Never propagate a manifest parser's source text.
    if let Some((_, suffix)) = error.0.rsplit_once(" field ") {
        for field in ["label", "owner", "path_class"] {
            for kind in ["identifier", "substring"] {
                if suffix == format!("{field} matches private audit kind {kind}") {
                    return refuse(format!(
                        "source ordinal {ordinal} field unpublished.{field} match kind {kind}"
                    ));
                }
            }
        }
    }
    refuse(format!(
        "source ordinal {ordinal}: public projection refused"
    ))
}

fn publish(
    stage: &Path,
    out: &Path,
    public_root: &str,
    writer: &mut Writer,
) -> Result<(), ReplayError> {
    let publish_start = Instant::now();
    if writer.parent != public_root {
        git(
            out,
            &[
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--",
                stage.to_str().ok_or_else(|| refuse("stage encoding"))?,
                &writer.parent,
            ],
        )?;
        git(
            out,
            &[
                "update-ref",
                "refs/heads/development",
                &writer.parent,
                public_root,
            ],
        )?;
        // Populate the index and worktree explicitly, without checkout filters.
        clear_stage(out)?;
        cut::write_projection(out, &writer.parent_tree)?;
    }
    writer.checks.push(Check {
        name: "expected-old-publication".into(),
        exit: 0,
        wall_seconds: publish_start.elapsed().as_secs_f64(),
    });
    Ok(())
}
