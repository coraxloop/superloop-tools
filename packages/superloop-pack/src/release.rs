//! Local, unsigned deployment release with an expected-old three-ref transaction.

use std::io::{self, BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Inputs pinned by the deployment coordinator; transport remains outside this command.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseRequest<'a> {
    pub repository: &'a Path,
    pub version: &'a str,
    pub manifest: &'a Path,
    pub author: &'a str,
    pub date: Option<&'a str>,
    pub tag_message: Option<&'a str>,
    pub changelog: &'a Path,
    pub expected_main: Option<&'a str>,
    pub expected_development: Option<&'a str>,
    pub dry_run: bool,
    pub check: bool,
}

/// Reproducible object identities and the complete transport allowlist.
#[derive(Debug)]
pub struct ReleaseReport {
    pub main: String,
    pub development: String,
    pub commit: String,
    pub tree: String,
    pub tag_object: String,
    pub title: String,
    pub body_bytes: usize,
    pub version_source: String,
    pub refspecs: [String; 3],
    pub state: &'static str,
}

/// A named release refusal. No refused preflight advances refs or stores objects.
#[derive(Debug, thiserror::Error)]
#[error("release refused: {code}: {detail}")]
pub struct ReleaseError {
    code: &'static str,
    detail: String,
}

fn refuse(code: &'static str, detail: impl Into<String>) -> ReleaseError {
    ReleaseError {
        code,
        detail: detail.into(),
    }
}

impl From<io::Error> for ReleaseError {
    fn from(error: io::Error) -> Self {
        refuse("io", error.to_string())
    }
}

fn command(root: &Path) -> Command {
    let mut command = crate::git_command(root);
    command.args(["-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0"]);
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command
}

fn run(command: &mut Command, input: Option<&[u8]>) -> Result<Vec<u8>, ReleaseError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| refuse("git", "missing stdin"))?
            .write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(refuse(
            "git",
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }
    Ok(output.stdout)
}

fn line(root: &Path, args: &[&str]) -> Result<String, ReleaseError> {
    let bytes = run(command(root).args(args), None)?;
    crate::one_line(&bytes).ok_or_else(|| refuse("git", "invalid single-line response"))
}

fn blob(root: &Path, commit: &str, path: &Path) -> Result<String, ReleaseError> {
    let path = path
        .to_str()
        .filter(|value| superloop_cli_common::public_set::safe_path(value))
        .ok_or_else(|| refuse("path", "expected a safe repository-relative path"))?;
    let bytes = run(
        command(root).args(["show", &format!("{commit}:{path}")]),
        None,
    )?;
    String::from_utf8(bytes).map_err(|error| refuse("text", error.to_string()))
}

fn validate_version(
    root: &Path,
    development: &str,
    manifest: &toml::Value,
    request: ReleaseRequest<'_>,
) -> Result<String, ReleaseError> {
    let entries = run(
        command(root).args(["ls-tree", "--name-only", development, "--", "Cargo.toml"]),
        None,
    )?;
    let (version, source) = if entries.is_empty() {
        let source = format!("{}:public.version", request.manifest.display());
        let version = manifest
            .get("public")
            .and_then(|public| public.get("version"))
            .ok_or_else(|| {
                refuse(
                    "version-missing",
                    format!("{source} is required without Cargo.toml"),
                )
            })?
            .as_str()
            .ok_or_else(|| refuse("version", format!("{source} must be a string")))?;
        (Some(version.to_owned()), source)
    } else {
        let cargo: toml::Value = toml::from_str(&blob(root, development, Path::new("Cargo.toml"))?)
            .map_err(|error| refuse("version", error.to_string()))?;
        let version = cargo
            .get("workspace")
            .and_then(|workspace| workspace.get("package"))
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str);
        let source = "Cargo.toml:workspace.package.version".to_owned();
        if let Some(declared) = manifest
            .get("public")
            .and_then(|public| public.get("version"))
            .and_then(toml::Value::as_str)
            && Some(declared) != version
        {
            return Err(refuse(
                "version-mismatch",
                format!(
                    "{}:public.version={declared} differs from {source}={}",
                    request.manifest.display(),
                    version.unwrap_or("<missing>"),
                ),
            ));
        }
        (version.map(str::to_owned), source)
    };
    if version.as_deref() != Some(request.version) {
        return Err(refuse(
            "version-mismatch",
            format!("{source} differs from requested version"),
        ));
    }
    Ok(source)
}

fn identity(root: &Path, author: &str, date: &str) -> Result<String, ReleaseError> {
    let (name, email) =
        crate::cut::author(author).map_err(|error| refuse("author", error.to_string()))?;
    let bytes = run(
        command(root)
            .args(["var", "GIT_AUTHOR_IDENT"])
            .env("GIT_AUTHOR_NAME", name)
            .env("GIT_AUTHOR_EMAIL", email)
            .env("GIT_AUTHOR_DATE", date),
        None,
    )?;
    crate::one_line(&bytes).ok_or_else(|| refuse("author", "invalid identity"))
}

fn hash(root: &Path, kind: &str, bytes: &[u8]) -> Result<String, ReleaseError> {
    let output = run(
        command(root).args(["hash-object", "-t", kind, "--stdin"]),
        Some(bytes),
    )?;
    crate::one_line(&output).ok_or_else(|| refuse("object", "invalid object identity"))
}

fn check_expected(
    actual: &str,
    expected: Option<&str>,
    code: &'static str,
) -> Result<(), ReleaseError> {
    if expected.is_some_and(|value| value != actual) {
        return Err(refuse(code, "expected tip changed"));
    }
    Ok(())
}

/// Validate a pinned public development tree, then optionally release it locally.
///
/// # Errors
/// Returns a named refusal for invalid inputs, stale refs, or failed object/ref IO.
pub fn release(request: ReleaseRequest<'_>) -> Result<ReleaseReport, ReleaseError> {
    if !request.check
        && !request.dry_run
        && (request.expected_main.is_none() || request.expected_development.is_none())
    {
        return Err(refuse(
            "unpinned",
            "apply requires both --expected-main and --expected-development from before deployment",
        ));
    }
    let root = request.repository;
    let (main, development, tag) = validate_refs(request)?;
    let tag_ref = format!("refs/tags/{tag}");
    let manifest: toml::Value = toml::from_str(&blob(root, &development, request.manifest)?)
        .map_err(|error| refuse("manifest", error.to_string()))?;
    let version_source = validate_version(root, &development, &manifest, request)?;
    let name = manifest
        .get("public")
        .and_then(|v| v.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.trim().is_empty() && !name.contains(['\n', '\r', '\0']))
        .ok_or_else(|| refuse("manifest-name", "manifest requires public.name"))?;
    let changelog = blob(root, &development, request.changelog)
        .map_err(|error| refuse("notes", error.to_string()))?;
    // Validate the release section even when explicit tag text replaces the notes.
    let notes = crate::cut::publication_tag_message(root, name, &tag, None, Some(&changelog))
        .map_err(|error| refuse("notes", error.to_string()))?;
    let message = if request.tag_message.is_some() {
        crate::cut::publication_tag_message(root, name, &tag, request.tag_message, Some(&changelog))
            .map_err(|error| refuse("tag-message", error.to_string()))?
    } else {
        notes
    };
    let (title, body) = message.split_once("\n\n").unwrap_or((&message, ""));
    let date = match request.date {
        Some(date) => {
            crate::cut::publication_date(date).map_err(|error| refuse("date", error.to_string()))?
        }
        None => line(root, &["show", "-s", "--format=%cI", &development])?,
    };
    let ident = identity(root, request.author, &date)?;
    let tree = line(root, &["rev-parse", &format!("{development}^{{tree}}")])?;
    let subject = format!("chore(release): merge development into main for {tag}\n");
    let commit_bytes = format!(
        "tree {tree}\nparent {main}\nparent {development}\nauthor {ident}\ncommitter {ident}\n\n{subject}"
    );
    let commit = hash(root, "commit", commit_bytes.as_bytes())?;
    let tag_bytes = format!("object {commit}\ntype commit\ntag {tag}\ntagger {ident}\n\n{message}");
    let tag_object = hash(root, "tag", tag_bytes.as_bytes())?;
    let report = ReleaseReport {
        main,
        development,
        commit,
        tree,
        tag_object,
        title: title.to_owned(),
        body_bytes: body.len(),
        version_source,
        refspecs: [
            "refs/heads/main".to_owned(),
            "refs/heads/development".to_owned(),
            tag_ref,
        ],
        state: if request.check {
            "checked"
        } else if request.dry_run {
            "prepared"
        } else {
            "locally-committed"
        },
    };
    if !request.check && !request.dry_run {
        apply(root, &report, &subject, &ident, &tag_bytes)?;
    }
    Ok(report)
}

fn validate_refs(request: ReleaseRequest<'_>) -> Result<(String, String, String), ReleaseError> {
    let root = request.repository;
    crate::validate_repository(root).map_err(|error| refuse("repository", error.to_string()))?;
    let status = run(
        command(root).args(["status", "--porcelain=v1", "--untracked-files=all"]),
        None,
    )?;
    if !status.is_empty() {
        return Err(refuse("dirty-tree", "working tree must be clean"));
    }
    let main = line(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", "refs/heads/main"),
        ],
    )?;
    let development = line(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", "refs/heads/development"),
        ],
    )?;
    check_expected(&main, request.expected_main, "stale-main")?;
    check_expected(
        &development,
        request.expected_development,
        "stale-development",
    )?;
    if main == development {
        return Err(refuse(
            "nothing-to-release",
            "nothing to release: development equals main",
        ));
    }
    let ancestor = command(root)
        .args(["merge-base", "--is-ancestor", &main, &development])
        .status()?;
    if !ancestor.success() {
        return Err(refuse(
            "main-not-ancestor",
            "main must be an ancestor of development",
        ));
    }
    let parts: Vec<_> = request.version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return Err(refuse("version", "version must be X.Y.Z"));
    }
    let tag = format!("v{}", request.version);
    let tag_ref = format!("refs/tags/{tag}");
    let existing = command(root)
        .args(["show-ref", "--verify", "--quiet", &tag_ref])
        .status()?;
    if existing.success() {
        return Err(refuse("existing-tag", &tag));
    }
    if existing.code() != Some(1) {
        return Err(refuse("tag", "cannot check tag absence"));
    }
    Ok((main, development, tag))
}

fn staged_command(root: &Path, objects: &Path, original: &Path) -> Command {
    let mut command = command(root);
    command
        .env("GIT_OBJECT_DIRECTORY", objects)
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", original);
    command
}

fn apply(
    root: &Path,
    report: &ReleaseReport,
    subject: &str,
    ident: &str,
    tag_bytes: &str,
) -> Result<(), ReleaseError> {
    let original = PathBuf::from(line(
        root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ],
    )?);
    let stage = tempfile::tempdir()?;
    let objects = stage.path();
    write_objects(
        || staged_command(root, objects, &original),
        report,
        subject,
        ident,
        tag_bytes,
    )?;
    commit_refs(root, report, objects, &original, || {
        write_objects(|| command(root), report, subject, ident, tag_bytes)
    })
}

fn write_objects(
    git: impl Fn() -> Command,
    report: &ReleaseReport,
    subject: &str,
    ident: &str,
    tag_bytes: &str,
) -> Result<(), ReleaseError> {
    let (author, date) = ident
        .rsplit_once("> ")
        .ok_or_else(|| refuse("author", "invalid normalized identity"))?;
    let author = format!("{author}>");
    let (name, email) =
        crate::cut::author(&author).map_err(|error| refuse("author", error.to_string()))?;
    let commit = run(
        git()
            .args([
                "-c",
                "commit.gpgsign=false",
                "commit-tree",
                &report.tree,
                "-p",
                &report.main,
                "-p",
                &report.development,
            ])
            .env("GIT_AUTHOR_NAME", name)
            .env("GIT_AUTHOR_EMAIL", email)
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_NAME", name)
            .env("GIT_COMMITTER_EMAIL", email)
            .env("GIT_COMMITTER_DATE", date),
        Some(subject.as_bytes()),
    )?;
    if crate::one_line(&commit).as_deref() != Some(&report.commit) {
        return Err(refuse("object", "commit identity mismatch"));
    }
    let tag = run(git().args(["mktag"]), Some(tag_bytes.as_bytes()))?;
    if crate::one_line(&tag).as_deref() != Some(&report.tag_object) {
        return Err(refuse("object", "tag identity mismatch"));
    }
    Ok(())
}

fn commit_refs(
    root: &Path,
    report: &ReleaseReport,
    objects: &Path,
    original: &Path,
    promote: impl FnOnce() -> Result<(), ReleaseError>,
) -> Result<(), ReleaseError> {
    let mut child = staged_command(root, objects, original)
        .args(["update-ref", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let transaction = (|| -> Result<(), ReleaseError> {
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| refuse("transaction", "missing stdin"))?;
        let mut output = io::BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| refuse("transaction", "missing stdout"))?,
        );
        writeln!(
            input,
            "start\nupdate refs/heads/main {} {}\nupdate refs/heads/development {} {}\ncreate {} {}\nprepare",
            report.commit,
            report.main,
            report.commit,
            report.development,
            report.refspecs[2],
            report.tag_object
        )?;
        input.flush()?;
        for expected in ["start: ok\n", "prepare: ok\n"] {
            let mut response = String::new();
            output.read_line(&mut response)?;
            if response != expected {
                return Err(refuse(
                    "stale-refs",
                    "main, development or tag changed before ref locks were acquired",
                ));
            }
        }
        // All three refs are locked and their old values verified before promotion.
        promote()?;
        writeln!(input, "commit")?;
        input.flush()?;
        let mut response = String::new();
        output.read_line(&mut response)?;
        if response != "commit: ok\n" {
            return Err(refuse("transaction", "ref commit failed"));
        }
        Ok(())
    })();
    // Closing stdin aborts an uncommitted prepared transaction; always reap Git.
    let output = child.wait_with_output()?;
    transaction?;
    if !output.status.success() {
        return Err(refuse(
            "transaction",
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(())
}

/// Write release evidence and the standard terminal verdict.
///
/// # Errors
/// Returns an IO error if the output cannot be written.
pub fn write_release_report<W: io::Write>(
    result: &Result<ReleaseReport, ReleaseError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    match result {
        Ok(report) => {
            writeln!(
                output,
                "release state={} M={} D={} R={} tree={} tag_object={} title={} body_bytes={} version_source={}",
                report.state,
                report.main,
                report.development,
                report.commit,
                report.tree,
                report.tag_object,
                serde_json::to_string(&report.title)?,
                report.body_bytes,
                serde_json::to_string(&report.version_source)?
            )?;
            writeln!(
                output,
                "refspecs {} {} {}",
                report.refspecs[0], report.refspecs[1], report.refspecs[2]
            )?;
            crate::write_terminal_report(output, "release", 0, wall, "ok")
        }
        Err(error) => {
            writeln!(
                output,
                "release outcome=refused status=3 reason={} detail={}",
                error.code,
                error.detail.replace(['\n', '\r'], " ")
            )?;
            crate::write_terminal_report(output, "release", 3, wall, "refused")
        }
    }
}
