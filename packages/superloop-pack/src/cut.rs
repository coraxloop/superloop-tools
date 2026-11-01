//! Fresh-history publication from a fixed, clean source tag.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::{resolve_tag, run_git, validate_checkout, validate_repository, write_terminal_report};
use superloop_cli_common::public_set::{Manifest, safe_path};

/// Inputs to one unsigned public commit.
#[derive(Clone, Copy, Debug)]
pub struct CutRequest<'a> {
    pub repository_root: &'a Path,
    pub tag: &'a str,
    pub manifest: &'a Path,
    pub out: &'a Path,
    pub previous: Option<&'a Path>,
    pub author: &'a str,
    /// RFC 3339 publication date; absent means the source commit time.
    pub date: Option<&'a str>,
    /// Optional annotated, unsigned tag on the public commit.
    pub public_tag: Option<&'a str>,
    /// Whole commit message override, with one trailing newline normalized.
    pub message: Option<&'a str>,
    /// Whole annotated tag message override, bypassing changelog extraction.
    pub tag_message: Option<&'a str>,
    /// Private audit input, never copied into the public tree.
    pub burn_register: Option<&'a Path>,
    /// Built linter executable providing the citation-sites protocol.
    pub linter: Option<&'a Path>,
}

/// Evidence naming both the private source and the independent public commit.
#[derive(Debug)]
pub struct CutReport {
    pub files: usize,
    pub bytes: u64,
    pub commit: String,
    pub date: String,
    pub public_tag: Option<String>,
    pub message_override: bool,
    pub tag_message_override: bool,
    pub tree: String,
    pub tag: String,
    pub source_commit: String,
}

/// A cut refusal; failed publication never claims a successful commit.
#[derive(Debug, thiserror::Error)]
#[error("cut refused: {0}")]
pub struct CutError(String);

impl From<io::Error> for CutError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

fn refuse(reason: &str) -> CutError {
    CutError(reason.to_owned())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, CutError> {
    let args: Vec<OsString> = ["-c", "core.hooksPath=/dev/null"]
        .iter()
        .chain(args)
        .map(OsString::from)
        .collect();
    let output = run_git(root, &args)?;
    if !output.status.success() {
        return Err(refuse("git operation failed"));
    }
    Ok(output.stdout)
}

fn line(root: &Path, args: &[&str]) -> Result<String, CutError> {
    let output = git(root, args)?;
    crate::one_line(&output).ok_or_else(|| refuse("invalid git response"))
}

pub fn author(text: &str) -> Result<(&str, &str), CutError> {
    let (name, address) = text
        .rsplit_once(" <")
        .ok_or_else(|| refuse("author requires Name <addr>"))?;
    let address = address
        .strip_suffix('>')
        .ok_or_else(|| refuse("author requires Name <addr>"))?;
    if name.trim().is_empty()
        || !address.contains('@')
        || address.chars().any(char::is_whitespace)
        || text.contains(['\n', '\r', '\0'])
        || name.contains(['<', '>'])
        || address.contains(['<', '>'])
    {
        return Err(refuse("invalid author identity"));
    }
    Ok((name.trim(), address))
}

pub fn publication_date(text: &str) -> Result<String, CutError> {
    let invalid = || refuse("date requires RFC 3339 with an explicit offset or Z");
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || !text.is_ascii()
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(invalid());
    }
    let number = |part: &str| -> Result<u32, CutError> {
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        part.parse().map_err(|_| invalid())
    };
    let year = number(&text[..4])?;
    let month = number(&text[5..7])?;
    let day = number(&text[8..10])?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return Err(invalid()),
    };
    if day == 0
        || day > days
        || number(&text[11..13])? > 23
        || number(&text[14..16])? > 59
        || number(&text[17..19])? > 60
    {
        return Err(invalid());
    }
    let mut zone = &text[19..];
    if let Some(fraction) = zone.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(invalid());
        }
        zone = &fraction[digits..];
    }
    if zone.eq_ignore_ascii_case("Z") {
        zone = "+00:00";
    } else if zone.len() != 6
        || !matches!(zone.as_bytes()[0], b'+' | b'-')
        || zone.as_bytes()[3] != b':'
        || number(&zone[1..3])? > 23
        || number(&zone[4..6])? > 59
    {
        return Err(invalid());
    }
    // Git stores whole seconds; normalize RFC 3339's optional fractional part.
    Ok(format!("{}T{}{zone}", &text[..10], &text[11..19]))
}

fn destination(request: &CutRequest<'_>) -> Result<PathBuf, CutError> {
    let source = fs::canonicalize(request.repository_root)?;
    let out = if let Some(previous) = request.previous {
        let previous = fs::canonicalize(previous)?;
        let out = fs::canonicalize(request.out)?;
        if previous != out {
            return Err(refuse("previous must name the same directory as out"));
        }
        validate_repository(&out).map_err(|_| refuse("previous must be a repository root"))?;
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
            return Err(refuse(
                "previous repository must be clean, including ignored files",
            ));
        }
        out
    } else {
        match request.out.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() && fs::read_dir(request.out)?.next().is_none() => {
                fs::canonicalize(request.out)?
            }
            Ok(_) => {
                return Err(refuse(
                    "out must be absent or an empty directory for an initial cut",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = fs::canonicalize(crate::usable_parent(request.out))?;
                parent.join(
                    request
                        .out
                        .file_name()
                        .ok_or_else(|| refuse("invalid output directory"))?,
                )
            }
            Err(error) => return Err(error.into()),
        }
    };
    if out.starts_with(&source) || source.starts_with(&out) {
        return Err(refuse("source and output directories must not overlap"));
    }
    Ok(out)
}

/// Cut an unsigned commit without importing any source-repository ancestry.
///
/// # Errors
/// Refuses an unclean source, invalid manifest, missing licence, invalid identity,
/// unsafe output, unsupported Git entry, moved tag, or failed publication.
pub fn cut(request: CutRequest<'_>) -> Result<CutReport, CutError> {
    let (name, email) = author(request.author)?;
    let message = publication_message(request.public_tag, request.message)?;
    if request.tag_message.is_some() && request.public_tag.is_none() {
        return Err(refuse("tag-message requires public-tag"));
    }
    let date = request.date.map(publication_date).transpose()?;
    validate_repository(request.repository_root).map_err(|_| refuse("source repository"))?;
    if let Some(tag) = request.public_tag {
        git(
            request.repository_root,
            &["check-ref-format", &format!("refs/tags/{tag}")],
        )
        .map_err(|_| refuse("invalid public tag name"))?;
    }
    let identity =
        resolve_tag(request.repository_root, request.tag).map_err(|_| refuse("source tag"))?;
    validate_checkout(request.repository_root, &identity.commit)
        .map_err(|_| refuse("clean checkout of tag required"))?;
    let (manifest, selection) = select_source(&request, &identity)?;
    let out = destination(&request)?;
    if let Some(tag) = request.public_tag
        && request.previous.is_some()
        && !git(&out, &["tag", "--list", tag])?.is_empty()
    {
        return Err(refuse("public tag already exists"));
    }
    let parent = if request.previous.is_some() {
        Some(line(&out, &["rev-parse", "HEAD"])?)
    } else {
        None
    };
    let temporary = tempfile::tempdir_in(crate::usable_parent(&out))?;
    let stage = temporary.path().join("repository");
    fs::create_dir(&stage)?;
    git(
        &stage,
        &["init", "-q", "--template=", "--initial-branch=main"],
    )?;
    if let Some(parent) = &parent {
        git(
            &stage,
            &[
                "fetch",
                "--no-tags",
                "--",
                out.to_str().ok_or_else(|| refuse("non-UTF-8 output"))?,
                parent,
            ],
        )?;
    }
    let (files, bytes) = stage_tree(
        &request,
        &stage,
        &identity.commit,
        &manifest,
        selection.included,
    )?;
    let tree = line(&stage, &["write-tree"])?;
    let commit = create_commit(
        &stage,
        &tree,
        parent.as_deref(),
        &message,
        &identity,
        (name, email),
        date.as_deref(),
    )?;
    let date = line(&stage, &["show", "-s", "--format=%aI", &commit])?;
    if let Some(tag) = request.public_tag {
        let tag_message = publication_tag_message(
            &stage,
            &manifest.public.name,
            tag,
            request.tag_message,
            None,
        )?;
        create_public_tag(&stage, tag, &commit, (name, email), &date, &tag_message)?;
    }
    let rechecked =
        resolve_tag(request.repository_root, request.tag).map_err(|_| refuse("tag moved"))?;
    if rechecked != identity {
        return Err(refuse("tag moved"));
    }
    publish_commit(&stage, &out, parent.as_deref(), &commit, request.public_tag)?;
    Ok(CutReport {
        files,
        bytes,
        commit,
        date,
        public_tag: request.public_tag.map(str::to_owned),
        message_override: request.message.is_some(),
        tag_message_override: request.tag_message.is_some(),
        tree,
        tag: request.tag.to_owned(),
        source_commit: identity.commit,
    })
}

fn publish_commit(
    stage: &Path,
    out: &Path,
    parent: Option<&str>,
    commit: &str,
    public_tag: Option<&str>,
) -> Result<(), CutError> {
    if let Some(parent) = parent {
        if line(out, &["rev-parse", "HEAD"])? != parent
            || !git(
                out,
                &[
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    "--ignored",
                ],
            )?
            .is_empty()
        {
            return Err(refuse("previous repository changed during cut"));
        }
        git(
            out,
            &[
                "fetch",
                "--no-tags",
                "--",
                stage
                    .to_str()
                    .ok_or_else(|| refuse("non-UTF-8 staging path"))?,
                commit,
            ],
        )?;
        git(
            out,
            &["-c", "core.hooksPath=/dev/null", "reset", "--hard", commit],
        )?;
        if let Some(tag) = public_tag {
            git(
                out,
                &[
                    "fetch",
                    "--no-tags",
                    "--",
                    stage
                        .to_str()
                        .ok_or_else(|| refuse("non-UTF-8 staging path"))?,
                    &format!("refs/tags/{tag}:refs/tags/{tag}"),
                ],
            )?;
        }
    } else {
        fs::rename(stage, out)?;
    }
    Ok(())
}

pub fn publication_tag_message(
    stage: &Path,
    name: &str,
    tag: &str,
    message: Option<&str>,
    content: Option<&str>,
) -> Result<String, CutError> {
    if let Some(message) = message {
        if message.trim().is_empty() || message.contains('\0') {
            return Err(refuse("tag-message must be non-empty and contain no NUL"));
        }
        return Ok(message.to_owned());
    }
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let heading = format!("## [{version}] - ");
    let selected_heading = format!("## [{version}] (optionally - DATE)");
    let missing = || {
        if content.is_some() {
            refuse(&format!(
                "selected changelog requires heading {selected_heading}"
            ))
        } else {
            refuse(&format!("CHANGELOG.md requires heading {heading}DATE"))
        }
    };
    let changelog = match content {
        Some(text) => text.to_owned(),
        None => String::from_utf8(git(stage, &["show", ":CHANGELOG.md"]).map_err(|_| missing())?)
            .map_err(|_| missing())?,
    };
    let mut lines = changelog.split_inclusive('\n');
    lines
        .find(|line| {
            (content.is_some() && line.trim_end() == format!("## [{version}]"))
                || line.trim_end().strip_prefix(&heading).is_some_and(|date| {
                    date.len() == 10 && publication_date(&format!("{date}T00:00:00Z")).is_ok()
                })
        })
        .ok_or_else(missing)?;
    let mut body: Vec<_> = lines
        .take_while(|line| !line.starts_with("## "))
        .filter(|line| {
            !line.trim_start().strip_prefix('[').is_some_and(|rest| {
                rest.split_once("]:")
                    .is_some_and(|(label, url)| !label.is_empty() && !url.trim().is_empty())
            })
        })
        .skip_while(|line| line.trim().is_empty())
        .collect();
    while body.last().is_some_and(|line| line.trim().is_empty()) {
        body.pop();
    }
    if body.is_empty() {
        if content.is_some() {
            return Err(refuse(&format!(
                "selected changelog requires non-empty body for heading {selected_heading}"
            )));
        }
        return Err(refuse(&format!(
            "CHANGELOG.md requires non-empty body for heading {heading}DATE"
        )));
    }
    Ok(format!("{name} {tag}\n\n{}", body.concat()))
}

fn create_public_tag(
    stage: &Path,
    tag: &str,
    commit: &str,
    author: (&str, &str),
    date: &str,
    message: &str,
) -> Result<(), CutError> {
    let output = crate::git_command(stage)
        .args([
            "-c",
            "tag.gpgsign=false",
            "tag",
            "--no-sign",
            "--annotate",
            "--cleanup=verbatim",
            "--message",
            message,
            "--",
            tag,
            commit,
        ])
        .env("GIT_COMMITTER_NAME", author.0)
        .env("GIT_COMMITTER_EMAIL", author.1)
        .env("GIT_COMMITTER_DATE", date)
        .output()?;
    if !output.status.success() {
        return Err(refuse("unsigned public tag creation failed"));
    }
    Ok(())
}

fn publication_message(
    public_tag: Option<&str>,
    message: Option<&str>,
) -> Result<String, CutError> {
    if let Some(message) = message {
        if message.trim().is_empty() || message.contains('\0') {
            return Err(refuse("message must be non-empty and contain no NUL"));
        }
        return Ok(format!("{}\n", message.trim_end_matches('\n')));
    }
    Ok(public_tag.map_or_else(
        || "feat(release): publish the source set\n".to_owned(),
        |name| format!("feat(release): publish {name}\n"),
    ))
}

fn create_commit(
    stage: &Path,
    tree: &str,
    parent: Option<&str>,
    message: &str,
    identity: &crate::SourceIdentity,
    author: (&str, &str),
    date: Option<&str>,
) -> Result<String, CutError> {
    let (name, email) = author;
    let mut command = crate::git_command(stage);
    command.args([
        "-c",
        "commit.gpgsign=false",
        "commit-tree",
        tree,
        "-m",
        message,
    ]);
    if let Some(parent) = parent {
        command.args(["-p", parent]);
    }
    for key in ["GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"] {
        command.env(key, name);
    }
    for key in ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"] {
        command.env(key, email);
    }
    for key in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
        command.env(
            key,
            date.map_or_else(|| format!("@{} +0000", identity.commit_time), str::to_owned),
        );
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(refuse("unsigned commit creation failed"));
    }
    let commit =
        crate::one_line(&output.stdout).ok_or_else(|| refuse("invalid commit identity"))?;
    git(stage, &["update-ref", "HEAD", &commit])?;
    Ok(commit)
}

pub fn select_source(
    request: &CutRequest<'_>,
    identity: &crate::SourceIdentity,
) -> Result<(Manifest, superloop_cli_common::public_set::Selection), CutError> {
    let manifest_path = request
        .manifest
        .to_str()
        .filter(|path| safe_path(path))
        .ok_or_else(|| refuse("manifest must be source-relative"))?;
    let paths: Vec<_> = tree_entries(request.repository_root, &identity.commit)?
        .into_keys()
        .collect();
    if !paths.iter().any(|path| path == manifest_path) {
        return Err(refuse("manifest must be tracked at the tag"));
    }
    let manifest_bytes = git(
        request.repository_root,
        &["show", &format!("{}:{manifest_path}", identity.commit)],
    )?;
    let manifest = Manifest::parse(
        std::str::from_utf8(&manifest_bytes).map_err(|_| refuse("manifest must be UTF-8"))?,
    )
    .map_err(CutError)?;
    let selection = manifest.select(&paths);
    if !selection.issues.is_empty() {
        return Err(CutError(selection.issues.join("; ")));
    }
    for (kind, path) in [
        ("code", &manifest.public.licence_code),
        ("documents", &manifest.public.licence_docs),
    ] {
        if !selection.included.contains(path) {
            return Err(CutError(format!(
                "{kind} licence {path} is absent from the public set; both licence files must be included before cutting"
            )));
        }
    }
    if !selection.included.contains(&manifest.public.readme) {
        return Err(refuse("public README source is absent from the public set"));
    }
    if manifest.public.readme == manifest.public.licence_code
        || manifest.public.readme == manifest.public.licence_docs
        || manifest.public.readme == manifest_path
    {
        return Err(refuse(
            "public README source must differ from manifest and licence paths",
        ));
    }
    Ok((manifest, selection))
}

fn stage_tree(
    request: &CutRequest<'_>,
    stage: &Path,
    commit: &str,
    manifest: &Manifest,
    included: Vec<String>,
) -> Result<(usize, u64), CutError> {
    let projected = project_tree(request, commit, manifest, included)?;
    write_projection(stage, &projected)
}

pub type Projection = BTreeMap<String, (String, Vec<u8>)>;

pub fn project_tree(
    request: &CutRequest<'_>,
    commit: &str,
    manifest: &Manifest,
    included: Vec<String>,
) -> Result<Projection, CutError> {
    project_tree_with_policy(request, commit, manifest, included, None, false)
}

pub fn project_tree_with_policy(
    request: &CutRequest<'_>,
    commit: &str,
    manifest: &Manifest,
    included: Vec<String>,
    policy_bytes: Option<&[u8]>,
    readme_fallback: bool,
) -> Result<Projection, CutError> {
    let root = request.repository_root;
    let manifest_path = request.manifest;
    let burn_register = request.burn_register;
    let linter = request.linter;
    let entries = tree_entries(root, commit)?;
    let mut selected = BTreeMap::new();
    for path in included {
        let entry = entries
            .get(&path)
            .ok_or_else(|| refuse("tracked path missing from tag tree"))?;
        if !matches!(entry.0.as_str(), "100644" | "100755" | "120000") {
            return Err(refuse("unsupported public tree entry"));
        }
        selected.insert(path, entry.clone());
    }
    let readme_source = if readme_fallback {
        "README.md"
    } else {
        &manifest.public.readme
    };
    for required in [
        manifest.public.licence_code.as_str(),
        manifest.public.licence_docs.as_str(),
        readme_source,
    ] {
        if !selected
            .get(required)
            .is_some_and(|(mode, _)| mode == "100644" || mode == "100755")
        {
            return Err(refuse(
                "both licence files and public README must be regular files",
            ));
        }
    }
    let readme = selected
        .get(readme_source)
        .cloned()
        .ok_or_else(|| refuse("missing public README"))?;
    selected.remove(readme_source);
    selected.insert("README.md".to_owned(), readme);
    let generated = unpublished_register(
        root,
        commit,
        manifest,
        readme_source,
        selected.keys(),
        burn_register,
        linter,
    )?;
    for path in generated.keys() {
        selected
            .entry(path.clone())
            .or_insert_with(|| ("100644".into(), String::new()));
    }
    let mut projected = BTreeMap::new();
    for (path, (mode, object)) in &selected {
        let content = match generated.get(path) {
            Some(content) => content.clone(),
            None => git(root, &["cat-file", "blob", object])?,
        };
        let content = if Path::new(path) == manifest_path {
            public_manifest(policy_bytes.unwrap_or(&content), selected.keys())?
        } else {
            content
        };
        projected.insert(path.clone(), (mode.clone(), content));
    }
    Ok(projected)
}

pub fn write_projection(stage: &Path, projected: &Projection) -> Result<(usize, u64), CutError> {
    let mut bytes = 0;
    for (path, (mode, content)) in projected {
        bytes += content.len() as u64;
        let target = stage.join(path);
        fs::create_dir_all(crate::usable_parent(&target))?;
        // Hash regular staging bytes without Git filters, then restore link/mode semantics.
        fs::write(&target, content)?;
        let object = line(stage, &["hash-object", "-w", "--no-filters", "--", path])?;
        git(
            stage,
            &["update-index", "--add", "--cacheinfo", mode, &object, path],
        )?;
        if mode == "120000" {
            fs::remove_file(&target)?;
            symlink(std::ffi::OsStr::from_bytes(content), &target)?;
        } else {
            fs::set_permissions(
                &target,
                fs::Permissions::from_mode(if mode == "100755" { 0o755 } else { 0o644 }),
            )?;
        }
    }
    Ok((projected.len(), bytes))
}

const UNPUBLISHED_PATH: &str = "docs/public/unpublished-labels.toml";

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct UnpublishedLabel {
    label: String,
    owner: String,
    path_class: String,
}

#[derive(Serialize)]
struct UnpublishedLabels {
    namespace: String,
    version: [u64; 3],
    labels: Vec<UnpublishedLabel>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationSites {
    namespace: String,
    version: [u64; 3],
    sites: Vec<CitationSite>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CitationSite {
    citing_path: String,
    target_path: String,
    surface: CitationSurface,
    label: String,
    owner: String,
    path_class: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CitationSurface {
    Document,
    Code,
    Imported,
    Unpublished,
}

fn resolved_sites(
    root: &Path,
    commit: &str,
    linter: Option<&Path>,
) -> Result<CitationSites, CutError> {
    let linter = linter.ok_or_else(|| refuse("unpublished labels require --linter"))?;
    let linter =
        fs::canonicalize(linter).map_err(|_| refuse("unreadable citation-sites linter"))?;
    let scratch = historical_tree(root, commit)?;
    let output = Command::new(linter)
        .arg("citation-sites")
        .arg("--root")
        .arg(scratch.path())
        .stdin(Stdio::null())
        .output()
        .map_err(|_| refuse("citation-sites linter could not run"))?;
    if !output.status.success() {
        return Err(refuse("citation-sites linter refused"));
    }
    let report: CitationSites = serde_json::from_slice(&output.stdout)
        .map_err(|_| refuse("invalid citation-sites JSON"))?;
    if report.namespace != "class.linter.citation-sites" || report.version != [1, 0, 0] {
        return Err(refuse("unknown citation-sites protocol"));
    }
    Ok(report)
}

fn unpublished_register<'a>(
    root: &Path,
    commit: &str,
    manifest: &Manifest,
    readme_source: &str,
    included: impl Iterator<Item = &'a String>,
    burn_register: Option<&Path>,
    linter: Option<&Path>,
) -> Result<BTreeMap<String, Vec<u8>>, CutError> {
    let mut included: std::collections::BTreeSet<_> = included.cloned().collect();
    // The root's public text is read from this source before it is consumed.
    included.remove("README.md");
    included.insert(readme_source.to_owned());
    let mut generated = BTreeMap::new();
    if !included.contains(".linter/owners.toml") {
        return Ok(generated);
    }
    let burn = cut_burn_register(root, burn_register)?;
    let sites = resolved_sites(root, commit, linter)?;
    let mut labels = std::collections::BTreeSet::new();
    for site in sites.sites {
        if !included.contains(&site.citing_path) {
            continue;
        }
        let class = match site.surface {
            CitationSurface::Unpublished => Some(
                site.path_class
                    .ok_or_else(|| refuse("unpublished site has no path class"))?,
            ),
            CitationSurface::Document => manifest
                .excluded_class(&site.target_path)
                .map(str::to_owned),
            CitationSurface::Code | CitationSurface::Imported => None,
        };
        if let Some(path_class) = class {
            if !safe_path(path_class.trim_end_matches('/')) {
                return Err(refuse("invalid unpublished path class"));
            }
            labels.insert(UnpublishedLabel {
                label: site.label,
                owner: site.owner,
                path_class,
            });
        }
    }
    let document = UnpublishedLabels {
        namespace: "class.linter.unpublished-labels".to_owned(),
        version: [1, 0, 0],
        labels: labels.into_iter().collect(),
    };
    let content = toml::to_string(&document).map_err(|error| CutError(error.to_string()))?;
    guard_unpublished(&document, &burn)?;
    generated.insert(UNPUBLISHED_PATH.to_owned(), content.into_bytes());
    generated.insert(
        ".linter/owners.toml".to_owned(),
        public_owners(root, commit)?,
    );
    Ok(generated)
}

fn public_owners(root: &Path, commit: &str) -> Result<Vec<u8>, CutError> {
    let content = git(root, &["show", &format!("{commit}:.linter/owners.toml")])?;
    let mut owners: toml::Value =
        toml::from_str(std::str::from_utf8(&content).map_err(|_| refuse("owners must be UTF-8"))?)
            .map_err(|error| CutError(error.to_string()))?;
    let table = owners
        .as_table_mut()
        .ok_or_else(|| refuse("owner snapshot must be a table"))?;
    let mut envelope = BTreeMap::new();
    for key in ["namespace", "version"] {
        envelope.insert(
            key,
            table
                .remove(key)
                .ok_or_else(|| refuse("owner snapshot envelope missing"))?,
        );
    }
    table.insert(
        "unpublished".to_owned(),
        toml::Value::String(UNPUBLISHED_PATH.to_owned()),
    );
    let mut content = toml::to_string(&envelope).map_err(|error| CutError(error.to_string()))?;
    content.push_str(&toml::to_string(table).map_err(|error| CutError(error.to_string()))?);
    Ok(content.into_bytes())
}

pub fn cut_burn_register(
    root: &Path,
    path: Option<&Path>,
) -> Result<crate::BurnDocument, CutError> {
    let path = path.ok_or_else(|| refuse("unpublished labels require --burn-register"))?;
    let path =
        fs::canonicalize(path).map_err(|_| refuse("unreadable unpublished-label burn register"))?;
    if path.starts_with(fs::canonicalize(root)?) {
        return Err(refuse(
            "unpublished-label burn register must stay outside the source tree",
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|_| refuse("unreadable unpublished-label burn register"))?;
    let document: crate::BurnDocument =
        toml::from_str(&text).map_err(|_| refuse("invalid unpublished-label burn register"))?;
    if document.values.is_empty()
        || document
            .values
            .iter()
            .any(|row| row.value.trim().is_empty())
    {
        return Err(refuse(
            "unpublished-label burn register must contain non-empty values",
        ));
    }
    Ok(document)
}

/// Audit each entry field with the same literal matcher as the build census.
fn guard_unpublished(
    document: &UnpublishedLabels,
    burn: &crate::BurnDocument,
) -> Result<(), CutError> {
    use superloop_cli_common::burn_match::burn_offsets;

    for (position, entry) in document.labels.iter().enumerate() {
        for (field, content) in [
            ("label", &entry.label),
            ("owner", &entry.owner),
            ("path_class", &entry.path_class),
        ] {
            let content = content.to_lowercase();
            for value in &burn.values {
                let needle = value.value.to_lowercase();
                let identifier = matches!(value.mode, crate::BurnMatch::Identifier);
                if burn_offsets(content.as_bytes(), needle.as_bytes(), identifier)
                    .next()
                    .is_some()
                {
                    // Even a non-matching fragment can disclose a private value in context.
                    let label = entry.label.to_lowercase();
                    let private_label = burn.values.iter().any(|value| {
                        burn_offsets(
                            label.as_bytes(),
                            value.value.to_lowercase().as_bytes(),
                            false,
                        )
                        .next()
                        .is_some()
                    });
                    let entry_name = if private_label {
                        format!("{} of {}", position + 1, document.labels.len())
                    } else {
                        format!("{:?}", entry.label)
                    };
                    let kind = if identifier {
                        "identifier"
                    } else {
                        "substring"
                    };
                    return Err(refuse(&format!(
                        "unpublished register entry {entry_name} field {field} matches private audit kind {kind}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn public_manifest<'a>(
    content: &[u8],
    paths: impl Iterator<Item = &'a String>,
) -> Result<Vec<u8>, CutError> {
    let text = std::str::from_utf8(content).map_err(|_| refuse("manifest must be UTF-8"))?;
    let mut public: toml::Value =
        toml::from_str(text).map_err(|error| CutError(error.to_string()))?;
    public["exclude"]["rows"] = toml::Value::Array(Vec::new());
    public["public"]["readme"] = toml::Value::String("README.md".to_owned());
    public["include"]["rows"] = toml::Value::Array(
        paths
            .map(|path| {
                let mut row = toml::map::Map::new();
                row.insert("pattern".to_owned(), toml::Value::String(path.clone()));
                toml::Value::Table(row)
            })
            .collect(),
    );
    let text = toml::to_string(&public).map_err(|error| CutError(error.to_string()))?;
    Ok(
        format!("# Exclusion is a source-side matter; the cut has consumed those rows.\n{text}")
            .into_bytes(),
    )
}

pub fn tree_entries(
    root: &Path,
    commit: &str,
) -> Result<BTreeMap<String, (String, String)>, CutError> {
    let output = git(root, &["ls-tree", "-r", "-z", commit])?;
    let mut entries = BTreeMap::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let record = std::str::from_utf8(record).map_err(|_| refuse("non-UTF-8 tree path"))?;
        let (header, path) = record
            .split_once('\t')
            .ok_or_else(|| refuse("invalid tree entry"))?;
        if !safe_path(path)
            || path
                .split('/')
                .any(|part| part.eq_ignore_ascii_case(".git"))
        {
            return Err(refuse("unsafe tree path"));
        }
        let fields: Vec<_> = header.split(' ').collect();
        if let [mode, _, object] = fields.as_slice() {
            entries.insert(path.to_owned(), ((*mode).to_owned(), (*object).to_owned()));
        } else {
            return Err(refuse("invalid tree entry fields"));
        }
    }
    Ok(entries)
}

// A disposable input snapshot, never inside a publication destination. Blob writes
// bypass attributes, filters and hooks; the index supplies the linter's tracked set.
fn historical_tree(root: &Path, commit: &str) -> Result<tempfile::TempDir, CutError> {
    let scratch = tempfile::Builder::new()
        .prefix("pack-citations-")
        .tempdir()?;
    git(scratch.path(), &["init", "-q", "--template="])?;
    let mut projected = Projection::new();
    for (path, (mode, object)) in tree_entries(root, commit)? {
        if !matches!(mode.as_str(), "100644" | "100755" | "120000") {
            return Err(refuse("unsupported historical tree entry"));
        }
        projected.insert(path, (mode, git(root, &["cat-file", "blob", &object])?));
    }
    write_projection(scratch.path(), &projected)?;
    Ok(scratch)
}

/// Publish a cut's evidence using the pack command's terminal report convention.
///
/// # Errors
/// Returns an IO error if the report cannot be written.
pub fn write_cut_report<W: io::Write>(
    result: &Result<CutReport, CutError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    match result {
        Ok(report) => {
            writeln!(
                output,
                "cut files={} bytes={} commit={} date={} tree={} tag={} source_commit={} public_tag={} message_override={} tag_message_override={}",
                report.files,
                report.bytes,
                report.commit,
                report.date,
                report.tree,
                report.tag,
                report.source_commit,
                report.public_tag.as_deref().unwrap_or("-"),
                if report.message_override { "yes" } else { "no" },
                if report.tag_message_override {
                    "yes"
                } else {
                    "no"
                }
            )?;
            write_terminal_report(output, "cut", 0, wall, "ok")
        }
        Err(error) => {
            writeln!(
                output,
                "cut outcome=refused status=3 reason={}",
                error.0.replace(['\n', '\r'], " ")
            )?;
            write_terminal_report(output, "cut", 3, wall, "refused")
        }
    }
}

#[cfg(test)]
mod guard_tests {
    use super::{cut_burn_register, guard_unpublished};

    /// Message overrides refuse blank text and embedded NUL bytes.
    ///
    /// # Panics
    /// Panics only if a message override accepts invalid text.
    /// ´test:unit:publication-overrides-refuse-invalid-text´
    #[test]
    fn publication_overrides_refuse_invalid_text() {
        for message in ["", " \t\n", "notes\0body"] {
            assert!(super::publication_message(None, Some(message)).is_err());
            let error = super::publication_tag_message(
                std::path::Path::new("."),
                "fixture",
                "v0.1.0",
                Some(message),
                None,
            )
            .expect_err("invalid tag message");
            assert_eq!(
                error.to_string(),
                "cut refused: tag-message must be non-empty and contain no NUL"
            );
        }
    }

    /// A private value in an unpublished slug refuses, and audit inputs cannot be absent or empty.
    ///
    /// # Panics
    /// Panics only if fixture IO fails or the guard accepts a private slug or invalid audit input.
    /// ´claim:cutguard:private-values-refuse-unpublished-slugs´
    /// ´test:unit:private-values-refuse-unpublished-slugs´
    #[test]
    fn private_values_refuse_unpublished_slugs() {
        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("source");
        std::fs::create_dir(&root).expect("source");
        let path = fixture.path().join("burn.toml");
        assert!(cut_burn_register(&root, None).is_err());
        std::fs::write(&path, "values = []\n").expect("empty input");
        assert!(cut_burn_register(&root, Some(&path)).is_err());
        std::fs::write(
            &path,
            "[[values]]\nvalue = \"PrIvAtE-NoDe\"\nmatch = \"substring\"\n",
        )
        .expect("private input");
        let burn = cut_burn_register(&root, Some(&path)).expect("outside input");
        let mut document = super::UnpublishedLabels {
            namespace: "class.linter.unpublished-labels".to_owned(),
            version: [1, 0, 0],
            labels: vec![super::UnpublishedLabel {
                label: "def:fixture:private-node".to_owned(),
                owner: "EXAMPLE".to_owned(),
                path_class: "private/".to_owned(),
            }],
        };
        let refusal = guard_unpublished(&document, &burn).expect_err("major reference");
        assert_eq!(
            refusal.to_string(),
            "cut refused: unpublished register entry 1 of 1 field label matches private audit kind substring"
        );
        document.labels[0].label = "def:fixture:ordinary".to_owned();
        document.labels[0].owner = "private-node".to_owned();
        assert!(guard_unpublished(&document, &burn).is_err());
        document.labels[0].owner = "EXAMPLE".to_owned();
        document.labels[0].path_class = "private-node/".to_owned();
        assert!(guard_unpublished(&document, &burn).is_err());
        std::fs::write(
            &path,
            "[[values]]\nvalue = \"unrelated-node\"\nmatch = \"identifier\"\n",
        )
        .expect("unrelated input");
        assert!(
            guard_unpublished(
                &document,
                &cut_burn_register(&root, Some(&path)).expect("input")
            )
            .is_ok()
        );
        let mut burn: crate::BurnDocument =
            toml::from_str("[[values]]\nvalue = \"Sagofink\"\nmatch = \"identifier\"\n")
                .expect("invented input");
        document.labels[0].label = "dec:fixture:xsagofinkable".to_owned();
        document.labels[0].path_class = "private/".to_owned();
        assert!(guard_unpublished(&document, &burn).is_ok());
        burn.values[0].mode = crate::BurnMatch::Substring;
        assert!(guard_unpublished(&document, &burn).is_err());
        burn.values[0].mode = crate::BurnMatch::Identifier;
        document.labels[0].label = "dec:fixture:ordinary".to_owned();
        for field in ["owner", "path_class", "label"] {
            let entry = &mut document.labels[0];
            entry.owner = "EXAMPLE".to_owned();
            entry.path_class = "private/".to_owned();
            match field {
                "owner" => entry.owner = "sagofink".to_owned(),
                "path_class" => entry.path_class = "private/sagofink/".to_owned(),
                _ => entry.label = "dec:fixture:sagofink".to_owned(),
            }
            let message = guard_unpublished(&document, &burn)
                .expect_err("whole identifier")
                .to_string();
            if field == "label" {
                assert!(message.contains("entry 1 of 1"));
            } else {
                assert!(message.contains("entry \"dec:fixture:ordinary\""));
            }
            assert!(message.contains(&format!("field {field}")));
            assert!(message.contains("kind identifier"));
            assert!(!message.contains("sagofink"));
        }
        document.labels[0].label = "dec:fixture:xsagofinkable".to_owned();
        document.labels[0].owner = "SAGOFINK".to_owned();
        document.labels.insert(
            0,
            super::UnpublishedLabel {
                label: "dec:fixture:ordinary".to_owned(),
                owner: "EXAMPLE".to_owned(),
                path_class: "private/".to_owned(),
            },
        );
        let message = guard_unpublished(&document, &burn)
            .expect_err("owner hit with non-matching label fragment")
            .to_string();
        assert_eq!(
            message,
            "cut refused: unpublished register entry 2 of 2 field owner matches private audit kind identifier"
        );
        assert!(!message.to_lowercase().contains("sagofink"));
        assert!(!message.contains(&document.labels[1].label));
        let inside = root.join("burn.toml");
        std::fs::copy(&path, &inside).expect("inside input");
        assert!(cut_burn_register(&root, Some(&inside)).is_err());
    }
}
