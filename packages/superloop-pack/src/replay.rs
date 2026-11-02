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
    pub author: Option<&'a str>,
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
pub struct ReplayError(String, Option<Box<ValidationEvidence>>);

impl From<io::Error> for ReplayError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string(), None)
    }
}

impl From<cut::CutError> for ReplayError {
    fn from(error: cut::CutError) -> Self {
        Self(error.to_string(), None)
    }
}

fn refuse(reason: impl Into<String>) -> ReplayError {
    ReplayError(reason.into(), None)
}

#[derive(Clone, Debug, Default, Serialize)]
struct ValidationContext {
    check: String,
    ordinal: Option<usize>,
    commit: Option<String>,
    field: String,
    path: Option<String>,
    matcher_kind: Option<String>,
    register_kind: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ValidationEvidence {
    scratch_root: PathBuf,
    report_path: PathBuf,
    validated: Vec<ValidationContext>,
    current: ValidationContext,
    #[serde(rename = "pre-existing")]
    pre_existing: Vec<ValidationContext>,
}

impl ValidationEvidence {
    fn begin(
        &mut self,
        check: &str,
        ordinal: Option<usize>,
        commit: Option<&str>,
        field: &str,
        path: Option<&str>,
    ) {
        if !self.current.check.is_empty() {
            self.validated.push(self.current.clone());
        }
        self.current = ValidationContext {
            check: check.into(),
            ordinal,
            commit: commit.map(str::to_owned),
            field: field.into(),
            path: path.map(str::to_owned),
            ..ValidationContext::default()
        };
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Identity {
    name: String,
    email: String,
    timestamp: String,
    timezone: String,
}

#[derive(Clone, Debug)]
struct SourceCommit {
    oid: String,
    parents: Vec<String>,
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
    projection_version: String,
    projection_sha256: String,
    policy_sha256: String,
    linter_version: serde_json::Value,
    linter_sha256: String,
    register_sha256: String,
    register_schema: &'static str,
    mapping: Vec<Mapping>,
    checks: Vec<Check>,
    #[serde(rename = "pre-existing")]
    pre_existing: Vec<ValidationContext>,
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
    let source = read_commit(root, oid)?;
    if source.parents.len() != 1 {
        return Err(refuse("merge or root commit in replay range"));
    }
    Ok(source)
}

fn read_commit(root: &Path, oid: &str) -> Result<SourceCommit, ReplayError> {
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
    if authors.len() != 1 || committers.len() != 1 {
        return Err(refuse("commit requires one author and one committer"));
    }
    let message = bytes[boundary + 2..].to_vec();
    if message.contains(&0) || (!message.is_empty() && !message.ends_with(b"\n")) {
        return Err(refuse("unsupported commit message framing"));
    }
    Ok(SourceCommit {
        oid: oid.into(),
        parents,
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
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    scan_with_root(burn, ordinal, field, bytes, None, evidence)
}

fn scan_with_root(
    burn: &crate::BurnDocument,
    ordinal: usize,
    field: &str,
    bytes: &[u8],
    root_bytes: Option<&[u8]>,
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    let folded = String::from_utf8_lossy(bytes).to_lowercase();
    let root_folded = root_bytes.map(|bytes| String::from_utf8_lossy(bytes).to_lowercase());
    for value in &burn.values {
        let identifier = matches!(value.mode, crate::BurnMatch::Identifier);
        let needle = value.value.to_lowercase();
        if burn_offsets(folded.as_bytes(), needle.as_bytes(), identifier)
            .next()
            .is_some()
        {
            let kind = if identifier {
                "identifier"
            } else {
                "substring"
            };
            evidence.current.matcher_kind = Some(kind.into());
            evidence.current.register_kind = Some("values".into());
            if root_folded.as_ref().is_some_and(|root| {
                burn_offsets(root.as_bytes(), needle.as_bytes(), identifier)
                    .next()
                    .is_some()
            }) {
                evidence.pre_existing.push(evidence.current.clone());
                continue;
            }
            if field == "path" {
                evidence.current.path = Some(format!("sha256:{}", crate::sha256_bytes(bytes)));
            }
            return Err(refuse(format!(
                "source ordinal {ordinal} field {field} match kind {kind} register kind values"
            )));
        }
    }
    Ok(())
}

fn scan_metadata(
    burn: &crate::BurnDocument,
    ordinal: usize,
    source: &SourceCommit,
    public: &SourceCommit,
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    evidence.begin(
        "metadata scan",
        Some(ordinal),
        Some(&source.oid),
        "message",
        None,
    );
    scan_with_root(
        burn,
        ordinal,
        "message",
        &source.message,
        Some(&public.message),
        evidence,
    )?;
    scan_identity_fields(burn, ordinal, source, public, "metadata scan", evidence)
}

fn scan_identity_fields(
    burn: &crate::BurnDocument,
    ordinal: usize,
    source: &SourceCommit,
    public: &SourceCommit,
    check: &str,
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    for (field, value, public_value) in [
        ("author.name", &source.author.name, &public.author.name),
        ("author.email", &source.author.email, &public.author.email),
        (
            "committer.name",
            &source.committer.name,
            &public.committer.name,
        ),
        (
            "committer.email",
            &source.committer.email,
            &public.committer.email,
        ),
    ] {
        evidence.begin(check, Some(ordinal), Some(&source.oid), field, None);
        scan_with_root(
            burn,
            ordinal,
            field,
            value.as_bytes(),
            Some(public_value.as_bytes()),
            evidence,
        )?;
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
            return Err(refuse("Git cannot preserve the identity and date verbatim"));
        }
    }
    Ok(())
}

fn map_author(source: &SourceCommit, author: Option<&(String, String)>) -> SourceCommit {
    let mut mapped = source.clone();
    if let Some((name, email)) = author {
        for identity in [&mut mapped.author, &mut mapped.committer] {
            identity.name.clone_from(name);
            identity.email.clone_from(email);
        }
    }
    mapped
}

fn prepare_author_override(
    request: &ReplayRequest<'_>,
    sources: &[SourceCommit],
    public: &SourceCommit,
    burn: &crate::BurnDocument,
    evidence: &mut ValidationEvidence,
) -> Result<Option<(String, String)>, ReplayError> {
    let author = request
        .author
        .map(cut::author)
        .transpose()?
        .map(|(name, email)| (name.to_owned(), email.to_owned()));
    if author.is_some() {
        for (index, source) in sources.iter().enumerate() {
            let mapped = map_author(source, author.as_ref());
            scan_identity_fields(
                burn,
                index + 1,
                &mapped,
                public,
                "mapped metadata scan",
                evidence,
            )?;
            validate_git_identity(request.repository_root, &mapped)?;
        }
    }
    Ok(author)
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

impl Policy {
    fn permits_public_path(&self, path: &str) -> bool {
        // The bound is on public destinations: the final README source is consumed
        // at README.md, never emitted at its source path as a second README.
        if path != "README.md" && path == self.manifest.public.readme {
            return false;
        }
        let source = if path == "README.md" {
            &self.manifest.public.readme
        } else {
            path
        };
        self.manifest
            .select(&[source.to_owned()])
            .included
            .iter()
            .any(|included| included == source)
    }
}

fn historical_policy(
    request: &ReplayRequest<'_>,
    oid: &str,
    bound: &Policy,
) -> Result<Policy, ReplayError> {
    let path = request
        .manifest
        .to_str()
        .ok_or_else(|| refuse("manifest must be UTF-8"))?;
    let bytes = git(request.repository_root, &["show", &format!("{oid}:{path}")])
        .map_err(|_| refuse("historical manifest missing or unreadable"))?;
    let mut document: toml::Value = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| refuse("historical manifest encoding"))?,
    )
    .map_err(|_| refuse("invalid historical manifest"))?;
    let public = document
        .get_mut("public")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| refuse("historical manifest public table missing"))?;
    // Backfill publication naming only for manifests that predate the field.
    // Historical selection and required input paths remain commit-local.
    if !public.contains_key("name") {
        public.insert(
            "name".into(),
            toml::Value::String(bound.manifest.public.name.clone()),
        );
    }
    let text = toml::to_string(&document).map_err(|_| refuse("historical manifest encoding"))?;
    let manifest = Manifest::parse(&text).map_err(|_| refuse("invalid historical manifest"))?;
    if [&manifest.public.licence_code, &manifest.public.licence_docs]
        .contains(&&manifest.public.readme)
        || manifest.public.readme == path
    {
        return Err(refuse(
            "public README source must differ from manifest and licence paths",
        ));
    }
    Ok(Policy {
        manifest,
        bytes: text.into_bytes(),
    })
}

fn bounded_policy(
    historical: &Policy,
    included: &[String],
    removed: &[String],
) -> Result<Policy, ReplayError> {
    let mut document: toml::Value = toml::from_str(
        std::str::from_utf8(&historical.bytes)
            .map_err(|_| refuse("historical manifest encoding"))?,
    )
    .map_err(|_| refuse("invalid historical manifest"))?;
    let rows = included
        .iter()
        .map(|path| {
            let mut row = toml::map::Map::new();
            row.insert("pattern".into(), toml::Value::String(path.clone()));
            toml::Value::Table(row)
        })
        .collect();
    document["include"]["rows"] = toml::Value::Array(rows);
    let exclusions = document["exclude"]["rows"]
        .as_array_mut()
        .ok_or_else(|| refuse("invalid historical manifest"))?;
    for path in removed {
        let mut row = toml::map::Map::new();
        row.insert("pattern".into(), toml::Value::String(path.clone()));
        row.insert(
            "reason".into(),
            toml::Value::String("Outside the final public-path bound.".into()),
        );
        exclusions.push(toml::Value::Table(row));
    }
    let text = toml::to_string(&document).map_err(|_| refuse("historical manifest encoding"))?;
    let manifest = Manifest::parse(&text).map_err(|_| refuse("invalid historical manifest"))?;
    Ok(Policy {
        manifest,
        bytes: text.into_bytes(),
    })
}

struct PlannedCommit {
    tree: Projection,
    omitted: usize,
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
    evidence: &mut ValidationEvidence,
) -> Result<PlannedCommit, ReplayError> {
    let ordinal = evidence.current.ordinal;
    evidence.begin(
        "manifest",
        ordinal,
        Some(oid),
        "historical policy",
        request.manifest.to_str(),
    );
    let historical = historical_policy(request, oid, policy)?;
    evidence.begin("projection", ordinal, Some(oid), "tree", None);
    let entries = cut::tree_entries(request.repository_root, oid)?;
    let manifest = &historical.manifest;
    let paths = entries.keys().cloned().collect::<Vec<_>>();
    let mut selected = manifest.select(&paths);
    // Classification is historical, before the final bound removes any paths.
    if let Some(issue) = selected
        .issues
        .iter()
        .find(|issue| !issue.starts_with("dead manifest row:"))
    {
        evidence.current.check = "manifest".into();
        evidence.current.field = "historical classification".into();
        evidence.current.path = issue.split_once(": ").map(|(_, path)| path.to_owned());
        return Err(refuse("historical policy cannot classify tree"));
    }
    let mut removed = Vec::new();
    selected.included.retain(|path| {
        let public_path = if path == &manifest.public.readme {
            "README.md"
        } else {
            path
        };
        let keep = policy.permits_public_path(public_path);
        if !keep {
            removed.push(path.clone());
        }
        keep
    });
    validate_required_entries(oid, manifest, &selected.included, &entries, evidence)?;
    let bounded = bounded_policy(&historical, &selected.included, &removed)?;
    let omitted = selected.tracked.saturating_sub(selected.included.len());
    let mut projected = cut::project_tree_with_policy(
        &cut_request(request),
        oid,
        &bounded.manifest,
        selected.included,
        Some(&bounded.bytes),
    )
    .map_err(|error| annotate_projection_error(evidence, error))?;
    // Generated paths obey the same public destination bound as source paths.
    projected.retain(|path, _| policy.permits_public_path(path));
    refresh_projected_manifest(request, &mut projected, &bounded.bytes).inspect_err(|_| {
        evidence.current.check = "manifest".into();
        evidence.current.field = "projected inventory".into();
        evidence.current.path = request.manifest.to_str().map(str::to_owned);
    })?;
    Ok(PlannedCommit {
        tree: projected,
        omitted,
    })
}

fn validate_required_entries(
    oid: &str,
    manifest: &Manifest,
    included: &[String],
    entries: &std::collections::BTreeMap<String, (String, String)>,
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    for path in [&manifest.public.licence_code, &manifest.public.licence_docs] {
        if !included.contains(path)
            || !entries
                .get(path)
                .is_some_and(|(mode, _)| matches!(mode.as_str(), "100644" | "100755"))
        {
            evidence.current.check = "licence/README validation".into();
            evidence.current.path = Some(path.clone());
            return Err(refuse(format!(
                "commit {oid}: required licence absent or not regular"
            )));
        }
    }
    let readme_path = &manifest.public.readme;
    if !included.iter().any(|path| path == readme_path)
        || !entries
            .get(readme_path)
            .is_some_and(|(mode, _)| matches!(mode.as_str(), "100644" | "100755"))
    {
        evidence.current.check = "licence/README validation".into();
        evidence.current.path = Some(readme_path.into());
        return Err(refuse("required README absent or not regular"));
    }
    for path in included {
        if !entries
            .get(path)
            .is_some_and(|(mode, _)| matches!(mode.as_str(), "100644" | "100755" | "120000"))
        {
            evidence.current.path = Some(path.clone());
            return Err(refuse("unsupported public tree entry"));
        }
    }
    Ok(())
}

fn refresh_projected_manifest(
    request: &ReplayRequest<'_>,
    projected: &mut Projection,
    policy_bytes: &[u8],
) -> Result<(), ReplayError> {
    // Cut retains historical reservations for archive reproduction. Replay consumes
    // them, just as it consumes exclusions, rather than publishing private selectors.
    let path = request
        .manifest
        .to_str()
        .ok_or_else(|| refuse("manifest must be UTF-8"))?;
    let bytes = cut::public_manifest(policy_bytes, projected.keys())?;
    let (_, content) = projected
        .get_mut(path)
        .ok_or_else(|| refuse("manifest excluded by final policy"))?;
    let mut document: toml::Value =
        toml::from_str(std::str::from_utf8(&bytes).map_err(|_| refuse("manifest encoding"))?)
            .map_err(|_| refuse("manifest encoding"))?;
    if let Some(table) = document.as_table_mut() {
        table.remove("reserved");
    }
    *content = format!(
        "# Exclusion is a source-side matter; the cut has consumed those rows.\n{}",
        toml::to_string(&document).map_err(|_| refuse("manifest encoding"))?
    )
    .into_bytes();
    Ok(())
}

fn annotate_projection_error(
    evidence: &mut ValidationEvidence,
    error: cut::CutError,
) -> ReplayError {
    evidence.current.field = "public projection inputs".into();
    if error.to_string().contains("citation-sites") {
        evidence.current.field = "citation-sites".into();
        evidence.current.path = Some(".linter/owners.toml".into());
    }
    if let Some((_, suffix)) = error.to_string().rsplit_once(" field ") {
        for field in ["label", "owner", "path_class"] {
            for kind in ["identifier", "substring"] {
                if suffix == format!("{field} matches private audit kind {kind}") {
                    evidence.current.check = "burn scan".into();
                    evidence.current.field = format!("unpublished.{field}");
                    evidence.current.path = Some("docs/public/unpublished-labels.toml".into());
                    evidence.current.matcher_kind = Some(kind.into());
                    evidence.current.register_kind = Some("values".into());
                }
            }
        }
    }
    ReplayError::from(error)
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
        return Err(refuse("commit-tree changed requested metadata"));
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
    let started = Instant::now();
    let scratch = fs::canonicalize(std::env::temp_dir())?;
    for root in [request.repository_root, request.out] {
        if fs::canonicalize(root).is_ok_and(|root| scratch.starts_with(root)) {
            return Err(refuse(
                "check=inputs field=TMPDIR: TMPDIR must be outside source and output",
            ));
        }
    }
    let temporary = tempfile::Builder::new()
        .prefix("pack-replay-evidence-")
        .tempdir()?;
    let mut evidence = ValidationEvidence {
        scratch_root: temporary.path().to_path_buf(),
        report_path: temporary.path().join("refusal.json"),
        ..ValidationEvidence::default()
    };
    evidence.begin("inputs", None, None, "source repository", None);
    let result = replay_preflight(request, &mut evidence);
    match result {
        Ok(report) => Ok(report),
        Err(mut error) => {
            drop(temporary.keep());
            redact_diagnostic_paths(&request, &mut evidence);
            let context = &evidence.current;
            error.0 = format!(
                "check={} source ordinal={} commit={} field={} path={}: {}",
                context.check,
                context
                    .ordinal
                    .map_or_else(|| "unresolved".into(), |value| value.to_string()),
                context.commit.as_deref().unwrap_or("unresolved"),
                context.field,
                context.path.as_deref().unwrap_or("none"),
                error.0,
            );
            error.1 = Some(Box::new(evidence));
            if let Some(evidence) = &error.1 {
                let saved = fs::File::create(&evidence.report_path).and_then(|file| {
                    serde_json::to_writer_pretty(
                        file,
                        &serde_json::json!({
                            "outcome": "refused", "reason": error.0, "validation": evidence,
                            "exit": 3, "wall_seconds": started.elapsed().as_secs_f64()
                        }),
                    )
                    .map_err(io::Error::other)
                });
                if saved.is_err() {
                    error.0.push_str("; private report write failed");
                }
            }
            Err(error)
        }
    }
}

fn redact_diagnostic_paths(request: &ReplayRequest<'_>, evidence: &mut ValidationEvidence) {
    let Ok(burn) = cut::cut_burn_register(request.repository_root, Some(request.burn_register))
    else {
        return;
    };
    for context in evidence
        .validated
        .iter_mut()
        .chain(std::iter::once(&mut evidence.current))
    {
        if let Some(path) = &mut context.path {
            let folded = path.to_lowercase();
            if burn.values.iter().any(|value| {
                burn_offsets(
                    folded.as_bytes(),
                    value.value.to_lowercase().as_bytes(),
                    matches!(value.mode, crate::BurnMatch::Identifier),
                )
                .next()
                .is_some()
            }) {
                *path = format!("sha256:{}", crate::sha256_bytes(path.as_bytes()));
            }
        }
    }
}

fn replay_preflight(
    request: ReplayRequest<'_>,
    evidence: &mut ValidationEvidence,
) -> Result<ReplayReport, ReplayError> {
    crate::validate_repository(request.repository_root).map_err(|_| refuse("source repository"))?;
    evidence.begin("inputs", None, None, "since", None);
    let since = resolve(request.repository_root, request.since)?;
    evidence.begin("inputs", Some(0), Some(&since), "tag", None);
    let tag = resolve(request.repository_root, request.tag)?;
    evidence.begin("inputs", Some(0), Some(&since), "public root", None);
    let public_root = resolve(request.out, request.public_root)?;
    let context = format!("since={since} tag={tag} public_root={public_root}");
    replay_resolved(request, since, tag, public_root, evidence)
        .map_err(|error| refuse(format!("{context}: {}", error.0)))
}

fn replay_resolved(
    request: ReplayRequest<'_>,
    since: String,
    tag: String,
    public_root: String,
    evidence: &mut ValidationEvidence,
) -> Result<ReplayReport, ReplayError> {
    let started = Instant::now();
    evidence.begin("inputs", Some(0), Some(&since), "source checkout", None);
    let (out, scratch_root) =
        preflight_destination(&request, &since, &tag, &public_root, evidence)?;
    evidence.begin("burn scan", Some(0), Some(&since), "burn register", None);
    let burn = cut::cut_burn_register(request.repository_root, Some(request.burn_register))?;
    let register = fs::canonicalize(request.burn_register)?;
    if register.starts_with(&out) {
        return Err(refuse("burn register must be outside output"));
    }
    let register_sha256 = crate::sha256_file(&register)?;
    evidence.begin("projection", Some(0), Some(&since), "linter", None);
    let linter = fs::canonicalize(request.linter)?;
    let linter_sha256 = crate::sha256_file(&linter)?;
    let version = Command::new(&linter).arg("--version").output()?;
    let linter_version = linter_version(&version)?;
    let projection_sha256 = crate::sha256_file(&std::env::current_exe()?)?;
    let public_metadata = read_public_root(request.out, &public_root, evidence)?;
    let sources = linear_sources(&request, &since, &tag, &burn, &public_metadata, evidence)?;
    evidence.begin("inputs", None, Some(&tag), "author override", None);
    let author_override =
        prepare_author_override(&request, &sources, &public_metadata, &burn, evidence)?;
    evidence.begin(
        "manifest",
        Some(sources.len()),
        Some(&tag),
        "final policy",
        request.manifest.to_str(),
    );
    let (policy, policy_sha256) = read_policy(&request, &tag)?;
    let (public, planned, generated_drift) = plan_trees(
        &request,
        &since,
        &public_root,
        &policy,
        &burn,
        &sources,
        evidence,
    )?;
    let checks = vec![Check {
        name: "whole-range-preflight".into(),
        exit: 0,
        wall_seconds: started.elapsed().as_secs_f64(),
    }];
    // No output write occurred above. Only input snapshots lived in TMPDIR.
    evidence.begin("staging", None, Some(&tag), "repository", None);
    let temporary = staging_repository(&evidence.scratch_root, &out, &public_root)?;
    let stage_path = temporary.keep();
    let stage = stage_path.as_path();
    let mut writer = Writer {
        author_override,
        parent: public_root.clone(),
        parent_tree: public,
        mapping: Vec::new(),
        checks,
    };
    replay_commits(
        stage,
        &linter,
        &register,
        &sources,
        planned,
        &mut writer,
        evidence,
    )?;
    evidence.begin("inputs", None, Some(&tag), "immutable inputs", None);
    if resolve(request.repository_root, request.since)? != since
        || resolve(request.repository_root, request.tag)? != tag
        || crate::sha256_file(&register)? != register_sha256
        || crate::sha256_file(&linter)? != linter_sha256
    {
        return Err(refuse("replay inputs changed"));
    }
    evidence.begin("destination", None, Some(&tag), "expected tip", None);
    output_ready(&request, &public_root)?;
    publish(stage, &out, &public_root, &mut writer)?;
    let final_tree = line(&out, &["rev-parse", &format!("{}^{{tree}}", writer.parent)])?;
    Ok(ReplayReport {
        since,
        tag,
        public_root,
        final_tip: writer.parent,
        final_tree,
        files: writer.parent_tree.len(),
        scratch_root,
        generated_drift,
        projection_version: env!("CARGO_PKG_VERSION").into(),
        projection_sha256,
        policy_sha256,
        linter_version,
        linter_sha256,
        register_sha256,
        register_schema: "unversioned-values",
        mapping: writer.mapping,
        checks: writer.checks,
        pre_existing: evidence.pre_existing.clone(),
    })
}

fn read_public_root(
    root: &Path,
    oid: &str,
    evidence: &mut ValidationEvidence,
) -> Result<SourceCommit, ReplayError> {
    evidence.begin("inputs", Some(0), Some(oid), "public root metadata", None);
    read_commit(root, oid)
}

fn linter_version(version: &std::process::Output) -> Result<serde_json::Value, ReplayError> {
    if !version.status.success() {
        return Err(refuse("linter version failed"));
    }
    serde_json::from_slice(&version.stderr).map_err(|_| refuse("linter version protocol"))
}

fn preflight_destination(
    request: &ReplayRequest<'_>,
    since: &str,
    tag: &str,
    public_root: &str,
    evidence: &mut ValidationEvidence,
) -> Result<(PathBuf, PathBuf), ReplayError> {
    crate::validate_checkout(request.repository_root, tag)
        .map_err(|_| refuse("clean checkout of tag required"))?;
    if since == tag {
        return Err(refuse("nothing to replay"));
    }
    evidence.begin(
        "destination",
        Some(0),
        Some(since),
        "output repository",
        None,
    );
    let out = output_ready(request, public_root)?;
    let scratch_root = fs::canonicalize(std::env::temp_dir())?;
    if scratch_root.starts_with(&out)
        || scratch_root.starts_with(fs::canonicalize(request.repository_root)?)
    {
        return Err(refuse("TMPDIR must be outside source and output"));
    }
    Ok((out, scratch_root))
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
                "replay since={} tag={} public_root={} tip={} files={} replayed={} skipped={} signatures=omitted pre-existing={}",
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
                    .count(),
                serde_json::to_string(&report.pre_existing)?
            )?;
            crate::write_terminal_report(output, "replay", 0, wall, "ok")
        }
        Err(error) => {
            let pre_existing = error
                .1
                .as_ref()
                .map_or(&[][..], |evidence| evidence.pre_existing.as_slice());
            serde_json::to_writer(
                &mut *output,
                &serde_json::json!({
                    "outcome": "refused", "scratch_root": error.1.as_ref().map(|evidence| &evidence.scratch_root),
                    "validation": error.1.as_ref().map(|evidence| serde_json::json!({
                        "current": evidence.current, "report_path": evidence.report_path,
                        "validated_checks": evidence.validated.len()
                    })),
                    "reason": error.0, "exit": 3, "wall_seconds": wall.as_secs_f64(),
                    "pre-existing": pre_existing
                }),
            )?;
            writeln!(output)?;
            writeln!(
                output,
                "replay outcome=refused status=3 reason={} pre-existing={}",
                error.0.replace(['\n', '\r'], " "),
                serde_json::to_string(pre_existing)?
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
    public_metadata: &SourceCommit,
    evidence: &mut ValidationEvidence,
) -> Result<Vec<SourceCommit>, ReplayError> {
    evidence.begin("range", None, Some(tag), "source range", None);
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
        evidence.begin(
            "range",
            Some(index + 1),
            Some(oid),
            "parents and commit headers",
            None,
        );
        let source = source_commit(request.repository_root, oid)
            .map_err(|error| refuse(format!("source ordinal {}: {error}", index + 1)))?;
        if source.parents[0] != previous {
            return Err(refuse(format!(
                "source ordinal {}: disconnected first-parent range",
                index + 1
            )));
        }
        scan_metadata(burn, index + 1, &source, public_metadata, evidence)?;
        evidence.begin(
            "metadata scan",
            Some(index + 1),
            Some(oid),
            "identity and date",
            None,
        );
        validate_git_identity(request.repository_root, &source)
            .map_err(|error| refuse(format!("source ordinal {}: {error}", index + 1)))?;
        previous = oid.into();
        sources.push(source);
    }
    Ok(sources)
}

struct Writer {
    author_override: Option<(String, String)>,
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
    evidence: &mut ValidationEvidence,
) -> Result<(), ReplayError> {
    for (index, (source, PlannedCommit { tree, omitted })) in
        sources.iter().zip(planned).enumerate()
    {
        evidence.begin(
            "projection",
            Some(index + 1),
            Some(&source.oid),
            "staged tree",
            None,
        );
        let mapped_parent = writer.parent.clone();
        let skipped = tree == writer.parent_tree;
        clear_stage(stage)?;
        cut::write_projection(stage, &tree)?;
        let tree_oid = line(stage, &["write-tree"])?;
        if read_projection(stage, &tree_oid)? != tree {
            return Err(refuse("written tree differs from preflight projection"));
        }
        let check_start = Instant::now();
        evidence.begin(
            "projection",
            Some(index + 1),
            Some(&source.oid),
            "public tree linter",
            None,
        );
        let observation = crate::run_linter(linter, stage, register).map_err(|_| {
            refuse(format!(
                "source ordinal {}: linter protocol failed",
                index + 1
            ))
        })?;
        if !valid_replay_linter(&observation, register, index + 1, evidence) {
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
        let mapped = map_author(source, writer.author_override.as_ref());
        if !skipped {
            writer.parent = write_commit(stage, &tree_oid, &writer.parent, &mapped)?;
        }
        writer.mapping.push(Mapping {
            ordinal: index + 1,
            source: source.oid.clone(),
            source_parent: source.parents[0].clone(),
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
            new_author: (!skipped).then_some(mapped.author),
            new_committer: (!skipped).then_some(mapped.committer),
            message_sha256: crate::sha256_bytes(&source.message),
            signature_omitted: source.signature_omitted,
            selected_paths: tree.len(),
            omitted_paths: omitted,
        });
        writer.parent_tree = tree;
    }
    Ok(())
}

fn valid_replay_linter(
    observation: &crate::LinterObservation,
    register: &Path,
    ordinal: usize,
    evidence: &ValidationEvidence,
) -> bool {
    if crate::validate_linter_verdict(observation, register).is_ok() {
        return true;
    }
    let report = &observation.report;
    let source = register.to_string_lossy();
    let bound: Vec<_> = report
        .burn
        .families
        .iter()
        .filter(|family| family.binds(&source))
        .collect();
    let paths: BTreeSet<_> = evidence
        .pre_existing
        .iter()
        .filter(|context| context.ordinal == Some(ordinal) && context.field == "blob")
        .filter_map(|context| context.path.as_deref())
        .collect();
    // The whole-range byte scan has already refused every introduced match.
    // Only external-register growth at those proved paths can excuse a finding;
    // all other linter failures and burn families retain their ordinary verdict.
    let failures: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "failure")
        .collect();
    !paths.is_empty()
        && !bound.is_empty()
        && report.public_pack
        && report.clean == (report.failures == 0)
        && observation.status_success == report.clean
        && failures.len() == report.failures
        && failures.iter().all(|finding| {
            finding.code == "burn_list_growth"
                && finding
                    .path
                    .as_deref()
                    .is_some_and(|path| paths.contains(path))
                && bound
                    .iter()
                    .any(|family| finding.family.as_deref() == Some(family.family.as_str()))
        })
        && report.burn.owed == bound.iter().map(|family| family.owed).sum::<usize>()
        && report.burn.families.iter().all(|family| {
            family.binds(&source) || (family.owed == 0 && family.occurrences <= family.registered)
        })
}

type PlannedTrees = (Projection, Vec<PlannedCommit>, Vec<String>);

fn plan_trees(
    request: &ReplayRequest<'_>,
    since: &str,
    public_root: &str,
    policy: &Policy,
    burn: &crate::BurnDocument,
    sources: &[SourceCommit],
    evidence: &mut ValidationEvidence,
) -> Result<PlannedTrees, ReplayError> {
    evidence.begin("projection", Some(0), Some(since), "historical tree", None);
    let base =
        project(request, since, policy, evidence).map_err(|error| projection_refusal(0, &error))?;
    let public = read_projection(request.out, public_root)?;
    let paths: BTreeSet<_> = base.tree.keys().chain(public.keys()).cloned().collect();
    let generated_drift: Vec<_> = paths
        .into_iter()
        .filter(|path| base.tree.get(path) != public.get(path))
        .collect();
    let mut planned = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        evidence.begin(
            "projection",
            Some(index + 1),
            Some(&source.oid),
            "historical tree",
            None,
        );
        let projection = project(request, &source.oid, policy, evidence)
            .map_err(|error| projection_refusal(index + 1, &error))?;
        for path in projection.tree.keys() {
            evidence.begin(
                "burn scan",
                Some(index + 1),
                Some(&source.oid),
                "path",
                None,
            );
            scan(burn, index + 1, "path", path.as_bytes(), evidence)?;
        }
        for (path, (_, bytes)) in &projection.tree {
            evidence.begin(
                "burn scan",
                Some(index + 1),
                Some(&source.oid),
                "blob",
                Some(path),
            );
            scan_with_root(
                burn,
                index + 1,
                "blob",
                bytes,
                public.get(path).map(|(_, bytes)| bytes.as_slice()),
                evidence,
            )?;
        }
        planned.push(projection);
    }
    if !generated_drift.is_empty() && !request.accept_generated_drift {
        for path in &generated_drift {
            evidence.begin("burn scan", Some(0), Some(since), "path", None);
            scan(burn, 0, "path", path.as_bytes(), evidence)?;
        }
        evidence.begin(
            "drift guard",
            Some(0),
            Some(since),
            "base projection versus public root",
            Some(&generated_drift.join(", ")),
        );
        return Err(refuse(format!(
            "generated drift: {}",
            generated_drift.join(", ")
        )));
    }
    Ok((public, planned, generated_drift))
}

fn projection_refusal(ordinal: usize, error: &ReplayError) -> ReplayError {
    let reason = error.0.strip_prefix("cut refused: ").unwrap_or(&error.0);
    if reason.starts_with("citation-sites linter refused; diagnostic scratch=") {
        return refuse(format!("source ordinal {ordinal}: {reason}"));
    }
    if [
        "git operation failed",
        "invalid git response",
        "non-UTF-8 tree path",
        "invalid tree entry",
        "unsafe tree path",
        "invalid tree entry fields",
        "unsupported historical tree entry",
        "tracked path missing from tag tree",
        "both licence files and public README must be regular files",
        "missing public README",
        "manifest must be UTF-8",
        "unpublished labels require --linter",
        "unreadable citation-sites linter",
        "citation-sites linter could not run",
        "owner snapshot must be a table",
        "unpublished labels require --burn-register",
        "unreadable unpublished-label burn register",
        "invalid unpublished-label burn register",
        "unpublished-label burn register must stay outside the source tree",
        "unpublished-label burn register must contain non-empty values",
        "citation-sites linter refused",
        "invalid citation-sites JSON",
        "unknown citation-sites protocol",
        "required README absent or not regular",
        "unsupported public tree entry",
        "historical policy cannot classify tree",
        "historical manifest missing or unreadable",
        "historical manifest encoding",
        "invalid historical manifest",
        "historical manifest public table missing",
        "public README source must differ from manifest and licence paths",
        "manifest excluded by final policy",
        "manifest encoding",
        "invalid unpublished path class",
        "unpublished site has no path class",
        "owner snapshot envelope missing",
        "owners must be UTF-8",
    ]
    .contains(&reason)
    {
        return refuse(format!("source ordinal {ordinal}: {reason}"));
    }
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
                        "source ordinal {ordinal} field unpublished.{field} match kind {kind} register kind values"
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

#[cfg(test)]
mod tests {
    use super::{ValidationContext, ValidationEvidence, valid_replay_linter};
    use std::path::Path;

    /// Only external burn growth at a proved pre-existing blob can pass replay lint.
    ///
    /// # Panics
    /// Panics only if fixture decoding fails or an unrelated failure is accepted.
    /// ´test:unit:pre-existing-lint-exception-is-bounded´
    #[test]
    fn pre_existing_lint_exception_is_bounded() {
        let evidence = ValidationEvidence {
            pre_existing: vec![ValidationContext {
                ordinal: Some(1),
                field: "blob".into(),
                path: Some("public/file.txt".into()),
                ..ValidationContext::default()
            }],
            ..ValidationEvidence::default()
        };
        let report = serde_json::json!({
            "clean": false, "failures": 1, "public_pack": true,
            "burn": {"owed": 0, "families": [{
                "family": "public-pack values", "declared": 1,
                "source": "/register.toml", "source_kind": "external",
                "occurrences": 1, "registered": 0, "owed": 0
            }]},
            "findings": [{"severity": "failure", "code": "burn_list_growth",
                "family": "public-pack values", "path": "public/file.txt"}]
        });
        let accepts = |report| {
            let observation = crate::LinterObservation {
                status_success: false,
                report: serde_json::from_value(report).expect("fixture report"),
            };
            valid_replay_linter(&observation, Path::new("/register.toml"), 1, &evidence)
        };
        assert!(accepts(report.clone()));
        for (pointer, replacement) in [
            ("/findings/0/code", serde_json::json!("malformed_label")),
            ("/findings/0/path", serde_json::json!("public/new.txt")),
            ("/findings/0/family", serde_json::json!("other family")),
            (
                "/burn/families/0/source_kind",
                serde_json::json!("repository"),
            ),
            ("/burn/owed", serde_json::json!(1)),
            ("/failures", serde_json::json!(2)),
            ("/public_pack", serde_json::json!(false)),
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).expect("fixture field") = replacement;
            assert!(!accepts(changed), "{pointer}");
        }
    }
}
