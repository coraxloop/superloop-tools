#![doc = include_str!("../README.md")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File, FileTimes};
use std::io::{self, BufReader, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

mod cut;
pub use cut::{CutError, CutReport, CutRequest, cut, write_cut_report};

#[cfg(test)]
mod tests;

/// Command name used by the superloop-pack binary and its report contract.
pub const COMMAND_NAME: &str = "superloop-pack";

/// Path of the provenance member inside every pack.
pub const MANIFEST_PATH: &str = "docs/public-pack-provenance.toml";

/// Current provenance-manifest and archive-format version.
pub const PACK_FORMAT: u32 = 1;

const DEFAULT_LINTER_VERSION: &str = "unspecified";
const ZIP_END_SIGNATURE: u32 = 0x0605_4b50;
const ZIP_CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const ZIP_LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const ZIP_END_MINIMUM: usize = 22;
const ZIP_END_SEARCH: u64 = 65_557;

/// Strict provenance document embedded in the final archive.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceManifest {
    pub pack_format: u32,
    pub tag: String,
    pub commit: String,
    pub tree: String,
    pub archive_sha256: String,
    pub burn_register_sha256: String,
    pub burn_register_count: usize,
    pub linter_version: String,
}

/// Inputs to one archive build.
#[derive(Clone, Copy, Debug)]
pub struct BuildRequest<'a> {
    pub tag: &'a str,
    pub out: &'a Path,
    pub burn_register: &'a Path,
    pub linter_version: Option<&'a str>,
    pub repository_root: &'a Path,
}

/// Successful archive-build evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildReport {
    pub manifest: ProvenanceManifest,
    pub final_zip_sha256: String,
}

/// Stable archive-build refusal reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildRefusal {
    Repository,
    Tag,
    Checkout,
    BurnRegister,
    Archive,
    TagMoved,
    Publication,
}

impl BuildRefusal {
    /// Stable report spelling for this refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Tag => "tag",
            Self::Checkout => "checkout",
            Self::BurnRegister => "burn_register",
            Self::Archive => "archive",
            Self::TagMoved => "tag_moved",
            Self::Publication => "publication",
        }
    }
}

impl fmt::Display for BuildRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One path-free archive-build refusal.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("archive build refused: {reason}")]
pub struct BuildError {
    reason: BuildRefusal,
}

impl BuildError {
    const fn new(reason: BuildRefusal) -> Self {
        Self { reason }
    }

    /// Stable reason for the refusal.
    #[must_use]
    pub const fn reason(self) -> BuildRefusal {
        self.reason
    }

    /// Declared process status for build refusals.
    #[must_use]
    pub const fn exit_status(self) -> u8 {
        3
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceIdentity {
    tag_ref: String,
    commit: String,
    tree: String,
    commit_time: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildStage {
    CheckoutValidated,
    BeforeTagRecheck,
}

/// Build one provenance-bound public archive.
///
/// # Errors
///
/// Returns a typed refusal if the repository, tag, checkout, register, archive,
/// tag recheck, or final publication does not satisfy the pack contract.
pub fn build(request: BuildRequest<'_>) -> Result<BuildReport, BuildError> {
    build_with_hook(request, |_stage| Ok(()))
}

fn build_with_hook<F>(request: BuildRequest<'_>, mut hook: F) -> Result<BuildReport, BuildError>
where
    F: FnMut(BuildStage) -> Result<(), BuildError>,
{
    validate_repository(request.repository_root)?;
    let identity = resolve_tag(request.repository_root, request.tag)?;
    validate_checkout(request.repository_root, &identity.commit)?;
    validate_output_identity(request.out, request.burn_register)?;
    hook(BuildStage::CheckoutValidated)?;

    let (burn_register_sha256, burn_register_count) = read_burn_register(request.burn_register)
        .map_err(|()| BuildError::new(BuildRefusal::BurnRegister))?;
    let linter_version = request
        .linter_version
        .unwrap_or(DEFAULT_LINTER_VERSION)
        .to_owned();
    if linter_version.is_empty() {
        return Err(BuildError::new(BuildRefusal::BurnRegister));
    }

    let temporary = tempfile::tempdir().map_err(|_error| BuildError::new(BuildRefusal::Archive))?;
    let plain_archive = temporary.path().join("public-pack-without-manifest.zip");
    run_git_archive(request.repository_root, &identity, &plain_archive, None)?;
    let archive_sha256 =
        sha256_file(&plain_archive).map_err(|_error| BuildError::new(BuildRefusal::Archive))?;

    let manifest = ProvenanceManifest {
        pack_format: PACK_FORMAT,
        tag: request.tag.to_owned(),
        commit: identity.commit.clone(),
        tree: identity.tree.clone(),
        archive_sha256,
        burn_register_sha256,
        burn_register_count,
        linter_version,
    };
    let manifest_text =
        toml::to_string(&manifest).map_err(|_error| BuildError::new(BuildRefusal::Archive))?;
    let manifest_file = temporary.path().join("public-pack-provenance.toml");
    fs::write(&manifest_file, manifest_text.as_bytes())
        .map_err(|_error| BuildError::new(BuildRefusal::Archive))?;
    set_file_time(&manifest_file, identity.commit_time)
        .map_err(|_error| BuildError::new(BuildRefusal::Archive))?;

    let final_archive = temporary.path().join("superloop-pack.zip");
    run_git_archive(
        request.repository_root,
        &identity,
        &final_archive,
        Some(&manifest_file),
    )?;
    let final_zip_sha256 =
        sha256_file(&final_archive).map_err(|_error| BuildError::new(BuildRefusal::Archive))?;

    hook(BuildStage::BeforeTagRecheck)?;
    let rechecked = resolve_tag(request.repository_root, request.tag)
        .map_err(|_error| BuildError::new(BuildRefusal::TagMoved))?;
    if rechecked != identity {
        return Err(BuildError::new(BuildRefusal::TagMoved));
    }

    publish_archive(&final_archive, request.out)?;
    Ok(BuildReport {
        manifest,
        final_zip_sha256,
    })
}

fn validate_repository(root: &Path) -> Result<(), BuildError> {
    let canonical =
        fs::canonicalize(root).map_err(|_error| BuildError::new(BuildRefusal::Repository))?;
    let output = run_git(
        root,
        &[
            OsString::from("rev-parse"),
            OsString::from("--show-toplevel"),
        ],
    )
    .map_err(|_error| BuildError::new(BuildRefusal::Repository))?;
    if !output.status.success() {
        return Err(BuildError::new(BuildRefusal::Repository));
    }
    let declared =
        one_line(&output.stdout).ok_or_else(|| BuildError::new(BuildRefusal::Repository))?;
    let discovered =
        fs::canonicalize(declared).map_err(|_error| BuildError::new(BuildRefusal::Repository))?;
    if canonical != discovered {
        return Err(BuildError::new(BuildRefusal::Repository));
    }
    Ok(())
}

fn resolve_tag(root: &Path, tag: &str) -> Result<SourceIdentity, BuildError> {
    if tag.is_empty() {
        return Err(BuildError::new(BuildRefusal::Tag));
    }
    let tag_ref = format!("refs/tags/{tag}");
    let checked = run_git(
        root,
        &[OsString::from("check-ref-format"), OsString::from(&tag_ref)],
    )
    .map_err(|_error| BuildError::new(BuildRefusal::Tag))?;
    if !checked.status.success() {
        return Err(BuildError::new(BuildRefusal::Tag));
    }

    let commit_spec = format!("{tag_ref}^{{commit}}");
    let commit = git_line(
        root,
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("--end-of-options"),
            OsString::from(commit_spec),
        ],
        BuildRefusal::Tag,
    )?;
    let tree_spec = format!("{commit}^{{tree}}");
    let tree = git_line(
        root,
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("--end-of-options"),
            OsString::from(tree_spec),
        ],
        BuildRefusal::Tag,
    )?;
    let commit_time = git_line(
        root,
        &[
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%ct"),
            OsString::from("--no-patch"),
            OsString::from(&commit),
        ],
        BuildRefusal::Tag,
    )?
    .parse::<u64>()
    .map_err(|_error| BuildError::new(BuildRefusal::Tag))?;

    Ok(SourceIdentity {
        tag_ref,
        commit,
        tree,
        commit_time,
    })
}

fn validate_checkout(root: &Path, commit: &str) -> Result<(), BuildError> {
    let head = git_line(
        root,
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        BuildRefusal::Checkout,
    )?;
    if head != commit {
        return Err(BuildError::new(BuildRefusal::Checkout));
    }
    let status = run_git(
        root,
        &[
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
            OsString::from("--untracked-files=all"),
        ],
    )
    .map_err(|_error| BuildError::new(BuildRefusal::Checkout))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(BuildError::new(BuildRefusal::Checkout));
    }
    Ok(())
}

fn validate_output_identity(out: &Path, burn_register: &Path) -> Result<(), BuildError> {
    let burn = fs::canonicalize(burn_register)
        .map_err(|_error| BuildError::new(BuildRefusal::BurnRegister))?;
    let destination =
        destination_identity(out).map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    if burn == destination {
        return Err(BuildError::new(BuildRefusal::Publication));
    }
    Ok(())
}

fn destination_identity(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path);
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("destination has no file name"))?;
    let parent = usable_parent(path);
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn run_git_archive(
    root: &Path,
    identity: &SourceIdentity,
    output: &Path,
    manifest: Option<&Path>,
) -> Result<(), BuildError> {
    let mut arguments = vec![
        OsString::from("archive"),
        OsString::from("--format=zip"),
        OsString::from(format!("--mtime=@{}", identity.commit_time)),
        path_option("--output=", output),
    ];
    if let Some(manifest) = manifest {
        arguments.push(OsString::from("--prefix=docs/"));
        arguments.push(path_option("--add-file=", manifest));
        arguments.push(OsString::from("--prefix="));
    }
    arguments.extend([
        OsString::from(&identity.tag_ref),
        OsString::from("--"),
        OsString::from("."),
        OsString::from(":!local"),
    ]);
    let archived =
        run_git(root, &arguments).map_err(|_error| BuildError::new(BuildRefusal::Archive))?;
    if !archived.status.success() {
        return Err(BuildError::new(BuildRefusal::Archive));
    }
    Ok(())
}

fn path_option(prefix: &str, path: &Path) -> OsString {
    let mut option = OsString::from(prefix);
    option.push(path);
    option
}

fn set_file_time(path: &Path, seconds: u64) -> io::Result<()> {
    let modified = UNIX_EPOCH + Duration::from_secs(seconds);
    File::options()
        .write(true)
        .open(path)?
        .set_times(FileTimes::new().set_modified(modified))
}

fn publish_archive(source: &Path, destination: &Path) -> Result<(), BuildError> {
    let parent = usable_parent(destination);
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    let mut input =
        File::open(source).map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    io::copy(&mut input, staged.as_file_mut())
        .map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    staged
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    staged
        .as_file_mut()
        .sync_all()
        .map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    staged
        .persist(destination)
        .map_err(|_error| BuildError::new(BuildRefusal::Publication))?;
    Ok(())
}

fn run_git(root: &Path, arguments: &[OsString]) -> io::Result<Output> {
    git_command(root).args(arguments).output()
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).stdin(Stdio::null());
    command
}

fn git_line(
    root: &Path,
    arguments: &[OsString],
    refusal: BuildRefusal,
) -> Result<String, BuildError> {
    let output = run_git(root, arguments).map_err(|_error| BuildError::new(refusal))?;
    if !output.status.success() {
        return Err(BuildError::new(refusal));
    }
    one_line(&output.stdout).ok_or_else(|| BuildError::new(refusal))
}

fn one_line(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim_end_matches(['\r', '\n']);
    if text.is_empty() || text.contains(['\r', '\n']) {
        None
    } else {
        Some(text.to_owned())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BurnDocument {
    values: Vec<BurnValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BurnValue {
    value: String,
    #[serde(rename = "match")]
    mode: BurnMatch,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BurnMatch {
    Substring,
    Identifier,
}

fn read_burn_register(path: &Path) -> Result<(String, usize), ()> {
    let bytes = fs::read(path).map_err(|_error| ())?;
    let text = std::str::from_utf8(&bytes).map_err(|_error| ())?;
    let document: BurnDocument = toml::from_str(text).map_err(|_error| ())?;
    if document.values.is_empty() || document.values.iter().any(|entry| entry.value.is_empty()) {
        return Err(());
    }
    Ok((sha256_bytes(&bytes), document.values.len()))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let bytes = digest.finalize();
    Ok(format_digest(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let bytes = digest.finalize();
    format_digest(&bytes)
}

fn format_digest(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _result = write!(&mut rendered, "{byte:02x}");
    }
    rendered
}

/// Ordered verification checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyCheck {
    Staging,
    ArchiveMembers,
    Extraction,
    Manifest,
    BurnRegister,
    InertIndex,
    LinterExecution,
    LinterVerdict,
}

const VERIFY_CHECKS: [VerifyCheck; 8] = [
    VerifyCheck::Staging,
    VerifyCheck::ArchiveMembers,
    VerifyCheck::Extraction,
    VerifyCheck::Manifest,
    VerifyCheck::BurnRegister,
    VerifyCheck::InertIndex,
    VerifyCheck::LinterExecution,
    VerifyCheck::LinterVerdict,
];

impl VerifyCheck {
    /// Stable report spelling of the check.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::ArchiveMembers => "archive_members",
            Self::Extraction => "extraction",
            Self::Manifest => "manifest",
            Self::BurnRegister => "burn_register",
            Self::InertIndex => "inert_index",
            Self::LinterExecution => "linter_execution",
            Self::LinterVerdict => "linter_verdict",
        }
    }

    /// Declared refusal status for this verification stage.
    #[must_use]
    pub const fn refusal_status(self) -> u8 {
        match self {
            Self::Staging => 4,
            Self::ArchiveMembers | Self::Extraction => 5,
            Self::Manifest => 6,
            Self::BurnRegister => 7,
            Self::InertIndex => 8,
            Self::LinterExecution => 9,
            Self::LinterVerdict => 10,
        }
    }
}

impl fmt::Display for VerifyCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable outcomes for the ordered verification ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    Passed,
    Refused,
    Skipped,
}

impl CheckOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Refused => "refused",
            Self::Skipped => "skipped",
        }
    }
}

/// Extra non-path evidence carried by selected checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckEvidence {
    None,
    Mount {
        staging_device: u64,
        temporary_root_device: u64,
    },
    Linter {
        declared: usize,
        occurrences: usize,
        source_kind: String,
    },
}

/// One entry in the ordered verification ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    pub check: VerifyCheck,
    pub outcome: CheckOutcome,
    pub wall: Duration,
    pub evidence: CheckEvidence,
}

/// Inputs to one archive verification.
#[derive(Clone, Copy, Debug)]
pub struct VerifyRequest<'a> {
    pub pack: &'a Path,
    pub burn_register: &'a Path,
    pub linter: &'a Path,
    pub staging: &'a Path,
}

/// Successful archive-verification evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub checks: Vec<CheckReport>,
    pub manifest: ProvenanceManifest,
    pub final_zip_sha256: String,
}

/// Stable path-free verification refusal reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyRefusal {
    StagingUnavailable,
    StagingUnsafe,
    StagingNotEmpty,
    StagingNotDiskBacked,
    ArchiveRead,
    ArchiveFormat,
    ForbiddenMember,
    UnsafeMember,
    Extraction,
    ManifestMissing,
    ManifestInvalid,
    BurnRegisterInvalid,
    BurnRegisterMismatch,
    BurnRegisterInsideStaging,
    Index,
    LinterLaunch,
    LinterReport,
    LinterStatus,
    LinterNotClean,
    LinterFailures,
    LinterNotPublicPack,
    BurnEvidence,
}

impl VerifyRefusal {
    /// Stable report spelling for this refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StagingUnavailable => "staging_unavailable",
            Self::StagingUnsafe => "staging_unsafe",
            Self::StagingNotEmpty => "staging_not_empty",
            Self::StagingNotDiskBacked => "staging_not_disk_backed",
            Self::ArchiveRead => "archive_read",
            Self::ArchiveFormat => "archive_format",
            Self::ForbiddenMember => "forbidden_member",
            Self::UnsafeMember => "unsafe_member",
            Self::Extraction => "extraction",
            Self::ManifestMissing => "manifest_missing",
            Self::ManifestInvalid => "manifest_invalid",
            Self::BurnRegisterInvalid => "burn_register_invalid",
            Self::BurnRegisterMismatch => "burn_register_mismatch",
            Self::BurnRegisterInsideStaging => "burn_register_inside_staging",
            Self::Index => "index",
            Self::LinterLaunch => "linter_launch",
            Self::LinterReport => "linter_report",
            Self::LinterStatus => "linter_status",
            Self::LinterNotClean => "linter_not_clean",
            Self::LinterFailures => "linter_failures",
            Self::LinterNotPublicPack => "linter_not_public_pack",
            Self::BurnEvidence => "burn_evidence",
        }
    }

    const fn check(self) -> VerifyCheck {
        match self {
            Self::StagingUnavailable
            | Self::StagingUnsafe
            | Self::StagingNotEmpty
            | Self::StagingNotDiskBacked => VerifyCheck::Staging,
            Self::ArchiveRead
            | Self::ArchiveFormat
            | Self::ForbiddenMember
            | Self::UnsafeMember => VerifyCheck::ArchiveMembers,
            Self::Extraction => VerifyCheck::Extraction,
            Self::ManifestMissing | Self::ManifestInvalid => VerifyCheck::Manifest,
            Self::BurnRegisterInvalid
            | Self::BurnRegisterMismatch
            | Self::BurnRegisterInsideStaging => VerifyCheck::BurnRegister,
            Self::Index => VerifyCheck::InertIndex,
            Self::LinterLaunch | Self::LinterReport => VerifyCheck::LinterExecution,
            Self::LinterStatus
            | Self::LinterNotClean
            | Self::LinterFailures
            | Self::LinterNotPublicPack
            | Self::BurnEvidence => VerifyCheck::LinterVerdict,
        }
    }
}

impl fmt::Display for VerifyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One verification refusal with its complete ordered ledger.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("archive verification refused: {reason}{detail}")]
pub struct VerifyError {
    reason: VerifyRefusal,
    checks: Vec<CheckReport>,
    detail: String,
}

impl VerifyError {
    fn at(reason: VerifyRefusal, mut checks: Vec<CheckReport>, wall: Duration) -> Self {
        let failed = reason.check();
        checks.push(CheckReport {
            check: failed,
            outcome: CheckOutcome::Refused,
            wall,
            evidence: CheckEvidence::None,
        });
        let failed_position = VERIFY_CHECKS
            .iter()
            .position(|check| *check == failed)
            .unwrap_or(VERIFY_CHECKS.len());
        checks.extend(
            VERIFY_CHECKS
                .iter()
                .skip(failed_position.saturating_add(1))
                .copied()
                .map(|check| CheckReport {
                    check,
                    outcome: CheckOutcome::Skipped,
                    wall: Duration::ZERO,
                    evidence: CheckEvidence::None,
                }),
        );
        Self {
            reason,
            checks,
            detail: String::new(),
        }
    }

    fn with_burn_families(mut self, families: &[String]) -> Self {
        use fmt::Write as _;

        for family in families {
            let _written = write!(self.detail, " family={family:?}");
        }
        self
    }

    /// Stable reason for the refusal.
    #[must_use]
    pub const fn reason(&self) -> VerifyRefusal {
        self.reason
    }

    /// Complete ordered ledger, including later skipped checks.
    #[must_use]
    pub fn checks(&self) -> &[CheckReport] {
        &self.checks
    }

    /// Declared process status for the refusing check.
    #[must_use]
    pub const fn exit_status(&self) -> u8 {
        self.reason.check().refusal_status()
    }
}

#[derive(Clone, Debug)]
struct StagingEvidence {
    root: PathBuf,
    staging_device: u64,
    temporary_root_device: u64,
}

#[derive(Clone, Debug)]
struct ArchiveAudit {
    members: Vec<ArchiveMember>,
}

#[derive(Clone, Debug)]
struct ArchiveMember {
    path: PathBuf,
    directory: bool,
}

#[derive(Debug, Deserialize)]
struct LinterReport {
    clean: bool,
    failures: usize,
    public_pack: bool,
    burn: LinterBurn,
}

#[derive(Debug, Deserialize)]
struct LinterBurn {
    owed: usize,
    families: Vec<LinterFamily>,
}

#[derive(Debug, Deserialize)]
struct LinterFamily {
    family: String,
    declared: Option<usize>,
    source: Option<String>,
    source_kind: Option<String>,
    occurrences: usize,
    registered: usize,
    owed: usize,
}

impl LinterFamily {
    fn binds(&self, source: &str) -> bool {
        self.source_kind.as_deref() == Some("external")
            && self.source.as_deref() == Some(source)
            && self.declared.unwrap_or(0) > 0
    }
}

#[derive(Debug)]
struct LinterObservation {
    status_success: bool,
    report: LinterReport,
}

/// Verify one archive in an empty disk-backed staging directory.
///
/// # Errors
///
/// Returns a typed refusal containing the full ordered check ledger when any
/// staging, archive, provenance, index, process, or verdict condition fails.
pub fn verify(request: VerifyRequest<'_>) -> Result<VerifyReport, VerifyError> {
    let mut checks = Vec::with_capacity(VERIFY_CHECKS.len());

    let started = Instant::now();
    let staging = validate_staging(request.staging)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    checks.push(CheckReport {
        check: VerifyCheck::Staging,
        outcome: CheckOutcome::Passed,
        wall: started.elapsed(),
        evidence: CheckEvidence::Mount {
            staging_device: staging.staging_device,
            temporary_root_device: staging.temporary_root_device,
        },
    });

    let started = Instant::now();
    let pack = fs::canonicalize(request.pack).map_err(|_error| {
        VerifyError::at(
            VerifyRefusal::ArchiveRead,
            checks.clone(),
            started.elapsed(),
        )
    })?;
    let audit = audit_archive(&pack)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    let final_zip_sha256 = sha256_file(&pack).map_err(|_error| {
        VerifyError::at(
            VerifyRefusal::ArchiveRead,
            checks.clone(),
            started.elapsed(),
        )
    })?;
    checks.push(passed(VerifyCheck::ArchiveMembers, started.elapsed()));

    let started = Instant::now();
    extract_archive(&pack, &staging.root, &audit)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    checks.push(passed(VerifyCheck::Extraction, started.elapsed()));

    let started = Instant::now();
    let manifest = read_manifest(&staging.root)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    checks.push(passed(VerifyCheck::Manifest, started.elapsed()));

    let started = Instant::now();
    let burn_register = fs::canonicalize(request.burn_register).map_err(|_error| {
        VerifyError::at(
            VerifyRefusal::BurnRegisterInvalid,
            checks.clone(),
            started.elapsed(),
        )
    })?;
    if burn_register.starts_with(&staging.root) {
        return Err(VerifyError::at(
            VerifyRefusal::BurnRegisterInsideStaging,
            checks,
            started.elapsed(),
        ));
    }
    let (burn_sha256, burn_count) = read_burn_register(&burn_register).map_err(|()| {
        VerifyError::at(
            VerifyRefusal::BurnRegisterInvalid,
            checks.clone(),
            started.elapsed(),
        )
    })?;
    if manifest.burn_register_sha256 != burn_sha256 || manifest.burn_register_count != burn_count {
        return Err(VerifyError::at(
            VerifyRefusal::BurnRegisterMismatch,
            checks,
            started.elapsed(),
        ));
    }
    checks.push(passed(VerifyCheck::BurnRegister, started.elapsed()));

    let started = Instant::now();
    construct_inert_index(&staging.root)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    checks.push(passed(VerifyCheck::InertIndex, started.elapsed()));

    let started = Instant::now();
    let observation = run_linter(request.linter, &staging.root, &burn_register)
        .map_err(|reason| VerifyError::at(reason, checks.clone(), started.elapsed()))?;
    checks.push(passed(VerifyCheck::LinterExecution, started.elapsed()));

    let started = Instant::now();
    let evidence =
        validate_linter_verdict(&observation, &burn_register).map_err(|(reason, families)| {
            VerifyError::at(reason, checks.clone(), started.elapsed()).with_burn_families(&families)
        })?;
    checks.push(CheckReport {
        check: VerifyCheck::LinterVerdict,
        outcome: CheckOutcome::Passed,
        wall: started.elapsed(),
        evidence,
    });

    Ok(VerifyReport {
        checks,
        manifest,
        final_zip_sha256,
    })
}

const fn passed(check: VerifyCheck, wall: Duration) -> CheckReport {
    CheckReport {
        check,
        outcome: CheckOutcome::Passed,
        wall,
        evidence: CheckEvidence::None,
    }
}

fn validate_staging(path: &Path) -> Result<StagingEvidence, VerifyRefusal> {
    validate_absolute_directory(path)?;
    if fs::read_dir(path)
        .map_err(|_error| VerifyRefusal::StagingUnavailable)?
        .next()
        .is_some()
    {
        return Err(VerifyRefusal::StagingNotEmpty);
    }
    let root = fs::canonicalize(path).map_err(|_error| VerifyRefusal::StagingUnavailable)?;
    let temporary_root = fs::canonicalize(std::env::temp_dir())
        .map_err(|_error| VerifyRefusal::StagingNotDiskBacked)?;
    let staging_metadata =
        fs::metadata(&root).map_err(|_error| VerifyRefusal::StagingUnavailable)?;
    let temporary_metadata =
        fs::metadata(&temporary_root).map_err(|_error| VerifyRefusal::StagingNotDiskBacked)?;
    let staging_device = staging_metadata.dev();
    let temporary_root_device = temporary_metadata.dev();
    if staging_device != temporary_root_device {
        return Err(VerifyRefusal::StagingNotDiskBacked);
    }
    Ok(StagingEvidence {
        root,
        staging_device,
        temporary_root_device,
    })
}

fn validate_absolute_directory(path: &Path) -> Result<(), VerifyRefusal> {
    if !path.is_absolute() {
        return Err(VerifyRefusal::StagingUnsafe);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(part) => {
                current.push(part);
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_error| VerifyRefusal::StagingUnavailable)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(VerifyRefusal::StagingUnsafe);
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(VerifyRefusal::StagingUnsafe);
            }
        }
    }
    Ok(())
}

fn audit_archive(path: &Path) -> Result<ArchiveAudit, VerifyRefusal> {
    let mut archive = File::open(path).map_err(|_error| VerifyRefusal::ArchiveRead)?;
    let length = archive
        .metadata()
        .map_err(|_error| VerifyRefusal::ArchiveRead)?
        .len();
    if length < ZIP_END_MINIMUM as u64 {
        return Err(VerifyRefusal::ArchiveFormat);
    }
    let (central, total_entries, central_offset) = read_central_directory(&mut archive, length)?;
    let mut cursor = 0_usize;
    let mut members = Vec::with_capacity(usize::from(total_entries));
    let mut paths = BTreeMap::new();
    for _index in 0..total_entries {
        let fixed = central
            .get(cursor..cursor.saturating_add(46))
            .ok_or(VerifyRefusal::ArchiveFormat)?;
        if little_u32(fixed, 0)? != ZIP_CENTRAL_SIGNATURE {
            return Err(VerifyRefusal::ArchiveFormat);
        }
        let flags = little_u16(fixed, 8)?;
        let method = little_u16(fixed, 10)?;
        let compressed_size = u64::from(little_u32(fixed, 20)?);
        let uncompressed_size = little_u32(fixed, 24)?;
        let name_length = usize::from(little_u16(fixed, 28)?);
        let extra_length = usize::from(little_u16(fixed, 30)?);
        let comment_length = usize::from(little_u16(fixed, 32)?);
        let starting_disk = little_u16(fixed, 34)?;
        let external_attributes = little_u32(fixed, 38)?;
        let local_offset = u64::from(little_u32(fixed, 42)?);
        let record_length = 46_usize
            .checked_add(name_length)
            .and_then(|value| value.checked_add(extra_length))
            .and_then(|value| value.checked_add(comment_length))
            .ok_or(VerifyRefusal::ArchiveFormat)?;
        let record = central
            .get(cursor..cursor.saturating_add(record_length))
            .ok_or(VerifyRefusal::ArchiveFormat)?;
        if flags & 1 != 0
            || !matches!(method, 0 | 8)
            || starting_disk != 0
            || compressed_size == u64::from(u32::MAX)
            || uncompressed_size == u32::MAX
            || local_offset == u64::from(u32::MAX)
        {
            return Err(VerifyRefusal::ArchiveFormat);
        }
        let name_bytes = record
            .get(46..46 + name_length)
            .ok_or(VerifyRefusal::ArchiveFormat)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_error| VerifyRefusal::UnsafeMember)?
            .to_owned();
        let path = validate_member_name(&name)?;
        let directory = member_is_directory(&name, external_attributes)?;
        if paths.insert(path.clone(), directory).is_some() {
            return Err(VerifyRefusal::UnsafeMember);
        }
        validate_local_header(
            &mut archive,
            local_offset,
            name_bytes,
            flags,
            method,
            compressed_size,
            central_offset,
        )?;
        members.push(ArchiveMember { path, directory });
        cursor = cursor
            .checked_add(record_length)
            .ok_or(VerifyRefusal::ArchiveFormat)?;
    }
    if cursor != central.len() || members.is_empty() {
        return Err(VerifyRefusal::ArchiveFormat);
    }
    validate_member_relationships(&paths)?;
    Ok(ArchiveAudit { members })
}

fn read_central_directory(
    archive: &mut File,
    length: u64,
) -> Result<(Vec<u8>, u16, u64), VerifyRefusal> {
    let tail_length = length.min(ZIP_END_SEARCH);
    let tail_distance =
        i64::try_from(tail_length).map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    let tail_size = usize::try_from(tail_length).map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    archive
        .seek(SeekFrom::End(-tail_distance))
        .map_err(|_error| VerifyRefusal::ArchiveRead)?;
    let mut tail = vec![0_u8; tail_size];
    archive
        .read_exact(&mut tail)
        .map_err(|_error| VerifyRefusal::ArchiveRead)?;
    let end_in_tail = find_end_record(&tail).ok_or(VerifyRefusal::ArchiveFormat)?;
    let end_position = u64::try_from(end_in_tail).map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    let end_offset = length - tail_length + end_position;
    let end = &tail[end_in_tail..];
    let disk = little_u16(end, 4)?;
    let central_disk = little_u16(end, 6)?;
    let disk_entries = little_u16(end, 8)?;
    let total_entries = little_u16(end, 10)?;
    let central_size = u64::from(little_u32(end, 12)?);
    let central_offset = u64::from(little_u32(end, 16)?);
    if disk != 0
        || central_disk != 0
        || disk_entries != total_entries
        || total_entries == u16::MAX
        || central_size == u64::from(u32::MAX)
        || central_offset == u64::from(u32::MAX)
        || central_offset.checked_add(central_size) != Some(end_offset)
    {
        return Err(VerifyRefusal::ArchiveFormat);
    }

    archive
        .seek(SeekFrom::Start(central_offset))
        .map_err(|_error| VerifyRefusal::ArchiveRead)?;
    let central_size =
        usize::try_from(central_size).map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    let mut central = vec![0_u8; central_size];
    archive
        .read_exact(&mut central)
        .map_err(|_error| VerifyRefusal::ArchiveRead)?;
    Ok((central, total_entries, central_offset))
}

fn find_end_record(tail: &[u8]) -> Option<usize> {
    if tail.len() < ZIP_END_MINIMUM {
        return None;
    }
    (0..=tail.len() - ZIP_END_MINIMUM).rev().find(|offset| {
        little_u32(tail, *offset).ok() == Some(ZIP_END_SIGNATURE)
            && little_u16(tail, offset + 20)
                .is_ok_and(|comment| offset + ZIP_END_MINIMUM + usize::from(comment) == tail.len())
    })
}

fn little_u16(bytes: &[u8], offset: usize) -> Result<u16, VerifyRefusal> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(VerifyRefusal::ArchiveFormat)?
        .try_into()
        .map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    Ok(u16::from_le_bytes(raw))
}

fn little_u32(bytes: &[u8], offset: usize) -> Result<u32, VerifyRefusal> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(VerifyRefusal::ArchiveFormat)?
        .try_into()
        .map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    Ok(u32::from_le_bytes(raw))
}

fn validate_member_name(name: &str) -> Result<PathBuf, VerifyRefusal> {
    if name.is_empty() || name.starts_with('/') || name.contains('\0') || name.contains('\\') {
        return Err(VerifyRefusal::UnsafeMember);
    }
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(VerifyRefusal::UnsafeMember);
    }
    let path = PathBuf::from(trimmed);
    let mut normal = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normal.push(part),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => return Err(VerifyRefusal::UnsafeMember),
        }
    }
    let first = normal.first().ok_or(VerifyRefusal::UnsafeMember)?;
    if *first == OsStr::new("local") || *first == OsStr::new(".git") {
        return Err(VerifyRefusal::ForbiddenMember);
    }
    if normal.iter().any(|part| *part == OsStr::new(".git")) {
        return Err(VerifyRefusal::ForbiddenMember);
    }
    Ok(path)
}

fn member_is_directory(name: &str, attributes: u32) -> Result<bool, VerifyRefusal> {
    let name_directory = name.ends_with('/');
    let mode = attributes >> 16;
    let file_type = mode & 0o170_000;
    match file_type {
        0 => Ok(name_directory),
        0o040_000 if name_directory => Ok(true),
        0o100_000 if !name_directory => Ok(false),
        _ => Err(VerifyRefusal::UnsafeMember),
    }
}

fn validate_local_header(
    archive: &mut File,
    offset: u64,
    central_name: &[u8],
    central_flags: u16,
    central_method: u16,
    compressed_size: u64,
    central_offset: u64,
) -> Result<(), VerifyRefusal> {
    archive
        .seek(SeekFrom::Start(offset))
        .map_err(|_error| VerifyRefusal::ArchiveRead)?;
    let mut fixed = [0_u8; 30];
    archive
        .read_exact(&mut fixed)
        .map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    if little_u32(&fixed, 0)? != ZIP_LOCAL_SIGNATURE
        || little_u16(&fixed, 6)? != central_flags
        || little_u16(&fixed, 8)? != central_method
    {
        return Err(VerifyRefusal::ArchiveFormat);
    }
    let name_length = usize::from(little_u16(&fixed, 26)?);
    let extra_length = usize::from(little_u16(&fixed, 28)?);
    let mut local_name = vec![0_u8; name_length];
    archive
        .read_exact(&mut local_name)
        .map_err(|_error| VerifyRefusal::ArchiveFormat)?;
    if local_name != central_name {
        return Err(VerifyRefusal::UnsafeMember);
    }
    let data_offset = offset
        .checked_add(30)
        .and_then(|value| value.checked_add(name_length as u64))
        .and_then(|value| value.checked_add(extra_length as u64))
        .ok_or(VerifyRefusal::ArchiveFormat)?;
    if data_offset
        .checked_add(compressed_size)
        .is_none_or(|end| end > central_offset)
    {
        return Err(VerifyRefusal::ArchiveFormat);
    }
    Ok(())
}

fn validate_member_relationships(paths: &BTreeMap<PathBuf, bool>) -> Result<(), VerifyRefusal> {
    for (path, directory) in paths {
        let mut ancestor = path.parent();
        while let Some(parent) = ancestor {
            if parent.as_os_str().is_empty() {
                break;
            }
            if paths.get(parent).is_some_and(|is_directory| !is_directory) {
                return Err(VerifyRefusal::UnsafeMember);
            }
            ancestor = parent.parent();
        }
        if !directory
            && paths
                .keys()
                .any(|candidate| candidate != path && candidate.starts_with(path))
        {
            return Err(VerifyRefusal::UnsafeMember);
        }
    }
    Ok(())
}

fn extract_archive(pack: &Path, staging: &Path, audit: &ArchiveAudit) -> Result<(), VerifyRefusal> {
    let output = Command::new("unzip")
        .arg("-qq")
        .arg(pack)
        .arg("-d")
        .arg(staging)
        .stdin(Stdio::null())
        .output()
        .map_err(|_error| VerifyRefusal::Extraction)?;
    if !output.status.success() {
        return Err(VerifyRefusal::Extraction);
    }
    validate_extracted_tree(staging, audit)
}

fn validate_extracted_tree(staging: &Path, audit: &ArchiveAudit) -> Result<(), VerifyRefusal> {
    let mut expected = BTreeMap::new();
    for member in &audit.members {
        expected.insert(member.path.clone(), member.directory);
        let mut ancestor = member.path.parent();
        while let Some(parent) = ancestor {
            if parent.as_os_str().is_empty() {
                break;
            }
            expected.entry(parent.to_path_buf()).or_insert(true);
            ancestor = parent.parent();
        }
    }
    let mut found = BTreeSet::new();
    walk_extracted(staging, staging, &expected, &mut found)?;
    if found.len() != expected.len() || expected.keys().any(|path| !found.contains(path)) {
        return Err(VerifyRefusal::Extraction);
    }
    Ok(())
}

fn walk_extracted(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<PathBuf, bool>,
    found: &mut BTreeSet<PathBuf>,
) -> Result<(), VerifyRefusal> {
    let entries = fs::read_dir(directory).map_err(|_error| VerifyRefusal::Extraction)?;
    for entry in entries {
        let entry = entry.map_err(|_error| VerifyRefusal::Extraction)?;
        let absolute = entry.path();
        let relative = absolute
            .strip_prefix(root)
            .map_err(|_error| VerifyRefusal::Extraction)?
            .to_path_buf();
        let metadata =
            fs::symlink_metadata(&absolute).map_err(|_error| VerifyRefusal::Extraction)?;
        if metadata.file_type().is_symlink() {
            return Err(VerifyRefusal::UnsafeMember);
        }
        let directory_entry = metadata.is_dir();
        if !directory_entry && !metadata.is_file() {
            return Err(VerifyRefusal::UnsafeMember);
        }
        if expected.get(&relative) != Some(&directory_entry) || !found.insert(relative) {
            return Err(VerifyRefusal::Extraction);
        }
        if directory_entry {
            walk_extracted(root, &absolute, expected, found)?;
        }
    }
    Ok(())
}

fn read_manifest(root: &Path) -> Result<ProvenanceManifest, VerifyRefusal> {
    let path = root.join(MANIFEST_PATH);
    let text = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            VerifyRefusal::ManifestMissing
        } else {
            VerifyRefusal::ManifestInvalid
        }
    })?;
    let manifest: ProvenanceManifest =
        toml::from_str(&text).map_err(|_error| VerifyRefusal::ManifestInvalid)?;
    if manifest.pack_format != PACK_FORMAT
        || manifest.tag.is_empty()
        || !valid_object_id(&manifest.commit)
        || !valid_object_id(&manifest.tree)
        || !valid_sha256(&manifest.archive_sha256)
        || !valid_sha256(&manifest.burn_register_sha256)
        || manifest.burn_register_count == 0
        || manifest.linter_version.is_empty()
    {
        return Err(VerifyRefusal::ManifestInvalid);
    }
    Ok(manifest)
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn construct_inert_index(root: &Path) -> Result<(), VerifyRefusal> {
    let init = [OsString::from("init"), OsString::from("-q")];
    let add = [OsString::from("add"), OsString::from("-A")];
    for arguments in [&init[..], &add[..]] {
        let output = run_git(root, arguments).map_err(|_error| VerifyRefusal::Index)?;
        if !output.status.success() {
            return Err(VerifyRefusal::Index);
        }
    }
    Ok(())
}

fn run_linter(
    linter: &Path,
    root: &Path,
    burn_register: &Path,
) -> Result<LinterObservation, VerifyRefusal> {
    let linter = fs::canonicalize(linter).map_err(|_error| VerifyRefusal::LinterLaunch)?;
    let output = Command::new(linter)
        .arg("check")
        .arg("--root")
        .arg(root)
        .arg("--public-pack")
        .arg("--burn-input")
        .arg(burn_register)
        .stdin(Stdio::null())
        .output()
        .map_err(|_error| VerifyRefusal::LinterLaunch)?;
    let code = output.status.code();
    if !output.status.success() && code != Some(3) {
        return Err(VerifyRefusal::LinterLaunch);
    }
    let report = serde_json::from_slice::<LinterReport>(&output.stdout)
        .map_err(|_error| VerifyRefusal::LinterReport)?;
    Ok(LinterObservation {
        status_success: output.status.success(),
        report,
    })
}

fn validate_linter_verdict(
    observation: &LinterObservation,
    burn_register: &Path,
) -> Result<CheckEvidence, (VerifyRefusal, Vec<String>)> {
    let burn = &observation.report.burn;
    let source = burn_register.to_string_lossy();
    // Growth is a burn refusal even when the linter exits with findings.
    // A bound private value may never be carried by a public pack, even kept.
    let families: Vec<String> = burn
        .families
        .iter()
        .filter(|family| {
            family.owed != 0
                || family.occurrences > family.registered
                || (family.binds(&source) && family.occurrences != 0)
        })
        .map(|family| family.family.clone())
        .collect();
    if burn.owed != 0 || !families.is_empty() {
        return Err((VerifyRefusal::BurnEvidence, families));
    }
    if !observation.status_success {
        return Err((VerifyRefusal::LinterStatus, Vec::new()));
    }
    if !observation.report.clean {
        return Err((VerifyRefusal::LinterNotClean, Vec::new()));
    }
    if observation.report.failures != 0 {
        return Err((VerifyRefusal::LinterFailures, Vec::new()));
    }
    if !observation.report.public_pack {
        return Err((VerifyRefusal::LinterNotPublicPack, Vec::new()));
    }
    // A clean verdict is non-vacuous only when the supplied register was read.
    let bound: Vec<&LinterFamily> = burn
        .families
        .iter()
        .filter(|family| family.binds(&source))
        .collect();
    if bound.is_empty() {
        let families = burn
            .families
            .iter()
            .filter(|family| family.source_kind.is_some())
            .map(|family| family.family.clone())
            .collect();
        return Err((VerifyRefusal::BurnEvidence, families));
    }
    Ok(CheckEvidence::Linter {
        declared: bound.iter().filter_map(|family| family.declared).sum(),
        occurrences: bound.iter().map(|family| family.occurrences).sum(),
        source_kind: String::from("external"),
    })
}

/// Publish a build result under the binary's agent-text contract.
///
/// # Errors
///
/// Returns an I/O error if the owned output stream cannot accept the report.
pub fn write_build_report<W: io::Write>(
    result: &Result<BuildReport, BuildError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    match result {
        Ok(report) => {
            writeln!(output, "archive final_sha256={}", report.final_zip_sha256)?;
            writeln!(output, "manifest-begin")?;
            let manifest = toml::to_string(&report.manifest).map_err(io::Error::other)?;
            output.write_all(manifest.as_bytes())?;
            if !manifest.ends_with('\n') {
                writeln!(output)?;
            }
            writeln!(output, "manifest-end")?;
            write_terminal_report(output, "build", 0, wall, "ok")
        }
        Err(error) => {
            writeln!(
                output,
                "build outcome=refused status={} reason={}",
                error.exit_status(),
                error.reason()
            )?;
            write_terminal_report(output, "build", error.exit_status(), wall, "refused")
        }
    }
}

/// Publish a verify result under the binary's agent-text contract.
///
/// # Errors
///
/// Returns an I/O error if the owned output stream cannot accept the report.
pub fn write_verify_report<W: io::Write>(
    result: &Result<VerifyReport, VerifyError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    let checks = match result {
        Ok(report) => &report.checks,
        Err(error) => error.checks(),
    };
    for check in checks {
        write_check(output, check)?;
    }
    match result {
        Ok(report) => {
            writeln!(output, "archive final_sha256={}", report.final_zip_sha256)?;
            write_terminal_report(output, "stage-verify", 0, wall, "ok")
        }
        Err(error) => {
            writeln!(
                output,
                "verify outcome=refused status={} reason={}{}",
                error.exit_status(),
                error.reason(),
                error.detail
            )?;
            write_terminal_report(output, "stage-verify", error.exit_status(), wall, "refused")
        }
    }
}

fn write_check<W: io::Write>(output: &mut W, check: &CheckReport) -> io::Result<()> {
    write!(
        output,
        "check name={} outcome={} refusal_status={} wall={}",
        check.check,
        check.outcome.as_str(),
        check.check.refusal_status(),
        format_wall(check.wall)
    )?;
    match &check.evidence {
        CheckEvidence::None => {}
        CheckEvidence::Mount {
            staging_device,
            temporary_root_device,
        } => {
            write!(
                output,
                " staging_device={staging_device} temporary_root_device={temporary_root_device} same_mount=yes"
            )?;
        }
        CheckEvidence::Linter {
            declared,
            occurrences,
            source_kind,
        } => {
            write!(
                output,
                " clean=yes failures=0 public_pack=yes burn_declared={declared} burn_occurrences={occurrences} source_kind={source_kind}"
            )?;
        }
    }
    writeln!(output)
}

fn write_terminal_report<W: io::Write>(
    output: &mut W,
    command: &str,
    status: u8,
    wall: Duration,
    verdict: &str,
) -> io::Result<()> {
    let wall = format_wall(wall);
    writeln!(
        output,
        "summary command={command} exit={status} wall={wall} verdict={verdict}"
    )?;
    writeln!(
        output,
        "RUN-REPORT exit={status} wall={wall} verdict={verdict}"
    )?;
    output.flush()
}

fn format_wall(wall: Duration) -> String {
    format!("{}.{:03}s", wall.as_secs(), wall.subsec_millis())
}
