#![doc = include_str!("../README.md")]

pub mod retirement;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, FileTimes, Metadata};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

#[cfg(test)]
mod tests;

/// Command name used by the installer binary and its report contract.
pub const COMMAND_NAME: &str = "superloop-install";

/// Stable refusal classes and their command exit statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalClass {
    /// The map could not be read, decoded, parsed, or validated.
    Map,
    /// A repository input was missing, unsafe, or unreadable.
    Source,
    /// Base/overlay assembly failed validation.
    Render,
    /// The root or a destination was unsafe or non-idempotent.
    Destination,
    /// Filesystem state changed after preflight.
    ConcurrentChange,
    /// Outgoing bytes could not be backed up and verified.
    Backup,
    /// Parent creation, staging, mode application, or replacement failed.
    Install,
    /// A completed replacement did not verify against the plan.
    Verification,
}

impl RefusalClass {
    /// Return this class's declared process status.
    #[must_use]
    pub const fn exit_status(self) -> u8 {
        match self {
            Self::Map => 3,
            Self::Source => 4,
            Self::Render => 5,
            Self::Destination => 6,
            Self::ConcurrentChange => 7,
            Self::Backup => 8,
            Self::Install => 9,
            Self::Verification => 10,
        }
    }

    /// Return the stable report spelling of this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Map => "map",
            Self::Source => "source",
            Self::Render => "render",
            Self::Destination => "destination",
            Self::ConcurrentChange => "concurrent_change",
            Self::Backup => "backup",
            Self::Install => "install",
            Self::Verification => "verification",
        }
    }
}

impl fmt::Display for RefusalClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable, path-free reason codes within the refusal classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    MapRead,
    MapUtf8,
    MapSyntax,
    TargetShape,
    InvalidMode,
    InvalidRoot,
    InvalidRelativePath,
    DuplicateDestination,
    BackupDestinationCollision,
    SourceMissing,
    SourceSymlink,
    SourceNotRegular,
    SourceRead,
    OverlayShape,
    DuplicateSlot,
    MissingOverlaySection,
    UnusedOverlaySection,
    DuplicateOverlaySection,
    BaseHeadingConflict,
    LeftoverSlot,
    RenderedSize,
    RootUnavailable,
    RootSymlink,
    RootNotDirectory,
    RootInaccessible,
    RootMetadata,
    DestinationSymlink,
    DestinationComponent,
    DestinationNotRegular,
    DestinationRead,
    EqualModeMismatch,
    SourceTargetAlias,
    BackupDestinationType,
    StateChanged,
    BackupWrite,
    BackupVerify,
    ParentCreate,
    TargetWrite,
    MtimeTransition,
    TargetVerify,
    BuildRootMissing,
    BuildRecordMissing,
    BuildRecordInvalid,
    BuildDigestMismatch,
    DomainMismatch,
    GitIdentity,
    ReleaseIdentity,
    RegistryRead,
    RegistryRootMissing,
    ProvenanceCollision,
}

impl RefusalReason {
    /// Return the stable report spelling of this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MapRead => "map_read",
            Self::MapUtf8 => "map_utf8",
            Self::MapSyntax => "map_syntax",
            Self::TargetShape => "target_shape",
            Self::InvalidMode => "invalid_mode",
            Self::InvalidRoot => "invalid_root",
            Self::InvalidRelativePath => "invalid_relative_path",
            Self::DuplicateDestination => "duplicate_destination",
            Self::BackupDestinationCollision => "backup_destination_collision",
            Self::SourceMissing => "source_missing",
            Self::SourceSymlink => "source_symlink",
            Self::SourceNotRegular => "source_not_regular",
            Self::SourceRead => "source_read",
            Self::OverlayShape => "overlay_shape",
            Self::DuplicateSlot => "duplicate_slot",
            Self::MissingOverlaySection => "missing_overlay_section",
            Self::UnusedOverlaySection => "unused_overlay_section",
            Self::DuplicateOverlaySection => "duplicate_overlay_section",
            Self::BaseHeadingConflict => "base_heading_conflict",
            Self::LeftoverSlot => "leftover_slot",
            Self::RenderedSize => "rendered_size",
            Self::RootUnavailable => "root_unavailable",
            Self::RootSymlink => "root_symlink",
            Self::RootNotDirectory => "root_not_directory",
            Self::RootInaccessible => "root_inaccessible",
            Self::RootMetadata => "root_metadata",
            Self::DestinationSymlink => "destination_symlink",
            Self::DestinationComponent => "destination_component",
            Self::DestinationNotRegular => "destination_not_regular",
            Self::DestinationRead => "destination_read",
            Self::EqualModeMismatch => "equal_mode_mismatch",
            Self::SourceTargetAlias => "source_target_alias",
            Self::BackupDestinationType => "backup_destination_type",
            Self::StateChanged => "state_changed",
            Self::BackupWrite => "backup_write",
            Self::BackupVerify => "backup_verify",
            Self::ParentCreate => "parent_create",
            Self::TargetWrite => "target_write",
            Self::MtimeTransition => "mtime_transition",
            Self::TargetVerify => "target_verify",
            Self::BuildRootMissing => "build_root_missing",
            Self::BuildRecordMissing => "build_record_missing",
            Self::BuildRecordInvalid => "build_record_invalid",
            Self::BuildDigestMismatch => "build_digest_mismatch",
            Self::DomainMismatch => "domain_mismatch",
            Self::GitIdentity => "git_identity",
            Self::ReleaseIdentity => "release_identity",
            Self::RegistryRead => "registry_read",
            Self::RegistryRootMissing => "registry_root_missing",
            Self::ProvenanceCollision => "provenance_collision",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One deterministic rendering refusal.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
#[error("rendering refused: {reason}")]
pub struct RenderError {
    reason: RefusalReason,
}

impl RenderError {
    const fn new(reason: RefusalReason) -> Self {
        Self { reason }
    }

    /// Return the stable reason for this refusal.
    #[must_use]
    pub const fn reason(self) -> RefusalReason {
        self.reason
    }
}

/// One installation refusal, including already completed and touched targets.
#[derive(Debug, thiserror::Error)]
#[error("installation refused: class={class} reason={reason}")]
pub struct InstallError {
    class: RefusalClass,
    reason: RefusalReason,
    target_index: Option<usize>,
    target_count: usize,
    completed: Vec<TargetReport>,
    touched: BTreeSet<usize>,
    last_completed: String,
    dry_run: bool,
    registry: Box<RegistryOutcomes>,
}

impl InstallError {
    fn with_skipped(mut self, roots: &[RegistryRoot]) -> Self {
        self.registry.skipped_roots = roots.to_vec();
        self
    }

    fn preflight(
        class: RefusalClass,
        reason: RefusalReason,
        target_index: Option<usize>,
        target_count: usize,
        dry_run: bool,
        last_completed: &str,
    ) -> Self {
        Self {
            class,
            reason,
            target_index,
            target_count,
            completed: Vec::new(),
            touched: BTreeSet::new(),
            last_completed: last_completed.to_owned(),
            dry_run,
            registry: Box::default(),
        }
    }

    /// Return the stable refusal class.
    #[must_use]
    pub const fn class(&self) -> RefusalClass {
        self.class
    }

    /// Return the stable refusal reason.
    #[must_use]
    pub const fn reason(&self) -> RefusalReason {
        self.reason
    }

    /// Return the one-based target index when the refusal belongs to a target.
    #[must_use]
    pub const fn target_index(&self) -> Option<usize> {
        self.target_index
    }

    /// Return reports for targets completed before the refusal.
    #[must_use]
    pub fn completed(&self) -> &[TargetReport] {
        &self.completed
    }

    /// Return one-based indices whose target or backup path was touched.
    #[must_use]
    pub const fn touched(&self) -> &BTreeSet<usize> {
        &self.touched
    }

    /// The registry loop whose root was refused, when applicable.
    #[must_use]
    pub fn loop_name(&self) -> Option<&str> {
        self.registry
            .unavailable_roots
            .first()
            .map(|row| row.loop_name.as_str())
    }
}

/// Request supplied to the library installation entry point.
#[derive(Clone, Copy, Debug)]
pub struct InstallRequest<'a> {
    /// TOML install-map path.
    pub map_path: &'a Path,
    /// Repository root against which copy sources, overlays, and default bases resolve.
    pub repository_root: &'a Path,
    /// Optional destination-root override.
    pub root_override: Option<&'a Path>,
    /// Optional build-output boundary.
    pub build_root: Option<&'a Path>,
    /// Optional boundary for render bases instead of the repository root.
    pub shape_root: Option<&'a Path>,
    /// Optional registry-file override.
    pub registry_override: Option<&'a Path>,
    /// Optional staging directory, equivalent to Meson's `DESTDIR`.
    pub destdir: Option<&'a Path>,
    /// Release tag and its already resolved commit, supplied together.
    pub release_tag: Option<&'a str>,
    pub release_commit: Option<&'a str>,
    /// Plan and report without creating, backing up, or replacing anything.
    pub dry_run: bool,
}

/// Stable per-target outcome vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetOutcome {
    Unchanged,
    New,
    Changed,
    DomainMismatch,
}

impl TargetOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::New => "new",
            Self::Changed => "changed",
            Self::DomainMismatch => "domain-mismatch",
        }
    }
}

/// Whether the changed target's outgoing-byte backup was planned or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupDisposition {
    Planned,
    Written,
}

impl BackupDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Written => "written",
        }
    }
}

/// Verified backup evidence for one changed target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupEvidence {
    /// Whether an older regular backup occupied the sibling path.
    pub replaced_existing: bool,
    /// SHA-256 of the outgoing target bytes.
    pub outgoing_sha256: String,
    /// SHA-256 of the verified backup bytes.
    pub backup_sha256: String,
    /// Whether this was only planned or was written and verified.
    pub disposition: BackupDisposition,
}

/// Filesystem evidence retained for a target state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEvidence {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
}

/// One completed or dry-run-planned target result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetReport {
    /// One-based declaration-order index.
    pub index: usize,
    pub outcome: TargetOutcome,
    /// Byte-state outcome when `outcome` marks a staged domain mismatch.
    pub state: TargetOutcome,
    pub backup: Option<BackupEvidence>,
    pub before: Option<FileEvidence>,
    pub after: Option<FileEvidence>,
    /// Number of target-path renames performed by this run.
    pub replacements: u8,
    /// Whether the target or its backup sibling was touched.
    pub touched: bool,
}

/// Successful installation or dry-run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    pub targets: Vec<TargetReport>,
    /// Registry loops omitted because their destination root is absent.
    pub skipped_roots: Vec<RegistryRoot>,
    pub dry_run: bool,
    pub identity: String,
    pub map_sha256: String,
}

impl InstallReport {
    /// Count reports carrying `outcome`.
    #[must_use]
    pub fn count(&self, outcome: TargetOutcome) -> usize {
        self.targets
            .iter()
            .filter(|target| {
                if outcome == TargetOutcome::DomainMismatch {
                    target.outcome == outcome
                } else {
                    target.state == outcome
                }
            })
            .count()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallMap {
    root: Option<PathBuf>,
    registry: Option<RegistryMap>,
    targets: Vec<MapTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryMap {
    path: PathBuf,
    root: String,
    #[serde(default)]
    missing_root: MissingRoot,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum MissingRoot {
    #[default]
    Refuse,
    Skip,
}

#[derive(Debug, Default)]
struct RegistryOutcomes {
    unavailable_roots: Vec<RegistryRoot>,
    skipped_roots: Vec<RegistryRoot>,
    unreached_roots: Vec<(PathBuf, String)>,
    resolution_failure: Option<(RefusalClass, RefusalReason)>,
}

/// A registry loop and the destination root implicated in a refusal or skip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryRoot {
    pub loop_name: String,
    pub root: PathBuf,
    /// The measured refusal, retained even when the whole plan is refused.
    pub reason: RefusalReason,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapTarget {
    kind: String,
    source: Option<PathBuf>,
    output: Option<PathBuf>,
    domain: Option<String>,
    provenance: Option<bool>,
    base: Option<PathBuf>,
    overlay: Option<PathBuf>,
    destination: PathBuf,
    mode: String,
    max_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileSnapshot {
    bytes: Vec<u8>,
    evidence: FileEvidence,
    modified: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DestinationState {
    Missing,
    Existing(FileSnapshot),
}

#[derive(Debug)]
struct PlannedTarget {
    index: usize,
    root: PathBuf,
    domain_mismatch: bool,
    destination_relative: PathBuf,
    destination: PathBuf,
    backup: PathBuf,
    mode: u32,
    bytes: Vec<u8>,
    source_identities: Vec<(u64, u64)>,
    destination_state: DestinationState,
    backup_state: Option<FileSnapshot>,
}

#[derive(Debug)]
struct Plan {
    roots: Vec<PathBuf>,
    skipped_roots: Vec<RegistryRoot>,
    staging: bool,
    targets: Vec<PlannedTarget>,
}

#[derive(Debug)]
struct LoadedBytes {
    bytes: Vec<u8>,
    identity: (u64, u64),
}

#[derive(Debug)]
struct MaterializedTarget {
    bytes: Vec<u8>,
    source_identities: Vec<(u64, u64)>,
    provenance: Option<Vec<u8>>,
    domain_mismatch: bool,
}

#[derive(Debug)]
struct StepFailure {
    class: RefusalClass,
    reason: RefusalReason,
    touched: bool,
    last_completed: String,
}

/// Parse, preflight, and install every target in declaration order.
///
/// All inputs and all destination states are validated before the first mutation. A later runtime failure stops subsequent targets and the returned error retains completed and touched target indices.
///
/// # Errors
///
/// Returns a typed [`InstallError`] for every map, source, rendering, destination, concurrency, backup, installation, or verification refusal. Unavailable registry roots retain the loop name and resolved path.
pub fn install(request: InstallRequest<'_>) -> Result<InstallReport, InstallError> {
    let map_bytes = fs::read(request.map_path).map_err(|_error| {
        InstallError::preflight(
            RefusalClass::Map,
            RefusalReason::MapRead,
            None,
            0,
            request.dry_run,
            "none",
        )
    })?;
    let map_text = std::str::from_utf8(&map_bytes).map_err(|_error| {
        InstallError::preflight(
            RefusalClass::Map,
            RefusalReason::MapUtf8,
            None,
            0,
            request.dry_run,
            "map_read",
        )
    })?;
    let map: InstallMap = toml::from_str(map_text).map_err(|_error| {
        InstallError::preflight(
            RefusalClass::Map,
            RefusalReason::MapSyntax,
            None,
            0,
            request.dry_run,
            "map_read",
        )
    })?;
    validate_map_destinations(&map.targets, request.dry_run)?;
    let staging = request.destdir.is_some() || request.root_override.is_some();
    if request.release_tag.is_some() != request.release_commit.is_some()
        || (!staging && request.release_tag.is_none())
    {
        return Err(release_identity_refusal(request, &map));
    }
    let identity = if let (Some(tag), Some(commit)) = (request.release_tag, request.release_commit)
    {
        verify_release(request.repository_root, tag, commit, request.dry_run)?;
        commit.to_owned()
    } else {
        "untagged".to_owned()
    };
    let source_identity = if map
        .targets
        .iter()
        .any(|target| target.kind == "build" || target.provenance == Some(true))
    {
        Some(git_identity(request.repository_root).map_err(|reason| {
            InstallError::preflight(
                RefusalClass::Source,
                reason,
                None,
                map.targets.len(),
                request.dry_run,
                "map_parsed",
            )
        })?)
    } else {
        None
    };
    let shape_root = validated_shape_root(&request, map.targets.len())?;
    let request = InstallRequest {
        shape_root: shape_root.as_deref(),
        ..request
    };
    let plan = build_plan(request, &map, source_identity.as_ref())?;
    let mut report = execute_plan(&plan, request.dry_run)
        .map_err(|error| error.with_skipped(&plan.skipped_roots))?;
    if let (Some(tag), Some(commit)) = (request.release_tag, request.release_commit) {
        verify_release(request.repository_root, tag, commit, request.dry_run).map_err(
            |mut error| {
                error.completed.clone_from(&report.targets);
                error
                    .registry
                    .skipped_roots
                    .clone_from(&report.skipped_roots);
                error.target_count = report.targets.len();
                "all_targets_verified".clone_into(&mut error.last_completed);
                error
            },
        )?;
    }
    report.identity = identity;
    let mut map_identity = map_bytes;
    if let Some(root) = shape_root.as_deref() {
        map_identity.extend_from_slice(b"\0shape-root\0");
        map_identity.extend_from_slice(root.as_os_str().as_encoded_bytes());
    }
    report.map_sha256 = hex_digest(&map_identity);
    Ok(report)
}

fn release_identity_refusal(request: InstallRequest<'_>, map: &InstallMap) -> InstallError {
    let mut error = InstallError::preflight(
        RefusalClass::Map,
        RefusalReason::ReleaseIdentity,
        None,
        map.targets.len(),
        request.dry_run,
        "map_parsed",
    );
    if map.registry.is_some() {
        match resolve_roots(request, map) {
            Ok(roots) => {
                error.registry.unreached_roots = roots
                    .into_iter()
                    .filter_map(|(root, loop_name)| loop_name.map(|name| (root, name)))
                    .collect();
            }
            Err(resolution) => {
                error.registry.resolution_failure = Some((resolution.class, resolution.reason));
            }
        }
    }
    error
}

fn build_plan(
    request: InstallRequest<'_>,
    map: &InstallMap,
    identity: Option<&GitIdentity>,
) -> Result<Plan, InstallError> {
    let roots = resolve_roots(request, map)?;
    let target_count = map
        .targets
        .iter()
        .map(|target| {
            if target.kind == "build" || target.provenance == Some(true) {
                2
            } else {
                1
            }
        })
        .sum::<usize>()
        * roots.len();
    validate_repository_root(request.repository_root).map_err(|reason| {
        InstallError::preflight(
            RefusalClass::Source,
            reason,
            None,
            target_count,
            request.dry_run,
            "map_parsed",
        )
    })?;

    let normalized_destinations = validate_map_destinations(&map.targets, request.dry_run)?;
    let staging = request.destdir.is_some();
    let mut targets = Vec::new();
    let targets_per_root = target_count.checked_div(roots.len()).unwrap_or(0);
    let (plain_roots, skipped_roots) = available_roots(request, map, roots, target_count)?;
    let target_count = target_count - skipped_roots.len() * targets_per_root;
    for root in &plain_roots {
        for (target, destination_relative) in map.targets.iter().zip(&normalized_destinations) {
            let index = targets.len() + 1;
            let planned = plan_target(
                request,
                root,
                target,
                destination_relative,
                index,
                target_count,
                identity,
                staging,
            )
            .map_err(|mut error| {
                error.registry.skipped_roots.clone_from(&skipped_roots);
                error
            })?;
            targets.extend(planned);
        }
    }
    Ok(Plan {
        roots: plain_roots,
        skipped_roots,
        staging,
        targets,
    })
}

fn available_roots(
    request: InstallRequest<'_>,
    map: &InstallMap,
    roots: Vec<(PathBuf, Option<String>)>,
    target_count: usize,
) -> Result<(Vec<PathBuf>, Vec<RegistryRoot>), InstallError> {
    let staging = request.destdir.is_some();
    let targets_per_root = target_count.checked_div(roots.len()).unwrap_or(0);
    let mut plain_roots = Vec::new();
    let mut skipped_roots = Vec::new();
    let mut unavailable_roots = Vec::new();
    for (root, loop_name) in roots {
        let valid = if staging {
            validate_root_prefix(&root)
        } else {
            validate_root(&root)
        };
        if let Err(reason) = valid {
            if let Some(loop_name) = loop_name {
                let missing = fs::symlink_metadata(&root)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
                    && validate_root_prefix(&root).is_ok();
                let row = RegistryRoot {
                    loop_name,
                    root,
                    reason,
                };
                if missing
                    && map
                        .registry
                        .as_ref()
                        .is_some_and(|registry| registry.missing_root == MissingRoot::Skip)
                {
                    skipped_roots.push(row);
                } else {
                    unavailable_roots.push(row);
                }
                continue;
            }
            return Err(InstallError::preflight(
                RefusalClass::Destination,
                reason,
                None,
                target_count,
                request.dry_run,
                "map_parsed",
            ));
        }
        plain_roots.push(root);
    }
    if !unavailable_roots.is_empty() {
        let reason = unavailable_roots
            .iter()
            .find(|row| row.reason != RefusalReason::RootUnavailable)
            .map_or(RefusalReason::RegistryRootMissing, |row| row.reason);
        let mut error = InstallError::preflight(
            RefusalClass::Destination,
            reason,
            None,
            target_count - skipped_roots.len() * targets_per_root,
            request.dry_run,
            "map_parsed",
        );
        error.registry.unavailable_roots = unavailable_roots;
        error.registry.skipped_roots = skipped_roots;
        return Err(error);
    }
    Ok((plain_roots, skipped_roots))
}

fn resolve_roots(
    request: InstallRequest<'_>,
    map: &InstallMap,
) -> Result<Vec<(PathBuf, Option<String>)>, InstallError> {
    let refuse = |reason| {
        InstallError::preflight(
            RefusalClass::Map,
            reason,
            None,
            map.targets.len(),
            request.dry_run,
            "map_parsed",
        )
    };
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| refuse(RefusalReason::InvalidRoot))?;
    let mut roots = Vec::new();
    match (&map.root, &map.registry) {
        (Some(root), None) => {
            let root = request
                .root_override
                .map_or_else(|| expand_home(root, &home), Path::to_path_buf);
            roots.push((root, None));
        }
        (None, Some(registry_map)) => {
            if !registry_map.path.starts_with("~/")
                || !registry_map.root.starts_with("~/")
                || registry_map.root.matches(NAME_PLACEHOLDER).count() != 1
                || registry_map
                    .root
                    .replace(NAME_PLACEHOLDER, "")
                    .contains('{')
                || registry_map
                    .root
                    .replace(NAME_PLACEHOLDER, "")
                    .contains('}')
            {
                return Err(refuse(RefusalReason::InvalidRoot));
            }
            let path = request
                .registry_override
                .map_or_else(|| expand_home(&registry_map.path, &home), Path::to_path_buf);
            let registry = loop_home::registry::load_registry(&path)
                .map_err(|_error| refuse(RefusalReason::RegistryRead))?;
            for row in registry.rows(&home) {
                let root = request.root_override.map_or_else(
                    || {
                        expand_home(
                            Path::new(&registry_root_name(&registry_map.root, &row.name)),
                            &home,
                        )
                    },
                    |override_root| override_root.join(&row.name),
                );
                roots.push((root, Some(row.name)));
            }
        }
        _ => return Err(refuse(RefusalReason::TargetShape)),
    }
    roots
        .into_iter()
        .map(|(root, name)| {
            let invalid = |root: &Path| {
                let mut error = refuse(RefusalReason::InvalidRoot);
                if let Some(loop_name) = &name {
                    error.registry.unavailable_roots.push(RegistryRoot {
                        loop_name: loop_name.clone(),
                        root: root.to_path_buf(),
                        reason: RefusalReason::InvalidRoot,
                    });
                }
                error
            };
            let resolved = normalize_absolute(&root).ok_or_else(|| invalid(&root))?;
            let staged = request.destdir.map_or_else(
                || resolved.clone(),
                |destdir| destdir.join(resolved.strip_prefix("/").unwrap_or(&resolved)),
            );
            let staged = normalize_absolute(&staged).ok_or_else(|| invalid(&staged))?;
            Ok((staged, name))
        })
        .collect()
}

const NAME_PLACEHOLDER: &str = concat!("{", "name}");
fn registry_root_name(pattern: &str, name: &str) -> String {
    pattern.replace(NAME_PLACEHOLDER, name)
}

fn expand_home(path: &Path, home: &Path) -> PathBuf {
    path.strip_prefix("~")
        .map_or_else(|_| path.to_path_buf(), |suffix| home.join(suffix))
}

fn validate_root_prefix(root: &Path) -> Result<(), RefusalReason> {
    check_root(root, true)
}

fn validate_map_destinations(
    targets: &[MapTarget],
    dry_run: bool,
) -> Result<Vec<PathBuf>, InstallError> {
    let target_count = targets.len();
    let mut destinations = BTreeSet::new();
    let mut normalized = Vec::with_capacity(target_count);
    for (offset, target) in targets.iter().enumerate() {
        let index = offset + 1;
        let relative = normalize_relative(&target.destination).ok_or_else(|| {
            InstallError::preflight(
                RefusalClass::Map,
                RefusalReason::InvalidRelativePath,
                Some(index),
                target_count,
                dry_run,
                "map_parsed",
            )
        })?;
        if !destinations.insert(relative.clone()) {
            return Err(InstallError::preflight(
                RefusalClass::Map,
                RefusalReason::DuplicateDestination,
                Some(index),
                target_count,
                dry_run,
                "map_parsed",
            ));
        }
        normalized.push(relative);
    }

    let mut reserved = BTreeSet::new();
    for (offset, destination) in normalized.iter().enumerate() {
        let provenance =
            targets[offset].kind == "build" || targets[offset].provenance == Some(true);
        reserved.insert(backup_relative(destination));
        if provenance {
            let sibling = provenance_relative(destination);
            reserved.insert(sibling.clone());
            reserved.insert(backup_relative(&sibling));
        }
        if destinations.contains(&backup_relative(destination)) {
            return Err(InstallError::preflight(
                RefusalClass::Map,
                RefusalReason::BackupDestinationCollision,
                Some(offset + 1),
                target_count,
                dry_run,
                "map_parsed",
            ));
        }
    }
    for (offset, destination) in normalized.iter().enumerate() {
        if reserved.contains(destination) {
            return Err(InstallError::preflight(
                RefusalClass::Map,
                RefusalReason::ProvenanceCollision,
                Some(offset + 1),
                target_count,
                dry_run,
                "map_parsed",
            ));
        }
    }
    Ok(normalized)
}

fn provenance_relative(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(".provenance");
    destination.with_file_name(name)
}

#[allow(clippy::too_many_arguments)]
fn plan_target(
    request: InstallRequest<'_>,
    root: &Path,
    target: &MapTarget,
    destination_relative: &Path,
    index: usize,
    target_count: usize,
    identity: Option<&GitIdentity>,
    staging: bool,
) -> Result<Vec<PlannedTarget>, InstallError> {
    let mode = parse_mode(&target.mode).ok_or_else(|| {
        InstallError::preflight(
            RefusalClass::Map,
            RefusalReason::InvalidMode,
            Some(index),
            target_count,
            request.dry_run,
            "map_parsed",
        )
    })?;
    let materialized = materialize_target(request, target, index, target_count, identity)?;
    let mut planned = vec![plan_file(
        request,
        root,
        destination_relative.to_path_buf(),
        mode,
        materialized.bytes,
        materialized.source_identities.clone(),
        index,
        target_count,
        materialized.domain_mismatch,
        staging,
    )?];
    if let Some(bytes) = materialized.provenance {
        planned.push(plan_file(
            request,
            root,
            provenance_relative(destination_relative),
            0o644,
            bytes,
            materialized.source_identities,
            index + 1,
            target_count,
            false,
            staging,
        )?);
    }
    Ok(planned)
}

#[allow(clippy::too_many_arguments)]
fn plan_file(
    request: InstallRequest<'_>,
    root: &Path,
    destination_relative: PathBuf,
    mode: u32,
    bytes: Vec<u8>,
    source_identities: Vec<(u64, u64)>,
    index: usize,
    target_count: usize,
    domain_mismatch: bool,
    staging: bool,
) -> Result<PlannedTarget, InstallError> {
    let destination = root.join(&destination_relative);
    let backup = destination.with_file_name(backup_file_name(&destination));
    let parent_check = if staging {
        validate_root_prefix(root)
    } else {
        validate_destination_parent(root, &destination_relative)
    };
    parent_check.map_err(|reason| {
        InstallError::preflight(
            RefusalClass::Destination,
            reason,
            Some(index),
            target_count,
            request.dry_run,
            "inputs_materialized",
        )
    })?;
    let destination_state = inspect_destination(&destination).map_err(|(class, reason)| {
        InstallError::preflight(
            class,
            reason,
            Some(index),
            target_count,
            request.dry_run,
            "inputs_materialized",
        )
    })?;

    if let DestinationState::Existing(existing) = &destination_state {
        validate_existing_target(existing, &source_identities, &bytes, mode).map_err(|reason| {
            InstallError::preflight(
                RefusalClass::Destination,
                reason,
                Some(index),
                target_count,
                request.dry_run,
                "destination_inspected",
            )
        })?;
    }

    let backup_state =
        planned_backup_state(&backup, &destination_state, &bytes).map_err(|reason| {
            InstallError::preflight(
                RefusalClass::Destination,
                reason,
                Some(index),
                target_count,
                request.dry_run,
                "destination_inspected",
            )
        })?;

    Ok(PlannedTarget {
        index,
        root: root.to_path_buf(),
        domain_mismatch,
        destination_relative,
        destination,
        backup,
        mode,
        bytes,
        source_identities,
        destination_state,
        backup_state,
    })
}

fn validate_existing_target(
    existing: &FileSnapshot,
    source_identities: &[(u64, u64)],
    bytes: &[u8],
    mode: u32,
) -> Result<(), RefusalReason> {
    if source_identities
        .iter()
        .any(|identity| *identity == evidence_identity(&existing.evidence))
    {
        return Err(RefusalReason::SourceTargetAlias);
    }
    if existing.bytes == bytes && existing.evidence.mode != mode {
        return Err(RefusalReason::EqualModeMismatch);
    }
    Ok(())
}

fn planned_backup_state(
    backup: &Path,
    destination: &DestinationState,
    installed_bytes: &[u8],
) -> Result<Option<FileSnapshot>, RefusalReason> {
    match destination {
        DestinationState::Existing(existing) if existing.bytes != installed_bytes => {
            inspect_backup(backup)
        }
        DestinationState::Missing | DestinationState::Existing(_) => Ok(None),
    }
}

#[allow(clippy::too_many_lines)]
fn materialize_target(
    request: InstallRequest<'_>,
    target: &MapTarget,
    index: usize,
    target_count: usize,
    identity: Option<&GitIdentity>,
) -> Result<MaterializedTarget, InstallError> {
    let dry_run = request.dry_run;
    let refuse_map = || {
        InstallError::preflight(
            RefusalClass::Map,
            RefusalReason::TargetShape,
            Some(index),
            target_count,
            dry_run,
            "map_parsed",
        )
    };
    match target.kind.as_str() {
        "copy"
            if target.source.is_some()
                && target.output.is_none()
                && target.domain.is_none()
                && target.base.is_none()
                && target.overlay.is_none()
                && target.max_bytes.is_none() =>
        {
            let source = target.source.as_deref().ok_or_else(refuse_map)?;
            let loaded = load_repository_file(request.repository_root, source).map_err(
                |(class, reason)| {
                    InstallError::preflight(
                        class,
                        reason,
                        Some(index),
                        target_count,
                        dry_run,
                        "map_validated",
                    )
                },
            )?;
            let provenance = if target.provenance == Some(true) {
                Some(provenance_bytes(
                    request.repository_root,
                    identity.ok_or_else(refuse_map)?,
                    "source",
                    &format!("copy {}", source.display()),
                    &loaded.bytes,
                ))
            } else {
                None
            };
            Ok(MaterializedTarget {
                bytes: loaded.bytes,
                source_identities: vec![loaded.identity],
                provenance,
                domain_mismatch: false,
            })
        }
        "render"
            if target.source.is_none()
                && target.output.is_none()
                && target.domain.is_none()
                && target.provenance.is_none()
                && target.base.is_some()
                && target.overlay.is_some() =>
        {
            let base_path = target.base.as_deref().ok_or_else(refuse_map)?;
            let overlay_path = target.overlay.as_deref().ok_or_else(refuse_map)?;
            let base_root = request.shape_root.unwrap_or(request.repository_root);
            let base = load_repository_file(base_root, base_path).map_err(|(class, reason)| {
                InstallError::preflight(
                    if request.shape_root.is_some() && reason == RefusalReason::InvalidRelativePath
                    {
                        RefusalClass::Source
                    } else {
                        class
                    },
                    reason,
                    Some(index),
                    target_count,
                    dry_run,
                    "map_validated",
                )
            })?;
            let overlay = load_repository_file(request.repository_root, overlay_path).map_err(
                |(class, reason)| {
                    InstallError::preflight(
                        class,
                        reason,
                        Some(index),
                        target_count,
                        dry_run,
                        "map_validated",
                    )
                },
            )?;
            let bytes = render(&base.bytes, &overlay.bytes, target.max_bytes).map_err(|error| {
                InstallError::preflight(
                    RefusalClass::Render,
                    error.reason(),
                    Some(index),
                    target_count,
                    dry_run,
                    "inputs_loaded",
                )
            })?;
            Ok(MaterializedTarget {
                bytes,
                source_identities: vec![base.identity, overlay.identity],
                provenance: None,
                domain_mismatch: false,
            })
        }
        "build"
            if target.output.is_some()
                && target.domain.is_some()
                && target.source.is_none()
                && target.base.is_none()
                && target.overlay.is_none()
                && target.max_bytes.is_none()
                && target.provenance.is_none() =>
        {
            let root = request.build_root.ok_or_else(|| {
                InstallError::preflight(
                    RefusalClass::Map,
                    RefusalReason::BuildRootMissing,
                    Some(index),
                    target_count,
                    dry_run,
                    "map_validated",
                )
            })?;
            validate_root(root).map_err(|reason| {
                InstallError::preflight(
                    RefusalClass::Source,
                    reason,
                    Some(index),
                    target_count,
                    dry_run,
                    "map_validated",
                )
            })?;
            let output = target.output.as_deref().ok_or_else(refuse_map)?;
            let loaded = load_repository_file(root, output).map_err(|(class, reason)| {
                InstallError::preflight(
                    class,
                    reason,
                    Some(index),
                    target_count,
                    dry_run,
                    "map_validated",
                )
            })?;
            let mut record_name = output.as_os_str().to_os_string();
            record_name.push(".build.json");
            let record = load_repository_file(root, Path::new(&record_name)).map_err(
                |(class, reason)| {
                    InstallError::preflight(
                        class,
                        if reason == RefusalReason::SourceMissing {
                            RefusalReason::BuildRecordMissing
                        } else {
                            reason
                        },
                        Some(index),
                        target_count,
                        dry_run,
                        "input_loaded",
                    )
                },
            )?;
            let fields = parse_build_record(&record.bytes).ok_or_else(|| {
                InstallError::preflight(
                    RefusalClass::Source,
                    RefusalReason::BuildRecordInvalid,
                    Some(index),
                    target_count,
                    dry_run,
                    "input_loaded",
                )
            })?;
            let digest = hex_digest(&loaded.bytes);
            if fields.get("sha256") != Some(&digest) {
                return Err(InstallError::preflight(
                    RefusalClass::Source,
                    RefusalReason::BuildDigestMismatch,
                    Some(index),
                    target_count,
                    dry_run,
                    "input_loaded",
                ));
            }
            let domain = target.domain.as_deref().ok_or_else(refuse_map)?;
            let mismatch = fields.get("domain").is_none_or(|actual| actual != domain);
            if mismatch && request.destdir.is_none() && request.root_override.is_none() {
                return Err(InstallError::preflight(
                    RefusalClass::Source,
                    RefusalReason::DomainMismatch,
                    Some(index),
                    target_count,
                    dry_run,
                    "input_verified",
                ));
            }
            let build_stamp = fields.get("written").ok_or_else(|| {
                InstallError::preflight(
                    RefusalClass::Source,
                    RefusalReason::BuildRecordInvalid,
                    Some(index),
                    target_count,
                    dry_run,
                    "input_loaded",
                )
            })?;
            let build_description = format!(
                "{} {} {} {} cargo={} rustc={}",
                fields.get("package").ok_or_else(refuse_map)?,
                fields.get("bin").ok_or_else(refuse_map)?,
                fields.get("profile").ok_or_else(refuse_map)?,
                fields.get("domain").ok_or_else(refuse_map)?,
                fields.get("cargo_version").ok_or_else(refuse_map)?,
                fields.get("rustc_version").ok_or_else(refuse_map)?
            );
            let provenance = provenance_bytes(
                request.repository_root,
                identity.ok_or_else(refuse_map)?,
                build_stamp,
                &build_description,
                &loaded.bytes,
            );
            Ok(MaterializedTarget {
                bytes: loaded.bytes,
                source_identities: vec![loaded.identity, record.identity],
                provenance: Some(provenance),
                domain_mismatch: mismatch,
            })
        }
        _ => Err(refuse_map()),
    }
}

#[derive(Debug)]
struct GitIdentity {
    commit: String,
    dirty: bool,
}

fn git_output(repository_root: &Path, arguments: &[&str]) -> Result<String, RefusalReason> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(arguments)
        .output()
        .map_err(|_| RefusalReason::GitIdentity)?;
    if !output.status.success() {
        return Err(RefusalReason::GitIdentity);
    }
    String::from_utf8(output.stdout).map_err(|_| RefusalReason::GitIdentity)
}

fn git_identity(repository_root: &Path) -> Result<GitIdentity, RefusalReason> {
    let commit = git_output(repository_root, &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let dirty = !git_output(
        repository_root,
        &["status", "--porcelain", "--untracked-files=all"],
    )?
    .is_empty();
    Ok(GitIdentity { commit, dirty })
}

fn verify_release(
    repository_root: &Path,
    tag: &str,
    commit: &str,
    dry_run: bool,
) -> Result<(), InstallError> {
    let refuse = || {
        InstallError::preflight(
            RefusalClass::Source,
            RefusalReason::ReleaseIdentity,
            None,
            0,
            dry_run,
            "identity_checked",
        )
    };
    if tag.is_empty() || commit.is_empty() {
        return Err(refuse());
    }
    let identity = git_identity(repository_root).map_err(|_| refuse())?;
    let tag_ref = format!("refs/tags/{tag}^{{commit}}");
    let tagged =
        git_output(repository_root, &["rev-parse", "--verify", &tag_ref]).map_err(|_| refuse())?;
    if identity.dirty || identity.commit != commit || tagged.trim() != commit {
        return Err(refuse());
    }
    Ok(())
}

fn provenance_bytes(
    repository_root: &Path,
    identity: &GitIdentity,
    build_stamp: &str,
    build_description: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let remote = git_output(repository_root, &["remote", "get-url", "origin"]).ok();
    let repo_path = remote.as_deref().unwrap_or_default().trim();
    let repo_path = if repo_path.is_empty() {
        repository_root
    } else {
        Path::new(repo_path)
    };
    let repo = repo_path.file_name().unwrap_or_default().to_string_lossy();
    let repo = repo.strip_suffix(".git").unwrap_or(&repo);
    format!("source-repo: {repo}\nsource-commit: {}\ndirty: {}\nbuilt: {build_stamp}\nbuild: {build_description}\nsha256-prefix: {}\n", identity.commit, if identity.dirty { "yes" } else { "no" }, &hex_digest(bytes)[..16]).into_bytes()
}

fn parse_build_record(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let source: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let source = source.as_object()?;
    if source.len() != 14 || !source.get("build_wall_ms")?.is_u64() {
        return None;
    }
    let mut fields = BTreeMap::new();
    for key in [
        "bin",
        "cargo_version",
        "domain",
        "installed_name",
        "package",
        "profile",
        "release_group",
        "repository",
        "rustc_version",
        "sha256",
        "source_commit",
        "version",
        "written",
    ] {
        let value = source.get(key)?.as_str()?;
        if value.is_empty() {
            return None;
        }
        fields.insert(key.to_owned(), value.to_owned());
    }
    let commit = fields.get("source_commit")?;
    if ![40, 64].contains(&commit.len())
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(fields)
}

fn load_repository_file(
    repository_root: &Path,
    relative: &Path,
) -> Result<LoadedBytes, (RefusalClass, RefusalReason)> {
    let normalized = normalize_relative(relative)
        .ok_or((RefusalClass::Map, RefusalReason::InvalidRelativePath))?;
    let path = repository_root.join(&normalized);
    validate_source_components(repository_root, &normalized)?;
    let before = capture_file(&path, FileRole::Source)?;
    let after = capture_file(&path, FileRole::Source)?;
    if before != after {
        return Err((RefusalClass::ConcurrentChange, RefusalReason::StateChanged));
    }
    Ok(LoadedBytes {
        bytes: before.bytes,
        identity: evidence_identity(&before.evidence),
    })
}

fn resolve_shape_root(root: &Path) -> Result<PathBuf, RefusalReason> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_error| RefusalReason::SourceRead)?
            .join(root)
    };
    let normalized = normalize_absolute(&absolute).ok_or(RefusalReason::InvalidRoot)?;
    validate_repository_root(&normalized)?;
    Ok(normalized)
}

fn validated_shape_root(
    request: &InstallRequest<'_>,
    target_count: usize,
) -> Result<Option<PathBuf>, InstallError> {
    request
        .shape_root
        .map(|root| {
            resolve_shape_root(root).map_err(|reason| {
                InstallError::preflight(
                    RefusalClass::Source,
                    reason,
                    None,
                    target_count,
                    request.dry_run,
                    "map_parsed",
                )
            })
        })
        .transpose()
}

/// Render one base and overlay without consulting timestamps or environment state.
///
/// # Errors
///
/// Returns [`RenderError`] when slots or sections are malformed, duplicated, unmatched, conflicting, left unresolved, or larger than `max_bytes` after assembly.
pub fn render(base: &[u8], overlay: &[u8], max_bytes: Option<u64>) -> Result<Vec<u8>, RenderError> {
    let base_lines = lines(base);
    let mut slots = Vec::new();
    let mut slot_set = BTreeSet::new();
    let mut base_heading_labels = BTreeSet::new();
    for line in &base_lines {
        let body = &base[line.start..line.body_end];
        if let Some((_level, label)) = heading(body) {
            base_heading_labels.insert(label);
        }
        if let Some(label) = slot_label(body) {
            if !slot_set.insert(label.clone()) {
                return Err(RenderError::new(RefusalReason::DuplicateSlot));
            }
            slots.push(label);
        }
    }

    let sections = overlay_sections(overlay)?;
    for slot in &slots {
        if base_heading_labels.contains(slot) {
            return Err(RenderError::new(RefusalReason::BaseHeadingConflict));
        }
        if !sections.contains_key(slot) {
            return Err(RenderError::new(RefusalReason::MissingOverlaySection));
        }
    }
    if sections.keys().any(|label| !slot_set.contains(label)) {
        return Err(RenderError::new(RefusalReason::UnusedOverlaySection));
    }

    let mut rendered = Vec::with_capacity(base.len().saturating_add(overlay.len()));
    for line in &base_lines {
        let body = &base[line.start..line.body_end];
        if let Some(label) = slot_label(body) {
            let section = sections
                .get(&label)
                .ok_or_else(|| RenderError::new(RefusalReason::MissingOverlaySection))?;
            rendered.extend_from_slice(section);
        } else {
            rendered.extend_from_slice(&base[line.start..line.end]);
        }
    }
    if contains_bytes(&rendered, b"{{overlay:") {
        return Err(RenderError::new(RefusalReason::LeftoverSlot));
    }
    if max_bytes.is_some_and(|limit| {
        u64::try_from(rendered.len()).map_or(true, |rendered_size| rendered_size > limit)
    }) {
        return Err(RenderError::new(RefusalReason::RenderedSize));
    }
    Ok(rendered)
}

#[derive(Clone, Copy, Debug)]
struct Line {
    start: usize,
    body_end: usize,
    end: usize,
}

fn lines(bytes: &[u8]) -> Vec<Line> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let newline = bytes[start..].iter().position(|byte| *byte == b'\n');
        let end = newline.map_or(bytes.len(), |offset| start + offset + 1);
        let mut body_end = newline.map_or(bytes.len(), |offset| start + offset);
        if body_end > start && bytes[body_end - 1] == b'\r' {
            body_end -= 1;
        }
        result.push(Line {
            start,
            body_end,
            end,
        });
        start = end;
    }
    result
}

fn slot_label(line: &[u8]) -> Option<String> {
    let label = line.strip_prefix(b"{{overlay:")?.strip_suffix(b"}}")?;
    valid_label(label).then(|| String::from_utf8_lossy(label).into_owned())
}

fn heading(line: &[u8]) -> Option<(u8, String)> {
    let level = heading_level(line)?;
    let suffix = line.strip_suffix(b"`")?;
    let open = suffix.iter().rposition(|byte| *byte == b'`')?;
    let label = &suffix[open + 1..];
    if !suffix[..open].ends_with(" · ".as_bytes()) || !valid_label(label) {
        return None;
    }
    Some((level, String::from_utf8_lossy(label).into_owned()))
}

fn heading_level(line: &[u8]) -> Option<u8> {
    let hashes = line.iter().take_while(|byte| **byte == b'#').count();
    if (1..=6).contains(&hashes) && line.get(hashes) == Some(&b' ') {
        u8::try_from(hashes).ok()
    } else {
        None
    }
}

fn valid_label(label: &[u8]) -> bool {
    let mut colon_count = 0;
    let mut segment_length = 0;
    for byte in label {
        if *byte == b':' {
            if segment_length == 0 {
                return false;
            }
            colon_count += 1;
            segment_length = 0;
        } else if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_') {
            segment_length += 1;
        } else {
            return false;
        }
    }
    colon_count >= 2 && segment_length > 0
}

fn overlay_sections(overlay: &[u8]) -> Result<BTreeMap<String, &[u8]>, RenderError> {
    let overlay_lines = lines(overlay);
    let first = overlay_lines
        .first()
        .ok_or_else(|| RenderError::new(RefusalReason::OverlayShape))?;
    let (mut section_level, mut section_label) = heading(&overlay[first.start..first.body_end])
        .ok_or_else(|| RenderError::new(RefusalReason::OverlayShape))?;
    let mut section_start = first.start;
    let mut sections = BTreeMap::new();

    for line in overlay_lines.iter().skip(1) {
        let body = &overlay[line.start..line.body_end];
        let Some(level) = heading_level(body) else {
            continue;
        };
        if level > section_level {
            continue;
        }
        let (_level, next_label) =
            heading(body).ok_or_else(|| RenderError::new(RefusalReason::OverlayShape))?;
        if sections
            .insert(section_label, &overlay[section_start..line.start])
            .is_some()
        {
            return Err(RenderError::new(RefusalReason::DuplicateOverlaySection));
        }
        section_start = line.start;
        section_level = level;
        section_label = next_label;
    }
    if sections
        .insert(section_label, &overlay[section_start..])
        .is_some()
    {
        return Err(RenderError::new(RefusalReason::DuplicateOverlaySection));
    }
    Ok(sections)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn execute_plan(plan: &Plan, dry_run: bool) -> Result<InstallReport, InstallError> {
    let target_count = plan.targets.len();
    if plan.staging && !dry_run {
        for root in &plan.roots {
            fs::create_dir_all(root).map_err(|_| {
                InstallError::preflight(
                    RefusalClass::Install,
                    RefusalReason::ParentCreate,
                    None,
                    target_count,
                    dry_run,
                    "preflight",
                )
            })?;
            validate_root(root).map_err(|reason| {
                InstallError::preflight(
                    RefusalClass::Destination,
                    reason,
                    None,
                    target_count,
                    dry_run,
                    "staging_root_created",
                )
            })?;
        }
    }
    let mut completed = Vec::with_capacity(target_count);
    let mut touched = BTreeSet::new();
    for target in &plan.targets {
        let result = if dry_run {
            dry_run_target(&target.root, target, plan.staging)
        } else {
            install_target(&target.root, target)
        };
        match result {
            Ok(mut report) => {
                if target.domain_mismatch {
                    report.outcome = TargetOutcome::DomainMismatch;
                }
                if report.touched {
                    touched.insert(target.index);
                }
                completed.push(report);
            }
            Err(failure) => {
                if failure.touched {
                    touched.insert(target.index);
                }
                return Err(InstallError {
                    class: failure.class,
                    reason: failure.reason,
                    target_index: Some(target.index),
                    target_count,
                    completed,
                    touched,
                    last_completed: failure.last_completed,
                    dry_run,
                    registry: Box::default(),
                });
            }
        }
    }
    Ok(InstallReport {
        targets: completed,
        skipped_roots: plan.skipped_roots.clone(),
        dry_run,
        identity: String::new(),
        map_sha256: String::new(),
    })
}

fn dry_run_target(
    root: &Path,
    target: &PlannedTarget,
    staging: bool,
) -> Result<TargetReport, StepFailure> {
    revalidate_target(root, target, staging)?;
    let (outcome, before, backup) = match &target.destination_state {
        DestinationState::Missing => (TargetOutcome::New, None, None),
        DestinationState::Existing(existing) if existing.bytes == target.bytes => (
            TargetOutcome::Unchanged,
            Some(existing.evidence.clone()),
            None,
        ),
        DestinationState::Existing(existing) => (
            TargetOutcome::Changed,
            Some(existing.evidence.clone()),
            Some(backup_evidence(
                &existing.bytes,
                target.backup_state.is_some(),
                BackupDisposition::Planned,
            )),
        ),
    };
    let after = if outcome == TargetOutcome::Unchanged {
        before.clone()
    } else {
        None
    };
    Ok(TargetReport {
        index: target.index,
        outcome,
        state: outcome,
        backup,
        before,
        after,
        replacements: 0,
        touched: false,
    })
}

fn install_target(root: &Path, target: &PlannedTarget) -> Result<TargetReport, StepFailure> {
    match &target.destination_state {
        DestinationState::Missing => install_new(root, target),
        DestinationState::Existing(existing) if existing.bytes == target.bytes => {
            revalidate_target(root, target, false)?;
            Ok(TargetReport {
                index: target.index,
                outcome: TargetOutcome::Unchanged,
                state: TargetOutcome::Unchanged,
                backup: None,
                before: Some(existing.evidence.clone()),
                after: Some(existing.evidence.clone()),
                replacements: 0,
                touched: false,
            })
        }
        DestinationState::Existing(existing) => install_changed(root, target, existing),
    }
}

fn install_new(root: &Path, target: &PlannedTarget) -> Result<TargetReport, StepFailure> {
    create_destination_parents(root, &target.destination_relative).map_err(|reason| {
        StepFailure {
            class: RefusalClass::Install,
            reason,
            touched: false,
            last_completed: "preflight".to_owned(),
        }
    })?;
    revalidate_target(root, target, false)?;
    let temporary = stage_file(
        target
            .destination
            .parent()
            .unwrap_or_else(|| Path::new(".")),
        ".superloop-install-target-",
        &target.bytes,
        target.mode,
        None,
    )
    .map_err(|_error| StepFailure {
        class: RefusalClass::Install,
        reason: RefusalReason::TargetWrite,
        touched: false,
        last_completed: "parent_created".to_owned(),
    })?;
    temporary
        .persist(&target.destination)
        .map_err(|_error| StepFailure {
            class: RefusalClass::Install,
            reason: RefusalReason::TargetWrite,
            touched: false,
            last_completed: "target_staged".to_owned(),
        })?;
    let after = verify_installed(target, None).map_err(|reason| StepFailure {
        class: RefusalClass::Verification,
        reason,
        touched: true,
        last_completed: format!("target_{}_replaced", target.index),
    })?;
    Ok(TargetReport {
        index: target.index,
        outcome: TargetOutcome::New,
        state: TargetOutcome::New,
        backup: None,
        before: None,
        after: Some(after),
        replacements: 1,
        touched: true,
    })
}

fn install_changed(
    root: &Path,
    target: &PlannedTarget,
    existing: &FileSnapshot,
) -> Result<TargetReport, StepFailure> {
    revalidate_target(root, target, false)?;
    revalidate_backup(target)?;
    let backup_temporary = stage_file(
        target.backup.parent().unwrap_or_else(|| Path::new(".")),
        ".superloop-install-backup-",
        &existing.bytes,
        existing.evidence.mode,
        None,
    )
    .map_err(|_error| StepFailure {
        class: RefusalClass::Backup,
        reason: RefusalReason::BackupWrite,
        touched: false,
        last_completed: "preflight".to_owned(),
    })?;
    backup_temporary
        .persist(&target.backup)
        .map_err(|_error| StepFailure {
            class: RefusalClass::Backup,
            reason: RefusalReason::BackupWrite,
            touched: false,
            last_completed: "backup_staged".to_owned(),
        })?;
    verify_backup(&target.backup, &existing.bytes).map_err(|reason| StepFailure {
        class: RefusalClass::Backup,
        reason,
        touched: true,
        last_completed: format!("backup_{}_written", target.index),
    })?;
    revalidate_target(root, target, false).map_err(|mut failure| {
        failure.touched = true;
        failure.last_completed = format!("backup_{}_verified", target.index);
        failure
    })?;
    let temporary = stage_file(
        target
            .destination
            .parent()
            .unwrap_or_else(|| Path::new(".")),
        ".superloop-install-target-",
        &target.bytes,
        target.mode,
        Some(existing.modified),
    )
    .map_err(|_error| StepFailure {
        class: RefusalClass::Install,
        reason: RefusalReason::TargetWrite,
        touched: true,
        last_completed: format!("backup_{}_verified", target.index),
    })?;
    temporary
        .persist(&target.destination)
        .map_err(|_error| StepFailure {
            class: RefusalClass::Install,
            reason: RefusalReason::TargetWrite,
            touched: true,
            last_completed: format!("target_{}_staged", target.index),
        })?;
    let after = verify_installed(target, Some(existing)).map_err(|reason| StepFailure {
        class: RefusalClass::Verification,
        reason,
        touched: true,
        last_completed: format!("target_{}_replaced", target.index),
    })?;
    Ok(TargetReport {
        index: target.index,
        outcome: TargetOutcome::Changed,
        state: TargetOutcome::Changed,
        backup: Some(backup_evidence(
            &existing.bytes,
            target.backup_state.is_some(),
            BackupDisposition::Written,
        )),
        before: Some(existing.evidence.clone()),
        after: Some(after),
        replacements: 1,
        touched: true,
    })
}

fn stage_file(
    directory: &Path,
    prefix: &str,
    bytes: &[u8],
    mode: u32,
    outgoing_modified: Option<SystemTime>,
) -> io::Result<tempfile::NamedTempFile> {
    let mut temporary = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    if let Some(outgoing) = outgoing_modified
        && temporary.as_file().metadata()?.modified()? == outgoing
    {
        let distinct = outgoing
            .checked_add(Duration::from_secs(1))
            .unwrap_or(UNIX_EPOCH);
        temporary
            .as_file()
            .set_times(FileTimes::new().set_modified(distinct))?;
        if temporary.as_file().metadata()?.modified()? == outgoing {
            return Err(io::Error::other("staged mtime did not become distinct"));
        }
    }
    Ok(temporary)
}

fn verify_installed(
    target: &PlannedTarget,
    outgoing: Option<&FileSnapshot>,
) -> Result<FileEvidence, RefusalReason> {
    let installed = capture_file(&target.destination, FileRole::Destination)
        .map_err(|_failure| RefusalReason::TargetVerify)?;
    if installed.bytes != target.bytes || installed.evidence.mode != target.mode {
        return Err(RefusalReason::TargetVerify);
    }
    if target
        .source_identities
        .iter()
        .any(|identity| *identity == evidence_identity(&installed.evidence))
    {
        return Err(RefusalReason::TargetVerify);
    }
    if let Some(outgoing) = outgoing
        && (installed.evidence.mtime_seconds == outgoing.evidence.mtime_seconds
            && installed.evidence.mtime_nanoseconds == outgoing.evidence.mtime_nanoseconds
            || evidence_identity(&installed.evidence) == evidence_identity(&outgoing.evidence))
    {
        return Err(RefusalReason::MtimeTransition);
    }
    Ok(installed.evidence)
}

fn verify_backup(path: &Path, expected: &[u8]) -> Result<(), RefusalReason> {
    let snapshot =
        capture_file(path, FileRole::Backup).map_err(|_failure| RefusalReason::BackupVerify)?;
    if snapshot.bytes == expected {
        Ok(())
    } else {
        Err(RefusalReason::BackupVerify)
    }
}

fn revalidate_target(
    root: &Path,
    target: &PlannedTarget,
    allow_missing_root: bool,
) -> Result<(), StepFailure> {
    (if allow_missing_root {
        validate_root_prefix(root)
    } else {
        validate_root(root)
    })
    .map_err(|reason| StepFailure {
        class: RefusalClass::ConcurrentChange,
        reason,
        touched: false,
        last_completed: "preflight".to_owned(),
    })?;
    (if allow_missing_root {
        Ok(())
    } else {
        validate_destination_parent(root, &target.destination_relative)
    })
    .map_err(|_reason| StepFailure {
        class: RefusalClass::ConcurrentChange,
        reason: RefusalReason::StateChanged,
        touched: false,
        last_completed: "preflight".to_owned(),
    })?;
    let current = inspect_destination(&target.destination).map_err(|_failure| StepFailure {
        class: RefusalClass::ConcurrentChange,
        reason: RefusalReason::StateChanged,
        touched: false,
        last_completed: "preflight".to_owned(),
    })?;
    if current != target.destination_state {
        return Err(StepFailure {
            class: RefusalClass::ConcurrentChange,
            reason: RefusalReason::StateChanged,
            touched: false,
            last_completed: "preflight".to_owned(),
        });
    }
    Ok(())
}

fn revalidate_backup(target: &PlannedTarget) -> Result<(), StepFailure> {
    let current = inspect_backup(&target.backup).map_err(|_reason| StepFailure {
        class: RefusalClass::ConcurrentChange,
        reason: RefusalReason::StateChanged,
        touched: false,
        last_completed: "preflight".to_owned(),
    })?;
    if current != target.backup_state {
        return Err(StepFailure {
            class: RefusalClass::ConcurrentChange,
            reason: RefusalReason::StateChanged,
            touched: false,
            last_completed: "preflight".to_owned(),
        });
    }
    Ok(())
}

fn backup_evidence(
    outgoing: &[u8],
    replaced_existing: bool,
    disposition: BackupDisposition,
) -> BackupEvidence {
    let digest = hex_digest(outgoing);
    BackupEvidence {
        replaced_existing,
        outgoing_sha256: digest.clone(),
        backup_sha256: digest,
        disposition,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(hash.len() * 2);
    for byte in hash {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn create_destination_parents(root: &Path, destination: &Path) -> Result<(), RefusalReason> {
    let Some(parent) = destination.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(part) = component else {
            return Err(RefusalReason::ParentCreate);
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RefusalReason::ParentCreate);
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_metadata) => return Err(RefusalReason::ParentCreate),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_error| RefusalReason::ParentCreate)?;
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_error| RefusalReason::ParentCreate)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(RefusalReason::ParentCreate);
                }
            }
            Err(_error) => return Err(RefusalReason::ParentCreate),
        }
    }
    Ok(())
}

fn inspect_destination(path: &Path) -> Result<DestinationState, (RefusalClass, RefusalReason)> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err((RefusalClass::Destination, RefusalReason::DestinationSymlink))
        }
        Ok(metadata) if !metadata.is_file() => Err((
            RefusalClass::Destination,
            RefusalReason::DestinationNotRegular,
        )),
        Ok(_metadata) => capture_file(path, FileRole::Destination).map(DestinationState::Existing),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DestinationState::Missing),
        Err(_error) => Err((RefusalClass::Destination, RefusalReason::DestinationRead)),
    }
}

fn inspect_backup(path: &Path) -> Result<Option<FileSnapshot>, RefusalReason> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(RefusalReason::BackupDestinationType)
        }
        Ok(_metadata) => capture_file(path, FileRole::Backup)
            .map(Some)
            .map_err(|_failure| RefusalReason::BackupDestinationType),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_error) => Err(RefusalReason::BackupDestinationType),
    }
}

#[derive(Clone, Copy)]
enum FileRole {
    Source,
    Destination,
    Backup,
}

fn capture_file(
    path: &Path,
    role: FileRole,
) -> Result<FileSnapshot, (RefusalClass, RefusalReason)> {
    let (class, missing, wrong_type, read_failure) = match role {
        FileRole::Source => (
            RefusalClass::Source,
            RefusalReason::SourceMissing,
            RefusalReason::SourceNotRegular,
            RefusalReason::SourceRead,
        ),
        FileRole::Destination => (
            RefusalClass::Destination,
            RefusalReason::DestinationRead,
            RefusalReason::DestinationNotRegular,
            RefusalReason::DestinationRead,
        ),
        FileRole::Backup => (
            RefusalClass::Backup,
            RefusalReason::BackupVerify,
            RefusalReason::BackupVerify,
            RefusalReason::BackupVerify,
        ),
    };
    let before = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            (class, missing)
        } else {
            (class, read_failure)
        }
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err((class, wrong_type));
    }
    let bytes = fs::read(path).map_err(|_error| (class, read_failure))?;
    let after = fs::symlink_metadata(path).map_err(|_error| (class, read_failure))?;
    if after.file_type().is_symlink() || !after.is_file() {
        return Err((class, wrong_type));
    }
    let before_evidence = evidence(&before);
    let after_evidence = evidence(&after);
    if before_evidence != after_evidence {
        return Err((RefusalClass::ConcurrentChange, RefusalReason::StateChanged));
    }
    let modified = after.modified().map_err(|_error| (class, read_failure))?;
    Ok(FileSnapshot {
        bytes,
        evidence: after_evidence,
        modified,
    })
}

fn evidence(metadata: &Metadata) -> FileEvidence {
    FileEvidence {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
    }
}

const fn evidence_identity(evidence: &FileEvidence) -> (u64, u64) {
    (evidence.device, evidence.inode)
}

fn validate_root(root: &Path) -> Result<(), RefusalReason> {
    check_root(root, false)
}

fn root_metadata_reason(error: &io::Error) -> RefusalReason {
    match error.kind() {
        io::ErrorKind::NotFound => RefusalReason::RootUnavailable,
        io::ErrorKind::PermissionDenied => RefusalReason::RootInaccessible,
        _ => RefusalReason::RootMetadata,
    }
}

fn check_root(root: &Path, allow_missing: bool) -> Result<(), RefusalReason> {
    if !root.is_absolute() {
        return Err(RefusalReason::InvalidRoot);
    }
    let mut current = PathBuf::new();
    let mut missing = false;
    for component in root.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(part) => {
                current.push(part);
                if missing {
                    continue;
                }
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(RefusalReason::RootSymlink);
                    }
                    Ok(metadata) if !metadata.is_dir() => {
                        return Err(RefusalReason::RootNotDirectory);
                    }
                    Ok(_) => {}
                    Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {
                        missing = true;
                    }
                    Err(error) => return Err(root_metadata_reason(&error)),
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(RefusalReason::InvalidRoot);
            }
        }
    }
    Ok(())
}

fn validate_repository_root(root: &Path) -> Result<(), RefusalReason> {
    if !root.is_absolute() {
        return Err(RefusalReason::InvalidRoot);
    }
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(RefusalReason::SourceSymlink),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_metadata) => Err(RefusalReason::SourceNotRegular),
        Err(_error) => Err(RefusalReason::SourceMissing),
    }
}

fn validate_source_components(
    root: &Path,
    relative: &Path,
) -> Result<(), (RefusalClass, RefusalReason)> {
    let mut current = root.to_path_buf();
    let count = relative.components().count();
    for (offset, component) in relative.components().enumerate() {
        let Component::Normal(part) = component else {
            return Err((RefusalClass::Map, RefusalReason::InvalidRelativePath));
        };
        current.push(part);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                (RefusalClass::Source, RefusalReason::SourceMissing)
            } else {
                (RefusalClass::Source, RefusalReason::SourceRead)
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err((RefusalClass::Source, RefusalReason::SourceSymlink));
        }
        if offset + 1 < count && !metadata.is_dir() {
            return Err((RefusalClass::Source, RefusalReason::SourceNotRegular));
        }
        if offset + 1 == count && !metadata.is_file() {
            return Err((RefusalClass::Source, RefusalReason::SourceNotRegular));
        }
    }
    Ok(())
}

fn validate_destination_parent(root: &Path, relative: &Path) -> Result<(), RefusalReason> {
    validate_root(root)?;
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    let mut missing = false;
    for component in parent.components() {
        let Component::Normal(part) = component else {
            return Err(RefusalReason::DestinationComponent);
        };
        current.push(part);
        if missing {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RefusalReason::DestinationSymlink);
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(RefusalReason::DestinationComponent);
            }
            Ok(_metadata) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing = true,
            Err(_error) => return Err(RefusalReason::DestinationComponent),
        }
    }
    Ok(())
}

fn normalize_relative(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

fn normalize_absolute(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Some(normalized)
}

fn parse_mode(mode: &str) -> Option<u32> {
    if mode.len() != 4 || !mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return None;
    }
    u32::from_str_radix(mode, 8).ok()
}

fn backup_relative(destination: &Path) -> PathBuf {
    destination.with_file_name(backup_file_name(destination))
}

fn backup_file_name(destination: &Path) -> OsString {
    let mut name = destination.file_name().unwrap_or_default().to_os_string();
    name.push(".pre-deploy");
    name
}

/// Write all target evidence, the count summary, and exactly one final agent-text report.
///
/// # Errors
///
/// Returns an I/O error if the report stream rejects any bytes or its final flush.
pub fn write_report<W: io::Write>(
    result: &Result<InstallReport, InstallError>,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    match result {
        Ok(report) => write_success_report(report, wall, output),
        Err(error) => write_refusal_report(error, wall, output),
    }
}

fn write_success_report<W: io::Write>(
    report: &InstallReport,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    write_registry_roots(&report.skipped_roots, "skipped", output)?;
    for target in &report.targets {
        write_target_report(target, report.dry_run, output)?;
    }
    let unchanged = report.count(TargetOutcome::Unchanged);
    let new = report.count(TargetOutcome::New);
    let changed = report.count(TargetOutcome::Changed);
    let domain_mismatch = report.count(TargetOutcome::DomainMismatch);
    let wall = format_wall(wall);
    writeln!(
        output,
        "summary unchanged={unchanged} new={new} changed={changed} refused=0 domain_mismatch={domain_mismatch} dry_run={} wall={wall} last_completed=all identity={} map_sha256={} skipped={}",
        yes_no(report.dry_run),
        report.identity,
        report.map_sha256,
        report.skipped_roots.len(),
    )?;
    writeln!(output, "RUN-REPORT exit=0 wall={wall} verdict=ok")?;
    output.flush()
}

fn write_refusal_report<W: io::Write>(
    error: &InstallError,
    wall: Duration,
    output: &mut W,
) -> io::Result<()> {
    write_registry_roots(&error.registry.skipped_roots, "skipped", output)?;
    write_registry_roots(&error.registry.unavailable_roots, "refused", output)?;
    for report in &error.completed {
        write_target_report(report, error.dry_run, output)?;
    }
    if error.target_index.is_none() && error.registry.unavailable_roots.is_empty() {
        writeln!(
            output,
            "target=map outcome=refused class={} reason={} touched=no{}",
            error.class,
            error.reason,
            error
                .loop_name()
                .map_or(String::new(), |name| format!(" loop={name}")),
        )?;
    }
    write_unreached_registry(&error.registry, output)?;
    for index in error.completed.len() + 1..=error.target_count {
        let primary = error.target_index == Some(index);
        let (class, reason) = if primary {
            (error.class.as_str(), error.reason.as_str())
        } else if error.completed.is_empty() {
            ("plan", "plan_refused")
        } else {
            ("plan", "not_attempted")
        };
        writeln!(
            output,
            "target={index} outcome=refused class={class} reason={reason} touched={}{}",
            yes_no(error.touched.contains(&index)),
            if primary {
                error
                    .loop_name()
                    .map_or(String::new(), |name| format!(" loop={name}"))
            } else {
                String::new()
            },
        )?;
    }
    let unchanged = error
        .completed
        .iter()
        .filter(|target| target.state == TargetOutcome::Unchanged)
        .count();
    let new = error
        .completed
        .iter()
        .filter(|target| target.state == TargetOutcome::New)
        .count();
    let changed = error
        .completed
        .iter()
        .filter(|target| target.state == TargetOutcome::Changed)
        .count();
    let refused = error
        .target_count
        .saturating_sub(error.completed.len())
        .max(1);
    let wall = format_wall(wall);
    writeln!(
        output,
        "summary unchanged={unchanged} new={new} changed={changed} refused={refused} dry_run={} wall={wall} last_completed={} skipped={}",
        yes_no(error.dry_run),
        error.last_completed,
        error.registry.skipped_roots.len(),
    )?;
    writeln!(
        output,
        "RUN-REPORT exit={} wall={wall} verdict=refused",
        error.class.exit_status(),
    )?;
    output.flush()
}

fn write_unreached_registry<W: io::Write>(
    registry: &RegistryOutcomes,
    output: &mut W,
) -> io::Result<()> {
    for (root, loop_name) in &registry.unreached_roots {
        writeln!(
            output,
            "target=registry outcome=not_reached class=plan reason=plan_refused loop={loop_name} root={} touched=no",
            root.display(),
        )?;
    }
    if let Some((class, reason)) = registry.resolution_failure {
        writeln!(
            output,
            "target=registry outcome=unresolved class={class} reason={reason} stage=root_resolution touched=no",
        )?;
    }
    Ok(())
}

fn write_registry_roots<W: io::Write>(
    roots: &[RegistryRoot],
    outcome: &str,
    output: &mut W,
) -> io::Result<()> {
    for row in roots {
        writeln!(
            output,
            "target=registry outcome={outcome} class={} reason={} loop={} root={} cause={}",
            if row.reason == RefusalReason::InvalidRoot {
                "map"
            } else {
                "destination"
            },
            if row.reason == RefusalReason::InvalidRoot {
                row.reason.as_str()
            } else {
                "root-unavailable"
            },
            row.loop_name,
            row.root.display(),
            row.reason
        )?;
    }
    Ok(())
}

fn write_target_report<W: io::Write>(
    target: &TargetReport,
    dry_run: bool,
    output: &mut W,
) -> io::Result<()> {
    write!(
        output,
        "target={} outcome={} touched={} replacements={} dry_run={}",
        target.index,
        target.outcome.as_str(),
        yes_no(target.touched),
        target.replacements,
        yes_no(dry_run),
    )?;
    if target.outcome == TargetOutcome::DomainMismatch {
        write!(output, " state={}", target.state.as_str())?;
    }
    if let Some(backup) = &target.backup {
        write!(
            output,
            " backup={} backup_replaced={} outgoing_sha256={} backup_sha256={}",
            backup.disposition.as_str(),
            yes_no(backup.replaced_existing),
            backup.outgoing_sha256,
            backup.backup_sha256,
        )?;
    }
    if let Some(before) = &target.before {
        write!(
            output,
            " before_identity={}:{} before_mtime={}.{:09}",
            before.device, before.inode, before.mtime_seconds, before.mtime_nanoseconds,
        )?;
    }
    if let Some(after) = &target.after {
        write!(
            output,
            " after_identity={}:{} after_mtime={}.{:09} mode={:04o}",
            after.device, after.inode, after.mtime_seconds, after.mtime_nanoseconds, after.mode,
        )?;
    }
    writeln!(output)
}

fn format_wall(wall: Duration) -> String {
    format!("{}.{:03}s", wall.as_secs(), wall.subsec_millis())
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
