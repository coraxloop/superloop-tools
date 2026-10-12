#![deny(clippy::indexing_slicing)]

//! Pure loop-registry parsing and caller-role resolution with one secure filesystem loader.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

/// The registry selected by the deployment instance.
pub const LOOP_REGISTRY_VARIABLE: &str = "PERMISSION_TRIAGE_LOOP_REGISTRY";
/// Decimal uid of the owner of a shared estate registry.
pub const ESTATE_UID_VARIABLE: &str = "PERMISSION_TRIAGE_ESTATE_UID";
const DIRECTORY_MODE: u32 = 0o700;
const ENTRY_MODE: u32 = 0o600;
const ESTATE_DIRECTORY_MODE: u32 = 0o755;
const ESTATE_ENTRY_MODE: u32 = 0o644;
const MAX_REGISTRY_ENTRIES: usize = 1_024;
const MAX_DIRECTORY_LISTING_BYTES: usize = 64 * 1_024;
const MAX_ENTRY_BYTES: u64 = 64 * 1_024;
const OPEN_DIRECTORY: i32 = 0x10_000;
pub(crate) const OPEN_NO_FOLLOW: i32 = 0x20_000;
const OPEN_PATH: i32 = 0x20_0000;
const LOOP_ERROR: i32 = 40;

/// One validated loop-registry entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    name: String,
    identifier: Option<String>,
    checkout: PathBuf,
    state_root: Option<PathBuf>,
    uid: Option<u32>,
    home: Option<PathBuf>,
    worker_uids: Option<WorkerBlock>,
    allocation_digest: Option<String>,
    allocation_copied_at: Option<String>,
    orchestrator_rubric: Option<PathBuf>,
}

impl RegistryEntry {
    /// Registered loop name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Registered main-session identifier.
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// Deployment state root, required before routing or assembly.
    #[must_use]
    pub fn state_root(&self) -> Option<&Path> {
        self.state_root.as_deref()
    }

    /// Registered subordinate uid of the loop's private home.
    ///
    /// Deployment metadata only: a uid a loop could assert by editing its own entry is not an
    /// identity, so no resolution rule reads this field.
    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        self.uid
    }

    /// Registered private home of the loop.
    ///
    /// Deployment metadata only, for the same reason as [`Self::uid`]: it records where a loop's
    /// material lives so a deployment check can test placement against it, and no resolution rule
    /// reads it.
    #[must_use]
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    /// Estate-held rubric for the loop's main session and in-session subagents.
    #[must_use]
    pub fn orchestrator_rubric(&self) -> Option<&Path> {
        self.orchestrator_rubric.as_deref()
    }

    /// Run directory owned by a worker uid beneath this loop's registered home.
    #[must_use]
    pub fn worker_run_root(&self, uid: u32) -> Option<PathBuf> {
        self.home()
            .map(|home| home.join("runs").join(uid.to_string()))
    }

    /// Worker UID block copied from the allocations ledger into the deployment snapshot.
    #[must_use]
    pub const fn worker_uids(&self) -> Option<WorkerBlock> {
        self.worker_uids
    }

    /// Digest of the exact allocation ledger copied into this deployment row.
    #[must_use]
    pub fn allocation_digest(&self) -> Option<&str> {
        self.allocation_digest.as_deref()
    }

    /// Time at which the allocation block was copied into this deployment row.
    #[must_use]
    pub fn allocation_copied_at(&self) -> Option<&str> {
        self.allocation_copied_at.as_deref()
    }

    /// Validate this entry's root without relying on another entry's domain.
    ///
    /// # Errors
    ///
    /// Rejects absent roots and unsafe directories.
    pub fn validated_state_root(&self) -> Result<File, RegistryError> {
        let root = self.state_root_path()?;
        open_state_root(root)
    }

    /// Validate this entry's root for a read-only review.
    ///
    /// # Errors
    ///
    /// Rejects absent roots and directories that are not private owner-readable roots.
    pub fn validated_state_root_for_review(&self) -> Result<File, RegistryError> {
        let root = self.state_root_path()?;
        open_state_root_for_review(root)
    }

    fn state_root_path(&self) -> Result<&Path, RegistryError> {
        let root = self
            .state_root()
            .ok_or(RegistryError::StateRoot("LOOP_STATE_ROOT is required"))?;
        for authorization in ["local/permissions/domain.md", "local/permissions/owner.md"] {
            if self.checkout().join(authorization).starts_with(root) {
                return Err(RegistryError::StateRoot(
                    "root contains an authorization source",
                ));
            }
        }
        Ok(root)
    }

    /// Registered loop checkout.
    #[must_use]
    pub fn checkout(&self) -> &Path {
        &self.checkout
    }
}

/// Inclusive uid block assigned to one loop's workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerBlock {
    base: u32,
    count: u32,
}

impl WorkerBlock {
    /// Lowest UID in the deployed block.
    #[must_use]
    pub const fn base(self) -> u32 {
        self.base
    }

    /// Number of UIDs in the deployed block.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }
    const fn top(self) -> u32 {
        self.base + self.count - 1
    }

    /// Whether this block contains a process uid.
    #[must_use]
    pub const fn contains(self, uid: u32) -> bool {
        uid >= self.base && uid <= self.top()
    }
}

/// Namespace-internal uid and gid capacity of the deployment account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubordinateMapping {
    uid_count: u32,
    gid_count: u32,
}

impl SubordinateMapping {
    /// Parse the deployment account and sum all of its matching subordinate ranges.
    ///
    /// # Errors
    ///
    /// Rejects a missing account, missing ranges, or malformed matching lines.
    pub fn parse(
        deployment_uid: u32,
        passwd: &[u8],
        uid_ranges: &[u8],
        gid_ranges: &[u8],
    ) -> Result<Self, RegistryError> {
        let passwd =
            std::str::from_utf8(passwd).map_err(|_error| RegistryError::SubordinateMapping {
                file: "/etc/passwd",
                detail: "invalid UTF-8",
            })?;
        let mut account = None;
        for line in passwd.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.get(2).and_then(|uid| decimal_uid(uid)) == Some(deployment_uid) {
                let name = fields.first().copied().unwrap_or_default();
                if fields.len() != 7 || name.is_empty() {
                    return Err(RegistryError::SubordinateMapping {
                        file: "/etc/passwd",
                        detail: "malformed deployment account line",
                    });
                }
                if account.replace(name).is_some() {
                    return Err(RegistryError::SubordinateMapping {
                        file: "/etc/passwd",
                        detail: "duplicate deployment uid",
                    });
                }
            }
        }
        let account = account.ok_or(RegistryError::SubordinateMapping {
            file: "/etc/passwd",
            detail: "deployment uid has no account",
        })?;
        Ok(Self {
            uid_count: subordinate_count("/etc/subuid", uid_ranges, account, deployment_uid)?,
            gid_count: subordinate_count("/etc/subgid", gid_ranges, account, deployment_uid)?,
        })
    }

    /// Read the host's deployment-account mapping files.
    ///
    /// # Errors
    ///
    /// Rejects unreadable files and invalid mapping data.
    pub fn read_system(deployment_uid: u32) -> Result<Self, RegistryError> {
        let read = |file| {
            fs::read(file).map_err(|source| RegistryError::SubordinateFileRead { file, source })
        };
        Self::parse(
            deployment_uid,
            &read("/etc/passwd")?,
            &read("/etc/subuid")?,
            &read("/etc/subgid")?,
        )
    }
}

fn subordinate_count(
    file: &'static str,
    bytes: &[u8],
    account: &str,
    deployment_uid: u32,
) -> Result<u32, RegistryError> {
    let text = std::str::from_utf8(bytes).map_err(|_error| RegistryError::SubordinateMapping {
        file,
        detail: "invalid UTF-8",
    })?;
    let mut total = 0_u32;
    let mut found = false;
    let numeric_principal = deployment_uid.to_string();
    for line in text.lines() {
        let Some(principal) = line.split(':').next() else {
            continue;
        };
        if principal != account && principal != numeric_principal {
            continue;
        }
        found = true;
        let mut fields = line.split(':');
        let parsed = fields.next().zip(fields.next()).zip(fields.next());
        let Some(((_principal, start), count)) = parsed else {
            return Err(RegistryError::SubordinateMapping {
                file,
                detail: "malformed matching line",
            });
        };
        let Some(count) = decimal_uid(count).filter(|count| *count > 0) else {
            return Err(RegistryError::SubordinateMapping {
                file,
                detail: "malformed matching line",
            });
        };
        if decimal_uid(start)
            .and_then(|start| start.checked_add(count - 1))
            .is_none()
            || fields.next().is_some()
        {
            return Err(RegistryError::SubordinateMapping {
                file,
                detail: "malformed matching line",
            });
        }
        total = total
            .checked_add(count)
            .ok_or(RegistryError::SubordinateMapping {
                file,
                detail: "matching counts overflow u32",
            })?;
    }
    if !found {
        return Err(RegistryError::SubordinateMapping {
            file,
            detail: "no matching range",
        });
    }
    Ok(total)
}

/// Valid entries parsed from one registry snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    entries: Vec<RegistryEntry>,
}

/// Access a deployment validation is performed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeploymentAccess {
    /// Routing that will append to the journal and therefore needs an owner-writable root.
    Write,
    /// Owner review that takes no lock and performs no write, so a read-only root is admissible.
    Review,
}

fn reject_duplicate_loop_uid(
    entry: &RegistryEntry,
    peer: &RegistryEntry,
) -> Result<(), RegistryError> {
    if entry.uid().is_some() && entry.uid() == peer.uid() {
        return Err(RegistryError::DeploymentEntry {
            entry: entry.name().to_owned(),
            detail: format!("LOOP_UID duplicates registered LOOP_UID of {}", peer.name()),
        });
    }
    Ok(())
}

impl Registry {
    /// Validated entries in stable order.
    #[must_use]
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Validate every deployment root and the separation of the complete snapshot.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, overlapping, or misplaced state roots.
    pub fn validate_deployment(&self) -> Result<(), RegistryError> {
        self.validate_deployment_for(DeploymentAccess::Write)
    }

    /// Validate every deployment root for a read-only review.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, overlapping, or misplaced state roots. A selected root may
    /// be owner-read-only because review takes no lock and performs no write.
    pub fn validate_deployment_for_review(&self) -> Result<(), RegistryError> {
        self.validate_deployment_for(DeploymentAccess::Review)
    }

    /// Validate a deployment as a supplied uid, for a caller with write access.
    ///
    /// # Errors
    ///
    /// Rejects unsafe roots or worker blocks that collide with another principal.
    pub fn validate_deployment_as(&self, deployment_uid: u32) -> Result<(), RegistryError> {
        self.validate_deployment_for_uid(DeploymentAccess::Write, deployment_uid)
    }

    /// Check all registered uids against both namespace-internal mapping counts.
    ///
    /// # Errors
    ///
    /// Rejects any loop uid or worker block outside either mapping count.
    pub fn validate_subordinate_mapping(
        &self,
        mapping: &SubordinateMapping,
    ) -> Result<(), RegistryError> {
        for entry in &self.entries {
            let check = |uid, field| {
                if uid > mapping.uid_count {
                    Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!("{field} exceeds /etc/subuid count"),
                    })
                } else if uid > mapping.gid_count {
                    Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!("{field} exceeds /etc/subgid count"),
                    })
                } else {
                    Ok(())
                }
            };
            if let Some(uid) = entry.uid() {
                check(uid, "LOOP_UID")?;
            }
            if let Some(block) = entry.worker_uids() {
                check(block.top(), "LOOP_WORKER_UIDS top")?;
            }
        }
        Ok(())
    }

    /// Validate a registry that is about to be deployed.
    ///
    /// A deployable registry names a main session for every entry. Resolution still accepts an
    /// entry without `LOOP_SID` before deployment validation, but rejects a rotated identifier.
    ///
    /// # Errors
    ///
    /// Rejects everything [`Self::validate_deployment`] rejects, including an entry without
    /// `LOOP_SID`.
    pub fn validate_deployment_registration(&self) -> Result<(), RegistryError> {
        self.validate_deployment()
    }

    fn validate_deployment_for(&self, access: DeploymentAccess) -> Result<(), RegistryError> {
        self.validate_deployment_for_uid(access, effective_uid()?)
    }

    fn validate_deployment_for_uid(
        &self,
        access: DeploymentAccess,
        deployment_uid: u32,
    ) -> Result<(), RegistryError> {
        self.validate_deployment_structure(Some(deployment_uid))?;
        for entry in &self.entries {
            // Opening the root under O_NOFOLLOW|O_DIRECTORY with its mode check is the validation;
            // the descriptor itself has no use here, so it is closed where it is produced.
            match access {
                DeploymentAccess::Write => entry.validated_state_root(),
                DeploymentAccess::Review => entry.validated_state_root_for_review(),
            }
            .map(drop)
            .map_err(|error| RegistryError::DeploymentEntry {
                entry: entry.name().to_owned(),
                detail: error.to_string(),
            })?;
        }
        Ok(())
    }

    fn validate_registered_session(entry: &RegistryEntry) -> Result<(), RegistryError> {
        if entry.identifier().is_none() {
            return Err(RegistryError::DeploymentEntry {
                entry: entry.name().to_owned(),
                detail: "LOOP_SID is required by a deployable registration".to_owned(),
            });
        }
        Ok(())
    }

    /// Validate the registry's structure without opening any registered state root.
    ///
    /// Supply the deployment uid when validating an assembler's deployment principal. A hook
    /// does not know that principal's uid, so it passes `None` and still checks every other
    /// structural invariant.
    ///
    /// # Errors
    ///
    /// Rejects entries without `LOOP_SID`, missing or overlapping roots, nested homes or launch
    /// directories, launch directories in homes, duplicate names, and colliding worker blocks.
    pub fn validate_deployment_structure(
        &self,
        deployment_uid: Option<u32>,
    ) -> Result<(), RegistryError> {
        if self.entries.is_empty() {
            return Err(RegistryError::StateRoot("registry has no deployable loops"));
        }
        for (index, entry) in self.entries.iter().enumerate() {
            Self::validate_registered_session(entry)?;
            for home_entry in &self.entries {
                if home_entry
                    .home()
                    .is_some_and(|home| entry.checkout().starts_with(home))
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!(
                            "LOOP_CWD is inside registered LOOP_HOME of {}",
                            home_entry.name()
                        ),
                    });
                }
            }
            for peer in self.entries.iter().take(index) {
                reject_duplicate_loop_uid(entry, peer)?;
                if entry.checkout().starts_with(peer.checkout())
                    || peer.checkout().starts_with(entry.checkout())
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!("LOOP_CWD overlaps registered LOOP_CWD of {}", peer.name()),
                    });
                }
                if let (Some(home), Some(peer_home)) = (entry.home(), peer.home())
                    && (home.starts_with(peer_home) || peer_home.starts_with(home))
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!(
                            "LOOP_HOME overlaps registered LOOP_HOME of {}",
                            peer.name()
                        ),
                    });
                }
            }
            if let Some(block) = entry.worker_uids() {
                if deployment_uid.is_some_and(|uid| block.contains(uid)) {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "LOOP_WORKER_UIDS contains deployment uid".to_owned(),
                    });
                }
                if self
                    .entries
                    .iter()
                    .any(|loop_entry| loop_entry.uid().is_some_and(|uid| block.contains(uid)))
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "LOOP_WORKER_UIDS contains a registered LOOP_UID".to_owned(),
                    });
                }
                if self
                    .entries
                    .iter()
                    .take(index)
                    .filter_map(RegistryEntry::worker_uids)
                    .any(|peer| block.base <= peer.top() && peer.base <= block.top())
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "LOOP_WORKER_UIDS overlaps another worker block".to_owned(),
                    });
                }
            }
            let root = entry
                .state_root()
                .ok_or_else(|| RegistryError::DeploymentEntry {
                    entry: entry.name().to_owned(),
                    detail: "loop state root: LOOP_STATE_ROOT is required".to_owned(),
                })?;
            for peer in self.entries.iter().take(index) {
                let peer_root =
                    peer.state_root()
                        .ok_or_else(|| RegistryError::DeploymentEntry {
                            entry: peer.name().to_owned(),
                            detail: "loop state root: LOOP_STATE_ROOT is required".to_owned(),
                        })?;
                if peer.name() == entry.name()
                    || root.starts_with(peer_root)
                    || peer_root.starts_with(root)
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "loop state root: duplicate name or overlapping state roots"
                            .to_owned(),
                    });
                }
            }
        }
        self.validate_root_layout(&[], None)
    }

    /// Reject roots placed in a registered home or around any authorization source, and
    /// authorization sources or the estate tree placed in a registered home.
    ///
    /// # Errors
    ///
    /// Names the entry whose root overlaps a home or contains a registered authorization source,
    /// or whose home contains an authorization source or the estate tree.
    pub fn validate_root_layout(
        &self,
        authorization_sources: &[&Path],
        registry_directory: Option<&Path>,
    ) -> Result<(), RegistryError> {
        for entry in &self.entries {
            let root = entry
                .state_root()
                .ok_or_else(|| RegistryError::DeploymentEntry {
                    entry: entry.name().to_owned(),
                    detail: "LOOP_STATE_ROOT is required".to_owned(),
                })?;
            for peer in &self.entries {
                if peer.home().is_some_and(|home| root.starts_with(home)) {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!(
                            "loop state root is inside registered LOOP_HOME of {}",
                            peer.name()
                        ),
                    });
                }
                for rubric in ["local/permissions/domain.md", "local/permissions/owner.md"] {
                    if peer.checkout().join(rubric).starts_with(root) {
                        return Err(RegistryError::DeploymentEntry {
                            entry: entry.name().to_owned(),
                            detail: format!(
                                "loop state root contains registered rubric of {}",
                                peer.name()
                            ),
                        });
                    }
                }
                if peer
                    .orchestrator_rubric()
                    .is_some_and(|rubric| rubric.starts_with(root))
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: format!(
                            "loop state root contains registered rubric of {}",
                            peer.name()
                        ),
                    });
                }
            }
            if authorization_sources
                .iter()
                .any(|source| source.starts_with(root))
            {
                return Err(RegistryError::DeploymentEntry {
                    entry: entry.name().to_owned(),
                    detail: "loop state root contains an authorization source".to_owned(),
                });
            }
            if let Some(home) = entry.home() {
                // This check names the estate tree directly; its registry source also triggers
                // the authorization-source rule, but that message hides the misplaced tree.
                if registry_directory
                    .filter(|directory| authorization_sources.contains(directory))
                    .and_then(Path::parent)
                    .is_some_and(|estate_tree| estate_tree.starts_with(home))
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "estate tree is inside registered LOOP_HOME".to_owned(),
                    });
                }
                if authorization_sources
                    .iter()
                    .any(|source| source.starts_with(home))
                    || self.entries.iter().any(|peer| {
                        peer.orchestrator_rubric()
                            .is_some_and(|rubric| rubric.starts_with(home))
                            || ["local/permissions/domain.md", "local/permissions/owner.md"]
                                .iter()
                                .any(|rubric| peer.checkout().join(rubric).starts_with(home))
                    })
                {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "authorization source is inside registered LOOP_HOME".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Require each registered orchestrator rubric to live below the owner rubric's directory.
    ///
    /// # Errors
    ///
    /// Names the entry whose rubric has no configured owner directory or lies outside it.
    pub fn validate_rubric_layout(&self, owner_rubric: Option<&Path>) -> Result<(), RegistryError> {
        for entry in &self.entries {
            if let Some(rubric) = entry.orchestrator_rubric() {
                let owner_directory = owner_rubric.and_then(Path::parent);
                if !owner_directory.is_some_and(|directory| {
                    directory != Path::new("/")
                        && rubric.starts_with(directory)
                        && rubric != directory
                }) {
                    return Err(RegistryError::DeploymentEntry {
                        entry: entry.name().to_owned(),
                        detail: "LOOP_ORCHESTRATOR_RUBRIC must be inside the configured owner rubric's directory".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Sorted complete deployment identity used for provenance.
    #[must_use]
    pub fn sorted_state_entries(&self) -> Vec<(String, Option<String>, String, Option<String>)> {
        self.entries
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    entry.identifier.clone(),
                    entry.checkout.to_string_lossy().into_owned(),
                    entry
                        .state_root
                        .as_ref()
                        .map(|root| root.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// Sorted triples used by assembly provenance.
    #[must_use]
    pub fn sorted_triples(&self) -> Vec<(String, Option<String>, String)> {
        self.entries
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    entry.identifier.clone(),
                    entry.checkout.to_string_lossy().into_owned(),
                )
            })
            .collect()
    }
}

/// Registry entry selected for a caller, plus corroborating session evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLoop {
    entry: RegistryEntry,
    stale_session: bool,
    worker: bool,
}

impl ResolvedLoop {
    /// Matched registry entry.
    #[must_use]
    pub const fn entry(&self) -> &RegistryEntry {
        &self.entry
    }

    /// Whether the checkout matched but `LOOP_SID` names a different session.
    #[must_use]
    pub const fn stale_session(&self) -> bool {
        self.stale_session
    }

    /// Whether the caller was selected by its registered worker uid block.
    #[must_use]
    pub const fn worker(&self) -> bool {
        self.worker
    }
}

/// Closed caller-role vocabulary and its matched loop, when known.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CallerRole {
    /// Main session of one registered loop.
    Orchestrator(ResolvedLoop),
    /// In-session subagent of one registered loop.
    OrchestratorSubagent(ResolvedLoop),
    /// No unique, consistent registry match.
    #[default]
    Unknown,
}

impl CallerRole {
    /// Closed role spelling carried to the classifier and journal.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Orchestrator(_) => "orchestrator",
            Self::OrchestratorSubagent(_) => "orchestrator-subagent",
            Self::Unknown => "unknown",
        }
    }

    /// Matched registry entry for either orchestrator role.
    #[must_use]
    pub const fn entry(&self) -> Option<&RegistryEntry> {
        match self {
            Self::Orchestrator(loop_match) | Self::OrchestratorSubagent(loop_match) => {
                Some(loop_match.entry())
            }
            Self::Unknown => None,
        }
    }

    /// Whether the matched loop's session id corroboration was stale.
    #[must_use]
    pub const fn stale_session(&self) -> bool {
        match self {
            Self::Orchestrator(loop_match) | Self::OrchestratorSubagent(loop_match) => {
                loop_match.stale_session()
            }
            Self::Unknown => false,
        }
    }

    /// Matched loop name for journal records.
    #[must_use]
    pub fn loop_name(&self) -> Option<&str> {
        self.entry().map(RegistryEntry::name)
    }

    /// Whether this is the registered loop's main orchestrator session.
    #[must_use]
    pub const fn is_orchestrator(&self) -> bool {
        matches!(self, Self::Orchestrator(_))
    }

    /// Exact closed role line carried in the classifier prompt.
    #[must_use]
    pub fn prompt_line(&self) -> String {
        self.entry().map_or_else(
            || "role=unknown".to_owned(),
            |entry| format!("role={} loop={}", self.as_str(), entry.name()),
        )
    }

    /// Domain-rubric path selected by the caller's resolved role.
    #[must_use]
    pub fn domain_rubric_path(&self) -> Option<PathBuf> {
        match self {
            Self::Orchestrator(loop_match) | Self::OrchestratorSubagent(loop_match) => {
                let entry = loop_match.entry();
                if loop_match.worker() {
                    entry
                        .home()
                        .map(|home| home.join("shared/permissions/domain.md"))
                } else {
                    Some(entry.orchestrator_rubric().map_or_else(
                        || entry.checkout().join("local/permissions/domain.md"),
                        Path::to_path_buf,
                    ))
                }
            }
            Self::Unknown => None,
        }
    }
}

/// Registry loading failure. The hook conservatively resolves these cases as unknown.
#[derive(Debug)]
pub enum RegistryError {
    /// The configured registry path was not valid Unicode.
    PathEncoding,
    /// The configured registry path was not absolute.
    PathNotAbsolute(PathBuf),
    /// A deployment root or its separation from other registered roots is invalid.
    StateRoot(&'static str),
    /// One named deployment entry has an invalid state root.
    DeploymentEntry {
        /// Stable loop name from the invalid registry entry.
        entry: String,
        /// Bounded validation detail.
        detail: String,
    },
    /// A deployment account mapping file could not be read.
    SubordinateFileRead {
        /// Mapping file path.
        file: &'static str,
        /// Read error.
        source: io::Error,
    },
    /// A deployment account mapping file lacks a usable matching record.
    SubordinateMapping {
        /// Mapping file path.
        file: &'static str,
        /// Validation failure.
        detail: &'static str,
    },
    /// Registry metadata could not be read.
    DirectoryMetadata(io::Error),
    /// The registry was not a private real directory.
    DirectoryShape,
    /// The registry directory had the wrong owner.
    DirectoryOwner {
        /// Owner reported by the opened directory.
        actual: u32,
        /// Effective uid derived from `/proc/self`.
        effective: u32,
    },
    /// A public worker root grants group or other write permission.
    PublicRootWritable(u32),
    /// An estate registry was selected without a declared owner uid.
    UndeclaredEstateUid(PathBuf),
    /// The instance's estate uid was not a decimal `u32`.
    InvalidEstateUid,
    /// A component of the estate registry path is writable by another principal.
    WritableComponent(PathBuf),
    /// An estate path component could not be opened without following a symlink.
    EstateComponentRead {
        /// Path of the component.
        path: PathBuf,
        /// Open error.
        source: io::Error,
    },
    /// The estate registry path contains a dot component.
    EstatePathShape(PathBuf),
    /// An estate path component has an owner outside the allowed principals.
    ForeignComponentOwner {
        /// Path of the component.
        path: PathBuf,
        /// Owner of the component.
        actual: u32,
        /// Declared estate uid.
        declared: u32,
        /// Deployment uid, when a path component established one.
        deployment: u32,
    },
    /// The estate directory or one of its entries has the wrong owner.
    EstateOwnerMismatch {
        /// Path of the directory or entry.
        path: PathBuf,
        /// Actual owner uid.
        actual: u32,
        /// Declared estate uid.
        declared: u32,
    },
    /// An estate entry is not a regular mode-0644 file.
    EstateEntryShape(PathBuf),
    /// The parsed registry did not contain exactly one entry for the declared estate uid.
    EstateEntryMismatch {
        /// Declared estate uid.
        declared: u32,
        /// Number of parsed entries carrying that uid.
        matches: usize,
    },
    /// The registry contents could not be read safely.
    DirectoryRead(io::Error),
    /// One registry entry could not be read safely.
    EntryRead(io::Error),
    /// A registry generation changed while its entries were being read.
    GenerationChanged,
    /// A listed registry row was incomplete while the generation was read.
    IncompleteGeneration,
    /// The bounded registry snapshot exceeded its entry or byte cap.
    TooLarge,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateRoot(reason) => write!(formatter, "loop state root: {reason}"),
            Self::DeploymentEntry { entry, detail } => {
                write!(formatter, "loop registry entry {entry}: {detail}")
            }
            Self::SubordinateFileRead { file, source } => {
                write!(
                    formatter,
                    "subordinate mapping file {file} could not be read: {source}"
                )
            }
            Self::SubordinateMapping { file, detail } => {
                write!(formatter, "subordinate mapping file {file}: {detail}")
            }
            Self::PathEncoding => write!(formatter, "loop registry path is not valid Unicode"),
            Self::PathNotAbsolute(path) => {
                write!(
                    formatter,
                    "loop registry path is not absolute: {}",
                    path.display()
                )
            }
            Self::DirectoryMetadata(error) => {
                write!(formatter, "loop registry metadata failed: {error}")
            }
            Self::DirectoryShape => write!(formatter, "loop registry is not a private directory"),
            Self::DirectoryOwner { actual, effective } => write!(
                formatter,
                "loop registry owner uid is {actual}, not process effective uid {effective}"
            ),
            Self::PublicRootWritable(mode) => write!(
                formatter,
                "public worker root mode {mode:04o} grants group or other write permission"
            ),
            Self::UndeclaredEstateUid(path) => write!(
                formatter,
                "loop registry is not a private directory: estate registry {} has no declared estate uid",
                path.display()
            ),
            Self::InvalidEstateUid => {
                write!(formatter, "{ESTATE_UID_VARIABLE} must be a decimal u32")
            }
            Self::WritableComponent(path) => write!(
                formatter,
                "estate registry path component {} is group- or world-writable",
                path.display()
            ),
            Self::EstateComponentRead { path, source } => write!(
                formatter,
                "estate registry path component {} could not be opened safely: {source}",
                path.display()
            ),
            Self::EstatePathShape(path) => write!(
                formatter,
                "estate registry path {} contains a dot component",
                path.display()
            ),
            Self::ForeignComponentOwner {
                path,
                actual,
                declared,
                deployment,
            } => write!(
                formatter,
                "estate registry path component {} has owner uid {actual}, outside root, estate uid {declared}, and deployment uid {deployment}",
                path.display()
            ),
            Self::EstateOwnerMismatch {
                path,
                actual,
                declared,
            } => write!(
                formatter,
                "estate registry {} has owner uid {actual}, not declared uid {declared}",
                path.display()
            ),
            Self::EstateEntryShape(path) => write!(
                formatter,
                "estate registry entry {} is not a mode-0644 regular file",
                path.display()
            ),
            Self::EstateEntryMismatch { declared, matches } => write!(
                formatter,
                "estate registry has {matches} parsed entries with LOOP_UID={declared}; expected exactly one"
            ),
            Self::DirectoryRead(error) => write!(formatter, "loop registry read failed: {error}"),
            Self::EntryRead(error) => write!(formatter, "loop registry entry read failed: {error}"),
            Self::GenerationChanged => {
                write!(formatter, "loop registry generation changed during read")
            }
            Self::IncompleteGeneration => {
                write!(
                    formatter,
                    "loop registry generation contains an incomplete row"
                )
            }
            Self::TooLarge => write!(formatter, "loop registry exceeds its bounded read cap"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DirectoryMetadata(error)
            | Self::DirectoryRead(error)
            | Self::EntryRead(error) => Some(error),
            Self::EstateComponentRead { source, .. } | Self::SubordinateFileRead { source, .. } => {
                Some(source)
            }
            Self::StateRoot(_)
            | Self::DeploymentEntry { .. }
            | Self::SubordinateMapping { .. }
            | Self::PathEncoding
            | Self::PathNotAbsolute(_)
            | Self::DirectoryShape
            | Self::GenerationChanged
            | Self::IncompleteGeneration
            | Self::DirectoryOwner { .. }
            | Self::PublicRootWritable(_)
            | Self::UndeclaredEstateUid(_)
            | Self::InvalidEstateUid
            | Self::WritableComponent(_)
            | Self::EstatePathShape(_)
            | Self::ForeignComponentOwner { .. }
            | Self::EstateOwnerMismatch { .. }
            | Self::EstateEntryShape(_)
            | Self::EstateEntryMismatch { .. }
            | Self::TooLarge => None,
        }
    }
}

/// Parse supplied directory-listing bytes and supplied entry bytes without filesystem access.
#[must_use]
pub fn parse_registry(listing: &[u8], entry_texts: &BTreeMap<String, Vec<u8>>) -> Registry {
    let mut entries = listing
        .split(|byte| *byte == b'\n')
        .filter(|name| !name.is_empty())
        .filter_map(|name| std::str::from_utf8(name).ok())
        .filter(|name| registry_filename(name))
        .filter_map(|name| entry_texts.get(name).and_then(|text| parse_entry(text)))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.identifier.cmp(&right.identifier))
            .then(left.checkout.cmp(&right.checkout))
    });
    Registry { entries }
}

/// Resolve one caller role from supplied registry and request values.
#[must_use]
pub fn resolve_role(
    registry: Option<&Registry>,
    effective_uid: u32,
    session_id: &str,
    cwd: &str,
    transcript_path: Option<&str>,
    agent_id_truthy: bool,
) -> CallerRole {
    let Some(registry) = registry else {
        return CallerRole::Unknown;
    };
    let mut worker = registry.entries.iter().filter(|entry| {
        entry
            .worker_uids()
            .is_some_and(|block| block.contains(effective_uid))
    });
    if let Some(entry) = worker.next() {
        if worker.next().is_some() {
            return CallerRole::Unknown;
        }
        return CallerRole::OrchestratorSubagent(ResolvedLoop {
            entry: entry.clone(),
            stale_session: false,
            worker: true,
        });
    }
    let Some(cwd) = normalized_request_cwd(cwd) else {
        return CallerRole::Unknown;
    };
    let Some(candidate_index) = checkout_candidate(registry, &cwd) else {
        return CallerRole::Unknown;
    };
    if registry
        .entries
        .iter()
        .enumerate()
        .any(|(index, entry)| index != candidate_index && entry.identifier() == Some(session_id))
    {
        return CallerRole::Unknown;
    }
    let Some(candidate) = registry.entries.get(candidate_index) else {
        return CallerRole::Unknown;
    };
    if candidate
        .identifier()
        .is_some_and(|identifier| identifier != session_id)
    {
        return CallerRole::Unknown;
    }
    let loop_match = ResolvedLoop {
        entry: candidate.clone(),
        stale_session: false,
        worker: false,
    };
    if agent_id_truthy || transcript_path.is_some_and(|path| path.contains("/subagents/")) {
        CallerRole::OrchestratorSubagent(loop_match)
    } else {
        CallerRole::Orchestrator(loop_match)
    }
}

fn normalized_request_cwd(cwd: &str) -> Option<PathBuf> {
    let path = Path::new(cwd);
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    normalized.is_absolute().then_some(normalized)
}

fn checkout_candidate(registry: &Registry, cwd: &Path) -> Option<usize> {
    let mut candidate: Option<(usize, &RegistryEntry)> = None;
    for (index, entry) in registry
        .entries
        .iter()
        .enumerate()
        .filter(|(_index, entry)| cwd.starts_with(entry.checkout()))
    {
        let Some((_, current)) = candidate else {
            candidate = Some((index, entry));
            continue;
        };
        let current_checkout = current.checkout();
        let checkout = entry.checkout();
        if checkout == current_checkout {
            return None;
        }
        if checkout.starts_with(current_checkout) {
            candidate = Some((index, entry));
        } else if !current_checkout.starts_with(checkout) {
            return None;
        }
    }
    candidate.map(|(index, _entry)| index)
}

/// Load the configured registry securely, returning `None` without a filesystem read when unset.
///
/// # Errors
///
/// Returns [`RegistryError`] when a configured registry cannot be read safely.
pub fn load_registry(value: Option<OsString>) -> Result<Option<Registry>, RegistryError> {
    load_registry_with_estate_uid(value, None)
}

/// Load a private registry, or an estate registry when its owner uid is declared by the instance.
///
/// # Errors
///
/// Returns [`RegistryError`] for an invalid uid value or a registry that cannot be read safely.
pub fn load_registry_with_estate_uid(
    value: Option<OsString>,
    estate_uid_value: Option<OsString>,
) -> Result<Option<Registry>, RegistryError> {
    let declared_uid = estate_uid_value
        .map(|value| {
            value
                .into_string()
                .ok()
                .and_then(|value| decimal_uid(&value))
                .ok_or(RegistryError::InvalidEstateUid)
        })
        .transpose()?;
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = value
        .into_string()
        .map(PathBuf::from)
        .map_err(|_value| RegistryError::PathEncoding)?;
    load_registry_from_path_with_uids(&path, effective_uid()?, declared_uid).map(Some)
}

/// Read the kernel-supplied uid of the reading process from `/proc/self`.
///
/// # Errors
///
/// Returns a metadata error if the process identity cannot be read.
pub fn effective_uid() -> Result<u32, RegistryError> {
    fs::metadata("/proc/self")
        .map_err(RegistryError::DirectoryMetadata)
        .map(|metadata| metadata.uid())
}

pub(crate) fn load_registry_from_path_with_uids(
    path: &Path,
    effective_uid: u32,
    declared_uid: Option<u32>,
) -> Result<Registry, RegistryError> {
    load_registry_with_listing_hook(path, effective_uid, declared_uid, &mut |_| {})
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    BeforeListing,
    AfterListing,
}

fn load_registry_with_listing_hook(
    path: &Path,
    effective_uid: u32,
    declared_uid: Option<u32>,
    on_phase: &mut impl FnMut(ReadPhase),
) -> Result<Registry, RegistryError> {
    for _attempt in 0..3 {
        match load_registry_once(path, effective_uid, declared_uid, on_phase) {
            Ok(registry) => return Ok(registry),
            Err(
                RegistryError::DirectoryRead(_)
                | RegistryError::EntryRead(_)
                | RegistryError::GenerationChanged
                | RegistryError::IncompleteGeneration,
            ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(RegistryError::GenerationChanged)
}

fn load_registry_once(
    path: &Path,
    effective_uid: u32,
    declared_uid: Option<u32>,
    on_phase: &mut impl FnMut(ReadPhase),
) -> Result<Registry, RegistryError> {
    if !path.is_absolute() {
        return Err(RegistryError::PathNotAbsolute(path.to_path_buf()));
    }
    let initial = open_registry_directory(path)?;
    let initial_metadata = initial
        .metadata()
        .map_err(RegistryError::DirectoryMetadata)?;
    let mode = initial_metadata.permissions().mode() & 0o7777;
    let (directory, entry_mode, entry_owner, estate) = match mode {
        DIRECTORY_MODE => {
            verify_directory(&initial, effective_uid)?;
            (initial, ENTRY_MODE, effective_uid, false)
        }
        ESTATE_DIRECTORY_MODE => {
            let declared = declared_uid
                .ok_or_else(|| RegistryError::UndeclaredEstateUid(path.to_path_buf()))?;
            let directory = open_estate_registry_directory(path, declared)?;
            (directory, ESTATE_ENTRY_MODE, declared, true)
        }
        _ if declared_uid.is_some() && mode & 0o022 != 0 => {
            return Err(RegistryError::WritableComponent(path.to_path_buf()));
        }
        _ => return Err(RegistryError::DirectoryShape),
    };
    let anchored = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
    on_phase(ReadPhase::BeforeListing);
    let mut names = fs::read_dir(&anchored)
        .map_err(RegistryError::DirectoryRead)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(RegistryError::DirectoryRead)?;
    if names.len() > MAX_REGISTRY_ENTRIES {
        return Err(RegistryError::TooLarge);
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    on_phase(ReadPhase::AfterListing);
    let mut listing = Vec::new();
    let mut texts = BTreeMap::new();
    for name in names {
        if listing.len().saturating_add(name.as_bytes().len() + 1) > MAX_DIRECTORY_LISTING_BYTES {
            return Err(RegistryError::TooLarge);
        }
        listing.extend_from_slice(name.as_bytes());
        listing.push(b'\n');
        let Some(name_text) = name.to_str().filter(|name| registry_filename(name)) else {
            continue;
        };
        let bytes = read_registry_entry(
            &anchored.join(&name),
            path.join(&name),
            entry_mode,
            entry_owner,
            estate,
        )?;
        if parse_entry(&bytes).is_none() {
            return Err(RegistryError::IncompleteGeneration);
        }
        texts.insert(name_text.to_owned(), bytes);
    }
    let registry = parse_registry(&listing, &texts);
    for (index, entry) in registry.entries().iter().enumerate() {
        if entry.uid().is_some()
            && registry
                .entries()
                .iter()
                .take(index)
                .any(|peer| peer.uid() == entry.uid())
        {
            return Err(RegistryError::IncompleteGeneration);
        }
    }
    let current = fs::metadata(path).map_err(|_error| RegistryError::GenerationChanged)?;
    if current.dev() != initial_metadata.dev() || current.ino() != initial_metadata.ino() {
        return Err(RegistryError::GenerationChanged);
    }
    if estate {
        let declared = entry_owner;
        let matches = registry
            .entries()
            .iter()
            .filter(|entry| entry.uid() == Some(declared))
            .count();
        if matches != 1 {
            return Err(RegistryError::EstateEntryMismatch { declared, matches });
        }
    }
    Ok(registry)
}

fn open_estate_registry_directory(path: &Path, declared: u32) -> Result<File, RegistryError> {
    if !absolute_normal_path(path) {
        return Err(RegistryError::EstatePathShape(path.to_path_buf()));
    }
    let mut directory = open_registry_directory(Path::new("/"))?;
    let mut component_path = PathBuf::from("/");
    let mut deployment = None;
    verify_estate_component(&directory, &component_path, declared, &mut deployment)?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            let anchored = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
            component_path.push(name);
            directory = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_NO_FOLLOW | OPEN_DIRECTORY)
                .open(anchored.join(name))
                .map_err(|source| RegistryError::EstateComponentRead {
                    path: component_path.clone(),
                    source,
                })?;
            verify_estate_component(&directory, &component_path, declared, &mut deployment)?;
        }
    }
    let metadata = directory
        .metadata()
        .map_err(RegistryError::DirectoryMetadata)?;
    if metadata.permissions().mode() & 0o7777 != ESTATE_DIRECTORY_MODE {
        return Err(RegistryError::DirectoryShape);
    }
    if metadata.uid() != declared {
        return Err(RegistryError::EstateOwnerMismatch {
            path: path.to_path_buf(),
            actual: metadata.uid(),
            declared,
        });
    }
    Ok(directory)
}

fn verify_estate_component(
    directory: &File,
    path: &Path,
    declared: u32,
    deployment: &mut Option<u32>,
) -> Result<(), RegistryError> {
    let metadata = directory
        .metadata()
        .map_err(RegistryError::DirectoryMetadata)?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(RegistryError::WritableComponent(path.to_path_buf()));
    }
    let actual = metadata.uid();
    if !accept_component_owner(actual, declared, deployment) {
        return Err(RegistryError::ForeignComponentOwner {
            path: path.to_path_buf(),
            actual,
            declared,
            deployment: deployment.expect("a foreign component follows a deployment owner"),
        });
    }
    Ok(())
}

const fn accept_component_owner(actual: u32, declared: u32, deployment: &mut Option<u32>) -> bool {
    if actual == 0 || actual == declared {
        return true;
    }
    if let Some(uid) = deployment {
        *uid == actual
    } else {
        *deployment = Some(actual);
        true
    }
}

#[cfg(test)]
mod estate_owner_tests {
    use super::accept_component_owner;

    /// ´test:unit:component-owner-accepts-root-declared-and-one-deployment-uid´
    #[test]
    fn component_owner_accepts_root_declared_and_one_deployment_uid() {
        let mut deployment = None;
        assert!(accept_component_owner(0, 41004, &mut deployment));
        assert!(accept_component_owner(41004, 41004, &mut deployment));
        assert_eq!(deployment, None);
        assert!(accept_component_owner(1000, 41004, &mut deployment));
        assert_eq!(deployment, Some(1000));
        assert!(accept_component_owner(1000, 41004, &mut deployment));
        assert!(!accept_component_owner(1001, 41004, &mut deployment));
        assert_eq!(deployment, Some(1000));
    }
}

fn registry_filename(name: &str) -> bool {
    name.strip_suffix(".env").is_some_and(|stem| {
        !stem.is_empty()
            && stem.len() <= 128
            && stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    })
}

fn parse_entry(bytes: &[u8]) -> Option<RegistryEntry> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut name = None;
    let mut identifier = None;
    let mut checkout = None;
    let mut state_root = None;
    let mut uid = None;
    let mut home = None;
    let mut worker_uids = None;
    let mut allocation_digest = None;
    let mut allocation_copied_at = None;
    let mut orchestrator_rubric = None;
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.bytes().any(|byte| byte == b'\r') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        if value.is_empty() {
            return None;
        }
        match key {
            "LOOP_NAME" if name.is_none() && registry_name(value) => name = Some(value.to_owned()),
            "LOOP_SID" if identifier.is_none() && registry_value(value) => {
                identifier = Some(value.to_owned());
            }
            "LOOP_CWD" if checkout.is_none() => {
                let path = PathBuf::from(value);
                if !absolute_normal_path(&path) {
                    return None;
                }
                checkout = Some(path);
            }
            "LOOP_STATE_ROOT" if state_root.is_none() => {
                state_root = Some(PathBuf::from(value));
            }
            "LOOP_UID" if uid.is_none() => {
                uid = Some(decimal_uid(value)?);
            }
            "LOOP_WORKER_UIDS" if worker_uids.is_none() => {
                let (base, count) = value.split_once(':')?;
                let base = decimal_uid(base).filter(|base| *base >= 1000)?;
                let count = decimal_uid(count).filter(|count| *count >= 1)?;
                if base.checked_add(count - 1)? > 65535 {
                    return None;
                }
                worker_uids = Some(WorkerBlock { base, count });
            }
            "LOOP_ALLOCATIONS_SHA256"
                if allocation_digest.is_none()
                    && value.len() == 64
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
            {
                allocation_digest = Some(value.to_owned());
            }
            "LOOP_ALLOCATIONS_COPIED_AT"
                if allocation_copied_at.is_none() && crate::evidence::valid_recorded_at(value) =>
            {
                allocation_copied_at = Some(value.to_owned());
            }
            "LOOP_HOME" if home.is_none() => {
                let path = PathBuf::from(value);
                if !absolute_normal_path(&path) {
                    return None;
                }
                home = Some(path);
            }
            "LOOP_ORCHESTRATOR_RUBRIC" if orchestrator_rubric.is_none() => {
                let path = PathBuf::from(value);
                if !absolute_normal_path(&path) {
                    return None;
                }
                orchestrator_rubric = Some(path);
            }
            _ => return None,
        }
    }
    if allocation_digest.is_some() != allocation_copied_at.is_some() {
        return None;
    }
    if worker_uids.is_some() && allocation_digest.is_none() {
        return None;
    }
    Some(RegistryEntry {
        name: name?,
        identifier,
        checkout: checkout?,
        state_root,
        uid,
        home,
        worker_uids,
        allocation_digest,
        allocation_copied_at,
        orchestrator_rubric,
    })
}

/// A loop name is additionally one path-safe component.
///
/// `registry_value` already excludes `/`, but it admits `.`, so a name of `.` or `..` parses under
/// it alone. A deployment derives per-loop paths from the registered name, and a dot component in
/// an authorization source's name would traverse out of the tree that names it, so the name is
/// narrowed here rather than at each site that joins it to a path.
fn registry_name(value: &str) -> bool {
    registry_value(value) && !matches!(value, "." | "..")
}

/// One decimal `u32` spelling, so a uid reads the same to the parser and to a human reviewer.
///
/// Signs, radix prefixes, and surrounding space are rejected rather than normalized, because the
/// value is compared against filesystem ownership that has exactly one spelling.
fn decimal_uid(value: &str) -> Option<u32> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn registry_value(value: &str) -> bool {
    value.len() <= 1_024
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .as_os_str()
            .as_bytes()
            .split(|byte| *byte == b'/')
            .all(|component| component != b"." && component != b"..")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Open an existing private state root without following any path component's symlink.
///
/// # Errors
///
/// Rejects non-absolute or dotted paths, missing directories, symlinks, and unsafe ownership/mode.
pub(crate) fn open_state_root(path: &Path) -> Result<File, RegistryError> {
    open_state_root_with_modes(path, &[0o700])
}

pub(crate) fn open_state_root_for_review(path: &Path) -> Result<File, RegistryError> {
    open_state_root_with_modes(path, &[0o500, 0o700])
}

fn open_state_root_with_modes(path: &Path, allowed_modes: &[u32]) -> Result<File, RegistryError> {
    let directory = open_root_directory(path, false)?;
    let effective_uid = effective_uid()?;
    verify_directory_mode(&directory, effective_uid, allowed_modes)?;
    Ok(directory)
}

/// Open an existing public run root without following any path component's symlink.
///
/// # Errors
///
/// Rejects non-absolute or dotted paths, missing directories, symlinks, foreign ownership, and
/// group or other write permission.
pub(crate) fn open_public_root(path: &Path, effective_uid: u32) -> Result<File, RegistryError> {
    let directory = open_root_directory(path, true)?;
    let metadata = directory
        .metadata()
        .map_err(RegistryError::DirectoryMetadata)?;
    if metadata.uid() != effective_uid {
        return Err(RegistryError::DirectoryOwner {
            actual: metadata.uid(),
            effective: effective_uid,
        });
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(RegistryError::PublicRootWritable(mode));
    }
    Ok(directory)
}

/// Open a directory with the same symlink-free component walk used for registered roots.
pub(crate) fn open_directory_no_follow(path: &Path) -> Result<File, RegistryError> {
    open_root_directory(path, false)
}

fn open_root_directory(path: &Path, traversal_only: bool) -> Result<File, RegistryError> {
    if !absolute_normal_path(path) {
        return Err(RegistryError::StateRoot(
            "root must be absolute without dot components",
        ));
    }
    let mut directory = open_registry_directory(Path::new("/"))?;
    for component in path.components() {
        if let Component::Normal(name) = component {
            let anchored = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
            directory = open_state_root_component(&anchored.join(name), traversal_only)?;
        }
    }
    Ok(directory)
}

fn open_state_root_component(path: &Path, traversal_only: bool) -> Result<File, RegistryError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW | OPEN_DIRECTORY | if traversal_only { OPEN_PATH } else { 0 })
        .open(path)
        .map_err(|error| {
            // A symlinked component fails `O_NOFOLLOW | O_DIRECTORY` with ENOTDIR, the same errno a
            // plain file yields, so the open alone cannot separate the two refusals; only an lstat
            // of the component that was just refused can. The refusal itself is unchanged either
            // way, but a reader of the reason learns which root shape was rejected.
            if error.raw_os_error() == Some(LOOP_ERROR)
                || fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink())
            {
                RegistryError::StateRoot("root contains a symlink")
            } else {
                RegistryError::DirectoryMetadata(error)
            }
        })
}

fn open_registry_directory(path: &Path) -> Result<File, RegistryError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW | OPEN_DIRECTORY)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(LOOP_ERROR) {
                RegistryError::DirectoryShape
            } else {
                RegistryError::DirectoryMetadata(error)
            }
        })
}

fn verify_directory(directory: &File, effective_uid: u32) -> Result<(), RegistryError> {
    verify_directory_mode(directory, effective_uid, &[DIRECTORY_MODE])
}

fn verify_directory_mode(
    directory: &File,
    effective_uid: u32,
    allowed_modes: &[u32],
) -> Result<(), RegistryError> {
    let metadata = directory
        .metadata()
        .map_err(RegistryError::DirectoryMetadata)?;
    if !metadata.is_dir() || !allowed_modes.contains(&(metadata.permissions().mode() & 0o7777)) {
        return Err(RegistryError::DirectoryShape);
    }
    if metadata.uid() != effective_uid {
        return Err(RegistryError::DirectoryOwner {
            actual: metadata.uid(),
            effective: effective_uid,
        });
    }
    Ok(())
}

pub(crate) fn read_registry_entry(
    path: &Path,
    display_path: PathBuf,
    expected_mode: u32,
    expected_uid: u32,
    estate: bool,
) -> Result<Vec<u8>, RegistryError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NO_FOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(LOOP_ERROR) {
                if estate {
                    RegistryError::EstateEntryShape(display_path.clone())
                } else {
                    RegistryError::DirectoryShape
                }
            } else {
                RegistryError::EntryRead(error)
            }
        })?;
    let metadata = file.metadata().map_err(RegistryError::EntryRead)?;
    if estate && metadata.uid() != expected_uid {
        return Err(RegistryError::EstateOwnerMismatch {
            path: display_path,
            actual: metadata.uid(),
            declared: expected_uid,
        });
    }
    if estate && metadata.permissions().mode() & 0o022 != 0 {
        return Err(RegistryError::WritableComponent(display_path));
    }
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || metadata.uid() != expected_uid
    {
        return Err(if estate {
            RegistryError::EstateEntryShape(display_path)
        } else {
            RegistryError::DirectoryShape
        });
    }
    if metadata.len() > MAX_ENTRY_BYTES {
        return Err(RegistryError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_ENTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(RegistryError::EntryRead)?;
    if bytes.len() as u64 > MAX_ENTRY_BYTES {
        return Err(RegistryError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{RenameFlags, renameat2};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "permission-triage-role-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("unique role fixture is created");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("role fixture is private");
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _permissions = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    fn source(entries: &[(&str, &str)]) -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
        let mut listing = Vec::new();
        let mut texts = BTreeMap::new();
        for (name, text) in entries {
            listing.extend_from_slice(name.as_bytes());
            listing.push(b'\n');
            texts.insert((*name).to_owned(), text.as_bytes().to_vec());
        }
        (listing, texts)
    }

    fn two_loops() -> Registry {
        let (listing, texts) = source(&[
            (
                "orchestration.env",
                "LOOP_NAME=orchestration\nLOOP_SID=session-one\nLOOP_CWD=/workspace/orchestration\n",
            ),
            (
                "sibling.env",
                "LOOP_NAME=sibling\nLOOP_SID=session-two\nLOOP_CWD=/workspace/sibling\n",
            ),
        ]);
        parse_registry(&listing, &texts)
    }

    fn two_loops_with_metadata() -> Registry {
        let (listing, texts) = source(&[
            (
                "orchestration.env",
                "LOOP_NAME=orchestration\nLOOP_SID=session-one\nLOOP_CWD=/workspace/orchestration\nLOOP_UID=41001\nLOOP_HOME=/loops/orchestration\n",
            ),
            (
                "sibling.env",
                "LOOP_NAME=sibling\nLOOP_SID=session-two\nLOOP_CWD=/workspace/sibling\nLOOP_UID=41002\nLOOP_HOME=/loops/sibling\n",
            ),
        ]);
        parse_registry(&listing, &texts)
    }

    /// ´test:unit:registry-parser-accepts-one-closed-complete-entry´
    #[test]
    fn registry_parser_accepts_one_closed_complete_entry() {
        let registry = two_loops();
        assert_eq!(
            registry.entries().len(),
            2,
            "a complete closed registry entry must be retained"
        );
        assert_eq!(
            registry
                .entries()
                .first()
                .expect("first parsed loop")
                .name(),
            "orchestration"
        );
    }

    /// ´test:unit:deployed-worker-block-requires-a-bounded-annotated-snapshot´
    #[test]
    fn deployed_worker_block_requires_a_bounded_annotated_snapshot() {
        let prefix = "LOOP_NAME=alpha\nLOOP_CWD=/workspace/alpha\n";
        let snapshot = format!(
            "LOOP_ALLOCATIONS_SHA256={}\nLOOP_ALLOCATIONS_COPIED_AT=2026-09-30T00:00:00.000000000Z\n",
            "a".repeat(64)
        );
        for suffix in [
            "LOOP_WORKER_UIDS=3000:64\n".to_owned(),
            format!("LOOP_WORKER_UIDS=999:1\n{snapshot}"),
            format!("LOOP_WORKER_UIDS=65535:2\n{snapshot}"),
            format!(
                "LOOP_WORKER_UIDS=3000:64\nLOOP_ALLOCATIONS_SHA256={}\n",
                "a".repeat(64)
            ),
            format!(
                "LOOP_WORKER_UIDS=3000:64\nLOOP_ALLOCATIONS_SHA256={}\nLOOP_ALLOCATIONS_COPIED_AT=invalid\n",
                "a".repeat(64)
            ),
        ] {
            let text = format!("{prefix}{suffix}");
            let (listing, texts) = source(&[("alpha.env", &text)]);
            assert_eq!(parse_registry(&listing, &texts).entries(), []);
        }
        let valid = format!("{prefix}LOOP_WORKER_UIDS=3000:64\n{snapshot}");
        let (listing, texts) = source(&[("alpha.env", &valid)]);
        assert_eq!(parse_registry(&listing, &texts).entries().len(), 1);
    }

    /// ´test:unit:deployment-refuses-duplicate-loop-uids´
    #[test]
    fn deployment_refuses_duplicate_loop_uids() {
        let (listing, texts) = source(&[
            (
                "alpha.env",
                "LOOP_NAME=alpha\nLOOP_SID=alpha-sid\nLOOP_CWD=/workspace/alpha\nLOOP_STATE_ROOT=/state/alpha\nLOOP_UID=41001\n",
            ),
            (
                "peer.env",
                "LOOP_NAME=peer\nLOOP_SID=peer-sid\nLOOP_CWD=/workspace/peer\nLOOP_STATE_ROOT=/state/peer\nLOOP_UID=41001\n",
            ),
        ]);
        let registry = parse_registry(&listing, &texts);
        assert!(
            registry
                .validate_deployment_structure(None)
                .expect_err("duplicate loop uid")
                .to_string()
                .contains("LOOP_UID duplicates registered LOOP_UID")
        );
    }

    /// ´test:unit:registry-parser-ignores-each-invalid-entry-shape´
    #[test]
    fn registry_parser_ignores_each_invalid_entry_shape() {
        let invalid = [
            "LOOP_NAME=relative\nLOOP_SID=relative-sid\nLOOP_CWD=workspace/relative\n",
            "LOOP_NAME=dotted\nLOOP_SID=dotted-sid\nLOOP_CWD=/workspace/../dotted\n",
            "LOOP_NAME=unknown\nLOOP_SID=unknown-sid\nLOOP_CWD=/workspace/unknown\nEXTRA=value\n",
        ];
        for text in invalid {
            let (listing, texts) = source(&[("invalid.env", text)]);
            assert_eq!(parse_registry(&listing, &texts).entries(), []);
        }
    }

    /// ´test:unit:registry-parser-accepts-an-entry-without-a-session-id´
    #[test]
    fn registry_parser_accepts_an_entry_without_a_session_id() {
        let (listing, texts) = source(&[(
            "missing-sid.env",
            "LOOP_NAME=missing-sid\nLOOP_CWD=/workspace/missing\n",
        )]);
        let registry = parse_registry(&listing, &texts);
        assert_eq!(registry.entries().len(), 1);
        let entry = registry.entries().first().expect("missing-sid entry");
        assert_eq!(entry.name(), "missing-sid");
        assert_eq!(entry.identifier(), None);
        assert_eq!(entry.checkout(), Path::new("/workspace/missing"));
    }

    /// ´test:unit:registry-parser-accepts-the-deployment-metadata-fields´
    #[test]
    fn registry_parser_accepts_the_deployment_metadata_fields() {
        let registry = two_loops_with_metadata();
        let plain = two_loops();
        assert_eq!(registry.entries().len(), plain.entries().len());
        let entry = registry.entries().first().expect("first parsed loop");
        assert_eq!(entry.uid(), Some(41001));
        assert_eq!(entry.home(), Some(Path::new("/loops/orchestration")));
        for (carrying, bare) in registry.entries().iter().zip(plain.entries()) {
            assert_eq!(carrying.name(), bare.name());
            assert_eq!(carrying.identifier(), bare.identifier());
            assert_eq!(carrying.checkout(), bare.checkout());
            assert_eq!(carrying.state_root(), bare.state_root());
        }

        let carrying = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-one",
            "/workspace/orchestration",
            None,
            false,
        );
        let bare = resolve_role(
            Some(&plain),
            4_000_000_000,
            "session-one",
            "/workspace/orchestration",
            None,
            false,
        );
        assert_eq!(carrying.as_str(), bare.as_str());
        assert_eq!(carrying.loop_name(), bare.loop_name());
        assert_eq!(carrying.stale_session(), bare.stale_session());
        assert_eq!(carrying.domain_rubric_path(), bare.domain_rubric_path());
    }

    /// ´test:unit:registry-parser-rejects-invalid-or-repeated-deployment-metadata´
    #[test]
    fn registry_parser_rejects_invalid_or_repeated_deployment_metadata() {
        let base = "LOOP_NAME=moved\nLOOP_SID=moved-sid\nLOOP_CWD=/workspace/moved\n";
        let invalid = [
            "LOOP_UID=two-thousand-one\n",
            "LOOP_UID=+41001\n",
            "LOOP_UID=4294967296\n",
            "LOOP_UID=41001\nLOOP_UID=41002\n",
            "LOOP_HOME=loops/moved\n",
            "LOOP_HOME=/loops/../moved\n",
            "LOOP_HOME=/loops/moved\nLOOP_HOME=/loops/other\n",
            "LOOP_HOMEDIR=/loops/moved\n",
        ];
        for tail in invalid {
            let text = format!("{base}{tail}");
            let (listing, texts) = source(&[("moved.env", text.as_str())]);
            assert_eq!(
                parse_registry(&listing, &texts).entries(),
                [],
                "the entry must be dropped whole for {tail:?}"
            );
        }
        let (listing, texts) = source(&[("moved.env", base)]);
        assert_eq!(
            parse_registry(&listing, &texts).entries().len(),
            1,
            "the same entry without deployment metadata must still parse"
        );
    }

    /// ´test:unit:registry-parser-requires-a-loop-name-of-one-path-component´
    #[test]
    fn registry_parser_requires_a_loop_name_of_one_path_component() {
        for name in [".", "..", "a/b", ""] {
            let text = format!("LOOP_NAME={name}\nLOOP_SID=named-sid\nLOOP_CWD=/workspace/named\n");
            let (listing, texts) = source(&[("named.env", text.as_str())]);
            assert_eq!(
                parse_registry(&listing, &texts).entries(),
                [],
                "a loop name that is not one path component must drop its entry: {name:?}"
            );
        }
        let (listing, texts) = source(&[(
            "named.env",
            "LOOP_NAME=named\nLOOP_SID=named-sid\nLOOP_CWD=/workspace/named\n",
        )]);
        let registry = parse_registry(&listing, &texts);
        assert_eq!(
            registry.entries().first().expect("named entry").name(),
            "named"
        );
    }

    /// ´test:unit:resolver-rejects-rotated-session-and-accepts-matching-session´
    #[test]
    fn resolver_rejects_rotated_session_and_accepts_matching_session() {
        let registry = two_loops();
        let rotated = resolve_role(
            Some(&registry),
            4_000_000_000,
            "fresh-session",
            "/workspace/orchestration",
            None,
            false,
        );
        assert!(matches!(rotated, CallerRole::Unknown));
        assert_eq!(rotated.loop_name(), None);
        assert!(!rotated.stale_session());

        let corroborated = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-one",
            "/workspace/orchestration",
            None,
            false,
        );
        assert!(matches!(corroborated, CallerRole::Orchestrator(_)));
        assert!(!corroborated.stale_session());
    }

    /// ´test:unit:resolver-covers-subagent-signals-after-checkout-match´
    #[test]
    fn resolver_covers_subagent_signals_after_checkout_match() {
        let registry = two_loops();
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/orchestration",
                Some("/run/subagents/agent.jsonl"),
                false
            ),
            CallerRole::OrchestratorSubagent(_)
        ));
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/orchestration",
                None,
                true
            ),
            CallerRole::OrchestratorSubagent(_)
        ));
    }

    /// ´test:unit:resolver-prefers-a-strictly-nested-checkout´
    #[test]
    fn resolver_prefers_a_strictly_nested_checkout() {
        let (listing, texts) = source(&[
            (
                "parent.env",
                "LOOP_NAME=parent\nLOOP_SID=session-parent\nLOOP_CWD=/workspace\n",
            ),
            (
                "child.env",
                "LOOP_NAME=child\nLOOP_SID=session-child\nLOOP_CWD=/workspace/child\n",
            ),
        ]);
        let registry = parse_registry(&listing, &texts);
        let role = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-child",
            "/workspace/child/project",
            None,
            false,
        );
        assert!(matches!(role, CallerRole::Orchestrator(_)));
        assert_eq!(role.loop_name(), Some("child"));
        assert!(!role.stale_session());
    }

    /// ´test:unit:sibling-checkouts-resolve-by-the-request-checkout´
    #[test]
    fn sibling_checkouts_resolve_by_the_request_checkout() {
        let registry = two_loops();
        let role = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-two",
            "/workspace/sibling/child",
            None,
            false,
        );
        assert!(matches!(role, CallerRole::Orchestrator(_)));
        assert_eq!(role.loop_name(), Some("sibling"));
        assert!(!role.stale_session());
    }

    /// ´test:unit:resolver-rejects-cwd-outside-every-checkout´
    #[test]
    fn resolver_rejects_cwd_outside_every_checkout() {
        let registry = two_loops();
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/scratch/outside",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:resolver-rejects-session-id-that-points-at-another-loop´
    #[test]
    fn resolver_rejects_session_id_that_points_at_another_loop() {
        let registry = two_loops();
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/sibling/child",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:resolver-accepts-entry-without-session-id´
    #[test]
    fn resolver_accepts_entry_without_session_id() {
        let (listing, texts) = source(&[(
            "orchestration.env",
            "LOOP_NAME=orchestration\nLOOP_CWD=/workspace/orchestration\n",
        )]);
        let registry = parse_registry(&listing, &texts);
        let role = resolve_role(
            Some(&registry),
            4_000_000_000,
            "fresh-session",
            "/workspace/orchestration",
            None,
            false,
        );
        assert!(matches!(role, CallerRole::Orchestrator(_)));
        assert_eq!(role.loop_name(), Some("orchestration"));
        assert!(!role.stale_session());
    }

    /// ´test:unit:resolver-rejects-parent-traversal-in-request-cwd´
    #[test]
    fn resolver_rejects_parent_traversal_in_request_cwd() {
        let registry = two_loops();
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/orchestration/../orchestration",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:resolver-rejects-duplicate-checkout-matches´
    #[test]
    fn resolver_rejects_duplicate_checkout_matches() {
        let (listing, texts) = source(&[
            (
                "one.env",
                "LOOP_NAME=one\nLOOP_SID=session-one\nLOOP_CWD=/workspace/shared\n",
            ),
            (
                "two.env",
                "LOOP_NAME=two\nLOOP_SID=session-two\nLOOP_CWD=/workspace/shared\n",
            ),
        ]);
        let registry = parse_registry(&listing, &texts);
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/shared/child",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:resolver-covers-missing-registry-and-relative-cwd´
    #[test]
    fn resolver_covers_missing_registry_and_relative_cwd() {
        let registry = two_loops();
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "workspace/orchestration",
                None,
                false
            ),
            CallerRole::Unknown
        ));
        assert!(matches!(
            resolve_role(
                None,
                4_000_000_000,
                "session-one",
                "/workspace/orchestration",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:duplicate-session-identifiers-resolve-unknown´
    #[test]
    fn duplicate_session_identifiers_resolve_unknown() {
        let (listing, texts) = source(&[
            (
                "one.env",
                "LOOP_NAME=one\nLOOP_SID=duplicate\nLOOP_CWD=/workspace/one\n",
            ),
            (
                "two.env",
                "LOOP_NAME=two\nLOOP_SID=duplicate\nLOOP_CWD=/workspace/two\n",
            ),
        ]);
        let registry = parse_registry(&listing, &texts);
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "duplicate",
                "/scratch",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:sibling-cross-check-does-not-trust-a-shared-checkout-path´
    #[test]
    fn sibling_cross_check_does_not_trust_a_shared_checkout_path() {
        let (listing, texts) = source(&[
            (
                "one.env",
                "LOOP_NAME=one\nLOOP_SID=session-one\nLOOP_CWD=/workspace/shared\n",
            ),
            (
                "two.env",
                "LOOP_NAME=two\nLOOP_SID=session-two\nLOOP_CWD=/workspace/shared\n",
            ),
        ]);
        let registry = parse_registry(&listing, &texts);
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/shared/child",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:unset-registry-value-performs-no-read-and-resolves-unknown´
    #[test]
    fn unset_registry_value_performs_no_read_and_resolves_unknown() {
        let registry = load_registry(None).expect("unset registry is accepted");
        assert!(registry.is_none());
        assert!(matches!(
            resolve_role(
                registry.as_ref(),
                4_000_000_000,
                "session-one",
                "/scratch",
                None,
                false
            ),
            CallerRole::Unknown
        ));
    }

    /// ´test:unit:identity-rules-are-unchanged-by-the-deployment-metadata-fields´
    #[test]
    fn identity_rules_are_unchanged_by_the_deployment_metadata_fields() {
        let registry = two_loops_with_metadata();
        // Rule 1: a request cwd beneath no registered checkout resolves unknown.
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/scratch/outside",
                None,
                false
            ),
            CallerRole::Unknown
        ));
        // Rule 2: the request cwd selects its checkout, and the strictly nested one wins.
        let sibling = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-two",
            "/workspace/sibling/child",
            None,
            false,
        );
        assert!(matches!(sibling, CallerRole::Orchestrator(_)));
        assert_eq!(sibling.loop_name(), Some("sibling"));
        let (listing, texts) = source(&[
            (
                "parent.env",
                "LOOP_NAME=parent\nLOOP_SID=session-parent\nLOOP_CWD=/workspace\nLOOP_UID=41003\nLOOP_HOME=/loops/parent\n",
            ),
            (
                "child.env",
                "LOOP_NAME=child\nLOOP_SID=session-child\nLOOP_CWD=/workspace/child\nLOOP_UID=41004\nLOOP_HOME=/loops/child\n",
            ),
        ]);
        let nested = parse_registry(&listing, &texts);
        assert_eq!(
            resolve_role(
                Some(&nested),
                4_000_000_000,
                "session-child",
                "/workspace/child/project",
                None,
                false
            )
            .loop_name(),
            Some("child")
        );
        // Rule 3: a session id registered to another entry rejects the candidate.
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/sibling",
                None,
                false
            ),
            CallerRole::Unknown
        ));
        // Rule 4: a matching session resolves and a rotated one is unknown.
        let matched = resolve_role(
            Some(&registry),
            4_000_000_000,
            "session-one",
            "/workspace/orchestration",
            None,
            false,
        );
        assert!(matches!(matched, CallerRole::Orchestrator(_)));
        assert!(!matched.stale_session());
        let rotated = resolve_role(
            Some(&registry),
            4_000_000_000,
            "rotated-unmatched",
            "/workspace/orchestration",
            None,
            false,
        );
        assert!(matches!(rotated, CallerRole::Unknown));
        assert!(!rotated.stale_session());
        // Rule 5: either subagent signal narrows the matched role and never widens it.
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/orchestration",
                Some("/run/subagents/agent.jsonl"),
                false
            ),
            CallerRole::OrchestratorSubagent(_)
        ));
        assert!(matches!(
            resolve_role(
                Some(&registry),
                4_000_000_000,
                "session-one",
                "/workspace/orchestration",
                None,
                true
            ),
            CallerRole::OrchestratorSubagent(_)
        ));
    }

    /// ´test:unit:deployment-registration-requires-a-session-for-every-entry´
    #[test]
    fn deployment_registration_requires_a_session_for_every_entry() {
        let fixture = Fixture::new("registration");
        let checkout = fixture.0.join("solo");
        let root = checkout.join("local/state");
        fs::create_dir_all(&root).expect("private state tree is created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("state root is private");
        let entry = format!(
            "LOOP_NAME=solo\nLOOP_CWD={}\nLOOP_STATE_ROOT={}\n",
            checkout.display(),
            root.display()
        );
        let (listing, texts) = source(&[("solo.env", entry.as_str())]);
        let registry = parse_registry(&listing, &texts);
        let refusal = registry
            .validate_deployment_registration()
            .expect_err("an entry registering no session is not deployable")
            .to_string();
        assert!(
            refusal.contains("solo") && refusal.contains("LOOP_SID"),
            "the refusal must name the loop and the missing registration: {refusal}"
        );
        let structural_refusal = registry
            .validate_deployment_structure(None)
            .expect_err("deployment structure requires a session")
            .to_string();
        assert_eq!(structural_refusal, refusal);
        assert!(registry.validate_deployment().is_err());

        let registered = format!("LOOP_SID=solo-session\n{entry}");
        let (listing, texts) = source(&[("solo.env", registered.as_str())]);
        parse_registry(&listing, &texts)
            .validate_deployment_registration()
            .expect("a registration naming its session is deployable");
    }

    /// ´test:unit:registry-loader-rejects-absent-unreadable-and-wrong-owner-directories´
    #[test]
    fn registry_loader_rejects_absent_unreadable_and_wrong_owner_directories() {
        let fixture = Fixture::new("loader");
        let missing = fixture.0.join("missing");
        assert!(
            matches!(
                load_registry_from_path_with_uids(
                    &missing,
                    fs::metadata(&fixture.0).expect("fixture metadata").uid(),
                    None
                ),
                Err(RegistryError::DirectoryMetadata(_))
            ),
            "an absent configured registry directory must fail loading"
        );

        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o000))
            .expect("fixture becomes unreadable");
        let uid = fs::metadata(&fixture.0).expect("unreadable metadata").uid();
        assert!(load_registry_from_path_with_uids(&fixture.0, uid, None).is_err());
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700))
            .expect("fixture privacy is restored");
        assert!(matches!(
            load_registry_from_path_with_uids(&fixture.0, uid.saturating_add(1), None),
            Err(RegistryError::DirectoryOwner { .. })
        ));
    }

    /// ´test:unit:registry-loader-retries-a-row-unlinked-after-listing´
    #[test]
    fn registry_loader_retries_a_row_unlinked_after_listing() {
        let fixture = Fixture::new("generation-exchange");
        let live = fixture.0.join("live");
        let staged = fixture.0.join("staged");
        fs::create_dir(&live).expect("live registry");
        fs::create_dir(&staged).expect("staged registry");
        for directory in [&live, &staged] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private registry");
        }
        let old = "LOOP_NAME=alpha\nLOOP_SID=old\nLOOP_CWD=/workspace/alpha\n";
        let new = "LOOP_NAME=alpha\nLOOP_SID=new\nLOOP_CWD=/workspace/alpha\n";
        for (directory, text) in [(&live, old), (&staged, new)] {
            let row = directory.join("alpha.env");
            fs::write(&row, text).expect("registry row");
            fs::set_permissions(row, fs::Permissions::from_mode(0o600))
                .expect("private registry row");
        }
        let mut exchanged = false;
        let registry = load_registry_with_listing_hook(
            &live,
            fs::metadata(&live).expect("registry metadata").uid(),
            None,
            &mut |phase| {
                if phase == ReadPhase::AfterListing && !exchanged {
                    exchanged = true;
                    fs::rename(&live, fixture.0.join("retired")).expect("retire old generation");
                    fs::rename(&staged, &live).expect("publish new generation");
                    fs::remove_dir_all(fixture.0.join("retired"))
                        .expect("remove old generation during read");
                }
            },
        )
        .expect("reader retries the complete live generation");
        assert!(exchanged);
        assert_eq!(registry.entries().len(), 1);
        assert_eq!(
            registry
                .entries()
                .first()
                .and_then(RegistryEntry::identifier),
            Some("new")
        );
    }

    /// ´test:unit:registry-loader-refuses-a-row-truncated-during-read´
    #[test]
    fn registry_loader_refuses_a_row_truncated_during_read() {
        let fixture = Fixture::new("truncated-row");
        let live = fixture.0.join("live");
        fs::create_dir(&live).expect("live registry");
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).expect("private registry");
        let row = live.join("alpha.env");
        fs::write(
            &row,
            "LOOP_NAME=alpha\nLOOP_SID=session-main\nLOOP_CWD=/workspace/alpha\n",
        )
        .expect("complete row");
        fs::set_permissions(&row, fs::Permissions::from_mode(0o600)).expect("private row");
        let uid = fs::metadata(&live).expect("registry metadata").uid();
        let mut reads = 0;
        let result = load_registry_with_listing_hook(&live, uid, None, &mut |phase| {
            if phase == ReadPhase::AfterListing {
                reads += 1;
                if reads == 1 {
                    fs::write(&row, "LOOP_NAME=alpha\nLOOP_SID=")
                        .expect("row truncated during read");
                }
            }
        });
        assert_eq!(reads, 3);
        assert!(matches!(result, Err(RegistryError::GenerationChanged)));
    }

    /// ´test:unit:registry-loader-survives-listing-cleanup-and-two-exchanges´
    #[test]
    fn registry_loader_survives_listing_cleanup_and_two_exchanges() {
        let fixture = Fixture::new("two-exchanges");
        let live = fixture.0.join("live");
        let first = fixture.0.join("first");
        let second = fixture.0.join("second");
        for (path, sid) in [(&live, "old"), (&first, "middle"), (&second, "new")] {
            fs::create_dir(path).expect("registry generation");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private generation");
            let row = path.join("alpha.env");
            fs::write(
                &row,
                format!("LOOP_NAME=alpha\nLOOP_SID={sid}\nLOOP_CWD=/workspace/alpha\n"),
            )
            .expect("generation row");
            fs::set_permissions(row, fs::Permissions::from_mode(0o600)).expect("private row");
        }
        let parent = File::open(&fixture.0).expect("generation parent");
        let mut exchanges = 0;
        let registry = load_registry_with_listing_hook(
            &live,
            fs::metadata(&live).expect("registry metadata").uid(),
            None,
            &mut |phase| {
                let stage = match (exchanges, phase) {
                    (0, ReadPhase::BeforeListing) => &first,
                    (1, ReadPhase::AfterListing) => &second,
                    _ => return,
                };
                renameat2(
                    &parent,
                    stage.file_name().expect("staged name"),
                    &parent,
                    live.file_name().expect("live name"),
                    RenameFlags::RENAME_EXCHANGE,
                )
                .expect("atomic generation exchange");
                fs::remove_dir_all(stage).expect("cleanup during read");
                exchanges += 1;
            },
        )
        .expect("reader retries the newest complete generation");
        assert_eq!(exchanges, 2);
        assert_eq!(
            registry
                .entries()
                .first()
                .and_then(RegistryEntry::identifier),
            Some("new")
        );
    }
}
