//! Closed launch-policy metadata; no manager transport or arbitrary property bag.
use super::{Result, require};
use crate::record;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// One fixture stdio template for manager submission/read-back and inventory.
pub(super) struct StandardStream {
    pub property: &'static str,
    pub manager_value: &'static str,
    pub access: u32,
    pub kind: u32,
    pub device: u64,
}
pub(super) const FIXTURE_STANDARD_STREAMS: [StandardStream; 3] = [
    StandardStream {
        property: "StandardInput",
        manager_value: "null",
        access: nix::libc::O_RDONLY as u32,
        kind: nix::libc::S_IFCHR,
        device: nix::sys::stat::makedev(1, 3),
    },
    StandardStream {
        property: "StandardOutput",
        manager_value: "null",
        access: nix::libc::O_WRONLY as u32,
        kind: nix::libc::S_IFCHR,
        device: nix::sys::stat::makedev(1, 3),
    },
    StandardStream {
        property: "StandardError",
        manager_value: "null",
        access: nix::libc::O_WRONLY as u32,
        kind: nix::libc::S_IFCHR,
        device: nix::sys::stat::makedev(1, 3),
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    pub schema: u32,
    pub command: String,
    pub campaign: String,
    pub roots: Roots,
    pub manager_sockets: [PathBuf; 2],
    pub host_key: PathBuf,
    pub slice: String,
    pub limits: Limits,
    pub artifacts: Vec<Artifact>,
    pub roles: Vec<RolePolicy>,
    pub sealer_construction: SealerConstruction,
    pub cases: Vec<Case>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Roots {
    pub runtime: PathBuf,
    pub sealed: PathBuf,
    pub evidence: PathBuf,
}
impl Roots {
    pub fn paths(&self) -> [&Path; 3] {
        [&self.runtime, &self.sealed, &self.evidence]
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub case_ms: u64,
    pub campaign_ms: u64,
    pub poll_ms: u64,
    pub sealed_bytes: u64,
    pub total_sealed_bytes: u64,
    pub diagnostic_bytes: u64,
    pub artifact_bytes: u64,
    pub observed_fds: u64,
    pub mapped_files: u64,
    pub event_queue: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ArtifactRole {
    Launcher,
    Fixture,
    Sealer,
    Parser,
    Interpreter,
    Library,
    ManagerStart,
    ManagerQuery,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub id: String,
    pub role: ArtifactRole,
    pub path: PathBuf,
    pub expected_sha256: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Role {
    CalibrationRun,
    Completion,
    Descriptors,
    BarrierRelease,
    Fixture,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Capability {
    SysPtrace,
    Kill,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Protection {
    Strict,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Namespace {
    Host,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RootKind {
    Runtime,
    Sealed,
    Evidence,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent manager properties retain their boolean wire types"
)]
pub(super) struct Properties {
    pub capability_bounding_set: Vec<Capability>,
    pub ambient_capabilities: Vec<Capability>,
    pub no_new_privileges: bool,
    pub protect_system: Protection,
    pub user_namespace: Namespace,
    pub pid_namespace: Namespace,
    pub manager_access: bool,
    pub dynamic_user: bool,
    pub writable: Vec<RootKind>,
    pub private_diagnostics: bool,
}
// A direct child construction, never a separate manager unit or a granted capability.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SealerConstruction {
    Landlock6SeccompV1,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RolePolicy {
    pub role: Role,
    pub properties: Properties,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub id: String,
    pub generator_unit: String,
    #[serde(rename = "public_case")]
    pub record: PathBuf,
    pub expected_case_sha256: String,
    pub streams: [Stream; 2],
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Pattern {
    Ascending,
    Descending,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Stream {
    pub name: String,
    pub output: String,
    pub length: u64,
    pub pattern: Pattern,
}

pub(super) fn parse(bytes: &[u8]) -> Result<Policy> {
    require(bytes.len() <= record::RECORD_LIMIT, "launch-policy-size")?;
    let policy: Policy = serde_json::from_slice(bytes).map_err(|_| "launch-policy-shape")?;
    policy.validate()?;
    Ok(policy)
}

fn absolute(path: &Path) -> bool {
    record::path(path, true)
        && path != Path::new("/")
        && path.as_os_str().len() <= 4096
        && path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(b))
}
fn disjoint(a: &Path, b: &Path) -> bool {
    let below = a.starts_with(b);
    let above = b.starts_with(a);
    !below && !above
}
fn unit(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix).is_some_and(record::name) && name.len() <= 96
}
impl Role {
    pub fn properties(self) -> Properties {
        use Capability::{Kill, SysPtrace};
        use RootKind::{Evidence, Runtime, Sealed};
        Properties {
            capability_bounding_set: match self {
                Self::CalibrationRun => vec![SysPtrace, Kill],
                Self::Descriptors => vec![SysPtrace],
                _ => vec![],
            },
            ambient_capabilities: vec![],
            no_new_privileges: true,
            protect_system: Protection::Strict,
            user_namespace: Namespace::Host,
            pid_namespace: Namespace::Host,
            manager_access: self == Self::CalibrationRun,
            dynamic_user: self == Self::Fixture,
            writable: match self {
                Self::CalibrationRun => vec![Runtime, Sealed, Evidence],
                Self::Completion | Self::Descriptors => vec![Evidence],
                Self::BarrierRelease => vec![Runtime, Evidence],
                Self::Fixture => vec![],
            },
            private_diagnostics: true,
        }
    }
}
impl Policy {
    fn validate(&self) -> Result<()> {
        require(
            self.schema == 2 && self.command == "launch-policy",
            "launch-policy-schema",
        )?;
        require(
            record::name(&self.campaign) && unit(&self.slice, ".slice"),
            "launch-policy-name",
        )?;
        let roots = self.roots.paths();
        require(
            roots.iter().all(|p| absolute(p))
                && absolute(&self.host_key)
                && self.manager_sockets.iter().all(|p| absolute(p)),
            "launch-policy-path",
        )?;
        require(
            roots.iter().enumerate().all(|(i, a)| {
                roots
                    .iter()
                    .enumerate()
                    .all(|(j, b)| i == j || disjoint(a, b))
            }) && self.manager_sockets[0] != self.manager_sockets[1]
                && self.manager_sockets.iter().all(|p| p != &self.host_key)
                && roots.iter().all(|root| {
                    !self.host_key.starts_with(root)
                        && self.manager_sockets.iter().all(|p| !p.starts_with(root))
                }),
            "launch-root-separation",
        )?;
        self.validate_limits()?;
        let mut roles = BTreeSet::new();
        require(
            self.roles.len() == 5 && self.roles.iter().all(|r| roles.insert(r.role)),
            "launch-role-roster",
        )?;
        require(
            self.roles
                .iter()
                .all(|r| r.properties == r.role.properties()),
            "launch-role-properties",
        )?;
        self.validate_artifacts()?;
        self.validate_cases()
    }
    fn validate_limits(&self) -> Result<()> {
        let l = &self.limits;
        require(
            (1..=600_000).contains(&l.case_ms)
                && (1..=3_600_000).contains(&l.campaign_ms)
                && (1..=1000).contains(&l.poll_ms)
                && l.poll_ms <= l.case_ms
                && (1..=16_777_216).contains(&l.sealed_bytes)
                && (1..=2_147_483_648).contains(&l.total_sealed_bytes)
                && (1..=16_384).contains(&l.diagnostic_bytes)
                && (1..=67_108_864).contains(&l.artifact_bytes)
                && (5..=64).contains(&l.observed_fds)
                && (1..=128).contains(&l.mapped_files)
                && (1..=256).contains(&l.event_queue),
            "launch-policy-limit",
        )?;
        require(
            (1..=64).contains(&self.cases.len())
                && l.case_ms
                    .checked_mul(self.cases.len() as u64)
                    .is_some_and(|n| n <= l.campaign_ms)
                && l.sealed_bytes
                    .checked_mul(2 * self.cases.len() as u64)
                    .is_some_and(|n| n <= l.total_sealed_bytes),
            "launch-campaign-bound",
        )?;
        Ok(())
    }
    fn validate_cases(&self) -> Result<()> {
        let roots = self.roots.paths();
        let mut cases = BTreeSet::new();
        let mut units = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut records = BTreeSet::new();
        let artifact_paths: BTreeSet<_> = self.artifacts.iter().map(|a| &a.path).collect();
        for case in &self.cases {
            require(
                record::name(&case.id)
                    && cases.insert(&case.id)
                    && unit(&case.generator_unit, ".service")
                    && units.insert(&case.generator_unit)
                    && absolute(&case.record)
                    && record::digest(&case.expected_case_sha256)
                    && records.insert(&case.record)
                    && roots.iter().all(|r| !case.record.starts_with(r))
                    && case.record != self.host_key
                    && self.manager_sockets.iter().all(|p| p != &case.record)
                    && !artifact_paths.contains(&case.record),
                "launch-case-identity",
            )?;
            require(
                case.streams[0].name != case.streams[1].name
                    && case.streams[0].output != case.streams[1].output
                    && case.streams[0].pattern != case.streams[1].pattern
                    && case.streams.iter().all(|s| {
                        record::name(&s.name)
                            && output_name(&s.output)
                            && (1..=1_048_576).contains(&s.length)
                    }),
                "launch-stream-contract",
            )?;
            for stream in &case.streams {
                names.insert(&stream.name);
            }
        }
        require(names.len() <= 16, "launch-name-bound")
    }
    fn validate_artifacts(&self) -> Result<()> {
        require(
            (6..=135).contains(&self.artifacts.len()),
            "launch-artifact-roster",
        )?;
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut roles = BTreeSet::new();
        let mut libraries = 0;
        for a in &self.artifacts {
            require(
                record::name(&a.id)
                    && ids.insert(&a.id)
                    && absolute(&a.path)
                    && paths.insert(&a.path)
                    && record::digest(&a.expected_sha256)
                    && self.roots.paths().iter().all(|r| !a.path.starts_with(r))
                    && a.path != self.host_key
                    && self.manager_sockets.iter().all(|p| p != &a.path),
                "launch-artifact-identity",
            )?;
            if a.role == ArtifactRole::Library {
                libraries += 1;
            } else {
                require(roles.insert(a.role), "launch-artifact-roster")?;
            }
        }
        require(
            [
                ArtifactRole::Launcher,
                ArtifactRole::Fixture,
                ArtifactRole::Sealer,
                ArtifactRole::Parser,
                ArtifactRole::Interpreter,
            ]
            .iter()
            .all(|role| roles.contains(role))
                && roles.contains(&ArtifactRole::ManagerStart)
                    == roles.contains(&ArtifactRole::ManagerQuery)
                && (1..=self.limits.mapped_files).contains(&libraries),
            "launch-artifact-roster",
        )
    }
}
pub(super) fn output_name(name: &str) -> bool {
    record::name(name) && !name.starts_with('.') && name.ends_with(".sealed")
}

impl Pattern {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Ascending => "ascending",
            Self::Descending => "descending",
        }
    }
}
