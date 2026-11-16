//! Measure held artifact bytes and typed configuration; declarations are references only.
use super::{
    Result,
    policy::{Artifact, ArtifactRole, Case, Policy, Properties},
    require,
};
use crate::{identity::hash, receipt, record};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Seek as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectIdentity {
    pub device: u64,
    pub inode: u64,
}
impl ObjectIdentity {
    pub fn of(file: &File) -> Result<Self> {
        let m = file.metadata().map_err(|_| "file-metadata")?;
        Ok(Self {
            device: m.dev(),
            inode: m.ino(),
        })
    }
}
#[derive(Debug)]
pub(super) struct HeldArtifact {
    pub id: String,
    pub role: ArtifactRole,
    pub file: File,
    pub object: ObjectIdentity,
    pub sha256: String,
    pub length: u64,
    stamp: (i64, i64, i64, i64),
}
impl HeldArtifact {
    pub fn verify_bytes(&self) -> Result<()> {
        self.unchanged()?;
        let mut file = self.file.try_clone().map_err(|_| "file-read")?;
        file.rewind().map_err(|_| "file-read")?;
        let bytes = receipt::read_file(file, self.length, false)?;
        require(hash(&bytes) == self.sha256, "launch-artifact-drift")?;
        self.unchanged()
    }
    pub fn unchanged(&self) -> Result<()> {
        let m = self.file.metadata().map_err(|_| "file-metadata")?;
        require(
            ObjectIdentity::of(&self.file)? == self.object
                && m.len() == self.length
                && (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()) == self.stamp,
            "launch-artifact-changed",
        )
    }
}
pub(super) struct CaseMeasurement {
    pub id: String,
    pub sha256: String,
}
pub(super) struct Admission {
    owner: u32,
    policy: Policy,
    policy_sha256: String,
    code_sha256: String,
    artifacts: Vec<HeldArtifact>,
    cases: Vec<CaseMeasurement>,
    fixture_image: ObjectIdentity,
}
impl Admission {
    pub const fn owner(&self) -> u32 {
        self.owner
    }
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn code_sha256(&self) -> &str {
        &self.code_sha256
    }
    pub fn artifacts(&self) -> &[HeldArtifact] {
        &self.artifacts
    }
    pub fn cases(&self) -> &[CaseMeasurement] {
        &self.cases
    }
    pub const fn fixture_image(&self) -> ObjectIdentity {
        self.fixture_image
    }
}
#[cfg(test)]
pub(super) fn admit_for_owner(bytes: &[u8], owner: u32) -> Result<Admission> {
    admit_bytes(bytes, owner)
}

pub(super) fn root_admission(path: &Path) -> Result<Admission> {
    require(
        nix::unistd::geteuid().is_root(),
        "launch-privilege-required",
    )?;
    admit_bytes(&receipt::parameters(path)?, 0)
}

// The owner parameter belongs to the private core, never a CLI or policy field.
// The root adapter always passes zero. Ordinary-user tests exercise held files.
fn admit_bytes(bytes: &[u8], owner: u32) -> Result<Admission> {
    let policy = super::policy::parse(bytes)?;
    // Empty-environment native sealing uses this fixed host-key path. Compare
    // before touching artifacts; the test-only owner adapter uses synthetic keys.
    require(
        owner != 0 || policy.host_key == Path::new("/var/lib/systemd/credential.secret"),
        "launch-host-key",
    )?;
    let mut objects = BTreeSet::new();
    let mut artifacts = Vec::new();
    for expected in &policy.artifacts {
        artifacts.push(measure_artifact(
            expected,
            policy.limits.artifact_bytes,
            owner,
            &mut objects,
        )?);
    }
    let cases = policy
        .cases
        .iter()
        .map(|case| measure_case(case, owner, policy.limits.case_ms))
        .collect::<Result<Vec<_>>>()?;
    artifacts.sort_by(|a, b| a.id.cmp(&b.id));
    let measured: Vec<_> = artifacts
        .iter()
        .map(|a| (&a.id, a.role, &a.sha256))
        .collect();
    let fixture_image = artifacts
        .iter()
        .find(|a| a.role == ArtifactRole::Fixture)
        .ok_or("launch-artifact-roster")?
        .object;
    Ok(Admission {
        owner,
        policy,
        policy_sha256: hash(bytes),
        code_sha256: canonical("custody-artifacts-v1", &measured)?,
        artifacts,
        cases,
        fixture_image,
    })
}

pub(super) fn canonical<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    let encoded = serde_json::to_vec(value).map_err(|_| "launch-evidence-encoding")?;
    let mut framed = Vec::new();
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain.as_bytes());
    framed.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    framed.extend_from_slice(&encoded);
    Ok(hash(&framed))
}

#[derive(Debug, Serialize)]
pub(super) struct ConfigurationMeasurement {
    pub raw_sha256: String,
    pub typed_sha256: String,
}
// A later adapter must supply actual loaded properties. This strict
// comparison/measurement core cannot attest to a manager it never contacts.
pub(super) fn configuration(
    expected: &Properties,
    observed: &[u8],
) -> Result<ConfigurationMeasurement> {
    require(
        observed.len() <= record::RECORD_LIMIT,
        "launch-configuration-size",
    )?;
    let actual: Properties =
        serde_json::from_slice(observed).map_err(|_| "launch-configuration-shape")?;
    require(&actual == expected, "launch-configuration-drift")?;
    Ok(ConfigurationMeasurement {
        raw_sha256: hash(observed),
        typed_sha256: canonical("custody-unit-properties-v1", &actual)?,
    })
}

fn measure_artifact(
    expected: &Artifact,
    limit: u64,
    owner: u32,
    objects: &mut BTreeSet<(u64, u64)>,
) -> Result<HeldArtifact> {
    let file = receipt::walk(&expected.path, false, true)?;
    let m = file.metadata().map_err(|_| "file-metadata")?;
    require(
        m.is_file()
            && (m.uid() == owner || (expected.role == ArtifactRole::Library && m.uid() == 0))
            && m.nlink() > 0
            && m.mode() & 0o7022 == 0
            && m.len() <= limit,
        "launch-artifact-custody",
    )?;
    require(objects.insert((m.dev(), m.ino())), "launch-artifact-alias")?;
    let content = receipt::read_file(file.try_clone().map_err(|_| "file-read")?, limit, false)?;
    let sha256 = hash(&content);
    require(sha256 == expected.expected_sha256, "launch-artifact-drift")?;
    let held = HeldArtifact {
        id: expected.id.clone(),
        role: expected.role,
        object: ObjectIdentity::of(&file)?,
        file,
        sha256,
        length: m.len(),
        stamp: (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
    };
    held.unchanged()?;
    Ok(held)
}
fn measure_case(case: &Case, owner: u32, timeout: u64) -> Result<CaseMeasurement> {
    let file = receipt::walk(&case.record, false, true)?;
    let m = file.metadata().map_err(|_| "file-metadata")?;
    require(
        m.is_file()
            && m.uid() == owner
            && m.mode() & 0o7777 == 0o444
            && m.nlink() == 1
            && m.len() <= record::RECORD_LIMIT as u64,
        "launch-public-case-custody",
    )?;
    let bytes = receipt::read_file(file, record::RECORD_LIMIT as u64, false)?;
    let sha256 = hash(&bytes);
    require(
        sha256 == case.expected_case_sha256,
        "launch-public-case-drift",
    )?;
    let streams = case
        .streams
        .each_ref()
        .map(|s| (s.name.as_str(), s.length, s.pattern.id()));
    crate::fixture::validate_launch_case(&bytes, &case.id, &streams, timeout)?;
    Ok(CaseMeasurement {
        id: case.id.clone(),
        sha256,
    })
}
