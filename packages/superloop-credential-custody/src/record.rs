//! Strict, bounded metadata records. No field carries a plaintext stream.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub type Result<T> = std::result::Result<T, &'static str>;
pub const RECORD_LIMIT: usize = 262_144;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub schema: u32,
    pub case: String,
    pub config_digest: String,
    pub code_digest: String,
    pub sealed_root: PathBuf,
    pub evidence_root: PathBuf,
    pub payload: Payload,
    pub limits: Limits,
    pub identity: Identity,
    pub probes: Vec<Probe>,
    pub names: Vec<String>,
    pub lengths: Vec<u64>,
    pub contents: [String; 2],
    pub comparisons: Vec<Comparison>,
    pub samples: Vec<Sample>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub path: PathBuf,
    pub sha256: String,
    pub repository: PathBuf,
    pub source_commit: String,
    pub document: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub file_bytes: u64,
    pub output_bytes: u64,
    pub timeout_ms: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub measure: String,
    pub computation: String,
    pub form: Form,
    pub files: Files,
    pub probes: Vec<ProbeIdentity>,
    pub source_commit: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Form {
    pub wrap: u64,
    pub final_lf: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Files {
    pub sealer: FileIdentity,
    pub library: FileIdentity,
    pub interpreter: FileIdentity,
    pub parser: FileIdentity,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeIdentity {
    pub role: ProbeRole,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeRole {
    Boot,
    Deployment,
    LiveApplied,
    SealerVersion,
    SealerPackage,
    LibraryMapping,
    InterpreterPackage,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub role: ProbeRole,
    pub argv: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub id: String,
    pub left: String,
    pub right: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub name: String,
    pub input_length: u64,
    pub content: String,
    pub completion: Completion,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub case: String,
    pub invocation: String,
    pub success: bool,
    pub distinct_content: bool,
    pub sealed_sha256: String,
}

pub fn parse(bytes: &[u8]) -> Result<Parameters> {
    if bytes.len() > RECORD_LIMIT {
        return Err("record-too-large");
    }
    // Struct deserialization rejects duplicate members, including nested members.
    // No map or untyped Value is used at this trust boundary.
    let record: Parameters = serde_json::from_slice(bytes).map_err(|_| "record-shape")?;
    record.validate()?;
    Ok(record)
}

pub fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn path(value: &Path, absolute: bool) -> bool {
    !value
        .as_os_str()
        .as_encoded_bytes()
        .split(|b| *b == b'/')
        .any(|c| c == b"." || c == b"..")
        && value.is_absolute() == absolute
        && value.as_os_str().len() <= 4096
        && !value.as_os_str().is_empty()
        && value
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !value.as_os_str().as_encoded_bytes().contains(&0)
        && !value
            .as_os_str()
            .as_encoded_bytes()
            .windows(2)
            .any(|b| b == b"//")
}

impl Parameters {
    fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err("record-schema");
        }
        if !name(&self.case) || !digest(&self.config_digest) || !digest(&self.code_digest) {
            return Err("record-identity");
        }
        if !path(&self.sealed_root, true)
            || !path(&self.evidence_root, true)
            || self.sealed_root == self.evidence_root
            || !path(&self.payload.path, true)
            || !path(&self.payload.repository, true)
            || !path(&self.payload.document, false)
        {
            return Err("record-path");
        }
        if !digest(&self.payload.sha256)
            || self.payload.source_commit.len() != 40
            || !self
                .payload
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.identity.source_commit != self.payload.source_commit
            || self.identity.files.parser.path != self.payload.path
            || self.identity.files.parser.sha256 != self.payload.sha256
            || self.identity.files.interpreter.path != Path::new("/usr/bin/python3")
        {
            return Err("record-payload-identity");
        }
        self.identity.validate()?;
        if !(1..=16_777_216).contains(&self.limits.file_bytes)
            || !(1..=4_194_304).contains(&self.limits.output_bytes)
            || !(1..=60_000).contains(&self.limits.timeout_ms)
        {
            return Err("record-limits");
        }
        let roles: BTreeSet<_> = self.probes.iter().map(|p| p.role).collect();
        if roles.len() != 7 || self.probes.len() != 7 {
            return Err("record-probes");
        }
        for probe in &self.probes {
            if probe.argv.is_empty()
                || probe.argv.len() > 32
                || !path(Path::new(&probe.argv[0]), true)
                || probe
                    .argv
                    .iter()
                    .any(|a| a.len() > 4096 || a.as_bytes().contains(&0))
            {
                return Err("record-probe-vector");
            }
        }
        let names: BTreeSet<_> = self.names.iter().collect();
        let lengths: BTreeSet<_> = self.lengths.iter().collect();
        if names.is_empty()
            || names.len() > 16
            || names.len() != self.names.len()
            || self.names.iter().any(|n| !name(n))
            || lengths.len() < 2
            || lengths.len() > 16
            || lengths.len() != self.lengths.len()
            || self.lengths.iter().any(|n| *n > self.limits.file_bytes)
            || self.contents.iter().any(|n| !name(n))
            || self.contents[0] == self.contents[1]
        {
            return Err("record-roster");
        }
        let mut ids = BTreeSet::new();
        for pair in &self.comparisons {
            if !name(&pair.id)
                || !ids.insert(&pair.id)
                || !names.contains(&pair.left)
                || !names.contains(&pair.right)
                || pair.left == pair.right
            {
                return Err("record-comparisons");
            }
        }
        if self.comparisons.len() > 16 || self.samples.len() != names.len() * lengths.len() * 2 {
            return Err("record-samples");
        }
        let mut matrix = BTreeSet::new();
        for sample in &self.samples {
            if !names.contains(&sample.name)
                || !lengths.contains(&sample.input_length)
                || !self.contents.contains(&sample.content)
                || !matrix.insert((&sample.name, sample.input_length, &sample.content))
                || sample.completion.case != self.case
                || !name(&sample.completion.invocation)
                || !sample.completion.success
                || !sample.completion.distinct_content
                || !digest(&sample.completion.sealed_sha256)
            {
                return Err("record-completion");
            }
        }
        Ok(())
    }
}

impl Identity {
    pub fn validate(&self) -> Result<()> {
        if self.measure != "decoded-length"
            || self.computation != "3*(N/4)-P"
            || self.form.wrap > 1_048_576
        {
            return Err("record-computation");
        }
        for file in [
            &self.files.sealer,
            &self.files.library,
            &self.files.interpreter,
            &self.files.parser,
        ] {
            if !path(&file.path, true) || !digest(&file.sha256) {
                return Err("record-file-identity");
            }
        }
        let roles: BTreeSet<_> = self.probes.iter().map(|p| p.role).collect();
        if roles.len() != 7
            || self.probes.len() != 7
            || self
                .probes
                .iter()
                .any(|p| p.bytes.is_empty() || p.bytes.len() > 16_384)
        {
            return Err("record-probe-identity");
        }
        Ok(())
    }
}
