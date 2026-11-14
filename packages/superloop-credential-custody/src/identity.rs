//! Calibration identities are compared, never repaired or updated.
use crate::{
    process, receipt,
    record::{Identity, Parameters, Result},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::Command;

pub fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .flat_map(|b| {
            [
                char::from(b"0123456789abcdef"[usize::from(b >> 4)]),
                char::from(b"0123456789abcdef"[usize::from(b & 15)]),
            ]
        })
        .collect()
}

pub fn live(record: &Parameters) -> Result<Identity> {
    let mut live = record.identity.clone();
    let mut objects = BTreeSet::new();
    for file in [
        &mut live.files.sealer,
        &mut live.files.library,
        &mut live.files.interpreter,
        &mut live.files.parser,
    ] {
        // The fixed interpreter entry is commonly a vendor symlink. Resolve it,
        // then read the resolved regular file without following further links.
        let resolved = if file.path == std::path::Path::new("/usr/bin/python3") {
            std::fs::canonicalize(&file.path).map_err(|_| "identity-path")?
        } else {
            file.path.clone()
        };
        let input = receipt::open(&resolved, false)?;
        let meta = input.metadata().map_err(|_| "file-metadata")?;
        if !objects.insert((meta.dev(), meta.ino())) {
            return Err("identity-file-alias");
        }
        file.sha256 = hash(&receipt::read_file(input, 268_435_456, false)?);
    }
    for expected in &mut live.probes {
        let probe = record
            .probes
            .iter()
            .find(|p| p.role == expected.role)
            .ok_or("identity-member")?;
        let mut command = Command::new(&probe.argv[0]);
        command.args(&probe.argv[1..]);
        expected.bytes = process::capture(command, &[], &record.limits)?;
        if expected.bytes.is_empty() {
            return Err("identity-member");
        }
    }
    if live != record.identity {
        return Err("identity-drift");
    }
    Ok(live)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Calibration {
    schema: u32,
    command: String,
    case: String,
    outcome: String,
    #[serde(rename = "wall_us")]
    _wall_us: u128,
    evidence: CalibrationEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationEvidence {
    identity: Identity,
    config_digest: String,
    code_digest: String,
    rows: Vec<crate::observe::Row>,
    constants: Vec<crate::observe::Constant>,
    comparisons: Vec<crate::observe::Compared>,
}

pub fn run(record: &Parameters, path: &Path) -> Result<Value> {
    if path.parent() != Some(record.evidence_root.as_path())
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| {
                !crate::record::name(name) || name.starts_with('.') || name.ends_with(".partial")
            })
    {
        return Err("calibration-path");
    }
    let bytes = receipt::protected_read(path, crate::record::RECORD_LIMIT as u64, true)?;
    let calibration: Calibration =
        serde_json::from_slice(&bytes).map_err(|_| "calibration-shape")?;
    let evidence = &calibration.evidence;
    if calibration.schema != 1
        || calibration.command != "length-observe"
        || calibration.case != record.case
        || calibration.outcome != "ok"
        || evidence.config_digest != record.config_digest
        || evidence.code_digest != record.code_digest
        || evidence.identity != record.identity
    {
        return Err("calibration-identity");
    }
    evidence.identity.validate()?;
    crate::observe::validate(
        record,
        &evidence.rows,
        &evidence.constants,
        &evidence.comparisons,
    )?;
    live(record)?;
    Ok(json!({"matches": true, "calibration_sha256": hash(&bytes)}))
}
