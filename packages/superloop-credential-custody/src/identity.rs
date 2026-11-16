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

pub struct LiveIdentity {
    pub identity: Identity,
    pub interpreter: std::fs::File,
}

pub fn live(record: &Parameters) -> Result<LiveIdentity> {
    let mut live = record.identity.clone();
    let mut objects = BTreeSet::new();
    let interpreter_path = live.files.interpreter.path.clone();
    let mut interpreter = None;
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
        if file.path == interpreter_path {
            interpreter = Some(input.try_clone().map_err(|_| "identity-interpreter-hold")?);
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
        let bytes = process::capture(command, &[], &record.limits)?;
        if bytes.is_empty() {
            return Err("identity-member");
        }
        expected.sha256 = hash(&bytes);
    }
    if live != record.identity {
        return Err("identity-drift");
    }
    Ok(LiveIdentity {
        identity: live,
        interpreter: interpreter.ok_or("identity-member")?,
    })
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
    campaign: crate::launch::observation::Evidence,
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
    if calibration.schema != 2
        || calibration.command != "length-observe"
        || calibration.case != record.case
        || calibration.outcome != "ok"
        || evidence.campaign != crate::launch::observation::bind(record)?.evidence
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
    Ok(json!({"matches": true, "calibration_sha256": hash(&bytes), "campaign": evidence.campaign}))
}
