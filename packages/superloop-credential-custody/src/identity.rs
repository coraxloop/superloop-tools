//! Calibration identities are compared, never repaired or updated.
use crate::{
    process, receipt,
    record::{Identity, Parameters, Result},
};
use sha2::{Digest as _, Sha256};
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
    for file in [
        &mut live.files.sealer,
        &mut live.files.library,
        &mut live.files.interpreter,
        &mut live.files.parser,
    ] {
        // The fixed interpreter entry is commonly a vendor symlink. Resolve it,
        // then read the resolved regular file without following further links.
        let resolved = std::fs::canonicalize(&file.path).map_err(|_| "identity-path")?;
        file.sha256 = hash(&receipt::read(&resolved, 268_435_456, false)?);
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
