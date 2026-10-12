//! Validate the writer, readers and format authority of shared-file protocols.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde_json::Value;

type Result<T> = std::result::Result<T, String>;

fn source(root: &Path, relative: &str) -> Result<String> {
    if Path::new(relative)
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "data contract source must be repository-relative: {relative}"
        ));
    }
    fs::read_to_string(root.join(relative))
        .map_err(|error| format!("data contract source {relative}: {error}"))
}

pub fn check(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut identities = BTreeSet::new();
    let mut result = Vec::new();
    for row in ledger.iter().filter(|row| row["kind"] == "data") {
        let identity = row["identity"].as_str().ok_or("data identity missing")?;
        if !identities.insert(identity) {
            findings.push(format!("duplicate data contract: {identity}"));
        }
        for field in ["writer", "format_authority", "format_contract", "owner"] {
            if row[field].as_str().is_none_or(str::is_empty) {
                findings.push(format!("data contract {identity} lacks {field}"));
            }
        }
        if let Some(authority) = row["format_authority"].as_str() {
            source(root, authority)?;
        }
        let readers = row["readers"]
            .as_array()
            .ok_or("data readers must be an explicit array")?;
        if readers.is_empty() {
            findings.push(format!("data contract {identity} has no reader"));
        }
        for participant in readers.iter().chain(std::iter::once(&row["writer"])) {
            let name = participant
                .as_str()
                .ok_or("data participant must be a name")?;
            if !name.starts_with("external:")
                && !ledger.iter().any(|candidate| {
                    (candidate["kind"] == "package" && candidate["name"] == name)
                        || (candidate["kind"] == "program" && candidate["identity"] == name)
                })
            {
                findings.push(format!(
                    "data contract {identity} names an unknown participant: {name}"
                ));
            }
        }
        let sites = row["sites"]
            .as_array()
            .ok_or("data contract sites missing")?;
        if sites.is_empty() {
            findings.push(format!("data contract {identity} has no source evidence"));
        }
        for site in sites {
            let path = site["path"].as_str().ok_or("data site path missing")?;
            let anchor = site["anchor"].as_str().ok_or("data site anchor missing")?;
            if anchor.is_empty() || !source(root, path)?.contains(anchor) {
                findings.push(format!(
                    "data contract {identity} has a stale source anchor: {path}"
                ));
            }
        }
        result.push(row.clone());
    }
    Ok(result)
}
