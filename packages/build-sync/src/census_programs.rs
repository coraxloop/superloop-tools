//! Program roster equality checks for the Meson ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn table(source: &str, name: &str, width: usize) -> Result<Vec<Vec<String>>> {
    let marker = format!("{name} = {{");
    let (_, body) = source
        .split_once(&marker)
        .ok_or_else(|| format!("missing {name}"))?;
    let (body, _) = body
        .split_once("\n}")
        .ok_or_else(|| format!("unterminated {name}"))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<_> = line
                .split('\'')
                .enumerate()
                .filter(|(index, _)| index % 2 == 1)
                .map(|(_, field)| field.to_owned())
                .collect();
            if fields.len() == width {
                Ok(fields)
            } else {
                Err(format!(
                    "{name} must contain literal rows with {width} fields: {line}"
                ))
            }
        })
        .collect()
}

fn manifest(root: &Path, authority: &str) -> Result<Value> {
    toml::from_str(&fs::read_to_string(root.join(authority)).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

pub fn manifest_version(root: &Path, document: &Value) -> Result<Value> {
    let version = &document["package"]["version"];
    if version.get("workspace").and_then(Value::as_bool) == Some(true) {
        Ok(manifest(root, "Cargo.toml")?["workspace"]["package"]["version"].clone())
    } else {
        Ok(version.clone())
    }
}

pub fn versioned(
    root: &Path,
    source: &str,
    row: &Value,
    findings: &mut Vec<String>,
) -> Result<Value> {
    let mut result = row.clone();
    let identity = row["identity"].as_str().ok_or("program identity missing")?;
    let authority = row["version_authority"]
        .as_str()
        .ok_or("program authority missing")?;
    if authority.ends_with("Cargo.toml") {
        let manifest = manifest(root, authority)?;
        result["version"] = manifest_version(root, &manifest)?;
        result["release_group"] =
            manifest["package"]["metadata"]["superloop"]["release-group"].clone();
        if manifest["package"]["name"] != row["package"] {
            findings.push(format!("wrong program version authority: {identity}"));
        }
    }
    let scripts = table(source, "script_version_roster", 4)?;
    if row["form"] == "shell" {
        if let Some(script) = scripts.iter().find(|script| script[0] == identity) {
            let expected_authority = if script[1].is_empty() {
                "meson.build:script_version_roster"
            } else {
                &script[1]
            };
            if authority != expected_authority || row["release_group"] != script[3] {
                findings.push(format!(
                    "script version authority differs from roster: {identity}"
                ));
            }
            if script[1].is_empty() {
                result["version"] = json!(script[2]);
            }
        } else {
            findings.push(format!(
                "shell program absent from script roster: {identity}"
            ));
        }
    }

    for field in ["version", "release_group"] {
        if result[field].as_str().is_none_or(str::is_empty) {
            findings.push(format!("program {identity} lacks {field}"));
        }
    }
    if let Some(version) = result["version"].as_str() {
        let parts: Vec<_> = version.split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || part.bytes().any(|byte| !byte.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
            })
        {
            findings.push(format!(
                "program {identity} has an invalid release version: {version}"
            ));
        }
    }
    Ok(result)
}

pub fn check(
    root: &Path,
    ledger: &[Value],
    metadata: &Value,
    findings: &mut Vec<String>,
) -> Result<Vec<Value>> {
    let source = fs::read_to_string(root.join("meson.build")).map_err(|error| error.to_string())?;
    let mut expected = BTreeMap::new();
    for row in table(&source, "rust_version_roster", 2)? {
        if expected.insert(row[0].clone(), row[1].clone()).is_some() {
            findings.push(format!("duplicate Rust version identity: {}", row[0]));
        }
    }
    for row in table(&source, "script_version_roster", 4)? {
        if expected
            .insert(
                row[0].clone(),
                format!("versioned-{}", row[0].replace('/', "-")),
            )
            .is_some()
        {
            findings.push(format!("duplicate script version identity: {}", row[0]));
        }
    }
    let mut binaries = BTreeSet::new();
    let members = metadata["workspace_members"]
        .as_array()
        .ok_or("metadata members missing")?;
    for package in metadata["packages"]
        .as_array()
        .ok_or("metadata packages missing")?
    {
        if !members.contains(&package["id"]) {
            continue;
        }
        for target in package["targets"]
            .as_array()
            .ok_or("metadata targets missing")?
        {
            if target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
            {
                binaries.insert((
                    package["name"]
                        .as_str()
                        .ok_or("package name missing")?
                        .to_owned(),
                    target["name"]
                        .as_str()
                        .ok_or("target name missing")?
                        .to_owned(),
                ));
            }
        }
    }
    let mut result = Vec::new();
    for row in ledger.iter().filter(|row| row["kind"] == "program") {
        let identity = row["identity"].as_str().ok_or("program identity missing")?;
        let output = row["output"].as_str().ok_or("program output missing")?;
        if expected.remove(identity).as_deref() != Some(output) {
            findings.push(format!("program differs from version roster: {identity}"));
        }
        let package = row["package"].as_str().ok_or("program package missing")?;
        if row["form"] == "rust" {
            let binary = row["cargo_binary"]
                .as_str()
                .ok_or("program Cargo target missing")?;
            if !binaries.remove(&(package.to_owned(), binary.to_owned())) {
                findings.push(format!(
                    "program Cargo target missing or duplicated: {identity}"
                ));
            }
        }
        result.push(versioned(root, &source, row, findings)?);
    }
    findings.extend(
        expected
            .keys()
            .map(|name| format!("unaccounted version identity: {name}")),
    );
    findings.extend(
        binaries
            .iter()
            .map(|(package, name)| format!("unaccounted Cargo binary: {package}/{name}")),
    );
    let mut groups = BTreeMap::new();
    for row in &result {
        let group = row["release_group"]
            .as_str()
            .ok_or("program group missing")?;
        let version_authority = (&row["version"], &row["version_authority"]);
        if let Some(previous) = groups.insert(group, version_authority)
            && previous != version_authority
        {
            findings.push(format!(
                "incompatible version authorities in release group: {group}"
            ));
        }
    }
    Ok(result)
}
