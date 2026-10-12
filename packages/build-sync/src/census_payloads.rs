//! Enumerate non-Rust executable sources and unit inputs without ignoring fixtures.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn visit(root: &Path, directory: &Path, output: &mut Vec<Value>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| error.to_string())?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            if entry.file_name() != "target" && entry.file_name() != ".git" {
                visit(root, &path, output)?;
            }
        } else if kind.is_file() {
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            let extension = path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            let template_extension = path
                .file_stem()
                .and_then(|stem| Path::new(stem).extension())
                .and_then(std::ffi::OsStr::to_str);
            let form = match extension {
                "py" => Some("python"),
                "sh" => Some("shell"),
                "service" | "timer" | "path" => Some("unit"),
                "in" if matches!(template_extension, Some("service" | "timer" | "path")) => {
                    Some("unit-template")
                }
                _ if bytes.starts_with(b"#!") && !bytes.starts_with(b"#![") => Some("script"),
                _ => None,
            };
            if let Some(form) = form {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_str()
                    .ok_or("non-UTF-8 payload path")?;
                output.push(json!({"path":relative,"form":form,"sha256":crate::digest(&bytes)}));
            }
        }
    }
    Ok(())
}

pub fn inventory(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut sources = Vec::new();
    for directory in ["packages", "bin", "ci", "hooks", "infra", "tests", "units"] {
        let path = root.join(directory);
        if path.exists() {
            visit(root, &path, &mut sources)?;
        }
    }
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "payload") {
        let path = row["path"].as_str().ok_or("payload path missing")?;
        if !crate::census::expects_source(root, path)? {
            continue;
        }
        if declared.insert(path.to_owned(), row).is_some() {
            findings.push(format!("duplicate payload declaration: {path}"));
        }
    }
    for source in &sources {
        let path = source["path"]
            .as_str()
            .ok_or("payload source path missing")?;
        if let Some(row) = declared.remove(path) {
            if row["sha256"] != source["sha256"] || row["form"] != source["form"] {
                findings.push(format!("payload differs from its reviewed source: {path}"));
            }
            for field in [
                "owner",
                "interpreter",
                "execution_host",
                "version_authority",
                "contract",
            ] {
                if row[field].as_str().is_none_or(str::is_empty) {
                    findings.push(format!("payload {path} lacks {field}"));
                }
            }
            calls(root, row, ledger, findings)?;
        } else {
            findings.push(format!("unaccounted executable payload: {path}"));
        }
    }
    findings.extend(
        declared
            .keys()
            .map(|path| format!("stale payload declaration: {path}")),
    );
    Ok(sources)
}

fn calls(root: &Path, row: &Value, ledger: &[Value], findings: &mut Vec<String>) -> Result<()> {
    let path = row["path"].as_str().ok_or("payload path missing")?;
    let Some(calls) = row["calls"].as_array() else {
        findings.push(format!("payload outgoing calls not reviewed: {path}"));
        return Ok(());
    };
    let source = fs::read_to_string(root.join(path)).map_err(|error| error.to_string())?;
    for call in calls {
        for field in ["callee", "selector", "lookup", "contract", "anchor"] {
            if call[field].as_str().is_none_or(str::is_empty) {
                findings.push(format!("payload call {path} lacks {field}"));
            }
        }
        if let Some(anchor) = call["anchor"].as_str()
            && !source.contains(anchor)
        {
            findings.push(format!(
                "payload call source anchor missing: {path}: {anchor}"
            ));
        }
        if !ledger.iter().any(|target| {
            (target["kind"] == "program" || target["kind"] == "external-program")
                && target["identity"] == call["callee"]
        }) {
            findings.push(format!(
                "payload call has unregistered executable: {path}: {}",
                call["callee"]
            ));
        }
        if ![
            "public-command",
            "private-exact-path",
            "configured-external",
            "unit-install-path",
            "test-executable",
        ]
        .contains(&call["lookup"].as_str().unwrap_or_default())
        {
            findings.push(format!("payload call has unknown lookup class: {path}"));
        }
    }
    Ok(())
}
