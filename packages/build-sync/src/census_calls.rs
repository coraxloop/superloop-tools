//! Inventory Rust process constructors without interpreting strings as Rust.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr as _;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn command_names(stream: TokenStream, names: &mut BTreeSet<String>) {
    let tokens: Vec<_> = stream.into_iter().collect();
    for window in tokens.windows(3) {
        if window[0].to_string() == "Command" && window[1].to_string() == "as" {
            names.insert(window[2].to_string());
        }
    }
    for token in tokens {
        if let TokenTree::Group(group) = token {
            command_names(group.stream(), names);
        }
    }
}

fn tokens(stream: TokenStream, path: &str, names: &BTreeSet<String>, output: &mut Vec<Value>) {
    let stream: Vec<_> = stream.into_iter().collect();
    for (index, token) in stream.iter().enumerate() {
        if let TokenTree::Group(arguments) = token {
            if arguments.delimiter() == Delimiter::Parenthesis && index >= 4 {
                let prefix = &stream[index - 4..index];
                if (prefix[0].to_string().ends_with("Command")
                    || names.contains(&prefix[0].to_string()))
                    && prefix[1].to_string() == ":"
                    && prefix[2].to_string() == ":"
                    && prefix[3].to_string() == "new"
                {
                    output.push(json!({"path":path,"line":arguments.span().start().line,
                        "form":"rust-process-constructor","selector":arguments.stream().to_string()}));
                }
            }
            if arguments.delimiter() == Delimiter::Parenthesis
                && index >= 1
                && [
                    "execl",
                    "execlp",
                    "execle",
                    "execv",
                    "execvp",
                    "execve",
                    "execvpe",
                    "posix_spawn",
                    "posix_spawnp",
                ]
                .contains(&stream[index - 1].to_string().as_str())
            {
                output.push(json!({"path":path,"line":arguments.span().start().line,
                    "form":"native-process-exec","selector":arguments.stream().to_string()}));
            }
            tokens(arguments.stream(), path, names, output);
        }
    }
}

fn directory(root: &Path, current: &Path, output: &mut Vec<Value>) -> Result<()> {
    let mut entries = fs::read_dir(current)
        .map_err(|error| format!("{}: {error}", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            if entry.file_name() != "target" {
                directory(root, &path, output)?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("non-UTF-8 source path")?;
            let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            let parsed =
                TokenStream::from_str(&source).map_err(|error| format!("{relative}: {error}"))?;
            let mut names = BTreeSet::new();
            command_names(parsed.clone(), &mut names);
            tokens(parsed, relative, &names, output);
        }
    }
    Ok(())
}

pub fn inventory(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut sites = Vec::new();
    directory(root, &root.join("packages"), &mut sites)?;
    let mut occurrence = BTreeMap::new();
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "call") {
        let key = row["site"].as_str().ok_or("call site identity missing")?;
        if declared.insert(key.to_owned(), row).is_some() {
            findings.push(format!("duplicate call site declaration: {key}"));
        }
    }
    for site in &mut sites {
        let key = format!(
            "{}:{}",
            site["path"].as_str().ok_or("site path missing")?,
            site["selector"].as_str().ok_or("site selector missing")?
        );
        let count = occurrence.entry(key.clone()).or_insert(0_u64);
        *count += 1;
        let key = format!("{key}#{count}");
        site["site"] = json!(key);
        if let Some(row) = declared.remove(&key) {
            for field in ["caller", "callee", "lookup", "contract", "owner"] {
                if row[field].as_str().is_none_or(str::is_empty) {
                    findings.push(format!("call {key} lacks {field}"));
                }
            }
            if ![
                "public-command",
                "private-exact-path",
                "configured-external",
                "unit-install-path",
                "test-executable",
            ]
            .contains(&row["lookup"].as_str().unwrap_or_default())
            {
                findings.push(format!("call {key} has an unknown lookup class"));
            }
            if !ledger.iter().any(|target| {
                (target["kind"] == "program" || target["kind"] == "external-program")
                    && target["identity"] == row["callee"]
            }) {
                findings.push(format!("call {key} has an unregistered executable"));
            }
        } else {
            findings.push(format!("unaccounted executable call: {key}"));
        }
    }
    findings.extend(
        declared
            .keys()
            .map(|key| format!("stale executable call: {key}")),
    );
    reverse_callers(ledger, findings)?;
    Ok(sites)
}

fn reverse_callers(ledger: &[Value], findings: &mut Vec<String>) -> Result<()> {
    for target in ledger
        .iter()
        .filter(|row| row["kind"] == "program" || row["kind"] == "external-program")
    {
        let mut callers: std::collections::BTreeSet<_> = ledger
            .iter()
            .filter(|row| {
                (row["kind"] == "call" || row["kind"] == "delegated-call")
                    && row["callee"] == target["identity"]
            })
            .filter_map(|row| row["caller"].as_str())
            .collect();
        for payload in ledger.iter().filter(|row| row["kind"] == "payload") {
            if payload["calls"].as_array().is_some_and(|calls| {
                calls
                    .iter()
                    .any(|call| call["callee"] == target["identity"])
            }) {
                callers.insert(payload["owner"].as_str().ok_or("payload owner missing")?);
            }
        }
        for build_call in ledger.iter().filter(|row| row["kind"] == "meson-call") {
            if build_call["callees"]
                .as_array()
                .is_some_and(|callees| callees.contains(&target["identity"]))
            {
                callers.insert(
                    build_call["caller"]
                        .as_str()
                        .ok_or("Meson caller missing")?,
                );
            }
        }
        let declared: std::collections::BTreeSet<_> = target["callers"]
            .as_array()
            .ok_or("target callers must be an explicit array")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if callers != declared {
            findings.push(format!("reverse callers differ for {}", target["identity"]));
        }
    }
    Ok(())
}

/// Check commands passed through a transport, container engine or generated service unit.
pub fn delegated(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut identities = BTreeSet::new();
    let mut result = Vec::new();
    for row in ledger.iter().filter(|row| row["kind"] == "delegated-call") {
        let identity = row["identity"]
            .as_str()
            .ok_or("delegated call identity missing")?;
        if !identities.insert(identity) {
            findings.push(format!("duplicate delegated call: {identity}"));
        }
        for field in [
            "caller",
            "callee",
            "selector",
            "lookup",
            "contract",
            "execution_host",
            "path",
            "anchor",
        ] {
            if row[field].as_str().is_none_or(str::is_empty) {
                findings.push(format!("delegated call {identity} lacks {field}"));
            }
        }
        let relative = row["path"].as_str().ok_or("delegated call path missing")?;
        if Path::new(relative)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "delegated call path must be repository-relative: {relative}"
            ));
        }
        let source = fs::read_to_string(root.join(relative)).map_err(|error| error.to_string())?;
        if row["anchor"]
            .as_str()
            .is_none_or(|anchor| anchor.is_empty() || !source.contains(anchor))
        {
            findings.push(format!(
                "delegated call has stale source anchor: {identity}"
            ));
        }
        if !ledger.iter().any(|target| {
            (target["kind"] == "program" || target["kind"] == "external-program")
                && target["identity"] == row["callee"]
        }) {
            findings.push(format!(
                "delegated call has unregistered executable: {identity}"
            ));
        }
        if ![
            "public-command",
            "private-exact-path",
            "configured-external",
            "unit-install-path",
            "test-executable",
        ]
        .contains(&row["lookup"].as_str().unwrap_or_default())
        {
            findings.push(format!(
                "delegated call has unknown lookup class: {identity}"
            ));
        }
        result.push(row.clone());
    }
    Ok(result)
}
