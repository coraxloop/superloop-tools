//! Account for cross-package Rust source inclusion outside Cargo edges.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::str::FromStr as _;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn references(stream: TokenStream, output: &mut Vec<String>) -> Result<()> {
    let tokens: Vec<_> = stream.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        if let TokenTree::Group(group) = token {
            let fields: Vec<_> = group.stream().into_iter().collect();
            let literal = if group.delimiter() == Delimiter::Bracket
                && fields.len() == 3
                && fields[0].to_string() == "path"
                && fields[1].to_string() == "="
            {
                Some(&fields[2])
            } else if group.delimiter() == Delimiter::Parenthesis
                && index >= 2
                && tokens[index - 2].to_string() == "include"
                && tokens[index - 1].to_string() == "!"
            {
                fields.first()
            } else {
                None
            };
            if let Some(literal) = literal {
                let path: String = serde_json::from_str(&literal.to_string()).map_err(|error| {
                    format!("source inclusion requires a literal path: {error}")
                })?;
                output.push(path);
            }
            references(group.stream(), output)?;
        }
    }
    Ok(())
}

fn visit(root: &Path, directory: &Path, output: &mut Vec<Value>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| error.to_string())?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() && entry.file_name() != "target" {
            visit(root, &path, output)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).map_err(|error| error.to_string())?;
            let mut paths = Vec::new();
            references(
                TokenStream::from_str(&source).map_err(|error| error.to_string())?,
                &mut paths,
            )?;
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("non-UTF-8 source")?;
            let package = relative.split('/').nth(1).ok_or("source package missing")?;
            for included in paths {
                // Only a parent traversal or absolute path can cross a package boundary.
                if !included.contains("..") && !Path::new(&included).is_absolute() {
                    continue;
                }
                let resolved = path
                    .parent()
                    .ok_or("source parent missing")?
                    .join(&included)
                    .canonicalize()
                    .map_err(|error| format!("source inclusion {relative}: {error}"))?;
                let target = resolved
                    .strip_prefix(root)
                    .map_err(|_| format!("source inclusion leaves repository: {relative}"))?
                    .to_str()
                    .ok_or("non-UTF-8 inclusion")?;
                let target_package = target
                    .strip_prefix("packages/")
                    .and_then(|path| path.split('/').next())
                    .ok_or("source inclusion outside workspace packages")?;
                if target_package != package {
                    output.push(json!({"source":package,"target":target_package,"path":relative,"included":target}));
                }
            }
        }
    }
    Ok(())
}

pub fn check(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut measured = Vec::new();
    visit(root, &root.join("packages"), &mut measured)?;
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "source-import") {
        let key = format!("{}:{}", row["path"], row["included"]);
        if declared.insert(key.clone(), row).is_some() {
            findings.push(format!("duplicate source import: {key}"));
        }
    }
    for actual in &measured {
        let key = format!("{}:{}", actual["path"], actual["included"]);
        if let Some(row) = declared.remove(&key) {
            if row["source"] != actual["source"] || row["target"] != actual["target"] {
                findings.push(format!("source import package mismatch: {key}"));
            }
            let tier = |name: &Value| {
                ledger
                    .iter()
                    .find(|row| row["kind"] == "package" && row["name"] == *name)
                    .and_then(|row| row["tier"].as_u64())
            };
            match (tier(&actual["source"]), tier(&actual["target"])) {
                (Some(from), Some(to)) if to < from && (from != 3 || to <= 1) => {}
                _ => findings.push(format!("source inclusion violates downward rule: {key}")),
            }
        } else {
            findings.push(format!("unaccounted source import: {key}"));
        }
    }
    findings.extend(
        declared
            .keys()
            .map(|key| format!("stale source import: {key}")),
    );
    Ok(measured)
}
