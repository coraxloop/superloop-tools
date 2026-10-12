//! Bounded migration rewrites; previews expose field names and digests, not account JSON.

use super::Result;
use serde_json::{Value, json};
use std::path::Path;

pub(super) fn spellings(owner: &Path, name: &str, vendor: &str) -> Vec<String> {
    let relative = if vendor == "previous" {
        format!(".claude-{name}")
    } else {
        format!(".config/loops/{name}/claude")
    };
    let mut owners = vec![owner.to_path_buf()];
    if let Ok(canonical) = std::fs::canonicalize(owner) {
        owners.push(canonical);
    }
    if let Some(user) = owner.file_name() {
        owners.push(Path::new("/home").join(user));
    }
    let mut paths = owners
        .iter()
        .map(|owner| owner.join(&relative).to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    paths.extend([
        format!("~/{relative}"),
        format!("$HOME/{relative}"),
        format!("${{HOME}}/{relative}"),
    ]);
    paths.sort();
    paths.dedup();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    paths
}

fn replace(value: &str, old: &[String], destination: &str) -> String {
    let mut result = value.to_owned();
    for spelling in old {
        let mut next = String::new();
        let mut rest = result.as_str();
        while let Some(offset) = rest.find(spelling) {
            let (prefix, matched) = rest.split_at(offset);
            let suffix = &matched[spelling.len()..];
            next.push_str(prefix);
            if suffix.chars().next().is_none_or(|c| {
                c == '/' || c.is_whitespace() || matches!(c, '\'' | '"' | ')' | '\\')
            }) {
                next.push_str(destination);
            } else {
                next.push_str(spelling);
            }
            rest = suffix;
        }
        next.push_str(rest);
        result = next;
    }
    result
}

fn settings(value: &mut Value, old: &[String], destination: &str) -> Result<Vec<Value>> {
    let mut changes = Vec::new();
    for pointer in ["/permissions/allow", "/sandbox/excludedCommands"] {
        let Some(entries) = value.pointer_mut(pointer) else {
            continue;
        };
        let entries = entries
            .as_array_mut()
            .ok_or("claude-home-move-json: settings array required")?;
        for (index, entry) in entries.iter_mut().enumerate() {
            let source = entry
                .as_str()
                .ok_or("claude-home-move-json: settings string required")?;
            let after = replace(source, old, destination);
            if after != source {
                changes.push(json!({"key":format!("{pointer}/{index}")}));
                *entry = Value::String(after);
            }
        }
    }
    Ok(changes)
}

fn projects(value: &mut Value, old: &[String], destination: &str) -> Result<Vec<Value>> {
    let Some(projects) = value.get_mut("projects") else {
        return Ok(Vec::new());
    };
    let projects = projects
        .as_object_mut()
        .ok_or("claude-home-move-json: projects object required")?;
    let mut changes = Vec::new();
    let mut renamed = serde_json::Map::new();
    for (key, value) in projects.iter() {
        let after = replace(key, old, destination);
        if after != *key {
            changes.push(json!({"project_key":key,"after_key":after}));
        }
        if renamed.insert(after, value.clone()).is_some() {
            return Err("claude-home-move-json: project-key collision".into());
        }
    }
    *projects = renamed;
    Ok(changes)
}

pub(super) fn rewrite(
    name: &str,
    bytes: &[u8],
    old: &[String],
    destination: &str,
) -> Result<(Vec<u8>, Vec<Value>)> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| format!("claude-home-move-encoding: {name}"))?;
    let (after, changes) = if name == "ssh_config" {
        let mut result = String::new();
        let mut changes = Vec::new();
        for (index, line) in text.split_inclusive('\n').enumerate() {
            let words = super::reconcile::words(line)?;
            let owned = words.first().is_some_and(|word| {
                matches!(
                    word.to_ascii_lowercase().as_str(),
                    "identityfile" | "userknownhostsfile" | "globalknownhostsfile"
                )
            });
            let after = if owned {
                replace(line, old, destination)
            } else {
                line.to_owned()
            };
            if after != line {
                changes.push(json!({"line":index + 1,"option":words[0]}));
            }
            result.push_str(&after);
        }
        (result, changes)
    } else {
        let mut value: Value =
            serde_json::from_slice(bytes).map_err(|_| format!("claude-home-move-json: {name}"))?;
        let changes = if name == "settings.json" {
            settings(&mut value, old, destination)?
        } else {
            projects(&mut value, old, destination)?
        };
        let after = if changes.is_empty() {
            text.to_owned()
        } else {
            format!(
                "{}\n",
                serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
            )
        };
        (after, changes)
    };
    if old.iter().any(|path| after.contains(path)) {
        return Err(format!("claude-home-old-path-remains: {name}"));
    }
    Ok((after.into_bytes(), changes))
}
