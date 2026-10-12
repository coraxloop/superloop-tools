// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Audit Meson's explicit path lists against the tracked-exclusive corpus.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{BytePath, ExecutionPlan, Finding};

/// One actionable difference between Meson's graph and the checkout.
#[derive(Debug, Serialize)]
pub struct MesonCensusRefusal {
    pub code: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl fmt::Display for MesonCensusRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.path)?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

/// The graph audit's stable, machine-readable result.
#[derive(Debug, Serialize)]
pub struct MesonCensusReport {
    pub tracked: usize,
    pub declared: usize,
    pub excluded: usize,
    pub pattern_matched: usize,
    pub failures: usize,
    pub clean: bool,
    pub refusals: Vec<MesonCensusRefusal>,
}

fn refusal(code: &'static str, path: &BytePath, detail: Option<String>) -> MesonCensusRefusal {
    MesonCensusRefusal {
        code,
        path: path.display(),
        detail,
    }
}

fn read_paths(file: &Path) -> Result<Vec<BytePath>, String> {
    let contents =
        fs::read_to_string(file).map_err(|error| format!("{}: {error}", file.display()))?;
    contents
        .lines()
        .map(|line| {
            BytePath::from_bytes(line.as_bytes().to_vec())
                .map_err(|error| format!("{}: {line}: {error}", file.display()))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredList {
    #[serde(rename = "version")]
    _version: [u64; 3],
    paths: Vec<RequiredPath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredPath {
    path: String,
    #[serde(rename = "purpose")]
    _purpose: String,
    required: bool,
    #[serde(rename = "template")]
    _template: bool,
}

fn read_required_list(file: &Path) -> Result<RequiredList, String> {
    let contents = fs::read_to_string(file).map_err(|error| error.to_string())?;
    toml::from_str(&contents).map_err(|error| error.to_string())
}

fn required_refusals(
    root: &Path,
    file: &Path,
    modes: &[(BytePath, String)],
) -> Vec<MesonCensusRefusal> {
    let list = match read_required_list(file) {
        Ok(list) => list,
        Err(detail) => {
            return vec![MesonCensusRefusal {
                code: "invalid_required_list",
                path: file.display().to_string(),
                detail: Some(detail),
            }];
        }
    };
    let regular: BTreeSet<_> = modes
        .iter()
        .filter(|(path, mode)| {
            (mode.as_str() == "100644" || mode.as_str() == "100755")
                && crate::pattern::native_path(path).is_some_and(|native| {
                    fs::symlink_metadata(root.join(native))
                        .is_ok_and(|metadata| metadata.file_type().is_file())
                })
        })
        .map(|(path, _)| path.as_bytes())
        .collect();
    let mut refusals = Vec::new();
    for row in list.paths.into_iter().filter(|row| row.required) {
        let path = row.path;
        if path.contains('*') {
            let basename = path.rsplit('/').next().unwrap_or(&path);
            if path.matches('*').count() != 1 || !basename.contains('*') {
                refusals.push(MesonCensusRefusal {
                    code: "invalid_required_pattern",
                    path,
                    detail: None,
                });
                continue;
            }
            let mut parts = path.split('*');
            let prefix = parts.next().unwrap_or("");
            let suffix = parts.next().unwrap_or("");
            if !regular.iter().any(|file| {
                file.strip_prefix(prefix.as_bytes())
                    .and_then(|middle| middle.strip_suffix(suffix.as_bytes()))
                    .is_some_and(|middle| !middle.contains(&b'/'))
            }) {
                refusals.push(MesonCensusRefusal {
                    code: "unmatched_required_pattern",
                    path,
                    detail: None,
                });
            }
        } else if path.ends_with('/') {
            if !regular.iter().any(|file| file.starts_with(path.as_bytes())) {
                refusals.push(MesonCensusRefusal {
                    code: "missing_required_path",
                    path,
                    detail: None,
                });
            }
        } else if !regular.contains(path.as_bytes()) {
            refusals.push(MesonCensusRefusal {
                code: "missing_required_path",
                path,
                detail: None,
            });
        }
    }
    refusals
}

fn tracked_modes(root: &Path) -> Result<Vec<(BytePath, String)>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--stage", "-z"])
        .output()
        .map_err(|error| format!("git ls-files --stage: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files --stage: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let mut parts = record.splitn(2, |byte| *byte == b'\t');
            let metadata = parts
                .next()
                .ok_or_else(|| String::from("git ls-files --stage: malformed record"))?;
            let path = parts
                .next()
                .ok_or_else(|| String::from("git ls-files --stage: malformed record"))?;
            let mode = metadata
                .split(|byte| *byte == b' ')
                .next()
                .ok_or_else(|| String::from("git ls-files --stage: mode absent"))?;
            let mode = std::str::from_utf8(mode)
                .map_err(|error| format!("git ls-files --stage: {error}"))?;
            let path = BytePath::from_bytes(path.to_vec())
                .map_err(|error| format!("git ls-files --stage: {error}"))?;
            Ok((path, mode.to_owned()))
        })
        .collect()
}

/// Compare the declared graph with the tracked-exclusive universe and index modes.
///
/// # Errors
///
/// Returns an error when an input list, regex, or Git metadata cannot be read.
pub fn audit_meson_census(
    plan: &ExecutionPlan,
    declared_file: &Path,
    excluded_file: &Path,
    pattern: &str,
    required_file: Option<&Path>,
) -> Result<MesonCensusReport, String> {
    let declared = read_paths(declared_file)?;
    let excluded = read_paths(excluded_file)?;
    let pattern = Regex::new(pattern).map_err(|error| error.to_string())?;
    let corpus = plan.topology().corpus();
    let tracked: BTreeSet<_> = corpus.base().iter().cloned().collect();
    let mut refusals = Vec::new();
    let mut declared_set = BTreeSet::new();
    let excluded_set: BTreeSet<_> = excluded.iter().cloned().collect();

    for path in &declared {
        if !declared_set.insert(path.clone()) {
            refusals.push(refusal("duplicate_declared_path", path, None));
        }
        if !tracked.contains(path) {
            refusals.push(refusal("stale_declared_path", path, None));
        }
        if pattern.is_match(&path.display()) {
            refusals.push(refusal("declared_pattern_overlap", path, None));
        }
    }
    for path in &excluded_set {
        if !tracked.contains(path) {
            refusals.push(refusal("stale_excluded_path", path, None));
        }
    }

    let mut pattern_matched = 0;
    for path in &tracked {
        if pattern.is_match(&path.display()) {
            pattern_matched += 1;
        } else if !declared_set.contains(path) && !excluded_set.contains(path) {
            refusals.push(refusal("missing_path", path, None));
        }
    }

    for finding in corpus.findings() {
        match finding {
            Finding::UntrackedPath { path } => refusals.push(MesonCensusRefusal {
                code: "untracked_path",
                path: path.clone(),
                detail: None,
            }),
            Finding::MissingTrackedPath { path } => refusals.push(MesonCensusRefusal {
                code: "missing_tracked_path",
                path: path.clone(),
                detail: None,
            }),
            Finding::TraversalFailure { path, message } => refusals.push(MesonCensusRefusal {
                code: "traversal_failure",
                path: path.clone(),
                detail: Some(message.clone()),
            }),
            _ => {}
        }
    }

    let modes = tracked_modes(plan.root())?;
    for (path, mode) in &modes {
        if mode.as_str() != "100644" && mode.as_str() != "100755" {
            refusals.push(refusal("invalid_tracked_mode", path, Some(mode.clone())));
        }
    }

    if let Some(file) = required_file {
        refusals.extend(required_refusals(plan.root(), file, &modes));
    }

    refusals.sort_by(|left, right| (&left.path, left.code).cmp(&(&right.path, right.code)));
    let failures = refusals.len();
    Ok(MesonCensusReport {
        tracked: tracked.len(),
        declared: declared.len(),
        excluded: excluded.len(),
        pattern_matched,
        failures,
        clean: failures == 0,
        refusals,
    })
}
