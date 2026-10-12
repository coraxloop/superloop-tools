//! The loop registry: one `*.env` file per loop naming the loop and the
//! working directory its sessions are recorded under.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

/// Reads every `*.env` file of a registry directory, in name order, and maps
/// each `LOOP_NAME` to its `LOOP_CWD`; a file without both is skipped and a
/// later file wins a repeated name.
///
/// # Errors
///
/// Returns the error of a directory or file that cannot be read.
pub fn read_registry(directory: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "env") && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    let mut loops = BTreeMap::new();
    for path in files {
        let text = fs::read_to_string(&path)?;
        let values = parse_env(&text);
        if let (Some(name), Some(cwd)) = (values.get("LOOP_NAME"), values.get("LOOP_CWD"))
            && !name.is_empty()
            && !cwd.is_empty()
        {
            loops.insert(name.clone(), cwd.clone());
        }
    }
    Ok(loops)
}

/// Parses `KEY=VALUE` lines, skipping comments and lines without `=`, and
/// trims whitespace and surrounding quote characters from each value.
#[must_use]
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            (
                key.trim().to_owned(),
                value.trim().trim_matches(['"', '\'']).to_owned(),
            )
        })
        .collect()
}

/// The harness's project directory name for a working directory: every
/// character other than an ASCII letter or digit becomes `-`.
#[must_use]
pub fn project_slug(cwd: &str) -> String {
    cwd.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}
