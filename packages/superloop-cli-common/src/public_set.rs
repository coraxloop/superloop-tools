//! The versioned publication selection, shared by the cut and repository check.

use serde::{Deserialize, Serialize};

/// Read Git's complete tracked set, without treating ignored paths as exclusions.
///
/// # Errors
/// Returns a diagnostic if Git fails or a tracked filename is not UTF-8.
pub fn tracked_paths(root: &std::path::Path) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "-z", "--cached"])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("cannot enumerate tracked public-set paths".into());
    }
    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| {
            String::from_utf8(part.to_vec()).map_err(|_| "non-UTF-8 tracked path".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// One strict publication declaration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    namespace: String,
    version: [u64; 3],
    include: Rows,
    exclude: Rows,
    #[serde(default)]
    reserved: Rows,
    pub public: Public,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rows {
    rows: Vec<Row>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    pattern: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    reserved: bool,
}

/// Public repository name and source-relative tree entry points.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub name: String,
    pub readme: String,
    pub licence_code: String,
    pub licence_docs: String,
}

/// Measured classification of the complete tracked set.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Selection {
    pub tracked: usize,
    pub included: Vec<String>,
    pub excluded: usize,
    pub issues: Vec<String>,
}

impl Manifest {
    /// The source-side exclusion selector classifying a path, if there is one.
    #[must_use]
    pub fn excluded_class(&self, path: &str) -> Option<&str> {
        self.rows().find_map(|(row, excluded, _)| {
            (excluded && matches_path(&row.pattern, path)).then_some(row.pattern.as_str())
        })
    }
    /// Decode a declaration without accepting unknown fields or unsafe paths.
    ///
    /// # Errors
    /// Returns the parse or schema defect, including an invalid selector.
    pub fn parse(text: &str) -> Result<Self, String> {
        let manifest: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        if manifest.namespace != "org.superloop-tools.public-set" || manifest.version != [1, 0, 0] {
            return Err("public-set requires namespace org.superloop-tools.public-set and version [1, 0, 0]".into());
        }
        for (row, excluded, _) in manifest.rows() {
            if !safe_path(row.pattern.trim_end_matches('/'))
                || row.pattern.contains("**")
                || row.pattern.contains(['[', ']', '\\'])
                || (excluded && row.reason.trim().is_empty())
            {
                return Err(format!(
                    "invalid public-set row: {} (exclusions require a reason)",
                    row.pattern
                ));
            }
        }
        if !safe_path(&manifest.public.readme)
            || manifest.public.readme.contains(['*', '?'])
            || !safe_path(&manifest.public.licence_code)
            || manifest.public.licence_code.contains(['*', '?'])
            || !safe_path(&manifest.public.licence_docs)
            || manifest.public.licence_docs.contains(['*', '?'])
            || manifest.public.licence_code == manifest.public.licence_docs
        {
            return Err(
                "public-set requires a relative README source and distinct relative licence_code and licence_docs paths".into(),
            );
        }
        Ok(manifest)
    }

    fn rows(&self) -> impl Iterator<Item = (&Row, bool, bool)> {
        self.include
            .rows
            .iter()
            .map(|row| (row, false, row.reserved))
            .chain(
                self.exclude
                    .rows
                    .iter()
                    .map(|row| (row, true, row.reserved)),
            )
            .chain(self.reserved.rows.iter().map(|row| (row, true, true)))
    }

    /// Classify every tracked path once, and account for every live row.
    #[must_use]
    pub fn select(&self, paths: &[String]) -> Selection {
        let rows: Vec<_> = self.rows().collect();
        let mut hits = vec![0_usize; rows.len()];
        let mut selection = Selection {
            tracked: paths.len(),
            ..Selection::default()
        };
        for path in paths {
            if !safe_path(path) {
                selection
                    .issues
                    .push(format!("unsafe tracked path: {path}"));
                continue;
            }
            let mut matched = Vec::new();
            for (index, (row, excluded, _)) in rows.iter().enumerate() {
                if matches_path(&row.pattern, path) {
                    hits[index] += 1;
                    matched.push(*excluded);
                }
            }
            match matched.as_slice() {
                [false] => selection.included.push(path.clone()),
                [true] => selection.excluded += 1,
                [] => selection
                    .issues
                    .push(format!("unclassified tracked file: {path}")),
                _ => selection
                    .issues
                    .push(format!("multiply classified tracked file: {path}")),
            }
        }
        for ((row, _, reserved), count) in rows.iter().zip(hits) {
            if count == 0 && !reserved {
                selection
                    .issues
                    .push(format!("dead manifest row: {}", row.pattern));
            }
        }
        selection.included.sort();
        selection.issues.sort();
        selection
    }
}

/// Whether a tracked path stays below the repository and outside Git metadata.
#[must_use]
pub fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\0', '\n', '\r', '\\'])
        && path.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.eq_ignore_ascii_case(".git")
        })
}

fn matches_path(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('/') {
        return path.starts_with(pattern);
    }
    let mut parts = path.split('/');
    pattern.split('/').all(|pattern| {
        parts
            .next()
            .is_some_and(|part| glob_component(pattern.as_bytes(), part.as_bytes()))
    }) && parts.next().is_none()
}

fn glob_component(pattern: &[u8], text: &[u8]) -> bool {
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for byte in pattern {
        let mut next = vec![false; text.len() + 1];
        if *byte == b'*' {
            next[0] = previous[0];
        }
        for (index, value) in text.iter().enumerate() {
            next[index + 1] = if *byte == b'*' {
                previous[index + 1] || next[index]
            } else {
                previous[index] && (*byte == b'?' || byte == value)
            };
        }
        previous = next;
    }
    previous[text.len()]
}
