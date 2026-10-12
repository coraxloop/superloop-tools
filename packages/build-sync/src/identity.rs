//! Resolve build provenance from the same program declarations used by the census.

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

/// Explicit source and configured-ledger inputs to a build record.
pub struct IdentityArgs<'a> {
    pub ledger: &'a Path,
    pub root: &'a Path,
    pub repository: &'a str,
    pub source_commit: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Identity {
    #[serde(skip)]
    pub package: String,
    pub installed_name: String,
    pub release_group: String,
    pub repository: String,
    pub source_commit: String,
    pub version: String,
}

fn text(row: &Value, key: &str) -> Result<String, String> {
    row[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("build identity lacks {key}"))
}

pub(crate) fn resolve(
    args: &IdentityArgs<'_>,
    output: &Path,
    package: Option<&str>,
) -> Result<Identity, String> {
    if args.repository.trim().is_empty()
        || ![40, 64].contains(&args.source_commit.len())
        || !args
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "build record requires a repository identity and full lowercase source commit".into(),
        );
    }
    let ledger = args
        .ledger
        .canonicalize()
        .map_err(|error| format!("build identity ledger: {error}"))?;
    let build = ledger
        .parent()
        .ok_or("build identity ledger has no parent")?;
    let output = std::path::absolute(output).map_err(|error| error.to_string())?;
    let parent = output
        .parent()
        .ok_or("build output has no parent")?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let output = parent.join(output.file_name().ok_or("build output has no filename")?);
    let relative = output
        .strip_prefix(build)
        .map_err(|_| "build output is outside its configured ledger directory")?;
    let source = fs::read_to_string(&ledger).map_err(|error| error.to_string())?;
    let rows: Vec<Value> = source
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("build identity ledger: {error}"))?;
    let programs: Vec<_> = rows
        .iter()
        .filter(|row| {
            row["kind"] == "program" && row["output"].as_str().map(Path::new) == Some(relative)
        })
        .collect();
    if programs.len() != 1 {
        return Err(format!(
            "build output needs exactly one program identity: {}",
            relative.display()
        ));
    }
    let program = programs[0];
    if package.is_some_and(|package| program["package"] != package) {
        return Err("build output package differs from its program identity".into());
    }
    let meson =
        fs::read_to_string(args.root.join("meson.build")).map_err(|error| error.to_string())?;
    let mut findings = Vec::new();
    let program = crate::census_programs::versioned(args.root, &meson, program, &mut findings)?;
    if !findings.is_empty() {
        return Err(findings.join("; "));
    }
    Ok(Identity {
        package: text(&program, "package")?,
        installed_name: Path::new(&text(&program, "identity")?)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("installed name missing")?
            .to_owned(),
        release_group: text(&program, "release_group")?,
        repository: args.repository.to_owned(),
        source_commit: args.source_commit.to_owned(),
        version: text(&program, "version")?,
    })
}
