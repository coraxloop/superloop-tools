//! Compare migration maps and configured native destinations with the ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .ok_or_else(|| format!("installation lacks {key}: {row}"))
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("decode {}: {error}", path.display()))
}

fn input_paths(ledger: &[Value], field: &str) -> Result<Vec<String>> {
    let rows: Vec<_> = ledger
        .iter()
        .filter(|row| row["kind"] == "installation-inputs")
        .collect();
    if rows.len() != 1 {
        return Err("installation census requires exactly one installation-inputs row".into());
    }
    if text(rows[0], "owner")?.is_empty() {
        return Err("installation-inputs requires an owner".into());
    }
    let mut paths = BTreeSet::new();
    for value in rows[0][field]
        .as_array()
        .ok_or_else(|| format!("installation-inputs lacks {field}"))?
    {
        let path = value.as_str().ok_or("installation input must be a path")?;
        if !superloop_cli_common::public_set::safe_path(path) || !paths.insert(path.to_owned()) {
            return Err(format!("invalid or duplicate installation input: {field}"));
        }
    }
    Ok(paths.into_iter().collect())
}

fn map_inventory(root: &Path, paths: &[String]) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for relative in paths {
        if !crate::census::expects_source(root, relative)? {
            continue;
        }
        let path = root.join(relative);
        let resolved = path
            .canonicalize()
            .map_err(|error| format!("map {relative}: {error}"))?;
        if !resolved.starts_with(root) || !resolved.is_file() {
            return Err(format!(
                "map must be a file within the source root: {relative}"
            ));
        }
        let map: Value =
            toml::from_str(&fs::read_to_string(&path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let destination_root = map["root"]
            .as_str()
            .or_else(|| map["registry"]["root"].as_str())
            .ok_or("map destination root missing")?;
        for target in map["targets"].as_array().ok_or("map targets missing")? {
            result.push(json!({"route":"map", "declaration":relative,
                "destination":format!("{destination_root}/{}", text(target,"destination")?),
                "target":target,"registry":map["registry"]}));
        }
    }
    Ok(result)
}

fn configured_destination(value: &str, options: &Value) -> Result<String> {
    if !value.starts_with('@') {
        return Ok(value.to_owned());
    }
    let (name, suffix) = value[1..]
        .split_once('@')
        .ok_or("invalid destination option")?;
    let option = |key: &str| -> Result<&str> {
        options
            .as_array()
            .ok_or("Meson build options missing")?
            .iter()
            .find(|row| row["name"] == key)
            .and_then(|row| row["value"].as_str())
            .ok_or_else(|| format!("Meson install option missing: {key}"))
    };
    let directory = Path::new(option(name)?);
    let directory = if directory.is_absolute() {
        directory.to_owned()
    } else {
        Path::new(option("prefix")?).join(directory)
    };
    Ok(format!("{}{suffix}", directory.display()))
}

fn destination_collisions(
    rows: &[Value],
    home: Option<&Path>,
    findings: &mut Vec<String>,
) -> Result<()> {
    let mut destinations = BTreeMap::new();
    for row in rows {
        let destination = text(row, "destination")?;
        let path = if let Some(relative) = destination.strip_prefix("~/") {
            home.ok_or("HOME required to resolve home-relative map destinations")?
                .join(relative)
        } else {
            std::path::PathBuf::from(destination)
        };
        let mut normalized = std::path::PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        let route = text(row, "route")?;
        if let Some(previous) = destinations.insert(normalized.clone(), route) {
            findings.push(format!(
                "installation destination collision: {} ({previous}, {route})",
                normalized.display()
            ));
        }
    }
    Ok(())
}

fn document_paths(build: &Path, roots: &[String]) -> Result<Vec<String>> {
    let path = build.join("declared-paths.txt");
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("docs-prose-unreadable: {error} in {}", path.display()))?;
    let mut documents = Vec::new();
    for (index, document) in source.lines().enumerate() {
        if document.is_empty()
            || document.contains(['\\', '\0'])
            || document.chars().any(char::is_control)
            || document
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(format!(
                "docs-prose-unreadable: line {} is not a normalized relative path in {}",
                index + 1,
                path.display()
            ));
        }
        if Path::new(document)
            .extension()
            .is_none_or(|extension| extension != "md")
            || !roots.iter().any(|root| {
                document
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            continue;
        }
        documents.push(document.to_owned());
    }
    Ok(documents)
}

fn documents(
    root: &Path,
    documents: &[String],
    installed: &[Value],
    findings: &mut Vec<String>,
) -> Result<()> {
    for document in documents {
        let document = document.as_str();
        let public = if root.join("public-set.toml").exists() {
            superloop_cli_common::public_set::Manifest::parse(
                &fs::read_to_string(root.join("public-set.toml"))
                    .map_err(|error| error.to_string())?,
            )?
            .select(&[document.to_owned()])
            .included
            .contains(&document.to_owned())
        } else {
            false
        };
        if !installed.iter().any(|row| {
            row["route"] == "map"
                && row["target"]["kind"] == "copy"
                && row["target"]["source"] == document
                && row["target"]["destination"] == document
                || (public
                    && row["route"] == "native"
                    && row["source"] == format!("source:{document}"))
        }) {
            findings.push(format!(
                "docs-prose-uninstalled: {document} declared in declared-paths.txt has no declared map or public native installation"
            ));
        }
    }
    Ok(())
}

fn enabled(row: &Value, options: &Value) -> Result<bool> {
    let Some(option) = row.get("when_option") else {
        return Ok(true);
    };
    let name = option
        .as_str()
        .ok_or("installation option must be a name")?;
    options
        .as_array()
        .ok_or("Meson build options missing")?
        .iter()
        .find(|row| row["name"] == name)
        .and_then(|row| row["value"].as_bool())
        .ok_or_else(|| format!("installation requires Boolean Meson option: {name}"))
}

pub fn inventory(
    root: &Path,
    configured_ledger: &Path,
    ledger: &[Value],
    findings: &mut Vec<String>,
) -> Result<Vec<Value>> {
    let build = configured_ledger.parent().ok_or_else(|| {
        format!(
            "docs-prose-unreadable: configured ledger has no build directory in {}",
            configured_ledger.display()
        )
    })?;
    let build = build
        .canonicalize()
        .map_err(|error| format!("docs-prose-unreadable: {error} in {}", build.display()))?;
    let maps = input_paths(ledger, "maps")?;
    let roots = input_paths(ledger, "document_roots")?;
    let mut measured = map_inventory(root, &maps)?;
    let declared_documents = document_paths(&build, &roots)?;
    let installed = read_json(&build.join("meson-info/intro-installed.json"))?;
    let options = read_json(&build.join("meson-info/intro-buildoptions.json"))?;
    for (source, destination) in installed
        .as_object()
        .ok_or("Meson installed object missing")?
    {
        let path = Path::new(source);
        let source = if let Ok(relative) = path.strip_prefix(&build) {
            format!("build:{}", relative.display())
        } else if let Ok(relative) = path.strip_prefix(root) {
            format!("source:{}", relative.display())
        } else {
            findings.push(format!(
                "native install source outside source and build roots: {source}"
            ));
            continue;
        };
        measured.push(json!({"route":"native","source":source,"destination":destination}));
    }
    let home = std::env::var_os("HOME");
    destination_collisions(&measured, home.as_deref().map(Path::new), findings)?;
    documents(root, &declared_documents, &measured, findings)?;
    let mut expected = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "installation") {
        if !enabled(row, &options)? {
            continue;
        }
        let input = if row["route"] == "map" {
            row["declaration"].as_str()
        } else {
            row["source"]
                .as_str()
                .and_then(|source| source.strip_prefix("source:"))
        };
        if let Some(input) = input
            && !crate::census::expects_source(root, input)?
        {
            continue;
        }
        let destination = configured_destination(text(row, "destination")?, &options)?;
        let route = text(row, "route")?;
        let key = format!("{route}:{destination}");
        if expected.insert(key.clone(), row).is_some() {
            findings.push(format!("duplicate installation declaration: {key}"));
        }
        if text(row, "owner")?.is_empty() {
            findings.push(format!("installation lacks owner: {key}"));
        }
    }
    for actual in &measured {
        let key = format!(
            "{}:{}",
            text(actual, "route")?,
            text(actual, "destination")?
        );
        if let Some(row) = expected.remove(&key) {
            let fields: &[&str] = if actual["route"] == "map" {
                &["declaration", "target", "registry"]
            } else {
                &["source"]
            };
            for field in fields {
                if row[*field] != actual[*field] {
                    findings.push(format!("installation {key} differs in {field}"));
                }
            }
        } else {
            findings.push(format!("unaccounted installation: {key}"));
        }
    }
    findings.extend(
        expected
            .keys()
            .map(|key| format!("stale installation declaration: {key}")),
    );
    Ok(measured)
}

pub fn programs(programs: &[Value], installed: &[Value], findings: &mut Vec<String>) {
    for program in programs {
        let class = program["installation_class"].as_str().unwrap_or_default();
        if class == "build" || class == "infra" {
            continue;
        }
        let output = format!("build:{}", program["output"].as_str().unwrap_or_default());
        let present = installed.iter().any(|row| {
            (row["route"] == "native" && row["source"] == output)
                || (row["route"] == "map"
                    && row["target"]["kind"] == "build"
                    && row["target"]["output"] == program["output"])
                || (row["route"] == "map"
                    && row["target"]["kind"] == "copy"
                    && !program["source"].is_null()
                    && row["target"]["source"] == program["source"])
        });
        let pending =
            program["identity"] == "bin/superloop-lane" && program["pending_install_bite"] == 4;
        if !present && !pending {
            findings.push(format!(
                "program has no installation destination: {}",
                program["identity"]
            ));
        }
        if present && program.get("pending_install_bite").is_some() {
            findings.push(format!(
                "stale pending installation: {}",
                program["identity"]
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::enabled;
    use serde_json::json;

    /// A map and native install cannot both own one configured destination.
    ///
    /// # Panics
    /// Panics only if the fixture destinations cannot be read or a collision is missed.
    /// ´claim:installation:routes-share-one-destination-space´
    /// ´test:unit:routes-share-one-destination-space´
    #[test]
    fn routes_share_one_destination_space() {
        let rows = vec![
            json!({"route":"map", "destination":"~/.local/share/tools/doc.md"}),
            json!({"route":"native", "destination":"/fixture/.local/share/tools/./doc.md"}),
        ];
        let mut findings = Vec::new();
        super::destination_collisions(&rows, Some(std::path::Path::new("/fixture")), &mut findings)
            .expect("destinations");
        assert_eq!(
            findings,
            [
                "installation destination collision: /fixture/.local/share/tools/doc.md (map, native)"
            ]
        );
        findings.clear();
        super::destination_collisions(
            &rows[..1],
            Some(std::path::Path::new("/fixture")),
            &mut findings,
        )
        .expect("one route");
        assert_eq!(findings, Vec::<String>::new());
        super::destination_collisions(&rows[1..], None, &mut findings)
            .expect("absolute destination needs no home");
        assert_eq!(findings, Vec::<String>::new());
        assert!(super::destination_collisions(&rows[..1], None, &mut findings).is_err());
    }

    /// ´test:unit:optional-installation-requires-an-explicit-boolean-option´
    #[test]
    fn optional_installation_requires_an_explicit_boolean_option() {
        let row = json!({"when_option":"server_kits"});
        for value in [false, true] {
            assert_eq!(
                enabled(&row, &json!([{"name":"server_kits","value":value}])),
                Ok(value)
            );
        }
        assert!(enabled(&row, &json!([])).is_err());
        assert!(enabled(&row, &json!([{"name":"server_kits","value":"true"}])).is_err());
        assert_eq!(enabled(&json!({}), &json!([])), Ok(true));
    }
}
