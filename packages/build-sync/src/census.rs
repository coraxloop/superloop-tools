//! Compare Meson's dependency declarations with Cargo's resolved workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))
}

// An input declared by any ordinary manifest class remains required. A public
// manifest has consumed the source exclusions, so their absent inputs have no
// class here. Repositories without a manifest retain the strict source contract.
pub(crate) fn expects_source(root: &Path, path: &str) -> Result<bool> {
    if root.join(path).exists() || !root.join("public-set.toml").exists() {
        return Ok(true);
    }
    let manifest =
        superloop_cli_common::public_set::Manifest::parse(&read(&root.join("public-set.toml"))?)?;
    let selected = manifest.select(&[path.to_owned()]);
    Ok(!selected.included.is_empty() || selected.excluded != 0)
}

fn record(root: &Path, path: &str) -> Result<Option<String>> {
    if expects_source(root, path)? {
        read(&root.join(path)).map(Some)
    } else {
        Ok(None)
    }
}

fn manifest(path: &Path) -> Result<Value> {
    toml::from_str(&read(path)?).map_err(|error| format!("decode {}: {error}", path.display()))
}

fn rows(path: &Path) -> Result<Vec<Value>> {
    let source = read(path)?;
    let mut rows = Vec::new();
    for block in source.split("dependency_ledger += ['''\n").skip(1) {
        if block.starts_with("''']") {
            continue;
        }
        let (body, _) = block
            .split_once("\n''']")
            .ok_or_else(|| format!("{}: unterminated dependency ledger", path.display()))?;
        for line in body.lines().filter(|line| !line.is_empty()) {
            rows.push(
                serde_json::from_str(line)
                    .map_err(|error| format!("{}: invalid ledger row: {error}", path.display()))?,
            );
        }
    }
    Ok(rows)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}: {value}"))
}

fn list<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("missing array {key}"))
}

fn dependencies(table: &Value, path: &str, findings: &mut Vec<String>) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(entries) = table.get(section).and_then(Value::as_object) {
            for (name, dependency) in entries {
                if dependency.get("workspace").and_then(Value::as_bool) != Some(true)
                    || dependency.get("features").is_some()
                    || dependency.get("default-features").is_some()
                    || dependency.get("version").is_some()
                    || dependency.get("path").is_some()
                {
                    findings.push(format!(
                        "{path}: {section}.{name} must inherit workspace authority"
                    ));
                }
            }
        }
    }
    if let Some(targets) = table.get("target").and_then(Value::as_object) {
        for (target, entries) in targets {
            dependencies(entries, &format!("{path}:target.{target}"), findings);
        }
    }
}

fn reachable(start: &str, target: &str, edges: &BTreeMap<String, BTreeSet<String>>) -> bool {
    let mut queue = vec![start.to_owned()];
    let mut seen = BTreeSet::new();
    while let Some(current) = queue.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if let Some(next) = edges.get(&current) {
            if next.contains(target) {
                return true;
            }
            queue.extend(next.iter().cloned());
        }
    }
    false
}

/// Write a census report, retaining findings even when acceptance fails.
///
/// # Errors
/// Refuses malformed declarations, failed Cargo metadata, unwritable reports,
/// or a measured graph that does not agree with its declarations.
pub fn run(
    root: &Path,
    cargo: &Path,
    configured_ledger: &Path,
    report: &Path,
    installations_only: bool,
) -> Result<()> {
    let result = if installations_only {
        measure_installations(root, configured_ledger)
    } else {
        measure(root, cargo, configured_ledger)
    };
    let document = match &result {
        Ok(document) => document.clone(),
        Err(reason) => json!({"schema":1,"complete":false,"error":reason}),
    };
    let bytes = serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())?;
    fs::write(report, bytes).map_err(|error| {
        let refusal = result
            .as_ref()
            .err()
            .map_or(String::new(), |reason| format!("{reason}; "));
        format!("{refusal}write {}: {error}", report.display())
    })?;
    let document = result?;
    let findings = list(&document, "unaccounted")?;
    if findings.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "dependency census has {} findings; see {}",
            findings.len(),
            report.display()
        ))
    }
}

fn measure_installations(root: &Path, configured_ledger: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("root: {error}"))?;
    let ledger = rows(&root.join("meson.build"))?;
    check_configured_ledger(configured_ledger, &ledger)?;
    let mut findings = Vec::new();
    ledger_kinds(&ledger, &mut findings)?;
    let installations =
        crate::census_install::inventory(&root, configured_ledger, &ledger, &mut findings)?;
    Ok(
        json!({"schema":1,"scope":"installations","installations":installations,"unaccounted":findings}),
    )
}

fn measure(root: &Path, cargo: &Path, configured_ledger: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("root: {error}"))?;
    let workspace = manifest(&root.join("Cargo.toml"))?;
    let members = workspace["workspace"]["members"]
        .as_array()
        .ok_or("workspace.members must be explicit")?;
    let mut ledger = rows(&root.join("meson.build"))?;
    for member in members {
        let path = member.as_str().ok_or("workspace member must be a path")?;
        ledger.extend(rows(&root.join(path).join("meson.build"))?);
    }
    for row in &ledger {
        if let Some(path) = row.get("when_source_absent") {
            let path = path
                .as_str()
                .ok_or("when_source_absent must name a source path")?;
            if !superloop_cli_common::public_set::safe_path(path) {
                return Err("when_source_absent must be a normalized relative path".into());
            }
        }
    }
    ledger.retain(|row| {
        row.get("when_source_absent")
            .and_then(Value::as_str)
            .is_none_or(|path| !root.join(path).exists())
    });
    check_configured_ledger(configured_ledger, &ledger)?;
    let lock_present = root.join("Cargo.lock").exists();
    let metadata = cargo_metadata(&root, cargo, lock_present)?;
    let mut findings = Vec::new();
    let mut packages = BTreeMap::new();
    let member_ids = list(&metadata, "workspace_members")?;
    for package in list(&metadata, "packages")? {
        if member_ids.contains(&package["id"]) {
            packages.insert(string(package, "id")?.to_owned(), package);
        }
    }
    let mut roster = package_census(&root, &ledger, &packages, &mut findings)?;
    ledger_kinds(&ledger, &mut findings)?;
    vendored_census(&root, &ledger, &roster, &mut findings)?;
    package_destinations(&root, &roster, &mut findings)?;
    let (internal_edges, tier_debt) = tier_census(&metadata, &ledger, &packages, &mut findings)?;
    accountability(
        &root,
        &ledger,
        &packages,
        &mut roster,
        &internal_edges,
        &mut findings,
    )?;
    let (lock_trace, unexplained_lock) = lock_census(&root, &workspace, &ledger, &metadata)?;
    findings.extend(unexplained_lock.iter().cloned());
    declaration_checks(
        &root,
        &workspace,
        &ledger,
        &metadata,
        &roster,
        &mut findings,
    )?;
    let pending_successors = successor_census(&root, &ledger, &metadata, &mut findings)?;
    let programs = crate::census_programs::check(&root, &ledger, &metadata, &mut findings)?;
    let calls = crate::census_calls::inventory(&root, &ledger, &mut findings)?;
    let delegated_calls = crate::census_calls::delegated(&root, &ledger, &mut findings)?;
    let meson_calls = crate::census_meson::inventory(&root, &ledger, &mut findings)?;
    let payloads = crate::census_payloads::inventory(&root, &ledger, &mut findings)?;
    let data = crate::census_data::check(&root, &ledger, &mut findings)?;
    let source_imports = crate::census_sources::check(&root, &ledger, &mut findings)?;
    let installations =
        crate::census_install::inventory(&root, configured_ledger, &ledger, &mut findings)?;
    crate::census_install::programs(&programs, &installations, &mut findings);
    let build = configured_ledger
        .parent()
        .ok_or("configured ledger has no build directory")?
        .canonicalize()
        .map_err(|error| format!("configured build directory: {error}"))?;
    let test_tools = crate::census_test_tools::check(&build, &ledger, &metadata, &mut findings)?;
    let result = json!({"schema":1,"packages":roster,"internal_edges":internal_edges,
        "tier_debt":tier_debt,"unaccounted":findings,"unexplained_lock":unexplained_lock,
        "lockfile": if lock_present { "present" } else { "absent; resolved through cargo metadata" },
        "lock_trace":lock_trace,"pending_successors":pending_successors,"programs":programs,"calls":calls,"delegated_calls":delegated_calls,"meson_calls":meson_calls,"payloads":payloads,"installations":installations,"data_edges":data,"source_imports":source_imports,"test_tools":test_tools});
    Ok(result)
}

fn cargo_metadata(root: &Path, cargo: &Path, lock_present: bool) -> Result<Value> {
    let mut command = Command::new(cargo);
    command.current_dir(root).arg("metadata");
    if lock_present {
        command.arg("--locked");
    }
    let output = command
        .args(["--format-version", "1"])
        .output()
        .map_err(|error| format!("cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("cargo metadata JSON: {error}"))
}

fn ledger_kinds(ledger: &[Value], findings: &mut Vec<String>) -> Result<()> {
    for row in ledger {
        let kind = string(row, "kind")?;
        if ![
            "package",
            "accountable-owner",
            "admission",
            "closure",
            "tier-debt",
            "successor",
            "program",
            "external-program",
            "call",
            "delegated-call",
            "meson-call",
            "payload",
            "vendored",
            "installation",
            "installation-inputs",
            "data",
            "source-import",
            "test-tool",
        ]
        .contains(&kind)
        {
            findings.push(format!("unknown dependency ledger kind: {kind}"));
        }
    }
    Ok(())
}

fn vendored_census(
    root: &Path,
    ledger: &[Value],
    roster: &[Value],
    findings: &mut Vec<String>,
) -> Result<()> {
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "vendored") {
        let name = string(row, "name")?;
        if declared.insert(name, row).is_some() {
            findings.push(format!("duplicate vendored admission: {name}"));
        }
    }
    for package in roster {
        let name = string(package, "name")?;
        let source = read(&root.join(string(package, "manifest")?))?;
        if !source.contains("# Vendored from ") {
            continue;
        }
        if let Some(row) = declared.remove(name) {
            for key in ["upstream", "tag", "commit", "license"] {
                let value = string(row, key)?;
                if value.is_empty() || !source.contains(value) {
                    findings.push(format!(
                        "vendored admission {name} has an unconfirmed {key}"
                    ));
                }
            }
            for key in ["owner", "reason"] {
                if string(row, key)?.is_empty() {
                    findings.push(format!("vendored admission {name} lacks {key}"));
                }
            }
            if list(row, "divergences")?.is_empty() {
                findings.push(format!(
                    "vendored admission {name} lacks a divergence review"
                ));
            }
        } else {
            findings.push(format!("unadmitted vendored package: {name}"));
        }
    }
    findings.extend(
        declared
            .keys()
            .map(|name| format!("stale vendored admission: {name}")),
    );
    Ok(())
}

fn package_destinations(root: &Path, roster: &[Value], findings: &mut Vec<String>) -> Result<()> {
    let Some(source) = record(root, "adr/036-tools-dependency-concept.md")? else {
        return Ok(());
    };
    let (_, table) = source
        .split_once("|Present source|Destination and tier|\n")
        .ok_or("package destination table missing")?;
    let (table, _) = table
        .split_once("\n\n")
        .ok_or("package destination table terminator missing")?;
    let mut names = BTreeSet::new();
    for line in table
        .lines()
        .filter(|line| line.starts_with('|') && !line.starts_with("|---"))
    {
        // Both the original packages and their recorded successors can be present
        // during the transition; the destination column names the final packages.
        for (index, word) in line.split('`').enumerate() {
            if index % 2 == 1 {
                names.insert(word);
            }
        }
    }
    for package in roster {
        let name = string(package, "name")?;
        if !names.contains(name) {
            findings.push(format!("package lacks a recorded destination: {name}"));
        }
    }
    Ok(())
}

fn check_configured_ledger(path: &Path, expected: &[Value]) -> Result<()> {
    let mut actual = read(path)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map(|row| row.to_string())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expected: Vec<_> = expected.iter().map(Value::to_string).collect();
    actual.sort();
    expected.sort();
    if actual != expected {
        return Err(
            "configured Meson ledger differs from source declarations; reconfigure the build"
                .into(),
        );
    }
    Ok(())
}

fn successor_census(
    root: &Path,
    ledger: &[Value],
    metadata: &Value,
    findings: &mut Vec<String>,
) -> Result<Vec<Value>> {
    let source = record(root, "adr/033-tool-executables-names-and-versions.md")?;
    let table = if let Some(source) = &source {
        let (_, table) = source
            .split_once("|Present name|Successor|Installs to|\n")
            .ok_or("successor table missing")?;
        table
            .split_once("\n\n")
            .ok_or("successor table terminator missing")?
            .0
    } else {
        ""
    };
    let mut expected: BTreeSet<_> = table
        .lines()
        .filter(|line| line.starts_with('|') && !line.starts_with("|---"))
        .collect();
    let mut pending = Vec::new();
    for row in ledger.iter().filter(|row| row["kind"] == "successor") {
        let text = string(row, "row")?;
        if row["record"] != "tab:toolnames:successors"
            || (source.is_some() && !expected.remove(text))
        {
            findings.push(format!("extra or duplicate successor ledger row: {text}"));
        }
        let bites = list(row, "pending_bites")?;
        if !bites.is_empty() {
            if bites
                .iter()
                .any(|bite| bite.as_u64().is_none_or(|bite| !(4..=15).contains(&bite)))
            {
                findings.push(format!("invalid successor pending bite: {text}"));
            }
            pending.push(row.clone());
        } else if let Some(absent) = row["absent_binary"].as_str() {
            for package in list(metadata, "packages")? {
                if let Some(targets) = package["targets"].as_array()
                    && targets.iter().any(|target| {
                        target["name"] == absent
                            && target["kind"]
                                .as_array()
                                .is_some_and(|kinds| kinds.contains(&json!("bin")))
                    })
                {
                    findings.push(format!("retired binary still built: {absent}"));
                }
            }
        } else if row.get("installed_programs").is_some()
            || row.get("build_programs").is_some()
            || row.get("generated_units").is_some()
            || row.get("generated_programs").is_some()
        {
            successor_destinations(root, ledger, row, findings)?;
        } else {
            findings.push(format!(
                "successor has no installation proof or pending bite: {text}"
            ));
        }
    }
    findings.extend(
        expected
            .iter()
            .map(|row| format!("unaccounted successor row: {row}")),
    );
    Ok(pending)
}

fn successor_destinations(
    root: &Path,
    ledger: &[Value],
    row: &Value,
    findings: &mut Vec<String>,
) -> Result<()> {
    let mut count = 0;
    if let Some(programs) = row.get("installed_programs") {
        for identity in programs
            .as_array()
            .ok_or("successor program list missing")?
        {
            count += 1;
            let program = ledger
                .iter()
                .find(|program| program["kind"] == "program" && program["identity"] == *identity);
            let installed = program.is_some_and(|program| {
                program["output"].as_str().is_some_and(|output| {
                    ledger.iter().any(|installation| {
                        installation["kind"] == "installation"
                            && installation["route"] == "native"
                            && installation["source"] == format!("build:{output}")
                    })
                })
            });
            if !installed {
                findings.push(format!(
                    "successor native program is not declared: {identity}"
                ));
            }
        }
    }
    if let Some(programs) = row.get("build_programs") {
        for identity in programs
            .as_array()
            .ok_or("successor build program list missing")?
        {
            count += 1;
            let declared = ledger.iter().any(|program| {
                program["kind"] == "program"
                    && program["identity"] == *identity
                    && program["installation_class"] == "build"
                    && program["output"].as_str().is_some_and(|output| {
                        !ledger.iter().any(|installation| {
                            installation["kind"] == "installation"
                                && (installation["source"] == format!("build:{output}")
                                    || installation["target"]["output"] == output)
                        })
                    })
            });
            if !declared {
                findings.push(format!(
                    "successor build-only program is not declared: {identity}"
                ));
            }
        }
    }
    for units in [row.get("generated_units"), row.get("generated_programs")]
        .into_iter()
        .flatten()
    {
        for unit in units
            .as_array()
            .ok_or("successor generated destinations missing")?
        {
            count += 1;
            let path = string(unit, "source")?;
            if !expects_source(root, path)? {
                continue;
            }
            let anchor = string(unit, "anchor")?;
            let destination = string(unit, "destination")?;
            let owner = string(unit, "program")?;
            if anchor.is_empty()
                || destination.is_empty()
                || !read(&root.join(path))?.contains(anchor)
                || !ledger
                    .iter()
                    .any(|program| program["kind"] == "program" && program["identity"] == owner)
            {
                findings.push(format!(
                    "successor generated destination lacks its owner or source anchor: {destination}"
                ));
            }
        }
    }
    if count == 0 {
        findings.push("completed successor has no destination proof".into());
    }
    Ok(())
}

fn declaration_checks(
    root: &Path,
    workspace: &Value,
    ledger: &[Value],
    metadata: &Value,
    roster: &[Value],
    findings: &mut Vec<String>,
) -> Result<()> {
    let readme = read(&root.join("packages/README.md"))?;
    let expected: BTreeSet<_> = roster
        .iter()
        .map(|row| {
            Ok(format!(
                "|`{}`|{}|`{}`|",
                string(row, "name")?,
                row["tier"],
                string(row, "release_group")?
            ))
        })
        .collect::<Result<_>>()?;
    let actual: BTreeSet<_> = readme
        .lines()
        .filter(|line| line.starts_with("|`"))
        .map(str::to_owned)
        .collect();
    if actual != expected {
        findings.push("packages/README.md member table differs from the census".into());
    }
    let external = workspace["workspace"]["dependencies"]
        .as_object()
        .ok_or("workspace dependencies missing")?;
    for row in ledger.iter().filter(|row| row["kind"] == "admission") {
        let name = string(row, "name")?;
        if !external.contains_key(name) || external[name].get("path").is_some() {
            findings.push(format!("extra external admission: {name}"));
        }
    }
    for package in list(metadata, "packages")? {
        if package["name"] == "petgraph" {
            for node in list(&metadata["resolve"], "nodes")? {
                if node["id"] == package["id"] {
                    let features = list(node, "features")?;
                    if !features.contains(&json!("serde-1"))
                        || features.contains(&json!("dot_parser"))
                        || features.contains(&json!("rayon"))
                    {
                        findings.push("petgraph resolved features violate admission".into());
                    }
                }
            }
        }
    }
    Ok(())
}

fn lock_census(
    root: &Path,
    workspace: &Value,
    ledger: &[Value],
    metadata: &Value,
) -> Result<(Vec<Value>, Vec<String>)> {
    // The source ledger describes the estate lock, not a consumer's resolution.
    let check_closure = if root.join("public-set.toml").exists() {
        superloop_cli_common::public_set::Manifest::parse(&read(&root.join("public-set.toml"))?)?
            .select(&["Cargo.lock".into()])
            .excluded
            != 0
    } else {
        true
    };
    let lock = manifest(&root.join("Cargo.lock"))?;
    let locked = lock["package"]
        .as_array()
        .ok_or("lockfile package array missing")?;
    let graph = lock_graph(locked)?;
    let mut findings = Vec::new();
    let mut roots = BTreeMap::new();
    let authority = workspace["workspace"]["dependencies"]
        .as_object()
        .ok_or("workspace dependencies missing")?;
    for (name, dependency) in authority {
        if dependency.get("path").is_some() {
            continue;
        }
        let actual = dependency
            .get("package")
            .and_then(Value::as_str)
            .unwrap_or(name);
        let admissions: Vec<_> = ledger
            .iter()
            .filter(|row| row["kind"] == "admission" && row["name"] == *name)
            .collect();
        if admissions.len() != 1
            || admissions[0]["reason"].as_str().is_none_or(str::is_empty)
            || admissions[0]["owner"].as_str().is_none_or(str::is_empty)
        {
            findings.push(format!("missing admission reason/owner: {name}"));
        }
        let mut ids = BTreeSet::new();
        for node in list(&metadata["resolve"], "nodes")? {
            if !list(metadata, "workspace_members")?.contains(&node["id"]) {
                continue;
            }
            for edge in list(node, "deps")? {
                for package in list(metadata, "packages")? {
                    if package["id"] == edge["pkg"]
                        && package["name"] == actual
                        && !package["source"].is_null()
                    {
                        ids.insert(format!("{} {}", actual, string(package, "version")?));
                    }
                }
            }
        }
        if ids.is_empty() {
            findings.push(format!("unused direct external root: {name}"));
        }
        roots.insert(name, ids);
    }
    let mut trace = Vec::new();
    for package in locked
        .iter()
        .filter(|package| package.get("source").is_some())
    {
        let id = lock_identity(package)?;
        let responsible: Vec<_> = roots
            .iter()
            .filter(|(_, ids)| {
                ids.iter()
                    .any(|start| start == &id || reachable(start, &id, &graph))
            })
            .map(|(name, _)| (*name).clone())
            .collect();
        let row = json!({"name":package["name"].as_str(),"version":package["version"].as_str(),
            "source":package["source"].as_str(),"checksum":package.get("checksum").and_then(Value::as_str),
            "direct_roots":responsible,"dependencies":graph[&id]});
        let declarations: Vec<_> = ledger
            .iter()
            .filter(|entry| {
                entry["kind"] == "closure"
                    && entry["name"] == row["name"]
                    && entry["version"] == row["version"]
                    && entry["source"] == row["source"]
            })
            .collect();
        if check_closure
            && (responsible.is_empty()
                || declarations.len() != 1
                || declarations[0]["checksum"] != row["checksum"]
                || declarations[0]["direct_roots"] != row["direct_roots"])
        {
            findings.push(format!("unexplained lock identity or closure drift: {id}"));
        }
        trace.push(row);
    }
    if check_closure {
        closure_checks(ledger, metadata, &trace, &mut findings)?;
    }
    Ok((trace, findings))
}

fn closure_checks(
    ledger: &[Value],
    metadata: &Value,
    trace: &[Value],
    findings: &mut Vec<String>,
) -> Result<()> {
    for row in ledger.iter().filter(|row| row["kind"] == "closure") {
        if !trace.iter().any(|measured| {
            measured["name"] == row["name"]
                && measured["version"] == row["version"]
                && measured["source"] == row["source"]
        }) {
            findings.push(format!(
                "stale reviewed closure identity: {} {}",
                row["name"], row["version"]
            ));
        }
        let roots = list(row, "direct_roots")?;
        let owners: BTreeSet<_> = ledger
            .iter()
            .filter(|admission| {
                admission["kind"] == "admission" && roots.contains(&admission["name"])
            })
            .filter_map(|admission| admission["owner"].as_str())
            .collect();
        let declared: BTreeSet<_> = list(row, "owners")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if owners != declared
            || owners.is_empty()
            || row["reason"].as_str().is_none_or(str::is_empty)
        {
            findings.push(format!(
                "closure reason or inherited owners differ: {} {}",
                row["name"], row["version"]
            ));
        }
    }
    for package in list(metadata, "packages")? {
        if package["source"].is_null()
            && !list(metadata, "workspace_members")?.contains(&package["id"])
        {
            findings.push(format!(
                "unaccounted non-workspace path dependency: {}",
                package["id"]
            ));
        }
    }
    Ok(())
}

fn domain_owners(root: &Path) -> Result<BTreeMap<String, String>> {
    let Some(source) = record(root, "adr/036-tools-dependency-concept.md")? else {
        return Ok(BTreeMap::new());
    };
    let (_, table) = source
        .split_once("|Package|Tier and domain|Accountable owner|Consumers|\n")
        .ok_or("record 036 domains table missing")?;
    let mut owners = BTreeMap::new();
    for line in table.lines().take_while(|line| line.starts_with('|')) {
        if line.starts_with("|---") {
            continue;
        }
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 6 {
            return Err("record 036 domains table row malformed".into());
        }
        let package = fields[1]
            .trim()
            .strip_prefix('`')
            .and_then(|name| name.strip_suffix('`'))
            .filter(|name| !name.is_empty())
            .ok_or("record 036 domains table package malformed")?;
        let owner = fields[3].trim();
        if owner.is_empty()
            || owners
                .insert(package.to_owned(), owner.to_owned())
                .is_some()
        {
            return Err(format!(
                "record 036 domains table owner malformed: {package}"
            ));
        }
    }
    Ok(owners)
}

fn accountability(
    root: &Path,
    ledger: &[Value],
    packages: &BTreeMap<String, &Value>,
    roster: &mut [Value],
    edges: &[Value],
    findings: &mut Vec<String>,
) -> Result<()> {
    let recorded_owners = domain_owners(root)?;
    for name in recorded_owners.keys() {
        if !packages
            .values()
            .any(|package| package["name"] == name.as_str())
        {
            return Err(format!(
                "record 036 domains table names a package the roster lacks: {name}"
            ));
        }
    }
    let mut owners = BTreeMap::new();
    for row in ledger
        .iter()
        .filter(|row| row["kind"] == "accountable-owner")
    {
        let package = string(row, "package")?;
        if owners
            .insert(package, row.get("owner").cloned().unwrap_or(Value::Null))
            .is_some()
        {
            findings.push(format!("duplicate accountable owner: {package}"));
        }
    }
    for package in roster {
        let name = string(package, "name")?.to_owned();
        let owner = owners.remove(name.as_str()).unwrap_or(Value::Null);
        if owner.as_str().is_none_or(|owner| {
            owner.is_empty() || !owner.bytes().all(|byte| byte.is_ascii_uppercase())
        }) {
            findings.push(format!("missing or invalid accountable owner: {name}"));
        }
        if recorded_owners
            .get(&name)
            .is_some_and(|recorded| owner.as_str() != Some(recorded.as_str()))
        {
            findings.push(format!(
                "accountable owner disagrees with record 036: {name}"
            ));
        }
        let consumers: BTreeSet<_> = edges
            .iter()
            .filter(|edge| edge["target"] == name)
            .filter_map(|edge| edge["source"].as_str())
            .collect();
        package["accountable_owner"] = owner;
        package["consumers"] = json!(consumers);
    }
    findings.extend(
        owners
            .keys()
            .map(|name| format!("stale accountable owner: {name}")),
    );
    Ok(())
}

fn package_census(
    root: &Path,
    ledger: &[Value],
    packages: &BTreeMap<String, &Value>,
    findings: &mut Vec<String>,
) -> Result<Vec<Value>> {
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "package") {
        let name = string(row, "name")?;
        if declared.insert(name, row).is_some() {
            findings.push(format!("duplicate package ledger row: {name}"));
        }
    }
    let mut roster = Vec::new();
    let mut groups = BTreeMap::new();
    for package in packages.values() {
        let name = string(package, "name")?;
        let Some(row) = declared.remove(name) else {
            findings.push(format!("unaccounted package: {name}"));
            continue;
        };
        let path = string(row, "manifest")?;
        let document = manifest(&root.join(path))?;
        dependencies(&document, path, findings);
        let authority = &package["metadata"]["superloop"];
        if row["tier"] != authority["tier"]
            || !row["tier"].is_u64()
            || row["release_group"] != authority["release-group"]
            || row["version_authority"] != path
            || root.join(path).to_str() != package["manifest_path"].as_str()
            || crate::census_programs::manifest_version(root, &document)?.as_str()
                != package["version"].as_str()
        {
            findings.push(format!(
                "package identity, tier or version authority differs: {name}"
            ));
        }
        let group = string(row, "release_group")?;
        let version = string(package, "version")?;
        if let Some(previous) = groups.insert(group.to_owned(), version.to_owned())
            && previous != version
        {
            findings.push(format!("incompatible release group versions: {group}"));
        }
        roster.push(json!({"name":name,"version":version,"tier":row["tier"],
            "release_group":group,"manifest":path}));
    }
    findings.extend(
        declared
            .keys()
            .map(|name| format!("extra package ledger row: {name}")),
    );
    Ok(roster)
}

fn lock_identity(package: &Value) -> Result<String> {
    Ok(format!(
        "{} {}",
        package["name"].as_str().ok_or("lock name missing")?,
        package["version"].as_str().ok_or("lock version missing")?
    ))
}

fn lock_graph(locked: &[Value]) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in locked {
        let mut edges = BTreeSet::new();
        if let Some(dependencies) = package.get("dependencies").and_then(Value::as_array) {
            for dependency in dependencies {
                let words: Vec<_> = dependency
                    .as_str()
                    .ok_or("lock dependency missing")?
                    .split_whitespace()
                    .collect();
                let matching: Vec<_> = locked
                    .iter()
                    .filter(|candidate| {
                        candidate["name"].as_str() == words.first().copied()
                            && (words.len() == 1
                                || candidate["version"].as_str() == words.get(1).copied())
                    })
                    .collect();
                if matching.len() != 1 {
                    return Err(format!("ambiguous lock dependency: {dependency}"));
                }
                edges.insert(lock_identity(matching[0])?);
            }
        }
        graph.insert(lock_identity(package)?, edges);
    }
    Ok(graph)
}

fn tier_census(
    metadata: &Value,
    ledger: &[Value],
    packages: &BTreeMap<String, &Value>,
    findings: &mut Vec<String>,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut tier_debt = Vec::new();
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut internal_edges = Vec::new();
    for node in list(&metadata["resolve"], "nodes")? {
        let Some(source) = packages.get(string(node, "id")?) else {
            continue;
        };
        for dependency in list(node, "deps")? {
            let Some(target) = packages.get(string(dependency, "pkg")?) else {
                continue;
            };
            let source_name = string(source, "name")?;
            let target_name = string(target, "name")?;
            graph
                .entry(source_name.to_owned())
                .or_default()
                .insert(target_name.to_owned());
            for kind in list(dependency, "dep_kinds")? {
                let dependency_kind = kind["kind"].as_str().unwrap_or("normal");
                let edge = json!({"source":source_name,"target":target_name,
                    "dependency_kind":dependency_kind,"target_condition":kind["target"]});
                internal_edges.push(edge.clone());
                let source_tier = source["metadata"]["superloop"]["tier"].as_u64();
                let target_tier = target["metadata"]["superloop"]["tier"].as_u64();
                if source_tier.is_none() || target_tier.is_none() || source_tier <= target_tier {
                    tier_debt.push(edge);
                    findings.push(format!(
                        "unadmitted tier edge: {source_name} -> {target_name} ({dependency_kind})"
                    ));
                }
            }
        }
    }
    for name in graph.keys() {
        if reachable(name, name, &graph) {
            findings.push(format!("source dependency cycle: {name}"));
        }
    }
    if ledger.iter().any(|row| row["kind"] == "tier-debt") {
        findings.push("tier debt declarations are retired after the lane merge".into());
    }
    Ok((internal_edges, tier_debt))
}

#[cfg(test)]
mod publication_tests {
    use super::expects_source;

    /// Publication classes keep missing declared inputs strict in both trees.
    ///
    /// # Panics
    /// Panics only if fixture IO or a classification assertion fails.
    /// ´test:unit:census-input-expectations-follow-publication-classes´
    #[test]
    fn census_input_expectations_follow_publication_classes() {
        let root = tempfile::tempdir().expect("fixture");
        assert!(expects_source(root.path(), "absent.md").expect("legacy expectation"));
        let manifest = r#"namespace = "org.superloop-tools.public-set"
version = [1, 0, 0]
[include]
rows = [{ pattern = "public/" }]
[exclude]
rows = [{ pattern = "private/", reason = "Source-only evidence." }]
[public]
name = "fixture-repository"
readme = "public/README.md"
licence_code = "LICENSE-CODE"
licence_docs = "LICENSE-DOCS"
"#;
        std::fs::write(root.path().join("public-set.toml"), manifest).expect("manifest");
        assert!(expects_source(root.path(), "public/missing.md").expect("public input"));
        assert!(expects_source(root.path(), "private/missing.md").expect("source input"));
        assert!(!expects_source(root.path(), "consumed/missing.md").expect("consumed input"));
        std::fs::write(root.path().join("present.md"), "evidence").expect("present input");
        assert!(expects_source(root.path(), "present.md").expect("existing input"));
        for (path, expected) in [
            ("public/missing.sh", 1),
            ("private/missing.sh", 1),
            ("consumed/missing.sh", 0),
        ] {
            let mut findings = Vec::new();
            crate::census_payloads::inventory(
                root.path(),
                &[serde_json::json!({"kind":"payload", "path":path})],
                &mut findings,
            )
            .expect("payload inventory");
            assert_eq!(findings.len(), expected, "{path}: {findings:?}");
        }
    }
}
