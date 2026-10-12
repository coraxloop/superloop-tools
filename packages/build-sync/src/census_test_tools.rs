//! Join test executable declarations to Cargo targets and Meson's configured environment.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

type Result<T> = std::result::Result<T, String>;

fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .ok_or_else(|| format!("test-tool lacks {key}: {row}"))
}

fn environment(
    build: &Path,
    row: &Value,
    program: &Value,
    tests: &Value,
    findings: &mut Vec<String>,
) -> Result<()> {
    let suite = text(row, "suite")?;
    let binding = text(row, "binding")?;
    let matches: Vec<_> = tests
        .as_array()
        .ok_or("Meson tests must be an array")?
        .iter()
        .filter(|test| test["name"] == suite)
        .collect();
    if matches.len() != 1 {
        findings.push(format!("test-tool suite must resolve once: {suite}"));
        return Ok(());
    }
    let expected = build.join(text(program, "output")?);
    if matches[0]["env"].get(binding).and_then(Value::as_str) != expected.to_str() {
        findings.push(format!(
            "test-tool environment differs: {suite} {binding}; expected {}",
            expected.display()
        ));
    }
    Ok(())
}

fn cargo_target(
    row: &Value,
    program: &Value,
    metadata: &Value,
    findings: &mut Vec<String>,
) -> Result<()> {
    let binding = text(row, "binding")?;
    let consumer = text(row, "consumer")?;
    let binary = binding
        .strip_prefix("CARGO_BIN_EXE_")
        .ok_or("Cargo test-tool binding must name a binary")?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("Cargo packages missing")?;
    let present = packages
        .iter()
        .filter(|package| package["name"] == consumer)
        .any(|package| {
            package["targets"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["name"] == binary
                        && target["kind"]
                            .as_array()
                            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
                })
            })
        });
    if !present || program["package"] != consumer || program["cargo_binary"] != binary {
        findings.push(format!(
            "test-tool Cargo target differs: {consumer} {binding}"
        ));
    }
    Ok(())
}

pub fn check(
    build: &Path,
    ledger: &[Value],
    metadata: &Value,
    findings: &mut Vec<String>,
) -> Result<Vec<Value>> {
    let rows: Vec<_> = ledger
        .iter()
        .filter(|row| row["kind"] == "test-tool")
        .cloned()
        .collect();
    let tests: Value = serde_json::from_slice(
        &fs::read(build.join("meson-info/intro-tests.json"))
            .map_err(|error| format!("read Meson test environments: {error}"))?,
    )
    .map_err(|error| error.to_string())?;
    let mut declared = BTreeSet::new();
    for row in &rows {
        let consumer = text(row, "consumer")?;
        let binding = text(row, "binding")?;
        let callee = text(row, "callee")?;
        if !declared.insert((consumer.to_owned(), binding.to_owned(), callee.to_owned())) {
            findings.push(format!("duplicate test-tool: {consumer} {binding}"));
        }
        if text(row, "contract")?.is_empty()
            || !ledger.iter().any(|member| {
                (member["kind"] == "package" && member["name"] == consumer)
                    || (member["kind"] == "program" && member["package"] == consumer)
            })
        {
            findings.push(format!(
                "test-tool consumer or contract missing: {consumer} {binding}"
            ));
        }
        let Some(program) = ledger
            .iter()
            .find(|program| program["kind"] == "program" && program["identity"] == callee)
        else {
            findings.push(format!("test-tool program absent: {callee}"));
            continue;
        };
        match text(row, "provider")? {
            "cargo-target" => cargo_target(row, program, metadata, findings)?,
            "meson-environment" => environment(build, row, program, &tests, findings)?,
            provider => findings.push(format!("unknown test-tool provider: {provider}")),
        }
    }
    let mut expected = BTreeSet::new();
    for call in ledger.iter().filter(|row| row["kind"] == "call") {
        if let Some(binding) = call["binding"].as_str().filter(|binding| {
            binding.starts_with("CARGO_BIN_EXE_")
                || ledger.iter().any(|program| {
                    program["kind"] == "program" && program["identity"] == call["callee"]
                })
        }) {
            expected.insert((
                text(call, "caller")?.to_owned(),
                binding.to_owned(),
                text(call, "callee")?.to_owned(),
            ));
        }
    }
    for payload in ledger.iter().filter(|row| row["kind"] == "payload") {
        for call in payload["calls"].as_array().ok_or("payload calls missing")? {
            if let Some(binding) = call["binding"].as_str() {
                expected.insert((
                    text(payload, "owner")?.to_owned(),
                    binding.to_owned(),
                    text(call, "callee")?.to_owned(),
                ));
            }
        }
    }
    for (consumer, binding, callee) in [
        (
            "superloop-pack",
            "PUBLIC_PACK_TEST_LINTER",
            "bin/superloop-lint",
        ),
        (
            "superloop-lane",
            "SUPERLOOP_TEST_REQUESTS_HELPER",
            "libexec/requests-helper",
        ),
    ] {
        if ledger
            .iter()
            .any(|row| row["kind"] == "package" && row["name"] == consumer)
        {
            expected.insert((consumer.to_owned(), binding.to_owned(), callee.to_owned()));
        }
    }
    for missing in expected.difference(&declared) {
        findings.push(format!(
            "unregistered test-tool: {} {} -> {}",
            missing.0, missing.1, missing.2
        ));
    }
    for stale in declared.difference(&expected) {
        findings.push(format!(
            "stale test-tool: {} {} -> {}",
            stale.0, stale.1, stale.2
        ));
    }
    Ok(rows)
}
