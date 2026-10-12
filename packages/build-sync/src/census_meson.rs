//! Inventory executable-bearing Meson forms, including calls nested in loops.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

type Result<T> = std::result::Result<T, String>;

fn quoted(input: &mut std::iter::Peekable<std::str::Chars<'_>>, quote: char) -> Result<String> {
    let mut token = String::from(quote);
    let triple = input.peek() == Some(&quote) && {
        let mut probe = input.clone();
        probe.next();
        probe.peek() == Some(&quote)
    };
    if triple {
        input.next();
        input.next();
        token.push(quote);
        token.push(quote);
    }
    let mut closing = 0;
    while let Some(value) = input.next() {
        token.push(value);
        if value == '\\' && !triple {
            token.push(input.next().ok_or("unfinished Meson string escape")?);
            continue;
        }
        closing = if value == quote { closing + 1 } else { 0 };
        if closing == if triple { 3 } else { 1 } {
            return Ok(token);
        }
    }
    Err("unfinished Meson string".into())
}

pub fn tokenize(source: &str) -> Result<Vec<String>> {
    let mut input = source.chars().peekable();
    let mut result = Vec::new();
    while let Some(value) = input.next() {
        if value.is_whitespace() {
            continue;
        }
        if value == '#' {
            for next in input.by_ref() {
                if next == '\n' {
                    break;
                }
            }
        } else if value == '\'' || value == '"' {
            result.push(quoted(&mut input, value)?);
        } else if value.is_alphanumeric() || value == '_' {
            let mut word = String::from(value);
            while input
                .peek()
                .is_some_and(|next| next.is_alphanumeric() || *next == '_')
            {
                word.push(input.next().ok_or("Meson token ended unexpectedly")?);
            }
            result.push(word);
        } else {
            result.push(String::from(value));
        }
    }
    Ok(result)
}

fn forms(path: &str, source: &str) -> Result<Vec<Value>> {
    let tokens = tokenize(source)?;
    let mut bodies = source.split("dependency_ledger += ['''\n");
    let mut scope = bodies.next().unwrap_or_default().to_owned();
    for body in bodies {
        let tail = body
            .strip_prefix("''']")
            .or_else(|| body.split_once("\n''']").map(|(_, tail)| tail))
            .ok_or("unfinished Meson dependency declaration")?;
        scope.push_str(tail);
    }
    let scope =
        crate::digest(&serde_json::to_vec(&tokenize(&scope)?).map_err(|error| error.to_string())?);
    let mut result = Vec::new();
    let mut occurrences = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        if ![
            "find_program",
            "run_command",
            "custom_target",
            "run_target",
            "test",
            "add_install_script",
            "configure_file",
        ]
        .contains(&token.as_str())
            || tokens.get(index + 1).is_none_or(|next| next != "(")
        {
            continue;
        }
        let mut depth = 1;
        let mut end = index + 2;
        while depth != 0 {
            match tokens
                .get(end)
                .map(String::as_str)
                .ok_or("unfinished Meson call")?
            {
                "(" => depth += 1,
                ")" => depth -= 1,
                _ => {}
            }
            end += 1;
        }
        let expression = &tokens[index..end];
        if ["configure_file", "custom_target"].contains(&token.as_str())
            && !expression.windows(2).any(|pair| pair == ["command", ":"])
        {
            continue;
        }
        let occurrence = occurrences.entry(token).or_insert(0_u64);
        *occurrence += 1;
        let encoded = serde_json::to_vec(expression).map_err(|error| error.to_string())?;
        result.push(
            json!({"site":format!("{path}:{token}#{occurrence}"),"path":path,
            "form":token,"expression":expression,"sha256":crate::digest(&encoded),"scope_sha256":scope}),
        );
    }
    Ok(result)
}

pub fn inventory(root: &Path, ledger: &[Value], findings: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut paths = vec!["meson.build".to_owned()];
    for entry in fs::read_dir(root.join("packages")).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path().join("meson.build").is_file() {
            paths.push(format!(
                "packages/{}/meson.build",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    paths.sort();
    let mut sites = Vec::new();
    for path in paths {
        let source = fs::read_to_string(root.join(&path)).map_err(|error| error.to_string())?;
        sites.extend(forms(&path, &source)?);
    }
    let mut declared = BTreeMap::new();
    for row in ledger.iter().filter(|row| row["kind"] == "meson-call") {
        let site = row["site"].as_str().ok_or("Meson call site missing")?;
        if declared.insert(site, row).is_some() {
            findings.push(format!("duplicate Meson call: {site}"));
        }
    }
    for site in &sites {
        let identity = site["site"].as_str().ok_or("Meson call identity missing")?;
        if let Some(row) = declared.remove(identity) {
            check(row, site, ledger, findings)?;
        } else {
            findings.push(format!("unaccounted Meson executable form: {identity}"));
        }
    }
    findings.extend(
        declared
            .keys()
            .map(|site| format!("stale Meson executable form: {site}")),
    );
    Ok(sites)
}

fn check(row: &Value, site: &Value, ledger: &[Value], findings: &mut Vec<String>) -> Result<()> {
    let identity = site["site"].as_str().ok_or("Meson call identity missing")?;
    if row["sha256"] != site["sha256"] {
        findings.push(format!(
            "Meson executable form differs from review: {identity}"
        ));
    }
    if row["scope_sha256"] != site["scope_sha256"] {
        findings.push(format!(
            "Meson executable variable scope differs from review: {identity}"
        ));
    }
    for field in ["caller", "contract", "lookup"] {
        if row[field].as_str().is_none_or(str::is_empty) {
            findings.push(format!("Meson executable form {identity} lacks {field}"));
        }
    }
    let callees = row["callees"]
        .as_array()
        .ok_or("Meson callees must be an array")?;
    if callees.is_empty() {
        findings.push(format!("Meson executable form has no callee: {identity}"));
    }
    for callee in callees {
        if !ledger.iter().any(|target| {
            (target["kind"] == "program" || target["kind"] == "external-program")
                && target["identity"] == *callee
        }) {
            findings.push(format!(
                "Meson executable form has unregistered callee: {identity}: {callee}"
            ));
        }
    }
    Ok(())
}
