//! Executable selectors transported by the trusted entry to a driver.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn required(name: &str, setting: &str) -> Result<Value, String> {
    let source = std::env::var(name).map_err(|_| format!("missing {setting}: {name} is absent"))?;
    if source.len() > 65_536 {
        return Err(format!("{setting}: {name} exceeds 65536 bytes"));
    }
    serde_json::from_str(&source).map_err(|error| format!("{setting}: {name}: {error}"))
}

fn argv(value: &Value, name: &str) -> Result<Vec<String>, String> {
    let words = value
        .as_array()
        .ok_or_else(|| format!("missing {name} argument array"))?;
    let words = words
        .iter()
        .map(|word| {
            word.as_str()
                .filter(|word| !word.contains('\0'))
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} has an invalid argument"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if words
        .first()
        .is_none_or(|program| !Path::new(program).is_absolute())
    {
        return Err(format!("{name} requires an absolute executable"));
    }
    Ok(words)
}

/// Resolve the configured backend without a search path or home-derived default.
///
/// # Errors
///
/// Names the missing or malformed selector before a driver allocates run state.
pub fn command(backend: &str) -> Result<Command, String> {
    let configured = required("LANE_BACKEND_ARGV", "backend_argv")?;
    let words = argv(&configured[backend], &format!("backend_argv.{backend}"))?;
    let mut command = Command::new(&words[0]);
    command.args(&words[1..]);
    Ok(command)
}

/// Validate the entry's transported settings and retain their source evidence.
///
/// # Errors
///
/// Refuses absent selectors, missing source evidence, or disagreeing values.
pub fn evidence(backend: &str) -> Result<Value, String> {
    let driver = required("LANE_DRIVER_ARGV", "driver_argv")?;
    argv(&driver, "driver_argv")?;
    let backends = required("LANE_BACKEND_ARGV", "backend_argv")?;
    let selected = argv(&backends[backend], &format!("backend_argv.{backend}"))?;
    let source = required("LANE_SETTINGS_EVIDENCE", "workers settings evidence")?;
    if source["path"]
        .as_str()
        .is_none_or(|path| !Path::new(path).is_absolute())
        || source["driver_argv"] != driver
        || source["backend_argv"] != backends
    {
        return Err("workers settings evidence differs from driver_argv or backend_argv".into());
    }
    Ok(serde_json::json!({"program": selected[0], "settings": source}))
}

fn token(text: &str) -> String {
    let mut output = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/._-:".contains(&byte) {
            output.push(char::from(byte));
        } else {
            let _written = write!(output, "%{byte:02X}");
        }
    }
    output
}

pub(crate) fn annotate(report: &mut Vec<u8>, evidence: &Value) {
    let Some(program) = evidence["program"].as_str() else {
        return;
    };
    let Some(path) = evidence["settings"]["path"].as_str() else {
        return;
    };
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(evidence["settings"].to_string().as_bytes()) {
        let _written = write!(digest, "{byte:02x}");
    }
    if report.last() == Some(&b'\n') {
        report.pop();
    }
    report.extend_from_slice(
        format!(
            " backend_program={} settings={} settings_sha256={digest}\n",
            token(program),
            token(path)
        )
        .as_bytes(),
    );
}
