//! Owner-operated derivation from the canonical sign-in into private loop custody.

use crate::error::LaneError;
use serde_json::{Value, json};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("door-sign-in", detail)
}

/// Parse and perform the placement; neither reports nor arguments carry sign-in bytes.
///
/// # Errors
/// Refuses invalid arguments, unsafe custody, a busy loop, or an unsuccessful handoff.
pub fn run(owner_home: &Path, args: &[String]) -> Result<Value, LaneError> {
    let started = Instant::now();
    let (loop_name, supplied, dry_run, digest) = match args {
        [name] => (name, None, false, ""),
        [name, flag] if flag == "--dry-run" => (name, None, true, ""),
        [name, flag, digest]
            if flag == "--expect-digest"
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            (name, None, false, digest.as_str())
        }
        [name, flag, source] if flag == "--source" => (name, Some(source), false, ""),
        [name, flag, source, dry] if flag == "--source" && dry == "--dry-run" => {
            (name, Some(source), true, "")
        }
        [name, flag, source, expected, digest]
            if flag == "--source"
                && expected == "--expect-digest"
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            (name, Some(source), false, digest.as_str())
        }
        _ => {
            return Err(refusal(
                "expected door-sign-in LOOP [--dry-run | --expect-digest HEX]; --source may name only the canonical file",
            ));
        }
    };
    loop_home::validate_name(loop_name).map_err(|error| refusal(error.message()))?;
    let source = crate::credential::sign_in_dir(owner_home, loop_name).join("auth.json");
    if supplied.is_some_and(|path| Path::new(path) != source) {
        return Err(refusal(
            "door-sign-in-canonical-source: --source must name this loop's canonical auth.json; no scratch login is needed",
        ));
    }
    let owner = nix::unistd::Uid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(loop_name);
    // Placement reads the entry/settings binding but does not change a generation.
    // The receiver serializes publication beneath its private configuration directory.
    let _guard = crate::install::lock_loop_config(&config, true)?;
    let settings = crate::settings::Settings::read(&config.join("workers.toml"))?;
    let entry = settings
        .entry_bin
        .as_deref()
        .ok_or_else(|| refusal("entry_bin is absent"))?;
    crate::pinned::owner_executable(entry, owner)?;
    let registry = loop_home::load_registry(&loop_home::registry_path(None, owner_home))
        .map_err(|error| refusal(error.message()))?;
    let row = registry
        .row(loop_name, owner_home)
        .map_err(|error| refusal(error.message()))?;
    let private_home = row.home.join("private");
    let _refresh_guard = crate::credential::lock(owner_home, loop_name)?;
    let output = crate::fixture_exec::spawn(
        Command::new("/usr/bin/timeout")
            .args(["--kill-after=1", "20", "/usr/bin/python3", "-I", "-c"])
            .arg(include_str!("door_sign_in_owner.py"))
            .arg(entry)
            .arg(loop_name)
            .arg(row.uid.to_string())
            .arg(&private_home)
            .arg(&source)
            .arg(dry_run.to_string())
            .arg(digest)
            .arg(include_str!("door_sign_in_private.py"))
            .env_clear()
            .env("HOME", owner_home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_RUNTIME_DIR", format!("/run/user/{owner}"))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{owner}/bus"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .and_then(std::process::Child::wait_with_output)
    .map_err(|error| refusal(error.to_string()))?;
    if !output.status.success() {
        return Err(refusal(format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let evidence: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| refusal("placement helper report is invalid"))?;
    Ok(
        json!({"schema":1,"command":"door-sign-in","loop":loop_name,"dry_run":dry_run,
        "source":evidence["source"],"destination":evidence["destination"],
        "source_removed":evidence["source_removed"],"preview_sha256":evidence["preview_sha256"],"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}
