use crate::ToggleError;
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use crate::orchestrator::{MAX_RULEBOOK_BYTES, configured_path, folded_cwd};
use crate::sha256::digest_hex;

#[derive(Clone, Copy)]
pub enum ToggleCommand {
    On,
    Off,
    Status,
}

/// Run the selected toggle operation.
///
/// # Errors
/// Returns a redacted error when configuration, state access or formatting fails.
pub fn execute(command: ToggleCommand, global: bool) -> Result<Vec<u8>, ToggleError> {
    let state_dir = configured_path(
        "ORCHESTRATOR_STATE_DIR",
        "~/.local/state/superloop-tools/hook",
    );
    let rulebook = configured_path(
        "ORCHESTRATION_FILE",
        "~/.local/share/orchestration-instance/ORCHESTRATION.md",
    );
    let cwd = env::var("PWD")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            env::current_dir().map_or_else(
                |_| String::from("."),
                |path| path.to_string_lossy().into_owned(),
            )
        });
    let (root, folded) = folded_cwd(&cwd);
    let root_text = root.to_string_lossy();
    if !matches!(command, ToggleCommand::Status) {
        fs::create_dir_all(&state_dir).map_err(|_| ToggleError)?;
    }
    let project_flag = state_dir.join(format!("orchestrator-disabled{folded}"));
    let global_flag = state_dir.join("orchestrator-disabled-GLOBAL");
    let selected = if global { &global_flag } else { &project_flag };

    match command {
        ToggleCommand::On => {
            if let Err(error) = fs::remove_file(selected)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(ToggleError);
            }
            let scope = if global {
                String::from("orchestrator ON globally\n")
            } else {
                format!("orchestrator ON for {root_text}\n")
            };
            Ok(scope.into_bytes())
        }
        ToggleCommand::Off => {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(selected)
                .map_err(|_| ToggleError)?;
            let scope = if global {
                String::from("orchestrator OFF globally\n")
            } else {
                format!("orchestrator OFF for {root_text}\n")
            };
            Ok(scope.into_bytes())
        }
        ToggleCommand::Status => status(
            &state_dir,
            &rulebook,
            &root_text,
            &global_flag,
            &project_flag,
        ),
    }
}

fn status(
    state_dir: &Path,
    rulebook: &Path,
    cwd: &str,
    global_flag: &Path,
    project_flag: &Path,
) -> Result<Vec<u8>, ToggleError> {
    let global_off = global_flag.exists();
    let project_off = project_flag.exists();
    let mut output = String::new();
    writeln!(
        output,
        "{} ({cwd})",
        if global_off || project_off {
            "OFF"
        } else {
            "ON"
        }
    )
    .map_err(|_| ToggleError)?;
    writeln!(output, "global: {}", if global_off { "off" } else { "on" })
        .map_err(|_| ToggleError)?;
    writeln!(
        output,
        "project: {}",
        if project_off { "off" } else { "on" }
    )
    .map_err(|_| ToggleError)?;
    write_rulebook_status(&mut output, rulebook)?;
    write_last_log(&mut output, state_dir);
    Ok(output.into_bytes())
}

fn write_rulebook_status(output: &mut String, rulebook: &Path) -> Result<(), ToggleError> {
    writeln!(output, "rulebook: {}", rulebook.to_string_lossy()).map_err(|_| ToggleError)?;
    let metadata = match fs::metadata(rulebook) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            output.push_str("exists: no (missing)\n");
            return Ok(());
        }
        Err(_) => {
            output.push_str("exists: no (missing)\n");
            return Ok(());
        }
    };
    let size = metadata.len();
    let mtime = metadata.mtime();
    if let Ok(bytes) = fs::read(rulebook) {
        let budget = if size <= MAX_RULEBOOK_BYTES as u64 {
            "ok"
        } else {
            "oversize"
        };
        writeln!(output, "exists: yes").map_err(|_| ToggleError)?;
        writeln!(
            output,
            "size: {size} bytes ({budget}, budget <= {MAX_RULEBOOK_BYTES})"
        )
        .map_err(|_| ToggleError)?;
        writeln!(output, "mtime: {mtime}").map_err(|_| ToggleError)?;
        writeln!(output, "sha256: {}", digest_hex(&bytes)).map_err(|_| ToggleError)?;
    } else {
        writeln!(output, "exists: yes").map_err(|_| ToggleError)?;
        writeln!(
            output,
            "size: {size} bytes (unreadable, budget <= {MAX_RULEBOOK_BYTES})"
        )
        .map_err(|_| ToggleError)?;
        writeln!(output, "mtime: {mtime}").map_err(|_| ToggleError)?;
        output.push_str("sha256: unreadable\n");
    }
    Ok(())
}

fn write_last_log(output: &mut String, state_dir: &Path) {
    let log = state_dir.join("orchestrator.log");
    let bytes = fs::read(log).unwrap_or_default();
    if bytes.is_empty() {
        output.push_str("last log: none\n");
        return;
    }
    let without_final_lf = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let last = without_final_lf
        .rsplit(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    output.push_str("last log: ");
    output.push_str(&String::from_utf8_lossy(last));
    output.push('\n');
}

#[must_use]
pub fn flags(state_dir: &Path, cwd: &str) -> (PathBuf, PathBuf) {
    let (_, folded) = folded_cwd(cwd);
    (
        state_dir.join("orchestrator-disabled-GLOBAL"),
        state_dir.join(format!("orchestrator-disabled{folded}")),
    )
}
