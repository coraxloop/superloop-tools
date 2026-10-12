//! Durable driver commands kept separate from the box command grammar.

#[path = "../../../lane-lifecycle/src/monitor_lock.rs"]
pub(crate) mod monitor_lock;

pub mod claude;
pub mod codex;
pub mod follow;
pub mod status;

use std::ffi::OsString;
use std::process::ExitCode;

/// Dispatch one public driver command without changing the box command grammar.
pub fn command(arguments: &[OsString]) -> ExitCode {
    let Some((action, rest)) = arguments.split_first() else {
        return usage();
    };
    if action == "status" {
        return status::command(rest.to_vec());
    }
    if action == "follow" {
        return follow::command(rest.to_vec());
    }
    if action != "start" && action != "resume" {
        return usage();
    }
    let [flag, backend, arguments @ ..] = rest else {
        return usage();
    };
    if flag != "--backend" {
        return usage();
    }
    if action == "resume"
        && !arguments.iter().any(|word| {
            use std::os::unix::ffi::OsStrExt as _;
            word.as_bytes().starts_with(b"-r")
        })
    {
        return usage();
    }
    match backend.to_str() {
        Some("claude") => claude::command(arguments.to_vec()),
        Some("codex") => codex::command(arguments.to_vec()),
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    let record = superloop_cli_common::ControlPlaneRecord::usage_error(
        "superloop-lane",
        "driver {start|resume} --backend {claude|codex} ARGS; driver status RUN; driver follow RUN [--save-offset]",
    );
    if superloop_cli_common::emit_control_plane_record(&record).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::from(2)
}
