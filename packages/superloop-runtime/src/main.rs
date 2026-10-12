mod runtime;

use std::process::ExitCode;
use superloop_cli_common::{ControlPlaneRecord, emit_control_plane_record};

const COMMAND: &str = "superloop-runtime";
const HELP: &str = "superloop-runtime create\nsuperloop-runtime exec [--] AGENT_ARGUMENTS...\nsuperloop-runtime run-host [--] AGENT_ARGUMENTS...\nsuperloop-runtime run-toolbox [--] AGENT_ARGUMENTS...";

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(COMMAND, env!("CARGO_PKG_VERSION"), None);
    superloop_cli_common::install_json_panic_hook(COMMAND);
    let mut args = std::env::args_os().skip(1);
    let verb = args.next();
    let mut tail: Vec<_> = args.collect();
    if tail.first().is_some_and(|arg| arg == "--") {
        tail.remove(0);
    }
    let result = match verb.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("--help" | "-h") if tail.is_empty() => {
            return publish(&ControlPlaneRecord::help(COMMAND, HELP), 0);
        }
        Some("create") if tail.is_empty() => runtime::create(),
        Some("exec") => runtime::execute(&tail),
        Some("run-host") => runtime::run_host(&tail),
        Some("run-toolbox") => runtime::run_toolbox(&tail),
        _ => return publish(&ControlPlaneRecord::usage_error(COMMAND, HELP), 2),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let status = if error.starts_with("runtime-start-refused:") {
                125
            } else {
                1
            };
            publish(&ControlPlaneRecord::diagnostic(COMMAND, &error), status)
        }
    }
}

fn publish(record: &ControlPlaneRecord, code: u8) -> ExitCode {
    match emit_control_plane_record(record) {
        Ok(()) => ExitCode::from(code),
        Err(_) => ExitCode::FAILURE,
    }
}
