//! Private gateway service command surface. Human decisions use common requests.
use lane_gateway::{Gateway, GatewayError, ServeConfig};
use serde::Serialize;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use superloop_cli_common::{CommandExit, ControlPlaneRecord, emit_control_plane_record};

const COMMAND_NAME: &str = "gateway-service";
const HELP: &str = "gateway-service register TOML_PATH | deregister LANE | status | check-request LANE JSON_PATH | migrate-proposals | serve";

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(COMMAND_NAME, env!("CARGO_PKG_VERSION"), None);
    superloop_cli_common::install_json_panic_hook(COMMAND_NAME);
    let arguments: Vec<_> = env::args().skip(1).collect();
    let words: Vec<_> = arguments.iter().map(String::as_str).collect();
    if matches!(words.as_slice(), ["--help" | "-h"]) {
        return emit_control(
            &ControlPlaneRecord::help(COMMAND_NAME, HELP),
            CommandExit::Success,
        );
    }
    if !matches!(
        words.as_slice(),
        ["register" | "deregister", _]
            | ["status" | "serve" | "migrate-proposals"]
            | ["check-request", _, _]
    ) {
        return emit_control(
            &ControlPlaneRecord::usage_error(COMMAND_NAME, "invalid_subcommand_arguments"),
            CommandExit::Usage,
        );
    }
    let gateway = match Gateway::from_environment() {
        Ok(gateway) => gateway,
        Err(error) => return emit_failure(&error),
    };
    match words.as_slice() {
        ["register", path] => match gateway.register_path(Path::new(path)) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => emit_failure(&error),
        },
        ["deregister", lane] => match gateway.deregister(lane) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => emit_failure(&error),
        },
        ["serve"] => {
            let config = match ServeConfig::from_environment(&gateway) {
                Ok(config) => config,
                Err(error) => return emit_failure(&error),
            };
            match gateway.serve(&config) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => emit_failure(&error),
            }
        }
        _ => {
            if let Some(exit) = refuse_terminal_stdout() {
                return exit;
            }
            match words.as_slice() {
                ["status"] => emit_result(gateway.status()),
                ["migrate-proposals"] => emit_result(gateway.migrate_proposals()),
                ["check-request", lane, path] => match std::fs::read_to_string(path) {
                    Ok(source) => emit_result(gateway.check_request(lane, &source)),
                    Err(error) => emit_fixed_failure(&format!("read request: {error}")),
                },
                _ => emit_fixed_failure("invalid dispatch"),
            }
        }
    }
}

fn refuse_terminal_stdout() -> Option<ExitCode> {
    superloop_cli_common::stdout_tty_refusal_record(COMMAND_NAME).map(|record| {
        emit_control_plane_record(&record)
            .map_or(CommandExit::Failure, |()| CommandExit::Usage)
            .exit_code()
    })
}

fn emit_result<T>(result: Result<T, GatewayError>) -> ExitCode
where
    T: Serialize,
{
    match result {
        Ok(result) => match superloop_cli_common::emit(&result) {
            Ok(()) => CommandExit::Success.exit_code(),
            Err(_error) => emit_fixed_failure("failed to write JSON result"),
        },
        Err(error) => emit_failure(&error),
    }
}

fn emit_failure(error: &GatewayError) -> ExitCode {
    if let GatewayError::CrashReportWriteFailed { failure, .. } = error {
        let original = ControlPlaneRecord::diagnostic(COMMAND_NAME, &failure.to_string());
        if emit_control_plane_record(&original).is_err() {
            return CommandExit::Failure.exit_code();
        }
        return emit_fixed_failure("serve crash report write failed");
    }
    emit_fixed_failure(&error.to_string())
}

fn emit_fixed_failure(message: &str) -> ExitCode {
    emit_control(
        &ControlPlaneRecord::diagnostic(COMMAND_NAME, message),
        CommandExit::Failure,
    )
}

fn emit_control(record: &ControlPlaneRecord, intended: CommandExit) -> ExitCode {
    emit_control_plane_record(record)
        .map_or(CommandExit::Failure, |()| intended)
        .exit_code()
}
