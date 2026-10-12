use std::io;
use std::process::ExitCode;

use super::{FeedError, USAGE_DIAGNOSTIC, emit_failure_document, parse_args, run_with_messages};
use superloop_cli_common::{
    CliExit, CommandExit, ControlPlaneRecord, emit_control_plane_record, install_json_panic_hook,
    redact_text,
};

const COMMAND_NAME: &str = "superloop-lane";

pub fn main(arguments: Vec<std::ffi::OsString>) -> ExitCode {
    install_json_panic_hook(COMMAND_NAME);

    let config = match parse_args(arguments) {
        Ok(config) => config,
        Err(exit) => return emit_cli_exit(&exit),
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    match run_with_messages(&config, &mut output, &mut io::stderr().lock()) {
        Ok(()) => CommandExit::Success.exit_code(),
        Err(error) => emit_runtime_failure(&mut output, error),
    }
}

fn emit_cli_exit(exit: &CliExit) -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if emit_failure_document(&mut output, "usage_error", USAGE_DIAGNOSTIC).is_err() {
        return emit_control(
            &ControlPlaneRecord::diagnostic(COMMAND_NAME, FeedError::Relay.diagnostic().trim_end()),
            CommandExit::Failure,
        );
    }
    emit_control(&exit.record, exit.exit)
}

fn emit_runtime_failure(output: &mut impl io::Write, error: FeedError) -> ExitCode {
    if error != FeedError::Relay
        && emit_failure_document(output, error.kind(), error.diagnostic()).is_err()
    {
        return emit_control(
            &ControlPlaneRecord::diagnostic(COMMAND_NAME, FeedError::Relay.diagnostic().trim_end()),
            CommandExit::Failure,
        );
    }

    let diagnostic = redact_text(error.diagnostic().trim_end());
    emit_control(
        &ControlPlaneRecord::diagnostic(COMMAND_NAME, &diagnostic),
        CommandExit::Failure,
    )
}

fn emit_control(record: &ControlPlaneRecord, intended: CommandExit) -> ExitCode {
    emit_control_plane_record(record)
        .map_or(CommandExit::Failure, |()| intended)
        .exit_code()
}
