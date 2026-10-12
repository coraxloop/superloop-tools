use std::process::ExitCode;

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"), None);
    ExitCode::from(permission_triage::hook_entry::execute())
}
