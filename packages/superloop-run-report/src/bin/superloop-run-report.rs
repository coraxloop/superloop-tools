use std::env;
use std::io;
use std::process::ExitCode;

use superloop_run_report::{Mounts, run_report};

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-run-report", env!("CARGO_PKG_VERSION"), None);
    let command: Vec<_> = env::args_os().skip(1).collect();
    ExitCode::from(run_report(&command, &Mounts::from_env(), io::stderr()))
}
