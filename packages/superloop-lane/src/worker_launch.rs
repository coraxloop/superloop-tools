//! Exact-path dispatch to the separate host worker helper.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, ExitCode};

/// Execute the configured host helper; successful exec preserves its streams and status.
pub fn command(args: &[OsString]) -> ExitCode {
    let program = std::env::var_os("SUPERLOOP_WORKER_RUN_BIN")
        .or_else(|| option_env!("SUPERLOOP_WORKER_RUN_BIN").map(OsString::from));
    let Some(program) = program.filter(|path| Path::new(path).is_absolute()) else {
        let _written = writeln!(
            std::io::stderr().lock(),
            "SUPERLOOP_WORKER_RUN_BIN must name the configured absolute private worker-run helper"
        );
        return ExitCode::from(2);
    };
    let failure = Command::new(&program).arg("launch").args(args).exec();
    let _written = writeln!(std::io::stderr().lock(), "worker-run: {failure}");
    ExitCode::from(1)
}
