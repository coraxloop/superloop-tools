//! Exact-path dispatch to the separate gateway service.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, ExitCode};

/// Execute the configured gateway service; successful exec preserves its streams and status.
pub fn command(args: &[OsString]) -> ExitCode {
    let program = std::env::var_os("SUPERLOOP_GATEWAY_SERVICE_BIN")
        .or_else(|| option_env!("SUPERLOOP_GATEWAY_SERVICE_BIN").map(OsString::from));
    let Some(program) = program.filter(|path| Path::new(path).is_absolute()) else {
        let _written = writeln!(
            std::io::stderr().lock(),
            "SUPERLOOP_GATEWAY_SERVICE_BIN must name the configured absolute private gateway-service helper"
        );
        return ExitCode::from(2);
    };
    let failure = Command::new(&program).args(args).exec();
    let _written = writeln!(std::io::stderr().lock(), "gateway-service: {failure}");
    ExitCode::from(1)
}
