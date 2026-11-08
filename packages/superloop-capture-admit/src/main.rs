#![doc = include_str!("../README.md")]
mod cli;
mod copy;
mod manifest;
mod store;

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(
        "superloop-capture-admit",
        env!("CARGO_PKG_VERSION"),
        None,
    );
    let start = Instant::now();
    // Argument refusals take the shared usage status; every other refusal is a failure.
    let result = cli::parse()
        .map_err(|error| (2, error))
        .and_then(|config| store::run(config).map_err(|error| (1, error)));
    let mut output = io::stdout().lock();
    let status = match result {
        Ok(report) => u8::from(output.write_all(&report).is_err()),
        Err((code, error)) => {
            let _ignored = writeln!(io::stderr().lock(), "superloop-capture-admit: {error}");
            code
        }
    };
    let wall = writeln!(output, "wall={:.6}s", start.elapsed().as_secs_f64());
    ExitCode::from(if wall.is_ok() { status } else { 1 })
}
