use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::{Instant, SystemTime};

use super::{
    INTERNAL_DIAGNOSTIC, PUBLICATION_DIAGNOSTIC, USAGE_DIAGNOSTIC, observe, parse_args,
    publish_failure, publish_observation,
};

pub fn main(arguments: Vec<std::ffi::OsString>) -> ExitCode {
    install_panic_hook();
    let started = Instant::now();
    match std::panic::catch_unwind(|| run_main(started, arguments)) {
        Ok(exit) => exit,
        Err(_panic) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if publish_failure(INTERNAL_DIAGNOSTIC, started.elapsed(), &mut output).is_err() {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
            }
            ExitCode::from(1)
        }
    }
}

fn run_main(started: Instant, arguments: Vec<std::ffi::OsString>) -> ExitCode {
    let Some(config) = parse_args(arguments) else {
        emit_stderr(USAGE_DIAGNOSTIC);
        return ExitCode::from(2);
    };

    let observation = match observe(&config, SystemTime::now()) {
        Ok(observation) => observation,
        Err(error) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if publish_failure(error.diagnostic(), started.elapsed(), &mut output).is_err() {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
            }
            return ExitCode::from(1);
        }
    };
    let status = observation.verdict().status();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if publish_observation(&observation, started.elapsed(), &mut output).is_err() {
        emit_stderr(PUBLICATION_DIAGNOSTIC);
        return ExitCode::from(1);
    }
    ExitCode::from(status)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_panic| {}));
}

fn emit_stderr(diagnostic: &[u8]) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    let _ignored = output.write_all(diagnostic).and_then(|()| output.flush());
}
