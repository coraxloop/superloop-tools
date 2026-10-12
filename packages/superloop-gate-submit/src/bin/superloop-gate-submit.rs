use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

use superloop_gate_submit::{
    INTERNAL_DIAGNOSTIC, PUBLICATION_DIAGNOSTIC, execute, fallback_name, parse_args, publish,
    publish_with_object,
};

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-gate-submit", env!("CARGO_PKG_VERSION"), None);
    install_panic_hook();
    let started = Instant::now();
    match std::panic::catch_unwind(|| run_main(started)) {
        Ok(exit) => exit,
        Err(_panic) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if publish(
                &mut output,
                &[],
                Some(INTERNAL_DIAGNOSTIC),
                fallback_name(),
                1,
                started.elapsed(),
            )
            .is_err()
            {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
            }
            ExitCode::from(1)
        }
    }
}

fn run_main(started: Instant) -> ExitCode {
    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("LANE_VERIFY_TEST_PANIC").is_none(),
        "injected superloop-gate-submit panic before argument handling"
    );

    let config = match parse_args(std::env::args_os().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if publish(
                &mut output,
                &[],
                Some(error.diagnostic()),
                fallback_name(),
                2,
                started.elapsed(),
            )
            .is_err()
            {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
            }
            return ExitCode::from(2);
        }
    };

    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("LANE_VERIFY_TEST_PANIC_AFTER_PARSE").is_none(),
        "injected superloop-gate-submit panic after argument handling"
    );

    let name = config.name().to_owned();
    let (evidence, diagnostic, status, object) = match execute(&config) {
        Ok(result) => (
            result.evidence().to_vec(),
            None,
            result.status(),
            result.object().map(str::to_owned),
        ),
        Err(failure) => (
            failure.evidence().to_vec(),
            Some(failure.kind().diagnostic()),
            1,
            None,
        ),
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if publish_with_object(
        &mut output,
        &evidence,
        diagnostic,
        &name,
        status,
        started.elapsed(),
        object.as_deref(),
    )
    .is_err()
    {
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
