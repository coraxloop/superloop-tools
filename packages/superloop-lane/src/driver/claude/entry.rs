use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

use super::{
    Backend as _, ClaudeBackend, execute, fallback_report, fallback_result, internal_diagnostic,
    parse_args, publication_diagnostic, publish, read_prompt, runtime_diagnostic, usage_diagnostic,
};

pub fn main(arguments: Vec<std::ffi::OsString>) -> ExitCode {
    install_panic_hook();
    let started = Instant::now();
    let backend = ClaudeBackend::default();
    match std::panic::catch_unwind(|| run_main(started, &backend, arguments)) {
        Ok(exit) => exit,
        Err(_panic) => {
            let result = fallback_result(
                1,
                0,
                internal_diagnostic(backend.name()),
                "unknown",
                "unknown",
                started.elapsed().as_secs(),
            );
            publish_result(&result, backend.name());
            ExitCode::from(1)
        }
    }
}

fn run_main(
    started: Instant,
    backend: &ClaudeBackend,
    arguments: Vec<std::ffi::OsString>,
) -> ExitCode {
    let (config, backend) = match parse_args(arguments) {
        Ok(config) => config,
        Err(error) => {
            let result = error.refusal_diagnostic(backend.name()).map_or_else(
                || {
                    fallback_result(
                        2,
                        error.budget(),
                        usage_diagnostic(backend.name()),
                        "unknown",
                        "unknown",
                        started.elapsed().as_secs(),
                    )
                },
                |diagnostic| {
                    publish_resume_diagnostic(&diagnostic);
                    fallback_report(
                        2,
                        error.budget(),
                        "unknown",
                        "unknown",
                        started.elapsed().as_secs(),
                    )
                },
            );
            publish_result(&result, backend.name());
            return ExitCode::from(2);
        }
    };
    if let Some(diagnostic) = config.crash_recovery_diagnostic(backend.name()) {
        publish_resume_diagnostic(&diagnostic);
    }
    let prompt = match read_prompt(&config) {
        Ok(prompt) => prompt,
        Err(_error) => {
            let result = fallback_result(
                1,
                config.budget(),
                runtime_diagnostic(backend.name()),
                config.name(),
                "unknown",
                started.elapsed().as_secs(),
            );
            publish_result(&result, backend.name());
            return ExitCode::from(1);
        }
    };
    let result = execute(&backend, &config, &prompt);
    if let Some(diagnostic) = result.stderr_diagnostic() {
        publish_resume_diagnostic(diagnostic);
    }
    publish_result(&result, backend.name());
    ExitCode::from(result.status())
}

fn publish_result(result: &super::LaneResult, backend_name: &str) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if publish(&mut output, result).is_err() {
        let stderr = io::stderr();
        let mut fallback = stderr.lock();
        let _ignored = fallback
            .write_all(&publication_diagnostic(backend_name))
            .and_then(|()| fallback.flush());
    }
}

fn publish_resume_diagnostic(diagnostic: &[u8]) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    let _ignored = output.write_all(diagnostic).and_then(|()| output.flush());
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_panic| {}));
}
