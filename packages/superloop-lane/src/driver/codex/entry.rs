use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

use super::{
    Backend as _, CodexBackend, execute, fallback_report, fallback_result, internal_diagnostic,
    parse_args, publication_diagnostic, publish, read_prompt, runtime_diagnostic, usage_diagnostic,
};

pub fn main(arguments: Vec<std::ffi::OsString>) -> ExitCode {
    if matches!(arguments.as_slice(), [arg] if arg == "--runtime-contract") {
        return if io::stdout().lock().write_all(b"boxed-runtime 1\n").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    install_panic_hook();
    let started = Instant::now();
    let backend = CodexBackend;
    match std::panic::catch_unwind(|| run_main(started, backend, arguments)) {
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
    backend: CodexBackend,
    arguments: Vec<std::ffi::OsString>,
) -> ExitCode {
    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("CODEX_LANE_TEST_PANIC").is_none(),
        "injected panic before argument handling"
    );

    let directory_error = directory_diagnostic(&arguments);
    let config = match parse_args(arguments) {
        Ok(config) => config,
        Err(error) => {
            let result = error
                .refusal_diagnostic(backend.name())
                .or(directory_error)
                .map_or_else(
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

    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("CODEX_LANE_TEST_PANIC_AFTER_PARSE").is_none(),
        "injected panic after argument handling"
    );

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
    let result = execute(&config, &prompt);
    if let Some(diagnostic) = result.stderr_diagnostic() {
        publish_resume_diagnostic(diagnostic);
    }
    publish_result(&result, backend.name());
    ExitCode::from(result.status())
}

fn directory_diagnostic(arguments: &[std::ffi::OsString]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let bytes = argument.as_bytes();
        if bytes == b"--" || bytes == b"-" || !bytes.starts_with(b"-") {
            break;
        }
        if bytes.starts_with(b"--") {
            if bytes != b"--ignore-pool" {
                arguments.next()?;
            }
            continue;
        }
        for (index, option) in bytes.iter().enumerate().skip(1) {
            if *option == b'P' {
                continue;
            }
            let value = if index + 1 < bytes.len() {
                std::ffi::OsStr::from_bytes(&bytes[index + 1..])
            } else if let Some(value) = arguments.next() {
                value.as_os_str()
            } else {
                return (*option == b'd').then(|| b"codex-lane: usage_error: -d received no value; expected an absolute existing run directory\n".to_vec());
            };
            if *option == b'd' {
                let path = std::path::Path::new(value);
                if !path.is_absolute() || !path.is_dir() {
                    let value = value.to_string_lossy();
                    return Some(format!("codex-lane: usage_error: -d received {value:?}; expected an absolute existing run directory\n").into_bytes());
                }
            }
            break;
        }
    }
    None
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
