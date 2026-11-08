#![doc = include_str!("../README.md")]
mod cli;
mod copy;
mod manifest;
mod store;

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type OperationResult = std::result::Result<Vec<u8>, (u8, &'static str, Box<dyn std::error::Error>)>;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_panic| {}));
    let start = Instant::now();
    let result = catch_operation(|| {
        superloop_cli_common::version_or_exit(
            "superloop-capture-admit",
            env!("CARGO_PKG_VERSION"),
            None,
        );
        cli::parse()
            .map_err(|error| (2, "usage-error", error))
            .and_then(|config| store::run(config).map_err(|error| (1, "runtime-error", error)))
    });
    let status = match result {
        Ok(report) => {
            let mut output = io::stdout().lock();
            u8::from(
                output
                    .write_all(&report)
                    .and_then(|()| output.flush())
                    .is_err(),
            )
        }
        Err((code, class, error)) => {
            let mut diagnostic = io::stderr().lock();
            let _ignored = writeln!(diagnostic, "superloop-capture-admit: {class}: {error}")
                .and_then(|()| diagnostic.flush());
            code
        }
    };
    let verdict = if status == 0 { "ok" } else { "failed" };
    let mut output = io::stdout().lock();
    let report = writeln!(
        output,
        "RUN-REPORT exit={status} wall={:.6}s verdict={verdict}",
        start.elapsed().as_secs_f64()
    )
    .and_then(|()| output.flush());
    ExitCode::from(if report.is_ok() { status } else { 1 })
}

fn catch_operation(
    operation: impl FnOnce() -> OperationResult + std::panic::UnwindSafe,
) -> OperationResult {
    std::panic::catch_unwind(operation)
        .unwrap_or_else(|_payload| Err((1, "internal-error", "operation panicked".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic becomes fixed failure data without retaining its payload.
    ///
    /// # Panics
    /// Panics when the production boundary does not catch or classify the fixture panic.
    /// ´test:unit:panic-payload-becomes-a-classed-failure´
    #[test]
    fn panic_payload_becomes_a_classed_failure() {
        let (status, class, detail) = catch_operation(|| panic!("fictional payload")).unwrap_err();
        assert_eq!(status, 1);
        assert_eq!(class, "internal-error");
        assert_eq!(detail.to_string(), "operation panicked");
    }
}
