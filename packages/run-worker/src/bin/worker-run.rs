use std::process::ExitCode;

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("worker-run", env!("CARGO_PKG_VERSION"), None);
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|argument| {
        argument == "_mail-worker-birth"
            || argument == "_mail-worker-state"
            || argument == "_mail-worker-pins"
    }) {
        return ExitCode::from(loop_home::mail::worker_provision::entry(
            &arguments,
            &mut std::io::stderr().lock(),
        ));
    }
    let environment = run_worker::Environment::from_process();
    let mut runner = loop_home::ProcessRunner;
    let mut output = std::io::stdout().lock();
    let mut error = std::io::stderr().lock();
    ExitCode::from(run_worker::run_worker_entry(
        arguments,
        &environment,
        &mut runner,
        &mut output,
        &mut error,
    ))
}
