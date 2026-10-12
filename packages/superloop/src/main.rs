use std::process::ExitCode;

mod bridges;
mod command;
mod dispatch;
mod session;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let argv0 = arguments.next().unwrap_or_default();
    if loop_home::app::argv0_bridge(&argv0).is_none() {
        superloop_cli_common::version_or_exit("superloop", env!("CARGO_PKG_VERSION"), None);
    }
    let arguments = arguments.collect::<Vec<_>>();
    if loop_home::app::argv0_bridge(&argv0).is_none()
        && let Some(status) = bridges::dispatch(&arguments)
            .or_else(|| command::dispatch(&arguments))
            .or_else(|| dispatch::dispatch(&arguments))
            .or_else(|| session::dispatch(&arguments))
    {
        return ExitCode::from(status);
    }
    let mut runner = loop_home::ProcessRunner;
    let mut output = std::io::stdout().lock();
    let mut error = std::io::stderr().lock();
    ExitCode::from(loop_home::enter_loop_entry(
        &argv0,
        arguments,
        &mut runner,
        &mut output,
        &mut error,
    ))
}
