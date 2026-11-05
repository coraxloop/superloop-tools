use std::process::ExitCode;
fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-mail", env!("CARGO_PKG_VERSION"), None);
    ExitCode::from(loop_home::mail::command::entry(
        &std::env::args_os().skip(1).collect::<Vec<_>>(),
        &mut std::io::stderr().lock(),
    ))
}
