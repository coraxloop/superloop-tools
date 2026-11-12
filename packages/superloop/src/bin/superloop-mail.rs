use std::process::ExitCode;
fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-mail", env!("CARGO_PKG_VERSION"), None);
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|mode| mode == "serve" || mode == "_serve" || mode == "scan")
    {
        superloop_cli_common::init_json_tracing(tracing::Level::INFO);
    }
    ExitCode::from(loop_home::mail::command::entry(
        &arguments,
        &mut std::io::stderr().lock(),
    ))
}
