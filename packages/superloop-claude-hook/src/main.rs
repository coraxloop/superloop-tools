fn main() -> std::process::ExitCode {
    superloop_cli_common::version_or_exit("superloop-claude-hook", env!("CARGO_PKG_VERSION"), None);
    std::panic::set_hook(Box::new(|_| {}));
    std::process::ExitCode::from(superloop_claude_hook::execute(
        &std::env::args_os().skip(1).collect::<Vec<_>>(),
    ))
}
