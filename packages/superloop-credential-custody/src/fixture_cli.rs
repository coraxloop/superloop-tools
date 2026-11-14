//! Rehearsal-only fixture. Ordinary installation never publishes this binary.
use crate::{fixture, process};
use clap::{Parser, Subcommand};
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use superloop_cli_common::{CommandExit, ControlPlaneRecord, emit_control_plane_record};

const PROGRAM: &str = "credential-fixture";
#[derive(Parser)]
#[command(name = PROGRAM, version, about = "Emit internal synthetic patterns to two named pipes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Validate the public case, stop for external inspection, then emit.
    Emit {
        #[arg(long)]
        case_record: PathBuf,
    },
}
fn diagnostic(class: &'static str, status: CommandExit) -> ExitCode {
    let _ignored = emit_control_plane_record(&ControlPlaneRecord::diagnostic(PROGRAM, class));
    status.exit_code()
}
pub fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    std::panic::catch_unwind(run)
        .unwrap_or_else(|_| diagnostic("internal-error", CommandExit::Failure))
}
fn run() -> ExitCode {
    if let Err(class) = process::initialize() {
        return diagnostic(class, CommandExit::Failure);
    }
    let cli = match superloop_cli_common::parse_args_from::<Cli, _, _>(std::env::args_os()) {
        Ok(cli) => cli,
        Err(control) => {
            return if emit_control_plane_record(&control.record).is_ok() {
                control.exit_code()
            } else {
                CommandExit::Failure.exit_code()
            };
        }
    };
    if std::io::stdout().is_terminal() {
        let _ignored = emit_control_plane_record(&ControlPlaneRecord::tty_refusal(PROGRAM));
        return CommandExit::Usage.exit_code();
    }
    let Command::Emit { case_record } = cli.command;
    match fixture::emit(&case_record) {
        Ok(()) => CommandExit::Success.exit_code(),
        Err(class) => diagnostic(class, CommandExit::Failure),
    }
}
