//! Observation command routing and metadata publication.
use crate::{Envelope, identity, launch::entry, observe, process, receipt, record};

use clap::{Parser, Subcommand};
use record::Result;
use std::io::{self, IsTerminal as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use superloop_cli_common::{CommandExit, ControlPlaneRecord, emit_control_plane_record};

const PROGRAM: &str = "superloop-credential-custody";

#[derive(Parser)]
#[command(name = PROGRAM, version, about = "Observe sealed-file metadata and calibration identity")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate completed sealed files with the reviewed isolated parser.
    LengthObserve {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        case: String,
        #[arg(long)]
        receipt: String,
    },
    /// Observe one file's representation in a separate non-calibration case.
    FormatDiscover {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        case: String,
        #[arg(long)]
        receipt: String,
    },
    /// Compare the complete live identity without modifying calibration.
    IdentityCheck {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        calibration: PathBuf,
        #[arg(long)]
        receipt: String,
    },
    /// Own a bounded sequential fixture campaign through retained completion.
    CalibrationRun {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        campaign: String,
    },
    /// Observe the live keeper's invocation-bound retained completion.
    Completion {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        case: String,
    },
    /// Request inventory and verify the retained observation-only process handle.
    Descriptors {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        case: String,
    },
    /// Request the keeper's single-use release against its immutable inventory.
    BarrierRelease {
        #[arg(long)]
        parameters: PathBuf,
        #[arg(long)]
        case: String,
    },
}

pub fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    std::panic::catch_unwind(run)
        .unwrap_or_else(|_| diagnostic("internal-error", CommandExit::Failure))
}

fn diagnostic(class: &'static str, exit: CommandExit) -> ExitCode {
    let _ignored = emit_control_plane_record(&ControlPlaneRecord::diagnostic(
        PROGRAM,
        &entry::failure_message(class),
    ));
    exit.exit_code()
}

fn run() -> ExitCode {
    if let Err(class) = process::initialize() {
        return diagnostic(class, CommandExit::Failure);
    }
    let start = Instant::now();
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
    if io::stdout().is_terminal() {
        let _ignored = emit_control_plane_record(&ControlPlaneRecord::tty_refusal(PROGRAM));
        return CommandExit::Usage.exit_code();
    }
    match execute(&cli.command, start) {
        Ok(()) => CommandExit::Success.exit_code(),
        Err(class) => diagnostic(class, CommandExit::Failure),
    }
}

fn launcher(command: &Command) -> Option<(entry::Command, &std::path::Path, &str)> {
    match command {
        Command::CalibrationRun {
            parameters,
            campaign,
        } => Some((entry::Command::CalibrationRun, parameters, campaign)),
        Command::Completion { parameters, case } => {
            Some((entry::Command::Completion, parameters, case))
        }
        Command::Descriptors { parameters, case } => {
            Some((entry::Command::Descriptors, parameters, case))
        }
        Command::BarrierRelease { parameters, case } => {
            Some((entry::Command::BarrierRelease, parameters, case))
        }
        _ => None,
    }
}

fn execute(command: &Command, start: Instant) -> Result<()> {
    let launch = launcher(command);
    if let Some((operation, parameters, case)) = launch {
        let evidence = entry::run(operation, parameters, case)?;
        let envelope = Envelope {
            schema: 1,
            command: operation.label(),
            case: case.into(),
            outcome: match operation {
                entry::Command::CalibrationRun | entry::Command::Completion => "completed",
                entry::Command::Descriptors => "observed",
                entry::Command::BarrierRelease => "released",
            },
            wall_us: start.elapsed().as_micros(),
            evidence,
        };
        return superloop_cli_common::emit(&envelope).map_err(|_| "output-write");
    }
    execute_observation(command, start)
}
fn execute_observation(command: &Command, start: Instant) -> Result<()> {
    let (Command::LengthObserve {
        parameters,
        receipt: receipt_name,
        ..
    }
    | Command::FormatDiscover {
        parameters,
        receipt: receipt_name,
        ..
    }
    | Command::IdentityCheck {
        parameters,
        receipt: receipt_name,
        ..
    }) = command
    else {
        return Err("launch-command");
    };
    if !record::name(receipt_name)
        || receipt_name.starts_with('.')
        || receipt_name.ends_with(".partial")
    {
        return Err("receipt-name");
    }
    let bytes = receipt::parameters(parameters)?;
    match command {
        Command::FormatDiscover { case, .. } => {
            let record = record::parse_discovery(&bytes)?;
            if case != &record.case {
                return Err("case-identity");
            }
            publish(
                "format-discover",
                "observed",
                &record.case,
                &record.evidence_root,
                receipt_name,
                observe::discover(&record)?,
                start,
            )
        }
        Command::LengthObserve { case, .. } => {
            let record = record::parse(&bytes)?;
            if case != &record.case {
                return Err("case-identity");
            }
            publish(
                "length-observe",
                "ok",
                &record.case,
                &record.evidence_root,
                receipt_name,
                observe::run(&record)?,
                start,
            )
        }
        Command::IdentityCheck { calibration, .. } => {
            let record = record::parse(&bytes)?;
            publish(
                "identity-check",
                "ok",
                &record.case,
                &record.evidence_root,
                receipt_name,
                identity::run(&record, calibration)?,
                start,
            )
        }
        _ => Err("launch-command"),
    }
}

fn publish(
    label: &'static str,
    outcome: &'static str,
    case: &str,
    root: &std::path::Path,
    receipt_name: &str,
    evidence: serde_json::Value,
    start: Instant,
) -> Result<()> {
    let envelope = Envelope {
        schema: if label == "format-discover" { 1 } else { 2 },
        command: label,
        case: case.into(),
        outcome,
        wall_us: start.elapsed().as_micros(),
        evidence,
    };
    let mut bytes = serde_json::to_vec(&envelope).map_err(|_| "result-encoding")?;
    bytes.push(b'\n');
    receipt::publish(root, receipt_name, &bytes)?;
    superloop_cli_common::emit(&envelope).map_err(|_| "output-write")
}

#[cfg(test)]
mod launch_routing_tests {
    use super::*;
    /// ´test:unit:launcher-routing-preserves-role-and-case´
    #[test]
    fn launcher_routing_preserves_role_and_case() {
        for (name, expected) in [
            ("calibration-run", entry::Command::CalibrationRun),
            ("descriptors", entry::Command::Descriptors),
            ("barrier-release", entry::Command::BarrierRelease),
            ("completion", entry::Command::Completion),
        ] {
            let parsed = Cli::try_parse_from([
                PROGRAM,
                name,
                "--parameters",
                "/synthetic-policy",
                if name == "calibration-run" {
                    "--campaign"
                } else {
                    "--case"
                },
                "sample",
            ])
            .unwrap();
            assert_eq!(
                launcher(&parsed.command),
                Some((
                    expected,
                    std::path::Path::new("/synthetic-policy"),
                    "sample"
                ))
            );
            assert_eq!(expected.label(), name);
        }
    }
}
