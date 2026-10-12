use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use superloop_cli_common::{CommandExit, ControlPlaneFields, parse_args_from};
use superloop_pack::{
    BuildRequest, VerifyRequest, build, verify, write_build_report, write_verify_report,
};

const USAGE_DIAGNOSTIC: &[u8] = b"superloop-pack: usage_error: invalid command-line arguments\n";
const INTERNAL_DIAGNOSTIC: &[u8] =
    b"superloop-pack: internal_failure: unexpected internal failure\n";
const PUBLICATION_DIAGNOSTIC: &[u8] =
    b"superloop-pack: publication_failure: agent-text publication failed\n";

#[derive(Debug, Parser)]
#[command(
    name = "superloop-pack",
    version,
    about = "Build and verify provenance-bound public source archives"
)]
struct Args {
    #[command(subcommand)]
    command: PackCommand,
}

#[derive(Debug, Subcommand)]
enum PackCommand {
    /// Cut the declared public tree into independent unsigned history.
    Cut {
        #[arg(long)]
        tag: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long)]
        author: String,
        /// Publication date in RFC 3339 form with an explicit offset or Z.
        #[arg(long, value_name = "RFC3339")]
        date: Option<String>,
        /// Annotated unsigned tag to create on the public commit.
        #[arg(long, value_name = "NAME")]
        public_tag: Option<String>,
        /// Override the whole commit message (non-empty; one trailing newline).
        #[arg(long, value_name = "TEXT")]
        message: Option<String>,
        /// Override the annotated tag message instead of reading CHANGELOG.md.
        #[arg(long, value_name = "TEXT", requires = "public_tag")]
        tag_message: Option<String>,
        /// Outside-tree private-value register required for unpublished addresses.
        #[arg(long)]
        burn_register: Option<PathBuf>,
        /// Built linter executable required for unpublished citation planning.
        #[arg(long)]
        linter: Option<PathBuf>,
    },
    /// Build a pack from one fixed tag and clean checkout.
    Build {
        /// Tag naming the reviewed source object.
        #[arg(long, value_name = "TAG", required = true)]
        tag: String,
        /// Destination ZIP file.
        #[arg(long, value_name = "FILE.zip", required = true)]
        out: PathBuf,
        /// Source-side burn-value register.
        #[arg(long, value_name = "PATH", required = true)]
        burn_register: PathBuf,
        /// Linter version recorded in provenance.
        #[arg(long, value_name = "TEXT")]
        linter_version: Option<String>,
    },
    /// Extract and verify a pack against its external burn register.
    StageVerify {
        /// Pack ZIP to verify.
        #[arg(long, value_name = "FILE.zip", required = true)]
        pack: PathBuf,
        /// Read-only source-side burn-value register.
        #[arg(long, value_name = "PATH", required = true)]
        burn_register: PathBuf,
        /// Linter executable to invoke.
        #[arg(long, value_name = "PATH", required = true)]
        linter: PathBuf,
        /// Existing empty absolute disk-backed directory.
        #[arg(long, value_name = "DIR", required = true)]
        staging: PathBuf,
    },
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-pack", env!("CARGO_PKG_VERSION"), None);
    install_panic_hook();
    let started = Instant::now();
    match std::panic::catch_unwind(|| run_main(started)) {
        Ok(exit) => exit,
        Err(_panic) => publish_boundary_failure(INTERNAL_DIAGNOSTIC, started.elapsed(), 1),
    }
}

fn run_main(started: Instant) -> ExitCode {
    let args = match parse_args_from::<Args, _, _>(std::env::args_os()) {
        Ok(args) => args,
        Err(exit) => return publish_parse_exit(exit, started.elapsed()),
    };
    run_command(args.command, started)
}

fn run_command(command: PackCommand, started: Instant) -> ExitCode {
    match command {
        PackCommand::Cut {
            tag,
            manifest,
            out,
            previous,
            author,
            date,
            public_tag,
            message,
            tag_message,
            burn_register,
            linter,
        } => {
            let Ok(repository_root) = std::env::current_dir() else {
                return publish_boundary_failure(INTERNAL_DIAGNOSTIC, started.elapsed(), 1);
            };
            let result = superloop_pack::cut(superloop_pack::CutRequest {
                repository_root: &repository_root,
                tag: &tag,
                manifest: &manifest,
                out: &out,
                previous: previous.as_deref(),
                author: &author,
                date: date.as_deref(),
                public_tag: public_tag.as_deref(),
                message: message.as_deref(),
                tag_message: tag_message.as_deref(),
                burn_register: burn_register.as_deref(),
                linter: linter.as_deref(),
            });
            publish_cut_result(&result, started.elapsed())
        }
        PackCommand::Build {
            tag,
            out,
            burn_register,
            linter_version,
        } => {
            let repository_root = match std::env::current_dir() {
                Ok(root) => root,
                Err(_error) => {
                    return publish_boundary_failure(
                        INTERNAL_DIAGNOSTIC,
                        started.elapsed(),
                        CommandExit::Failure.code(),
                    );
                }
            };
            let result = build(BuildRequest {
                tag: &tag,
                out: &out,
                burn_register: &burn_register,
                linter_version: linter_version.as_deref(),
                repository_root: &repository_root,
            });
            let status = result
                .as_ref()
                .map_or_else(|error| error.exit_status(), |_report| 0);
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if write_build_report(&result, started.elapsed(), &mut output).is_err() {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
                return CommandExit::Failure.exit_code();
            }
            ExitCode::from(status)
        }
        PackCommand::StageVerify {
            pack,
            burn_register,
            linter,
            staging,
        } => {
            let result = verify(VerifyRequest {
                pack: &pack,
                burn_register: &burn_register,
                linter: &linter,
                staging: &staging,
            });
            let status = result
                .as_ref()
                .map_or_else(superloop_pack::VerifyError::exit_status, |_report| 0);
            let stdout = io::stdout();
            let mut output = stdout.lock();
            if write_verify_report(&result, started.elapsed(), &mut output).is_err() {
                emit_stderr(PUBLICATION_DIAGNOSTIC);
                return CommandExit::Failure.exit_code();
            }
            ExitCode::from(status)
        }
    }
}

fn publish_cut_result(
    result: &Result<superloop_pack::CutReport, superloop_pack::CutError>,
    wall: Duration,
) -> ExitCode {
    let status = if result.is_ok() { 0 } else { 3 };
    if superloop_pack::write_cut_report(result, wall, &mut io::stdout().lock()).is_err() {
        emit_stderr(PUBLICATION_DIAGNOSTIC);
        return CommandExit::Failure.exit_code();
    }
    ExitCode::from(status)
}

fn publish_parse_exit(exit: superloop_cli_common::CliExit, wall: Duration) -> ExitCode {
    match exit.record.fields {
        Some(
            ControlPlaneFields::Help { text } | ControlPlaneFields::Version { version: text, .. },
        ) => publish_control_text(text.as_bytes(), wall, exit.exit.code(), "ok"),
        _ => publish_boundary_failure(USAGE_DIAGNOSTIC, wall, CommandExit::Usage.code()),
    }
}

fn publish_boundary_failure(diagnostic: &[u8], wall: Duration, status: u8) -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if output
        .write_all(diagnostic)
        .and_then(|()| write_terminal_lines(&mut output, wall, status, "FAILED"))
        .is_err()
    {
        emit_stderr(PUBLICATION_DIAGNOSTIC);
        return CommandExit::Failure.exit_code();
    }
    ExitCode::from(status)
}

fn publish_control_text(text: &[u8], wall: Duration, status: u8, verdict: &str) -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let published = output.write_all(text).and_then(|()| {
        if !text.ends_with(b"\n") {
            output.write_all(b"\n")?;
        }
        write_terminal_lines(&mut output, wall, status, verdict)
    });
    if published.is_err() {
        emit_stderr(PUBLICATION_DIAGNOSTIC);
        CommandExit::Failure.exit_code()
    } else {
        ExitCode::from(status)
    }
}

fn write_terminal_lines<W: io::Write>(
    output: &mut W,
    wall: Duration,
    status: u8,
    verdict: &str,
) -> io::Result<()> {
    let wall = format!("{}.{:03}s", wall.as_secs(), wall.subsec_millis());
    writeln!(
        output,
        "summary command=control exit={status} wall={wall} verdict={verdict}"
    )?;
    writeln!(
        output,
        "RUN-REPORT exit={status} wall={wall} verdict={verdict}"
    )?;
    output.flush()
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|_panic| {}));
}

fn emit_stderr(diagnostic: &[u8]) {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    let _ignored = output.write_all(diagnostic).and_then(|()| output.flush());
}
