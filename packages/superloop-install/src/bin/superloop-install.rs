use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;
use superloop_cli_common::{CommandExit, ControlPlaneFields, parse_args_from};
use superloop_install::{InstallRequest, install, write_report};

const USAGE_DIAGNOSTIC: &[u8] = b"superloop-install: usage_error: invalid command-line arguments\n";
const INTERNAL_DIAGNOSTIC: &[u8] =
    b"superloop-install: internal_failure: unexpected internal failure\n";
const PUBLICATION_DIAGNOSTIC: &[u8] =
    b"superloop-install: publication_failure: agent-text publication failed\n";

#[derive(Debug, Parser)]
#[command(
    name = "superloop-install",
    version,
    about = "Render and transactionally install declared rulebook targets"
)]
struct Args {
    /// TOML install map.
    #[arg(long, value_name = "PATH", required = true)]
    map: PathBuf,

    /// Override the destination root declared by the map.
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,

    /// Boundary containing build outputs and their build records.
    #[arg(long, value_name = "PATH")]
    build_root: Option<PathBuf>,

    /// Boundary containing generic render bases.
    #[arg(long, value_name = "PATH")]
    shape_root: Option<PathBuf>,

    /// Override the registry file named by a registry map.
    #[arg(long, value_name = "PATH")]
    registry: Option<PathBuf>,

    /// Stage the resolved destination roots below this directory.
    #[arg(long, value_name = "PATH")]
    destdir: Option<PathBuf>,

    /// Release tag to bind to the checkout and report.
    #[arg(long, value_name = "TAG")]
    release_tag: Option<String>,

    /// Expected commit of the release tag and checkout.
    #[arg(long, value_name = "COMMIT")]
    release_commit: Option<String>,

    /// Validate and report the plan without mutation.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("superloop-install", env!("CARGO_PKG_VERSION"), None);
    install_panic_hook();
    let started = Instant::now();
    match std::panic::catch_unwind(|| run_main(started)) {
        Ok(exit) => exit,
        Err(_panic) => publish_boundary_failure(INTERNAL_DIAGNOSTIC, started.elapsed(), 1),
    }
}

fn run_main(started: Instant) -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    match arguments.get(1).and_then(|argument| argument.to_str()) {
        Some("inventory") => return run_inventory(arguments.into_iter().skip(1), started),
        Some("retire") => return run_retirement(arguments.into_iter().skip(1), started),
        _ => {}
    }
    let args = match parse_args_from::<Args, _, _>(std::env::args_os()) {
        Ok(args) => args,
        Err(exit) => return publish_parse_exit(exit, started.elapsed()),
    };
    let repository_root = match std::env::var_os("MESON_SOURCE_ROOT")
        .map(PathBuf::from)
        .map_or_else(std::env::current_dir, Ok)
    {
        Ok(root) => root,
        Err(_error) => {
            return publish_boundary_failure(INTERNAL_DIAGNOSTIC, started.elapsed(), 1);
        }
    };
    let destdir = args
        .destdir
        .or_else(|| std::env::var_os("DESTDIR").map(PathBuf::from));
    let registry = args
        .registry
        .or_else(|| std::env::var_os("RULEBOOK_INSTALL_REGISTRY").map(PathBuf::from));
    let result = install(InstallRequest {
        map_path: &args.map,
        repository_root: &repository_root,
        root_override: args.root.as_deref(),
        build_root: args.build_root.as_deref(),
        shape_root: args.shape_root.as_deref(),
        registry_override: registry.as_deref(),
        destdir: destdir.as_deref(),
        release_tag: args.release_tag.as_deref(),
        release_commit: args.release_commit.as_deref(),
        dry_run: args.dry_run,
    });
    let status = result
        .as_ref()
        .map_or_else(|error| error.class().exit_status(), |_report| 0);
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if write_report(&result, started.elapsed(), &mut output).is_err() {
        emit_stderr(PUBLICATION_DIAGNOSTIC);
        return CommandExit::Failure.exit_code();
    }
    ExitCode::from(status)
}

fn publish_retirement_result(result: Result<usize, String>, started: Instant) -> ExitCode {
    match result {
        Ok(count) => publish_control_text(
            format!("destinations={count}\n").as_bytes(),
            started.elapsed(),
            0,
            "ok",
        ),
        Err(error) => publish_boundary_failure(
            format!("superloop-install: retirement_refused: {error}\n").as_bytes(),
            started.elapsed(),
            1,
        ),
    }
}

fn run_inventory(
    arguments: impl Iterator<Item = std::ffi::OsString>,
    started: Instant,
) -> ExitCode {
    match parse_args_from::<superloop_install::retirement::InventoryArgs, _, _>(arguments) {
        Ok(args) => {
            publish_retirement_result(superloop_install::retirement::inventory(&args), started)
        }
        Err(exit) => publish_parse_exit(exit, started.elapsed()),
    }
}

fn run_retirement(
    arguments: impl Iterator<Item = std::ffi::OsString>,
    started: Instant,
) -> ExitCode {
    match parse_args_from::<superloop_install::retirement::RetireArgs, _, _>(arguments) {
        Ok(args) => {
            publish_retirement_result(superloop_install::retirement::retire(&args), started)
        }
        Err(exit) => publish_parse_exit(exit, started.elapsed()),
    }
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
        "summary unchanged=0 new=0 changed=0 refused={} dry_run=no wall={wall} last_completed=none",
        usize::from(status != 0),
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
