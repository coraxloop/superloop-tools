use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use superloop_cli_common::{
    CommandExit, ControlPlaneRecord, emit_control_plane_record, parse_args_or_exit,
};

const COMMAND: &str = "build-sync";

#[derive(Parser)]
#[command(name = COMMAND, version, about = "Sync a Cargo binary or record a generated output")]
struct Args {
    #[arg(long, required_unless_present = "probe", conflicts_with = "probe")]
    ledger: Option<PathBuf>,
    #[arg(long, required_unless_present = "probe", conflicts_with = "probe")]
    source_root: Option<PathBuf>,
    #[arg(long, required_unless_present = "probe", conflicts_with = "probe")]
    source_repository: Option<String>,
    #[arg(long, required_unless_present = "probe", conflicts_with = "probe")]
    source_commit: Option<String>,
    #[arg(long, value_name = "NAME", default_value = "unset")]
    domain: String,
    #[arg(long, value_name = "EXECUTABLE", conflicts_with_all = ["probe", "record"])]
    artifact: Option<PathBuf>,
    #[arg(long, value_name = "STAMP", conflicts_with_all = ["record", "producer", "cargo", "manifest", "package", "bin", "output"])]
    probe: Option<PathBuf>,
    #[arg(long, value_name = "OUTPUT", requires = "producer", conflicts_with_all = ["cargo", "manifest", "package", "bin", "output"])]
    record: Option<PathBuf>,
    #[arg(long, value_name = "PROGRAM", requires = "record")]
    producer: Option<PathBuf>,
    #[arg(required_unless_present_any = ["probe", "record"])]
    cargo: Option<PathBuf>,
    #[arg(required_unless_present_any = ["probe", "record"])]
    manifest: Option<PathBuf>,
    #[arg(required_unless_present_any = ["probe", "record"])]
    package: Option<String>,
    #[arg(required_unless_present_any = ["probe", "record"])]
    bin: Option<String>,
    #[arg(required_unless_present_any = ["probe", "record"])]
    output: Option<PathBuf>,
}

#[derive(Parser)]
#[command(
    name = COMMAND,
    bin_name = "build-sync census",
    about = "Check the declared dependency graph"
)]
struct CensusArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    report: PathBuf,
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
    #[arg(long)]
    ledger: Option<PathBuf>,
}

fn main() -> ExitCode {
    superloop_cli_common::install_json_panic_hook(COMMAND);
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "census")
    {
        let args = match superloop_cli_common::parse_args_from::<CensusArgs, _, _>(
            std::env::args_os().skip(1),
        ) {
            Ok(args) => args,
            Err(exit) => {
                let _ignored = emit_control_plane_record(&exit.record);
                return exit.exit_code();
            }
        };
        let ledger = args.ledger.or_else(|| {
            std::env::current_exe()
                .ok()?
                .ancestors()
                .map(|parent| parent.join("dependency-ledger.jsonl"))
                .find(|candidate| candidate.is_file())
        });
        let Some(ledger) = ledger else {
            return finish(Err(
                "census requires --ledger or its Meson build's dependency-ledger.jsonl".into(),
            ));
        };
        return finish(build_sync::census::run(
            &args.root,
            &args.cargo,
            &ledger,
            &args.report,
        ));
    }
    let args = parse_args_or_exit::<Args>();
    if let Some(stamp) = args.probe {
        return if build_sync::probe(&stamp) {
            CommandExit::Success.exit_code()
        } else {
            CommandExit::Failure.exit_code()
        };
    }

    let identity = build_sync::identity::IdentityArgs {
        ledger: args.ledger.as_deref().expect("clap requires ledger"),
        root: args
            .source_root
            .as_deref()
            .expect("clap requires source root"),
        repository: args
            .source_repository
            .as_deref()
            .expect("clap requires repository identity"),
        source_commit: args
            .source_commit
            .as_deref()
            .expect("clap requires source commit"),
    };
    let result = if let Some(output) = args.record.as_deref() {
        build_sync::record(&build_sync::RecordArgs {
            identity: &identity,
            output,
            producer: args.producer.as_deref().expect("clap requires producer"),
            domain: &args.domain,
        })
    } else {
        let sync = build_sync::SyncArgs {
            identity: &identity,
            cargo: args.cargo.as_deref().expect("clap requires cargo"),
            manifest: args.manifest.as_deref().expect("clap requires manifest"),
            package: args.package.as_deref().expect("clap requires package"),
            bin: args.bin.as_deref().expect("clap requires bin"),
            output: args.output.as_deref().expect("clap requires output"),
            domain: &args.domain,
        };
        args.artifact.as_deref().map_or_else(
            || build_sync::sync(&sync),
            |artifact| build_sync::stage(&sync, artifact),
        )
    };
    finish(result)
}

fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => CommandExit::Success.exit_code(),
        Err(cause) => {
            let safe = superloop_cli_common::redact_text(&cause);
            let record = ControlPlaneRecord::diagnostic(COMMAND, &safe);
            let _ignored = emit_control_plane_record(&record);
            CommandExit::Failure.exit_code()
        }
    }
}
