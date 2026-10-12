use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use permission_triage::{ProbeStatus, run_topology_probe};

const USAGE: &str =
    "usage: permission-triage-topology --fixture-root DIR [--verdict FILE] [--test-roster ROSTER]";

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit(
        "permission-triage-topology",
        env!("CARGO_PKG_VERSION"),
        None,
    );
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    match run(&arguments) {
        Ok(code) => code,
        Err(CommandError::Usage) => {
            write_stderr(USAGE);
            ExitCode::from(2)
        }
        Err(CommandError::Infrastructure(reason)) => {
            write_stderr(&reason);
            ExitCode::from(1)
        }
    }
}

fn run(arguments: &[OsString]) -> Result<ExitCode, CommandError> {
    let parsed = parse_arguments(arguments)?;
    let report = {
        let stderr = io::stderr();
        let mut progress = stderr.lock();
        let result = if let Some(roster) = parsed.test_roster.as_deref() {
            permission_triage::topology::run_topology_probe_for_test(
                &parsed.fixture_root,
                parsed.verdict.as_deref(),
                &mut progress,
                roster,
            )
        } else {
            run_topology_probe(
                &parsed.fixture_root,
                parsed.verdict.as_deref(),
                &mut progress,
            )
        };
        result.map_err(|error| CommandError::Infrastructure(error.to_string()))?
    };
    let mut bytes = serde_json::to_vec_pretty(report.verdict())
        .map_err(|error| CommandError::Infrastructure(format!("verdict JSON failed: {error}")))?;
    bytes.push(b'\n');
    if let Some(path) = parsed.verdict {
        write_verdict_atomic(&path, &bytes)?;
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.flush())
            .map_err(|error| {
                CommandError::Infrastructure(format!("verdict output failed: {error}"))
            })?;
    }
    Ok(match report.status() {
        ProbeStatus::Ready => ExitCode::SUCCESS,
        ProbeStatus::Blocked => ExitCode::from(3),
        ProbeStatus::Infrastructure => ExitCode::from(1),
    })
}

fn write_verdict_atomic(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CommandError::Infrastructure("verdict path has no file name".to_owned()))?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    let nanoseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CommandError::Infrastructure(format!("verdict clock failed: {error}")))?
        .as_nanos();
    temporary_name.push(format!(
        ".permission-triage-topology.{}.{nanoseconds}.tmp",
        std::process::id()
    ));
    let temporary = path.with_file_name(temporary_name);
    let mut created = false;
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        created = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if write_result.is_err() && created {
        let _cleanup = fs::remove_file(&temporary);
    }
    write_result
        .map_err(|error| CommandError::Infrastructure(format!("verdict write failed: {error}")))
}

struct ParsedArguments {
    fixture_root: PathBuf,
    verdict: Option<PathBuf>,
    test_roster: Option<String>,
}

fn parse_arguments(arguments: &[OsString]) -> Result<ParsedArguments, CommandError> {
    let (arguments, test_roster) =
        if arguments.len() >= 2 && arguments[arguments.len() - 2] == "--test-roster" {
            let roster = arguments
                .last()
                .and_then(|value| value.to_str())
                .ok_or(CommandError::Usage)?;
            (&arguments[..arguments.len() - 2], Some(roster.to_owned()))
        } else {
            (arguments, None)
        };
    match arguments {
        [fixture_flag, fixture_root] if fixture_flag == "--fixture-root" => Ok(ParsedArguments {
            fixture_root: PathBuf::from(fixture_root.as_os_str()),
            verdict: None,
            test_roster,
        }),
        [fixture_flag, fixture_root, verdict_flag, verdict]
            if fixture_flag == "--fixture-root" && verdict_flag == "--verdict" =>
        {
            Ok(ParsedArguments {
                fixture_root: PathBuf::from(fixture_root.as_os_str()),
                verdict: Some(PathBuf::from(verdict.as_os_str())),
                test_roster,
            })
        }
        _ => Err(CommandError::Usage),
    }
}

enum CommandError {
    Usage,
    Infrastructure(String),
}

fn write_stderr(reason: &str) {
    let mut stderr = io::stderr().lock();
    if writeln!(stderr, "{reason}").is_ok() && stderr.flush().is_err() {}
}
