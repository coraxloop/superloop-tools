use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use staff_provision::{CommandOutput, CommandSpec, ProcessRunner, RunError, Runner};

struct PinnedRunner {
    known_hosts: Option<PathBuf>,
}

impl Runner for PinnedRunner {
    fn run(&mut self, request: &CommandSpec) -> Result<CommandOutput, RunError> {
        let mut request = request.clone();
        if request.remote {
            let hosts = self.known_hosts.as_ref().filter(|path| path.is_absolute() && path.is_file()).ok_or_else(|| RunError {
                detail: "SUPERLOOP_ACCOUNT_KNOWN_HOSTS must name an existing absolute pinned host-key file".into(),
                wall: Duration::ZERO,
            })?;
            let options = [
                "StrictHostKeyChecking=yes".to_owned(),
                format!("UserKnownHostsFile={}", hosts.display()),
                "GlobalKnownHostsFile=/dev/null".into(),
                "UpdateHostKeys=no".into(),
                "ControlMaster=no".into(),
                "ControlPath=none".into(),
                "PermitLocalCommand=no".into(),
                "KnownHostsCommand=none".into(),
            ];
            request.argv.splice(
                1..1,
                options.into_iter().flat_map(|option| ["-o".into(), option]),
            );
        }
        ProcessRunner.run(&request)
    }
}

fn main() -> ExitCode {
    superloop_cli_common::version_or_exit("account", env!("CARGO_PKG_VERSION"), None);
    let mut arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut output = io::stdout().lock();
    let mut error = io::stderr().lock();
    let Some(action) = arguments.first().cloned() else {
        let _written = writeln!(error, "usage: account keygen|check|create|admit-key ARG…");
        return ExitCode::from(2);
    };
    arguments.remove(0);
    if action == "keygen" {
        return ExitCode::from(staff_provision::loop_keygen_entry(
            arguments,
            &mut ProcessRunner,
            &mut output,
            &mut error,
        ));
    }
    if !matches!(action.to_str(), Some("check" | "create" | "admit-key")) {
        let _written = writeln!(error, "usage: account keygen|check|create|admit-key ARG…");
        return ExitCode::from(2);
    }
    let position = arguments
        .chunks(2)
        .take_while(|pair| {
            pair.len() == 2 && matches!(pair[0].to_str(), Some("--server" | "--ssh-alias"))
        })
        .count()
        * 2;
    arguments.insert(position, action);
    let mut runner = PinnedRunner {
        known_hosts: std::env::var_os("SUPERLOOP_ACCOUNT_KNOWN_HOSTS").map(PathBuf::from),
    };
    ExitCode::from(staff_provision::staff_provision_entry(
        arguments,
        &mut runner,
        &mut io::stdin().lock(),
        &mut output,
        &mut error,
    ))
}
