use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

pub fn dispatch(args: &[OsString]) -> Option<u8> {
    if args.first().is_some_and(|a| a == "--help" || a == "-h") {
        let help = b"usage: superloop enter|provision|verify|show|driver-launch|run-bridge|account|heartbeat|orchestrator|command ARG...\ndriver-launch LOOP RUN --driver-bin PATH --run-dir DIR -- ARGS...\nrun-bridge gpg|ssh LOOP -- ARG...; run-bridge gh -- ARG...\naccount keygen|check|create|admit-key ARG...\nheartbeat|orchestrator on|off|status|decide FILE\ncommand judge|answer|claim|complete|status LOOP (schema-one JSON on stdin)\n";
        return Some(u8::from(std::io::stdout().lock().write_all(help).is_err()));
    }
    if args.first().is_some_and(|a| a == "account") {
        return Some(account(&args[1..]));
    }
    if args.first().is_some_and(|a| a == "run-bridge") && args.get(1).is_some_and(|a| a == "gh") {
        return Some(gh(&args[2..]));
    }
    None
}

fn refuse(reason: impl std::fmt::Display) -> u8 {
    let _written = writeln!(std::io::stderr().lock(), "superloop: {reason}");
    2
}

fn account(args: &[OsString]) -> u8 {
    let program = std::env::var_os("SUPERLOOP_ACCOUNT_BIN")
        .or_else(|| option_env!("SUPERLOOP_ACCOUNT_BIN").map(OsString::from));
    let Some(program) = program.filter(|program| Path::new(program).is_absolute()) else {
        return refuse(
            "SUPERLOOP_ACCOUNT_BIN must name the configured absolute private account helper",
        );
    };
    refuse(Command::new(&program).args(args).exec())
}

fn gh(args: &[OsString]) -> u8 {
    let Some(toolbox) = std::env::var_os("CLAUDE_TOOLBOX").filter(|s| !s.is_empty()) else {
        return refuse("CLAUDE_TOOLBOX is required");
    };
    let Some(config) = std::env::var_os("GH_CONFIG_DIR").filter(|s| !s.is_empty()) else {
        return refuse("GH_CONFIG_DIR must name the loop forge configuration");
    };
    let mut assignment = OsString::from("GH_CONFIG_DIR=");
    assignment.push(config);
    let args = args.strip_prefix(&[OsString::from("--")]).unwrap_or(args);
    refuse(
        Command::new("flatpak-spawn")
            .args(["--host", "toolbox", "run", "-c"])
            .arg(toolbox)
            .arg("env")
            .arg(assignment)
            .arg("gh")
            .args(args)
            .exec(),
    )
}
