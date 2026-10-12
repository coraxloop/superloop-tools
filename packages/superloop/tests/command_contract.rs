use serde_json::{Value, json};
use std::io::Write as _;
use std::process::{Command, Stdio};

fn refused(action: &str, loop_name: &str, input: &Value, rule: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_superloop"))
        .args(["command", action, loop_name])
        .env("HOME", "/caller-supplied/home")
        .env(
            "SUPERLOOP_COMMAND_REQUESTS_HELPER",
            "/caller-supplied/helper",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("built entry");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.to_string().as_bytes())
        .expect("input");
    let output = child.wait_with_output().expect("entry result");
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(output.stdout, [] as [u8; 0]);
    let refusal: Value = serde_json::from_slice(&output.stderr).expect("named refusal");
    assert_eq!(refusal["rule"], rule, "{refusal}");
}

/// ´claim:command:direct-command-unknown-envelope-refuses-before-identity-lookup´
/// ´test:integration:direct-command-unknown-envelope-refuses-before-identity-lookup´
#[test]
fn direct_command_unknown_envelope_refuses_before_identity_lookup() {
    refused(
        "status",
        "fixture",
        &json!({"schema":2,"binding":null,"resolve":null}),
        "execute-command-request-shape",
    );
}

/// ´claim:command:direct-command-caller-environment-cannot-select-loop-identity´
/// ´test:integration:direct-command-caller-environment-cannot-select-loop-identity´
#[test]
fn direct_command_caller_environment_cannot_select_loop_identity() {
    let caller = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .expect("identity lookup")
        .expect("registered test account");
    let different = if caller.name == "fixture" {
        "different"
    } else {
        "fixture"
    };
    refused(
        "status",
        different,
        &json!({"schema":1,"binding":null,"resolve":null}),
        "execute-command-snapshot-custody",
    );
}
