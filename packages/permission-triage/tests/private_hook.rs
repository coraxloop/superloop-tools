use std::io::Write as _;
use std::process::{Command, Output, Stdio};

fn invoke(binary: &str, arguments: &[&str], mode: Option<&str>, input: &[u8]) -> Output {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(mode) = mode {
        command.env("PERMISSION_TRIAGE_MODE", mode);
    }
    let mut child = command.spawn().expect("start helper");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("input");
    child.wait_with_output().expect("helper output")
}

/// ´test:integration:private-hook-version-identifies-the-private-binary´
#[test]
fn private_hook_version_identifies_the_private_binary() {
    let output = invoke(
        env!("CARGO_BIN_EXE_permission-triage-hook"),
        &["--version"],
        None,
        b"",
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    let record: serde_json::Value = serde_json::from_slice(&output.stderr).expect("version record");
    assert_eq!(record["command"], "permission-triage-hook");
    assert_eq!(record["kind"], "version");
}
