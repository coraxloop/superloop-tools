use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_superloop-run-report");
const MISSING_MOUNT: &str = "/superloop-run-report-test-mount-does-not-exist";

fn invoke(args: &[&str], rootfs_tmp: &str, workspace: &str) -> Output {
    Command::new(BINARY)
        .args(args)
        .env("RUN_REPORT_ROOTFS_TMP_MOUNT", rootfs_tmp)
        .env("RUN_REPORT_WORKSPACE_MOUNT", workspace)
        .output()
        .expect("superloop-run-report subprocess")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr")
}

/// ´test:integration:ordinary-child-status-passes-through´
#[test]
fn ordinary_child_status_passes_through() {
    let output = invoke(&["sh", "-c", "exit 23"], "/", "/");
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let stderr = stderr_text(&output);
    assert_eq!(stderr.lines().count(), 1);
    assert!(stderr.starts_with("RUN-REPORT exit=23 wall="));
    assert!(stderr.contains("s rootfs_tmp_left="));
    assert!(stderr.contains(" workspace_left="));
}

/// ´test:integration:missing-mounts-degrade-to-na´
#[test]
fn missing_mounts_degrade_to_na() {
    let output = invoke(&["true"], MISSING_MOUNT, MISSING_MOUNT);
    assert_eq!(output.status.code(), Some(0));
    let stderr = stderr_text(&output);
    assert!(stderr.ends_with(" rootfs_tmp_left=n/a workspace_left=n/a\n"));
}

/// ´test:integration:signal-death-is-128-plus-signal´
#[test]
fn signal_death_is_128_plus_signal() {
    let output = invoke(&["sh", "-c", "kill -TERM $$"], "/", "/");
    assert_eq!(output.status.code(), Some(143));
    assert!(stderr_text(&output).starts_with("RUN-REPORT exit=143 wall="));
}

/// ´test:integration:missing-executable-is-distinct-spawn-status´
#[test]
fn missing_executable_is_distinct_spawn_status() {
    let output = invoke(
        &["/superloop-run-report-test-command-does-not-exist"],
        MISSING_MOUNT,
        MISSING_MOUNT,
    );
    assert_eq!(output.status.code(), Some(127));
    assert!(stderr_text(&output).starts_with("RUN-REPORT exit=127 wall="));
}

/// ´test:integration:non-not-found-spawn-failure-is-status-126´
#[test]
fn non_not_found_spawn_failure_is_status_126() {
    let output = invoke(&["/"], MISSING_MOUNT, MISSING_MOUNT);
    assert_eq!(output.status.code(), Some(126));
    assert!(stderr_text(&output).starts_with("RUN-REPORT exit=126 wall="));
}

/// ´test:integration:empty-command-is-reported-usage-status´
#[test]
fn empty_command_is_reported_usage_status() {
    let output = invoke(&[], MISSING_MOUNT, MISSING_MOUNT);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_text(&output).starts_with("RUN-REPORT exit=2 wall="));
}

/// ´test:integration:child-streams-precede-terminal-report´
#[test]
fn child_streams_precede_terminal_report() {
    let output = invoke(
        &["sh", "-c", "printf child-out; printf child-err >&2"],
        MISSING_MOUNT,
        MISSING_MOUNT,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"child-out");
    assert!(stderr_text(&output).starts_with("child-errRUN-REPORT exit=0 wall="));
}
