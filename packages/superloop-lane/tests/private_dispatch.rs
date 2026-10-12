#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

/// ´test:integration:subject-roots-preserve-private-helper-argv-streams-and-status´
#[test]
fn subject_roots_preserve_private_helper_argv_streams_and_status() {
    let fixture = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let helper = fixture.path().join("private helper");
    let capture = fixture.path().join("capture");
    fs::write(&helper, b"#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$CAPTURE\"\nprintf 'helper stdout\\n'\nprintf 'helper stderr\\n' >&2\nexit 37\n").expect("helper");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("mode");
    let mut account = Command::new(std::env::var_os("SUPERLOOP_TEST_BINARY").expect(concat!(
        "SUPERLOOP_TEST_BINARY must name the registered superloop executable; ",
        "the cargo-test test in root meson.build supplies this binding; superloop is declared in packages/superloop/meson.build; ",
        "lane route: on the assigned worker node run cargo build --locked --workspace --bins, then ",
        "export SUPERLOOP_TEST_BINARY=\"$CARGO_TARGET_DIR/debug/superloop\" ",
        "before cargo test --locked with --no-fail-fast"
    )));
    account.args(["account", "check", "--server", "node a", "account"]);
    let mut worker = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    worker.args(["launch", "--host", "loop", "run", "--", "two words", "a\nb"]);
    let mut gateway = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
    gateway.args(["gateway", "check-request", "lane", "two words"]);
    for (mut command, setting, expected) in [
        (
            account,
            "SUPERLOOP_ACCOUNT_BIN",
            "check\0--server\0node a\0account\0",
        ),
        (
            worker,
            "SUPERLOOP_WORKER_RUN_BIN",
            "launch\0loop\0run\0--\0two words\0a\nb\0",
        ),
        (
            gateway,
            "SUPERLOOP_GATEWAY_SERVICE_BIN",
            "check-request\0lane\0two words\0",
        ),
    ] {
        let output = command
            .env(setting, &helper)
            .env("CAPTURE", &capture)
            .output()
            .expect("dispatch");
        assert_eq!(output.status.code(), Some(37), "{output:?}");
        assert_eq!(output.stdout, b"helper stdout\n");
        assert_eq!(output.stderr, b"helper stderr\n");
        assert_eq!(fs::read(&capture).expect("argv"), expected.as_bytes());
        fs::remove_file(&capture).expect("remove capture");
        let output = command
            .env(setting, "relative-helper")
            .output()
            .expect("refusal");
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains(setting));
        assert!(!capture.exists());
    }
}
