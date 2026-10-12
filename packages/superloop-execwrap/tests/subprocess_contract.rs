//! Real child-process proofs of the library's capture and outcome contracts.

use std::ffi::OsString;
use std::path::Path;
use superloop_execwrap::{ExecError, ExecOutcome, RoutingConfig, preflight_routing, run};

fn shell(script: &str, config: &RoutingConfig) -> ExecOutcome {
    let command = [OsString::from("sh"), "-c".into(), script.into()];
    run(&command, config, |_| {}).expect("child runs")
}

/// ´test:integration:raw-redirect-is-byte-exact´
#[test]
fn raw_redirect_is_byte_exact() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let log = directory.path().join("raw.log");
    let config = RoutingConfig {
        redirect: Some(log.clone()),
        ..RoutingConfig::default()
    };
    let result = shell(
        r"printf '\377\376\000\033[31m'; head -c 65536 /dev/zero | tr '\000' '\245'; printf '\n'",
        &config,
    );
    assert_eq!(result.exit_code, 0);
    assert!(!result.data_loss);
    let mut expected = vec![0xff, 0xfe, 0, 0x1b, b'[', b'3', b'1', b'm'];
    expected.extend(std::iter::repeat_n(0xa5_u8, 65536));
    expected.push(b'\n');
    assert_eq!(std::fs::read(log).expect("captured bytes"), expected);
}

/// ´test:integration:split-streams-route-to-their-own-files´
#[test]
fn split_streams_route_to_their_own_files() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let stdout = directory.path().join("stdout");
    let stderr = directory.path().join("stderr");
    let config = RoutingConfig {
        redirect_output: Some(stdout.clone()),
        redirect_error: Some(stderr.clone()),
        ..RoutingConfig::default()
    };
    let result = shell("printf 'out\\n'; printf 'err\\n' >&2", &config);
    assert_eq!(result.exit_code, 0);
    assert!(!result.data_loss);
    assert_eq!(std::fs::read(stdout).expect("stdout bytes"), b"out\n");
    assert_eq!(std::fs::read(stderr).expect("stderr bytes"), b"err\n");
}

/// ´test:integration:child-exit-code-is-propagated´
#[test]
fn child_exit_code_is_propagated() {
    for status in [0, 1, 2, 3, 7, 42, 255] {
        let outcome = shell(&format!("exit {status}"), &RoutingConfig::default());
        assert_eq!(outcome.exit_code, status);
        assert!(!outcome.data_loss);
    }
}

/// ´test:integration:signal-termination-maps-to-128-plus-signal´
#[test]
fn signal_termination_maps_to_128_plus_signal() {
    let outcome = shell("kill -TERM $$", &RoutingConfig::default());
    assert_eq!(outcome.exit_code, 143);
    assert!(!outcome.data_loss);
}

/// ´test:integration:spawn-failure-does-not-echo-child-program-text´
#[test]
fn spawn_failure_does_not_echo_child_program_text() {
    for program in [
        "/nonexistent/SHOULD_NOT_APPEAR",
        "https://user:SHOULD_NOT_APPEAR@example.invalid/tool",
    ] {
        let error =
            run(&[program.into()], &RoutingConfig::default(), |_| {}).expect_err("no executable");
        assert!(matches!(error, ExecError::Spawn { .. }));
        assert!(!error.to_string().contains("SHOULD_NOT_APPEAR"));
        assert!(!format!("{error:?}").contains("SHOULD_NOT_APPEAR"));
    }
}

/// ´test:integration:ambiguous-same-path-routing-is-a-usage-failure´
#[test]
fn ambiguous_same_path_routing_is_a_usage_failure() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let log = directory.path().join("both.log");
    let config = RoutingConfig {
        redirect: Some(log.clone()),
        redirect_output: Some(log.clone()),
        ..RoutingConfig::default()
    };
    assert!(matches!(
        preflight_routing(&config),
        Err(ExecError::AmbiguousRedirection { .. })
    ));
    assert!(!log.exists());
    assert!(matches!(
        run(&["true".into()], &config, |_| {}),
        Err(ExecError::AmbiguousRedirection { .. })
    ));
    assert!(!log.exists());
}

/// ´test:integration:prefixed-redirect-tags-streams´
#[test]
fn prefixed_redirect_tags_streams() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let log = directory.path().join("prefixed.log");
    let config = RoutingConfig {
        redirect_prefixed: Some(log.clone()),
        ..RoutingConfig::default()
    };
    let outcome = shell("printf 'out-line\\n'; printf 'err-line\\n' >&2", &config);
    assert_eq!(outcome.exit_code, 0);
    assert!(!outcome.data_loss);
    let text = std::fs::read_to_string(log).expect("prefixed output");
    assert!(text.contains(">>> out-line"));
    assert!(text.contains("*** err-line"));
}

/// ´test:integration:data-loss-fails-a-successful-child´
#[test]
fn data_loss_fails_a_successful_child() {
    if !Path::new("/dev/full").exists() {
        return;
    }
    let config = RoutingConfig {
        redirect: Some("/dev/full".into()),
        ..RoutingConfig::default()
    };
    let result = shell("printf 'doomed bytes\\n'", &config);
    assert_eq!(result.exit_code, 0);
    assert!(result.data_loss, "callers must reject incomplete capture");
}

/// ´test:integration:unredirected-streams-pass-through-pipes´
#[test]
fn unredirected_streams_pass_through_pipes() {
    // A fresh test process isolates parent-stream relay from harness capture.
    let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "relay_fixture", "--nocapture"])
        .env("EXECWRAP_RELAY_FIXTURE", "1")
        .output()
        .expect("fixture process");
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .windows(b"out-bytes".len())
            .any(|bytes| bytes == b"out-bytes")
    );
    assert!(
        output
            .stderr
            .windows(b"err-bytes".len())
            .any(|bytes| bytes == b"err-bytes")
    );
    assert!(
        !output
            .stderr
            .windows(b"SHOULD_NOT_APPEAR".len())
            .any(|bytes| bytes == b"SHOULD_NOT_APPEAR")
    );
}

/// ´test:integration:relay-fixture´
#[test]
fn relay_fixture() {
    if std::env::var_os("EXECWRAP_RELAY_FIXTURE").is_none() {
        return;
    }
    let command: Vec<OsString> = [
        "sh",
        "-c",
        "printf out-bytes; printf err-bytes >&2",
        "sh",
        "SHOULD_NOT_APPEAR",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let result = run(&command, &RoutingConfig::default(), |_| {}).expect("child runs");
    assert_eq!(result.exit_code, 0);
    assert!(!result.data_loss);
}
