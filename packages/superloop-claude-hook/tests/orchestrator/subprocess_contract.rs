//! ADR-001 hook-JSON stream, status, redaction, and panic-boundary tests.

mod support;

use std::ffi::OsString;
use std::fs;

use serde_json::{Value, json};

use support::{
    NEW_MTIME_NS, NEW_RULEBOOK, OLD_MTIME_NS, OLD_RULEBOOK, TestDir, hook_payload,
    response_context, run_cli, run_hook, run_hook_bytes, run_hook_with_deployed_defaults,
    run_hook_with_env, write_rulebook,
};

fn startup(directory: &TestDir, session: &str) -> Value {
    let mut payload = hook_payload(directory, "SessionStart", session);
    payload["source"] = json!("startup");
    payload
}

/// ´test:integration:allow-with-context-is-one-hook-json-object-on-stdout´
#[test]
fn allow_with_context_is_one_hook_json_object_on_stdout() {
    let directory = TestDir::new("contract-context");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);

    let output = run_hook(&directory, &startup(&directory, "contract-session"));

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    let value: Value = serde_json::from_slice(&output.stdout).expect("one response object");
    assert_eq!(value.as_object().expect("object").len(), 1);
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "SessionStart");
    assert!(response_context(&output).contains(OLD_RULEBOOK));
    assert!(!output.stdout.ends_with(b"\n"));
}

/// ´test:integration:allow-without-context-has-empty-both-streams´
#[test]
fn allow_without_context_has_empty_both_streams() {
    let directory = TestDir::new("contract-empty");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let payload = startup(&directory, "contract-session");
    let first = run_hook(&directory, &payload);

    let second = run_hook(&directory, &payload);

    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(second.stdout, [] as [u8; 0]);
    assert_eq!(second.stderr, [] as [u8; 0]);
}

/// ´test:integration:malformed-nonobject-and-unsupported-events-refuse-without-state´
#[test]
fn malformed_nonobject_and_unsupported_events_refuse_without_state() {
    for (label, input) in [
        ("corrupt", b"{not-json".to_vec()),
        ("array", b"[]".to_vec()),
        ("null", b"null".to_vec()),
        ("unsupported", br#"{"hook_event_name":"Stop"}"#.to_vec()),
    ] {
        let directory = TestDir::new(label);
        let output = run_hook_bytes(&directory, &input, []);

        assert_eq!(output.status.code(), Some(2), "case {label}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("hook-event-mismatch"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("hook-event-mismatch"));
        assert!(!directory.state_dir().exists(), "case {label}");
    }
}

/// ´test:integration:internal-persistence-error-logs-only-a-class-and-fails-open´
#[test]
fn internal_persistence_error_logs_only_a_class_and_fails_open() {
    let directory = TestDir::new("contract-internal-error");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    directory.mkdir("state");
    directory.mkdir("state/orchestration-snapshot-contract-session-current.md.tmp");

    let output = run_hook(&directory, &startup(&directory, "contract/session"));

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let log = directory.read_string("state/orchestrator.log");
    assert!(log.contains("\"action\":\"internal_error\""));
    assert!(log.contains("\"error\":\"Io\""));
    assert!(!log.contains(OLD_RULEBOOK));
    assert!(!log.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!log.contains("traceback"));
}

/// ´test:integration:unknown-state-field-refuses-without-rewriting-the-record´
#[test]
fn unknown_state_field_refuses_without_rewriting_the_record() {
    let directory = TestDir::new("unknown-state-field");
    let session = "unknown-field";
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let first = run_hook(&directory, &startup(&directory, session));
    assert_eq!(first.status.code(), Some(0));
    assert_ne!(first.stdout, [] as [u8; 0]);
    let mut state = directory.state(session);
    state["future_compatible_field"] = json!({"kept": true});
    let mut bytes = serde_json::to_vec(&state).expect("serialize altered state");
    bytes.push(b'\n');
    let path = directory
        .state_dir()
        .join("orchestrator-scope-unknown-field.json");
    fs::write(&path, &bytes).expect("write altered state");
    write_rulebook(&directory.rulebook(), NEW_RULEBOOK, NEW_MTIME_NS);

    let mut prompt = hook_payload(&directory, "UserPromptSubmit", session);
    prompt["prompt_id"] = json!("new-prompt");
    let output = run_hook(&directory, &prompt);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(fs::read(path).expect("reread state"), bytes);
    assert_eq!(
        directory.read("state/orchestration-snapshot-unknown-field-current.md"),
        OLD_RULEBOOK.as_bytes()
    );
    let log = directory.read_string("state/orchestrator.log");
    let refusal: Value = serde_json::from_str(log.lines().last().expect("refusal log line"))
        .expect("parse refusal diagnostic");
    assert_eq!(refusal["action"], "internal_error");
    assert_eq!(refusal["error"], "UnknownStateField");
}

/// ´test:integration:debug-test-panic-uses-replaced-hook-and-never-exposes-payload´
#[test]
fn debug_test_panic_uses_replaced_hook_and_never_exposes_payload() {
    let directory = TestDir::new("contract-panic");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let output = run_hook_with_env(
        &directory,
        &startup(&directory, "panic-session"),
        [(
            OsString::from("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC"),
            OsString::from("redacted-payload-sentinel"),
        )],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let log = directory.read_string("state/orchestrator.log");
    assert!(log.contains("\"action\":\"internal_error\""));
    assert!(log.contains("\"error\":\"Panic\""));
    assert!(!log.contains("redacted-payload-sentinel"));
    assert!(!log.contains("panicked at"));
}

/// ´test:integration:payload-write-survives-a-child-that-exits-before-reading-stdin´
#[test]
fn payload_write_survives_a_child_that_exits_before_reading_stdin() {
    let directory = TestDir::new("contract-unread-stdin");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    // The adapter bounds its stdin read, and four mebibytes
    // exceed every pipe capacity an unprivileged process can arrange, so the write
    // cannot rest in the buffer: it blocks and then meets the read end the exiting
    // child closed. The outcome of record is the child's, never the write's.
    let payload = vec![b'x'; 4 << 20];

    let output = run_hook_bytes(
        &directory,
        &payload,
        [(
            OsString::from("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC"),
            OsString::from("redacted-payload-sentinel"),
        )],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let log = directory.read_string("home/.local/state/superloop-tools/hook/orchestrator.log");
    assert!(log.contains("Payload"));
    assert!(!log.contains("redacted-payload-sentinel"));
}

/// ´test:integration:refusal-log-is-structured-and-omits-configured-path-and-content´
#[test]
fn refusal_log_is_structured_and_omits_configured_path_and_content() {
    let directory = TestDir::new("contract-redaction");
    let payload = startup(&directory, "redaction-session");

    let output = run_hook(&directory, &payload);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let line = directory.read_string("state/orchestrator.log");
    let value: Value = serde_json::from_str(line.trim_end()).expect("structured log line");
    assert_eq!(value["action"], "guard4_refusal");
    assert_eq!(value["reason"], "rulebook_missing");
    assert_eq!(value["event"], "SessionStart");
    assert_eq!(value["session_id"], "redaction-session");
    assert!(value.get("path").is_none());
    assert!(value.get("prompt_id").is_none());
    assert!(value.get("message").is_none());
}

/// ´test:integration:hook-subcommand-rejects-arguments-as-usage-without-echoing-them´
#[test]
fn hook_subcommand_rejects_arguments_as_usage_without_echoing_them() {
    let directory = TestDir::new("contract-hook-usage");
    let secret = "SHOULD_NOT_APPEAR-secret-argument";
    let output = run_cli(&directory, ["hook", secret]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        output.stderr,
        b"superloop orchestrator: expected on|off|status [--global] or decide FILE\n"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

/// ´test:integration:toggle-usage-returns-two-and-never-creates-state´
#[test]
fn toggle_usage_returns_two_and_never_creates_state() {
    for arguments in [
        vec!["unknown"],
        vec!["status", "--other"],
        vec!["off", "--global", "extra"],
    ] {
        let directory = TestDir::new("contract-toggle-usage");
        let project = directory.project();
        let output = std::process::Command::new(
            std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"),
        )
        .arg("orchestrator")
        .args(&arguments)
        .env("HOME", directory.home())
        .env("ORCHESTRATOR_STATE_DIR", directory.state_dir())
        .env("ORCHESTRATION_FILE", directory.rulebook())
        .env("PWD", &project)
        .current_dir(project)
        .output()
        .expect("run invalid toggle command");

        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(
            output.stderr,
            b"superloop orchestrator: expected on|off|status [--global] or decide FILE\n"
        );
        assert!(!directory.state_dir().exists());
    }
}

/// ´test:integration:no-arguments-preserves-shell-toggle-default-status´
#[test]
fn no_arguments_preserves_shell_toggle_default_status() {
    let directory = TestDir::new("contract-default-status");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let project = directory.project();

    let output = std::process::Command::new(
        std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"),
    )
    .arg("orchestrator")
    .env("HOME", directory.home())
    .env("ORCHESTRATOR_STATE_DIR", directory.state_dir())
    .env("ORCHESTRATION_FILE", directory.rulebook())
    .env("PWD", &project)
    .current_dir(&project)
    .output()
    .expect("run default status");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .expect("status UTF-8")
            .starts_with(&format!(
                "ON ({})\nglobal: on\nproject: on\n",
                project.display()
            ))
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!directory.state_dir().exists());
    for arguments in [vec!["status"], vec!["status", "--global"]] {
        let output = std::process::Command::new(
            std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"),
        )
        .arg("orchestrator")
        .args(arguments)
        .env("HOME", directory.home())
        .env("ORCHESTRATOR_STATE_DIR", directory.state_dir())
        .env("ORCHESTRATION_FILE", directory.rulebook())
        .env("PWD", &project)
        .current_dir(&project)
        .output()
        .expect("run explicit status");
        assert_eq!(output.status.code(), Some(0));
        assert!(!directory.state_dir().exists());
    }
    for argument in ["on", "off"] {
        let output = std::process::Command::new(
            std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"),
        )
        .arg("orchestrator")
        .arg(argument)
        .env("HOME", directory.home())
        .env("ORCHESTRATOR_STATE_DIR", directory.state_dir())
        .env("PWD", &project)
        .output()
        .expect("run changing toggle");
        assert_eq!(output.status.code(), Some(0));
        assert!(directory.state_dir().is_dir());
        fs::remove_dir_all(directory.state_dir()).expect("reset absent state fixture");
    }
}

/// ´test:integration:deployed-rulebook-and-state-defaults-derive-from-home´
#[test]
fn deployed_rulebook_and_state_defaults_derive_from_home() {
    let directory = TestDir::new("deployed-defaults");
    let home = directory.home();
    let state = home.join(".local/state/superloop-tools/hook");
    let rulebook = home.join(".local/share/orchestration-instance/ORCHESTRATION.md");
    fs::create_dir_all(rulebook.parent().expect("rulebook parent"))
        .expect("create deployed rulebook directory");
    write_rulebook(&rulebook, OLD_RULEBOOK, OLD_MTIME_NS);
    let project = directory.project();

    let output = std::process::Command::new(
        std::env::var_os("SUPERLOOP_TEST_BINARY").expect("SUPERLOOP_TEST_BINARY"),
    )
    .arg("orchestrator")
    .arg("status")
    .env("HOME", &home)
    .env_remove("ORCHESTRATOR_STATE_DIR")
    .env_remove("ORCHESTRATION_FILE")
    .env("PWD", &project)
    .current_dir(&project)
    .output()
    .expect("run status with deployed defaults");

    assert_eq!(output.status.code(), Some(0));
    assert!(!state.exists());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("rulebook: {}\nexists: yes\n", rulebook.display()))
    );
}

/// ´test:integration:hook-uses-deployed-rulebook-and-state-defaults-from-home´
#[test]
fn hook_uses_deployed_rulebook_and_state_defaults_from_home() {
    let directory = TestDir::new("hook-deployed-defaults");
    let home = directory.home();
    let state = home.join(".local/state/superloop-tools/hook");
    let rulebook = home.join(".local/share/orchestration-instance/ORCHESTRATION.md");
    fs::create_dir_all(rulebook.parent().expect("rulebook parent"))
        .expect("create deployed rulebook directory");
    write_rulebook(&rulebook, OLD_RULEBOOK, OLD_MTIME_NS);

    let output =
        run_hook_with_deployed_defaults(&directory, &startup(&directory, "deployed-hook-defaults"));

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(response_context(&output).contains(OLD_RULEBOOK));
    assert!(
        state
            .join("orchestrator-scope-deployed-hook-defaults.json")
            .is_file()
    );
    assert!(!directory.state_dir().exists());
}

/// ´test:integration:unsupported-event-returns-before-rulebook-or-state-access´
#[test]
fn unsupported_event_returns_before_rulebook_or_state_access() {
    let directory = TestDir::new("contract-unsupported-order");
    fs::write(directory.rulebook(), vec![b'x'; 20_000]).expect("write oversized rulebook");
    let output = run_hook(
        &directory,
        &json!({
            "hook_event_name": "Stop",
            "session_id": "secret-prompt",
            "cwd": directory.project()
        }),
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("hook-event-mismatch"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("hook-event-mismatch"));
    assert!(!directory.state_dir().exists());
}
