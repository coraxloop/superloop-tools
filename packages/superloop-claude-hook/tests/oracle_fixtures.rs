//! Committed Python-oracle agreement and named specification-divergence fixtures.

mod oracle_support;

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use oracle_support::{TestDir, run_hook, write_rulebook};

const FIXTURES: [&str; 11] = [
    "change-notice",
    "duplicate-startup",
    "fresh-startup",
    "resume-marker-absent",
    "resume-marker-present",
    "spec-nonstring-cwd",
    "spec-nonstring-prompt",
    "spec-nonstring-source",
    "spec-project-root-disable",
    "spec-redacted-refusal",
    "unchanged-prompt",
];

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/orchestrator/fixtures/expected")
        .join(format!("{name}.json"));
    serde_json::from_slice(&fs::read(path).expect("read oracle fixture"))
        .expect("parse oracle fixture")
}

fn rulebook_from(value: &Value) -> (&str, u64) {
    let rulebook = &value["state_precondition"]["rulebook"];
    (
        rulebook["text"].as_str().expect("fixture rulebook text"),
        rulebook["mtime_ns"]
            .as_u64()
            .expect("fixture rulebook mtime"),
    )
}

fn normalized_stdout(directory: &TestDir, output: &[u8]) -> String {
    String::from_utf8(output.to_vec())
        .expect("hook output UTF-8")
        .replace(
            directory.state_dir().to_string_lossy().as_ref(),
            "<STATE_DIR>",
        )
}

/// ´test:integration:adapter-fixture-inventory-is-complete-and-authorities-are-declared´
#[test]
fn adapter_fixture_inventory_is_complete_and_authorities_are_declared() {
    for name in FIXTURES {
        let value = fixture(name);
        assert_eq!(value["name"], name);
        assert!(value["payload"].is_object());
        assert!(value["state_precondition"].is_object());
        assert!(value["expected_stdout"].is_string());
        match value["authority"].as_str().expect("authority") {
            "python" => assert!(value.get("divergence").is_none()),
            "spec" => {
                assert!(value["spec_label"].is_string());
                assert!(value["divergence"].is_string());
                assert!(value["expected_effect"].is_object());
                assert!(value["python_effect"].is_object());
            }
            other => panic!("unknown fixture authority {other}"),
        }
    }
}

/// ´test:integration:adapter-relative-fixture-cwd-fails-localization´
#[test]
fn adapter_relative_fixture_cwd_fails_localization() {
    let directory = TestDir::new("oracle-relative-cwd");
    let payload = json!({"cwd": "relative/project"});

    let panic = std::panic::catch_unwind(|| run_hook(&directory, &payload))
        .expect_err("relative fixture cwd must fail localization");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("fixture helper panic message");
    assert_eq!(
        message,
        "string fixture cwd must be the literal /fixture/project or a path under TestDir: relative/project"
    );
}

/// ´test:integration:adapter-fresh-startup-is-byte-exact-with-python-oracle´
#[test]
fn adapter_fresh_startup_is_byte_exact_with_python_oracle() {
    let value = fixture("fresh-startup");
    let directory = TestDir::new("oracle-fresh");
    let (text, stamp) = rulebook_from(&value);
    write_rulebook(&directory.rulebook(), text, stamp);

    let output = run_hook(&directory, &value["payload"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        normalized_stdout(&directory, &output.stdout),
        value["expected_stdout"].as_str().expect("expected stdout")
    );
}

/// ´test:integration:adapter-duplicate-and-unchanged-fixtures-are-byte-exact-with-python´
#[test]
fn adapter_duplicate_and_unchanged_fixtures_are_byte_exact_with_python() {
    let fresh = fixture("fresh-startup");
    let directory = TestDir::new("oracle-dedupe");
    let (text, stamp) = rulebook_from(&fresh);
    write_rulebook(&directory.rulebook(), text, stamp);
    let first = run_hook(&directory, &fresh["payload"]);
    assert_ne!(first.stdout, [] as [u8; 0]);

    for name in ["duplicate-startup", "unchanged-prompt"] {
        let value = fixture(name);
        let output = run_hook(&directory, &value["payload"]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert_eq!(
            normalized_stdout(&directory, &output.stdout),
            value["expected_stdout"].as_str().expect("expected stdout"),
            "fixture {name}"
        );
    }
}

/// ´test:integration:adapter-content-change-notice-is-byte-exact-with-python-after-path-normalization´
#[test]
fn adapter_content_change_notice_is_byte_exact_with_python_after_path_normalization() {
    let fresh = fixture("fresh-startup");
    let change = fixture("change-notice");
    let directory = TestDir::new("oracle-change");
    let (old_text, old_stamp) = rulebook_from(&fresh);
    write_rulebook(&directory.rulebook(), old_text, old_stamp);
    assert_eq!(
        run_hook(&directory, &fresh["payload"]).status.code(),
        Some(0)
    );
    let (new_text, new_stamp) = rulebook_from(&change);
    write_rulebook(&directory.rulebook(), new_text, new_stamp);

    let output = run_hook(&directory, &change["payload"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        normalized_stdout(&directory, &output.stdout),
        change["expected_stdout"].as_str().expect("expected stdout")
    );
}

/// ´test:integration:adapter-resumed-marker-fixtures-match-python-oracle´
#[test]
fn adapter_resumed_marker_fixtures_match_python_oracle() {
    for witness in [false, true] {
        let fresh = fixture("fresh-startup");
        let name = if witness {
            "resume-marker-present"
        } else {
            "resume-marker-absent"
        };
        let resume = fixture(name);
        let directory = TestDir::new(name);
        let (text, stamp) = rulebook_from(&fresh);
        write_rulebook(&directory.rulebook(), text, stamp);
        assert_eq!(
            run_hook(&directory, &fresh["payload"]).status.code(),
            Some(0)
        );
        let digest = directory.state("fixture/session")["hash"]
            .as_str()
            .expect("fixture digest")
            .to_owned();
        let transcript = directory.transcript();
        fs::write(
            &transcript,
            if witness {
                format!("ORCHESTRATION_SCOPE_MARKER v1 sha256={digest}")
            } else {
                String::from("no marker")
            },
        )
        .expect("write oracle transcript");
        let mut payload = resume["payload"].clone();
        payload["transcript_path"] = json!(transcript);

        let output = run_hook(&directory, &payload);

        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert_eq!(
            normalized_stdout(&directory, &output.stdout),
            resume["expected_stdout"].as_str().expect("expected stdout"),
            "fixture {name}"
        );
    }
}

/// ´test:integration:adapter-specified-nonstring-source-and-cwd-effects-override-python-state-details´
#[test]
fn adapter_specified_nonstring_source_and_cwd_effects_override_python_state_details() {
    let source_fixture = fixture("spec-nonstring-source");
    let source_directory = TestDir::new("spec-source");
    let (text, stamp) = rulebook_from(&source_fixture);
    write_rulebook(&source_directory.rulebook(), text, stamp);
    let source_output = run_hook(&source_directory, &source_fixture["payload"]);
    assert_eq!(source_output.status.code(), Some(0));
    assert_eq!(
        source_directory.state("fixture/session")["sessionstart_dedupe"]["key"][1],
        ""
    );

    let cwd_fixture = fixture("spec-nonstring-cwd");
    let cwd_directory = TestDir::new("spec-cwd");
    let cwd_project = cwd_directory
        .project()
        .canonicalize()
        .expect("canonicalize fixture project");
    let (text, stamp) = rulebook_from(&cwd_fixture);
    write_rulebook(&cwd_directory.rulebook(), text, stamp);
    let cwd_output = run_hook(&cwd_directory, &cwd_fixture["payload"]);
    assert_eq!(cwd_output.status.code(), Some(0));
    assert_eq!(
        cwd_directory.state("fixture/session")["cwd"],
        cwd_project.to_string_lossy().as_ref()
    );
}

/// ´test:integration:adapter-specified-project-root-disable-overrides-python-raw-cwd-key´
#[test]
fn adapter_specified_project_root_disable_overrides_python_raw_cwd_key() {
    let value = fixture("spec-project-root-disable");
    let directory = TestDir::new("spec-project-root-disable");
    let project_root = directory.path().join("fixture");
    let cwd = project_root.join("project");
    fs::create_dir_all(project_root.join(".git")).expect("create project marker");
    fs::write(project_root.join(".git/HEAD"), "ref: refs/heads/main\n")
        .expect("create project HEAD");
    fs::create_dir_all(&cwd).expect("create project subdirectory");
    fs::create_dir_all(directory.state_dir()).expect("create fixture state directory");
    let flag = format!(
        "orchestrator-disabled{}",
        project_root.to_string_lossy().replace('/', "-")
    );
    fs::write(directory.state_dir().join(flag), []).expect("create project disable flag");
    let (text, stamp) = rulebook_from(&value);
    write_rulebook(&directory.rulebook(), text, stamp);
    let mut payload = value["payload"].clone();
    payload["cwd"] = json!(cwd);

    let output = run_hook(&directory, &payload);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        normalized_stdout(&directory, &output.stdout),
        value["expected_stdout"].as_str().expect("expected stdout")
    );
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!directory.exists("state/orchestrator-scope-fixture-session.json"));
}

/// ´test:integration:adapter-specified-nonstring-prompt-and-redacted-log-override-python-details´
#[test]
fn adapter_specified_nonstring_prompt_and_redacted_log_override_python_details() {
    let prompt_fixture = fixture("spec-nonstring-prompt");
    let prompt_directory = TestDir::new("spec-prompt");
    let (text, stamp) = rulebook_from(&prompt_fixture);
    write_rulebook(&prompt_directory.rulebook(), text, stamp);
    let prompt_output = run_hook(&prompt_directory, &prompt_fixture["payload"]);
    assert_eq!(prompt_output.status.code(), Some(0));
    assert_eq!(
        prompt_directory.state("fixture/session")["dedupe_key"],
        json!({"event": "UserPromptSubmit"})
    );

    let refusal_fixture = fixture("spec-redacted-refusal");
    let refusal_directory = TestDir::new("spec-refusal");
    let refusal_output = run_hook(&refusal_directory, &refusal_fixture["payload"]);
    assert_eq!(refusal_output.status.code(), Some(0));
    assert_eq!(refusal_output.stdout, [] as [u8; 0]);
    let log: Value = serde_json::from_str(
        refusal_directory
            .read_string("state/orchestrator.log")
            .trim_end(),
    )
    .expect("parse refusal log");
    assert!(log.get("path").is_none());
}
