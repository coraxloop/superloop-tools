//! The eleven canonical orchestration-injection scenarios from the original implementation lane.

mod support;

use std::ffi::OsString;
use std::fs;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use support::{
    NEW_MTIME_NS, NEW_RULEBOOK, OLD_MTIME_NS, OLD_RULEBOOK, THIRD_MTIME_NS, TestDir, hook_payload,
    response_context, run_cli, run_hook, run_hook_with_env, write_rulebook,
};

const SESSION: &str = "canonical/session";

fn startup_payload(directory: &TestDir, source: &str) -> Value {
    let mut payload = hook_payload(directory, "SessionStart", SESSION);
    payload["source"] = Value::String(source.to_owned());
    payload
}

fn prompt_payload(directory: &TestDir, prompt_id: &str) -> Value {
    let mut payload = hook_payload(directory, "UserPromptSubmit", SESSION);
    payload["prompt_id"] = Value::String(prompt_id.to_owned());
    payload
}

fn assert_allow(output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
}

/// ´test:integration:scenario-01-fresh-startup-injects-marker-rulebook-snapshot-and-state´
#[test]
fn scenario_01_fresh_startup_injects_marker_rulebook_snapshot_and_state() {
    let directory = TestDir::new("scenario-01");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);

    let output = run_hook(&directory, &startup_payload(&directory, "startup"));

    assert_allow(&output);
    let context = response_context(&output);
    let state = directory.state(SESSION);
    assert_eq!(
        state
            .as_object()
            .expect("writer state object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "cwd",
            "dedupe_key",
            "hash",
            "mtime",
            "session_id",
            "sessionstart_dedupe",
            "snapshot_current",
            "updated_at",
        ]
    );
    let digest = state["hash"].as_str().expect("state digest");
    assert!(context.starts_with(&format!(
        "ORCHESTRATION_SCOPE_MARKER v1 sha256={digest} mtime={OLD_MTIME_NS}\n"
    )));
    assert!(context.contains(OLD_RULEBOOK));
    assert!(context.ends_with(&format!(
        "ORCHESTRATION_SCOPE_MARKER_END v1 sha256={digest}"
    )));
    assert_eq!(state["mtime"], OLD_MTIME_NS);
    assert_eq!(
        directory.read("state/orchestration-snapshot-canonical-session-current.md"),
        OLD_RULEBOOK.as_bytes()
    );
    assert!(directory.exists("state/orchestrator-scope-canonical-session.json"));
}

/// ´test:integration:scenario-02-duplicate-startup-inside-grace-window-is-silent´
#[test]
fn scenario_02_duplicate_startup_inside_grace_window_is_silent() {
    let directory = TestDir::new("scenario-02");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let payload = startup_payload(&directory, "startup");
    let first = run_hook(&directory, &payload);

    let second = run_hook(&directory, &payload);

    assert_allow(&first);
    assert_allow(&second);
    assert_ne!(first.stdout, [] as [u8; 0]);
    assert_eq!(second.stdout, [] as [u8; 0]);
}

/// ´test:integration:scenario-03-unchanged-prompt-uses-silent-stat-only-fast-path´
#[test]
fn scenario_03_unchanged_prompt_uses_silent_stat_only_fast_path() {
    let directory = TestDir::new("scenario-03");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &startup_payload(&directory, "startup"),
    ));
    let start = Instant::now();

    let output = run_hook(&directory, &prompt_payload(&directory, "prompt-1"));
    let elapsed = start.elapsed();

    assert_allow(&output);
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(
        elapsed < Duration::from_millis(250),
        "fast path took {elapsed:?}"
    );
}

/// ´test:integration:scenario-04-mtime-only-change-restamps-without-output-or-rotation´
#[test]
fn scenario_04_mtime_only_change_restamps_without_output_or_rotation() {
    let directory = TestDir::new("scenario-04");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &startup_payload(&directory, "startup"),
    ));
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, NEW_MTIME_NS);

    let output = run_hook(&directory, &prompt_payload(&directory, "prompt-2"));

    assert_allow(&output);
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(directory.state(SESSION)["mtime"], NEW_MTIME_NS);
    assert!(!directory.exists("state/orchestration-snapshot-canonical-session-prev.md"));
    assert_eq!(
        directory.read("state/orchestration-snapshot-canonical-session-current.md"),
        OLD_RULEBOOK.as_bytes()
    );
}

/// ´test:integration:scenario-05-content-change-emits-short-notice-and-rotates-snapshots´
#[test]
fn scenario_05_content_change_emits_short_notice_and_rotates_snapshots() {
    let directory = TestDir::new("scenario-05");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &startup_payload(&directory, "startup"),
    ));
    write_rulebook(&directory.rulebook(), NEW_RULEBOOK, NEW_MTIME_NS);

    let output = run_hook(&directory, &prompt_payload(&directory, "prompt-3"));

    assert_allow(&output);
    assert_eq!(
        directory
            .state(SESSION)
            .as_object()
            .expect("writer state object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "cwd",
            "dedupe_key",
            "emitted_prompt_ids",
            "hash",
            "last_prompt_id",
            "mtime",
            "session_id",
            "sessionstart_dedupe",
            "snapshot_current",
            "updated_at",
        ]
    );
    let context = response_context(&output);
    assert!(context.starts_with(&format!(
        "ORCHESTRATION.md changed (mtime {OLD_MTIME_NS} -> {NEW_MTIME_NS})."
    )));
    assert!(!context.contains(NEW_RULEBOOK));
    assert_eq!(
        directory.read("state/orchestration-snapshot-canonical-session-prev.md"),
        OLD_RULEBOOK.as_bytes()
    );
    assert_eq!(
        directory.read("state/orchestration-snapshot-canonical-session-current.md"),
        NEW_RULEBOOK.as_bytes()
    );
    assert_eq!(directory.state(SESSION)["mtime"], NEW_MTIME_NS);
}

/// ´test:integration:scenario-06-compact-after-change-emits-full-current-rulebook´
#[test]
fn scenario_06_compact_after_change_emits_full_current_rulebook() {
    let directory = TestDir::new("scenario-06");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &startup_payload(&directory, "startup"),
    ));
    write_rulebook(&directory.rulebook(), NEW_RULEBOOK, NEW_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &prompt_payload(&directory, "prompt-4"),
    ));

    let compact = run_hook(&directory, &startup_payload(&directory, "compact"));

    assert_allow(&compact);
    let context = response_context(&compact);
    assert!(context.contains(NEW_RULEBOOK));
    assert!(context.contains("ORCHESTRATION_SCOPE_MARKER v1 sha256="));
    assert!(context.contains("ORCHESTRATION_SCOPE_MARKER_END v1 sha256="));
}

/// ´test:integration:compact-session-start-preserves-the-heartbeat-toggle´
#[test]
fn compact_session_start_preserves_the_heartbeat_toggle() {
    for (label, enabled) in [("compact-guard-off", false), ("compact-guard-on", true)] {
        let directory = TestDir::new(label);
        write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
        let project = directory.project();
        let flag = directory.state_dir().join(format!(
            "heartbeat{}",
            project.to_string_lossy().replace('/', "-")
        ));
        fs::create_dir_all(directory.state_dir()).expect("create shared state directory");
        fs::write(&flag, b"prior-on").expect("write prior ON flag");
        assert_allow(&run_hook(
            &directory,
            &startup_payload(&directory, "startup"),
        ));
        if !enabled {
            fs::remove_file(&flag).expect("store OFF before compaction");
        }

        let compact = run_hook(&directory, &startup_payload(&directory, "compact"));

        assert_allow(&compact);
        assert!(response_context(&compact).contains(OLD_RULEBOOK));
        assert_eq!(fs::read(&flag).ok(), enabled.then(|| b"prior-on".to_vec()));
    }
}

/// ´test:integration:scenario-07-resume-uses-only-current-marker-witness-in-transcript-tail´
#[test]
fn scenario_07_resume_uses_only_current_marker_witness_in_transcript_tail() {
    let directory = TestDir::new("scenario-07");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let startup = run_hook(&directory, &startup_payload(&directory, "startup"));
    let digest = directory.state(SESSION)["hash"]
        .as_str()
        .expect("digest")
        .to_owned();
    let marker = format!("ORCHESTRATION_SCOPE_MARKER v1 sha256={digest}");
    fs::write(directory.transcript(), format!("prefix {marker} suffix"))
        .expect("write marker transcript");
    let mut resume = startup_payload(&directory, "resume");
    resume["transcript_path"] = json!(directory.transcript());

    let present = run_hook(&directory, &resume);
    fs::write(directory.transcript(), "marker is absent").expect("replace transcript");
    let absent = run_hook(&directory, &resume);

    assert_allow(&startup);
    assert_allow(&present);
    assert_eq!(present.stdout, [] as [u8; 0]);
    assert_allow(&absent);
    assert!(response_context(&absent).contains(OLD_RULEBOOK));
}

/// ´test:integration:scenario-08-derived-agent-and-structural-subagent-path-are-silent´
#[test]
fn scenario_08_derived_agent_and_structural_subagent_path_are_silent() {
    let directory = TestDir::new("scenario-08");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    let mut derived = startup_payload(&directory, "startup");
    derived["agent_id"] = json!("agent-17");
    let mut structural = startup_payload(&directory, "startup");
    structural["transcript_path"] = json!("/safe/subagents/agent.jsonl");

    for output in [
        run_hook(&directory, &derived),
        run_hook(&directory, &structural),
    ] {
        assert_allow(&output);
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
    assert!(!directory.state_dir().exists());
}

/// ´test:integration:scenario-09-project-and-global-toggle-status-control-injection´
#[test]
fn scenario_09_project_and_global_toggle_status_control_injection() {
    let directory = TestDir::new("scenario-09");
    let project = directory.project();
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);

    let project_off = run_cli(&directory, ["off"]);
    let blocked = run_hook(&directory, &startup_payload(&directory, "startup"));
    let project_status = run_cli(&directory, ["status"]);
    let project_on = run_cli(&directory, ["on"]);
    let enabled = run_hook(&directory, &startup_payload(&directory, "clear"));
    let global_off = run_cli(&directory, ["off", "--global"]);
    let globally_blocked = run_hook(&directory, &{
        let mut value = startup_payload(&directory, "startup");
        value["session_id"] = json!("global-session");
        value
    });
    let global_status = run_cli(&directory, ["status", "--global"]);
    let global_on = run_cli(&directory, ["on", "--global"]);

    assert_eq!(
        project_off.stdout,
        format!("orchestrator OFF for {}\n", project.display()).into_bytes()
    );
    assert_eq!(blocked.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8(project_status.stdout)
            .expect("status UTF-8")
            .starts_with(&format!(
                "OFF ({})\nglobal: on\nproject: off\n",
                project.display()
            ))
    );
    assert_eq!(
        project_on.stdout,
        format!("orchestrator ON for {}\n", project.display()).into_bytes()
    );
    assert_ne!(enabled.stdout, [] as [u8; 0]);
    assert_eq!(global_off.stdout, b"orchestrator OFF globally\n");
    assert_eq!(globally_blocked.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8(global_status.stdout)
            .expect("global status UTF-8")
            .starts_with(&format!(
                "OFF ({})\nglobal: off\nproject: on\n",
                project.display()
            ))
    );
    assert_eq!(global_on.stdout, b"orchestrator ON globally\n");
}

/// ´test:integration:scenario-10-oversized-and-missing-rulebooks-are-silent-and-logged´
#[test]
fn scenario_10_oversized_and_missing_rulebooks_are_silent_and_logged() {
    let directory = TestDir::new("scenario-10-oversized");
    write_rulebook(&directory.rulebook(), &"x".repeat(9_501), OLD_MTIME_NS);
    let oversized = run_hook(&directory, &startup_payload(&directory, "startup"));

    assert_allow(&oversized);
    assert_eq!(oversized.stdout, [] as [u8; 0]);
    let oversized_log = directory.read_string("state/orchestrator.log");
    assert!(oversized_log.contains("rulebook_oversized"));
    assert!(!oversized_log.contains(directory.rulebook().to_string_lossy().as_ref()));

    let missing_directory = TestDir::new("scenario-10-missing");
    let missing = run_hook(
        &missing_directory,
        &startup_payload(&missing_directory, "startup"),
    );
    assert_allow(&missing);
    assert_eq!(missing.stdout, [] as [u8; 0]);
    let missing_log = missing_directory.read_string("state/orchestrator.log");
    assert!(missing_log.contains("rulebook_missing"));
    assert!(!missing_log.contains("ORCHESTRATION.md"));
}

/// ´test:integration:scenario-11-repeated-prompt-identity-allows-only-one-change-emission´
#[test]
fn scenario_11_repeated_prompt_identity_allows_only_one_change_emission() {
    let directory = TestDir::new("scenario-11");
    write_rulebook(&directory.rulebook(), OLD_RULEBOOK, OLD_MTIME_NS);
    assert_allow(&run_hook(
        &directory,
        &startup_payload(&directory, "startup"),
    ));
    write_rulebook(&directory.rulebook(), NEW_RULEBOOK, NEW_MTIME_NS);
    let first = run_hook(&directory, &prompt_payload(&directory, "same-prompt"));
    write_rulebook(&directory.rulebook(), "# Third edition\n", THIRD_MTIME_NS);
    let repeated = run_hook(&directory, &prompt_payload(&directory, "same-prompt"));

    assert_allow(&first);
    assert_ne!(first.stdout, [] as [u8; 0]);
    assert_allow(&repeated);
    assert_eq!(repeated.stdout, [] as [u8; 0]);
    assert_eq!(directory.state(SESSION)["mtime"], NEW_MTIME_NS);
    assert_eq!(
        directory.read("state/orchestration-snapshot-canonical-session-current.md"),
        NEW_RULEBOOK.as_bytes()
    );
}

/// ´test:integration:environment-override-values-are-the-only-paths-touched´
#[test]
fn environment_override_values_are_the_only_paths_touched() {
    let directory = TestDir::new("override-paths");
    let alternate_state = directory.path().join("alternate-state");
    let alternate_rulebook = directory.path().join("alternate-rules.md");
    write_rulebook(&alternate_rulebook, OLD_RULEBOOK, OLD_MTIME_NS);
    let output = run_hook_with_env(
        &directory,
        &startup_payload(&directory, "startup"),
        [
            (
                OsString::from("ORCHESTRATOR_STATE_DIR"),
                alternate_state.clone().into_os_string(),
            ),
            (
                OsString::from("ORCHESTRATION_FILE"),
                alternate_rulebook.into_os_string(),
            ),
        ],
    );

    assert_allow(&output);
    assert!(
        alternate_state
            .join("orchestrator-scope-canonical-session.json")
            .exists()
    );
    assert!(!directory.state_dir().exists());
}
