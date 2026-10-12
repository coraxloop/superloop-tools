//! Retained subprocess cases run sequentially from the custom harness main.
//! The same ELF serves the isolated permission fixture before any case runs.

mod support;

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

use support::{TestDir, fold, prompt_path, user, write_payload};

const PROMPT_MARKER: &str = "guard-prompt";
const REFUSAL_REASON: &[u8] = b"HEARTBEAT GUARD: unprompted ScheduleWakeup arming is refused. End the turn and arm only when the heartbeat guard's Stop prompt asks. If this turn is genuinely ending blocked on the user, run `superloop heartbeat off` first, then end the turn.";
const OFF_WARNING: &[u8] = b"HEARTBEAT GUARD WARNING: this ScheduleWakeup call may be a legitimate deliberate timer while the heartbeat is OFF. If the session is reaching for heartbeat behavior instead, run `superloop heartbeat on` and arm only when the heartbeat guard's Stop prompt asks.";

fn run_hook(directory: &TestDir, input: &[u8]) -> Output {
    run_hook_with_env(directory, input, &[])
}

fn run_hook_with_env(directory: &TestDir, input: &[u8], environment: &[(&str, &str)]) -> Output {
    if support::event_command(input) == "pre-tool-use" {
        let helper = directory
            .home()
            .join(".local/libexec/superloop/hooks/permission-triage-hook");
        std::fs::create_dir_all(helper.parent().expect("helper parent"))
            .expect("private helper directory");
        std::fs::create_dir_all(directory.home().join(".claude")).expect("instance directory");
        std::fs::copy(std::env::current_exe().expect("fixture binary"), &helper)
            .expect("ELF permission fixture");
        std::fs::write(directory.home().join(".claude/permission-triage.env"), "PERMISSION_TRIAGE_MODE=audit\nPERMISSION_TRIAGE_STATE_ROOT=/fixture/state\nPERMISSION_TRIAGE_CLI=/fixture/cli\n").expect("instance");
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-claude-hook"));
    command
        .arg(support::event_command(input))
        .env("HOME", directory.home())
        .env_remove("ENTER_LOOP_REGISTRY");
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn heartbeat guard");
    write_payload(
        child.stdin.take().expect("hook stdin"),
        input,
        "write hook input",
    );
    child.wait_with_output().expect("wait for heartbeat guard")
}

fn run_toggle(directory: &TestDir, argument: Option<&str>, pwd: &Path) -> Output {
    let mut command = support::toggle_command();
    if let Some(argument) = argument {
        command.arg(argument);
    }
    command
        .env("HOME", directory.home())
        .env("PWD", pwd)
        .output()
        .expect("run toggle command")
}

/// Contract case: `superloop-default-state-derives-from-home`.
fn superloop_default_state_derives_from_home() {
    let directory = TestDir::new("superloop-default-state");
    let project = fixture_cwd(&directory);
    let output = support::toggle_command()
        .arg("on")
        .env("HOME", directory.home())
        .env("PWD", &project)
        .output()
        .expect("run superloop toggle");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&project.to_string_lossy())))
            .exists()
    );
}

fn create_git_directory(root: &Path) {
    let marker = root.join(".git");
    std::fs::create_dir_all(&marker).expect("create repository marker");
    std::fs::write(marker.join("HEAD"), "ref: refs/heads/main\n").expect("create repository HEAD");
}

fn fixture_cwd(directory: &TestDir) -> PathBuf {
    let cwd = directory.home().join("fixture/project");
    std::fs::create_dir_all(&cwd).expect("create fixture working directory");
    cwd
}

fn fixture_cwd_text(directory: &TestDir) -> String {
    fixture_cwd(directory).to_string_lossy().into_owned()
}

fn enable_fixture(directory: &TestDir) {
    directory.enable(&fixture_cwd_text(directory));
}

fn payload(directory: &TestDir, entries: &[Value], session: &str) -> Vec<u8> {
    let transcript = directory.write_transcript("subprocess.jsonl", entries);
    serde_json::to_vec(&TestDir::payload(
        &transcript,
        &fixture_cwd_text(directory),
        session,
    ))
    .expect("serialize subprocess payload")
}

fn future_unprompted_arm() -> Vec<Value> {
    vec![
        user("question", 30),
        json!({
            "type": "assistant", "timestamp": "2099-01-01T00:00:00Z",
            "message": {"role": "assistant", "content": [{
                "type": "tool_use", "id": "future-arm", "name": "ScheduleWakeup",
                "input": {"delaySeconds": 1800}
            }]}
        }),
        json!({
            "type": "user", "timestamp": "2099-01-01T00:00:01Z",
            "message": {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": "future-arm",
                "is_error": false, "content": "ignored"
            }]}
        }),
    ]
}

fn pre_tool_payload(directory: &TestDir, tool_name: &str) -> Vec<u8> {
    pre_tool_payload_for(directory, tool_name, Some("test-session"))
}

fn pre_tool_payload_for(directory: &TestDir, tool_name: &str, session: Option<&str>) -> Vec<u8> {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "cwd": fixture_cwd_text(directory)
    });
    if let Some(session) = session {
        payload["session_id"] = json!(session);
    }
    serde_json::to_vec(&payload).expect("serialize PreToolUse payload")
}

fn prompt_once(directory: &TestDir, session: &str) -> Output {
    enable_fixture(directory);
    run_hook(
        directory,
        &payload(directory, &[user("question", 30)], session),
    )
}

/// Contract case: `intentional-prompt-block-uses-stderr-and-harness-exit-two`.
fn intentional_prompt_block_uses_stderr_and_harness_exit_two() {
    let directory = TestDir::new("contract-prompt");
    enable_fixture(&directory);
    let output = run_hook(
        &directory,
        &payload(&directory, &[user("question", 30)], "prompt"),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let reason = String::from_utf8(output.stderr).expect("block reason UTF-8");
    let expected = "HEARTBEAT GUARD: no wakeup is currently armed and the heartbeat toggle is ON. did you use ListAgents, are all your watchers happy? Please set the ScheduleWakeup now (the turn then ends naturally on its result), or - if this turn genuinely ends blocked on the user with nothing in flight - run `superloop heartbeat off` first, then end the turn.";
    assert_eq!(reason.trim_end(), expected);
}

/// Contract case: `stop-prompt-writes-an-iso-utc-prompt-marker`.
fn stop_prompt_writes_an_iso_utc_prompt_marker() {
    let directory = TestDir::new("contract-prompt-marker");
    let output = prompt_once(&directory, "prompt-marker");
    assert_eq!(output.status.code(), Some(2));
    let marker = std::fs::read_to_string(directory.state_path(&prompt_path("prompt-marker")))
        .expect("read prompt marker");
    assert_eq!(marker.len(), 20);
    assert_eq!(marker.as_bytes().get(4), Some(&b'-'));
    assert_eq!(marker.as_bytes().get(10), Some(&b'T'));
    assert!(marker.ends_with('Z'));
    for (stamp, found) in [
        ("2027-01-02T01:58:20", "naive"),
        ("2027-01-02T03:58:20+02:00", "offset +02:00"),
    ] {
        let mut entry = user("question", 30);
        entry["timestamp"] = json!(stamp);
        let output = run_hook(&directory, &payload(&directory, &[entry], found));
        let reason = String::from_utf8(output.stderr).expect("refusal UTF-8");
        assert!(reason.contains(&format!("heartbeat timestamp refused: {found};")));
    }
}

/// Contract case: `stop-prompt-without-session-identity-writes-no-marker`.
fn stop_prompt_without_session_identity_writes_no_marker() {
    for (label, identity) in [("absent", None), ("empty", Some(""))] {
        let directory = TestDir::new(label);
        enable_fixture(&directory);
        let mut request: Value =
            serde_json::from_slice(&payload(&directory, &[user("question", 30)], "ignored"))
                .expect("parse Stop payload");
        if let Some(identity) = identity {
            request["session_id"] = json!(identity);
        } else {
            request
                .as_object_mut()
                .expect("object payload")
                .remove("session_id");
        }

        let input = serde_json::to_vec(&request).expect("serialize Stop payload");
        let output = run_hook(&directory, &input);
        assert_eq!(output.status.code(), Some(2), "case {label}");
        assert_eq!(output.stdout, [] as [u8; 0], "case {label}");
        assert!(output.stderr.starts_with(b"HEARTBEAT GUARD:"));
        for entry in std::fs::read_dir(directory.state_dir()).expect("read state directory") {
            let name = entry.expect("state entry").file_name();
            assert!(
                !name.to_string_lossy().starts_with(PROMPT_MARKER),
                "unexpected prompt marker {} in case {label}",
                name.display()
            );
        }
    }
}

/// Contract case: `schedule-wakeup-allows-and-consumes-a-fresh-prompt-marker`.
fn schedule_wakeup_allows_and_consumes_a_fresh_prompt_marker() {
    let directory = TestDir::new("contract-fresh-prompt-marker");
    assert_eq!(
        prompt_once(&directory, "fresh-marker").status.code(),
        Some(2)
    );
    assert!(directory.state_path(&prompt_path("fresh-marker")).exists());
    let output = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("fresh-marker")),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!directory.state_path(&prompt_path("fresh-marker")).exists());
}

/// Contract case: `schedule-wakeup-without-a-marker-is-refused-with-guidance`.
fn schedule_wakeup_without_a_marker_is_refused_with_guidance() {
    let directory = TestDir::new("contract-no-prompt-marker");
    enable_fixture(&directory);
    let output = run_hook(&directory, &pre_tool_payload(&directory, "ScheduleWakeup"));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
}

/// Contract case: `schedule-wakeup-with-a-stale-marker-is-refused-and-cleans-it-up`.
fn schedule_wakeup_with_a_stale_marker_is_refused_and_cleans_it_up() {
    let directory = TestDir::new("contract-stale-prompt-marker");
    enable_fixture(&directory);
    directory.write_state(&prompt_path("test-session"), "2000-01-01T00:00:00Z");
    let output = run_hook(&directory, &pre_tool_payload(&directory, "ScheduleWakeup"));
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
    assert!(!directory.state_path(&prompt_path("test-session")).exists());
}

/// Contract case: `two-prompted-sessions-consume-only-their-own-markers`.
fn two_prompted_sessions_consume_only_their_own_markers() {
    let directory = TestDir::new("contract-two-session-markers");
    assert_eq!(prompt_once(&directory, "alpha").status.code(), Some(2));
    assert_eq!(prompt_once(&directory, "beta").status.code(), Some(2));
    let beta_marker =
        std::fs::read(directory.state_path(&prompt_path("beta"))).expect("read beta marker");

    let alpha_arm = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("alpha")),
    );
    assert_eq!(alpha_arm.status.code(), Some(0));
    assert_eq!(alpha_arm.stderr, [] as [u8; 0]);
    assert!(!directory.state_path(&prompt_path("alpha")).exists());
    assert_eq!(
        std::fs::read(directory.state_path(&prompt_path("beta"))).expect("reread beta marker"),
        beta_marker
    );

    let beta_arm = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("beta")),
    );
    assert_eq!(beta_arm.status.code(), Some(0));
    assert_eq!(beta_arm.stderr, [] as [u8; 0]);
    assert!(!directory.state_path(&prompt_path("beta")).exists());
}

/// Contract case: `arming-without-a-marker-of-its-own-is-refused`.
fn arming_without_a_marker_of_its_own_is_refused() {
    let directory = TestDir::new("contract-foreign-session-marker");
    assert_eq!(prompt_once(&directory, "prompted").status.code(), Some(2));
    let prompted_marker = std::fs::read(directory.state_path(&prompt_path("prompted")))
        .expect("read prompted marker");

    let output = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("silent")),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
    assert_eq!(
        std::fs::read(directory.state_path(&prompt_path("prompted")))
            .expect("reread prompted marker"),
        prompted_marker
    );
}

/// Contract case: `an-unkeyed-marker-does-not-authorize-a-keyed-session`.
fn an_unkeyed_marker_does_not_authorize_a_keyed_session() {
    let directory = TestDir::new("contract-unkeyed-marker-refusal");
    assert_eq!(prompt_once(&directory, "legacy").status.code(), Some(2));
    std::fs::rename(
        directory.state_path(&prompt_path("legacy")),
        directory.state_path(PROMPT_MARKER),
    )
    .expect("rename the marker to the pre-session name");

    let output = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("legacy")),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
    assert!(directory.state_path(PROMPT_MARKER).exists());
}

/// Contract case: `missing-session-identity-fails-open-without-marker-access`.
fn missing_session_identity_fails_open_without_marker_access() {
    let directory = TestDir::new("contract-missing-session-identity");
    enable_fixture(&directory);
    directory.write_state(PROMPT_MARKER, "2000-01-01T00:00:00Z");
    directory.write_state(&prompt_path("other"), "2000-01-01T00:00:00Z");
    let mut payload: Value =
        serde_json::from_slice(&pre_tool_payload_for(&directory, "ScheduleWakeup", None))
            .expect("parse fixture payload");
    for (index, identity) in [None, Some(json!(null)), Some(json!("")), Some(json!(23))]
        .into_iter()
        .enumerate()
    {
        if let Some(identity) = identity {
            payload["session_id"] = identity;
        } else {
            payload
                .as_object_mut()
                .expect("object payload")
                .remove("session_id");
        }
        let input = serde_json::to_vec(&payload).expect("serialize fixture payload");
        let output = run_hook(&directory, &input);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, [] as [u8; 0]);
        assert_eq!(output.stderr, [] as [u8; 0]);
        assert!(directory.state_path(PROMPT_MARKER).exists());
        assert!(directory.state_path(&prompt_path("other")).exists());
        let log = std::fs::read_to_string(directory.state_path("orchestrator.log"))
            .expect("read payload failure log");
        assert_eq!(log.lines().count(), index + 1);
        let record: Value = serde_json::from_str(log.lines().last().expect("log record"))
            .expect("parse payload failure log");
        assert_eq!(record["action"], "internal_error");
        assert_eq!(record["error"], "Payload");
    }
    payload
        .as_object_mut()
        .expect("object payload")
        .remove("session_id");
    payload["cwd"] = json!(23);
    let input = serde_json::to_vec(&payload).expect("serialize malformed cwd payload");
    let output = run_hook(&directory, &input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(directory.state_path(PROMPT_MARKER).exists());
    assert!(directory.state_path(&prompt_path("other")).exists());
    let log = std::fs::read_to_string(directory.state_path("orchestrator.log"))
        .expect("read malformed cwd failure log");
    assert_eq!(log.lines().count(), 5);
    let record: Value = serde_json::from_str(log.lines().last().expect("log record"))
        .expect("parse malformed cwd failure log");
    assert_eq!(record["action"], "internal_error");
    assert_eq!(record["error"], "Payload");
}

/// Contract case: `a-stale-keyed-marker-is-refused-and-removed`.
fn a_stale_keyed_marker_is_refused_and_removed() {
    let directory = TestDir::new("contract-stale-keyed-marker");
    enable_fixture(&directory);
    directory.write_state(&prompt_path("stale"), "2000-01-01T00:00:00Z");

    let output = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("stale")),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
    assert!(!directory.state_path(&prompt_path("stale")).exists());
}

/// Contract case: `other-pre-tool-calls-pass-through-without-state-access`.
fn other_pre_tool_calls_pass_through_without_state_access() {
    let directory = TestDir::new("contract-other-pre-tool");
    let output = run_hook(&directory, &pre_tool_payload(&directory, "Read"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert!(!directory.state_dir().exists());
}

/// Contract case: `toggle-off-leaves-the-unkeyed-prompt-marker`.
fn toggle_off_leaves_the_unkeyed_prompt_marker() {
    let directory = TestDir::new("contract-toggle-leaves-unkeyed-marker");
    enable_fixture(&directory);
    directory.write_state(PROMPT_MARKER, "2000-01-01T00:00:00Z");
    let output = support::toggle_command()
        .arg("off")
        .env("HOME", directory.home())
        .env("PWD", fixture_cwd(&directory))
        .output()
        .expect("run toggle off");
    assert_eq!(output.status.code(), Some(0));
    assert!(directory.state_path(PROMPT_MARKER).exists());
}

/// Contract case: `garbled-prompt-marker-fails-open-without-consumption`.
fn garbled_prompt_marker_fails_open_without_consumption() {
    let directory = TestDir::new("contract-garbled-prompt-marker");
    enable_fixture(&directory);
    directory.write_state(&prompt_path("test-session"), "not a timestamp");
    let output = run_hook(&directory, &pre_tool_payload(&directory, "ScheduleWakeup"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        std::fs::read_to_string(directory.state_path(&prompt_path("test-session")))
            .expect("read garbled marker"),
        "not a timestamp"
    );
}

/// Contract case: `schedule-wakeup-with-a-missing-toggle-flag-warns-without-creating-state`.
fn schedule_wakeup_with_a_missing_toggle_flag_warns_without_creating_state() {
    let directory = TestDir::new("contract-missing-pre-tool-state");
    let output = run_hook(&directory, &pre_tool_payload(&directory, "ScheduleWakeup"));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, OFF_WARNING);
    assert!(!directory.state_dir().exists());
}

/// Contract case: `toggle-off-warning-leaves-a-fresh-prompt-marker-untouched`.
fn toggle_off_warning_leaves_a_fresh_prompt_marker_untouched() {
    let directory = TestDir::new("contract-off-fresh-prompt-marker");
    assert_eq!(
        prompt_once(&directory, "off-fresh-marker").status.code(),
        Some(2)
    );
    let marker = std::fs::read(directory.state_path(&prompt_path("off-fresh-marker")))
        .expect("read fresh marker");
    std::fs::remove_file(
        directory.state_path(&format!("heartbeat{}", fold(&fixture_cwd_text(&directory)))),
    )
    .expect("disable heartbeat without clearing marker");

    let output = run_hook(
        &directory,
        &pre_tool_payload_for(&directory, "ScheduleWakeup", Some("off-fresh-marker")),
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, OFF_WARNING);
    assert_eq!(
        std::fs::read(directory.state_path(&prompt_path("off-fresh-marker")))
            .expect("reread fresh marker"),
        marker
    );
}

/// Contract case: `unreadable-toggle-state-fails-open-without-marker-interaction`.
#[cfg(unix)]
fn unreadable_toggle_state_fails_open_without_marker_interaction() {
    let directory = TestDir::new("contract-unreadable-toggle");
    directory.write_state(&prompt_path("test-session"), "2000-01-01T00:00:00Z");
    let marker = std::fs::read(directory.state_path(&prompt_path("test-session")))
        .expect("read stale marker");
    let flag = directory.state_path(&format!("heartbeat{}", fold(&fixture_cwd_text(&directory))));
    std::os::unix::fs::symlink(&flag, &flag).expect("create unreadable toggle state");

    let output = run_hook(&directory, &pre_tool_payload(&directory, "ScheduleWakeup"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    assert_eq!(
        std::fs::read(directory.state_path(&prompt_path("test-session")))
            .expect("reread stale marker"),
        marker
    );
}

/// Contract case: `unreadable-hook-payload-refuses-before-event-dispatch`.
fn unreadable_hook_payload_refuses_before_event_dispatch() {
    let directory = TestDir::new("contract-unreadable-dispatch-payload");
    let output = run_hook(&directory, &[0xff, 0xfe]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("hook-event-mismatch"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("hook-event-mismatch"));
}

/// Contract case: `correction-block-is-agent-directed-stderr-not-user-json`.
fn correction_block_is_agent_directed_stderr_not_user_json() {
    let directory = TestDir::new("contract-correction");
    enable_fixture(&directory);
    let output = run_hook(
        &directory,
        &payload(&directory, &future_unprompted_arm(), "correction"),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("unprompted arm"));
}

/// Contract case: `off-and-armed-allows-are-silent-at-zero`.
fn off_and_armed_allows_are_silent_at_zero() {
    let off = TestDir::new("contract-off");
    let missing = off.path().join("missing.jsonl");
    let off_input = serde_json::to_vec(&TestDir::payload(&missing, &fixture_cwd_text(&off), "off"))
        .expect("serialize off payload");
    let off_output = run_hook(&off, &off_input);
    assert_eq!(off_output.status.code(), Some(0));
    assert_eq!(off_output.stdout, [] as [u8; 0]);
    assert_eq!(off_output.stderr, [] as [u8; 0]);

    let armed = TestDir::new("contract-armed");
    enable_fixture(&armed);
    armed.write_state("guard-warn-armed", "0");
    let armed_output = run_hook(&armed, &payload(&armed, &future_unprompted_arm(), "armed"));
    assert_eq!(armed_output.status.code(), Some(0));
    assert_eq!(armed_output.stdout, [] as [u8; 0]);
    assert_eq!(armed_output.stderr, [] as [u8; 0]);
}

/// Contract case: `lapse-allow-is-one-hook-json-object-on-stdout`.
fn lapse_allow_is_one_hook_json_object_on_stdout() {
    let directory = TestDir::new("contract-lapse");
    enable_fixture(&directory);
    directory.write_state("guard-count-lapse", "0 3");
    let output = run_hook(
        &directory,
        &payload(&directory, &[user("question", 30)], "lapse"),
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, [] as [u8; 0]);
    let response: Value = serde_json::from_slice(&output.stdout).expect("lapse hook JSON");
    assert!(response["systemMessage"].as_str().is_some());
    assert!(!output.stdout.ends_with(b"\n"));
}

/// Contract case: `malformed-events-refuse-and-unavailable-decision-inputs-fail-open`.
fn malformed_events_refuse_and_unavailable_decision_inputs_fail_open() {
    let malformed = TestDir::new("contract-malformed");
    let malformed_output = run_hook(&malformed, b"not json{{");
    assert_eq!(malformed_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&malformed_output.stdout).contains("hook-event-mismatch"));
    assert!(String::from_utf8_lossy(&malformed_output.stderr).contains("hook-event-mismatch"));

    let missing = TestDir::new("contract-missing");
    enable_fixture(&missing);
    let missing_input = serde_json::to_vec(&TestDir::payload(
        &missing.path().join("missing.jsonl"),
        &fixture_cwd_text(&missing),
        "missing",
    ))
    .expect("serialize missing payload");
    let missing_output = run_hook(&missing, &missing_input);
    assert_eq!(missing_output.status.code(), Some(0));
    assert_eq!(missing_output.stdout, [] as [u8; 0]);
    assert_eq!(missing_output.stderr, [] as [u8; 0]);

    let invalid = TestDir::new("contract-invalid");
    enable_fixture(&invalid);
    let invalid_input = serde_json::to_vec(&json!({
        "cwd": fixture_cwd_text(&invalid), "transcript_path": 17,
        "session_id": "invalid", "hook_event_name": "Stop"
    }))
    .expect("serialize invalid payload");
    let invalid_output = run_hook(&invalid, &invalid_input);
    assert_eq!(invalid_output.status.code(), Some(0));
    assert_eq!(invalid_output.stdout, [] as [u8; 0]);
    assert_eq!(invalid_output.stderr, [] as [u8; 0]);

    let unreadable = TestDir::new("contract-state-unreadable");
    enable_fixture(&unreadable);
    std::fs::create_dir_all(unreadable.state_path("guard-count-unreadable"))
        .expect("create unreadable state path");
    let unreadable_output = run_hook(
        &unreadable,
        &payload(&unreadable, &[user("question", 30)], "unreadable"),
    );
    assert_eq!(unreadable_output.status.code(), Some(0));
    assert_eq!(unreadable_output.stdout, [] as [u8; 0]);
    assert_eq!(unreadable_output.stderr, [] as [u8; 0]);
}

/// Contract case: `debug-panic-hook-is-replaced-before-argument-handling`.
fn debug_panic_hook_is_replaced_before_argument_handling() {
    let directory = TestDir::new("contract-panic");
    let input = payload(&directory, &[], "panic");
    let output = run_hook_with_env(
        &directory,
        &input,
        &[("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC", "secret-panic-payload")],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let log = std::fs::read_to_string(directory.state_path("orchestrator.log")).expect("panic log");
    assert!(log.contains("Panic"));
    assert!(!log.contains("secret-panic-payload"));
    assert!(!log.contains("panicked at"));
}

/// Contract case: `injected-panic-leaves-an-oversized-payload-write-without-a-reader`.
fn injected_panic_leaves_an_oversized_payload_write_without_a_reader() {
    let directory = TestDir::new("contract-unread-stdin");
    // The injected panic leaves the guard before its stdin read, and four mebibytes
    // exceed every pipe capacity an unprivileged process can arrange, so the write
    // cannot rest in the buffer: it blocks and then meets the read end the exiting
    // child closed. The outcome of record is the child's, never the write's.
    let payload = vec![b'x'; 4 << 20];

    let output = run_hook_with_env(
        &directory,
        &payload,
        &[("SUPERLOOP_CLAUDE_HOOK_TEST_PANIC", "secret-panic-payload")],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, [] as [u8; 0]);
    let log =
        std::fs::read_to_string(directory.state_path("orchestrator.log")).expect("read panic log");
    assert!(log.contains("Payload"));
    assert!(!log.contains("secret-panic-payload"));
}

/// Contract case: `toggle-subcommands-preserve-shell-output-and-folded-pwd-flag`.
fn toggle_subcommands_preserve_shell_output_and_folded_pwd_flag() {
    let directory = TestDir::new("contract-toggle");
    let cwd = fixture_cwd(&directory);
    let cwd_text = cwd.to_string_lossy();
    let run = |argument: Option<&str>| {
        let mut command = support::toggle_command();
        if let Some(argument) = argument {
            command.arg(argument);
        }
        command
            .env("HOME", directory.home())
            .env("PWD", &cwd)
            .output()
            .expect("run toggle command")
    };
    let initial = run(None);
    assert_eq!(initial.status.code(), Some(0));
    assert_eq!(initial.stdout, format!("OFF ({cwd_text})\n").into_bytes());
    let state = directory.home().join(".local/state/superloop-tools/hook");
    assert!(!state.exists());
    assert_eq!(run(Some("status")).stdout, initial.stdout);
    assert!(!state.exists());
    assert_eq!(run(Some("off")).status.code(), Some(0));
    assert!(state.is_dir());
    let on = run(Some("on"));
    assert_eq!(
        on.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
    assert_eq!(
        run(Some("status")).stdout,
        format!("ON ({cwd_text})\n").into_bytes()
    );
    let off = run(Some("off"));
    assert_eq!(
        off.stdout,
        format!("heartbeat guard OFF for {cwd_text} (blocked-on-user state)\n").into_bytes()
    );
    assert_eq!(
        run(Some("status")).stdout,
        format!("OFF ({cwd_text})\n").into_bytes()
    );
}

/// Contract case: `subdirectory-toggle-and-root-stop-share-one-project-flag`.
fn subdirectory_toggle_and_root_stop_share_one_project_flag() {
    let directory = TestDir::new("contract-project-root-stop");
    let root = directory.home().join("project");
    let nested = root.join("nested/deeper");
    create_git_directory(&root);
    std::fs::create_dir_all(&nested).expect("create nested working directory");

    let toggle = run_toggle(&directory, Some("on"), &nested);
    let root_text = root.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {root_text}\n").into_bytes()
    );
    let transcript = directory.write_transcript("root-stop.jsonl", &[user("question", 30)]);
    let input = serde_json::to_vec(&TestDir::payload(&transcript, &root_text, "root-stop"))
        .expect("serialize root Stop payload");
    let stop = run_hook(&directory, &input);
    assert_eq!(stop.status.code(), Some(2));
}

/// Contract case: `nested-worktree-marker-selects-its-directory-as-project-root`.
fn nested_worktree_marker_selects_its_directory_as_project_root() {
    let directory = TestDir::new("contract-nested-worktree");
    let outer = directory.home().join("outer");
    let worktree = outer.join("worktree");
    let nested = worktree.join("source/module");
    create_git_directory(&outer);
    std::fs::create_dir_all(&nested).expect("create nested worktree directory");
    std::fs::write(worktree.join(".git"), "gitdir: ../.git/worktrees/example\n")
        .expect("create worktree marker");

    let toggle = run_toggle(&directory, Some("on"), &nested);
    let worktree_text = worktree.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {worktree_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&worktree_text)))
            .exists()
    );
}

/// Contract case: `nonrepository-cwd-keeps-its-own-key`.
fn nonrepository_cwd_keeps_its_own_key() {
    let directory = TestDir::new("contract-nonrepository-cwd");
    let boundary = directory.home();
    let outside = boundary.join("outside/leaf");
    create_git_directory(&boundary);
    std::fs::create_dir_all(&outside).expect("create nonrepository working directory");
    let outside_text = outside.to_string_lossy();

    let toggle = run_toggle(&directory, Some("on"), &outside);
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {outside_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&outside_text)))
            .exists()
    );

    let root = boundary.join("repository");
    let nested = root.join("nested");
    create_git_directory(&root);
    std::fs::create_dir_all(&nested).expect("create repository child");
    let status = run_toggle(&directory, Some("status"), &nested);
    let root_text = root.to_string_lossy();
    assert_eq!(status.stdout, format!("OFF ({root_text})\n").into_bytes());
}

/// Contract case: `root-cwd-retains-deployed-folded-flag-name`.
fn root_cwd_retains_deployed_folded_flag_name() {
    let directory = TestDir::new("contract-root-literal");
    let markerless = fixture_cwd(&directory);
    let markerless_toggle = run_toggle(&directory, Some("on"), &markerless);
    let markerless_text = markerless.to_string_lossy();
    assert_eq!(
        markerless_toggle.stdout,
        format!("heartbeat guard ON for {markerless_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&markerless_text)))
            .exists()
    );

    let root = directory.home().join("project");
    create_git_directory(&root);
    let root_toggle = run_toggle(&directory, Some("on"), &root);
    let root_text = root.to_string_lossy();
    assert_eq!(
        root_toggle.stdout,
        format!("heartbeat guard ON for {root_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&root_text)))
            .exists()
    );
}

/// Contract case: `boundary-git-marker-is-never-a-project-key`.
fn boundary_git_marker_is_never_a_project_key() {
    let directory = TestDir::new("contract-boundary-marker");
    let boundary = directory.home();
    let cwd = boundary.join("plain/leaf");
    create_git_directory(&boundary);
    std::fs::create_dir_all(&cwd).expect("create working directory");

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `cwd-equal-to-home-is-returned-as-the-exclusive-boundary`.
fn cwd_equal_to_home_is_returned_as_the_exclusive_boundary() {
    let directory = TestDir::new("contract-cwd-equal-home");
    let home = directory.home();
    create_git_directory(&home);

    let toggle = run_toggle(&directory, Some("on"), &home);
    let home_text = home.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {home_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&home_text)))
            .exists()
    );
}

/// Contract case: `home-trailing-slash-still-bounds-the-search`.
fn home_trailing_slash_still_bounds_the_search() {
    let directory = TestDir::new("contract-home-trailing-slash");
    let home = directory.home();
    let cwd = home.join("plain/leaf");
    create_git_directory(&home);
    std::fs::create_dir_all(&cwd).expect("create working directory");
    let home_with_slash = format!("{}/", home.display());

    let output = support::toggle_command()
        .arg("on")
        .env("HOME", home_with_slash)
        .env("PWD", &cwd)
        .output()
        .expect("run trailing slash toggle");
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        output.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `nested-repository-cwd-selects-its-own-project-key`.
fn nested_repository_cwd_selects_its_own_project_key() {
    let directory = TestDir::new("contract-nested-project");
    let project = directory.home().join("project");
    let nested = project.join("vendor/repository");
    create_git_directory(&project);
    create_git_directory(&nested);

    let toggle = run_toggle(&directory, Some("on"), &nested);
    let nested_text = nested.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {nested_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&nested_text)))
            .exists()
    );
}

/// Contract case: `cwd-outside-home-finds-nearest-project-without-a-boundary`.
fn cwd_outside_home_finds_nearest_project_without_a_boundary() {
    let directory = TestDir::new("contract-outside-boundary");
    let project = directory.path().join("outside/project");
    let cwd = project.join("nested");
    create_git_directory(&project);
    std::fs::create_dir_all(&cwd).expect("create cwd outside home");

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    let project_text = project.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {project_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&project_text)))
            .exists()
    );
}

/// Contract case: `pre-tool-subdirectory-cwd-reads-the-project-root-flag`.
fn pre_tool_subdirectory_cwd_reads_the_project_root_flag() {
    let directory = TestDir::new("contract-pre-tool-project-root");
    let project = directory.home().join("project");
    let cwd = project.join("nested/deeper");
    create_git_directory(&project);
    std::fs::create_dir_all(&cwd).expect("create nested working directory");
    directory.enable(&project.to_string_lossy());
    let input = serde_json::to_vec(&json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "ScheduleWakeup",
        "session_id": "project-root",
        "cwd": cwd
    }))
    .expect("serialize nested PreToolUse payload");

    let output = run_hook(&directory, &input);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(output.stderr, REFUSAL_REASON);
}

/// Contract case: `implausible-git-directory-stops-before-outer-project`.
fn implausible_git_directory_stops_before_outer_project() {
    let directory = TestDir::new("contract-empty-marker");
    let outer = directory.home().join("outer");
    let cwd = outer.join("checkout");
    create_git_directory(&outer);
    std::fs::create_dir_all(cwd.join(".git")).expect("create empty marker");

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `short-git-file-stops-before-outer-project`.
fn short_git_file_stops_before_outer_project() {
    let directory = TestDir::new("contract-short-marker");
    let outer = directory.home().join("outer");
    let cwd = outer.join("checkout");
    create_git_directory(&outer);
    std::fs::create_dir_all(&cwd).expect("create checkout directory");
    std::fs::write(cwd.join(".git"), "git").expect("create short marker");

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `wrong-prefix-git-file-stops-before-outer-project`.
fn wrong_prefix_git_file_stops_before_outer_project() {
    let directory = TestDir::new("contract-wrong-prefix-marker");
    let outer = directory.home().join("outer");
    let cwd = outer.join("checkout");
    create_git_directory(&outer);
    std::fs::create_dir_all(&cwd).expect("create checkout directory");
    std::fs::write(cwd.join(".git"), "not-gitdir: elsewhere\n")
        .expect("create wrong-prefix marker");

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `permission-denied-git-directory-stops-before-outer-project`.
#[cfg(unix)]
fn permission_denied_git_directory_stops_before_outer_project() {
    let directory = TestDir::new("contract-permission-denied-marker");
    let outer = directory.home().join("outer");
    let project = outer.join("checkout");
    let cwd = project.join("nested");
    create_git_directory(&outer);
    create_git_directory(&project);
    std::fs::create_dir_all(&cwd).expect("create nested working directory");
    let marker = project.join(".git");
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o000))
        .expect("deny marker inspection");

    if marker.join("HEAD").is_file() {
        writeln!(
            std::io::stderr(),
            "permission-denied marker assertion skipped: process can inspect mode 000"
        )
        .expect("write permission-denied skip notice");
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o755))
            .expect("restore marker permissions");
        return;
    }

    let toggle = run_toggle(&directory, Some("on"), &cwd);
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o755))
        .expect("restore marker permissions");
    let cwd_text = cwd.to_string_lossy();
    assert_eq!(
        toggle.stdout,
        format!("heartbeat guard ON for {cwd_text}\n").into_bytes()
    );
    assert!(
        directory
            .state_path(&format!("heartbeat{}", fold(&cwd_text)))
            .exists()
    );
}

/// Contract case: `relative-cwd-is-returned-without-probing-the-process-directory`.
fn relative_cwd_is_returned_without_probing_the_process_directory() {
    let directory = TestDir::new("contract-relative-cwd");
    let process_directory = directory.path().join("process");
    let cwd = Path::new("relative/project");
    create_git_directory(&process_directory);
    std::fs::create_dir_all(process_directory.join(cwd))
        .expect("create relative working directory");

    let output = support::toggle_command()
        .arg("on")
        .current_dir(&process_directory)
        .env("HOME", directory.home())
        .env("PWD", cwd)
        .output()
        .expect("run relative cwd toggle");
    assert_eq!(output.stdout, b"heartbeat guard ON for relative/project\n");
    assert!(directory.state_path("heartbeatrelative-project").exists());
}

/// Contract case: `empty-cwd-is-returned-unchanged`.
fn empty_cwd_is_returned_unchanged() {
    let directory = TestDir::new("contract-empty-cwd");
    let process_directory = directory.path().join("process");
    create_git_directory(&process_directory);

    let output = support::toggle_command()
        .arg("on")
        .current_dir(&process_directory)
        .env("HOME", directory.home())
        .env("PWD", "")
        .output()
        .expect("run empty cwd toggle");
    assert_eq!(output.stdout, b"heartbeat guard ON for \n");
    assert!(directory.state_path("heartbeat").exists());
}

/// Contract case: `invalid-arguments-use-redacted-usage-and-do-not-create-state`.
fn invalid_arguments_use_redacted_usage_and_do_not_create_state() {
    let directory = TestDir::new("contract-usage");
    let secret = "secret-argument-value";
    let output = support::toggle_command()
        .args(["hook", secret])
        .env("HOME", directory.home())
        .output()
        .expect("run invalid command");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, [] as [u8; 0]);
    assert_eq!(
        output.stderr,
        b"superloop heartbeat: expected on|off|status [--global] or decide FILE\n"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    assert!(!directory.state_dir().exists());
}

fn main() {
    if std::env::args().skip(1).eq(["hook"]) {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut bytes)
            .expect("fixture request");
        return;
    }
    superloop_default_state_derives_from_home();
    intentional_prompt_block_uses_stderr_and_harness_exit_two();
    stop_prompt_writes_an_iso_utc_prompt_marker();
    stop_prompt_without_session_identity_writes_no_marker();
    schedule_wakeup_allows_and_consumes_a_fresh_prompt_marker();
    schedule_wakeup_without_a_marker_is_refused_with_guidance();
    schedule_wakeup_with_a_stale_marker_is_refused_and_cleans_it_up();
    two_prompted_sessions_consume_only_their_own_markers();
    arming_without_a_marker_of_its_own_is_refused();
    an_unkeyed_marker_does_not_authorize_a_keyed_session();
    missing_session_identity_fails_open_without_marker_access();
    a_stale_keyed_marker_is_refused_and_removed();
    other_pre_tool_calls_pass_through_without_state_access();
    toggle_off_leaves_the_unkeyed_prompt_marker();
    garbled_prompt_marker_fails_open_without_consumption();
    schedule_wakeup_with_a_missing_toggle_flag_warns_without_creating_state();
    toggle_off_warning_leaves_a_fresh_prompt_marker_untouched();
    unreadable_toggle_state_fails_open_without_marker_interaction();
    unreadable_hook_payload_refuses_before_event_dispatch();
    correction_block_is_agent_directed_stderr_not_user_json();
    off_and_armed_allows_are_silent_at_zero();
    lapse_allow_is_one_hook_json_object_on_stdout();
    malformed_events_refuse_and_unavailable_decision_inputs_fail_open();
    debug_panic_hook_is_replaced_before_argument_handling();
    injected_panic_leaves_an_oversized_payload_write_without_a_reader();
    toggle_subcommands_preserve_shell_output_and_folded_pwd_flag();
    subdirectory_toggle_and_root_stop_share_one_project_flag();
    nested_worktree_marker_selects_its_directory_as_project_root();
    nonrepository_cwd_keeps_its_own_key();
    root_cwd_retains_deployed_folded_flag_name();
    boundary_git_marker_is_never_a_project_key();
    cwd_equal_to_home_is_returned_as_the_exclusive_boundary();
    home_trailing_slash_still_bounds_the_search();
    nested_repository_cwd_selects_its_own_project_key();
    cwd_outside_home_finds_nearest_project_without_a_boundary();
    pre_tool_subdirectory_cwd_reads_the_project_root_flag();
    implausible_git_directory_stops_before_outer_project();
    short_git_file_stops_before_outer_project();
    wrong_prefix_git_file_stops_before_outer_project();
    permission_denied_git_directory_stops_before_outer_project();
    relative_cwd_is_returned_without_probing_the_process_directory();
    empty_cwd_is_returned_unchanged();
    invalid_arguments_use_redacted_usage_and_do_not_create_state();
    std::io::stdout()
        .write_all(b"heartbeat subprocess contracts passed\n")
        .expect("fixture result");
}
