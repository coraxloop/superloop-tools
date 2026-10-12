mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use serde_json::{Value, json};
use superloop_claude_hook::heartbeat::State;

use support::{
    ArmOptions, RunOptions, TestDir, append, arm, assert_block, assert_silent_allow, feedback,
    system_message, user,
};

fn base() -> Vec<Value> {
    vec![user("question", 30)]
}

fn project_cwd(directory: &TestDir) -> String {
    directory.project("project").to_string_lossy().into_owned()
}

/// ´test:integration:absent-malformed-mismatched-and-negative-counts-recover-as-zero´
#[test]
fn absent_malformed_mismatched_and_negative_counts_recover_as_zero() {
    for (label, stored) in [
        ("absent", None),
        ("malformed", Some("not a count")),
        ("mismatch", Some("9 2")),
        ("negative", Some("0 -4")),
    ] {
        let directory = TestDir::new(label);
        if let Some(stored) = stored {
            directory.write_state("guard-count-count-session", stored);
        }
        let result = directory.run(
            &base(),
            RunOptions {
                session: "count-session",
                ..RunOptions::default()
            },
        );
        assert_eq!(result.state, State::BlockPrompt, "case {label}");
        assert_eq!(
            fs::read(directory.state_path("guard-count-count-session"))
                .expect("read recovered count"),
            b"0 1",
            "case {label}"
        );
    }
}

/// ´test:integration:zero-and-two-counts-block-while-three-and-larger-lapse´
#[test]
fn zero_and_two_counts_block_while_three_and_larger_lapse() {
    for (count, expected) in [
        (0, State::BlockPrompt),
        (2, State::BlockPrompt),
        (3, State::AllowLapseAlarm),
        (8, State::AllowLapseAlarm),
    ] {
        let directory = TestDir::new(&format!("count-{count}"));
        directory.write_state("guard-count-count-session", format!("0 {count}"));
        let result = directory.run(
            &base(),
            RunOptions {
                session: "count-session",
                ..RunOptions::default()
            },
        );
        assert_eq!(result.state, expected, "count {count}");
    }
}

/// ´test:integration:no-real-user-turn-uses-none-marker´
#[test]
fn no_real_user_turn_uses_none_marker() {
    let directory = TestDir::new("no-user-turn");
    let result = directory.run(&[], RunOptions::default());
    assert_block(&result);
    assert_eq!(
        fs::read(directory.state_path("guard-count-reference-session"))
            .expect("read no-turn count"),
        b"None 1"
    );
}

/// ´test:integration:warning-absent-blocks-once-and-warning-present-allows-pending-arm´
#[test]
fn warning_absent_blocks_once_and_warning_present_allows_pending_arm() {
    let entries = append(base(), arm(ArmOptions::pending(100)));
    let fresh = TestDir::new("warning-fresh");
    let fresh_result = fresh.run(&entries, RunOptions::default());
    assert_eq!(fresh_result.state, State::BlockViolation);
    assert_eq!(
        fs::read(fresh.state_path("guard-warn-reference-session")).expect("read written warning"),
        b"0"
    );

    let warned = TestDir::new("warning-recorded");
    warned.write_state("guard-warn-reference-session", "0");
    let warned_result = warned.run(&entries, RunOptions::default());
    assert_silent_allow(&warned_result);
    assert!(
        warned_result
            .path
            .contains(&State::ExceptionUnpromptedArmed)
    );
}

/// ´test:integration:string-and-list-feedback-both-authorize-a-later-arm´
#[test]
fn string_and_list_feedback_both_authorize_a_later_arm() {
    let list_feedback = json!({
        "type": "user",
        "timestamp": support::ts(110),
        "message": {"role": "user", "content": [{
            "type": "text", "text": "Stop hook feedback:\nHEARTBEAT GUARD: ..."
        }]}
    });
    for (label, feedback_entry) in [("string", feedback(110)), ("list", list_feedback)] {
        let directory = TestDir::new(label);
        let entries = append(
            append(base(), [feedback_entry]),
            arm(ArmOptions::pending(100)),
        );
        assert_silent_allow(&directory.run(&entries, RunOptions::default()));
    }
}

/// ´test:integration:session-counters-are-isolated´
#[test]
fn session_counters_are_isolated() {
    let directory = TestDir::new("session-isolation");
    assert_block(&directory.run(
        &base(),
        RunOptions {
            session: "one",
            ..RunOptions::default()
        },
    ));
    assert_block(&directory.run(
        &base(),
        RunOptions {
            session: "two",
            ..RunOptions::default()
        },
    ));
    assert_eq!(
        fs::read_to_string(directory.state_path("guard-count-one")).expect("session one"),
        "0 1"
    );
    assert_eq!(
        fs::read_to_string(directory.state_path("guard-count-two")).expect("session two"),
        "0 1"
    );
}

/// ´test:integration:project-flags-are-isolated-and-checked-before-transcript´
#[test]
fn project_flags_are_isolated_and_checked_before_transcript() {
    let directory = TestDir::new("project-isolation");
    let project_one = directory.project("project/one");
    let project_one_text = project_one.to_string_lossy();
    let project_two = directory.project("project/two");
    let project_two_text = project_two.to_string_lossy();
    let enabled = directory.run(
        &base(),
        RunOptions {
            cwd: Some(&project_one_text),
            ..RunOptions::default()
        },
    );
    assert_block(&enabled);
    let disabled = directory.run(
        &base(),
        RunOptions {
            toggle_on: false,
            cwd: Some(&project_two_text),
            missing_transcript: true,
            ..RunOptions::default()
        },
    );
    assert_silent_allow(&disabled);
    assert!(disabled.path.contains(&State::Off));
}

/// ´test:integration:unreadable-count-or-warning-state-fails-open-without-a-block´
#[test]
fn unreadable_count_or_warning_state_fails_open_without_a_block() {
    for name in [
        "guard-count-reference-session",
        "guard-warn-reference-session",
    ] {
        let directory = TestDir::new("unreadable-state");
        fs::create_dir_all(directory.state_path(name)).expect("create unreadable state directory");
        let result = directory.run(&base(), RunOptions::default());
        assert_silent_allow(&result);
        assert!(result.path.contains(&State::FailOpen));
    }
}

/// ´test:integration:count-write-failure-takes-the-anti-wedge-fail-open-edge´
#[test]
fn count_write_failure_takes_the_anti_wedge_fail_open_edge() {
    let directory = TestDir::new("count-write-failure");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let transcript = directory.write_transcript("count-write.jsonl", &base());
    fs::set_permissions(directory.state_dir(), fs::Permissions::from_mode(0o555))
        .expect("make state root read-only");
    let payload = serde_json::to_vec(&TestDir::payload(&transcript, &cwd, "write-failure"))
        .expect("serialize payload");
    let result = superloop_claude_hook::heartbeat::fixture_evaluate(
        &payload,
        &directory.state_dir(),
        support::NOW,
        support::NOW,
    );
    fs::set_permissions(directory.state_dir(), fs::Permissions::from_mode(0o755))
        .expect("restore state root permissions");
    assert_silent_allow(&result);
    assert!(result.path.contains(&State::Prompt));
    assert!(result.path.contains(&State::FailOpen));
}

/// ´test:integration:warning-write-failure-takes-the-anti-wedge-fail-open-edge´
#[test]
fn warning_write_failure_takes_the_anti_wedge_fail_open_edge() {
    let directory = TestDir::new("warning-write-failure");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let entries = append(base(), arm(ArmOptions::pending(100)));
    let transcript = directory.write_transcript("warning-write.jsonl", &entries);
    fs::set_permissions(directory.state_dir(), fs::Permissions::from_mode(0o555))
        .expect("make state root read-only");
    let payload = serde_json::to_vec(&TestDir::payload(&transcript, &cwd, "write-failure"))
        .expect("serialize payload");
    let result = superloop_claude_hook::heartbeat::fixture_evaluate(
        &payload,
        &directory.state_dir(),
        support::NOW,
        support::NOW,
    );
    fs::set_permissions(directory.state_dir(), fs::Permissions::from_mode(0o755))
        .expect("restore state root permissions");
    assert_silent_allow(&result);
    assert!(result.path.contains(&State::ExceptionUnpromptedArmed));
    assert!(result.path.contains(&State::FailOpen));
}

/// ´test:integration:malformed-transcript-lines-are-skipped-but-invalid-structure-fails-open´
#[test]
fn malformed_transcript_lines_are_skipped_but_invalid_structure_fails_open() {
    let directory = TestDir::new("transcript-shape");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let transcript = directory.path().join("mixed.jsonl");
    fs::write(
        &transcript,
        format!(
            "not json\n[]\n{}\n",
            serde_json::to_string(&user("question", 30)).expect("serialize user")
        ),
    )
    .expect("write mixed transcript");
    let payload = serde_json::to_vec(&TestDir::payload(&transcript, &cwd, "mixed-lines"))
        .expect("serialize payload");
    assert_block(&superloop_claude_hook::heartbeat::fixture_evaluate(
        &payload,
        &directory.state_dir(),
        support::NOW,
        support::NOW,
    ));

    let invalid = vec![json!({
        "type": "user", "timestamp": support::ts(30), "message": "not-an-object"
    })];
    let result = directory.run(&invalid, RunOptions::default());
    assert_silent_allow(&result);
    assert!(result.path.contains(&State::FailOpen));
}

/// ´test:integration:fresh-unprompted-lapse-uses-the-sixth-verdict-path´
#[test]
fn fresh_unprompted_lapse_uses_the_sixth_verdict_path() {
    let directory = TestDir::new("fresh-unprompted-lapse");
    directory.write_state("guard-count-reference-session", "0 3");
    let result = directory.run(
        &append(base(), arm(ArmOptions::pending(2_000))),
        RunOptions::default(),
    );
    assert_eq!(result.state, State::AllowLapseAndViolationAlarm);
    let message = system_message(&result);
    assert!(message.contains("heartbeat has LAPSED"));
    assert!(message.contains("unprompted arm"));
}

fn json_lines(entries: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend(serde_json::to_vec(entry).expect("serialize retry entry"));
        bytes.push(b'\n');
    }
    bytes
}

/// ´test:integration:active-stop-retries-once-and-consumes-replacement-entries´
#[test]
fn active_stop_retries_once_and_consumes_replacement_entries() {
    let directory = TestDir::new("retry-replacement");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let transcript = directory.write_transcript("retry.jsonl", &base());
    let mut payload = TestDir::payload(&transcript, &cwd, "retry");
    payload["stop_hook_active"] = json!(true);
    let replacement = append(
        append(base(), [feedback(110)]),
        arm(ArmOptions::pending(100)),
    );
    let result = superloop_claude_hook::heartbeat::fixture_evaluate_with_reload(
        &serde_json::to_vec(&payload).expect("serialize retry payload"),
        &directory.state_dir(),
        support::NOW,
        support::NOW,
        &json_lines(&replacement),
    );
    assert_silent_allow(&result);
    assert_eq!(result.retry_count, 1);
    assert!(result.path.contains(&State::RetryOnce));
    assert!(result.path.contains(&State::Armed));
}

/// ´test:integration:unreadable-second-load-after-retry-fails-open´
#[test]
fn unreadable_second_load_after_retry_fails_open() {
    let directory = TestDir::new("retry-unreadable");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let transcript = directory.write_transcript("retry-unreadable.jsonl", &base());
    let mut payload = TestDir::payload(&transcript, &cwd, "retry-unreadable");
    payload["stop_hook_active"] = json!(true);
    let result = superloop_claude_hook::heartbeat::fixture_evaluate_with_reload(
        &serde_json::to_vec(&payload).expect("serialize retry payload"),
        &directory.state_dir(),
        support::NOW,
        support::NOW,
        &[0xff, 0xfe],
    );
    assert_silent_allow(&result);
    assert_eq!(result.retry_count, 1);
    assert!(result.path.contains(&State::RetryOnce));
    assert!(result.path.contains(&State::FailOpen));
}

/// ´test:integration:undecodable-first-transcript-load-fails-open´
#[test]
fn undecodable_first_transcript_load_fails_open() {
    let directory = TestDir::new("undecodable-transcript");
    let cwd = project_cwd(&directory);
    directory.enable(&cwd);
    let transcript = directory.path().join("undecodable.jsonl");
    fs::write(&transcript, [0xff, 0xfe]).expect("write undecodable transcript");
    let payload = serde_json::to_vec(&TestDir::payload(&transcript, &cwd, "undecodable"))
        .expect("serialize undecodable payload");
    let result = superloop_claude_hook::heartbeat::fixture_evaluate(
        &payload,
        &directory.state_dir(),
        support::NOW,
        support::NOW,
    );
    assert_silent_allow(&result);
    assert!(result.path.contains(&State::FailOpen));
}
