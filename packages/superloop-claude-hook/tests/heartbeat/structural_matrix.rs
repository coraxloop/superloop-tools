mod support;

use serde_json::{Value, json};
use superloop_claude_hook::heartbeat::State;

use support::{ArmOptions, RunOptions, TestDir, append, arm, feedback, user};

fn prompted_arm(options: ArmOptions<'_>) -> Vec<Value> {
    append(
        append(vec![user("question", 300)], [feedback(250)]),
        arm(options),
    )
}

fn state(entries: &[Value], label: &str) -> State {
    TestDir::new(label)
        .run(entries, RunOptions::default())
        .state
}

/// ´test:integration:lower-delay-clamp-and-strict-expiry-are-exact´
#[test]
fn lower_delay_clamp_and_strict_expiry_are_exact() {
    for (label, delay, age, expected) in [
        ("delay-59-pending", 59, 180, State::AllowSilent),
        ("delay-60-pending", 60, 180, State::AllowSilent),
        ("delay-59-equality", 59, 181, State::BlockPrompt),
        ("delay-60-equality", 60, 181, State::BlockPrompt),
    ] {
        let entries = prompted_arm(ArmOptions {
            delay: Some(json!(delay)),
            age,
            ..ArmOptions::pending(age)
        });
        assert_eq!(state(&entries, label), expected, "case {label}");
    }
}

/// ´test:integration:upper-delay-clamp-and-slack-are-exact´
#[test]
fn upper_delay_clamp_and_slack_are_exact() {
    for (label, delay, age, expected) in [
        ("delay-3600-pending", 3_600, 3_720, State::AllowSilent),
        ("delay-3601-pending", 3_601, 3_720, State::AllowSilent),
        ("delay-3600-equality", 3_600, 3_721, State::BlockPrompt),
        ("delay-3601-equality", 3_601, 3_721, State::BlockPrompt),
    ] {
        let entries = prompted_arm(ArmOptions {
            delay: Some(json!(delay)),
            age,
            ..ArmOptions::pending(age)
        });
        assert_eq!(state(&entries, label), expected, "case {label}");
    }
}

/// ´test:integration:horizon-boundary-is-strictly-greater-than-3720-seconds´
#[test]
fn horizon_boundary_is_strictly_greater_than_3720_seconds() {
    let armed = prompted_arm(ArmOptions::pending(100));
    for (age, expected) in [(3_720, State::AllowSilent), (3_721, State::BlockPrompt)] {
        let entries = append(
            armed.clone(),
            [json!({
                "type": "assistant", "timestamp": support::ts(age),
                "message": {"role": "assistant", "content": []}
            })],
        );
        assert_eq!(state(&entries, &format!("horizon-{age}")), expected);
    }
}

/// ´test:integration:result-must-follow-call-in-append-order-for-backward-association´
#[test]
fn result_must_follow_call_in_append_order_for_backward_association() {
    let ordinary = prompted_arm(ArmOptions::pending(100));
    assert_eq!(state(&ordinary, "association-normal"), State::AllowSilent);

    let pair = arm(ArmOptions::pending(100));
    let reversed = append(
        append(
            append(vec![user("question", 300)], [feedback(250)]),
            [pair[1].clone()],
        ),
        [pair[0].clone()],
    );
    assert_eq!(state(&reversed, "association-reversed"), State::BlockPrompt);
}

/// ´test:integration:newest-usable-call-wins-across-multiple-calls´
#[test]
fn newest_usable_call_wins_across_multiple_calls() {
    let mut stopped = prompted_arm(ArmOptions {
        id: "arm",
        ..ArmOptions::pending(300)
    });
    stopped.extend(arm(ArmOptions {
        delay: None,
        age: 100,
        id: "stop",
        stop: true,
        error: false,
        no_result: false,
        sidechain: false,
    }));
    assert_eq!(state(&stopped, "latest-stop"), State::BlockPrompt);

    let mut rearmed = prompted_arm(ArmOptions {
        delay: None,
        age: 300,
        id: "stop",
        stop: true,
        error: false,
        no_result: false,
        sidechain: false,
    });
    rearmed.extend(arm(ArmOptions {
        id: "arm",
        ..ArmOptions::pending(100)
    }));
    assert_eq!(state(&rearmed, "latest-arm"), State::AllowSilent);
}

/// ´test:integration:only-explicit-utc-timestamps-supply-scheduling-evidence´
#[test]
fn only_explicit_utc_timestamps_supply_scheduling_evidence() {
    for (label, stamp, expected) in [
        ("naive", "2027-01-02T01:58:20", State::BlockPrompt),
        ("zulu", "2027-01-02T01:58:20Z", State::AllowSilent),
        ("offset", "2027-01-02T03:58:20+02:00", State::BlockPrompt),
        (
            "zero-offset",
            "2027-01-02T01:58:20+00:00",
            State::BlockPrompt,
        ),
        ("invalid-day", "2027-02-29T01:58:20Z", State::BlockPrompt),
        ("space", "2027-01-02 01:58:20Z", State::BlockPrompt),
    ] {
        let mut entries = prompted_arm(ArmOptions::pending(100));
        let call_index = entries.len() - 2;
        entries[call_index]["timestamp"] = json!(stamp);
        entries.last_mut().expect("arm result")["timestamp"] = json!(stamp);
        assert_eq!(state(&entries, label), expected, "case {label}");
    }
}

/// ´test:integration:call-or-result-timestamp-can-supply-scheduling-time´
#[test]
fn call_or_result_timestamp_can_supply_scheduling_time() {
    let mut result_only = prompted_arm(ArmOptions::pending(100));
    let call_index = result_only.len() - 2;
    result_only[call_index]
        .as_object_mut()
        .expect("call object")
        .remove("timestamp");
    assert_eq!(state(&result_only, "result-stamp"), State::AllowSilent);

    let mut call_only = prompted_arm(ArmOptions::pending(100));
    call_only
        .last_mut()
        .expect("result")
        .as_object_mut()
        .expect("result object")
        .remove("timestamp");
    assert_eq!(state(&call_only, "call-stamp"), State::AllowSilent);

    let mut neither = call_only;
    let call_index = neither.len() - 2;
    neither[call_index]
        .as_object_mut()
        .expect("call object")
        .remove("timestamp");
    assert_eq!(state(&neither, "no-stamp"), State::BlockPrompt);
}

/// ´test:integration:malformed-delay-is-skipped-in-favor-of-an-older-usable-call´
#[test]
fn malformed_delay_is_skipped_in_favor_of_an_older_usable_call() {
    let mut entries = prompted_arm(ArmOptions {
        id: "older",
        ..ArmOptions::pending(300)
    });
    entries.extend(arm(ArmOptions {
        delay: Some(json!("not numeric")),
        age: 100,
        id: "newer",
        stop: false,
        error: false,
        no_result: false,
        sidechain: false,
    }));
    assert_eq!(state(&entries, "malformed-newest"), State::AllowSilent);
}

/// ´test:integration:failed-and-in-flight-newer-calls-do-not-hide-older-evidence´
#[test]
fn failed_and_in_flight_newer_calls_do_not_hide_older_evidence() {
    for (label, error, no_result) in [("failed", true, false), ("in-flight", false, true)] {
        let mut entries = prompted_arm(ArmOptions {
            id: "older",
            ..ArmOptions::pending(300)
        });
        entries.extend(arm(ArmOptions {
            id: "newer",
            age: 100,
            error,
            no_result,
            ..ArmOptions::pending(100)
        }));
        assert_eq!(state(&entries, label), State::AllowSilent, "case {label}");
    }
}

/// ´test:integration:future-entries-do-not-trigger-the-old-entry-cutoff´
#[test]
fn future_entries_do_not_trigger_the_old_entry_cutoff() {
    let entries = append(
        prompted_arm(ArmOptions::pending(100)),
        [json!({
            "type": "assistant", "timestamp": "2027-01-03T02:00:00Z",
            "message": {"role": "assistant", "content": []}
        })],
    );
    assert_eq!(state(&entries, "future-entry"), State::AllowSilent);
}

/// ´test:integration:scheduler-result-prose-is-never-inspected´
#[test]
fn scheduler_result_prose_is_never_inspected() {
    let mut pending = prompted_arm(ArmOptions::pending(100));
    pending.last_mut().expect("result")["message"]["content"][0]["content"] =
        json!("Loop stopped, allegedly; arbitrary prose is irrelevant");
    assert_eq!(state(&pending, "prose-pending"), State::AllowSilent);

    let mut stopped = prompted_arm(ArmOptions {
        delay: None,
        age: 100,
        id: "stop",
        stop: true,
        error: false,
        no_result: false,
        sidechain: false,
    });
    stopped.last_mut().expect("result")["message"]["content"][0]["content"] =
        json!("Next wakeup scheduled, allegedly");
    assert_eq!(state(&stopped, "prose-stopped"), State::BlockPrompt);
}

/// ´test:integration:short-and-non-ascii-malformed-timestamps-are-no-evidence´
#[test]
fn short_and_non_ascii_malformed_timestamps_are_no_evidence() {
    for (label, stamp) in [("short-stamp", "x"), ("unicode-stamp", "éééééé")] {
        let mut entries = append(vec![user("question", 300)], arm(ArmOptions::pending(100)));
        let call_index = entries.len() - 2;
        entries[call_index]["timestamp"] = json!(stamp);
        entries.last_mut().expect("result")["timestamp"] = json!(stamp);
        assert_eq!(
            state(&entries, label),
            State::BlockViolationAndPrompt,
            "case {label}"
        );
    }
}
