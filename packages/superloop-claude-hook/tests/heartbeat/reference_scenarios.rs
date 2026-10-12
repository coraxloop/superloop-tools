//! The 26 scenarios from the deployed Python heartbeat-guard audit.

mod support;

use serde_json::{Value, json};

use support::{
    ArmOptions, RunOptions, TestDir, append, arm, assert_block, assert_silent_allow, count_path,
    feedback, system_message, user, warning_path,
};

fn base() -> Vec<Value> {
    vec![user("question", 30)]
}

/// ´test:integration:p01-stdin-not-json-fails-open´
#[test]
fn p01_stdin_not_json_fails_open() {
    let directory = TestDir::new("p01");
    let result = directory.run(
        &[],
        RunOptions {
            raw_input: Some("not json{{"),
            ..RunOptions::default()
        },
    );
    assert_silent_allow(&result);
}

/// ´test:integration:p02-missing-transcript-with-toggle-on-fails-open´
#[test]
fn p02_missing_transcript_with_toggle_on_fails_open() {
    let directory = TestDir::new("p02");
    let result = directory.run(
        &base(),
        RunOptions {
            missing_transcript: true,
            ..RunOptions::default()
        },
    );
    assert_silent_allow(&result);
}

/// ´test:integration:p03-toggle-off-skips-transcript´
#[test]
fn p03_toggle_off_skips_transcript() {
    let directory = TestDir::new("p03");
    let entries = append(base(), arm(ArmOptions::pending(100)));
    let result = directory.run(
        &entries,
        RunOptions {
            toggle_on: false,
            ..RunOptions::default()
        },
    );
    assert_silent_allow(&result);
}

/// ´test:integration:p04-fresh-pending-arm-gets-one-agent-correction´
#[test]
fn p04_fresh_pending_arm_gets_one_agent_correction() {
    let directory = TestDir::new("p04");
    let result = directory.run(
        &append(base(), arm(ArmOptions::pending(100))),
        RunOptions::default(),
    );
    assert_block(&result);
    assert!(String::from_utf8_lossy(&result.stderr).contains("unprompted arm"));
}

/// ´test:integration:p05-previous-turn-pending-arm-is-ratified´
#[test]
fn p05_previous_turn_pending_arm_is_ratified() {
    let directory = TestDir::new("p05");
    let entries = append(arm(ArmOptions::pending(600)), [user("later question", 30)]);
    assert_silent_allow(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p06-expired-arm-prompts´
#[test]
fn p06_expired_arm_prompts() {
    let directory = TestDir::new("p06");
    let result = directory.run(
        &append(base(), arm(ArmOptions::pending(2_000))),
        RunOptions::default(),
    );
    assert_block(&result);
}

/// ´test:integration:p07-stop-after-arm-disarms´
#[test]
fn p07_stop_after_arm_disarms() {
    let directory = TestDir::new("p07");
    let mut entries = append(
        base(),
        arm(ArmOptions {
            id: "a",
            age: 300,
            ..ArmOptions::pending(300)
        }),
    );
    entries.extend(arm(ArmOptions {
        delay: None,
        age: 100,
        id: "b",
        stop: true,
        error: false,
        no_result: false,
        sidechain: false,
    }));
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p08-rearm-after-stop-is-pending-but-unprompted´
#[test]
fn p08_rearm_after_stop_is_pending_but_unprompted() {
    let directory = TestDir::new("p08");
    let mut entries = append(
        base(),
        arm(ArmOptions {
            delay: None,
            age: 300,
            id: "a",
            stop: true,
            error: false,
            no_result: false,
            sidechain: false,
        }),
    );
    entries.extend(arm(ArmOptions {
        id: "b",
        age: 100,
        ..ArmOptions::pending(100)
    }));
    let result = directory.run(&entries, RunOptions::default());
    assert_block(&result);
    assert!(String::from_utf8_lossy(&result.stderr).contains("unprompted arm"));
}

/// ´test:integration:p09-call-without-result-is-no-evidence´
#[test]
fn p09_call_without_result_is_no_evidence() {
    let directory = TestDir::new("p09");
    let entries = append(
        base(),
        arm(ArmOptions {
            no_result: true,
            ..ArmOptions::pending(100)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p10-errored-call-is-no-evidence´
#[test]
fn p10_errored_call_is_no_evidence() {
    let directory = TestDir::new("p10");
    let entries = append(
        base(),
        arm(ArmOptions {
            error: true,
            ..ArmOptions::pending(100)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p11-old-entry-ends-the-horizon-scan´
#[test]
fn p11_old_entry_ends_the_horizon_scan() {
    let directory = TestDir::new("p11");
    let entries = append(
        append(
            base(),
            arm(ArmOptions {
                error: true,
                ..ArmOptions::pending(100)
            }),
        ),
        [user("ancient", 5_000)],
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p12-missing-delay-is-no-evidence´
#[test]
fn p12_missing_delay_is_no_evidence() {
    let directory = TestDir::new("p12");
    let entries = append(
        base(),
        arm(ArmOptions {
            delay: None,
            ..ArmOptions::pending(100)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p13-large-delay-is-clamped-and-pending-but-unprompted´
#[test]
fn p13_large_delay_is_clamped_and_pending_but_unprompted() {
    let directory = TestDir::new("p13");
    let entries = append(
        base(),
        arm(ArmOptions {
            delay: Some(json!(99_999)),
            ..ArmOptions::pending(100)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p14-clamped-large-delay-expires´
#[test]
fn p14_clamped_large_delay_expires() {
    let directory = TestDir::new("p14");
    let entries = append(
        base(),
        arm(ArmOptions {
            delay: Some(json!(99_999)),
            ..ArmOptions::pending(3_800)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p15-sidechain-arm-is-invisible´
#[test]
fn p15_sidechain_arm_is_invisible() {
    let directory = TestDir::new("p15");
    let entries = append(
        base(),
        arm(ArmOptions {
            sidechain: true,
            ..ArmOptions::pending(100)
        }),
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p16-scheduler-prose-never-counts´
#[test]
fn p16_scheduler_prose_never_counts() {
    let directory = TestDir::new("p16");
    let entries = append(
        append(base(), arm(ArmOptions::pending(2_000))),
        [json!({
            "type": "assistant", "timestamp": support::ts(20),
            "message": {"role": "assistant", "content": [{
                "type": "text",
                "text": "Next wakeup scheduled for 23:59:59; delaySeconds: 1800"
            }]}
        })],
    );
    assert_block(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p17-prompt-cap-blocks-first-three-evaluations´
#[test]
fn p17_prompt_cap_blocks_first_three_evaluations() {
    let directory = TestDir::new("p17");
    let session = "cap-session";
    let entries = append(
        append(base(), arm(ArmOptions::pending(2_000))),
        [feedback(20), feedback(10)],
    );
    for _index in 0..3 {
        assert_block(&directory.run(
            &entries,
            RunOptions {
                session,
                ..RunOptions::default()
            },
        ));
    }
    assert_eq!(
        std::fs::read_to_string(directory.state_path(&count_path(session)))
            .expect("read prompt counter"),
        "0 3"
    );
}

/// ´test:integration:p18-unprompted-lapse-allows-with-alarm´
#[test]
fn p18_unprompted_lapse_allows_with_alarm() {
    let directory = TestDir::new("p18");
    let session = "unprompted-lapse-session";
    let entries = append(
        append(base(), arm(ArmOptions::pending(2_000))),
        [feedback(20), feedback(10)],
    );
    let mut result = directory.run(
        &entries,
        RunOptions {
            session,
            ..RunOptions::default()
        },
    );
    for _index in 1..4 {
        result = directory.run(
            &entries,
            RunOptions {
                session,
                ..RunOptions::default()
            },
        );
    }
    assert!(system_message(&result).contains("heartbeat has LAPSED"));
}

/// ´test:integration:p19-grace-retry-is-scoped-and-controlled´
#[test]
fn p19_grace_retry_is_scoped_and_controlled() {
    let directory = TestDir::new("p19");
    let armed = directory.run(
        &append(base(), arm(ArmOptions::pending(100))),
        RunOptions::default(),
    );
    let first = directory.run(
        &append(base(), arm(ArmOptions::pending(2_000))),
        RunOptions::default(),
    );
    let retried = directory.run(
        &append(base(), arm(ArmOptions::pending(2_000))),
        RunOptions {
            stop_hook_active: true,
            ..RunOptions::default()
        },
    );
    assert_eq!(armed.retry_count, 0);
    assert_eq!(first.retry_count, 0);
    assert_eq!(retried.retry_count, 1);
}

/// ´test:integration:p20-prompted-arm-draws-no-correction´
#[test]
fn p20_prompted_arm_draws_no_correction() {
    let directory = TestDir::new("p20");
    let entries = append(
        append(base(), [feedback(110)]),
        arm(ArmOptions::pending(100)),
    );
    assert_silent_allow(&directory.run(&entries, RunOptions::default()));
}

/// ´test:integration:p21-unprompted-correction-fires-once-per-turn´
#[test]
fn p21_unprompted_correction_fires_once_per_turn() {
    let directory = TestDir::new("p21");
    let session = "warning-session";
    let entries = append(base(), arm(ArmOptions::pending(100)));
    let options = RunOptions {
        session,
        ..RunOptions::default()
    };
    let first = directory.run(&entries, options);
    let second = directory.run(&entries, options);
    assert_block(&first);
    assert!(String::from_utf8_lossy(&first.stderr).contains("unprompted arm"));
    assert_silent_allow(&second);
    assert_eq!(
        std::fs::read_to_string(directory.state_path(&warning_path(session)))
            .expect("read warning marker"),
        "0"
    );
}

/// ´test:integration:p22-unprompted-stop-is-exempt´
#[test]
fn p22_unprompted_stop_is_exempt() {
    let directory = TestDir::new("p22");
    let entries = append(
        base(),
        arm(ArmOptions {
            delay: None,
            age: 100,
            id: "t1",
            stop: true,
            error: false,
            no_result: false,
            sidechain: false,
        }),
    );
    let result = directory.run(&entries, RunOptions::default());
    assert_block(&result);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("unprompted arm"));
}

/// ´test:integration:p23-expired-unprompted-arm-combines-correction-and-prompt´
#[test]
fn p23_expired_unprompted_arm_combines_correction_and_prompt() {
    let directory = TestDir::new("p23");
    let result = directory.run(
        &append(base(), arm(ArmOptions::pending(2_000))),
        RunOptions::default(),
    );
    assert_block(&result);
    let reason = String::from_utf8_lossy(&result.stderr);
    assert!(reason.contains("unprompted arm"));
    assert!(reason.contains("no wakeup is currently armed"));
}

/// ´test:integration:p24-new-user-turn-resets-warning-marker´
#[test]
fn p24_new_user_turn_resets_warning_marker() {
    let directory = TestDir::new("p24");
    let session = "turn-reset-session";
    let first_turn = append(base(), arm(ArmOptions::pending(100)));
    assert_block(&directory.run(
        &first_turn,
        RunOptions {
            session,
            ..RunOptions::default()
        },
    ));
    let second_turn = append(
        append(first_turn, [user("next question", 20)]),
        arm(ArmOptions {
            id: "t2",
            age: 10,
            ..ArmOptions::pending(10)
        }),
    );
    let result = directory.run(
        &second_turn,
        RunOptions {
            session,
            ..RunOptions::default()
        },
    );
    assert_block(&result);
    assert!(String::from_utf8_lossy(&result.stderr).contains("unprompted arm"));
}

/// ´test:integration:p25-pure-lapse-blocks-three-then-allows-with-alarm´
#[test]
fn p25_pure_lapse_blocks_three_then_allows_with_alarm() {
    let directory = TestDir::new("p25");
    let session = "pure-lapse-session";
    let entries = append(base(), [feedback(20), feedback(10)]);
    let options = RunOptions {
        session,
        ..RunOptions::default()
    };
    for _index in 0..3 {
        assert_block(&directory.run(&entries, options));
    }
    let lapse = directory.run(&entries, options);
    assert!(system_message(&lapse).contains("heartbeat has LAPSED"));
}

/// ´test:integration:p26-lapse-resolves-on-next-user-turn´
#[test]
fn p26_lapse_resolves_on_next_user_turn() {
    let directory = TestDir::new("p26");
    let session = "lapse-recovery-session";
    let entries = append(base(), [feedback(20), feedback(10)]);
    let options = RunOptions {
        session,
        ..RunOptions::default()
    };
    for _index in 0..4 {
        let _result = directory.run(&entries, options);
    }
    let next_turn = append(entries, [user("next question", 5)]);
    assert_block(&directory.run(&next_turn, options));
}
