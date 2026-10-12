use std::ffi::{OsStr, OsString};
use std::path::Path;

use serde_json::{Value, json};

use crate::command_checks::matching_read_only_entry;
use crate::request::PermissionRequest;
use crate::topology::{
    SUPPORTED_HARNESS_VERSION, TABLE_CONFIRMATION_SPECS, TOPOLOGY_COMMAND, TableConfirmationSpec,
    TablePositiveEvidence, TableToolOutcome, TopologyEvidence, TopologyResultEvidence,
    TrialConditions, classify_preexisting_deny_evidence, classify_real_hook_tool_failure,
    classify_table_member, classify_table_negative, classify_table_positive,
    classify_topology_evidence, extract_harness_version, harness_provenance_fixture_value,
    harness_result_arguments, hook_was_consulted, parse_audit, planned_trial_count,
    preexisting_deny_settings_fixture, prompt_requested, real_hook_expectations, select_topology,
    settings_fixture, start_progress_fixture, table_tool_outcome, trial_progress_fixture,
    version_supported,
};

fn audit(events: &[(&str, &str)]) -> Vec<super::super::topology::AuditEvent> {
    let lines = events
        .iter()
        .map(|(event, command)| {
            format!(
                "{{\"event\":\"{event}\",\"tool_use_id\":\"use-1\",\"tool\":\"Bash\",\"command\":\"{command}\"}}"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    parse_audit(lines.as_bytes()).expect("synthetic audit log parses")
}

fn preexisting_deny_command() -> &'static str {
    real_hook_expectations()
        .into_iter()
        .find_map(|(_row, command, preexisting_deny, _expected)| {
            preexisting_deny.then_some(command)
        })
        .expect("real hook specifications carry a pre-existing-deny row")
}

fn evidence<'a>(
    events: &'a [super::super::topology::AuditEvent],
    ran: bool,
    permission_denials: &'a [Value],
) -> TopologyEvidence<'a> {
    TopologyEvidence {
        events,
        ran,
        exit_code: Some(0),
        conditions: TrialConditions {
            timed_out: false,
            output_overflow: false,
        },
        result_document: Some(TopologyResultEvidence {
            permission_denials,
            is_error: false,
        }),
    }
}

fn table_confirmation_request(spec: &TableConfirmationSpec, positive: bool) -> PermissionRequest {
    if spec.tool == "Bash" {
        return super::bash(
            if positive {
                spec.positive_command
            } else {
                spec.negative_command
            }
            .expect("Bash matrix form carries a command"),
            None,
            None,
        );
    }
    let request_json = if positive {
        spec.positive_request_json
    } else {
        spec.negative_request_json
    }
    .expect("native matrix form carries request JSON");
    let input: Value = serde_json::from_str(request_json).expect("native request JSON parses");
    super::decoded(spec.tool, input)
}

/// ´test:crate:every-table-confirmation-twin-leaves-its-expected-entry´
#[test]
fn every_table_confirmation_twin_leaves_its_expected_entry() {
    for spec in TABLE_CONFIRMATION_SPECS {
        let positive = table_confirmation_request(spec, true);
        let negative = table_confirmation_request(spec, false);
        assert_eq!(
            matching_read_only_entry(&positive).map(|entry| entry.entry),
            Some(spec.table_entry),
            "positive member={}",
            spec.member
        );
        assert_eq!(
            matching_read_only_entry(&negative).map(|entry| entry.entry),
            None,
            "negative member={}",
            spec.member
        );
        if spec.member == "native-get-web-fetch" {
            assert_eq!(
                spec.positive_instruction,
                "Use WebFetch exactly once with URL exactly https://example.com/ and method exactly GET"
            );
            assert_eq!(
                serde_json::from_str::<Value>(
                    spec.positive_request_json
                        .expect("WebFetch positive carries request JSON")
                )
                .expect("WebFetch positive request parses"),
                json!({"url": "https://example.com/"})
            );
            assert_eq!(
                spec.negative_instruction,
                "Use WebFetch exactly once with URL exactly https://triage:TRIAGE_NEGATIVE_SENTINEL@example.com/ and method exactly GET"
            );
            assert_eq!(
                serde_json::from_str::<Value>(
                    spec.negative_request_json
                        .expect("WebFetch negative carries request JSON")
                )
                .expect("WebFetch negative request parses"),
                json!({"url": "https://triage:TRIAGE_NEGATIVE_SENTINEL@example.com/"})
            );
        }
    }
}

/// ´test:crate:preexisting-deny-classifier-grades-authority-not-hook-order´
#[test]
fn preexisting_deny_classifier_grades_authority_not_hook_order() {
    let command = preexisting_deny_command();
    let consulted = audit(&[("PreToolUse", command)]);
    let denial = vec![json!({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })];
    assert_eq!(
        classify_preexisting_deny_evidence(&consulted, false, &denial, command),
        "expected-result"
    );
    assert!(hook_was_consulted(&consulted));
    assert_eq!(
        classify_preexisting_deny_evidence(&consulted, true, &denial, command),
        "preexisting-deny-bypassed"
    );
    let post = audit(&[("PreToolUse", command), ("PostToolUse", command)]);
    assert_eq!(
        classify_preexisting_deny_evidence(&post, false, &denial, command),
        "preexisting-deny-bypassed"
    );
    assert_eq!(
        classify_preexisting_deny_evidence(&consulted, false, &[], command),
        "preexisting-deny-bypassed"
    );
    let changed = vec![json!({
        "tool_name": "Bash",
        "tool_input": {"command": "negative-twin TRIAGE_CHANGED_SENTINEL"},
    })];
    assert_eq!(
        classify_preexisting_deny_evidence(&consulted, false, &changed, command),
        "changed-command"
    );
    assert_eq!(
        classify_preexisting_deny_evidence(
            &consulted,
            false,
            &[denial[0].clone(), denial[0].clone()],
            command,
        ),
        "multiple-denials"
    );
}

/// ´test:crate:only-a-recorded-permission-request-is-prompt-evidence´
#[test]
fn only_a_recorded_permission_request_is_prompt_evidence() {
    let denial = vec![json!({
        "tool_name": "Bash",
        "tool_input": {"command": TOPOLOGY_COMMAND},
    })];
    let refused = audit(&[("PreToolUse", TOPOLOGY_COMMAND)]);
    assert!(!prompt_requested(&refused));
    assert_eq!(
        classify_topology_evidence(&evidence(&refused, false, &denial)),
        ("refused", "denial-observed"),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE topology-refusal-is-not-a-prompt"
    );
    let requested = audit(&[
        ("PreToolUse", TOPOLOGY_COMMAND),
        ("PermissionRequest", TOPOLOGY_COMMAND),
    ]);
    assert!(prompt_requested(&requested));
    assert_eq!(
        classify_topology_evidence(&evidence(&requested, false, &denial)),
        ("invalid", "prompt"),
        "\ntest result: PROMPT-EVIDENCE-FAIL-BEFORE topology-permission-request-is-a-prompt"
    );
}

/// ´test:crate:preexisting-deny-distinguishes-the-denial-tool-from-its-command´
#[test]
fn preexisting_deny_distinguishes_the_denial_tool_from_its_command() {
    let command = preexisting_deny_command();
    let consulted = audit(&[("PreToolUse", command)]);
    let denial = vec![json!({
        "tool_name": "Read",
        "tool_input": {"command": command},
    })];
    assert_eq!(
        classify_preexisting_deny_evidence(&consulted, false, &denial, command),
        "denial-tool-mismatch",
        "\ntest result: CORRECTION-FAIL-BEFORE denial-tool-mismatch"
    );
}

/// ´test:crate:preexisting-deny-tool-failure-retains-bypass-reason´
#[test]
fn preexisting_deny_tool_failure_retains_bypass_reason() {
    let command = preexisting_deny_command();
    let failed = audit(&[("PreToolUse", command), ("PostToolUseFailure", command)]);
    let denial = vec![json!({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })];
    assert_eq!(
        classify_preexisting_deny_evidence(&failed, false, &denial, command),
        "preexisting-deny-bypassed",
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE deny-row-tool-failure-precedence"
    );
}

/// ´test:crate:table-tool-failure-is-invalid-not-execution-evidence´
#[test]
fn table_tool_failure_is_invalid_not_execution_evidence() {
    let failed = audit(&[
        ("PreToolUse", TOPOLOGY_COMMAND),
        ("PostToolUseFailure", TOPOLOGY_COMMAND),
    ]);
    let tool_outcome = table_tool_outcome(&failed, "Bash", 0);
    assert_eq!(tool_outcome, TableToolOutcome::Failed);
    assert_eq!(
        classify_table_positive(
            false,
            TablePositiveEvidence {
                reason_matches: false,
                capture_observed: true,
                lifecycle_executed: false,
                tool_outcome,
            },
        ),
        ("invalid", "tool-failure")
    );
}

/// ´test:crate:table-negative-tool-failure-grades-only-the-capture´
#[test]
fn table_negative_tool_failure_grades_only_the_capture() {
    assert_eq!(
        classify_table_negative(true, TableToolOutcome::Failed),
        ("pass", "model-capture-observed")
    );
    assert_eq!(
        classify_table_negative(false, TableToolOutcome::Failed),
        ("fail", "model-capture-absent")
    );
}

/// ´test:crate:real-hook-tool-failure-grades-the-expected-decision´
#[test]
fn real_hook_tool_failure_grades_the_expected_decision() {
    assert_eq!(
        classify_real_hook_tool_failure("allow", true),
        Some("tool-failure")
    );
    assert_eq!(
        classify_real_hook_tool_failure("deny", true),
        Some("tool-invoked-despite-deny")
    );
}

/// ´test:crate:any-invalid-table-repetition-invalidates-and-blocks-the-member´
#[test]
fn any_invalid_table_repetition_invalidates_and_blocks_the_member() {
    let summary = classify_table_member(
        "native-get-web-fetch",
        false,
        &[
            "candidate".to_owned(),
            "invalid".to_owned(),
            "candidate".to_owned(),
        ],
        &["pass".to_owned(), "pass".to_owned(), "pass".to_owned()],
    );
    assert_eq!(summary.positive, "invalid");
    assert_eq!(summary.negative, "pass");
    assert_eq!(summary.classification, "invalid");
    assert_eq!(
        summary.blocking_reason.as_deref(),
        Some("table-confirmation:native-get-web-fetch:invalid")
    );
}

/// ´test:crate:all-written-settings-register-the-tool-failure-audit-hook´
#[test]
fn all_written_settings_register_the_tool_failure_audit_hook() {
    for real_hook in [false, true] {
        let settings = settings_fixture(real_hook);
        let hooks = settings["hooks"].as_object().expect("hooks are an object");
        assert_eq!(hooks.len(), 5);
        assert_eq!(
            hooks["PostToolUseFailure"][0]["hooks"][0]["command"],
            "\"$PERMISSION_TRIAGE_FIXTURE_ROOT/bin/audit-hook\" audit"
        );
    }
}

/// ´test:crate:topology-settings-have-five-registrations´
#[test]
fn topology_settings_have_five_registrations() {
    let settings = settings_fixture(false);
    assert_eq!(
        settings["hooks"]
            .as_object()
            .expect("hooks are an object")
            .len(),
        5,
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE topology-registration-count"
    );
}

/// ´test:crate:topology-settings-pretool-first-hook-allows´
#[test]
fn topology_settings_pretool_first_hook_allows() {
    let settings = settings_fixture(false);
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "\"$PERMISSION_TRIAGE_FIXTURE_ROOT/bin/audit-hook\" allow",
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE topology-pretool-allow"
    );
}

/// ´test:crate:topology-settings-lifecycle-hooks-audit´
#[test]
fn topology_settings_lifecycle_hooks_audit() {
    let settings = settings_fixture(false);
    for event in [
        "PostToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUseFailure",
    ] {
        assert_eq!(
            settings["hooks"][event][0]["hooks"][0]["command"],
            "\"$PERMISSION_TRIAGE_FIXTURE_ROOT/bin/audit-hook\" audit",
            "\ntest result: SECOND-CORRECTION-FAIL-BEFORE topology-lifecycle-audit event={event}"
        );
    }
}

/// ´test:crate:topology-settings-permissions-are-empty´
#[test]
fn topology_settings_permissions_are_empty() {
    let settings = settings_fixture(false);
    assert_eq!(
        settings["permissions"],
        json!({}),
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE topology-permissions-empty"
    );
}

/// ´test:crate:deny-row-settings-name-only-negative-twin-rules´
#[test]
fn deny_row_settings_name_only_negative_twin_rules() {
    let command = preexisting_deny_command();
    let settings = preexisting_deny_settings_fixture(command);
    // `UNMATCHED_DENY_COMMAND` is private production data; only the row command has a test accessor.
    let unmatched_rule = "Bash(negative-twin TRIAGE_UNMATCHED_SENTINEL)";
    assert_eq!(
        settings["permissions"],
        json!({
            "deny": [
                unmatched_rule,
                format!("Bash({command})"),
            ],
        }),
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE deny-row-negative-twins"
    );
}

/// ´test:crate:deny-row-settings-do-not-match-a-topology-prefix´
#[test]
fn deny_row_settings_do_not_match_a_topology_prefix() {
    let settings = preexisting_deny_settings_fixture(preexisting_deny_command());
    assert_eq!(
        topology_prefix_matching_rule(&settings["permissions"]),
        None,
        "\ntest result: SECOND-CORRECTION-FAIL-BEFORE deny-row-sentinel-prefix"
    );
}

/// ´test:crate:all-matching-deny-rule-matches-the-empty-topology-prefix´
#[test]
fn all_matching_deny_rule_matches_the_empty_topology_prefix() {
    let permissions = json!({"deny": ["Bash(*)"]});
    assert_eq!(
        topology_prefix_matching_rule(&permissions),
        Some("Bash(*)"),
        "\ntest result: BACKLOG-74-FAIL-BEFORE all-matching-deny-rule"
    );
}

fn topology_prefix_matching_rule(permissions: &Value) -> Option<&str> {
    let prefixes = TOPOLOGY_COMMAND
        .char_indices()
        .map(|(end, _value)| &TOPOLOGY_COMMAND[..end])
        .chain(std::iter::once(TOPOLOGY_COMMAND))
        .collect::<Vec<_>>();
    for rules in permissions
        .as_object()
        .expect("permissions are an object")
        .values()
    {
        for rule in rules.as_array().expect("permission rules are arrays") {
            let rule = rule.as_str().expect("permission rule is a string");
            if rule == "Bash" {
                return Some(rule);
            }
            let Some(pattern) = rule
                .strip_prefix("Bash(")
                .and_then(|pattern| pattern.strip_suffix(')'))
            else {
                continue;
            };
            let literal = pattern
                .strip_suffix(":*")
                .or_else(|| pattern.strip_suffix('*'))
                .unwrap_or(pattern);
            if prefixes.contains(&literal) {
                return Some(rule);
            }
        }
    }
    None
}

/// ´test:crate:progress-identifies-mode-without-changing-the-start-contract´
#[test]
fn progress_identifies_mode_without_changing_the_start_contract() {
    assert!(trial_progress_fixture().starts_with(
        "trial phase=table-confirmation mode=auto name=native-get-web-fetch polarity=positive"
    ));
    assert_eq!(planned_trial_count(), 345);
    assert_eq!(
        start_progress_fixture(),
        format!(
            "start fixture_root=/fixture harness=/harness ceiling_ms=120000 planned_trials={} topology_trials=6 table_confirmation_trials=132 real_hook_trials=42",
            planned_trial_count()
        )
    );
}

/// ´test:crate:topology-verdict-classifies-synthetic-audit-lifecycles´
#[test]
fn topology_verdict_classifies_synthetic_audit_lifecycles() {
    let empty_denials = Vec::new();
    let executed = audit(&[
        ("PreToolUse", TOPOLOGY_COMMAND),
        ("PostToolUse", TOPOLOGY_COMMAND),
    ]);
    assert_eq!(
        classify_topology_evidence(&evidence(&executed, true, &empty_denials)),
        ("executed", "execution-observed")
    );

    let refused = audit(&[("PreToolUse", TOPOLOGY_COMMAND)]);
    let denials = vec![json!({
        "tool_name": "Bash",
        "tool_input": {"command": TOPOLOGY_COMMAND},
    })];
    assert_eq!(
        classify_topology_evidence(&evidence(&refused, false, &denials)),
        ("refused", "denial-observed")
    );

    assert_eq!(
        classify_topology_evidence(&evidence(&[], false, &empty_denials)),
        ("never-called", "no-command-proposed")
    );
    assert_eq!(
        classify_topology_evidence(&evidence(&executed, true, &denials)),
        ("invalid", "evidence-mismatch")
    );
}

/// ´test:crate:topology-tool-failure-is-a-named-invalid-trial´
#[test]
fn topology_tool_failure_is_a_named_invalid_trial() {
    let empty_denials = Vec::new();
    let failed = audit(&[
        ("PreToolUse", TOPOLOGY_COMMAND),
        ("PostToolUseFailure", TOPOLOGY_COMMAND),
    ]);
    assert_eq!(
        classify_topology_evidence(&evidence(&failed, false, &empty_denials)),
        ("invalid", "tool-failure"),
        "\ntest result: CORRECTION-FAIL-BEFORE topology-tool-failure"
    );
}

/// ´test:crate:topology-argv-is-pinned-byte-for-byte´
#[test]
fn topology_argv_is_pinned_byte_for_byte() {
    let settings = Path::new("/fixture/settings.json");
    assert_eq!(
        harness_result_arguments(
            settings,
            "Bash",
            "manual",
            "Use Bash exactly once with the exact command: triage-sentinel TRIAGE_AUTO_SENTINEL",
        ),
        vec![
            OsString::from("--print"),
            OsString::from("--no-session-persistence"),
            OsString::from("--output-format"),
            OsString::from("json"),
            OsString::from("--setting-sources"),
            OsString::from("project"),
            OsString::from("--settings"),
            OsString::from("/fixture/settings.json"),
            OsString::from("--tools"),
            OsString::from("Bash"),
            OsString::from("--permission-mode"),
            OsString::from("manual"),
            OsString::from(
                "Use Bash exactly once with the exact command: triage-sentinel TRIAGE_AUTO_SENTINEL",
            ),
        ]
    );
}

/// ´test:crate:bypass-argv-is-explicit-and-pinned-byte-for-byte´
#[test]
fn bypass_argv_is_explicit_and_pinned_byte_for_byte() {
    let arguments = harness_result_arguments(
        Path::new("/fixture/settings.json"),
        "Bash",
        "bypass",
        crate::topology::TOPOLOGY_INSTRUCTION,
    );
    let expected = [
        "--print",
        "--no-session-persistence",
        "--output-format",
        "json",
        "--setting-sources",
        "project",
        "--settings",
        "/fixture/settings.json",
        "--tools",
        "Bash",
        "--permission-mode",
        "bypassPermissions",
        crate::topology::TOPOLOGY_INSTRUCTION,
    ];
    assert_eq!(arguments, expected.map(OsString::from));
}

/// ´test:crate:topology-three-repetition-rule-blocks-mixed-results´
#[test]
fn topology_three_repetition_rule_blocks_mixed_results() {
    let manual = vec!["executed".to_owned(); 3];
    let mixed = vec![
        "executed".to_owned(),
        "refused".to_owned(),
        "executed".to_owned(),
    ];
    assert_eq!(
        select_topology(&manual, &mixed),
        ("blocked", Some("topology:mixed-result".to_owned()))
    );
    assert_eq!(
        select_topology(&manual, &vec!["refused".to_owned(); 3]),
        ("manual", None)
    );
    assert_eq!(
        select_topology(&manual, &vec!["executed".to_owned(); 3]),
        ("auto", None)
    );
    assert_eq!(
        select_topology(
            &vec!["legacy-manual".to_owned(); 3],
            &vec!["legacy-auto".to_owned(); 3]
        ),
        ("blocked", Some("topology:manual-failed".to_owned()))
    );
}

/// ´test:crate:topology-version-gate-requires-pin-or-exact-override´
#[test]
fn topology_version_gate_requires_pin_or_exact_override() {
    assert!(version_supported(SUPPORTED_HARNESS_VERSION, None));
    assert!(!version_supported("9.9.9", None));
    assert!(version_supported("9.9.9", Some(OsStr::new("9.9.9"))));
    assert!(!version_supported(
        "9.9.9",
        Some(OsStr::new(SUPPORTED_HARNESS_VERSION))
    ));
}

/// ´test:crate:topology-harness-provenance-kind-honors-version-override´
#[test]
fn topology_harness_provenance_kind_honors_version_override() {
    let allowed = harness_provenance_fixture_value("9.9.9", Some(OsStr::new("9.9.9")));
    assert_eq!(allowed["kind"], "real");
    let unsupported = harness_provenance_fixture_value("9.9.9", None);
    assert_eq!(unsupported["kind"], "unsupported");
}

/// ´test:crate:topology-version-token-requires-exact-boundaries´
#[test]
fn topology_version_token_requires_exact_boundaries() {
    for accepted in ["2.1.258", "v2.1.258", "2.1.258 (Claude Code)"] {
        assert_eq!(
            extract_harness_version(accepted.as_bytes()).as_deref(),
            Some(SUPPORTED_HARNESS_VERSION),
            "accepted={accepted}"
        );
    }
    for rejected in [
        "2.1.258-rc",
        "v2.1.258+build9",
        "2.1.2580",
        "02.1.258",
        "2.1.258-rc (2.1.258)",
        "2.1.258 (9.9.9)",
    ] {
        assert!(
            extract_harness_version(rejected.as_bytes())
                .as_deref()
                .is_none_or(|actual| !version_supported(actual, None)),
            "rejected={rejected}"
        );
    }
    assert_eq!(
        extract_harness_version(b"2.1.258 (2.1.258)").as_deref(),
        Some(SUPPORTED_HARNESS_VERSION)
    );
}

/// ´test:crate:topology-version-consensus-counts-a-two-part-token´
#[test]
fn topology_version_consensus_counts_a_two_part_token() {
    for disagreement in [
        "2.1.258 (2.1)",
        "2.1 2.1.258",
        "2.1",
        "v2.1 (2.1.258)",
        "2.1.258 9.9",
    ] {
        assert_eq!(
            extract_harness_version(disagreement.as_bytes()),
            None,
            "disagreement={disagreement}"
        );
    }
    assert_eq!(
        extract_harness_version(b"2.1.258 (Claude Code)").as_deref(),
        Some(SUPPORTED_HARNESS_VERSION)
    );
}

/// ´test:crate:topology-readme-pins-environment-pass-through-and-numeric-override´
#[test]
fn topology_readme_pins_environment_pass_through_and_numeric_override() {
    let readme = include_str!("../../README.md");
    assert!(readme.contains("nonnumeric or suffixed versions cannot be overridden"));
    assert!(readme.contains(
        "`PERMISSION_TRIAGE_HARNESS_BIN`, `PERMISSION_TRIAGE_HARNESS_ALLOW_VERSION`, and `PERMISSION_TRIAGE_TOPOLOGY_CEILING_MS` values pass through to the child"
    ));
}

/// ´test:crate:topology-table-confirmation-distinguishes-accepted-and-candidate-rows´
#[test]
fn topology_table_confirmation_distinguishes_accepted_and_candidate_rows() {
    assert_eq!(
        classify_table_positive(
            true,
            TablePositiveEvidence {
                reason_matches: true,
                capture_observed: false,
                lifecycle_executed: true,
                tool_outcome: TableToolOutcome::NoFailure,
            },
        ),
        ("pass", "accepted-entry-criterion-met")
    );
    assert_eq!(
        classify_table_positive(
            true,
            TablePositiveEvidence {
                reason_matches: true,
                capture_observed: true,
                lifecycle_executed: true,
                tool_outcome: TableToolOutcome::NoFailure,
            },
        ),
        ("fail", "unexpected-model-capture")
    );
    assert_eq!(
        classify_table_positive(
            false,
            TablePositiveEvidence {
                reason_matches: false,
                capture_observed: true,
                lifecycle_executed: true,
                tool_outcome: TableToolOutcome::NoFailure,
            },
        ),
        ("candidate", "disabled-entry-routed-to-model")
    );
    assert_eq!(
        classify_table_positive(
            false,
            TablePositiveEvidence {
                reason_matches: false,
                capture_observed: false,
                lifecycle_executed: true,
                tool_outcome: TableToolOutcome::NoFailure,
            },
        ),
        ("fail", "disabled-entry-capture-absent")
    );
}

/// ´test:crate:only-the-settings-deny-row-does-not-grade-the-hook-reason´
#[test]
fn only_the_settings_deny_row_does_not_grade_the_hook_reason() {
    let rows = real_hook_expectations();
    assert_eq!(rows.len(), 14);
    for (row, _command, harness_denied, expected) in rows {
        assert_eq!(
            expected.is_none(),
            harness_denied,
            "row={row}: only the settings-authority row leaves the observed hook reason ungraded"
        );
        if let Some(expected) = expected {
            assert!(!expected.is_empty(), "row={row}");
        }
    }
}
