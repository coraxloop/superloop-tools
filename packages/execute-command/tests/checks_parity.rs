//! Caller fixtures copied at 074c78c; only observation construction is adapted.

mod support;

use execute_command::checks;
use execute_command::request::{Judgement, LearnedGroup, MatchEvaluation, MatchKey, Rung, Text};
use serde_json::json;

fn text(value: &str) -> Text {
    value.to_owned().try_into().unwrap()
}

/// ´test:integration:hygiene-retains-observed-scope´
#[test]
fn hygiene_retains_observed_scope() {
    use execute_command::request::HygieneObservation;
    let request = support::request("rm -rf /", "/project");
    let observation = HygieneObservation::Shell {
        timeout_ms: None,
        declared_background: None,
    };
    for scope in ["loop", "estate"] {
        let verdict = checks::hygiene(&request, &observation, scope)
            .unwrap()
            .unwrap();
        assert_eq!(verdict.scope.as_str(), scope);
        assert_eq!(
            checks::malformed_correction(&request, &text("revise"), scope)
                .unwrap()
                .scope
                .as_str(),
            scope
        );
    }
}

/// Non-UTF-8 shell bytes have no inherited caller rule and remain a miss.
/// ´test:integration:non-utf8-shell-observation-is-a-miss´
#[test]
fn non_utf8_shell_observation_is_a_miss() {
    use execute_command::request::{HygieneObservation, Request};

    let mut wire = serde_json::to_value(support::request("fixture", "/project")).unwrap();
    wire["command"]["bytes"] = json!([255]);
    let request = Request::from_json(&serde_json::to_vec(&wire).unwrap()).unwrap();
    let observation = HygieneObservation::Shell {
        timeout_ms: None,
        declared_background: None,
    };
    assert_eq!(
        checks::hygiene(&request, &observation, "estate").unwrap(),
        None
    );
}

/// ´test:integration:registered-exact-rubric´
#[test]
fn registered_exact_rubric() {
    use execute_command::request::ExactRule;
    // the door mode fixture fixture_rubric_states_allow_refuse_and_undecided_reasons.
    let request = support::request("fixture", "/project");
    let rules = [
        ExactRule {
            key: MatchKey {
                class: text("fixture"),
                operation: text("read"),
                shape_key: text("shape:read"),
            },
            allow: true,
            reason: text("fixture read"),
        },
        ExactRule {
            key: MatchKey {
                class: text("fixture"),
                operation: text("write"),
                shape_key: text("shape:write"),
            },
            allow: false,
            reason: text("fixture write"),
        },
    ];
    for (class, operation, shape, decision, reason) in [
        ("fixture", "read", "shape:read", "allow", "fixture read"),
        ("fixture", "write", "shape:write", "refuse", "fixture write"),
        (
            "fixture",
            "other",
            "shape:other",
            "undecided",
            "no exact fixture rule",
        ),
        (
            "another",
            "read",
            "shape:read",
            "undecided",
            "no exact fixture rule",
        ),
    ] {
        let key = MatchKey {
            class: text(class),
            operation: text(operation),
            shape_key: text(shape),
        };
        match checks::registered_exact_match(&request, &key, &rules, &text("no exact fixture rule"))
            .unwrap()
        {
            MatchEvaluation::Undecided { reason: actual } => {
                assert_eq!(decision, "undecided");
                assert_eq!(actual.as_str(), reason);
            }
            MatchEvaluation::Decided(verdict) => {
                verdict.validate().unwrap();
                let value = serde_json::to_value(verdict).unwrap();
                assert_eq!(value["judgement"], decision);
                assert_eq!(value["reason"], reason);
                assert_eq!(value["correction"].is_null(), decision == "allow");
                assert!(value.get("escalation").unwrap().is_null());
            }
        }
    }
}
fn key() -> MatchKey {
    MatchKey {
        class: text("git"),
        operation: text("git-upload"),
        shape_key: text("git:upload"),
    }
}

/// ´test:integration:learned-retired-agreement-conflict-and-exact-keys´
#[test]
fn learned_retired_agreement_conflict_and_exact_keys() {
    // the door store fixture learned_rubric_keeps_retired_conflicts_and_citations:
    // R:1a allow/read-only; S:2b refuse/conflicting evidence remains after retirement.
    // The (0 allow, 1 refuse) row comes from
    // learned_index_status_and_rebuild_retain_retired_labels (store lines 2439-2444).
    // The decided enforce refusal name comes from the door module, lines 1103-1104
    // at 074c78c, where both learned and registered decisions share the refusal.
    let request = support::request("git push", "/project");
    for (allow, refuse, citations, expected, reason) in [
        (
            0,
            0,
            vec![],
            "undecided",
            "no adjudicated label for this shape",
        ),
        (
            1,
            0,
            vec!["R:1a"],
            "allow",
            "applicable adjudicated labels agree",
        ),
        (
            1,
            1,
            vec!["R:1a", "S:2b"],
            "undecided",
            "adjudicated labels conflict",
        ),
        (
            0,
            1,
            vec!["S:2b"],
            "refuse",
            "applicable adjudicated labels agree",
        ),
    ] {
        let group = LearnedGroup {
            key: key(),
            allow,
            refuse,
            citations: citations
                .iter()
                .map(|id| text(id))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };
        let actual = checks::learned_exact_match(&request, &key(), Some(&group)).unwrap();
        match actual {
            MatchEvaluation::Undecided { reason: actual } => {
                assert_eq!(expected, "undecided");
                assert_eq!(actual.as_str(), reason);
            }
            MatchEvaluation::Decided(verdict) => {
                verdict.validate().unwrap();
                assert_eq!(verdict.binding, *request.binding());
                assert_eq!(verdict.tier, Rung::LearnedExactMatch);
                let value = serde_json::to_value(&verdict).unwrap();
                assert_eq!(value["judgement"], expected);
                assert_eq!(value["reason"], reason);
                assert_eq!(value["evidence"], json!(citations));
                assert!(value.get("correction").is_some());
                assert!(value.get("escalation").is_some());
                assert!(value["escalation"].is_null());
                assert_eq!(value["correction"].is_null(), expected == "allow");
                if expected == "refuse" {
                    assert_eq!(value["correction"]["rule"], "door-rubric-refusal");
                }
            }
        }
        for other in [
            MatchKey {
                class: text("another"),
                ..key()
            },
            MatchKey {
                operation: text("other"),
                ..key()
            },
            MatchKey {
                shape_key: text("git:upload-other"),
                ..key()
            },
        ] {
            assert_eq!(
                checks::learned_exact_match(&request, &other, Some(&group)).unwrap(),
                MatchEvaluation::Undecided {
                    reason: text("no adjudicated label for this shape")
                }
            );
        }
    }
    assert_eq!(
        checks::learned_exact_match(&request, &key(), None).unwrap(),
        MatchEvaluation::Undecided {
            reason: text("no adjudicated label for this shape")
        }
    );
}

/// ´test:integration:hook-correction-and-scope-floor´
#[test]
fn hook_correction_and_scope_floor() {
    // the permission hook integration fixtures: agent-error/deny/"correction: fixture reason".
    let request = support::request("pwd", "/project");
    let verdict =
        checks::malformed_correction(&request, &text("fixture reason"), "estate").unwrap();
    verdict.validate().unwrap();
    assert_eq!(verdict.judgement, Judgement::Refuse);
    assert_eq!(verdict.tier, Rung::BoundedAgent);
    assert_eq!(
        format!("correction: {}", verdict.reason.as_str()),
        "correction: fixture reason"
    );
    assert_eq!(
        verdict.correction.unwrap().changes.as_str(),
        "fixture reason"
    );
    assert!(verdict.escalation.is_none());
    // A model contradicting the scope floor is invalid output and requires service review.
    for (reports_loop, requires_estate, refused) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
        (false, false, false),
    ] {
        let actual = checks::scope_floor(&request, reports_loop, requires_estate).unwrap();
        assert_eq!(actual.is_some(), refused);
        if let Some(verdict) = actual {
            verdict.validate().unwrap();
            let value = serde_json::to_value(verdict).unwrap();
            assert_eq!(value["judgement"], "refer");
            assert_eq!(value["status"], "invalid-output");
            assert_eq!(
                value["reason"],
                "loop scope contradicts a protected target or unresolved identity/effect"
            );
            assert!(value["correction"].is_null());
            assert_eq!(value["escalation"]["route"], "unprovisioned:operations");
        }
    }
}

/// ´test:integration:door-malformed-correction-refusals´
#[test]
fn door_malformed_correction_refusals() {
    use execute_command::request::LabelObservation;
    // the door store fixture mode_citations_refuse_every_non_agreeing_source and
    // mode_refusals_leave_protected_history_unchanged, copied before extraction.
    let request = support::request("mode correct fixture", "/project");
    for (id, class, adjudicated, would_do, treatment, expected) in [
        ("R:1a", "fixture", false, Some(Judgement::Allow), None, true),
        (
            "R:2b",
            "fixture",
            true,
            Some(Judgement::Refuse),
            Some(Judgement::Allow),
            false,
        ),
        ("R:3c", "fixture", true, None, Some(Judgement::Allow), true),
        (
            "S:4d",
            "other",
            true,
            Some(Judgement::Allow),
            Some(Judgement::Allow),
            true,
        ),
        (
            "R:5e",
            "fixture",
            true,
            Some(Judgement::Allow),
            Some(Judgement::Allow),
            true,
        ),
    ] {
        let label = LabelObservation {
            id: text(id),
            class: text(class),
            adjudicated,
            would_do,
            treatment,
        };
        let verdict =
            checks::correction_evidence(&request, &text("fixture"), &text(id), Some(&label))
                .unwrap();
        assert_eq!(verdict.is_some(), expected, "{id}");
        if let Some(verdict) = verdict {
            verdict.validate().unwrap();
            assert_eq!(verdict.judgement, Judgement::Refuse);
            assert_eq!(
                verdict.reason.as_str(),
                "request is not a rubric correction for this class"
            );
            assert_eq!(
                verdict.correction.unwrap().rule.as_str(),
                "door-mode-evidence-refusal"
            );
            assert!(verdict.escalation.is_none());
        }
    }
    let missing = checks::correction_evidence(&request, &text("fixture"), &text("R:ff"), None)
        .unwrap()
        .unwrap();
    assert_eq!(missing.reason.as_str(), "correction request is absent");
    assert_eq!(
        missing.correction.unwrap().rule.as_str(),
        "door-mode-evidence-refusal"
    );
}
