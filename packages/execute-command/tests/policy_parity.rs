//! Pure observations and expected outcomes copied from the door and gateway
//! fixtures at 074c78c; caller storage, clocks and execution are not linked.

mod support;

use execute_command::policy::{self, DoorMode, RunAdmission, SettingEvidence};
use execute_command::request::{Judgement, LabelObservation, Text, TextList, Verdict};
use serde_json::json;

fn text(value: &str) -> Text {
    value.to_owned().try_into().unwrap()
}
fn citations(ids: &[&str]) -> TextList {
    ids.iter()
        .map(|id| text(id))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn raw_citations(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

fn assert_refusal(verdict: &Verdict, rule: &str, reason: &str) {
    verdict.validate().unwrap();
    let value = serde_json::to_value(verdict).unwrap();
    assert_eq!(value["judgement"], "refuse");
    assert_eq!(value["reason"], reason);
    assert_eq!(value["correction"]["rule"], rule);
    assert!(
        value["correction"]["changes"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(
        value["correction"]["revalidation"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(value.get("escalation").unwrap().is_null());
}

/// ´test:integration:door-floor-and-effective-mode-parity´
#[test]
fn door_floor_and_effective_mode_parity() {
    use DoorMode::{Allow, Audit, Enforce};
    let request = support::request("mode set", "/project");
    // Door first_setting_evidence_and_below_floor_refusal, completed across all floors.
    for (floor, accepted) in [
        (Audit, [true, false, false]),
        (Enforce, [true, true, false]),
        (Allow, [true, true, true]),
    ] {
        for (mode, accepted) in [Audit, Enforce, Allow].into_iter().zip(accepted) {
            let result = policy::mode_floor(&request, mode, floor).unwrap();
            assert_eq!(result.is_none(), accepted);
            if let Some(verdict) = result {
                assert_refusal(
                    &verdict,
                    "door-mode-floor-refusal",
                    "setting is less strict than the registry floor",
                );
            }
        }
    }
    // Door effective: class, loop and current row floor are all upper bounds.
    for (floor, expected) in [
        (
            Audit,
            [
                Audit, Audit, Audit, Audit, Audit, Audit, Audit, Audit, Audit,
            ],
        ),
        (
            Enforce,
            [
                Audit, Audit, Audit, Audit, Enforce, Enforce, Audit, Enforce, Enforce,
            ],
        ),
        (
            Allow,
            [
                Audit, Audit, Audit, Audit, Enforce, Enforce, Audit, Enforce, Allow,
            ],
        ),
    ] {
        let pairs = [Audit, Enforce, Allow].into_iter().flat_map(|class| {
            [Audit, Enforce, Allow]
                .into_iter()
                .map(move |loop_mode| (class, loop_mode))
        });
        for ((class, loop_mode), expected) in pairs.zip(expected) {
            assert_eq!(
                policy::effective_mode(class, loop_mode, floor, false),
                expected
            );
            assert_eq!(policy::effective_mode(class, loop_mode, floor, true), Audit);
        }
    }
}

/// ´test:integration:stored-door-mode-never-defaults´
#[test]
fn stored_door_mode_never_defaults() {
    for mode in [DoorMode::Audit, DoorMode::Enforce, DoorMode::Allow] {
        assert_eq!(DoorMode::from_record(Some(mode.as_str())), Ok(mode));
    }
    for mode in [None, Some(""), Some("unknown")] {
        assert_eq!(
            DoorMode::from_record(mode).unwrap_err().0,
            "door-mode-record-refusal"
        );
    }
}

/// ´test:integration:floor-initialization-preserves-existing-settings´
#[test]
fn floor_initialization_preserves_existing_settings() {
    // Door ensure_first_mode supplies the same floor and evidence for loop and class.
    for floor in [DoorMode::Audit, DoorMode::Enforce, DoorMode::Allow] {
        let initial = policy::initial_setting(None, floor).unwrap().unwrap();
        assert_eq!(initial.mode, floor);
        assert_eq!(
            initial.evidence.as_str(),
            format!(
                "row door_floor={} initializes absent setting",
                floor.as_str()
            )
        );
        for prior in [DoorMode::Audit, DoorMode::Enforce, DoorMode::Allow] {
            assert_eq!(policy::initial_setting(Some(prior), floor).unwrap(), None);
        }
        assert_eq!(
            policy::initial_setting(Some(initial.mode), floor).unwrap(),
            None
        );
    }
}

/// ´test:integration:mode-history-transition-parity´
#[test]
fn mode_history_transition_parity() {
    use DoorMode::{Allow, Audit, Enforce};
    let request = support::request("mode set", "/project");
    // mode_history_keeps_first_moves_and_strictest_effective_setting:
    // owner/floor permits fixture; known harmless fixture; correction; agreeing label.
    for (previous, mode, ids, direction) in [
        (None, Enforce, vec![], "first"),
        (None, Allow, vec![], "first"),
        (Some(Allow), Audit, vec![], "stricter"),
        (Some(Audit), Enforce, vec!["R:1a"], "relaxed"),
        (Some(Enforce), Allow, vec!["R:1a"], "relaxed"),
    ] {
        let result =
            policy::mode_transition(&request, previous, mode, Allow, &citations(&ids)).unwrap();
        result.validate().unwrap();
        assert_eq!(result.judgement, Judgement::Allow);
        assert_eq!(result.reason.as_str(), direction);
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["evidence"], json!(ids));
        assert!(value.get("correction").unwrap().is_null());
        assert!(value.get("escalation").unwrap().is_null());
    }
}

/// ´test:integration:mode-history-refusal-parity´
#[test]
fn mode_history_refusal_parity() {
    use DoorMode::{Allow, Audit, Enforce};
    let request = support::request("mode set", "/project");
    // mode_history_refuses_floor_uncited_relaxation_and_changed_shapes, and
    // mode_citations_refuse_every_non_agreeing_source (first with citation).
    for (previous, selected, floor, ids, rule, reason) in [
        (
            Some(Audit),
            Enforce,
            Audit,
            vec![],
            "door-mode-floor-refusal",
            "setting is less strict than the registry floor",
        ),
        (
            Some(Audit),
            Audit,
            Audit,
            vec![],
            "door-mode-setting-refusal",
            "mode is unchanged",
        ),
        (
            Some(Audit),
            Enforce,
            Allow,
            vec![],
            "door-mode-evidence-refusal",
            "relaxation needs adjudicated labels",
        ),
        (
            None,
            Audit,
            Allow,
            vec!["S:4d"],
            "door-mode-evidence-refusal",
            "first setting has no prior label basis",
        ),
    ] {
        assert_refusal(
            &policy::mode_transition(&request, previous, selected, floor, &citations(&ids))
                .unwrap(),
            rule,
            reason,
        );
    }
}

fn labels() -> Vec<LabelObservation> {
    // The door mode_citations_refuse_every_non_agreeing_source fixture.
    [
        ("R:1a", "fixture", false, Some(Judgement::Allow), None),
        (
            "R:2b",
            "fixture",
            true,
            Some(Judgement::Refuse),
            Some(Judgement::Allow),
        ),
        ("R:3c", "fixture", true, None, Some(Judgement::Allow)),
        (
            "R:5e",
            "fixture",
            true,
            Some(Judgement::Allow),
            Some(Judgement::Allow),
        ),
        (
            "S:4d",
            "other",
            true,
            Some(Judgement::Allow),
            Some(Judgement::Allow),
        ),
    ]
    .into_iter()
    .map(
        |(id, class, adjudicated, would_do, treatment)| LabelObservation {
            id: text(id),
            class: text(class),
            adjudicated,
            would_do,
            treatment,
        },
    )
    .collect()
}

/// ´test:integration:mode-citation-evidence-parity´
#[test]
fn mode_citation_evidence_parity() {
    let request = support::request("mode set", "/project");
    let labels = labels();
    let class = text("fixture");
    for id in ["R:1a", "R:2b", "R:3c", "S:4d"] {
        let result =
            policy::citation_evidence(&request, Some(&class), &raw_citations(&[id]), &labels, true)
                .unwrap()
                .unwrap();
        assert_refusal(
            &result,
            "door-mode-evidence-refusal",
            "cited request is not an agreeing label for this setting",
        );
    }
    for (ids, reason) in [
        (vec!["R:5e"; 33], "citation list exceeds limit"),
        (vec!["R:ff"], "cited request is absent"),
        (vec![""], "cited request is absent"),
        (vec![" "], "cited request is absent"),
        (
            vec!["R:5e", "R:5e"],
            "cited request is not an agreeing label for this setting",
        ),
    ] {
        assert_refusal(
            &policy::citation_evidence(&request, Some(&class), &raw_citations(&ids), &labels, true)
                .unwrap()
                .unwrap(),
            "door-mode-evidence-refusal",
            reason,
        );
    }
    assert!(
        policy::citation_evidence(
            &request,
            Some(&class),
            &raw_citations(&["R:5e"]),
            &labels,
            true
        )
        .unwrap()
        .is_none()
    );
    assert!(
        policy::citation_evidence(&request, None, &raw_citations(&["S:4d"]), &labels, true)
            .unwrap()
            .is_none()
    );
    assert!(
        policy::citation_evidence(
            &request,
            Some(&class),
            &raw_citations(&["R:2b"]),
            &labels,
            false
        )
        .unwrap()
        .is_none()
    );
}

/// ´test:integration:mode-setting-evidence-bounds-parity´
#[test]
fn mode_setting_evidence_bounds_parity() {
    let request = support::request("mode set", "/project");
    let none: Vec<String> = Vec::new();
    let valid = SettingEvidence {
        setter: "owner",
        evidence: "row evidence",
        set_at: "1",
        revision: 1,
        citations: &none,
    };
    assert!(
        policy::setting_evidence(&request, &valid)
            .unwrap()
            .is_none()
    );
    // The existing ModeSetting reader uses nonempty byte lengths, not trim.
    assert!(
        policy::setting_evidence(
            &request,
            &SettingEvidence {
                evidence: " ",
                ..valid
            }
        )
        .unwrap()
        .is_none()
    );
    for invalid in [
        SettingEvidence {
            setter: "",
            ..valid
        },
        SettingEvidence {
            evidence: "",
            ..valid
        },
        SettingEvidence {
            set_at: "",
            ..valid
        },
        SettingEvidence {
            revision: 0,
            ..valid
        },
    ] {
        assert_refusal(
            &policy::setting_evidence(&request, &invalid)
                .unwrap()
                .unwrap(),
            "requests-record-refusal",
            "mode setting shape differs",
        );
    }
    for ids in [
        citations(&["R:1a", "R:1a"]),
        citations(&vec!["R:1a"; 33]),
        citations(&[&"x".repeat(161)]),
    ] {
        assert_refusal(
            &policy::setting_evidence(
                &request,
                &SettingEvidence {
                    citations: &ids
                        .as_slice()
                        .iter()
                        .map(|id| id.as_str().to_owned())
                        .collect::<Vec<_>>(),
                    ..valid
                },
            )
            .unwrap()
            .unwrap(),
            "requests-record-refusal",
            "mode setting shape differs",
        );
    }
    for (setter, evidence, set_at) in [
        ("x".repeat(129), "row".into(), "1".into()),
        ("owner".into(), "x".repeat(1025), "1".into()),
        ("owner".into(), "row".into(), "x".repeat(65)),
    ] {
        assert!(
            policy::setting_evidence(
                &request,
                &SettingEvidence {
                    setter: &setter,
                    evidence: &evidence,
                    set_at: &set_at,
                    ..valid
                }
            )
            .unwrap()
            .is_some()
        );
    }
}

/// ´test:integration:gateway-budget-snapshot-cooldown-parity´
#[test]
fn gateway_budget_snapshot_cooldown_parity() {
    let request = support::request("clippy", "/project");
    // run_cap_exhaustion_directs_worker_to_final_verify: two completed runs, cap 2.
    let mut observed = RunAdmission {
        runs: 2,
        run_cap: 2,
        has_snapshot: true,
        last_run_timestamp_ms: None,
        cooldown_seconds: 0,
        now_unix_ms: 60_000,
    };
    let result = policy::gateway_admission(&request, &observed)
        .unwrap()
        .unwrap();
    assert_refusal(
        &result,
        "run_budget_exhausted",
        "registered run cap has been consumed; continue with READY FOR VERIFY",
    );
    assert_eq!(
        serde_json::to_value(result.evidence).unwrap(),
        json!(["run_cap=2", "runs=2"])
    );
    // Before a push, and after a later failed push, the caller supplies no snapshot.
    observed.runs = 0;
    observed.has_snapshot = false;
    assert_refusal(
        &policy::gateway_admission(&request, &observed)
            .unwrap()
            .unwrap(),
        "no_snapshot",
        "run requires a fresh successful mirror snapshot",
    );
    // refuses_run_during_registered_cooldown: cap 20, cooldown 60, one accepted run.
    observed = RunAdmission {
        runs: 1,
        run_cap: 20,
        has_snapshot: true,
        last_run_timestamp_ms: Some(1_000),
        cooldown_seconds: 60,
        now_unix_ms: 1_000,
    };
    assert_refusal(
        &policy::gateway_admission(&request, &observed)
            .unwrap()
            .unwrap(),
        "run_cooldown_active",
        "registered run cooldown has not elapsed",
    );
    observed.now_unix_ms = 60_999;
    assert!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .is_some()
    );
    observed.now_unix_ms = 61_000;
    assert!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .is_none()
    );
}

/// ´test:integration:gateway-precedence-and-saturation´
#[test]
fn gateway_precedence_and_saturation() {
    let request = support::request("clippy", "/project");
    let mut observed = RunAdmission {
        runs: 2,
        run_cap: 2,
        has_snapshot: false,
        last_run_timestamp_ms: Some(100),
        cooldown_seconds: u64::MAX,
        now_unix_ms: 0,
    };
    assert_eq!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .unwrap()
            .correction
            .unwrap()
            .rule
            .as_str(),
        "run_budget_exhausted"
    );
    observed.runs = 1;
    assert_eq!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .unwrap()
            .correction
            .unwrap()
            .rule
            .as_str(),
        "no_snapshot"
    );
    observed.has_snapshot = true;
    assert_eq!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .unwrap()
            .correction
            .unwrap()
            .rule
            .as_str(),
        "run_cooldown_active"
    );
    observed.last_run_timestamp_ms = Some(0);
    observed.now_unix_ms = u64::MAX;
    assert!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .is_none()
    );
    observed.last_run_timestamp_ms = None;
    assert!(
        policy::gateway_admission(&request, &observed)
            .unwrap()
            .is_none()
    );
}
