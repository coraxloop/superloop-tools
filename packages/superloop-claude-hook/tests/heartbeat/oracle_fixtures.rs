use serde_json::Value;

const PYTHON_SUITE: &str = include_str!("fixtures/expected/python-reference-suite.stdout");
const PYTHON_STATUS: &str = include_str!("fixtures/expected/python-reference-suite.status");

/// ´test:integration:captured-python-suite-contains-all-26-named-scenarios´
#[test]
fn captured_python_suite_contains_all_26_named_scenarios() {
    for number in 1..=26 {
        assert!(
            PYTHON_SUITE.contains(&format!("P{number}")),
            "missing Python scenario P{number}"
        );
    }
    assert!(PYTHON_SUITE.contains("20/26 paths verified"));
    assert_eq!(PYTHON_SUITE.matches("FAIL P").count(), 6);
    assert_eq!(PYTHON_STATUS, "1\n");
}

/// ´test:integration:every-specification-divergence-fixture-names-its-warrant´
#[test]
fn every_specification_divergence_fixture_names_its_warrant() {
    for fixture in [
        include_str!("fixtures/expected/spec-block-stderr.json"),
        include_str!("fixtures/expected/spec-invalid-field-fail-open.json"),
        include_str!("fixtures/expected/spec-unreadable-state-fail-open.json"),
        include_str!("fixtures/expected/spec-state-write-fail-open.json"),
        include_str!("fixtures/expected/spec-nonnumeric-delay.json"),
        include_str!("fixtures/expected/spec-list-feedback-turn-marker.json"),
    ] {
        let value: Value = serde_json::from_str(fixture).expect("valid divergence fixture JSON");
        assert!(value["fixture"].as_str().is_some());
        assert!(value["spec"].as_str().is_some());
        assert!(value["python"].is_object());
        assert!(value["specified"].is_object());
    }
}
