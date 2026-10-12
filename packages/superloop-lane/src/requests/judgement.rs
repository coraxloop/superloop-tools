//! Schema-four judgement evidence, independent of effect and queue updates.

use crate::door::agent::RunnerOutcome;
use serde_json::{Value, json};

pub const KEYS: [&str; 11] = [
    "decision_tier",
    "would_do_source",
    "matched_rule",
    "agent_verdict",
    "agent_scope",
    "agent_reason",
    "agent_model",
    "agent_configured_model",
    "agent_wall_ms",
    "agent_status",
    "rubric_digest",
];

/// Initialize an intent or mechanically convert historical evidence.
pub fn initialize(record: &mut Value) {
    record["schema"] = json!(4);
    let source = if matches!(
        record["would_do"]["decision"].as_str(),
        Some("allow" | "refuse")
    ) {
        "fast-lane"
    } else {
        "superloop"
    };
    for key in KEYS {
        record[key] = Value::Null;
    }
    record["would_do_source"] = json!(source);
    record["decision_tier"] = json!(if record["label"].is_null() {
        source
    } else {
        "superloop"
    });
}

/// Merge judgement only; concurrent effects and adjudications retain custody.
pub fn apply(
    record: &mut Value,
    result: &RunnerOutcome,
    digest: Option<&str>,
    model: Option<&str>,
) {
    record["would_do_source"] = json!("agent");
    record["decision_tier"] = json!(if record["label"].is_null() {
        "agent"
    } else {
        "superloop"
    });
    record["would_do"] = json!({"decision":result.verdict,"reason":result.reason});
    record["agent_verdict"] = json!(result.verdict);
    record["agent_scope"] = json!(result.scope);
    record["agent_reason"] = json!(result.reason);
    record["agent_model"] = json!(result.model);
    record["agent_configured_model"] = json!(model);
    record["agent_wall_ms"] = json!(result.wall_ms);
    record["agent_status"] = json!(result.status);
    record["rubric_digest"] = json!(digest);
    result.record_runner_fields(record);
    if !record["label"].is_null() {
        record["label"]["would_do"] = record["would_do"].clone();
    }
}

#[must_use]
pub fn valid(record: &Value) -> bool {
    if !crate::door::agent::valid_runner_fields(record) {
        return false;
    }
    if !matches!(
        record["decision_tier"].as_str(),
        Some("fast-lane" | "agent" | "superloop")
    ) || !matches!(
        record["would_do_source"].as_str(),
        Some("fast-lane" | "agent" | "superloop")
    ) {
        return false;
    }
    if (!record["label"].is_null() && record["decision_tier"] != "superloop")
        || (record["label"].is_null() && record["decision_tier"] != record["would_do_source"])
    {
        return false;
    }
    let rule = &record["matched_rule"];
    if !rule.is_null()
        && (!super::exact(rule, &["class", "operation", "shape_key", "request_ids"])
            || rule["class"] != record["class"]
            || rule["operation"] != record["operation"]
            || rule["shape_key"] != record["shape_key"]
            || record["would_do_source"] != "fast-lane"
            || rule["request_ids"].as_array().is_none_or(|ids| {
                ids.is_empty() || ids.len() > 16_384 || ids.iter().any(|id| !super::word(id, 160))
            }))
    {
        return false;
    }
    if record["would_do_source"] != "agent" {
        return record.get("agent_runner_exit").is_none()
            && record.get("agent_runner_stderr_tail").is_none()
            && KEYS[3..].iter().all(|key| record[*key].is_null())
            && match record["would_do_source"].as_str() {
                Some("fast-lane") => matches!(
                    record["would_do"]["decision"].as_str(),
                    Some("allow" | "refuse")
                ),
                Some("superloop") => record["would_do"]["decision"] == "undecided",
                _ => false,
            };
    }
    matches!(
        record["agent_verdict"].as_str(),
        Some("allow" | "refuse" | "refer")
    ) && matches!(record["agent_scope"].as_str(), Some("loop" | "estate"))
        && record["agent_reason"]
            .as_str()
            .is_some_and(|s| !s.trim().is_empty() && s.len() <= 1024)
        && matches!(
            record["agent_status"].as_str(),
            Some("verdict" | "failure" | "invalid-output" | "timeout")
        )
        && (record["agent_status"] == "verdict" || record["agent_verdict"] == "refer")
        && record["agent_wall_ms"].as_u64().is_some()
        && ["agent_model", "agent_configured_model"].iter().all(|key| {
            record[*key].is_null()
                || record[*key]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 256)
        })
        && (record["rubric_digest"].is_null()
            || record["rubric_digest"]
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())))
        && record["would_do"]["decision"] == record["agent_verdict"]
        && record["would_do"]["reason"] == record["agent_reason"]
}

pub(super) fn invalid_field(record: &Value) -> &'static str {
    for key in ["decision_tier", "would_do_source"] {
        if !matches!(
            record[key].as_str(),
            Some("fast-lane" | "agent" | "superloop")
        ) {
            return key;
        }
    }
    if (!record["label"].is_null() && record["decision_tier"] != "superloop")
        || (record["label"].is_null() && record["decision_tier"] != record["would_do_source"])
    {
        return "decision_tier differs from label or would_do_source";
    }
    if !crate::door::agent::valid_runner_fields(record) {
        let mut with_line = record.clone();
        with_line["agent_runner_first_line"] = json!("");
        if crate::door::agent::valid_runner_fields(&with_line) {
            return "agent_runner_first_line";
        }
        let mut without_tail = record.clone();
        if let Some(object) = without_tail.as_object_mut() {
            object.remove("agent_runner_stderr_tail");
        }
        return if crate::door::agent::valid_runner_fields(&without_tail) {
            "agent_runner_stderr_tail"
        } else {
            "agent_runner_exit"
        };
    }
    if record["would_do_source"] != "agent" {
        for key in ["agent_runner_exit", "agent_runner_stderr_tail"] {
            if record.get(key).is_some() {
                return key;
            }
        }
        for key in &KEYS[3..] {
            if !record[*key].is_null() {
                return key;
            }
        }
        return "matched_rule or would_do.decision differs from would_do_source";
    }
    for (key, accepted) in [
        (
            "agent_verdict",
            matches!(
                record["agent_verdict"].as_str(),
                Some("allow" | "refuse" | "refer")
            ),
        ),
        (
            "agent_scope",
            matches!(record["agent_scope"].as_str(), Some("loop" | "estate")),
        ),
        (
            "agent_reason",
            record["agent_reason"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && s.len() <= 1024),
        ),
        (
            "agent_status",
            matches!(
                record["agent_status"].as_str(),
                Some("verdict" | "failure" | "invalid-output" | "timeout")
            ),
        ),
        ("agent_wall_ms", record["agent_wall_ms"].as_u64().is_some()),
    ] {
        if !accepted {
            return key;
        }
    }
    for key in ["agent_model", "agent_configured_model"] {
        if !record[key].is_null()
            && !record[key]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
        {
            return key;
        }
    }
    if !record["rubric_digest"].is_null()
        && !record["rubric_digest"]
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return "rubric_digest";
    }
    if record["agent_status"] != "verdict" && record["agent_verdict"] != "refer" {
        return "agent_verdict differs from agent_status";
    }
    if record["would_do"]["decision"] != record["agent_verdict"] {
        return "would_do.decision differs from agent_verdict";
    }
    if record["would_do"]["reason"] != record["agent_reason"] {
        return "would_do.reason differs from agent_reason";
    }
    "matched_rule"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::{Mode, RequestRecord, tests::waiting};

    /// ´test:unit:agent-runner-first-line-requires-bounded-single-line´
    #[test]
    fn agent_runner_first_line_requires_bounded_single_line() {
        let mut record = waiting("R", "1a", 3000, Mode::Audit).into_value();
        let result = RunnerOutcome::referral("failure", "fixture", std::time::Instant::now());
        apply(&mut record, &result, None, None);
        for line in [
            Value::Null,
            json!(7),
            json!("x".repeat(1025)),
            json!("first\nsecond"),
            json!("first\rsecond"),
        ] {
            record["agent_runner_first_line"] = line;
            assert_eq!(
                RequestRecord::decode(record.clone())
                    .expect_err("invalid first line")
                    .kind,
                "requests-record-refusal"
            );
        }
        record
            .as_object_mut()
            .expect("record")
            .remove("agent_runner_first_line");
        let older = RequestRecord::decode(record.clone()).expect("unrecorded first stderr line");
        assert!(older.value().get("agent_runner_first_line").is_none());
        record["agent_runner_first_line"] = json!("runner refusal");
        RequestRecord::decode(record).expect("bounded first line");
    }

    /// ´test:unit:agent-runner-fields-read-old-records-and-refuse-malformed-evidence´
    #[test]
    fn agent_runner_fields_read_old_records_and_refuse_malformed_evidence() {
        let mut record = waiting("R", "1a", 3000, Mode::Audit).into_value();
        let mut result = RunnerOutcome::referral("failure", "fixture", std::time::Instant::now());
        apply(&mut record, &result, None, None);
        assert_eq!(record.get("agent_runner_exit"), Some(&Value::Null));
        let fields = record.as_object_mut().expect("record");
        fields.remove("agent_runner_exit");
        fields.remove("agent_runner_first_line");
        let old = RequestRecord::decode(record.clone()).expect("older record");
        assert!(old.value().get("agent_runner_first_line").is_none());
        assert!(old.value()["agent_runner_exit"].is_null());
        assert!(old.value().get("agent_runner_stderr_tail").is_none());
        assert!(
            crate::door::agent::valid_runner_fields(&json!({"agent_status":"verdict"})),
            "older exercise observation"
        );
        for exit in [json!({"code":7}), json!({"signal":9}), Value::Null] {
            record["agent_runner_exit"] = exit;
            RequestRecord::decode(record.clone()).expect("observed or absent exit");
        }
        for exit in [
            json!(7),
            json!({}),
            json!({"code":-1}),
            json!({"code":256}),
            json!({"signal":0}),
            json!({"signal":65}),
            json!({"signal":9,"code":1}),
            json!({"code":0,"extra":true}),
            json!({"code":"7"}),
        ] {
            record["agent_runner_exit"] = exit;
            assert_eq!(
                RequestRecord::decode(record.clone())
                    .expect_err("invalid exit")
                    .kind,
                "requests-record-refusal"
            );
        }
        record["agent_runner_exit"] = json!({"code":7});
        for tail in [Value::Null, json!(7), json!("x".repeat(4097))] {
            record["agent_runner_stderr_tail"] = tail;
            assert_eq!(
                RequestRecord::decode(record.clone())
                    .expect_err("invalid tail")
                    .kind,
                "requests-record-refusal"
            );
        }
        record["agent_runner_stderr_tail"] = json!("whole failure");
        RequestRecord::decode(record.clone()).expect("valid failure tail");
        result.status = "verdict".into();
        result.runner_exit = Some(crate::door::agent::RunnerExit::Code(0));
        apply(&mut record, &result, None, None);
        assert!(
            record.get("agent_runner_stderr_tail").is_none(),
            "successful merge removes stale tail"
        );
        RequestRecord::decode(record.clone()).expect("success exit");
        assert_eq!(record["agent_runner_first_line"], "");
        record["agent_runner_first_line"] = json!("stale refusal");
        assert_eq!(
            RequestRecord::decode(record.clone())
                .expect_err("first line on success")
                .kind,
            "requests-record-refusal"
        );
        record["agent_runner_first_line"] = json!("");
        record["agent_runner_stderr_tail"] = json!("");
        assert_eq!(
            RequestRecord::decode(record)
                .expect_err("tail on success")
                .kind,
            "requests-record-refusal"
        );
        result.runner_stderr_tail = Some("invalid success tail".into());
        let exercise = result.exercise_observation(3000, None);
        assert_eq!(exercise["status"], "fail");
        assert_eq!(exercise["reason"], "door-agent-runner-evidence");
        result.runner_stderr_tail = None;
        result.runner_exit = Some(crate::door::agent::RunnerExit::Signal(0));
        assert_eq!(
            result.exercise_observation(3000, None)["reason"],
            "door-agent-runner-evidence"
        );
        let mut non_agent = waiting("R", "1a", 3000, Mode::Audit).into_value();
        non_agent["agent_runner_exit"] = Value::Null;
        assert_eq!(
            RequestRecord::decode(non_agent.clone())
                .expect_err("explicit null is not absence")
                .kind,
            "requests-record-refusal"
        );
        non_agent["agent_runner_exit"] = json!({"code":7});
        assert_eq!(
            RequestRecord::decode(non_agent)
                .expect_err("non-agent exit")
                .kind,
            "requests-record-refusal"
        );
    }

    /// ´test:unit:schema-four-requires-every-key-and-separates-observed-model´
    #[test]
    fn schema_four_requires_every_key_and_separates_observed_model() {
        let mut record = waiting("R", "1a", 3000, Mode::Audit).into_value();
        let result =
            RunnerOutcome::referral("failure", "missing sign-in", std::time::Instant::now());
        apply(&mut record, &result, None, Some("configured-model"));
        assert!(record["agent_model"].is_null());
        assert_eq!(record["agent_configured_model"], "configured-model");
        RequestRecord::decode(record.clone()).expect("service referral");
        for key in KEYS {
            let mut missing = record.clone();
            missing.as_object_mut().expect("record").remove(key);
            let error = RequestRecord::decode(missing).expect_err("required key");
            assert_eq!(error.kind, "requests-record-refusal");
            assert!(error.detail.contains(key));
        }
        record["agent_verdict"] = json!("allow");
        record["would_do"]["decision"] = json!("allow");
        assert!(
            RequestRecord::decode(record).is_err(),
            "service failure cannot be allowance"
        );
    }
}
