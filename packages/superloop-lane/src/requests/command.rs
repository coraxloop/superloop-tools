//! Door observations and existing envelope rendering around the shared decisions.
use crate::error::LaneError;
use execute_command::request::{
    Binding, Judgement, MatchEvaluation, MatchKey, ShapeError, Text, TextList, Verdict,
};
use serde_json::{Value, json};

/// Hash caller observations; no new persisted identity or authority is introduced.
///
/// # Panics
/// Panics only if a SHA-256 hex digest exceeds the text bound, which source data cannot arrange.
pub fn binding(source: &Value) -> Binding {
    let context = if source.get("id").is_some() && source.get("loop").is_some() {
        [
            "id",
            "loop",
            "run",
            "worker_uid",
            "class",
            "operation",
            "shape_key",
            "filed_at",
            "mode",
            "would_do",
        ]
        .into_iter()
        .map(|field| (field.to_owned(), source[field].clone()))
        .collect::<serde_json::Map<_, _>>()
        .into()
    } else {
        source.clone()
    };
    let digest = request_core::request_id(context.to_string().as_bytes());
    let request_id = source["id"].as_str().map_or_else(
        || digest.clone(),
        |id| request_core::request_id(id.as_bytes()),
    );
    Binding {
        request_id: request_id.try_into().expect("SHA-256 text"),
        context_digest: digest.try_into().expect("SHA-256 text"),
    }
}

/// Validate the existing label's source and review bindings before claiming its effect.
pub fn validate_label(source: &Value) -> Result<(), LaneError> {
    use execute_command::escalation::{Answer, ReviewAnswer, validate_answer};
    use execute_command::request::VerdictStatus;
    use execute_command::triage::Scope;
    let label = &source["label"];
    let mut answered = source.clone();
    answered["id"] = label["request_id"].clone();
    answered["shape_key"] = label["shape_key"].clone();
    answered["would_do"] = label["would_do"].clone();
    let review = |value: &Value| {
        value
            .as_str()
            .map(|id| text(&request_core::request_id(id.as_bytes())))
            .transpose()
    };
    let current = review(&source["review"]["id"])?;
    let verdict = execute_command::triage::referral(
        &binding(source),
        Scope::Loop,
        VerdictStatus::Valid,
        text("door loop review")?,
    );
    let Some(mut escalation) = verdict.escalation else {
        return Err(shape(ShapeError("execute-command-escalation-shape")));
    };
    escalation.requires_current_review = current.is_some();
    let answer = Answer {
        binding: binding(&answered),
        review: review(&label["review_id"])?,
        answer: if label["treatment"] == "allow" {
            ReviewAnswer::Approve
        } else {
            ReviewAnswer::Deny
        },
        adjudicator: text(&format!(
            "adjudicator: {}",
            label["adjudicator"].as_str().unwrap_or_default()
        ))?,
        reason: text(&format!(
            "review: {}",
            label["reason"].as_str().unwrap_or_default()
        ))?,
    };
    validate_answer(&escalation, &answer, current.as_ref()).map_err(shape)
}

pub(super) fn text(value: &str) -> Result<Text, LaneError> {
    value
        .to_owned()
        .try_into()
        .map_err(|_| shape(ShapeError("execute-command-verdict-shape")))
}

pub(super) fn texts(values: &[String]) -> Result<TextList, LaneError> {
    values
        .iter()
        .map(|value| text(value))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| shape(ShapeError("execute-command-verdict-shape")))
}

pub(super) fn shape(error: ShapeError) -> LaneError {
    super::refusal(error.0, "invalid command observation")
}

pub(super) fn accept(verdict: Option<Verdict>) -> Result<(), LaneError> {
    let Some(verdict) = verdict else {
        return Ok(());
    };
    if verdict.judgement == Judgement::Allow {
        return Ok(());
    }
    let rule = verdict
        .correction
        .as_ref()
        .map(|correction| correction.rule.as_str());
    let name = match rule {
        Some("door-mode-floor-refusal") => "door-mode-floor-refusal",
        Some("door-mode-setting-refusal") => "door-mode-setting-refusal",
        Some("door-mode-evidence-refusal") => "door-mode-evidence-refusal",
        Some("requests-record-refusal") => "requests-record-refusal",
        _ => "execute-command-verdict-shape",
    };
    Err(super::refusal(name, verdict.reason.as_str()))
}

pub(super) fn key(class: &str, operation: &str, shape: &str) -> Result<MatchKey, LaneError> {
    Ok(MatchKey {
        class: text(class)?,
        operation: text(operation)?,
        shape_key: text(shape)?,
    })
}

pub(super) fn would_do(evaluation: MatchEvaluation) -> Value {
    match evaluation {
        MatchEvaluation::Undecided { reason } => {
            json!({"decision":"undecided","reason":reason.as_str()})
        }
        MatchEvaluation::Decided(verdict) => {
            json!({"decision":verdict.judgement,"reason":verdict.reason.as_str()})
        }
    }
}

pub(super) fn label(
    record: &super::RequestRecord,
) -> Result<execute_command::request::LabelObservation, LaneError> {
    let value = record.value();
    let judgement = |value: &Value| match value.as_str() {
        Some("allow") => Some(Judgement::Allow),
        Some("refuse") => Some(Judgement::Refuse),
        Some("refer") => Some(Judgement::Refer),
        _ => None,
    };
    Ok(execute_command::request::LabelObservation {
        id: text(record.id())?,
        class: text(value["class"].as_str().unwrap_or_default())?,
        adjudicated: value["state"] == "adjudicated",
        would_do: judgement(&value["would_do"]["decision"]),
        treatment: judgement(&value["label"]["treatment"]),
    })
}

pub(super) fn feedback(value: &Value) -> execute_command::learning::Feedback {
    let decision = |value: &Value| match value.as_str() {
        Some("allow") => Some(Judgement::Allow),
        Some("refuse") => Some(Judgement::Refuse),
        Some("refer") => Some(Judgement::Refer),
        _ => None,
    };
    execute_command::learning::Feedback {
        adjudicated: value["state"] == "adjudicated",
        enforced: value["mode"] == "enforce",
        would_do: decision(&value["would_do"]["decision"]),
        treatment: decision(&value["label"]["treatment"]),
        labelled_at: value["label"]["at"].as_str().and_then(|at| at.parse().ok()),
    }
}

pub(super) fn retained_decision(value: &Value) -> Result<Verdict, LaneError> {
    use execute_command::request::{Rung, VerdictStatus};
    use execute_command::triage::Scope;
    let observation = feedback(value);
    let reason = value["would_do"]["reason"].as_str().unwrap_or_default();
    execute_command::record::retained_decision(
        &binding(value),
        observation.would_do,
        match value["would_do_source"].as_str() {
            Some("agent") => Rung::BoundedAgent,
            Some("fast-lane") if !value["matched_rule"].is_null() => Rung::LearnedExactMatch,
            Some("fast-lane") => Rung::DeterministicChecks,
            _ => Rung::LoopReview,
        },
        if value["agent_scope"] == "estate" {
            Scope::Estate
        } else {
            Scope::Loop
        },
        text(if reason.trim().is_empty() {
            "retained judgement has no nonblank rationale"
        } else {
            reason
        })?,
        match value["agent_status"].as_str() {
            Some("failure") => VerdictStatus::AgentFailure,
            Some("invalid-output") => VerdictStatus::InvalidOutput,
            Some("timeout") => VerdictStatus::Timeout,
            _ => VerdictStatus::Valid,
        },
    )
    .map_err(shape)
}

pub(super) fn retained_outcome(
    value: &Value,
) -> Result<execute_command::record::OutcomeRecord, LaneError> {
    use execute_command::record::{Outcome, OutcomeRecord, execution_outcome};
    let effect = &value["effect"];
    let completed = if effect["state"] == "completed" {
        effect["exit_status"].as_i64().map(|code| code == 0)
    } else {
        None
    };
    let outcome = execution_outcome(
        completed,
        effect["state"] == "refused" && effect["ref_check"] == "not-reached",
    );
    let milliseconds = |key: &str| {
        effect[key]
            .as_f64()
            .and_then(|wall| std::time::Duration::try_from_secs_f64(wall).ok())
            .and_then(|wall| u64::try_from(wall.as_millis()).ok())
    };
    OutcomeRecord::new(
        binding(value),
        outcome,
        text(
            effect["reason"]
                .as_str()
                .unwrap_or("no completion observation; permission is not execution evidence"),
        )?,
        milliseconds("queue_wall_seconds"),
        milliseconds("mediation_wall_seconds"),
        if matches!(
            outcome,
            Outcome::OutcomeUnknown | Outcome::RefusedBeforeEffect
        ) {
            None
        } else {
            milliseconds("compute_wall_seconds")
        },
    )
    .map_err(shape)
}

#[cfg(test)]
mod tests {
    use super::binding;
    use serde_json::json;

    /// ´test:unit:door-label-binds-source-shape-and-current-review´
    #[test]
    fn door_label_binds_source_shape_and_current_review() {
        let source = json!({"id":"R:1a","loop":"alpha","run":"R","worker_uid":3000,"class":"git","operation":"git-upload","shape_key":"git:upload","filed_at":"1","mode":"audit","would_do":{"decision":"allow","reason":"fixture"},"review":{"id":"review-a","at":"2"},"label":{"request_id":"R:1a","shape_key":"git:upload","would_do":{"decision":"allow","reason":"fixture"},"review_id":"review-a","treatment":"allow","adjudicator":"requests-helper","reason":"reviewed"}});
        super::validate_label(&source).expect("current bound answer");
        for field in ["request_id", "shape_key", "would_do", "review_id"] {
            let mut changed = source.clone();
            changed["label"][field] = json!("stale");
            assert_eq!(
                super::validate_label(&changed)
                    .expect_err("changed answer binding")
                    .kind,
                "execute-command-escalation-shape"
            );
        }
        let mut triaged = source;
        triaged["review"] = json!(null);
        triaged["label"]["review_id"] = json!(null);
        super::validate_label(&triaged).expect("direct triage keeps its null review");
    }

    /// ´test:unit:context-binds-source-and-mode-without-review-state´
    #[test]
    fn context_binds_source_and_mode_without_review_state() {
        let mut source = json!({"id":"R:1a","loop":"alpha","run":"R","worker_uid":3000,"class":"git","operation":"git-upload","shape_key":"git:upload","filed_at":"1","mode":"audit","would_do":{"decision":"allow","reason":"fixture"}});
        let first = binding(&source);
        source["state"] = json!("marked");
        source["review"] = json!("review-a");
        assert_eq!(binding(&source), first);
        for field in ["mode", "would_do", "worker_uid", "operation"] {
            let mut changed = source.clone();
            changed[field] = json!("changed");
            let next = binding(&changed);
            assert_eq!(next.request_id, first.request_id);
            assert_ne!(next.context_digest, first.context_digest);
        }
        source["id"] = json!("R:2b");
        assert_ne!(binding(&source).request_id, first.request_id);
    }
}
