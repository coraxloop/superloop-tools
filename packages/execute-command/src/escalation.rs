//! Structured remedies, referral targets and request-bound review answers.
//!
//! Callers retain authenticated routes, delivery, notifications and identity
//! verification. A route identifier does not establish a deliverable route.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::request::{Binding, Text, TextList};

/// Describe the existing loop-review option from caller-authenticated role observations.
/// This text grants no authority and installs no policy.
#[must_use]
pub fn loop_review_reason(role: &str, loop_name: Option<&str>, detail: &str) -> String {
    match (role, loop_name) {
        ("orchestrator", Some(name)) => format!(
            "escalation: role=orchestrator loop={name}; review the scoped journal record; loop work may be marked adjudicated-approved for one identical main-session request; {detail}"
        ),
        ("orchestrator-subagent", Some(name)) => format!(
            "escalation: role=orchestrator-subagent loop={name}; send to the superloop orchestrator agent for adjudication; {detail}"
        ),
        _ => format!(
            "escalation: role=unknown; send to the superloop orchestrator agent for adjudication; {detail}"
        ),
    }
}

/// The three authority destinations, distinct from the deciding rung.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReferralTarget {
    LoopReview,
    Operations,
    Owner,
}

/// Required changes and revalidation; never a silently rewritten command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub rule: Text,
    pub changes: Text,
    pub revalidation: Text,
}

/// Evidence and authority needed to resume a bound request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    pub target: ReferralTarget,
    pub required_authority: Text,
    pub route: Text,
    pub binding: Binding,
    pub requires_current_review: bool,
    pub evidence: TextList,
    pub resume_conditions: Text,
}

/// A gateway answer is an authorized lifecycle input, not an execution result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewAnswer {
    Approve,
    Deny,
    Abandon,
}

/// Denial and abandonment retain an explicit human reason; approval may omit it.
#[must_use]
pub fn proposal_reason(answer: ReviewAnswer, reason: &str) -> bool {
    answer == ReviewAnswer::Approve || !reason.trim().is_empty()
}

/// An expired attention window parks a proposal without terminating its lifetime.
#[must_use]
pub const fn attention_elapsed(
    queued_unix_ms: u64,
    timeout_seconds: u64,
    now_unix_ms: u64,
) -> bool {
    now_unix_ms.saturating_sub(queued_unix_ms) >= timeout_seconds.saturating_mul(1_000)
}

/// A caller-authenticated answer, bound to the reviewed request and context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub binding: Binding,
    pub review: Option<Text>,
    pub answer: ReviewAnswer,
    pub adjudicator: Text,
    pub reason: Text,
}

/// Check answer identity after the adapter authenticates its sender and route.
///
/// # Errors
/// Returns `execute-command-escalation-shape` for changed context or a missing/stale review.
pub fn validate_answer(
    escalation: &Escalation,
    answer: &Answer,
    current_review: Option<&Text>,
) -> Result<(), crate::request::ShapeError> {
    if answer.binding != escalation.binding
        || (escalation.requires_current_review && current_review.is_none())
        || answer.review.as_ref() != current_review
    {
        return Err(crate::request::ShapeError(
            "execute-command-escalation-shape",
        ));
    }
    Ok(())
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|word| {
        word.len() == 64
            && word
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Validate the four existing hook dispositions; a rule proposal installs no policy.
#[must_use]
pub fn permission_answer(body: &Value, value: &Value) -> bool {
    match value["outcome"].as_str() {
        Some("adjudicated-rejected") => exact(value, &["outcome"]),
        Some("adjudicated-rule-added") => {
            exact(value, &["outcome", "rule"])
                && value["rule"]
                    .as_str()
                    .is_some_and(|word| !word.trim().is_empty())
        }
        Some("corrected-and-rerun") => {
            exact(value, &["outcome", "request_digest"]) && digest(&value["request_digest"])
        }
        Some("adjudicated-approved") => {
            exact(value, &["outcome", "request_digest"])
                && digest(&value["request_digest"])
                && value["request_digest"] == body["request_digest"]
                && body["role"] == "orchestrator"
        }
        _ => false,
    }
}
