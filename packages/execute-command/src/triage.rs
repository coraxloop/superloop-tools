//! Profile-specific judgement validation and pure bounded-agent decisions.
//! Runners, clocks, authenticated context, process custody and effects stay with callers.

use crate::escalation::{Correction, Escalation, ReferralTarget};
use crate::request::{Binding, Judgement, Rung, Text, TextList, Verdict, VerdictStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// Existing backend output profiles; neither accepts the other's vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    DoorVerdict,
    HookSixClass,
}

/// A caller-observed bounded invocation; no runner or ambient state enters the crate.
#[derive(Clone, Debug)]
pub enum RunnerOutcome {
    Output(Vec<u8>),
    Failure { status: VerdictStatus, reason: Text },
}

/// Total call budget, including caller-specific cleanup, or no permission to invoke.
#[must_use]
pub fn budget(remaining: Duration, cap: Duration, cleanup: Duration) -> Option<Duration> {
    let total = remaining.min(cap);
    (total > cleanup).then_some(total)
}

/// Effect scope, independent of the policy classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Effects wholly within the resolved caller's domain.
    Loop,
    /// Protected, shared, outside-domain, or unresolved effects.
    Estate,
}

impl Scope {
    /// Parse the exact closed model and journal vocabulary.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "loop" => Some(Self::Loop),
            "estate" => Some(Self::Estate),
            _ => None,
        }
    }

    /// Stable serialized spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loop => "loop",
            Self::Estate => "estate",
        }
    }
}

/// Hook evidence retained beside the common judgement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    RoutineGeneral,
    RoutineSuperloop,
    Safe,
    AdvancedReadOnly,
    AgentError,
    Suspicious,
}

impl Classification {
    /// Fixed serialized class name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoutineGeneral => "routine-general",
            Self::RoutineSuperloop => "routine-superloop",
            Self::Safe => "safe",
            Self::AdvancedReadOnly => "advanced-read-only",
            Self::AgentError => "agent-error",
            Self::Suspicious => "suspicious",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "routine-general" => Some(Self::RoutineGeneral),
            "routine-superloop" => Some(Self::RoutineSuperloop),
            "safe" => Some(Self::Safe),
            "advanced-read-only" => Some(Self::AdvancedReadOnly),
            "agent-error" => Some(Self::AgentError),
            "suspicious" => Some(Self::Suspicious),
            _ => None,
        }
    }
}

/// Validated output from one classifier invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelResult {
    classification: Classification,
    reason: String,
    scope: Scope,
}

impl ModelResult {
    /// Validated effect scope, which the hook must check against protected targets.
    #[must_use]
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Validated policy class.
    #[must_use]
    pub const fn classification(&self) -> Classification {
        self.classification
    }

    /// Nonempty model reason of at most 1,000 bytes.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Read the hook profile without decoding its vendor envelope.
///
/// # Errors
/// Returns the existing profile diagnostic for an invalid classification, reason or scope.
pub fn parse_hook(value: &Value) -> Result<ModelResult, &'static str> {
    let object = value.as_object().ok_or("result is not an object")?;
    if object.len() != 3
        || !object.contains_key("classification")
        || !object.contains_key("reason")
        || !object.contains_key("scope")
    {
        return Err("result must contain only classification, reason, and scope");
    }
    let classification = object
        .get("classification")
        .and_then(Value::as_str)
        .and_then(Classification::parse)
        .ok_or("classification is not a known class name")?;
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .ok_or("reason is not a string")?;
    if reason.is_empty() || reason.len() > 1000 {
        return Err("reason must contain between 1 and 1000 UTF-8 bytes");
    }
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .and_then(Scope::parse)
        .ok_or("scope is not loop or estate")?;
    Ok(ModelResult {
        scope,
        classification,
        reason: reason.to_owned(),
    })
}

/// Reject duplicate keys as well as extra keys, unlike a map-only JSON decoder.
///
/// # Errors
/// Refuses anything except the exact verdict object, including trailing data.
pub fn parse_door(text: &str) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_str(text).map_err(|_| "agent-invalid-json")?;
    let object = value.as_object().ok_or("agent-object-required")?;
    if object.len() != 3
        || !["verdict", "scope", "reason"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return Err("agent-exact-keys-required");
    }
    // Count top-level string tokens followed by a colon. JSON parsing above
    // validates escapes, so escaped property names cannot hide a duplicate.
    let bytes = text.as_bytes();
    let mut strings = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                if bytes[index] == b'\\' {
                    index += 1;
                }
                index += 1;
            }
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) == Some(&b':') {
                strings += 1;
            }
        } else {
            index += 1;
        }
    }
    if strings != 3
        || !matches!(
            value["verdict"].as_str(),
            Some("allow" | "refuse" | "refer")
        )
        || !matches!(value["scope"].as_str(), Some("loop" | "estate"))
        || value["reason"]
            .as_str()
            .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 1024)
    {
        return Err("agent-verdict-shape");
    }
    Ok(value)
}

fn text(value: &str) -> Text {
    value
        .to_owned()
        .try_into()
        .expect("validated profile text or bounded static vocabulary")
}

fn evidence() -> TextList {
    Vec::new().try_into().expect("empty evidence is bounded")
}

/// Describe referral evidence without claiming that an external authority route exists.
/// Callers retain their review path until the external route is provisioned under its hold.
///
/// # Panics
/// Panics only if static vocabulary exceeds the text bound, which callers cannot arrange.
#[must_use]
pub fn referral(binding: &Binding, scope: Scope, status: VerdictStatus, reason: Text) -> Verdict {
    let (target, authority, route, resume) = match scope {
        Scope::Loop => (
            ReferralTarget::LoopReview,
            "registered loop adjudicator",
            "caller-loop",
            "obtain a current authenticated answer bound to this request and context",
        ),
        Scope::Estate => (
            ReferralTarget::Operations,
            "delegated operations authority",
            "unprovisioned:operations",
            "execute-command-route-unprovisioned: provision the authenticated operations route and its delegation before resuming",
        ),
    };
    Verdict {
        binding: binding.clone(),
        judgement: Judgement::Refer,
        tier: Rung::BoundedAgent,
        scope: text(scope.as_str()),
        reason,
        evidence: evidence(),
        correction: None,
        escalation: Some(Escalation {
            target,
            required_authority: text(authority),
            route: text(route),
            binding: binding.clone(),
            requires_current_review: false,
            evidence: evidence(),
            resume_conditions: text(resume),
        }),
        status,
    }
}

/// Validate one runner outcome and decide its shared semantics without executing anything.
///
/// A contradictory model scope is invalid output, never a requester correction.
///
/// # Panics
/// Panics only if validated profile text or static vocabulary exceeds its declared bounds,
/// which a runner's bytes cannot arrange because both profile readers enforce smaller limits.
#[must_use]
pub fn judge(
    binding: &Binding,
    profile: Profile,
    outcome: &RunnerOutcome,
    floor: Scope,
) -> Verdict {
    let bytes = match outcome {
        RunnerOutcome::Failure { status, reason } => {
            return referral(
                binding,
                Scope::Estate,
                if *status == VerdictStatus::Valid {
                    VerdictStatus::AgentFailure
                } else {
                    *status
                },
                reason.clone(),
            );
        }
        RunnerOutcome::Output(bytes) => bytes,
    };
    let parsed = parse(profile, bytes);
    let (decision, scope, reason) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            return referral(
                binding,
                Scope::Estate,
                VerdictStatus::InvalidOutput,
                text(error),
            );
        }
    };
    if scope == Scope::Loop && floor == Scope::Estate {
        return referral(
            binding,
            Scope::Estate,
            VerdictStatus::InvalidOutput,
            text("loop scope contradicts a protected target or unresolved identity/effect"),
        );
    }
    if decision == Judgement::Refer {
        return referral(binding, scope, VerdictStatus::Valid, reason);
    }
    let correction = (decision == Judgement::Refuse).then(|| Correction {
        rule: text(match profile {
            Profile::DoorVerdict => "door-rubric-refusal",
            Profile::HookSixClass => "agent-error",
        }),
        changes: reason.clone(),
        revalidation: text("submit the corrected request for fresh checks and judgement"),
    });
    Verdict {
        binding: binding.clone(),
        judgement: decision,
        tier: Rung::BoundedAgent,
        scope: text(scope.as_str()),
        reason,
        evidence: evidence(),
        correction,
        escalation: None,
        status: VerdictStatus::Valid,
    }
}

fn parse(profile: Profile, bytes: &[u8]) -> Result<(Judgement, Scope, Text), &'static str> {
    if bytes.len() > 65_536 {
        return Err("execute-command-agent-output-limit");
    }
    match profile {
        Profile::DoorVerdict => {
            let source = std::str::from_utf8(bytes).map_err(|_| "agent-invalid-json")?;
            let value = parse_door(source)?;
            let decision = match value["verdict"].as_str() {
                Some("allow") => Judgement::Allow,
                Some("refuse") => Judgement::Refuse,
                _ => Judgement::Refer,
            };
            let scope = Scope::parse(value["scope"].as_str().unwrap_or_default())
                .ok_or("agent-verdict-shape")?;
            Ok((
                decision,
                scope,
                text(value["reason"].as_str().unwrap_or_default()),
            ))
        }
        Profile::HookSixClass => {
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "result is not JSON")?;
            let result = parse_hook(&value)?;
            let (decision, prefix) = match result.classification() {
                Classification::AgentError => (Judgement::Refuse, "correction"),
                Classification::Suspicious => (Judgement::Refer, "suspicious"),
                class => (Judgement::Allow, class.as_str()),
            };
            // The existing hook profile admits whitespace-only reasons. Its rendered prefix
            // makes the shared rationale nonblank without changing that accepted profile.
            Ok((
                decision,
                result.scope(),
                text(&format!("{prefix}: {}", result.reason())),
            ))
        }
    }
}
