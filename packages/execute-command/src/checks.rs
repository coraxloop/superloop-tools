//! Mechanical hygiene, reusable admission predicates and learned exact matches.
//!
//! Callers retain transport validation and registered resource evidence.

pub mod compute;
mod hygiene;

pub use hygiene::{
    FastLane, HYGIENE_RULE_COUNT, HYGIENE_RULES, HygieneRule, HygieneRuleId, READ_ONLY_TABLE,
    ReadOnlyEntry, hygiene_rule, matching_read_only_entry, scope_words,
};

#[cfg(test)]
mod hygiene_parity;

use crate::escalation::Correction;
use crate::request::{
    Binding, HygieneObservation, HygieneRequest, Judgement, LearnedGroup, MatchEvaluation,
    MatchKey, Rung, ShapeError, Text, TextList, Verdict, VerdictStatus,
};

/// Evaluate the hook's eight ordered predicates without executing a command.
///
/// A miss (including every disabled read claim) returns None, not an allowance.
/// Argv is not joined into shell syntax. The caller keeps audit silence and rendering.
///
/// # Errors
/// Returns `execute-command-verdict-shape` if a generated field exceeds its bound.
pub fn hygiene(
    request: &impl HygieneRequest,
    observation: &HygieneObservation<'_>,
    scope: &str,
) -> Result<Option<Verdict>, ShapeError> {
    let result = hygiene::classify(request, observation);
    match result {
        hygiene::FastLane::AgentError {
            rule,
            defect,
            correction,
        } => refusal(request, scope, rule, defect, correction).map(Some),
        hygiene::FastLane::ReadOnlyAllow { rule } => verdict(
            request,
            scope,
            Judgement::Allow,
            Rung::DeterministicChecks,
            rule,
            None,
            empty_evidence()?,
        )
        .map(Some),
        hygiene::FastLane::ToModel => Ok(None),
    }
}

/// Refuse a named command absent from the caller-authenticated roster.
///
/// # Errors
/// Returns `execute-command-verdict-shape` if the binding cannot form a verdict.
pub fn registered_command(
    request: &impl AsRef<Binding>,
    registered: bool,
) -> Result<Option<Verdict>, ShapeError> {
    if registered {
        return Ok(None);
    }
    refusal(
        request,
        "loop",
        "unknown_roster_command",
        "run command is not in the registered roster",
        "select a registered command or submit an explicit proposal",
    )
    .map(Some)
}

/// Evaluate one exact learned key without loading or updating its index.
///
/// Agreement preserves citations; no labels, another key and conflicting labels
/// remain misses. Counts are validated index observations, not new standing policy.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn learned_exact_match(
    request: &impl AsRef<Binding>,
    key: &MatchKey,
    group: Option<&LearnedGroup>,
) -> Result<MatchEvaluation, ShapeError> {
    let group = group.filter(|group| group.key == *key);
    let (allow, refuse) = group.map_or((0, 0), |group| (group.allow, group.refuse));
    let decision = match (allow > 0, refuse > 0) {
        (true, false) => Judgement::Allow,
        (false, true) => Judgement::Refuse,
        _ => {
            return Ok(MatchEvaluation::Undecided {
                reason: text(if allow == 0 && refuse == 0 {
                    "no adjudicated label for this shape"
                } else {
                    "adjudicated labels conflict"
                })?,
            });
        }
    };
    let correction = if decision == Judgement::Refuse {
        Some(Correction {
            rule: text("door-rubric-refusal")?,
            changes: text(
                "revise the request or obtain a new adjudicated label through loop review",
            )?,
            revalidation: text(
                "recheck the exact class, operation, shape and current adjudicated evidence",
            )?,
        })
    } else {
        None
    };
    let evidence = group.map_or(empty_evidence()?, |group| group.citations.clone());
    verdict(
        request,
        "loop",
        decision,
        Rung::LearnedExactMatch,
        "applicable adjudicated labels agree",
        correction,
        evidence,
    )
    .map(|verdict| MatchEvaluation::Decided(Box::new(verdict)))
}

/// Evaluate the door's caller-validated registered rubric by the complete key.
///
/// A caller supplies this path instead of the learned index, never as a prefix
/// fallback. Rubric loading, strict decoding and duplicate detection stay there.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn registered_exact_match(
    request: &impl AsRef<Binding>,
    key: &MatchKey,
    rules: &[crate::request::ExactRule],
    undecided_reason: &Text,
) -> Result<MatchEvaluation, ShapeError> {
    let Some(rule) = rules.iter().find(|rule| rule.key == *key) else {
        return Ok(MatchEvaluation::Undecided {
            reason: undecided_reason.clone(),
        });
    };
    let mut result = if rule.allow {
        verdict(
            request,
            "loop",
            Judgement::Allow,
            Rung::LearnedExactMatch,
            rule.reason.as_str(),
            None,
            empty_evidence()?,
        )?
    } else {
        refusal(
            request,
            "loop",
            "door-rubric-refusal",
            rule.reason.as_str(),
            "revise the request or obtain review of the exact registered rubric rule",
        )?
    };
    result.tier = Rung::LearnedExactMatch;
    Ok(MatchEvaluation::Decided(Box::new(result)))
}

/// Reject a model's loop scope when caller-supplied protected-target evidence sets an estate floor.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn scope_floor(
    request: &impl AsRef<Binding>,
    reports_loop: bool,
    requires_estate: bool,
) -> Result<Option<Verdict>, ShapeError> {
    if !reports_loop || !requires_estate {
        return Ok(None);
    }
    Ok(Some(crate::triage::referral(
        request.as_ref(),
        crate::triage::Scope::Estate,
        VerdictStatus::InvalidOutput,
        text("loop scope contradicts a protected target or unresolved identity/effect")?,
    )))
}

/// Preserve a hook agent-error correction as a refusal, without rewriting the command.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn malformed_correction(
    request: &impl AsRef<Binding>,
    reason: &Text,
    scope: &str,
) -> Result<Verdict, ShapeError> {
    let mut result = refusal(
        request,
        scope,
        "agent-error",
        reason.as_str(),
        reason.as_str(),
    )?;
    result.tier = Rung::BoundedAgent;
    Ok(result)
}

/// Validate the door's cited rubric correction before any mode-store access.
///
/// A missing, foreign, unadjudicated, undecided or agreeing label is not a
/// correction. A valid correction returns None; its publication remains caller-owned.
///
/// # Errors
/// Returns `execute-command-verdict-shape` for an unrepresentable verdict.
pub fn correction_evidence(
    request: &impl AsRef<Binding>,
    class: &Text,
    id: &Text,
    observation: Option<&crate::request::LabelObservation>,
) -> Result<Option<Verdict>, ShapeError> {
    let Some(label) = observation.filter(|label| label.id == *id) else {
        return refusal(
            request,
            "loop",
            "door-mode-evidence-refusal",
            "correction request is absent",
            "cite an existing adjudicated correction request",
        )
        .map(Some);
    };
    if label.class != *class
        || !label.adjudicated
        || !matches!(label.would_do, Some(Judgement::Allow | Judgement::Refuse))
        || label.would_do == label.treatment
    {
        return refusal(request, "loop", "door-mode-evidence-refusal", "request is not a rubric correction for this class",
            "cite an adjudicated request for this class whose label corrects its allow or refuse judgement").map(Some);
    }
    Ok(None)
}

pub(crate) fn text(value: &str) -> Result<Text, ShapeError> {
    value
        .to_owned()
        .try_into()
        .map_err(|_| ShapeError("execute-command-verdict-shape"))
}

pub(crate) fn empty_evidence() -> Result<TextList, ShapeError> {
    Vec::new()
        .try_into()
        .map_err(|_| ShapeError("execute-command-verdict-shape"))
}

pub(crate) fn refusal(
    request: &impl AsRef<Binding>,
    scope: &str,
    rule: &str,
    reason: &str,
    changes: &str,
) -> Result<Verdict, ShapeError> {
    verdict(
        request,
        scope,
        Judgement::Refuse,
        Rung::DeterministicChecks,
        reason,
        Some(Correction {
            rule: text(rule)?,
            changes: text(changes)?,
            revalidation: text(
                "resubmit the corrected request through the same checks before any effect",
            )?,
        }),
        empty_evidence()?,
    )
}

pub(crate) fn verdict(
    request: &impl AsRef<Binding>,
    scope: &str,
    judgement: Judgement,
    tier: Rung,
    reason: &str,
    correction: Option<Correction>,
    evidence: TextList,
) -> Result<Verdict, ShapeError> {
    let verdict = Verdict {
        binding: request.as_ref().clone(),
        judgement,
        tier,
        scope: text(scope)?,
        reason: text(reason)?,
        evidence,
        correction,
        escalation: None,
        status: VerdictStatus::Valid,
    };
    verdict.validate()?;
    Ok(verdict)
}
