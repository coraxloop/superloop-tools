//! Required records and semantic persistence preconditions.
//! Callers retain stores, journals, locks, custody and authority validation.

use serde::{Deserialize, Serialize};

use crate::request::{Binding, ShapeError, Text, Verdict, required_nullable};

/// Whether custody has published effect evidence; this does not imply success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectPublication {
    Pending,
    Recorded,
}

/// Publication facts supplied by the owner of a command's custody record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewState<'a> {
    pub state: Option<&'a str>,
    pub effect: EffectPublication,
    pub review: bool,
    pub label: bool,
    pub mark: bool,
}

impl ReviewState<'_> {
    /// Validate command review semantics without replacing request-core transitions.
    #[must_use]
    pub fn valid(self) -> bool {
        match self.state {
            None | Some("waiting") => !self.review && !self.label && !self.mark,
            Some("observed" | "preflight-refused") => {
                self.effect == EffectPublication::Recorded
                    && !self.review
                    && !self.label
                    && !self.mark
            }
            Some("marked") => self.mark && !self.label,
            Some("adjudicated") => self.label,
            _ => false,
        }
    }
}

/// Review identity must remain current before an answer can attach to its source.
///
/// # Errors
/// Refuses a stale or absent marked review with the caller's established name.
pub fn current_review(marked: bool, current: Option<&str>, answer: &str) -> Result<(), ShapeError> {
    if !marked {
        return Err(ShapeError("requests-state-refusal"));
    }
    if current != Some(answer) {
        return Err(ShapeError("requests-review-id-refusal"));
    }
    Ok(())
}

/// Distinguish a new completion, an identical retry and conflicting evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDisposition {
    Publish,
    IdenticalRetry,
    Conflict,
}

#[must_use]
pub const fn completion_disposition(completed: bool, identical: bool) -> CompletionDisposition {
    if !completed {
        CompletionDisposition::Publish
    } else if identical {
        CompletionDisposition::IdenticalRetry
    } else {
        CompletionDisposition::Conflict
    }
}

/// Render retained judgement fields as a common decision without granting an effect.
///
/// # Errors
/// Refuses contradictory outcome/status combinations as `execute-command-verdict-shape`.
pub fn retained_decision(
    binding: &Binding,
    judgement: Option<crate::request::Judgement>,
    tier: crate::request::Rung,
    scope: crate::triage::Scope,
    reason: Text,
    status: crate::request::VerdictStatus,
) -> Result<Verdict, ShapeError> {
    use crate::request::Judgement;
    let mut verdict = crate::triage::referral(binding, scope, status, reason);
    verdict.tier = tier;
    if let Some(judgement @ (Judgement::Allow | Judgement::Refuse)) = judgement {
        verdict.judgement = judgement;
        verdict.escalation = None;
        if judgement == Judgement::Refuse {
            verdict.correction = Some(crate::escalation::Correction {
                rule: crate::checks::text("recorded-command-refusal")?,
                changes: crate::checks::text(
                    "revise the request or obtain a current authenticated review",
                )?,
                revalidation: crate::checks::text(
                    "resubmit through the command checks; a retained record grants no execution",
                )?,
            });
        }
    }
    verdict.validate()?;
    Ok(verdict)
}

/// Execution evidence, never inferred from judgement publication or approval.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Completed,
    Failed,
    TimedOut,
    RefusedBeforeEffect,
    Abandoned,
    OutcomeUnknown,
}

/// Separate an observed completion from a no-effect refusal or uncertain attempt.
/// A permission decision alone supplies neither completion nor no-effect proof.
#[must_use]
pub const fn execution_outcome(
    completed_successfully: Option<bool>,
    refused_before_effect: bool,
) -> Outcome {
    match completed_successfully {
        Some(true) => Outcome::Completed,
        Some(false) => Outcome::Failed,
        None if refused_before_effect => Outcome::RefusedBeforeEffect,
        None => Outcome::OutcomeUnknown,
    }
}

/// Harness publication policy after record storage fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookRecordFailure {
    LostAuditEvent,
    RetainStateRootRefusal,
    Refuse,
}

/// Audit stays silent because its harness owns execution; enforcement requires publication.
#[must_use]
pub const fn hook_record_failure(audit: bool, state_root_refusal: bool) -> HookRecordFailure {
    if audit {
        HookRecordFailure::LostAuditEvent
    } else if state_root_refusal {
        HookRecordFailure::RetainStateRootRefusal
    } else {
        HookRecordFailure::Refuse
    }
}

/// Audit publishes no harness decision; enforcement publishes its judgement.
#[must_use]
pub const fn hook_emission(audit: bool, refuse: bool) -> Option<crate::request::Judgement> {
    if audit {
        None
    } else if refuse {
        Some(crate::request::Judgement::Refuse)
    } else {
        Some(crate::request::Judgement::Allow)
    }
}

/// An outcome and its rationale remain paired under immutable request identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutcomeRecord {
    binding: Binding,
    outcome: Outcome,
    rationale: Text,
    queue_wall_ms: Option<u64>,
    judgement_wall_ms: Option<u64>,
    execution_wall_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRecordWire {
    binding: Binding,
    outcome: Outcome,
    rationale: Text,
    #[serde(deserialize_with = "required_nullable")]
    queue_wall_ms: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    judgement_wall_ms: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    execution_wall_ms: Option<u64>,
}

impl<'de> Deserialize<'de> for OutcomeRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OutcomeRecordWire::deserialize(deserializer)?;
        let record = Self {
            binding: wire.binding,
            outcome: wire.outcome,
            rationale: wire.rationale,
            queue_wall_ms: wire.queue_wall_ms,
            judgement_wall_ms: wire.judgement_wall_ms,
            execution_wall_ms: wire.execution_wall_ms,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl OutcomeRecord {
    /// Construct execution evidence that is safe to place in an adapter snapshot.
    ///
    /// # Errors
    /// Refuses measured execution for refused or unknown outcomes as
    /// `execute-command-record-shape`.
    pub fn new(
        binding: Binding,
        outcome: Outcome,
        rationale: Text,
        queue_wall_ms: Option<u64>,
        judgement_wall_ms: Option<u64>,
        execution_wall_ms: Option<u64>,
    ) -> Result<Self, ShapeError> {
        let record = Self {
            binding,
            outcome,
            rationale,
            queue_wall_ms,
            judgement_wall_ms,
            execution_wall_ms,
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }

    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    #[must_use]
    pub const fn rationale(&self) -> &Text {
        &self.rationale
    }

    #[must_use]
    pub const fn queue_wall_ms(&self) -> Option<u64> {
        self.queue_wall_ms
    }

    #[must_use]
    pub const fn judgement_wall_ms(&self) -> Option<u64> {
        self.judgement_wall_ms
    }

    #[must_use]
    pub const fn execution_wall_ms(&self) -> Option<u64> {
        self.execution_wall_ms
    }

    /// Validate measured execution evidence; null walls explicitly mean unmeasured.
    ///
    /// # Errors
    /// Refuses measured execution for refused or unknown outcomes as
    /// `execute-command-record-shape`.
    pub const fn validate(&self) -> Result<(), ShapeError> {
        if self.execution_wall_ms.is_some()
            && matches!(
                self.outcome,
                Outcome::RefusedBeforeEffect | Outcome::OutcomeUnknown
            )
        {
            return Err(ShapeError("execute-command-record-shape"));
        }
        Ok(())
    }
}

/// Adapter-local monotone revision for atomic compare-and-commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision(pub u64);

/// A bounded semantic write, validated before reaching the adapter.
///
/// `expected = None` means create only if absent; a revision means replace only
/// that revision. The adapter must also enforce custody and authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionalCommit {
    operation_id: Text,
    expected: Option<Revision>,
    verdict: Verdict,
}

impl ConditionalCommit {
    /// Construct a bounded, actionable judgement publication.
    ///
    /// # Errors
    /// Refuses an invalid verdict as `execute-command-verdict-shape`.
    pub fn new(
        operation_id: Text,
        expected: Option<Revision>,
        verdict: Verdict,
    ) -> Result<Self, ShapeError> {
        verdict.validate()?;
        Ok(Self {
            operation_id,
            expected,
            verdict,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> &Text {
        &self.operation_id
    }

    #[must_use]
    pub const fn expected(&self) -> Option<Revision> {
        self.expected
    }

    #[must_use]
    pub const fn verdict(&self) -> &Verdict {
        &self.verdict
    }
}

/// Identity and revision shared by intent, claim and completion requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub binding: Binding,
    pub operation_id: Text,
    pub expected: Revision,
}

/// Persist the identity of the intended effect before any claim or execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    pub transition: Transition,
    pub effect_digest: Text,
}

/// Consume the single execution opportunity represented by a durable intent.
///
/// A duplicate request must not return a fresh executable grant. The adapter
/// returns the existing custody through load, or refuses a second claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub transition: Transition,
    pub intent_operation_id: Text,
    pub claimant: Text,
}

/// Durable custody identity required to attach an execution outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimReceipt {
    pub binding: Binding,
    pub operation_id: Text,
    pub claimant: Text,
    pub revision: Revision,
}

/// Complete exactly the claimed attempt, retaining explicit outcome uncertainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Completion {
    transition: Transition,
    claim: ClaimReceipt,
    outcome: OutcomeRecord,
}

impl Completion {
    /// Bind completion to the request and its current claim revision.
    ///
    /// # Errors
    /// Refuses mismatched identity or revision as `execute-command-record-shape`.
    /// Refuses invalid execution evidence as `execute-command-record-shape`.
    pub fn new(
        transition: Transition,
        claim: ClaimReceipt,
        outcome: OutcomeRecord,
    ) -> Result<Self, ShapeError> {
        outcome.validate()?;
        let identity_matches =
            transition.binding == claim.binding && transition.binding == outcome.binding;
        if !identity_matches || transition.expected != claim.revision {
            return Err(ShapeError("execute-command-record-shape"));
        }
        Ok(Self {
            transition,
            claim,
            outcome,
        })
    }

    #[must_use]
    pub const fn transition(&self) -> &Transition {
        &self.transition
    }

    #[must_use]
    pub const fn claim(&self) -> &ClaimReceipt {
        &self.claim
    }

    #[must_use]
    pub const fn outcome(&self) -> &OutcomeRecord {
        &self.outcome
    }
}

/// Evidence required to resolve a possibly published write before retrying.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UncertainCommit {
    pub binding: Binding,
    pub operation_id: Text,
    pub expected: Option<Revision>,
}

/// Reads either current state or the durable disposition of one uncertain write.
///
/// A current read of the record with an unresolved publication returns
/// `CommitUncertain` with that operation's identity, never a possibly unpublished
/// snapshot as durable. A different binding must not receive its uncertainty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Load {
    Current(Binding),
    Resolve(UncertainCommit),
}

/// A resolution establishes durability, not merely visibility after rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolution {
    Committed,
    NotCommitted,
}

/// Bounded current state; the adapter keeps any longer history in its own store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub revision: Revision,
    pub verdict: Verdict,
    pub intent: Option<Intent>,
    pub claim: Option<ClaimReceipt>,
    pub outcome: Option<OutcomeRecord>,
}

/// Load evidence identifies the exact uncertain operation when resolving it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Loaded {
    pub snapshot: Option<Snapshot>,
    pub resolution: Option<(UncertainCommit, Resolution)>,
}

/// Named persistence refusals never imply that a possibly published write failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Conflict,
    Authority,
    Capacity,
    InvalidTransition,
    Storage,
    ReadBeforeRetry,
    ClaimUsed,
}

impl Refusal {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Conflict => "execute-command-commit-conflict",
            Self::Authority => "execute-command-persistence-authority",
            Self::Capacity => "execute-command-persistence-capacity",
            Self::InvalidTransition => "execute-command-record-transition",
            Self::Storage => "execute-command-persistence-storage",
            Self::ReadBeforeRetry => "execute-command-read-before-retry",
            Self::ClaimUsed => "execute-command-claim-used",
        }
    }
}

/// An unchanged refusal, a durable result, or a write whose durability is unknown.
///
/// Only `Durable` can authorize the next transition. `Refused` guarantees no
/// partial semantic update, stranded intent or consumed claim. `CommitUncertain`
/// requires `Load::Resolve` before any retry or effect; if recovery cannot prove
/// durability, it must return uncertainty again. A resolved claim is custody
/// evidence, never permission to replay an attempt of unknown execution outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistenceResult<T> {
    Durable(T),
    Refused(Refusal),
    CommitUncertain(UncertainCommit),
}

/// Persistence contract for caller-owned stores, journals and channels.
///
/// All requests have bounded typed fields and fixed semantic operations. Each
/// mutation atomically compares identity, revision and transition preconditions
/// under caller custody, then publishes all of the update or none. The adapter
/// validates authority and common-record rules without redefining these command
/// transitions. Operation identities must not be reused for different writes.
/// No mutation closure, arbitrary JSON update or request-core type crosses here.
pub trait Persistence {
    /// Current reads preserve uncertainty until `Load::Resolve` proves disposition.
    fn load(&mut self, request: Load) -> PersistenceResult<Loaded>;
    fn commit(&mut self, request: ConditionalCommit) -> PersistenceResult<Revision>;
    fn intent(&mut self, request: Intent) -> PersistenceResult<Revision>;
    fn claim(&mut self, request: Claim) -> PersistenceResult<ClaimReceipt>;
    fn complete(&mut self, request: Completion) -> PersistenceResult<Revision>;
}
