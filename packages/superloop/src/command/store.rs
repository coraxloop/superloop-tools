//! Direct-call custody translates typed command operations into request-core.

use std::fs::File;

use execute_command::escalation::{Answer, ReviewAnswer};
use execute_command::record::{
    Claim, ClaimReceipt, Completion, ConditionalCommit, Intent, Load, Loaded, Outcome,
    OutcomeRecord, Persistence, PersistenceResult, Refusal, Resolution, Revision, Snapshot,
    Transition, UncertainCommit,
};
use execute_command::request::{Binding, Judgement, Request, Text, Verdict};
use request_core::{Collection, Kind, Request as CommonRequest, transaction::Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Authority, Error, text};

const FILE: &str = "command-requests.jsonl";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedIntent {
    operation_id: Text,
    effect_digest: Text,
    expected: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedClaim {
    operation_id: Text,
    claimant: Text,
    revision: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    request: Value,
    verdict: Verdict,
    principal: Text,
    registration: Text,
    snapshot_digest: Text,
    revision: u64,
    operations: Vec<Text>,
    #[serde(deserialize_with = "required_nullable")]
    answer: Option<Answer>,
    #[serde(deserialize_with = "required_nullable")]
    intent: Option<SavedIntent>,
    #[serde(deserialize_with = "required_nullable")]
    claim: Option<SavedClaim>,
    #[serde(deserialize_with = "required_nullable")]
    outcome: Option<OutcomeRecord>,
}

impl Row {
    fn snapshot(&self) -> Snapshot {
        let binding = self.verdict.binding.clone();
        Snapshot {
            revision: Revision(self.revision),
            verdict: self.verdict.clone(),
            intent: self.intent.as_ref().map(|intent| Intent {
                transition: Transition {
                    binding: binding.clone(),
                    operation_id: intent.operation_id.clone(),
                    expected: Revision(intent.expected),
                },
                effect_digest: intent.effect_digest.clone(),
            }),
            claim: self.claim.as_ref().map(|claim| ClaimReceipt {
                binding,
                operation_id: claim.operation_id.clone(),
                claimant: claim.claimant.clone(),
                revision: Revision(claim.revision),
            }),
            outcome: self.outcome.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Database {
    schema: u32,
    collection: Collection,
    rows: Vec<Row>,
}

fn kinds() -> [Kind<'static>; 1] {
    [Kind {
        name: "direct-command",
        service: true,
        body: |value| {
            serde_json::to_vec(value).is_ok_and(|bytes| Request::from_json(&bytes).is_ok())
        },
        answer: |_, value| {
            value.as_object().is_some_and(|object| object.len() == 1)
                && matches!(value["outcome"].as_str(), Some("allow" | "refuse"))
        },
    }]
}

fn filed(binding: &Binding, source: &Value, authority: &Authority, now: u64) -> CommonRequest {
    CommonRequest::filed(
        binding.request_id.as_str().into(),
        "direct-command".into(),
        source.clone(),
        authority.principal.clone(),
        "direct".into(),
        now,
    )
}

impl Database {
    fn read(bytes: Option<&[u8]>) -> Result<Self, Error> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                schema: 1,
                collection: Collection {
                    schema: 1,
                    revision: 0,
                    requests: Vec::new(),
                },
                rows: Vec::new(),
            });
        };
        let database: Self = serde_json::from_slice(bytes).map_err(|_| Error::record())?;
        database.validate()?;
        Ok(database)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.schema != 1
            || self.rows.len() != self.collection.requests.len()
            || self.rows.len() > 4096
        {
            return Err(Error::record());
        }
        self.collection
            .validate(&kinds())
            .map_err(|_| Error::record())?;
        let mut seen = std::collections::BTreeSet::new();
        for row in &self.rows {
            let request =
                Request::from_json(&serde_json::to_vec(&row.request).map_err(|_| Error::record())?)
                    .map_err(|_| Error::record())?;
            let id = row.verdict.binding.request_id.as_str();
            let common = self
                .collection
                .requests
                .iter()
                .find(|common| common.id == id)
                .ok_or_else(Error::record)?;
            if !seen.insert(id)
                || common.body != row.request
                || request.binding() != &row.verdict.binding
                || !super::binding_valid(&request)
                || row.revision == 0
                || row.operations.is_empty()
                || row.operations.len() > 5
                || row
                    .operations
                    .iter()
                    .map(Text::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != row.operations.len()
                || (common.decision_state == Some(request_core::State::Adjudicated))
                    != row.answer.is_some()
                || row.answer.as_ref().is_some_and(|answer| {
                    answer.binding != row.verdict.binding
                        || answer.reason != row.verdict.reason
                        || answer.review.as_ref().map(Text::as_str)
                            != common
                                .review
                                .as_ref()
                                .map(|review| review.review_id.as_str())
                        || (answer.answer == ReviewAnswer::Approve)
                            != (row.verdict.judgement == Judgement::Allow)
                })
                || row.principal != request.context().requester
                || row.registration != request.context().registration
                || common.worker != row.principal.as_str()
                || common.decision.as_ref().is_some_and(|decision| {
                    decision.answer["outcome"]
                        != serde_json::to_value(row.verdict.judgement).unwrap_or(Value::Null)
                })
                || (row.verdict.judgement == Judgement::Refer) != common.decision.is_none()
                || row.claim.as_ref().is_some_and(|claim| {
                    common.service_claim.as_deref() != Some(claim.operation_id.as_str())
                        || claim.revision > row.revision
                        || row.intent.is_none()
                })
                || row
                    .outcome
                    .as_ref()
                    .is_some_and(|outcome| outcome.binding() != request.binding())
                || (common.state == request_core::State::Completed || row.claim.is_some())
                    != row.outcome.is_some()
                || row.claim.is_some() && row.verdict.judgement != Judgement::Allow
            {
                return Err(Error::record());
            }
            if let Some(outcome) = &row.outcome
                && ((common.state == request_core::State::Completed
                    && common.service_result.as_ref()
                        != Some(&serde_json::to_value(outcome).map_err(|_| Error::record())?))
                    || (common.state != request_core::State::Completed
                        && outcome.outcome() != Outcome::OutcomeUnknown)
                    || (row.verdict.judgement == Judgement::Refuse
                        && outcome.outcome() != Outcome::RefusedBeforeEffect))
            {
                return Err(Error::record());
            }
        }
        Ok(())
    }
}

pub struct Store<'a> {
    directory: &'a File,
    transaction: Transaction<'a>,
    database: Database,
    authority: &'a Authority,
    source: Option<Value>,
    answer: Option<Answer>,
    now: u64,
    uncertain: Option<UncertainCommit>,
}

impl<'a> Store<'a> {
    pub fn open(directory: &'a File, authority: &'a Authority, now: u64) -> Result<Self, Error> {
        let transaction =
            Transaction::open(directory, FILE, ".command-requests.lock").map_err(Error::storage)?;
        let database = Database::read(transaction.bytes())?;
        directory.sync_all().map_err(Error::storage)?;
        Ok(Self {
            directory,
            transaction,
            database,
            authority,
            source: None,
            answer: None,
            now,
            uncertain: None,
        })
    }

    pub fn prepare_source(&mut self, request: Value) {
        self.source = Some(request);
    }
    pub fn prepare_answer(&mut self, answer: Answer) {
        self.answer = Some(answer);
    }

    pub fn request(&self, binding: &Binding) -> Result<&Value, Error> {
        self.row(binding)
            .map(|row| &row.request)
            .ok_or_else(Error::record)
    }

    pub fn review(&self, binding: &Binding) -> Option<Text> {
        self.database
            .collection
            .requests
            .iter()
            .find(|row| row.id == binding.request_id.as_str())
            .and_then(|row| row.review.as_ref())
            .and_then(|review| Text::try_from(review.review_id.clone()).ok())
    }

    fn row(&self, binding: &Binding) -> Option<&Row> {
        self.database
            .rows
            .iter()
            .find(|row| row.verdict.binding == *binding)
    }

    pub fn require_current_policy(&self, binding: &Binding) -> Result<(), Error> {
        let row = self.row(binding).ok_or_else(Error::record)?;
        if row.snapshot_digest.as_str() != self.authority.snapshot_digest {
            return Err(Error::named(
                "execute-command-persistence-authority",
                "policy changed since judgement; file a fresh request before another effect",
            ));
        }
        Ok(())
    }

    fn admitted(&self, binding: &Binding, expected: u64, actor_only: bool) -> Result<(), Refusal> {
        let row = self.row(binding).ok_or(Refusal::Conflict)?;
        if row.registration.as_str() != self.authority.registration
            || row.principal.as_str() != self.authority.principal
                && (actor_only || self.authority.role != "orchestrator")
        {
            return Err(Refusal::Authority);
        }
        if row.revision != expected {
            return Err(Refusal::Conflict);
        }
        Ok(())
    }

    fn publish<T>(
        &mut self,
        mut next: Database,
        binding: &Binding,
        operation: &Text,
        expected: Option<Revision>,
        value: T,
    ) -> PersistenceResult<T> {
        if let Some(uncertain) = &self.uncertain {
            return PersistenceResult::CommitUncertain(uncertain.clone());
        }
        let Some(revision) = next.collection.revision.checked_add(1) else {
            return PersistenceResult::Refused(Refusal::Capacity);
        };
        next.collection.revision = revision;
        let Some(row) = next
            .rows
            .iter_mut()
            .find(|row| row.verdict.binding == *binding)
        else {
            return PersistenceResult::Refused(Refusal::Conflict);
        };
        if !row.operations.contains(operation) {
            row.operations.push(operation.clone());
        }
        if next.validate().is_err() {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        let Ok(mut bytes) = serde_json::to_vec(&next) else {
            return PersistenceResult::Refused(Refusal::Storage);
        };
        bytes.push(b'\n');
        if bytes.len() > 64 * 1024 * 1024 {
            return PersistenceResult::Refused(Refusal::Capacity);
        }
        match self.transaction.replace(&bytes) {
            Ok(()) => {
                self.database = next;
                PersistenceResult::Durable(value)
            }
            Err(error) if error.class == "requests-commit-uncertain" => {
                let uncertain = UncertainCommit {
                    binding: binding.clone(),
                    operation_id: operation.clone(),
                    expected,
                };
                self.database = next;
                self.uncertain = Some(uncertain.clone());
                PersistenceResult::CommitUncertain(uncertain)
            }
            Err(error) if error.class == "requests-conflict" => {
                PersistenceResult::Refused(Refusal::Conflict)
            }
            Err(_) => PersistenceResult::Refused(Refusal::Storage),
        }
    }
}

impl Persistence for Store<'_> {
    fn load(&mut self, request: Load) -> PersistenceResult<Loaded> {
        let (binding, resolving) = match &request {
            Load::Current(binding) => (binding, None),
            Load::Resolve(uncertain) => (&uncertain.binding, Some(uncertain)),
        };
        if let Some(row) = self.row(binding)
            && let Err(refusal) = self.admitted(binding, row.revision, false)
        {
            return PersistenceResult::Refused(refusal);
        }
        if self.database.rows.iter().any(|row| {
            row.verdict.binding.request_id == binding.request_id && row.verdict.binding != *binding
        }) {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        if resolving.is_none()
            && let Some(uncertain) = &self.uncertain
        {
            return PersistenceResult::CommitUncertain(uncertain.clone());
        }
        let resolution = if let Some(uncertain) = resolving {
            if self.directory.sync_all().is_err() {
                return PersistenceResult::CommitUncertain(uncertain.clone());
            }
            self.uncertain = None;
            Some((
                uncertain.clone(),
                if self
                    .row(binding)
                    .is_some_and(|row| row.operations.contains(&uncertain.operation_id))
                {
                    Resolution::Committed
                } else {
                    Resolution::NotCommitted
                },
            ))
        } else {
            None
        };
        PersistenceResult::Durable(Loaded {
            snapshot: self.row(binding).map(Row::snapshot),
            resolution,
        })
    }

    fn commit(&mut self, request: ConditionalCommit) -> PersistenceResult<Revision> {
        let binding = &request.verdict().binding;
        let mut next = self.database.clone();
        let revision = if let Some(expected) = request.expected() {
            if let Err(refusal) = self.admitted(binding, expected.0, false) {
                return PersistenceResult::Refused(refusal);
            }
            if self.authority.role != "orchestrator" {
                return PersistenceResult::Refused(Refusal::Authority);
            }
            let Some(row) = next
                .rows
                .iter_mut()
                .find(|row| row.verdict.binding == *binding)
            else {
                return PersistenceResult::Refused(Refusal::Conflict);
            };
            if row.verdict.judgement != Judgement::Refer
                || row.claim.is_some()
                || row.outcome.is_some()
            {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            }
            let Some(answer) = &self.answer else {
                return PersistenceResult::Refused(Refusal::Authority);
            };
            if answer.adjudicator.as_str() != self.authority.principal {
                return PersistenceResult::Refused(Refusal::Authority);
            }
            let document = json!({"schema":1,"id":answer.binding.request_id,"review_id":answer.review,"decision":{"answer":{"outcome":request.verdict().judgement},"reason":answer.reason}});
            if next.collection.adjudicate(&document, &kinds()).is_err() {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            }
            let Some(revision) = row.revision.checked_add(1) else {
                return PersistenceResult::Refused(Refusal::Capacity);
            };
            row.verdict = request.verdict().clone();
            row.revision = revision;
            row.answer = Some(answer.clone());
            revision
        } else {
            if next
                .rows
                .iter()
                .any(|row| row.verdict.binding.request_id == binding.request_id)
            {
                return PersistenceResult::Refused(Refusal::Conflict);
            }
            if next.rows.len() >= 4096 {
                return PersistenceResult::Refused(Refusal::Capacity);
            }
            let Some(source) = &self.source else {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            };
            let common = filed(binding, source, self.authority, self.now);
            if next.collection.file(common, &kinds()).is_err() {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            }
            let item = if request.verdict().judgement == Judgement::Refer {
                json!({"id":binding.request_id,"mark_for_review":true})
            } else {
                json!({"id":binding.request_id,"decision":{"answer":{"outcome":request.verdict().judgement},"reason":request.verdict().reason}})
            };
            if next
                .collection
                .triage(&json!({"schema":1,"items":[item]}), &kinds())
                .is_err()
            {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            }
            if request.verdict().judgement == Judgement::Refer
                && next
                    .collection
                    .review(binding.request_id.as_str(), self.now)
                    .is_err()
            {
                return PersistenceResult::Refused(Refusal::InvalidTransition);
            }
            let row = match new_row(source, &request, self.authority) {
                Ok(row) => row,
                Err(refusal) => return PersistenceResult::Refused(refusal),
            };
            next.rows.push(row);
            1
        };
        if let Err(refusal) = record_refusal(&mut next, request.verdict()) {
            return PersistenceResult::Refused(refusal);
        }
        self.publish(
            next,
            binding,
            request.operation_id(),
            request.expected(),
            Revision(revision),
        )
    }

    fn intent(&mut self, request: Intent) -> PersistenceResult<Revision> {
        let transition = &request.transition;
        if let Err(refusal) = self.admitted(&transition.binding, transition.expected.0, true) {
            return PersistenceResult::Refused(refusal);
        }
        let mut next = self.database.clone();
        let Some(row) = next
            .rows
            .iter_mut()
            .find(|row| row.verdict.binding == transition.binding)
        else {
            return PersistenceResult::Refused(Refusal::Conflict);
        };
        if row.verdict.judgement != Judgement::Allow
            || row.intent.is_some()
            || row.claim.is_some()
            || row.outcome.is_some()
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        let Some(revision) = row.revision.checked_add(1) else {
            return PersistenceResult::Refused(Refusal::Capacity);
        };
        row.intent = Some(SavedIntent {
            operation_id: transition.operation_id.clone(),
            effect_digest: request.effect_digest,
            expected: transition.expected.0,
        });
        row.revision = revision;
        self.publish(
            next,
            &transition.binding,
            &transition.operation_id,
            Some(transition.expected),
            Revision(revision),
        )
    }

    fn claim(&mut self, request: Claim) -> PersistenceResult<ClaimReceipt> {
        let transition = &request.transition;
        if let Err(refusal) = self.admitted(&transition.binding, transition.expected.0, true) {
            return PersistenceResult::Refused(refusal);
        }
        let mut next = self.database.clone();
        let Some(row) = next
            .rows
            .iter_mut()
            .find(|row| row.verdict.binding == transition.binding)
        else {
            return PersistenceResult::Refused(Refusal::Conflict);
        };
        if row.claim.is_some() {
            return PersistenceResult::Refused(Refusal::ClaimUsed);
        }
        if row.verdict.judgement != Judgement::Allow
            || row.outcome.is_some()
            || row
                .intent
                .as_ref()
                .is_none_or(|intent| intent.operation_id != request.intent_operation_id)
            || request.claimant.as_str() != self.authority.principal
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        if !matches!(
            next.collection.claim(
                transition.binding.request_id.as_str(),
                transition.operation_id.as_str()
            ),
            Ok(true)
        ) {
            return PersistenceResult::Refused(Refusal::ClaimUsed);
        }
        let Some(revision) = row.revision.checked_add(1) else {
            return PersistenceResult::Refused(Refusal::Capacity);
        };
        let receipt = ClaimReceipt {
            binding: transition.binding.clone(),
            operation_id: transition.operation_id.clone(),
            claimant: request.claimant,
            revision: Revision(revision),
        };
        row.claim = Some(SavedClaim {
            operation_id: receipt.operation_id.clone(),
            claimant: receipt.claimant.clone(),
            revision,
        });
        let Ok(rationale) = text("durable claim; caller execution has not been observed") else {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        };
        let Ok(outcome) = OutcomeRecord::new(
            transition.binding.clone(),
            Outcome::OutcomeUnknown,
            rationale,
            None,
            None,
            None,
        ) else {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        };
        row.outcome = Some(outcome);
        row.revision = revision;
        self.publish(
            next,
            &transition.binding,
            &transition.operation_id,
            Some(transition.expected),
            receipt,
        )
    }

    fn complete(&mut self, request: Completion) -> PersistenceResult<Revision> {
        let transition = request.transition();
        let Some(old) = self.row(&transition.binding) else {
            return PersistenceResult::Refused(Refusal::Conflict);
        };
        if let Err(refusal) = self.admitted(&transition.binding, old.revision, true) {
            return PersistenceResult::Refused(refusal);
        }
        if old.snapshot().claim.as_ref() != Some(request.claim()) {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        if let Some(outcome) = &old.outcome
            && self.database.collection.requests.iter().any(|row| {
                row.id == transition.binding.request_id.as_str()
                    && row.state == request_core::State::Completed
            })
        {
            return if outcome == request.outcome() {
                PersistenceResult::Durable(Revision(old.revision))
            } else {
                PersistenceResult::Refused(Refusal::InvalidTransition)
            };
        }
        if old.revision != transition.expected.0 {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        let mut next = self.database.clone();
        let Ok(result) = serde_json::to_value(request.outcome()) else {
            return PersistenceResult::Refused(Refusal::Storage);
        };
        if next
            .collection
            .complete(
                transition.binding.request_id.as_str(),
                request.claim().operation_id.as_str(),
                result,
            )
            .is_err()
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        let Some(row) = next
            .rows
            .iter_mut()
            .find(|row| row.verdict.binding == transition.binding)
        else {
            return PersistenceResult::Refused(Refusal::Conflict);
        };
        let Some(revision) = row.revision.checked_add(1) else {
            return PersistenceResult::Refused(Refusal::Capacity);
        };
        row.outcome = Some(request.outcome().clone());
        row.revision = revision;
        self.publish(
            next,
            &transition.binding,
            &transition.operation_id,
            Some(transition.expected),
            Revision(revision),
        )
    }
}

fn record_refusal(next: &mut Database, verdict: &Verdict) -> Result<(), Refusal> {
    let binding = &verdict.binding;
    if verdict.judgement == Judgement::Refuse {
        let claim = format!("no-effect:{}", binding.request_id.as_str());
        let outcome = OutcomeRecord::new(
            binding.clone(),
            Outcome::RefusedBeforeEffect,
            verdict.reason.clone(),
            None,
            None,
            None,
        );
        let Ok(outcome) = outcome else {
            return Err(Refusal::InvalidTransition);
        };
        let Ok(result) = serde_json::to_value(&outcome) else {
            return Err(Refusal::Storage);
        };
        if next
            .collection
            .claim(binding.request_id.as_str(), &claim)
            .is_err()
            || next
                .collection
                .complete(binding.request_id.as_str(), &claim, result)
                .is_err()
        {
            return Err(Refusal::InvalidTransition);
        }
        if let Some(row) = next
            .rows
            .iter_mut()
            .find(|row| row.verdict.binding == *binding)
        {
            row.outcome = Some(outcome);
        }
    }
    Ok(())
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn new_row(
    source: &Value,
    request: &ConditionalCommit,
    authority: &Authority,
) -> Result<Row, Refusal> {
    Ok(Row {
        request: source.clone(),
        verdict: request.verdict().clone(),
        principal: text(&authority.principal).map_err(|_| Refusal::Authority)?,
        registration: text(&authority.registration).map_err(|_| Refusal::Authority)?,
        snapshot_digest: text(&authority.snapshot_digest).map_err(|_| Refusal::Authority)?,
        revision: 1,
        operations: Vec::new(),
        answer: None,
        intent: None,
        claim: None,
        outcome: None,
    })
}
