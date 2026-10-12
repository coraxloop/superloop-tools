use std::collections::BTreeSet;

use execute_command::record::{
    Claim, ClaimReceipt, Completion, ConditionalCommit, Intent, Load, Loaded, Outcome,
    OutcomeRecord, Persistence, PersistenceResult, Refusal, Resolution, Revision, Snapshot,
    Transition, UncertainCommit,
};
use execute_command::request::{Binding, Judgement, Text, Verdict};
use serde_json::json;

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Refuse,
    UncertainBefore,
    UncertainAfter,
}

/// One bounded record with atomic staging and explicit durability fault injection.
#[derive(Default)]
struct Memory {
    row: Option<Snapshot>,
    operations: BTreeSet<String>,
    unresolved: Option<UncertainCommit>,
    fault: Fault,
    events: Vec<&'static str>,
}

impl Memory {
    fn guard(&self, transition: &Transition) -> Result<Snapshot, Refusal> {
        if self.unresolved.is_some() {
            return Err(Refusal::ReadBeforeRetry);
        }
        let row = self.row.clone().ok_or(Refusal::Conflict)?;
        if row.revision != transition.expected || row.verdict.binding != transition.binding {
            return Err(Refusal::Conflict);
        }
        if self.operations.contains(transition.operation_id.as_str()) {
            return Err(Refusal::InvalidTransition);
        }
        Ok(row)
    }

    fn publish<T>(
        &mut self,
        identity: UncertainCommit,
        staged: Snapshot,
        value: T,
    ) -> PersistenceResult<T> {
        self.events.push("write");
        let fault = std::mem::take(&mut self.fault);
        if matches!(fault, Fault::Refuse) {
            return PersistenceResult::Refused(Refusal::Storage);
        }
        if !matches!(fault, Fault::UncertainBefore) {
            self.operations
                .insert(identity.operation_id.as_str().to_owned());
            self.row = Some(staged);
        }
        if matches!(fault, Fault::UncertainBefore | Fault::UncertainAfter) {
            self.unresolved = Some(identity.clone());
            return PersistenceResult::CommitUncertain(identity);
        }
        PersistenceResult::Durable(value)
    }
}

fn uncertainty(transition: &Transition) -> UncertainCommit {
    UncertainCommit {
        binding: transition.binding.clone(),
        operation_id: transition.operation_id.clone(),
        expected: Some(transition.expected),
    }
}

impl Persistence for Memory {
    fn load(&mut self, request: Load) -> PersistenceResult<Loaded> {
        self.events.push("read");
        let (binding, resolution) = match request {
            Load::Current(binding) => {
                if self
                    .row
                    .as_ref()
                    .is_some_and(|row| row.verdict.binding != binding)
                    || self
                        .unresolved
                        .as_ref()
                        .is_some_and(|identity| identity.binding != binding)
                {
                    return PersistenceResult::Refused(Refusal::Conflict);
                }
                if let Some(identity) = &self.unresolved {
                    return PersistenceResult::CommitUncertain(identity.clone());
                }
                (binding, None)
            }
            Load::Resolve(identity) => {
                if self.unresolved.as_ref() != Some(&identity) {
                    return PersistenceResult::Refused(Refusal::InvalidTransition);
                }
                // The fixture can prove durability from its committed operation set.
                // A real adapter must establish it through its own recovery protocol.
                let disposition = if self.operations.contains(identity.operation_id.as_str()) {
                    Resolution::Committed
                } else {
                    Resolution::NotCommitted
                };
                self.unresolved = None;
                (identity.binding.clone(), Some((identity, disposition)))
            }
        };
        if self
            .row
            .as_ref()
            .is_some_and(|row| row.verdict.binding != binding)
        {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        PersistenceResult::Durable(Loaded {
            snapshot: self.row.clone(),
            resolution,
        })
    }

    fn commit(&mut self, request: ConditionalCommit) -> PersistenceResult<Revision> {
        if self.unresolved.is_some() {
            return PersistenceResult::Refused(Refusal::ReadBeforeRetry);
        }
        if self.row.as_ref().map(|row| row.revision) != request.expected() {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        if self.operations.contains(request.operation_id().as_str())
            || self.row.as_ref().is_some_and(|row| {
                row.verdict.binding != request.verdict().binding || row.intent.is_some()
            })
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        let revision = Revision(request.expected().map_or(1, |r| r.0 + 1));
        let staged = Snapshot {
            revision,
            verdict: request.verdict().clone(),
            intent: None,
            claim: None,
            outcome: None,
        };
        let identity = UncertainCommit {
            binding: request.verdict().binding.clone(),
            operation_id: request.operation_id().clone(),
            expected: request.expected(),
        };
        self.publish(identity, staged, revision)
    }

    fn intent(&mut self, request: Intent) -> PersistenceResult<Revision> {
        let mut staged = match self.guard(&request.transition) {
            Ok(row) => row,
            Err(reason) => return PersistenceResult::Refused(reason),
        };
        if staged.verdict.judgement != Judgement::Allow || staged.intent.is_some() {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        staged.revision.0 += 1;
        let revision = staged.revision;
        let identity = uncertainty(&request.transition);
        staged.intent = Some(request);
        self.publish(identity, staged, revision)
    }

    fn claim(&mut self, request: Claim) -> PersistenceResult<ClaimReceipt> {
        let mut staged = match self.guard(&request.transition) {
            Ok(row) => row,
            Err(reason) => return PersistenceResult::Refused(reason),
        };
        if staged.claim.is_some() {
            return PersistenceResult::Refused(Refusal::ClaimUsed);
        }
        if staged
            .intent
            .as_ref()
            .map(|intent| &intent.transition.operation_id)
            != Some(&request.intent_operation_id)
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        staged.revision.0 += 1;
        let receipt = ClaimReceipt {
            binding: request.transition.binding.clone(),
            operation_id: request.transition.operation_id.clone(),
            claimant: request.claimant,
            revision: staged.revision,
        };
        staged.claim = Some(receipt.clone());
        self.publish(uncertainty(&request.transition), staged, receipt)
    }

    fn complete(&mut self, request: Completion) -> PersistenceResult<Revision> {
        let mut staged = match self.guard(request.transition()) {
            Ok(row) => row,
            Err(reason) => return PersistenceResult::Refused(reason),
        };
        if staged.claim.as_ref() != Some(request.claim()) || staged.outcome.is_some() {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        staged.revision.0 += 1;
        staged.outcome = Some(request.outcome().clone());
        let revision = staged.revision;
        self.publish(uncertainty(request.transition()), staged, revision)
    }
}

fn text(value: &str) -> Text {
    value.to_owned().try_into().unwrap()
}

fn binding() -> Binding {
    Binding {
        request_id: text("request-1"),
        context_digest: text("context-1"),
    }
}

fn commit() -> ConditionalCommit {
    let verdict = Verdict::from_json(json!({"binding":{"request_id":"request-1","context_digest":"context-1"},
        "judgement":"allow","tier":"deterministic-checks","scope":"loop","reason":"registered fixture",
        "evidence":[],"correction":null,"escalation":null,"status":"valid"}).to_string().as_bytes()).unwrap();
    ConditionalCommit::new(text("commit-1"), None, verdict).unwrap()
}

fn transition(operation: &str, revision: u64) -> Transition {
    Transition {
        binding: binding(),
        operation_id: text(operation),
        expected: Revision(revision),
    }
}

fn intent() -> Intent {
    Intent {
        transition: transition("intent-1", 1),
        effect_digest: text("exact-effect"),
    }
}

fn claim() -> Claim {
    Claim {
        transition: transition("claim-1", 2),
        intent_operation_id: text("intent-1"),
        claimant: text("worker-1"),
    }
}

fn outcome() -> OutcomeRecord {
    OutcomeRecord::new(
        binding(),
        Outcome::OutcomeUnknown,
        text("transport lost after start; do not replay"),
        Some(0),
        Some(1),
        None,
    )
    .unwrap()
}

/// ´test:integration:outcome-walls-require-measured-evidence´
#[test]
fn outcome_walls_require_measured_evidence() {
    let receipt = ClaimReceipt {
        binding: binding(),
        operation_id: text("claim-1"),
        claimant: text("worker-1"),
        revision: Revision(3),
    };
    for kind in [Outcome::RefusedBeforeEffect, Outcome::OutcomeUnknown] {
        let record = OutcomeRecord::new(
            binding(),
            kind,
            text("no execution evidence"),
            Some(0),
            Some(1),
            None,
        )
        .unwrap();
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            serde_json::from_value::<OutcomeRecord>(value).unwrap(),
            record
        );
        assert!(
            Completion::new(transition("complete-1", 3), receipt.clone(), record.clone()).is_ok()
        );
        for measured in [0, 2] {
            assert_eq!(
                OutcomeRecord::new(
                    binding(),
                    kind,
                    text("no execution evidence"),
                    Some(0),
                    Some(1),
                    Some(measured)
                )
                .unwrap_err()
                .0,
                "execute-command-record-shape"
            );
            let mut invalid = serde_json::to_value(&record).unwrap();
            invalid["execution_wall_ms"] = json!(measured);
            assert!(
                serde_json::from_value::<OutcomeRecord>(invalid)
                    .unwrap_err()
                    .to_string()
                    .contains("execute-command-record-shape")
            );
        }
    }
    for kind in [
        Outcome::Completed,
        Outcome::Failed,
        Outcome::TimedOut,
        Outcome::Abandoned,
    ] {
        let record = OutcomeRecord::new(
            binding(),
            kind,
            text("observed completion"),
            Some(0),
            Some(1),
            Some(2),
        )
        .unwrap();
        assert_eq!(record.binding(), &binding());
        assert_eq!(record.outcome(), kind);
        assert_eq!(record.rationale().as_str(), "observed completion");
        assert_eq!(record.queue_wall_ms(), Some(0));
        assert_eq!(record.judgement_wall_ms(), Some(1));
        assert_eq!(record.execution_wall_ms(), Some(2));
        assert!(
            Completion::new(transition("complete-1", 3), receipt.clone(), record.clone()).is_ok()
        );
        assert_eq!(
            serde_json::from_value::<OutcomeRecord>(serde_json::to_value(&record).unwrap())
                .unwrap(),
            record
        );
    }
}

/// ´test:integration:outcome-walls-require-explicit-null´
#[test]
fn outcome_walls_require_explicit_null() {
    let record = OutcomeRecord::new(
        binding(),
        Outcome::OutcomeUnknown,
        text("unmeasured"),
        None,
        None,
        None,
    )
    .unwrap();
    let original = serde_json::to_value(&record).unwrap();
    assert_eq!(
        serde_json::from_value::<OutcomeRecord>(original.clone()).unwrap(),
        record
    );
    for field in ["queue_wall_ms", "judgement_wall_ms", "execution_wall_ms"] {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<OutcomeRecord>(missing).is_err());
    }
}

/// ´test:integration:refused-commit-leaves-no-stranded-state´
#[test]
fn refused_commit_leaves_no_stranded_state() {
    let mut store = Memory {
        fault: Fault::Refuse,
        ..Memory::default()
    };
    assert_eq!(
        store.commit(commit()),
        PersistenceResult::Refused(Refusal::Storage)
    );
    assert!(store.row.is_none());
    assert!(store.operations.is_empty());
    assert_eq!(
        store.commit(commit()),
        PersistenceResult::Durable(Revision(1))
    );
    let before = store.row.clone();
    store.fault = Fault::Refuse;
    assert_eq!(
        store.intent(intent()),
        PersistenceResult::Refused(Refusal::Storage)
    );
    assert_eq!(store.row, before);
    assert!(!store.operations.contains("intent-1"));
    assert_eq!(
        store.intent(intent()),
        PersistenceResult::Durable(Revision(2))
    );
    let before = store.row.clone();
    store.fault = Fault::Refuse;
    assert_eq!(
        store.claim(claim()),
        PersistenceResult::Refused(Refusal::Storage)
    );
    assert_eq!(store.row, before);
    assert!(!store.operations.contains("claim-1"));
    assert!(matches!(
        store.claim(claim()),
        PersistenceResult::Durable(_)
    ));
}

/// ´test:integration:uncertain-commit-is-read-before-retry´
#[test]
fn uncertain_commit_is_read_before_retry() {
    for (fault, expected) in [
        (Fault::UncertainBefore, Resolution::NotCommitted),
        (Fault::UncertainAfter, Resolution::Committed),
    ] {
        let mut store = Memory {
            fault,
            ..Memory::default()
        };
        let PersistenceResult::CommitUncertain(identity) = store.commit(commit()) else {
            panic!("uncertainty required")
        };
        assert_eq!(
            store.commit(commit()),
            PersistenceResult::Refused(Refusal::ReadBeforeRetry)
        );
        assert_eq!(
            store.intent(intent()),
            PersistenceResult::Refused(Refusal::ReadBeforeRetry)
        );
        // A normal read does not resolve the exact uncertain operation.
        assert_eq!(
            store.load(Load::Current(binding())),
            PersistenceResult::CommitUncertain(identity.clone())
        );
        assert_eq!(
            store.commit(commit()),
            PersistenceResult::Refused(Refusal::ReadBeforeRetry)
        );
        let PersistenceResult::Durable(loaded) = store.load(Load::Resolve(identity.clone())) else {
            panic!("resolved read")
        };
        assert_eq!(loaded.resolution, Some((identity, expected)));
        if expected == Resolution::NotCommitted {
            assert!(loaded.snapshot.is_none());
            assert_eq!(
                store.commit(commit()),
                PersistenceResult::Durable(Revision(1))
            );
            assert_eq!(store.events, ["write", "read", "read", "write"]);
        } else {
            assert_eq!(loaded.snapshot.unwrap().revision, Revision(1));
            assert_eq!(
                store.commit(commit()),
                PersistenceResult::Refused(Refusal::Conflict)
            );
            assert_eq!(store.events, ["write", "read", "read"]);
        }
    }
}

/// ´test:integration:claim-is-single-use-and-completion-is-bound´
#[test]
fn claim_is_single_use_and_completion_is_bound() {
    let mut store = Memory::default();
    assert_eq!(
        store.claim(claim()),
        PersistenceResult::Refused(Refusal::Conflict)
    );
    assert_eq!(
        store.commit(commit()),
        PersistenceResult::Durable(Revision(1))
    );
    assert_eq!(
        store.intent(intent()),
        PersistenceResult::Durable(Revision(2))
    );
    let PersistenceResult::Durable(receipt) = store.claim(claim()) else {
        panic!("durable claim")
    };
    assert_eq!(
        store.claim(claim()),
        PersistenceResult::Refused(Refusal::Conflict)
    );
    let mut second = claim();
    second.transition = transition("claim-2", 3);
    assert_eq!(
        store.claim(second),
        PersistenceResult::Refused(Refusal::ClaimUsed)
    );
    let mut wrong_binding = binding();
    wrong_binding.context_digest = text("stale");
    let wrong = OutcomeRecord::new(
        wrong_binding,
        Outcome::OutcomeUnknown,
        text("unknown"),
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        Completion::new(transition("complete-1", 3), receipt.clone(), wrong)
            .unwrap_err()
            .0,
        "execute-command-record-shape"
    );
    let completed =
        Completion::new(transition("complete-1", 3), receipt.clone(), outcome()).unwrap();
    let before = store.row.clone();
    store.fault = Fault::Refuse;
    assert_eq!(
        store.complete(completed.clone()),
        PersistenceResult::Refused(Refusal::Storage)
    );
    assert_eq!(store.row, before);
    assert_eq!(
        store.complete(completed.clone()),
        PersistenceResult::Durable(Revision(4))
    );
    assert_eq!(
        store.complete(completed),
        PersistenceResult::Refused(Refusal::Conflict)
    );
    let row = store.row.unwrap();
    assert_eq!(row.claim, Some(receipt));
    assert_eq!(row.outcome, Some(outcome()));
}

/// ´test:integration:uncertain-claim-does-not-grant-a-second-attempt´
#[test]
fn uncertain_claim_does_not_grant_a_second_attempt() {
    let mut store = Memory::default();
    assert_eq!(
        store.commit(commit()),
        PersistenceResult::Durable(Revision(1))
    );
    assert_eq!(
        store.intent(intent()),
        PersistenceResult::Durable(Revision(2))
    );
    store.fault = Fault::UncertainAfter;
    let PersistenceResult::CommitUncertain(identity) = store.claim(claim()) else {
        panic!("uncertain claim")
    };
    assert_eq!(
        store.claim(claim()),
        PersistenceResult::Refused(Refusal::ReadBeforeRetry)
    );
    assert_eq!(
        store.load(Load::Current(binding())),
        PersistenceResult::CommitUncertain(identity.clone())
    );
    let PersistenceResult::Durable(loaded) = store.load(Load::Resolve(identity)) else {
        panic!("recovery")
    };
    assert_eq!(loaded.resolution.unwrap().1, Resolution::Committed);
    let receipt = loaded.snapshot.unwrap().claim.unwrap();
    assert_eq!(
        store.claim(claim()),
        PersistenceResult::Refused(Refusal::Conflict)
    );
    let completion = Completion::new(transition("complete-1", 3), receipt, outcome()).unwrap();
    assert_eq!(
        store.complete(completion),
        PersistenceResult::Durable(Revision(4))
    );
}

/// ´test:integration:uncertainty-is-scoped-to-the-requested-record´
#[test]
fn uncertainty_is_scoped_to_the_requested_record() {
    for fault in [Fault::UncertainBefore, Fault::UncertainAfter] {
        let mut store = Memory {
            fault,
            ..Memory::default()
        };
        let PersistenceResult::CommitUncertain(identity) = store.commit(commit()) else {
            panic!("uncertain publication required")
        };
        for other in [
            Binding {
                request_id: text("request-2"),
                ..binding()
            },
            Binding {
                context_digest: text("context-2"),
                ..binding()
            },
        ] {
            assert_eq!(
                store.load(Load::Current(other)),
                PersistenceResult::Refused(Refusal::Conflict)
            );
            assert_eq!(store.unresolved, Some(identity.clone()));
        }
        assert_eq!(
            store.load(Load::Current(binding())),
            PersistenceResult::CommitUncertain(identity)
        );
    }
}
