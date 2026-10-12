//! The caller composes the two domains; neither tier-one crate imports the other.
use execute_command::record::{
    Claim, ClaimReceipt, Completion, ConditionalCommit, Intent, Load, Loaded, Outcome,
    OutcomeRecord, Persistence, PersistenceResult, Refusal, Revision, Transition,
};
use execute_command::request::{Binding, Text};
use request_core::{Collection, Kind, Request};
use serde_json::json;

struct Adapter {
    collection: Collection,
    binding: Binding,
}

impl Persistence for Adapter {
    fn load(&mut self, _: Load) -> PersistenceResult<Loaded> {
        PersistenceResult::Refused(Refusal::InvalidTransition)
    }
    fn commit(&mut self, _: ConditionalCommit) -> PersistenceResult<Revision> {
        PersistenceResult::Refused(Refusal::InvalidTransition)
    }
    fn intent(&mut self, _: Intent) -> PersistenceResult<Revision> {
        PersistenceResult::Refused(Refusal::InvalidTransition)
    }
    fn claim(&mut self, request: Claim) -> PersistenceResult<ClaimReceipt> {
        if request.transition.binding != self.binding
            || request.transition.expected.0 != self.collection.revision
        {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        let mut next = self.collection.clone();
        match next.claim(
            self.binding.request_id.as_str(),
            request.transition.operation_id.as_str(),
        ) {
            Ok(true) => {
                self.collection = next;
                self.collection.revision += 1;
                PersistenceResult::Durable(ClaimReceipt {
                    binding: self.binding.clone(),
                    operation_id: request.transition.operation_id,
                    claimant: request.claimant,
                    revision: Revision(self.collection.revision),
                })
            }
            Ok(false) => PersistenceResult::Refused(Refusal::ClaimUsed),
            Err(_) => PersistenceResult::Refused(Refusal::InvalidTransition),
        }
    }
    fn complete(&mut self, request: Completion) -> PersistenceResult<Revision> {
        if request.transition().binding != self.binding {
            return PersistenceResult::Refused(Refusal::Conflict);
        }
        let result = serde_json::to_value(request.outcome()).unwrap();
        let before = self.collection.clone();
        if self
            .collection
            .complete(
                self.binding.request_id.as_str(),
                request.claim().operation_id.as_str(),
                result,
            )
            .is_err()
        {
            return PersistenceResult::Refused(Refusal::InvalidTransition);
        }
        if self.collection != before {
            if request.transition().expected.0 != before.revision {
                self.collection = before;
                return PersistenceResult::Refused(Refusal::Conflict);
            }
            self.collection.revision += 1;
        }
        PersistenceResult::Durable(Revision(self.collection.revision))
    }
}

fn text(value: &str) -> Text {
    value.to_owned().try_into().unwrap()
}

fn adapter(gone: bool) -> Adapter {
    let id = request_core::request_id(b"command fixture");
    let kinds = [Kind {
        name: "command",
        service: true,
        body: serde_json::Value::is_object,
        answer: |_, answer| answer == &json!({"outcome":"approve"}),
    }];
    let mut collection = Collection::default();
    collection
        .file(
            Request::filed(
                id.clone(),
                "command".into(),
                json!({}),
                "worker".into(),
                "run".into(),
                1,
            ),
            &kinds,
        )
        .unwrap();
    collection.triage(&json!({"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"approve"},"reason":"registered command"}}]}), &kinds).unwrap();
    if gone {
        collection.waiter_gone(&id).unwrap();
    }
    Adapter {
        collection,
        binding: Binding {
            request_id: text(&id),
            context_digest: text("context"),
        },
    }
}

fn claim(adapter: &Adapter) -> Claim {
    Claim {
        transition: Transition {
            binding: adapter.binding.clone(),
            operation_id: text("claim"),
            expected: Revision(adapter.collection.revision),
        },
        intent_operation_id: text("intent"),
        claimant: text("service"),
    }
}

/// ´test:integration:command-persistence-uses-common-claim-and-completion´
#[test]
fn command_persistence_uses_common_claim_and_completion() {
    let mut adapter = adapter(false);
    let claim = claim(&adapter);
    let PersistenceResult::Durable(receipt) = adapter.claim(claim.clone()) else {
        panic!("first claim")
    };
    assert_eq!(
        adapter.claim(claim.clone()),
        PersistenceResult::Refused(Refusal::Conflict)
    );
    let mut second = claim;
    second.transition.expected = receipt.revision;
    assert_eq!(
        adapter.claim(second),
        PersistenceResult::Refused(Refusal::ClaimUsed)
    );
    let completion = Completion::new(
        Transition {
            binding: adapter.binding.clone(),
            operation_id: text("complete"),
            expected: receipt.revision,
        },
        receipt,
        OutcomeRecord::new(
            adapter.binding.clone(),
            Outcome::Completed,
            text("observed exit zero"),
            Some(0),
            Some(1),
            Some(2),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        adapter.complete(completion.clone()),
        PersistenceResult::Durable(Revision(2))
    );
    let before = adapter.collection.clone();
    assert_eq!(
        adapter.complete(completion),
        PersistenceResult::Durable(Revision(2))
    );
    assert_eq!(adapter.collection, before);
}

/// ´test:integration:command-persistence-refuses-departed-waiter´
#[test]
fn command_persistence_refuses_departed_waiter() {
    let mut adapter = adapter(true);
    let claim = claim(&adapter);
    let before = adapter.collection.clone();
    assert_eq!(
        adapter.claim(claim.clone()),
        PersistenceResult::Refused(Refusal::ClaimUsed)
    );
    // A refused persistence operation rolls back even request-core's terminal
    // waiter-gone projection; the recorded departure still forbids execution.
    assert_eq!(adapter.collection, before);
    assert_eq!(
        adapter.claim(claim),
        PersistenceResult::Refused(Refusal::ClaimUsed)
    );
    assert_eq!(adapter.collection, before);
}
