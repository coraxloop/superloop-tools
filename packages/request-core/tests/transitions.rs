use request_core::{Collection, Kind, Request, State, request_id};
use serde_json::{Value, json};

fn kinds() -> [Kind<'static>; 2] {
    [
        Kind {
            name: "label",
            service: false,
            body: Value::is_object,
            answer: |_, answer| {
                answer.as_object().is_some_and(|object| {
                    object.len() == 1
                        && matches!(answer["outcome"].as_str(), Some("allow" | "refuse"))
                })
            },
        },
        Kind {
            name: "effect",
            service: true,
            body: Value::is_object,
            answer: |_, answer| matches!(answer["outcome"].as_str(), Some("allow" | "refuse")),
        },
    ]
}

fn collection() -> Collection {
    let mut collection = Collection::default();
    for kind in ["label", "effect"] {
        collection
            .file(
                Request::filed(
                    request_id(kind.as_bytes()),
                    kind.to_owned(),
                    json!({}),
                    "worker".to_owned(),
                    "run".to_owned(),
                    1,
                ),
                &kinds(),
            )
            .expect("file");
    }
    collection
}

fn mark(id: &str) -> Value {
    json!({"schema":1,"items":[{"id":id,"mark_for_review":true}]})
}
fn decide(id: &str) -> Value {
    json!({"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"allow"},"reason":"reviewed"}}]})
}

/// ´test:integration:persisted-request-requires-every-key-including-nullable-fields´
#[test]
fn persisted_request_requires_every_key_including_nullable_fields() {
    let original = collection();
    let encoded = serde_json::to_value(&original).expect("serialize collection");
    let row = encoded["requests"][0].as_object().expect("request object");
    assert_eq!(
        serde_json::from_value::<Collection>(encoded.clone()).expect("complete keys"),
        original
    );
    for key in row.keys() {
        let mut missing = encoded.clone();
        missing["requests"][0]
            .as_object_mut()
            .expect("request object")
            .remove(key);
        assert!(
            serde_json::from_value::<Collection>(missing).is_err(),
            "missing {key}"
        );
    }
}

/// ´test:integration:atomic-triage-refuses-every-member-before-changing-any-record´
#[test]
fn atomic_triage_refuses_every_member_before_changing_any_record() {
    let original = collection();
    let id = original.requests[0].id.clone();
    let good = decide(&id)["items"][0].clone();
    for bad in [
        good.clone(),
        json!({"id":"f".repeat(64),"mark_for_review":true}),
        json!({"id":original.requests[1].id,"mark_for_review":false}),
        json!({"id":original.requests[1].id,"decision":{"answer":{},"reason":" "}}),
    ] {
        let mut candidate = original.clone();
        assert!(
            candidate
                .triage(&json!({"schema":1,"items":[good,bad]}), &kinds())
                .is_err()
        );
        assert_eq!(candidate, original);
    }
    let mut candidate = original;
    assert_eq!(
        candidate.triage(&mark(&id), &kinds()).expect("mark"),
        json!({"applied":1,"decided":0,"marked":1})
    );
    let marked = candidate.clone();
    assert!(candidate.triage(&mark(&id), &kinds()).is_err());
    assert_eq!(candidate, marked);
    assert_eq!(
        candidate
            .triage(&decide(&id), &kinds())
            .expect("decide marked"),
        json!({"applied":1,"decided":1,"marked":0})
    );
    let decided = candidate.clone();
    assert!(candidate.triage(&decide(&id), &kinds()).is_err());
    assert_eq!(candidate, decided);
}

/// ´test:integration:review-is-monotonic-and-stale-adjudication-is-write-free´
#[test]
fn review_is_monotonic_and_stale_adjudication_is_write_free() {
    let mut collection = collection();
    let id = collection.requests[0].id.clone();
    assert!(collection.review(&id, 1).is_err());
    collection.triage(&mark(&id), &kinds()).expect("mark");
    let before = collection.list(false, 100);
    let first = collection
        .review(&id, 100)
        .expect("review")
        .review
        .expect("identity");
    let second = collection
        .review(&id, 99)
        .expect("review")
        .review
        .expect("identity");
    assert_eq!(second.at_ns, 101);
    assert_eq!(second.at, "1970-01-01T00:00:00.000000101Z");
    assert_ne!(first.review_id, second.review_id);
    assert_eq!(collection.list(false, 100), before);
    let mut adjudication = json!({"schema":1,"id":id,"review_id":first.review_id,"decision":{"answer":{"outcome":"allow"},"reason":"reviewed"}});
    let before = collection.clone();
    assert!(collection.adjudicate(&adjudication, &kinds()).is_err());
    assert_eq!(collection, before);
    adjudication["review_id"] = json!(second.review_id);
    let request = collection
        .adjudicate(&adjudication, &kinds())
        .expect("current view");
    assert_eq!(request.state, State::Adjudicated);
    assert!(request.answer().is_some());
    collection.validate(&kinds()).expect("valid record");
}

/// ´test:integration:service-claims-and-results-are-idempotent-and-lost-waiters-grant-nothing´
#[test]
fn service_claims_and_results_are_idempotent_and_lost_waiters_grant_nothing() {
    for gone in [false, true] {
        let mut collection = collection();
        let id = collection.requests[1].id.clone();
        assert!(collection.claim(&id, "service-generation").is_err());
        collection.triage(&decide(&id), &kinds()).expect("decision");
        assert_eq!(collection.requests[1].state, State::ServicePending);
        assert!(collection.requests[1].answer().is_none());
        if gone {
            collection.waiter_gone(&id).expect("gone");
        }
        assert_eq!(
            collection.claim(&id, "service-generation").expect("claim"),
            !gone
        );
        assert!(
            !collection
                .claim(&id, "service-generation")
                .expect("repeat claim")
        );
        assert!(collection.claim(&id, "another-service").is_err());
        if !gone {
            let result = json!({"performed":true});
            collection
                .complete(&id, "service-generation", result.clone())
                .expect("complete");
            collection
                .complete(&id, "service-generation", result)
                .expect("idempotent complete");
            assert!(
                collection
                    .complete(&id, "service-generation", json!({"performed":false}))
                    .is_err()
            );
        }
        assert_eq!(collection.requests[1].state, State::Completed);
        assert_eq!(collection.requests[1].answer().is_some(), !gone);
        collection.validate(&kinds()).expect("valid record");
    }
}

/// ´test:integration:request-status-counts-pending-kinds-and-uses-null-for-no-waiter´
#[test]
fn request_status_counts_pending_kinds_and_uses_null_for_no_waiter() {
    let empty = Collection::default();
    assert!(empty.status(false, 10)["oldest_waiting_age"].is_null());
    let mut collection = collection();
    let id = collection.requests[0].id.clone();
    collection.triage(&decide(&id), &kinds()).expect("decision");
    assert_eq!(
        collection.list(true, 3_000_000_001)["requests"]
            .as_array()
            .expect("rows")
            .len(),
        1
    );
    assert_eq!(
        collection.status(true, 3_000_000_001)["oldest_waiting_age"],
        3
    );
}

/// ´test:integration:stored-service-decisions-cannot-skip-the-required-result´
#[test]
fn stored_service_decisions_cannot_skip_the_required_result() {
    let mut collection = collection();
    let id = collection.requests[1].id.clone();
    collection.triage(&decide(&id), &kinds()).expect("decision");
    for state in [
        State::Filed,
        State::Marked,
        State::TriageDecided,
        State::Adjudicated,
        State::Completed,
    ] {
        let mut malformed = collection.clone();
        malformed.requests[1].state = state;
        assert!(malformed.validate(&kinds()).is_err(), "{state:?}");
    }
    let mut malformed = collection.clone();
    malformed.requests[1].decision_state = Some(State::Adjudicated);
    assert!(malformed.validate(&kinds()).is_err());
}
