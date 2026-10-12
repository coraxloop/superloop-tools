use request_core::{Collection, Request, State, gateway, request_id};
use serde_json::{Value, json};

fn body() -> Value {
    json!({"schema":1,"loop_name":"owner","gateway_id":"a".repeat(64),
        "registration_digest":"b".repeat(64),"proposal":{"schema":1,"lane":"lane-a",
        "seq":7,"argv":["/bin/printf","exact argument"],"reason":"fixture",
        "queued_unix_ms":1,"timeout_seconds":60}})
}

fn filed(body: Value) -> Request {
    Request::filed(
        request_id(b"gateway/lane-a/7"),
        "gateway-proposal".into(),
        body,
        "lane-a".into(),
        "7".into(),
        1_000_000,
    )
}

/// ´test:integration:gateway-admission-binds-proposal-and-registration-evidence´
#[test]
fn gateway_admission_binds_proposal_and_registration_evidence() {
    let original = body();
    Collection::default()
        .file(filed(original.clone()), &[gateway::kind()])
        .expect("admit");
    for key in original.as_object().expect("body").keys() {
        let mut malformed = original.clone();
        malformed.as_object_mut().expect("body").remove(key);
        assert!(
            Collection::default()
                .file(filed(malformed), &[gateway::kind()])
                .is_err(),
            "missing {key}"
        );
    }
    for (key, value) in [
        ("argv", json!([])),
        ("argv", json!(["/bin/printf", "bad\u{0000}word"])),
        ("reason", json!(" ")),
        ("seq", json!(0)),
        ("timeout_seconds", json!(0)),
    ] {
        let mut malformed = original.clone();
        malformed["proposal"][key] = value;
        assert!(
            Collection::default()
                .file(filed(malformed), &[gateway::kind()])
                .is_err()
        );
    }
}

/// ´test:integration:gateway-promotion-belongs-only-to-approval-and-requires-a-service-result´
#[test]
fn gateway_promotion_belongs_only_to_approval_and_requires_a_service_result() {
    for answer in [
        json!({"outcome":"approve"}),
        json!({"outcome":"approve","promote":true}),
        json!({"outcome":"approve","promote":"checked-name"}),
        json!({"outcome":"deny"}),
        json!({"outcome":"abandon"}),
    ] {
        let mut collection = Collection::default();
        let row = filed(body());
        let id = row.id.clone();
        collection.file(row, &[gateway::kind()]).expect("file");
        collection.triage(&json!({"schema":1,"items":[{"id":id,"decision":{"answer":answer,"reason":"reviewed"}}]}), &[gateway::kind()]).expect("decide");
        assert_eq!(collection.requests[0].state, State::ServicePending);
        assert!(collection.requests[0].answer().is_none());
        assert!(
            collection
                .claim(&id, "gateway-generation")
                .expect("first claim")
        );
        assert!(
            !collection
                .claim(&id, "gateway-generation")
                .expect("repeat claim")
        );
        collection
            .complete(&id, "gateway-generation", json!({"projected":true}))
            .expect("complete");
        assert!(collection.requests[0].answer().is_some());
    }
    for answer in [
        json!({"outcome":"deny","promote":true}),
        json!({"outcome":"abandon","promote":"name"}),
        json!({"outcome":"approve","promote":false}),
        json!({"outcome":"approve","promote":"bad/name"}),
    ] {
        let mut collection = Collection::default();
        let row = filed(body());
        let id = row.id.clone();
        collection.file(row, &[gateway::kind()]).expect("file");
        let before = collection.clone();
        assert!(collection.triage(&json!({"schema":1,"items":[{"id":id,"decision":{"answer":answer,"reason":"reviewed"}}]}), &[gateway::kind()]).is_err());
        assert_eq!(collection, before);
    }
}
