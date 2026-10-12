use execute_command::request::{Request, Verdict};
use serde_json::{Value, json};

fn request() -> Value {
    json!({"schema":1,"binding":{"request_id":"r1","context_digest":"ctx1"},
        "command":{"representation":"argv","argv":["echo",""]},
        "context":{"cwd":"/fixture","requester":"worker","loop_id":"loop",
            "lane":null,"run":null,"purpose":"fixture","deadline_unix_ms":100,
            "snapshot":"snapshot","registration":"registration","resources":[],
            "authority":"loop","checks":[],"rubric":"reviewed","mode":"audit",
            "floor":"audit","policy":"policy"},
        "implications":{"effects":[],"resources":[],"principals":[],
            "reversibility":"read-only","scope_uncertainty":"none","evidence":[]}})
}

fn verdict() -> Value {
    json!({"binding":{"request_id":"r1","context_digest":"ctx1"},
        "judgement":"allow","tier":"deterministic-checks","scope":"loop",
        "reason":"registered fixture","evidence":[],"correction":null,
        "escalation":null,"status":"valid"})
}

/// ´test:integration:strict-request-shapes´
#[test]
fn strict_request_shapes() {
    let original = request();
    let parsed = Request::from_json(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), original);
    for (field, value) in [("schema", json!(2)), ("unknown", json!(true))] {
        let mut invalid = original.clone();
        invalid[field] = value;
        assert_eq!(
            Request::from_json(invalid.to_string().as_bytes())
                .unwrap_err()
                .0,
            "execute-command-request-shape"
        );
    }
    for command in [
        json!({"representation":"argv","argv":["echo"],"unknown":true}),
        json!({"representation":"shell","bytes":[1]}),
        json!({"representation":"argv","argv":[]}),
        json!({"representation":"bytes","bytes":[]}),
        json!({"representation":"argv","argv":["echo","\u{0000}"]}),
    ] {
        let mut invalid = original.clone();
        invalid["command"] = command;
        assert!(Request::from_json(invalid.to_string().as_bytes()).is_err());
    }
    for field in ["lane", "run"] {
        let mut invalid = original.clone();
        invalid["context"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            Request::from_json(invalid.to_string().as_bytes())
                .unwrap_err()
                .0,
            "execute-command-request-shape"
        );
    }
    let mut exact = original;
    exact["command"] = json!({"representation":"bytes","bytes":[255,0,10]});
    assert_eq!(
        serde_json::to_value(Request::from_json(exact.to_string().as_bytes()).unwrap()).unwrap(),
        exact
    );
}

/// ´test:integration:actionable-verdicts´
#[test]
fn actionable_verdicts() {
    let mut value = verdict();
    assert!(Verdict::from_json(value.to_string().as_bytes()).is_ok());
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<Verdict>(value.clone()).unwrap()).unwrap(),
        value
    );
    value["judgement"] = json!("refuse");
    assert_eq!(
        serde_json::from_value::<Verdict>(value.clone())
            .unwrap_err()
            .to_string(),
        "execute-command-verdict-shape"
    );
    assert_eq!(
        Verdict::from_json(value.to_string().as_bytes())
            .unwrap_err()
            .0,
        "execute-command-verdict-shape"
    );
    value["correction"] =
        json!({"rule":"execute-command-fixture","changes":"supply cwd","revalidation":"resubmit"});
    assert!(Verdict::from_json(value.to_string().as_bytes()).is_ok());
    assert!(serde_json::from_value::<Verdict>(value.clone()).is_ok());
    value["judgement"] = json!("refer");
    assert!(Verdict::from_json(value.to_string().as_bytes()).is_err());
    value["escalation"] = json!({"target":"loop-review","required_authority":"loop",
        "route":"fixture","binding":value["binding"],"requires_current_review":true,
        "evidence":[],"resume_conditions":"current authenticated answer"});
    assert!(Verdict::from_json(value.to_string().as_bytes()).is_ok());
    value["escalation"]["binding"]["context_digest"] = json!("stale");
    assert!(Verdict::from_json(value.to_string().as_bytes()).is_err());
}

/// ´test:integration:verdicts-require-explicit-null-and-valid-status´
#[test]
fn verdicts_require_explicit_null_and_valid_status() {
    for field in ["correction", "escalation"] {
        let mut value = verdict();
        value.as_object_mut().unwrap().remove(field);
        assert!(Verdict::from_json(value.to_string().as_bytes()).is_err());
    }
    for (field, invalid) in [
        ("reason", " "),
        ("judgement", "undecided"),
        ("tier", "fast-lane"),
        ("status", "timeout"),
    ] {
        let mut value = verdict();
        value[field] = json!(invalid);
        assert!(Verdict::from_json(value.to_string().as_bytes()).is_err());
    }
}

/// ´test:integration:bounded-request-input´
#[test]
fn bounded_request_input() {
    let mut value = request();
    value["context"]["purpose"] = json!("x".repeat(4096));
    assert!(Request::from_json(value.to_string().as_bytes()).is_ok());
    value["context"]["purpose"] = json!("x".repeat(4097));
    assert!(Request::from_json(value.to_string().as_bytes()).is_err());
    value = request();
    value["context"]["resources"] = json!(vec!["x"; 65]);
    assert!(Request::from_json(value.to_string().as_bytes()).is_err());
    let original = request();
    let mut envelope = serde_json::to_vec(&original).unwrap();
    envelope.resize(1_048_576, b' ');
    assert_eq!(
        serde_json::to_value(Request::from_json(&envelope).unwrap()).unwrap(),
        original
    );
    envelope.push(b' ');
    assert_eq!(envelope.len(), 1_048_577);
    assert_eq!(
        serde_json::from_slice::<Value>(&envelope).unwrap(),
        original
    );
    assert_eq!(
        Request::from_json(&envelope).unwrap_err().0,
        "execute-command-request-shape"
    );
}
