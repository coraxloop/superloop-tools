#![allow(clippy::indexing_slicing)]
//! Equivalence to the pre-index loops, over deterministic shuffled collections.
use super::*;
use request_core::{Decision, State};

fn shuffle(rows: &mut [Request], seed: usize) {
    if !rows.is_empty() {
        rows.rotate_left(seed % rows.len());
    }
    if seed % 2 == 1 {
        rows.reverse();
    }
}
fn door(n: usize) -> Request {
    Request::filed(
        format!("{n:064x}"),
        "door-after-effect".into(),
        json!({"source_id":format!("R:{n}"),"record":{"id":format!("R:{n}"),"payload":n}}),
        "worker".into(),
        "R".into(),
        1,
    )
}
fn gateway(n: usize) -> Request {
    Request::filed(
        format!("{n:064x}"),
        "gateway-proposal".into(),
        json!({"schema":1,"loop_name":"orchestration","gateway_id":"a".repeat(64),
        "registration_digest":"b".repeat(64),"proposal":{"schema":1,"lane":"lane",
        "seq":n+1,"argv":["true"],"reason":"fixture","queued_unix_ms":1,"timeout_seconds":30}}),
        "worker".into(),
        "R".into(),
        1,
    )
}
fn collected(rows: Vec<Request>) -> Collection {
    let value = Collection {
        schema: 1,
        revision: 1,
        requests: rows,
    };
    value.validate(&kinds()).expect("admitted collection");
    value
}
fn outcome<T: serde::Serialize>(result: Result<T, Error>) -> Result<Vec<u8>, String> {
    result
        .map(|v| serde_json::to_vec(&v).expect("observable bytes"))
        .map_err(|e| e.to_string())
}

/// ´test:unit:owner-index-merge-matches-linear-shuffled-inputs´
#[test]
fn owner_index_merge_matches_linear_shuffled_inputs() {
    for seed in 0..32 {
        let mut rows = (1..9)
            .map(door)
            .chain((20..24).map(gateway))
            .collect::<Vec<_>>();
        shuffle(&mut rows, seed);
        let before = collected(rows);
        for variant in 0..4 {
            let mut records = vec![door(3), door(19), gateway(21), gateway(29)];
            if variant == 1 {
                records[0].waiter_gone = true;
            }
            if variant == 2 {
                records[2].body["proposal"]["reason"] = json!("changed");
            }
            if variant == 3 {
                records[0].body["record"]["payload"] = json!("replacement");
            }
            shuffle(&mut records, seed + 3);
            let mut expected = before.clone();
            let mut actual = before.clone();
            assert_eq!(
                outcome(merge(&mut actual, records.clone())),
                outcome(linear_merge(&mut expected, records))
            );
            assert_eq!(
                actual, expected,
                "partial results and row order {seed}/{variant}"
            );
        }
    }
}

/// ´test:unit:owner-index-publication-matches-linear-shuffled-inputs´
#[test]
fn owner_index_publication_matches_linear_shuffled_inputs() {
    for seed in 0..32 {
        let mut rows = (1..9).map(door).collect::<Vec<_>>();
        shuffle(&mut rows, seed);
        let next = collected(rows);
        for variant in 0..5 {
            let mut candidate = next.clone();
            match variant {
                0 => candidate.requests[3].body["record"]["payload"] = json!("projected"),
                1 => candidate.requests[3].id = "f".repeat(64),
                2 => candidate.requests[3].body["source_id"] = json!("different"),
                3 => candidate.requests.reverse(),
                _ => candidate.requests[3].body["extra"] = json!(true),
            }
            assert_eq!(
                outcome(publication(&next, &candidate)),
                outcome(linear_publication(&next, &candidate)),
                "{seed}/{variant}"
            );
        }
    }
}

fn authority_fixture() -> (Journal, CallerRole) {
    let root = std::path::Path::new("/fixture-state");
    let mut journal = Journal::from_state_root(root);
    journal.registered_root = Some(root.to_owned());
    let entry = concat!(
        "LOOP_NAME=orchestration\nLOOP_CWD=/workspace/project\n",
        "LOOP_SID=main\nLOOP_STATE_ROOT=/fixture-state\n"
    );
    let entries = BTreeMap::from([("orchestration.env".to_owned(), entry.as_bytes().to_vec())]);
    let registry = crate::parse_registry(b"orchestration.env\n", &entries);
    let caller = crate::resolve_role(
        Some(&registry),
        4_000_000_000,
        "main",
        "/workspace/project",
        None,
        false,
    );
    assert!(caller.is_orchestrator());
    (journal, caller)
}

/// ´test:unit:owner-index-gateway-authority-matches-linear-shuffled-inputs´
#[test]
fn owner_index_gateway_authority_matches_linear_shuffled_inputs() {
    let (journal, caller) = authority_fixture();
    for seed in 0..32 {
        let mut rows = (1..9).map(gateway).collect::<Vec<_>>();
        shuffle(&mut rows, seed);
        let before = collected(rows);
        let mut next = before.clone();
        next.requests[2].state = State::Marked;
        shuffle(&mut next.requests, seed + 7);
        for role in [&caller, &CallerRole::Unknown] {
            for action in ["triage", "file"] {
                assert_eq!(
                    outcome(gateway_authority(&journal, role, action, &before, &next)),
                    outcome(linear_gateway_authority(
                        &journal, role, action, &before, &next
                    ))
                );
            }
        }
    }
}

// Produce the actual legacy source shape through its writer, then retain only bytes.
fn permission_rows() -> Vec<Request> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("own fixture cleanup");
        }
    }
    let root = std::env::temp_dir().join(format!(
        "permission-index-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).expect("own fixture root");
    let root = Root(root);
    let journal = Journal::from_state_root(&root.0.join("state"));
    for n in 0..8 {
        journal
            .append_test_escalation(&format!("printf {n}"), "index proof")
            .expect("real source writer");
    }
    let bytes = journal.read().expect("journal bytes");
    super::super::requests::collection(&bytes)
        .expect("source collection")
        .requests
}

/// ´test:unit:owner-index-permission-authority-matches-linear-shuffled-inputs´
#[test]
fn owner_index_permission_authority_matches_linear_shuffled_inputs() {
    let rows = permission_rows();
    let (journal, caller) = authority_fixture();
    for seed in 0..32 {
        let mut before = collected(rows.clone());
        shuffle(&mut before.requests, seed);
        let mut next = before.clone();
        next.requests[2].state = State::Marked;
        shuffle(&mut next.requests, seed + 7);
        for role in [&caller, &CallerRole::Unknown] {
            assert_eq!(
                outcome(permission_authority(&journal, role, &before, &next)),
                outcome(linear_permission_authority(&journal, role, &before, &next))
            );
        }
    }
}

/// ´test:unit:owner-index-dispositions-preserve-linear-row-order´
#[test]
fn owner_index_dispositions_preserve_linear_row_order() {
    let rows = permission_rows();
    let (_, caller) = authority_fixture();
    for seed in 0..32 {
        let mut saved = collected(rows.clone());
        shuffle(&mut saved.requests, seed);
        let mut next = saved.clone();
        for row in &mut next.requests {
            row.state = State::TriageDecided;
            row.decision_state = Some(State::TriageDecided);
            row.decision = Some(Decision {
                answer: json!({"outcome":"adjudicated-rejected"}),
                reason: "fixture".into(),
            });
        }
        shuffle(&mut next.requests, seed + 7);
        next.validate(&kinds()).expect("decided collection");
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        assert_eq!(
            outcome(append_dispositions(&mut actual, &saved, &next, &caller)),
            outcome(linear_append_dispositions(
                &mut expected,
                &saved,
                &next,
                &caller
            ))
        );
        let normalize = |bytes: &[u8]| {
            bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let mut value: Value = serde_json::from_slice(line).unwrap();
                    value["recorded_at"] = json!("clock");
                    value
                })
                .collect::<Vec<_>>()
        };
        let actual = normalize(&actual);
        assert_eq!(actual.len(), 8);
        assert_eq!(actual, normalize(&expected));
    }
}

// Verbatim pre-index search references.
fn linear_merge(collection: &mut Collection, records: Vec<Request>) -> Result<(), Error> {
    let supplied = Collection {
        schema: 1,
        revision: 0,
        requests: records,
    };
    supplied.validate(&kinds())?;
    for request in supplied.requests {
        if request.kind == "gateway-proposal" {
            let filed = Request::filed(
                request.id.clone(),
                request.kind.clone(),
                request.body.clone(),
                request.worker.clone(),
                request.run.clone(),
                request.filed_ns,
            );
            if request != filed {
                return Err(failure(
                    "gateway filing cannot supply a decision or service state",
                ));
            }
            if let Some(old) = collection.requests.iter().find(|row| row.id == request.id) {
                if old.body != request.body
                    || old.worker != request.worker
                    || old.run != request.run
                    || old.filed_ns != request.filed_ns
                {
                    return Err(Error::new("requests-conflict", &request.id));
                }
            } else {
                collection.file(request, &kinds())?;
            }
            continue;
        }
        if !matches!(
            request.kind.as_str(),
            "door-before-effect" | "door-after-effect"
        ) {
            return Err(failure("custody owner supplied a foreign kind"));
        }
        if let Some(old) = collection
            .requests
            .iter_mut()
            .find(|row| row.id == request.id)
        {
            let mut comparison = request.clone();
            comparison.body = old.body.clone();
            comparison.waiter_gone = old.waiter_gone;
            if comparison != *old || (old.waiter_gone && !request.waiter_gone) {
                return Err(Error::new("requests-conflict", &request.id));
            }
            *old = request;
        } else {
            collection.file(request, &kinds())?;
        }
    }
    Ok(())
}

fn linear_publication(next: &Collection, candidate: &Collection) -> Result<Collection, Error> {
    let mut comparison = candidate.clone();
    for row in &mut comparison.requests {
        if matches!(
            row.kind.as_str(),
            "door-before-effect" | "door-after-effect"
        ) {
            let source = next
                .requests
                .iter()
                .find(|source| source.id == row.id)
                .ok_or_else(|| Error::new("requests-conflict", &row.id))?;
            if row.body.get("source_id") != source.body.get("source_id") {
                return Err(Error::new("requests-conflict", &row.id));
            }
            row.body = source.body.clone();
        }
    }
    if comparison != *next {
        return Err(failure(
            "owner publication changes the evaluated transition",
        ));
    }
    candidate.validate(&kinds())?;
    Ok(candidate.clone())
}

fn linear_gateway_authority(
    journal: &Journal,
    caller: &CallerRole,
    action: &str,
    before: &Collection,
    next: &Collection,
) -> Result<(), Error> {
    for row in next
        .requests
        .iter()
        .filter(|row| row.kind == "gateway-proposal")
    {
        let old = before.requests.iter().find(|old| old.id == row.id);
        let judgement_changed = old.is_some_and(|old| {
            (matches!(action, "triage" | "review" | "adjudicate") && old != row)
                || old.decision != row.decision
                || old.review != row.review
                || old.review_history != row.review_history
        });
        if judgement_changed
            && (!caller.is_orchestrator()
                || caller
                    .entry()
                    .and_then(crate::role::RegistryEntry::state_root)
                    != journal.registered_root.as_deref()
                || row.body.get("loop_name").and_then(Value::as_str) != caller.loop_name())
        {
            return Err(Error::new("requests-authority", &row.id));
        }
    }
    Ok(())
}
fn linear_permission_authority(
    journal: &Journal,
    caller: &CallerRole,
    before: &Collection,
    next: &Collection,
) -> Result<(), Error> {
    // Permission records stay behind the established caller and scope checks,
    // even when a door-owning process transports the transaction.
    for row in next
        .requests
        .iter()
        .filter(|row| row.kind == "permission-case")
    {
        if before.requests.iter().find(|old| old.id == row.id) != Some(row)
            && (!caller.is_orchestrator()
                || caller
                    .entry()
                    .and_then(crate::role::RegistryEntry::state_root)
                    != journal.registered_root.as_deref()
                || row.body.get("scope").and_then(Value::as_str) != Some("loop")
                || row.body.get("loop_name").and_then(Value::as_str) != caller.loop_name())
        {
            return Err(Error::new("requests-authority", &row.id));
        }
    }
    Ok(())
}

fn linear_append_dispositions(
    published: &mut Vec<u8>,
    saved: &Collection,
    next: &Collection,
    caller: &CallerRole,
) -> Result<(), Error> {
    for row in next
        .requests
        .iter()
        .filter(|row| row.kind == "permission-case" && row.decision.is_some())
    {
        if saved
            .requests
            .iter()
            .any(|old| old.id == row.id && old.decision.is_none())
        {
            published.extend(
                serde_json::to_vec(&super::super::requests::disposition(row, caller)?)
                    .map_err(failure)?,
            );
            published.push(b'\n');
        }
    }
    Ok(())
}
