//! Real owner protocol evidence for the request-lock view boundary.
use super::super::{publication_tests, tests::Fixture};
use super::*;
use std::cell::RefCell;
use std::io::Write as _;

type CommitHook = Box<dyn FnOnce(&Store)>;
type ReadHook = Box<dyn FnOnce(&Client)>;
type ReplyHook = Box<dyn FnOnce(&mut Value)>;
thread_local! { static READ: RefCell<Option<ReadHook>> = const { RefCell::new(None) }; }
thread_local! { static REPLY: RefCell<Option<ReplyHook>> = const { RefCell::new(None) }; }
thread_local! { static SERVICE_BOUNDARIES: RefCell<Option<[Value; 4]>> = const { RefCell::new(None) }; }
pub(super) fn capture_service_before(preview: &Value, candidate: &Collection, input: &Value) {
    SERVICE_BOUNDARIES.with(|slot| {
        if slot.borrow().is_some() {
            slot.replace(Some([
                preview["collection"].clone(),
                serde_json::to_value(candidate).expect("candidate value"),
                input["publication"].clone(),
                Value::Null,
            ]));
        }
    });
}
pub(super) fn capture_service_boundaries(
    preview: &Value,
    candidate: &Collection,
    input: &Value,
    reply: &Value,
) {
    SERVICE_BOUNDARIES.with(|slot| {
        if slot.borrow().is_some() {
            slot.replace(Some([
                preview["collection"].clone(),
                serde_json::to_value(candidate).expect("candidate value"),
                input["publication"].clone(),
                reply["collection"].clone(),
            ]));
        }
    });
}
pub(super) fn after_reply(reply: &mut Value) {
    let hook = REPLY.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(reply);
    }
}
pub(super) fn after_read(client: &Client) {
    let hook = READ.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(client);
    }
}
thread_local! { static COMMITTED: RefCell<Option<CommitHook>> = const { RefCell::new(None) }; }
pub(super) fn after_commit(store: &Store) {
    let hook = COMMITTED.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(store);
    }
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        COMMITTED.with(|slot| slot.replace(None));
        READ.with(|slot| slot.replace(None));
        REPLY.with(|slot| slot.replace(None));
        SERVICE_BOUNDARIES.with(|slot| slot.replace(None));
    }
}

fn seed() -> (Fixture, Store, Client) {
    let fixture = Fixture::new();
    let store = publication_tests::provision(&fixture);
    for nonce in ["aa", "bb"] {
        store
            .file(crate::requests::tests::waiting(
                "R",
                nonce,
                3000,
                crate::requests::Mode::Audit,
            ))
            .expect("seed local custody");
    }
    fixture
        .command(
            &["triage", "alpha", "R"],
            br#"[{"id":"R:bb","action":"mark","reason":"fixture"}]"#,
        )
        .expect("bind real owner helper");
    let client = store.bound_client().unwrap().unwrap();
    (fixture, store, client)
}

fn seed_compute(reason: &str) -> (Fixture, Store, Client) {
    let fixture = Fixture::new();
    let store = publication_tests::provision(&fixture);
    let mut value =
        crate::requests::tests::waiting("R", "aa", 3000, crate::requests::Mode::Audit).into_value();
    let words = vec![
        "./tools/check".to_owned(),
        "--root".to_owned(),
        ".".to_owned(),
    ];
    value["class"] = json!("compute");
    value["operation"] = json!("compute");
    value["shape_key"] = json!(execute_command::checks::compute::shape(&words));
    value["would_do"]["reason"] = json!(reason);
    value["effect"]
        .as_object_mut()
        .expect("effect")
        .remove("bound");
    value["effect"]
        .as_object_mut()
        .expect("effect")
        .remove("output_bytes");
    value["effect"]["compute"] = json!({"words":words,"checkout_path":null,
        "checkout_ref":null,"checkout_commit":null,"wrapper_exit_status":null,
        "wrapper_wall_seconds":null,"wrapper_user_cpu_seconds":null,
        "wrapper_system_cpu_seconds":null,"preparation_wall_seconds":null,
        "tree_clean":null,"tree_change_count":null,"discarded":null});
    let record = crate::requests::RequestRecord::decode(value).expect("compute intent");
    store.file(record).expect("seed compute custody");
    store
        .file(crate::requests::tests::waiting(
            "R",
            "bb",
            3000,
            crate::requests::Mode::Audit,
        ))
        .expect("seed second request");
    fixture
        .command(
            &["triage", "alpha", "R"],
            br#"[{"id":"R:bb","action":"mark","reason":"fixture"}]"#,
        )
        .expect("bind owner helper");
    let client = store.bound_client().unwrap().unwrap();
    (fixture, store, client)
}

fn first_value_difference(path: &str, left: &Value, right: &Value) -> Option<String> {
    match (left, right) {
        (Value::Object(a), Value::Object(b)) => {
            let keys = a
                .keys()
                .chain(b.keys())
                .collect::<std::collections::BTreeSet<_>>();
            for key in keys {
                if !a.contains_key(key) || !b.contains_key(key) {
                    return Some(format!(
                        "{path}.{key}: {:?} -> {:?}",
                        a.get(key),
                        b.get(key)
                    ));
                }
                if let Some(diff) =
                    first_value_difference(&format!("{path}.{key}"), &a[key], &b[key])
                {
                    return Some(diff);
                }
            }
            None
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!("{path}.len: {} -> {}", a.len(), b.len()));
            }
            a.iter().zip(b).enumerate().find_map(|(index, (a, b))| {
                first_value_difference(&format!("{path}[{index}]"), a, b)
            })
        }
        (Value::Number(a), Value::Number(b)) if a.is_f64() && b.is_f64() => {
            let a = a.as_f64().expect("left float").to_bits();
            let b = b.as_f64().expect("right float").to_bits();
            (a != b).then(|| format!("{path}: {a:016x} -> {b:016x}"))
        }
        _ => (left != right).then(|| format!("{path}: {left:?} -> {right:?}")),
    }
}

fn collection_row<'a>(collection: &'a Value, id: &str) -> &'a Value {
    collection["requests"]
        .as_array()
        .expect("collection rows")
        .iter()
        .find(|row| row["id"] == id)
        .expect("compute request")
}

fn same_value(path: &str, left: &Value, right: &Value) {
    assert!(
        first_value_difference(path, left, right).is_none(),
        "{}",
        first_value_difference(path, left, right).unwrap_or_default()
    );
}

struct ComputeCase {
    wall_ns: u64,
    cpu_ns: u64,
    output_bytes: u64,
    queue_ns: Option<u64>,
    reason: &'static str,
    path: &'static str,
}

fn finished_compute_effect(record: &crate::requests::RequestRecord, case: &ComputeCase) -> Value {
    let wall = std::time::Duration::from_nanos(case.wall_ns).as_secs_f64();
    let cpu = std::time::Duration::from_nanos(case.cpu_ns).as_secs_f64();
    let mut detail = record.value()["effect"]["compute"].clone();
    detail["checkout_path"] = json!(case.path);
    detail["checkout_ref"] = record.value()["mirror_ref"].clone();
    detail["checkout_commit"] = json!("a".repeat(40));
    detail["wrapper_exit_status"] = json!(0);
    detail["wrapper_wall_seconds"] = json!(wall + 0.25);
    detail["wrapper_user_cpu_seconds"] = json!(cpu);
    detail["wrapper_system_cpu_seconds"] = json!(cpu / 3.0);
    detail["preparation_wall_seconds"] = json!(wall / 7.0);
    detail["tree_clean"] = json!(true);
    detail["tree_change_count"] = json!(0);
    detail["discarded"] = json!({"tracked":0,"untracked":0});
    let reply = json!({"reason":"door-complete","status":0,"ref_check":"not-applicable",
        "stdin_bytes":0,"stdout_bytes":case.output_bytes,"stderr_bytes":0,
        "queue_wall_seconds":case.queue_ns.map(|ns| std::time::Duration::from_nanos(ns).as_secs_f64()),
        "mediation_wall_seconds":cpu,"compute_wall_seconds":wall,"compute":detail});
    crate::door::effect_from_final(&reply)
}

fn measure_compute_case(case: &ComputeCase) {
    let (_fixture, store, client) = seed_compute(case.reason);
    let id = common_id("alpha", "R:aa");
    store
        .collection_command(
            "triage",
            Some(&json!({"schema":1,"items":[{"id":id,
        "decision":{"answer":{"outcome":"allow"},"reason":"fixture"}}]})),
            None,
            false,
        )
        .expect("triage through owner");
    store
        .channel_service_locked(
            &client,
            "claim",
            &json!({"schema":1,"id":id,"claim":"fixture-compute"}),
            None,
        )
        .expect("claim through owner");
    let mut record = store.request("R:aa").expect("local compute record");
    let effect = finished_compute_effect(&record, case);
    record
        .record_effect(effect.clone())
        .expect("door effect record");
    let document = json!({"schema":1,"id":id,"claim":"fixture-compute","result":effect});
    SERVICE_BOUNDARIES.with(|slot| slot.replace(Some(std::array::from_fn(|_| Value::Null))));
    let _reset = Reset;
    let completion = store.channel_service_locked(&client, "complete", &document, Some(&record));
    let [preview, candidate, submitted, reply] =
        SERVICE_BOUNDARIES.with(|slot| slot.borrow_mut().take().expect("service boundaries"));
    let encoded = serde_json::to_vec(&submitted).expect("client publication encoding");
    let decoded: Value = serde_json::from_slice(&encoded).expect("helper publication decoding");
    let boundary_diff = first_value_difference("candidate -> submitted", &candidate, &submitted)
        .or_else(|| first_value_difference("submitted -> helper parse", &submitted, &decoded));
    assert!(
        completion.is_ok(),
        "completion={completion:?}; boundary={boundary_diff:?}"
    );
    let stored = client
        .call("--owner-read", "", "alpha", None)
        .expect("stored collection");
    let preview_row = collection_row(&preview, &id);
    let candidate_row = collection_row(&candidate, &id);
    same_value(
        "record.effect -> preview.service_result",
        &effect,
        &preview_row["service_result"],
    );
    same_value(
        "record -> candidate.body.record",
        record.value(),
        &candidate_row["body"]["record"],
    );
    same_value(
        "preview.service_result -> candidate.service_result",
        &preview_row["service_result"],
        &candidate_row["service_result"],
    );
    same_value("candidate -> submitted", &candidate, &submitted);
    same_value("submitted -> reply", &submitted, &reply);
    same_value("reply -> stored", &reply, &stored);
}

/// ´test:unit:compute-record-survives-owner-service-publication´
#[test]
fn compute_record_survives_owner_service_publication() {
    if !publication_tests::in_namespace() {
        return;
    }
    for case in [
        ComputeCase {
            wall_ns: 1,
            cpu_ns: 2,
            output_bytes: 0,
            queue_ns: None,
            reason: "learned: ./tools/check --root .",
            path: "/work/checkout",
        },
        ComputeCase {
            wall_ns: 123_456,
            cpu_ns: 789,
            output_bytes: 1,
            queue_ns: Some(0),
            reason: "agent: allowed ~ ^ @ % #",
            path: "/work/space #1",
        },
        ComputeCase {
            wall_ns: 1_234_567_890,
            cpu_ns: 987_654_321,
            output_bytes: 65_536,
            queue_ns: Some(12_345),
            reason: r#"agent: path with "quote" and backslash \"#,
            path: "/work/%23@^",
        },
        ComputeCase {
            wall_ns: 86_400_000_000_000,
            cpu_ns: 3_600_000_000_000,
            output_bytes: 16_777_216,
            queue_ns: None,
            reason: "agent: accented café",
            path: "/work/checkout with space",
        },
    ] {
        measure_compute_case(&case);
    }
}

/// ´test:unit:compute-record-measurements-survive-owner-service-sweep´
#[test]
fn compute_record_measurements_survive_owner_service_sweep() {
    if !publication_tests::in_namespace() {
        return;
    }
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    for scale in [
        10,
        1_000,
        1_000_000,
        1_000_000_000,
        60_000_000_000,
        86_400_000_000_000,
    ] {
        for index in 0..16 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let case = ComputeCase {
                wall_ns: 1 + state % scale,
                cpu_ns: 1 + state.rotate_left(19) % scale,
                output_bytes: [0, 1, 65_536, 16_777_216][index % 4],
                queue_ns: (index % 2 == 0).then_some(state % 1_000_000),
                reason: "agent: command path ./tools/check @%#",
                path: "/work/checkout with space",
            };
            measure_compute_case(&case);
        }
    }
}

fn duration_measurements() -> Vec<f64> {
    let mut measurements = Vec::new();
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for scale in [
        1_u64,
        10,
        1_000,
        1_000_000,
        1_000_000_000,
        86_400_000_000_000,
    ] {
        for _ in 0..1_024 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let nanos = 1 + state % scale;
            measurements.push(std::time::Duration::from_nanos(nanos).as_secs_f64());
        }
    }
    measurements
}

/// ´test:unit:owner-service-reply-preserves-duration-measurement-bits´
#[test]
fn owner_service_reply_preserves_duration_measurement_bits() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (_fixture, store, client) = seed();
    let id = common_id("alpha", "R:aa");
    store
        .collection_command(
            "triage",
            Some(&json!({"schema":1,"items":[{"id":id,"decision":{
                "answer":{"outcome":"allow"},"reason":"fixture"}}]})),
            None,
            false,
        )
        .expect("triage through owner");
    store
        .channel_service_locked(
            &client,
            "claim",
            &json!({"schema":1,"id":id,"claim":"fixture-measurement"}),
            None,
        )
        .expect("claim through owner");
    let measurements = duration_measurements();
    let original_bits = measurements
        .iter()
        .map(|value| value.to_bits())
        .collect::<Vec<_>>();
    let document = json!({"schema":1,"id":id,"claim":"fixture-measurement",
        "result":{"effect":{"compute_wall_seconds":measurements}}});
    let mut input = envelope(
        &[],
        Some(&document),
        None,
        false,
        request_core::now_ns().expect("fixture clock"),
    );
    let preview = client
        .call("--owner-preview", "complete", "alpha", Some(&input))
        .expect("preview through helper");
    let next = decode(preview["collection"].clone()).expect("preview collection");
    input["expected"] = preview["before"].clone();
    input["publication"] = serde_json::to_value(&next).expect("publication value");
    let committed = client
        .call("--owner-commit", "complete", "alpha", Some(&input))
        .expect("commit through helper");
    let returned = decode(committed["collection"].clone()).expect("returned collection");
    let submitted = next
        .requests
        .iter()
        .find(|row| row.id == id)
        .and_then(|row| row.service_result.as_ref())
        .expect("submitted result");
    let received = returned
        .requests
        .iter()
        .find(|row| row.id == id)
        .and_then(|row| row.service_result.as_ref())
        .expect("returned result");
    let submitted = submitted["effect"]["compute_wall_seconds"]
        .as_array()
        .expect("submitted measurements");
    let received = received["effect"]["compute_wall_seconds"]
        .as_array()
        .expect("returned measurements");
    assert_eq!(submitted.len(), received.len());
    let preview_differences = original_bits
        .iter()
        .zip(submitted)
        .enumerate()
        .filter_map(|(index, (before, after))| {
            let after = after.as_f64().expect("preview float").to_bits();
            (*before != after).then_some((index, *before, after))
        })
        .collect::<Vec<_>>();
    let differences = submitted
        .iter()
        .zip(received)
        .enumerate()
        .filter_map(|(index, (before, after))| {
            let before = before.as_f64().expect("submitted float").to_bits();
            let after = after.as_f64().expect("returned float").to_bits();
            (before != after).then_some((index, before, after))
        })
        .collect::<Vec<_>>();
    let preview_first = preview_differences.first().map(|(index, before, after)| {
        format!("effect.compute_wall_seconds[{index}]: {before:016x} -> {after:016x}")
    });
    let commit_first = differences.first().map(|(index, before, after)| {
        format!("effect.compute_wall_seconds[{index}]: {before:016x} -> {after:016x}")
    });
    assert_eq!(
        preview_differences.len() + differences.len(),
        0,
        "{} of {} values changed at preview, first {preview_first:?}; {} changed at commit, first {commit_first:?}",
        preview_differences.len(),
        submitted.len(),
        differences.len(),
    );
    assert_eq!(next, returned, "owner collection differs after commit");
}

/// ´test:unit:status-names-incomplete-attempt-after-successful-owner-commit´
#[test]
fn status_names_incomplete_attempt_after_successful_owner_commit() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (fixture, store, client) = seed();
    let id = common_id("alpha", "R:aa");
    store
        .collection_command(
            "triage",
            Some(&json!({"schema":1,"items":[{"id":id,"decision":{
                "answer":{"outcome":"allow"},"reason":"fixture"}}]})),
            None,
            false,
        )
        .expect("triage through owner");
    store
        .channel_service_locked(
            &client,
            "claim",
            &json!({"schema":1,"id":id,"claim":"fixture-status"}),
            None,
        )
        .expect("claim through owner");
    let document = json!({"schema":1,"id":id,"claim":"fixture-status",
        "result":{"reason":"door-complete","compute_exit_status":0}});
    let wanted = id.clone();
    let _reset = Reset;
    REPLY.with(|slot| {
        slot.replace(Some(Box::new(move |reply| {
            let rows = reply["collection"]["requests"]
                .as_array_mut()
                .expect("owner rows");
            let row = rows
                .iter_mut()
                .find(|row| row["id"] == wanted)
                .expect("request");
            row["service_result"] = json!({"reason":"changed"});
        })));
    });
    let error = store
        .channel_service_locked(&client, "complete", &document, None)
        .expect_err("changed publication reply");
    assert_eq!(error.kind, "requests-channel-refusal");
    assert_eq!(error.detail, "service publication reply differs");
    let saved = store
        .channel_owner_read(&client)
        .expect("owner committed despite reply mismatch");
    assert_eq!(
        saved
            .requests
            .iter()
            .find(|row| row.id == id)
            .expect("request")
            .state,
        State::Completed
    );
    store
        .record_incomplete("R", "R:aa", "requests-channel-refusal")
        .expect("door's incomplete marker");
    let status = fixture
        .command(&["status", "alpha"], b"")
        .expect("production status");
    assert_eq!(status["incomplete_attempt"]["phase"], "incomplete");
    assert_eq!(status["incomplete_attempt"]["run"], "R");
    assert_eq!(
        status["incomplete_attempt"]["reason"],
        "R:aa: requests-channel-refusal"
    );
    assert!(
        status["counts"]
            .as_array()
            .expect("status counts")
            .iter()
            .any(|row| {
                row["kind"] == "door-before-effect"
                    && row["state"] == "completed"
                    && row["count"] == 1
            })
    );
    let listed = fixture
        .command(&["list", "alpha"], b"")
        .expect("production list");
    assert_eq!(
        listed["requests"]
            .as_array()
            .expect("owner rows")
            .iter()
            .find(|row| row["id"] == id)
            .expect("completed row")["state"],
        "completed"
    );
}

/// ´test:unit:collection-view-triage-refreshes-before-claim´
#[test]
fn collection_view_triage_refreshes_before_claim() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (_fixture, store, client) = seed();
    let id = common_id("alpha", "R:aa");
    let wanted = id.clone();
    let _reset = Reset;
    COMMITTED.with(|slot| {
        slot.replace(Some(Box::new(move |store| {
            let key = store.channel_view_key().unwrap();
            let committed = super::super::view::get(key).expect("commit replaces the held view");
            let row = committed
                .requests
                .iter()
                .find(|row| row.id == wanted)
                .unwrap();
            assert_eq!(
                row.state,
                State::ServicePending,
                "triage must precede the claim"
            );
            assert!(row.service_claim.is_none());
            let result = store
                .channel_service_locked(
                    &client,
                    "claim",
                    &json!({"schema":1,"id":wanted,"claim":"fixture-held-claim"}),
                    None,
                )
                .unwrap();
            assert_eq!(result["claimed"], true);
            let claimed = store.channel_owner_read(&client).unwrap();
            assert_eq!(
                claimed
                    .requests
                    .iter()
                    .find(|row| row.id == wanted)
                    .unwrap()
                    .service_claim
                    .as_deref(),
                Some("fixture-held-claim")
            );
            assert!(Arc::ptr_eq(
                &claimed,
                &super::super::view::get(key).unwrap()
            ));
        })))
    });
    let decision = json!({"schema":1,"items":[{"id":id,"decision":{
        "answer":{"outcome":"allow"},"reason":"fixture"}}]});
    store
        .collection_command("triage", Some(&decision), None, false)
        .unwrap();
    assert!(
        COMMITTED.with(|slot| slot.borrow().is_none()),
        "commit hook ran"
    );
    assert!(
        store
            .channel_read()
            .unwrap()
            .unwrap()
            .requests
            .iter()
            .any(|row| row.id == id && row.service_claim.as_deref() == Some("fixture-held-claim"))
    );
}

fn append_permission(client: &Client, name: &str) -> Vec<u8> {
    let value = json!({"classification":"suspicious","command":"printf fixture",
        "cwd":"/workspace/project","domain_rubric_digest":null,"emitted_decision":"deny",
        "event":"escalated","event_id":name,"general_rubric_digest":"general-fixed",
        "loop_name":null,"mode":"enforce","model_status":"success","model_wall_ms":0,
        "owner_rubric_digest":null,"reason":"fixture reason",
        "recorded_at":"2026-09-03T00:00:00.000000000Z","request_digest":"request-fixed",
        "role":"unknown","schema":2,"scope":"estate","stale_session":false,
        "tool":"Bash","tool_use_id":"use-fixed","wall_ms":0,"would_be_decision":"deny"});
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    let path = client
        .registry
        .parent()
        .unwrap()
        .join("permission-state/escalations.jsonl");
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    bytes
}

/// ´test:unit:collection-view-permission-append-stays-live-at-commit´
#[test]
fn collection_view_permission_append_stays_live_at_commit() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (_fixture, store, client) = seed();
    append_permission(&client, "permission-before-hold");
    let guard = store.write_lock("view_permission_append").unwrap();
    let first = store.channel_owner_read(&client).unwrap();
    assert_eq!(
        first
            .requests
            .iter()
            .filter(|row| row.kind == "permission-case")
            .count(),
        1
    );
    let before = projection(&store);
    let id = common_id("alpha", "R:aa");
    let mut input = envelope(
        &[],
        Some(&json!({"schema":1,"items":[{
        "id":id,"mark_for_review":true}]})),
        None,
        false,
        request_core::now_ns().unwrap(),
    );
    let preview = client
        .call("--owner-preview", "triage", "alpha", Some(&input))
        .unwrap();
    input["expected"] = preview["before"].clone();
    // No publication is supplied: only the helper's fresh evaluated transition can be written.
    let legacy = append_permission(&client, "permission-during-hold");
    assert!(Arc::ptr_eq(
        &first,
        &store.channel_owner_read(&client).unwrap()
    ));
    assert_eq!(
        before,
        projection(&store),
        "permission append leaves door projection identical"
    );
    assert_fresh_projection(&store, &client, &before);
    let error = client
        .call("--owner-commit", "triage", "alpha", Some(&input))
        .unwrap_err();
    let refusal: Value = serde_json::from_str(&error.detail).expect("helper refusal envelope");
    assert_eq!(refusal["class"], "requests-conflict");
    assert_eq!(refusal["detail"], "preview preimage changed");
    let path = client
        .registry
        .parent()
        .unwrap()
        .join("permission-state/escalations.jsonl");
    assert!(
        std::fs::read(&path).unwrap().ends_with(&legacy),
        "conflict preserves appended bytes"
    );
    let fresh = client
        .call(
            "--owner-preview",
            "triage",
            "alpha",
            Some(&envelope(
                &[],
                input["document"].as_object().map(|_| &input["document"]),
                None,
                false,
                request_core::now_ns().unwrap(),
            )),
        )
        .unwrap();
    input["expected"] = fresh["before"].clone();
    let committed = client
        .call("--owner-commit", "triage", "alpha", Some(&input))
        .unwrap();
    let next = decode(committed["collection"].clone()).unwrap();
    assert_eq!(
        next.requests
            .iter()
            .filter(|row| row.kind == "permission-case")
            .count(),
        2
    );
    assert!(
        std::fs::read(&path)
            .unwrap()
            .windows(legacy.len())
            .any(|part| part == legacy)
    );
    // This explicit owner call is the test's writer; production's commit path performs this update.
    store.channel_committed(next);
    assert!(
        store
            .channel_owner_read(&client)
            .unwrap()
            .requests
            .iter()
            .any(|row| row.id == id && row.state == State::Marked)
    );
    drop(guard);
    publish_with_permission_append(&store, &client, &id);
}

/// ´test:unit:collection-view-provisioned-paths-read-once´
#[test]
fn collection_view_provisioned_paths_read_once() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (fixture, _store, _) = seed();
    fixture.set_floor("allow");
    let store = fixture.store();
    store
        .set_mode(
            &super::super::ModeTarget::Loop,
            crate::requests::Mode::Allow,
            "owner",
            "fixture",
            "1",
            &[],
        )
        .unwrap();
    for class in ["git", "build", "lint"] {
        store
            .set_mode(
                &super::super::ModeTarget::class(class).unwrap(),
                crate::requests::Mode::Allow,
                "owner",
                "fixture",
                "2",
                &[],
            )
            .unwrap();
    }
    let id = common_id("alpha", "R:aa");
    store
        .collection_command(
            "triage",
            Some(&json!({"schema":1,"items":[{
        "id":id,"decision":{"answer":{"outcome":"allow"},"reason":"fixture"}}]})),
            None,
            false,
        )
        .unwrap();
    assert!(store.claim_request("R:aa").unwrap());
    let request = crate::requests::tests::waiting("R", "cc", 3000, crate::requests::Mode::Allow);
    let mut value = request.into_value();
    let setting = store.effective_mode("git").unwrap();
    value["class_setting"] = setting["class"].clone();
    value["loop_setting"] = setting["loop"].clone();
    value["mode"] = setting["mode"].clone();
    value["state"] = Value::Null;
    let request = RequestRecord::decode(value).unwrap();
    store.file(request.clone()).unwrap();
    let outcome = crate::door::agent::RunnerOutcome::referral(
        "failure",
        "fixture",
        std::time::Instant::now(),
    );
    store
        .record_agent("R:cc", &outcome, None, None, None)
        .unwrap();
    let mut effect = request.value()["effect"].clone();
    effect["state"] = json!("completed");
    effect["reason"] = json!("door-complete");
    effect["exit_status"] = json!(0);
    effect["ref_check"] = json!("not-applicable");
    store.record_effect("R:cc", effect.clone()).unwrap();
    // Keep the channel-backed completion last: the parent pins its release line.
    store.record_effect("R:aa", effect).unwrap();
    store.publish_waiting("R:cc").unwrap();
    assert_eq!(store.publish_snapshot().unwrap()["published"], true);
    let rows = store.channel_read().unwrap().unwrap();
    assert_eq!(
        rows.requests.iter().find(|row| row.id == id).unwrap().state,
        State::Completed
    );
}

/// ´test:unit:collection-view-next-hold-sees-owner-change´
#[test]
fn collection_view_next_hold_sees_owner_change() {
    if !publication_tests::in_namespace() {
        return;
    }
    let (_fixture, store, client) = seed();
    shared_views(&store, &client);
    let id = common_id("alpha", "R:aa");
    {
        let _guard = store.write_lock("view_before_owner").unwrap();
        let first = store.channel_owner_read(&client).unwrap();
        assert_eq!(
            first
                .requests
                .iter()
                .find(|row| row.id == id)
                .unwrap()
                .state,
            State::Filed
        );
    }
    // The helper is another process; do not call the lane's view-refresh path.
    let mut input = envelope(
        &[],
        Some(&json!({"schema":1,"items":[{"id":id,"mark_for_review":true}]})),
        None,
        false,
        request_core::now_ns().unwrap(),
    );
    let preview = client
        .call("--owner-preview", "triage", "alpha", Some(&input))
        .unwrap();
    input["expected"] = preview["before"].clone();
    client
        .call("--owner-commit", "triage", "alpha", Some(&input))
        .unwrap();
    let _guard = store.write_lock("view_after_owner").unwrap();
    let next = store.channel_owner_read(&client).unwrap();
    assert_eq!(
        next.requests.iter().find(|row| row.id == id).unwrap().state,
        State::Marked
    );
}

fn projection(store: &Store) -> Vec<u8> {
    serde_json::to_vec(
        &store
            .read_run("R")
            .unwrap()
            .2
            .iter()
            .map(RequestRecord::value)
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn assert_fresh_projection(store: &Store, client: &Client, expected: &[u8]) {
    let fresh = decode(client.call("--owner-read", "", "alpha", None).unwrap()).unwrap();
    let mut records = store.read_run("R").unwrap().2;
    store.channel_project(&mut records, Some(&fresh)).unwrap();
    let values = records.iter().map(RequestRecord::value).collect::<Vec<_>>();
    assert_eq!(serde_json::to_vec(&values).unwrap(), expected);
}

fn publish_with_permission_append(store: &Store, client: &Client, id: &str) {
    let _reset = Reset;
    READ.with(|slot| {
        slot.replace(Some(Box::new(|client| {
            append_permission(client, "permission-before-live-preview");
        })))
    });
    let reviewed = store
        .collection_command("review", None, Some(id), false)
        .unwrap();
    assert!(
        reviewed["review"].is_object(),
        "real production command published the review"
    );
    assert!(READ.with(|slot| slot.borrow().is_none()), "read hook ran");
    let current = decode(client.call("--owner-read", "", "alpha", None).unwrap()).unwrap();
    assert_eq!(
        current
            .requests
            .iter()
            .filter(|row| row.kind == "permission-case")
            .count(),
        3,
        "publication must use the helper's live collection, never the held copy"
    );
}

fn shared_views(store: &Store, client: &Client) {
    let first_guard = store.lock(false).unwrap();
    let first = store.channel_owner_read(client).unwrap();
    assert!(
        !first
            .requests
            .iter()
            .any(|row| row.kind == "permission-case")
    );
    append_permission(client, "permission-between-shared-holds");
    let second_guard = store.lock(false).unwrap();
    let second = store.channel_owner_read(client).unwrap();
    assert!(
        !Arc::ptr_eq(&first, &second),
        "real shared holds own separate views"
    );
    assert_eq!(
        second
            .requests
            .iter()
            .filter(|row| row.kind == "permission-case")
            .count(),
        1
    );
    drop(second_guard);
    assert!(Arc::ptr_eq(
        &first,
        &store.channel_owner_read(client).unwrap()
    ));
    drop(first_guard);
}
