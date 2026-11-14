//! Real owner protocol evidence for the request-lock view boundary.
use super::super::{publication_tests, tests::Fixture};
use super::*;
use std::cell::RefCell;
use std::io::Write as _;

type CommitHook = Box<dyn FnOnce(&Store)>;
type ReadHook = Box<dyn FnOnce(&Client)>;
thread_local! { static READ: RefCell<Option<ReadHook>> = const { RefCell::new(None) }; }
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
    store.record_agent("R:cc", &outcome, None, None).unwrap();
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
