//! Reader-before-writer acceptance for workspace custody.
use super::tests::Fixture;
use crate::requests::{Mode, RequestRecord, tests::waiting};
use execute_command::workspace::{Envelope, Grant, WorkspaceEffect, canonical_digest, learned_key};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;

fn detail() -> Value {
    let grant=Grant::decode(json!({"schema":1,"loop":"alpha","run":"R","node":"fixture-node","workspace":"/work/R","baseline_env":[["PATH","/usr/bin"]],"resources":{},"shells":["/bin/sh"],"quick_policy_digest":"a".repeat(64),"blacklist_digest":"b".repeat(64),"executor_protocol":1})).unwrap();
    let envelope=Envelope::decode(json!({"schema":3,"grant_digest":grant.digest().unwrap(),"cwd":["checkout"],"execution":{"kind":"Argv","words":[b"custom".to_vec(),vec![255]]},"env_additions":[],"deadline_ms":1000})).unwrap();
    let policy_digest = grant.quick_policy_digest.clone();
    json!({"execution_digest":canonical_digest(&envelope.execution).unwrap(),"context_digest":learned_key("compute",&envelope,&grant,&policy_digest).unwrap()[2],"envelope":envelope,"grant":grant,"policy_revision":policy_digest,"blacklist_revision":"black-1","result":{"outcome":{"kind":"Unknown"},"wall_seconds":null,"user_cpu_seconds":null,"system_cpu_seconds":null},"admission_wall_seconds":null,"steps":[]})
}
fn record() -> Value {
    let mut record = waiting("R", "1a", 3000, Mode::Audit).into_value();
    record["schema"] = json!(7);
    record["class"] = json!("compute");
    record["operation"] = json!("compute-workspace");
    let detail = detail();
    record["shape_key"] = detail["context_digest"].clone();
    record["effect"]["workspace"] = detail;
    record["effect"].as_object_mut().unwrap().remove("bound");
    record["effect"]
        .as_object_mut()
        .unwrap()
        .remove("output_bytes");
    record
}

/// ´test:unit:workspace-quick-rule-citation-reads-only-for-its-grant-table´
#[test]
fn workspace_quick_rule_citation_reads_only_for_its_grant_table() {
    let mut row = record();
    let grant: Grant = serde_json::from_value(row["effect"]["workspace"]["grant"].clone()).unwrap();
    let envelope: Envelope =
        serde_json::from_value(row["effect"]["workspace"]["envelope"].clone()).unwrap();
    let digest = grant.quick_policy_digest.clone();
    let key = learned_key("compute", &envelope, &grant, &digest).unwrap();
    row["shape_key"] = key[2].clone();
    row["effect"]["workspace"]["context_digest"] = key[2].clone();
    row["effect"]["workspace"]["policy_revision"] = json!(digest);
    row["would_do_source"] = json!("quick-rule");
    row["decision_tier"] = json!("quick-rule");
    row["would_do"] = json!({"decision":"allow","reason":"fixture-rule"});
    row["matched_rule"] = json!({"rule":"fixture-rule","policy_digest":digest});
    assert_eq!(
        RequestRecord::decode(row.clone()).unwrap().into_value(),
        row
    );
    let mut changed = row.clone();
    changed["matched_rule"]["policy_digest"] = json!("b".repeat(64));
    assert!(RequestRecord::decode(changed).is_err());
    let mut changed = row.clone();
    changed["would_do"]["reason"] = json!("another-rule");
    assert!(RequestRecord::decode(changed).is_err());
    let mut changed = row;
    changed["would_do_source"] = json!("fast-lane");
    assert!(RequestRecord::decode(changed).is_err());
}

/// ´test:unit:workspace-unserved-executor-refusal-records-its-effect´
#[test]
fn workspace_unserved_executor_refusal_records_its_effect() {
    let mut row = record();
    let digest = row["effect"]["workspace"]["grant"]["quick_policy_digest"].clone();
    row["state"] = Value::Null;
    row["would_do_source"] = json!("quick-rule");
    row["decision_tier"] = json!("quick-rule");
    row["would_do"] = json!({"decision":"allow","reason":"fixture-rule"});
    row["matched_rule"] = json!({"rule":"fixture-rule","policy_digest":digest});
    row["effect"]["state"] = json!("refused");
    row["effect"]["reason"] = json!("door-workspace-protocol-refusal");
    row["effect"]["ref_check"] = json!("not-applicable");
    row["effect"]["ending"] = crate::requests::unobserved_ending();
    RequestRecord::decode(row).expect("unserved executor refusal remains readable");
}

fn finished_row(
    ending: &str,
    reason: &str,
    cause: &str,
    outcome: Value,
    output_bytes: u64,
) -> Value {
    let mut row = record();
    row["state"] = json!("observed");
    row["effect"]["state"] = json!(ending);
    row["effect"]["reason"] = json!(reason);
    row["effect"]["ref_check"] = json!("not-applicable");
    row["effect"]["workspace"]["result"]["outcome"] = outcome;
    if row["effect"]["workspace"]["result"]["outcome"]["kind"] != "Unknown" {
        row["effect"]["workspace"]["result"]["wall_seconds"] = json!(0.0);
    }
    row["effect"]["exit_status"] = row["effect"]["workspace"]["result"]["outcome"]["code"].clone();
    row["effect"]["workspace_node"] = json!({
        "node_reason":cause,"entry_version":"0.11.0",
        "entry_version_differs":false,
        "output_incomplete":matches!(ending, "incomplete" | "unknown"),
        "child_started":if cause == "unobserved" { Value::Null } else { json!(ending != "not-started") },
        "start_failure":null,
        "output_bytes":output_bytes,
        "result":row["effect"]["workspace"]["result"],
        "steps":row["effect"]["workspace"]["steps"],
        "ending":ending,
        "cause":match ending {
            "not-started" | "interrupted" => Some("input-closed"),
            "refused" => Some("output-limit"),
            "incomplete" => Some("held-output"),
            "unknown" => Some("route-incomplete"),
            _ => None,
        },
        "door_cause":null});
    row
}

/// ´test:unit:workspace-caller-endings-read-before-their-writer´
#[test]
fn workspace_caller_endings_read_before_their_writer() {
    for (ending, reason, node_reason, outcome, output_bytes) in [
        (
            "completed",
            "door-complete",
            "node-complete",
            json!({"kind":"Exited","code":0}),
            0,
        ),
        (
            "interrupted",
            "door-disconnect-refusal",
            "node-input-closed",
            json!({"kind":"Signalled","signal":15}),
            1,
        ),
        (
            "not-started",
            "door-workspace-not-started",
            "node-input-closed",
            json!({"kind":"TimedOut"}),
            0,
        ),
        (
            "refused",
            "door-output-limit-refusal",
            "node-output-limit",
            json!({"kind":"Signalled","signal":15}),
            1,
        ),
        (
            "incomplete",
            "door-workspace-incomplete",
            "node-output-incomplete",
            json!({"kind":"Exited","code":0}),
            1,
        ),
        (
            "unknown",
            "door-workspace-unknown",
            "unobserved",
            json!({"kind":"Unknown"}),
            1,
        ),
    ] {
        let row = finished_row(ending, reason, node_reason, outcome, output_bytes);
        assert_eq!(RequestRecord::decode(row.clone()).unwrap().value(), &row);
        let mut bad = row;
        bad["effect"]["workspace_node"]["entry_version"] = json!("bad version with space");
        assert_eq!(
            RequestRecord::decode(bad).unwrap_err().kind,
            "requests-record-refusal"
        );
    }
    for (field, value) in [
        ("node_reason", json!("node-input-closed")),
        (
            "result",
            json!({"outcome":{"kind":"Unknown"},"wall_seconds":null,"user_cpu_seconds":null,"system_cpu_seconds":null}),
        ),
        ("cause", json!("stop")),
    ] {
        let mut bad = finished_row(
            "completed",
            "door-complete",
            "node-complete",
            json!({"kind":"Exited","code":0}),
            0,
        );
        bad["effect"]["workspace_node"][field] = value.clone();
        if field == "result" {
            bad["effect"]["workspace"]["result"] = value;
            bad["effect"]["exit_status"] = Value::Null;
        }
        assert_eq!(
            RequestRecord::decode(bad).unwrap_err().kind,
            "requests-record-refusal"
        );
    }
    let mut legacy = waiting("R", "2a", 3000, Mode::Audit).into_value();
    legacy["effect"]["state"] = json!("not-started");
    legacy["effect"]["reason"] = json!("door-workspace-not-started");
    legacy["effect"]["ref_check"] = json!("not-applicable");
    assert_eq!(
        RequestRecord::decode(legacy).unwrap_err().kind,
        "requests-record-refusal"
    );
}

/// ´test:unit:workspace-terminal-shapes-are-not-pending´
#[test]
fn workspace_terminal_shapes_are_not_pending() {
    let rows = ["not-started", "incomplete", "unknown"]
        .into_iter()
        .enumerate()
        .map(|(index, ending)| {
            let (reason, node_reason, outcome, bytes) = match ending {
                "not-started" => (
                    "door-workspace-not-started",
                    "node-input-closed",
                    json!({"kind":"TimedOut"}),
                    0,
                ),
                "incomplete" => (
                    "door-workspace-incomplete",
                    "node-output-incomplete",
                    json!({"kind":"Exited","code":0}),
                    1,
                ),
                _ => (
                    "door-workspace-unknown",
                    "unobserved",
                    json!({"kind":"Unknown"}),
                    1,
                ),
            };
            let mut row = finished_row(ending, reason, node_reason, outcome, bytes);
            row["id"] = json!(format!("R:{index:02x}"));
            RequestRecord::decode(row).unwrap()
        })
        .collect::<Vec<_>>();
    let groups = super::Store::shapes(&[("R".to_owned(), 1, rows)]).unwrap();
    let group = &groups["groups"][0];
    assert_eq!(group["effect_pending"], 0);
    for name in ["effect_not_started", "effect_incomplete", "effect_unknown"] {
        assert_eq!(group[name], 1, "{name}");
    }
}

/// ´test:unit:workspace-record-reader-agrees-with-adapter-terminal-mapping´
#[test]
fn workspace_record_reader_agrees_with_adapter_terminal_mapping() {
    use crate::door::workspace_adapter::fixture_terminal_evidence;
    let cases = [
        ("node-complete", "Exited", true, false),
        ("node-complete", "Signalled", true, false),
        ("node-complete", "Unknown", false, false),
        ("node-deadline", "TimedOut", false, false),
        ("node-deadline", "TimedOut", true, false),
        ("node-stopped", "TimedOut", false, false),
        ("node-stopped", "Exited", false, false),
        ("node-stopped", "Exited", true, false),
        ("node-stopped", "Signalled", true, false),
        ("node-input-closed", "TimedOut", false, false),
        ("node-input-closed", "Exited", true, false),
        ("node-heartbeat-silence", "TimedOut", true, false),
        ("node-malformed-control", "TimedOut", false, false),
        ("node-output-limit", "TimedOut", true, false),
        ("node-output-limit", "Signalled", true, false),
        ("node-output-incomplete", "Exited", true, true),
        ("node-output-incomplete", "Unknown", true, true),
    ];
    for (reason, outcome, started, held) in cases {
        for bytes in [0, 1] {
            let result = match outcome {
                "Exited" => {
                    json!({"outcome":{"kind":"Exited","code":0},"wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null})
                }
                "Signalled" => {
                    json!({"outcome":{"kind":"Signalled","signal":15},"wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null})
                }
                "Unknown" => {
                    json!({"outcome":{"kind":"Unknown"},"wall_seconds":null,"user_cpu_seconds":null,"system_cpu_seconds":null})
                }
                _ => {
                    json!({"outcome":{"kind":"TimedOut"},"wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null})
                }
            };
            let frame = json!({"schema":1,"type":"terminal","request_id":"R:1a",
                "nonce":"fixture","result":result,"steps":[],"output_bytes":bytes,
                "reason":reason,"output_incomplete":held,"child_started":started});
            match fixture_terminal_evidence(frame) {
                Ok(evidence) => {
                    let ending = evidence["ending"].as_str().unwrap();
                    let record_reason = match ending {
                        "completed" => "door-complete",
                        "not-started" => "door-workspace-not-started",
                        "interrupted" => "door-disconnect-refusal",
                        "refused" => "door-output-limit-refusal",
                        "incomplete" => "door-workspace-incomplete",
                        _ => panic!("unexpected adapter ending"),
                    };
                    let mut row = finished_row(
                        ending,
                        record_reason,
                        reason,
                        evidence["result"]["outcome"].clone(),
                        bytes,
                    );
                    row["effect"]["workspace_node"] = evidence.clone();
                    row["effect"]["workspace"]["result"] = evidence["result"].clone();
                    row["effect"]["exit_status"] = evidence["result"]["outcome"]["code"].clone();
                    assert!(
                        RequestRecord::decode(row).is_ok(),
                        "{reason} {outcome} {started} {bytes}"
                    );
                }
                Err(error) => assert_eq!(error.kind, "door-workspace-protocol-refusal"),
            }
        }
    }
    let mut no_evidence = finished_row(
        "not-started",
        "door-workspace-not-started",
        "node-input-closed",
        json!({"kind":"TimedOut"}),
        0,
    );
    no_evidence["effect"]["workspace_node"]["child_started"] = Value::Null;
    assert_eq!(
        RequestRecord::decode(no_evidence).unwrap_err().kind,
        "requests-record-refusal"
    );
    let mut older_entry = finished_row(
        "interrupted",
        "door-disconnect-refusal",
        "node-input-closed",
        json!({"kind":"Exited","code":0}),
        0,
    );
    older_entry["effect"]["workspace_node"]["child_started"] = Value::Null;
    assert!(RequestRecord::decode(older_entry).is_ok());
}

fn failed_sequence_fixture() -> (Value, Value) {
    let output_len = b"prior".len() + b"/no-such-workspace-program: not found\n".len();
    let mut row = finished_row(
        "interrupted",
        "door-complete",
        "node-start-failed",
        json!({"kind":"Unknown"}),
        output_len as u64,
    );
    let grant = Grant::decode(row["effect"]["workspace"]["grant"].clone()).unwrap();
    let envelope = Envelope::decode(json!({
        "schema":3,"grant_digest":grant.digest().unwrap(),"cwd":["checkout"],
        "execution":{"kind":"Sequence","steps":[
            [b"/bin/sh".to_vec(),b"-c".to_vec(),b"printf prior".to_vec()],
            [b"/no-such-workspace-program".to_vec()]]},
        "env_additions":[],"deadline_ms":1000
    }))
    .unwrap();
    let detail = &mut row["effect"]["workspace"];
    detail["execution_digest"] = json!(canonical_digest(&envelope.execution).unwrap());
    detail["context_digest"] =
        json!(learned_key("compute", &envelope, &grant, &grant.quick_policy_digest).unwrap()[2]);
    detail["envelope"] = json!(envelope);
    row["shape_key"] = detail["context_digest"].clone();
    let successful = json!({"outcome":{"kind":"Exited","code":0},
        "wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null});
    let failed = json!({"outcome":{"kind":"Unknown"},
        "wall_seconds":0.0,"user_cpu_seconds":null,"system_cpu_seconds":null});
    row["effect"]["workspace"]["steps"] = json!([successful, failed]);
    let frame = json!({"schema":1,"type":"terminal","request_id":"R:1a",
        "nonce":"fixture","result":row["effect"]["workspace"]["result"],
        "steps":row["effect"]["workspace"]["steps"],"output_bytes":output_len,
        "reason":"node-start-failed","output_incomplete":false,"child_started":true,
        "start_failure":{"kind":"not-found","step_index":1}});
    (row, frame)
}

/// ´test:unit:workspace-failed-start-status-is-record-readable´
#[test]
fn workspace_failed_start_status_is_record_readable() {
    use crate::door::workspace_adapter::fixture_failed_start;
    for (kind, status, line) in [
        ("not-found", 127, "custom: not found\n"),
        ("not-executable", 126, "custom: not executable\n"),
        ("other", 126, "custom: could not start\n"),
    ] {
        let mut row = finished_row(
            "not-started",
            "door-workspace-not-started",
            "node-start-failed",
            json!({"kind":"Unknown"}),
            line.len() as u64,
        );
        let frame = json!({"schema":1,"type":"terminal","request_id":"R:1a",
            "nonce":"fixture","result":row["effect"]["workspace"]["result"],
            "steps":[],"output_bytes":line.len(),"reason":"node-start-failed",
            "output_incomplete":false,"child_started":false,
            "start_failure":{"kind":kind,"step_index":0}});
        let (evidence, mapped_status) =
            fixture_failed_start(frame, &row["effect"]["workspace"]["envelope"]["execution"])
                .unwrap();
        assert_eq!(mapped_status, Some(status), "{kind}");
        assert_eq!(evidence["ending"], "not-started");
        row["effect"]["workspace_node"] = evidence;
        row["effect"]["exit_status"] = json!(status);
        assert!(RequestRecord::decode(row).is_ok(), "{kind}");
    }
    let (mut row, frame) = failed_sequence_fixture();
    let mut held_row = row.clone();
    let mut held_frame = frame.clone();
    let (evidence, status) =
        fixture_failed_start(frame, &row["effect"]["workspace"]["envelope"]["execution"]).unwrap();
    assert_eq!(evidence["ending"], "interrupted");
    assert_eq!(status, Some(127));
    row["effect"]["workspace_node"] = evidence;
    row["effect"]["exit_status"] = json!(127);
    assert!(RequestRecord::decode(row).is_ok());

    held_frame["reason"] = json!("node-output-incomplete");
    held_frame["output_incomplete"] = json!(true);
    held_row["effect"]["state"] = json!("incomplete");
    held_row["effect"]["reason"] = json!("door-workspace-incomplete");
    let (evidence, status) = fixture_failed_start(
        held_frame.clone(),
        &held_row["effect"]["workspace"]["envelope"]["execution"],
    )
    .unwrap();
    assert_eq!(evidence["ending"], "incomplete");
    assert_eq!(evidence["cause"], "held-output");
    assert_eq!(
        evidence["start_failure"],
        json!({"kind":"not-found","step_index":1})
    );
    assert_eq!(status, Some(127));
    held_row["effect"]["workspace_node"] = evidence;
    held_row["effect"]["exit_status"] = json!(127);
    assert!(RequestRecord::decode(held_row.clone()).is_ok());

    held_frame["child_started"] = json!(false);
    assert_eq!(
        fixture_failed_start(
            held_frame,
            &held_row["effect"]["workspace"]["envelope"]["execution"],
        )
        .unwrap_err()
        .kind,
        "door-workspace-protocol-refusal"
    );
}

/// ´test:unit:workspace-output-limit-retains-a-later-failed-start´
#[test]
fn workspace_output_limit_retains_a_later_failed_start() {
    use crate::door::workspace_adapter::fixture_failed_start;
    let (mut row, mut frame) = failed_sequence_fixture();
    frame["reason"] = json!("node-output-limit");
    frame["output_incomplete"] = json!(true);
    row["effect"]["state"] = json!("refused");
    row["effect"]["reason"] = json!("door-output-limit-refusal");
    let (evidence, status) = fixture_failed_start(
        frame.clone(),
        &row["effect"]["workspace"]["envelope"]["execution"],
    )
    .unwrap();
    assert_eq!(evidence["ending"], "refused");
    assert_eq!(evidence["cause"], "output-limit");
    assert_eq!(
        evidence["start_failure"],
        json!({"kind":"not-found","step_index":1})
    );
    assert_eq!(status, Some(127));
    row["effect"]["workspace_node"] = evidence;
    row["effect"]["exit_status"] = json!(127);
    assert!(RequestRecord::decode(row.clone()).is_ok());

    frame["child_started"] = json!(false);
    assert_eq!(
        fixture_failed_start(frame, &row["effect"]["workspace"]["envelope"]["execution"])
            .unwrap_err()
            .kind,
        "door-workspace-protocol-refusal"
    );
    let first_row = finished_row(
        "refused",
        "door-output-limit-refusal",
        "node-output-limit",
        json!({"kind":"Unknown"}),
        1,
    );
    let first_frame = json!({"schema":1,"type":"terminal","request_id":"R:1a",
        "nonce":"fixture","result":first_row["effect"]["workspace"]["result"],
        "steps":[],"output_bytes":1,"reason":"node-output-limit",
        "output_incomplete":true,"child_started":false,
        "start_failure":{"kind":"not-found","step_index":0}});
    assert_eq!(
        fixture_failed_start(
            first_frame,
            &first_row["effect"]["workspace"]["envelope"]["execution"],
        )
        .unwrap_err()
        .kind,
        "door-workspace-protocol-refusal"
    );
}
/// ´test:unit:workspace-record-seven-is-strict-and-six-is-unchanged´
#[test]
fn workspace_record_seven_is_strict_and_six_is_unchanged() {
    let row = record();
    assert_eq!(
        RequestRecord::decode(row.clone()).unwrap().into_value(),
        row
    );
    let old = waiting("S", "2b", 3000, Mode::Audit).into_value();
    assert_eq!(old["schema"], 6);
    assert_eq!(
        RequestRecord::decode(old.clone()).unwrap().into_value(),
        old
    );
    let mut legacy = old;
    legacy["class"] = json!("compute");
    legacy["operation"] = json!("compute");
    legacy["shape_key"] = json!("compute:cargo test");
    legacy["effect"].as_object_mut().unwrap().remove("bound");
    legacy["effect"]
        .as_object_mut()
        .unwrap()
        .remove("output_bytes");
    legacy["effect"]["state"] = json!("completed");
    legacy["effect"]["reason"] = json!("door-complete");
    legacy["effect"]["exit_status"] = json!(0);
    legacy["effect"]["ref_check"] = json!("not-applicable");
    legacy["effect"]["compute"] = json!({"words":["cargo","test","--locked"],"checkout_path":"/work/S","checkout_ref":"refs/heads/lane/alpha","checkout_commit":"c".repeat(40),"wrapper_exit_status":0,"wrapper_wall_seconds":0.2,"wrapper_user_cpu_seconds":0.1,"wrapper_system_cpu_seconds":0.0,"preparation_wall_seconds":0.0,"tree_clean":true,"tree_change_count":0,"discarded":{"tracked":0,"untracked":0}});
    assert_eq!(
        RequestRecord::decode(legacy.clone()).unwrap().into_value(),
        legacy
    );
    for (pointer, value) in [
        ("/schema", json!(6)),
        ("/shape_key", json!("compute:cargo test")),
        ("/effect/workspace/context_digest", json!("c".repeat(64))),
        ("/effect/workspace/envelope/cwd", json!([".."])),
        ("/effect/workspace/result/wall_seconds", json!(-1)),
    ] {
        let mut bad = row.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            RequestRecord::decode(bad).unwrap_err().kind,
            "requests-record-refusal",
            "{pointer}"
        );
    }
    let mut missing = detail();
    missing["result"]
        .as_object_mut()
        .unwrap()
        .remove("wall_seconds");
    assert_eq!(
        WorkspaceEffect::decode(missing, "compute", "alpha", "R")
            .unwrap_err()
            .kind,
        "door-workspace-protocol-refusal"
    );
    let mut detail = detail();
    detail["tree_clean"] = json!(true);
    assert!(WorkspaceEffect::decode(detail, "compute", "alpha", "R").is_err());
}
fn prepared_fixture() -> Fixture {
    let fixture = Fixture::new();
    let socket = fixture.home.join("socket");
    let door = socket.join("door");
    for path in [&socket, &door] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let settings = fixture.home.join(".config/loops/alpha/workers.toml");
    fs::write(&settings, format!("socket_dir = {}\n", json!(socket))).unwrap();
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
    fixture
}

fn custodied_request(fixture: &Fixture, envelope: &Envelope) -> crate::door::WorkspaceRequest {
    use crate::door::{Registration, Scope};
    let runs = fixture.home.join("runs");
    let held = File::open(&runs).expect("held runs").into();
    let registration = Registration {
        loop_name: "alpha".into(),
        run: "R".into(),
        worker_uid: 3000,
        loop_uid: 41001,
        scope: Scope::Work,
        mirror_ref: "refs/heads/lane/R".into(),
    };
    let reservation = crate::launch::reservation_path(&runs, "R");
    let saved = json!({"schema":1,"phase":"started","loop":"alpha","run":"R",
        "worker_uid":3000,"door_scope":"work","plan":{"loop":"alpha","run":"R",
        "compute_workspace":crate::plan::fixture_workspace_snapshot()}});
    crate::launch::publish_reservation(&reservation, &saved).expect("protected grant");
    let wire = serde_json::to_vec(envelope).expect("workspace wire");
    crate::door::workspace_request(
        &held,
        &registration,
        nix::unistd::Uid::effective().as_raw(),
        "fixture-node",
        &wire,
    )
    .expect("custodied request")
}

/// ´test:unit:workspace-caller-files-exact-pending-schema-seven-intent´
#[test]
fn workspace_caller_files_exact_pending_schema_seven_intent() {
    let fixture = prepared_fixture();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let registration = crate::door::Registration {
        loop_name: "alpha".into(),
        run: "R".into(),
        worker_uid: 3000,
        loop_uid: 41001,
        scope: crate::door::Scope::Work,
        mirror_ref: "refs/heads/lane/R".into(),
    };
    let seed = waiting("R", "1a", 3000, Mode::Audit).into_value();
    let setting = json!({"mode":seed["mode"],"floor":seed["floor"],
        "class":seed["class_setting"],"loop":seed["loop_setting"]});
    let row = crate::door::workspace_record(
        &registration,
        &setting,
        &request,
        execute_command::workspace::Disposition::WaitForJudgement,
        &json!({"decision":"undecided","reason":"workspace miss"}),
        Value::Null,
    )
    .expect("schema-seven intent");
    let value = row.value();
    assert_eq!(value["schema"], 7);
    assert_eq!(value["state"], "waiting");
    assert_eq!(value["effect"]["state"], "pending");
    assert_eq!(value["effect"]["workspace"]["envelope"], json!(envelope));
    assert_eq!(
        value["effect"]["workspace"]["grant"],
        json!(request.grant())
    );
    assert_eq!(
        value["effect"]["workspace"]["policy_revision"],
        request.grant().quick_policy_digest
    );
    assert_eq!(RequestRecord::decode(value.clone()).unwrap().value(), value);
}

fn approved_record(
    store: &crate::requests::store::Store,
    id: &str,
    envelope: &Envelope,
) -> RequestRecord {
    let mut row = record();
    row["id"] = json!(id);
    let grant: Grant =
        serde_json::from_value(row["effect"]["workspace"]["grant"].clone()).expect("grant");
    let revision = grant.quick_policy_digest.clone();
    let key = learned_key("compute", envelope, &grant, &revision).expect("learned key");
    row["shape_key"] = key[2].clone();
    row["effect"]["workspace"]["envelope"] = json!(envelope);
    row["effect"]["workspace"]["policy_revision"] = json!(revision);
    row["effect"]["workspace"]["execution_digest"] =
        json!(canonical_digest(&envelope.execution).expect("execution digest"));
    row["effect"]["workspace"]["context_digest"] = key[2].clone();
    store
        .file(RequestRecord::decode(row).expect("workspace intent"))
        .expect("file intent");
    let result = crate::door::agent::RunnerOutcome {
        verdict: "allow".into(),
        scope: "loop".into(),
        reason: "fictional reviewed allow".into(),
        status: "verdict".into(),
        model: None,
        wall_ms: 1,
        rubric_digest: None,
        observations: json!({}),
        runner_exit: None,
        runner_stderr_tail: None,
        runner_first_line: String::new(),
    };
    let input = execute_command::workspace::agent_input(
        envelope,
        &grant,
        &["fictional unknown command".into()],
    )
    .expect("judge input");
    store
        .record_agent(id, &result, None, None, Some(&input))
        .expect("agent judgement")
}

/// ´test:unit:workspace-judgement-input-reader-binds-exact-execution´
#[test]
fn workspace_judgement_input_reader_binds_exact_execution() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let recorded = approved_record(&store, "R:1a", &envelope);
    let row = recorded.into_value();
    let grant: Grant = serde_json::from_value(row["effect"]["workspace"]["grant"].clone()).unwrap();
    assert_eq!(row["workspace_agent_input"]["grant_summary"], json!(grant));
    assert_eq!(
        RequestRecord::decode(row.clone()).unwrap().into_value(),
        row
    );
    for pointer in [
        "/workspace_agent_input/execution/words/0/0",
        "/workspace_agent_input/cwd/0",
        "/workspace_agent_input/env_additions",
    ] {
        let mut changed = row.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        assert_eq!(
            RequestRecord::decode(changed).unwrap_err().kind,
            "requests-record-refusal",
            "{pointer}"
        );
    }
    let mut different_display = row.clone();
    different_display["workspace_agent_input"]["execution_readable_display_only"]["words"][0] =
        json!("different table rendering");
    RequestRecord::decode(different_display).expect("stored display is not regenerated");
    let mut malformed_display = row.clone();
    malformed_display["workspace_agent_input"]["execution_readable_display_only"]["words"] =
        json!([]);
    assert_eq!(
        RequestRecord::decode(malformed_display).unwrap_err().kind,
        "requests-record-refusal"
    );
    let mut false_flag = row.clone();
    false_flag["workspace_agent_input"]["flagged_code_points"]["rows"] = json!([{"field":"execution.words[0]","first_byte_offset":0,"code_point":"U+00E9","count":1}]);
    assert_eq!(
        RequestRecord::decode(false_flag).unwrap_err().kind,
        "requests-record-refusal"
    );
    let mut old = row;
    old.as_object_mut().unwrap().remove("workspace_agent_input");
    assert_eq!(
        RequestRecord::decode(old).unwrap_err().kind,
        "requests-record-refusal"
    );
}

/// ´test:unit:workspace-judgement-reader-requires-flag-coverage-floor´
#[test]
fn workspace_judgement_reader_requires_flag_coverage_floor() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let mut envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    envelope.execution = execute_command::workspace::Execution::Argv {
        words: vec!["сargo".as_bytes().to_vec()],
    };
    let mut missing = approved_record(&store, "R:2b", &envelope).into_value();
    missing["workspace_agent_input"]["flagged_code_points"]["rows"] = json!([]);
    missing["workspace_agent_input"]["flagged_code_points"]["omitted_count"] = json!(0);
    assert_eq!(
        RequestRecord::decode(missing.clone()).unwrap_err().kind,
        "requests-record-refusal"
    );
    missing["workspace_agent_input"]["flagged_code_points"]["omitted_count"] = json!(1);
    RequestRecord::decode(missing).expect("the omitted count covers the Cyrillic point");
}

/// ´test:unit:workspace-judgement-reader-accepts-true-ascii-extra-flag´
#[test]
fn workspace_judgement_reader_accepts_true_ascii_extra_flag() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let mut envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    envelope.execution = execute_command::workspace::Execution::Argv {
        words: vec!["сargo".as_bytes().to_vec()],
    };
    let mut row = approved_record(&store, "R:2c", &envelope).into_value();
    row["workspace_agent_input"]["flagged_code_points"]["rows"]
        .as_array_mut().unwrap().push(json!({"field":"execution.words[0]","first_byte_offset":2,"code_point":"U+0061","count":1}));
    RequestRecord::decode(row).expect("a true ASCII row is allowed beyond the floor");
}

/// ´test:unit:workspace-judgement-reader-refuses-false-grant-flag-and-display-shape´
#[test]
fn workspace_judgement_reader_refuses_false_grant_flag_and_display_shape() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let mut envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    envelope.execution = execute_command::workspace::Execution::Argv {
        words: vec!["сargo".as_bytes().to_vec()],
    };
    let row = approved_record(&store, "R:2d", &envelope).into_value();
    let flag = row["workspace_agent_input"]["flagged_code_points"]["rows"][0].clone();
    let mutations = [
        (
            "grant",
            "/workspace_agent_input/grant_summary/workspace",
            json!("/work/other"),
        ),
        (
            "first offset",
            "/workspace_agent_input/flagged_code_points/rows/0/first_byte_offset",
            json!(1),
        ),
        (
            "count",
            "/workspace_agent_input/flagged_code_points/rows/0/count",
            json!(2),
        ),
        (
            "unknown field",
            "/workspace_agent_input/flagged_code_points/rows/0/field",
            json!("execution.words[9]"),
        ),
        (
            "display kind",
            "/workspace_agent_input/execution_readable_display_only/kind",
            json!("shell"),
        ),
    ];
    for (name, pointer, value) in mutations {
        let mut changed = row.clone();
        *changed.pointer_mut(pointer).expect("fixture member") = value;
        assert_eq!(
            RequestRecord::decode(changed).unwrap_err().kind,
            "requests-record-refusal",
            "{name}"
        );
    }
    let mut repeated = row;
    repeated["workspace_agent_input"]["flagged_code_points"]["rows"]
        .as_array_mut()
        .expect("flag rows")
        .push(flag);
    assert_eq!(
        RequestRecord::decode(repeated).unwrap_err().kind,
        "requests-record-refusal",
        "repeated row"
    );
}

/// ´test:unit:workspace-judgement-input-refused-on-unjudged-intent´
#[test]
fn workspace_judgement_input_refused_on_unjudged_intent() {
    let mut row = record();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let grant: Grant = serde_json::from_value(detail()["grant"].clone()).unwrap();
    row["workspace_agent_input"] =
        execute_command::workspace::agent_input(&envelope, &grant, &[]).unwrap();
    assert_eq!(
        RequestRecord::decode(row).unwrap_err().kind,
        "requests-record-refusal"
    );
}

/// ´test:unit:workspace-unanswered-miss-follows-door-mode´
#[test]
fn workspace_unanswered_miss_follows_door_mode() {
    use execute_command::policy::DoorMode;
    use execute_command::workspace::{Classification, Disposition};
    let fixture = prepared_fixture();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let miss = Classification::Miss {
        reasons: vec!["unrecognised command".into()],
    };
    for (mode, expected) in [
        (DoorMode::Allow, Disposition::ImmediateJudgeAlongside),
        (DoorMode::Audit, Disposition::WaitForJudgement),
        (DoorMode::Enforce, Disposition::WaitForJudgement),
    ] {
        assert_eq!(request.disposition(mode, &miss, None).unwrap(), expected);
    }
}

/// ´test:unit:workspace-agent-input-uses-the-existing-door-call-envelope´
#[test]
fn workspace_agent_input_uses_the_existing_door_call_envelope() {
    let fixture = prepared_fixture();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let input = request
        .agent_input(&["fictional miss".into()], "fictional rubric")
        .unwrap();
    let encoded: Value = serde_json::from_slice(&input.encode().unwrap()).unwrap();
    assert_eq!(encoded["capability_class"], "compute");
    assert_eq!(encoded["reviewed_rubric"], "fictional rubric");
    assert_eq!(encoded["request"]["execution"], json!(envelope.execution));
    assert_eq!(
        encoded["request"]["miss_reasons"],
        json!(["fictional miss"])
    );
}

/// ´test:unit:workspace-judgement-allowance-refuses-envelope-replays´
#[test]
fn workspace_judgement_allowance_refuses_envelope_replays() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1a", &envelope);
    let allowance =
        crate::door::WorkspaceAllowance::from_judgement_record(&store, "R:1a", &request)
            .expect("recorded allowance");
    assert_eq!(allowance.evidence()["source"], "judgement");
    allowance.check(&request).expect("exact envelope");
    for changed in [
        {
            let mut value = envelope.clone();
            value.cwd.push("other".into());
            value
        },
        {
            let mut value = envelope.clone();
            value.env_additions.push(("X".into(), "1".into()));
            value
        },
        {
            let mut value = envelope;
            value.execution = execute_command::workspace::Execution::Argv {
                words: vec![b"different".to_vec()],
            };
            value
        },
    ] {
        let changed_request = custodied_request(&fixture, &changed);
        assert_eq!(
            allowance.check(&changed_request).unwrap_err().kind,
            "door-workspace-context-differs"
        );
        assert_eq!(
            crate::door::WorkspaceAllowance::from_judgement_record(
                &store,
                "R:1a",
                &changed_request
            )
            .err()
            .expect("replay refused")
            .kind,
            "door-workspace-context-differs"
        );
    }
}

/// ´test:unit:workspace-judgement-allowance-refuses-changed-shell-text´
#[test]
fn workspace_judgement_allowance_refuses_changed_shell_text() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let mut envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    envelope.execution = execute_command::workspace::Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf original".into(),
    };
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1b", &envelope);
    let allowance =
        crate::door::WorkspaceAllowance::from_judgement_record(&store, "R:1b", &request)
            .expect("shell allowance");
    let mut changed = envelope;
    changed.execution = execute_command::workspace::Execution::Shell {
        shell: "/bin/sh".into(),
        text: "printf changed".into(),
    };
    let changed_request = custodied_request(&fixture, &changed);
    assert_eq!(
        allowance.check(&changed_request).unwrap_err().kind,
        "door-workspace-context-differs"
    );
}

/// ´test:unit:workspace-judgement-allowance-needs-stored-agent-allow-without-loop-refusal´
#[test]
fn workspace_judgement_allowance_needs_stored_agent_allow_without_loop_refusal() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1a", &envelope);
    assert!(
        crate::door::WorkspaceAllowance::from_judgement_record(&store, "R:9f", &request).is_err()
    );
    store
        .triage(
            "R",
            &[json!({"id":"R:1a","action":"adjudicate",
        "treatment":"refuse","reason":"fictional loop refusal"})],
            "superloop",
            "2",
        )
        .expect("loop refusal");
    assert_eq!(
        crate::door::WorkspaceAllowance::from_judgement_record(&store, "R:1a", &request)
            .err()
            .expect("loop refusal wins")
            .kind,
        "door-workspace-context-differs"
    );
}

/// ´test:unit:workspace-learned-allowance-comes-from-the-store-lookup´
#[test]
fn workspace_learned_allowance_comes_from_the_store_lookup() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let (allowance, fault) = crate::door::WorkspaceAllowance::from_store_lookup(&store, &request)
        .expect("unavailable learned store is a miss");
    assert!(allowance.is_none());
    assert!(fault.is_some());
    approved_record(&store, "R:1a", &envelope);
    let (allowance, fault) = crate::door::WorkspaceAllowance::from_store_lookup(&store, &request)
        .expect("unanswered lookup");
    assert!(allowance.is_none() && fault.is_none());
    store
        .triage(
            "R",
            &[json!({"id":"R:1a","action":"adjudicate",
        "treatment":"allow","reason":"fictional reviewed decision"})],
            "superloop",
            "2",
        )
        .expect("protected label");
    let learned = crate::door::WorkspaceAllowance::from_store_lookup(&store, &request)
        .expect("label lookup")
        .0
        .expect("learned allow");
    let allowance = learned.allowance().expect("positive label");
    assert_eq!(allowance.evidence()["source"], "learned");
    allowance.check(&request).expect("exact context");
    assert_eq!(
        request
            .disposition(
                execute_command::policy::DoorMode::Enforce,
                &execute_command::workspace::Classification::Miss {
                    reasons: vec!["fictional miss".into()],
                },
                Some(&learned),
            )
            .unwrap(),
        execute_command::workspace::Disposition::Immediate,
    );
}

/// ´test:unit:workspace-learned-refusal-reaches-door-disposition´
#[test]
fn workspace_learned_refusal_reaches_door_disposition() {
    use execute_command::policy::DoorMode;
    use execute_command::workspace::{Classification, Disposition};
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1a", &envelope);
    store
        .triage(
            "R",
            &[json!({"id":"R:1a","action":"adjudicate",
                "treatment":"refuse","reason":"fictional reviewed refusal"})],
            "superloop",
            "2",
        )
        .expect("protected refusal");
    let learned = crate::door::WorkspaceAllowance::from_store_lookup(&store, &request)
        .expect("label lookup")
        .0
        .expect("learned refusal");
    assert!(learned.allowance().is_none());
    let miss = Classification::Miss {
        reasons: vec!["fictional miss".into()],
    };
    for (mode, expected) in [
        (DoorMode::Allow, Disposition::ImmediateRecordRefusal),
        (DoorMode::Enforce, Disposition::Block),
        (DoorMode::Audit, Disposition::WaitForJudgement),
    ] {
        assert_eq!(
            request.disposition(mode, &miss, Some(&learned)).unwrap(),
            expected
        );
    }
}

/// ´test:unit:workspace-allow-intent-reads-unpublished-request-state´
#[test]
fn workspace_allow_intent_reads_unpublished_request_state() {
    let fixture = prepared_fixture();
    fixture.set_floor("allow");
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let mut row = record();
    let mode = crate::requests::ModeSetting::first(
        Mode::Allow,
        Mode::Allow,
        "owner",
        "fictional allow mode",
        "1",
    )
    .unwrap();
    row["mode"] = json!("allow");
    row["floor"] = json!("allow");
    row["class_setting"] = mode.value().clone();
    row["loop_setting"] = mode.value().clone();
    row["state"] = Value::Null;
    let grant = request.grant();
    let key = learned_key("compute", &envelope, grant, &grant.quick_policy_digest).unwrap();
    row["shape_key"] = key[2].clone();
    row["effect"]["workspace"]["policy_revision"] = json!(grant.quick_policy_digest);
    row["effect"]["workspace"]["context_digest"] = key[2].clone();
    store.file(RequestRecord::decode(row).unwrap()).unwrap();
    let intent = crate::door::WorkspaceIntent::from_store(&store, "R:1a", &request)
        .expect("filed but unpublished allow intent");
    intent.check(&request, "R:1a").unwrap();
    assert_eq!(
        intent.check(&request, "R:9f").unwrap_err().kind,
        "door-workspace-context-differs"
    );
}
/// ´test:unit:workspace-schema-seven-survives-rewrite-and-index-rebuild´
#[test]
fn workspace_schema_seven_survives_rewrite_and_index_rebuild() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let row = record();
    store
        .file(RequestRecord::decode(row.clone()).unwrap())
        .unwrap();
    store.file(waiting("S", "2b", 3000, Mode::Audit)).unwrap();
    let path = fixture.home.join("runs/.launch-R/door-requests.json");
    let before = fs::read(&path).unwrap();
    let preview = store.rewrite(None).unwrap();
    assert_eq!(preview["changed"], 0);
    store.rewrite(preview["preview_sha256"].as_str()).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    store.rebuild_index().unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(store.request("R:1a").unwrap().into_value(), row);
    let status = store.learned_status();
    assert_eq!(status["state"], "current");
    let index: Value = serde_json::from_slice(
        &fs::read(fixture.home.join(".config/loops/alpha/door-learned.json")).unwrap(),
    )
    .unwrap();
    let key = json!(["compute", "compute-workspace", row["shape_key"]]).to_string();
    assert!(index["groups"][&key].is_object());
    assert!(
        index["groups"][json!(["compute", "compute", "compute:cargo test"]).to_string()].is_null()
    );
}
/// ´test:unit:workspace-cut-pins-legacy-node-payloads-until-w5´
#[test]
fn workspace_cut_pins_legacy_node_payloads_until_w5() {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let hash = |bytes: &[u8]| {
        let mut hex = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            let _written = write!(hex, "{byte:02x}");
        }
        hex
    };
    assert_eq!(
        hash(include_bytes!("../door/compute_node.py")),
        "8966f160980b65c4868f32e53a5cc40f70cb868f85d26c828ceb8b1590b1c0ec"
    );
    assert_eq!(
        hash(include_bytes!("../door/retire_node.py")),
        "94a7ac7fd5c6c82e086ccec13c0a410f16d32ebd86506a4e40da2f80309a99b5"
    );
}

fn preflight(check: &str, words: Value) -> Value {
    let mut row = waiting("R", "1a", 3000, Mode::Audit).into_value();
    row["class"] = json!("preflight");
    row["operation"] = json!("preflight");
    row["shape_key"] = json!(format!("preflight:{check}"));
    row["state"] = json!("preflight-refused");
    row["would_do"] = json!({"decision":"refuse","reason":check});
    row["would_do_source"] = json!("fast-lane");
    row["effect"] = json!({"state":"refused","reason":check,"exit_status":125,
        "ref_check":"not-reached","stdin_bytes":0,"stdout_bytes":0,"stderr_bytes":0,
        "queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0,
        "preflight":{"check":check,"words":null}});
    row["effect"]["ending"] = crate::requests::unobserved_ending();
    row["effect"]["preflight"]["words"] = words;
    row
}

/// ´test:unit:workspace-shared-preflight-refusals-use-empty-untagged-words´
#[test]
fn workspace_shared_preflight_refusals_use_empty_untagged_words() {
    for check in [
        "door-caller-authority-refusal",
        "door-review-compute-refusal",
    ] {
        let row = preflight(check, json!([]));
        assert_eq!(
            RequestRecord::decode(row.clone()).unwrap().into_value(),
            row,
            "{check}"
        );
        let tagged = preflight(check, json!({"schema":3,"wire_bytes":[],"truncated":false}));
        assert_eq!(
            RequestRecord::decode(tagged).unwrap_err().kind,
            "requests-record-refusal",
            "{check}"
        );
    }
}
/// ´test:unit:workspace-preflight-reader-preserves-bounded-wire-evidence´
#[test]
fn workspace_preflight_reader_preserves_bounded_wire_evidence() {
    let mut envelope = detail()["envelope"].clone();
    envelope["execution"] = json!({"kind":"Argv","words":vec![vec![b'x';256];256]});
    let wire = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        Envelope::from_bytes(&wire).unwrap().execution,
        execute_command::workspace::Execution::Argv {
            words: vec![vec![b'x'; 256]; 256]
        }
    );
    let words = json!({"schema":3,"wire_bytes":&wire[..super::super::MAX_WORKSPACE_PREFLIGHT_BYTES],"truncated":true});
    for check in [
        "door-workspace-unregistered",
        "door-workspace-context-differs",
        "door-workspace-protocol-refusal",
    ] {
        let row = preflight(check, words.clone());
        assert_eq!(
            RequestRecord::decode(row.clone()).unwrap().into_value(),
            row,
            "{check}"
        );
    }
    // Malformed wire is evidence of a refusal, not input to a second decoder.
    let malformed = json!({"schema":3,"wire_bytes":[255,0,123],"truncated":false});
    let row = preflight("door-workspace-protocol-refusal", malformed);
    let fixture = prepared_fixture();
    let store = fixture.store();
    store
        .file(RequestRecord::decode(row.clone()).unwrap())
        .unwrap();
    let path = fixture.home.join("runs/.launch-R/door-requests.json");
    let before = fs::read(&path).unwrap();
    let preview = store.rewrite(None).unwrap();
    assert_eq!(preview["changed"], 0);
    store.rewrite(preview["preview_sha256"].as_str()).unwrap();
    store.rebuild_index().unwrap();
    assert_eq!(store.request("R:1a").unwrap().into_value(), row);
    assert_eq!(fs::read(path).unwrap(), before);
    for bad in [
        json!([]),
        json!({"schema":3,"wire_bytes":[256],"truncated":false}),
        json!({"schema":3,"wire_bytes":[255],"truncated":true}),
        json!({"schema":3,"wire_bytes":[],"truncated":false,"extra":0}),
        json!({"schema":2,"wire_bytes":[],"truncated":false}),
    ] {
        let error =
            RequestRecord::decode(preflight("door-workspace-protocol-refusal", bad)).unwrap_err();
        assert_eq!(error.kind, "requests-record-refusal");
        assert!(error.to_string().contains("preflight refusal differs"));
    }
    let legacy = preflight("door-compute-words-refusal", json!([b"cargo".to_vec()]));
    assert!(RequestRecord::decode(legacy).is_ok());
    assert!(
        RequestRecord::decode(preflight(
            "door-request-refusal",
            json!({"schema":3,"bad":"legacy raw argv"})
        ))
        .is_ok()
    );
    assert!(
        RequestRecord::decode(preflight(
            "door-compute-words-refusal",
            json!(vec![vec![120]; 256])
        ))
        .is_err()
    );
}
/// ´test:unit:workspace-preflight-reader-bounds-truncated-evidence´
#[test]
fn workspace_preflight_reader_bounds_truncated_evidence() {
    let maximum = super::super::MAX_WORKSPACE_PREFLIGHT_BYTES;
    let words = json!({"schema":3,"wire_bytes":vec![255;maximum],"truncated":true});
    assert!(
        RequestRecord::decode(preflight("door-workspace-protocol-refusal", words.clone())).is_ok()
    );
    for check in [
        "door-workspace-unregistered",
        "door-workspace-context-differs",
        "door-workspace-protocol-refusal",
    ] {
        assert!(
            RequestRecord::decode(preflight(check, words.clone())).is_ok(),
            "{check}"
        );
        let mut short = words.clone();
        short["wire_bytes"].as_array_mut().unwrap().pop();
        assert!(
            RequestRecord::decode(preflight(check, short)).is_err(),
            "short truncated {check}"
        );
    }
    let mut complete = words.clone();
    complete["truncated"] = json!(false);
    assert!(RequestRecord::decode(preflight("door-workspace-unregistered", complete)).is_ok());
    assert!(
        serde_json::to_vec(&preflight("door-workspace-unregistered", words.clone()))
            .unwrap()
            .len()
            < 270_000
    );
    for check in [
        "door-compute-words-refusal",
        "door-compute-command-refusal",
        "door-compute-wrapper-refusal",
        "door-compute-locked-refusal",
        "door-compute-unregistered",
        "door-compute-root-refusal",
        "door-transport-pending",
        "door-requests-unregistered",
        "door-caller-authority-refusal",
        "door-review-compute-refusal",
    ] {
        assert!(
            RequestRecord::decode(preflight(check, words.clone())).is_err(),
            "legacy check {check}"
        );
    }
    for check in ["door-changed-ref-refusal", "door-request-refusal"] {
        for words in [
            json!({"schema":3,"wire_bytes":[1,2],"truncated":false}),
            json!({"schema":3,"wire_bytes":[256],"truncated":true}),
        ] {
            let row = preflight(check, words);
            assert_eq!(
                RequestRecord::decode(row.clone()).unwrap().into_value(),
                row,
                "legacy evidence for {check} is not decoded as tagged workspace evidence"
            );
        }
    }
    let too_long = json!({"schema":3,"wire_bytes":vec![255;maximum+1],"truncated":false});
    assert!(RequestRecord::decode(preflight("door-workspace-protocol-refusal", too_long)).is_err());
}

/// ´test:unit:workspace-claim-checks-own-mode-ground-before-start´
#[test]
fn workspace_claim_checks_own_mode_ground_before_start() {
    use crate::requests::modes::ModeTarget;
    let fixture = prepared_fixture();
    fixture.set_floor("allow");
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    let registration = crate::door::Registration {
        loop_name: "alpha".into(),
        run: "R".into(),
        worker_uid: 3000,
        loop_uid: 41001,
        scope: crate::door::Scope::Work,
        mirror_ref: "refs/heads/lane/R".into(),
    };
    store
        .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "fixture", "1", &[])
        .unwrap();
    store
        .set_mode(
            &ModeTarget::class("compute").unwrap(),
            Mode::Allow,
            "owner",
            "fixture",
            "1",
            &[],
        )
        .unwrap();
    let setting = store.effective_mode("compute").unwrap();
    let row = crate::door::workspace_record(
        &registration,
        &setting,
        &request,
        execute_command::workspace::Disposition::ImmediateJudgeAlongside,
        &json!({"decision":"undecided","reason":"fixture miss"}),
        Value::Null,
    )
    .unwrap()
    .into_value();
    assert!(row["state"].is_null());
    let id = row["id"].as_str().unwrap().to_owned();
    let lease = store
        .file_active_workspace_claim(RequestRecord::decode(row).unwrap(), &request)
        .expect("allow-mode filed claim");
    assert!(store.request(&id).unwrap().value()["state"].is_null());
    assert_eq!(
        store.claim_workspace(&lease, &request).unwrap_err().kind,
        "requests-state-refusal"
    );
}

/// ´test:unit:workspace-waiting-claim-moves-state-once-under-the-store-lock´
#[test]
fn workspace_waiting_claim_moves_state_once_under_the_store_lock() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1a", &envelope);
    let lease = store.publication_activity("R:1a").unwrap();
    let claimed = store
        .claim_workspace(&lease, &request)
        .expect("agent claim");
    assert!(claimed.value()["state"].is_null());
    assert_eq!(
        store.claim_workspace(&lease, &request).unwrap_err().kind,
        "requests-state-refusal"
    );
}

/// ´test:unit:workspace-claim-reads-owner-label-under-the-lock´
#[test]
fn workspace_claim_reads_owner_label_under_the_lock() {
    let fixture = prepared_fixture();
    let store = fixture.store();
    let envelope: Envelope = serde_json::from_value(detail()["envelope"].clone()).unwrap();
    let request = custodied_request(&fixture, &envelope);
    approved_record(&store, "R:1a", &envelope);
    store
        .triage(
            "R",
            &[
                json!({"id":"R:1a","action":"adjudicate", "treatment":"allow",
                "reason":"fictional owner allow"}),
            ],
            "superloop",
            "2",
        )
        .unwrap();
    let lease = store.publication_activity("R:1a").unwrap();
    let claimed = store
        .claim_workspace(&lease, &request)
        .expect("owner allow");
    assert_eq!(claimed.value()["state"], "adjudicated");

    approved_record(&store, "R:2b", &envelope);
    store
        .triage(
            "R",
            &[
                json!({"id":"R:2b","action":"adjudicate", "treatment":"refuse",
                "reason":"fictional owner refusal"}),
            ],
            "superloop",
            "3",
        )
        .unwrap();
    let refused_lease = store.publication_activity("R:2b").unwrap();
    assert_eq!(
        store
            .claim_workspace(&refused_lease, &request)
            .unwrap_err()
            .kind,
        "door-workspace-context-differs"
    );
}
