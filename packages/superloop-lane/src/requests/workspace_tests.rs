//! Reader-before-writer acceptance for workspace custody.
use super::tests::Fixture;
use crate::requests::{Mode, RequestRecord, tests::waiting};
use execute_command::workspace::{Envelope, Grant, WorkspaceEffect, canonical_digest, learned_key};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

fn detail() -> Value {
    let grant=Grant::decode(json!({"schema":1,"loop":"alpha","run":"R","node":"fixture-node","workspace":"/work/R","baseline_env":[["PATH","/usr/bin"]],"resources":{},"shells":["/bin/sh"],"quick_policy_digest":"a".repeat(64),"blacklist_digest":"b".repeat(64),"executor_protocol":1})).unwrap();
    let envelope=Envelope::decode(json!({"schema":3,"grant_digest":grant.digest().unwrap(),"cwd":["checkout"],"execution":{"kind":"Argv","words":[b"custom".to_vec(),vec![255]]},"env_additions":[],"deadline_ms":1000})).unwrap();
    json!({"execution_digest":canonical_digest(&envelope.execution).unwrap(),"context_digest":learned_key("compute",&envelope,&grant,"quick-1").unwrap()[2],"envelope":envelope,"grant":grant,"policy_revision":"quick-1","blacklist_revision":"black-1","result":{"outcome":{"kind":"Unknown"},"wall_seconds":null,"user_cpu_seconds":null,"system_cpu_seconds":null},"admission_wall_seconds":null,"steps":[]})
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
/// ´test:unit:workspace-schema-seven-survives-rewrite-and-index-rebuild´
#[test]
fn workspace_schema_seven_survives_rewrite_and_index_rebuild() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let socket = fixture.home.join("socket");
    let door = socket.join("door");
    for path in [&socket, &door] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let settings = fixture.home.join(".config/loops/alpha/workers.toml");
    fs::write(&settings, format!("socket_dir = {}\n", json!(socket))).unwrap();
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
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
/// ´test:unit:workspace-plan-and-reservation-read-snapshot-before-writer´
#[test]
fn workspace_plan_and_reservation_read_snapshot_before_writer() {
    let grant = Grant::decode(detail()["grant"].clone()).unwrap();
    let mut plan = json!({"loop":"alpha","run":"R","compute_workspace":{"digest":grant.digest().unwrap(),"grant":grant}});
    assert!(crate::plan::workspace_snapshot(&plan).unwrap().is_some());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reservation.json");
    let mut reservation = json!({"schema":1,"phase":"preparing","worker_uid":3000,"loop":"alpha","run":"R","plan":plan});
    fs::write(&path, serde_json::to_vec(&reservation).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        crate::launch::read_reservation(&path).unwrap().unwrap(),
        reservation
    );
    plan["compute_workspace"]["grant"]["workspace"] = json!("/foreign");
    assert_eq!(
        crate::plan::workspace_snapshot(&plan).unwrap_err().kind,
        "door-workspace-context-differs"
    );
    reservation["run"] = json!("S");
    fs::write(&path, serde_json::to_vec(&reservation).unwrap()).unwrap();
    assert_eq!(
        crate::launch::read_reservation(&path).unwrap_err().kind,
        "door-workspace-context-differs"
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
        "3a3df220c0b5e005f9e83fcfee1b6792b84e922cb1ec40a273fa0a2c5076872b"
    );
    assert_eq!(
        hash(include_bytes!("../door/retire_node.py")),
        "94a7ac7fd5c6c82e086ccec13c0a410f16d32ebd86506a4e40da2f80309a99b5"
    );
}
