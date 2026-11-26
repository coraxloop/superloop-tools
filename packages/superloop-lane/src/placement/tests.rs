use super::*;
use serde_json::json;
use std::io::Write as _;

fn plan() -> Value {
    let grant = crate::plan::fixture_workspace_snapshot();
    json!({"loop":"alpha", "run":"R", "compute_workspace":grant,
        "compute_placement":{"schema":1,"placement":"1".repeat(32),"loop":"alpha","run":"R",
        "node":"fixture-node","grant_digest":grant["digest"],"mode":"own-path","root":"/work/R",
        "root_identity":{"filesystem_uuid":"2".repeat(32),"handle_type":129,"handle":"0102"},"seed":null}})
}
fn record() -> Value {
    json!({"schema":1,"phase":"preparing","worker_uid":2001,"loop":"alpha","run":"R","plan":plan()})
}
fn read(bytes: &[u8]) -> Result<Value, LaneError> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    crate::launch::read_reservation_file(File::open(file.path()), file.path(), true)
        .map(|v| v.unwrap())
}
fn assert_refusal(value: &Value, case: &str) {
    let error = read(&serde_json::to_vec(value).unwrap()).unwrap_err();
    assert_eq!(
        error.kind, "door-workspace-context-differs",
        "{case}: {error}"
    );
}
fn member(value: &Value) -> Placement {
    let grant = crate::plan::workspace_snapshot(value).unwrap().unwrap();
    Placement::decode(value["compute_placement"].clone(), &grant).unwrap()
}

/// ´test:unit:placement-record-fields-bind-the-grant´
#[test]
fn placement_record_fields_bind_the_grant() {
    let control = record();
    assert_eq!(
        read(&serde_json::to_vec(&control).unwrap()).unwrap(),
        control
    );
    let mutations = [
        ("schema", json!(2)),
        ("placement", json!("A".repeat(32))),
        ("loop", json!("other")),
        ("run", json!("other")),
        ("node", json!("other")),
        ("grant_digest", json!("f".repeat(64))),
        ("mode", json!("fixed-path")),
        ("root", json!("/work/other")),
        ("root_identity", json!(null)),
        ("seed", json!("../seed")),
    ];
    for (key, bad) in mutations {
        let mut changed = control.clone();
        changed["plan"]["compute_placement"][key] = bad;
        assert_eq!(
            read(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .kind,
            "door-workspace-context-differs",
            "{key}"
        );
        let mut absent = control.clone();
        absent["plan"]["compute_placement"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert_refusal(&absent, &format!("missing {key}"));
    }
}

/// ´test:unit:placement-root-identity-shapes-and-seed-are-bounded´
#[test]
fn placement_root_identity_shapes_and_seed_are_bounded() {
    let control = record();
    assert_eq!(
        read(&serde_json::to_vec(&control).unwrap()).unwrap(),
        control
    );
    for (key, bad) in [
        ("filesystem_uuid", json!("2".repeat(31))),
        ("handle_type", json!(2_147_483_648_u64)),
        ("handle", json!("01".repeat(129))),
    ] {
        let mut changed = control.clone();
        changed["plan"]["compute_placement"]["root_identity"][key] = bad;
        assert_eq!(
            read(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .kind,
            "door-workspace-context-differs",
            "{key}"
        );
        changed["plan"]["compute_placement"]["root_identity"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert_refusal(&changed, &format!("missing {key}"));
    }
    for field in ["created_roots", "namespace", "holder", "seed_digest"] {
        let mut changed = control.clone();
        changed["plan"]["compute_placement"][field] = json!(null);
        assert_refusal(&changed, &format!("unknown {field}"));
    }
    for handle in [String::new(), "0".to_owned(), "AA".to_owned()] {
        let mut changed = control.clone();
        changed["plan"]["compute_placement"]["root_identity"]["handle"] = json!(handle);
        assert_refusal(&changed, "invalid handle encoding");
    }
    let mut unknown = control.clone();
    unknown["plan"]["compute_placement"]["root_identity"]["device"] = json!(1);
    assert_refusal(&unknown, "unknown identity field");
    let mut seeded = control;
    seeded["plan"]["compute_placement"]["seed"] = json!("generation-1");
    assert_eq!(read(&serde_json::to_vec(&seeded).unwrap()).unwrap(), seeded);
}

fn duplicate(object: &Value, key: &str) -> String {
    let encoded = object.to_string();
    format!("{{{}:{},{}", json!(key), object[key], &encoded[1..])
}
/// ´test:unit:placement-reservation-byte-path-refuses-duplicates´
#[test]
fn placement_reservation_byte_path_refuses_duplicates() {
    let control = record();
    let p = &control["plan"];
    let placement = &p["compute_placement"];
    let wrap = |plan: &str| {
        format!(
            "{{\"schema\":1,\"phase\":\"preparing\",\"worker_uid\":2001,\"loop\":\"alpha\",\"run\":\"R\",\"plan\":{plan}}}"
        )
    };
    let wrap_member = |m: &str| p.to_string().replacen(&placement.to_string(), m, 1);
    let mut cases = vec![
        duplicate(&control, "plan"),
        wrap(&duplicate(p, "compute_placement")),
    ];
    let escaped = duplicate(placement, "root").replacen("\"root\"", r#""ro\u006ft""#, 1);
    cases.push(wrap(&wrap_member(&escaped)));
    // The duplicate enclosing plan must refuse even when its last value hides placement.
    cases.push(format!(
        "{{\"plan\":{p},{}",
        &json!({"plan":{},"schema":1,"phase":"preparing","worker_uid":2001}).to_string()[1..]
    ));
    for key in placement.as_object().unwrap().keys() {
        cases.push(wrap(&wrap_member(&duplicate(placement, key))));
    }
    for key in ["filesystem_uuid", "handle_type", "handle"] {
        let changed = placement.to_string().replacen(
            &placement["root_identity"].to_string(),
            &duplicate(&placement["root_identity"], key),
            1,
        );
        cases.push(wrap(&wrap_member(&changed)));
    }
    assert_eq!(read(control.to_string().as_bytes()).unwrap(), control);
    for (index, bytes) in cases.iter().enumerate() {
        let error = read(bytes.as_bytes()).unwrap_err();
        assert_eq!(
            error.kind, "door-workspace-context-differs",
            "duplicate {index}"
        );
        assert!(
            error.detail.contains("duplicate"),
            "duplicate {index}: {error}"
        );
    }
    // A duplicate outside the path is explicitly not made strict by P1.
    let unrelated = format!("{{\"other\":1,\"other\":2,{}", &control.to_string()[1..]);
    assert_eq!(read(unrelated.as_bytes()).unwrap()["other"], 2);
}

/// ´test:unit:placement-absent-keeps-legacy-byte-decoding´
#[test]
fn placement_absent_keeps_legacy_byte_decoding() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/plan.json")).unwrap();
    let mut values = vec![
        json!({"schema":1,"phase":"preparing","worker_uid":2001}),
        json!({"schema":1,"phase":"settled","worker_uid":2001,"plan":fixture,
            "rounds":[{"step":"dispatch","reply_designation":{"state":"unmeasured"}}]}),
    ];
    for phase in ["started", "failed", "retiring", "retired"] {
        values.push(json!({"schema":1,"phase":phase,"worker_uid":2001}));
    }
    for value in values {
        let bytes = value.to_string();
        assert_eq!(
            reservation_bytes(bytes.as_bytes(), |e| LaneError::input(
                "uid-table",
                e.to_string()
            ))
            .unwrap(),
            value
        );
        assert_eq!(read(bytes.as_bytes()).unwrap(), value);
    }
    for bytes in [
        b"{\"plan\":{},\"plan\":{},\"schema\":1,\"phase\":\"preparing\",\"worker_uid\":2001}"
            .as_slice(),
        b"{",
        b"[] trailing",
        b"{\"schema\":",
    ] {
        let old = serde_json::from_slice::<Value>(bytes).map_err(|e| e.to_string());
        let new = reservation_bytes(bytes, |e| LaneError::input("uid-table", e.to_string()))
            .map_err(|e| e.detail);
        assert_eq!(new, old);
    }
    for bytes in [
        r#"{"plan":[{"compute_placement":{"x":1,"x":2}}]}"#,
        r#"{"elsewhere":{"compute_placement":{"x":1,"x":2}}}"#,
        r#"{"plan":{"unrelated":{"x":1,"x":2}}}"#,
        "null",
        "[]",
        "true",
        "123",
        "1.25",
        "\"text\"",
    ] {
        assert_eq!(
            reservation_bytes(bytes.as_bytes(), |e| LaneError::input(
                "uid-table",
                e.to_string()
            ))
            .unwrap(),
            serde_json::from_str::<Value>(bytes).unwrap()
        );
    }
    // Syntax failure through the actual bounded reader keeps its path-prefixed text.
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"{").unwrap();
    let old = serde_json::from_slice::<Value>(b"{").unwrap_err();
    let error = crate::launch::read_reservation_file(File::open(file.path()), file.path(), true)
        .unwrap_err();
    assert_eq!(error.kind, "uid-table");
    assert_eq!(error.detail, format!("{}: {old}", file.path().display()));
}

/// ´test:unit:placement-retains-and-removes-with-workspace´
#[test]
fn placement_retains_and_removes_with_workspace() {
    let protected = plan();
    let mut rebuilt = crate::plan::Plan {
        home: "/unused".into(),
        driver_dir: "/unused".into(),
        letter: "/unused".into(),
        document: json!({"loop":"alpha","run":"R"}),
    };
    rebuilt.retain_workspace(&protected).unwrap();
    assert_eq!(rebuilt.document, protected);
    let mut absent = protected.clone();
    absent.as_object_mut().unwrap().remove("compute_placement");
    rebuilt.retain_workspace(&absent).unwrap();
    assert_eq!(rebuilt.document, absent);
    let mut orphan = protected;
    orphan.as_object_mut().unwrap().remove("compute_workspace");
    assert_eq!(
        rebuilt.retain_workspace(&orphan).unwrap_err().kind,
        "door-workspace-context-differs"
    );
}

/// ´test:unit:placement-binding-compares-every-identity-component´
#[test]
fn placement_binding_compares_every_identity_component() {
    let p = member(&plan());
    p.bind(Ok(p.root_identity.clone())).unwrap();
    for n in 0..3 {
        let mut changed = p.root_identity.clone();
        match n {
            0 => changed.filesystem_uuid = "3".repeat(32),
            1 => changed.handle_type += 1,
            _ => changed.handle = "0304".into(),
        }
        assert_eq!(
            p.bind(Ok(changed)).unwrap_err().kind,
            "door-workspace-context-differs",
            "identity component {n}"
        );
    }
    assert_eq!(
        p.bind(Err(LaneError::input("fixture", "unreadable")))
            .unwrap_err()
            .kind,
        "door-workspace-context-differs"
    );
}

/// ´test:unit:placement-root-handle-survives-rename-not-recreation´
#[test]
fn placement_root_handle_survives_rename_not_recreation() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("root");
    std::fs::create_dir(&original).unwrap();
    let first = File::open(&original).unwrap();
    let identity = read_identity(&first)
        .expect("gate prerequisite: temporary filesystem must provide directory handles and a filesystem UUID");
    let mut placement = member(&plan());
    placement.root_identity = identity;
    let renamed = temp.path().join("renamed");
    std::fs::rename(&original, &renamed).unwrap();
    placement
        .bind(read_identity(&File::open(&renamed).unwrap()))
        .unwrap();
    drop(first);
    std::fs::remove_dir(&renamed).unwrap();
    std::fs::create_dir(&renamed).unwrap();
    assert_eq!(
        placement
            .bind(read_identity(&File::open(&renamed).unwrap()))
            .unwrap_err()
            .kind,
        "door-workspace-context-differs"
    );
    let file = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
    assert_eq!(
        read_identity(file.as_file()).unwrap_err().kind,
        "door-workspace-context-differs"
    );
}

/// ´test:unit:placement-rewrite-journal-checks-embedded-reservations´
#[test]
fn placement_rewrite_journal_checks_embedded_reservations() {
    let mut record = record();
    record["rounds"] = json!([{"step":"dispatch","reply_designation":{"state":"unmeasured"}}]);
    let journal = json!({"plan":{"files":[{"before":record,"after":record}]}});
    assert_eq!(
        journal_bytes(journal.to_string().as_bytes(), |e| refusal(e.to_string())).unwrap(),
        journal
    );
    let mutated = journal
        .to_string()
        .replacen(&record.to_string(), &duplicate(&record, "plan"), 1);
    assert_eq!(
        journal_bytes(mutated.as_bytes(), |e| refusal(e.to_string()))
            .unwrap_err()
            .kind,
        "door-workspace-context-differs"
    );
    let unrelated = format!(
        r#"{{"plan":{{"files":[{{"before":{{"plan":{{}},"plan":{{}}}},"after":{record}}}]}}}}"#
    );
    assert_eq!(
        journal_bytes(unrelated.as_bytes(), |e| refusal(e.to_string())).unwrap(),
        serde_json::from_str::<Value>(&unrelated).unwrap()
    );
    let p = plan();
    assert_eq!(
        plan_bytes(p.to_string().as_bytes(), |e| refusal(e.to_string())).unwrap(),
        p
    );
    assert_eq!(
        plan_bytes(duplicate(&p, "compute_placement").as_bytes(), |e| refusal(
            e.to_string()
        ))
        .unwrap_err()
        .kind,
        "door-workspace-context-differs"
    );
}
