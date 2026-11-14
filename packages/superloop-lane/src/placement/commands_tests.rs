use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn private_temp() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

fn declaration(parent: &Path) -> String {
    let mut grant = crate::plan::fixture_workspace_snapshot()["grant"].clone();
    grant["workspace"] = json!(parent.join("R"));
    for (name, child) in [
        ("CARGO_TARGET_DIR", "target"),
        ("CARGO_HOME", "cargo"),
        ("TMPDIR", "tmp"),
    ] {
        grant["baseline_env"]
            .as_array_mut()
            .unwrap()
            .push(json!([name, parent.join("R").join(child)]));
    }
    json!({"grant":grant,"baseline_environment_is_public":true}).to_string()
}
fn placed(parent: &Path) -> Value {
    let text = declaration(parent);
    let preview = prepare(parent, &text, None, true).unwrap();
    prepare(parent, &text, preview["preview_sha256"].as_str(), false).unwrap()
}

/// ´test:unit:placement-owner-prepare-binds-preview-and-refuses-reuse´
#[test]
fn placement_owner_prepare_binds_preview_and_refuses_reuse() {
    let temp = private_temp();
    let root = temp.path().join("parent");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let text = declaration(root.as_path());
    let mut wrong: Value = serde_json::from_str(&text).unwrap();
    wrong["grant"]["baseline_env"] = json!([["PATH", "/usr/bin"]]);
    assert!(
        prepare(root.as_path(), &wrong.to_string(), None, true)
            .unwrap_err()
            .detail
            .contains("own target")
    );
    let preview = prepare(root.as_path(), &text, None, true).unwrap();
    assert_eq!(fs::read_dir(root.as_path()).unwrap().count(), 0);
    fs::rename(&root, temp.path().join("old-parent")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        prepare(&root, &text, preview["preview_sha256"].as_str(), false)
            .unwrap_err()
            .detail
            .contains("preview digest differs")
    );
    let preview = prepare(&root, &text, None, true).unwrap();

    assert!(
        prepare(root.as_path(), &text, Some(&"0".repeat(64)), false)
            .unwrap_err()
            .detail
            .contains("digest differs")
    );
    assert_eq!(fs::read_dir(root.as_path()).unwrap().count(), 0);
    let result = prepare(
        root.as_path(),
        &text,
        preview["preview_sha256"].as_str(),
        false,
    )
    .unwrap();
    let snapshot = crate::launch::workspace::declaration(&text).unwrap();
    let placement = Placement::decode(
        result["declaration"]["compute_placement"].clone(),
        &snapshot,
    )
    .unwrap();
    placement
        .bind(read_identity(
            &File::open(root.as_path().join("R")).unwrap(),
        ))
        .unwrap();
    assert_eq!(placement.seed, None);
    for name in ["source", "target", "build", "cargo", "tmp"] {
        assert!(root.as_path().join("R").join(name).is_dir());
    }
    assert!(
        prepare(root.as_path(), &text, None, true)
            .unwrap_err()
            .detail
            .contains("already exists")
    );
    assert!(
        prepare(
            root.as_path(),
            &text,
            preview["preview_sha256"].as_str(),
            false
        )
        .unwrap_err()
        .detail
        .contains("already exists")
    );
    assert!(
        prepare(
            root.as_path(),
            &result["declaration"].to_string(),
            None,
            true
        )
        .unwrap_err()
        .detail
        .contains("unplaced")
    );
}

/// ´test:unit:placement-owner-parent-and-destination-refusals´
#[test]
fn placement_owner_parent_and_destination_refusals() {
    let temp = private_temp();
    let root = temp.path().join("parent");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let held = File::open(&root).unwrap();
    private(&held).unwrap();
    assert!(
        private_for(
            &held,
            nix::unistd::Uid::effective().as_raw().wrapping_add(1)
        )
        .unwrap_err()
        .detail
        .contains("owned")
    );
    let text = declaration(&root);
    prepare(&root, &text, None, true).unwrap();
    for mode in [0o755, 0o770, 0o1700] {
        fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            prepare(&root, &text, None, true)
                .unwrap_err()
                .detail
                .contains("mode 0700")
        );
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        prepare(Path::new("relative"), &text, None, true)
            .unwrap_err()
            .detail
            .contains("absolute")
    );
    let link = temp.path().join("alias");
    symlink(".", &link).unwrap();
    let linked = link.join("parent");
    assert!(
        prepare(&linked, &declaration(&linked), None, true)
            .unwrap_err()
            .detail
            .contains("directory open")
    );
    let bad = text.replace("/R\"", "/elsewhere/R\"");
    assert!(
        prepare(&root, &bad, None, true)
            .unwrap_err()
            .detail
            .contains("directly beneath")
    );
    symlink(temp.path(), root.join("R")).unwrap();
    assert!(
        prepare(&root, &text, None, true)
            .unwrap_err()
            .detail
            .contains("already exists")
    );
}

/// ´test:unit:placement-census-reports-orphans-without-descending´
#[test]
fn placement_census_reports_orphans_without_descending() {
    let temp = private_temp();
    let runs = tempfile::tempdir().unwrap();
    let result = placed(temp.path());
    fs::write(temp.path().join("unrecognised-file"), b"not a placement").unwrap();
    symlink("/", temp.path().join("external")).unwrap();
    fs::create_dir(temp.path().join("R/source/not-an-entry")).unwrap();
    // A cut immediately after mkdir leaves no receipt or layout, but is inventory.
    fs::create_dir(temp.path().join("interrupted")).unwrap();
    fs::set_permissions(
        temp.path().join("interrupted"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let inv = inventory(temp.path()).unwrap();
    assert_eq!(inv["entries"].as_array().unwrap().len(), 4);
    let report = census(
        temp.path(),
        inv.to_string().as_bytes(),
        "alpha",
        runs.path(),
    )
    .unwrap();
    assert_eq!(report["entries"][0]["state"], "orphan-candidate");
    assert_eq!(report["entries"][1]["state"], "unreadable-or-unrecognised");
    assert_eq!(report["entries"][2]["name"], "interrupted");
    assert_eq!(report["entries"][2]["state"], "orphan-candidate");
    assert_eq!(report["entries"][3]["state"], "unreadable-or-unrecognised");
    let declared = &result["declaration"];
    let grant = crate::launch::workspace::declaration(&declared.to_string()).unwrap();
    let record = json!({"schema":1,"phase":"preparing","worker_uid":3000,"loop":"alpha","run":"R","plan":{
        "loop":"alpha","run":"R","compute_workspace":grant,"compute_placement":declared["compute_placement"]}});
    let path = runs.path().join(".reservation-R.json");
    crate::launch::publish_reservation(&path, &record).unwrap();
    let before = fs::read(&path).unwrap();
    let report = census(
        temp.path(),
        inv.to_string().as_bytes(),
        "alpha",
        runs.path(),
    )
    .unwrap();
    assert_eq!(report["entries"][0]["state"], "live-binding");
    let mut replaced = inv.clone();
    replaced["entries"][0]["identity"]["handle"] = json!("abcd");
    assert_eq!(
        census(
            temp.path(),
            replaced.to_string().as_bytes(),
            "alpha",
            runs.path()
        )
        .unwrap()["entries"][0]["state"],
        "root-replaced"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::write(&path, b"{").unwrap();
    assert_eq!(
        census(
            temp.path(),
            inv.to_string().as_bytes(),
            "alpha",
            runs.path()
        )
        .unwrap()["entries"][0]["state"],
        "reservation-unreadable"
    );
    assert!(temp.path().join("R/source/not-an-entry").exists());
    let mut invalid = inv.clone();
    invalid["schema"] = json!(2);
    assert!(
        census(
            temp.path(),
            invalid.to_string().as_bytes(),
            "alpha",
            runs.path()
        )
        .is_err()
    );
    let duplicate = inv["entries"][0].clone();
    invalid = inv;
    invalid["entries"].as_array_mut().unwrap().push(duplicate);
    assert!(
        census(
            temp.path(),
            invalid.to_string().as_bytes(),
            "alpha",
            runs.path()
        )
        .unwrap_err()
        .detail
        .contains("repeats")
    );
}

/// ´test:unit:placement-declaration-digest-covers-both-members´
#[test]
fn placement_declaration_digest_covers_both_members() {
    let temp = private_temp();
    let result = placed(temp.path());
    let text = result["declaration"].to_string();
    let first = crate::launch::workspace::declaration_digest(&text).unwrap();
    let mut declaration = result["declaration"].clone();
    declaration["compute_placement"]["placement"] = json!("f".repeat(32));
    assert_ne!(
        crate::launch::workspace::declaration_digest(&declaration.to_string()).unwrap(),
        first
    );
    let duplicate = text.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
    assert!(crate::launch::workspace::declaration(&duplicate).is_err());
    declaration["compute_placement"]
        .as_object_mut()
        .unwrap()
        .remove("seed");
    assert!(crate::launch::workspace::declaration(&declaration.to_string()).is_err());
    let mut malformed = result["declaration"].clone();
    malformed["compute_placement"]["grant_digest"] = json!("0".repeat(64));
    assert!(crate::launch::workspace::declaration_digest(&malformed.to_string()).is_err());
}
