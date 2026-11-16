use serde_json::{Value, json};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

fn call(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(args)
        .output()
        .unwrap()
}
/// ´test:integration:placement-owner-entry-shares-descriptor-identity´
#[test]
fn placement_owner_entry_shares_descriptor_identity() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = temp.path().to_str().unwrap();
    let input = json!({"baseline_environment_is_public":true,"grant":{"schema":1,"loop":"fixture","run":"run1","node":"fixture","workspace":temp.path().join("run1"),"baseline_env":[["PATH","/usr/bin"],["CARGO_TARGET_DIR",temp.path().join("run1/target")],["CARGO_HOME",temp.path().join("run1/cargo")],["TMPDIR",temp.path().join("run1/tmp")]],"resources":{},"shells":["/bin/sh"],"quick_policy_digest":"a".repeat(64),"blacklist_digest":"b".repeat(64),"executor_protocol":1}}).to_string();
    let preview = call(&[
        "placement",
        "prepare",
        "--parent",
        parent,
        "--declaration",
        &input,
        "--dry-run",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let value: Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    let apply = call(&[
        "placement",
        "prepare",
        "--parent",
        parent,
        "--declaration",
        &input,
        "--expect-digest",
        value["preview_sha256"].as_str().unwrap(),
    ]);
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let value: Value = serde_json::from_slice(&apply.stdout).unwrap();
    // The actual CLI and the executor's library reader observe the same root.
    let opened = File::open(temp.path().join("run1")).unwrap();
    let identity = superloop_lane::placement::read_identity(&opened).unwrap();
    assert_eq!(
        value["declaration"]["compute_placement"]["root_identity"],
        json!(identity)
    );
    let inventory = call(&["placement", "inventory", "--parent", parent]);
    assert!(inventory.status.success());
    let inventory: Value = serde_json::from_slice(&inventory.stdout).unwrap();
    assert_eq!(inventory["entries"][0]["identity"], json!(identity));
    let again = call(&[
        "placement",
        "prepare",
        "--parent",
        parent,
        "--declaration",
        &input,
        "--dry-run",
    ]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
}
