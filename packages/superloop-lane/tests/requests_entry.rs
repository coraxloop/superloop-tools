//! Common requests through the production command and separately built helper.

#[path = "support/temporary_root.rs"]
mod temporary_root;

#[path = "../src/requests/test_helper.rs"]
mod support;

use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use superloop_lane::requests::{Mode, ModeSetting, RequestRecord, judgement, store::Store};

struct Fixture {
    home: tempfile::TempDir,
    _executables: tempfile::TempDir,
    registry: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // Tiny custody records need private ancestors; builds retain the node target root.
        let home = tempfile::tempdir_in("/tmp").expect("private fixture");
        let runs = home.path().join("runs");
        for path in [
            home.path().to_path_buf(),
            home.path().join(".config"),
            home.path().join(".config/loops"),
            home.path().join(".config/loops/alpha"),
            runs.clone(),
            runs.join(".launch-R"),
            runs.join(".launch-S"),
        ] {
            fs::create_dir_all(&path).expect("directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        }
        let path = home.path().join(".config/loops/registry.toml");
        fs::write(&path, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", runs.display())).expect("loop registry");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("registry mode");
        let registry = support::registry(home.path(), "alpha");
        // An unrelated basename proves dispatch uses the configured absolute path.
        let executables = tempfile::tempdir_in(temporary_root::temporary_root())
            .expect("disk-backed executable fixture");
        let helper = executables.path().join("configured-request-executable");
        fs::copy(support::binary(), &helper).expect("executable fixture");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).expect("executable mode");
        Self {
            home,
            _executables: executables,
            registry,
            helper,
        }
    }

    fn store(&self) -> Store {
        Store::open(self.home.path(), "alpha", true).expect("store")
    }

    fn invoke(&self, args: &[&str], document: Option<&Value>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .arg("requests")
            .args(args)
            .env("HOME", self.home.path())
            .env("SUPERLOOP_LANE_REQUESTS_HELPER", &self.helper)
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", &self.registry)
            .env_remove("PERMISSION_TRIAGE_REQUEST_CONTEXT")
            .env_remove("ENTER_LOOP_REGISTRY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("lane entry");
        if let Some(document) = document {
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(document.to_string().as_bytes())
                .expect("document");
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().expect("command completion")
    }

    fn success(&self, args: &[&str], document: Option<&Value>) -> Value {
        let output = self.invoke(args, document);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("response JSON")
    }

    fn file(&self, run: &str) -> String {
        let first =
            ModeSetting::first(Mode::Audit, Mode::Audit, "owner", "fixture", "1").expect("mode");
        let mut record = json!({"schema":3,"id":format!("{run}:1a"),"loop":"alpha","run":run,"worker_uid":3000,
            "class":"git","shape_key":"git:upload","operation":"git-upload","mirror_ref":"refs/heads/lane/alpha",
            "mode":"audit","floor":"audit","class_setting":first.value(),"loop_setting":first.value(),
            "would_do":{"decision":"allow","reason":"read-only fetch"},
            "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,"stdin_bytes":0,"bound":16_777_216,"output_bytes":0,"stdout_bytes":0,"stderr_bytes":0,"queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
            "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1"});
        judgement::initialize(&mut record);
        let store = self.store();
        store
            .file(RequestRecord::decode(record).expect("request"))
            .expect("file");
        store.collection_id(&format!("{run}:1a"))
    }
}

fn assert_direct_provision(fixture: &Fixture, loop_root: &std::path::Path, report: &Value) {
    let retained: Value = serde_json::from_slice(
        &fs::read(fixture.registry.join("alpha.provision.json"))
            .expect("retained provision report"),
    )
    .expect("provision report");
    assert_eq!(retained["direct_policy"]["published"], false);
    assert_eq!(
        retained["direct_policy"]["rule"],
        "execute-command-snapshot-custody"
    );
    assert_eq!(
        report["direct_snapshot"],
        json!(loop_root.join("policy/snapshot.json"))
    );
    assert_eq!(
        report["direct_journal"],
        json!(loop_root.join("direct/command-requests.jsonl"))
    );
    assert!(
        !loop_root.join("direct").exists(),
        "owner provisioning never opens or creates the journal tier"
    );
    let refused = fixture.invoke(&["publish-snapshot", "alpha"], None);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("execute-command-snapshot-custody"));
}

/// Preview declares both direct paths; incomplete policy custody is reported without blocking the private dispatcher entry.
/// ´claim:requests:registry-deploy-enables-dispatch´
/// ´test:integration:requests-entry-provisions-private-registry´
#[test]
fn requests_entry_provisions_private_registry() {
    let fixture = Fixture::new();
    let refused = fixture.invoke(&["provision-registry", "alpha", "--dry-run"], None);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("estate row requires session"));
    let estate = fixture.home.path().join(".config/loops/registry.toml");
    let source = fs::read_to_string(&estate).expect("estate");
    fs::write(
        &estate,
        source.replace("uid = 41001", "uid = 41001, session = \"bad session\""),
    )
    .expect("incompatible session");
    let refused = fixture.invoke(&["provision-registry", "alpha", "--dry-run"], None);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("not a valid private-registry LOOP_SID")
    );
    let loop_uid = 41001;
    fs::write(
        &estate,
        source.replace(
            "uid = 41001",
            &format!("uid = {loop_uid}, session = \"live-session\""),
        ),
    )
    .expect("registered session");
    let state = fixture.home.path().join("permission-state");
    let state = state.to_str().expect("state path");
    let args = ["provision-registry", "alpha", "--state-root", state];
    let preview = fixture.success(
        &[
            "provision-registry",
            "alpha",
            "--state-root",
            state,
            "--dry-run",
        ],
        None,
    );
    assert_eq!(preview["changed"], true);
    assert!(!fixture.registry.join("alpha.provision.json").exists());
    let loop_root = fixture.home.path().join(".var/loops/alpha");
    prepare_owner_tiers(fixture.home.path(), &loop_root);
    for _ in 0..2 {
        let applied = fixture.invoke(&args, None);
        assert!(applied.status.success());
        assert!(
            String::from_utf8_lossy(&applied.stderr).contains("execute-command-snapshot-custody")
        );
        let report: Value = serde_json::from_slice(&applied.stdout).expect("provision report");
        assert_eq!(report["direct_policy"]["published"], false);
        assert_eq!(
            report["direct_policy"]["rule"],
            "execute-command-snapshot-custody"
        );
    }
    assert_direct_provision(&fixture, &loop_root, &preview);
    let entry_path = fixture.registry.join("alpha.env");
    assert!(
        fs::read_to_string(&entry_path)
            .expect("provisioned entry")
            .contains("LOOP_SID=live-session\n")
    );
    // Positive snapshot publication runs under the two-identity fixture.
    fixture.success(&["status", "alpha"], None);
    let entry = fs::read_to_string(fixture.registry.join("alpha.env")).expect("private entry");
    assert!(entry.contains("LOOP_SID=live-session\n"));
    assert!(entry.contains(&format!("LOOP_UID={loop_uid}\n")));
    for args in [
        vec!["provision-registry", "alpha"],
        vec!["provision-registry", "alpha", "--dry-run"],
    ] {
        let refused = fixture.invoke(&args, None);
        assert_eq!(refused.status.code(), Some(2));
        let detail = String::from_utf8_lossy(&refused.stderr);
        assert!(detail.contains("requests-registry-refusal"), "{detail}");
        assert!(
            detail.contains(&format!(
                "existing LOOP_STATE_ROOT differs; use --state-root {state}"
            )),
            "{detail}"
        );
        assert!(
            !fixture
                .home
                .path()
                .join(".local/state/superloop/permission-state/alpha")
                .exists()
        );
    }
    let refused = fixture.invoke(&args, None);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("execute-command-snapshot-custody"));
    fs::set_permissions(&fixture.registry, fs::Permissions::from_mode(0o755))
        .expect("nonprivate registry");
    let refused = fixture.invoke(&args, None);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("not a private directory"));
}

fn prepare_owner_tiers(home: &std::path::Path, root: &std::path::Path) {
    for path in [
        home.join(".var"),
        home.join(".var/loops"),
        root.to_path_buf(),
    ] {
        fs::create_dir(&path).expect("ensured owner tier");
        fs::set_permissions(path, fs::Permissions::from_mode(0o711)).expect("owner tier mode");
    }
    fs::create_dir(root.join("policy")).expect("ensured policy tier");
    fs::set_permissions(root.join("policy"), fs::Permissions::from_mode(0o2750))
        .expect("policy tier mode");
}

/// The command passes all estate rows to separation validation, not just the selected loop.
/// ´test:integration:requests-entry-provision-refuses-other-estate-home´
#[test]
fn requests_entry_provision_refuses_other_estate_home() {
    let mut fixture = Fixture::new();
    let home = fixture.home.path();
    let estate = home.join(".config/loops/registry.toml");
    fs::write(&estate, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"src-alpha\", session = \"alpha-session\" }, { name = \"beta\", uid = 41002, launch = \"src-beta\", session = \"beta-session\" }]\n").expect("two estate rows");
    let peer = home.join(".var/loops/beta");
    fs::create_dir_all(&peer).expect("peer home");
    fs::set_permissions(&peer, fs::Permissions::from_mode(0o711)).expect("estate mode");
    for dry in [true, false] {
        for registry_inside in [true, false] {
            fixture.registry = if registry_inside {
                peer.join("registry")
            } else {
                home.join("new-registry")
            };
            let state = if registry_inside {
                home.join("new-state")
            } else {
                peer.join("state")
            };
            let mut args = vec![
                "provision-registry",
                "alpha",
                "--state-root",
                state.to_str().expect("state path"),
            ];
            if dry {
                args.push("--dry-run");
            }
            let output = fixture.invoke(&args, None);
            assert_eq!(output.status.code(), Some(2));
            let detail = String::from_utf8_lossy(&output.stderr);
            assert!(detail.contains("requests-registry-refusal"), "{detail}");
            assert!(
                detail.contains("inside estate LOOP_HOME of beta"),
                "{detail}"
            );
            let bad = if registry_inside {
                &fixture.registry
            } else {
                &state
            };
            assert!(detail.contains(bad.to_str().expect("path")), "{detail}");
            assert!(!fixture.registry.exists());
            assert!(!state.exists());
        }
    }
    assert_eq!(fs::read_dir(&peer).expect("empty peer").count(), 0);
}

/// ´test:integration:requests-entry-transactions-review-and-effect-claim´
#[test]
fn requests_entry_transactions_review_and_effect_claim() {
    let fixture = Fixture::new();
    let first = fixture.file("R");
    let second = fixture.file("S");
    fixture.success(&["status", "alpha"], None);
    fixture.success(&["list", "alpha", "--pending"], None);
    let binding = fixture
        .home
        .path()
        .join(".config/loops/alpha/requests-channel.json");
    assert!(!binding.exists());
    assert_eq!(
        fs::read_dir(fixture.home.path().join("permission-state"))
            .expect("state")
            .count(),
        0
    );
    let invalid = json!({"schema":1,"items":[{"id":first,"mark_for_review":true},{"id":"f".repeat(64),"mark_for_review":true}]});
    assert!(
        !fixture
            .invoke(&["triage", "alpha"], Some(&invalid))
            .status
            .success()
    );
    assert!(!binding.exists());
    let batch = json!({"schema":1,"items":[{"id":first,"mark_for_review":true},{"id":second,"decision":{"answer":{"outcome":"refuse"},"reason":"fixture refusal"}}]});
    assert_eq!(
        fixture.success(&["triage", "alpha"], Some(&batch))["applied"],
        2
    );
    let old = fixture.success(&["review", "alpha", &first], None);
    let current = fixture.success(&["review", "alpha", &first], None);
    assert_ne!(old["review"], current["review"]);
    let mut decision = json!({"schema":1,"id":first,"review_id":old["review"]["review_id"],"decision":{"answer":{"outcome":"allow"},"reason":"checked"}});
    assert!(
        !fixture
            .invoke(&["adjudicate", "alpha"], Some(&decision))
            .status
            .success()
    );
    decision["review_id"] = current["review"]["review_id"].clone();
    fixture.success(&["adjudicate", "alpha"], Some(&decision));
    let store = fixture.store();
    assert!(store.claim_request("R:1a").expect("claim"));
    assert!(!store.claim_request("R:1a").expect("same claim"));
    let mut effect = store.waiting_request("R:1a").expect("request").value()["effect"].clone();
    effect["state"] = json!("completed");
    effect["ref_check"] = json!("admitted");
    effect["reason"] = json!("fixture-completed");
    effect["exit_status"] = json!(0);
    store
        .record_effect("R:1a", effect.clone())
        .expect("complete");
    assert_eq!(
        fixture
            .store()
            .waiting_request("R:1a")
            .expect("restart")
            .value()["effect"],
        effect
    );
}

/// ´test:integration:requests-entry-departed-waiters-never-perform´
#[test]
fn requests_entry_departed_waiters_never_perform() {
    for judgement_first in [false, true] {
        let fixture = Fixture::new();
        let id = fixture.file("R");
        let batch = json!({"schema":1,"items":[{"id":id,"decision":{"answer":{"outcome":"allow"},"reason":"late judgement"}}]});
        if judgement_first {
            fixture.success(&["triage", "alpha"], Some(&batch));
        }
        let store = fixture.store();
        let mut effect = store.waiting_request("R:1a").expect("request").value()["effect"].clone();
        effect["state"] = json!("refused");
        effect["reason"] = json!("door-disconnect-refusal");
        effect["ref_check"] = json!("not-reached");
        effect["exit_status"] = json!(125);
        store
            .record_effect("R:1a", effect.clone())
            .expect("departed waiter");
        if !judgement_first {
            fixture.success(&["triage", "alpha"], Some(&batch));
        }
        let listing = fixture.success(&["list", "alpha"], None);
        assert_eq!(listing["requests"][0]["state"], "completed");
        assert_eq!(
            fixture
                .store()
                .waiting_request("R:1a")
                .expect("durable refusal")
                .value()["effect"],
            effect
        );
    }
}

fn own_fixture_tree(path: &std::path::Path, uid: nix::unistd::Uid) {
    if path.is_dir() {
        for entry in fs::read_dir(path).expect("fixture entries") {
            own_fixture_tree(&entry.expect("entry").path(), uid);
        }
    }
    nix::unistd::chown(path, Some(uid), None).expect("mapped fixture custody");
}

/// ´test:integration:requests-entry-requires-one-account-for-door-and-permission-custody´
#[test]
#[ignore = "requires provisioned namespace root with UIDs 41001 and 41002 mapped"]
fn requests_entry_requires_one_account_for_door_and_permission_custody() {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::{Uid, chown};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    assert!(
        Uid::effective().is_root(),
        "provisioned namespace root required"
    );
    let binary = fs::File::open(env!("CARGO_BIN_EXE_superloop-lane")).expect("lane binary");
    let helper = fs::File::open(support::binary()).expect("helper binary");
    for file in [&binary, &helper] {
        fcntl(file, FcntlArg::F_SETFD(FdFlag::empty())).expect("inherit executable descriptor");
    }
    for caller in [41001, 41002] {
        let other = if caller == 41001 { 41002 } else { 41001 };
        let fixture = Fixture::new();
        let id = fixture.file("R");
        own_fixture_tree(fixture.home.path(), Uid::from_raw(caller));
        let run = |args: &[&str], document: Option<&Value>| {
            let mut child = Command::new(format!("/proc/self/fd/{}", binary.as_raw_fd()))
                .arg("requests")
                .args(args)
                .env_clear()
                .env("HOME", fixture.home.path())
                .env(
                    "SUPERLOOP_LANE_REQUESTS_HELPER",
                    format!("/proc/self/fd/{}", helper.as_raw_fd()),
                )
                .env("PERMISSION_TRIAGE_LOOP_REGISTRY", &fixture.registry)
                .uid(caller)
                .gid(caller)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("lane under mapped uid");
            if let Some(document) = document {
                let _written = child
                    .stdin
                    .take()
                    .expect("stdin")
                    .write_all(document.to_string().as_bytes());
            } else {
                drop(child.stdin.take());
            }
            child.wait_with_output().expect("mapped lane completion")
        };
        for foreign in [
            &fixture.registry,
            &fixture.home.path().join("permission-state"),
        ] {
            chown(foreign, Some(Uid::from_raw(other)), None).expect("foreign permission owner");
            for command in ["status", "list", "triage", "review", "adjudicate"] {
                let mut args = vec![command, "alpha"];
                if command == "review" {
                    args.push(&id);
                }
                let output = run(&args, Some(&json!({"schema":1,"items":[]})));
                assert_eq!(output.status.code(), Some(2), "{command}");
                assert_eq!(output.stdout, b"");
                assert_ne!(output.stderr, b"");
            }
            chown(foreign, Some(Uid::from_raw(caller)), None).expect("restore permission owner");
        }
        for command in ["status", "list"] {
            let output = run(&[command, "alpha"], None);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(serde_json::from_slice::<Value>(&output.stdout).is_ok());
        }
        let mark = json!({"schema":1,"items":[{"id":id,"mark_for_review":true}]});
        let output = run(&["triage", "alpha"], Some(&mark));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = run(&["review", "alpha", &id], None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let review: Value = serde_json::from_slice(&output.stdout).expect("review");
        let decision = json!({"schema":1,"id":id,"review_id":review["review"]["review_id"],"decision":{"answer":{"outcome":"refuse"},"reason":"mapped owner decision"}});
        let output = run(&["adjudicate", "alpha"], Some(&decision));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
