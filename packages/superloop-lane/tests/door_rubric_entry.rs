//! Rubric access through the production runner and installer with real entered identities.

#[path = "../src/requests/test_helper.rs"]
mod requests_support;

use execute_command::rubric::DoorInput;
use nix::unistd::{Gid, Uid, chown};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use superloop_lane::door::agent::{AgentRunner as _, CodexRunner, RunnerOutcome};

// A sibling test's fork can retain an executable's writer until its exec.
// Keep fixture creation and every child using it in one ordered lifetime.
static FIXTURE_PROCESS: Mutex<()> = Mutex::new(());

fn namespace() {
    assert!(
        Uid::effective().is_root(),
        "provisioned namespace root is required"
    );
}

fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).expect("fixture mode");
}

fn file(path: &Path, bytes: &[u8], value: u32) {
    fs::write(path, bytes).expect("fixture bytes");
    mode(path, value);
}

struct Fixture {
    root: tempfile::TempDir,
    runner: CodexRunner,
    uid: u32,
    _process: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new(uid: u32) -> Self {
        Self::entered(uid, true)
    }

    fn unprivileged() -> Self {
        Self::entered(Uid::effective().as_raw(), false)
    }

    fn entered(uid: u32, mapped: bool) -> Self {
        let process = FIXTURE_PROCESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = tempfile::tempdir_in("/tmp").expect("small protected fixture");
        mode(root.path(), if mapped { 0o711 } else { 0o311 });
        fs::create_dir_all(root.path().join(".config/loops/alpha/lanes/codex"))
            .expect("canonical lock root");
        for relative in [
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
            ".config/loops/alpha/lanes/codex",
        ] {
            mode(&root.path().join(relative), 0o700);
        }
        let home = root.path().join("loop");
        fs::create_dir_all(home.join(".codex")).expect("loop home");
        fs::create_dir(home.join("tmp")).expect("loop temporary root");
        file(
            &home.join(".codex/auth.json"),
            b"synthetic-fixture-only",
            0o600,
        );
        for leaf in if mapped {
            vec!["", ".codex", ".codex/auth.json", "tmp"]
        } else {
            Vec::new()
        } {
            chown(
                &home.join(leaf),
                Some(Uid::from_raw(uid)),
                Some(Gid::from_raw(uid)),
            )
            .expect("mapped loop custody");
        }
        mode(&home, 0o700);
        mode(&home.join(".codex"), 0o700);
        let publication = root.path().join("publication");
        fs::create_dir(&publication).expect("publication");
        mode(&publication, 0o711);
        fs::create_dir(publication.join("permissions")).expect("permissions");
        mode(&publication.join("permissions"), 0o755);
        let rubric = publication.join("permissions/door.md");
        file(&rubric, b"Reviewed rubric.", 0o644);
        let entry = root.path().join("entry");
        file(&entry, format!(
            "#!/usr/bin/python3\nimport os,sys\nassert sys.argv[1:4] == ['enter','alpha','--']\n{identity}assert os.getuid() == {uid}\nos.environ['HOME'] = {home}\nos.environ['TMPDIR'] = {tmp}\ntry: os.listdir({publication})\nexcept PermissionError: pass\nelse: raise AssertionError('search-only ancestor was readable')\nos.execv(sys.argv[4],sys.argv[4:])\n",
            identity=if mapped { format!("os.setgroups([])\nos.setgid({uid})\nos.setuid({uid})\n") } else { String::new() },
            home=json!(home), tmp=json!(home.join("tmp")), publication=json!(root.path())
        ).as_bytes(), 0o700);
        let executable = root.path().join("codex");
        file(&executable, b"#!/usr/bin/python3\nimport json,sys\ndocument=json.load(sys.stdin)\nassert document['reviewed_rubric'] == 'Reviewed rubric.'\nprint(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':json.dumps({'verdict':'refer','scope':'estate','reason':'fixture'})}}))\n", 0o755);
        let runner = CodexRunner {
            entry,
            owner_home: root.path().into(),
            loop_name: "alpha".into(),
            executable,
            model: "fixture".into(),
            effort: "medium".into(),
            cap_ms: 5000,
            rubric_path: rubric,
        };
        Self {
            root,
            runner,
            uid,
            _process: process,
        }
    }

    fn judge(&self) -> RunnerOutcome {
        self.runner.judge(
            &DoorInput {
                request: json!({"words":[]}),
                class: "ssh".into(),
                shape_record: json!([]),
                rubric: String::new(),
            }
            .encode()
            .expect("bounded fixture input"),
            Duration::from_secs(5),
        )
    }

    fn preflight(&self) -> Result<Value, superloop_lane::error::LaneError> {
        superloop_lane::door::agent::check_rubric(
            &self.runner.entry,
            self.root.path(),
            "alpha",
            &self.runner.rubric_path,
            self.uid,
        )
    }

    fn ancestor(&self) -> PathBuf {
        self.root.path().join("publication")
    }

    fn refused(&self, check: &str, path: &Path, owner: Option<u32>) -> Value {
        let result = self.judge();
        assert_eq!(result.reason, "door-rubric-unavailable", "{result:?}");
        let failure = result.observations["rubric_failure"].clone();
        assert_eq!(failure["check"], check);
        assert_eq!(failure["path"], json!(path));
        assert_eq!(failure["owner_uid"], json!(owner));
        assert_eq!(failure.as_object().expect("failure object").len(), 5);
        let refusal = self.preflight().expect_err("install policy refuses");
        assert_eq!(
            serde_json::from_str::<Value>(&refusal.detail).expect("structured refusal")["rubric_failure"],
            failure
        );
        failure
    }

    fn install_config(&self) {
        let config = self.root.path().join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("configuration");
        for path in [".config", ".config/loops", ".config/loops/alpha"] {
            mode(&self.root.path().join(path), 0o700);
        }
        file(&self.root.path().join(".config/loops/registry.toml"), format!(
            "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1,0,0]\nloops = [{{name='alpha',uid={},launch='src'}}]\n", self.uid).as_bytes(), 0o600);
        file(
            &config.join("workers.toml"),
            format!("entry_bin = '{}'\n", self.runner.entry.display()).as_bytes(),
            0o600,
        );
        file(
            &config.join("door.toml"),
            format!(
                "rubric_root = '{}'\nexecutable = '{}'\nmodel = 'fixture'\n",
                self.ancestor().display(),
                self.runner.executable.display()
            )
            .as_bytes(),
            0o600,
        );
    }
}

/// ´test:integration:rubric-entry-admits-service-custody-for-two-loop-uids´
#[test]
#[ignore = "requires namespace root with loop uids 41001 and 41002 and worker uids 3000/3001 mapped"]
fn rubric_entry_admits_service_custody_for_two_loop_uids() {
    namespace();
    for uid in [41001, 41002] {
        let fixture = Fixture::new(uid);
        let admitted = fixture.preflight().expect("rubric admitted as loop");
        let result = fixture.judge();
        assert_eq!(result.status, "verdict", "{result:?}");
        assert_eq!(json!(result.rubric_digest), admitted["rubric_digest"]);
        assert_eq!(result.observations["loop_uid"], uid);
        drop(fixture);
    }
}

/// ´test:integration:rubric-entry-refuses-third-uid-and-writable-ancestors´
#[test]
#[ignore = "requires namespace root with loop uids 41001 and 41002 and worker uids 3000/3001 mapped"]
fn rubric_entry_refuses_third_uid_and_writable_ancestors() {
    namespace();
    for uid in [41001, 41002] {
        let fixture = Fixture::new(uid);
        let ancestor = fixture.ancestor();
        chown(&ancestor, Some(Uid::from_raw(41003)), None).expect("third owner");
        fixture.refused("ancestor-owner", &ancestor, Some(41003));
        chown(&ancestor, Some(Uid::from_raw(0)), None).expect("restore owner");
        mode(&ancestor, 0o733);
        fixture.refused("ancestor-writable", &ancestor, Some(0));
        mode(&ancestor, 0o700);
        let denied = fixture.refused("ancestor-open", &ancestor.join("permissions"), None);
        assert_eq!(denied["errno"], nix::libc::EACCES);
        mode(&ancestor, 0o711);
        let saved = ancestor.with_extension("saved");
        fs::rename(&ancestor, &saved).expect("save publication");
        symlink(&saved, &ancestor).expect("linked component");
        fixture.refused("ancestor-open", &ancestor, None);
        fs::remove_file(&ancestor).expect("remove link");
        fs::rename(saved, &ancestor).expect("restore publication");
        file(&fixture.runner.rubric_path, &vec![b'x'; 65_537], 0o644);
        fixture.refused("file-size", &fixture.runner.rubric_path, Some(0));
        file(&fixture.runner.rubric_path, &[0xff], 0o644);
        fixture.refused("file-utf8", &fixture.runner.rubric_path, Some(0));
        fs::remove_file(&fixture.runner.rubric_path).expect("missing rubric");
        fixture.refused("file-open", &fixture.runner.rubric_path, None);
    }
}

/// ´test:integration:install-and-refresh-refuse-runtime-invalid-rubric´
#[test]
#[ignore = "requires namespace root with loop uids 41001 and 41002 and worker uids 3000/3001 mapped"]
fn install_and_refresh_refuse_runtime_invalid_rubric() {
    namespace();
    for uid in [41001, 41002] {
        install_refusals(&Fixture::new(uid));
    }
}

fn install_refusals(fixture: &Fixture) {
    mode(fixture.root.path(), 0o711);
    // The owner-facing installer reads its home. The entered runner's listing
    // assertion belongs to the separate search-only traversal fixtures.
    let entry = fs::read_to_string(&fixture.runner.entry).expect("entry");
    let start = entry.find("try: os.listdir").expect("listing assertion");
    let end = entry.find("os.execv").expect("exec entry");
    file(
        &fixture.runner.entry,
        format!("{}{}", &entry[..start], &entry[end..]).as_bytes(),
        0o700,
    );
    fixture.install_config();
    mode(&fixture.ancestor(), 0o733);
    let generation = fixture
        .root
        .path()
        .join(".config/loops/alpha/door-install-generation.json");
    for existing in [false, true] {
        if existing {
            file(&generation, b"{\"prior-generation\":true}", 0o600);
        }
        for dry in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
            command
                .args(["install-door", "alpha"])
                .env("HOME", fixture.root.path())
                .env_remove("ENTER_LOOP_REGISTRY");
            if dry {
                command.arg("--dry-run");
            }
            let output = command.output().expect("production installer entry");
            assert_eq!(output.status.code(), Some(2));
            let refusal = String::from_utf8_lossy(&output.stderr);
            assert!(refusal.contains("door-rubric-unavailable"), "{refusal}");
            assert!(refusal.contains("ancestor-writable"), "{refusal}");
            assert!(
                refusal.contains(fixture.ancestor().to_str().expect("path")),
                "{refusal}"
            );
            assert!(
                refusal.contains(&format!("\"owner_uid\":{}", Uid::effective())),
                "{refusal}"
            );
            assert_eq!(generation.exists(), existing);
        }
    }
}

/// ´test:integration:rubric-failure-survives-request-record-and-rewrite´
#[test]
#[ignore = "requires namespace root with loop uids 41001 and 41002 and worker uids 3000/3001 mapped"]
fn rubric_failure_survives_request_record_and_rewrite() {
    // The approved historical test name is retained; this lane deliberately adds no record rewrite.
    namespace();
    for uid in [41001, 41002] {
        let fixture = Fixture::new(uid);
        file(&fixture.runner.rubric_path, &[0xff], 0o644);
        let result = fixture.judge();
        let report = result.exercise_observation(5000, None);
        assert_eq!(
            report["observations"]["rubric_failure"],
            result.observations["rubric_failure"]
        );
        assert_eq!(
            report["observations"]["rubric_failure"]["check"],
            "file-utf8"
        );
        for worker in [3000, 3001] {
            let setting = superloop_lane::requests::ModeSetting::first(
                superloop_lane::requests::Mode::Audit,
                superloop_lane::requests::Mode::Audit,
                "owner",
                "fixture",
                "1",
            )
            .expect("setting");
            let mut record = json!({"schema":4,"id":"R:1a","loop":"alpha","run":"R",
                "worker_uid":worker,"class":"git","shape_key":"git:upload","operation":"git-upload",
                "mirror_ref":"refs/heads/lane/alpha","mode":"audit","floor":"audit",
                "class_setting":setting.value(),"loop_setting":setting.value(),
                "would_do":{"decision":"undecided","reason":"fixture"},
                "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,"stdin_bytes":0,
                    "stdout_bytes":0,"stderr_bytes":0,"queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
                "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1"});
            superloop_lane::requests::judgement::initialize(&mut record);
            superloop_lane::requests::judgement::apply(&mut record, &result, None, Some("fixture"));
            let decoded = superloop_lane::requests::RequestRecord::decode(record)
                .expect("unchanged record schema");
            assert_eq!(decoded.value()["schema"], 4);
            assert!(decoded.value().get("agent_evidence").is_none());
            assert!(decoded.value().get("rubric_failure").is_none());
        }
        drop(fixture);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        mode(self.root.path(), 0o700);
    }
}

/// ´test:integration:rubric-entry-compares-distinct-loop-uids-at-leaf´
#[test]
fn rubric_entry_compares_distinct_loop_uids_at_leaf() {
    let mut fixture = Fixture::unprivileged();
    let observed = fixture.uid;
    let admitted = fixture.preflight().expect("search-only prefixes admitted");
    assert_eq!(
        json!(fixture.judge().rubric_digest),
        admitted["rubric_digest"]
    );
    for expected in [observed + 1, observed + 2] {
        fixture.uid = expected;
        let refusal = fixture.preflight().expect_err("different expected loop");
        let report: Value = serde_json::from_str(&refusal.detail).expect("refusal report");
        assert_eq!(report["expected_uid"], expected);
        assert_eq!(
            report["rubric_failure"],
            json!({"check":"file-owner",
            "path":fixture.runner.rubric_path,"owner_uid":observed,"mode":"0644","errno":null})
        );
    }
    drop(fixture);
}

/// ´test:integration:rubric-entry-checks-unprivileged-ancestors´
#[test]
fn rubric_entry_checks_unprivileged_ancestors() {
    let fixture = Fixture::unprivileged();
    let ancestor = fixture.ancestor();
    for expected in [fixture.uid + 1, fixture.uid + 2] {
        // Invoke the production ancestor predicate through the entry with real stat data.
        let output = Command::new(&fixture.runner.entry)
            .args(["enter", "alpha", "--", "/usr/bin/python3", "-I", "-c"])
            .arg(format!("{}{}", loop_home::runner::SIGN_IN_POLICY,
                "\nimport json,sys\ntry:\n rubric_ancestor(os.stat(sys.argv[1]), sys.argv[1], int(sys.argv[2]))\nexcept RubricFailure as error:\n print(json.dumps(error.evidence))\n"))
            .arg(&ancestor).arg(expected.to_string()).output().expect("entry policy");
        assert!(output.status.success());
        let failure: Value = serde_json::from_slice(&output.stdout).expect("ancestor evidence");
        assert_eq!(
            failure,
            json!({"check":"ancestor-owner","path":ancestor,
            "owner_uid":fixture.uid,"mode":"0711","errno":null})
        );
    }
    mode(&ancestor, 0o733);
    fixture.refused("ancestor-writable", &ancestor, Some(fixture.uid));
    mode(&ancestor, 0o600);
    let result = fixture.judge();
    let preflight = fixture.preflight();
    mode(&ancestor, 0o711);
    assert_eq!(
        result.observations["rubric_failure"],
        json!({"check":"ancestor-open",
        "path":ancestor.join("permissions"),"owner_uid":null,"mode":null,"errno":nix::libc::EACCES})
    );
    assert!(
        preflight
            .expect_err("unsearchable ancestor")
            .detail
            .contains("ancestor-open")
    );
    let saved = ancestor.with_extension("saved");
    fs::rename(&ancestor, &saved).expect("save publication");
    symlink(&saved, &ancestor).expect("linked ancestor");
    let failure = fixture.refused("ancestor-open", &ancestor, None);
    assert_eq!(failure["errno"], nix::libc::ENOTDIR);
    fs::remove_file(&ancestor).expect("remove link");
    fs::rename(saved, ancestor).expect("restore publication");
    file(&fixture.runner.rubric_path, &vec![b'x'; 65_537], 0o644);
    fixture.refused("file-size", &fixture.runner.rubric_path, Some(fixture.uid));
    file(&fixture.runner.rubric_path, &[0xff], 0o644);
    fixture.refused("file-utf8", &fixture.runner.rubric_path, Some(fixture.uid));
}

/// ´test:integration:install-and-refresh-report-unprivileged-rubric-failure´
#[test]
fn install_and_refresh_report_unprivileged_rubric_failure() {
    install_refusals(&Fixture::unprivileged());
}

/// ´test:integration:rubric-failure-reaches-exercise-and-schema-four-readers´
#[test]
fn rubric_failure_reaches_exercise_and_schema_four_readers() {
    let fixture = Fixture::unprivileged();
    file(&fixture.runner.rubric_path, &[0xff], 0o644);
    let result = fixture.judge();
    let evidence = json!({"check":"file-utf8","path":fixture.runner.rubric_path,
        "owner_uid":fixture.uid,"mode":"0644","errno":null});
    assert_eq!(result.observations["rubric_failure"], evidence);
    assert_eq!(
        result.exercise_observation(5000, None)["observations"]["rubric_failure"],
        evidence
    );
    record_readers(&fixture, &result);
    drop(fixture);
}

fn record_readers(fixture: &Fixture, result: &RunnerOutcome) {
    use superloop_lane::requests::{RequestRecord, store::Store};
    fixture.install_config();
    mode(fixture.root.path(), 0o700);
    let home = fixture.root.path();
    let runs = home.join("runs");
    fs::create_dir_all(runs.join(".launch-R")).expect("run custody");
    mode(&runs, 0o700);
    mode(&runs.join(".launch-R"), 0o700);
    file(&home.join(".config/loops/registry.toml"), format!(
        "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1,0,0]\nloops = [{{name='alpha',uid={},launch='src',runs_root='{}'}}]\n",
        fixture.uid + 1, runs.display()).as_bytes(), 0o600);
    let home_fd = fs::File::open(home).expect("home descriptor");
    let runs_fd = fs::File::open(&runs).expect("runs descriptor");
    let _binding = superloop_lane::home::activate_private_launch(
        home,
        &home_fd,
        &runs,
        &runs_fd,
        None,
        fixture.uid,
    )
    .expect("private fixture binding");
    let store = Store::open(home, "alpha", true).expect("production store");
    let setting = superloop_lane::requests::ModeSetting::first(
        superloop_lane::requests::Mode::Audit,
        superloop_lane::requests::Mode::Audit,
        "owner",
        "fixture",
        "1",
    )
    .expect("setting");
    for (nonce, worker) in [("1a", fixture.uid + 10), ("1b", fixture.uid + 11)] {
        let mut record = json!({"schema":4,"id":format!("R:{nonce}"),"loop":"alpha","run":"R",
            "worker_uid":worker,"class":"git","shape_key":"git:upload","operation":"git-upload",
            "mirror_ref":"refs/heads/lane/alpha","mode":"audit","floor":"audit",
            "class_setting":setting.value(),"loop_setting":setting.value(),
            "would_do":{"decision":"undecided","reason":"fixture"},
            "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,"stdin_bytes":0,
                "stdout_bytes":0,"stderr_bytes":0,"queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
            "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1"});
        superloop_lane::requests::judgement::initialize(&mut record);
        let mut record = RequestRecord::decode(record).expect("schema four");
        record.mark("fixture review").expect("mark for review");
        store.file(record).expect("file request");
        store
            .record_agent(&format!("R:{nonce}"), result, None, Some("fixture"))
            .expect("production agent writer");
    }
    for row in store.list_run("R").expect("exercise run reader") {
        assert_eq!(row.value()["schema"], 4);
        assert_eq!(row.value()["agent_reason"], "door-rubric-unavailable");
        assert!(row.value().get("rubric_failure").is_none());
        assert!(row.value().get("agent_evidence").is_none());
        assert_eq!(
            store.request(row.id()).expect("single reader").value(),
            row.value()
        );
    }
    assert_eq!(store.list().expect("aggregate reader").0.len(), 2);
    let permission_registry = requests_support::registry(fixture.root.path(), "alpha");
    for args in [
        vec!["list", "alpha"],
        vec!["status", "alpha"],
        vec!["review", "alpha", "R:1a"],
        vec!["rewrite", "alpha", "--dry-run"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .arg("requests")
            .args(args)
            .env("HOME", home)
            .env("SUPERLOOP_LANE_REQUESTS_HELPER", requests_support::binary())
            .env("PERMISSION_TRIAGE_LOOP_REGISTRY", &permission_registry)
            .env_remove("PERMISSION_TRIAGE_REQUEST_CONTEXT")
            .env_remove("ENTER_LOOP_REGISTRY")
            .output()
            .expect("request command reader");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("reader JSON");
        assert!(!report.to_string().contains("rubric_failure"));
    }
}
