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

// Mirror the inbound fixture: keep data under the supplied temporary root,
// overlay only an unsearchable ancestor inside each child's mount namespace.
fn vendor_mount(root: &Path) -> String {
    format!(
        concat!(
            "import ctypes,pathlib\n",
            "libc=ctypes.CDLL(None,use_errno=True)\n",
            "assert libc.unshare(0x20000)==0,ctypes.get_errno()\n",
            "fd=os.open({root},os.O_RDONLY|os.O_DIRECTORY)\n",
            "assert libc.mount(None,b'/',None,0x44000,None)==0,ctypes.get_errno()\n",
            "parents=reversed(pathlib.Path({root}).parents)\n",
            "blocked=next((str(p) for p in parents if os.stat(p).st_mode & 0o023 != 1),None)\n",
            "if blocked is not None:\n",
            " assert blocked!='/'\n",
            " assert libc.mount(b'tmpfs',blocked.encode(),b'tmpfs',6,",
            "b'mode=0755,size=1m')==0,ctypes.get_errno()\n",
            " os.makedirs({root})\n",
            " cursor=pathlib.Path({root})\n",
            " while True:\n",
            "  os.chown(cursor,0,0);os.chmod(cursor,0o755)\n",
            "  if str(cursor)==blocked: break\n",
            "  cursor=cursor.parent\n",
            " source=('/proc/self/fd/'+str(fd)).encode()\n",
            " assert libc.mount(source,{root}.encode(),None,4096,None)==0,ctypes.get_errno()\n",
            "os.close(fd)\n",
        ),
        root = json!(root)
    )
}

struct Fixture {
    root: tempfile::TempDir,
    _owner_root: tempfile::TempDir,
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

    #[allow(clippy::too_many_lines)]
    fn entered(uid: u32, mapped: bool) -> Self {
        let process = FIXTURE_PROCESS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = tempfile::tempdir().expect("parent-owned fixture under supplied temporary root");
        mode(root.path(), if mapped { 0o711 } else { 0o311 });
        let owner_root = tempfile::tempdir().expect("separate owner fixture");
        let owner_home = owner_root.path().to_path_buf();
        fs::create_dir_all(owner_home.join(".config/loops/alpha/lanes/codex"))
            .expect("canonical lock root");
        for relative in [
            "",
            ".config",
            ".config/loops",
            ".config/loops/alpha",
            ".config/loops/alpha/lanes",
            ".config/loops/alpha/lanes/codex",
        ] {
            mode(&owner_home.join(relative), 0o700);
        }
        let token = "header.eyJleHAiOjQxMDAwMDAwMDB9.signature";
        let authority = json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,
            "tokens":{"id_token":token,"access_token":token,
                "refresh_token":"fictional-fixture-refresh","account_id":"fictional-account"},
            "last_refresh":"2026-10-05T00:00:00Z"});
        file(
            &owner_home.join(".config/loops/alpha/lanes/codex/auth.json"),
            authority.to_string().as_bytes(),
            0o600,
        );
        let home = root.path().join("loop/private");
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
        file(
            &entry,
            format!(
                concat!(
                    "#!/usr/bin/python3\nimport os,sys\n{mount}",
                    "assert sys.argv[1:4] == ['enter','alpha','--']\n",
                    "{identity}assert os.getuid() == {uid}\n",
                    "os.environ['HOME'] = {home}\nos.environ['TMPDIR'] = {tmp}\n",
                    "try: os.listdir({publication})\nexcept PermissionError: pass\n",
                    "else: raise AssertionError('search-only ancestor was readable')\n",
                    "os.execv(sys.argv[4],sys.argv[4:])\n",
                ),
                uid = uid,
                mount = if mapped {
                    vendor_mount(root.path())
                } else {
                    String::new()
                },
                identity = if mapped {
                    format!("os.setgroups([])\nos.setgid({uid})\nos.setuid({uid})\n")
                } else {
                    String::new()
                },
                home = json!(home),
                tmp = json!(home.join("tmp")),
                publication = json!(root.path())
            )
            .as_bytes(),
            0o700,
        );
        let executable = root.path().join("codex");
        file(&executable, b"#!/usr/bin/python3\nimport json,sys\ndocument=json.load(sys.stdin)\nassert document['reviewed_rubric'] == 'Reviewed rubric.'\nprint(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':json.dumps({'verdict':'refer','scope':'estate','reason':'fixture'})}}))\n", 0o755);
        let runner = CodexRunner {
            usage_monitor: std::sync::Arc::new(superloop_lane::door::agent::usage::Monitor::new(
                superloop_lane::door::agent::usage::DEFAULT_EXPECTED_TOKENS,
            )),
            entry,
            owner_home,
            private_home: home,
            loop_name: "alpha".into(),
            loop_uid: Some(uid),
            executable,
            model: "fixture".into(),
            effort: "medium".into(),
            cap_ms: 5000,
            rubric_path: rubric,
        };
        Self {
            root,
            _owner_root: owner_root,
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
#[ignore = "requires namespace root with UID/GID 0, 3000, 3001, 41001, 41002 and 41003 mapped"]
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

// Preserve the caller's mount capability until its entry has overlaid the
// temporary ancestors; drop every capability before the loop reads policy.
fn non_root_entry(fixture: &Fixture) {
    for path in [
        fixture.root.path().to_path_buf(),
        fixture.root.path().join("publication/permissions"),
        fixture.ancestor(),
        fixture.runner.rubric_path.clone(),
        fixture.runner.executable.clone(),
    ] {
        chown(&path, Some(Uid::from_raw(0)), None).expect("trusted fixture custody");
    }
    let source = fs::read_to_string(&fixture.runner.entry).expect("entry source");
    let identity = format!(
        "os.setgroups([])\nos.setgid({0})\nos.setuid({0})\n",
        fixture.uid
    );
    let (before, after) = source
        .split_once(&identity)
        .expect("entry identity boundary");
    let tail = format!(
        concat!(
            "import os,sys\n",
            "assert all(int(l.split()[1],16)==0 for l in open('/proc/self/status') ",
            "if l.startswith(('CapEff:','CapInh:','CapAmb:')))\n{}"
        ),
        after
    );
    let entry = format!(
        concat!(
            "{}os.execv('/usr/bin/setpriv',['setpriv','--reuid={uid}','--regid={uid}',",
            "'--clear-groups','--inh-caps=-all','--ambient-caps=-all',",
            "'/usr/bin/python3','-I','-c',{}]+sys.argv[1:])\n"
        ),
        before,
        json!(tail),
        uid = fixture.uid
    );
    file(&fixture.runner.entry, entry.as_bytes(), 0o700);
}

/// ´test:integration:rubric-entry-refuses-host-numeric-subordinate-owner´
#[test]
#[ignore = "requires namespace root and loop 41001 and subordinate 41000 mapped"]
fn rubric_entry_refuses_host_numeric_subordinate_owner() {
    const CHILD: &str = "SUPERLOOP_RUBRIC_SERVICE_FIXTURE";
    if std::env::var_os(CHILD).is_none() {
        namespace();
        let output = Command::new("/usr/bin/timeout")
            .args(["--kill-after=2", "30", "/usr/bin/setpriv"])
            .args([
                "--reuid=41000",
                "--regid=41000",
                "--clear-groups",
                "--inh-caps=+chown,+dac_override,+fowner,+setuid,+setgid,+sys_admin",
                "--ambient-caps=+chown,+dac_override,+fowner,+setuid,+setgid,+sys_admin",
            ])
            .arg(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "rubric_entry_refuses_host_numeric_subordinate_owner",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("bounded non-root caller");
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
            "{output:?}"
        );
        return;
    }
    assert_eq!(Uid::effective().as_raw(), 41000);
    assert_eq!(Gid::effective().as_raw(), 41000);
    let fixture = Fixture::new(41001);
    non_root_entry(&fixture);
    fixture.preflight().expect("host-owned rubric control");
    assert_eq!(
        fixture.judge().status,
        "verdict",
        "host-owned runtime control"
    );
    chown(
        &fixture.runner.rubric_path,
        Some(Uid::from_raw(41001)),
        None,
    )
    .unwrap();
    fixture.preflight().expect("loop-owned rubric control");
    assert_eq!(
        fixture.judge().status,
        "verdict",
        "loop-owned runtime control"
    );
    chown(
        &fixture.runner.rubric_path,
        Some(Uid::from_raw(41000)),
        None,
    )
    .unwrap();
    fixture.refused("file-owner", &fixture.runner.rubric_path, Some(41000));
    chown(&fixture.runner.rubric_path, Some(Uid::from_raw(0)), None).unwrap();
    let ancestor = fixture.ancestor();
    chown(&ancestor, Some(Uid::from_raw(41000)), None).unwrap();
    fixture.refused("ancestor-owner", &ancestor, Some(41000));
    drop(fixture);
}

/// ´test:integration:rubric-runtime-refuses-effective-only-uid-change´
#[test]
#[ignore = "requires namespace root with UID/GID 0 and loop 41001 mapped"]
fn rubric_runtime_refuses_effective_only_uid_change() {
    namespace();
    let fixture = Fixture::new(41001);
    assert_eq!(
        fixture.judge().status,
        "verdict",
        "complete uid entry control"
    );
    let entry = fs::read_to_string(&fixture.runner.entry).expect("fixture entry");
    let partial = entry
        .replace("os.setuid(41001)", "os.seteuid(41001)")
        .replace(
            "assert os.getuid() == 41001",
            "assert os.getuid() == 0 and os.geteuid() == 41001",
        );
    assert_ne!(entry, partial);
    file(&fixture.runner.entry, partial.as_bytes(), 0o700);
    let result = fixture.judge();
    assert_eq!(result.reason, "door-rubric-unavailable", "{result:?}");
    assert_eq!(result.observations["rubric_failure"]["check"], "entry-uid");
    assert_eq!(
        result.observations["rubric_failure"]["path"],
        json!(fixture.runner.rubric_path)
    );
    assert!(result.rubric_digest.is_none());
}

/// ´test:integration:rubric-entry-refuses-third-uid-and-writable-ancestors´
#[test]
#[ignore = "requires namespace root with UID/GID 0, 3000, 3001, 41001, 41002 and 41003 mapped"]
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
#[ignore = "requires namespace root with UID/GID 0, 3000, 3001, 41001, 41002 and 41003 mapped"]
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
    let entered = fixture.runner.entry.with_extension("entered");
    let entry_path = if entered.exists() {
        &entered
    } else {
        &fixture.runner.entry
    };
    let entry = fs::read_to_string(entry_path).expect("entry");
    let start = entry.find("try: os.listdir").expect("listing assertion");
    let end = entry.find("os.execv").expect("exec entry");
    file(
        entry_path,
        format!("{}{}", &entry[..start], &entry[end..]).as_bytes(),
        if entered.exists() { 0o755 } else { 0o700 },
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
        let previous = fs::read(&generation).ok();
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
            assert_eq!(fs::read(&generation).ok(), previous);
        }
    }
}

/// ´test:integration:rubric-failure-survives-current-request-record´
#[test]
#[ignore = "requires namespace root with UID/GID 0, 3000, 3001, 41001, 41002 and 41003 mapped"]
fn rubric_failure_survives_current_request_record() {
    // The mapped failure evidence survives the current strict record decoder.
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
            let mut record = json!({"schema":6,"id":"R:1a","loop":"alpha","run":"R",
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
                .expect("current record schema");
            assert_eq!(decoded.value()["schema"], 6);
            assert!(
                !decoded
                    .value()
                    .to_string()
                    .contains("synthetic-fixture-only")
            );
            assert_eq!(decoded.value()["agent_observations"], result.observations);
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

/// ´test:integration:rubric-entry-refuses-distinct-loop-uids´
#[test]
fn rubric_entry_refuses_distinct_loop_uids() {
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
        let failure = &report["rubric_failure"];
        assert_eq!(failure["check"], "ancestor-owner", "{report}");
        assert_eq!(failure["owner_uid"], observed);
        let refused = Path::new(failure["path"].as_str().expect("refused ancestor"));
        assert!(fixture.runner.rubric_path.starts_with(refused), "{report}");
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
            .arg(format!(
                "{}{}",
                loop_home::runner::SIGN_IN_POLICY,
                concat!(
                    "\nimport json,sys\ntry:\n rubric_ancestor(os.stat(sys.argv[1]), ",
                    "sys.argv[1], int(sys.argv[2]))\n",
                    "except RubricFailure as error:\n print(json.dumps(error.evidence))\n",
                )
            ))
            .arg(&ancestor)
            .arg(expected.to_string())
            .output()
            .expect("entry policy");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
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

/// ´test:integration:rubric-failure-reaches-exercise-and-current-readers´
#[test]
fn rubric_failure_reaches_exercise_and_current_readers() {
    let fixture = Fixture::unprivileged();
    file(&fixture.runner.rubric_path, &[0xff], 0o644);
    let result = fixture.judge();
    let evidence = json!({"check":"file-utf8","path":fixture.runner.rubric_path,
        "owner_uid":fixture.uid,"mode":"0644","errno":null});
    assert_eq!(result.observations["rubric_failure"], evidence);
    assert_eq!(result.reason, "door-rubric-unavailable", "{result:?}");
    assert_eq!(
        result.exercise_observation(5000, None)["observations"]["rubric_failure"],
        evidence
    );
    record_readers(&fixture, &result);
    drop(fixture);
}

/// ´test:integration:agent-signin-bytes-stay-out-of-records-and-listings´
#[test]
fn agent_signin_bytes_stay_out_of_records_and_listings() {
    let fixture = Fixture::unprivileged();
    let result = fixture.judge();
    assert_eq!(result.status, "verdict", "{result:?}");
    assert_eq!(result.observations["agent_calls"], 1);
    assert_eq!(result.observations["sign_in_link_preserved"], true);
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
        let mut record = json!({"schema":6,"id":format!("R:{nonce}"),"loop":"alpha","run":"R",
            "worker_uid":worker,"class":"git","shape_key":"git:upload","operation":"git-upload",
            "mirror_ref":"refs/heads/lane/alpha","mode":"audit","floor":"audit",
            "class_setting":setting.value(),"loop_setting":setting.value(),
            "would_do":{"decision":"undecided","reason":"fixture"},
            "effect":{"state":"pending","reason":null,"exit_status":null,"ref_check":null,"stdin_bytes":0,
                "stdout_bytes":0,"stderr_bytes":0,"queue_wall_seconds":null,"mediation_wall_seconds":0.0,"compute_wall_seconds":0.0},
            "state":"waiting","mark_reason":null,"review":null,"label":null,"filed_at":"1"});
        superloop_lane::requests::judgement::initialize(&mut record);
        let mut record = RequestRecord::decode(record).expect("schema six");
        record.mark("fixture review").expect("mark for review");
        store.file(record).expect("file request");
        store
            .record_agent(&format!("R:{nonce}"), result, None, Some("fixture"))
            .expect("production agent writer");
    }
    for row in store.list_run("R").expect("exercise run reader") {
        assert_eq!(row.value()["schema"], 6);
        assert!(!row.value().to_string().contains("synthetic-fixture-only"));
        assert_eq!(row.value()["agent_reason"], result.reason);
        assert!(row.value().get("rubric_failure").is_none());
        assert_eq!(row.value()["agent_observations"], result.observations);
        assert_eq!(
            row.value()["agent_observations"]["rubric_failure"],
            result.observations["rubric_failure"]
        );
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
        let action = args[0];
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
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-fixture-only"));
        let report: Value = serde_json::from_slice(&output.stdout).expect("reader JSON");
        assert_reader_observations(&report, action, result);
    }
}

fn assert_reader_observations(report: &Value, action: &str, result: &RunnerOutcome) {
    match action {
        "review" => assert_eq!(report["agent_observations"], result.observations),
        "rewrite" => assert_eq!(
            report["plan"]["files"][0]["after"]["requests"][0]["agent_observations"],
            result.observations
        ),
        _ => assert_eq!(
            report["door_judgements"][0]["agent_observations"],
            result.observations
        ),
    }
}

/// ´test:integration:rubric-runtime-compares-registry-loop-uid´
#[test]
#[ignore = "requires namespace root and loop 41001 mapped"]
fn rubric_runtime_compares_registry_loop_uid() {
    namespace();
    let mut fixture = Fixture::new(41001);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    fixture.runner.loop_uid = Some(41002);
    let result = fixture.judge();
    assert_eq!(result.reason, "door-rubric-unavailable", "{result:?}");
    assert_eq!(result.observations["rubric_failure"]["check"], "entry-uid");
    drop(fixture);
}

fn vendor_refused(fixture: &Fixture, check: &str, path: &Path) {
    let result = fixture.judge();
    assert_eq!(result.reason, "door-agent-program-custody", "{result:?}");
    assert_eq!(
        result.observations["program_failure"]["check"], check,
        "{result:?}"
    );
    assert_eq!(result.observations["program_failure"]["path"], json!(path));
}

/// ´test:integration:door-agent-refuses-foreign-vendor-program´
#[test]
#[ignore = "requires namespace root and loop 41001 and outsider 41003 mapped"]
fn door_agent_refuses_foreign_vendor_program() {
    namespace();
    let fixture = Fixture::new(41001);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    chown(&fixture.runner.executable, Some(Uid::from_raw(41003)), None).unwrap();
    vendor_refused(&fixture, "program-owner", &fixture.runner.executable);
    drop(fixture);
}

/// ´test:integration:door-agent-refuses-group-writable-vendor-ancestor´
#[test]
#[ignore = "requires namespace root and loop 41001 mapped"]
fn door_agent_refuses_group_writable_vendor_ancestor() {
    namespace();
    let mut fixture = Fixture::new(41001);
    let parent = fixture.root.path().join("vendor");
    fs::create_dir(&parent).unwrap();
    mode(&parent, 0o755);
    let program = parent.join("codex");
    fs::rename(&fixture.runner.executable, &program).unwrap();
    fixture.runner.executable = program;
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    mode(&parent, 0o775);
    vendor_refused(&fixture, "program-writable", &parent);
    drop(fixture);
}

/// ´test:integration:door-agent-refuses-linked-vendor-program´
#[test]
#[ignore = "requires namespace root and loop 41001 mapped"]
fn door_agent_refuses_linked_vendor_program() {
    namespace();
    let fixture = Fixture::new(41001);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    let target = fixture.runner.executable.with_extension("real");
    fs::rename(&fixture.runner.executable, &target).unwrap();
    symlink(&target, &fixture.runner.executable).unwrap();
    vendor_refused(&fixture, "program-link", &fixture.runner.executable);
    drop(fixture);
}

/// ´test:integration:door-agent-admits-loop-owned-vendor-program´
#[test]
#[ignore = "requires namespace root and loop 41001 mapped"]
fn door_agent_admits_loop_owned_vendor_program() {
    namespace();
    let fixture = Fixture::new(41001);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    chown(&fixture.runner.executable, Some(Uid::from_raw(41001)), None).unwrap();
    mode(&fixture.runner.executable, 0o500);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    drop(fixture);
}

/// ´test:integration:door-agent-admits-host-owned-vendor-program´
#[test]
#[ignore = "requires namespace root and loop 41001 mapped"]
fn door_agent_admits_host_owned_vendor_program() {
    namespace();
    let mut fixture = Fixture::new(41001);
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    let root = fixture
        .root
        .path()
        .join("runner-templates/codex/digest/bin");
    fs::create_dir_all(&root).unwrap();
    mode(&fixture.root.path().join("runner-templates"), 0o711);
    mode(&fixture.root.path().join("runner-templates/codex"), 0o711);
    for parent in [root.parent().unwrap(), &root] {
        chown(parent, None, Some(Gid::from_raw(41001))).unwrap();
        mode(parent, 0o550);
    }
    let program = root.join("codex");
    fs::rename(&fixture.runner.executable, &program).unwrap();
    chown(&program, None, Some(Gid::from_raw(41001))).unwrap();
    mode(&program, 0o550);
    fixture.runner.executable = program;
    let control = fixture.judge();
    assert_eq!(control.status, "verdict", "{control:?}");
    drop(fixture);
}

/// ´test:integration:agent-metadata-reports-vendor-admission´
#[test]
#[ignore = "requires namespace root and loop 41001 and outsider 41003 mapped"]
fn agent_metadata_reports_vendor_admission() {
    namespace();
    let fixture = Fixture::new(41001);
    fixture.install_config();
    let inspect = || {
        superloop_lane::door::metadata::inspect(
            &fixture.runner.entry,
            fixture.root.path(),
            "alpha",
            &fixture.runner.executable,
        )
    };
    assert_eq!(inspect()["executable_status"]["admitted"], true);
    chown(&fixture.runner.executable, Some(Uid::from_raw(41003)), None).unwrap();
    let value = inspect();
    assert_eq!(value["executable_status"]["admitted"], false, "{value}");
    assert_eq!(
        value["executable_status"]["refusal"]["check"],
        "program-owner"
    );
    drop(fixture);
}
