use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

/// # Panics
/// Panics only if the asserted boundary contract fails.
///
/// ´test:unit:door-repin-interrupted-boundary-requires-ended-driver´
#[test]
fn door_repin_interrupted_boundary_requires_ended_driver() {
    let record = json!({"run":"R","phase":"started","active_round":"work",
        "driver_end":{"state":"completed"},"rounds":[{"step":"work","phase":"running"}]});
    assert_eq!(
        settled_boundary(&record, crate::launch::driver_report::fixture_read)
            .expect("interrupted boundary")
            .2,
        "interrupted-settlement"
    );
    for (key, value) in [
        ("driver_end", json!({"state":"running"})),
        ("reaping_recovery", json!({"state":"collected"})),
        ("rotation", json!({"old_run":"R"})),
        ("rotation_intent", json!({})),
        ("active_round", json!("other")),
        (
            "rounds",
            json!([{"step":"work","phase":"running","report":{}}]),
        ),
    ] {
        let mut invalid = record.clone();
        invalid[key] = value;
        assert_eq!(
            settled_boundary(&invalid, crate::launch::driver_report::fixture_read)
                .expect_err("unsafe boundary")
                .kind,
            "repin-door-state"
        );
    }
}

fn interrupted_fixture(completed_driver: bool, report_step: &str, successful: bool) -> Fixture {
    let fixture = Fixture::new(3000);
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    record["phase"] = json!("started");
    record["active_round"] = json!("work");
    record["driver_end"] = if completed_driver {
        json!({"state":"completed","successful":successful})
    } else {
        Value::Null
    };
    record["observer_end"] = if completed_driver {
        json!({"state":"not-started","socket":{"state":"not-applicable"}})
    } else {
        Value::Null
    };
    record["helper_parent_pid"] = json!(u32::MAX);
    record["helper_parent_start"] = json!(1);
    let report_directory = PathBuf::from(
        record["rounds"][0]["driver_dir"]
            .as_str()
            .expect("prior directory"),
    );
    directory(&report_directory, 0o700);
    let (exit, verdict) = if successful { (0, "ok") } else { (1, "FAILED") };
    fs::write(report_directory.join("run-report.txt"), format!(
        "RUN-REPORT lane={report_step} exit={exit} wall=3500s budget=7200s verdict={verdict} dir={}\n", report_directory.display()
    )).expect("driver end report");
    record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(json!({
            "step":"work","phase":"running","budget_seconds":2,"driver_dir":report_directory
        }));
    publish_reservation(&fixture.path, &record).expect("interrupted resumed round");
    directory(
        &fixture.path.parent().expect("runs").join(".launch-R"),
        0o700,
    );
    fixture
}

fn hard_wall_fixture(end: Option<Value>) -> Fixture {
    let fixture = interrupted_fixture(true, "work", false);
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    directory(
        Path::new(
            record["plan"]["driver_dir"]
                .as_str()
                .expect("driver directory"),
        ),
        0o700,
    );
    if let Some(end) = end {
        record["observer_end"] = end;
    } else {
        record
            .as_object_mut()
            .expect("object")
            .remove("observer_end");
    }
    if record["observer_end"].is_null() {
        record["active_round"] = json!("dispatch");
        record["rounds"].as_array_mut().expect("rounds").truncate(1);
        record["rounds"][0]["phase"] = json!("running");
    }
    let round = record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .last_mut()
        .expect("last round");
    round["budget_seconds"] = json!(7200);
    let report =
        Path::new(round["driver_dir"].as_str().expect("driver directory")).join("run-report.txt");
    fs::write(report, format!("RUN-REPORT lane={} exit=1 wall=14403s budget=7200s verdict=FAILED backend_program=/usr/libexec/superloop/codex\n", record["active_round"].as_str().expect("round"))).expect("hard-wall report");
    publish_reservation(&fixture.path, &record).expect("hard-wall record");
    fixture.install_b();
    fixture
}

fn measured_observer(
    record: &Value,
    owner_home: &Path,
    wall_seconds: f64,
) -> Result<Value, LaneError> {
    let route = json!({"alias":"fixture","mirror_root":"~/mirrors",
        "key_path":owner_home.join(".config/loops/alpha/door-key"),
        "node_root":"/srv/loops/loop-a","ssh_config_sha256":"a".repeat(64)});
    super::super::retire::proof::observer_absence_with_node(record, owner_home, |record, _| {
        Ok(json!({"schema":1,"loop":record["loop"],"run":record["run"],
            "state":"absent","processes":[],"lock":"unheld","route":route,
            "wall_seconds":wall_seconds,"host_wall_seconds":wall_seconds + 0.1}))
    })
}

/// # Panics
/// Panics only if fixture setup or the measured re-pin contract fails.
/// ´test:unit:door-repin-hard-wall-measures-missing-and-stale-observer-end´
#[test]
fn door_repin_hard_wall_measures_missing_and_stale_observer_end() {
    for end in [
        None,
        Some(Value::Null),
        Some(json!({"state":"stopped","socket":{"state":"removed"}})),
    ] {
        let fixture = hard_wall_fixture(end);
        let before = fs::read(&fixture.path).expect("before");
        let mut measurements = 0;
        let mut measure = |record: &Value, home: &Path| {
            measurements += 1;
            measured_observer(record, home, f64::from(measurements))
        };
        let preview = run_with_observer(fixture.home.path(), &Fixture::request(None), &mut measure)
            .expect("absence preview");
        assert_eq!(fs::read(&fixture.path).expect("after preview"), before);
        assert_eq!(
            preview["identities"]["observer"]["presence"],
            "absence-proved-without-identity"
        );
        for measurement in ["host", "locks", "node"] {
            assert_eq!(
                preview["evidence"]["observer"][measurement]["state"],
                "absent"
            );
        }
        assert!(preview["evidence"]["observer"]["node"]["route"].is_object());
        let digest = preview["preview_sha256"].as_str().expect("digest");
        let applied = run_with_observer(
            fixture.home.path(),
            &Fixture::request(Some(digest)),
            &mut measure,
        )
        .expect("apply freshly measured absence");
        assert_eq!(measurements, 2);
        assert_eq!(applied["evidence"], preview["evidence"]);
        assert!(
            preview["evidence"]["observer"]["node"]
                .get("wall_seconds")
                .is_none()
        );
        assert!(
            preview["evidence"]["observer"]["node"]
                .get("host_wall_seconds")
                .is_none()
        );
        let saved = read_reservation(&fixture.path)
            .expect("read")
            .expect("saved");
        assert_eq!(
            saved["door_pin_history"][0]["evidence"]["observer"],
            preview["evidence"]["observer"]
        );
        assert_eq!(
            saved["observer_end"],
            serde_json::from_slice::<Value>(&before).expect("before record")["observer_end"]
        );
    }
}

/// # Panics
/// Panics only if fixture setup or a live/uncertain observer is admitted.
/// ´test:unit:door-repin-hard-wall-keeps-live-and-uncertain-refusals´
#[test]
fn door_repin_hard_wall_keeps_live_and_uncertain_refusals() {
    for (kind, expected) in [
        ("retire-busy", "repin-door-live"),
        ("retire-uncertain", "repin-door-uncertain"),
    ] {
        let fixture = hard_wall_fixture(None);
        let error = run_with_observer(fixture.home.path(), &Fixture::request(None), |_, _| {
            Err(LaneError::input(kind, "observer measurement"))
        })
        .expect_err("presence refuses");
        assert_eq!(error.kind, expected);
    }
    let fixture = hard_wall_fixture(None);
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    record["observer_pid"] = json!(std::process::id());
    record["observer_start"] =
        json!(crate::container_helper::process_start(std::process::id()).expect("start"));
    publish_reservation(&fixture.path, &record).expect("live observer");
    let error = run_with_observer(fixture.home.path(), &Fixture::request(None), |_, _| {
        panic!("recorded observer must not use fallback")
    })
    .expect_err("live observer refuses");
    assert_eq!(error.kind, "repin-door-live");
}

/// # Panics
/// Panics only if fixture setup or the existing never-started observer proof fails.
/// ´test:unit:door-repin-hard-wall-retains-prior-never-started-observer-proof´
#[test]
fn door_repin_hard_wall_retains_prior_never_started_observer_proof() {
    let fixture = hard_wall_fixture(Some(
        json!({"state":"not-started","socket":{"state":"not-applicable"}}),
    ));
    let preview = run_with_observer(fixture.home.path(), &Fixture::request(None), |_, _| {
        panic!("existing proof must remain sufficient")
    })
    .expect("prior observer end");
    assert_eq!(
        preview["identities"]["observer"]["presence"],
        "absence-proved-without-identity"
    );
    assert!(preview["evidence"]["observer"].is_null());
}

fn container_runtime(fixture: &Fixture, state: &Value) {
    let id = "a".repeat(64);
    let inspection = json!([{"Id":id,"Name":"exited-box",
        "Config":{"Labels":{"org.superloop.loop":"alpha","org.superloop.run":"R"}},"State":state}]);
    crate::fixture_exec::write_executable(&fixture.runtime, format!(
        "#!/bin/sh\ncase \"$1\" in\nps) printf '%s\\n' '{id}';;\ncontainer) test \"$2\" = inspect && test \"$#\" = 3 && test \"$3\" = '{id}' || exit 9; printf '%s\\n' '{inspection}';;\n*) exit 9;;\nesac\n"
    ).as_bytes()).expect("inspection runtime");
}

/// # Panics
/// Panics only if malformed inspection or the old template invocation is admitted.
/// ´test:unit:door-repin-inspection-requires-one-plain-json-object´
#[test]
fn door_repin_inspection_requires_one_plain_json_object() {
    let fixture = interrupted_fixture(true, "work", false);
    fixture.install_b();
    let state = json!({"Status":"exited","Running":false,"Paused":false,
        "Restarting":false,"Pid":0,"ExitCode":143,"FinishedAt":"finished"});
    container_runtime(&fixture, &state);
    let error = crate::build::run_checked(
        &fixture.runtime,
        vec![
            "container".into(),
            "inspect".into(),
            "--format".into(),
            "{{json .Id}}".into(),
            "a".repeat(64),
        ],
        &crate::build::podman_environment(fixture.home.path()).expect("environment"),
        fixture.home.path(),
        30,
        "settlement-container",
    )
    .expect_err("fixture must reject --format");
    assert_eq!(error.kind, "settlement-container");
    let id = "a".repeat(64);
    let row = json!({"Id":id,"Name":"exited-box","Config":{"Labels":{"org.superloop.loop":"alpha","org.superloop.run":"R"}},"State":state});
    for response in [
        json!([row.clone(), row.clone()]),
        json!([]),
        json!([null]),
        row.clone(),
    ] {
        let error = super::super::exited_inspection(&response.to_string(), &id, "alpha", "R")
            .expect_err("array shape");
        assert_eq!(error.kind, "settlement-container");
        assert!(error.detail.contains("array of exactly one object"));
        assert!(error.detail.contains(&id));
    }
    let two = json!([row.clone(), row]);
    crate::fixture_exec::write_executable(&fixture.runtime, format!("#!/bin/sh\nif [ \"$1\" = ps ]; then printf '%s\\n' '{id}'; else printf '%s\\n' '{two}'; fi\n").as_bytes()).expect("two containers");
    let error =
        run(fixture.home.path(), &Fixture::request(None)).expect_err("ambiguous inspection");
    assert_eq!(error.kind, "repin-door-live");
    assert!(error.detail.contains("array of exactly one object"));
    assert!(
        super::super::exited_inspection(&" ".repeat(1_048_577), &id, "alpha", "R")
            .expect_err("bound")
            .detail
            .contains("exceeds 1 MiB")
    );
}

/// # Panics
/// Panics only if the fixture cannot be built or container evidence escapes the digest.
/// ´test:unit:door-repin-proved-exited-container-is-bound-and-retained´
#[test]
fn door_repin_proved_exited_container_is_bound_and_retained() {
    for completed_driver in [true, false] {
        let fixture = interrupted_fixture(completed_driver, "work", false);
        fixture.install_b();
        let mut state = json!({"Status":"exited","Running":false,"Paused":false,
            "Restarting":false,"Pid":0,"ExitCode":143,"FinishedAt":"2026-10-26T13:10:41+01:00"});
        container_runtime(&fixture, &state);
        let original = fs::read(&fixture.path).expect("original");
        let preview = run(fixture.home.path(), &Fixture::request(None)).expect("exited preview");
        assert_eq!(preview["container_presence"], "proved-exited");
        assert_eq!(
            preview["evidence"]["containers"],
            json!([{"id":"a".repeat(64),
            "name":"exited-box","exit_code":143,"finished_at":state["FinishedAt"]}])
        );
        let mut bound = preview["transition"].clone();
        bound
            .as_object_mut()
            .expect("transition")
            .remove("preview_sha256");
        assert_eq!(
            preview["preview_sha256"],
            value_hash(&bound).expect("digest")
        );
        assert_eq!(fs::read(&fixture.path).expect("unchanged"), original);
        state["ExitCode"] = json!(1);
        container_runtime(&fixture, &state);
        assert_eq!(
            run(
                fixture.home.path(),
                &Fixture::request(preview["preview_sha256"].as_str())
            )
            .expect_err("apply remeasures container")
            .kind,
            "repin-door-digest"
        );
        state["ExitCode"] = json!(143);
        container_runtime(&fixture, &state);
        run(
            fixture.home.path(),
            &Fixture::request(preview["preview_sha256"].as_str()),
        )
        .expect("apply");
        let saved = read_reservation(&fixture.path)
            .expect("read")
            .expect("saved");
        assert_eq!(
            saved["door_pin_history"][0]["evidence"],
            preview["evidence"]
        );
        assert!(
            !super::super::container_absent_for_run(
                &fixture.runtime,
                fixture.home.path(),
                "alpha",
                "R"
            )
            .expect("container retained")
        );
        for (key, value) in [
            ("extra", json!(true)),
            ("exit_code", json!(-1)),
            ("id", json!("short")),
            ("name", json!("")),
            ("finished_at", Value::Null),
        ] {
            let mut malformed = saved.clone();
            let row = &mut malformed["door_pin_history"][0];
            row["evidence"]["containers"][0][key] = value;
            row.as_object_mut().expect("row").remove("preview_sha256");
            row["preview_sha256"] = json!(value_hash(row).expect("digest"));
            assert_eq!(
                validate(&malformed).expect_err("strict evidence").kind,
                "repin-door-record"
            );
        }
    }
}

/// # Panics
/// Panics only if the fixture cannot be built or unproved exit permits re-pinning.
/// ´test:unit:door-repin-running-container-refuses´
#[test]
fn door_repin_running_container_refuses() {
    let fixture = interrupted_fixture(true, "work", false);
    fixture.install_b();
    let exited = json!({"Status":"exited","Running":false,"Paused":false,
        "Restarting":false,"Pid":0,"ExitCode":143,"FinishedAt":"finished"});
    let original = fs::read(&fixture.path).expect("original");
    for (key, value) in [
        ("Status", json!("running")),
        ("Running", json!(true)),
        ("Paused", json!(true)),
        ("Restarting", json!(true)),
        ("Pid", json!(1)),
        ("ExitCode", Value::Null),
        ("FinishedAt", json!("")),
    ] {
        let mut state = exited.clone();
        state[key] = value;
        container_runtime(&fixture, &state);
        assert_eq!(
            run(fixture.home.path(), &Fixture::request(None))
                .expect_err("not proved exited")
                .kind,
            "repin-door-live"
        );
        assert_eq!(fs::read(&fixture.path).expect("unchanged"), original);
    }
}

fn finish_fixture_recovery(fixture: &Fixture) -> Value {
    let saved = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    let plan = super::super::pinned_plan_from_record(
        fixture.home.path(),
        "alpha",
        "R",
        &fixture.runtime,
        &saved,
    )
    .expect("verified plan")
    .0;
    let letter = Path::new(saved["letter_source"].as_str().expect("letter"));
    let completed = super::super::finish_interrupted_settlement_with(
        &fixture.path,
        &plan,
        letter,
        Uid::effective().as_raw(),
        || Ok(Value::Null),
        || {
            Err(LaneError::input(
                "readback",
                "interrupted worker left no reply",
            ))
        },
        |_, _| crate::container_helper::ProcessPresence::Absent,
        || Ok(true),
        |_| Ok(json!({"state":"verified-empty","container_payload":{"state":"absent"}})),
        crate::launch::driver_report::fixture_read,
    )
    .expect("recovery completes");
    assert_eq!(completed["state"], "completed-interrupted-settlement");
    read_reservation(&fixture.path)
        .expect("read recovery")
        .expect("record")
}

/// # Panics
/// Panics only if fixture setup or interrupted recovery fails.
/// ´test:unit:door-repin-interrupted-run-recovers-after-stub-change´
#[test]
fn door_repin_interrupted_run_recovers_after_stub_change() {
    for completed_driver in [true, false] {
        let fixture = interrupted_fixture(completed_driver, "work", false);
        let record = read_reservation(&fixture.path)
            .expect("read")
            .expect("record");
        fixture.install_b();
        assert_eq!(
            fixture
                .resume(true)
                .expect_err("door drift blocks recovery")
                .kind,
            "plan-read"
        );
        let before = fs::read(&fixture.path).expect("before preview");
        let preview =
            run(fixture.home.path(), &Fixture::request(None)).expect("interrupted preview");
        assert_eq!(preview["boundary"], "interrupted-settlement");
        assert_eq!(preview["transition"]["boundary"], "interrupted-settlement");
        if !completed_driver {
            assert_eq!(preview["evidence"]["driver"], "absent");
            assert_eq!(preview["evidence"], preview["transition"]["evidence"]);
        }
        assert_eq!(fs::read(&fixture.path).expect("after preview"), before);
        run(
            fixture.home.path(),
            &Fixture::request(preview["preview_sha256"].as_str()),
        )
        .expect("digest-bound re-pin");
        let saved = read_reservation(&fixture.path)
            .expect("read re-pin")
            .expect("record");
        assert_eq!(saved["phase"], "started");
        assert_eq!(saved["driver_end"], record["driver_end"]);
        assert_eq!(saved["observer_end"], record["observer_end"]);
        assert_eq!(saved["rounds"], record["rounds"]);
        let recovery = fixture.resume(true).expect("recovery plan now matches");
        assert_eq!(
            recovery["interrupted_settlement"]["state"],
            "would-complete-interrupted-settlement"
        );
        let recovered = finish_fixture_recovery(&fixture);
        assert_eq!(recovered["door_pin_history"], saved["door_pin_history"]);
        assert_eq!(recovered["rounds"][1]["phase"], "failed");
        assert_eq!(recovered["driver_end"]["state"], "completed");
        assert_eq!(recovered["driver_end"]["successful"], false);
        if !completed_driver {
            assert_eq!(
                recovered["driver_end"]["source"],
                json!({"record":"run-report","driver":"measured-absent"})
            );
            assert_eq!(
                recovered["driver_end"]["evidence"],
                saved["door_pin_history"][0]["evidence"]
            );
        }
    }
}

/// # Panics
/// Panics only if a prior round's report prevents ordinary recovery.
/// ´test:unit:interrupted-recovery-retains-fallback-for-prior-round-report´
#[test]
fn interrupted_recovery_retains_fallback_for_prior_round_report() {
    let fixture = interrupted_fixture(false, "dispatch", true);
    let record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    assert_eq!(
        record["rounds"][0]["driver_dir"],
        record["rounds"][1]["driver_dir"]
    );
    assert_eq!(
        settled_boundary(&record, crate::launch::driver_report::fixture_read)
            .expect_err("prior report is not re-pin proof")
            .kind,
        "repin-door-state"
    );
    fixture.resume(true).expect("ordinary recovery preview");
    let recovered = finish_fixture_recovery(&fixture);
    assert_eq!(
        recovered["driver_end"],
        json!({"state":"absent-on-recovery"})
    );
}

/// # Panics
/// Panics only if matching successful evidence is contradicted by recovery.
/// ´test:unit:interrupted-recovery-preserves-successful-driver-report´
#[test]
fn interrupted_recovery_preserves_successful_driver_report() {
    let fixture = interrupted_fixture(false, "work", true);
    fixture.install_b();
    let preview =
        run(fixture.home.path(), &Fixture::request(None)).expect("successful report boundary");
    run(
        fixture.home.path(),
        &Fixture::request(preview["preview_sha256"].as_str()),
    )
    .expect("repin");
    let recovered = finish_fixture_recovery(&fixture);
    assert_eq!(recovered["driver_end"]["state"], "completed");
    assert_eq!(recovered["driver_end"]["successful"], true);
    assert_eq!(
        recovered["driver_end"]["evidence"]["run_report"]["verdict"],
        "ok"
    );
}

fn directory(path: &Path, mode: u32) {
    fs::create_dir_all(path).expect("directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("directory mode");
}

fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("file");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("file mode");
}

struct Fixture {
    _report_reader: super::super::driver_report::FixtureReader,
    home: tempfile::TempDir,
    path: PathBuf,
    stub: PathBuf,
    service: PathBuf,
    runtime: PathBuf,
}

impl Fixture {
    fn new(worker: u32) -> Self {
        Self::with_wall(worker, None)
    }

    #[allow(clippy::too_many_lines)]
    fn with_wall(worker: u32, wall: Option<u64>) -> Self {
        let report_reader = super::super::driver_report::FixtureReader::enter();
        let home = tempfile::tempdir_in("/tmp").expect("fixture with protected ancestors");
        let h = home.path();
        directory(h, 0o700);
        let config = h.join(".config/loops/alpha");
        let units = h.join(".config/systemd/user");
        let root = h.join(".var/loops/alpha/runs");
        let template = h
            .join(".var/loops/alpha/runner-templates/codex")
            .join("a".repeat(64));
        let sockets = h.join(".var/loops/alpha/sockets");
        for path in [
            h.join(".config"),
            h.join(".config/loops"),
            config.clone(),
            h.join(".config/systemd"),
            units.clone(),
            h.join(".var"),
            h.join(".var/loops"),
            h.join(".var/loops/alpha"),
            root.clone(),
            h.join(".var/loops/alpha/runner-templates"),
            h.join(".var/loops/alpha/runner-templates/codex"),
            template.clone(),
            sockets.clone(),
            h.join(".cache"),
            h.join(".cache/tmp"),
        ] {
            directory(&path, 0o700);
        }
        directory(&template.join("libexec"), 0o550);
        file(
            &config.join("door-compute-registration.json"),
            b"{\"node_root\":\"/srv/loops/loop-a\",\"alias\":\"fixture\"}",
            0o600,
        );
        file(&h.join(".config/loops/registry.toml"), format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", root.display()).as_bytes(), 0o600);
        file(
            &h.join(".config/loops/allocations.toml"),
            b"mail_uid = 61000\n[alpha]\nuids = { base = 3000, count = 2 }\nmail_gids = { base = 43000, count = 3 }\n",
            0o600,
        );
        crate::door_node::fixture(&config);
        let entry = h.join("entry");
        let driver = h.join("driver");
        let runtime = h.join("runtime");
        crate::fixture_exec::write_executable(&entry, b"#!/bin/sh\nexit 0\n").expect("entry");
        crate::fixture_exec::write_executable(&driver, b"#!/bin/sh\nexit 0\n").expect("driver");
        crate::fixture_exec::write_executable(&runtime, format!("#!/bin/sh\ncase \"$1\" in\nps) if [ -f '{}/unknown' ]; then exit 9; fi; if [ -f '{}/live' ]; then echo container; fi;;\nunshare) echo '{{\"thread_id\":\"thread-1\"}}';;\n*) exit 9;;\nesac\n",h.display(),h.display()).as_bytes()).expect("fake runtime control");
        file(&config.join("workers.toml"), format!("runs_root = \"{}\"\nentry_bin = \"{}\"\ndriver_argv = [\"{}\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nbackend_argv = {{ codex = [\"/usr/libexec/superloop/codex\"] }}\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\nvendor_hosts = {{ codex = [\"api.example.com\"] }}\n",root.display(),entry.display(),driver.display(),"a".repeat(64),template.display(),sockets.display()).as_bytes(),0o600);
        file(&config.join("install-generation.json"), &serde_json::to_vec(&json!({"phase":"complete","template_dir":template,"socket_dir":sockets,"unit_dir":units})).expect("vendor generation"),0o600);
        let stub = h.join("stub-source");
        let service = h.join("service-source");
        crate::fixture_exec::write_executable(&stub, b"#!/bin/sh\nexit 125\n").expect("stub A");
        crate::fixture_exec::write_executable(&service, b"#!/bin/sh\nexit 125\n").expect("service");
        let request = crate::install_door::DoorRequest {
            podman_bin: runtime.clone(),
            loop_name: "alpha".into(),
            dry_run: false,
        };
        crate::install_door::run_with(
            h,
            &request,
            &stub,
            &service,
            Some(nix::unistd::Gid::effective().as_raw()),
        )
        .expect("production installer A");
        if let Some(seconds) = wall {
            let path = config.join("workers.toml");
            let source = fs::read_to_string(&path).expect("settings");
            fs::write(&path, format!("{source}attempt_wall_seconds = {seconds}\n"))
                .expect("explicit wall");
        }
        let (mut plan, _) = load_plan(h, "alpha", "R", (0, 0)).expect("installed plan");
        let selection = super::super::LaunchModel::select(
            b"Work on the next step.\n",
            Some("gpt-6-sol"),
            Some("high"),
        )
        .expect("model")
        .record();
        plan.select_worker_uid(worker).expect("worker");
        let birth = loop_home::mail::birth::Identity::for_reservation(
            worker,
            format!("superloop-lane:{}", "R"),
        );
        plan.select_mailbox(
            &h.join(".var/loops/alpha/workers")
                .join(&birth.name)
                .join("mail"),
            &birth,
            61000,
        )
        .expect("mail mount");
        plan.select_container_program(&runtime).expect("runtime");
        plan.select_launch_model(&selection).expect("selection");
        directory(&plan.home, 0o750);
        directory(&plan.home.join(".local"), 0o750);
        directory(&plan.home.join(".local/inbox"), 0o750);
        let letter = b"Work on the next step.\n";
        file(&plan.home.join(".local/inbox/work.md"), letter, 0o600);
        let step_dir = plan.driver_dir.join("20261016T000000Z-dispatch");
        let path = reservation_path(&root, "R");
        let record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,"door_scope":"work","plan":plan.document,"model_selection":selection,"letter_source":plan.home.join(".local/inbox/work.md"),"active_round":"dispatch","thread_id":"thread-1","rounds":[{"step":"dispatch","phase":"settled","driver_dir":step_dir}],"letters":[{"name":"work.md","step":"work","in_round":false,"state":"placed","bytes":letter.len(),"sha256":hash(letter),"stop":false,"placed_at_unix_ns":1}],"launcher_pid":u32::MAX,"launcher_start":1,"driver_entry_pid":u32::MAX,"driver_entry_start":1,"helper_pid":u32::MAX,"helper_start":1,"observer_state":"not-started","helper_spawn_state":"not-started","imports":[],"harvest_agreement":null,"collection":null});
        let mut record = record;
        record["observer_end"] = json!({"state":"not-started"});
        publish_reservation(&path, &record).expect("settled reservation");
        drop(
            super::super::lock_run_preparation(&root, "R", Uid::effective().as_raw())
                .expect("lease"),
        );
        drop(super::super::lock_mailbox(&root, "R", Uid::effective().as_raw()).expect("mailbox"));
        Self {
            _report_reader: report_reader,
            home,
            path,
            stub,
            service,
            runtime,
        }
    }

    fn install_b(&self) {
        crate::fixture_exec::write_executable(&self.stub, b"#!/bin/sh\n# installed B\nexit 125\n")
            .expect("stub B");
        crate::install_door::run_with(
            self.home.path(),
            &crate::install_door::DoorRequest {
                podman_bin: self.runtime.clone(),
                loop_name: "alpha".into(),
                dry_run: false,
            },
            &self.stub,
            &self.service,
            Some(nix::unistd::Gid::effective().as_raw()),
        )
        .expect("production installer B");
    }

    fn install_report(&self, dry_run: bool) -> Value {
        crate::install_door::run_with(
            self.home.path(),
            &crate::install_door::DoorRequest {
                podman_bin: self.runtime.clone(),
                loop_name: "alpha".into(),
                dry_run,
            },
            &self.stub,
            &self.service,
            Some(nix::unistd::Gid::effective().as_raw()),
        )
        .expect("installer report")
    }

    fn request(digest: Option<&str>) -> Request {
        let mut words = vec!["alpha".into(), "R".into(), "--repin-door".into()];
        if let Some(digest) = digest {
            words.extend(["--expect-digest".into(), digest.into()]);
        } else {
            words.push("--dry-run".into());
        }
        Request::parse(&words).expect("listed form")
    }

    fn resume(&self, dry_run: bool) -> Result<Value, LaneError> {
        let mut words = vec![
            "alpha".into(),
            "R".into(),
            "--round".into(),
            "work".into(),
            "--podman-bin".into(),
            self.runtime.display().to_string(),
        ];
        if dry_run {
            words.push("--dry-run".into());
        }
        let request = super::super::LaunchRequest::parse(&words).expect("resume form");
        super::super::run_with_host_root_and_proxy(
            self.home.path(),
            &request,
            self.home.path(),
            Uid::effective().as_raw(),
            |_| Ok(("active".into(), "fixture".into())),
        )
    }
}

/// # Panics
/// Panics only if fixture setup or the asserted attempt-wall contract fails.
///
/// ´test:unit:door-repin-retains-the-configured-attempt-wall´
#[test]
fn door_repin_retains_the_configured_attempt_wall() {
    let fixture = Fixture::with_wall(3000, Some(12));
    let settings = fixture.home.path().join(".config/loops/alpha/workers.toml");
    let source = fs::read_to_string(&settings).expect("settings");
    fs::write(
        &settings,
        source.replace("attempt_wall_seconds = 12", "attempt_wall_seconds = 24"),
    )
    .expect("changed policy");
    fixture.install_b();
    let preview =
        run(fixture.home.path(), &Fixture::request(None)).expect("wall retained in preview");
    run(
        fixture.home.path(),
        &Fixture::request(preview["preview_sha256"].as_str()),
    )
    .expect("repin");
    let saved = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    assert_eq!(saved["plan"]["attempt_wall_seconds"], 12);
}

/// # Panics
/// Panics only if fixture setup or the asserted attempt-wall contract fails.
///
/// ´test:unit:resumed-round-retains-the-configured-attempt-wall´
#[test]
fn resumed_round_retains_the_configured_attempt_wall() {
    let fixture = Fixture::with_wall(3000, Some(12));
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    record["phase"] = json!("started");
    record["active_round"] = json!("work");
    record["helper_parent_pid"] = json!(u32::MAX);
    record["helper_parent_start"] = json!(1);
    record["rounds"]
        .as_array_mut()
        .expect("rounds")
        .push(json!({"step":"work","phase":"running","budget_seconds":2}));
    publish_reservation(&fixture.path, &record).expect("interrupted resumed round");
    let custody = fixture.path.parent().expect("runs").join(".launch-R");
    directory(&custody, 0o700);
    let settings = fixture.home.path().join(".config/loops/alpha/workers.toml");
    let source = fs::read_to_string(&settings).expect("settings");
    fs::write(
        &settings,
        source.replace("attempt_wall_seconds = 12", "attempt_wall_seconds = 24"),
    )
    .expect("changed policy");
    let preview = fixture.resume(true).expect("resume retains pinned wall");
    assert!(preview.get("round").is_none());
    assert!(preview["checks_performed"].is_array());
    assert_eq!(preview["bound_source_matrix"]["state"], "not-applicable");
    assert_eq!(preview["plan"]["attempt_wall_seconds"], 12);
    let saved = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    assert_eq!(saved["plan"]["attempt_wall_seconds"], 12);
}

/// ´test:unit:door-repin-install-reports-zero-one-and-two-previous-pins-before-mutation´
#[test]
fn door_repin_install_reports_zero_one_and_two_previous_pins_before_mutation() {
    for count in 0..=2 {
        let fixture = Fixture::new(3000);
        let root = fixture.path.parent().expect("runs root");
        let original = read_reservation(&fixture.path)
            .expect("read")
            .expect("reservation");
        if count == 0 {
            fs::remove_file(&fixture.path).expect("remove sole pin");
        }
        if count == 2 {
            let mut another = original.clone();
            another["run"] = json!("A");
            another["plan"]["run"] = json!("A");
            another["plan"]["door"]["mirror_ref"] = json!("refs/heads/lane/A");
            publish_reservation(&reservation_path(root, "A"), &another).expect("second pin");
        }
        for name in [
            "different",
            "no-door",
            "failed",
            "binding",
            "rotated",
            "rotating",
        ] {
            let mut unrelated = original.clone();
            unrelated["run"] = json!(name);
            unrelated["plan"]["run"] = json!(name);
            unrelated["plan"]["door"]["mirror_ref"] = json!(format!("refs/heads/lane/{name}"));
            match name {
                "different" => unrelated["plan"]["door"]["stub_sha256"] = json!("f".repeat(64)),
                "no-door" => unrelated["plan"]["door"] = Value::Null,
                "failed" => unrelated["phase"] = json!("failed"),
                "rotated" => unrelated["rotation"] = json!({"old_run":name}),
                "rotating" => unrelated["rotation_intent"] = json!({}),
                _ => unrelated["plan"]["door"]["peer_uid"] = json!(9999),
            }
            publish_reservation(&reservation_path(root, name), &unrelated)
                .expect("unrelated reservation");
        }
        crate::fixture_exec::write_executable(
            &fixture.stub,
            b"#!/bin/sh\n# installed B\nexit 125\n",
        )
        .expect("stub B");
        let expected = match count {
            0 => json!(["different"]),
            1 => json!(["R", "different"]),
            _ => json!(["A", "R", "different"]),
        };
        let preview = fixture.install_report(true);
        assert_eq!(preview["repin_required_runs"], expected);
        if count > 0 {
            assert_eq!(
                read_reservation(&fixture.path).expect("read after preview"),
                Some(original.clone())
            );
        }
        let changed = fixture.install_report(false);
        assert_eq!(changed["repin_required_runs"], expected);
        assert_eq!(changed["actions"], preview["actions"]);
        if count > 0 {
            assert_eq!(
                read_reservation(&fixture.path).expect("read after install"),
                Some(original)
            );
        }
        assert_eq!(
            fixture.install_report(true)["repin_required_runs"],
            json!([])
        );
        assert_eq!(
            fixture.install_report(false)["repin_required_runs"],
            json!([])
        );
    }
}

/// ´test:unit:door-repin-install-reports-no-runs-for-service-agent-or-unchanged-install´
#[test]
fn door_repin_install_reports_no_runs_for_service_agent_or_unchanged_install() {
    let fixture = Fixture::new(3000);
    for dry_run in [true, false] {
        let report = fixture.install_report(dry_run);
        assert_eq!(report["changed"], 0);
        assert_eq!(report["repin_required_runs"], json!([]));
        assert_eq!(report["repin_unmeasured_runs"], json!([]));
    }
    crate::fixture_exec::write_executable(&fixture.service, b"#!/bin/sh\n# service B\nexit 125\n")
        .expect("service B");
    for dry_run in [true, false] {
        let report = fixture.install_report(dry_run);
        assert!(report["changed"].as_u64().expect("changed count") > 0);
        assert_eq!(report["repin_required_runs"], json!([]));
        assert_eq!(report["repin_unmeasured_runs"], json!([]));
    }
    let path = fixture
        .home
        .path()
        .join(".config/loops/alpha/door-install-generation.json");
    let mut generation: Value =
        serde_json::from_slice(&fs::read(&path).expect("generation")).expect("JSON");
    generation["agent"]["model"] = json!("previous-model");
    fs::write(
        &path,
        serde_json::to_vec(&generation).expect("generation bytes"),
    )
    .expect("old agent");
    for dry_run in [true, false] {
        let report = fixture.install_report(dry_run);
        assert!(report["changed"].as_u64().expect("changed count") > 0);
        assert_eq!(report["repin_required_runs"], json!([]));
        assert_eq!(report["repin_unmeasured_runs"], json!([]));
    }
}

/// ´test:unit:door-repin-installer-transition-preserves-round-pins´
#[test]
fn door_repin_installer_transition_preserves_round_pins() {
    for worker in [3000, 3001] {
        let fixture = Fixture::new(worker);
        fixture.install_b();
        let before = fs::read(&fixture.path).expect("before");
        for preview in [true, false] {
            assert_eq!(
                fixture
                    .resume(preview)
                    .expect_err("ordinary resume refuses")
                    .kind,
                "plan-read"
            );
            assert_eq!(fs::read(&fixture.path).expect("record"), before);
        }
        let preview = run(fixture.home.path(), &Fixture::request(None)).expect("preview");
        assert_eq!(preview["boundary"], "settled");
        assert_eq!(preview["transition"]["boundary"], "settled");
        assert_eq!(fs::read(&fixture.path).expect("unchanged"), before);
        assert_ne!(
            preview["before"]["stub_sha256"],
            preview["after"]["stub_sha256"]
        );
        assert_eq!(
            run(
                fixture.home.path(),
                &Fixture::request(Some(&"0".repeat(64)))
            )
            .expect_err("wrong digest")
            .kind,
            "repin-door-digest"
        );
        assert_eq!(
            fs::read(&fixture.path).expect("wrong digest leaves record"),
            before
        );
        let digest = preview["preview_sha256"].as_str().expect("digest");
        let mut changed: Value = serde_json::from_slice(&before).expect("record");
        changed["note"] = json!("changed since preview");
        publish_reservation(&fixture.path, &changed).expect("stale input");
        assert_eq!(
            run(fixture.home.path(), &Fixture::request(Some(digest)))
                .expect_err("stale digest")
                .kind,
            "repin-door-digest"
        );
        file(&fixture.path, &before, 0o600);
        run(fixture.home.path(), &Fixture::request(Some(digest))).expect("explicit transition");
        let saved = read_reservation(&fixture.path)
            .expect("validated history")
            .expect("record");
        assert_eq!(saved["plan"]["door"], preview["after"]);
        assert_eq!(saved["door_pin_history"][0]["before"], preview["before"]);
        let mut legacy = saved.clone();
        let row = &mut legacy["door_pin_history"][0];
        row.as_object_mut().expect("transition").remove("boundary");
        row.as_object_mut()
            .expect("transition")
            .remove("preview_sha256");
        row["preview_sha256"] = json!(value_hash(row).expect("legacy digest"));
        validate(&legacy).expect("existing settled history remains valid");
        assert_eq!(saved["thread_id"], "thread-1");
        assert_eq!(saved["worker_uid"], worker);
        assert_eq!(
            round_pins(&saved).expect("round history")[0]["door"],
            preview["before"]
        );
        let current = super::super::pinned_plan_from_record(
            fixture.home.path(),
            "alpha",
            "R",
            &fixture.runtime,
            &saved,
        )
        .expect("helper plan accepts re-pin")
        .0;
        assert_eq!(current.document["door"], preview["after"]);
        let vector = current.document["runtime_argv"]
            .as_array()
            .expect("box command")
            .iter()
            .map(|word| word.as_str().expect("argument").to_owned())
            .collect::<Vec<_>>();
        let resumed = crate::container_helper::resume_box_vector(&vector, "thread-1")
            .expect("resume uses the admitted current plan");
        assert!(resumed.ends_with(&["resume".into(), "thread-1".into(), "-".into()]));
        let root = fixture.path.parent().expect("root");
        let bound =
            crate::home::pin_parent(root, Uid::effective().as_raw()).expect("bound reader root");
        let (reread, _) =
            super::super::checkout::read_record_bound(&bound, "R", Uid::effective().as_raw())
                .expect("bound reader validates history");
        assert_eq!(reread["door_pin_history"], saved["door_pin_history"]);
        assert_retained_history(&fixture, &saved);
    }
}

fn assert_retained_history(fixture: &Fixture, saved: &Value) {
    let census = super::super::census::run(fixture.home.path(), "alpha").expect("census");
    assert_eq!(
        census["reservations"][0]["door_pin_history"],
        saved["door_pin_history"]
    );
    let preview_request =
        super::super::retire::RetireRequest::parse(&["alpha", "R", "--dry-run"].map(String::from))
            .expect("retire preview form");
    let preview =
        super::super::retire::run(fixture.home.path(), &preview_request).expect("retire preview");
    let request = super::super::retire::RetireRequest::parse(
        &[
            "alpha",
            "R",
            "--expect-digest",
            preview["preview_sha256"].as_str().expect("retire digest"),
        ]
        .map(String::from),
    )
    .expect("retire apply form");
    let retired =
        super::super::retire::run(fixture.home.path(), &request).expect("retire keeps history");
    let path = retired["retirement"]["record"]
        .as_str()
        .expect("retired path");
    let retained = read_reservation(Path::new(path))
        .expect("retired reader")
        .expect("retired record");
    assert_eq!(
        serde_json::to_vec(&retained["door_pin_history"]).expect("retained bytes"),
        serde_json::to_vec(&saved["door_pin_history"]).expect("original history bytes")
    );
    let census = super::super::census::run(fixture.home.path(), "alpha").expect("retired census");
    assert_eq!(
        census["retired_records"][0]["door_pin_history"],
        saved["door_pin_history"]
    );
}

/// ´test:unit:door-repin-live-unknown-and-malformed-history-refuse´
#[test]
fn door_repin_live_unknown_and_malformed_history_refuse() {
    let fixture = Fixture::new(3001);
    fixture.install_b();
    let original = fs::read(&fixture.path).expect("original");
    for (marker, kind) in [
        ("live", "repin-door-live"),
        ("unknown", "repin-door-uncertain"),
    ] {
        file(&fixture.home.path().join(marker), b"", 0o600);
        for digest in [None, Some("a".repeat(64))] {
            assert_eq!(
                run(fixture.home.path(), &Fixture::request(digest.as_deref()))
                    .expect_err("presence refuses")
                    .kind,
                kind
            );
            assert_eq!(fs::read(&fixture.path).expect("unchanged"), original);
        }
        fs::remove_file(fixture.home.path().join(marker)).expect("remove marker");
    }
    let mut record: Value = serde_json::from_slice(&original).expect("record");
    record["launcher_pid"] = json!(std::process::id());
    record["launcher_start"] =
        json!(crate::container_helper::process_start(std::process::id()).expect("start tick"));
    publish_reservation(&fixture.path, &record).expect("live identity");
    assert_eq!(
        run(fixture.home.path(), &Fixture::request(None))
            .expect_err("live launcher")
            .kind,
        "repin-door-live"
    );
    file(&fixture.path, &original, 0o600);
    let preview = run(fixture.home.path(), &Fixture::request(None)).expect("preview");
    run(
        fixture.home.path(),
        &Fixture::request(preview["preview_sha256"].as_str()),
    )
    .expect("apply");
    let saved = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    let mut malformed = vec![Value::Null, json!([]), json!([{}])];
    for (field, value) in [
        ("schema", json!(2)),
        ("command", json!("implicit-repin")),
        ("boundary", json!("live")),
        ("owner_uid", json!("owner")),
        ("loop", json!("beta")),
        ("run", json!("S")),
        ("prior_record_sha256", json!("bad")),
        ("plan_context_sha256", json!("0".repeat(64))),
        ("after_round", json!("other")),
        ("round_count", json!(0)),
        ("preview_sha256", json!("0".repeat(64))),
    ] {
        let mut history = saved["door_pin_history"].clone();
        history[0][field] = value;
        if field != "preview_sha256" {
            let mut bound = history[0].clone();
            bound
                .as_object_mut()
                .expect("transition")
                .remove("preview_sha256");
            history[0]["preview_sha256"] = json!(value_hash(&bound).expect("bound digest"));
        }
        malformed.push(history);
    }
    for history in malformed {
        let mut invalid = saved.clone();
        invalid["door_pin_history"] = history;
        publish_reservation(&fixture.path, &invalid).expect("invalid history");
        assert_eq!(
            read_reservation(&fixture.path)
                .expect_err("strict reader")
                .kind,
            "repin-door-record"
        );
        let bound = crate::home::pin_parent(
            fixture.path.parent().expect("root"),
            Uid::effective().as_raw(),
        )
        .expect("root");
        assert_eq!(
            super::super::checkout::read_record_bound(&bound, "R", Uid::effective().as_raw())
                .expect_err("strict bound reader")
                .kind,
            "repin-door-record"
        );
    }
}

/// ´test:unit:door-repin-refuses-binding-and-non-door-drift´
#[test]
fn door_repin_refuses_binding_and_non_door_drift() {
    let fixture = Fixture::new(3001);
    fixture.install_b();
    let record = read_reservation(&fixture.path)
        .expect("reader")
        .expect("record");
    let mut recovered = record.clone();
    recovered["rounds"][0]["phase"] = json!("failed");
    publish_reservation(&fixture.path, &recovered).expect("settled recovery");
    let preview = run(fixture.home.path(), &Fixture::request(None))
        .expect("settled recovery may retain a failed final round");
    run(
        fixture.home.path(),
        &Fixture::request(preview["preview_sha256"].as_str()),
    )
    .expect("explicit transition after recovery");
    assert_eq!(
        read_reservation(&fixture.path)
            .expect("validated history")
            .expect("record")["rounds"][0]["phase"],
        "failed"
    );
    publish_reservation(&fixture.path, &record).expect("restore initial pin");
    for (field, value, kind) in [
        ("binding", json!("/another/socket"), "repin-door-binding"),
        ("floor", json!("enforce"), "plan-read"),
        ("state", json!("started"), "repin-door-state"),
    ] {
        let mut changed = record.clone();
        match field {
            "binding" => changed["plan"]["door"]["socket"] = value,
            "floor" => changed["plan"]["door_floor"] = value,
            _ => changed["phase"] = value,
        }
        publish_reservation(&fixture.path, &changed).expect("changed record");
        let bytes = fs::read(&fixture.path).expect("before");
        assert_eq!(
            run(fixture.home.path(), &Fixture::request(None))
                .expect_err("refusal")
                .kind,
            kind
        );
        assert_eq!(fs::read(&fixture.path).expect("after"), bytes);
    }
    for words in [
        vec!["alpha", "R", "--repin-door"],
        vec!["alpha", "R", "--repin-door", "--dry-run", "--round", "work"],
        vec!["alpha", "R", "--repin-door", "--expect-digest", "bad"],
    ] {
        assert!(Request::parse(&words.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
    }
}

/// # Panics
/// Panics only if fixture setup or the asserted admission contract fails.
///
/// ´test:unit:door-repin-without-door-refuses-before-worker-settings´
#[test]
fn door_repin_without_door_refuses_before_worker_settings() {
    for absence in ["registration", "reservation", "pin"] {
        let fixture = Fixture::new(3001);
        let config = fixture.home.path().join(".config/loops/alpha");
        match absence {
            "registration" => fs::remove_file(config.join("door-install-generation.json"))
                .expect("remove registration"),
            "reservation" => {
                fs::remove_file(&fixture.path).expect("host run has no boxed reservation");
            }
            _ => {
                let mut record = read_reservation(&fixture.path)
                    .expect("read")
                    .expect("record");
                record["plan"].as_object_mut().expect("plan").remove("door");
                publish_reservation(&fixture.path, &record).expect("unboxed plan");
            }
        }
        file(
            &config.join("workers.toml"),
            b"this is deliberately not TOML",
            0o600,
        );
        for digest in [
            None,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let error = run(fixture.home.path(), &Fixture::request(digest)).expect_err("no door");
            assert_eq!(error.kind, "repin-door");
            assert_eq!(error.detail, "this run has no door");
        }
    }
}

/// # Panics
/// Panics only if fixture setup or the registry refusal assertion fails.
///
/// ´test:unit:door-repin-missing-registry-root-keeps-registry-reason´
#[test]
fn door_repin_missing_registry_root_keeps_registry_reason() {
    for (rows, detail) in [
        ("", "unknown loop: alpha"),
        (
            "{ name = \"alpha\", uid = 41001, launch = \"src\" }",
            "runs_root is absent from the registry row",
        ),
    ] {
        let fixture = Fixture::new(3001);
        file(
            &fixture.home.path().join(".config/loops/registry.toml"),
            format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{rows}]\n").as_bytes(),
            0o600,
        );
        for digest in [
            None,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let error = run(fixture.home.path(), &Fixture::request(digest))
                .expect_err("registry root is required");
            assert_eq!(error.kind, "registry-row");
            assert_eq!(error.detail, detail);
        }
    }
}

/// Synthetic boundary fields; callers supply only local custody and process identity.
/// # Panics
/// Panics only if the synthetic boundary JSON is invalid.
pub fn captured_record(first: bool) -> Value {
    let mut record: Value = serde_json::from_str(if first {
        r#"{
    "phase": "started",
    "active_round": "dispatch",
    "driver_end": null,
    "observer_end": null,
    "reaping_recovery": null,
    "rotation": null,
    "rotation_intent": null,
    "last": {
        "budget_seconds": 10800,
        "credential_publication": {
            "published_unix_ns": 1700000002000000000,
            "source_inode": 101
        },
        "driver_dir": "/home/owner/.var/loops/loop-a/runs/fixture-run-a/1700000000-000000001-41001-dispatch",
        "ended_by": null,
        "in_round_letters": [],
        "letter": "dispatch.md",
        "phase": "running",
        "placed_at_unix_ns": 1700000001000000000,
        "step": "dispatch"
    }
}"#
    } else {
        r#"{
    "phase": "started",
    "active_round": "work2",
    "driver_end": null,
    "observer_end": {
        "socket": {
            "state": "not-applicable"
        },
        "state": "not-started"
    },
    "reaping_recovery": null,
    "rotation": null,
    "rotation_intent": null,
    "last": {
        "budget_seconds": 7200,
        "credential_publication": {
            "published_unix_ns": 1700000102000000000,
            "source_inode": 102
        },
        "driver_dir": "/home/owner/.var/loops/loop-b/runs/fixture-run-b/1700000100-000000002-41002-dispatch",
        "ended_by": null,
        "in_round_letters": [],
        "letter": "work2.md",
        "phase": "running",
        "placed_at_unix_ns": 1700000101000000000,
        "step": "work2"
    }
}"#
    }).expect("captured record");
    let last = record
        .as_object_mut()
        .expect("record")
        .remove("last")
        .expect("last");
    record["rounds"] = json!([last]);
    record["run"] = json!(if first {
        "fixture-run-a"
    } else {
        "fixture-run-b"
    });
    record
}

/// # Panics
/// Panics only if fixture custody or the measured boundary contract fails.
/// ´test:unit:door-repin-host-restart-measures-driver-and-report´
#[test]
#[allow(clippy::too_many_lines)]
fn door_repin_host_restart_measures_driver_and_report() {
    use crate::container_helper::ProcessPresence;
    for first in [false, true] {
        let directory = tempfile::tempdir().expect("report directory");
        let mut record = captured_record(first);
        record["rounds"][0]["driver_dir"] = json!(directory.path());
        record["driver_entry_pid"] = json!(u32::MAX);
        record["driver_entry_start"] = json!(1);
        let step = record["active_round"].as_str().expect("step");
        let report = captured_report(first)
            .split_whitespace()
            .map(|word| {
                if word.starts_with("dir=") {
                    format!("dir={}", directory.path().display())
                } else {
                    word.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let path = directory.path().join("run-report.txt");
        assert_eq!(
            boundary_with(
                &record,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("missing report")
            .kind,
            "repin-door-state"
        );
        fs::write(&path, &report).expect("report");
        let boundary = boundary_with(
            &record,
            |_, _| ProcessPresence::Absent,
            crate::launch::driver_report::fixture_read,
        )
        .expect("measured boundary");
        assert_eq!(boundary.2, "interrupted-settlement");
        let evidence = boundary.3.expect("evidence");
        let mut unidentified = record.clone();
        unidentified["driver_entry_pid"] = Value::Null;
        unidentified["driver_entry_start"] = Value::Null;
        assert_eq!(
            boundary_with(
                &unidentified,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("missing identity is not absence")
            .kind,
            "repin-door-uncertain"
        );
        assert_eq!(evidence["driver"], "absent");
        assert_eq!(evidence["run_report"]["lane"], step);
        assert_eq!(evidence["run_report"]["exit"], "1");
        assert_eq!(evidence["run_report"]["verdict"], "FAILED");
        assert_eq!(
            evidence["run_report"]["wall"],
            if first { "4416s" } else { "3500s" }
        );
        assert_eq!(
            evidence["run_report"]["budget"],
            if first { "10800s" } else { "7200s" }
        );
        for (presence, kind) in [
            (ProcessPresence::Present, "repin-door-live"),
            (ProcessPresence::Unknown, "repin-door-uncertain"),
        ] {
            assert_eq!(
                boundary_with(
                    &record,
                    |_, _| presence,
                    crate::launch::driver_report::fixture_read
                )
                .expect_err("not absent")
                .kind,
                kind
            );
        }
        fs::write(&path, report.replace(&format!("lane={step}"), "lane=other"))
            .expect("wrong round");
        assert_eq!(
            boundary_with(
                &record,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("wrong report")
            .kind,
            "repin-door-state"
        );
        fs::write(
            &path,
            report.replace(
                &format!("dir={}", directory.path().display()),
                "dir=/other/run",
            ),
        )
        .expect("wrong directory");
        assert_eq!(
            boundary_with(
                &record,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("same step from another directory")
            .kind,
            "repin-door-state"
        );
        fs::write(&path, format!("stale prefix\n{report}\n")).expect("last line report");
        assert!(
            boundary_with(
                &record,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .is_ok()
        );
        fs::write(&path, format!("{report}\nnot a report\n")).expect("invalid last line");
        assert_eq!(
            boundary_with(
                &record,
                |_, _| ProcessPresence::Absent,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("first line is not terminal evidence")
            .kind,
            "repin-door-state"
        );
    }
}

/// The first line of each captured driver's own end record.
fn captured_report(first: bool) -> &'static str {
    if first {
        "RUN-REPORT lane=dispatch exit=1 wall=4416s budget=10800s verdict=FAILED dir=... backend_program=/usr/libexec/superloop/codex settings=.../workers.toml settings_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    } else {
        "RUN-REPORT lane=work2 exit=1 wall=3500s budget=7200s verdict=FAILED dir=/home/owner/.var/loops/loop-b/runs/fixture-run-b/1700000100-000000002-41002-dispatch backend_program=/usr/libexec/superloop/codex settings=/home/owner/.config/loops/loop-b/workers.toml settings_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
}

/// # Panics
/// Panics only if unreadable or uncertain recovery evidence is silently accepted.
/// ´test:unit:interrupted-recovery-names-unreadable-report-and-driver-presence´
#[test]
fn interrupted_recovery_names_unreadable_report_and_driver_presence() {
    use crate::container_helper::ProcessPresence;
    let fixture = interrupted_fixture(false, "work", false);
    let record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    for (presence, kind) in [
        (ProcessPresence::Unknown, "settlement-uncertain"),
        (ProcessPresence::Present, "launch-busy"),
    ] {
        assert_eq!(
            super::super::interrupted_driver_end(
                &record,
                |_, _| presence,
                crate::launch::driver_report::fixture_read
            )
            .expect_err("presence refusal")
            .kind,
            kind
        );
    }
    let path = Path::new(
        record["rounds"][1]["driver_dir"]
            .as_str()
            .expect("directory"),
    )
    .join("run-report.txt");
    fs::write(&path, [0xff]).expect("unreadable UTF-8");
    assert_eq!(
        super::super::interrupted_driver_end(
            &record,
            |_, _| ProcessPresence::Absent,
            crate::launch::driver_report::fixture_read
        )
        .expect_err("unreadable report")
        .kind,
        "settlement-uncertain"
    );
    fs::remove_file(&path).expect("missing report");
    assert_eq!(
        super::super::interrupted_driver_end(
            &record,
            |_, _| ProcessPresence::Absent,
            crate::launch::driver_report::fixture_read
        )
        .expect("missing report fallback"),
        None
    );
}

/// # Panics
/// Panics only if a started observer is supplied an absence proof.
/// ´test:unit:door-repin-never-supplies-end-for-started-observer´
#[test]
fn door_repin_never_supplies_end_for_started_observer() {
    let fixture = interrupted_fixture(false, "work", false);
    fixture.install_b();
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    record["observer_state"] = json!("running");
    publish_reservation(&fixture.path, &record).expect("started observer");
    let before = fs::read(&fixture.path).expect("before");
    let error =
        run(fixture.home.path(), &Fixture::request(None)).expect_err("observer not proved absent");
    assert_eq!(error.kind, "repin-door-uncertain");
    assert!(error.detail.contains("observer"));
    assert_eq!(fs::read(&fixture.path).expect("after"), before);
}

/// # Panics
/// Panics only if malformed evidence survives strict history validation.
/// ´test:unit:door-repin-history-requires-interrupted-evidence-shape´
#[test]
fn door_repin_history_requires_interrupted_evidence_shape() {
    let fixture = Fixture::new(3000);
    let mut record = read_reservation(&fixture.path)
        .expect("read")
        .expect("record");
    let mut current = record["plan"].clone();
    current["door"]["stub_sha256"] = json!("b".repeat(64));
    let transition = proposal(
        &record,
        &current,
        b"record",
        Uid::effective().as_raw(),
        crate::launch::driver_report::fixture_read,
    )
    .expect("proposal");
    record["plan"] = current;
    record["door_pin_history"] = json!([transition]);
    validate(&record).expect("old shape");
    let evidence = json!({"driver":"absent","run_report":{
        "lane":"dispatch","dir":"/fixture/driver","exit":"1","verdict":"FAILED"}});
    for (boundary, value, accepted) in [
        ("interrupted-settlement", evidence.clone(), true),
        ("settled", evidence.clone(), false),
        ("interrupted-settlement", Value::Null, false),
        (
            "interrupted-settlement",
            json!({"driver":"absent","run_report":[]}),
            false,
        ),
        (
            "interrupted-settlement",
            json!({"driver":"present","run_report":evidence["run_report"]}),
            false,
        ),
        (
            "interrupted-settlement",
            json!({"driver":"absent","run_report":evidence["run_report"],"extra":true}),
            false,
        ),
        (
            "interrupted-settlement",
            json!({"driver":"absent","run_report":{"lane":"other","dir":"/fixture/driver","exit":"1","verdict":"FAILED"}}),
            false,
        ),
    ] {
        let row = &mut record["door_pin_history"][0];
        row["boundary"] = json!(boundary);
        row["evidence"] = value;
        row.as_object_mut().expect("row").remove("preview_sha256");
        row["preview_sha256"] = json!(value_hash(row).expect("fresh digest"));
        if accepted {
            validate(&record).expect("valid interrupted evidence");
        } else {
            assert_eq!(
                validate(&record).expect_err("invalid evidence").kind,
                "repin-door-record"
            );
        }
    }
}
