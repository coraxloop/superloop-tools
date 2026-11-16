//! Real policy publication and failure recovery under the rootless namespace.
use super::*;
use std::cell::RefCell;

#[derive(Clone, Default)]
struct Probe {
    attempts: u32,
    renamed: u32,
    fail_before: u32,
    fail_sync: u32,
    fail_learned: bool,
    prior_snapshot: Vec<bool>,
    snapshot: PathBuf,
}
thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PROBE.with(|slot| slot.replace(None));
    }
}
fn injected() -> LaneError {
    problem(
        "execute-command-snapshot-custody",
        "injected publication failure",
    )
}
pub(super) fn begin_publication() -> Result<(), LaneError> {
    PROBE.with(|slot| {
        let mut value = slot.borrow_mut();
        if let Some(probe) = value.as_mut() {
            probe
                .prior_snapshot
                .push(probe.snapshot.try_exists().expect("snapshot metadata"));
            probe.attempts += 1;
            if probe.fail_before & (1 << (probe.attempts - 1)) != 0 {
                return Err(injected());
            }
        }
        Ok(())
    })
}
pub(super) fn directory_sync(directory: &OwnedFd) -> Result<(), LaneError> {
    PROBE.with(|slot| {
        let mut value = slot.borrow_mut();
        if let Some(probe) = value.as_mut() {
            nix::sys::stat::fstatat(
                directory,
                "snapshot.json",
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .expect("rename precedes directory sync");
            probe.renamed += 1;
            if probe.fail_sync & (1 << (probe.attempts - 1)) != 0 {
                return Err(injected());
            }
        }
        Ok(())
    })
}
pub(super) fn learned_write() -> Result<(), LaneError> {
    PROBE.with(|slot| {
        if slot
            .borrow()
            .as_ref()
            .is_some_and(|probe| probe.fail_learned)
        {
            return Err(injected());
        }
        Ok(())
    })
}

pub(super) fn in_namespace() -> bool {
    let name = std::thread::current().name().expect("test name").to_owned();
    if std::env::var("SUPERLOOP_PUBLICATION_PROOF").as_deref() == Ok(name.as_str()) {
        assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);
        return true;
    }
    let mut environment: BTreeMap<String, String> = std::env::vars().collect();
    for key in [
        "_CONTAINERS_USERNS_CONFIGURED",
        "_CONTAINERS_ROOTLESS_UID",
        "SUPERLOOP_TEST_DIRECT_HOME",
    ] {
        environment.remove(key);
    }
    environment.insert("SUPERLOOP_PUBLICATION_PROOF".into(), name.clone());
    let image = std::env::current_exe().expect("package test image");
    let argv = vec![
        "unshare".into(),
        image.display().to_string(),
        "--exact".into(),
        name.clone(),
        "--nocapture".into(),
    ];
    let spec = crate::build::child(
        Path::new("/usr/bin/podman"),
        argv,
        &environment,
        &std::env::current_dir().expect("working directory"),
        120,
        "publication fixture",
    );
    let output = crate::build::run_child(&spec, None).expect("bounded namespace child");
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "{output:?}"
    );
    if name.ends_with("publication_inventory_matches_old_modes_and_counts") {
        let lines = String::from_utf8_lossy(&output.stderr);
        let last = lines
            .lines()
            .filter_map(|line| line.strip_prefix("door-request-lock "))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .rfind(|line| line["path"] == "file" && line["outcome"] == "released")
            .expect("filing release line");
        assert_eq!(last["phases"]["helper_read"]["calls"], 1, "{last}");
        assert_eq!(last["phases"]["inventory_other"]["calls"], 3, "{last}");
        assert_eq!(last["phases"]["policy"]["calls"], 1, "{last}");
    }
    if name.ends_with("collection_view_provisioned_paths_read_once") {
        let lines = String::from_utf8_lossy(&output.stderr);
        for path in [
            "file",
            "record_agent",
            "record_effect",
            "publish_waiting",
            "publish_snapshot",
        ] {
            let last = lines
                .lines()
                .filter_map(|line| line.strip_prefix("door-request-lock "))
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .rfind(|line| line["path"] == path && line["outcome"] == "released")
                .unwrap_or_else(|| panic!("missing {path} release: {lines}"));
            assert_eq!(last["phases"]["helper_read"]["calls"], 1, "{last}");
        }
    }
    false
}

fn exercise(fail_before: u32, fail_sync: u32, fail_learned: bool) -> (Probe, Option<Value>, Value) {
    let fixture = super::tests::Fixture::new();
    let store = provision(&fixture);
    store
        .file(crate::requests::tests::waiting(
            "R",
            "aa",
            3000,
            Mode::Audit,
        ))
        .expect("seed");
    fixture
        .command(
            &["triage", "alpha", "R"],
            br#"[{"id":"R:aa","action":"mark","reason":"fixture"}]"#,
        )
        .expect("bind real helper");
    let snapshot = store.loop_root.join("policy/snapshot.json");
    assert!(snapshot.try_exists().expect("positive publication"));
    PROBE.with(|slot| {
        slot.replace(Some(Probe {
            fail_before,
            fail_sync,
            fail_learned,
            snapshot: snapshot.clone(),
            ..Probe::default()
        }))
    });
    let _reset = Reset;
    let result = crate::door::agent::RunnerOutcome::referral("failure", "fixture", Instant::now());
    store
        .record_agent("R:aa", &result, None, None)
        .expect("record remains durable");
    let probe = PROBE.with(|slot| slot.borrow().clone().expect("probe"));
    let retained = store.read_run("R").expect("durable record").2;
    let recorded = retained
        .iter()
        .find(|record| record.id() == "R:aa")
        .expect("record retained");
    assert_eq!(
        recorded.value()["would_do"]["decision"],
        "refer",
        "publication failure never loses the agent record"
    );
    let published = if snapshot.try_exists().expect("final snapshot metadata") {
        let bytes = std::fs::read(snapshot).expect("published bytes");
        execute_command::snapshot::PolicySnapshot::decode(&bytes).expect("valid policy");
        Some(serde_json::from_slice::<Value>(&bytes).expect("policy JSON"))
    } else {
        None
    };
    let learned = store.read_learned().expect("retained learned state");
    if let Some(policy) = &published {
        assert_eq!(
            policy["learned"]["value"], learned,
            "publication carries current learned state"
        );
    }
    (probe, published, learned)
}

/// ´test:unit:publication-once-success-skips-final-attempt´
#[test]
fn publication_once_success_skips_final_attempt() {
    if !in_namespace() {
        return;
    }
    let (probe, policy, _) = exercise(0, 0, false);
    assert_eq!(probe.attempts, 1);
    assert_eq!(probe.renamed, 1);
    assert!(policy.is_some());
}

/// ´test:unit:publication-once-failure-retries-successfully´
#[test]
fn publication_once_failure_retries_successfully() {
    if !in_namespace() {
        return;
    }
    let (probe, policy, _) = exercise(1, 0, false);
    assert_eq!(probe.attempts, 2);
    assert_eq!(probe.renamed, 1);
    assert!(policy.is_some());
}

/// ´test:unit:publication-once-two-failures-leave-no-snapshot´
#[test]
fn publication_once_two_failures_leave_no_snapshot() {
    if !in_namespace() {
        return;
    }
    let (probe, policy, _) = exercise(0, 3, false);
    assert_eq!(probe.attempts, 2);
    assert_eq!(probe.renamed, 2);
    assert!(policy.is_none());
}

/// ´test:unit:publication-once-directory-sync-failure-is-not-success´
#[test]
fn publication_once_directory_sync_failure_is_not_success() {
    if !in_namespace() {
        return;
    }
    let (probe, policy, _) = exercise(0, 1, false);
    assert_eq!(probe.attempts, 2);
    assert_eq!(probe.renamed, 2);
    assert_eq!(
        probe.prior_snapshot,
        [false, false],
        "uncertain rename is withdrawn before retry"
    );
    assert!(policy.is_some());
}

/// ´test:unit:publication-once-learned-write-failure-keeps-retry´
#[test]
fn publication_once_learned_write_failure_keeps_retry() {
    if !in_namespace() {
        return;
    }
    let (probe, policy, learned) = exercise(0, 0, true);
    assert_eq!(
        probe.attempts, 1,
        "final attempt after learned write failed before publication"
    );
    assert_eq!(
        learned,
        json!({"unavailable":true}),
        "commit tombstone survives"
    );
    assert!(
        policy.is_some(),
        "final publication can describe the unavailable index"
    );
}

pub(super) fn provision(fixture: &super::tests::Fixture) -> Store {
    use nix::unistd::{Gid, Uid, chown};
    let store = fixture.snapshot_store();
    for name in ["shared", "private", "direct"] {
        let path = store.loop_root.join(name);
        std::fs::create_dir(&path).expect("loop tier");
        chown(
            &path,
            Some(Uid::from_raw(41001)),
            Some(Gid::from_raw(41001)),
        )
        .expect("loop owner");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("tier mode");
    }
    let policy = store.loop_root.join("policy");
    chown(&policy, None, Some(Gid::from_raw(41001))).expect("policy group");
    std::fs::set_permissions(policy, std::fs::Permissions::from_mode(0o2750)).expect("policy mode");
    let generation = fixture
        .home
        .join(".config/loops/alpha/door-install-generation.json");
    std::fs::write(&generation, b"{}").expect("installed door");
    std::fs::set_permissions(generation, std::fs::Permissions::from_mode(0o600))
        .expect("generation mode");
    store
}

impl Store {
    fn linear_effective_locked(
        &self,
        ledger: &ModeLedger,
        class: &str,
    ) -> Result<Value, LaneError> {
        let mut effective = ledger.effective(class, self.floor).ok_or_else(|| {
            problem(
                "door-mode-setting-refusal",
                "class or loop first setting is absent",
            )
        })?;
        if effective["mode"] != "audit" {
            let pending = self
                .all_runs(None)?
                .iter()
                .flat_map(|(_, _, rows)| rows)
                .filter(|request| request.value()["class"] == class)
                .try_fold(false, |pending, request| -> Result<bool, LaneError> {
                    Ok(pending || correction_pending(request, ledger)?)
                })?;
            if pending {
                let mode =
                    execute_command::policy::DoorMode::from_record(effective["mode"].as_str())
                        .map_err(crate::requests::command::shape)?;
                effective["mode"] = json!(
                    execute_command::policy::effective_mode(mode, mode, self.floor.domain(), true)
                        .as_str()
                );
                effective["correction_pending"] = json!(true);
            }
        }
        Ok(effective)
    }
}

/// ´test:unit:publication-inventory-matches-old-modes-and-counts´
#[test]
fn publication_inventory_matches_old_modes_and_counts() {
    if !in_namespace() {
        return;
    }
    let fixture = super::tests::Fixture::new();
    fixture.set_floor("allow");
    let store = provision(&fixture);
    store
        .set_mode(&ModeTarget::Loop, Mode::Allow, "owner", "fixture", "1", &[])
        .unwrap();
    for (name, mode) in [
        ("audit", Mode::Audit),
        ("pending", Mode::Enforce),
        ("git", Mode::Allow),
        ("clear", Mode::Enforce),
    ] {
        store
            .set_mode(
                &ModeTarget::class(name).unwrap(),
                mode,
                "owner",
                "fixture",
                "2",
                &[],
            )
            .unwrap();
    }
    let mut value = crate::requests::tests::waiting("R", "aa", 3000, Mode::Allow).into_value();
    value["class"] = json!("pending");
    value["would_do"]["decision"] = json!("refuse");
    crate::requests::judgement::initialize(&mut value);
    let ledger = store.read_modes().unwrap();
    let setting = store.base_effective(&ledger, "pending").unwrap();
    value["mode"] = setting["mode"].clone();
    value["class_setting"] = setting["class"].clone();
    value["loop_setting"] = setting["loop"].clone();
    let mut record = RequestRecord::decode(value).unwrap();
    record.triage("allow", "correction", "owner", "3").unwrap();
    assert!(correction_pending(&record, &ledger).unwrap());
    replace_leaf(
        &store.custody("R").unwrap(),
        RUN_FILE,
        &encode_run("R", 1, &[record]).unwrap(),
        store.owner,
        MAX_RUN_BYTES,
    )
    .unwrap();
    // Verbatim old per-class loop, against the same records and ledger.
    let modes = ledger.value();
    let mut expected = serde_json::Map::new();
    for class in modes["classes"].as_array().into_iter().flatten() {
        let name = class["class"].as_str().unwrap();
        if ledger.current(&ModeTarget::Loop).is_some() {
            expected.insert(
                name.to_owned(),
                store.linear_effective_locked(&ledger, name).unwrap(),
            );
        }
    }
    store.publish_snapshot().unwrap();
    let policy: Value = serde_json::from_slice(
        &std::fs::read(store.loop_root.join("policy/snapshot.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&policy["modes"]["value"]["effective"]).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(expected["audit"]["mode"], "audit");
    assert_eq!(expected["pending"]["correction_pending"], true);
    // Only the correction's own class is tightened.
    assert_eq!(expected["clear"]["mode"], "enforce");
    assert_eq!(expected["git"]["mode"], "allow");
    let setting = store.effective_mode("git").unwrap();
    let mut value = crate::requests::tests::waiting("R", "bb", 3000, Mode::Allow).into_value();
    value["mode"] = setting["mode"].clone();
    value["class_setting"] = setting["class"].clone();
    value["loop_setting"] = setting["loop"].clone();
    let request = RequestRecord::decode(value).unwrap();
    let mut seed = request.value().clone();
    seed["id"] = json!("R:cc");
    store.file(RequestRecord::decode(seed).unwrap()).unwrap();
    fixture
        .command(
            &["triage", "alpha", "R"],
            br#"[{"id":"R:cc","action":"mark","reason":"fixture"}]"#,
        )
        .unwrap();
    store.file(request).unwrap();
}

/// ´test:unit:publication-audit-modes-do-not-inventory´
#[test]
fn publication_audit_modes_do_not_inventory() {
    if !in_namespace() {
        return;
    }
    let fixture = super::tests::Fixture::new();
    let store = provision(&fixture);
    store
        .set_mode(&ModeTarget::Loop, Mode::Audit, "owner", "fixture", "1", &[])
        .unwrap();
    store
        .set_mode(
            &ModeTarget::class("git").unwrap(),
            Mode::Audit,
            "owner",
            "fixture",
            "2",
            &[],
        )
        .unwrap();
    replace_leaf(
        &store.custody("R").unwrap(),
        RUN_FILE,
        b"not a run record",
        store.owner,
        MAX_RUN_BYTES,
    )
    .unwrap();
    assert_eq!(
        store.publish_snapshot().unwrap()["published"],
        true,
        "audit publication never reads the malformed run"
    );
}
