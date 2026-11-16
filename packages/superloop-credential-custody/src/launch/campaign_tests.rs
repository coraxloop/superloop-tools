use super::*;
use crate::launch::measure::ObjectIdentity;
use crate::launch::{campaign, inventory::tests as fixture, manager, tests::Fixture};
use std::{
    fs,
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, PermissionsExt as _},
    },
    time::{Duration, Instant},
};

fn setup() -> Fixture {
    let mut f = release::tests::setup("normal");
    let first = f.value["cases"][0].clone();
    let mut second = first.clone();
    second["id"] = "second".into();
    second["generator_unit"] = "synthetic-second.service".into();
    let path = f.dir.path().join("second.json");
    let mut public: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("public.json")).unwrap()).unwrap();
    public["case"] = "second".into();
    let bytes = serde_json::to_vec(&public).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    second["public_case"] = path.to_str().unwrap().into();
    second["expected_case_sha256"] = crate::identity::hash(&bytes).into();
    f.value["cases"] = serde_json::json!([first, second]);
    f.value["limits"]["campaign_ms"] = 1_200_000.into();
    f
}
fn run_case(
    f: &Fixture,
    admission: &Admission,
    index: usize,
    store: &mut Store,
    fault: &str,
) -> Result<()> {
    if fault == "reserved" {
        return Err("synthetic-reserved-failure");
    }
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), admission, index, store)?;
    if fault == "sealers" {
        return Err(keeper.fail("synthetic-sealers-failure"));
    }
    keeper.submit()?;
    if fault == "submitted" {
        return Err(keeper.fail("synthetic-submitted-failure"));
    }
    let writers = keeper
        .pipes
        .paths()
        .each_ref()
        .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
    fs::set_permissions(
        &admission.policy().cases[index].record,
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let (mut child, _pin) = fixture::start_case(f, &writers, index);
    let id = format!("{:032x}", if fault == "repeated" { 1 } else { index + 1 });
    let reply = String::from_utf8(manager::tests::reply_case(admission, index))
        .unwrap()
        .replace("MainPID=123", &format!("MainPID={}", child.child.id()))
        .replace("1234567890abcdef1234567890abcdef", &id);
    fs::write(f.dir.path().join("manager-reply"), &reply).unwrap();
    keeper.capture_with(
        |_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())),
        Control::test_bind,
    )?;
    drop(writers);
    if fault == "capture" {
        return Err(keeper.fail("synthetic-capture-failure"));
    }
    let digest = keeper.inventory()?;
    if fault == "inventory" {
        return Err(keeper.fail("synthetic-inventory-failure"));
    }
    let exit = keeper.process.as_ref().unwrap().duplicate()?;
    keeper.release(&digest)?;
    if fault == "release" {
        return Err(keeper.fail("synthetic-release-failure"));
    }
    let mut event = nix::libc::pollfd {
        fd: exit.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    crate::launch::channel::poll(std::slice::from_mut(&mut event), 600_000).unwrap();
    assert_ne!(event.revents & nix::libc::POLLIN, 0);
    assert!(child.child.wait().unwrap().success());
    let terminal = reply
        .replace(
            &format!("\nMainPID={}\n", child.child.id()),
            "\nMainPID=0\n",
        )
        .replace("ActiveState=activating", "ActiveState=active")
        .replace("SubState=start", "SubState=exited")
        .replace("ExecMainCode=0", "ExecMainCode=1")
        .replace(
            "ExecMainExitTimestampMonotonic=0",
            "ExecMainExitTimestampMonotonic=200",
        );
    fs::write(f.dir.path().join("manager-reply"), terminal).unwrap();
    assert!(keeper.capture_generator()?);
    if fault == "generator" {
        return Err(keeper.fail("synthetic-generator-failure"));
    }
    keeper.finish_completion()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1200)
}

/// ´test:unit:campaign-runs-completed-pairs-in-order-and-publishes-one-matrix´
#[test]
fn campaign_runs_completed_pairs_in_order_and_publishes_one_matrix() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut visited = Vec::new();
    let matrix = campaign::run(&admission, deadline(), |index, store, _deadline| {
        if index == 1 {
            assert!(
                f.dir
                    .path()
                    .join("evidence/sample/completion.json")
                    .is_file()
            );
        }
        visited.push(index);
        run_case(&f, &admission, index, store, "normal")
    })
    .unwrap();
    assert_eq!(visited, [0, 1]);
    let path = f.dir.path().join("evidence/campaign.json");
    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&matrix).unwrap());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["rows"].as_array().unwrap().len(), 2);
    assert_ne!(
        value["rows"][0]["completed"]["case"],
        value["rows"][1]["completed"]["case"]
    );
    assert_eq!(value["rows"][1]["completed"]["case"], "second");
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o400);
    assert_eq!(
        campaign::run(&admission, deadline(), |_, _, _| panic!("rerun")).err(),
        Some("receipt-no-replace")
    );
}

/// ´test:unit:campaign-refuses-repeated-invocations-and-final-publication-collisions´
#[test]
fn campaign_refuses_repeated_invocations_and_final_publication_collisions() {
    let _guard = crate::launch::test_support::case_guard();
    for fault in ["repeated", "collision", "root", "artifact"] {
        let f = setup();
        let admission = f.admit();
        let result = campaign::run(&admission, deadline(), |index, store, _deadline| {
            run_case(&f, &admission, index, store, fault)?;
            if index == 1 {
                if fault == "artifact" {
                    let path = f.dir.path().join("parser");
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(path, b"changed").unwrap();
                }
                if fault == "collision" {
                    fs::write(f.dir.path().join("evidence/campaign.json"), b"occupied").unwrap();
                }
                if fault == "root" {
                    fs::rename(
                        f.dir.path().join("evidence"),
                        f.dir.path().join("old-evidence"),
                    )
                    .unwrap();
                    fs::create_dir(f.dir.path().join("evidence")).unwrap();
                    fs::set_permissions(
                        f.dir.path().join("evidence"),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
            }
            Ok(())
        });
        assert_eq!(
            result.err(),
            Some(match fault {
                "repeated" => "campaign-invocation-repeated",
                "collision" => "receipt-no-replace",
                "artifact" => "launch-artifact-changed",
                _ => "campaign-root-binding",
            })
        );
        if fault == "collision" {
            assert_eq!(
                fs::read(f.dir.path().join("evidence/campaign.json")).unwrap(),
                b"occupied"
            );
        } else {
            assert!(!f.dir.path().join("evidence/campaign.json").exists());
        }
    }
}

fn stops_after_failure(fault: &str) {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut visited = Vec::new();
    let result = campaign::run(&admission, deadline(), |index, store, _deadline| {
        visited.push(index);
        run_case(&f, &admission, index, store, fault)
    });
    assert_eq!(
        result.err(),
        Some(match fault {
            "reserved" => "synthetic-reserved-failure",
            "sealers" => "synthetic-sealers-failure",
            "submitted" => "synthetic-submitted-failure",
            "capture" => "synthetic-capture-failure",
            "inventory" => "synthetic-inventory-failure",
            "release" => "synthetic-release-failure",
            _ => "synthetic-generator-failure",
        })
    );
    assert_eq!(visited, [0]);
    assert!(!f.dir.path().join("evidence/second").exists());
    assert!(!f.dir.path().join("evidence/campaign.json").exists());
    let failure: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/campaign-failure.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        failure["completed_prefix"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

/// ´test:unit:campaign-stops-after-reserved-failure´
#[test]
fn campaign_stops_after_reserved_failure() {
    stops_after_failure("reserved");
}

/// ´test:unit:campaign-stops-after-sealers-failure´
#[test]
fn campaign_stops_after_sealers_failure() {
    stops_after_failure("sealers");
}

/// ´test:unit:campaign-stops-after-submitted-failure´
#[test]
fn campaign_stops_after_submitted_failure() {
    stops_after_failure("submitted");
}

/// ´test:unit:campaign-stops-after-capture-failure´
#[test]
fn campaign_stops_after_capture_failure() {
    stops_after_failure("capture");
}

/// ´test:unit:campaign-stops-after-inventory-failure´
#[test]
fn campaign_stops_after_inventory_failure() {
    stops_after_failure("inventory");
}

/// ´test:unit:campaign-stops-after-release-failure´
#[test]
fn campaign_stops_after_release_failure() {
    stops_after_failure("release");
}

/// ´test:unit:campaign-stops-after-generator-failure´
#[test]
fn campaign_stops_after_generator_failure() {
    stops_after_failure("generator");
}

/// ´test:unit:campaign-refuses-incomplete-callback-expiry-and-replaced-evidence´
#[test]
fn campaign_refuses_incomplete_callback_expiry_and_replaced_evidence() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    assert_eq!(
        campaign::run(&admission, Instant::now(), |_, _, _| panic!("expired")).err(),
        Some("campaign-deadline")
    );
    assert!(!f.dir.path().join("evidence/campaign-start.json").exists());
    assert_eq!(
        campaign::run(&admission, deadline(), |_, _, _| Ok(())).err(),
        Some("campaign-case-incomplete")
    );
    let failed: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/sample/state-01.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed["phase"], "uncertain");
    assert_eq!(failed["original_cause"], "campaign-case-incomplete");
    for fault in ["receipt", "mode", "output"] {
        let f = setup();
        let admission = f.admit();
        let result = campaign::run(&admission, deadline(), |index, store, _deadline| {
            run_case(&f, &admission, index, store, "normal")?;
            if index != 0 {
                return Ok(());
            }
            let path = f.dir.path().join("evidence/sample/completion.json");
            if fault == "receipt" {
                fs::remove_file(&path).unwrap();
                fs::write(&path, b"{}").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
            } else if fault == "mode" {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                fs::remove_file(f.dir.path().join("sealed/sample/left.sealed")).unwrap();
            }
            Ok(())
        });
        assert_eq!(
            result.err(),
            Some(if fault == "output" {
                "launch-output-binding"
            } else {
                "campaign-completion-binding"
            })
        );
        assert!(!f.dir.path().join("evidence/campaign.json").exists());
    }
}

/// ´test:unit:campaign-failure-publication-cannot-overwrite-or-accept´
#[test]
fn campaign_failure_publication_cannot_overwrite_or_accept() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let path = f.dir.path().join("evidence/campaign-failure.json");
    fs::write(&path, b"occupied").unwrap();
    let mut visited = Vec::new();
    assert_eq!(
        campaign::run(&admission, deadline(), |index, _, _| {
            visited.push(index);
            Err("synthetic-failure")
        })
        .err(),
        Some("receipt-no-replace")
    );
    assert_eq!(visited, [0]);
    assert_eq!(fs::read(path).unwrap(), b"occupied");
    assert!(!f.dir.path().join("evidence/campaign.json").exists());
}

/// ´test:unit:campaign-full-output-then-sealer-failure-stops-the-next-case´
#[test]
fn campaign_full_output_then_sealer_failure_stops_the_next_case() {
    let _guard = crate::launch::test_support::case_guard();
    let mut f = setup();
    let path = f.dir.path().join("public.json");
    let mut public: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    public["streams"][0]["name"] = "fail".into();
    let bytes = serde_json::to_vec(&public).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
    f.value["cases"][0]["streams"][0]["name"] = "fail".into();
    f.value["cases"][0]["expected_case_sha256"] = crate::identity::hash(&bytes).into();
    let admission = f.admit();
    let mut visited = Vec::new();
    assert_eq!(
        campaign::run(&admission, deadline(), |index, store, _deadline| {
            visited.push(index);
            run_case(&f, &admission, index, store, "normal")
        })
        .err(),
        Some("sealer-exit")
    );
    assert_eq!(visited, [0]);
    assert!(!f.dir.path().join("evidence/second").exists());
    assert!(!f.dir.path().join("evidence/campaign.json").exists());
}

/// ´test:unit:campaign-reservation-collision-never-starts-a-case´
#[test]
fn campaign_reservation_collision_never_starts_a_case() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    fs::create_dir(f.dir.path().join("sealed/sample")).unwrap();
    assert_eq!(
        campaign::run(&admission, deadline(), |_, _, _| panic!(
            "occupied case started"
        ))
        .err(),
        Some("launch-exclusive-directory")
    );
    assert!(!f.dir.path().join("evidence/campaign.json").exists());
    assert!(
        f.dir
            .path()
            .join("evidence/campaign-failure.json")
            .is_file()
    );
}

/// ´test:unit:campaign-uses-resident-driver-for-each-pair´
#[test]
fn campaign_uses_resident_driver_for_each_pair() {
    let _guard = crate::launch::test_support::case_guard();
    let mut f = setup();
    super::driver::tests::install_launcher(&mut f);
    let admission = f.admit();
    let mut visited = Vec::new();
    let matrix = campaign::run(&admission, deadline(), |index, store, _deadline| {
        if index == 1 {
            assert!(!f.dir.path().join("runtime/sample/control.sock").exists());
        }
        visited.push(index);
        super::driver::tests::resident_case(&f, &admission, index, store)
    })
    .unwrap();
    assert_eq!(visited, [0, 1]);
    assert_eq!(
        serde_json::to_value(matrix).unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(f.dir.path().join("evidence/campaign.json").is_file());
    assert!(!f.dir.path().join("runtime/second/control.sock").exists());
}
/// ´test:unit:completed-campaign-returns-descriptors-to-baseline´
#[test]
fn completed_campaign_returns_descriptors_to_baseline() {
    const CHILD: &str = "CUSTODY_CASE_BASELINE_CONTROL";
    if std::env::var_os(CHILD).is_some() {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let baseline = count();
        campaign_runs_completed_pairs_in_order_and_publishes_one_matrix();
        assert_eq!(
            count(),
            baseline,
            "completed campaign retained a descriptor"
        );
        return;
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "launch::keeper::campaign_tests::completed_campaign_returns_descriptors_to_baseline",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1");
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
}

fn replace_protected(path: &std::path::Path, bytes: &[u8]) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

/// ´test:unit:campaign-handoff-producer-rechecks-objects-before-hashing´
#[test]
fn campaign_handoff_producer_rechecks_objects_before_hashing() {
    let _guard = crate::launch::test_support::case_guard();
    for replace in [false, true] {
        let f = setup();
        let admission = f.admit();
        let result = campaign::run(&admission, deadline(), |index, store, _| {
            run_case(&f, &admission, index, store, "normal")?;
            let path = f
                .dir
                .path()
                .join("sealed/sample")
                .join(&admission.policy().cases[0].streams[0].output);
            let bytes = fs::read(&path).unwrap();
            store
                .completed_case_with(|| {
                    fs::rename(&path, path.with_extension("retained")).unwrap();
                    if replace {
                        fs::write(&path, bytes).unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                    }
                })
                .map(|_| ())
        });
        assert_eq!(
            result.err(),
            Some(if replace {
                "campaign-output-binding"
            } else {
                "campaign-output-open"
            })
        );
        assert!(!f.dir.path().join("evidence/campaign.json").exists());
        assert!(f.dir.path().join("evidence/campaign-failure.json").exists());
    }
}

/// ´test:unit:campaign-handoff-measures-completed-outputs-and-rejects-stale-evidence´
#[test]
fn campaign_handoff_measures_completed_outputs_and_rejects_stale_evidence() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let matrix = campaign::run(&admission, deadline(), |index, store, _| {
        run_case(&f, &admission, index, store, "normal")
    })
    .unwrap();
    let path = f.dir.path().join("evidence/campaign.json");
    let bytes = fs::read(&path).unwrap();
    let digest = crate::identity::hash(&bytes);
    handoff_positive(&f, &admission, &matrix, &path, &bytes, &digest);
    handoff_records(&admission, &path, &bytes);
    handoff_files(&f, &admission, &path, &bytes, &digest);
    handoff_roots(&f, &admission, &path, &bytes, &digest);
}

fn handoff_positive(
    f: &Fixture,
    admission: &Admission,
    matrix: &campaign::Matrix,
    path: &std::path::Path,
    bytes: &[u8],
    digest: &str,
) {
    let mut oversized = bytes.to_vec();
    oversized.resize(256 * 1024 + 1, b' ');
    replace_protected(path, &oversized);
    assert_eq!(
        campaign::observation(admission, &crate::identity::hash(&oversized)).err(),
        Some("file-custody")
    );
    replace_protected(path, bytes);
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        campaign::observation(admission, digest).err(),
        Some("file-custody")
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    let alias = path.with_extension("alias");
    fs::hard_link(path, &alias).unwrap();
    assert_eq!(
        campaign::observation(admission, digest).err(),
        Some("file-custody")
    );
    fs::remove_file(alias).unwrap();
    let observed = campaign::observation(admission, digest).unwrap();
    assert_eq!(serde_json::to_vec(&observed).unwrap(), bytes);
    assert_eq!(matrix.schema, 2);
    for (row, case) in matrix.rows.iter().zip(&admission.policy().cases) {
        let completion = fs::read(
            f.dir
                .path()
                .join("evidence")
                .join(&case.id)
                .join("completion.json"),
        )
        .unwrap();
        let completion: serde_json::Value = serde_json::from_slice(&completion).unwrap();
        assert_eq!(
            serde_json::to_value(&row.completed.configuration).unwrap(),
            completion["configuration"]
        );
        assert_eq!(
            row.completed.manager_configuration_sha256,
            completion["manager_configuration_sha256"].as_str().unwrap()
        );
        for (output, stream) in row.completed.outputs.iter().zip(&case.streams) {
            let file = f
                .dir
                .path()
                .join("sealed")
                .join(&case.id)
                .join(&stream.output);
            assert_eq!(
                output.sha256,
                crate::identity::hash(&fs::read(&file).unwrap())
            );
            assert_eq!(
                output.object,
                ObjectIdentity::of(&fs::File::open(file).unwrap()).unwrap()
            );
        }
    }
    assert_eq!(
        campaign::observation(admission, &"0".repeat(64)).err(),
        Some("campaign-handoff-digest")
    );
}

fn handoff_header_changes() -> Vec<(&'static str, serde_json::Value, &'static str)> {
    vec![
        ("/schema", serde_json::json!(1), "campaign-handoff-version"),
        (
            "/command",
            serde_json::json!("completion"),
            "campaign-handoff-version",
        ),
        (
            "/campaign",
            serde_json::json!("other"),
            "campaign-handoff-identity",
        ),
        (
            "/policy_sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-identity",
        ),
        (
            "/code_sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-identity",
        ),
        ("/rows", serde_json::json!([]), "campaign-handoff-roster"),
    ]
}

fn handoff_case_changes(
    original: &serde_json::Value,
) -> Vec<(&'static str, serde_json::Value, &'static str)> {
    vec![
        (
            "/rows/0/index",
            serde_json::json!(1),
            "campaign-handoff-case",
        ),
        (
            "/rows/0/completed/case",
            serde_json::json!("other"),
            "campaign-handoff-case",
        ),
        (
            "/rows/0/completed/policy_sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-case",
        ),
        (
            "/rows/0/completed/case_sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-case",
        ),
        (
            "/rows/0/completed/invocation/unit",
            serde_json::json!("other.service"),
            "campaign-handoff-case",
        ),
        (
            "/rows/0/completed/invocation/image/inode",
            serde_json::json!(0),
            "campaign-handoff-case",
        ),
        (
            "/rows/1/completed/invocation/id",
            original["rows"][0]["completed"]["invocation"]["id"].clone(),
            "campaign-handoff-invocation",
        ),
        (
            "/rows/0/completed/completion_sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-completion",
        ),
        (
            "/rows/0/completed/outputs/0/name",
            serde_json::json!("other"),
            "campaign-handoff-output",
        ),
        (
            "/rows/0/completed/sealed_bytes/0",
            serde_json::json!(0),
            "campaign-handoff-output",
        ),
        (
            "/rows/0/completed/outputs/0/object/inode",
            serde_json::json!(0),
            "campaign-handoff-object",
        ),
        (
            "/rows/0/completed/outputs/0/sha256",
            serde_json::json!("0".repeat(64)),
            "campaign-handoff-content",
        ),
        (
            "/rows/0/completed/sealed_bytes/0",
            serde_json::json!(1),
            "campaign-handoff-content",
        ),
    ]
}

fn handoff_records(admission: &Admission, path: &std::path::Path, bytes: &[u8]) {
    let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    for (field, value, class) in handoff_header_changes()
        .into_iter()
        .chain(handoff_case_changes(&original))
    {
        let mut changed = original.clone();
        *changed.pointer_mut(field).unwrap() = value;
        let changed = serde_json::to_vec(&changed).unwrap();
        replace_protected(path, &changed);
        assert_eq!(
            campaign::observation(admission, &crate::identity::hash(&changed)).err(),
            Some(class),
            "{field}"
        );
    }
    for pointer in [
        "",
        "/rows/0",
        "/rows/0/completed",
        "/rows/0/completed/outputs/0",
        "/rows/0/completed/configuration",
    ] {
        let mut changed = original.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unreviewed".into(), true.into());
        let changed = serde_json::to_vec(&changed).unwrap();
        replace_protected(path, &changed);
        assert_eq!(
            campaign::observation(admission, &crate::identity::hash(&changed)).err(),
            Some("campaign-handoff-shape"),
            "{pointer}"
        );
    }
    let duplicate = String::from_utf8(bytes.to_vec())
        .unwrap()
        .replacen('{', "{\"schema\":2,", 1);
    replace_protected(path, duplicate.as_bytes());
    assert_eq!(
        campaign::observation(admission, &crate::identity::hash(duplicate.as_bytes())).err(),
        Some("campaign-handoff-shape")
    );
    replace_protected(path, bytes);
}

fn handoff_files(
    f: &Fixture,
    admission: &Admission,
    path: &std::path::Path,
    bytes: &[u8],
    digest: &str,
) {
    let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let output = f
        .dir
        .path()
        .join("sealed/sample")
        .join(&admission.policy().cases[0].streams[0].output);
    let content = fs::read(&output).unwrap();
    let mut changed = content.clone();
    changed[0] ^= 1;
    replace_protected(&output, &changed);
    assert_eq!(
        campaign::observation(admission, digest).err(),
        Some("campaign-handoff-content")
    );
    replace_protected(&output, &content);
    let old = output.with_extension("retained");
    fs::rename(&output, &old).unwrap();
    fs::write(&output, &content).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        campaign::observation(admission, digest).err(),
        Some("campaign-handoff-object")
    );
    fs::remove_file(&output).unwrap();
    fs::rename(old, &output).unwrap();
    let completion = f.dir.path().join("evidence/sample/completion.json");
    let retained = fs::read(&completion).unwrap();
    let mut oversized = retained.clone();
    oversized.resize(64 * 1024 + 1, b' ');
    replace_protected(&completion, &oversized);
    let mut expanded = original;
    expanded["rows"][0]["completed"]["completion_sha256"] =
        crate::identity::hash(&oversized).into();
    let expanded = serde_json::to_vec(&expanded).unwrap();
    replace_protected(path, &expanded);
    assert_eq!(
        campaign::observation(admission, &crate::identity::hash(&expanded)).err(),
        Some("file-custody")
    );
    replace_protected(path, bytes);
    replace_protected(&completion, b"{}");
    assert_eq!(
        campaign::observation(admission, digest).err(),
        Some("campaign-handoff-completion")
    );
    replace_protected(&completion, &retained);
    assert!(campaign::observation(admission, digest).is_ok());
}

fn handoff_roots(
    f: &Fixture,
    admission: &Admission,
    path: &std::path::Path,
    bytes: &[u8],
    digest: &str,
) {
    for (directory, class) in [
        ("evidence", "campaign-root-binding"),
        ("sealed", "campaign-handoff-root"),
    ] {
        let root = f.dir.path().join(directory);
        let retained = f.dir.path().join(format!("old-{directory}"));
        let result = campaign::observation_with(admission, digest, || {
            fs::rename(&root, &retained).unwrap();
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        });
        assert_eq!(result.err(), Some(class));
        fs::remove_dir(&root).unwrap();
        fs::rename(retained, root).unwrap();
    }
    assert_eq!(
        campaign::observation_with(admission, digest, || replace_protected(path, b"{}")).err(),
        Some("campaign-handoff-changed")
    );
    replace_protected(path, bytes);
    let parser = f.dir.path().join("parser");
    assert_eq!(
        campaign::observation_with(admission, digest, || replace_protected(&parser, b"changed"))
            .err(),
        Some("launch-artifact-changed")
    );
}
