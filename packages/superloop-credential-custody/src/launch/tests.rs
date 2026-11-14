//! Synthetic private-core boundaries; no manager, host root or host key.
use super::{
    measure,
    policy::{self, Role},
    state::{Phase, State},
    store::{Invocation, Store},
};
use crate::identity::hash;
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

pub(super) struct Fixture {
    pub(super) dir: tempfile::TempDir,
    pub(super) value: Value,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for name in ["runtime", "sealed", "evidence"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let artifacts: Vec<_> = [
            "launcher",
            "fixture",
            "sealer",
            "parser",
            "interpreter",
            "library",
        ]
        .into_iter()
        .map(|role| {
            let path = root.join(role);
            fs::write(&path, role).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
            json!({"id":role,"role":role,"path":path,"expected_sha256":hash(role.as_bytes())})
        })
        .collect();
        let roles: Vec<_> = [
            Role::CalibrationRun,
            Role::Completion,
            Role::Descriptors,
            Role::BarrierRelease,
            Role::Sealer,
            Role::Fixture,
        ]
        .into_iter()
        .map(|role| json!({"role":role,"properties":role.properties()}))
        .collect();
        let public_case=serde_json::to_vec(&json!({"schema":1,"command":"fixture-emit","case":"sample",
            "streams":[{"name":"left","length":5,"pattern":"ascending"},{"name":"right","length":5,"pattern":"descending"}],
            "behavior":"normal","timeout_ms":1000})).unwrap();
        fs::write(root.join("public.json"), &public_case).unwrap();
        fs::set_permissions(root.join("public.json"), fs::Permissions::from_mode(0o444)).unwrap();
        let value = json!({"schema":1,"command":"launch-policy","campaign":"synthetic",
            "roots":{"runtime":root.join("runtime"),"sealed":root.join("sealed"),"evidence":root.join("evidence")},
            "manager_sockets":[root.join("bus.sock"),root.join("manager.sock")],"host_key":root.join("admitted-key"),
            "slice":"synthetic.slice",
            "limits":{"case_ms":1000,"campaign_ms":64_000,"poll_ms":10,"sealed_bytes":4096,"total_sealed_bytes":524_288,
                "diagnostic_bytes":1024,"artifact_bytes":4096,"observed_fds":16,"mapped_files":8,"event_queue":16},
            "artifacts":artifacts,"roles":roles,
            "cases":[{"id":"sample","generator_unit":"synthetic-sample.service","public_case":root.join("public.json"),"expected_case_sha256":hash(&public_case),
                "streams":[{"name":"left","output":"left.sealed","length":5,"pattern":"ascending"},
                    {"name":"right","output":"right.sealed","length":5,"pattern":"descending"}]}]});
        Self { dir, value }
    }
    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.value).unwrap()
    }
    pub(super) fn admit(&self) -> measure::Admission {
        measure::admit_for_owner(&self.bytes(), nix::unistd::geteuid().as_raw()).unwrap()
    }
    fn refusal(&self, class: &str) {
        assert_eq!(policy::parse(&self.bytes()).unwrap_err(), class);
    }
}
fn err<T>(result: super::Result<T>, class: &str) {
    assert_eq!(result.err(), Some(class));
}

/// ´test:unit:launch-policy-rejects-open-shapes´
#[test]
fn launch_policy_rejects_open_shapes() {
    let f = Fixture::new();
    assert_eq!(policy::parse(&f.bytes()).unwrap().cases.len(), 1);
    for key in [
        "credential",
        "command_line",
        "code_digest",
        "config_digest",
        "manager_endpoint",
    ] {
        let mut value = f.value.clone();
        value[key] = json!("synthetic forbidden");
        err(
            policy::parse(&serde_json::to_vec(&value).unwrap()),
            "launch-policy-shape",
        );
    }
    for pointer in [
        "/roots",
        "/limits",
        "/artifacts/0",
        "/roles/0",
        "/roles/0/properties",
        "/cases/0",
        "/cases/0/streams/0",
    ] {
        let mut value = f.value.clone();
        value.pointer_mut(pointer).unwrap()["foreign"] = json!("synthetic forbidden");
        err(
            policy::parse(&serde_json::to_vec(&value).unwrap()),
            "launch-policy-shape",
        );
    }
    let text = String::from_utf8(f.bytes()).unwrap();
    err(
        policy::parse(
            text.replace("\"schema\":1", "\"schema\":1,\"schema\":1")
                .as_bytes(),
        ),
        "launch-policy-shape",
    );
    err(
        policy::parse(
            text.replace(
                "\"pattern\":\"ascending\"",
                "\"pattern\":\"ascending\",\"pattern\":\"ascending\"",
            )
            .as_bytes(),
        ),
        "launch-policy-shape",
    );
    let mut oversized = f.bytes();
    oversized.resize(crate::record::RECORD_LIMIT + 1, b' ');
    err(policy::parse(&oversized), "launch-policy-size");
    let mut value = f.value;
    value.as_object_mut().unwrap().remove("roles");
    err(
        policy::parse(&serde_json::to_vec(&value).unwrap()),
        "launch-policy-shape",
    );
    for (pointer, value, class) in [
        ("/schema", json!(2), "launch-policy-schema"),
        ("/command", json!("length-observe"), "launch-policy-schema"),
        ("/campaign", json!("../invalid"), "launch-policy-name"),
        ("/slice", json!("invalid@.slice"), "launch-policy-name"),
        ("/roots/runtime", json!("/"), "launch-policy-path"),
        ("/host_key", json!("../invalid"), "launch-policy-path"),
        ("/host_key", json!("/synthetic/%n"), "launch-policy-path"),
        (
            "/roles/0/properties/unknown",
            json!(true),
            "launch-policy-shape",
        ),
    ] {
        let mut f = Fixture::new();
        if let Some(field) = f.value.pointer_mut(pointer) {
            *field = value;
        } else {
            f.value["roles"][0]["properties"]["unknown"] = value;
        }
        f.refusal(class);
    }
}

/// ´test:unit:launch-policy-bounds-all-work´
#[test]
fn launch_policy_bounds_all_work() {
    for field in [
        "case_ms",
        "campaign_ms",
        "poll_ms",
        "sealed_bytes",
        "total_sealed_bytes",
        "diagnostic_bytes",
        "artifact_bytes",
        "observed_fds",
        "mapped_files",
        "event_queue",
    ] {
        for value in [0, u64::MAX] {
            let mut f = Fixture::new();
            f.value["limits"][field] = json!(value);
            f.refusal("launch-policy-limit");
        }
    }
    let mut oversized = Fixture::new();
    oversized.value["limits"]["artifact_bytes"] = json!(134_217_729);
    oversized.refusal("launch-policy-limit");
    for (field, value) in [("campaign_ms", 1), ("total_sealed_bytes", 1)] {
        let mut f = Fixture::new();
        f.value["limits"][field] = json!(value);
        f.refusal("launch-campaign-bound");
    }
    for count in [0, 65] {
        let mut f = Fixture::new();
        f.value["cases"] = json!(vec![f.value["cases"][0].clone(); count]);
        f.refusal("launch-campaign-bound");
    }
    let mut f = Fixture::new();
    f.value["limits"]["poll_ms"] = json!(1000);
    f.value["limits"]["case_ms"] = json!(10);
    f.refusal("launch-policy-limit");
}

/// ´test:unit:launch-policy-rosters-and-mappings-are-closed´
#[test]
fn launch_policy_rosters_and_mappings_are_closed() {
    for pointer in ["/roles", "/artifacts"] {
        let mut f = Fixture::new();
        *f.value.pointer_mut(pointer).unwrap() = json!([]);
        f.refusal(if pointer == "/roles" {
            "launch-role-roster"
        } else {
            "launch-artifact-roster"
        });
    }
    let mut f = Fixture::new();
    f.value["roles"][1] = f.value["roles"][0].clone();
    f.refusal("launch-role-roster");
    for pointer in ["/artifacts/1/id", "/artifacts/1/path"] {
        let mut f = Fixture::new();
        let key = pointer.rsplit('/').next().unwrap();
        let first = f.value["artifacts"][0][key].clone();
        *f.value.pointer_mut(pointer).unwrap() = first;
        f.refusal("launch-artifact-identity");
    }
    let mut f = Fixture::new();
    f.value["artifacts"][0]["expected_sha256"] = json!("bad");
    f.refusal("launch-artifact-identity");
    let mut f = Fixture::new();
    f.value["artifacts"][1]["role"] = json!("launcher");
    f.refusal("launch-artifact-roster");
    let mut f = Fixture::new();
    let mut optional = f.value["artifacts"][0].clone();
    optional["id"] = json!("manager-start");
    optional["role"] = json!("manager-start");
    optional["path"] = json!(f.dir.path().join("manager-start"));
    f.value["artifacts"].as_array_mut().unwrap().push(optional);
    f.refusal("launch-artifact-roster");
    let mut query = f.value["artifacts"][6].clone();
    query["id"] = json!("manager-query");
    query["role"] = json!("manager-query");
    query["path"] = json!(f.dir.path().join("manager-query"));
    f.value["artifacts"].as_array_mut().unwrap().push(query);
    assert_eq!(policy::parse(&f.bytes()).unwrap().artifacts.len(), 8);
}

/// ´test:unit:launch-policy-cases-and-paths-are-distinct´
#[test]
fn launch_policy_cases_and_paths_are_distinct() {
    let mut f = Fixture::new();
    f.value["roots"]["evidence"] = f.value["roots"]["sealed"].clone();
    f.refusal("launch-root-separation");
    let mut f = Fixture::new();
    f.value["manager_sockets"][1] = f.value["manager_sockets"][0].clone();
    f.refusal("launch-root-separation");
    let mut f = Fixture::new();
    f.value["host_key"] = f.value["manager_sockets"][0].clone();
    f.refusal("launch-root-separation");
    for key in ["id", "generator_unit", "public_case"] {
        let mut f = Fixture::new();
        let mut second = f.value["cases"][0].clone();
        second["id"] = json!("second");
        second["generator_unit"] = json!("second.service");
        second["public_case"] = json!(f.dir.path().join("second.json"));
        second[key] = f.value["cases"][0][key].clone();
        f.value["cases"].as_array_mut().unwrap().push(second);
        f.refusal("launch-case-identity");
    }
    for key in ["name", "output", "pattern"] {
        let mut f = Fixture::new();
        f.value["cases"][0]["streams"][1][key] = f.value["cases"][0]["streams"][0][key].clone();
        f.refusal("launch-stream-contract");
    }
    for (key, value) in [
        ("output", json!("../escape.sealed")),
        ("length", json!(0)),
        ("length", json!(1_048_577)),
    ] {
        let mut f = Fixture::new();
        f.value["cases"][0]["streams"][0][key] = value;
        f.refusal("launch-stream-contract");
    }
    let mut f = Fixture::new();
    let template = f.value["cases"][0].clone();
    let mut cases = Vec::new();
    for i in 0..9 {
        let mut c = template.clone();
        c["id"] = json!(format!("case-{i}"));
        c["generator_unit"] = json!(format!("case-{i}.service"));
        c["public_case"] = json!(f.dir.path().join(format!("public-{i}.json")));
        for j in 0..2 {
            c["streams"][j]["name"] = json!(format!("name-{i}-{j}"));
        }
        cases.push(c);
    }
    f.value["cases"] = json!(cases);
    f.refusal("launch-name-bound");
}

/// ´test:unit:launch-roles-require-the-reviewed-property-matrix´
#[test]
fn launch_roles_require_the_reviewed_property_matrix() {
    for index in 0..6 {
        for key in [
            "no_new_privileges",
            "manager_access",
            "dynamic_user",
            "private_diagnostics",
        ] {
            let mut f = Fixture::new();
            let old = f.value["roles"][index]["properties"][key]
                .as_bool()
                .unwrap();
            f.value["roles"][index]["properties"][key] = json!(!old);
            f.refusal("launch-role-properties");
        }
        for (key, value) in [
            ("ambient_capabilities", json!(["KILL"])),
            ("writable", json!(["runtime", "runtime"])),
        ] {
            let mut f = Fixture::new();
            f.value["roles"][index]["properties"][key] = value;
            f.refusal("launch-role-properties");
        }
        let mut f = Fixture::new();
        f.value["roles"][index]["properties"]["capability_bounding_set"] = json!(["KILL", "KILL"]);
        f.refusal("launch-role-properties");
    }
    for key in ["user_namespace", "pid_namespace", "protect_system"] {
        let mut f = Fixture::new();
        f.value["roles"][0]["properties"][key] = json!("unconfined");
        f.refusal("launch-policy-shape");
    }
}

/// ´test:unit:launch-measurement-uses-held-artifact-bytes´
#[test]
fn launch_measurement_uses_held_artifact_bytes() {
    let f = Fixture::new();
    let a = f.admit();
    assert_eq!(a.policy_sha256(), hash(&f.bytes()));
    assert_eq!(a.artifacts().len(), 6);
    for held in a.artifacts() {
        assert_eq!(held.sha256, hash(held.id.as_bytes()));
        held.unchanged().unwrap();
    }
    let path = f.dir.path().join("launcher");
    fs::rename(&path, f.dir.path().join("old-launcher")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    // Holding binds the measured inode; a future use verifies before execution.
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-artifact-drift",
    );
    let held = a.artifacts().iter().find(|a| a.id == "launcher").unwrap();
    fs::set_permissions(
        f.dir.path().join("old-launcher"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(f.dir.path().join("old-launcher"), b"changed").unwrap();
    err(held.unchanged(), "launch-artifact-changed");
    assert_ne!(a.code_sha256(), a.policy_sha256());
    err(
        measure::root_admission(std::path::Path::new("/nonexistent")),
        "launch-privilege-required",
    );
}

/// ´test:unit:launch-artifact-custody-and-alias-refuse´
#[test]
fn launch_artifact_custody_and_alias_refuse() {
    for mode in [0o666, 0o4444] {
        let f = Fixture::new();
        fs::set_permissions(
            f.dir.path().join("launcher"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        err(
            measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
            "launch-artifact-custody",
        );
    }
    let f = Fixture::new();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw() + 1),
        "launch-artifact-custody",
    );
    let mut f = Fixture::new();
    f.value["artifacts"][1]["expected_sha256"] = json!(hash(b"launcher"));
    fs::remove_file(f.dir.path().join("fixture")).unwrap();
    fs::hard_link(f.dir.path().join("launcher"), f.dir.path().join("fixture")).unwrap();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-artifact-alias",
    );
    let f = Fixture::new();
    fs::remove_file(f.dir.path().join("launcher")).unwrap();
    std::os::unix::fs::symlink("fixture", f.dir.path().join("launcher")).unwrap();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "path-open",
    );
    let mut f = Fixture::new();
    f.value["limits"]["artifact_bytes"] = json!(1);
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-artifact-custody",
    );
}

/// ´test:unit:launch-configuration-is-measured-and-closed´
#[test]
fn launch_configuration_is_measured_and_closed() {
    let p = Role::Descriptors.properties();
    let bytes = serde_json::to_vec(&p).unwrap();
    let m = measure::configuration(&p, &bytes).unwrap();
    assert_eq!(m.raw_sha256, hash(&bytes));
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    let other = measure::configuration(&p, &spaced).unwrap();
    assert_ne!(m.raw_sha256, other.raw_sha256);
    assert_eq!(m.typed_sha256, other.typed_sha256);
    err(
        measure::configuration(
            &p,
            &serde_json::to_vec(&Role::Completion.properties()).unwrap(),
        ),
        "launch-configuration-drift",
    );
    let mut foreign = serde_json::to_value(&p).unwrap();
    foreign["raw_secret"] = json!("synthetic-sentinel");
    err(
        measure::configuration(&p, &serde_json::to_vec(&foreign).unwrap()),
        "launch-configuration-shape",
    );
    let mut oversized = bytes;
    oversized.resize(crate::record::RECORD_LIMIT + 1, b' ');
    err(
        measure::configuration(&p, &oversized),
        "launch-configuration-size",
    );
}

const FLOW: [Phase; 9] = [
    Phase::SealersStarted,
    Phase::Submitted,
    Phase::Captured,
    Phase::InventoryComplete,
    Phase::ReleaseIntent,
    Phase::Released,
    Phase::GeneratorRetained,
    Phase::HolderReleased,
    Phase::EofAndSealersComplete,
];

/// ´test:unit:launch-state-never-releases-twice-or-recovers-success´
#[test]
fn launch_state_never_releases_twice_or_recovers_success() {
    let mut state = State::default();
    err(state.commit(Phase::Released), "launch-state-order");
    for p in FLOW {
        state.commit(p).unwrap();
    }
    state.commit(Phase::SealedSynced).unwrap();
    state.commit(Phase::Complete).unwrap();
    for p in [Phase::Complete, Phase::Released, Phase::Failed] {
        err(state.commit(p), "launch-terminal-state");
    }
    for terminal in [Phase::Failed, Phase::Uncertain] {
        let mut s = State::default();
        s.commit(terminal).unwrap();
        err(s.commit(Phase::SealersStarted), "launch-terminal-state");
    }
}

/// ´test:unit:launch-store-publishes-immutable-measured-manifests´
#[test]
fn launch_store_publishes_immutable_measured_manifests() {
    let f = Fixture::new();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let writers = store
        .output_files()
        .unwrap()
        .map(|f| f.try_clone().unwrap());
    let dir = f.dir.path().join("evidence/sample");
    let first = fs::read(dir.join("state-00.json")).unwrap();
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["policy_sha256"], admission.policy_sha256());
    assert_eq!(value["code_sha256"], admission.code_sha256());
    assert_eq!(value["created_outputs"].as_array().unwrap().len(), 2);
    assert_eq!(
        fs::metadata(dir.join("state-00.json")).unwrap().mode() & 0o7777,
        0o400
    );
    err(store.advance(Phase::SealedSynced), "launch-sync-order");
    err(store.sync_outputs(), "launch-sync-order");
    err(store.cleanup_outputs(), "launch-cleanup-state");
    err(Store::reserve(&admission, 0), "launch-exclusive-directory");
    for p in FLOW {
        if p == Phase::Captured {
            let image = admission
                .artifacts()
                .iter()
                .find(|a| a.id == "fixture")
                .unwrap()
                .object;
            store
                .capture(
                    Invocation {
                        id: "a".repeat(32),
                        unit: "synthetic-sample.service".to_owned(),
                        pid: 123,
                        birth: 1,
                        uid: 1234,
                        image,
                    },
                    &serde_json::to_vec(&Role::Fixture.properties()).unwrap(),
                )
                .unwrap();
        } else {
            store.advance(p).unwrap();
        }
    }
    err(store.sync_outputs(), "launch-sealed-size");
    writers[1].set_len(1).unwrap();
    writers[0]
        .set_len(admission.policy().limits.sealed_bytes + 1)
        .unwrap();
    err(store.sync_outputs(), "launch-sealed-size");
    writers[0].set_len(0).unwrap();
    for mut file in writers {
        file.write_all(b"synthetic sealed bytes").unwrap();
    }
    store.sync_outputs().unwrap();
    store.advance(Phase::Complete).unwrap();
    assert_eq!(store.phase(), Phase::Complete);
    assert_eq!(
        fs::metadata(f.dir.path().join("sealed/sample/left.sealed"))
            .unwrap()
            .mode()
            & 0o7777,
        0o400
    );
    assert_eq!(fs::read(dir.join("state-00.json")).unwrap(), first);
    assert!(!dir.join("marker").exists());
}

/// ´test:unit:launch-store-refuses-replacement-and-publication-collision´
#[test]
fn launch_store_refuses_replacement_and_publication_collision() {
    output_custody_drift();
    let f = Fixture::new();
    let a = f.admit();
    err(Store::reserve(&a, usize::MAX), "launch-case-binding");
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let dir = f.dir.path().join("sealed/sample");
    fs::rename(&dir, f.dir.path().join("sealed/original")).unwrap();
    fs::create_dir(&dir).unwrap();
    err(s.advance(Phase::SealersStarted), "launch-directory-binding");
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let out = f.dir.path().join("sealed/sample/left.sealed");
    fs::rename(&out, f.dir.path().join("sealed/sample/original")).unwrap();
    fs::write(&out, b"foreign").unwrap();
    err(s.advance(Phase::SealersStarted), "launch-output-binding");
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let target = f.dir.path().join("evidence/sample/state-01.json");
    fs::write(&target, b"occupied").unwrap();
    err(s.advance(Phase::SealersStarted), "receipt-no-replace");
    assert_eq!(s.phase(), Phase::Uncertain);
    assert_eq!(fs::read(&target).unwrap(), b"occupied");
    err(s.advance(Phase::SealersStarted), "launch-terminal-state");
}

/// ´test:unit:launch-cleanup-is-manifest-bound-and-failure-only´
#[test]
fn launch_cleanup_is_manifest_bound_and_failure_only() {
    // A failed sealing step may have changed only one output to immutable mode.
    // A terminal failure can retain that mixed-mode manifest and clean it safely.
    let partial = Fixture::new();
    let admission = partial.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    fs::set_permissions(
        partial.dir.path().join("sealed/sample/left.sealed"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    store.fail("synthetic-failure").unwrap();
    store.cleanup_outputs().unwrap();
    assert!(
        !partial
            .dir
            .path()
            .join("sealed/sample/left.sealed")
            .exists()
    );
    assert!(
        !partial
            .dir
            .path()
            .join("sealed/sample/right.sealed")
            .exists()
    );
    assert!(
        !partial
            .dir
            .path()
            .join("evidence/sample/state-11.json")
            .exists()
    );
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let dir = f.dir.path().join("sealed/sample");
    fs::write(dir.join("unrelated"), b"retained").unwrap();
    s.fail("synthetic-failure").unwrap();
    s.cleanup_outputs().unwrap();
    assert!(!dir.join("left.sealed").exists());
    assert_eq!(fs::read(dir.join("unrelated")).unwrap(), b"retained");
    assert!(!f.dir.path().join("evidence/sample/state-11.json").exists());
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    s.fail("synthetic-failure").unwrap();
    let dir = f.dir.path().join("sealed/sample");
    fs::rename(dir.join("right.sealed"), dir.join("original")).unwrap();
    fs::write(dir.join("right.sealed"), b"foreign").unwrap();
    err(s.cleanup_outputs(), "launch-output-binding");
    assert!(dir.join("left.sealed").exists());
}

/// ´test:unit:launch-capture-binds-invocation-image-and-effective-properties´
#[test]
fn launch_capture_binds_invocation_image_and_effective_properties() {
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let image = a
        .artifacts()
        .iter()
        .find(|a| a.id == "fixture")
        .unwrap()
        .object;
    let good = Invocation {
        id: "a".repeat(32),
        unit: "synthetic-sample.service".to_owned(),
        pid: 123,
        birth: 1,
        uid: 1234,
        image,
    };
    let bytes = serde_json::to_vec(&Role::Fixture.properties()).unwrap();
    err(s.capture(good.clone(), &bytes), "launch-capture-order");
    s.advance(Phase::SealersStarted).unwrap();
    s.advance(Phase::Submitted).unwrap();
    err(s.advance(Phase::Captured), "launch-capture-required");
    for bad in [
        Invocation {
            unit: "foreign.service".to_owned(),
            ..good.clone()
        },
        Invocation {
            id: "0".repeat(32),
            ..good.clone()
        },
        Invocation {
            pid: 0,
            ..good.clone()
        },
        Invocation {
            birth: 0,
            ..good.clone()
        },
        Invocation {
            uid: 0,
            ..good.clone()
        },
        Invocation {
            image: measure::ObjectIdentity {
                device: 0,
                inode: 0,
            },
            ..good.clone()
        },
    ] {
        let isolated = Fixture::new();
        let admission = isolated.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let actual_image = admission.fixture_image();
        let bad = Invocation {
            image: if bad.image == image {
                actual_image
            } else {
                bad.image
            },
            ..bad
        };
        store.advance(Phase::SealersStarted).unwrap();
        store.advance(Phase::Submitted).unwrap();
        err(store.capture(bad, &bytes), "launch-invocation-binding");
        assert_eq!(store.phase(), Phase::Uncertain);
        err(store.capture(good.clone(), &bytes), "launch-capture-order");
        let receipt: Value = serde_json::from_slice(
            &fs::read(isolated.dir.path().join("evidence/sample/state-03.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["original_cause"], "launch-invocation-binding");
    }
    err(
        s.capture(
            good.clone(),
            &serde_json::to_vec(&Role::Descriptors.properties()).unwrap(),
        ),
        "launch-configuration-drift",
    );
    assert_eq!(s.phase(), Phase::Uncertain);
    err(s.capture(good.clone(), &bytes), "launch-capture-order");
    let f = Fixture::new();
    let a = f.admit();
    let mut s = Store::reserve(&a, 0).unwrap();
    let good = Invocation {
        image: a.fixture_image(),
        ..good
    };
    s.advance(Phase::SealersStarted).unwrap();
    s.advance(Phase::Submitted).unwrap();
    s.capture(good, &bytes).unwrap();
    let receipt: Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/sample/state-03.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["configuration"]["raw_sha256"], hash(&bytes));
    assert_eq!(receipt["invocation"]["id"], "a".repeat(32));
    err(s.output_files(), "launch-output-transfer-order");
}

/// ´test:unit:launch-public-case-is-measured-before-reservation´
#[test]
fn launch_public_case_is_measured_before_reservation() {
    let f = Fixture::new();
    let path = f.dir.path().join("public.json");
    let a = f.admit();
    assert_eq!(a.cases()[0].sha256, hash(&fs::read(&path).unwrap()));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-public-case-custody",
    );
    let mut changed = fs::read(&path).unwrap();
    changed.push(b' ');
    fs::write(&path, changed).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-public-case-drift",
    );
    let mut f = Fixture::new();
    f.value["cases"][0]["streams"][0]["length"] = json!(6);
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-public-case-binding",
    );
    let f = Fixture::new();
    fs::hard_link(
        f.dir.path().join("public.json"),
        f.dir.path().join("alias.json"),
    )
    .unwrap();
    err(
        measure::admit_for_owner(&f.bytes(), nix::unistd::geteuid().as_raw()),
        "launch-public-case-custody",
    );
}

fn output_custody_drift() {
    let occupied = Fixture::new();
    let admitted = occupied.admit();
    let directory = occupied.dir.path().join("sealed/sample");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    err(Store::reserve(&admitted, 0), "launch-exclusive-directory");
    for linked in [false, true] {
        let f = Fixture::new();
        let a = f.admit();
        let mut store = Store::reserve(&a, 0).unwrap();
        let output = f.dir.path().join("sealed/sample/left.sealed");
        if linked {
            fs::hard_link(&output, f.dir.path().join("sealed/sample/alias")).unwrap();
        } else {
            fs::set_permissions(&output, fs::Permissions::from_mode(0o644)).unwrap();
        }
        err(
            store.advance(Phase::SealersStarted),
            "launch-output-binding",
        );
    }
}

/// ´test:unit:launch-binding-loss-latches-and-publishes-uncertainty´
#[test]
fn launch_binding_loss_latches_and_publishes_uncertainty() {
    for at_sync in [false, true] {
        let f = Fixture::new();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        for phase in FLOW {
            if phase == Phase::EofAndSealersComplete && !at_sync {
                break;
            }
            if phase == Phase::Captured {
                store
                    .capture(
                        Invocation {
                            id: "b".repeat(32),
                            unit: "synthetic-sample.service".into(),
                            pid: 123,
                            birth: 1,
                            uid: 1234,
                            image: admission.fixture_image(),
                        },
                        &serde_json::to_vec(&Role::Fixture.properties()).unwrap(),
                    )
                    .unwrap();
            } else {
                store.advance(phase).unwrap();
            }
        }
        let root = f.dir.path().join("sealed/sample");
        let output = root.join("left.sealed");
        let original = root.join("original");
        fs::rename(&output, &original).unwrap();
        fs::write(&output, b"foreign").unwrap();
        let result = if at_sync {
            store.sync_outputs()
        } else {
            store.advance(Phase::EofAndSealersComplete)
        };
        err(result, "launch-output-binding");
        assert_eq!(store.phase(), Phase::Uncertain);
        err(store.fail("generator-failed"), "launch-terminal-state");
        err(store.cleanup_outputs(), "launch-output-binding");
        assert_eq!(fs::read(&output).unwrap(), b"foreign");
        fs::remove_file(&output).unwrap();
        fs::rename(&original, &output).unwrap();
        err(
            store.advance(Phase::EofAndSealersComplete),
            "launch-terminal-state",
        );
        err(store.sync_outputs(), "launch-sync-order");
        err(store.advance(Phase::Complete), "launch-terminal-state");
        let receipts: Vec<Value> = fs::read_dir(f.dir.path().join("evidence/sample"))
            .unwrap()
            .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
            .collect();
        let terminal: Vec<_> = receipts
            .iter()
            .filter(|r| r["phase"] == "uncertain")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["refusal_class"], "launch-output-binding");
        assert!(receipts.iter().all(|r| r["phase"] != "complete"));
        store.cleanup_outputs().unwrap();
        assert!(!output.exists());
    }
}
/// ´test:unit:launch-terminal-receipts-name-the-refusal-class´
#[test]
fn launch_terminal_receipts_name_the_refusal_class() {
    for uncertain in [false, true] {
        let f = Fixture::new();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        err(
            store.advance(Phase::Failed),
            "launch-failure-class-required",
        );
        err(
            store.advance(Phase::Uncertain),
            "launch-failure-class-required",
        );
        if uncertain {
            store.uncertain("keeper-lost").unwrap();
        } else {
            store.fail("generator-failed").unwrap();
        }
        let receipt: Value = serde_json::from_slice(
            &fs::read(f.dir.path().join("evidence/sample/state-01.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            receipt["refusal_class"],
            if uncertain {
                "keeper-lost"
            } else {
                "generator-failed"
            }
        );
        assert_eq!(
            receipt["phase"],
            if uncertain { "uncertain" } else { "failed" }
        );
    }
}

/// ´test:unit:launch-failure-publication-cannot-reopen-success´
#[test]
fn launch_failure_publication_cannot_reopen_success() {
    let f = Fixture::new();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let evidence = f.dir.path().join("evidence/sample");
    fs::write(evidence.join("state-01.json"), b"occupied").unwrap();
    err(store.fail("generator-failed"), "receipt-no-replace");
    assert_eq!(store.phase(), Phase::Uncertain);
    assert_eq!(
        fs::read(evidence.join("state-01.json")).unwrap(),
        b"occupied"
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(evidence.join("state-02.json")).unwrap()).unwrap();
    assert_eq!(receipt["phase"], "uncertain");
    assert_eq!(receipt["refusal_class"], "receipt-no-replace");
    err(
        store.advance(Phase::SealersStarted),
        "launch-terminal-state",
    );
}

/// ´test:unit:launch-original-cause-survives-output-loss´
#[test]
fn launch_original_cause_survives_output_loss() {
    let fixture = Fixture::new();
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let output = fixture.dir.path().join("sealed/sample/left.sealed");
    fs::remove_file(&output).unwrap();
    fs::write(&output, b"foreign").unwrap();
    err(store.fail("generator-failed"), "launch-output-binding");
    let receipt: Value = serde_json::from_slice(
        &fs::read(fixture.dir.path().join("evidence/sample/state-01.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["original_cause"], "generator-failed");
    assert_eq!(receipt["refusal_class"], "launch-output-binding");
    assert_eq!(store.phase(), Phase::Uncertain);
}
