use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

use crate::home::{MAX_LETTER, make_home_pinned, read_letter};
use crate::plan::{Plan, box_gate, registry_with_timeout, verify_box_attestation};
use crate::settings::{Resources, Settings};
use crate::{load_plan, valid_run_name};

mod install;
mod launch;
mod prepare;

fn gate_fixture() -> serde_json::Value {
    Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &fixture_settings(Path::new("/opt/superloop/superloop")),
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan")
    .document
}

/// ´test:crate:worker-mail-group-is-part-of-the-attested-runtime-vector´
#[test]
fn worker_mail_group_is_part_of_the_attested_runtime_vector() {
    let mut plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &fixture_settings(Path::new("/opt/superloop/superloop")),
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    plan.select_mail_group(43001).expect("reserved mail group");
    verify_box_attestation(&plan.document).expect("mail group attested");
    assert!(
        plan.document["runtime_argv"]
            .as_array()
            .expect("vector")
            .iter()
            .any(|word| word == "--group-add=43001")
    );
    plan.select_worker_uid(3001).expect("next worker");
    plan.select_mail_group(43002).expect("next mailbox");
    verify_box_attestation(&plan.document).expect("replacement group attested");
    assert!(
        !plan.document["runtime_argv"]
            .as_array()
            .expect("vector")
            .iter()
            .any(|word| word == "--group-add=43001")
    );
    let mut changed = plan.document.clone();
    let vector = changed["runtime_argv"].as_array_mut().expect("vector");
    let index = vector
        .iter()
        .position(|word| word == "--cap-drop=ALL")
        .expect("option boundary");
    vector.insert(index, json!("--group-add=43003"));
    assert!(box_gate(&changed).is_err());
    for invalid in [0, 999, 3001, 41001, 65534, 65536] {
        assert!(plan.select_mail_group(invalid).is_err(), "{invalid}");
    }
}

/// ´test:crate:second-worker-slot-rederives-the-mount-inventory´
#[test]
fn second_worker_slot_rederives_the_mount_inventory() {
    let mut plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &fixture_settings(Path::new("/opt/superloop/superloop")),
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    plan.select_worker_uid(3001).expect("second worker slot");
    box_gate(&plan.document).expect("second-slot gate");
    let entries = plan.document["mount_inventory"]["entries"]
        .as_array()
        .expect("inventory entries");
    for entry in entries {
        match entry["source_role"].as_str() {
            Some("worker-leaf" | "worker-runtime") => assert_eq!(entry["owner"], 3001),
            Some("worker-home" | "runner-template") => assert_eq!(entry["owner"], 1000),
            _ => {}
        }
    }
}

/// ´test:crate:bind-inventory-uses-the-source-owner-row´
#[test]
fn bind_inventory_uses_the_source_owner_row() {
    let mut plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &fixture_settings(Path::new("/opt/superloop/superloop")),
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    let source = plan.document["mounts"]
        .as_array()
        .expect("mounts")
        .iter()
        .find(|row| row["target"] == "/home/worker/.local/bin")
        .expect("template bind")["source"]
        .clone();
    for row in plan.document["mount_sources"]
        .as_array_mut()
        .expect("sources")
    {
        if row["path"] == source {
            row["uid"] = json!(41001);
        }
    }
    plan.select_worker_uid(3001).expect("second slot");
    let entry = plan.document["mount_inventory"]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|row| row["target"] == "/home/worker/.local/bin")
        .expect("inventory bind");
    assert_eq!(entry["owner"], 41001);
    assert_eq!(plan.document["worker_uid"], 3001);
    box_gate(&plan.document).expect("source-owned inventory passes");
}

/// ´test:crate:mount-inventory-version-one-pins-its-entry-set´
#[test]
fn mount_inventory_version_one_pins_its_entry_set() {
    let inventory = gate_fixture()["mount_inventory"].clone();
    assert_eq!(inventory["version"], 1);
    assert_eq!(
        crate::repair::inventory_entry_digest(&inventory).expect("inventory digest"),
        "07eb7c692be74b1f59c7894857e79edf2cf535193e716e9cc46b93727327b812"
    );
}

/// ´test:crate:box-gate-refuses-conflicting-driver-owner´
#[test]
fn box_gate_refuses_conflicting_driver_owner() {
    let mut document = gate_fixture();
    let driver = document["driver_dir"].clone();
    let row = document["paths"]
        .as_array_mut()
        .expect("paths")
        .iter_mut()
        .find(|row| row["path"] == driver)
        .expect("driver row");
    row["uid"] = json!(3001);
    assert_eq!(
        box_gate(&document)
            .expect_err("conflicting driver owner")
            .kind,
        "loop-identity"
    );
}

/// ´test:crate:box-gate-refuses-missing-cap-drop´
#[test]
fn box_gate_refuses_missing_cap_drop() {
    let mut document = gate_fixture();
    document["runtime_argv"]
        .as_array_mut()
        .expect("argv")
        .retain(|word| word != "--cap-drop=ALL");
    assert!(
        box_gate(&document)
            .expect_err("missing cap drop")
            .line()
            .contains("--cap-drop=ALL")
    );
}

/// ´test:crate:box-gate-refuses-writable-mount-outside-worker-leaves´
#[test]
fn box_gate_refuses_writable_mount_outside_worker_leaves() {
    let mut document = gate_fixture();
    document["mounts"].as_array_mut().expect("mounts").push(json!({"kind":"bind","source":"/home/owner/other","target":"/home/worker/other","access":"rw"}));
    assert!(
        box_gate(&document)
            .expect_err("foreign write")
            .line()
            .contains("outside worker leaves")
    );
}

/// ´test:crate:box-gate-refuses-writable-root´
#[test]
fn box_gate_refuses_writable_root() {
    let mut document = gate_fixture();
    document["runtime_argv"]
        .as_array_mut()
        .expect("argv")
        .retain(|word| word != "--read-only");
    assert!(
        box_gate(&document)
            .expect_err("writable root")
            .line()
            .contains("--read-only")
    );
}

/// ´test:crate:box-gate-refuses-equals-form-extra-mount´
#[test]
fn box_gate_refuses_equals_form_extra_mount() {
    let mut document = gate_fixture();
    let image = document["image_digest"].clone();
    let argv = document["runtime_argv"].as_array_mut().expect("argv");
    let position = argv.iter().position(|word| word == &image).expect("image");
    argv.insert(
        position,
        json!("--mount=type=bind,src=/home/owner/other,dst=/home/worker/other,rw"),
    );
    assert_eq!(
        box_gate(&document).expect_err("extra mount").kind,
        "box-gate"
    );
}

/// ´test:crate:box-gate-refuses-split-network-option´
#[test]
fn box_gate_refuses_split_network_option() {
    let mut document = gate_fixture();
    let image = document["image_digest"].clone();
    let argv = document["runtime_argv"].as_array_mut().expect("argv");
    let position = argv.iter().position(|word| word == &image).expect("image");
    argv.splice(position..position, [json!("--network"), json!("host")]);
    assert_eq!(
        box_gate(&document).expect_err("split network").kind,
        "box-gate"
    );
}

/// ´test:crate:box-gate-refuses-repeated-option´
#[test]
fn box_gate_refuses_repeated_option() {
    let mut document = gate_fixture();
    let argv = document["runtime_argv"].as_array_mut().expect("argv");
    argv.insert(3, json!("--pull=never"));
    assert_eq!(
        box_gate(&document).expect_err("repeated option").kind,
        "box-gate"
    );
}

/// ´test:crate:box-gate-refuses-unknown-option´
#[test]
fn box_gate_refuses_unknown_option() {
    let mut document = gate_fixture();
    let argv = document["runtime_argv"].as_array_mut().expect("argv");
    argv.insert(3, json!("--unlisted-option"));
    assert_eq!(
        box_gate(&document).expect_err("unknown option").kind,
        "box-gate"
    );
}

fn fixture_settings(entry: &Path) -> Settings {
    Settings {
        sandbox_mode: "danger-full-access".into(),
        runs_root: None,
        backend_argv: std::collections::BTreeMap::from([(
            "codex".into(),
            vec!["/usr/libexec/superloop/codex".into()],
        )]),
        driver_argv: vec!["/opt/superloop/codex-lane".into()],
        entry_bin: Some(entry.to_path_buf()),
        driver_bin: Some(PathBuf::from("/opt/superloop/codex-lane")),
        image_digest: Some(format!("sha256:{}", "a".repeat(64))),
        template_dir: Some(PathBuf::from(
            "/home/owner/.var/loops/alpha/runner-templates/codex/DIGEST",
        )),
        resources: Some(Resources {
            memory_bytes: 2_147_483_648,
            pids_max: 128,
            cpu_shares: 512,
        }),
        socket_dir: Some(PathBuf::from("/home/owner/.var/loops/alpha/sockets/R")),
        vendor_hosts: std::collections::BTreeMap::new(),
        context_threshold: None,
        retention: String::from("keep"),
        source: String::new(),
    }
}

fn fixture_row() -> serde_json::Value {
    json!({"name": "alpha", "uid": 41001, "runs_root": "/home/owner/.var/loops/alpha/runs"})
}

fn fixture_block() -> loop_home::registry::WorkerBlock {
    loop_home::registry::WorkerBlock {
        base: 3000,
        count: 4,
    }
}

fn fixture_script(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    crate::fixture_exec::write_executable(&path, crate::registry_fixture::script(body).as_bytes())
        .expect("closed and synced registry fixture");
    path
}

/// ´test:crate:plan-refuses-missing-backend-before-allocation´
#[test]
fn plan_refuses_missing_backend_before_allocation() {
    let mut settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    settings.backend_argv.clear();
    let failure = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect_err("required selector");
    assert_eq!(failure.kind, "missing-setting");
    assert!(failure.detail.contains("backend_argv.codex"));
}

/// ´test:crate:full-plan-is-pinned-for-the-fixture´
#[test]
fn full_plan_is_pinned_for_the_fixture() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("fixture plan");
    let actual = plan.json().expect("JSON plan");
    if std::env::var_os("UPDATE_LANE_PLAN").is_some() {
        fs::write(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/plan.json"),
            format!("{actual}\n"),
        )
        .expect("write fixture");
        return;
    }
    assert_eq!(
        actual,
        include_str!("../../tests/fixtures/plan.json").trim_end()
    );
}

/// ´test:crate:codex-state-is-per-run-and-only-auth-path-reaches-shared-sign-in´
#[test]
fn codex_state_is_per_run_and_only_auth_path_reaches_shared_sign_in() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("fixture plan");
    assert!(
        plan.document["paths"]
            .as_array()
            .expect("paths")
            .iter()
            .any(|row| {
                row["path"] == "/home/owner/.cache/tmp/lane-alpha-R/.codex"
                    && row["uid"] == plan.document["worker_uid"]
                    && row["mode"] == "0700"
            })
    );
    assert!(
        !plan.document["mounts"]
            .as_array()
            .expect("mounts")
            .iter()
            .any(|row| row["target"] == "/home/worker/.local/sign-in/codex")
    );
    assert!(
        plan.document["mounts"]
            .as_array()
            .expect("mounts")
            .iter()
            .any(|row| {
                row["target"] == "/home/worker/.codex"
                    && row["access"] == "rw"
                    && row["source"] == plan.home.join(".codex").to_string_lossy().as_ref()
            })
    );
}

/// ´test:crate:plan-puts-owner-inputs-outside-loop-writable-run´
#[test]
fn plan_puts_owner_inputs_outside_loop_writable_run() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    let root = plan.driver_dir.parent().expect("runs root");
    let identity = root.join(".launch-R");
    for path in [identity.join("passwd"), identity.join("group")] {
        assert!(
            plan.document["mounts"]
                .as_array()
                .expect("mounts")
                .iter()
                .any(|mount| mount["source"] == path.to_string_lossy().as_ref())
        );
        assert!(
            plan.document["paths"]
                .as_array()
                .expect("paths")
                .iter()
                .any(|row| row["path"] == path.to_string_lossy().as_ref()
                    && row["uid"] == 1000
                    && row["gid"] == 41001)
        );
    }
    assert!(
        plan.document["runtime_argv"]
            .as_array()
            .expect("runtime vector")
            .iter()
            .any(|word| word
                == &format!(
                    "--cidfile={}",
                    root.join(".container-R-attempt-1.id").display()
                ))
    );
}

/// ´test:crate:plan-separates-equal-run-names-across-loops´
#[test]
fn plan_separates_equal_run_names_across_loops() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let first = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("first plan");
    let mut other_row = fixture_row();
    other_row["name"] = json!("beta");
    other_row["runs_root"] = json!("/home/owner/.var/loops/beta/runs");
    let second = Plan::build(
        Path::new("/home/owner"),
        "beta",
        "R",
        &settings,
        &other_row,
        fixture_block(),
        (1000, 1000),
    )
    .expect("second plan");
    assert_ne!(first.home, second.home);
    assert_ne!(
        first.document["runtime_argv"][3],
        second.document["runtime_argv"][3]
    );
    assert_eq!(
        first.home,
        PathBuf::from("/home/owner/.cache/tmp/lane-alpha-R")
    );
    assert_eq!(
        second.home,
        PathBuf::from("/home/owner/.cache/tmp/lane-beta-R")
    );
}

/// ´test:crate:observing-plan-names-one-run-and-writable-reply-roots´
#[test]
fn observing_plan_names_one_run_and_writable_reply_roots() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let mut plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    let argv = plan.document["runtime_argv"].as_array().expect("argv");
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["--sandbox", "danger-full-access"])
    );
    assert_eq!(plan.document["box_gate"]["verdict"], "passed");
    assert!(
        argv.windows(2)
            .any(|pair| { pair == ["-o", "/home/worker/.cache/work/last-message.md"] })
    );
    assert!(
        !plan.document["mounts"]
            .as_array()
            .expect("mounts")
            .iter()
            .any(|mount| mount["target"] == "/home/worker/.local/door")
    );
    plan.observe_vendor().expect("observing form");
    verify_box_attestation(&plan.document).expect("observing vector is attested after insertion");
    assert!(plan.document["box_gate"]["runtime_argv_sha256"].is_string());
    let argv = plan.document["runtime_argv"].as_array().expect("argv");
    assert!(
        argv.iter()
            .any(|arg| arg == "SUPERLOOP_VENDOR_SOCKET=/home/worker/.local/vendor/observe-R.sock")
    );
    assert_eq!(
        plan.document["vendor_mode"],
        "observing; host and port only; not enforcing"
    );
    assert_eq!(plan.document["vendor_socket"], "observe-R.sock");
    assert_eq!(
        plan.document["vendor_socket_address_length"],
        crate::socket_address_length("observe-R.sock")
    );
}

/// ´test:crate:socket-address-binds-and-connects-beneath-a-deep-directory´
#[test]
fn socket_address_binds_and_connects_beneath_a_deep_directory() {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    let fixture = TempDir::new().expect("socket fixture");
    let directory = fixture.path().join("synthetic-home-prefix".repeat(6));
    fs::create_dir(&directory).expect("deep socket directory");
    let socket = directory.join("observe-synthetic-run.sock");
    assert!(socket.as_os_str().len() > 107);
    assert!(std::os::unix::net::UnixListener::bind(&socket).is_err());
    let directory_fd = open(
        &directory,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .expect("held fixture directory");
    let held = crate::SocketSlot::new(
        nix::unistd::dup(&directory_fd).expect("duplicate directory"),
        socket.file_name().expect("socket name"),
    )
    .expect("short descriptor address");
    let listener = std::os::unix::net::UnixListener::bind(held.address()).expect("observer bind");
    let client = crate::SocketSlot::new(directory_fd, socket.file_name().expect("socket name"))
        .expect("client address");
    assert_eq!(held.address().file_name(), client.address().file_name());
    let _client = std::os::unix::net::UnixStream::connect(client.address())
        .expect("client reaches observed socket");
    let _accepted = listener.accept().expect("same socket receives client");
}

/// ´test:crate:socket-slot-survives-replaced-parent-for-bind-check-and-remove´
#[test]
fn socket_slot_survives_replaced_parent_for_bind_check_and_remove() {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    let fixture = TempDir::new().expect("socket fixture");
    let original = fixture.path().join("socket-directory");
    let moved = fixture.path().join("held-directory");
    fs::create_dir(&original).expect("original directory");
    let directory = open(
        &original,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .expect("hold verified directory");
    let slot = crate::SocketSlot::new(directory, std::ffi::OsStr::new("observe-synthetic.sock"))
        .expect("socket slot");
    fs::rename(&original, &moved).expect("move held directory");
    fs::create_dir(&original).expect("replacement directory");
    let _listener =
        std::os::unix::net::UnixListener::bind(slot.address()).expect("bind held directory");
    assert!(slot.metadata().expect("held metadata").is_some());
    assert!(!original.join("observe-synthetic.sock").exists());
    slot.remove().expect("remove from held directory");
    assert!(!moved.join("observe-synthetic.sock").exists());
    assert!(!original.join("observe-synthetic.sock").exists());
}

/// ´test:crate:observer-socket-address-refuses-measured-overflow´
#[test]
fn observer_socket_address_refuses_measured_overflow() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let mut plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("plan");
    plan.document["run"] = json!("r".repeat(100));
    let refusal = plan
        .observe_vendor()
        .expect_err("long synthetic socket name");
    assert_eq!(refusal.kind, "socket-path");
    assert!(refusal.detail.contains("address length"));
}

fn setup() -> (TempDir, PathBuf, Settings, serde_json::Value, (u32, u32)) {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    let root = temp.path().to_path_buf();
    fs::create_dir_all(root.join(".cache/tmp")).expect("home parent");
    fs::create_dir(root.join("runs")).expect("driver parent");
    let mut settings = fixture_settings(Path::new("/unused/entry"));
    settings.source = String::from("entry_bin = \"/unused/entry\"\n");
    let row = json!({"name": "alpha", "uid": 41001, "runs_root": root.join("runs")});
    let caller = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    (temp, root, settings, row, caller)
}

/// ´test:crate:make-home-creates-three-roots-and-reports-unassigned-ownership´
#[test]
fn make_home_creates_three_roots_and_reports_unassigned_ownership() {
    let (_temp, root, settings, row, caller) = setup();
    let mut plan = Plan::build(
        &root,
        "alpha",
        "R",
        &settings,
        &row,
        fixture_block(),
        caller,
    )
    .expect("plan");
    assert!(!plan.home.exists());
    assert!(!plan.driver_dir.exists());
    let home_parent = nix::fcntl::open(
        root.join(".cache/tmp").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("home parent");
    let driver_parent = nix::fcntl::open(
        root.join("runs").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("driver parent");
    let driver_index = plan.document["paths"]
        .as_array()
        .expect("paths")
        .iter()
        .position(|row| row["path"] == plan.driver_dir.display().to_string())
        .expect("driver row");
    let original_owner = plan.document["paths"][driver_index]["uid"].clone();
    plan.document["paths"][driver_index]["uid"] = json!(3001);
    let identity_error = make_home_pinned(
        &plan,
        &settings,
        b"Read back this letter.\n",
        caller,
        &home_parent,
        &driver_parent,
    )
    .expect_err("conflicting driver owner");
    assert_eq!(identity_error.kind, "loop-identity");
    assert!(!plan.home.exists());
    assert!(!plan.driver_dir.exists());
    plan.document["paths"][driver_index]["uid"] = original_owner;
    let report = make_home_pinned(
        &plan,
        &settings,
        b"Read back this letter.\n",
        caller,
        &home_parent,
        &driver_parent,
    )
    .expect("make home");
    assert_eq!(
        fs::read(&plan.letter).expect("letter"),
        b"Read back this letter.\n"
    );
    assert_eq!(
        fs::read(plan.driver_dir.join("settings.toml")).expect("settings"),
        settings.source.as_bytes()
    );
    assert_eq!(
        fs::read_to_string(plan.driver_dir.join("plan.json")).expect("plan file"),
        format!("{}\n", plan.json().expect("plan JSON"))
    );
    assert!(plan.driver_dir.join("launch").is_dir());
    assert_eq!(report["created"].as_array().expect("created").len(), 27);
    assert!(plan.home.join(".codex/auth.json").is_file());
    assert!(plan.home.join(".codex/config.toml").is_file());
    assert!(plan.home.join(".codex/AGENTS.md").is_file());
    assert!(!plan.home.join(".local/sign-in").exists());
    let scratch_path = root
        .join(".cache/tmp/lane-alpha-R/.cache")
        .to_string_lossy()
        .into_owned();
    let scratch = report["created"]
        .as_array()
        .expect("created")
        .iter()
        .find(|entry| entry["path"].as_str() == Some(&scratch_path))
        .expect("scratch");
    assert_eq!(scratch["wanted"]["uid"], 3000);
    assert_eq!(scratch["actual"]["uid"], caller.0);
    let failure = make_home_pinned(
        &plan,
        &settings,
        b"again",
        caller,
        &home_parent,
        &driver_parent,
    )
    .expect_err("existing roots");
    assert_eq!(failure.status, 2);
    assert_eq!(failure.kind, "already-exists");
}

/// ´test:crate:make-home-pinned-cleans-bares-after-late-failure´
#[test]
fn make_home_pinned_cleans_bares_after_late_failure() {
    let (_temp, root, settings, row, caller) = setup();
    let mut plan = Plan::build(
        &root,
        "alpha",
        "R",
        &settings,
        &row,
        fixture_block(),
        caller,
    )
    .expect("plan");
    plan.letter = plan.home.join(".local/inbox/bad\0name");
    let home_parent = nix::fcntl::open(
        root.join(".cache/tmp").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("home parent");
    let driver_parent = nix::fcntl::open(
        root.join("runs").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("driver parent");
    let failure = make_home_pinned(
        &plan,
        &settings,
        b"Sources: one\n",
        caller,
        &home_parent,
        &driver_parent,
    )
    .expect_err("late letter creation refuses");
    assert!(failure.line().contains("bad"), "{}", failure.line());
    assert!(!plan.home.join(".local/sources/one.git").exists());
}

/// ´test:crate:private-make-home-hands-seeded-and-empty-bares-to-distinct-worker´
#[test]
#[ignore = "requires namespace root with loop uid 41001 and worker uid 3000 mapped"]
#[allow(clippy::too_many_lines)]
fn private_make_home_hands_seeded_and_empty_bares_to_distinct_worker() {
    let (_temp, root, settings, row, caller) = setup();
    let src = root.join(".var/loops/alpha/src");
    fs::create_dir_all(&src).expect("loop source root");
    let bare = src.join("tools.git");
    let work = root.join("source-work");
    let git = |path: &Path, arguments: &[&str]| {
        let output = std::process::Command::new("/usr/bin/git")
            .args(["-c", "safe.directory=*"])
            .arg("-C")
            .arg(path)
            .args(arguments)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@invalid")
            .output()
            .expect("fixture git starts");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("fixture git output")
    };
    git(
        &root,
        &["init", "--bare", bare.to_str().expect("bare path")],
    );
    git(&root, &["init", work.to_str().expect("work path")]);
    fs::write(work.join("file"), b"seed\n").expect("seed file");
    git(&work, &["add", "file"]);
    git(&work, &["commit", "-m", "seed"]);
    let seed = git(&work, &["rev-parse", "HEAD"]).trim().to_owned();
    git(
        &work,
        &[
            "push",
            bare.to_str().expect("bare path"),
            "HEAD:refs/heads/main",
        ],
    );
    fs::set_permissions(&src, fs::Permissions::from_mode(0o700)).expect("private source root mode");
    for path in [&src, &bare] {
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(41001)),
            Some(nix::unistd::Gid::from_raw(41001)),
        )
        .expect("mapped loop owner");
    }
    for path in [root.join(".var/loops"), root.join(".var/loops/alpha")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o711))
            .expect("session-owned traversal mode");
    }
    let plan = Plan::build(
        &root,
        "alpha",
        "R",
        &settings,
        &row,
        fixture_block(),
        caller,
    )
    .expect("plan");
    let owner = fs::File::open(&root).expect("held owner home");
    let runs = fs::File::open(root.join("runs")).expect("held runs root");
    let _private =
        crate::home::activate_private_launch(&root, &owner, &root.join("runs"), &runs, None, 0)
            .expect("private entry anchors");
    let letter = format!("Sources: tools@{seed} empty\n");
    let report =
        crate::home::make_home_in_namespace(&plan, &settings, letter.as_bytes(), &root, "alpha")
            .expect("distinct-uid private handover");
    assert_eq!(report["declared_sources"][0]["seed"], seed);
    assert!(report["declared_sources"][0]["source_identity"].is_object());
    assert!(
        report["declared_sources"][0]["seeded_at_unix_ns"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        report["declared_sources"][1]["seed"],
        serde_json::Value::Null
    );
    assert!(report["declared_sources"][1]["source_identity"].is_null());
    assert!(report["declared_sources"][1]["seeded_at_unix_ns"].is_null());
    let sources = plan.home.join(".local/sources");
    let sources_meta = fs::symlink_metadata(&sources).expect("handed sources directory");
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&sources_meta), 3000);
    assert_eq!(std::os::unix::fs::MetadataExt::gid(&sources_meta), 3000);
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&sources_meta.permissions()) & 0o7777,
        0o700
    );
    for name in ["tools", "empty"] {
        let path = plan.home.join(format!(".local/sources/{name}.git"));
        let meta = fs::symlink_metadata(&path).expect("handed bare");
        assert_eq!(std::os::unix::fs::MetadataExt::uid(&meta), 3000);
        assert_eq!(std::os::unix::fs::MetadataExt::gid(&meta), 3000);
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777,
            0o700
        );
    }
    let nested = fs::symlink_metadata(sources.join("tools.git/refs/seeds/tools"))
        .expect("nested seeded bare entry");
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&nested), 3000);
    assert_eq!(std::os::unix::fs::MetadataExt::gid(&nested), 3000);
    let objects = sources.join("tools.git/objects");
    let fetched_object = fs::read_dir(&objects)
        .expect("object store")
        .map(|entry| entry.expect("object directory"))
        .filter(|entry| entry.file_name().to_string_lossy() != "info")
        .flat_map(|entry| fs::read_dir(entry.path()).expect("object contents"))
        .map(|entry| entry.expect("fetched object").path())
        .find(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_none_or(|extension| extension.to_string_lossy() == "pack")
        })
        .expect("fetch created a loose object or pack");
    let fetched_meta = fs::symlink_metadata(&fetched_object).expect("fetched object metadata");
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&fetched_meta), 3000);
    assert_eq!(std::os::unix::fs::MetadataExt::gid(&fetched_meta), 3000);
    assert_eq!(
        git(
            &plan.home.join(".local/sources/tools.git"),
            &["symbolic-ref", "HEAD"]
        )
        .trim(),
        "refs/heads/lane/R"
    );
    assert_eq!(
        git(
            &plan.home.join(".local/sources/tools.git"),
            &["for-each-ref", "--format=%(refname)"]
        )
        .trim(),
        "refs/seeds/tools"
    );
    assert_eq!(
        git(
            &plan.home.join(".local/sources/empty.git"),
            &["symbolic-ref", "HEAD"]
        )
        .trim(),
        "refs/heads/main"
    );
    let mut failing = Plan::build(
        &root,
        "alpha",
        "S",
        &settings,
        &row,
        fixture_block(),
        caller,
    )
    .expect("second plan");
    failing.letter = failing.home.join(".local/inbox/bad\0name");
    let failure =
        crate::home::make_home_in_namespace(&failing, &settings, letter.as_bytes(), &root, "alpha")
            .expect_err("outer private-entry guard refuses after creating bares");
    assert!(failure.line().contains("bad"), "{}", failure.line());
    assert!(!failing.home.join(".local/sources/tools.git").exists());
    assert!(!failing.home.join(".local/sources/empty.git").exists());
}

/// ´test:crate:run-name-follows-entry-grammar´
#[test]
fn run_name_follows_entry_grammar() {
    assert!(valid_run_name("R-1_a.b"));
    for bad in ["", ".R", "-R", "R/2", "R\n2"] {
        assert!(!valid_run_name(bad), "{bad:?}");
    }
    let (_temp, root, _settings, _row, caller) = setup();
    assert_eq!(
        load_plan(&root, "alpha", "../bad", caller)
            .expect_err("bad run")
            .kind,
        "run-name"
    );
}

/// ´test:crate:setting-reader-refuses-unknown-link-and-oversize´
#[test]
fn setting_reader_refuses_unknown_link_and_oversize() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private fixture");
    let path = temp.path().join("workers.toml");
    fs::write(&path, "surprise = 1\n").expect("setting");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private setting");
    let error = Settings::read(&path).expect_err("unknown key");
    assert_eq!(error.status, 2);
    assert_eq!(
        error.line(),
        format!("unknown-setting: {}: surprise", path.display())
    );
    let link = temp.path().join("link.toml");
    std::os::unix::fs::symlink(&path, &link).expect("symlink");
    assert_eq!(
        Settings::read(&link).expect_err("linked settings").kind,
        "settings-read"
    );
    fs::write(&path, vec![b'x'; 65_537]).expect("oversized settings");
    assert_eq!(
        Settings::read(&path).expect_err("oversized settings").kind,
        "settings-size"
    );
}

/// ´test:crate:old-settings-name-is-a-named-refusal´
#[test]
fn old_settings_name_is_a_named_refusal() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private fixture");
    fs::write(
        temp.path().join("box.toml"),
        "driver_argv = [\"/bin/true\"]\n",
    )
    .expect("old settings");
    let error = Settings::read(&temp.path().join("workers.toml")).expect_err("old name");
    assert_eq!(error.kind, "settings-read");
    assert!(error.line().contains("rename box.toml to workers.toml"));
}

/// ´test:crate:worker-settings-grammar-and-absent-grants´
#[test]
fn worker_settings_grammar_and_absent_grants() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private fixture");
    let path = temp.path().join("workers.toml");
    fs::write(&path, "").expect("empty settings");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private setting");
    let empty = Settings::read(&path).expect("absent settings");
    assert!(empty.image_digest.is_none());
    assert!(empty.resources.is_none());
    assert!(empty.vendor_hosts.is_empty());
    for (source, kind) in [
        ("image_digest = \"sha256:ABC\"\n", "bad-setting"),
        (
            "resources = { memory_bytes = 0, pids_max = 2, cpu_shares = 3 }\n",
            "bad-setting",
        ),
        ("backend_argv = { codex = [] }\n", "bad-setting"),
        (
            "vendor_hosts = { codex = [\"api.example.com\", \"api.example.com\"] }\n",
            "bad-setting",
        ),
        ("vendor_hosts = { codex = [\"10.0.0.1\"] }\n", "bad-setting"),
    ] {
        fs::write(&path, source).expect("candidate setting");
        assert_eq!(
            Settings::read(&path).expect_err(source).kind,
            kind,
            "{source}"
        );
    }
    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .expect("page size query")
        .expect("page size value");
    fs::write(&path, format!("backend_argv = {{ codex = [\"/usr/bin/codex\", \"exec\"] }}\nresources = {{ memory_bytes = {page_size}, pids_max = 64, cpu_shares = 512 }}\nvendor_hosts = {{ codex = [\"api.example.com\"] }}\n")).expect("valid setting");
    let parsed = Settings::read(&path).expect("valid settings");
    assert_eq!(parsed.resources.expect("resources").pids_max, 64);
    assert_eq!(parsed.backend_argv["codex"][0], "/usr/bin/codex");
    assert_eq!(parsed.vendor_hosts["codex"], ["api.example.com"]);
}

/// ´test:crate:settings-configure-vendors-and-cannot-widen-runs-root´
#[test]
fn settings_configure_vendors_and_cannot_widen_runs_root() {
    let mut settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    settings
        .vendor_hosts
        .insert("codex".into(), vec!["api.example.com".into()]);
    Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("settings name the vendor");
    settings.vendor_hosts.clear();
    settings.runs_root = Some(PathBuf::from("/outside/runs"));
    assert_eq!(
        Plan::build(
            Path::new("/home/owner"),
            "alpha",
            "R",
            &settings,
            &fixture_row(),
            fixture_block(),
            (1000, 1000)
        )
        .expect_err("different root")
        .kind,
        "settings-grant"
    );
}

/// ´test:crate:settings-file-and-parent-must-be-caller-controlled´
#[test]
fn settings_file_and_parent_must_be_caller_controlled() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private fixture");
    let path = temp.path().join("workers.toml");
    fs::write(&path, "surprise = 1\n").expect("setting");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("group-writable file");
    let file_error = Settings::read(&path).expect_err("writable file");
    assert_eq!(file_error.kind, "settings-owner");
    assert_eq!(file_error.status, 2);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private file");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o770))
        .expect("group-writable directory");
    let directory_error = Settings::read(&path).expect_err("writable directory");
    assert_eq!(directory_error.kind, "unsafe-path");
    assert_eq!(directory_error.status, 2);
}

/// ´test:crate:registry-capture-refuses-both-overflows-and-timeout´
#[test]
fn registry_capture_refuses_both_overflows_and_timeout() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    for (name, body, kind) in [
        ("stdout", "head -c 65537 /dev/zero", "registry-stdout-size"),
        (
            "stderr",
            "head -c 65537 /dev/zero >&2",
            "registry-stderr-size",
        ),
        ("timeout", "", "registry-timeout"),
    ] {
        let body = format!("{body}\nprintf ready > \"$0.ready\"\nsleep 30");
        let entry = fixture_script(temp.path(), name, &body);
        let ready = temp.path().join(format!("{name}.ready"));
        let settings = fixture_settings(&entry);
        let mut attempts = 0;
        let error = loop {
            let error = crate::plan::registry_with_ready(
                &settings,
                "alpha",
                Duration::from_millis(250),
                || {
                    let deadline = std::time::Instant::now() + Duration::from_secs(10);
                    while !ready.exists() {
                        if std::time::Instant::now() >= deadline {
                            return Err(crate::error::LaneError::input(
                                "fixture-ready",
                                "registry fixture did not finish producing its measured stream",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(())
                },
            )
            .expect_err("bounded registry response");
            if error.kind != "registry-command"
                || !error.detail.contains("Text file busy")
                || attempts == 3
            {
                break error;
            }
            attempts += 1;
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(error.kind, kind, "{name}: {error:?}");
        assert_eq!(error.status, 2);
        assert_eq!(error.line().lines().count(), 1);
    }
}

/// ´test:crate:registry-capture-waits-for-child-and-both-streams-under-load´
#[test]
fn registry_capture_waits_for_child_and_both_streams_under_load() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    let entry = fixture_script(
        temp.path(),
        "late-output",
        "printf '%s\\n' \"$0\" \"$@\" > \"$0.argv\"; printf '{\"part\":\"first\",\"late\":'; sleep 0.15; printf 'true}'; printf 'last stderr bytes' >&2",
    );
    let started = std::time::Instant::now();
    let row = registry_with_timeout(&fixture_settings(&entry), "alpha", Duration::from_secs(5))
        .expect("complete stdout after pause");
    assert_eq!(row["late"], true);
    assert_eq!(
        fs::read_to_string(temp.path().join("late-output.argv"))
            .expect("entry argument vector")
            .lines()
            .collect::<Vec<_>>(),
        [entry.to_str().expect("entry path"), "show", "alpha"]
    );
    assert!(started.elapsed() >= Duration::from_millis(100));

    let entry = fixture_script(
        temp.path(),
        "late-exit",
        "printf '{\"part\":true}'; exec 1>&-; exec 2>&-; sleep 0.15",
    );
    let started = std::time::Instant::now();
    let row = registry_with_timeout(&fixture_settings(&entry), "alpha", Duration::from_secs(5))
        .expect("child exit after streams close");
    assert_eq!(row["part"], true);
    assert!(started.elapsed() >= Duration::from_millis(100));

    let entry = fixture_script(
        temp.path(),
        "late-error",
        "printf '{\"part\":true}'; sleep 0.15; printf 'late stderr detail' >&2; exit 7",
    );
    let error = registry_with_timeout(&fixture_settings(&entry), "alpha", Duration::from_secs(5))
        .expect_err("late stderr and exit status");
    assert_eq!(error.kind, "registry-command");
    assert!(error.detail.contains("late stderr detail"));
    assert!(error.detail.contains("exited exit status: 7"));
}

/// ´test:crate:mount-argv-matches-document-and-comma-paths-refuse´
#[test]
fn mount_argv_matches_document_and_comma_paths_refuse() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let row = fixture_row();
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &row,
        fixture_block(),
        (1000, 1000),
    )
    .expect("fixture plan");
    let args = plan.document["runtime_argv"].as_array().expect("argv");
    let from_argv = args
        .windows(2)
        .filter(|window| {
            window[0] == "--mount"
                && window[1]
                    .as_str()
                    .is_some_and(|binding| binding.starts_with("type=bind,"))
        })
        .map(|window| {
            let binding = window[1].as_str().expect("mount argument");
            let fields = binding.split(',').collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "{binding}");
            assert_eq!(fields[0], "type=bind");
            json!({"access": fields[3], "source": fields[1].strip_prefix("src=").expect("source"), "target": fields[2].strip_prefix("dst=").expect("target")})
        })
        .collect::<Vec<_>>();
    let from_document = plan.document["mounts"]
        .as_array()
        .expect("mounts")
        .iter()
        .filter(|mount| mount["kind"] == "bind")
        .map(|mount| json!({"access": mount["access"], "source": mount["source"], "target": mount["target"]}))
        .collect::<Vec<_>>();
    assert_eq!(from_argv, from_document);
    assert_eq!(
        Plan::build(
            Path::new("/home/ow,ner"),
            "alpha",
            "R",
            &settings,
            &row,
            fixture_block(),
            (1000, 1000)
        )
        .expect_err("comma home")
        .kind,
        "path-delimiter"
    );
    let mut comma_row = row;
    comma_row["runs_root"] = json!("/home/owner/r,uns");
    assert_eq!(
        Plan::build(
            Path::new("/home/owner"),
            "alpha",
            "R",
            &settings,
            &comma_row,
            fixture_block(),
            (1000, 1000)
        )
        .expect_err("comma runs root")
        .kind,
        "path-delimiter"
    );
    let mut comma_settings = settings;
    comma_settings.template_dir = Some(PathBuf::from("/home/owner/t,emplate"));
    assert_eq!(
        Plan::build(
            Path::new("/home/owner"),
            "alpha",
            "R",
            &comma_settings,
            &fixture_row(),
            fixture_block(),
            (1000, 1000)
        )
        .expect_err("comma template")
        .kind,
        "path-delimiter"
    );
}

/// ´test:crate:runtime-tmpfs-belongs-to-the-worker´
#[test]
fn runtime_tmpfs_belongs_to_the_worker() {
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &fixture_settings(Path::new("/opt/superloop/superloop")),
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("fixture plan");
    let mount = plan.document["mounts"]
        .as_array()
        .expect("mounts")
        .iter()
        .find(|row| row["target"] == "/run/worker")
        .expect("worker runtime mount");
    assert_eq!(mount["kind"], "tmpfs");
    assert_eq!(mount["owner_uid"], 3000);
    assert_eq!(mount["group_gid"], 3000);
    assert_eq!(mount["mode"], "0700");
    assert_eq!(mount["empty"], true);
    let args = plan.document["runtime_argv"].as_array().expect("argv");
    assert!(args.windows(2).any(|pair| {
        pair[0] == "--mount"
            && pair[1] == "type=tmpfs,dst=/run/worker,tmpfs-mode=0700,U=true,notmpcopyup"
    }));
    assert!(
        args.windows(2)
            .any(|pair| pair[0] == "-e" && pair[1] == "XDG_RUNTIME_DIR=/run/worker")
    );
}

/// ´test:crate:box-init-refuses-wrong-runtime-directory-metadata´
#[test]
fn box_init_refuses_wrong_runtime_directory_metadata() {
    let fixture = TempDir::new_in("/tmp").expect("fixture");
    let runtime = fixture.path().join("worker");
    fs::create_dir(&runtime).expect("runtime directory");
    let source =
        include_str!("../../data/box-init").replace("/run/worker", &runtime.display().to_string());
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).expect("wrong mode");
    let wrong_mode = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&source)
        .output()
        .expect("shell check");
    assert!(!wrong_mode.status.success());
    assert!(String::from_utf8_lossy(&wrong_mode.stderr).contains("wrong owner or mode"));
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).expect("correct mode");
    let wrong_owner = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(source.replace("$(id -u)", "65534"))
        .output()
        .expect("shell check");
    assert!(!wrong_owner.status.success());
    assert!(String::from_utf8_lossy(&wrong_owner.stderr).contains("wrong owner or mode"));
}

/// ´test:crate:box-init-sets-private-worker-umask´
#[test]
fn box_init_sets_private_worker_umask() {
    let source = include_str!("../../data/box-init");
    assert!(source.contains("umask 077\n"));
    assert!(!source.contains("umask 007\n"));
}

/// ´test:crate:plan-marks-unmeasured-candidate-state´
#[test]
fn plan_marks_unmeasured_candidate_state() {
    let settings = fixture_settings(Path::new("/opt/superloop/superloop"));
    let plan = Plan::build(
        Path::new("/home/owner"),
        "alpha",
        "R",
        &settings,
        &fixture_row(),
        fixture_block(),
        (1000, 1000),
    )
    .expect("fixture plan");
    assert!(
        plan.document["runtime_measurement"]
            .as_str()
            .expect("runtime marker")
            .starts_with("provisional")
    );
    assert!(
        plan.document["template_measurement"]
            .as_str()
            .expect("template marker")
            .starts_with("provisional")
    );
    assert!(
        plan.document["source_measurement"]
            .as_str()
            .expect("source marker")
            .starts_with("provisional")
    );
    assert_eq!(
        plan.document["worker_uid_allocation"],
        "provisional-first-slot; launch must reserve"
    );
    for mount in plan.document["mounts"].as_array().expect("mounts") {
        assert!(
            mount["measurement"]
                .as_str()
                .expect("mount marker")
                .starts_with("provisional")
        );
    }
    for target in ["/proc", "/sys", "/sys/fs/cgroup", "/dev/pts", "/dev/mqueue"] {
        let mount = plan.document["mounts"]
            .as_array()
            .expect("mounts")
            .iter()
            .find(|mount| mount["target"] == target)
            .expect("candidate runtime mount");
        assert_eq!(mount["kind"], "conditional");
    }
}

/// ´test:crate:letter-refuses-nonregular-link-and-oversize´
#[test]
fn letter_refuses_nonregular_link_and_oversize() {
    let temp = TempDir::new_in("/tmp").expect("temporary fixture");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).expect("private fixture");
    let directory = temp.path().join("directory");
    fs::create_dir(&directory).expect("directory fixture");
    let directory_error =
        read_letter(&directory, nix::unistd::Uid::effective().as_raw()).expect_err("directory");
    assert_eq!(directory_error.kind, "letter-kind", "{directory_error:?}");
    let path = temp.path().join("letter.md");
    fs::write(
        &path,
        vec![b'a'; usize::try_from(MAX_LETTER + 1).expect("bounded letter size")],
    )
    .expect("big letter");
    assert_eq!(
        read_letter(&path, nix::unistd::Uid::effective().as_raw())
            .expect_err("big letter")
            .kind,
        "letter-size"
    );
    let link = temp.path().join("linked.md");
    std::os::unix::fs::symlink(&path, &link).expect("link");
    assert_eq!(
        read_letter(&link, nix::unistd::Uid::effective().as_raw())
            .expect_err("linked letter")
            .kind,
        "letter-read"
    );
}

/// ´test:crate:parent-refuses-link-and-worker-writable-mode´
#[test]
fn parent_refuses_link_and_worker_writable_mode() {
    let (_temp, root, _settings, _row, caller) = setup();
    let link = root.join("linked");
    std::os::unix::fs::symlink(root.join("runs"), &link).expect("link");
    assert_eq!(
        crate::home::pin_parent(&link, caller.0)
            .expect_err("linked parent")
            .kind,
        "unsafe-path"
    );
    fs::set_permissions(root.join("runs"), fs::Permissions::from_mode(0o777)).expect("mode");
    assert_eq!(
        crate::home::pin_parent(&root.join("runs"), caller.0)
            .expect_err("writable parent")
            .kind,
        "unsafe-path"
    );
}

/// ´test:crate:refusals-have-status-and-one-escaped-line´
#[test]
fn refusals_have_status_and_one_escaped_line() {
    let (_temp, root, settings, row, caller) = setup();
    let plan = Plan::build(
        &root,
        "alpha",
        "R",
        &settings,
        &row,
        fixture_block(),
        caller,
    )
    .expect("plan");
    let home_parent = nix::fcntl::open(
        root.join(".cache/tmp").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("home parent");
    let driver_parent = nix::fcntl::open(
        root.join("runs").as_path(),
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
        nix::sys::stat::Mode::empty(),
    )
    .expect("driver parent");
    fs::create_dir(&plan.home).expect("existing home");
    let existing = make_home_pinned(
        &plan,
        &settings,
        b"letter",
        caller,
        &home_parent,
        &driver_parent,
    )
    .expect_err("existing home");
    assert_eq!(existing.status, 2);
    assert_eq!(
        existing.line(),
        format!("already-exists: {} already exists", plan.home.display())
    );
    let escaped = crate::error::LaneError::input("fixture", "first\nsecond");
    assert_eq!(escaped.status, 2);
    assert_eq!(escaped.line(), "fixture: first\\nsecond");
    assert_eq!(escaped.line().lines().count(), 1);
    let operation = crate::error::LaneError::operation("stdout", "closed\npipe");
    assert_eq!(operation.status, 1);
    assert_eq!(operation.line(), "stdout: closed\\npipe");
    assert_eq!(operation.line().lines().count(), 1);
}
