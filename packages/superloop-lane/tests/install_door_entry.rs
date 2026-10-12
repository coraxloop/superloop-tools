//! Pin install-door holder wording through the public binary entry.

#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use nix::fcntl::{Flock, FlockArg};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
enum ReservationSource {
    MissingRegistry,
    MissingRunsRoot,
    EmptyRunsRoot,
}

/// # Panics
/// Panics only if the public registration command violates its preview contract.
/// ´test:integration:door-node-registration-public-command´
#[test]
fn door_node_registration_public_command() {
    let fixture = tempfile::tempdir_in("/tmp").expect("small fixture with protected ancestors");
    let home = fixture.path();
    let config = home.join(".config/loops/alpha");
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        config.clone(),
    ] {
        fs::create_dir_all(&path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    fs::write(home.join(".config/loops/registry.toml"), "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{name = 'alpha', uid = 41001, launch = 'src'}]\n").expect("registry");
    let call = |mode: &[&str], address: &str| {
        Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .args([
                "register-door-node",
                "alpha",
                "--alias",
                "fixture",
                "--address",
                address,
                "--port",
                "22",
                "--user",
                "account",
                "--host-key",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ])
            .args(mode)
            .env("HOME", home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .output()
            .expect("public command")
    };
    let preview = call(&["--dry-run"], "192.0.2.1");
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: Value = serde_json::from_slice(&preview.stdout).expect("preview");
    assert!(!config.join("door-node-registration.json").exists());
    assert!(!config.join("door-ssh_config").exists());
    let digest = preview["preview_sha256"].as_str().expect("digest");
    let stale = call(&["--expect-digest", digest], "192.0.2.2");
    assert_eq!(stale.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("door-node-digest"));
    let applied = call(&["--expect-digest", digest], "192.0.2.1");
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(
        fs::metadata(config.join("door-node-registration.json"))
            .expect("record")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!config.join("door-ssh_config").exists());
    let invalid = call(&["--dry-run"], "node\nProxyCommand false");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("door-node-registration"));
    let repeated: Value =
        serde_json::from_slice(&call(&["--dry-run"], "192.0.2.1").stdout).expect("repeat");
    assert_eq!(repeated["changed"], false);
    std::os::unix::fs::symlink(home.join("outside"), config.join("door-known_hosts"))
        .expect("unsafe derivative");
    let unsafe_file = call(&["--dry-run"], "192.0.2.1");
    assert_eq!(unsafe_file.status.code(), Some(2));
    assert!(!home.join("outside").exists());
    fs::remove_file(config.join("door-node-registration.json")).expect("remove record");
    fs::write(config.join("door-ssh_config"), "hand maintained\n").expect("legacy config");
    let refused = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["install-door", "alpha", "--dry-run"])
        .env("HOME", home)
        .env_remove("ENTER_LOOP_REGISTRY")
        .output()
        .expect("public installer");
    assert_eq!(refused.status.code(), Some(2));
    let diagnostic = String::from_utf8_lossy(&refused.stderr);
    assert!(
        diagnostic.contains("door-node-unregistered-files"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("door-ssh_config") && diagnostic.contains("door-known_hosts"));
}

fn refused_with_shared_holder(source: ReservationSource) -> String {
    let fixture = tempfile::tempdir_in(temporary_root::temporary_root()).expect("fixture");
    let home = fixture.path();
    let config = home.join(".config/loops/alpha");
    fs::create_dir_all(&config).expect("configuration directory");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("configuration mode");
    let runs = home.join("runs");
    if matches!(source, ReservationSource::EmptyRunsRoot) {
        fs::create_dir(&runs).expect("empty runs root");
    }
    if !matches!(source, ReservationSource::MissingRegistry) {
        let registry = format!(
            "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n",
            runs.display()
        );
        fs::write(home.join(".config/loops/registry.toml"), registry).expect("registry");
    }
    let directory = File::open(&config).expect("configuration lock directory");
    let _holder = Flock::lock(directory, FlockArg::LockSharedNonblock).expect("shared holder");
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
        .args(["install-door", "alpha"])
        .env("HOME", home)
        .env_remove("ENTER_LOOP_REGISTRY")
        .output()
        .expect("install-door binary entry");
    assert_eq!(output.status.code(), Some(2));
    let refusal = String::from_utf8(output.stderr).expect("refusal text");
    assert!(refusal.contains("install-busy:"), "{refusal}");
    refusal
}

/// ´test:integration:install-door-entry-missing-registry-names-unreadable-reservations´
#[test]
fn install_door_entry_missing_registry_names_unreadable_reservations() {
    let refusal = refused_with_shared_holder(ReservationSource::MissingRegistry);
    assert!(refusal.contains("reservations unreadable"), "{refusal}");
    assert!(!refusal.contains("launch planning"), "{refusal}");
}

/// ´test:integration:install-door-entry-missing-runs-root-names-unreadable-reservations´
#[test]
fn install_door_entry_missing_runs_root_names_unreadable_reservations() {
    let refusal = refused_with_shared_holder(ReservationSource::MissingRunsRoot);
    assert!(refusal.contains("reservations unreadable"), "{refusal}");
    assert!(!refusal.contains("launch planning"), "{refusal}");
}

/// ´test:integration:install-door-entry-empty-runs-root-names-shared-holder-list´
#[test]
fn install_door_entry_empty_runs_root_names_shared_holder_list() {
    let refusal = refused_with_shared_holder(ReservationSource::EmptyRunsRoot);
    assert!(
        refusal.contains(
            "launch planning, a starting round, census, exercise, install --pilot --refresh-proxy, record-hosts --list, or a dry run"
        ),
        "{refusal}"
    );
    assert!(!refusal.contains("reservations unreadable"), "{refusal}");
}

/// # Panics
/// Panics only if fixture setup or the public entry violates the presence contract.
/// ´test:integration:install-door-entry-recorded-and-measuring-programs´
#[test]
fn install_door_entry_recorded_and_measuring_programs() {
    let fixture = tempfile::TempDir::new_in("/tmp").expect("small protected program fixture");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let config = home.join(".config/loops/alpha");
    fs::create_dir_all(&config).expect("configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("mode");
    let runs = home.join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    fs::write(home.join(".config/loops/registry.toml"), format!(
        "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{ name = 'alpha', uid = 41001, launch = 'src', runs_root = '{}' }}]\n",
        runs.display()
    )).expect("registry");
    let recorded = home.join("recorded-program");
    let selected = home.join("selected-program");
    fs::write(
        &selected,
        b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nprintf 'running\\n'\n",
    )
    .expect("measuring program");
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).expect("program mode");
    for run in ["R1", "R2"] {
        let path = runs.join(format!(".reservation-{run}.json"));
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema":1,"loop":"alpha","run":run,"phase":"started","worker_uid":3000,
                "launcher_pid":u32::MAX,"launcher_start":1,"plan":{"runtime_argv":[recorded]}
            }))
            .expect("record JSON"),
        )
        .expect("record");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("record mode");
    }
    let preview = |explicit: bool| -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command.args(["install-door", "alpha", "--dry-run"]);
        if explicit {
            command.arg("--podman-bin").arg(&selected);
        }
        let output = command
            .env("HOME", home)
            .env_remove("ENTER_LOOP_REGISTRY")
            .output()
            .expect("public entry");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("preview JSON")
    };
    let unknown = preview(false);
    assert_eq!(unknown["blocked"], true);
    for holder in unknown["busy"].as_array().expect("holders") {
        let text = holder.as_str().expect("holder text");
        assert!(text.contains("container unknown"), "{text}");
        assert!(
            text.contains(recorded.to_str().expect("recorded path")),
            "{text}"
        );
        assert!(text.contains("/usr/bin/podman"), "{text}");
    }
    assert_eq!(unknown["busy"].as_array().expect("holders").len(), 2);
    assert_eq!(unknown["container_states"], json!([]));
    let measured = preview(true);
    assert_eq!(measured["blocked"], true);
    let entries = measured["container_states"]
        .as_array()
        .expect("measurements");
    assert_eq!(entries.len(), 2, "{measured}");
    for entry in entries {
        assert_eq!(entry["program"], json!(selected));
        assert_eq!(entry["states"], json!(["running"]));
    }
}
