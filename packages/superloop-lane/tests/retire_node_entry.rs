//! Archived node debt through the built command and the production node helper.
#![cfg(debug_assertions)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).expect("fixture file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
}

struct Fixture {
    home: tempfile::TempDir,
    config: PathBuf,
    record: PathBuf,
    node: PathBuf,
    ssh: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // The custody walker requires root-owned ancestors above the owner home.
        // Only small synthetic records live here; the build remains in CARGO_TARGET_DIR.
        let home = tempfile::TempDir::new_in("/tmp").expect("fixture home");
        let config = home.path().join(".config/loops/alpha");
        let runs = home.path().join("runs");
        let node = home.path().join("node");
        for path in [
            home.path().to_path_buf(),
            home.path().join(".config"),
            home.path().join(".config/loops"),
            config.clone(),
            runs.clone(),
            node.clone(),
        ] {
            fs::create_dir_all(&path).expect("fixture directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("private directory");
        }
        write(
            &home.path().join(".config/loops/registry.toml"),
            format!(
                "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n",
                runs.display()
            ),
        );
        write(
            &config.join("workers.toml"),
            format!(
                "runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n",
                runs.display(),
                "a".repeat(64),
                home.path().join("template").display(),
                home.path().join("sockets").display()
            ),
        );
        write(&runs.join(".prepare-R.lock"), "");
        let record = runs.join(".retired-R-20-1-2");
        write(&record, json!({"schema":1,"phase":"retired","loop":"alpha","run":"R","worker_uid":3000,
            "current_retirement":{"reservation_path":{"target":record},"planned_paths":[],"state":"retired"},
            "plan":{"home":"retained historical home"},"imports":["preserved"],"settlement_uncertain":true,
            "fixture_evidence":{"nested":[1,null,"preserved"]}}).to_string());
        let ssh = home.path().join("fixture-ssh");
        let script = r"#!/usr/bin/python3
import json, os, sys
from pathlib import Path
home = Path(__file__).parent
record = json.loads((home / 'runs/.retired-R-20-1-2').read_text())
assert record['phase'] == 'retired'
assert record['node_retirement']['outcome']['owed'] is True
assert record['node_retirement']['outcome']['reason'] == 'node-retirement-in-progress'
args = sys.argv[1:]
assert args[:2] == ['-F', 'none']
assert 'BatchMode=yes' in args and 'ConnectTimeout=10' in args
assert args[-2] == 'fixture'
assert 'timeout -k 5 105' in args[-1]
with (home / 'ssh-calls').open('a') as log:
    log.write(json.dumps(args) + '\n')
if (home / 'unreachable').exists():
    sys.exit(255)
os.environ['HOME'] = str(home / 'node')
os.execv('/bin/sh', ['sh', '-c', args[-1]])
";
        write(&ssh, script);
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).expect("stub SSH mode");
        let fixture = Self {
            home,
            config,
            record,
            node,
            ssh,
        };
        fixture.registration();
        fixture
    }

    fn registration(&self) {
        write(&self.config.join("door-compute-registration.json"), json!({"schema":1,"loop":"alpha","alias":"fixture",
            "mirror_root":"~/mirrors","node_root":self.node,"key_path":self.config.join("door-key")}).to_string());
        write(
            &self.config.join("door-ssh_config"),
            format!(
                "# Registered host key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nHost fixture\n  HostName fixture.invalid\n  Port 22\n  User fixture\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  BatchMode yes\n",
                self.config.join("door-known_hosts").display()
            ),
        );
        write(&self.config.join("door-node-registration.json"), json!({"schema":1,"loop":"alpha","alias":"fixture","address":"fixture.invalid","port":22,"user":"fixture","host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}).to_string());
        write(
            &self.config.join("door-known_hosts"),
            "fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        );
    }

    fn invoke(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_superloop-lane"))
            .args(["retire", "alpha", "R", "--node"])
            .args(args)
            .env("HOME", self.home.path())
            .env_remove("ENTER_LOOP_REGISTRY")
            .env("SUPERLOOP_LANE_TEST_RETIRE_SSH", &self.ssh)
            .output()
            .expect("production retire entry")
    }

    fn preview(&self) -> Value {
        report(&self.invoke(&["--dry-run"]))
    }

    fn read(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.record).expect("record bytes")).expect("record JSON")
    }

    fn debt(&self) -> Value {
        let mut plan = self.preview()["node_plan"].clone();
        plan["route"] = Value::Null;
        plan["paths"] = Value::Null;
        plan["marker"] = Value::Null;
        plan["reason"] = json!("node-retirement-registration-refusal");
        plan["detail"] = json!("door-compute-registration: SSH directive batchmode is unsupported");
        let outcome = json!({"state":"unmeasured","reason":plan["reason"],"owed":true,
            "host_wall_seconds":null,"helper_exit":null,"remote_completion":"unknown","evidence":null});
        let mut record = self.read();
        record["node_retirement"] = json!({"schema":1,"plan":plan,"outcome":outcome,
            "attempts":[{"plan":plan,"outcome":outcome}],"attempts_omitted":2});
        write(&self.record, record.to_string());
        record
    }

    fn paths(&self) -> [PathBuf; 4] {
        ["R", "R-build", "R-tmp", "R.lock"].map(|name| self.node.join("lanes").join(name))
    }

    fn refuse_unchanged(&self, expected: &str) {
        let before = fs::read(&self.record).expect("original bytes");
        let calls = fs::read(self.home.path().join("ssh-calls")).ok();
        for args in [
            vec!["--dry-run"],
            vec![
                "--expect-digest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
        ] {
            let output = self.invoke(&args);
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(expected), "{stderr}");
            assert_eq!(fs::read(&self.record).expect("unchanged record"), before);
            assert_eq!(fs::read(self.home.path().join("ssh-calls")).ok(), calls);
        }
    }
}

fn report(output: &Output) -> Value {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("command JSON")
}

fn without_node(mut record: Value) -> Value {
    record
        .as_object_mut()
        .expect("record")
        .remove("node_retirement");
    record
}

/// # Panics
/// Panics only if the built command fails to measure debt or changes unrelated archived evidence.
/// ´test:integration:retired-node-debt-completes-through-built-entry´
#[test]
fn retired_node_debt_completes_through_built_entry() {
    for already_absent in [false, true] {
        let fixture = Fixture::new();
        let before = fixture.debt();
        if !already_absent {
            for path in &fixture.paths()[..3] {
                fs::create_dir_all(path).expect("node path");
                fs::write(path.join("payload"), b"allocated fixture bytes").expect("node payload");
            }
            fs::write(&fixture.paths()[3], b"").expect("node lock");
        }
        assert!(
            fixture
                .paths()
                .iter()
                .all(|path| path.exists() != already_absent)
        );
        let bytes = fs::read(&fixture.record).expect("before preview");
        let preview = fixture.preview();
        assert_eq!(fs::read(&fixture.record).expect("preview unchanged"), bytes);
        assert!(!fixture.home.path().join("ssh-calls").exists());
        let bad = fixture.invoke(&["--expect-digest", &"0".repeat(64)]);
        assert_eq!(bad.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&bad.stderr).contains("retire-digest:"));
        let completed = report(&fixture.invoke(&[
            "--expect-digest",
            preview["preview_sha256"].as_str().expect("digest"),
        ]));
        let after = fixture.read();
        assert_eq!(without_node(after.clone()), without_node(before.clone()));
        let node = &after["node_retirement"];
        assert_eq!(node, &completed["node_retirement"]);
        assert_eq!(node["outcome"]["state"], "complete");
        assert_eq!(node["outcome"]["owed"], false);
        assert_eq!(node["outcome"]["remote_completion"], "measured");
        assert_eq!(node["outcome"]["helper_exit"], 0);
        assert_eq!(node["attempts_omitted"], 2);
        assert_eq!(node["attempts"].as_array().expect("history").len(), 2);
        assert_eq!(
            node["attempts"][0],
            before["node_retirement"]["attempts"][0]
        );
        assert_eq!(
            node["attempts"][1],
            json!({"plan":before["node_retirement"]["plan"],"outcome":before["node_retirement"]["outcome"]})
        );
        assert!(completed["worker_uid_released"].is_null());
        assert!(fixture.paths().iter().all(|path| !path.exists()));
        assert!(fixture.node.join("lanes/R.retired").is_file());
        let evidence = &node["outcome"]["evidence"];
        assert_eq!(evidence["before"].as_array().expect("before").len(), 4);
        assert!(
            evidence["after"]
                .as_array()
                .expect("after")
                .iter()
                .all(|row| row["exists"] == false)
        );
        if already_absent {
            for row in &evidence["before"].as_array().expect("before")[..3] {
                assert_eq!(row["exists"], false);
            }
            // The helper creates its own fourth path when acquiring the run lock.
            assert_eq!(evidence["before"][3]["exists"], true);
        }
        fixture.refuse_unchanged("retire-node-not-owed:");
    }
}

/// # Panics
/// Panics only if a refusal loses its name, starts SSH, or changes the retired record.
/// ´test:integration:retired-node-entry-keeps-named-registration-refusals´
#[test]
fn retired_node_entry_keeps_named_registration_refusals() {
    let fixture = Fixture::new();
    fixture.debt();
    for source in [
        "Host *\nBatchMode no\n",
        "Host *\nIdentityFile /unregistered\n",
        "Host *\nUnknownOption value\n",
    ] {
        write(&fixture.config.join("door-ssh_config"), source);
        fixture.refuse_unchanged("retire-node-registration: door-node-derived-drift:");
    }
    fs::remove_file(fixture.config.join("door-compute-registration.json"))
        .expect("missing registration");
    fixture.refuse_unchanged("retire-node-registration: node-retirement-no-registration:");
}

/// # Panics
/// Panics only if a historical record cannot complete or a failed attempt loses debt.
/// ´test:integration:retired-node-entry-preserves-historical-shape-and-failed-attempt´
#[test]
fn retired_node_entry_preserves_historical_shape_and_failed_attempt() {
    let fixture = Fixture::new();
    let original = fixture.read();
    fs::remove_file(fixture.config.join("door-compute-registration.json"))
        .expect("no registration");
    fixture.refuse_unchanged("retire-node-not-owed: node-retirement-no-registration:");
    fixture.registration();
    let preview = fixture.preview();
    assert_eq!(
        preview["node_retirement"]["reason"],
        "retired before node retirement existed"
    );
    write(&fixture.home.path().join("unreachable"), "");
    let failed = report(&fixture.invoke(&[
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    assert_eq!(failed["node_retirement"]["outcome"]["owed"], true);
    assert_eq!(
        failed["node_retirement"]["outcome"]["reason"],
        "node-retirement-unreachable"
    );
    assert_eq!(without_node(fixture.read()), original);
    fs::remove_file(fixture.home.path().join("unreachable")).expect("reachable node");
    let preview = fixture.preview();
    let completed = report(&fixture.invoke(&[
        "--expect-digest",
        preview["preview_sha256"].as_str().expect("digest"),
    ]));
    assert_eq!(completed["node_retirement"]["outcome"]["owed"], false);
    assert_eq!(
        completed["node_retirement"]["attempts"][0]["outcome"],
        failed["node_retirement"]["outcome"]
    );
    assert_eq!(without_node(fixture.read()), original);
}
