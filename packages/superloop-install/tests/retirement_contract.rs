use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            root: tempfile::tempdir().expect("fixture root"),
        };
        fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
        for stage in ["old", "new", "live"] {
            fs::create_dir_all(fixture.path(&format!("{stage}/opt/tools/bin"))).expect("stage");
            for suffix in ["", "/opt", "/opt/tools", "/opt/tools/bin"] {
                fs::set_permissions(
                    fixture.path(&format!("{stage}{suffix}")),
                    fs::Permissions::from_mode(0o700),
                )
                .expect("private stage directory");
            }
            fixture.write(&format!("{stage}/opt/tools/bin/keep"), b"retained");
        }
        for stage in ["old", "live"] {
            fixture.write(&format!("{stage}/opt/tools/bin/retired"), b"old executable");
            fixture.write(
                &format!("{stage}/opt/tools/bin/retired.provenance"),
                b"old provenance",
            );
        }
        fixture.inventory("old", &"a".repeat(40));
        fixture.inventory("new", &"b".repeat(40));
        fixture
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.path(relative);
        fs::write(&path, bytes).expect("fixture bytes");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("fixture mode");
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-install"));
        command.current_dir(self.root.path());
        command
    }

    fn inventory(&self, stage: &str, commit: &str) {
        let output = self
            .command()
            .arg("inventory")
            .arg("--stage")
            .arg(self.path(stage))
            .args([
                "--prefix",
                "/opt/tools",
                "--repository",
                "fixture",
                "--source-commit",
                commit,
            ])
            .arg("--report")
            .arg(self.path(&format!("{stage}.json")))
            .output()
            .expect("inventory binary");
        success(&output);
    }

    fn retire(&self, destinations: &[&str]) -> Output {
        let mut command = self.command();
        command
            .arg("retire")
            .arg("--old-inventory")
            .arg(self.path("old.json"))
            .arg("--new-inventory")
            .arg(self.path("new.json"))
            .args(["--prefix", "/opt/tools"])
            .arg("--destdir")
            .arg(self.path("live"))
            .arg("--recovery")
            .arg(self.path("recovery"))
            .arg("--report")
            .arg(self.path("report.json"));
        for destination in destinations {
            command.args(["--destination", destination]);
        }
        command.output().expect("retirement binary")
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(self.path("report.json")).expect("report bytes"))
            .expect("report JSON")
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// ´test:integration:staged-retirement-preserves-identity-and-second-invocation-changes-nothing´
#[test]
fn staged_retirement_preserves_identity_and_second_invocation_changes_nothing() {
    let fixture = Fixture::new();
    let old = fs::metadata(fixture.path("live/opt/tools/bin/retired")).expect("old identity");
    success(&fixture.retire(&[]));
    assert!(!fixture.path("live/opt/tools/bin/retired").exists());
    assert_eq!(
        fs::read(fixture.path("live/opt/tools/bin/keep")).expect("retained"),
        b"retained"
    );
    let report = fixture.report();
    assert_eq!(report["changes"].as_array().expect("changes").len(), 2);
    assert_eq!(report["planned"].as_array().expect("plan").len(), 2);
    let recovered = Path::new(
        report["changes"][0]["recovery"]
            .as_str()
            .expect("recovery name"),
    );
    assert_eq!(
        fs::metadata(recovered).expect("recovered identity").ino(),
        old.ino()
    );
    assert_eq!(
        fs::metadata(fixture.path("recovery"))
            .expect("recovery mode")
            .mode()
            & 0o777,
        0o700
    );
    let second = fixture.retire(&[]);
    success(&second);
    assert!(String::from_utf8_lossy(&second.stdout).contains("destinations=0"));
    assert_eq!(fixture.report()["changes"], serde_json::json!([]));
    assert_eq!(
        fixture.report()["already_retired"]
            .as_array()
            .expect("prior retirements")
            .len(),
        2
    );
    assert!(
        fixture.report()["already_retired"]
            .as_array()
            .expect("changes")
            .iter()
            .all(|row| row["outcome"] == "already-retired")
    );
}

/// ´test:integration:changed-bytes-refuse-before-any-retirement´
#[test]
fn changed_bytes_refuse_before_any_retirement() {
    let fixture = Fixture::new();
    fixture.write("live/opt/tools/bin/retired.provenance", b"unreviewed");
    let output = fixture.retire(&[]);
    assert!(!output.status.success());
    assert!(fixture.path("live/opt/tools/bin/retired").exists());
    assert!(
        fixture.report()["conflict"]
            .as_str()
            .expect("conflict")
            .contains("digest")
    );
}

/// ´test:integration:links-are-refused-and-new-release-destinations-cannot-be-selected´
#[test]
fn links_are_refused_and_new_release_destinations_cannot_be_selected() {
    for hard in [false, true] {
        let fixture = Fixture::new();
        let target = fixture.path("live/opt/tools/bin/retired");
        if hard {
            fs::hard_link(&target, fixture.path("alias")).expect("hard link");
        } else {
            fs::remove_file(&target).expect("remove target");
            symlink(fixture.path("old/opt/tools/bin/retired"), &target).expect("symlink");
        }
        assert!(!fixture.retire(&[]).status.success());
        assert!(target.symlink_metadata().is_ok());
    }
    let fixture = Fixture::new();
    assert!(!fixture.retire(&["bin/keep"]).status.success());
    assert!(fixture.path("live/opt/tools/bin/keep").exists());
}

/// ´test:integration:recovery-collision-and-unexplained-absence-refuse´
#[test]
fn recovery_collision_and_unexplained_absence_refuse() {
    let fixture = Fixture::new();
    success(&fixture.retire(&["bin/retired"]));
    fixture.write("live/opt/tools/bin/retired", b"old executable");
    assert!(!fixture.retire(&["bin/retired"]).status.success());
    assert!(
        fixture.report()["conflict"]
            .as_str()
            .expect("collision")
            .contains("already exists")
    );
    fs::remove_file(fixture.path("live/opt/tools/bin/retired.provenance"))
        .expect("remove unexplained");
    assert!(!fixture.retire(&["bin/retired.provenance"]).status.success());
    assert!(
        fixture.report()["conflict"]
            .as_str()
            .expect("absence")
            .contains("both absent")
    );
}

/// ´test:integration:inventory-identity-and-relative-destinations-are-checked´
#[test]
fn inventory_identity_and_relative_destinations_are_checked() {
    let fixture = Fixture::new();
    for destination in ["../escape", "/absolute", "bin/unknown"] {
        assert!(!fixture.retire(&[destination]).status.success());
    }
    let path = fixture.path("new.json");
    let mut value: Value =
        serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("JSON");
    value["repository"] = "other".into();
    fs::write(path, serde_json::to_vec(&value).expect("JSON")).expect("changed identity");
    assert!(!fixture.retire(&[]).status.success());
    assert!(fixture.path("live/opt/tools/bin/retired").exists());
}

/// # Panics
/// Panics only if fixture setup or the asserted two-deploy contract fails.
///
/// ´test:integration:first-staged-install-inventory-governs-the-following-retirement´
#[test]
fn first_staged_install_inventory_governs_the_following_retirement() {
    let fixture = Fixture {
        root: tempfile::tempdir().expect("two-deploy fixture"),
    };
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700))
        .expect("private root");
    for stage in ["old", "new", "live"] {
        for suffix in ["", "/opt", "/opt/tools", "/opt/tools/bin"] {
            let directory = fixture.path(&format!("{stage}{suffix}"));
            fs::create_dir_all(&directory).expect("stage directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private staging ancestors");
        }
    }
    fixture.write("keep", b"first retained payload");
    fixture.write("retired", b"first retired payload");
    let first_map = r#"root = "/opt/tools"
[[targets]]
kind = "copy"
source = "keep"
destination = "bin/keep"
mode = "0600"
[[targets]]
kind = "copy"
source = "retired"
destination = "bin/retired"
mode = "0600"
"#;
    let second_map = first_map
        .split("[[targets]]")
        .take(2)
        .collect::<Vec<_>>()
        .join("[[targets]]");
    fixture.write("first.toml", first_map.as_bytes());
    fixture.write("second.toml", second_map.as_bytes());
    let install = |map: &str, stage: &str| {
        let output = fixture
            .command()
            .arg("--map")
            .arg(fixture.path(map))
            .arg("--destdir")
            .arg(fixture.path(stage))
            .output()
            .expect("staged installer");
        success(&output);
        fixture.write(&format!("{stage}-{map}.report"), &output.stdout);
    };
    install("first.toml", "old");
    install("first.toml", "live");
    fixture.inventory("old", &"a".repeat(40));
    let retained_inventory = fs::read(fixture.path("old.json")).expect("bootstrap inventory");
    fixture.write("keep", b"second retained payload");
    install("second.toml", "new");
    install("second.toml", "live");
    fixture.inventory("new", &"b".repeat(40));
    success(&fixture.retire(&[]));
    assert!(!fixture.path("live/opt/tools/bin/retired").exists());
    assert_eq!(
        fs::read(fixture.path("live/opt/tools/bin/keep")).expect("successor"),
        b"second retained payload"
    );
    let report = fixture.report();
    let changes = report["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), 1);
    assert_eq!(
        fs::read(changes[0]["recovery"].as_str().expect("recovery path")).expect("archive"),
        b"first retired payload"
    );
    assert_eq!(
        fs::read(fixture.path("old.json")).expect("unchanged inventory"),
        retained_inventory
    );
    success(&fixture.retire(&[]));
    assert_eq!(fixture.report()["changes"], serde_json::json!([]));
}
