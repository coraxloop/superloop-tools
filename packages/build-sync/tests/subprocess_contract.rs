#[path = "support/temporary_root.rs"]
mod temporary_root;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, PoisonError};

const BINARY: &str = env!("CARGO_BIN_EXE_build-sync");
static STUB_PROCESS_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    root: tempfile::TempDir,
    cargo: PathBuf,
    artifact: PathBuf,
    output: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root =
            tempfile::tempdir_in(temporary_root::temporary_root()).expect("temporary directory");
        let cargo = root.path().join("cargo-stub");
        let artifact = root.path().join("artifact");
        let output = root.path().join("declared-output");
        fs::create_dir(root.path().join("packages")).expect("fixture packages");
        fs::create_dir(root.path().join("packages/superloop-run-report")).expect("fixture owner");
        fs::write(root.path().join("packages/superloop-run-report/Cargo.toml"), "[package]\nname = \"superloop-run-report\"\nversion = \"0.1.1\"\n[package.metadata.superloop]\nrelease-group = \"superloop-run-report\"\n").expect("version authority");
        fs::write(
            root.path().join("meson.build"),
            "script_version_roster = {\n}\npassthrough_roster = {\n}\n",
        )
        .expect("fixture rosters");
        fs::write(root.path().join("dependency-ledger.jsonl"), serde_json::json!({"kind":"program","identity":"build/superloop-run-report","output":"declared-output","package":"superloop-run-report","version_authority":"packages/superloop-run-report/Cargo.toml","form":"rust"}).to_string()).expect("program identity");
        write_executable(&cargo, br#"#!/bin/sh
set -eu
case "$1" in
  --version)
    if [ "${STUB_VERSION_DELAY:-}" = yes ]; then sleep 0.02; fi
    printf '%s\n' 'stub-tool 1.0'
    ;;
  build)
    if [ "$STUB_STATUS" != 0 ]; then
      exit "$STUB_STATUS"
    fi
    printf '%s' "$STUB_BYTES" > "$STUB_ARTIFACT"
    if [ "$STUB_MESSAGE" = yes ]; then
      printf '{"reason":"compiler-artifact","target":{"name":"superloop-run-report"},"executable":"%s"}\n' "$STUB_ARTIFACT"
    fi
    ;;
  *) exit 7 ;;
esac
"#, 0o755);
        Self {
            root,
            cargo,
            artifact,
            output,
        }
    }

    fn record(&self) -> PathBuf {
        PathBuf::from(format!("{}.build.json", self.output.display()))
    }

    fn sync(&self, bytes: &str, status: u8, message: bool) -> Output {
        let mut command = Command::new(BINARY);
        command
            .args([
                "--source-repository",
                "fixture",
                "--source-commit",
                &"a".repeat(40),
            ])
            .arg("--source-root")
            .arg(self.root.path())
            .arg("--ledger")
            .arg(self.root.path().join("dependency-ledger.jsonl"))
            .arg("--domain")
            .arg("server")
            .arg(&self.cargo)
            .arg(self.root.path().join("Cargo.toml"))
            .args(["superloop-run-report", "superloop-run-report"])
            .arg(&self.output)
            .env("RUSTC", &self.cargo)
            .env("STUB_STATUS", status.to_string())
            .env("STUB_BYTES", bytes)
            .env("STUB_ARTIFACT", &self.artifact)
            .env("STUB_MESSAGE", if message { "yes" } else { "no" });
        output_serialized(&mut command)
    }

    fn record_generated(&self) -> Output {
        let mut command = Command::new(BINARY);
        command
            .args([
                "--source-repository",
                "fixture",
                "--source-commit",
                &"a".repeat(40),
            ])
            .arg("--source-root")
            .arg(self.root.path())
            .arg("--ledger")
            .arg(self.root.path().join("dependency-ledger.jsonl"))
            .arg("--record")
            .arg(&self.output)
            .arg("--producer")
            .arg(&self.cargo)
            .args(["--domain", "server"]);
        output_serialized(&mut command)
    }

    fn stage(&self) -> Output {
        self.stage_from(self.root.path())
    }

    fn stage_from(&self, directory: &Path) -> Output {
        let mut command = Command::new(BINARY);
        command
            .current_dir(directory)
            .args([
                "--source-repository",
                "fixture",
                "--source-commit",
                &"a".repeat(40),
            ])
            .arg("--source-root")
            .arg(self.root.path())
            .arg("--ledger")
            .arg(self.root.path().join("dependency-ledger.jsonl"))
            .arg("--artifact")
            .arg(&self.artifact)
            .args(["--domain", "server"])
            .arg(&self.cargo)
            .arg(self.root.path().join("Cargo.toml"))
            .args(["superloop-run-report", "superloop-run-report"])
            .arg(&self.output)
            .env("RUSTC", &self.cargo)
            .env("STUB_STATUS", "99")
            .env("STUB_VERSION_DELAY", "yes");
        output_serialized(&mut command)
    }
}

/// Staging queries the compiler selected by the producer's source directory.
/// ´test:integration:staging-records-source-toolchain´
#[test]
fn staging_records_source_toolchain() {
    let fixture = Fixture::new();
    let build = fixture.root.path().join("build");
    fs::create_dir(&build).expect("build directory");
    fs::write(
        fixture.root.path().join("compiler-version"),
        "source-toolchain 1.0\n",
    )
    .expect("source toolchain");
    fs::write(build.join("compiler-version"), "build-toolchain 2.0\n").expect("build toolchain");
    write_executable(
        &fixture.cargo,
        b"#!/bin/sh\nset -eu\ncat compiler-version\n",
        0o755,
    );
    fs::write(&fixture.artifact, b"workspace artifact").expect("artifact");
    let selected = Command::new(&fixture.cargo)
        .current_dir(&build)
        .arg("--version")
        .output()
        .expect("build toolchain query");
    assert!(selected.status.success());
    assert_eq!(selected.stdout, b"build-toolchain 2.0\n");
    let staged = fixture.stage_from(&build);
    assert!(
        staged.status.success(),
        "{}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.record()).expect("record")).expect("JSON record");
    assert_eq!(record["cargo_version"], "source-toolchain 1.0");
    assert_eq!(record["rustc_version"], "source-toolchain 1.0");
}

/// Staging preserves bytes and records without running the failing build stub.
/// ´test:integration:staging-reuses-artifact-without-building´
#[test]
fn staging_reuses_artifact_without_building() {
    let fixture = Fixture::new();
    fs::write(&fixture.artifact, b"workspace artifact").expect("artifact");
    let staged = fixture.stage();
    assert!(staged.status.success(), "{:?}", staged.stderr);
    assert_eq!(
        fs::read(&fixture.output).expect("output"),
        b"workspace artifact"
    );
    assert_eq!(mode(&fixture.output), 0o755);
    let before = fs::read(fixture.record()).expect("record");
    let record: serde_json::Value = serde_json::from_slice(&before).expect("JSON");
    assert!(
        record["build_wall_ms"]
            .as_u64()
            .expect("measured staging wall")
            >= 40
    );
    assert_eq!(record["profile"], "release");
    assert!(fixture.stage().status.success());
    assert_eq!(fs::read(fixture.record()).expect("record"), before);
    fs::remove_file(&fixture.artifact).expect("remove artifact");
    assert_eq!(fixture.stage().status.code(), Some(1));
    assert_eq!(fs::read(fixture.record()).expect("record"), before);
    assert_eq!(
        fs::read(&fixture.output).expect("output"),
        b"workspace artifact"
    );
}

fn write_executable(path: &Path, bytes: &[u8], mode: u32) {
    let _guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    fs::write(path, bytes).expect("write executable stub");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set executable stub mode");
}

fn output_serialized(command: &mut Command) -> Output {
    let guard = STUB_PROCESS_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().expect("spawn build-sync");
    drop(guard);
    child.wait_with_output().expect("wait for build-sync")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("file metadata")
        .permissions()
        .mode()
        & 0o7777
}

/// ´test:integration:new-output-is-executable-with-build-record´
#[test]
fn new_output_is_executable_with_build_record() {
    let fixture = Fixture::new();
    let run = fixture.sync("first", 0, true);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.stdout, [] as [u8; 0]);
    assert_eq!(fs::read(&fixture.output).expect("output bytes"), b"first");
    assert_eq!(mode(&fixture.output), 0o755);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.record()).expect("build record"))
            .expect("record JSON");
    assert_eq!(record["package"], "superloop-run-report");
    assert_eq!(record["bin"], "superloop-run-report");
    assert_eq!(record["profile"], "release");
    assert_eq!(record["domain"], "server");
    assert_eq!(record["cargo_version"], "stub-tool 1.0");
    assert_eq!(record["rustc_version"], "stub-tool 1.0");
    assert_eq!(
        record["sha256"],
        "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
    );
    assert!(record["build_wall_ms"].is_u64());
    assert!(
        record["written"]
            .as_str()
            .expect("written string")
            .ends_with('Z')
    );
}

/// ´test:integration:changed-bytes-replace-output-and-record´
#[test]
fn changed_bytes_replace_output_and_record() {
    let fixture = Fixture::new();
    assert!(fixture.sync("first", 0, true).status.success());
    let before = fs::read(fixture.record()).expect("first record");
    assert!(fixture.sync("second", 0, true).status.success());
    assert_eq!(fs::read(&fixture.output).expect("new output"), b"second");
    let after = fs::read(fixture.record()).expect("second record");
    let first: serde_json::Value = serde_json::from_slice(&before).expect("first JSON");
    let second: serde_json::Value = serde_json::from_slice(&after).expect("second JSON");
    assert_ne!(first["sha256"], second["sha256"]);
}

/// ´test:integration:equal-bytes-repair-mode-without-changing-mtime-or-record´
#[test]
fn equal_bytes_repair_mode_without_changing_mtime_or_record() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same", 0, true).status.success());
    let before_record = fs::read(fixture.record()).expect("record");
    let record_mtime = fs::metadata(fixture.record())
        .expect("record metadata")
        .modified()
        .expect("record mtime");
    fs::set_permissions(&fixture.output, fs::Permissions::from_mode(0o644)).expect("wrong mode");
    let output_mtime = fs::metadata(&fixture.output)
        .expect("output metadata")
        .modified()
        .expect("output mtime");
    assert!(fixture.sync("same", 0, true).status.success());
    assert_eq!(mode(&fixture.output), 0o755);
    assert_eq!(
        fs::metadata(&fixture.output)
            .expect("output metadata")
            .modified()
            .expect("output mtime"),
        output_mtime
    );
    assert_eq!(
        fs::metadata(fixture.record())
            .expect("record metadata")
            .modified()
            .expect("record mtime"),
        record_mtime
    );
    assert_eq!(fs::read(fixture.record()).expect("record"), before_record);
}

/// ´test:integration:equal-output-leaves-both-mtimes-untouched´
#[test]
fn equal_output_leaves_both_mtimes_untouched() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same", 0, true).status.success());
    let output_mtime = fs::metadata(&fixture.output)
        .expect("output metadata")
        .modified()
        .expect("output mtime");
    let record_mtime = fs::metadata(fixture.record())
        .expect("record metadata")
        .modified()
        .expect("record mtime");
    assert!(fixture.sync("same", 0, true).status.success());
    assert_eq!(
        fs::metadata(&fixture.output)
            .expect("output metadata")
            .modified()
            .expect("output mtime"),
        output_mtime
    );
    assert_eq!(
        fs::metadata(fixture.record())
            .expect("record metadata")
            .modified()
            .expect("record mtime"),
        record_mtime
    );
}

/// ´test:integration:missing-record-is-created-beside-equal-output´
#[test]
fn missing_record_is_created_beside_equal_output() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same", 0, true).status.success());
    let output_mtime = fs::metadata(&fixture.output)
        .expect("output metadata")
        .modified()
        .expect("output mtime");
    fs::remove_file(fixture.record()).expect("remove record");
    assert!(fixture.sync("same", 0, true).status.success());
    assert!(fixture.record().exists());
    assert_eq!(
        fs::metadata(&fixture.output)
            .expect("output metadata")
            .modified()
            .expect("output mtime"),
        output_mtime
    );
}

/// ´test:integration:failing-cargo-leaves-output-and-record-alone´
#[test]
fn failing_cargo_leaves_output_and_record_alone() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same", 0, true).status.success());
    let output = fs::read(&fixture.output).expect("old output");
    let record = fs::read(fixture.record()).expect("old record");
    let failed = fixture.sync("different", 9, true);
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("cargo build exited"));
    assert_eq!(fs::read(&fixture.output).expect("output"), output);
    assert_eq!(fs::read(fixture.record()).expect("record"), record);
}

/// ´test:integration:missing-artifact-leaves-output-and-record-alone´
#[test]
fn missing_artifact_leaves_output_and_record_alone() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same", 0, true).status.success());
    let output = fs::read(&fixture.output).expect("old output");
    let record = fs::read(fixture.record()).expect("old record");
    let failed = fixture.sync("different", 0, false);
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("no executable artifact"));
    assert_eq!(fs::read(&fixture.output).expect("output"), output);
    assert_eq!(fs::read(fixture.record()).expect("record"), record);
}

/// ´test:integration:probe-classifies-empty-nonempty-missing-and-directory´
#[test]
fn probe_classifies_empty_nonempty_missing_and_directory() {
    let fixture = Fixture::new();
    let empty = fixture.root.path().join("empty");
    let filled = fixture.root.path().join("filled");
    fs::write(&empty, []).expect("empty stamp");
    fs::write(&filled, b"x").expect("filled stamp");
    for (path, expected) in [
        (&empty, 0),
        (&filled, 1),
        (&fixture.root.path().join("missing"), 1),
        (&fixture.root.path().to_path_buf(), 1),
    ] {
        let mut command = Command::new(BINARY);
        command.arg("--probe").arg(path);
        let result = output_serialized(&mut command);
        assert_eq!(result.status.code(), Some(expected));
        assert_eq!(result.stdout, [] as [u8; 0]);
        assert_eq!(result.stderr, [] as [u8; 0]);
    }
}

/// Record mode writes a generated record with source identity beside an existing output and updates its producer version without touching output bytes.
/// ´test:integration:record-mode-writes-generated-record-beside-output´
#[test]
fn record_mode_writes_generated_record_beside_output() {
    let fixture = Fixture::new();
    fs::write(&fixture.output, b"generated").expect("generated output");
    let output_mtime = fs::metadata(&fixture.output)
        .expect("output metadata")
        .modified()
        .expect("output mtime");
    let run = fixture.record_generated();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.stdout, [] as [u8; 0]);
    assert_eq!(
        fs::read(&fixture.output).expect("output bytes"),
        b"generated"
    );
    assert_eq!(
        fs::metadata(&fixture.output)
            .expect("output metadata")
            .modified()
            .expect("output mtime"),
        output_mtime
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.record()).expect("record bytes"))
            .expect("record JSON");
    assert_eq!(record.as_object().expect("record object").len(), 14);
    assert_eq!(record["installed_name"], "superloop-run-report");
    assert_eq!(record["source_commit"], "a".repeat(40));
    assert_eq!(record["repository"], "fixture");
    assert_eq!(record["release_group"], "superloop-run-report");
    assert_eq!(record["version"], "0.1.1");
    assert_eq!(record["bin"], "declared-output");
    assert_eq!(record["package"], "superloop-run-report");
    assert_eq!(record["profile"], "generated");
    assert_eq!(record["domain"], "server");
    assert_eq!(record["cargo_version"], "stub-tool 1.0");
    assert_eq!(record["rustc_version"], "stub-tool 1.0");
    assert_eq!(
        record["sha256"],
        "e0cb800a5ccda4cb1b2ad7990de082aaa1e40e771898c0bcb28fcb23c261e422"
    );
    assert!(record["build_wall_ms"].is_u64());
    assert!(
        record["written"]
            .as_str()
            .expect("UTC timestamp")
            .ends_with('Z')
    );
    write_executable(
        &fixture.cargo,
        br#"#!/bin/sh
printf '%s\n' '{"schema":1,"command":"stub","kind":"version","message":"version requested","fields":{"type":"version","version":"stub-tool 2.0"}}' >&2
"#,
        0o755,
    );
    assert!(fixture.record_generated().status.success());
    let updated: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.record()).expect("updated record"))
            .expect("updated JSON");
    assert_eq!(updated["cargo_version"], "stub-tool 2.0");
    assert_eq!(updated["rustc_version"], "stub-tool 2.0");
    assert_eq!(updated["sha256"], record["sha256"]);
}

/// An unchanged output and producer leave the generated record's bytes and modification time equal across runs.
/// ´test:integration:record-mode-preserves-unchanged-record´
#[test]
fn record_mode_preserves_unchanged_record() {
    let fixture = Fixture::new();
    fs::write(&fixture.output, b"same").expect("generated output");
    assert!(fixture.record_generated().status.success());
    let before = fs::read(fixture.record()).expect("record bytes");
    let mtime = fs::metadata(fixture.record())
        .expect("record metadata")
        .modified()
        .expect("record mtime");
    assert!(fixture.record_generated().status.success());
    assert_eq!(fs::read(fixture.record()).expect("record bytes"), before);
    assert_eq!(
        fs::metadata(fixture.record())
            .expect("record metadata")
            .modified()
            .expect("record mtime"),
        mtime
    );
}

/// Changed generated output bytes cause record mode to publish the new digest.
/// ´test:integration:record-mode-rewrites-changed-output´
#[test]
fn record_mode_rewrites_changed_output() {
    let fixture = Fixture::new();
    fs::write(&fixture.output, b"first").expect("first output");
    assert!(fixture.record_generated().status.success());
    let before = fs::read(fixture.record()).expect("first record");
    fs::write(&fixture.output, b"second").expect("second output");
    assert!(fixture.record_generated().status.success());
    let after = fs::read(fixture.record()).expect("second record");
    let first: serde_json::Value = serde_json::from_slice(&before).expect("first JSON");
    let second: serde_json::Value = serde_json::from_slice(&after).expect("second JSON");
    assert_ne!(first["sha256"], second["sha256"]);
}

/// A missing or nonregular generated output is refused with status one and no record.
/// ´test:integration:record-mode-refuses-missing-and-nonregular-output´
#[test]
fn record_mode_refuses_missing_and_nonregular_output() {
    let fixture = Fixture::new();
    let missing = fixture.record_generated();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("inspect generated output"));
    assert!(!fixture.record().exists());
    fs::create_dir(&fixture.output).expect("directory output");
    let directory = fixture.record_generated();
    assert_eq!(directory.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&directory.stderr).contains("not a regular file"));
    assert!(!fixture.record().exists());
}

/// A producer that fails or gives no version is refused with status one and no record.
/// ´test:integration:record-mode-refuses-producer-without-version´
#[test]
fn record_mode_refuses_producer_without_version() {
    let fixture = Fixture::new();
    fs::write(&fixture.output, b"generated").expect("generated output");
    write_executable(&fixture.cargo, b"#!/bin/sh\nexit 7\n", 0o755);
    let run = fixture.record_generated();
    assert_eq!(run.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&run.stderr).contains("producer version query exited"));
    assert!(!fixture.record().exists());
    write_executable(&fixture.cargo, b"#!/bin/sh\nexit 0\n", 0o755);
    let silent = fixture.record_generated();
    assert_eq!(silent.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&silent.stderr).contains("returned no version"));
    assert!(!fixture.record().exists());
}

/// Record mode refuses a sync positional or probe argument with usage status two.
/// ´test:integration:record-mode-refuses-positional-and-probe-arguments´
#[test]
fn record_mode_refuses_positional_and_probe_arguments() {
    let fixture = Fixture::new();
    for extra in ["positional", "--probe"] {
        let mut command = Command::new(BINARY);
        command
            .arg("--record")
            .arg(&fixture.output)
            .arg("--producer")
            .arg(&fixture.cargo)
            .arg(extra);
        if extra == "--probe" {
            command.arg(fixture.root.path().join("stamp"));
        }
        let run = output_serialized(&mut command);
        assert_eq!(run.status.code(), Some(2), "{extra}");
        assert!(String::from_utf8_lossy(&run.stderr).contains("usage_error"));
        assert!(!fixture.record().exists());
    }
}

/// Equal executable bytes keep their identity while a new release identity updates only provenance.
/// ´test:integration:changed-release-identity-rewrites-record-only´
#[test]
fn changed_release_identity_rewrites_record_only() {
    let fixture = Fixture::new();
    assert!(fixture.sync("same executable", 0, true).status.success());
    let before = fs::metadata(&fixture.output)
        .expect("output metadata")
        .modified()
        .expect("output mtime");
    let manifest = fixture
        .root
        .path()
        .join("packages/superloop-run-report/Cargo.toml");
    let source = fs::read_to_string(&manifest)
        .expect("manifest")
        .replace("0.1.1", "0.2.0");
    fs::write(manifest, source).expect("new version identity");
    assert!(fixture.sync("same executable", 0, true).status.success());
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.record()).expect("record")).expect("JSON");
    assert_eq!(record["version"], "0.2.0");
    assert_eq!(record["source_commit"], "a".repeat(40));
    assert_eq!(
        fs::metadata(&fixture.output)
            .expect("output metadata")
            .modified()
            .expect("output mtime"),
        before
    );
}

/// A missing program registration refuses before existing output bytes or records are replaced.
/// ´test:integration:unregistered-build-output-preserves-published-bytes´
#[test]
fn unregistered_build_output_preserves_published_bytes() {
    let fixture = Fixture::new();
    assert!(fixture.sync("reviewed", 0, true).status.success());
    let record = fs::read(fixture.record()).expect("record");
    fs::write(fixture.root.path().join("dependency-ledger.jsonl"), "")
        .expect("remove registration");
    let refused = fixture.sync("unreviewed", 0, true);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("exactly one program identity"));
    assert_eq!(fs::read(&fixture.output).expect("output"), b"reviewed");
    assert_eq!(fs::read(fixture.record()).expect("record"), record);
}
