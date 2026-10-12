//! Retired settings through the separately installed host worker reader.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove private reader fixture");
    }
}

/// ´claim:runworker:private-reader-keeps-unverified-driver-path-literal´
/// ´test:integration:private-reader-keeps-unverified-driver-path-literal´
#[test]
fn private_reader_keeps_unverified_driver_path_literal() {
    // The real verifier rejects group-writable build ancestors. Keep the copied
    // executable on disk under the sticky system temporary directory.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let fixture = Fixture(
        PathBuf::from("/var/tmp").join(format!("worker-settings-{}-{stamp}", std::process::id())),
    );
    fs::create_dir(&fixture.0).expect("fixture root");
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).expect("private root");
    for suffix in ["private", ".config", ".config/loops", ".config/loops/alpha"] {
        let path = fixture.0.join(suffix);
        fs::create_dir(&path).expect("fixture directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("directory mode");
    }
    let binary = fixture.0.join("private/worker-run");
    let built = fs::canonicalize(env!("CARGO_BIN_EXE_worker-run")).expect("resolved build binary");
    fs::copy(built, &binary).expect("private worker reader");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("installed worker mode");
    let owner = fs::metadata(&binary).expect("worker metadata").uid();
    loop_home::workers_settings::owner_executable(&binary, owner).expect("protected reader");
    assert!(!binary.with_file_name("superloop-lane").exists());
    let registry = fixture.0.join("registry.toml");
    fs::write(&registry, "namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{ name = \"alpha\", uid = 41001, launch = \"work/alpha\" }]\n").expect("registry");
    let settings = fixture.0.join(".config/loops/alpha/workers.toml");
    fs::write(&settings, "driver_bin = '/retired/codex-lane'\n").expect("retired setting");
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
    let output = Command::new(&binary)
        .args(["launch", "alpha", "r", "--driver", "claude", "--estate"])
        .arg(&fixture.0)
        .env("HOME", &fixture.0)
        .env("ENTER_LOOP_REGISTRY", &registry)
        .output()
        .expect("private worker refusal");
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        String::from_utf8(output.stderr).expect("refusal text"),
        "REFUSED retired-setting: driver_bin; set driver_argv = [PATH, \"driver\", \"start\", \"--backend\", \"codex\"]\n"
    );
    assert!(
        !fixture.0.join(".local").exists(),
        "refusal precedes launch state"
    );
}
