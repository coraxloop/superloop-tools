//! Runtime preparation executes the received program after its pathname is replaced.
use super::helper_service;
use loop_home::CommandSpec;
use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// # Panics
/// Panics if the real namespace entry does not execute the received runtime program.
/// ´claim:superlooplane:runtime-preparation-executes-received-podman´
/// ´test:crate:runtime-preparation-executes-received-podman´
#[test]
fn runtime_preparation_executes_received_podman() {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "tests::launch::proxy_refresh_preserves_live_helper_pins",
            "--nocapture",
        ])
        .env("SUPERLOOP_RUNTIME_PROOF", "1")
        .env("SUPERLOOP_REFRESH_PROOF", "1")
        .env("_CONTAINERS_USERNS_CONFIGURED", "1")
        .env(
            "_CONTAINERS_ROOTLESS_UID",
            nix::unistd::Uid::effective().as_raw().to_string(),
        )
        .output()
        .expect("runtime fixture");
    std::io::Write::write_all(&mut std::io::stdout().lock(), &output.stderr)
        .expect("entry observations");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("RUNTIME-PODMAN-MEASURED"), "{stdout}");
}

struct MappedStorage(PathBuf, String);
impl Drop for MappedStorage {
    fn drop(&mut self) {
        drop(helper_service::namespace_python(
            &self.0,
            "import shutil,sys\nfrom pathlib import Path\np=Path(sys.argv[1]);shutil.rmtree(p/'.var/loops/alpha/private',ignore_errors=True);shutil.rmtree(p/'.var/loops/alpha/workers',ignore_errors=True);shutil.rmtree(p/'.var/loops/alpha/runs/R',ignore_errors=True);shutil.rmtree(sys.argv[2],ignore_errors=True)\n",
            &self.1,
        ));
    }
}

/// # Panics
/// Panics if the package binary built beside Cargo's unit test executable is absent.
fn binary() -> PathBuf {
    let image = std::env::current_exe().expect("test executable");
    // The nearest ancestor holding the binary is its profile directory, the gate's custom one too.
    let binary = image
        .ancestors()
        .map(|path| path.join("superloop-lane"))
        .find(|path| path.is_file())
        .unwrap_or_default();
    assert!(
        binary.is_file(),
        "unmeasured runtime entry: build the package binary before the focused library test"
    );
    binary
}

/// # Panics
/// Panics if the complete production vector cannot enter a real namespace with its descriptors.
fn run(request: &CommandSpec) -> std::process::Output {
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .env_remove("_CONTAINERS_USERNS_CONFIGURED")
        .env_remove("_CONTAINERS_ROOTLESS_UID");
    request
        .descriptors
        .configure(&mut command)
        .expect("entry descriptor transfer");
    command.output().expect("real namespace entry")
}

const STORAGE: &str = r"
import os,sys,tomllib,shutil
from pathlib import Path
home=Path(sys.argv[1]);root=home/'.var/loops/alpha'
assert os.geteuid()==0
assert os.stat('/').st_uid==int(Path('/proc/sys/kernel/overflowuid').read_text())
gid=tomllib.loads((home/'.config/loops/registry.toml').read_text())['loops'][0]['uid']
shutil.rmtree(root/'workers')
private=root/'private'
for p in [private,private/'.config',private/'.config/mail']:
 p.mkdir(exist_ok=True);os.chmod(p,0o700);os.chown(p,gid,gid)
p=private/'.config/mail/loop.toml'
p.write_text('workers=[]\n[mail]\nversion=1\nallow=[]\n');os.chmod(p,0o600);os.chown(p,gid,gid)
for p in [root/'runs/R',root/'runs/R/launch']:
 p.mkdir(exist_ok=True);os.chmod(p,0o700);os.chown(p,gid,gid)
";

/// # Panics
/// Panics if mapped storage cannot supply a real protected lifetime before runtime verification.
fn birth(home: &Path, runs: &Path, image: &Path, record: &mut Value) {
    let output =
        helper_service::namespace_python(home, STORAGE, "").expect("mapped runtime storage");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity: loop_home::mail::birth::Identity =
        serde_json::from_value(record["plan"]["mail"]["identity"].clone()).expect("planned birth");
    for phase in ["reserve", "finish"] {
        let request = loop_home::mail::worker_provision::anchored_command(
            home,
            "alpha",
            &identity,
            "_mail-worker-birth",
            phase,
            image,
            &["/usr/bin/podman".into(), "unshare".into()],
        )
        .expect("production worker composer");
        let output = run(&request);
        assert!(
            output.status.success(),
            "{phase}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    record["mail_birth"] = serde_json::to_value(identity).expect("birth record");
    crate::launch::publish_reservation(&runs.join(".reservation-R.json"), record)
        .expect("birth bound to reservation");
}

/// # Panics
/// Panics if the composer fails to pin the runtime or the real entry misses image inspection.
pub(super) fn exercise(home: &Path, runs: &Path, program: &Path) {
    let mut record = helper_service::prepare(home, runs, program);
    let _storage = MappedStorage(
        home.to_path_buf(),
        record["plan"]["home"]
            .as_str()
            .expect("worker home")
            .to_owned(),
    );
    let image = binary();
    birth(home, runs, &image, &mut record);
    let held_home = fs::File::open(home).expect("home descriptor").into();
    let held_runs = fs::File::open(runs).expect("runs descriptor").into();
    let argv = vec![
        "unshare".into(),
        image.display().to_string(),
        "_prepare-runtime".into(),
        "alpha".into(),
        "R".into(),
        "--owner-home".into(),
        home.display().to_string(),
        "--podman-bin".into(),
        program.display().to_string(),
    ];
    for status in [23, 29] {
        fs::copy("/bin/sh", program).expect("native runtime capability");
        fs::set_permissions(program, fs::Permissions::from_mode(0o700)).expect("executable mode");
        fs::write(
            home.join("image"),
            format!("printf 'received-image-{status}\\n' > runtime-inspection\nexit {status}\n"),
        )
        .expect("image inspection fixture");
        let mut request =
            crate::runtime_entry::command(program, &argv, home, &held_home, runs, &held_runs)
                .expect("production runtime composer");
        let replacement = home.join("runtime-replacement");
        fs::copy("/usr/bin/false", &replacement).expect("replacement native file");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
            .expect("replacement mode");
        fs::rename(replacement, program).expect("replace pinned name");
        // Podman bootstraps the real entry; the payload's program key and held inode stay bound.
        request.argv[0] = "/usr/bin/podman".into();
        let output = run(&request);
        let report = String::from_utf8_lossy(&output.stderr);
        writeln!(std::io::stderr().lock(), "RUNTIME-INSPECTION {report}")
            .expect("inspection observation");
        assert!(!output.status.success(), "image inspection fixture refuses");
        assert!(report.contains("image-identity"), "{report}");
        assert!(
            report.contains(&format!(" exited exit status: {status}: ")),
            "{report}"
        );
        assert_eq!(
            fs::read_to_string(home.join("runtime-inspection")).expect("held program ran"),
            format!("received-image-{status}\n")
        );
        fs::remove_file(home.join("runtime-inspection")).expect("reset execution evidence");
    }
    std::io::Write::write_all(&mut std::io::stdout().lock(), b"RUNTIME-PODMAN-MEASURED\n")
        .expect("measurement marker");
}
