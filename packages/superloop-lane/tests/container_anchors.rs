use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};

use loop_home::anchor::{
    HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Transport, transport,
};

/// # Panics
/// Panics if the production helper does not reach its protected-run refusal under a partial map.
///
/// ´claim:superlooplane:container-helper-enters-with-held-root-files´
/// ´test:integration:container-helper-enters-with-held-root-files´
#[test]
#[allow(clippy::too_many_lines)]
fn container_helper_enters_with_held_root_files() {
    let fixture = tempfile::tempdir().expect("fixture");
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).expect("home mode");
    let runs = fixture.path().join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    let image = Path::new(env!("CARGO_BIN_EXE_superloop-lane"));
    let verifier = HostVerifier::current()
        .expect("host map")
        .for_operation("container-helper");
    let mut records = Vec::new();
    let mut descriptors = Vec::new();
    for (slot, purpose, path, policy) in [
        (
            0,
            "owner-home",
            fixture.path(),
            Policy {
                kind: Kind::Directory,
                owner: Owner::Host,
                mode: ModePolicy::Exact(0o700),
            },
        ),
        (
            1,
            "runs-root",
            runs.as_path(),
            Policy {
                kind: Kind::Directory,
                owner: Owner::Host,
                mode: ModePolicy::Exact(0o700),
            },
        ),
        (
            2,
            "entry-executable",
            image,
            Policy {
                kind: Kind::File,
                owner: Owner::Host,
                mode: ModePolicy::Executable,
            },
        ),
        (
            3,
            "podman-executable",
            Path::new("/usr/bin/podman"),
            Policy {
                kind: Kind::File,
                owner: Owner::RootFile,
                mode: ModePolicy::Executable,
            },
        ),
        (
            4,
            "hash-executable",
            Path::new("/usr/bin/sha256sum"),
            Policy {
                kind: Kind::File,
                owner: Owner::RootFile,
                mode: ModePolicy::Executable,
            },
        ),
    ] {
        let pin = verifier
            .pin(path, purpose, slot, policy)
            .expect("host file custody");
        records.push(pin.record());
        descriptors.push(pin.into_fd());
    }
    let declaration = serde_json::to_string(&Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: "container-helper".into(),
        loop_name: "alpha".into(),
        records,
    })
    .expect("manifest");
    let (sender, input) = UnixStream::pair().expect("channel");
    let child = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(image)
        .arg("_container-helper")
        .arg("--run-dir")
        .arg(runs.join("R"))
        .arg("--owner-home")
        .arg(fixture.path())
        .args(["--verified-home-fd", "0", "--verified-runs-root"])
        .arg(&runs)
        .args(["--verified-runs-root-fd", "1", "--anchor-manifest"])
        .arg(declaration)
        .env("HOME", fixture.path())
        .stdin(Stdio::from(OwnedFd::from(input)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("namespace bootstrap");
    transport::send(&sender, &descriptors).expect("bundle");
    let output = child.wait_with_output().expect("helper end");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("helper-pin: protected run reservation is absent"),
        "namespace availability and the production receiver are unmeasured unless the protected-run check is reached: {stderr}"
    );
    assert!(!stderr.contains("container-anchor:"), "{stderr}");
}
