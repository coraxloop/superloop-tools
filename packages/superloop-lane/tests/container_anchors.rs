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
    for (slot, purpose, path) in [
        (5, "credential-client", "/usr/bin/curl"),
        (6, "credential-clock", "/usr/bin/date"),
    ] {
        let pin = verifier
            .pin(
                Path::new(path),
                purpose,
                slot,
                Policy {
                    kind: Kind::File,
                    owner: Owner::RootFile,
                    mode: ModePolicy::Executable,
                },
            )
            .expect("credential executable");
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

/// # Panics
/// Panics if runtime custody is not validated in a real partial user namespace.
///
/// ´claim:superlooplane:runtime-entry-retains-configuration-and-executables´
/// ´test:integration:runtime-entry-retains-configuration-and-executables´
#[test]
#[allow(clippy::too_many_lines)]
fn runtime_entry_retains_configuration_and_executables() {
    use loop_home::{ProcessRunner, Runner};
    let fixture = tempfile::tempdir().expect("home");
    let home = fixture.path();
    for path in [
        home.to_path_buf(),
        home.join(".config"),
        home.join(".config/loops"),
        home.join("runs"),
    ] {
        fs::create_dir_all(&path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for (name, source) in [
        (
            "registry.toml",
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=64000,launch='dev/alpha'}]\n",
        ),
        (
            "allocations.toml",
            "mail_uid=64001\n[alpha]\nuids={base=64010,count=2}\nmail_gids={base=64020,count=3}\n",
        ),
    ] {
        let path = home.join(".config/loops").join(name);
        fs::write(&path, source).expect("configuration");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("file mode");
    }
    let script = r"
import os,sys
from pathlib import Path
home=Path(sys.argv[1])
assert os.geteuid()==0
assert os.stat('/').st_uid==int(Path('/proc/sys/kernel/overflowuid').read_text())
for path,uid,mode in [(home/'.var',0,0o711),(home/'.var/loops',0,0o711),(home/'.var/loops/alpha',0,0o711),(home/'.var/loops/alpha/private',64000,0o700)]:
 path.mkdir()
 os.chmod(path,mode)
 os.chown(path,uid,uid)
";
    let output = Command::new("/usr/bin/podman")
        .args(["unshare", "/usr/bin/python3", "-I", "-c", script])
        .arg(home)
        .output()
        .expect("fixture entry");
    assert!(
        output.status.success(),
        "unmeasured namespace fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let held_home = fs::File::open(home).expect("held home").into();
    let held_runs = fs::File::open(home.join("runs")).expect("held runs").into();
    let argv = vec![
        "unshare".into(),
        env!("CARGO_BIN_EXE_superloop-lane").into(),
        "_prepare-runtime".into(),
        "alpha".into(),
        "lane-a".into(),
        "--owner-home".into(),
        home.to_str().expect("UTF-8").into(),
        "--podman-bin".into(),
        "/usr/bin/podman".into(),
    ];
    let set_private = |uid: u32, mode: u32| {
        let output = Command::new("/usr/bin/podman")
            .args(["unshare", "/usr/bin/python3", "-I", "-c",
                "import os,sys; os.chmod(sys.argv[1],int(sys.argv[3])); os.chown(sys.argv[1],int(sys.argv[2]),int(sys.argv[2]))"])
            .arg(home.join(".var/loops/alpha/private"))
            .arg(uid.to_string()).arg(mode.to_string()).output().expect("private custody fixture");
        assert!(
            output.status.success(),
            "private custody fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let source_path = home.join("rotation-source");
    fs::write(&source_path, b"source").expect("source");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).expect("source mode");
    let held_source = fs::File::open(&source_path).expect("held source").into();
    for entry in ["runtime", "creation", "rotation"] {
        for case in [
            "valid",
            "override-canonical",
            "override-other",
            "operation",
            "identity",
            "missing",
            "extra-argument",
            "owner",
            "mode",
        ] {
            let mut request = if entry == "runtime" {
                superloop_lane::runtime_entry::command(
                    Path::new("/usr/bin/podman"),
                    &argv,
                    home,
                    &held_home,
                    &home.join("runs"),
                    &held_runs,
                )
                .expect("runtime composer")
            } else {
                let mut native = vec![
                    "unshare".into(),
                    env!("CARGO_BIN_EXE_superloop-lane").into(),
                    "_make-home".into(),
                    "alpha".into(),
                    "lane-a".into(),
                    "--letter".into(),
                    home.join("letter").to_str().expect("letter").into(),
                    "--owner-home".into(),
                    home.to_str().expect("home").into(),
                    "--worker-uid".into(),
                    "64010".into(),
                    "--podman-bin".into(),
                    "/usr/bin/podman".into(),
                    "--model".into(),
                    "model".into(),
                    "--effort".into(),
                    "high".into(),
                    "--model-source".into(),
                    "argument".into(),
                    "--effort-source".into(),
                    "argument".into(),
                    "--door-scope".into(),
                    "work".into(),
                ];
                if entry == "rotation" {
                    native.extend(["--rotation-sha256".into(), "0".repeat(64)]);
                }
                superloop_lane::creation_entry::command(
                    Path::new("/usr/bin/podman"),
                    &native,
                    (home, &held_home),
                    (&home.join("runs"), &held_runs),
                    (home, &held_home),
                    (entry == "rotation").then_some(&held_source),
                )
                .expect("creation composer")
            };
            if case == "missing" {
                request.descriptors = loop_home::CommandDescriptors::default();
            }
            if case == "operation" || case == "identity" {
                let last = request.argv.last_mut().expect("manifest");
                let mut manifest: Manifest = serde_json::from_str(last).expect("manifest");
                if case == "operation" {
                    manifest.operation = "container-helper".into();
                } else {
                    manifest.records[3].inode = manifest.records[3].inode.wrapping_add(1);
                }
                *last = serde_json::to_string(&manifest).expect("declaration");
            }
            if case == "extra-argument" {
                // The private vector cannot append an undeclared argument to its complete frame.
                request.argv.push("extra".into());
            }
            if case == "owner" {
                set_private(0, 0o700);
            }
            if case == "mode" {
                set_private(64000, 0o750);
            }
            let output = if case.starts_with("override-") {
                let registry = if case == "override-canonical" {
                    home.join(".config/loops/registry.toml")
                } else {
                    home.join("absent-registry")
                };
                runtime_override(&request, &registry)
            } else {
                ProcessRunner.run(&request).expect("runtime entry")
            };
            if case == "owner" || case == "mode" {
                set_private(64000, 0o700);
            }

            assert_ne!(output.status, 0, "fixture has no installed plan");
            let report = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            match case {
                "valid" => assert!(
                    !report.contains("anchor-")
                        && report.contains("unsafe-path:")
                        && report.contains(".config/loops/alpha"),
                    "validated runtime reaches settings: {report}"
                ),
                "override-canonical" | "override-other" => assert!(
                    report.contains("anchor-declaration")
                        && report.contains("purpose=registry-override"),
                    "{report}"
                ),
                "operation" => assert!(report.contains("anchor-declaration"), "{report}"),
                "identity" => assert!(report.contains("anchor-identity"), "{report}"),
                "owner" => assert!(report.contains("anchor-owner"), "{report}"),
                "mode" => assert!(report.contains("anchor-mode"), "{report}"),
                "missing" => assert!(report.contains("anchor-transport"), "{report}"),
                _ => assert!(
                    report.contains(if entry == "runtime" {
                        "anchor-declaration: operation=prepare-runtime purpose=vector"
                    } else {
                        "anchor-declaration: operation=make-home purpose=vector"
                    }),
                    "{report}"
                ),
            }
        }
    }
    set_private(0, 0o700);
}

/// # Panics
/// Panics if a container-backed exercise loses its selected program or protected record binding.
///
/// ´claim:superlooplane:exercise-entries-retain-selected-program-custody´
/// ´test:integration:exercise-entries-retain-selected-program-custody´
#[test]
fn exercise_entries_retain_selected_program_custody() {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    let fixture = tempfile::tempdir().expect("home");
    let home = fixture.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
    let runs = home.join("runs");
    fs::create_dir(&runs).expect("runs");
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700)).expect("runs mode");
    let alternate = home.join("selected-podman");
    fs::copy("/usr/bin/podman", &alternate).expect("real alternate program");
    fs::set_permissions(&alternate, fs::Permissions::from_mode(0o700)).expect("program mode");
    let held_home = fs::File::open(home).expect("home descriptor").into();
    let held_runs = fs::File::open(&runs).expect("runs descriptor").into();
    let record_path = runs.join(".reservation-R.json");
    for program in [Path::new("/usr/bin/podman"), alternate.as_path()] {
        let bytes=serde_json::to_vec(&serde_json::json!({"schema":1,"phase":"preparing","worker_uid":3000,"loop":"alpha","run":"R","plan":{"runtime_argv":[program]}})).expect("record bytes");
        fs::write(&record_path, &bytes).expect("protected record");
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).expect("record mode");
        let stat = fs::metadata(&record_path).expect("record identity");
        let mut identity = format!("{}:{}:", stat.dev(), stat.ino());
        for byte in Sha256::digest(&bytes) {
            write!(identity, "{byte:02x}").expect("digest word");
        }
        for mode in [
            "_exercise-mounts",
            "_exercise-network",
            "_exercise-door-shape",
            "_exercise-door-attribution",
        ] {
            let argv = vec![
                "unshare".into(),
                env!("CARGO_BIN_EXE_superloop-lane").into(),
                mode.into(),
                "alpha".into(),
                "R".into(),
                "--expect-record".into(),
                identity.clone(),
                "--owner-home".into(),
                home.to_str().expect("home word").into(),
            ];
            for case in ["valid", "operation", "record", "program", "missing"] {
                let request = superloop_lane::launch::exercise_entry::command(
                    Path::new("/usr/bin/podman"),
                    &argv,
                    home,
                    &held_home,
                    &runs,
                    &held_runs,
                )
                .expect("production exercise composer");
                exercise_case(request, case, &record_path, &bytes, mode);
            }
        }
        assert_eq!(fs::read(&record_path).expect("retained record"), bytes);
    }
}

/// # Panics
/// Panics if a production entry accepts changed custody or fails before the recorded check.
fn exercise_case(
    mut request: loop_home::CommandSpec,
    case: &str,
    record_path: &Path,
    bytes: &[u8],
    mode: &str,
) {
    use loop_home::{ProcessRunner, Runner};
    if case == "operation" {
        let source = request.argv.last_mut().expect("declaration");
        let mut manifest: Manifest = serde_json::from_str(source).expect("manifest");
        manifest.operation = "container-helper".into();
        *source = serde_json::to_string(&manifest).expect("changed operation");
    }
    if case == "program" {
        let flag = request
            .argv
            .iter()
            .position(|word| word == "--anchored-program")
            .expect("program binding");
        request.argv[flag + 1] = "/usr/bin/false".into();
    }
    if case == "record" {
        fs::write(record_path, b"{\"schema\":1,\"worker_uid\":3000}").expect("changed record");
    }
    if case == "missing" {
        request.descriptors = loop_home::CommandDescriptors::default();
    }
    let output = ProcessRunner.run(&request).expect("exercise entry");
    fs::write(record_path, bytes).expect("restore record");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(output.status, 0, "fixture lacks installed configuration");
    match case {
        "valid" => assert!(
            !report.contains("anchor-") && report.contains("unsafe-path"),
            "{mode} valid: {report}"
        ),
        "missing" => assert!(
            report.contains("anchor-transport"),
            "{mode} {case}: {report}"
        ),
        _ => assert!(
            report.contains("anchor-declaration"),
            "{mode} {case}: {report}"
        ),
    }
}

/// # Panics
/// Panics if the real namespace receiver cannot be launched with the selected override.
fn runtime_override(request: &loop_home::CommandSpec, registry: &Path) -> loop_home::CommandOutput {
    let start = std::time::Instant::now();
    let mut command = Command::new("/usr/bin/podman");
    command
        .args(&request.argv[1..])
        .env("ENTER_LOOP_REGISTRY", registry);
    request
        .descriptors
        .configure(&mut command)
        .expect("descriptor transport");
    let output = command.output().expect("runtime override entry");
    loop_home::CommandOutput {
        status: output.status.code().unwrap_or(1),
        stdout: output.stdout,
        stderr: output.stderr,
        wall: start.elapsed(),
    }
}
