//! Exercise the production mail launcher and receiver under a real partial UID map.
use loop_home::anchor::{HostVerifier, Kind, Manifest, ModePolicy, Owner, Policy, Transport};
use std::ffi::OsString;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_superloop-mail")
}
fn namespace() -> Vec<OsString> {
    ["/usr/bin/unshare", "--user", "--map-root-user"]
        .map(OsString::from)
        .to_vec()
}
fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("fixture");
    for path in [
        root.path().to_owned(),
        root.path().join(".config"),
        root.path().join(".config/loops"),
    ] {
        fs::create_dir_all(&path).expect("directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for (name, source) in [
        (
            "registry.toml",
            "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{ name = 'alpha', uid = 41001, launch = 'dev/alpha' }]\n",
        ),
        ("allocations.toml", "mail_uid = 42000\n"),
        (
            "mail-service.toml",
            "version=1\nuid=42000\ncrash_consistent_rename=true\ndurable_sync=true\n",
        ),
    ] {
        let path = root.path().join(".config/loops").join(name);
        fs::write(&path, source).expect("configuration");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private file");
    }
    root
}
fn refusal(output: Output, name: &str) -> String {
    let error = String::from_utf8(output.stderr).expect("diagnostic");
    assert_eq!(
        output.status.code(),
        Some(2),
        "named refusal status: {error}"
    );
    assert!(error.contains(name), "expected {name}: {error}");
    error
}
fn partial_map() {
    let result = Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "/usr/bin/python3",
            "-I",
            "-c",
            r"
import os
with open('/proc/self/uid_map') as source:
    rows = [tuple(map(int, line.split())) for line in source]
with open('/proc/sys/kernel/overflowuid') as source:
    overflow = int(source.read())
assert rows != [(0, 0, 2**32 - 1)]
assert os.geteuid() == 0 and os.stat('/').st_uid == overflow
",
        ])
        .output()
        .expect("namespace probe");
    assert!(
        result.status.success(),
        "unmeasured: partial user namespace with overflow root unavailable: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn launch(home: &Path) -> Command {
    loop_home::mail::command::serve_command(home, Path::new(binary()), &namespace())
        .expect("production host launcher")
}
fn private(home: &Path) -> Command {
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args(["--user", "--map-root-user", binary(), "_serve"])
        .arg(home);
    command
}

/// # Panics
/// Panics on unavailable namespaces (unmeasured), or an unexpected production endpoint.
/// ´claim:superloop:mail-entry-holds-configuration-across-a-partial-map´
/// ´test:integration:mail-entry-holds-configuration-across-a-partial-map´
#[test]
fn mail_entry_holds_configuration_across_a_partial_map() {
    partial_map();
    let home = fixture();
    let control = Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            binary(),
            "_serve",
            "--check-ancestry",
        ])
        .arg(home.path())
        .output()
        .expect("unanchored control");
    let error = refusal(control, "ancestor-unmapped-uid: /:");
    assert!(error.contains("unmapped or ambiguous ancestor uid"));
    let outside = Command::new(binary())
        .args(["_serve", "--check-ancestry"])
        .arg(home.path())
        .output()
        .expect("outside control");
    assert!(
        outside.status.success(),
        "{}",
        String::from_utf8_lossy(&outside.stderr)
    );
    let error = refusal(
        launch(home.path()).output().expect("anchored entry"),
        "mail-identity-drop:",
    );
    assert!(!error.contains("namespace-root entry required"));
    let mut command = launch(home.path());
    fs::rename(
        home.path().join(".config/loops"),
        home.path().join("configuration-moved"),
    )
    .expect("rename configuration");
    refusal(
        command.output().expect("held configuration entry"),
        "mail-identity-drop:",
    );
    assert!(
        !home.path().join(".var").exists(),
        "identity-drop endpoint precedes mutation"
    );
}

fn raw(home: &Path, change: impl FnOnce(&mut Manifest, &mut Vec<OwnedFd>)) -> Command {
    let host = HostVerifier::current().expect("host map");
    let config = host
        .pin(
            &home.join(".config/loops"),
            "configuration",
            0,
            Policy {
                kind: Kind::Directory,
                owner: Owner::Host,
                mode: ModePolicy::Exact(0o700),
            },
        )
        .expect("configuration");
    let entry = host
        .pin(
            Path::new(binary()),
            "entry-executable",
            1,
            Policy {
                kind: Kind::File,
                owner: Owner::Host,
                mode: ModePolicy::Executable,
            },
        )
        .expect("fixture executable");
    let mut manifest = Manifest {
        version: 1,
        transport: Transport::Rights,
        operation: "mail-serve".into(),
        loop_name: String::new(),
        records: vec![config.record(), entry.record()],
    };
    let mut fds = vec![config.into_fd(), entry.into_fd()];
    change(&mut manifest, &mut fds);
    let (sender, receiver) = UnixStream::pair().expect("handoff");
    loop_home::anchor::transport::send(&sender, &fds).expect("rights");
    drop(sender);
    let input: OwnedFd = receiver.into();
    let mut command = private(home);
    command
        .arg("--anchor-manifest")
        .arg(serde_json::to_string(&manifest).expect("manifest"))
        .stdin(input);
    command
}

fn substituted_entry(home: &Path) -> Command {
    let other = home.join("other-entry");
    fs::copy(binary(), &other).expect("different entry inode");
    fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).expect("entry mode");
    raw(home, |manifest, descriptors| {
        let pin = HostVerifier::current()
            .expect("host")
            .pin(
                &other,
                "entry-executable",
                1,
                Policy {
                    kind: Kind::File,
                    owner: Owner::Host,
                    mode: ModePolicy::Executable,
                },
            )
            .expect("other entry");
        manifest.records[1] = pin.record();
        descriptors[1] = pin.into_fd();
    })
}

/// # Panics
/// Panics if a malformed private handoff acquires configuration authority.
/// ´claim:superloop:mail-entry-refuses-missing-substituted-and-misdeclared-anchors´
/// ´test:integration:mail-entry-refuses-missing-substituted-and-misdeclared-anchors´
#[test]
fn mail_entry_refuses_missing_substituted_and_misdeclared_anchors() {
    partial_map();
    let home = fixture();
    refusal(
        private(home.path()).output().expect("missing bundle"),
        "anchor-missing:",
    );
    refusal(
        raw(home.path(), |manifest, _| {
            manifest.operation = "other".into();
        })
        .output()
        .expect("wrong operation"),
        "anchor-declaration:",
    );
    refusal(
        raw(home.path(), |manifest, _| manifest.records[0].inode += 1)
            .output()
            .expect("changed identity"),
        "anchor-identity:",
    );
    refusal(
        raw(home.path(), |manifest, _| {
            manifest.records[0].owner_uid += 1;
        })
        .output()
        .expect("wrong owner"),
        "anchor-owner:",
    );
    refusal(
        raw(home.path(), |_, fds| {
            fds[0] = fs::File::open(home.path().join(".config/loops/mail-service.toml"))
                .expect("wrong kind")
                .into();
        })
        .output()
        .expect("file in directory slot"),
        "anchor-kind:",
    );
    refusal(
        substituted_entry(home.path())
            .output()
            .expect("different running executable"),
        "anchor-identity:",
    );
    let mut missing = launch(home.path());
    missing.stdin(Stdio::null());
    refusal(
        missing.output().expect("missing rights socket"),
        "anchor-missing:",
    );
    for name in ["registry.toml", "allocations.toml", "mail-service.toml"] {
        let absent = fixture();
        let mut command = launch(absent.path());
        fs::remove_file(absent.path().join(".config/loops").join(name)).expect("remove input");
        refusal(
            command.output().expect("missing configuration input"),
            "anchor-missing:",
        );
    }
    let replacement = fixture();
    refusal(
        raw(home.path(), |_, fds| {
            fds[0] = HostVerifier::current()
                .expect("host")
                .pin(
                    &replacement.path().join(".config/loops"),
                    "configuration",
                    0,
                    Policy {
                        kind: Kind::Directory,
                        owner: Owner::Host,
                        mode: ModePolicy::Exact(0o700),
                    },
                )
                .expect("replacement")
                .into_fd();
        })
        .output()
        .expect("substitution"),
        "anchor-identity:",
    );
    let mut command = launch(home.path());
    fs::set_permissions(
        home.path().join(".config/loops"),
        fs::Permissions::from_mode(0o750),
    )
    .expect("unsafe mode");
    refusal(command.output().expect("wrong mode"), "anchor-mode:");
}

/// # Panics
/// Panics if a relative escape or a settings link reaches service entry.
/// ´claim:superloop:mail-entry-refuses-configuration-escapes´
/// ´test:integration:mail-entry-refuses-configuration-escapes´
#[test]
fn mail_entry_refuses_configuration_escapes() {
    partial_map();
    let home = fixture();
    let parent = home
        .path()
        .join("..")
        .join(home.path().file_name().expect("fixture name"));
    let error = loop_home::mail::command::serve_command(&parent, Path::new(binary()), &namespace())
        .expect_err("parent escape");
    assert!(error.to_string().contains("anchor-escape:"), "{error}");
    let mut command = launch(home.path());
    let settings = home.path().join(".config/loops/mail-service.toml");
    let outside: PathBuf = home.path().join("outside-settings");
    fs::rename(&settings, &outside).expect("move settings");
    symlink(&outside, &settings).expect("link");
    refusal(command.output().expect("linked settings"), "anchor-escape:");
}
