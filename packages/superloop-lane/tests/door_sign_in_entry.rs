//! Drive canonical sign-in derivation through the production lane command and entry protocol.

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    root: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new_in("/tmp").expect("small protected executable fixture");
        let home = root.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("protected root");
        let uid = nix::unistd::Uid::effective().as_raw();
        let entry = home.join("entry");
        fs::write(&entry, format!(
            "#!/usr/bin/python3\nimport os, sys\nassert sys.argv[1] == 'enter' and sys.argv[3] == '--'\nos.environ['HOME'] = {} + '/.var/loops/' + sys.argv[2] + '/private'\nos.execv(sys.argv[4], sys.argv[4:])\n",
            serde_json::json!(home),
        )).expect("registered fixture entry");
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o700)).expect("entry mode");
        for loop_name in ["alpha", "beta"] {
            let config = home.join(".config/loops").join(loop_name);
            fs::create_dir_all(&config).expect("configuration");
            fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("config mode");
            let settings = config.join("workers.toml");
            fs::write(&settings, format!("entry_bin = '{}'\n", entry.display())).expect("settings");
            fs::set_permissions(settings, fs::Permissions::from_mode(0o600))
                .expect("settings mode");
            let private = home.join(".var/loops").join(loop_name).join("private");
            fs::create_dir_all(&private).expect("private home");
            fs::set_permissions(private, fs::Permissions::from_mode(0o700)).expect("private mode");
            let canonical = config.join("lanes/codex");
            fs::create_dir_all(&canonical).expect("canonical root");
            fs::set_permissions(config.join("lanes"), fs::Permissions::from_mode(0o700))
                .expect("protected source parent");
            fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700))
                .expect("canonical mode");
            fs::write(
                canonical.join("auth.json"),
                b"synthetic credential fixture only",
            )
            .expect("synthetic source");
            fs::set_permissions(
                canonical.join("auth.json"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("source mode");
        }
        for path in [
            ".config",
            ".config/loops",
            ".var",
            ".var/loops",
            ".var/loops/alpha",
            ".var/loops/beta",
        ] {
            fs::set_permissions(home.join(path), fs::Permissions::from_mode(0o700))
                .expect("protected ancestor");
        }
        fs::write(home.join(".config/loops/registry.toml"), format!(
            "namespace = 'org.superloop-tools.loophome.registry'\nversion = [1, 0, 0]\nloops = [{{name = 'alpha', uid = {uid}, launch = 'src'}}, {{name = 'beta', uid = {}, launch = 'src'}}]\n", uid + 1
        )).expect("two registered loop identities");
        let source = home.join(".config/loops/alpha/lanes/codex/auth.json");
        let destination = home.join(".var/loops/alpha/private/.codex/auth.json");
        Self {
            root,
            source,
            destination,
        }
    }

    fn call(&self, loop_name: &str, dry: bool) -> Output {
        self.call_digest(loop_name, dry, None)
    }

    fn call_digest(&self, loop_name: &str, dry: bool, digest: Option<&str>) -> Output {
        self.call_options(loop_name, dry, digest, &[])
    }

    fn call_options(
        &self,
        loop_name: &str,
        dry: bool,
        digest: Option<&str>,
        extra: &[&str],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-lane"));
        command
            .args(["door-sign-in", loop_name])
            .args(extra)
            .env("HOME", self.root.path())
            .env_remove("ENTER_LOOP_REGISTRY");
        if dry {
            command.arg("--dry-run");
        }
        if let Some(digest) = digest {
            command.args(["--expect-digest", digest]);
        }
        command.output().expect("production lane entry")
    }
}

/// ´test:integration:door-sign-in-stale-digest-preserves-both-credentials´
#[test]
fn door_sign_in_stale_digest_preserves_both_credentials() {
    let fixture = Fixture::new();
    let preview = report(&fixture.call("alpha", true));
    fs::write(&fixture.source, b"new synthetic credential").expect("source changes");
    let result = fixture.call_digest("alpha", false, preview["preview_sha256"].as_str());
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("door-sign-in-digest-mismatch"));
    assert!(fixture.source.exists());
    assert!(!fixture.destination.exists());
}

/// ´test:integration:door-sign-in-shares-round-lock-and-excludes-installation´
#[test]
fn door_sign_in_shares_round_lock_and_excludes_installation() {
    use nix::fcntl::{Flock, FlockArg};
    let fixture = Fixture::new();
    let config = fixture.root.path().join(".config/loops/alpha");
    let lock = Flock::lock(
        fs::File::open(&config).expect("config"),
        FlockArg::LockSharedNonblock,
    )
    .expect("round reader");
    report(&fixture.call("alpha", false));
    drop(lock);
    fs::write(&fixture.source, b"replacement").expect("source");
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o600)).expect("mode");
    let _lock = Flock::lock(
        fs::File::open(&config).expect("config"),
        FlockArg::LockExclusiveNonblock,
    )
    .expect("installation writer");
    let result = fixture.call("alpha", false);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("install-busy"));
    assert!(fixture.source.exists());
}

/// ´test:integration:door-sign-in-refuses-content-change-after-descriptor-handoff´
#[test]
fn door_sign_in_refuses_content_change_after_descriptor_handoff() {
    let fixture = Fixture::new();
    let entry = fixture.root.path().join("entry");
    let original = fs::read_to_string(&entry).expect("entry");
    let changed = original.replace("os.execv(sys.argv[4], sys.argv[4:])", &format!(
        "p = {}\ns = os.stat(p)\nwith open(p, 'r+b') as f: f.write(b'X' * s.st_size)\nos.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))\nos.execv(sys.argv[4], sys.argv[4:])",
        serde_json::json!(fixture.source)));
    assert_ne!(original, changed);
    fs::write(&entry, changed).expect("mutating entry");
    let result = fixture.call("alpha", false);
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("door-sign-in-source-changed-or-size")
    );
    assert!(fixture.source.exists());
    assert!(!fixture.destination.exists());
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic credential"));
    serde_json::from_slice(&output.stdout).expect("metadata report")
}

/// ´test:integration:door-sign-in-holds-canonical-refresh-lock-and-retains-source´
#[test]
fn door_sign_in_holds_canonical_refresh_lock_and_retains_source() {
    let fixture = Fixture::new();
    let before = fs::metadata(&fixture.source).expect("source metadata");
    let bytes = fs::read(&fixture.source).expect("synthetic source");
    let entry = fixture.root.path().join("entry");
    let original = fs::read_to_string(&entry).expect("entry");
    let lock = fixture
        .source
        .parent()
        .expect("canonical root")
        .join(".refresh.lock");
    let check = format!(
        "import fcntl\nf = open({}, 'r+')\ntry:\n fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n pass\nelse:\n raise SystemExit('canonical refresh lock was not held')\nos.execv(sys.argv[4], sys.argv[4:])",
        serde_json::json!(lock)
    );
    fs::write(
        &entry,
        original.replace("os.execv(sys.argv[4], sys.argv[4:])", &check),
    )
    .expect("lock-checking entry");
    for dry in [true, false] {
        assert_eq!(report(&fixture.call("alpha", dry))["source_removed"], false);
        assert_eq!(
            fs::metadata(&fixture.source).expect("source").ino(),
            before.ino()
        );
        assert_eq!(fs::read(&fixture.source).expect("synthetic source"), bytes);
    }
    let refusal = fixture.call_options(
        "alpha",
        false,
        None,
        &["--source", "/not-the-canonical-file"],
    );
    assert_eq!(refusal.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("door-sign-in-canonical-source"));
}

/// ´test:integration:door-sign-in-retains-content-changed-after-publication´
#[test]
fn door_sign_in_retains_content_changed_after_publication() {
    let fixture = Fixture::new();
    let entry = fixture.root.path().join("entry");
    let original = fs::read_to_string(&entry).expect("entry");
    let changed = original.replace("os.execv(sys.argv[4], sys.argv[4:])", &format!(
        "import subprocess\nr = subprocess.run(sys.argv[4:], stdout=subprocess.PIPE, check=True)\np = {}\ns = os.stat(p)\nwith open(p, 'r+b') as f: f.write(b'X' * s.st_size)\nos.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))\nos.write(1, r.stdout)",
        serde_json::json!(fixture.source)));
    assert_ne!(original, changed);
    fs::write(&entry, changed).expect("post-publication mutation");
    let result = fixture.call("alpha", false);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("source-changed-after-publication"));
    assert_eq!(
        fs::read(&fixture.destination).expect("published original"),
        b"synthetic credential fixture only"
    );
    assert!(
        fs::read(&fixture.source)
            .expect("changed source retained")
            .iter()
            .all(|byte| *byte == b'X')
    );
}

/// ´test:integration:door-sign-in-entry-previews-and-publishes-without-consuming-canonical-source´
#[test]
fn door_sign_in_entry_previews_and_publishes_without_consuming_canonical_source() {
    let fixture = Fixture::new();
    let metadata = || {
        superloop_lane::door::metadata::inspect(
            &fixture.root.path().join("entry"),
            fixture.root.path(),
            "alpha",
            &fixture.root.path().join("entry"),
        )
    };
    let before = metadata();
    assert_eq!(before["sign_in"]["exists"], false, "{before}");
    let preview = report(&fixture.call("alpha", true));
    assert_eq!(preview["destination"]["exists"], false);
    assert_eq!(preview["source_removed"], false);
    assert!(fixture.source.exists());
    assert!(!fixture.destination.parent().expect("parent").exists());
    let changed = report(&fixture.call_digest("alpha", false, preview["preview_sha256"].as_str()));
    assert_eq!(
        changed["destination"]["sha256"],
        preview["source"]["sha256"]
    );
    assert_eq!(
        changed["destination"]["byte_count"],
        preview["source"]["byte_count"]
    );
    assert_eq!(changed["destination"]["published"], true);
    assert_eq!(changed["destination"]["mode"], "0600");
    assert_eq!(
        changed["destination"]["owner_uid"],
        nix::unistd::Uid::effective().as_raw()
    );
    assert_eq!(changed["source_removed"], false);
    assert!(fixture.source.exists());
    assert_eq!(metadata()["sign_in"]["usable"], true);
    assert_eq!(metadata()["executable_status"]["usable"], true);
    assert_eq!(
        fs::read(&fixture.destination).expect("synthetic destination"),
        b"synthetic credential fixture only"
    );
    assert_eq!(
        fs::metadata(&fixture.destination).expect("metadata").mode() & 0o777,
        0o600
    );
    fs::write(&fixture.source, b"synthetic replacement").expect("canonical replacement");
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o600)).expect("mode");
    let existing = report(&fixture.call("alpha", true));
    assert_eq!(existing["destination"]["exists"], true);
    assert!(fixture.source.exists());
}

/// ´test:integration:door-sign-in-entry-traverses-search-only-destination-ancestor´
#[test]
fn door_sign_in_entry_traverses_search_only_destination_ancestor() {
    let fixture = Fixture::new();
    let config = fixture
        .destination
        .parent()
        .expect("configuration directory");
    fs::create_dir(config).expect("existing destination configuration");
    fs::set_permissions(config, fs::Permissions::from_mode(0o700)).expect("config mode");
    fs::write(&fixture.destination, b"previous synthetic credential")
        .expect("existing destination");
    fs::set_permissions(&fixture.destination, fs::Permissions::from_mode(0o600))
        .expect("destination mode");
    let ancestor = fixture.root.path().join(".var/loops/alpha");
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o311))
        .expect("search-only destination ancestor");
    let listing = fs::read_dir(&ancestor);
    let preview = fixture.call("alpha", true);
    let source_retained = fixture.source.exists();
    let preview_bytes = fs::read(&fixture.destination).expect("destination after preview");
    let changed = fixture.call("alpha", false);
    // Restore directory listing for TempDir cleanup before asserting either command's output.
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).expect("restore ancestor");
    assert_eq!(
        listing.expect_err("caller cannot read ancestor").kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let preview = report(&preview);
    assert_eq!(
        preview["destination"]["path"],
        fixture.destination.to_str().expect("path")
    );
    assert_eq!(preview["destination"]["exists"], true);
    assert_eq!(preview["destination"]["mode"], "0600");
    let uid = nix::unistd::Uid::effective().as_raw();
    assert_eq!(preview["destination"]["owner_uid"], uid);
    assert_eq!(preview["destination"]["loop_uid"], uid);
    assert_eq!(preview["destination"]["published"], false);
    assert_eq!(preview["source_removed"], false);
    assert!(source_retained);
    assert_eq!(preview_bytes, b"previous synthetic credential");
    let changed = report(&changed);
    assert_eq!(changed["destination"]["published"], true);
    assert_eq!(changed["destination"]["mode"], "0600");
    assert_eq!(changed["destination"]["owner_uid"], uid);
    assert_eq!(changed["destination"]["loop_uid"], uid);
    assert_eq!(changed["source_removed"], false);
    assert!(fixture.source.exists());
    assert_eq!(
        fs::read(&fixture.destination).expect("published destination"),
        b"synthetic credential fixture only"
    );
}

/// ´test:integration:door-sign-in-entry-refuses-other-loop-uid-and-retains-source´
#[test]
fn door_sign_in_entry_refuses_other_loop_uid_and_retains_source() {
    let fixture = Fixture::new();
    for dry in [true, false] {
        let result = fixture.call("beta", dry);
        assert_eq!(result.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("door-sign-in-entry-identity"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(fixture.source.exists());
        assert!(!fixture.destination.exists());
    }
}

/// ´test:integration:door-sign-in-entry-refuses-linked-custody-without-consuming-source´
#[test]
fn door_sign_in_entry_refuses_linked_custody_without_consuming_source() {
    let fixture = Fixture::new();
    let parent = fixture.destination.parent().expect("parent");
    symlink(fixture.root.path().join("scratch"), parent).expect("linked destination");
    assert_eq!(fixture.call("alpha", false).status.code(), Some(2));
    assert!(fixture.source.exists());
    fs::remove_file(parent).expect("unlink destination");
    let saved = fixture.source.with_extension("saved");
    fs::rename(&fixture.source, &saved).expect("save source");
    symlink(&saved, &fixture.source).expect("linked source");
    assert_eq!(fixture.call("alpha", false).status.code(), Some(2));
    assert!(saved.exists());
    assert!(!fixture.destination.exists());
}

/// ´test:integration:door-sign-in-entry-binds-source-and-retains-a-replacement´
#[test]
fn door_sign_in_entry_binds_source_and_retains_a_replacement() {
    let fixture = Fixture::new();
    let entry = fixture.root.path().join("entry");
    let original = fs::read_to_string(&entry).expect("entry");
    let changed = original.replace("os.execv(sys.argv[4], sys.argv[4:])", &format!(
        "os.rename({0}, {1})\nwith open({0}, 'w') as f: f.write('replacement scratch source')\nos.chmod({0}, 0o600)\nos.execv(sys.argv[4], sys.argv[4:])",
        serde_json::json!(fixture.source), serde_json::json!(fixture.source.with_extension("original"))));
    assert_ne!(original, changed);
    fs::write(&entry, changed).expect("entry replaces source after descriptor handoff");
    let output = fixture.call("alpha", false);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("source-changed-after-publication"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(&fixture.source).expect("replacement retained"),
        b"replacement scratch source"
    );
    assert_eq!(
        fs::read(&fixture.destination).expect("bound source published"),
        b"synthetic credential fixture only"
    );
}
