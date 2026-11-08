use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    temporary: tempfile::TempDir,
    store: PathBuf,
    source: PathBuf,
    manifest: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix("capture-contract-")
            .tempdir_in(std::env::var_os("TMPDIR").expect("TMPDIR required"))
            .unwrap();
        let store = temporary.path().join("store");
        let source = temporary.path().join("source");
        let manifest = temporary.path().join("manifest");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/data"), b"capture bytes").unwrap();
        fs::write(
            &manifest,
            format!(
                "format=fictional\n{} 13 nested/data\n",
                hex(&Sha256::digest(b"capture bytes"))
            ),
        )
        .unwrap();
        Self {
            temporary,
            store,
            source,
            manifest,
        }
    }
    fn run(&self, command: &str, extra: &[&str]) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_superloop-capture-admit"));
        process.arg(command).arg("--store").arg(&self.store);
        if command == "admit" {
            process
                .arg("--source")
                .arg(&self.source)
                .arg("--manifest")
                .arg(&self.manifest);
        }
        process.args(extra).output().unwrap()
    }
    fn admit(&self, name: &str) {
        success(&self.run("admit", &["--name", name]));
    }
    fn lease(&self, file: &str, name: &str, expiry: &str) {
        fs::write(
            self.store.join("leases").join(file),
            format!("identity={name}\nholder=fictional-reader\nexpiry={expiry}\n"),
        )
        .unwrap();
    }
    fn refused(&self, extra: &[&str], cause: &str) {
        let before = snapshot(&self.store);
        let output = self.run("admit", extra);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(cause),
            "{output:?}"
        );
        assert_eq!(before, snapshot(&self.store));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .last()
                .unwrap()
                .starts_with("wall=")
        );
    }
}
fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap()
            .starts_with("wall=")
    );
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let bytes = if meta.is_symlink() {
            fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else if meta.is_file() {
            fs::read(path).unwrap()
        } else {
            Vec::new()
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            (meta.permissions().mode() & 0o7777, bytes),
        );
        if meta.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:admission-modes-receipt-and-same-identity-noop´
#[test]
fn admission_modes_receipt_and_same_identity_noop() {
    let f = Fixture::new();
    f.admit("first");
    let root = &f.store;
    assert_eq!(
        fs::read(root.join("current/nested/data")).unwrap(),
        b"capture bytes"
    );
    for (name, mode) in [
        ("generations/first", 0o755),
        ("generations/first/nested", 0o755),
        ("generations/first/nested/data", 0o644),
        ("leases", 0o770),
        (".incoming", 0o700),
    ] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o7777,
            mode
        );
    }
    assert_eq!(fs::read_dir(root.join(".incoming")).unwrap().count(), 0);
    let digest = hex(&Sha256::digest(fs::read(&f.manifest).unwrap()));
    assert_eq!(
        fs::read_to_string(root.join("receipts/first.receipt")).unwrap(),
        format!("format=fictional\nname=first\ndigest={digest}\nfiles=1\nbytes=13\n")
    );
    let before = snapshot(root);
    let out = f.run("admit", &["--name", "first"]);
    success(&out);
    assert!(out.stdout.starts_with(b"already-sealed\n"));
    assert_eq!(before, snapshot(root));
    fs::write(&f.manifest, b"other=header\n").unwrap();
    f.refused(&["--name", "first"], "identity-conflict");
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:manifest-and-copy-refusals-leave-store-unchanged´
#[test]
fn manifest_and_copy_refusals_leave_store_unchanged() {
    for kind in [
        "digest",
        "size",
        "missing",
        "extra",
        "symlink",
        "parent",
        "malformed",
        "blank",
        "duplicate",
        "directory",
        "quota",
    ] {
        let f = Fixture::new();
        f.admit("seed");
        let original = fs::read_to_string(&f.manifest).unwrap();
        match kind {
            "digest" => {
                fs::write(&f.manifest, format!("{} 13 nested/data\n", "0".repeat(64))).unwrap();
            }
            "size" => fs::write(&f.manifest, original.replace(" 13 ", " 12 ")).unwrap(),
            "missing" => fs::remove_file(f.source.join("nested/data")).unwrap(),
            "extra" => fs::write(f.source.join("extra"), b"extra").unwrap(),
            "symlink" => {
                fs::remove_file(f.source.join("nested/data")).unwrap();
                symlink(&f.manifest, f.source.join("nested/data")).unwrap();
            }
            "parent" => fs::write(&f.manifest, original.replace("nested/data", "../data")).unwrap(),
            "malformed" => fs::write(&f.manifest, b"# comment\n").unwrap(),
            "blank" => fs::write(&f.manifest, b"\n").unwrap(),
            "duplicate" => fs::write(
                &f.manifest,
                format!("{original}{}", original.lines().nth(1).unwrap()),
            )
            .unwrap(),
            "directory" => {
                fs::remove_file(f.source.join("nested/data")).unwrap();
                fs::create_dir(f.source.join("nested/data")).unwrap();
            }
            "quota" => (),
            _ => unreachable!(),
        }
        let before = snapshot(&f.store);
        let args = if kind == "quota" {
            vec!["--name", "next", "--quota-bytes", "25"]
        } else {
            vec!["--name", "next"]
        };
        let out = f.run("admit", &args);
        assert!(!out.status.success(), "{kind}");
        assert_eq!(before, snapshot(&f.store), "{kind}");
    }
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:first-use-refusal-and-wrong-root-mode-do-not-mutate´
#[test]
fn first_use_refusal_and_wrong_root_mode_do_not_mutate() {
    let f = Fixture::new();
    fs::write(&f.manifest, b"bad\n").unwrap();
    f.refused(&["--name", "first"], "malformed-manifest");
    f.refused(&["--name", "../escape"], "invalid-name");
    let usage = f.run("admit", &["--name", "../escape"]);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    fs::set_permissions(&f.store, fs::Permissions::from_mode(0o755)).unwrap();
    f.refused(&["--name", "first"], "store-owner-or-mode");
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:keep-and-leases-protect-exactly-their-generations´
#[test]
fn keep_and_leases_protect_exactly_their_generations() {
    let f = Fixture::new();
    f.admit("kept");
    success(&f.run("admit", &["--name", "leased", "--keep-previous"]));
    f.admit("expired");
    f.admit("discard");
    f.admit("current");
    assert_eq!(fs::read(f.store.join("keep")).unwrap(), b"kept\n");
    f.lease("live.lease", "leased", "9999-01-01T00:00:00.123Z");
    f.lease("old.lease", "expired", "2000-01-01T00:00:00+00:00");
    let selector = fs::read_link(f.store.join("current")).unwrap();
    let out = f.run("prune", &[]);
    success(&out);
    for name in ["kept", "leased", "current"] {
        assert!(f.store.join("generations").join(name).is_dir());
    }
    for name in ["expired", "discard"] {
        assert!(!f.store.join("generations").join(name).exists());
        assert!(
            !f.store
                .join("receipts")
                .join(format!("{name}.receipt"))
                .exists()
        );
    }
    assert!(!f.store.join("leases/old.lease").exists());
    assert!(f.store.join("leases/live.lease").exists());
    assert_eq!(selector, fs::read_link(f.store.join("current")).unwrap());
    assert!(String::from_utf8_lossy(&out.stdout).contains("removed=2\nbytes=26\n"));
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:malformed-lease-refuses-before-any-prune-or-expired-removal´
#[test]
fn malformed_lease_refuses_before_any_prune_or_expired_removal() {
    let f = Fixture::new();
    f.admit("first");
    f.admit("current");
    f.lease("expired.lease", "first", "2000-01-01T00:00:00Z");
    for bad in [
        "bad\n",
        "identity=first\nholder=reader\nexpiry=2026-02-30T00:00:00Z\n",
        "identity=../outside\nholder=reader\nexpiry=9999-01-01T00:00:00Z\n",
    ] {
        fs::write(f.store.join("leases/bad.lease"), bad).unwrap();
        let before = snapshot(&f.store);
        let out = f.run("prune", &[]);
        assert!(!out.status.success());
        assert_eq!(before, snapshot(&f.store));
    }
}
/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:symlink-ancestor-and-foreign-lease-file-refuse´
#[test]
fn symlink_ancestor_and_foreign_lease_file_refuse() {
    let f = Fixture::new();
    f.admit("first");
    fs::rename(f.source.join("nested"), f.temporary.path().join("outside")).unwrap();
    symlink(f.temporary.path().join("outside"), f.source.join("nested")).unwrap();
    f.refused(&["--name", "next"], "");
    symlink(&f.manifest, f.store.join("leases/reader.lease")).unwrap();
    let before = snapshot(&f.store);
    assert!(!f.run("prune", &[]).status.success());
    assert_eq!(before, snapshot(&f.store));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::new();
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:opaque-headers-empty-manifest-and-unreadable-file´
#[test]
fn opaque_headers_empty_manifest_and_unreadable_file() {
    let f = Fixture::new();
    let original = fs::read(&f.manifest).unwrap();
    let mut bytes = b"opaque=\xff\0\n".to_vec();
    bytes.extend(original);
    fs::write(&f.manifest, &bytes).unwrap();
    f.admit("opaque");
    assert!(
        fs::read(f.store.join("receipts/opaque.receipt"))
            .unwrap()
            .starts_with(b"opaque=\xff\0\n")
    );
    fs::set_permissions(
        f.source.join("nested/data"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    f.refused(&["--name", "unreadable"], "Permission denied");
    fs::set_permissions(
        f.source.join("nested/data"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::remove_dir_all(f.source.join("nested")).unwrap();
    fs::write(&f.manifest, b"").unwrap();
    f.admit("empty");
    assert!(
        fs::read_to_string(f.store.join("receipts/empty.receipt"))
            .unwrap()
            .ends_with("files=0\nbytes=0\n")
    );
}

/// # Panics
/// Panics if fixture setup fails or the production command violates the asserted contract.
/// ´test:integration:legal-generation-names-do-not-collide-with-staging-and-busy-store-refuses´
#[test]
fn legal_generation_names_do_not_collide_with_staging_and_busy_store_refuses() {
    let f = Fixture::new();
    f.admit("receipt");
    f.admit("keep");
    f.admit(".receipt");
    let lock = nix::fcntl::Flock::lock(
        fs::File::open(&f.store).unwrap(),
        nix::fcntl::FlockArg::LockExclusive,
    )
    .unwrap();
    f.refused(&["--name", "blocked"], "store-busy");
    drop(lock);
}

/// # Panics
/// Panics if fixture setup fails or the quota hint disagrees with protected bytes.
/// ´test:integration:quota-hint-names-reclaimable-generations-and-sufficiency´
#[test]
fn quota_hint_names_reclaimable_generations_and_sufficiency() {
    let f = Fixture::new();
    f.admit("first");
    f.admit("second");
    f.admit("current");
    f.refused(
        &["--name", "candidate", "--quota-bytes", "26"],
        "prune candidates=first,second reclaimable=26 sufficient=true",
    );
    f.refused(
        &["--name", "candidate", "--quota-bytes", "12"],
        "sufficient=false",
    );
}

/// # Panics
/// Panics if fixture setup fails or the byte paths and streamed payload differ.
/// ´test:integration:byte-paths-and-multiple-copy-chunks-are-preserved´
#[test]
fn byte_paths_and_multiple_copy_chunks_are_preserved() {
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    let f = Fixture::new();
    let payload = vec![0xa5; 131_073];
    fs::write(f.source.join("large part"), &payload).unwrap();
    let raw_name = std::ffi::OsStr::from_bytes(b"\xff");
    fs::write(f.source.join(raw_name), b"").unwrap();
    let mut manifest = fs::read(&f.manifest).unwrap();
    writeln!(
        manifest,
        "{} {} large part",
        hex(&Sha256::digest(&payload)),
        payload.len()
    )
    .unwrap();
    write!(manifest, "{} 0 ", hex(&Sha256::digest(b""))).unwrap();
    manifest.extend_from_slice(b"\xff\n");
    fs::write(&f.manifest, manifest).unwrap();
    f.admit("bytes");
    assert_eq!(
        fs::read(f.store.join("current/large part")).unwrap(),
        payload
    );
    assert!(f.store.join("current").join(raw_name).is_file());
    assert!(
        fs::read_to_string(f.store.join("receipts/bytes.receipt"))
            .unwrap()
            .ends_with("files=3\nbytes=131086\n")
    );
}
