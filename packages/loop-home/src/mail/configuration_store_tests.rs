use super::*;
use crate::mail::configuration::{Worker, WorkerState};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
struct Fixture {
    root: PathBuf,
    private: PathBuf,
    service: u32,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mail-birth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
        let private = root.join("private");
        fs::create_dir(&private).expect("private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("private mode");
        Self {
            root,
            private,
            service: nix::unistd::geteuid().as_raw() + 1,
        }
    }
    fn open(&self) -> ConfigurationStore {
        ConfigurationStore::open(&self.private, self.service).expect("loop configuration")
    }
    fn path(&self) -> PathBuf {
        ConfigurationStore::path(&self.private)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.root);
    }
}

/// ´claim:loophome:mail-birth-creates-explicit-empty-configuration-and-preserves-valid-retries´
/// ´test:unit:mail-birth-creates-explicit-empty-configuration-and-preserves-valid-retries´
#[test]
fn mail_birth_creates_explicit_empty_configuration_and_preserves_valid_retries() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    assert!(store.configuration.workers.is_empty());
    assert!(store.configuration.mail.allow.is_empty());
    let source = fs::read_to_string(fixture.path()).expect("explicit source");
    assert!(source.contains("workers = []"));
    assert!(source.contains("allow = []"));
    store.configuration.workers.push(Worker {
        name: "retained".into(),
        state: WorkerState::Retired,
    });
    store.configuration.other.insert(
        "private-preference".into(),
        toml::Value::String("retained".into()),
    );
    store.publish().expect("publish full snapshot");
    drop(store);
    let before = fs::read(fixture.path()).expect("before retry");
    let store = fixture.open();
    assert_eq!(store.configuration.workers[0].name, "retained");
    assert_eq!(fs::read(fixture.path()).expect("after retry"), before);
    acl::verify(
        &File::open(fixture.path()).expect("configuration"),
        fixture.service,
        false,
    )
    .expect("file-only read grant");
}

/// ´claim:loophome:mail-configuration-loss-never-resets-retained-worker-names´
/// ´test:unit:mail-configuration-loss-never-resets-retained-worker-names´
#[test]
fn mail_configuration_loss_never_resets_retained_worker_names() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.configuration.workers.push(Worker {
        name: "reserved".into(),
        state: WorkerState::Retired,
    });
    store.publish().expect("reserve name");
    drop(store);
    fs::remove_file(fixture.path()).expect("lost primary");
    assert!(ConfigurationStore::open(&fixture.private, fixture.service).is_err());
    assert!(!fixture.path().exists());
    let other = Fixture::new();
    fs::create_dir(other.root.join("workers")).expect("prior worker homes");
    assert!(ConfigurationStore::open(&other.private, other.service).is_err());
    assert!(!other.path().exists());
}

/// ´claim:loophome:mail-configuration-writers-preserve-each-others-reservations´
/// ´test:unit:mail-configuration-writers-preserve-each-others-reservations´
#[test]
fn mail_configuration_writers_preserve_each_others_reservations() {
    let fixture = Fixture::new();
    let mut first = fixture.open();
    let private = fixture.private.clone();
    let service = fixture.service;
    let second = std::thread::spawn(move || {
        let mut store =
            ConfigurationStore::open(&private, service).expect("serialized second writer");
        assert!(
            store
                .configuration
                .workers
                .iter()
                .any(|worker| worker.name == "first")
        );
        store.configuration.workers.push(Worker {
            name: "second".into(),
            state: WorkerState::Retired,
        });
        store.publish().expect("second reservation");
    });
    first.configuration.workers.push(Worker {
        name: "first".into(),
        state: WorkerState::Retired,
    });
    first.publish().expect("first reservation");
    drop(first);
    second.join().expect("writer completed");
    let store = fixture.open();
    assert_eq!(store.configuration.workers.len(), 2);
}

/// ´claim:loophome:root-mode-correction-preserves-mail-search-acl-and-queued-bytes´
/// ´test:unit:root-mode-correction-preserves-mail-search-acl-and-queued-bytes´
#[test]
fn root_mode_correction_preserves_mail_search_acl_and_queued_bytes() {
    let fixture = Fixture::new();
    let home = fixture.root.join("owner");
    fs::create_dir(&home).expect("home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("home mode");
    for name in [".var", ".cache", ".config"] {
        let path = home.join(name);
        fs::create_dir(&path).expect("class root");
        fs::set_permissions(path, fs::Permissions::from_mode(0o711)).expect("class mode");
    }
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    crate::ensure::ensure_roots(
        &crate::ensure::standard_roots(&home, "alpha"),
        (uid, gid),
        (uid, gid),
        &mut Vec::new(),
    )
    .expect("initial roots");
    let private = home.join(".var/loops/alpha/private");
    drop(ConfigurationStore::open(&private, fixture.service).expect("configuration"));
    let queued = private.join("queued-fixture");
    fs::write(&queued, b"opaque\0bytes").expect("existing bytes");
    for path in [&private, &private.join(".config")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o711))
            .expect("mode needs correction");
    }
    crate::ensure::ensure_roots(
        &crate::ensure::standard_roots(&home, "alpha"),
        (uid, gid),
        (uid, gid),
        &mut Vec::new(),
    )
    .expect("repeat ensure");
    for path in [&private, &private.join(".config")] {
        acl::verify(&File::open(path).expect("ancestor"), fixture.service, true)
            .expect("effective search grant survives correction");
    }
    assert_eq!(fs::read(queued).expect("preserved bytes"), b"opaque\0bytes");
}

/// ´claim:loophome:mail-configuration-replacement-rechecks-ancestor-grants´
/// ´test:unit:mail-configuration-replacement-rechecks-ancestor-grants´
#[test]
fn mail_configuration_replacement_rechecks_ancestor_grants() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let before = fs::read(fixture.path()).expect("prior source");
    fs::set_permissions(&fixture.private, fs::Permissions::from_mode(0o700))
        .expect("lost effective grant");
    store.configuration.workers.push(Worker {
        name: "reserved".into(),
        state: WorkerState::Retired,
    });
    assert!(store.publish().is_err());
    assert_eq!(fs::read(fixture.path()).expect("unchanged source"), before);
}

/// ´claim:loophome:mail-configuration-preview-never-creates-or-repairs-state´
/// ´test:unit:mail-configuration-preview-never-creates-or-repairs-state´
#[test]
fn mail_configuration_preview_never_creates_or_repairs_state() {
    use std::os::unix::fs::MetadataExt as _;
    let fixture = Fixture::new();
    acl::install(
        &File::open(&fixture.private).unwrap(),
        fixture.service,
        true,
    )
    .unwrap();
    assert!(ConfigurationStore::open_existing(&fixture.private, fixture.service).is_err());
    assert!(!fixture.private.join(".config").exists());
    drop(fixture.open());
    let paths = [
        fixture.private.clone(),
        fixture.private.join(".config"),
        fixture.private.join(".config/mail"),
        fixture.private.join(".config/mail/loop.lock"),
        fixture.path(),
    ];
    let stamp = |path: &PathBuf| {
        let info = fs::metadata(path).expect("metadata");
        (
            info.dev(),
            info.ino(),
            info.mode(),
            info.ctime(),
            info.ctime_nsec(),
        )
    };
    let before = paths.each_ref().map(stamp);
    let bytes = fs::read(fixture.path()).unwrap();
    drop(
        ConfigurationStore::open_existing(&fixture.private, fixture.service)
            .expect("existing state"),
    );
    assert_eq!(paths.each_ref().map(stamp), before);
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    for path in [&paths[0], &paths[1], &paths[2], &paths[4]] {
        let nominal = if path == &paths[4] { 0o600 } else { 0o700 };
        fs::set_permissions(path, fs::Permissions::from_mode(nominal)).unwrap();
        let before = stamp(path);
        assert!(ConfigurationStore::open_existing(&fixture.private, fixture.service).is_err());
        assert_eq!(stamp(path), before);
        acl::install(
            &File::open(path).unwrap(),
            fixture.service,
            path != &paths[4],
        )
        .unwrap();
    }
    fs::remove_file(&paths[3]).unwrap();
    assert!(ConfigurationStore::open_existing(&fixture.private, fixture.service).is_err());
    assert!(!paths[3].exists());
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
}
