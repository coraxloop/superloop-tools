use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
struct Fixture {
    root: PathBuf,
    service: u32,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mail-worker-birth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("fixture");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("fixture mode");
        let private = root.join("private");
        fs::create_dir(&private).expect("private");
        fs::set_permissions(private, fs::Permissions::from_mode(0o700)).expect("private mode");
        Self {
            root,
            service: nix::unistd::Uid::effective().as_raw() + 1,
        }
    }
    fn open(&self) -> ConfigurationStore {
        ConfigurationStore::open(&self.root.join("private"), self.service)
            .expect("loop-owned configuration")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.root);
    }
}
fn identity(name: &str, uid: u32) -> Identity {
    Identity {
        name: name.into(),
        uid,
        reservation: format!("fixture:{uid}"),
    }
}

/// ´claim:loophome:worker-birth-retains-interrupted-and-retired-identities´
/// ´test:unit:worker-birth-retains-interrupted-and-retired-identities´
#[test]
fn worker_birth_retains_interrupted_and_retired_identities() {
    let fixture = Fixture::new();
    let first = identity("worker-3000", 3000);
    let mut store = fixture.open();
    reserve(&mut store, &first).expect("reserve before home");
    assert_eq!(store.configuration.workers[0].state, WorkerState::Retired);
    assert!(verify(&store, &first).is_err());
    drop(store);
    let mut store = fixture.open();
    reserve(&mut store, &first).expect("interrupted birth retry");
    activate(&mut store, &first).expect("complete endpoint");
    verify(&store, &first).expect("ready binding");
    drop(store);
    let mut store = fixture.open();
    reserve(&mut store, &first).expect("resume preserves identity");
    activate(&mut store, &first).expect("active retry");
    retire(&mut store, &first).expect("retire lifetime");
    assert!(verify(&store, &first).is_err());
    drop(store);
    let mut store = fixture.open();
    assert!(reserve(&mut store, &first).is_err());
    assert!(activate(&mut store, &first).is_err());
    let same_name = Identity {
        reservation: "replacement".into(),
        uid: 3001,
        ..first.clone()
    };
    assert!(reserve(&mut store, &same_name).is_err());
    let mut reused_uid = identity("replacement", 3000);
    reused_uid.reservation = "fixture:different-lifetime".into();
    reserve(&mut store, &reused_uid).expect("retired UID is reusable with a fresh name");
    let replacement = identity("worker-3001", 3001);
    reserve(&mut store, &replacement).expect("new lifetime");
    activate(&mut store, &replacement).expect("replacement ready");
    assert_eq!(store.configuration.workers.len(), 3);
    assert_eq!(store.configuration.workers[0].state, WorkerState::Retired);
}

/// ´claim:loophome:worker-birth-reservation-serializes-concurrent-uid-claims´
/// ´test:unit:worker-birth-reservation-serializes-concurrent-uid-claims´
#[test]
fn worker_birth_reservation_serializes_concurrent_uid_claims() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: [std::thread::JoinHandle<bool>; 2] = std::array::from_fn(|index| {
        let private = fixture.root.join("private");
        let service = fixture.service;
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let mut store = ConfigurationStore::open(&private, service).expect("writer lock");
            let mut candidate = identity(&format!("worker-{index}"), 3000);
            candidate.reservation = format!("fixture:concurrent-{index}");
            reserve(&mut store, &candidate).is_ok()
        })
    });
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().expect("writer")))
            .sum::<usize>(),
        1
    );
    assert_eq!(fixture.open().configuration.workers.len(), 1);
}

/// ´claim:loophome:worker-birth-uses-the-mail-identity-production´
/// ´test:unit:worker-birth-uses-the-mail-identity-production´
#[test]
fn worker_birth_uses_the_mail_identity_production() {
    let long = "a".repeat(512);
    for (name, expected) in [
        ("0", true),
        ("0-worker", true),
        ("a-", true),
        ("a--b", true),
        ("enter", true),
        ("letters-private", true),
        (long.as_str(), true),
        ("", false),
        ("-a", false),
        ("-", false),
        ("A", false),
        ("a_b", false),
        ("a.b", false),
        ("a+b", false),
        ("a/b", false),
        ("é", false),
        ("a b", false),
        ("a\n", false),
        ("a\0", false),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let result = reserve(&mut store, &identity(name, 3000));
        assert_eq!(result.is_ok(), expected, "{name:?}");
        if !expected {
            assert!(
                result
                    .expect_err("name refusal")
                    .to_string()
                    .starts_with("invalid-name:")
            );
        }
    }
}

/// ´claim:loophome:worker-birth-never-acknowledges-an-unwritten-in-memory-reservation´
/// ´test:unit:worker-birth-never-acknowledges-an-unwritten-in-memory-reservation´
#[test]
fn worker_birth_never_acknowledges_an_unwritten_in_memory_reservation() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let worker = identity("pending", 3000);
    fs::set_permissions(
        fixture.root.join("private"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("lost traversal grant");
    assert!(reserve(&mut store, &worker).is_err());
    assert!(reserve(&mut store, &worker).is_err());
    assert!(activate(&mut store, &worker).is_err());
    drop(store);
    let store = fixture.open();
    assert!(store.configuration.workers.is_empty());
}

/// ´claim:loophome:missing-protected-receipt-does-not-reuse-surviving-loop-history´
/// ´test:unit:missing-protected-receipt-does-not-reuse-surviving-loop-history´
#[test]
fn missing_protected_receipt_does_not_reuse_surviving_loop_history() {
    let fixture = Fixture::new();
    let identity = identity("worker-3000", 3000);
    let mut store = fixture.open();
    unreserved(&store, &identity).expect("first receipt admission");
    reserve(&mut store, &identity).expect("receipt precedes configuration reserve");
    assert!(unreserved(&store, &identity).is_err());
    activate(&mut store, &identity).expect("complete birth");
    drop(store);
    let mut store = fixture.open();
    assert!(unreserved(&store, &identity).is_err());
    retire(&mut store, &identity).expect("retained lifetime");
    assert!(unreserved(&store, &identity).is_err());
    let replacement = Identity {
        name: "replacement".into(),
        reservation: "different".into(),
        ..identity
    };
    unreserved(&store, &replacement).expect("retired UID is released");
}

/// ´claim:loophome:missing-configuration-never-resets-protected-birth-history´
/// ´test:unit:missing-configuration-never-resets-protected-birth-history´
#[test]
fn missing_configuration_never_resets_protected_birth_history() {
    for history in ["workers", ".mail-births", ".mail-worker-staging"] {
        let fixture = Fixture::new();
        drop(fixture.open());
        fs::create_dir(fixture.root.join(history)).expect("retained history");
        let primary = ConfigurationStore::path(&fixture.root.join("private"));
        fs::remove_file(&primary).expect("primary lost before a backup exists");
        assert!(ConfigurationStore::open(&fixture.root.join("private"), fixture.service).is_err());
        assert!(
            !primary.exists(),
            "history must not become a fresh empty configuration"
        );
    }
}
