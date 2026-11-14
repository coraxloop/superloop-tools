//! Event/count controls with a native peer; no root, manager, host key or encryption claim.
use super::{
    sealer::{Exit, Session},
    state::Phase,
    store::Store,
    tests::Fixture,
};
use crate::identity::hash;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use std::fs::{self, File};
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::time::{Duration, Instant};

pub(super) fn make_fixture(mode: &str) -> Fixture {
    let mut fixture = Fixture::new();
    // The workspace may relocate the test executable under build/.../out.
    let current = std::env::current_exe().unwrap();
    let executable = current
        .ancestors()
        .take(8)
        .map(|p| {
            p.join(if mode == "confinement" {
                "examples/custody-confinement-probe"
            } else {
                "examples/custody-sealer-test"
            })
        })
        .find(|p| p.is_file())
        .expect("Cargo's profile contains its built native example");
    let bytes = fs::read(executable).expect("Cargo's test-only native example must be built");
    let path = fixture.dir.path().join("sealer");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
    fixture.value["artifacts"][2]["expected_sha256"] = hash(&bytes).into();
    fixture.value["limits"]["artifact_bytes"] = (64 * 1024 * 1024).into();
    fixture.value["limits"]["sealed_bytes"] = 32768.into();
    fixture.value["limits"]["case_ms"] = 600_000.into();
    fixture.value["limits"]["campaign_ms"] = 600_000.into();
    fixture.value["cases"][0]["streams"][0]["name"] = mode.into();
    let public_path = fixture.dir.path().join("public.json");
    let mut case: serde_json::Value =
        serde_json::from_slice(&fs::read(&public_path).unwrap()).unwrap();
    case["streams"][0]["name"] = mode.into();
    let bytes = serde_json::to_vec(&case).unwrap();
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&public_path, &bytes).unwrap();
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o444)).unwrap();
    fixture.value["cases"][0]["expected_case_sha256"] = hash(&bytes).into();
    let key = fixture.dir.path().join("key");
    fs::create_dir(&key).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(key.join("synthetic-key"), b"public synthetic control").unwrap();
    fixture.value["host_key"] = key.join("synthetic-key").to_str().unwrap().into();
    // The native peer uses the same loader and standard libraries as this test
    // binary. These are measured file allowances, never a directory-wide grant.
    let paths: std::collections::BTreeSet<_> = fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .filter(|path| path.starts_with('/') && path.contains(".so"))
        .map(|path| fs::canonicalize(path).unwrap())
        .collect();
    for (index, path) in paths.into_iter().enumerate() {
        fixture.value["artifacts"].as_array_mut().unwrap().push(serde_json::json!({"id":format!("system-library-{index}"),"role":"library","path":path,"expected_sha256":hash(&fs::read(&path).unwrap())}));
    }
    fixture
}
fn pipes() -> ([OwnedFd; 2], [File; 2]) {
    let (a, aw) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    let (b, bw) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    ([a, b], [File::from(aw), File::from(bw)])
}
fn feed(writers: [File; 2], bytes: &[u8]) {
    for mut writer in writers {
        writer.write_all(bytes).unwrap();
    }
}
fn hang_guard() -> Instant {
    // An emergency hang bound, not a success predicate. No test asserts elapsed
    // time or expects this to fire; every verdict comes from an event or count.
    Instant::now() + Duration::from_secs(600)
}
fn assert_failed(fixture: &Fixture, store: &Store) {
    assert_eq!(store.phase(), Phase::Failed);
    assert_eq!(
        fs::read_dir(fixture.dir.path().join("sealed/sample"))
            .unwrap()
            .count(),
        0
    );
    let states: Vec<serde_json::Value> = fs::read_dir(fixture.dir.path().join("evidence/sample"))
        .unwrap()
        .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect();
    assert!(states.iter().all(|state| state["phase"] != "complete"));
    assert_eq!(
        states
            .iter()
            .filter(|state| state["phase"] == "failed")
            .count(),
        1
    );
}

/// ´test:unit:sealers-complete-from-events-not-length-claims´
#[test]
fn sealers_complete_from_events_not_length_claims() {
    // Short, exact and excess synthetic inputs all reach EOF; C7, not C2, will
    // compare decoded lengths with the declared five-byte case.
    for length in [1, 5, 17] {
        let fixture = make_fixture("normal");
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (readers, writers) = pipes();
        feed(writers, &vec![42; length]);
        let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
        let complete = session.wait_until(hang_guard()).unwrap();
        assert_eq!(session.exits(), &[Some(Exit::Code(0)); 2]);
        assert_eq!(
            complete.sealed_bytes,
            [4 * (length as u64).div_ceil(3) + 1; 2]
        );
        assert_eq!(
            session.wait_until(hang_guard()).err(),
            Some("sealer-session-terminal")
        );
        drop(session);
        assert_eq!(store.phase(), Phase::SealersStarted); // No completion marker.
    }
}
/// ´test:unit:sealers-consume-a-pre-filled-pipe-without-a-plaintext-observer´
#[test]
fn sealers_consume_a_pre_filled_pipe_without_a_plaintext_observer() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, mut writers) = pipes();
    let mut counts = [0_u64; 2];
    for (writer, count) in writers.iter_mut().zip(&mut counts) {
        fcntl(&*writer, FcntlArg::F_SETPIPE_SZ(4096)).unwrap();
        fcntl(&*writer, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        loop {
            match writer.write(&[7; 4096]) {
                Ok(n) => *count += n as u64,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                result => panic!("unexpected fill result {result:?}"),
            }
        }
        assert!(*count > 0);
    }
    // Both pipes reached capacity before any reader process was started.
    drop(writers);
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).unwrap().sealed_bytes,
        counts.map(|n| 4 * n.div_ceil(3) + 1)
    );
}
/// ´test:unit:sealers-refuse-early-zero-and-buffered-hangup´
#[test]
fn sealers_refuse_early_zero_and_buffered_hangup() {
    let mode = "early";
    let fixture = make_fixture(mode);
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    feed(writers, b"synthetic remainder");
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).err(),
        Some("sealer-early-exit")
    );
    drop(session);
    assert_failed(&fixture, &store);
}
/// ´test:unit:sealers-refuse-an-exit-with-a-retained-writer´
#[test]
fn sealers_refuse_an_exit_with_a_retained_writer() {
    let fixture = make_fixture("early");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    // Neither writer task is ever started. Exit is a pidfd event, not a timeout.
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).err(),
        Some("sealer-early-exit")
    );
    drop(session);
    drop(writers);
    assert_failed(&fixture, &store);
}
/// ´test:unit:sealers-refuse-failure-signal-empty-and-overflow´
#[test]
fn sealers_refuse_failure_signal_empty_and_overflow() {
    for (mode, class) in [
        ("fail", "sealer-exit"),
        ("signal", "sealer-exit"),
        ("empty", "sealer-output-size"),
        ("excess", "sealer-exit"),
        ("diagnostic", "sealer-diagnostic-limit"),
    ] {
        let fixture = make_fixture(mode);
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (readers, writers) = pipes();
        feed(writers, b"synthetic");
        let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
        assert_eq!(
            session.wait_until(hang_guard()).err(),
            Some(class),
            "{mode}"
        );
        if mode == "fail" {
            assert_eq!(session.exits()[0], Some(Exit::Code(7)));
        }
        if mode == "signal" {
            assert_eq!(session.exits()[0], Some(Exit::Signal(15)));
        }
        drop(session);
        assert_failed(&fixture, &store);
        for receipt in fs::read_dir(fixture.dir.path().join("evidence/sample")).unwrap() {
            assert!(
                !fs::read(receipt.unwrap().path())
                    .unwrap()
                    .windows(32)
                    .any(|s| s == [b'X'; 32])
            );
        }
    }
}
/// ´test:unit:sealer-cancellation-is-an-event-with-manifest-cleanup´
#[test]
fn sealer_cancellation_is_an_event_with_manifest_cleanup() {
    for event in ["sealer-deadline", "generator-failed", "keeper-cancelled"] {
        let fixture = make_fixture("normal");
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (readers, writers) = pipes();
        let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
        let pidfds = session.test_pidfds();
        session.store().advance(Phase::Submitted).unwrap();
        assert_eq!(session.fail(event), event);
        assert_eq!(session.exits(), &[Some(Exit::Signal(9)); 2]);
        let receipts: Vec<serde_json::Value> =
            fs::read_dir(fixture.dir.path().join("evidence/sample"))
                .unwrap()
                .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
                .collect();
        assert_eq!(
            receipts
                .iter()
                .filter(|r| r["refusal_class"] == event)
                .count(),
            1
        );
        assert_exited(&pidfds);
        assert_eq!(session.fail(event), "sealer-session-terminal");
        drop(session);
        drop(writers);
        assert_failed(&fixture, &store);
    }
}
/// ´test:unit:sealer-drop-reaps-and-cleans-manifest´
#[test]
fn sealer_drop_reaps_and_cleans_manifest() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    let session = Session::start(&admission, 0, &mut store, readers).unwrap();
    let pidfds = session.test_pidfds();
    drop(session);
    assert_exited(&pidfds);
    drop(writers);
    assert_failed(&fixture, &store);
}
/// ´test:unit:sealers-build-child-descriptors-explicitly´
#[test]
fn sealers_build_child_descriptors_explicitly() {
    let ambient = tempfile::tempfile().unwrap();
    fcntl(&ambient, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    feed(writers, b"synthetic");
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).unwrap().sealed_bytes,
        [13; 2]
    );
    assert_eq!(fcntl(&ambient, FcntlArg::F_GETFD).unwrap(), 0);
}
/// ´test:unit:sealer-admission-binds-image-and-store-before-spawn´
#[test]
fn sealer_admission_binds_image_and_store_before_spawn() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let path = fixture.dir.path().join("sealer");
    let replacement = fixture.dir.path().join("replacement");
    fs::copy(&path, &replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o555)).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let (readers, writers) = pipes();
    assert_eq!(
        Session::start(&admission, 0, &mut store, readers).err(),
        Some("launch-artifact-changed")
    );
    drop(writers);
    assert_eq!(store.phase(), Phase::Reserved);
    let other = make_fixture("normal");
    let other_admission = other.admit();
    assert_eq!(
        store.sealer_outputs(&other_admission, 0).err(),
        Some("sealer-store-binding")
    );
}

fn assert_exited(pidfds: &[OwnedFd]) {
    let mut items: Vec<_> = pidfds
        .iter()
        .map(|fd| nix::libc::pollfd {
            fd: fd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        })
        .collect();
    super::channel::poll(&mut items, 0).unwrap();
    assert_eq!(
        items
            .iter()
            .filter(|p| p.revents & nix::libc::POLLIN != 0)
            .count(),
        2
    );
}
/// ´test:unit:sealer-success-does-not-override-generator-failure´
#[test]
fn sealer_success_does_not_override_generator_failure() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    feed(writers, b"synthetic");
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).unwrap().sealed_bytes,
        [13; 2]
    );
    drop(session);
    store.fail("generator-failed").unwrap();
    store.cleanup_outputs().unwrap();
    assert_failed(&fixture, &store);
}
/// ´test:unit:sealer-preparation-refuses-occupied-output-and-wrong-phase´
#[test]
fn sealer_preparation_refuses_occupied_output_and_wrong_phase() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let output = store.output_files().unwrap()[0].try_clone().unwrap();
    output.set_len(1).unwrap();
    assert_eq!(
        store.sealer_outputs(&admission, 0).err(),
        Some("sealer-output-not-empty")
    );
    output.set_len(0).unwrap();
    store.advance(Phase::SealersStarted).unwrap();
    assert_eq!(
        store.sealer_outputs(&admission, 0).err(),
        Some("sealer-store-binding")
    );
}
/// ´test:unit:sealer-failure-publication-collision-retains-quarantine´
#[test]
fn sealer_failure_publication_collision_retains_quarantine() {
    let fixture = make_fixture("normal");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    fs::write(
        fixture.dir.path().join("evidence/sample/state-02.json"),
        b"occupied",
    )
    .unwrap();
    assert_eq!(session.fail("generator-failed"), "sealer-failure-custody");
    drop(session);
    drop(writers);
    assert_eq!(store.phase(), Phase::Uncertain);
    assert_eq!(
        fs::read_dir(fixture.dir.path().join("sealed/sample"))
            .unwrap()
            .count(),
        2
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.dir.path().join("evidence/sample/state-03.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["original_cause"], "generator-failed");
    assert_ne!(receipt["refusal_class"], receipt["original_cause"]);
    store.cleanup_outputs().unwrap();
}

/// ´test:unit:sealer-deadline-conversion-uses-injected-instants´
#[test]
fn sealer_deadline_conversion_uses_injected_instants() {
    let now = Instant::now();
    assert_eq!(
        super::sealer::remaining_timeout(now, now, now),
        Err("sealer-deadline")
    );
    assert_eq!(
        super::sealer::remaining_timeout(now + Duration::from_secs(1), now, now),
        Err("sealer-deadline")
    );
    assert_eq!(
        super::sealer::remaining_timeout(
            now,
            now + Duration::from_millis(20),
            now + Duration::from_secs(1)
        ),
        Ok(21)
    );
}

/// ´test:unit:sealers-refuse-a-partial-reader-with-buffered-hangup´
#[test]
fn sealers_refuse_a_partial_reader_with_buffered_hangup() {
    let fixture = make_fixture("partial");
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    feed(writers, b"synthetic remainder");
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).err(),
        Some("sealer-early-exit")
    );
    drop(session);
    assert_failed(&fixture, &store);
}

/// ´test:unit:sealer-output-loss-latches-before-or-after-spawn´
#[test]
fn sealer_output_loss_latches_before_or_after_spawn() {
    for after_spawn in [false, true] {
        let fixture = make_fixture("normal");
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (readers, writers) = pipes();
        feed(writers, b"synthetic");
        let out = fixture.dir.path().join("sealed/sample/left.sealed");
        let original = fixture.dir.path().join("sealed/sample/original");
        if after_spawn {
            let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
            fs::rename(&out, &original).unwrap();
            fs::write(&out, b"foreign").unwrap();
            assert_eq!(
                session.wait_until(hang_guard()).err(),
                Some("sealer-failure-custody")
            );
        } else {
            fs::rename(&out, &original).unwrap();
            fs::write(&out, b"foreign").unwrap();
            assert_eq!(
                Session::start(&admission, 0, &mut store, readers).err(),
                Some("launch-output-binding")
            );
        }
        assert_eq!(store.phase(), Phase::Uncertain);
        assert_eq!(fs::read(&out).unwrap(), b"foreign");
        fs::remove_file(&out).unwrap();
        fs::rename(&original, &out).unwrap();
        assert_eq!(
            store.sealer_outputs(&admission, 0).err(),
            Some("sealer-store-binding")
        );
        store.cleanup_outputs().unwrap();
    }
}

/// ´test:unit:sealer-native-exec-failure-retains-a-typed-failure´
#[test]
fn sealer_native_exec_failure_retains_a_typed_failure() {
    let mut fixture = make_fixture("normal");
    let path = fixture.dir.path().join("sealer");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"not a native executable").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
    fixture.value["artifacts"][2]["expected_sha256"] = hash(b"not a native executable").into();
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, _writers) = pipes();
    assert_eq!(
        Session::start(&admission, 0, &mut store, readers).err(),
        Some("sealer-start")
    );
    assert_failed(&fixture, &store);
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.dir.path().join("evidence/sample/state-01.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["refusal_class"], "sealer-start");
}

/// ´test:unit:sealer-confinement-denies-new-authority-and-keeps-held-output´
#[test]
fn sealer_confinement_denies_new_authority_and_keeps_held_output() {
    let fixture = make_fixture("confinement");
    fs::write(fixture.dir.path().join("outside-canary"), b"public").unwrap();
    fs::write(fixture.dir.path().join("evidence/canary"), b"public").unwrap();
    let admission = fixture.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let (readers, writers) = pipes();
    feed(writers, b"synthetic");
    let mut session = Session::start(&admission, 0, &mut store, readers).unwrap();
    assert_eq!(
        session.wait_until(hang_guard()).unwrap().sealed_bytes,
        [10, 10]
    );
    drop(session);
    for name in ["left.sealed", "right.sealed"] {
        assert_eq!(
            fs::read(fixture.dir.path().join("sealed/sample").join(name)).unwrap(),
            b"1111111111"
        );
    }
    assert!(!fixture.dir.path().join("key/forbidden").exists());
}

/// ´test:unit:sealer-confinement-refuses-unprotected-key-and-missing-loader´
#[test]
fn sealer_confinement_refuses_unprotected_key_and_missing_loader() {
    for missing_loader in [false, true] {
        let mut fixture = make_fixture("normal");
        if missing_loader {
            fixture.value["artifacts"]
                .as_array_mut()
                .unwrap()
                .retain(|a| !a["id"].as_str().unwrap().starts_with("system-library-"));
        } else {
            fs::set_permissions(
                fixture.dir.path().join("key"),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap();
        }
        let admission = fixture.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let (readers, _writers) = pipes();
        assert_eq!(
            Session::start(&admission, 0, &mut store, readers).err(),
            Some(if missing_loader {
                "sealer-start"
            } else {
                "sealer-key-directory"
            })
        );
        assert_eq!(
            store.phase(),
            if missing_loader {
                Phase::Failed
            } else {
                Phase::Reserved
            }
        );
    }
}
