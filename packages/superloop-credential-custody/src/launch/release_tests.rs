use super::*;
use crate::launch::{
    control::Control, inventory::tests as fixture, manager, measure::Admission,
    startup::RootStartup, tests::Fixture,
};
use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
fn setup(behavior: &str) -> Fixture {
    let mut f = fixture::fixture(behavior);
    manager::tests::add_images(&mut f);
    let bytes = fs::read(f.dir.path().join("manager-start")).unwrap();
    let own = f.dir.path().join("launcher");
    fs::set_permissions(&own, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&own, &bytes).unwrap();
    fs::set_permissions(&own, fs::Permissions::from_mode(0o555)).unwrap();
    f.value["artifacts"][0]["expected_sha256"] = crate::identity::hash(&bytes).into();
    fs::set_permissions(
        f.dir.path().join("public.json"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    f
}
fn captured(f: &Fixture, admission: &Admission, keeper: &mut Keeper<'_>) -> fixture::ChildGuard {
    // Ordinary-user stand-in: admission checks the public layout; the real
    // fixture then uses its caller-owned immutable form. No root ownership is faked.
    fs::set_permissions(
        f.dir.path().join("public.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    keeper.submit().unwrap();
    let writers = keeper
        .pipes
        .paths()
        .each_ref()
        .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
    let (child, _pin) = fixture::start(f, &writers);
    let reply = String::from_utf8(manager::tests::reply(admission))
        .unwrap()
        .replace("MainPID=123", &format!("MainPID={}", child.child.id()));
    fs::write(f.dir.path().join("manager-reply"), reply).unwrap();
    keeper
        .capture_with(
            |_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())),
            Control::test_bind,
        )
        .unwrap();
    child
}
fn evidence(f: &Fixture) -> std::path::PathBuf {
    f.dir.path().join("evidence/sample")
}
fn receipt(f: &Fixture) -> std::path::PathBuf {
    evidence(f).join("inventory.json")
}
fn stopped(child: &fixture::ChildGuard) {
    let directory = File::open(format!("/proc/{}", child.child.id())).unwrap();
    assert!(crate::launch::process_pin::stat(&directory).unwrap().1);
}
/// ´test:unit:release-is-bound-to-retained-inventory-and-consumed-once´
#[test]
fn release_is_bound_to_retained_inventory_and_consumed_once() {
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let mut child = captured(&f, &admission, &mut keeper);
    assert_eq!(keeper.release("missing"), Err("release-order"));
    let digest = keeper.inventory().unwrap();
    assert_eq!(keeper.inventory(), Err("inventory-order"));
    let path = receipt(&f);
    let m = fs::metadata(&path).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o400);
    assert_eq!(m.nlink(), 1);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(value["command"], "descriptors");
    assert_eq!(
        value["inventory"]["descriptors"].as_array().unwrap().len(),
        5
    );
    assert_eq!(value["sealers"].as_array().unwrap().len(), 2);
    keeper.release(&digest).unwrap();
    assert_eq!(keeper.phase(), Phase::Released);
    assert_eq!(keeper.release(&digest), Err("release-order"));
    assert_eq!(
        keeper.process.as_mut().unwrap().resume(),
        Err("release-duplicate")
    );
    assert!(child.child.wait().unwrap().success());
    for (n, phase) in [(5, "release-intent"), (6, "released")] {
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read(evidence(&f).join(format!("state-{n:02}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(value["phase"], phase);
        assert_eq!(value["inventory_sha256"], digest);
    }
    assert!(!evidence(&f).join("complete.json").exists());
}
/// ´test:unit:release-refuses-stale-or-changed-evidence-before-signalling´
#[test]
fn release_refuses_stale_or_changed_evidence_before_signalling() {
    for case in [
        "digest",
        "mode",
        "link",
        "replace",
        "bytes",
        "invocation",
        "inventory",
        "status",
    ] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        let child = captured(&f, &admission, &mut keeper);
        let mut digest = keeper.inventory().unwrap();
        let path = receipt(&f);
        let expected = match case {
            "digest" => {
                digest = "0".repeat(64);
                "inventory-receipt-digest"
            }
            "mode" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                "inventory-receipt-binding"
            }
            "link" => {
                fs::hard_link(&path, path.with_extension("link")).unwrap();
                "inventory-receipt-binding"
            }
            "replace" => {
                let bytes = fs::read(&path).unwrap();
                fs::remove_file(&path).unwrap();
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                "inventory-receipt-binding"
            }
            "bytes" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&path, b"{}").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                "inventory-receipt-digest"
            }
            "invocation" => {
                keeper.inventory.as_mut().unwrap().invocation.birth += 1;
                "inventory-invocation"
            }
            "inventory" => {
                keeper.inventory.as_mut().unwrap().inventory.boot = "stale".into();
                "inventory-changed"
            }
            _ => {
                keeper.inventory.as_mut().unwrap().children[0].birth += 1;
                "inventory-sealers-changed"
            }
        };
        let mut calls = 0;
        assert_eq!(
            keeper.release_with(&digest, |_| {
                calls += 1;
                Ok(())
            }),
            Err(expected),
            "{case}"
        );
        assert_eq!(calls, 0, "{case}");
        assert_eq!(keeper.phase(), Phase::Uncertain);
        stopped(&child);
        assert_eq!(keeper.release(&digest), Err("release-order"));
    }
}
/// ´test:unit:release-intent-and-signal-failures-never-retry´
#[test]
fn release_intent_and_signal_failures_never_retry() {
    for case in ["intent", "signal", "published"] {
        let f = setup("normal");
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        let child = captured(&f, &admission, &mut keeper);
        let digest = keeper.inventory().unwrap();
        if case != "signal" {
            fs::write(
                evidence(&f).join(if case == "intent" {
                    "state-05.json"
                } else {
                    "state-06.json"
                }),
                b"occupied",
            )
            .unwrap();
        }
        let mut calls = 0;
        let result = keeper.release_with(&digest, |pin| {
            calls += 1;
            if case == "signal" {
                Err("release-signal")
            } else {
                pin.resume()
            }
        });
        assert_eq!(
            result,
            Err(if case == "signal" {
                "release-signal"
            } else {
                "receipt-no-replace"
            }),
            "{case}"
        );
        assert_eq!(calls, usize::from(case != "intent"));
        assert_eq!(keeper.phase(), Phase::Uncertain);
        assert_eq!(keeper.release(&digest), Err("release-order"));
        if case != "published" {
            stopped(&child);
        }
    }
}
/// ´test:unit:reexecuted-fixture-never-reaches-release´
#[test]
fn reexecuted_fixture_never_reaches_release() {
    let f = setup("reexec-extra");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    assert_eq!(keeper.inventory(), Err("inventory-count"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
    stopped(&child);
    assert!(!receipt(&f).exists());
    assert_eq!(keeper.release("absent"), Err("release-order"));
    for name in ["left.sealed", "right.sealed"] {
        assert_eq!(
            fs::metadata(f.dir.path().join("sealed/sample").join(name))
                .unwrap()
                .len(),
            0
        );
    }
}
/// ´test:unit:inventory-publication-collision-latches-uncertainty´
#[test]
fn inventory_publication_collision_latches_uncertainty() {
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    fs::write(receipt(&f), b"occupied").unwrap();
    assert_eq!(keeper.inventory(), Err("receipt-no-replace"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
    stopped(&child);
    assert_eq!(fs::read(receipt(&f)).unwrap(), b"occupied");
    assert_eq!(keeper.inventory(), Err("inventory-order"));
}
/// ´test:unit:release-rechecks-sealer-liveness-before-input´
#[test]
fn release_rechecks_sealer_liveness_before_input() {
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    let digest = keeper.inventory().unwrap();
    let pid = keeper.session.statuses().unwrap()[0].pid;
    let pins = keeper.session.test_pidfds();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    let mut event = nix::libc::pollfd {
        fd: pins[0].as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    crate::launch::channel::poll(std::slice::from_mut(&mut event), 600_000).unwrap();
    assert_ne!(event.revents & nix::libc::POLLIN, 0);
    let mut calls = 0;
    assert_eq!(
        keeper.release_with(&digest, |_| {
            calls += 1;
            Ok(())
        }),
        Err("sealer-status-exited")
    );
    assert_eq!(calls, 0);
    assert_eq!(keeper.phase(), Phase::Uncertain);
    stopped(&child);
}
/// ´test:unit:release-rechecks-manager-invocation-before-signalling´
#[test]
fn release_rechecks_manager_invocation_before_signalling() {
    let f = setup("normal");
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    let digest = keeper.inventory().unwrap();
    let path = f.dir.path().join("manager-reply");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        text.replace(
            &format!(
                "InvocationID={}",
                keeper.process.as_ref().unwrap().invocation().id
            ),
            &format!("InvocationID={}", "b".repeat(32)),
        ),
    )
    .unwrap();
    let mut calls = 0;
    assert_eq!(
        keeper.release_with(&digest, |_| {
            calls += 1;
            Ok(())
        }),
        Err("manager-invocation-binding")
    );
    assert_eq!(calls, 0);
    assert_eq!(keeper.phase(), Phase::Uncertain);
    stopped(&child);
}
