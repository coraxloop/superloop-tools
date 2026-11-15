use super::*;
use crate::launch::{inventory::tests as fixture, measure::ObjectIdentity};
use std::fs::File;
use std::os::fd::OwnedFd;
fn binding(invocation: &Invocation) -> Binding<'_> {
    Binding {
        schema: 1,
        case: "sample",
        nonce: "0123456789abcdef0123456789abcdef",
        keeper_pid: std::process::id(),
        keeper_birth: 1,
        keeper_uid: nix::unistd::geteuid().as_raw(),
        invocation,
        inventory_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(600)
}
fn pair() -> (UnixStream, UnixStream) {
    let (a, b) = UnixStream::pair().unwrap();
    a.set_nonblocking(true).unwrap();
    (a, b)
}
/// ´test:unit:pidfd-handoff-binds-peer-receipt-and-stopped-process´
#[test]
fn pidfd_handoff_binds_peer_receipt_and_stopped_process() {
    let f = fixture::fixture("normal");
    let (_readers, writers) = fixture::pipes();
    let (_child, pin) = fixture::start(&f, &writers);
    let expected = binding(pin.invocation());
    let (mut sender, mut receiver) = pair();
    send(&mut sender, &expected, &pin, deadline()).unwrap();
    // Entire bounded frame and EOF are queued before receiving, so the shared
    // transport's 30-second emergency limit is not the readiness witness.
    let imported = receive(&mut receiver, &expected, deadline()).unwrap();
    imported.matches(pin.invocation()).unwrap();
    assert!(imported.close_on_exec());
    for change in [
        "peer",
        "owner",
        "nonce",
        "case",
        "birth",
        "digest",
        "invocation",
    ] {
        let (mut sender, mut receiver) = pair();
        let mut wanted = binding(pin.invocation());
        let mut invocation = pin.invocation().clone();
        match change {
            "peer" => wanted.keeper_pid += 1,
            "owner" => wanted.keeper_uid += 1,
            "nonce" => wanted.nonce = "1123456789abcdef0123456789abcdef",
            "case" => wanted.case = "other",
            "birth" => wanted.keeper_birth += 1,
            "digest" => wanted.inventory_sha256 = "stale",
            _ => {
                invocation.birth += 1;
                wanted.invocation = &invocation;
            }
        }
        send(
            &mut sender,
            if matches!(change, "peer" | "owner") {
                &wanted
            } else {
                &expected
            },
            &pin,
            deadline(),
        )
        .unwrap();
        assert_eq!(
            receive(&mut receiver, &wanted, deadline()).err(),
            Some(if matches!(change, "peer" | "owner") {
                "handoff-peer"
            } else {
                "handoff-binding"
            }),
            "{change}"
        );
    }
    let (mut sender, _receiver) = pair();
    let mut invocation = pin.invocation().clone();
    invocation.birth += 1;
    assert_eq!(
        send(&mut sender, &binding(&invocation), &pin, deadline()),
        Err("keeper-invocation-binding")
    );
}
fn raw(sender: &mut UnixStream, binding: &Binding<'_>, fds: &[OwnedFd]) {
    sender.write_all(&encoded(binding).unwrap()).unwrap();
    loop_home::anchor::transport::send(sender, fds).unwrap();
}
/// ´test:unit:pidfd-handoff-refuses-missing-extra-and-mismatched-rights´
#[test]
fn pidfd_handoff_refuses_missing_extra_and_mismatched_rights() {
    let f = fixture::fixture("normal");
    let (_readers, writers) = fixture::pipes();
    let (_child, pin) = fixture::start(&f, &writers);
    for change in ["missing", "extra", "file", "pid", "birth", "uid", "image"] {
        let (mut sender, mut receiver) = pair();
        let mut invocation = pin.invocation().clone();
        let fds = match change {
            "missing" => vec![],
            "extra" => vec![pin.duplicate().unwrap(), pin.duplicate().unwrap()],
            "file" => vec![File::open("/dev/null").unwrap().into()],
            _ => vec![pin.duplicate().unwrap()],
        };
        match change {
            "pid" => invocation.pid += 1,
            "birth" => invocation.birth += 1,
            "uid" => invocation.uid += 1,
            "image" => {
                invocation.image =
                    ObjectIdentity::of(&File::open("/usr/bin/true").unwrap()).unwrap();
            }
            _ => {}
        }
        let expected = binding(&invocation);
        raw(&mut sender, &expected, &fds);
        let class = match change {
            "missing" | "extra" => "handoff-rights",
            "file" => "keeper-process-exited",
            "pid" => "keeper-pidfd-binding",
            "birth" => "keeper-barrier",
            "uid" => "keeper-process-identity",
            _ => "keeper-image",
        };
        assert_eq!(
            receive(&mut receiver, &expected, deadline()).err(),
            Some(class),
            "{change}"
        );
    }
}
/// ´test:unit:pidfd-handoff-refuses-exited-target-and-expired-operation´
#[test]
fn pidfd_handoff_refuses_exited_target_and_expired_operation() {
    let f = fixture::fixture("normal");
    let (_readers, writers) = fixture::pipes();
    let (mut child, pin) = fixture::start(&f, &writers);
    let expected = binding(pin.invocation());
    let (mut sender, mut receiver) = pair();
    send(&mut sender, &expected, &pin, deadline()).unwrap();
    child.child.kill().unwrap();
    child.child.wait().unwrap();
    assert_eq!(
        receive(&mut receiver, &expected, deadline()).err(),
        Some("keeper-process-exited")
    );
    let (mut sender, mut receiver) = pair();
    raw(&mut sender, &expected, &[]);
    assert_eq!(
        receive(
            &mut receiver,
            &expected,
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap()
        )
        .err(),
        Some("handoff-deadline")
    );
}
/// ´test:unit:pidfd-handoff-bounds-metadata-before-rights´
#[test]
fn pidfd_handoff_bounds_metadata_before_rights() {
    let f = fixture::fixture("normal");
    let (_readers, writers) = fixture::pipes();
    let (_child, pin) = fixture::start(&f, &writers);
    let expected = binding(pin.invocation());
    for (bytes, class) in [
        (vec![b'x'; 4096], "handoff-size"),
        (b"unterminated".to_vec(), "handoff-closed"),
    ] {
        let (mut sender, mut receiver) = pair();
        sender.write_all(&bytes).unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            receive(&mut receiver, &expected, deadline()).err(),
            Some(class)
        );
    }
    let large = "x".repeat(4096);
    let mut wanted = binding(pin.invocation());
    wanted.case = &large;
    assert_eq!(encoded(&wanted).err(), Some("handoff-size"));
}
