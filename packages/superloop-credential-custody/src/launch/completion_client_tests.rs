use super::*;
use crate::launch::measure::ObjectIdentity;
use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::Duration;
fn invocation() -> Invocation {
    Invocation {
        id: "1".repeat(32),
        unit: "sample.service".into(),
        pid: 123,
        birth: 5,
        uid: 1000,
        image: ObjectIdentity {
            device: 2,
            inode: 3,
        },
    }
}
fn expected(invocation: &Invocation) -> Binding<'_> {
    Binding {
        case: "sample",
        nonce: "0123456789abcdef0123456789abcdef",
        keeper_pid: std::process::id(),
        keeper_birth: 1,
        keeper_uid: nix::unistd::geteuid().as_raw(),
        invocation,
        sealed_limit: 4096,
    }
}
fn reply(binding: &Binding<'_>) -> serde_json::Value {
    serde_json::json!({"schema":1,"case":binding.case,"nonce":binding.nonce,"keeper_pid":binding.keeper_pid,
        "keeper_birth":binding.keeper_birth,"invocation":binding.invocation.id,"view":{"phase":"complete",
        "generator":{"invocation":binding.invocation,"started":100,"exited":200,"code":1,"status":0,"result":"success","successful":true,
        "reply_sha256":"a".repeat(64),"configuration_sha256":"b".repeat(64)},
        "sealers":{"sealed_bytes":[4,4],"eof":[true,true],"exits":[{"Code":0},{"Code":0}]}}})
}
fn encoded(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
fn observe(bytes: &[u8], binding: &Binding<'_>) -> Result<Observation> {
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    writer.write_all(bytes).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    receive(
        &mut reader,
        binding,
        Instant::now() + Duration::from_secs(600),
    )
}
/// ´test:unit:completion-client-requires-live-bound-evidence´
#[test]
fn completion_client_requires_live_bound_evidence() {
    let invocation = invocation();
    let binding = expected(&invocation);
    let good = reply(&binding);
    assert_eq!(
        observe(&encoded(&good), &binding),
        Ok(Observation::Complete)
    );
    for phase in [
        "released",
        "generator-retained",
        "holder-released",
        "eof-and-sealers-complete",
        "sealed-synced",
    ] {
        let mut value = good.clone();
        value["view"]["phase"] = phase.into();
        assert_eq!(
            observe(&encoded(&value), &binding),
            Ok(Observation::Pending)
        );
    }
    for phase in ["failed", "uncertain"] {
        let mut value = good.clone();
        value["view"]["phase"] = phase.into();
        assert_eq!(
            observe(&encoded(&value), &binding),
            Err("completion-refused")
        );
    }
    for (key, value) in [
        ("schema", 2.into()),
        ("case", "other".into()),
        ("invocation", "2".repeat(32).into()),
        ("nonce", "f".repeat(32).into()),
        ("keeper_pid", 1.into()),
        ("keeper_birth", 2.into()),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert_eq!(
            observe(&encoded(&bad), &binding),
            Err("completion-binding"),
            "{key}"
        );
    }
    let mut wrong = expected(&invocation);
    wrong.keeper_uid += 1;
    assert_eq!(observe(&encoded(&good), &wrong), Err("completion-peer"));
    wrong = expected(&invocation);
    wrong.keeper_pid += 1;
    assert_eq!(observe(&encoded(&good), &wrong), Err("completion-peer"));
}
/// ´test:unit:completion-client-rejects-incomplete-and-failed-proofs´
#[test]
fn completion_client_rejects_incomplete_and_failed_proofs() {
    let invocation = invocation();
    let binding = expected(&invocation);
    let good = reply(&binding);
    for (pointer, value, class) in [
        (
            "/view/generator/result",
            "exit-code".into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator",
            serde_json::Value::Null,
            "completion-generator-evidence",
        ),
        (
            "/view/generator/successful",
            false.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/status",
            7.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/reply_sha256",
            "invalid".into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/configuration_sha256",
            "invalid".into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/code",
            0.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/started",
            0.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/exited",
            99.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/generator/invocation/birth",
            6.into(),
            "completion-generator-evidence",
        ),
        (
            "/view/sealers",
            serde_json::Value::Null,
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/eof/0",
            false.into(),
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/eof/1",
            false.into(),
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/exits/0/Code",
            7.into(),
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/exits/1/Code",
            7.into(),
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/sealed_bytes/0",
            0.into(),
            "completion-sealer-evidence",
        ),
        (
            "/view/sealers/sealed_bytes/1",
            4097.into(),
            "completion-sealer-evidence",
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert_eq!(observe(&encoded(&bad), &binding), Err(class), "{pointer}");
    }
}
/// ´test:unit:completion-client-record-is-closed-and-bounded´
#[test]
fn completion_client_record_is_closed_and_bounded() {
    let invocation = invocation();
    let binding = expected(&invocation);
    let good = reply(&binding);
    for pointer in [
        "/view",
        "/view/generator",
        "/view/generator/invocation",
        "/view/generator/invocation/image",
        "/view/sealers",
    ] {
        let mut value = good.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("foreign".into(), true.into());
        assert_eq!(
            observe(&encoded(&value), &binding),
            Err("completion-record"),
            "{pointer}"
        );
    }
    let mut unknown = good.clone();
    unknown["payload"] = "foreign".into();
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("nonce");
    let valid = String::from_utf8(encoded(&good)).unwrap();
    for bytes in [
        encoded(&unknown),
        encoded(&missing),
        valid.replacen('{', "{\"schema\":1,", 1).into_bytes(),
    ] {
        assert_eq!(observe(&bytes, &binding), Err("completion-record"));
    }
    assert_eq!(observe(b"", &binding), Err("control-closed"));
    assert_eq!(
        observe(valid.trim_end().as_bytes(), &binding),
        Err("control-record")
    );
    assert_eq!(observe(&vec![b'x'; 4097], &binding), Err("control-size"));
}
/// ´test:unit:completion-client-refuses-a-lost-keeper-despite-buffered-success´
#[test]
fn completion_client_refuses_a_lost_keeper_despite_buffered_success() {
    let f = crate::launch::keeper::tests::fixture();
    let socket = f.dir.path().join("peer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let mut command = Command::new(f.dir.path().join("launcher"));
    command
        .arg("--control-client")
        .arg(&socket)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let mut child = command.spawn().unwrap();
    let invocation = invocation();
    let mut binding = expected(&invocation);
    binding.keeper_pid = child.id();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&encoded(&reply(&binding)))
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut event = nix::libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    channel::poll(std::slice::from_mut(&mut event), 600_000).unwrap();
    assert_ne!(event.revents & nix::libc::POLLIN, 0);
    let mut ready = [0; 10];
    stdout.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"connected\n");
    let (mut stream, _) = listener.accept().unwrap();
    let handle = peer_pidfd(&stream).unwrap();
    child.kill().unwrap();
    let mut exited = nix::libc::pollfd {
        fd: handle.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    channel::poll(std::slice::from_mut(&mut exited), 600_000).unwrap();
    assert_ne!(exited.revents & nix::libc::POLLIN, 0);
    // The complete success frame was buffered before the event. The dead
    // connection peer cannot authenticate it, even while its pid is unreaped.
    assert_eq!(
        receive(
            &mut stream,
            &binding,
            Instant::now() + Duration::from_secs(600)
        ),
        Err("completion-keeper-lost")
    );
    child.wait().unwrap();
}
