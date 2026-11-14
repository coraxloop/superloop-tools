use super::super::{keeper::tests::fixture, store::Invocation};
use super::*;
use std::fs;
use std::net::Shutdown;
use std::time::Duration;
fn setup() -> (crate::launch::tests::Fixture, Control) {
    let f = fixture();
    let admission = f.admit();
    let pipes = Pipes::create(&admission, 0).unwrap();
    let invocation = Invocation {
        id: "1234567890abcdef1234567890abcdef".into(),
        unit: admission.policy().cases[0].generator_unit.clone(),
        pid: 123,
        birth: 1,
        uid: nix::unistd::geteuid().as_raw(),
        image: admission.fixture_image(),
    };
    let control = Control::bind(
        &RootStartup::test_owner(),
        &pipes,
        &admission,
        0,
        &invocation,
    )
    .unwrap();
    (f, control)
}
fn request(control: &Control) -> serde_json::Value {
    serde_json::json!({"schema":1,"case":"sample","keeper_pid":control.keeper.invocation().pid,"keeper_birth":control.keeper.invocation().birth,"invocation":control.invocation,"operation":"status","nonce":"0123456789abcdef0123456789abcdef"})
}
fn transaction(control: &Control, bytes: Vec<u8>) -> (Result<()>, Vec<u8>) {
    let path = format!(
        "/proc/self/fd/{}/control.sock",
        control.directory.file().as_raw_fd()
    );
    let mut client = UnixStream::connect(path).unwrap();
    let thread = std::thread::spawn(move || {
        let _write = client.write_all(&bytes);
        let _shutdown = client.shutdown(Shutdown::Write);
        let mut result = Vec::new();
        let _read = client.read_to_end(&mut result);
        result
    });
    let result = control.serve_once(Phase::Captured, Instant::now() + Duration::from_secs(600));
    // A deadline can refuse before accept. Close this harness-owned queued
    // connection before waiting for its reader; the test never waits for time.
    if result.is_err()
        && let Ok((pending, _address)) = control.listener.accept()
    {
        drop(pending);
    }
    let response = thread.join().unwrap();
    (result, response)
}
fn encoded(value: &serde_json::Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(value).unwrap();
    b.push(b'\n');
    b
}
/// ´test:unit:control-transaction-binds-owner-image-case-and-keeper-birth´
#[test]
fn control_transaction_binds_owner_image_case_and_keeper_birth() {
    let (_f, mut control) = setup();
    let (result, bytes) = transaction(&control, encoded(&request(&control)));
    assert_eq!(result, Ok(()));
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["phase"], "captured");
    assert_eq!(reply["nonce"], "0123456789abcdef0123456789abcdef");
    assert_eq!(reply["invocation"], control.invocation);
    assert_eq!(
        control
            .authenticate(control.owner + 1, std::process::id())
            .err(),
        Some("control-peer-owner")
    );
    for (key, value) in [
        ("schema", serde_json::json!(2)),
        ("case", serde_json::json!("other")),
        ("keeper_pid", serde_json::json!(1)),
        ("keeper_birth", serde_json::json!(0)),
        (
            "invocation",
            serde_json::json!("ffffffffffffffffffffffffffffffff"),
        ),
    ] {
        let mut r = request(&control);
        r[key] = value;
        let (result, bytes) = transaction(&control, encoded(&r));
        assert_eq!(result, Err("control-transaction"), "{key}");
        assert_eq!(bytes.len(), 0);
    }
    for nonce in [
        "",
        "not-hex",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdef0",
    ] {
        let mut value = request(&control);
        value["nonce"] = serde_json::json!(nonce);
        let (result, bytes) = transaction(&control, encoded(&value));
        assert_eq!(result, Err("control-nonce"));
        assert_eq!(bytes.len(), 0);
    }
    let image = control.image;
    control.image = super::super::measure::ObjectIdentity {
        device: 0,
        inode: 0,
    };
    let (result, bytes) = transaction(&control, encoded(&request(&control)));
    assert_eq!(result, Err("keeper-image"));
    assert_eq!(bytes.len(), 0);
    control.image = image;
    control.cleanup().unwrap();
}
/// ´test:unit:control-record-is-closed-bounded-and-metadata-only´
#[test]
fn control_record_is_closed_bounded_and_metadata_only() {
    let (_f, mut control) = setup();
    let mut unknown = request(&control);
    unknown["payload"] = serde_json::json!("foreign bytes");
    let mut operation = request(&control);
    operation["operation"] = serde_json::json!("release");
    let valid = String::from_utf8(encoded(&request(&control))).unwrap();
    let duplicate = valid.replacen('{', "{\"schema\":1,", 1);
    for bytes in [
        valid.trim_end().as_bytes().to_vec(),
        encoded(&unknown),
        encoded(&operation),
        duplicate.into_bytes(),
        b"not-json\n".to_vec(),
        format!("{valid}{valid}").into_bytes(),
    ] {
        let (result, response) = transaction(&control, bytes);
        assert_eq!(result, Err("control-record"));
        assert_eq!(response.len(), 0);
    }
    let (result, response) = transaction(&control, vec![b'x'; REQUEST_LIMIT + 1]);
    assert_eq!(result, Err("control-size"));
    assert_eq!(response.len(), 0);
    let path = format!(
        "/proc/self/fd/{}/control.sock",
        control.directory.file().as_raw_fd()
    );
    let mut pending = UnixStream::connect(path).unwrap();
    pending.write_all(&encoded(&request(&control))).unwrap();
    pending.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        control.serve_once(Phase::Captured, Instant::now()),
        Err("control-deadline")
    );
    drop(pending);
    let (stale, _address) = control.listener.accept().unwrap();
    drop(stale);
    control.deadline = Instant::now();
    let (result, response) = transaction(&control, encoded(&request(&control)));
    assert_eq!(result, Err("control-deadline"));
    assert_eq!(response.len(), 0);
    control.cleanup().unwrap();
}
/// ´test:unit:control-cleanup-never-removes-a-replacement´
#[test]
fn control_cleanup_never_removes_a_replacement() {
    let (f, control) = setup();
    let path = f.dir.path().join("runtime/sample/control.sock");
    let old = path.with_extension("old");
    fs::rename(&path, &old).unwrap();
    let foreign = UnixListener::bind(format!(
        "/proc/self/fd/{}/control.sock",
        control.directory.file().as_raw_fd()
    ))
    .unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    assert_eq!(control.cleanup(), Err("control-binding"));
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    drop(foreign);
    fs::remove_file(&path).unwrap();
    fs::rename(old, &path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap();
    assert_eq!(control.cleanup(), Err("control-binding"));
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let link = path.with_extension("link");
    fs::hard_link(&path, &link).unwrap();
    assert_eq!(control.cleanup(), Err("control-binding"));
    fs::remove_file(link).unwrap();
    control.cleanup().unwrap();
    assert_eq!(
        fs::metadata(f.dir.path().join("runtime/sample/control-manifest.json"))
            .unwrap()
            .mode()
            & 0o7777,
        0o400
    );
}
