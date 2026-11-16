use super::*;
use crate::launch::{
    keeper::release::tests as harness, startup::RootStartup, store::Store, tests::Fixture,
};
use std::{
    fs,
    io::Write as _,
    os::{fd::AsRawFd as _, unix::fs::PermissionsExt as _},
    path::Path,
    process::{Command, Stdio},
};

/// ´test:unit:starting-binding-is-durable-before-process-capture´
#[test]
fn starting_binding_is_durable_before_process_capture() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let reply = String::from_utf8(crate::launch::manager::tests::reply(&admission))
        .unwrap()
        .replace("MainPID=123", "MainPID=0")
        .replace("ExecMainPID=123", "ExecMainPID=0")
        .replace(
            "ExecMainStartTimestampMonotonic=100",
            "ExecMainStartTimestampMonotonic=0",
        );
    fs::write(f.dir.path().join("manager-reply"), reply).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    keeper.submit().unwrap();
    assert!(!keeper.start_ready().unwrap());
    assert!(keeper.process.is_none());
    let path = f.dir.path().join("evidence/sample/lifecycle-01.json");
    let before = fs::read(&path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(record["event"]["kind"], "start-binding");
    assert_eq!(
        record["event"]["observation"]["invocation"],
        "1234567890abcdef1234567890abcdef"
    );
    assert_eq!(
        keeper.invocation.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
    assert!(!keeper.start_ready().unwrap());
    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(
        keeper.fail("synthetic-start-failure"),
        "synthetic-start-failure"
    );
}
fn setup() -> Fixture {
    let mut f = harness::setup("normal");
    install_launcher(&mut f);
    f
}
pub(in crate::launch::keeper) fn install_launcher(f: &mut Fixture) {
    let current = std::env::current_exe().unwrap();
    let native = current
        .ancestors()
        .take(8)
        .map(|p| p.join("examples/custody-startup-test"))
        .find(|p| p.is_file())
        .unwrap();
    let bytes = fs::read(native).unwrap();
    let path = f.dir.path().join("launcher");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
    f.value["artifacts"][0]["expected_sha256"] = crate::identity::hash(&bytes).into();
}
fn request(manifest: &serde_json::Value, operation: serde_json::Value) -> serde_json::Value {
    let mut value = serde_json::json!({"schema":2,"case":manifest["case"],"keeper_pid":manifest["keeper_pid"],"keeper_birth":manifest["keeper_birth"],"invocation":manifest["invocation"],"nonce":"a".repeat(32)});
    value["operation"] = operation;
    value
}
fn peer(root: &Path, value: &serde_json::Value, observer: bool) -> Result<Vec<u8>> {
    let mut command = Command::new(root.join("launcher"));
    command
        .arg(if observer {
            "--observer-metadata"
        } else {
            "--control-client"
        })
        .arg(
            root.join("runtime")
                .join(value["case"].as_str().ok_or("test-case")?)
                .join("control.sock"),
        )
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .map_err(|_| "test-descriptors")?;
    let mut child = command.spawn().map_err(|_| "test-spawn")?;
    let mut bytes = serde_json::to_vec(value).map_err(|_| "test-record")?;
    bytes.push(b'\n');
    child
        .stdin
        .take()
        .ok_or("test-input")?
        .write_all(&bytes)
        .map_err(|_| "test-input")?;
    let output = child.wait_with_output().map_err(|_| "test-wait")?;
    require(output.status.success(), "test-peer")?;
    output
        .stdout
        .strip_prefix(b"connected\n")
        .map(<[u8]>::to_vec)
        .ok_or("test-frame")
}
fn run_client(
    root: &Path,
    manifest: &serde_json::Value,
    mut child: crate::launch::inventory::tests::ChildGuard,
    exit: &std::os::fd::OwnedFd,
) -> Result<()> {
    let inventory = peer(
        root,
        &request(manifest, serde_json::json!("inventory")),
        true,
    )?;
    let value: serde_json::Value =
        serde_json::from_slice(&inventory).map_err(|_| "test-inventory")?;
    let digest = value["outcome"]["inventory"]["inventory_sha256"]
        .as_str()
        .ok_or("test-inventory")?;
    let released = peer(
        root,
        &request(
            manifest,
            serde_json::json!({"release":{"inventory_sha256":digest}}),
        ),
        true,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&released).map_err(|_| "test-release")?;
    require(
        value["outcome"]["released"]["inventory_sha256"] == digest,
        "test-release",
    )?;
    let mut event = nix::libc::pollfd {
        fd: exit.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    channel::poll(std::slice::from_mut(&mut event), 600_000)?;
    if event.revents & nix::libc::POLLIN == 0 {
        let _killed = child.child.kill();
        return Err("test-exit-guard");
    }
    require(
        child.child.wait().map_err(|_| "test-exit")?.success(),
        "test-exit",
    )?;
    let reply = fs::read_to_string(root.join("manager-reply"))
        .map_err(|_| "test-manager")?
        .replace(
            &format!("\nMainPID={}\n", child.child.id()),
            "\nMainPID=0\n",
        )
        .replace("ActiveState=activating", "ActiveState=active")
        .replace("SubState=start", "SubState=exited")
        .replace("ExecMainCode=0", "ExecMainCode=1")
        .replace(
            "ExecMainExitTimestampMonotonic=0",
            "ExecMainExitTimestampMonotonic=200",
        );
    // The manager stand-in publishes one complete property snapshot atomically.
    let staged = root.join("manager-terminal");
    fs::write(&staged, reply).map_err(|_| "test-manager")?;
    fs::rename(staged, root.join("manager-reply")).map_err(|_| "test-manager")?;
    loop {
        let mut query = request(manifest, serde_json::json!("completion"));
        query["schema"] = 1.into();
        let bytes = peer(root, &query, false)?;
        let reply: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "test-completion")?;
        if reply["view"]["phase"] == "complete" {
            break;
        }
        require(reply["view"]["phase"] == "released", "test-pending")?;
    }
    let reply = peer(
        root,
        &request(manifest, serde_json::json!("observed")),
        false,
    )?;
    require(reply.is_empty(), "test-observed")
}
fn manifest(f: &Fixture) -> serde_json::Value {
    serde_json::from_slice(
        &fs::read(f.dir.path().join("runtime/sample/control-manifest.json")).unwrap(),
    )
    .unwrap()
}
/// ´test:unit:resident-driver-completes-through-owned-transactions´
#[test]
fn resident_driver_completes_through_owned_transactions() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = harness::captured(&f, &admission, &mut keeper);
    let exit = keeper.process.as_ref().unwrap().duplicate().unwrap();
    let binding = manifest(&f);
    std::thread::scope(|scope| {
        let client = scope.spawn(|| run_client(f.dir.path(), &binding, child, &exit));
        assert_eq!(keeper.run_captured(), Ok(()));
        assert_eq!(client.join().unwrap(), Ok(()));
    });
    assert_eq!(keeper.phase(), Phase::Complete);
    drop(keeper);
    store.completed_case().unwrap();
    assert!(!f.dir.path().join("runtime/sample/control.sock").exists());
}
/// ´test:unit:resident-driver-refuses-wrong-order-and-binding-before-input´
#[test]
fn resident_driver_refuses_wrong_order_and_binding_before_input() {
    let _guard = crate::launch::test_support::case_guard();
    for (fault, class) in [
        ("invocation", "control-transaction"),
        ("observed", "keeper-observation-order"),
        ("release", "release-order"),
        ("digest", "inventory-receipt-digest"),
        ("duplicate", "inventory-order"),
    ] {
        let f = setup();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        let child = harness::captured(&f, &admission, &mut keeper);
        let binding = manifest(&f);
        std::thread::scope(|scope| {
            let client = scope.spawn(|| {
                if matches!(fault, "digest" | "duplicate") {
                    peer(
                        f.dir.path(),
                        &request(&binding, serde_json::json!("inventory")),
                        true,
                    )?;
                }
                let operation = match fault {
                    "observed" => serde_json::json!("observed"),
                    "release" | "digest" => {
                        serde_json::json!({"release":{"inventory_sha256":"f".repeat(64)}})
                    }
                    _ => serde_json::json!("inventory"),
                };
                let mut value = request(&binding, operation);
                if fault == "invocation" {
                    value["invocation"] = "f".repeat(32).into();
                }
                peer(f.dir.path(), &value, fault != "observed")
            });
            assert_eq!(keeper.run_captured(), Err(class), "{fault}");
            let _closed = client.join().unwrap();
        });
        assert_eq!(keeper.phase(), Phase::Uncertain);
        assert!(!harness::evidence(&f).join("completion.json").exists());
        drop(child);
    }
}
/// ´test:unit:resident-driver-expiry-does-not-wait-for-a-request´
#[test]
fn resident_driver_expiry_does_not_wait_for_a_request() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let _child = harness::captured(&f, &admission, &mut keeper);
    keeper.manager.cap_deadline(Instant::now());
    assert_eq!(keeper.run_captured(), Err("keeper-deadline"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
}

/// ´test:unit:resident-start-observes-pending-and-stopped-without-rebinding´
#[test]
fn resident_start_observes_pending_and_stopped_without_rebinding() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    keeper.submit().unwrap();
    let reply = String::from_utf8(crate::launch::manager::tests::reply(&admission)).unwrap();
    let pending = reply.replace("MainPID=123", "MainPID=0").replace(
        "ExecMainStartTimestampMonotonic=100",
        "ExecMainStartTimestampMonotonic=0",
    );
    fs::write(f.dir.path().join("manager-reply"), &pending).unwrap();
    assert_eq!(keeper.start_ready(), Ok(false));
    assert_eq!(
        keeper.invocation.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
    fs::write(
        f.dir.path().join("manager-reply"),
        pending.replace("1234567890abcdef1234567890abcdef", &"f".repeat(32)),
    )
    .unwrap();
    assert_eq!(keeper.start_ready(), Err("manager-invocation-binding"));
    let writers = keeper
        .pipes
        .paths()
        .each_ref()
        .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
    fs::set_permissions(
        f.dir.path().join("public.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let (_child, pin) = crate::launch::inventory::tests::start(&f, &writers);
    let pid = pin.invocation().pid;
    fs::write(
        f.dir.path().join("manager-reply"),
        reply.replace("MainPID=123", &format!("MainPID={pid}")),
    )
    .unwrap();
    assert_eq!(keeper.start_ready(), Ok(true));
    keeper.invocation = Some("f".repeat(32));
    assert_eq!(
        keeper.capture_with(
            |_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())),
            crate::launch::control::Control::test_bind
        ),
        Err("manager-invocation-binding")
    );
}

pub(in crate::launch::keeper) fn resident_case(
    f: &Fixture,
    admission: &crate::launch::measure::Admission,
    index: usize,
    store: &mut Store,
) -> Result<()> {
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), admission, index, store)?;
    keeper.submit()?;
    let writers = keeper
        .pipes
        .paths()
        .each_ref()
        .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
    fs::set_permissions(
        &admission.policy().cases[index].record,
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let (child, _pin) = crate::launch::inventory::tests::start_case(f, &writers, index);
    let reply = String::from_utf8(crate::launch::manager::tests::reply_case(admission, index))
        .unwrap()
        .replace("MainPID=123", &format!("MainPID={}", child.child.id()))
        .replace(
            "1234567890abcdef1234567890abcdef",
            &format!("{:032x}", index + 1),
        );
    fs::write(f.dir.path().join("manager-reply"), reply).unwrap();
    keeper.capture_with(
        |_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())),
        crate::launch::control::Control::test_bind,
    )?;
    drop(writers);
    let exit = keeper.process.as_ref().unwrap().duplicate()?;
    let binding = serde_json::from_slice(
        &fs::read(
            f.dir
                .path()
                .join("runtime")
                .join(&admission.policy().cases[index].id)
                .join("control-manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    std::thread::scope(|scope| {
        let client = scope.spawn(|| run_client(f.dir.path(), &binding, child, &exit));
        let result = keeper.run_captured();
        assert_eq!(client.join().unwrap(), Ok(()));
        result
    })
}
