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

/// ´test:unit:recovery-finishes-a-holder-stop-interrupted-by-termination´
#[test]
// Synthetic public record evidence stays inside libtest capture.
#[allow(clippy::print_stderr)]
fn recovery_finishes_a_holder_stop_interrupted_by_termination() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    let listener = crate::launch::stop::Guard::install().unwrap();
    let mut store = Store::reserve(&admission, 0).unwrap();
    fs::write(
        f.dir.path().join("manager-reply"),
        crate::launch::manager::tests::reply(&admission),
    )
    .unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    keeper.submit().unwrap();
    assert!(!keeper.start_ready().unwrap());
    assert!(keeper.invocation.is_some());
    fs::write(
        f.dir.path().join("manager-stop-signal"),
        nix::unistd::gettid().as_raw().to_string(),
    )
    .unwrap();
    let result = keeper.stop_holder();
    assert_eq!(result, Err("campaign-stopped"));
    assert!(f.dir.path().join("manager-stopped").exists());
    assert_eq!(keeper.release_result(result), Err("campaign-stopped"));
    let last = keeper
        .session
        .store()
        .failure_context()
        .last_lifecycle_receipt
        .unwrap();
    let recovery: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("evidence/sample").join(last)).unwrap())
            .unwrap();
    eprintln!("interrupted-stop recovery: {recovery}");
    assert_eq!(
        recovery["event"]["observation"]["holder"]["evidence"],
        "unit-unloaded"
    );
    assert_eq!(recovery["schema"], 3);
    assert_eq!(
        recovery["event"]["observation"]["holder"]["unit"],
        "synthetic-sample.service"
    );
    let last_call: serde_json::Value =
        serde_json::from_slice(&fs::read(f.dir.path().join("manager-argv.json")).unwrap()).unwrap();
    assert!(last_call.to_string().contains("show"));
    assert!(!last_call.to_string().contains("\"stop\""));
    assert!(f.dir.path().join("manager-stopped").exists());
    assert_eq!(recovery["original_cause"], "campaign-stopped");
    drop(keeper);
    listener.finish();
}

/// ´test:unit:recovery-adopts-only-the-whole-start-comparison´
#[test]
fn recovery_adopts_only_the_whole_start_comparison() {
    let _guard = crate::launch::test_support::case_guard();
    for fault in ["good", "slice", "state"] {
        let changed = fault != "good";
        let f = setup();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut reply = String::from_utf8(crate::launch::manager::tests::reply(&admission))
            .unwrap()
            .replace("MainPID=123", "MainPID=0")
            .replace("ExecMainPID=123", "ExecMainPID=0")
            .replace(
                "ExecMainStartTimestampMonotonic=100",
                "ExecMainStartTimestampMonotonic=0",
            );
        if fault == "slice" {
            reply = reply.replace(
                &format!("Slice={}", admission.policy().slice),
                "Slice=foreign.slice",
            );
        }
        if fault == "state" {
            reply = reply.replace("ActiveState=activating", "ActiveState=failed");
        }
        fs::write(f.dir.path().join("manager-reply"), reply).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        keeper.submit().unwrap();
        assert!(keeper.invocation.is_none());
        keeper
            .session
            .store()
            .uncertain("synthetic-start-interrupted")
            .unwrap();
        assert_eq!(
            keeper.fail("synthetic-start-interrupted"),
            "synthetic-start-interrupted"
        );
        assert_eq!(f.dir.path().join("manager-stopped").exists(), !changed);
        assert_eq!(keeper.invocation.is_some(), !changed);
        let context = keeper.session.store().failure_context();
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read(
                f.dir
                    .path()
                    .join("evidence/sample")
                    .join(context.last_lifecycle_receipt.unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value["original_cause"], "synthetic-start-interrupted");
        assert_eq!(
            value["event"]["observation"]["holder"]["evidence"],
            if changed {
                "unbound"
            } else {
                "stop-job-completed"
            }
        );
        if !changed {
            assert_eq!(
                value["binding"]["manager_configuration_sha256"]
                    .as_str()
                    .unwrap()
                    .len(),
                64
            );
        }
    }
}

/// ´test:unit:recovery-expired-allowance-never-starts-a-manager-call´
#[test]
fn recovery_expired_allowance_never_starts_a_manager_call() {
    let _guard = crate::launch::test_support::case_guard();
    for bound in [false, true] {
        let f = setup();
        let admission = f.admit();
        fs::write(
            f.dir.path().join("manager-reply"),
            crate::launch::manager::tests::reply(&admission),
        )
        .unwrap();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        keeper.submit().unwrap();
        if bound {
            keeper.invocation = Some("1234567890abcdef1234567890abcdef".into());
        }
        keeper
            .session
            .store()
            .uncertain("synthetic-start-interrupted")
            .unwrap();
        fs::remove_file(f.dir.path().join("manager-argv.json")).unwrap();
        assert_eq!(
            keeper
                .recover_holder(
                    Instant::now()
                        .checked_sub(std::time::Duration::from_secs(1))
                        .unwrap()
                )
                .map(|_| ()),
            Err("manager-deadline")
        );
        assert!(!f.dir.path().join("manager-argv.json").exists());
        assert!(!f.dir.path().join("manager-stopped").exists());
        keeper.terminal = true; // This core-only control has deliberately spent its allowance.
    }
}

/// ´test:unit:keeper-signal-mask-does-not-escape-into-held-exec´
#[test]
fn keeper_signal_mask_does_not_escape_into_held_exec() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let listener = crate::launch::stop::Guard::install().unwrap();
    let mut command = Command::new(f.dir.path().join("manager-start"));
    command.arg("--signal-mask");
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let output = crate::process::capture(
        command,
        &[],
        &crate::record::Limits {
            file_bytes: 0,
            output_bytes: 128,
            timeout_ms: 600_000,
        },
    )
    .unwrap();
    assert_eq!(output, b"false false\n");
    listener.finish();
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

/// ´test:unit:keeper-child-reply-cannot-cross-an-observed-stop´
#[test]
#[allow(unsafe_code)]
fn keeper_child_reply_cannot_cross_an_observed_stop() {
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let listener = crate::launch::stop::Guard::install().unwrap();
    let mut command = Command::new(f.dir.path().join("manager-start"));
    // SAFETY: gettid only identifies this thread for the child-to-parent event.
    command
        .arg("--signal-keeper")
        .arg(unsafe { nix::libc::syscall(nix::libc::SYS_gettid) }.to_string());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let result = crate::process::capture(
        command,
        &[],
        &crate::record::Limits {
            file_bytes: 0,
            output_bytes: 128,
            timeout_ms: 600_000,
        },
    );
    // Consume even if a mutation let the reply through, so restoring the mask
    // cannot terminate libtest before its acceptance assertion is reported.
    let observed = crate::launch::stop::check();
    let request = crate::launch::stop::request();
    listener.finish();
    assert_eq!(result, Err("campaign-stopped"));
    assert_eq!(observed, Err("campaign-stopped"));
    assert_eq!(request.unwrap().signal, 15);
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

fn doomed_keeper_control() {
    use std::io::Read as _;
    let _guard = crate::launch::test_support::case_guard();
    let f = setup();
    let admission = f.admit();
    fs::write(
        f.dir.path().join("policy.json"),
        serde_json::to_vec(&f.value).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        f.dir.path().join("policy.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let _result = crate::launch::campaign::run(
        &admission,
        Instant::now() + std::time::Duration::from_secs(600),
        |index, store, _| {
            let reply = String::from_utf8(crate::launch::manager::tests::reply(&admission))
                .unwrap()
                .replace("MainPID=123", "MainPID=0")
                .replace("ExecMainPID=123", "ExecMainPID=0")
                .replace(
                    "ExecMainStartTimestampMonotonic=100",
                    "ExecMainStartTimestampMonotonic=0",
                );
            fs::write(f.dir.path().join("manager-reply"), reply).unwrap();
            let mut keeper =
                Keeper::prepare(RootStartup::test_owner(), &admission, index, store).unwrap();
            keeper.submit().unwrap();
            assert!(!keeper.start_ready().unwrap());
            let ready =
                serde_json::json!({"root":f.dir.path(),"sealers":keeper.session.test_pids()});
            writeln!(std::io::stdout(), "keeper-ready {ready}").unwrap();
            std::io::stdout().flush().unwrap();
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
            panic!("the parent must kill the keeper, never release this wait");
        },
    );
    panic!("the killed campaign must not return");
}
fn keeper_ready(stdout: &mut std::process::ChildStdout) -> serde_json::Value {
    use std::io::Read as _;
    let deadline = Instant::now() + std::time::Duration::from_secs(600);
    let mut line = Vec::new();
    loop {
        let mut event = nix::libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let timeout =
            crate::launch::sealer::remaining_timeout(Instant::now(), deadline, deadline).unwrap();
        assert!(
            channel::poll(std::slice::from_mut(&mut event), timeout).unwrap(),
            "600 s event hang guard"
        );
        let mut byte = [0];
        stdout.read_exact(&mut byte).unwrap();
        line.push(byte[0]);
        assert!(line.len() <= 4096);
        if byte[0] == b'\n' {
            let text = std::str::from_utf8(&line).unwrap();
            if let Some((_, value)) = text.split_once("keeper-ready ") {
                return serde_json::from_str(value).unwrap();
            }
            line.clear();
        }
    }
}
struct DoomedControl {
    finished: bool,
    child: std::process::Child,
    sealers: Vec<std::os::fd::OwnedFd>,
    root: Option<std::path::PathBuf>,
}
impl Drop for DoomedControl {
    fn drop(&mut self) {
        if !self.finished {
            let _status = crate::process::cancel(&mut self.child);
        }
        for fd in &self.sealers {
            crate::process::kill_pidfd(std::os::fd::AsFd::as_fd(fd));
        }
        if let Some(root) = &self.root {
            let _removed = fs::remove_dir_all(root);
        }
    }
}
/// ´test:unit:killed-keeper-leaves-binding-and-no-terminal-but-sealers-exit´
#[test]
fn killed_keeper_leaves_binding_and_no_terminal_but_sealers_exit() {
    use std::os::unix::process::CommandExt as _;
    if std::env::var_os("CUSTODY_KEEPER_DEATH_CONTROL").is_some() {
        doomed_keeper_control();
        return;
    }
    let _guard = crate::launch::test_support::case_guard();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact","launch::keeper::driver::tests::killed_keeper_leaves_binding_and_no_terminal_but_sealers_exit","--nocapture","--test-threads=1"])
        .env_clear().env("TMPDIR",std::env::temp_dir()).env("CUSTODY_KEEPER_DEATH_CONTROL","1")
        .process_group(0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let mut control = DoomedControl {
        finished: false,
        child: command.spawn().unwrap(),
        sealers: Vec::new(),
        root: None,
    };
    let ready = keeper_ready(control.child.stdout.as_mut().unwrap());
    let root = std::path::PathBuf::from(ready["root"].as_str().unwrap());
    control.root = Some(root.clone());
    for pid in ready["sealers"].as_array().unwrap() {
        control.sealers.push(
            crate::launch::sealer::pidfd(u32::try_from(pid.as_u64().unwrap()).unwrap()).unwrap(),
        );
    }
    assert_eq!(control.sealers.len(), 2);
    // Keep external writers alive after the keeper dies: EOF cannot explain exit.
    let writers = ["left.fifo", "right.fifo"].map(|name| {
        fs::OpenOptions::new()
            .write(true)
            .open(root.join("runtime/sample").join(name))
            .unwrap()
    });
    let binding: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("evidence/sample/lifecycle-01.json")).unwrap())
            .unwrap();
    assert_eq!(
        binding["event"]["observation"]["invocation"],
        "1234567890abcdef1234567890abcdef"
    );
    control.child.kill().unwrap();
    control.child.wait().unwrap();
    control.finished = true;
    let deadline = Instant::now() + std::time::Duration::from_secs(600);
    for fd in &control.sealers {
        let mut event = nix::libc::pollfd {
            fd: fd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        let timeout =
            crate::launch::sealer::remaining_timeout(Instant::now(), deadline, deadline).unwrap();
        assert!(
            channel::poll(std::slice::from_mut(&mut event), timeout).unwrap(),
            "600 s event hang guard"
        );
        assert_ne!(event.revents & nix::libc::POLLIN, 0);
    }
    drop(writers);
    for entry in fs::read_dir(root.join("evidence/sample")).unwrap() {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap();
        assert!(!["failed", "uncertain", "complete"].contains(&value["phase"].as_str().unwrap()));
        assert_ne!(value["event"]["kind"], "recovery");
    }
    assert!(root.join("runtime/sample/left.fifo").exists());
    assert!(!root.join("evidence/campaign-failure.json").exists());
}
