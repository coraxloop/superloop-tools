use super::super::{keeper::tests::fixture, store::Invocation};
use super::*;
use std::fs;
use std::net::Shutdown;
use std::time::Duration;

/// ´test:unit:control-accept-exhaustion-retains-kernel-context-in-test-capture´
#[test]
#[allow(unsafe_code)]
fn control_accept_exhaustion_retains_kernel_context_in_test_capture() {
    const CHILD: &str = "CUSTODY_ACCEPT_EXHAUSTION_CHILD";
    if let Some(mode) = std::env::var_os(CHILD) {
        let _guard = super::super::test_support::case_guard();
        let (_fixture, control) = setup();
        let _client = std::os::unix::net::UnixStream::connect(format!(
            "/proc/self/fd/{}/control.sock",
            control.directory.file().as_raw_fd()
        ))
        .unwrap();
        let result = control.accept_with(Instant::now() + Duration::from_secs(600), || {
            let limits = nix::libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            };
            // SAFETY: only this reexecuted, single-test process changes limits.
            assert_eq!(
                unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NOFILE, &raw const limits) },
                0
            );
            let mut files = Vec::new();
            while let Ok(file) = fs::File::open("/dev/null") {
                files.push(file);
            }
            files
        });
        assert_eq!(result.err(), Some("control-accept"));
        let message = crate::process::diagnostic_message("control-accept");
        let (_, bytes) = message
            .split_once("; kernel=")
            .expect("accept retained kernel context");
        let context: serde_json::Value = serde_json::from_str(bytes).unwrap();
        assert_eq!(context["errno"], nix::libc::EMFILE);
        assert_eq!(context["open_descriptors"], 256);
        assert_eq!(context["nofile_soft"], 256);
        assert_eq!(context["test_threads"], 1);
        assert_ne!(mode, "fail", "deliberate captured failure");
        return;
    }
    for mode in ["pass", "fail"] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "launch::control::tests::control_accept_exhaustion_retains_kernel_context_in_test_capture", "--test-threads=1"]).env(CHILD, mode);
        loop_home::CommandDescriptors::default()
            .configure(&mut child)
            .unwrap();
        let output = child.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.success(),
            mode == "pass",
            "{stdout}\n{stderr}"
        );
        assert!(
            !stderr.contains("kernel="),
            "test context bypassed capture: {stderr}"
        );
        assert_eq!(stdout.contains("kernel="), mode == "fail", "{stdout}");
        if mode == "fail" {
            assert!(stdout.contains("deliberate captured failure"), "{stdout}");
        }
    }
}
fn setup() -> (crate::launch::tests::Fixture, Control) {
    setup_with(None)
}
fn setup_with(captured: Option<Invocation>) -> (crate::launch::tests::Fixture, Control) {
    let mut f = fixture();
    if captured.is_some() {
        let current = std::env::current_exe().unwrap();
        let image = current
            .ancestors()
            .take(8)
            .map(|p| p.join("examples/custody-startup-test"))
            .find(|p| p.is_file())
            .unwrap();
        let bytes = fs::read(image).unwrap();
        let path = f.dir.path().join("launcher");
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o555)).unwrap();
        f.value["artifacts"][0]["expected_sha256"] = crate::identity::hash(&bytes).into();
    }
    let admission = f.admit();
    let pipes = Pipes::create(&admission, 0).unwrap();
    let invocation = captured.unwrap_or_else(|| Invocation {
        id: "1234567890abcdef1234567890abcdef".into(),
        unit: admission.policy().cases[0].generator_unit.clone(),
        pid: 123,
        birth: 1,
        uid: nix::unistd::geteuid().as_raw(),
        image: admission.fixture_image(),
    });
    // A production keeper must still match the admitted image; the test runner
    // is deliberately a different inode from the small native control client.
    assert_eq!(
        Control::bind(
            &RootStartup::test_owner(),
            &pipes,
            &admission,
            0,
            &invocation
        )
        .err(),
        Some("keeper-image")
    );
    let control = Control::test_bind(
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
fn transaction(control: &Control, bytes: &[u8]) -> (Result<()>, Vec<u8>) {
    transaction_with(control, bytes, None)
}
fn transaction_with(
    control: &Control,
    bytes: &[u8],
    pin: Option<&ProcessPin>,
) -> (Result<()>, Vec<u8>) {
    transaction_at(control, bytes, pin, Phase::InventoryComplete)
}
fn transaction_at(
    control: &Control,
    bytes: &[u8],
    pin: Option<&ProcessPin>,
    phase: Phase,
) -> (Result<()>, Vec<u8>) {
    transaction_role(control, bytes, pin, phase, false)
}
fn transaction_role(
    control: &Control,
    bytes: &[u8],
    pin: Option<&ProcessPin>,
    phase: Phase,
    observer: bool,
) -> (Result<()>, Vec<u8>) {
    transaction_completion(control, bytes, pin, phase, observer, None)
}
fn transaction_completion(
    control: &Control,
    bytes: &[u8],
    pin: Option<&ProcessPin>,
    phase: Phase,
    observer: bool,
    completion: Option<&super::completion_client::View>,
) -> (Result<()>, Vec<u8>) {
    transaction_dispatch(control, bytes, pin, observer, |deadline| {
        pin.map_or_else(
            || {
                completion.map_or_else(
                    || control.serve_once(Phase::Captured, deadline),
                    |view| control.serve_completion(view, deadline),
                )
            },
            |pin| control.serve_pidfd(phase, deadline, pin, &"a".repeat(64)),
        )
    })
}
fn transaction_dispatch(
    control: &Control,
    bytes: &[u8],
    pin: Option<&ProcessPin>,
    observer: bool,
    serve: impl FnOnce(Instant) -> Result<()>,
) -> (Result<()>, Vec<u8>) {
    let path = format!(
        "/proc/{}/fd/{}/control.sock",
        std::process::id(),
        control.directory.file().as_raw_fd()
    );
    let directory = fs::read_link(format!(
        "/proc/self/fd/{}",
        control.directory.file().as_raw_fd()
    ))
    .unwrap();
    let path = if observer {
        directory.join("control.sock").display().to_string()
    } else {
        path
    };
    let image = directory
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("launcher");
    let mut command = std::process::Command::new(&image);
    command
        .args([
            if observer && pin.is_none() {
                "--observer-metadata"
            } else if observer {
                "--observer-client"
            } else if pin.is_some() {
                "--pidfd-client"
            } else {
                "--control-client"
            },
            &path,
        ])
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let mut child = command.spawn().unwrap();
    if pin.is_some() {
        let input = child.stdin.as_mut().unwrap();
        input
            .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
            .unwrap();
        input.write_all(bytes).unwrap();
    } else {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    let stdout = child.stdout.as_mut().unwrap();
    let mut ready = nix::libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    // Emergency hang guard only. The peer writes this ten-byte readiness frame
    // in one PIPE_BUF-sized write after it has connected and sent the request.
    super::super::channel::poll(std::slice::from_mut(&mut ready), 600_000).unwrap();
    assert_ne!(ready.revents & nix::libc::POLLIN, 0);
    let mut frame = [0; 10];
    stdout.read_exact(&mut frame).unwrap();
    assert_eq!(&frame, b"connected\n");
    let deadline = Instant::now() + Duration::from_secs(600);
    let result = serve(deadline);
    if pin.is_some() {
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
    }
    // A deadline can refuse before accept. Close this harness-owned queued
    // connection before waiting for its reader; the test never waits for time.
    if result.is_err()
        && let Ok((pending, _address)) = control.listener.accept()
    {
        drop(pending);
    }
    let output = child.wait_with_output().unwrap();
    if result.is_ok() {
        assert!(output.status.success());
    }
    (result, output.stdout)
}
fn encoded(value: &serde_json::Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(value).unwrap();
    b.push(b'\n');
    b
}
/// ´test:unit:control-transaction-binds-owner-image-case-and-keeper-birth´
#[test]
fn control_transaction_binds_owner_image_case_and_keeper_birth() {
    let _case = crate::launch::test_support::case_guard();
    let (_f, mut control) = setup();
    let (result, bytes) = transaction(&control, &encoded(&request(&control)));
    assert_eq!(result, Ok(()));
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["phase"], "captured");
    assert_eq!(reply["nonce"], "0123456789abcdef0123456789abcdef");
    assert_eq!(reply["invocation"], control.invocation);
    assert_eq!(
        control
            .authenticate(
                &UnixStream::pair().unwrap().0,
                control.owner + 1,
                std::process::id()
            )
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
        let (result, bytes) = transaction(&control, &encoded(&r));
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
        let (result, bytes) = transaction(&control, &encoded(&value));
        assert_eq!(result, Err("control-nonce"));
        assert_eq!(bytes.len(), 0);
    }
    let image = control.image;
    control.image = super::super::measure::ObjectIdentity {
        device: 0,
        inode: 0,
    };
    let (result, bytes) = transaction(&control, &encoded(&request(&control)));
    assert_eq!(result, Err("keeper-image"));
    assert_eq!(bytes.len(), 0);
    control.image = image;
    control.cleanup().unwrap();
}
/// ´test:unit:control-record-is-closed-bounded-and-metadata-only´
#[test]
fn control_record_is_closed_bounded_and_metadata_only() {
    let _case = crate::launch::test_support::case_guard();
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
        let (result, response) = transaction(&control, &bytes);
        assert_eq!(result, Err("control-record"));
        assert_eq!(response.len(), 0);
    }
    let (result, response) = transaction(&control, &vec![b'x'; REQUEST_LIMIT + 1]);
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
    let (result, response) = transaction(&control, &encoded(&request(&control)));
    assert_eq!(result, Err("control-deadline"));
    assert_eq!(response.len(), 0);
    control.cleanup().unwrap();
}
/// ´test:unit:control-cleanup-never-removes-a-replacement´
#[test]
fn control_cleanup_never_removes_a_replacement() {
    let _case = crate::launch::test_support::case_guard();
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

/// ´test:unit:control-refuses-signalling-peer-before-pidfd-transfer´
#[test]
fn control_refuses_signalling_peer_before_pidfd_transfer() {
    let _case = crate::launch::test_support::case_guard();
    let f = crate::launch::inventory::tests::fixture("normal");
    let (_readers, writers) = crate::launch::inventory::tests::pipes();
    let (_child, pin) = crate::launch::inventory::tests::start(&f, &writers);
    let (_control_files, mut control) = setup_with(Some(pin.invocation().clone()));
    let mut value = request(&control);
    value["operation"] = "pidfd".into();
    assert_eq!(
        transaction_at(&control, &encoded(&value), Some(&pin), Phase::Captured).0,
        Err("handoff-phase")
    );
    let original = control.invocation.clone();
    control.invocation = "b".repeat(32);
    let mut other = request(&control);
    other["operation"] = "pidfd".into();
    assert_eq!(
        transaction_with(&control, &encoded(&other), Some(&pin)).0,
        Err("handoff-invocation")
    );
    control.invocation = original;
    let (result, bytes) = transaction_with(&control, &encoded(&value), Some(&pin));
    // Ordinary-user processes retain CAP_KILL in their bounding set. Read it
    // live through the authenticated native peer and refuse before sending bytes.
    assert_eq!(result, Err("handoff-peer-signalling"));
    assert_eq!(bytes.len(), 0);
    pin.verify().unwrap();
}
/// ´test:unit:control-status-endpoint-refuses-descriptor-requests´
#[test]
fn control_status_endpoint_refuses_descriptor_requests() {
    let _case = crate::launch::test_support::case_guard();
    let (_files, status_only) = setup();
    let mut value = request(&status_only);
    value["operation"] = "pidfd".into();
    assert_eq!(
        transaction(&status_only, &encoded(&value)).0,
        Err("control-operation")
    );
}

/// ´test:unit:control-transfers-pidfd-to-a-nonsignalling-live-peer´
#[test]
fn control_transfers_pidfd_to_a_nonsignalling_live_peer() {
    let _case = crate::launch::test_support::case_guard();
    let f = crate::launch::inventory::tests::fixture("normal");
    let (_readers, writers) = crate::launch::inventory::tests::pipes();
    let (_child, pin) = crate::launch::inventory::tests::start(&f, &writers);
    let (_files, control) = setup_with(Some(pin.invocation().clone()));
    let mut value = request(&control);
    value["operation"] = "pidfd".into();
    let (result, bytes) = transaction_role(
        &control,
        &encoded(&value),
        Some(&pin),
        Phase::InventoryComplete,
        true,
    );
    assert_eq!(result, Ok(()));
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["invocation"]["pid"], pin.invocation().pid);
    assert_eq!(reply["invocation"]["birth"], pin.invocation().birth);
    assert_eq!(reply["nonce"], value["nonce"]);
    assert_eq!(reply["inventory_sha256"], "a".repeat(64));
    pin.verify().unwrap();
}

/// ´test:unit:control-peer-handle-refuses-a-different-live-process´
#[test]
#[allow(unsafe_code)]
fn control_peer_handle_refuses_a_different_live_process() {
    let _case = crate::launch::test_support::case_guard();
    let (_files, mut control) = setup();
    control.image =
        ObjectIdentity::of(&File::open(std::env::current_exe().unwrap()).unwrap()).unwrap();
    let (connection, _other) = UnixStream::pair().unwrap();
    let handle = peer_pidfd(&connection).unwrap();
    assert_ne!(
        nix::fcntl::fcntl(&handle, nix::fcntl::FcntlArg::F_GETFD).unwrap() & nix::libc::FD_CLOEXEC,
        0
    );
    let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    // SAFETY: the child performs only scalar async-signal-safe syscalls and
    // exits without Rust destructors. It never uses or passes the connection.
    let pid = unsafe { nix::libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if nix::libc::dup2(read.as_raw_fd(), 0) != 0
                || nix::libc::syscall(nix::libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) != 0
            {
                nix::libc::_exit(72);
            }
            let mut byte = 0_u8;
            nix::libc::read(0, std::ptr::from_mut(&mut byte).cast(), 1);
            nix::libc::_exit(0);
        }
    }
    let correct = control.authenticate(&connection, control.owner, std::process::id());
    let wrong = control.authenticate(&connection, control.owner, pid.cast_unsigned());
    // Release by an explicit byte, independent of other forks retaining a writer.
    nix::unistd::write(&write, &[1]).unwrap();
    let reaped = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).unwrap();
    assert_eq!(
        reaped,
        nix::sys::wait::WaitStatus::Exited(nix::unistd::Pid::from_raw(pid), 0)
    );
    correct.unwrap().verify().unwrap();
    assert_eq!(wrong.err(), Some("keeper-pidfd-binding"));
}

/// ´test:unit:completion-server-is-read-only-and-requires-its-operation´
#[test]
fn completion_server_is_read_only_and_requires_its_operation() {
    let _case = crate::launch::test_support::case_guard();
    let (_files, control) = setup();
    let mut value = request(&control);
    value["operation"] = "completion".into();
    assert_eq!(
        transaction(&control, &encoded(&value)).0,
        Err("control-operation")
    );
    let view = super::completion_client::View {
        phase: Phase::Released,
        generator: None,
        sealers: None,
    };
    let (result, bytes) = transaction_completion(
        &control,
        &encoded(&value),
        None,
        Phase::Released,
        false,
        Some(&view),
    );
    assert_eq!(result, Ok(()));
    let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["view"]["phase"], "released");
    assert_eq!(reply["view"]["generator"], serde_json::Value::Null);
    assert_eq!(reply["keeper_pid"], control.keeper.invocation().pid);
    assert_eq!(reply["keeper_birth"], control.keeper.invocation().birth);
    assert_eq!(reply["nonce"], value["nonce"]);
    value["operation"] = "pidfd".into();
    assert_eq!(
        transaction_completion(
            &control,
            &encoded(&value),
            None,
            Phase::Released,
            false,
            Some(&view)
        )
        .0,
        Err("control-operation")
    );
    control.cleanup().unwrap();
}

#[path = "control_action_tests.rs"]
mod action_tests;
