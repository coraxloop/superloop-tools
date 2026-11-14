use super::super::{manager, measure::ObjectIdentity, sealer_tests::make_fixture, tests::Fixture};
use super::*;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::{fs::PermissionsExt as _, process::CommandExt as _};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
pub(in crate::launch) fn fixture() -> Fixture {
    let mut f = make_fixture("normal");
    manager::tests::add_images(&mut f);
    f.value["limits"]["artifact_bytes"] = (128 * 1024 * 1024).into();
    let peer = f.dir.path().join("manager-start");
    let bytes = fs::read(peer).unwrap();
    let path = f.dir.path().join("fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
    f.value["artifacts"][1]["expected_sha256"] = crate::identity::hash(&bytes).into();
    let own = std::env::current_exe().unwrap();
    f.value["artifacts"][0]["path"] = own.to_str().unwrap().into();
    f.value["artifacts"][0]["expected_sha256"] =
        crate::identity::hash(&fs::read(&own).unwrap()).into();
    f
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_some()) {
            return;
        }
        let _killed = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(i32::try_from(self.0.id()).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _reaped = self.0.wait();
    }
}
#[allow(unsafe_code)]
fn start(fixture: &Fixture, pipes: &Pipes) -> (ChildGuard, [File; 2]) {
    let writers = pipes
        .paths()
        .each_ref()
        .map(|p| fs::OpenOptions::new().append(true).open(p).unwrap());
    let copies = writers.each_ref().map(|f| {
        let raw = nix::fcntl::fcntl(f, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(10)).unwrap();
        unsafe { OwnedFd::from_raw_fd(raw) }
    });
    let path = fixture.dir.path().join("fixture");
    let mut command = Command::new(&path);
    command
        .args(["emit", "--case-record"])
        .arg(fixture.dir.path().join("public.json"))
        .env_clear()
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    // SAFETY: only descriptor syscalls and retained copies after fork. Sources
    // are above the destination slots and remain CLOEXEC after dup2.
    unsafe {
        command.pre_exec(move || {
            for (copy, slot) in copies.iter().zip([3, 4]) {
                if nix::libc::dup2(copy.as_raw_fd(), slot) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = ChildGuard(command.spawn().unwrap());
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap());
    let (send, receive) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        send.send(nix::sys::wait::waitpid(
            pid,
            Some(nix::sys::wait::WaitPidFlag::WUNTRACED),
        ))
        .unwrap();
    });
    let stopped = receive.recv_timeout(Duration::from_secs(600));
    if stopped.is_err() {
        let _killed = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
    }
    waiter.join().unwrap();
    assert_eq!(
        stopped.unwrap().unwrap(),
        nix::sys::wait::WaitStatus::Stopped(pid, nix::sys::signal::Signal::SIGSTOP)
    );
    (child, writers)
}
fn set_reply(fixture: &Fixture, admission: &Admission, pid: u32) {
    let text = String::from_utf8(manager::tests::reply(admission))
        .unwrap()
        .replace("MainPID=123", &format!("MainPID={pid}"));
    fs::write(fixture.dir.path().join("manager-reply"), text).unwrap();
}
fn captured(fixture: &Fixture, admission: &Admission, keeper: &mut Keeper<'_>) -> ChildGuard {
    keeper.submit().unwrap();
    let (child, writers) = start(fixture, &keeper.pipes);
    set_reply(fixture, admission, child.0.id());
    keeper
        .capture_with(|_| Ok(writers.each_ref().map(|f| f.try_clone().unwrap())))
        .unwrap();
    drop(writers);
    child
}
/// ´test:unit:keeper-captures-real-stopped-image-with-manager-stand-in´
#[test]
fn keeper_captures_real_stopped_image_with_manager_stand_in() {
    let f = fixture();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    assert_eq!(keeper.phase(), Phase::Captured);
    keeper.verify_capture().unwrap();
    assert_eq!(
        keeper.capture_with(|_| panic!("duplicate capture must not copy")),
        Err("keeper-capture-order")
    );
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/sample/state-03.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["invocation"]["pid"], child.0.id());
    assert_eq!(
        receipt["manager_reply_sha256"],
        crate::identity::hash(&fs::read(f.dir.path().join("manager-reply")).unwrap())
    );
    assert_eq!(
        receipt["manager_configuration_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(keeper.fail("synthetic-abort"), "synthetic-abort");
    assert_eq!(keeper.phase(), Phase::Failed);
    assert_eq!(keeper.fail("retry"), "keeper-terminal");
    drop(child);
}
/// ´test:unit:keeper-contradiction-and-ambiguous-start-retain-quarantine´
#[test]
fn keeper_contradiction_and_ambiguous_start_retain_quarantine() {
    let f = fixture();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    fs::write(f.dir.path().join("manager-start-output"), b"foreign").unwrap();
    assert_eq!(keeper.submit(), Err("manager-start-output"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
    assert_eq!(
        fs::read_dir(f.dir.path().join("sealed/sample"))
            .unwrap()
            .count(),
        2
    );
    let f = fixture();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    keeper.submit().unwrap();
    let (child, writers) = start(&f, &keeper.pipes);
    set_reply(&f, &admission, child.0.id());
    assert_eq!(
        keeper.capture_with(|_| Ok([
            writers[0].try_clone().unwrap(),
            writers[0].try_clone().unwrap()
        ])),
        Err("fifo-writer-binding")
    );
    assert_eq!(keeper.phase(), Phase::Uncertain);
    assert_eq!(keeper.capture(), Err("keeper-capture-order"));
    drop(child);
}
/// ´test:unit:keeper-refuses-invocation-drift-and-preserves-first-failure´
#[test]
fn keeper_refuses_invocation_drift_and_preserves_first_failure() {
    let f = fixture();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    let path = f.dir.path().join("manager-reply");
    let text = fs::read_to_string(&path).unwrap().replace(
        "1234567890abcdef1234567890abcdef",
        "ffffffffffffffffffffffffffffffff",
    );
    fs::write(path, text).unwrap();
    assert_eq!(keeper.verify_capture(), Err("manager-invocation-binding"));
    assert_eq!(keeper.phase(), Phase::Uncertain);
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/sample/state-04.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["original_cause"], "manager-invocation-binding");
    assert_eq!(receipt["refusal_class"], "manager-invocation-binding");
    assert_eq!(
        fs::read_dir(f.dir.path().join("sealed/sample"))
            .unwrap()
            .count(),
        2
    );
    drop(child);
}
/// ´test:unit:process-pin-refuses-wrong-image-command-and-exit´
#[test]
fn process_pin_refuses_wrong_image_command_and_exit() {
    let f = fixture();
    let admission = f.admit();
    let pipes = Pipes::create(&admission, 0).unwrap();
    let (mut child, writers) = start(&f, &pipes);
    let id = "1234567890abcdef1234567890abcdef";
    let path = f.dir.path().join("fixture");
    let record = f.dir.path().join("public.json");
    let args = [
        path.as_path(),
        Path::new("emit"),
        Path::new("--case-record"),
        record.as_path(),
    ];
    assert_eq!(
        ProcessPin::capture(
            child.0.id(),
            "synthetic-sample.service",
            id,
            ObjectIdentity {
                device: 0,
                inode: 0
            },
            &args
        )
        .err(),
        Some("keeper-image")
    );
    assert_eq!(
        ProcessPin::capture(
            child.0.id(),
            "synthetic-sample.service",
            id,
            admission.fixture_image(),
            &[]
        )
        .err(),
        Some("keeper-command")
    );
    let pin = ProcessPin::capture(
        child.0.id(),
        "synthetic-sample.service",
        id,
        admission.fixture_image(),
        &args,
    )
    .unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(pin.verify(), Err("keeper-process-exited"));
    drop(writers);
}

/// ´test:unit:resident-startup-closes-ambient-descriptors-before-residency´
#[test]
#[allow(unsafe_code)]
fn resident_startup_closes_ambient_descriptors_before_residency() {
    let f = fixture();
    let file = tempfile::tempfile().unwrap();
    let raw = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(1000)).unwrap();
    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let program = f.dir.path().join("manager-start");
    let mut command = Command::new(&program);
    command
        .args(["--startup-control", &raw.to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    loop_home::CommandDescriptors::inherit(vec![fd])
        .unwrap()
        .configure(&mut command)
        .unwrap();
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"resident-descriptors-closed\n");
    let mut command = Command::new(&program);
    command
        .arg("--root-control")
        .env_clear()
        .stdin(Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut command)
        .unwrap();
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"root-required\n");
}

/// ´test:unit:keeper-refuses-live-pid-and-barrier-state-drift´
#[test]
fn keeper_refuses_live_pid_and_barrier_state_drift() {
    for (field, value, class) in [
        ("MainPID", "999999", "keeper-process-binding"),
        ("ActiveState", "active", "keeper-unit-state"),
        ("SubState", "running", "keeper-unit-state"),
        ("ExecMainCode", "1", "keeper-unit-state"),
        ("ExecMainStatus", "1", "keeper-unit-state"),
        ("Result", "exit-code", "keeper-unit-state"),
    ] {
        let f = fixture();
        let admission = f.admit();
        let mut store = Store::reserve(&admission, 0).unwrap();
        let mut keeper =
            Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
        let child = captured(&f, &admission, &mut keeper);
        let path = f.dir.path().join("manager-reply");
        let text = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{field}=")) {
                    format!("{field}={value}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect::<String>();
        fs::write(path, text).unwrap();
        assert_eq!(keeper.verify_capture(), Err(class), "{field}");
        assert_eq!(keeper.phase(), Phase::Uncertain);
        assert_eq!(
            fs::read_dir(f.dir.path().join("sealed/sample"))
                .unwrap()
                .count(),
            2
        );
        drop(child);
    }
}

/// ´test:unit:keeper-failed-stop-keeps-the-original-cause´
#[test]
fn keeper_failed_stop_keeps_the_original_cause() {
    let f = fixture();
    let admission = f.admit();
    let mut store = Store::reserve(&admission, 0).unwrap();
    let mut keeper = Keeper::prepare(RootStartup::test_owner(), &admission, 0, &mut store).unwrap();
    let child = captured(&f, &admission, &mut keeper);
    fs::write(f.dir.path().join("manager-stop-output"), b"foreign").unwrap();
    assert_eq!(keeper.fail("generator-failed"), "generator-failed");
    assert_eq!(keeper.phase(), Phase::Uncertain);
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(f.dir.path().join("evidence/sample/state-04.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["original_cause"], "generator-failed");
    assert_eq!(receipt["refusal_class"], "manager-stop");
    assert_eq!(
        fs::read_dir(f.dir.path().join("sealed/sample"))
            .unwrap()
            .count(),
        2
    );
    drop(child);
}
