//! A small synthetic supervisor proves only the fixture side of the protocol.
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{Pid, pipe2};
use serde_json::{Value, json};
use std::ffi::CString;
use std::fs;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Serialize staging and fork: another test child must not inherit a staging
// writer and transiently deny exec with ETXTBSY. This does not serialize streams.
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
const BINARY: &str = env!("CARGO_BIN_EXE_credential-fixture");
struct Case {
    dir: tempfile::TempDir,
    value: Value,
}
impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            value: json!({"schema":1,"command":"fixture-emit","case":"synthetic",
            "streams":[{"name":"left","length":5,"pattern":"ascending"},{"name":"right","length":5,"pattern":"descending"}],
            "behavior":"normal","timeout_ms":1000}),
        }
    }
    fn save(&self) -> std::path::PathBuf {
        let path = self.dir.path().join("case.json");
        fs::write(&path, serde_json::to_vec(&self.value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        path
    }
}
struct Observed {
    output: std::process::Output,
    streams: [Vec<u8>; 2],
    stopped: bool,
    extra: bool,
}

// A negative-control assertion must not leave a stopped fixture behind.
struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

// Keep the pre-fork resources and their child callback in one reviewed lifetime.
#[allow(unsafe_code, clippy::too_many_lines)]
fn invoke(case: &Case, convention: &str, raw: Option<&[u8]>, mode: u32, drain: bool) -> Observed {
    let _guard = SPAWN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = case.save();
    if let Some(bytes) = raw {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, bytes).unwrap();
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    if convention == "symlink" {
        let saved = case.dir.path().join("saved.json");
        fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &path).unwrap();
    }
    if convention == "hardlink" {
        fs::hard_link(&path, case.dir.path().join("alias.json")).unwrap();
    }

    let (read_a, write_a) = pipe2(OFlag::O_CLOEXEC).unwrap();
    let mut read_a = Some(read_a);
    let (read_b, write_b) = pipe2(OFlag::O_CLOEXEC).unwrap();
    // Stable high source slots avoid dup2 collisions with the convention slots.
    let high = |fd: &OwnedFd| {
        let raw = fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(100)).unwrap();
        // SAFETY: a fresh owned duplicate is returned by F_DUPFD_CLOEXEC.
        unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) }
    };
    let wrong_file = fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    let a = if convention == "wrong-kind" {
        high(&wrong_file.into())
    } else {
        high(&write_a)
    };
    let b = high(&write_b);
    let read_source = high(read_a.as_ref().unwrap());
    let staged = case.dir.path().join("credential-fixture");
    fs::copy(BINARY, &staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o555)).unwrap();
    let executable = CString::new(staged.as_os_str().as_encoded_bytes()).unwrap();
    let args = [
        executable.clone(),
        CString::new("emit").unwrap(),
        CString::new("--case-record").unwrap(),
        CString::new(path.as_os_str().as_encoded_bytes()).unwrap(),
    ];
    let count = CString::new(match convention {
        "count" => "LISTEN_FDS=3",
        "missing-count" => "NOT_LISTEN_FDS=2",
        _ => "LISTEN_FDS=2",
    })
    .unwrap();
    let names = CString::new(match convention {
        "repeat" => "LISTEN_FDNAMES=left:left",
        "wrong-name" => "LISTEN_FDNAMES=left:alien",
        "extra-name" => "LISTEN_FDNAMES=left:right:extra",
        "reverse" => "LISTEN_FDNAMES=right:left",
        "missing-names" => "NOT_LISTEN_FDNAMES=left:right",
        _ => "LISTEN_FDNAMES=left:right",
    })
    .unwrap();
    let marker = CString::new(if convention == "marker" {
        "CREDENTIAL_FIXTURE_REEXEC=invalid"
    } else {
        "FIXTURE_TEST=metadata"
    })
    .unwrap();
    let wrong_pid = convention == "pid";
    let missing_pid = convention == "missing-pid";
    let missing = convention == "missing-fd";
    let alias = convention == "alias";
    let readonly = convention == "readonly";
    // The root-refusal control needs enabled unprivileged user namespaces.
    // A gate without them cannot execute this control; it is not a product failure.
    let root_namespace = convention == "root";
    let mapping = format!("0 {} 1\n", nix::unistd::geteuid()).into_bytes();
    let mapping_length = isize::try_from(mapping.len()).unwrap();
    let raw_a = a.as_raw_fd();
    let raw_b = b.as_raw_fd();
    let raw_read = read_source.as_raw_fd();
    let mut command = Command::new(BINARY);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: child-only callback performs raw fd/user-namespace/exec syscalls and stack
    // arithmetic only. All C strings are prepared before fork. No allocation,
    // environment mutation, lock or foreign runtime runs after fork.
    unsafe {
        command.pre_exec(move || {
            if root_namespace {
                if nix::libc::unshare(nix::libc::CLONE_NEWUSER) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let map = nix::libc::open(
                    c"/proc/self/uid_map".as_ptr(),
                    nix::libc::O_WRONLY | nix::libc::O_CLOEXEC,
                );
                if map < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let n = nix::libc::write(map, mapping.as_ptr().cast(), mapping.len());
                nix::libc::close(map);
                if n != mapping_length {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if nix::libc::dup2(if readonly { raw_read } else { raw_a }, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if missing {
                nix::libc::close(4);
            } else if nix::libc::dup2(if alias { raw_a } else { raw_b }, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Only stdio and the two convention streams cross exec. Mark rather
            // than close so Rust's spawn-error pipe still reports exec failures.
            if nix::libc::syscall(nix::libc::SYS_close_range, 5_u32, u32::MAX, 4_u32) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut pid = if wrong_pid {
                1
            } else {
                nix::libc::getpid().unsigned_abs()
            };
            let mut digits = [0_u8; 16];
            let mut n = 0;
            while pid > 0 {
                digits[n] = b'0' + (pid % 10) as u8;
                pid /= 10;
                n += 1;
            }
            let mut variable = [0_u8; 32];
            variable[..11].copy_from_slice(if missing_pid {
                b"ABSENT_PID="
            } else {
                b"LISTEN_PID="
            });
            for i in 0..n {
                variable[11 + i] = digits[n - 1 - i];
            }
            let env = [
                variable.as_ptr().cast(),
                count.as_ptr(),
                names.as_ptr(),
                marker.as_ptr(),
                std::ptr::null(),
            ];
            let pointers = [
                args[0].as_ptr(),
                args[1].as_ptr(),
                args[2].as_ptr(),
                args[3].as_ptr(),
                std::ptr::null(),
            ];
            nix::libc::execve(executable.as_ptr(), pointers.as_ptr(), env.as_ptr());
            Err(std::io::Error::last_os_error())
        });
    }
    let mut child = ChildGuard(Some(command.spawn().unwrap()));
    drop(command);
    drop(a);
    drop(b);
    drop(read_source);
    drop(write_a);
    drop(write_b);
    let pid = Pid::from_raw(i32::try_from(child.0.as_ref().unwrap().id()).unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = false;
    let mut extra = false;
    loop {
        match waitid(
            Id::Pid(pid),
            WaitPidFlag::WSTOPPED
                | WaitPidFlag::WEXITED
                | WaitPidFlag::WNOHANG
                | WaitPidFlag::WNOWAIT,
        )
        .unwrap()
        {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => {
                stopped = true;
                // The observer, never the fixture, enumerates descriptors.
                extra = fs::read_dir(format!("/proc/{}/fd", pid.as_raw()))
                    .unwrap()
                    .filter_map(std::result::Result::ok)
                    .any(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .parse::<u32>()
                            .is_ok_and(|fd| fd >= 5)
                    });
                for fd in [read_a.as_ref().unwrap(), &read_b] {
                    fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
                    let mut byte = [0];
                    assert_eq!(
                        nix::unistd::read(fd, &mut byte).unwrap_err(),
                        nix::errno::Errno::EAGAIN,
                        "no bytes before release"
                    );
                    fcntl(fd, FcntlArg::F_SETFL(OFlag::empty())).unwrap();
                }
                if convention == "broken" {
                    drop(read_a.take());
                }
                kill(pid, Signal::SIGCONT).unwrap();
                break;
            }
            WaitStatus::StillAlive => {}
            _ => break,
        }
        if Instant::now() >= deadline {
            let _ignored = child.0.as_mut().unwrap().kill();
            panic!("fixture did not reach barrier or exit");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let readers = [read_a, Some(read_b)].map(|fd| {
        std::thread::spawn(move || {
            if !drain {
                std::thread::sleep(Duration::from_millis(1500));
            }
            let mut bytes = Vec::new();
            if let Some(fd) = fd {
                fs::File::from(fd).read_to_end(&mut bytes).unwrap();
            }
            bytes
        })
    });
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    let mut streams = readers.into_iter().map(|r| r.join().unwrap());
    Observed {
        output,
        streams: [streams.next().unwrap(), streams.next().unwrap()],
        stopped,
        extra,
    }
}
fn refuse(observed: &Observed, class: &str) {
    assert_eq!(
        observed.output.status.code(),
        Some(1),
        "{:?}",
        observed.output
    );
    assert_eq!(observed.output.stdout, b"");
    let diagnostic: Value = serde_json::from_slice(&observed.output.stderr).unwrap();
    assert_eq!(diagnostic["message"], class);
}
/// ´test:integration:fixture-patterns-and-barrier´
#[test]
#[allow(unsafe_code)]
fn fixture_patterns_and_barrier() {
    let input = fs::File::open("/dev/null").unwrap();
    let raw = fcntl(&input, FcntlArg::F_DUPFD(5)).unwrap();
    // SAFETY: F_DUPFD returns a fresh owned descriptor without CLOEXEC. Keep
    // this parent descriptor alive while the normal invocation crosses exec.
    let inherited = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
    assert_eq!(fcntl(&inherited, FcntlArg::F_GETFD).unwrap(), 0);
    let observed = invoke(&Case::new(), "normal", None, 0o400, true);
    assert!(observed.output.status.success(), "{:?}", observed.output);
    assert!(observed.stopped);
    assert!(!observed.extra);
    assert_eq!(
        observed.streams,
        [vec![0, 1, 2, 3, 4], vec![255, 254, 253, 252, 251]]
    );
    drop(inherited);
    for length in [1_u64, 3, 4, 5, 4096, 65537] {
        let mut case = Case::new();
        for stream in case.value["streams"].as_array_mut().unwrap() {
            stream["length"] = json!(length);
        }
        let observed = invoke(&case, "normal", None, 0o400, true);
        assert!(observed.output.status.success(), "{:?}", observed.output);
        assert!(observed.stopped);
        assert!(!observed.extra);
        assert_eq!(
            observed.streams[0],
            (0..length).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        );
        assert_eq!(
            observed.streams[1],
            (0..length)
                .map(|i| 255 - (i % 251) as u8)
                .collect::<Vec<_>>()
        );
        assert_ne!(observed.streams[0], observed.streams[1]);
        let result: Value = serde_json::from_slice(&observed.output.stdout).unwrap();
        assert_eq!(result["command"], "fixture-emit");
        assert_eq!(result["outcome"], "ok");
    }
    let mut case = Case::new();
    case.value["streams"][1]["length"] = json!(3);
    let observed = invoke(&case, "reverse", None, 0o400, true);
    assert!(observed.output.status.success());
    assert_eq!(observed.streams[0], vec![255, 254, 253]);
    assert_eq!(observed.streams[1], vec![0, 1, 2, 3, 4]);
}
/// ´test:integration:fixture-convention-refusals´
#[test]
fn fixture_convention_refusals() {
    for (variant, class) in [
        ("pid", "fixture-convention-pid"),
        ("missing-pid", "fixture-convention-pid"),
        ("missing-names", "fixture-convention-names"),
        ("wrong-kind", "fixture-convention-descriptor"),
        ("count", "fixture-convention-count"),
        ("missing-count", "fixture-convention-count"),
        ("repeat", "fixture-convention-names"),
        ("wrong-name", "fixture-convention-names"),
        ("extra-name", "fixture-convention-names"),
        ("missing-fd", "fixture-convention-descriptor"),
        ("alias", "fixture-convention-descriptor"),
        ("readonly", "fixture-convention-descriptor"),
    ] {
        let observed = invoke(&Case::new(), variant, None, 0o400, true);
        refuse(&observed, class);
        assert!(!observed.stopped);
        assert!(observed.streams.iter().all(Vec::is_empty));
    }
}
/// ´test:integration:fixture-record-refusals´
#[test]
fn fixture_record_refusals() {
    for (pointer, value, class) in [
        ("/schema", json!(2), "fixture-record-schema"),
        ("/command", json!("length-observe"), "fixture-record-schema"),
        ("/case", json!("../invalid"), "fixture-record-case"),
        ("/streams/0/name", json!("right"), "fixture-record-streams"),
        (
            "/streams/0/pattern",
            json!("descending"),
            "fixture-record-streams",
        ),
        ("/streams/0/length", json!(0), "fixture-record-streams"),
        (
            "/streams/0/length",
            json!(1_048_577),
            "fixture-record-streams",
        ),
        ("/timeout_ms", json!(0), "fixture-record-timeout"),
        ("/timeout_ms", json!(60001), "fixture-record-timeout"),
        ("/timeout_ms", json!("1000"), "fixture-record-shape"),
        ("/behavior", json!("unknown"), "fixture-record-shape"),
    ] {
        let mut case = Case::new();
        *case.value.pointer_mut(pointer).unwrap() = value;
        let observed = invoke(&case, "normal", None, 0o400, true);
        refuse(&observed, class);
        assert!(!observed.stopped);
        assert!(observed.streams.iter().all(Vec::is_empty));
    }
    let duplicate = serde_json::to_string(&Case::new().value)
        .unwrap()
        .replace("\"schema\":1", "\"schema\":1,\"schema\":1");
    let mut excessive = serde_json::to_vec(&Case::new().value).unwrap();
    excessive.resize(262_145, b' ');
    for bytes in [duplicate.into_bytes(), excessive] {
        let observed = invoke(&Case::new(), "normal", Some(&bytes), 0o400, true);
        refuse(
            &observed,
            if bytes.len() > 262_144 {
                "parameter-custody"
            } else {
                "fixture-record-shape"
            },
        );
    }
    let mut missing = Case::new();
    missing.value.as_object_mut().unwrap().remove("timeout_ms");
    refuse(
        &invoke(&missing, "normal", None, 0o400, true),
        "fixture-record-shape",
    );
    let mut nested = Case::new();
    nested.value["streams"][0]["unknown"] = json!(true);
    refuse(
        &invoke(&nested, "normal", None, 0o400, true),
        "fixture-record-shape",
    );
    let mut case = Case::new();
    case.value["unknown"] = json!(true);
    refuse(
        &invoke(&case, "normal", None, 0o400, true),
        "fixture-record-shape",
    );
    refuse(
        &invoke(&Case::new(), "normal", None, 0o600, true),
        "parameter-custody",
    );
}
/// ´test:integration:fixture-injected-behaviors´
#[test]
fn fixture_injected_behaviors() {
    for (behavior, lengths) in [
        ("short", [4, 5]),
        ("excess", [6, 5]),
        ("partial", [2, 0]),
        ("fail-after-output", [5, 5]),
    ] {
        let mut case = Case::new();
        case.value["behavior"] = json!(behavior);
        let observed = invoke(&case, "normal", None, 0o400, true);
        refuse(&observed, "fixture-injected-failure");
        assert!(observed.stopped);
        assert_eq!(observed.streams.each_ref().map(Vec::len), lengths);
    }
    let mut case = Case::new();
    case.value["behavior"] = json!("reexec-extra");
    let observed = invoke(&case, "normal", None, 0o400, true);
    assert!(observed.output.status.success(), "{:?}", observed.output);
    assert!(observed.stopped && observed.extra);
}
/// ´test:integration:fixture-blocked-stream-is-bounded´
#[test]
fn fixture_blocked_stream_is_bounded() {
    let mut case = Case::new();
    case.value["streams"][0]["length"] = json!(1_048_576);
    case.value["timeout_ms"] = json!(10);
    refuse(
        &invoke(&case, "normal", None, 0o400, false),
        "fixture-stream-timeout",
    );
}

/// ´test:integration:fixture-control-plane´
#[test]
fn fixture_control_plane() {
    let _guard = SPAWN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for argument in ["--help", "--version"] {
        let output = Command::new(BINARY).arg(argument).output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"");
        let record: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(record["command"], "credential-fixture");
    }
    let output = Command::new(BINARY)
        .args(["emit", "--unknown"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
}

/// ´test:integration:fixture-custody-and-root-refusal´
#[test]
fn fixture_custody_and_root_refusal() {
    for (variant, class) in [
        ("symlink", "path-open"),
        ("hardlink", "parameter-custody"),
        ("root", "fixture-privilege"),
    ] {
        let observed = invoke(&Case::new(), variant, None, 0o400, true);
        refuse(&observed, class);
        assert!(!observed.stopped);
        assert!(observed.streams.iter().all(Vec::is_empty));
    }
    let case = Case::new();
    fs::set_permissions(case.dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    refuse(
        &invoke(&case, "normal", None, 0o400, true),
        "directory-ancestor-custody",
    );
}

/// ´test:integration:fixture-broken-pipe-refuses´
#[test]
fn fixture_broken_pipe_refuses() {
    refuse(
        &invoke(&Case::new(), "broken", None, 0o400, true),
        "fixture-stream-write",
    );
}

/// ´test:integration:fixture-reexec-state-refuses´
#[test]
fn fixture_reexec_state_refuses() {
    for behavior in ["normal", "reexec-extra"] {
        let mut case = Case::new();
        case.value["behavior"] = json!(behavior);
        let observed = invoke(&case, "marker", None, 0o400, true);
        refuse(&observed, "fixture-reexec-state");
        assert!(!observed.stopped);
        assert!(observed.streams.iter().all(Vec::is_empty));
    }
}

/// ´test:integration:fixture-case-rejects-nonpublic-input´
#[test]
fn fixture_case_rejects_nonpublic_input() {
    for field in ["bytes", "credential", "key", "environment", "input_path"] {
        let mut case = Case::new();
        case.value[field] = json!("synthetic forbidden value");
        refuse(
            &invoke(&case, "normal", None, 0o400, true),
            "fixture-record-shape",
        );
        let mut case = Case::new();
        case.value["streams"][0][field] = json!("synthetic forbidden value");
        refuse(
            &invoke(&case, "normal", None, 0o400, true),
            "fixture-record-shape",
        );
    }
    // Readability alone does not authorize the public class: its owner is root.
    refuse(
        &invoke(&Case::new(), "normal", None, 0o444, true),
        "parameter-custody",
    );
}
