use super::*;
use crate::launch::{sealer_tests::make_fixture, tests::Fixture};
use std::ffi::CString;
use std::os::fd::{AsFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::{fs::PermissionsExt as _, process::CommandExt as _};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub(in crate::launch) fn fixture(behavior: &str) -> Fixture {
    let mut f = make_fixture("normal");
    let current = std::env::current_exe().unwrap();
    let binary = current
        .ancestors()
        .take(8)
        .map(|p| p.join("credential-fixture"))
        .find(|p| p.is_file())
        .unwrap();
    let image = std::fs::read(binary).unwrap();
    let path = f.dir.path().join("fixture");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, &image).unwrap();
    // The dev artifact's debug sections exceed the production image ceiling.
    // Remove debug metadata from this private copy, then measure the bytes that run.
    let mut strip = Command::new("strip");
    strip
        .args(["--strip-debug", "--"])
        .arg(&path)
        .env_clear()
        .stdin(Stdio::null());
    loop_home::CommandDescriptors::default()
        .configure(&mut strip)
        .unwrap();
    assert!(strip.status().unwrap().success());
    let image = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
    f.value["artifacts"][1]["expected_sha256"] = crate::identity::hash(&image).into();
    let path = f.dir.path().join("public.json");
    let mut case: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    case["streams"][0]["name"] = "left".into();
    f.value["cases"][0]["streams"][0]["name"] = "left".into();
    case["behavior"] = behavior.into();
    case["timeout_ms"] = 60000.into();
    let bytes = serde_json::to_vec(&case).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    f.value["cases"][0]["expected_case_sha256"] = crate::identity::hash(&bytes).into();
    f
}
pub(in crate::launch) struct ChildGuard {
    pub child: Child,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}
#[allow(unsafe_code)]
pub(in crate::launch) fn start(f: &Fixture, writers: &[File; 2]) -> (ChildGuard, ProcessPin) {
    let path = f.dir.path().join("fixture");
    let case = f.dir.path().join("public.json");
    let args = [
        CString::new(path.as_os_str().as_encoded_bytes()).unwrap(),
        CString::new("emit").unwrap(),
        CString::new("--case-record").unwrap(),
        CString::new(case.as_os_str().as_encoded_bytes()).unwrap(),
    ];
    let copies = writers.each_ref().map(|f| unsafe {
        OwnedFd::from_raw_fd(
            nix::fcntl::fcntl(f, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(10)).unwrap(),
        )
    });
    let mut command = Command::new(&path);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .env_clear();
    // SAFETY: only scalar syscalls and stack bytes after fork; argv exists before it.
    unsafe {
        command.pre_exec(move || {
            for (fd, slot) in copies.iter().zip([3, 4]) {
                if nix::libc::dup2(fd.as_raw_fd(), slot) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if nix::libc::syscall(nix::libc::SYS_close_range, 5_u32, u32::MAX, 4_u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut pid = nix::libc::getpid().unsigned_abs();
            let mut reversed = [0_u8; 16];
            let mut n = 0;
            while pid > 0 {
                reversed[n] = b'0' + (pid % 10) as u8;
                pid /= 10;
                n += 1;
            }
            let mut variable = [0_u8; 32];
            variable[..11].copy_from_slice(b"LISTEN_PID=");
            for i in 0..n {
                variable[11 + i] = reversed[n - 1 - i];
            }
            let env = [
                variable.as_ptr().cast(),
                c"LISTEN_FDS=2".as_ptr(),
                c"LISTEN_FDNAMES=left:right".as_ptr(),
                std::ptr::null(),
            ];
            let pointers = [
                args[0].as_ptr(),
                args[1].as_ptr(),
                args[2].as_ptr(),
                args[3].as_ptr(),
                std::ptr::null(),
            ];
            nix::libc::execve(args[0].as_ptr(), pointers.as_ptr(), env.as_ptr());
            Err(std::io::Error::last_os_error())
        });
    }
    let mut guard = ChildGuard {
        child: command.spawn().unwrap(),
    };
    drop(command);
    let pid = nix::unistd::Pid::from_raw(i32::try_from(guard.child.id()).unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let _sent = tx.send(nix::sys::wait::waitpid(
            pid,
            Some(nix::sys::wait::WaitPidFlag::WUNTRACED),
        ));
    });
    let result = rx.recv_timeout(Duration::from_secs(600));
    if result.is_err() {
        let _killed = guard.child.kill();
    }
    waiter.join().unwrap();
    assert_eq!(
        result.unwrap().unwrap(),
        nix::sys::wait::WaitStatus::Stopped(pid, nix::sys::signal::Signal::SIGSTOP)
    );
    let pin = ProcessPin::capture(
        guard.child.id(),
        "synthetic-sample.service",
        "1234567890abcdef1234567890abcdef",
        ObjectIdentity::of(&File::open(&path).unwrap()).unwrap(),
        &[
            &path,
            std::path::Path::new("emit"),
            std::path::Path::new("--case-record"),
            &case,
        ],
    )
    .unwrap();
    (guard, pin)
}
pub(in crate::launch) fn pipes() -> ([File; 2], [File; 2]) {
    let (a, b) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    let (c, d) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    (
        [File::from(a), File::from(c)],
        [File::from(b), File::from(d)],
    )
}
/// ´test:unit:external-inventory-observes-real-fixture-barrier´
#[test]
fn external_inventory_observes_real_fixture_barrier() {
    let _case = crate::launch::test_support::case_guard();
    let f = fixture("normal");
    let (_readers, writers) = pipes();
    let (_guard, pin) = start(&f, &writers);
    let expected = writers.each_ref().map(|f| ObjectIdentity::of(f).unwrap());
    let inventory = Inventory::observe(&pin, expected, 16).unwrap();
    assert_eq!(inventory.descriptors.len(), 5);
    assert_eq!(
        Inventory::observe(&pin, expected, 65).err(),
        Some("inventory-ceiling")
    );
    assert_eq!(
        Inventory::observe(&pin, expected, 4).err(),
        Some("inventory-ceiling")
    );
    for (change, class) in [
        (0, "inventory-count"),
        (1, "inventory-slot"),
        (2, "inventory-stream"),
        (3, "inventory-flags"),
        (4, "inventory-stdin"),
        (5, "inventory-output"),
        (6, "inventory-output"),
        (7, "inventory-output"),
        (8, "inventory-output"),
    ] {
        let mut rows = inventory.descriptors.clone();
        match change {
            0 => {
                rows.pop();
            }
            1 => rows[4].slot = 3,
            2 => rows[4].object = rows[3].object,
            3 => rows[3].flags |= nix::libc::O_NONBLOCK as u32,
            4 => rows[0].device = 0,
            5 => rows[2].kind = SFlag::S_IFREG.bits(),
            6 => rows[1].kind = SFlag::S_IFSOCK.bits(),
            7 => rows[1].device = 0,
            8 => rows[2].flags = nix::libc::O_RDONLY as u32,
            _ => unreachable!(),
        }
        assert_eq!(validate(&rows, expected), Err(class));
    }
    let mut aliased = inventory.descriptors;
    aliased[4].object = aliased[3].object;
    assert_eq!(validate(&aliased, [expected[0]; 2]), Err("inventory-alias"));
    assert_eq!(flags(b"flags:\t01\nflags:\t01\n"), Err("inventory-fdinfo"));
    assert_eq!(flags(b"unrecognized\n"), Err("inventory-fdinfo"));
    assert_eq!(flags(b"flags:\tbogus\n"), Err("inventory-fdinfo"));
}
/// ´test:unit:reexecuted-extra-descriptor-refuses-before-any-byte´
#[test]
fn reexecuted_extra_descriptor_refuses_before_any_byte() {
    let _case = crate::launch::test_support::case_guard();
    let f = fixture("reexec-extra");
    let (readers, writers) = pipes();
    let (_guard, pin) = start(&f, &writers);
    let expected = writers.each_ref().map(|f| ObjectIdentity::of(f).unwrap());
    assert_eq!(
        Inventory::observe(&pin, expected, 16).err(),
        Some("inventory-count")
    );
    for reader in readers {
        nix::fcntl::fcntl(&reader, nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        assert_eq!(
            nix::unistd::read(reader.as_fd(), &mut [0_u8]).unwrap_err(),
            nix::errno::Errno::EAGAIN
        );
    }
    pin.verify().unwrap();
}
