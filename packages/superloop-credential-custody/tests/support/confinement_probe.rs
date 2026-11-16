//! Synthetic negative control; only fixed metadata leaves the already-open stdout.
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
#[allow(unsafe_code)]
fn socket_denied(family: i32) -> bool {
    // SAFETY: scalar socket syscall; successful descriptors are closed immediately.
    let fd = unsafe { nix::libc::socket(family, nix::libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe {
            nix::libc::close(fd);
        }
        false
    } else {
        std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    }
}
#[allow(unsafe_code)]
fn pair_denied() -> bool {
    let mut fds = [-1; 2];
    // SAFETY: two initialized output slots, immediately close any successful pair.
    let result = unsafe {
        nix::libc::socketpair(
            nix::libc::AF_UNIX,
            nix::libc::SOCK_STREAM,
            0,
            fds.as_mut_ptr(),
        )
    };
    if result == 0 {
        for fd in fds {
            unsafe {
                nix::libc::close(fd);
            }
        }
        false
    } else {
        std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    }
}
#[allow(unsafe_code)]
fn ring_denied() -> bool {
    // SAFETY: a null parameter pointer cannot establish a ring. The seccomp
    // refusal must precede argument processing; no ring descriptor can leak.
    let denied = |result| {
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    };
    unsafe {
        denied(nix::libc::syscall(
            nix::libc::SYS_io_uring_setup,
            1,
            std::ptr::null::<u8>(),
        )) && denied(nix::libc::syscall(
            nix::libc::SYS_io_uring_enter,
            -1,
            0,
            0,
            0,
            std::ptr::null::<u8>(),
            0,
        )) && denied(nix::libc::syscall(
            nix::libc::SYS_io_uring_register,
            -1,
            0,
            std::ptr::null::<u8>(),
            0,
        ))
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["outside"] {
        std::io::copy(&mut std::io::stdin(), &mut std::io::sink()).unwrap();
        return;
    }
    assert_eq!(args.len(), 5);
    assert_eq!(args[0], "encrypt");
    assert_eq!(args[1], "--with-key=host");
    assert!(args[2].starts_with("--name="));
    assert_eq!(&args[3..], ["-", "-"]);
    assert_eq!(std::env::vars_os().count(), 0);
    let image = std::env::current_exe().unwrap();
    let root = image.parent().unwrap();
    let mut input = String::new();
    std::io::stdin()
        .take(1024)
        .read_to_string(&mut input)
        .unwrap();
    let outside: i32 = input.trim().parse().unwrap();
    assert!(outside > 1);

    let mut evidence = Vec::new();
    for family in [nix::libc::AF_UNIX, nix::libc::AF_INET, nix::libc::AF_INET6] {
        evidence.push(u8::from(socket_denied(family)) + b'0');
    }
    evidence.push(u8::from(pair_denied()) + b'0');
    evidence.push(u8::from(ring_denied()) + b'0');
    for path in [root.join("outside-canary"), root.join("evidence/canary")] {
        let denied = OpenOptions::new()
            .write(true)
            .open(path)
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(nix::libc::EACCES));
        evidence.push(u8::from(denied) + b'0');
    }
    let denied = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("key/forbidden"))
        .err()
        .is_some_and(|e| e.raw_os_error() == Some(nix::libc::EACCES));
    evidence.push(u8::from(denied) + b'0');
    evidence.push(u8::from(std::fs::read(root.join("key/synthetic-key")).is_ok()) + b'0');
    let denied = std::fs::set_permissions(
        root.join("evidence/canary"),
        std::fs::Permissions::from_mode(0o600),
    )
    .err()
    .is_some_and(|e| e.raw_os_error() == Some(nix::libc::EPERM));
    evidence.push(u8::from(denied) + b'0');
    evidence.extend(process_authority(outside));
    evidence.extend(scheduling(outside));
    evidence.push(u8::from(std::fs::read_dir(root.join("key")).is_ok()) + b'0');
    evidence.push(
        u8::from(
            std::fs::read(root.join("key/unrelated"))
                .err()
                .is_some_and(|e| e.raw_os_error() == Some(nix::libc::EACCES)),
        ) + b'0',
    );
    evidence.extend(ipc());
    evidence.extend(group_changes());
    evidence.push(u8::from(parent_death_is_kill()) + b'0');
    evidence.extend(parent_death_changes());
    evidence.extend(process_creation());
    std::io::stdout().write_all(&evidence).unwrap();
}

#[allow(unsafe_code)]
fn parent_death_changes() -> [u8; 10] {
    let denied = |result| {
        u8::from(
            result == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM),
        ) + b'0'
    };
    // SAFETY: probe only its own metadata, with current identity arguments.
    // Mutants can change no other process and cannot gain another identity.
    unsafe {
        let uid = nix::libc::getuid();
        let gid = nix::libc::getgid();
        [
            denied(nix::libc::syscall(
                nix::libc::SYS_prctl,
                nix::libc::PR_SET_PDEATHSIG,
                0,
                0,
                0,
                0,
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_prctl,
                nix::libc::PR_SET_PDEATHSIG,
                nix::libc::SIGTERM,
                0,
                0,
                0,
            )),
            denied(nix::libc::syscall(nix::libc::SYS_setuid, uid)),
            denied(nix::libc::syscall(nix::libc::SYS_setgid, gid)),
            denied(nix::libc::syscall(nix::libc::SYS_setreuid, uid, uid)),
            denied(nix::libc::syscall(nix::libc::SYS_setregid, gid, gid)),
            denied(nix::libc::syscall(nix::libc::SYS_setresuid, uid, uid, uid)),
            denied(nix::libc::syscall(nix::libc::SYS_setresgid, gid, gid, gid)),
            denied(nix::libc::syscall(nix::libc::SYS_setfsuid, uid)),
            denied(nix::libc::syscall(nix::libc::SYS_setfsgid, gid)),
        ]
    }
}

#[allow(unsafe_code)]
fn process_authority(outside: i32) -> [u8; 4] {
    let denied = |result| {
        result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    };
    // SAFETY: the parent supplies its live, owned control child's pid. SIGCONT
    // is harmless; the mutation can only lower that control's core-file limit.
    unsafe {
        let limit = nix::libc::rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let mut own = limit;
        [
            u8::from(denied(nix::libc::kill(outside, nix::libc::SIGCONT).into())) + b'0',
            u8::from(denied(nix::libc::syscall(
                nix::libc::SYS_prlimit64,
                outside,
                nix::libc::RLIMIT_CORE,
                &raw const limit,
                std::ptr::null::<u8>(),
            ))) + b'0',
            u8::from(nix::libc::kill(nix::libc::getpid(), nix::libc::SIGCONT) == 0) + b'0',
            u8::from(
                nix::libc::syscall(
                    nix::libc::SYS_prlimit64,
                    0,
                    nix::libc::RLIMIT_CORE,
                    std::ptr::null::<u8>(),
                    &raw mut own,
                ) == 0,
            ) + b'0',
        ]
    }
}

#[allow(unsafe_code)]
fn scheduling(outside: i32) -> [u8; 6] {
    let denied = |result| {
        u8::from(
            result == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM),
        ) + b'0'
    };
    // SAFETY: targets only the owned control child; null structures cannot
    // change scheduling if the filter is deliberately removed by a mutation.
    unsafe {
        [
            denied(nix::libc::syscall(
                nix::libc::SYS_setpriority,
                nix::libc::PRIO_PROCESS,
                outside,
                19,
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_sched_setparam,
                outside,
                std::ptr::null::<u8>(),
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_sched_setscheduler,
                outside,
                0,
                std::ptr::null::<u8>(),
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_sched_setattr,
                outside,
                std::ptr::null::<u8>(),
                0,
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_sched_setaffinity,
                outside,
                0,
                std::ptr::null::<u8>(),
            )),
            denied(nix::libc::syscall(nix::libc::SYS_ioprio_set, 1, outside, 0)),
        ]
    }
}

#[allow(unsafe_code)]
fn ipc() -> Vec<u8> {
    // Invalid pointers/IDs and no creation flags: even a mutation cannot create,
    // read payloads from or remove another process's IPC object. EPERM must precede argument
    // validation, proving the syscall route is closed independently of ownership.
    [
        nix::libc::SYS_keyctl,
        nix::libc::SYS_add_key,
        nix::libc::SYS_request_key,
        nix::libc::SYS_semget,
        nix::libc::SYS_semop,
        nix::libc::SYS_semtimedop,
        nix::libc::SYS_semctl,
        nix::libc::SYS_shmget,
        nix::libc::SYS_shmat,
        nix::libc::SYS_shmdt,
        nix::libc::SYS_shmctl,
        nix::libc::SYS_msgget,
        nix::libc::SYS_msgsnd,
        nix::libc::SYS_msgrcv,
        nix::libc::SYS_msgctl,
        nix::libc::SYS_mq_open,
        nix::libc::SYS_mq_unlink,
        nix::libc::SYS_mq_timedsend,
        nix::libc::SYS_mq_timedreceive,
        nix::libc::SYS_mq_notify,
        nix::libc::SYS_mq_getsetattr,
    ]
    .into_iter()
    .map(|number| {
        // SAFETY: scalar syscall selectors; every possible pointer is invalid
        // or null, every object ID is -1, and creation flags are zero.
        let result =
            unsafe { nix::libc::syscall(number, -1_i64, 0_u64, 0_u64, 0_u64, 0_u64, 0_u64) };
        u8::from(
            result == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM),
        ) + b'0'
    })
    .collect()
}

#[allow(unsafe_code)]
fn group_changes() -> [u8; 2] {
    // SAFETY: own process only. With process creation denied this leader cannot
    // make a nonleader to isolate setsid from the kernel's leader restriction.
    // This row witnesses refusal; the independent creation rows close that route.
    let denied = |result| {
        u8::from(
            result == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM),
        ) + b'0'
    };
    unsafe {
        [
            denied(nix::libc::setpgid(0, 0)),
            denied(nix::libc::setsid()),
        ]
    }
}

#[allow(unsafe_code)]
fn process_creation() -> Vec<u8> {
    let denied = |result| {
        u8::from(
            result == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM),
        ) + b'0'
    };
    // SAFETY: deliberately invalid clone flags and null clone3 arguments cannot
    // create a process even when a mutation removes the relevant filter rule.
    let rows = unsafe {
        vec![
            denied(nix::libc::syscall(
                nix::libc::SYS_clone,
                u64::MAX,
                0_u64,
                0_u64,
                0_u64,
                0_u64,
            )),
            denied(nix::libc::syscall(
                nix::libc::SYS_clone3,
                std::ptr::null::<u8>(),
                88_u64,
            )),
        ]
    };
    #[cfg(target_arch = "x86_64")]
    let rows = {
        let mut rows = rows;
        for number in [nix::libc::SYS_fork, nix::libc::SYS_vfork] {
            // SAFETY: only a mutation can create this child. It immediately uses
            // _exit, with no allocation or return through the shared vfork stack.
            unsafe {
                let pid = if number == nix::libc::SYS_vfork {
                    raw_vfork()
                } else {
                    nix::libc::syscall(number)
                };
                if pid == 0 {
                    nix::libc::_exit(0);
                }
                rows.push(if number == nix::libc::SYS_vfork {
                    u8::from(pid == -i64::from(nix::libc::EPERM)) + b'0'
                } else {
                    denied(pid)
                });
                if pid > 0 {
                    let mut status = 0;
                    assert_eq!(
                        nix::libc::waitpid(i32::try_from(pid).unwrap(), &raw mut status, 0),
                        i32::try_from(pid).unwrap()
                    );
                }
            }
        }
        rows
    };
    rows
}

#[allow(unsafe_code)]
fn parent_death_is_kill() -> bool {
    let mut signal = 0;
    // SAFETY: scalar prctl with a live initialized output integer.
    unsafe {
        nix::libc::prctl(nix::libc::PR_GET_PDEATHSIG, &raw mut signal, 0, 0, 0) == 0
            && signal == nix::libc::SIGKILL
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
fn raw_vfork() -> i64 {
    let result: i64;
    // SAFETY: no stack or memory operation occurs in the child. It exits in
    // assembly before Rust can observe the shared vfork stack. The parent
    // receives the raw kernel return value; rcx/r11 are syscall clobbers.
    unsafe {
        std::arch::asm!(
            "syscall", "test rax, rax", "jnz 2f",
            "mov eax, 60", "xor edi, edi", "syscall", "ud2", "2:",
            inlateout("rax") nix::libc::SYS_vfork => result,
            lateout("rcx") _, lateout("r11") _, lateout("rdi") _,
            options(nostack),
        );
    }
    result
}
