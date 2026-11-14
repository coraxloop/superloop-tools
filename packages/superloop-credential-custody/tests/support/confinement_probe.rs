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
    assert_eq!(args.len(), 5);
    assert_eq!(args[0], "encrypt");
    assert_eq!(args[1], "--with-key=host");
    assert!(args[2].starts_with("--name="));
    assert_eq!(&args[3..], ["-", "-"]);
    assert_eq!(std::env::vars_os().count(), 0);
    let image = std::env::current_exe().unwrap();
    let root = image.parent().unwrap();
    std::io::copy(
        &mut std::io::stdin().take(2 * 1024 * 1024),
        &mut std::io::sink(),
    )
    .unwrap();
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
    std::io::stdout().write_all(&evidence).unwrap();
}
