//! Test-only native stdin/stdout/stderr peer. This is not encryption or an operator artifact.
use std::io::{Read as _, Write as _};

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}
fn run() -> Result<(), i32> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 5
        || args[0] != "encrypt"
        || args[1] != "--with-key=host"
        || args[3] != "-"
        || args[4] != "-"
        || std::env::vars_os().next().is_some()
    {
        return Err(90);
    }
    let mode = args[2].strip_prefix("--name=").ok_or(91)?;
    if !self_check() {
        return Err(96);
    }
    if mode == "early" {
        return Ok(());
    }
    if mode == "diagnostic" {
        for _ in 0..8 {
            std::io::stderr().write_all(&[b'X'; 4096]).map_err(|_| 97)?;
        }
        return Ok(());
    }
    if mode == "partial" {
        let mut one = [0];
        nix::unistd::read(std::io::stdin(), &mut one).map_err(|_| 98)?;
        std::io::stdout().write_all(b"QQ==\n").map_err(|_| 99)?;
        return Ok(());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(2 * 1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| 100)?;
    if mode == "excess" {
        for _ in 0..16 {
            std::io::stdout()
                .write_all(&[b'A'; 4096])
                .map_err(|_| 101)?;
        }
        return Ok(());
    }
    if mode == "empty" {
        return Ok(());
    }
    let mut encoded = Vec::new();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for part in bytes.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        encoded.push(alphabet[usize::from(a >> 2)]);
        encoded.push(alphabet[usize::from(((a & 3) << 4) | (b >> 4))]);
        encoded.push(if part.len() > 1 {
            alphabet[usize::from(((b & 15) << 2) | (c >> 6))]
        } else {
            b'='
        });
        encoded.push(if part.len() > 2 {
            alphabet[usize::from(c & 63)]
        } else {
            b'='
        });
    }
    encoded.push(b'\n');
    std::io::stdout().write_all(&encoded).map_err(|_| 102)?;
    if mode == "fail" {
        return Err(7);
    }
    if mode == "signal" {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).map_err(|_| 103)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn self_check() -> bool {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: fixed kernel ABI stack buffers and scalar metadata queries only.
    unsafe {
        if nix::libc::syscall(nix::libc::SYS_capget, &raw const header, caps.as_mut_ptr()) != 0
            || caps
                .iter()
                .any(|c| c.effective != 0 || c.permitted != 0 || c.inheritable != 0)
            || nix::libc::prctl(nix::libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        {
            return false;
        }
        for capability in 0..64 {
            if nix::libc::prctl(
                nix::libc::PR_CAP_AMBIENT,
                nix::libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            ) == 1
            {
                return false;
            }
        }
        // Bounded synthetic control includes the harness's inherited slot >=1000.
        // No /proc filesystem allowance is granted just to support this check.
        for fd in 3..2048 {
            if nix::libc::fcntl(fd, nix::libc::F_GETFD) >= 0 {
                return false;
            }
        }
    }
    true
}
