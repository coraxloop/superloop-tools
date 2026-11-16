//! Native entry controls are separate from the small manager/control peer.
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    reason = "the peer includes the exact entry-only closure mechanism, not a second implementation"
)]
#[path = "../../src/launch/startup.rs"]
mod startup;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(std::env::vars_os().count(), 0);
    let result = match args.first().map(String::as_str) {
        Some("--startup-control") => startup_control(&args),
        Some("--root-control") => root_control(),
        Some("--pidfd-client") => pidfd_client(&args),
        Some("--observer-client" | "--observer-metadata") => observer_client(&args),
        Some("--control-client") => metadata_client(&args),
        _ => Err("arguments".into()),
    };
    if result.is_err() {
        std::process::exit(71);
    }
}
#[allow(unsafe_code)]
fn unsafe_fd(fd: i32) -> bool {
    // SAFETY: scalar query, never reads inherited bytes.
    unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) >= 0 }
}
#[allow(unsafe_code)]
fn startup_control(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let fd = args.get(1).ok_or("fd")?.parse::<i32>()?;
    if fd < 9 || !unsafe_fd(fd) {
        return Err("ambient missing".into());
    }
    // SAFETY: this native peer is single-threaded and owns no nonstandard
    // descriptors; the selected fd is an inherited raw capability only.
    unsafe {
        startup::close_inherited().map_err(std::io::Error::other)?;
    }
    if unsafe_fd(fd) {
        return Err("ambient retained".into());
    }
    std::io::stdout().write_all(b"resident-descriptors-closed\n")?;
    Ok(())
}
#[allow(unsafe_code)]
fn root_control() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::geteuid().as_raw() == 0 {
        return Err("ordinary control required".into());
    }
    // SAFETY: this fresh native peer is single-threaded with no owned fd above 2.
    if unsafe { startup::RootStartup::initialize() }.err() != Some("keeper-root-required") {
        return Err("root guard".into());
    }
    std::io::stdout().write_all(b"root-required\n")?;
    Ok(())
}

fn pidfd_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = std::io::stdin();
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 4096 {
        return Err("request bound".into());
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    let mut stream = std::os::unix::net::UnixStream::connect(args.get(1).ok_or("socket")?)?;
    stream.write_all(&bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    std::io::stdout().write_all(b"connected\n")?;
    // Parent releases this test-only event after the complete frame is queued.
    let mut ready = [0];
    input.read_exact(&mut ready)?;
    if ready != [1] {
        return Err("ready".into());
    }
    let mut reply = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        reply.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if reply.len() > 4096 {
            return Err("reply bound".into());
        }
    }
    let value: serde_json::Value = serde_json::from_slice(&reply)?;
    let fds =
        loop_home::anchor::transport::receive(&stream, 1, std::time::Duration::from_secs(30))?;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fds[0].as_raw_fd()))?;
    let pid = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .ok_or("pidfd")?
        .trim()
        .parse::<u32>()?;
    if value["invocation"]["pid"] != pid {
        return Err("pid mismatch".into());
    }
    std::io::stdout().write_all(&reply)?;
    Ok(())
}

#[allow(unsafe_code)]
fn observer_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let uid = nix::unistd::geteuid().as_raw();
    // This control requires unprivileged user namespaces. It never acquires
    // authority over the host namespace or changes the parent keeper's role.
    if unsafe { nix::libc::unshare(nix::libc::CLONE_NEWUSER) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))?;
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: single-threaded native peer, initialized ABI-sized buffers and
    // scalar prctl calls. Drop the bounding bit before losing SETPCAP.
    unsafe {
        if nix::libc::prctl(nix::libc::PR_CAPBSET_DROP, 5, 0, 0, 0) != 0
            || nix::libc::syscall(nix::libc::SYS_capget, &raw const header, caps.as_mut_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        caps[0].effective &= !(1 << 5);
        caps[0].permitted &= !(1 << 5);
        caps[0].inheritable &= !(1 << 5);
        if nix::libc::syscall(nix::libc::SYS_capset, &raw const header, caps.as_ptr()) != 0
            || nix::libc::prctl(
                nix::libc::PR_CAP_AMBIENT,
                nix::libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
            || nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 1, 0, 0, 0) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    if args[0] == "--observer-metadata" {
        metadata_client(args)
    } else {
        pidfd_client(args)
    }
}

fn metadata_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("request bound".into());
    }
    let mut stream = std::os::unix::net::UnixStream::connect(args.get(1).ok_or("socket")?)?;
    stream.write_all(&bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    std::io::stdout().write_all(b"connected\n")?;
    let mut reply = Vec::new();
    stream.take(4097).read_to_end(&mut reply)?;
    if reply.len() > 4096 {
        return Err("reply bound".into());
    }
    std::io::stdout().write_all(&reply)?;
    Ok(())
}
