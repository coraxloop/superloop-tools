//! Signals interrupt a framed reply in the production library, without cfg(test) helpers.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn partial_header_read(pid: u32) -> bool {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .expect("child tasks")
        .filter_map(Result::ok)
        .filter_map(|task| std::fs::read_to_string(task.path().join("syscall")).ok())
        .any(|call| {
            let fields: Vec<_> = call.split_whitespace().collect();
            fields
                .first()
                .and_then(|number| number.parse::<i64>().ok())
                .is_some_and(|number| number == libc::SYS_read || number == libc::SYS_recvfrom)
                && fields.get(3) == Some(&"0x2")
        })
}

/// # Panics
/// Panics only if the child cannot be observed reading the partial header and then stopped.
fn observe_partial_header_read_and_stop(
    child: &mut std::process::Child,
    deadline: Instant,
) -> nix::unistd::Pid {
    // Observe the read of the remaining two header bytes, not a scheduling delay.
    while !partial_header_read(child.id()) {
        if Instant::now() >= deadline {
            child.kill().expect("read readiness kill");
            child.wait().expect("read readiness reap");
            panic!("child did not block inside the partial header");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("pid"));
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGSTOP).expect("stop mid-frame");
    loop {
        if matches!(
            nix::sys::wait::waitpid(
                pid,
                Some(nix::sys::wait::WaitPidFlag::WUNTRACED | nix::sys::wait::WaitPidFlag::WNOHANG)
            )
            .expect("observe stop"),
            nix::sys::wait::WaitStatus::Stopped(_, _)
        ) {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop observation kill");
            child.wait().expect("stop observation reap");
            panic!("child did not stop inside the partial header");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    pid
}

/// # Panics
/// Panics only if fixture setup fails or the framed reader misses its observed signal contract.
/// ´test:integration:door-stub-retries-signal-interrupted-frame´
#[test]
fn door_stub_retries_signal_interrupted_frame() {
    if let Some(socket) = std::env::var_os("SUPERLOOP_DOOR_SIGNAL_CHILD") {
        let reply = superloop_lane::door::stub_call_stream(
            std::path::Path::new(&socket),
            &["door-attribution-probe".into()],
            std::io::empty(),
            std::io::sink(),
            std::io::sink(),
        )
        .expect("production reader retries interrupted frame");
        assert_eq!(reply["status"], 0);
        return;
    }
    let root = tempfile::tempdir_in("/tmp").expect("small socket fixture");
    let socket = root.path().join("signal.sock");
    let listener = UnixListener::bind(&socket).expect("listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "door_stub_retries_signal_interrupted_frame",
            "--nocapture",
        ])
        .env("SUPERLOOP_DOOR_SIGNAL_CHILD", &socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("child");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut peer = loop {
        if let Ok((peer, _)) = listener.accept() {
            break peer;
        }
        if Instant::now() >= deadline {
            let _killed = child.kill();
            let _reaped = child.wait();
            panic!("signal fixture accept deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut header = [0; 4];
    peer.read_exact(&mut header).expect("request header");
    let mut request = vec![0; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut request).expect("request body");
    let reply = serde_json::to_vec(&serde_json::json!({"schema":2,"type":"final",
        "status":0,"reason":"door-complete","ref_check":"not-applicable",
        "stdout_bytes":0,"stderr_bytes":0,"queue_state":"no-queue","queue_wall_seconds":null,
        "mediation_wall_seconds":0.0,"compute_wall_seconds":0.0}))
    .expect("reply");
    let header = u32::try_from(reply.len())
        .expect("small frame")
        .to_be_bytes();
    peer.write_all(&header[..2]).expect("partial frame");
    let pid = observe_partial_header_read_and_stop(&mut child, deadline);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGCONT)
        .expect("resume interrupted read");
    // Keep the child reap on the failure path too: an old reader exits on EINTR.
    let written = peer
        .write_all(&header[2..])
        .and_then(|()| peer.write_all(&reply));
    while child.try_wait().expect("child status").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("deadline kill");
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().expect("reap child");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    written.expect("complete interrupted frame");
}
