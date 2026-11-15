//! Exact retained-pidfd handoff; no stream capability or release permission.
use super::{Result, channel, process_pin::ProcessPin, require, store::Invocation};
use serde::Serialize;
use std::io::{Read as _, Write as _};
use std::os::{fd::AsRawFd as _, unix::net::UnixStream};
use std::time::{Duration, Instant};
#[derive(Serialize)]
pub(super) struct Binding<'a> {
    pub schema: u32,
    pub case: &'a str,
    pub nonce: &'a str,
    pub keeper_pid: u32,
    pub keeper_birth: u64,
    pub keeper_uid: u32,
    pub invocation: &'a Invocation,
    pub inventory_sha256: &'a str,
}
fn encoded(binding: &Binding<'_>) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(binding).map_err(|_| "handoff-encoding")?;
    bytes.push(b'\n');
    require(bytes.len() <= 4096, "handoff-size")?;
    Ok(bytes)
}
fn wait(stream: &UnixStream, event: i16, deadline: Instant) -> Result<()> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or("handoff-deadline")?;
    let mut item = nix::libc::pollfd {
        fd: stream.as_raw_fd(),
        events: event,
        revents: 0,
    };
    channel::poll(
        std::slice::from_mut(&mut item),
        i32::try_from(timeout.as_millis().clamp(1, 30_000)).map_err(|_| "handoff-deadline")?,
    )?;
    require(item.revents & event != 0, "handoff-closed")
}
pub fn send(
    stream: &mut UnixStream,
    binding: &Binding<'_>,
    pin: &ProcessPin,
    deadline: Instant,
) -> Result<()> {
    pin.matches(binding.invocation)?;
    let descriptor = pin.duplicate()?;
    let bytes = encoded(binding)?;
    let mut remaining = bytes.as_slice();
    while !remaining.is_empty() {
        wait(stream, nix::libc::POLLOUT, deadline)?;
        let n = stream.write(remaining).map_err(|_| "handoff-write")?;
        require(n > 0, "handoff-write")?;
        remaining = &remaining[n..];
    }
    pin.verify()?;
    wait(stream, nix::libc::POLLOUT, deadline)?;
    loop_home::anchor::transport::send(stream, &[descriptor]).map_err(|_| "handoff-rights")
}
// The caller obtained this binding through the protected case/control manifest
// and immutable inventory receipt. A raw peer-supplied binding is never authority.
pub fn receive(
    stream: &mut UnixStream,
    binding: &Binding<'_>,
    deadline: Instant,
) -> Result<ProcessPin> {
    let peer = super::control::peer_credentials(stream)?;
    require(
        peer.uid == binding.keeper_uid && u32::try_from(peer.pid).ok() == Some(binding.keeper_pid),
        "handoff-peer",
    )?;
    stream.set_nonblocking(true).map_err(|_| "handoff-mode")?;
    let expected = encoded(binding)?;
    let mut bytes = Vec::new();
    loop {
        require(bytes.len() < 4096, "handoff-size")?;
        wait(stream, nix::libc::POLLIN, deadline)?;
        let mut byte = [0];
        require(
            stream.read(&mut byte).map_err(|_| "handoff-read")? == 1,
            "handoff-closed",
        )?;
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    require(bytes == expected, "handoff-binding")?;
    // Read metadata one byte at a time so no buffered read consumes SCM_RIGHTS.
    wait(stream, nix::libc::POLLIN, deadline)?;
    stream.set_nonblocking(false).map_err(|_| "handoff-mode")?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("handoff-deadline")?
        .min(Duration::from_secs(30));
    let mut descriptors = loop_home::anchor::transport::receive(stream, 1, remaining)
        .map_err(|_| "handoff-rights")?;
    let descriptor = descriptors.pop().ok_or("handoff-rights")?;
    ProcessPin::transferred(descriptor, binding.invocation.clone())
}
#[cfg(test)]
#[path = "handoff_tests.rs"]
mod tests;
