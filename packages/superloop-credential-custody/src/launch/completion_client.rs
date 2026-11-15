//! Read-only completion observations from a live, protected keeper connection.
use super::{Result, channel, peer_credentials, peer_pidfd, read_request, require};
use crate::launch::{
    keeper::completion::Generator,
    sealer::{Completion, Exit},
    state::Phase,
    store::Invocation,
};
use serde::{Deserialize, Serialize};
use std::os::{fd::AsRawFd as _, unix::net::UnixStream};
use std::time::Instant;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::launch) struct View {
    pub phase: Phase,
    pub generator: Option<Generator>,
    pub sealers: Option<Completion>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub schema: u32,
    pub case: String,
    pub invocation: String,
    pub keeper_pid: u32,
    pub keeper_birth: u64,
    pub nonce: String,
    pub view: View,
}
// C6 obtains these expectations from the protected immutable case/control
// binding. A reply or an old completion receipt cannot supply authority.
pub(in crate::launch) struct Binding<'a> {
    pub case: &'a str,
    pub nonce: &'a str,
    pub keeper_pid: u32,
    pub keeper_birth: u64,
    pub keeper_uid: u32,
    pub invocation: &'a Invocation,
    pub sealed_limit: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub(in crate::launch) enum Observation {
    Pending,
    Complete,
}
fn live(handle: &std::os::fd::OwnedFd) -> Result<()> {
    let mut item = nix::libc::pollfd {
        fd: handle.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    channel::poll(std::slice::from_mut(&mut item), 0)?;
    require(item.revents == 0, "completion-keeper-lost")
}
pub(in crate::launch) fn receive(
    stream: &mut UnixStream,
    binding: &Binding<'_>,
    deadline: Instant,
) -> Result<Observation> {
    let peer = peer_credentials(stream)?;
    require(
        peer.uid == binding.keeper_uid && u32::try_from(peer.pid).ok() == Some(binding.keeper_pid),
        "completion-peer",
    )?;
    let handle = peer_pidfd(stream)?;
    live(&handle)?;
    crate::launch::process_pin::verify_pidfd(&handle, binding.keeper_pid)?;
    stream.set_nonblocking(true).map_err(|_| "control-mode")?;
    let bytes = read_request(stream, deadline)?;
    let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| "completion-record")?;
    require(
        reply.schema == 1
            && reply.case == binding.case
            && reply.invocation == binding.invocation.id
            && reply.keeper_pid == binding.keeper_pid
            && reply.keeper_birth == binding.keeper_birth
            && reply.nonce == binding.nonce
            && binding.nonce.len() == 32
            && binding
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "completion-binding",
    )?;
    live(&handle)?;
    require(
        !matches!(reply.view.phase, Phase::Failed | Phase::Uncertain),
        "completion-refused",
    )?;
    if reply.view.phase != Phase::Complete {
        return Ok(Observation::Pending);
    }
    require(
        reply
            .view
            .generator
            .as_ref()
            .is_some_and(|g| g.accepts(binding.invocation)),
        "completion-generator-evidence",
    )?;
    require(
        reply.view.sealers.as_ref().is_some_and(|s| {
            s.eof == [true; 2]
                && s.exits == [Exit::Code(0); 2]
                && s.sealed_bytes
                    .iter()
                    .all(|n| (1..=binding.sealed_limit).contains(n))
        }),
        "completion-sealer-evidence",
    )?;
    Ok(Observation::Complete)
}
#[cfg(test)]
#[path = "completion_client_tests.rs"]
mod tests;
