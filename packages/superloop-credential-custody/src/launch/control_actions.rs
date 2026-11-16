//! Owned administrative requests; accepting a socket never borrows the keeper.
use super::{Operation, Request, Result, completion_client, require, write_record};
use crate::launch::{handoff, process_pin::ProcessPin, state::Phase};
use serde::{Deserialize, Serialize};
use std::{os::unix::net::UnixStream, time::Instant};

pub(in crate::launch) struct Transaction {
    pub(super) stream: UnixStream,
    pub(super) peer: ProcessPin,
    pub(super) request: Request,
    pub(super) owner: u32,
    pub(super) deadline: Instant,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(in crate::launch) enum Outcome {
    Inventory { inventory_sha256: String },
    Released { inventory_sha256: String },
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reply {
    pub schema: u32,
    pub case: String,
    pub keeper_pid: u32,
    pub keeper_birth: u64,
    pub invocation: String,
    pub nonce: String,
    pub outcome: Outcome,
}
impl Transaction {
    pub const fn operation(&self) -> &Operation {
        &self.request.operation
    }
    pub fn authorize(&self) -> Result<()> {
        self.peer.verify()?;
        if matches!(
            self.operation(),
            Operation::Inventory | Operation::Release { .. }
        ) {
            self.peer.observer_role()?;
        }
        super::budget(self.deadline)?;
        Ok(())
    }
    fn write(&mut self, mut bytes: Vec<u8>) -> Result<()> {
        self.peer.verify()?;
        bytes.push(b'\n');
        write_record(&mut self.stream, &bytes, self.deadline)
    }
    pub fn reply_action(&mut self, outcome: Outcome) -> Result<()> {
        let response = Reply {
            schema: 2,
            case: self.request.case.clone(),
            keeper_pid: self.request.keeper_pid,
            keeper_birth: self.request.keeper_birth,
            invocation: self.request.invocation.clone(),
            nonce: self.request.nonce.clone(),
            outcome,
        };
        self.write(serde_json::to_vec(&response).map_err(|_| "control-encoding")?)
    }
    pub fn reply_completion(&mut self, view: &completion_client::View) -> Result<()> {
        let response = completion_client::Reply {
            schema: 1,
            case: self.request.case.clone(),
            keeper_pid: self.request.keeper_pid,
            keeper_birth: self.request.keeper_birth,
            invocation: self.request.invocation.clone(),
            nonce: self.request.nonce.clone(),
            view: view.clone(),
        };
        self.write(serde_json::to_vec(&response).map_err(|_| "control-encoding")?)
    }
    pub fn reply_status(&mut self, phase: Phase) -> Result<()> {
        self.write(
            serde_json::to_vec(&serde_json::json!({"schema":1,"case":self.request.case,
            "invocation":self.request.invocation,"phase":phase,"nonce":self.request.nonce}))
            .map_err(|_| "control-encoding")?,
        )
    }
    pub fn reply_pidfd(&mut self, pin: &ProcessPin, digest: &str) -> Result<()> {
        self.peer.observer_role()?;
        require(
            pin.invocation().id == self.request.invocation,
            "handoff-invocation",
        )?;
        let binding = handoff::Binding {
            schema: 1,
            case: &self.request.case,
            nonce: &self.request.nonce,
            keeper_pid: self.request.keeper_pid,
            keeper_birth: self.request.keeper_birth,
            keeper_uid: self.owner,
            invocation: pin.invocation(),
            inventory_sha256: digest,
        };
        handoff::send(&mut self.stream, &binding, pin, self.deadline)
    }
}
