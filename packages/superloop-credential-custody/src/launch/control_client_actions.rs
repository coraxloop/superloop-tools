//! Installed-adapter transactions built on the protected completion opener.
use super::{Opened, Result, completion_client, require};
use crate::launch::{
    control::{
        self, Operation,
        actions::{Outcome, Reply},
    },
    handoff,
};
use std::{net::Shutdown, os::fd::AsRawFd as _, time::Instant};
impl Opened {
    pub(super) fn reconnect(&mut self, deadline: Instant) -> Result<()> {
        self.verify()?;
        let path = format!("/proc/self/fd/{}/control.sock", self.directory.as_raw_fd());
        self.stream = super::connect(&path, deadline)?;
        self.verify()
    }

    fn write_request(
        &mut self,
        operation: Operation,
        schema: u32,
        deadline: Instant,
    ) -> Result<String> {
        self.verify()?;
        let nonce = completion_client::fresh_nonce()?;
        let request = control::Request {
            schema,
            case: self.manifest.case.clone(),
            keeper_pid: self.manifest.keeper_pid,
            keeper_birth: self.manifest.keeper_birth,
            invocation: self.manifest.invocation.clone(),
            operation,
            nonce: nonce.clone(),
        };
        let mut bytes = serde_json::to_vec(&request).map_err(|_| "control-encoding")?;
        bytes.push(b'\n');
        control::write_record(&mut self.stream, &bytes, deadline)?;
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| "control-write")?;
        Ok(nonce)
    }
    pub(super) fn action(&mut self, operation: Operation, deadline: Instant) -> Result<Outcome> {
        let inventory = matches!(operation, Operation::Inventory);
        let expected = match &operation {
            Operation::Inventory => None,
            Operation::Release { inventory_sha256 } => Some(inventory_sha256.clone()),
            _ => return Err("client-operation"),
        };
        let nonce = self.write_request(operation, 2, deadline)?;
        let bytes = control::read_request(&mut self.stream, deadline)?;
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| "client-action-record")?;
        require(
            reply.schema == 2
                && reply.case == self.manifest.case
                && reply.invocation == self.manifest.invocation
                && reply.keeper_pid == self.manifest.keeper_pid
                && reply.keeper_birth == self.manifest.keeper_birth
                && reply.nonce == nonce,
            "client-action-binding",
        )?;
        let digest = match &reply.outcome {
            Outcome::Inventory { inventory_sha256 } if inventory => inventory_sha256,
            Outcome::Released { inventory_sha256 } if !inventory => inventory_sha256,
            _ => return Err("client-action-outcome"),
        };
        require(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && expected.as_ref().is_none_or(|e| e == digest),
            "client-action-digest",
        )?;
        self.verify()?;
        Ok(reply.outcome)
    }
    pub(super) fn observation(
        &mut self,
        digest: &str,
        deadline: Instant,
    ) -> Result<crate::launch::process_pin::ObservationPin> {
        let nonce = self.write_request(Operation::Pidfd, 1, deadline)?;
        let binding = handoff::Binding {
            schema: 1,
            case: &self.manifest.case,
            nonce: &nonce,
            keeper_pid: self.manifest.keeper_pid,
            keeper_birth: self.manifest.keeper_birth,
            keeper_uid: self.owner,
            invocation: &self.manifest.captured,
            inventory_sha256: digest,
        };
        let pin = handoff::receive(&mut self.stream, &binding, deadline)?;
        self.verify()?;
        Ok(pin)
    }
    pub(super) fn observed(&mut self, deadline: Instant) -> Result<()> {
        // The read-only Complete observation already passed. This one-way frame
        // allows its keeper to exit; no post-write liveness check can be required.
        self.write_request(Operation::Observed, 2, deadline)?;
        Ok(())
    }
}
