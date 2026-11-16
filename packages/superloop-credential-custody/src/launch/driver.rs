//! One resident keeper dispatches the existing cores and owns every cleanup.
use super::{Keeper, Phase, Result, require};
use crate::launch::{
    channel,
    control::{
        Operation,
        actions::{Outcome, Transaction},
    },
    process_pin,
};
use std::{fs::File, time::Instant};
impl Keeper<'_> {
    pub fn run(&mut self, deadline: Instant) -> Result<()> {
        self.manager.cap_deadline(deadline);
        let result = (|| {
            self.submit()?;
            while !self.start_ready()? {
                self.poll_interval()?;
            }
            self.capture()?;
            self.run_captured()
        })();
        self.release_result(result)
    }
    fn start_ready(&mut self) -> Result<bool> {
        let snapshot = self.manager.starting(self.invocation.as_deref())?;
        if !snapshot.invocation.is_empty() {
            self.session.store().retain_start(&snapshot)?;
            self.invocation = Some(snapshot.invocation.clone());
        }
        if snapshot.pid == 0 {
            return Ok(false);
        }
        let directory = File::open(format!("/proc/{}", snapshot.pid))
            .map_err(|error| crate::process::io_failure("keeper-start-process", error))?;
        let (_, stopped) = process_pin::stat(&directory)?;
        Ok(stopped)
    }
    fn poll_interval(&self) -> Result<()> {
        let timeout = crate::launch::sealer::remaining_timeout(
            Instant::now(),
            self.manager.deadline(),
            self.manager.deadline(),
        )?
        .min(
            i32::try_from(self.admission.policy().limits.poll_ms)
                .map_err(|_| "keeper-poll-bound")?,
        );
        channel::poll(&mut [], timeout).map(|_| ())
    }
    fn run_captured(&mut self) -> Result<()> {
        let result = (|| {
            loop {
                require(Instant::now() < self.manager.deadline(), "keeper-deadline")?;
                if self.session.store().phase() == Phase::Released && self.capture_generator()? {
                    self.finish_completion()?;
                }
                let control = self.control.as_ref().ok_or("keeper-not-captured")?;
                if !control.ready(
                    self.admission.policy().limits.poll_ms,
                    self.manager.deadline(),
                )? {
                    continue;
                }
                let mut transaction = control.accept(self.manager.deadline())?;
                if self.dispatch(&mut transaction)? {
                    self.control
                        .as_ref()
                        .ok_or("keeper-not-captured")?
                        .cleanup()?;
                    return Ok(());
                }
            }
        })();
        let outcome = self.release_result(result);
        if outcome.is_err() {
            drop(self.control.take());
        }
        outcome
    }
    fn dispatch(&mut self, transaction: &mut Transaction) -> Result<bool> {
        transaction.authorize()?;
        match transaction.operation() {
            Operation::Inventory => {
                let digest = self.inventory()?;
                transaction.reply_action(Outcome::Inventory {
                    inventory_sha256: digest,
                })?;
            }
            Operation::Release { inventory_sha256 } => {
                let digest = inventory_sha256.clone();
                self.release(&digest)?;
                transaction.reply_action(Outcome::Released {
                    inventory_sha256: digest,
                })?;
            }
            Operation::Pidfd => {
                let digest = self.validated_inventory()?;
                transaction
                    .reply_pidfd(self.process.as_ref().ok_or("keeper-not-captured")?, &digest)?;
            }
            Operation::Completion => {
                transaction.reply_completion(&self.session.store().completion_view())?;
            }
            Operation::Status => transaction.reply_status(self.session.store().phase())?,
            Operation::Observed => {
                require(
                    self.session.store().phase() == Phase::Complete,
                    "keeper-observation-order",
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}
#[cfg(test)]
#[path = "driver_tests.rs"]
pub(super) mod tests;
