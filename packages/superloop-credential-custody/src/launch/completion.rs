//! Invocation-bound generator retention and keeper-only holder cleanup.
use super::{Keeper, Phase, Result, require};
use crate::launch::{manager::Snapshot, store::Invocation};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::launch) struct Generator {
    invocation: Invocation,
    started: u64,
    exited: u64,
    code: i32,
    status: i32,
    result: String,
    successful: bool,
    reply_sha256: String,
    configuration_sha256: String,
}
impl Generator {
    pub(in crate::launch) fn accepts(&self, invocation: &Invocation) -> bool {
        self.invocation == *invocation
            && self.successful
            && self.started > 0
            && self.exited >= self.started
            && self.code == 1
            && self.status == 0
            && self.result == "success"
            && [&self.reply_sha256, &self.configuration_sha256]
                .iter()
                .all(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
    }
    fn observe(
        snapshot: &Snapshot,
        invocation: &Invocation,
        execution: &(u64, String),
        process_exited: bool,
    ) -> Result<Option<Self>> {
        require(snapshot.load == "loaded", "completion-unloaded")?;
        require(snapshot.condition, "completion-condition")?;
        require(snapshot.assertion, "completion-assertion")?;
        require(
            snapshot.invocation == invocation.id && snapshot.exec_pid == invocation.pid,
            "completion-execution-binding",
        )?;
        require(
            execution.0 > 0 && snapshot.started == execution.0,
            "completion-start-binding",
        )?;
        require(
            snapshot.configuration_sha256 == execution.1,
            "completion-configuration",
        )?;
        if snapshot.active == "activating"
            && snapshot.sub == "start"
            && snapshot.pid == invocation.pid
            && snapshot.code == 0
            && snapshot.status == 0
            && snapshot.exited == 0
            && snapshot.result == "success"
        {
            return Ok(None);
        }
        require(process_exited, "completion-process-live")?;
        require(
            snapshot.pid == 0
                && ((snapshot.active == "active" && snapshot.sub == "exited")
                    || (snapshot.active == "failed" && snapshot.sub == "failed")),
            "completion-holder",
        )?;
        require(
            snapshot.exited >= snapshot.started && snapshot.exited > 0,
            "completion-exit-time",
        )?;
        require((1..=3).contains(&snapshot.code), "completion-exit-code")?;
        require(
            matches!(
                snapshot.result.as_str(),
                "success"
                    | "exit-code"
                    | "signal"
                    | "core-dump"
                    | "timeout"
                    | "watchdog"
                    | "resources"
                    | "protocol"
                    | "oom-kill"
            ),
            "completion-result",
        )?;
        let successful = snapshot.active == "active"
            && snapshot.sub == "exited"
            && snapshot.code == 1
            && snapshot.status == 0
            && snapshot.result == "success";
        Ok(Some(Self {
            invocation: invocation.clone(),
            started: snapshot.started,
            exited: snapshot.exited,
            code: snapshot.code,
            status: snapshot.status,
            result: snapshot.result.clone(),
            successful,
            reply_sha256: snapshot.raw_sha256.clone(),
            configuration_sha256: snapshot.configuration_sha256.clone(),
        }))
    }
}

impl Keeper<'_> {
    // One observation, never a sleep or an unbounded retry. C6 schedules pending
    // observations within the same manager deadline and owns the event loop.
    pub fn capture_generator(&mut self) -> Result<bool> {
        self.capture_generator_at(self.manager.deadline())
    }
    fn capture_generator_at(&mut self, deadline: Instant) -> Result<bool> {
        self.capture_generator_with_clock(deadline, Instant::now)
    }
    fn capture_generator_with_clock(
        &mut self,
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
    ) -> Result<bool> {
        require(
            !self.terminal && self.session.store().phase() == Phase::Released,
            "completion-order",
        )?;
        let result = (|| {
            require(now() < deadline, "completion-deadline")?;
            let pin = self.process.as_ref().ok_or("keeper-not-captured")?;
            let snapshot = self.manager.snapshot(Some(&pin.invocation().id))?;
            let observation = Generator::observe(
                &snapshot,
                pin.invocation(),
                self.execution.as_ref().ok_or("completion-start-binding")?,
                pin.exited()?,
            )?;
            let Some(observation) = observation else {
                return Ok(false);
            };
            let successful = observation.successful;
            self.session.store().retain_generator(observation)?;
            // Retention is evidence, not acceptance. Even expiry after a valid
            // terminal observation must preserve it before matched-holder cleanup.
            let decision_time = now();
            super::super::stop::check()?;
            require(decision_time < deadline, "completion-deadline")?;
            require(successful, "completion-generator-failed")?;
            Ok(true)
        })();
        self.release_result(result)
    }
    pub fn serve_completion(&mut self, deadline: Instant) -> Result<()> {
        let view = self.session.store().completion_view();
        self.control
            .as_ref()
            .ok_or("keeper-not-captured")?
            .serve_completion(&view, deadline.min(self.manager.deadline()))
    }
    pub fn finish_completion(&mut self) -> Result<()> {
        self.finish_completion_at(self.manager.deadline())
    }
    fn finish_completion_at(&mut self, deadline: Instant) -> Result<()> {
        require(
            !self.terminal && self.session.store().phase() == Phase::GeneratorRetained,
            "completion-order",
        )?;
        let result = (|| {
            require(Instant::now() < deadline, "completion-deadline")?;
            self.stop_holder()?;
            self.session.store().advance(Phase::HolderReleased)?;
            let completed = self.session.wait_until(deadline)?;
            self.session.store().retain_sealers(completed)?;
            self.session.store().sync_outputs()?;
            require(Instant::now() < deadline, "completion-deadline")?;
            super::super::stop::check()?;
            self.session.store().advance(Phase::Complete)?;
            self.terminal = true;
            Ok(())
        })();
        self.release_result(result)
    }
}

#[cfg(test)]
#[path = "completion_tests.rs"]
mod tests;
