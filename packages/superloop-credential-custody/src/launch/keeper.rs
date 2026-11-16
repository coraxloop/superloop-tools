//! Per-case ownership through captured inventory, release and observed completion.
use super::control::Control;
use super::{
    Result, fifo::Pipes, manager::Manager, measure::Admission, policy::ArtifactRole,
    process_pin::ProcessPin, require, sealer::Session, startup::RootStartup, state::Phase,
    store::Store,
};
use std::fs::File;
use std::path::Path;

pub(super) struct Keeper<'a> {
    admission: &'a Admission,
    index: usize,
    startup: RootStartup,
    manager: Manager<'a>,
    pipes: Pipes,
    session: Session<'a>,
    process: Option<ProcessPin>,
    invocation: Option<String>,
    terminal: bool,
    holder_stopped: bool,
    holder_stop_attempted: bool,
    holder_stop_failure: Option<&'static str>,
    execution: Option<(u64, String)>,
    control: Option<Control>,
    inventory: Option<release::Evidence>,
}
impl<'a> Keeper<'a> {
    pub fn prepare(
        startup: RootStartup,
        admission: &'a Admission,
        index: usize,
        store: &'a mut Store,
    ) -> Result<Self> {
        #[cfg(test)]
        super::test_support::assert_owned();
        require(
            startup.owner() == nix::unistd::geteuid().as_raw(),
            "keeper-owner",
        )?;
        let manager = Manager::new(admission, index)?;
        let pipes = Pipes::create(admission, index)?;
        let session = Session::start(admission, index, store, pipes.readers()?)?;
        Ok(Self {
            admission,
            index,
            startup,
            manager,
            pipes,
            session,
            process: None,
            invocation: None,
            terminal: false,
            holder_stopped: false,
            holder_stop_attempted: false,
            holder_stop_failure: None,
            execution: None,
            control: None,
            inventory: None,
        })
    }
    pub fn submit(&mut self) -> Result<()> {
        require(!self.terminal, "keeper-terminal")?;
        self.session.store().advance(Phase::Submitted)?;
        if let Err(class) = self.manager.start(self.pipes.paths()) {
            return Err(self.fail(class));
        }
        if let Err(class) = self.session.store().submission_acknowledged() {
            return Err(self.fail(class));
        }
        Ok(())
    }
    pub fn capture(&mut self) -> Result<()> {
        self.capture_with(ProcessPin::writers, Control::bind)
    }
    fn capture_with(
        &mut self,
        copy: impl FnOnce(&ProcessPin) -> Result<[File; 2]>,
        bind: impl FnOnce(
            &RootStartup,
            &Pipes,
            &Admission,
            usize,
            &super::store::Invocation,
        ) -> Result<Control>,
    ) -> Result<()> {
        require(
            !self.terminal && self.session.store().phase() == Phase::Submitted,
            "keeper-capture-order",
        )?;
        let result = (|| {
            let snapshot = self.manager.snapshot(self.invocation.as_deref())?;
            self.session.store().retain_start(&snapshot)?;
            self.invocation = Some(snapshot.invocation.clone());
            require(
                snapshot.active == "activating"
                    && snapshot.sub == "start"
                    && snapshot.code == 0
                    && snapshot.status == 0
                    && snapshot.result == "success",
                "keeper-unit-state",
            )?;
            require(
                snapshot.load == "loaded"
                    && snapshot.condition
                    && snapshot.assertion
                    && snapshot.exec_pid == snapshot.pid
                    && snapshot.started > 0
                    && snapshot.exited == 0,
                "keeper-execution",
            )?;
            self.execution = Some((snapshot.started, snapshot.configuration_sha256.clone()));
            let policy = self.admission.policy();
            let case = &policy.cases[self.index];
            let fixture = policy
                .artifacts
                .iter()
                .find(|a| a.role == ArtifactRole::Fixture)
                .ok_or("manager-artifact-roster")?;
            let process = ProcessPin::capture(
                snapshot.pid,
                &case.generator_unit,
                &snapshot.invocation,
                self.admission.fixture_image(),
                &[
                    &fixture.path,
                    Path::new("emit"),
                    Path::new("--case-record"),
                    &case.record,
                ],
            )?;
            let writers = copy(&process)?;
            process.verify()?;
            self.session
                .store()
                .capture_manager(process.invocation().clone(), &snapshot)?;
            self.pipes.capture([&writers[0], &writers[1]])?;
            drop(writers); // Poll-only sealer duplicates remain; no keeper writer remains.
            self.control = Some(bind(
                &self.startup,
                &self.pipes,
                self.admission,
                self.index,
                process.invocation(),
            )?);
            self.process = Some(process);
            Ok(())
        })();
        if let Err(class) = result {
            let _latched = self.session.store().uncertain(class);
            return Err(self.fail(class));
        }
        Ok(())
    }
    pub fn verify_capture(&mut self) -> Result<()> {
        require(!self.terminal, "keeper-terminal")?;
        let result = (|| {
            let process = self.process.as_ref().ok_or("keeper-not-captured")?;
            process.verify()?;
            let snapshot = self.manager.snapshot(Some(&process.invocation().id))?;
            require(
                snapshot.pid == process.invocation().pid,
                "keeper-process-binding",
            )?;
            require(
                snapshot.active == "activating"
                    && snapshot.sub == "start"
                    && snapshot.code == 0
                    && snapshot.status == 0
                    && snapshot.result == "success",
                "keeper-unit-state",
            )
        })();
        if let Err(class) = result {
            let _latched = self.session.store().uncertain(class);
            return Err(self.fail(class));
        }
        Ok(())
    }
    pub fn fail(&mut self, class: &'static str) -> &'static str {
        if self.terminal {
            return "keeper-terminal";
        }
        self.terminal = true;
        self.session.store().remember_cause(class);
        self.recover(class)
    }
    fn recover(&mut self, class: &'static str) -> &'static str {
        use super::store::lifecycle::{Disposition as D, Recovery};
        super::stop::recovering();
        let intent = self.session.store().recovery_intent();
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(self.admission.policy().limits.case_ms);
        let stop = self.recover_holder(deadline);
        let holder = match &stop {
            Ok(()) => D::StopJobCompleted {
                invocation: self.invocation.clone().unwrap_or_default(),
            },
            Err(error) if self.invocation.is_none() => D::Unbound { class: error },
            Err(error) => D::Failed { class: error },
        };
        let mut socket = D::Retained;
        let mut fifos = if self.pipes.was_unlinked() {
            D::UnlinkedAtCapture
        } else {
            D::Retained
        };
        let uncertain = self.session.store().phase() == Phase::Uncertain;
        if stop.is_err() || uncertain || intent.is_err() {
            let _cancelled =
                self.session
                    .quarantine(if stop.is_err() { "manager-stop" } else { class });
        } else {
            let control = self.control.as_ref().map_or(Ok(()), Control::cleanup);
            socket = match control {
                Ok(()) if self.control.is_some() => D::UnlinkSucceeded,
                Ok(()) => D::NotAttempted,
                Err(error) => D::Failed { class: error },
            };
            if control.is_err() {
                let _cancelled = self.session.quarantine(class);
            } else {
                let _cancelled = self.session.fail(class);
            }
            if !self.pipes.was_unlinked() {
                fifos = match self.pipes.cleanup() {
                    Ok(()) => D::UnlinkSucceeded,
                    Err(error) => D::Failed { class: error },
                };
            }
        }
        let observed = Recovery {
            holder,
            sealer_exits: *self.session.exits(),
            outputs: self.session.cleanup_evidence(),
            fifos,
            socket,
            evidence: D::Retained,
        };
        if self.session.store().retain_recovery(&observed).is_err() || intent.is_err() {
            return "lifecycle-publication-missing";
        }
        class
    }

    fn recover_holder(&mut self, deadline: std::time::Instant) -> Result<()> {
        if self.holder_stopped {
            return Ok(());
        }
        if let Some(class) = self.holder_stop_failure {
            return Err(class);
        }
        require(!self.holder_stop_attempted, "completion-stop-attempted")?;
        if self.invocation.is_none() {
            require(
                self.session.store().failure_context().stage == Phase::Submitted,
                "keeper-not-submitted",
            )?;
            loop {
                let snapshot = self.manager.starting_at(None, deadline)?;
                if !snapshot.invocation.is_empty() {
                    self.session.store().retain_start(&snapshot)?;
                    self.invocation = Some(snapshot.invocation);
                    break;
                }
                let timeout = super::sealer::remaining_timeout(
                    std::time::Instant::now(),
                    deadline,
                    deadline,
                )?
                .min(
                    i32::try_from(self.admission.policy().limits.poll_ms)
                        .map_err(|_| "keeper-poll-bound")?,
                );
                super::channel::poll(&mut [], timeout)?;
            }
        }
        self.holder_stop_attempted = true;
        if let Err(class) = self.manager.stop_at(
            self.invocation.as_deref().ok_or("keeper-not-captured")?,
            deadline,
        ) {
            self.holder_stop_failure = Some(class);
            return Err(class);
        }
        self.holder_stopped = true;
        Ok(())
    }

    pub fn serve_status(&mut self, deadline: std::time::Instant) -> Result<()> {
        self.verify_capture()?;
        let phase = self.session.store().phase();
        self.control
            .as_ref()
            .ok_or("keeper-not-captured")?
            .serve_once(phase, deadline.min(self.manager.deadline()))
    }
    pub const fn phase(&mut self) -> Phase {
        self.session.store().phase()
    }
    fn stop_holder(&mut self) -> Result<()> {
        require(!self.holder_stop_attempted, "completion-stop-attempted")?;
        let id = self.invocation.as_deref().ok_or("keeper-not-captured")?;
        self.holder_stop_attempted = true;
        if let Err(class) = self.manager.stop(id) {
            self.holder_stop_failure = Some(class);
            return Err(class);
        }
        self.holder_stopped = true;
        Ok(())
    }
}
impl Drop for Keeper<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            let _failure = self.fail("keeper-abandoned");
        }
    }
}

#[cfg(test)]
#[path = "keeper_tests.rs"]
pub(super) mod tests;

#[path = "release.rs"]
mod release;

#[path = "completion.rs"]
pub(in crate::launch) mod completion;

// Only the keeper and its children can name Manager or invoke its stop method.
// Other cores receive snapshots; C6 cannot create a second cleanup owner.
#[path = "manager.rs"]
pub(in crate::launch) mod manager;

#[cfg(test)]
#[path = "campaign_tests.rs"]
mod campaign_tests;

#[path = "driver.rs"]
mod driver;
