//! Per-case ownership through capture. No descriptor release or completion claim.
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
    control: Option<Control>,
}
impl<'a> Keeper<'a> {
    pub fn prepare(
        startup: RootStartup,
        admission: &'a Admission,
        index: usize,
        store: &'a mut Store,
    ) -> Result<Self> {
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
            control: None,
        })
    }
    pub fn submit(&mut self) -> Result<()> {
        require(!self.terminal, "keeper-terminal")?;
        self.session.store().advance(Phase::Submitted)?;
        if let Err(class) = self.manager.start(self.pipes.paths()) {
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
            let snapshot = self.manager.snapshot(None)?;
            self.invocation = Some(snapshot.invocation.clone());
            require(
                snapshot.active == "activating"
                    && snapshot.sub == "start"
                    && snapshot.code == 0
                    && snapshot.status == 0
                    && snapshot.result == "success",
                "keeper-unit-state",
            )?;
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
        let stopped = self
            .invocation
            .as_deref()
            .is_some_and(|id| self.manager.stop(id).is_ok());
        if !stopped || self.session.store().phase() == Phase::Uncertain {
            self.session
                .quarantine(if self.invocation.is_some() && !stopped {
                    "manager-stop"
                } else {
                    class
                });
            return class;
        }
        if let Some(control) = &self.control
            && control.cleanup().is_err()
        {
            self.session.quarantine("control-binding");
            return "keeper-control-custody";
        }
        let failure = self.session.fail(class);
        // Captured pipes were already unlinked. Before capture, cleanup remains
        // manifest-bound after the matched unit is stopped; failure quarantines.
        if self.process.is_none() && self.pipes.cleanup().is_err() {
            return "keeper-fifo-custody";
        }
        failure
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
