//! Root-only installed adapters. Tests enter private cores, never this boundary.
use super::{
    Result, campaign,
    child_status::ChildStatus,
    control::client,
    keeper::Keeper,
    measure::{self, ObjectIdentity},
    policy::{ArtifactRole, Role},
    require,
    startup::RootStartup,
};
use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    CalibrationRun,
    Completion,
    Descriptors,
    BarrierRelease,
}
impl Command {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CalibrationRun => "calibration-run",
            Self::Completion => "completion",
            Self::Descriptors => "descriptors",
            Self::BarrierRelease => "barrier-release",
        }
    }
    const fn role(self) -> Role {
        match self {
            Self::CalibrationRun => Role::CalibrationRun,
            Self::Completion => Role::Completion,
            Self::Descriptors => Role::Descriptors,
            Self::BarrierRelease => Role::BarrierRelease,
        }
    }
}
#[allow(unsafe_code)]
pub fn run(command: Command, parameters: &Path, case: &str) -> Result<serde_json::Value> {
    // SAFETY: the sole caller is the fresh single-threaded CLI boundary, before
    // policy admission or opening any owned nonstandard descriptor.
    let startup = unsafe { RootStartup::initialize() }?;
    ChildStatus::read(&File::open("/proc/self").map_err(|_| "launch-role-status")?)?
        .launcher_role(command.role())?;
    let admission = measure::root_admission(parameters)?;
    let own =
        ObjectIdentity::of(&File::open("/proc/self/exe").map_err(|_| "launch-running-image")?)?;
    let expected = admission
        .artifacts()
        .iter()
        .find(|a| a.role == ArtifactRole::Launcher)
        .ok_or("launch-artifact-roster")?;
    require(own == expected.object, "launch-running-image")?;
    if matches!(command, Command::CalibrationRun) {
        require(
            case == admission.policy().campaign,
            "launch-campaign-binding",
        )?;
        for role in [ArtifactRole::ManagerStart, ArtifactRole::ManagerQuery] {
            require(
                admission.artifacts().iter().any(|a| a.role == role),
                "manager-artifact-roster",
            )?;
        }
        let deadline =
            Instant::now() + Duration::from_millis(admission.policy().limits.campaign_ms);
        let matrix = campaign::run(&admission, deadline, |index, store, deadline| {
            let mut keeper = Keeper::prepare(startup.clone(), &admission, index, store)?;
            keeper.run(deadline)
        })?;
        return serde_json::to_value(matrix).map_err(|_| "result-encoding");
    }
    let index = admission
        .policy()
        .cases
        .iter()
        .position(|c| c.id == case)
        .ok_or("launch-case-binding")?;
    let deadline = Instant::now() + Duration::from_millis(admission.policy().limits.case_ms);
    match command {
        Command::Descriptors => Ok(
            serde_json::json!({"inventory_sha256":client::descriptors(&admission,index,deadline)?}),
        ),
        Command::BarrierRelease => {
            Ok(serde_json::json!({"inventory_sha256":client::release(&admission,index,deadline)?}))
        }
        Command::Completion => {
            client::wait_completion(&admission, index, deadline)?;
            Ok(serde_json::json!({"completion":"retained"}))
        }
        Command::CalibrationRun => Err("launch-command"),
    }
}
