use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::error::WorkerError;

/// What the waiter found in a lane's run directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The step published its run report, whose first line is carried here.
    Report(String),
    /// The worker's journal gained a line, carried here.
    Escalation(String),
    /// The events file stopped growing while the child was alive.
    Stall,
    /// The budget passed with no report.
    Budget,
}

impl Outcome {
    /// Return the process status this outcome selects.
    #[must_use]
    pub const fn status(&self) -> u8 {
        match self {
            Self::Report(_) => 0,
            Self::Escalation(_) => 3,
            Self::Stall => 42,
            Self::Budget => 5,
        }
    }

    /// Return the outcome word printed after `WATCH`.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Report(_) => "report",
            Self::Escalation(_) => "escalation",
            Self::Stall => "stall",
            Self::Budget => "budget",
        }
    }

    /// Return the evidence text carried beside the word.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Report(line) | Self::Escalation(line) => line,
            Self::Stall => "events file stopped growing",
            Self::Budget => "budget passed without a run report",
        }
    }
}

/// What the waiter knows about the monitored child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Child {
    /// The lock names no child yet, so nothing is known.
    Unknown,
    /// The named process is still running.
    Alive,
    /// The named process is gone.
    Gone,
}

/// What a lane's run directory holds at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// First line of the run report, when it exists.
    pub report: Option<String>,
    /// The first journal line beyond those already reported.
    pub escalation: Option<String>,
    /// Size of the events file, zero when it does not exist.
    pub events_size: u64,
    /// What is known about the monitored child.
    pub child: Child,
}

fn first_line(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let line = text.lines().next()?.trim_end();
    (!line.is_empty()).then(|| line.to_owned())
}

fn nth_line(path: &Path, index: usize) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let line = text.lines().nth(index)?.trim_end();
    (!line.is_empty()).then(|| line.to_owned())
}

/// Read the monitor's own PID and its child's PID from the lock.
#[must_use]
pub fn lock_pids(lock: &Path) -> Option<(u32, u32)> {
    let text = fs::read_to_string(lock).ok()?;
    let mut lines = text.lines();
    let monitor = lines.next()?.trim().parse().ok()?;
    let child = lines.next()?.trim().parse().ok()?;
    Some((monitor, child))
}

/// Read one instant of a lane's run directory.
///
/// # Errors
///
/// Returns a runtime failure when the run directory itself is absent.
pub fn snapshot(
    run_dir: &Path,
    seen_escalations: usize,
    proc_root: &Path,
    child: Option<u32>,
) -> Result<Snapshot, WorkerError> {
    if !run_dir.is_dir() {
        return Err(WorkerError::runtime(format!(
            "no run directory: {}",
            run_dir.display()
        )));
    }
    let events = run_dir.join("events.jsonl");
    Ok(Snapshot {
        report: first_line(&run_dir.join("run-report.txt")),
        escalation: nth_line(&run_dir.join("escalation.jsonl"), seen_escalations),
        events_size: fs::metadata(&events).map_or(0, |metadata| metadata.len()),
        child: child.map_or(Child::Unknown, |pid| {
            if proc_root.join(pid.to_string()).exists() {
                Child::Alive
            } else {
                Child::Gone
            }
        }),
    })
}

/// Select the outcome one instant justifies, if any.
#[must_use]
pub fn evaluate(
    snapshot: &Snapshot,
    elapsed: Duration,
    since_growth: Duration,
    stall: Duration,
    budget: Duration,
) -> Option<Outcome> {
    if let Some(line) = &snapshot.report {
        return Some(Outcome::Report(line.clone()));
    }
    if let Some(line) = &snapshot.escalation {
        return Some(Outcome::Escalation(line.clone()));
    }
    if snapshot.child == Child::Gone {
        return Some(Outcome::Stall);
    }
    if snapshot.child == Child::Alive && since_growth >= stall {
        return Some(Outcome::Stall);
    }
    (elapsed >= budget).then_some(Outcome::Budget)
}
