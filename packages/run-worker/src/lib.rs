#![doc = include_str!("../README.md")]

pub mod alloc;
pub mod app;
pub mod cli;
pub mod clock;
pub mod entry;
pub mod error;
pub mod layout;
pub mod table;
pub mod watch;

pub use alloc::{Account, AllocationRequest, Reservation, Subordinate, allocate};
pub use app::{Environment, execute, run_worker_entry};
pub use cli::{Action, Invocation, parse_invocation};
pub use clock::utc_stamp;
pub use entry::{EntryRequest, MonitorRequest, WorkerCredentials, WorkerEntryPlan};
pub use error::WorkerError;
pub use layout::{
    Group, LaunchEnv, LayoutRow, Node, Owner, Placement, Stage, install_command, layout_plan,
};
pub use watch::{Child, Outcome, Snapshot, evaluate};

#[cfg(test)]
mod tests;
