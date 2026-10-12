#![doc = include_str!("../README.md")]

pub mod app;
pub mod config;
pub mod error;
pub mod keys;
pub mod loop_keygen;
pub mod planner;
pub mod probe;
pub mod report;
pub mod runner;
pub mod staff;
pub mod state;

pub use app::{loop_keygen_entry, staff_provision_entry};
pub use config::{LOOP_KEYGEN_HELP, STAFF_PROVISION_HELP};
pub use error::{DIAGNOSTIC_CLASSES, ProvisionError};
pub use planner::validate_create_prestate;
pub use runner::{CommandOutput, CommandSpec, ProcessRunner, RunError, Runner};
pub use state::{AccountState, SurfaceState, guard_account};

#[cfg(test)]
pub mod tests;
