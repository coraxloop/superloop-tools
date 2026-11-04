#![doc = include_str!("../README.md")]

pub mod allocations;
pub mod app;
pub mod custody;
mod driver_launch;
pub mod ensure;
pub mod error;
mod letters;
pub mod mail;
pub mod planner;
pub mod registry;
pub mod runner;
pub mod verify;
pub mod workers_settings;

pub use app::enter_loop_entry;
pub use custody::{bind_custody_entry, mount_pinned, pin_custody};
pub use ensure::{
    EnsureClass, EnsureCounts, EnsureFailure, RootOwner, StandardRoot, ensure_roots,
    ensure_roots_entry, standard_roots,
};
pub use error::LoopError;
pub use letters::{LetterMetadata, letter_metadata, parse_letter_metadata};
pub use planner::{
    BridgeKind, CommandSpec, Custody, EntryPlan, IoMode, ProvisionPlan, custody_tier, entry_plan,
    provision_plan,
};
pub use registry::{LoopRecord, Registry, load_registry, registry_path, validate_name};
pub use runner::{CommandOutput, ProcessRunner, RunError, Runner};
pub use verify::{VerifyRecord, assemble_verify, cleanup_probe_plan, verify_probe_plan};

#[cfg(test)]
mod tests;
