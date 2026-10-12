#![doc = include_str!("../README.md")]
pub mod heartbeat;
pub mod heartbeat_toggle;
pub mod letters;
pub mod orchestrator;
pub mod orchestrator_toggle;
pub mod pre_tool;
pub mod project_root;
mod sha256;

/// Redacted toggle failure; callers retain their existing runtime diagnostics.
#[derive(Clone, Copy, Debug)]
pub struct ToggleError;
