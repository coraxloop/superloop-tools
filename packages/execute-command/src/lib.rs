//! Shared command vocabulary and explicit persistence boundary.
//!
//! This crate grants no authority and performs no execution or ambient discovery.

#[cfg(test)]
extern crate self as execute_command;

pub mod checks;
pub mod escalation;
pub mod learning;
pub mod policy;
pub mod process;
pub mod record;
pub mod request;
pub mod rubric;
pub mod snapshot;
pub mod triage;
