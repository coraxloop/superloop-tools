//! Mail identity and transport contracts.
//!
//! Names follow the generic specification's ``reg:mail:identity-names`` and
//! ``req:mail:name-alignment`` without command-word or lexical length exclusions.

pub mod instant;
pub mod journal;
mod names;
pub mod publication;
mod store;

pub use names::{Address, NameError, Outgoing, valid_identity_name};

pub mod acl;
pub mod command;
pub mod configuration;
mod directory;
mod io;
mod refusal;
mod service;

pub mod configuration_store;
pub mod provision;

pub mod birth;

pub mod worker_provision;

pub mod steering;

pub mod migration;

mod migration_metadata;

pub mod migration_tree;

pub mod migration_relocation;

pub mod migration_hold;

pub mod migration_history;

pub mod migration_inventory;

pub mod migration_control;

pub mod migration_cutover;
