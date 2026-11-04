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
