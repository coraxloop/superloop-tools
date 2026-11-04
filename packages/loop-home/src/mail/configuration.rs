//! Loop-owned mail configuration, separate from the host identity registry.

use super::journal::{MailError, Result};
use super::{Address, valid_identity_name};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A lifetime worker registration; retired names remain reserved.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Worker {
    /// Immutable birth name.
    pub name: String,
    /// Current lifecycle state.
    pub state: WorkerState,
}
/// Worker directory membership, never authority inferred from a filename.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerState {
    Active,
    Retired,
}
/// One directed permission between workers of this loop.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: String,
    pub to: String,
}
/// Strict reserved mail keys; arbitrary unrelated loop keys remain untouched.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mail {
    pub version: u32,
    pub allow: Vec<Edge>,
}
/// Whole-file replacement preserves unrelated loop configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub workers: Vec<Worker>,
    pub mail: Mail,
    #[serde(flatten)]
    pub other: toml::Table,
}
impl Configuration {
    /// Parse all reserved fields before selecting a worker or grant.
    ///
    /// # Errors
    /// Refuses unknown mail fields, duplicate names or edges and dangling grants.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| MailError::Invalid("invalid-directory: configuration encoding"))?;
        let config: Self = toml::from_str(source)
            .map_err(|_| MailError::Invalid("invalid-directory: configuration schema"))?;
        config.validate()?;
        Ok(config)
    }
    /// Validate the complete directory, including retired names.
    ///
    /// # Errors
    /// Refuses malformed identities, duplicate registrations and invalid edges.
    pub fn validate(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        if self.mail.version != 1
            || self.workers.iter().any(|worker| {
                !valid_identity_name(&worker.name) || !names.insert(worker.name.as_str())
            })
        {
            return Err(MailError::Invalid("invalid-directory: worker directory"));
        }
        let mut edges = BTreeSet::new();
        if self.mail.allow.iter().any(|edge| {
            !names.contains(edge.from.as_str())
                || !names.contains(edge.to.as_str())
                || !edges.insert((&edge.from, &edge.to))
        }) {
            return Err(MailError::Invalid("invalid-directory: directed whitelist"));
        }
        Ok(())
    }
    /// Require a live worker registration without treating absence as permissive.
    ///
    /// # Errors
    /// Distinguishes an unknown worker from a retained retired registration.
    pub fn active(&self, name: &str) -> Result<()> {
        match self
            .workers
            .iter()
            .find(|worker| worker.name == name)
            .map(|worker| worker.state)
        {
            Some(WorkerState::Active) => Ok(()),
            Some(WorkerState::Retired) => {
                Err(MailError::Invalid("retired-worker: inactive birth entry"))
            }
            None => Err(MailError::Invalid(
                "unknown-recipient: worker is not registered",
            )),
        }
    }
    /// Authorize a worker sender under a fresh snapshot of its own loop.
    ///
    /// # Errors
    /// Refuses other estates and missing directed edges, including self-mail.
    pub fn authorize(&self, sender: &Address, recipient: &Address) -> Result<()> {
        let Some(worker) = sender.worker() else {
            return Ok(());
        };
        self.active(worker)?;
        if sender.loop_name() != recipient.loop_name() {
            return Err(MailError::Invalid(
                "outside-estate: worker recipient belongs to another loop",
            ));
        }
        if let Some(to) = recipient.worker() {
            self.active(to)?;
            if !self
                .mail
                .allow
                .iter()
                .any(|edge| edge.from == worker && edge.to == to)
            {
                return Err(MailError::Invalid(
                    "not-whitelisted: directed edge is absent",
                ));
            }
        }
        Ok(())
    }
}
