//! Durable worker-name reservations in the loop-owned configuration transaction.
use super::configuration::{Worker, WorkerState};
use super::configuration_store::ConfigurationStore;
use super::journal::{MailError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Holds the launcher-side lifetime exclusion across launch or explicit close.
pub struct LifetimeLock {
    _file: nix::fcntl::Flock<std::fs::File>,
}
/// Acquire the protected lifetime file without waiting behind a running worker.
///
/// # Errors
/// Refuses an occupied or unavailable lock.
pub fn lock_lifetime(file: std::fs::File) -> Result<LifetimeLock> {
    let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| MailError::from(error))?;
    Ok(LifetimeLock { _file: file })
}

const KEY: &str = "worker_births";

/// The launcher's immutable binding for one worker lifetime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Exact mail name, independent of a round or provider process name.
    pub name: String,
    /// Reserved subordinate worker identity.
    pub uid: u32,
    /// Protected launcher reservation identity, qualified by its harness.
    pub reservation: String,
}
impl Identity {
    pub(super) fn pin_family(&self, loop_name: &str) -> String {
        format!("{}:{loop_name}{}", loop_name.len(), self.reservation)
    }

    /// Derive a stable mail name from a protected, never-reused launcher reservation.
    #[must_use]
    pub fn for_reservation(uid: u32, reservation: String) -> Self {
        Self {
            name: format!("worker-{}", super::journal::digest(reservation.as_bytes())),
            uid,
            reservation,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Pending,
    Active,
    Retired,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    identity: Identity,
    phase: Phase,
}

const fn invalid() -> MailError {
    MailError::Invalid("invalid-directory: worker birth binding")
}
fn bindings(store: &ConfigurationStore) -> Result<BTreeMap<String, Binding>> {
    store.available()?;
    let bindings: BTreeMap<String, Binding> = match store.configuration.other.get(KEY) {
        None => BTreeMap::new(),
        Some(value) => value.clone().try_into().map_err(|_| invalid())?,
    };
    let mut uids = std::collections::BTreeSet::new();
    let mut reservations = std::collections::BTreeSet::new();
    for (name, binding) in &bindings {
        validate(&binding.identity)?;
        if *name != binding.identity.name
            || (binding.phase != Phase::Retired && !uids.insert(binding.identity.uid))
            || !reservations.insert(&binding.identity.reservation)
        {
            return Err(invalid());
        }
        let worker = store
            .configuration
            .workers
            .iter()
            .find(|worker| worker.name == *name)
            .ok_or_else(invalid)?;
        if (worker.state == WorkerState::Active) != (binding.phase == Phase::Active) {
            return Err(invalid());
        }
    }
    Ok(bindings)
}
fn validate(identity: &Identity) -> Result<()> {
    crate::registry::validate_name(&identity.name)
        .map_err(|_| MailError::Invalid("invalid-name: worker birth name"))?;
    if !(1000..=65535).contains(&identity.uid)
        || identity.uid == 65534
        || identity.reservation.is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}
fn publish(store: &mut ConfigurationStore, bindings: &BTreeMap<String, Binding>) -> Result<()> {
    store.configuration.other.insert(
        KEY.into(),
        toml::Value::try_from(bindings).map_err(|_| invalid())?,
    );
    store.publish()
}

/// Reserve a name and UID before exposing an active endpoint; retry keeps its binding.
///
/// # Errors
/// Refuses malformed names, duplicate names or UIDs, changed reservations and retirement.
pub fn reserve(store: &mut ConfigurationStore, identity: &Identity) -> Result<()> {
    validate(identity)?;
    let mut births = bindings(store)?;
    if let Some(binding) = births.get(&identity.name) {
        if binding.identity != *identity || binding.phase == Phase::Retired {
            return Err(invalid());
        }
        return Ok(());
    }
    if store
        .configuration
        .workers
        .iter()
        .any(|worker| worker.name == identity.name)
        || births.values().any(|binding| {
            (binding.phase != Phase::Retired && binding.identity.uid == identity.uid)
                || binding.identity.reservation == identity.reservation
        })
    {
        return Err(invalid());
    }
    store.configuration.workers.push(Worker {
        name: identity.name.clone(),
        state: WorkerState::Retired,
    });
    births.insert(
        identity.name.clone(),
        Binding {
            identity: identity.clone(),
            phase: Phase::Pending,
        },
    );
    publish(store, &births)
}

/// Refuse surviving configuration history before creating a new protected receipt.
///
/// # Errors
/// Refuses any existing name, UID or reservation, including an identical prior binding.
pub fn unreserved(store: &ConfigurationStore, identity: &Identity) -> Result<()> {
    validate(identity)?;
    let births = bindings(store)?;
    if store
        .configuration
        .workers
        .iter()
        .any(|worker| worker.name == identity.name)
        || births.values().any(|binding| {
            (binding.phase != Phase::Retired && binding.identity.uid == identity.uid)
                || binding.identity.reservation == identity.reservation
        })
    {
        Err(invalid())
    } else {
        Ok(())
    }
}

/// Verify the retained active binding before launching an existing worker.
///
/// # Errors
/// Refuses a pending, retired, missing or changed identity.
pub fn verify(store: &ConfigurationStore, identity: &Identity) -> Result<()> {
    let births = bindings(store)?;
    if births
        .get(&identity.name)
        .is_some_and(|binding| binding.identity == *identity && binding.phase == Phase::Active)
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Verify the loop-owned terminal binding without recreating or replacing history.
///
/// # Errors
/// Missing, changed or nonterminal history refuses migration recovery.
pub fn verify_retired(store: &ConfigurationStore, identity: &Identity) -> Result<()> {
    let births = bindings(store)?;
    if births
        .get(&identity.name)
        .is_some_and(|binding| binding.identity == *identity && binding.phase == Phase::Retired)
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

/// Publish active state only after the trusted launcher verifies its complete endpoint.
///
/// # Errors
/// Refuses an unreserved, changed or retired worker identity.
pub fn activate(store: &mut ConfigurationStore, identity: &Identity) -> Result<()> {
    transition(store, identity, Phase::Active)
}
/// Retain the name and reservation while releasing the UID after custody transfer.
///
/// # Errors
/// Refuses an absent or changed birth binding.
pub fn retire(store: &mut ConfigurationStore, identity: &Identity) -> Result<()> {
    transition(store, identity, Phase::Retired)
}
fn transition(store: &mut ConfigurationStore, identity: &Identity, phase: Phase) -> Result<()> {
    let mut births = bindings(store)?;
    let binding = births.get_mut(&identity.name).ok_or_else(invalid)?;
    if binding.identity != *identity || (binding.phase == Phase::Retired && phase != Phase::Retired)
    {
        return Err(invalid());
    }
    if binding.phase == phase {
        return Ok(());
    }
    binding.phase = phase;
    let worker = store
        .configuration
        .workers
        .iter_mut()
        .find(|worker| worker.name == identity.name)
        .ok_or_else(invalid)?;
    worker.state = if phase == Phase::Active {
        WorkerState::Active
    } else {
        WorkerState::Retired
    };
    publish(store, &births)
}

#[cfg(test)]
#[path = "birth_tests.rs"]
mod tests;
