//! Explicit runtime admission carried through the helper service.
//!
//! Production uses Gate; isolated fixture authority exists only in unit-test builds.

use crate::error::LaneError;
use crate::settings::BoxBackend;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
pub mod fixture;

pub enum RuntimeAdmission {
    Gate,
    #[cfg(test)]
    Fixture(Box<fixture::FixtureAdmission>),
}

impl RuntimeAdmission {
    pub(crate) fn check(&self, backend: BoxBackend) -> Result<(), LaneError> {
        match self {
            Self::Gate => backend.require_runtime(),
            #[cfg(test)]
            Self::Fixture(proof) => proof.backend(backend),
        }
    }

    pub(crate) const fn program_binding(&self) -> &ReviewedProgramBinding {
        match self {
            Self::Gate => &ReviewedProgramBinding::Schema,
            #[cfg(test)]
            Self::Fixture(proof) => proof.binding(),
        }
    }
}

/// The independent program reference, borrowed from its runtime admission.
pub enum ReviewedProgramBinding {
    Schema,
    #[cfg(test)]
    Fixture(fixture::FixtureBinding),
}

impl ReviewedProgramBinding {
    pub(crate) const fn required_sha256(&self) -> &str {
        match self {
            Self::Schema => crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256,
            #[cfg(test)]
            Self::Fixture(binding) => binding.digest(),
        }
    }
}

impl RuntimeAdmission {
    #[cfg(test)]
    pub(crate) fn scope_names(&self, home: &Path, scope: &str, run: &str) -> Result<(), LaneError> {
        match self {
            Self::Gate => {
                let _ = (home, scope, run);
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture(proof) => proof.names(home, scope, run),
        }
    }
    #[cfg(test)]
    pub(crate) fn scope_plan(&self, plan: &serde_json::Value) -> Result<(), LaneError> {
        match self {
            Self::Gate => {
                let _ = plan;
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture(proof) => proof.plan(plan),
        }
    }
    #[cfg(test)]
    pub(crate) fn scope_round(
        &self,
        home: &Path,
        scope: &str,
        worker: &Path,
        uid: u32,
    ) -> Result<(), LaneError> {
        match self {
            Self::Gate => {
                let _ = (home, scope, worker, uid);
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture(proof) => proof.round(home, scope, worker, uid),
        }
    }
    #[cfg(test)]
    pub(crate) fn scope_periodic(
        &self,
        home: &Path,
        scope: &str,
        runs: &Path,
    ) -> Result<(), LaneError> {
        match self {
            Self::Gate => {
                let _ = (home, scope, runs);
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture(proof) => proof.periodic(home, scope, runs),
        }
    }
}

impl RuntimeAdmission {
    #[cfg(test)]
    pub(crate) fn scope_recipient(&self, worker: &Path) -> Result<(), LaneError> {
        match self {
            Self::Gate => {
                let _ = worker;
                Ok(())
            }
            #[cfg(test)]
            Self::Fixture(proof) => proof.recipient(worker),
        }
    }
}

#[cfg(test)]
impl RuntimeAdmission {
    pub(crate) fn scope_evidence(&self, driver: &Path) -> Result<(), LaneError> {
        match self {
            Self::Gate => Ok(()),
            Self::Fixture(proof) => proof.evidence(driver),
        }
    }
}

#[cfg(test)]
impl RuntimeAdmission {
    pub(crate) fn scope_roots(
        &self,
        home: &Path,
        scope: &str,
        runs: &Path,
    ) -> Result<(), LaneError> {
        match self {
            Self::Gate => Ok(()),
            Self::Fixture(proof) => proof.roots(home, scope, runs),
        }
    }
}

#[cfg(test)]
impl RuntimeAdmission {
    pub(crate) fn scope_record(&self, record: &serde_json::Value) -> Result<(), LaneError> {
        match self {
            Self::Gate => Ok(()),
            Self::Fixture(proof) => proof.record(record),
        }
    }
}
