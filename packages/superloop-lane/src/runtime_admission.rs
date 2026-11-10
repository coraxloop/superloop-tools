//! Explicit runtime admission carried through the helper service.
//!
//! Only the production gate exists here. Fixture scope and its constructor are a later step.

use crate::error::LaneError;
use crate::settings::BoxBackend;

pub enum RuntimeAdmission {
    Gate,
}

impl RuntimeAdmission {
    pub(crate) fn check(&self, backend: BoxBackend) -> Result<(), LaneError> {
        match self {
            Self::Gate => backend.require_runtime(),
        }
    }

    pub(crate) const fn program_binding(&self) -> ReviewedProgramBinding {
        match self {
            Self::Gate => ReviewedProgramBinding::Schema,
        }
    }

    pub(crate) const fn thread_token(&self) -> RuntimeAdmissionThread {
        match self {
            Self::Gate => RuntimeAdmissionThread(Self::Gate),
        }
    }
}

/// A non-cloneable transfer consumed when credential custody is activated.
pub struct RuntimeAdmissionThread(RuntimeAdmission);

impl RuntimeAdmissionThread {
    pub(crate) const fn activate(self) -> RuntimeAdmission {
        self.0
    }
}

/// The independent program reference; the scoped fixture form is not admitted here.
pub enum ReviewedProgramBinding {
    Schema,
}

impl ReviewedProgramBinding {
    pub(crate) const fn required_sha256(&self) -> &str {
        match self {
            Self::Schema => crate::credential::CLAUDE_SCHEMA_PROGRAM_SHA256,
        }
    }
}
