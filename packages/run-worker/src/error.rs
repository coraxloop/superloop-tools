use std::fmt;

/// A refusal, a waiting outcome, or a runtime failure with its process status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerError {
    status: u8,
    message: String,
}

impl WorkerError {
    /// A command-line form this binary does not accept, status two.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            status: 2,
            message: message.into(),
        }
    }

    /// A refusal decided before any privileged call, status four.
    #[must_use]
    pub fn refusal(message: impl Into<String>) -> Self {
        Self {
            status: 4,
            message: message.into(),
        }
    }

    /// Any other failure, status one.
    #[must_use]
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            status: 1,
            message: message.into(),
        }
    }

    /// Return the process status this failure selects.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Return the single-line diagnostic without its terminating newline.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WorkerError {}
