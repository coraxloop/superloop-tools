use std::fmt;

/// A stable command refusal or runtime failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopError {
    status: u8,
    message: String,
}

impl LoopError {
    pub(crate) fn refusal(message: impl Into<String>) -> Self {
        Self {
            status: 2,
            message: message.into(),
        }
    }

    pub(crate) fn runtime(message: impl Into<String>) -> Self {
        Self {
            status: 1,
            message: message.into(),
        }
    }

    /// Return the process status associated with the failure.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Return the single-line diagnostic text without its terminating newline.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LoopError {}
