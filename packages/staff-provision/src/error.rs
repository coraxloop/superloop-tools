use std::io;

/// Documented diagnostic class and the condition that emits it.
pub const DIAGNOSTIC_CLASSES: &[(&str, &str)] = &[
    (
        "usage_error",
        "the command line, name, UID, or environment is invalid",
    ),
    ("path_exists", "a loop-keygen destination already exists"),
    ("public_key_missing", "no public-key lines were supplied"),
    (
        "public_key_malformed",
        "an input line is not a type token plus decodable base64",
    ),
    (
        "input_failure",
        "a named key file or standard input cannot be read",
    ),
    (
        "command_failure",
        "a local command or SSH process cannot be executed",
    ),
    (
        "ssh_failure",
        "an unprivileged SSH command exits unsuccessfully",
    ),
    (
        "sudo_refused",
        "a remote sudo -n command exits unsuccessfully",
    ),
    (
        "remote_probe_failure",
        "a read-only remote probe returns invalid state",
    ),
    ("account_missing", "an admit-key target does not exist"),
    ("account_exists", "a create target already exists"),
    ("uid_taken", "a create UID is already assigned"),
    (
        "showcase_required",
        "a loop-class create omitted its explicit showcase account",
    ),
    (
        "guard_mapping",
        "a mutation target's effective SELinux mapping is not staff_u",
    ),
    ("guard_wheel", "a mutation target belongs to wheel"),
    (
        "guard_uid",
        "a mutation target UID is not greater than 1000",
    ),
    (
        "unsafe_path",
        "a managed SSH or home-surface path has an unsafe file type",
    ),
    (
        "critical_divergence",
        "a changed account fails post-change verification",
    ),
    (
        "publication_failure",
        "the tool cannot publish its report or diagnostic",
    ),
];

/// One classed, operator-actionable failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionError {
    pub(crate) class: &'static str,
    pub(crate) detail: String,
    status: u8,
}

impl ProvisionError {
    pub(crate) fn runtime(class: &'static str, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
            status: 1,
        }
    }

    pub(crate) fn usage(detail: impl Into<String>) -> Self {
        Self {
            class: "usage_error",
            detail: detail.into(),
            status: 2,
        }
    }

    pub(crate) fn refusal(class: &'static str, detail: impl Into<String>) -> Self {
        Self {
            class,
            detail: detail.into(),
            status: 3,
        }
    }

    /// Process status assigned to this class.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Stable diagnostic class.
    #[must_use]
    pub const fn class(&self) -> &'static str {
        self.class
    }

    /// Render the complete one-line stderr diagnostic.
    #[must_use]
    pub fn diagnostic(&self, program: &str) -> String {
        format!("{program}: {}: {}\n", self.class, self.detail)
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "this signature is used directly as an io::Result::map_err function"
)]
pub(crate) fn publication_error(error: io::Error) -> ProvisionError {
    ProvisionError::runtime("publication_failure", error.to_string())
}
