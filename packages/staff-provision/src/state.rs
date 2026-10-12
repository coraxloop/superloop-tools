use crate::error::ProvisionError;

pub(crate) const HOME_ROOT: &str = "/var/home";
pub(crate) const STAFF_USER: &str = "staff_u";
pub(crate) const MINIMUM_STAFF_UID: u32 = 1000;

/// Read-only facts about one required home surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SurfaceState {
    /// Whether the path exists, including a symbolic link.
    pub exists: bool,
    /// C-locale GNU `stat` file-kind text.
    pub kind: String,
    /// Permission bits when a non-link path exists.
    pub mode: Option<u32>,
    /// Numeric owner when a non-link path exists.
    pub uid: Option<u32>,
    /// Numeric group when a non-link path exists.
    pub gid: Option<u32>,
}

impl SurfaceState {
    pub(crate) fn is_directory(&self) -> bool {
        self.exists && self.kind == "directory"
    }

    pub(crate) fn is_regular(&self) -> bool {
        self.exists && self.kind == "regular file"
    }
}

/// Read-only account facts consumed by the guard and planners.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountState {
    /// Account name requested by the caller.
    pub name: String,
    /// Whether NSS resolves the account.
    pub exists: bool,
    /// Numeric UID when present.
    pub uid: Option<u32>,
    /// Numeric primary GID when present.
    pub gid: Option<u32>,
    /// NSS home path when present.
    pub home: Option<String>,
    /// Supplementary and primary group names.
    pub groups: Vec<String>,
    /// Explicit `SELinux` login mapping, if present.
    pub mapping: Option<String>,
    /// `SELinux` login mapping from the `__default__` row, if present.
    pub default_mapping: Option<String>,
    /// `.ssh/` state.
    pub ssh: SurfaceState,
    /// `authorized_keys` state.
    pub authorized_keys: SurfaceState,
    /// `git/` state.
    pub git: SurfaceState,
    /// `loops/` state.
    pub loops: SurfaceState,
    /// `correspondence/` state.
    pub correspondence: SurfaceState,
    /// Fetched `authorized_keys` bytes, decoded as UTF-8.
    pub authorized_text: String,
}

/// Enforce the named owner invariant against pure probed state.
///
/// # Errors
///
/// Refuses a missing account, an effective mapping other than `staff_u`, wheel
/// membership, or a UID at or below 1000. An explicit mapping takes precedence
/// over the `__default__` mapping.
pub fn guard_account(state: &AccountState) -> Result<(), ProvisionError> {
    if !state.exists {
        return Err(ProvisionError::refusal(
            "account_missing",
            format!("staff account does not exist: {}", state.name),
        ));
    }
    match (state.mapping.as_deref(), state.default_mapping.as_deref()) {
        (Some(STAFF_USER), _) | (None, Some(STAFF_USER)) => {}
        (Some(mapping), _) => {
            return Err(ProvisionError::refusal(
                "guard_mapping",
                format!(
                    "account {} explicit mapping is {mapping}, required staff_u",
                    state.name
                ),
            ));
        }
        (None, Some(mapping)) => {
            return Err(ProvisionError::refusal(
                "guard_mapping",
                format!(
                    "account {} inherited __default__ mapping is {mapping}, required staff_u",
                    state.name
                ),
            ));
        }
        (None, None) => {
            return Err(ProvisionError::refusal(
                "guard_mapping",
                format!(
                    "account {} has no explicit or __default__ mapping, required staff_u",
                    state.name
                ),
            ));
        }
    }
    if state.groups.iter().any(|group| group == "wheel") {
        return Err(ProvisionError::refusal(
            "guard_wheel",
            format!("account {} is a member of wheel", state.name),
        ));
    }
    let uid = state.uid.unwrap_or(0);
    if uid <= MINIMUM_STAFF_UID {
        return Err(ProvisionError::refusal(
            "guard_uid",
            format!(
                "account {} has uid {uid}, required greater than {MINIMUM_STAFF_UID}",
                state.name
            ),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_safe_managed_paths(state: &AccountState) -> Result<(), ProvisionError> {
    let required_home = account_home(&state.name);
    if state.home.as_deref() != Some(required_home.as_str()) {
        return Err(ProvisionError::refusal(
            "unsafe_path",
            format!(
                "account {} home is {}, required {required_home}",
                state.name,
                state.home.as_deref().unwrap_or("missing")
            ),
        ));
    }
    for (label, surface, expected_kind) in [
        (".ssh/", &state.ssh, "directory"),
        ("authorized_keys", &state.authorized_keys, "regular file"),
    ] {
        if surface.exists && surface.kind != expected_kind {
            return Err(ProvisionError::refusal(
                "unsafe_path",
                format!(
                    "account {} path {label} is {}, required {expected_kind}",
                    state.name, surface.kind
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn account_home(account: &str) -> String {
    format!("{HOME_ROOT}/{account}")
}

pub(crate) fn account_paths(home: &str) -> [(&'static str, String); 5] {
    [
        (".ssh/", format!("{home}/.ssh")),
        ("authorized_keys", format!("{home}/.ssh/authorized_keys")),
        ("git/", format!("{home}/git")),
        ("loops/", format!("{home}/loops")),
        ("correspondence/", format!("{home}/correspondence")),
    ]
}
