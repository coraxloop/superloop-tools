use std::io;

use crate::config::AccountClass;
use crate::error::ProvisionError;
use crate::keys::{KeyLine, MergeResult, merge_keys};
use crate::runner::{CommandSpec, Runner, invoke, require_success};
use crate::state::{
    AccountState, MINIMUM_STAFF_UID, STAFF_USER, SurfaceState, account_home, account_paths,
    ensure_safe_managed_paths, guard_account,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MutationPlan {
    pub(crate) commands: Vec<CommandSpec>,
    pub(crate) merge: MergeResult,
}

/// Apply the inverted create guard to pure pre-state.
///
/// # Errors
///
/// Refuses a low UID, an existing account, or an assigned UID.
pub fn validate_create_prestate(
    target: &AccountState,
    requested_uid: u32,
    owner: Option<&str>,
) -> Result<(), ProvisionError> {
    if requested_uid <= MINIMUM_STAFF_UID {
        return Err(ProvisionError::refusal(
            "guard_uid",
            format!(
                "requested uid {requested_uid} for {} must be greater than {MINIMUM_STAFF_UID}",
                target.name
            ),
        ));
    }
    if target.exists {
        return Err(ProvisionError::refusal(
            "account_exists",
            format!("create target already exists: {}", target.name),
        ));
    }
    if let Some(owner) = owner {
        return Err(ProvisionError::refusal(
            "uid_taken",
            format!(
                "uid {requested_uid} requested for {} is owned by {owner}",
                target.name
            ),
        ));
    }
    Ok(())
}

fn directory_converged(surface: &SurfaceState, mode: u32, uid: u32, gid: u32) -> bool {
    surface.is_directory()
        && surface.mode == Some(mode)
        && surface.uid == Some(uid)
        && surface.gid == Some(gid)
}

fn file_converged(surface: &SurfaceState, mode: u32, uid: u32, gid: u32) -> bool {
    surface.is_regular()
        && surface.mode == Some(mode)
        && surface.uid == Some(uid)
        && surface.gid == Some(gid)
}

fn install_directory(
    alias: &str,
    account: &str,
    path: &str,
    mode: &str,
    label: &str,
) -> CommandSpec {
    CommandSpec::remote(
        alias,
        format!("install-{account}-{label}"),
        true,
        [
            String::from("install"),
            String::from("-d"),
            String::from("-m"),
            mode.to_owned(),
            String::from("-o"),
            account.to_owned(),
            String::from("-g"),
            account.to_owned(),
            path.to_owned(),
        ],
        Vec::new(),
        true,
    )
}

fn install_authorized_keys(alias: &str, account: &str, path: &str, content: &str) -> CommandSpec {
    CommandSpec::remote(
        alias,
        format!("install-{account}-authorized-keys"),
        true,
        [
            String::from("install"),
            String::from("-D"),
            String::from("-m"),
            String::from("0600"),
            String::from("-o"),
            account.to_owned(),
            String::from("-g"),
            account.to_owned(),
            String::from("/dev/stdin"),
            path.to_owned(),
        ],
        content.as_bytes().to_vec(),
        true,
    )
}

fn restorecon(alias: &str, account: &str, path: &str) -> CommandSpec {
    CommandSpec::remote(
        alias,
        format!("restorecon-{account}"),
        true,
        [
            String::from("restorecon"),
            String::from("-RF"),
            path.to_owned(),
        ],
        Vec::new(),
        true,
    )
}

pub(crate) fn plan_key_mutation(
    alias: &str,
    state: &AccountState,
    keys: &[KeyLine],
) -> Result<MutationPlan, ProvisionError> {
    guard_account(state)?;
    ensure_safe_managed_paths(state)?;
    let uid = state.uid.unwrap_or(0);
    let gid = state.gid.unwrap_or(0);
    let home = state.home.as_deref().ok_or_else(|| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("account {} has no home", state.name),
        )
    })?;
    let ssh_path = format!("{home}/.ssh");
    let authorized_path = format!("{ssh_path}/authorized_keys");
    let merge = merge_keys(&state.authorized_text, keys);
    let mut commands = Vec::new();
    if !directory_converged(&state.ssh, 0o700, uid, gid) {
        commands.push(install_directory(
            alias,
            &state.name,
            &ssh_path,
            "0700",
            "ssh-directory",
        ));
    }
    if state.authorized_text != merge.content
        || !file_converged(&state.authorized_keys, 0o600, uid, gid)
    {
        commands.push(install_authorized_keys(
            alias,
            &state.name,
            &authorized_path,
            &merge.content,
        ));
    }
    if !commands.is_empty() {
        commands.push(restorecon(alias, &state.name, &ssh_path));
    }
    Ok(MutationPlan { commands, merge })
}

pub(crate) fn create_setup_plan(
    alias: &str,
    account: &str,
    class: AccountClass,
    uid: u32,
    keys: &[KeyLine],
) -> Vec<CommandSpec> {
    let home = account_home(account);
    let key_text = merge_keys("", keys).content;
    let mut commands = vec![
        CommandSpec::remote(
            alias,
            format!("create-{account}"),
            true,
            [
                String::from("useradd"),
                String::from("--uid"),
                uid.to_string(),
                String::from("--user-group"),
                String::from("--home-dir"),
                home.clone(),
                String::from("--create-home"),
                String::from("--shell"),
                String::from("/bin/bash"),
                account.to_owned(),
            ],
            Vec::new(),
            true,
        ),
        CommandSpec::remote(
            alias,
            format!("map-{account}-staff-u"),
            true,
            [
                String::from("semanage"),
                String::from("login"),
                String::from("-a"),
                String::from("-s"),
                String::from(STAFF_USER),
                account.to_owned(),
            ],
            Vec::new(),
            true,
        ),
        CommandSpec::remote(
            alias,
            format!("lock-{account}-password"),
            true,
            [
                String::from("passwd"),
                String::from("-l"),
                account.to_owned(),
            ],
            Vec::new(),
            true,
        ),
        install_directory(
            alias,
            account,
            &format!("{home}/.ssh"),
            "0700",
            "ssh-directory",
        ),
        install_authorized_keys(
            alias,
            account,
            &format!("{home}/.ssh/authorized_keys"),
            &key_text,
        ),
        install_directory(
            alias,
            account,
            &format!("{home}/correspondence"),
            "0755",
            "correspondence",
        ),
    ];
    if class == AccountClass::Loop {
        commands.push(install_directory(
            alias,
            account,
            &format!("{home}/git"),
            "0755",
            "git",
        ));
        commands.push(install_directory(
            alias,
            account,
            &format!("{home}/loops"),
            "0755",
            "loops",
        ));
    }
    commands.push(restorecon(alias, account, &home));
    commands
}

pub(crate) fn verify_created_state(
    state: &AccountState,
    requested_uid: u32,
    expected_home: &str,
) -> Result<(), ProvisionError> {
    guard_account(state).map_err(|error| {
        ProvisionError::runtime(
            "critical_divergence",
            format!(
                "created account {} failed {}: {}",
                state.name, error.class, error.detail
            ),
        )
    })?;
    if state.uid != Some(requested_uid) || state.home.as_deref() != Some(expected_home) {
        return Err(ProvisionError::runtime(
            "critical_divergence",
            format!(
                "created account {} has uid {:?} home {:?}, required uid {requested_uid} home {expected_home}",
                state.name, state.uid, state.home
            ),
        ));
    }
    Ok(())
}

pub(crate) fn surface_completion_plan(
    alias: &str,
    state: &AccountState,
    class: AccountClass,
    keys: &[KeyLine],
) -> Result<Vec<CommandSpec>, ProvisionError> {
    ensure_safe_managed_paths(state)?;
    let uid = state.uid.unwrap_or(0);
    let gid = state.gid.unwrap_or(0);
    let home = state.home.as_deref().ok_or_else(|| {
        ProvisionError::runtime(
            "critical_divergence",
            format!("created account {} has no home", state.name),
        )
    })?;
    let paths = account_paths(home);
    let desired_keys = merge_keys("", keys).content;
    let mut commands = Vec::new();
    if !directory_converged(&state.ssh, 0o700, uid, gid) {
        commands.push(install_directory(
            alias,
            &state.name,
            &paths[0].1,
            "0700",
            "ssh-directory",
        ));
    }
    if state.authorized_text != desired_keys
        || !file_converged(&state.authorized_keys, 0o600, uid, gid)
    {
        commands.push(install_authorized_keys(
            alias,
            &state.name,
            &paths[1].1,
            &desired_keys,
        ));
    }
    if state.correspondence.exists && !state.correspondence.is_directory() {
        return Err(ProvisionError::refusal(
            "unsafe_path",
            format!(
                "account {} path correspondence/ is {}",
                state.name, state.correspondence.kind
            ),
        ));
    }
    if !directory_converged(&state.correspondence, 0o755, uid, gid) {
        commands.push(install_directory(
            alias,
            &state.name,
            &paths[4].1,
            "0755",
            "correspondence",
        ));
    }
    if class == AccountClass::Loop {
        for (label, path, surface) in [
            ("git", &paths[2].1, &state.git),
            ("loops", &paths[3].1, &state.loops),
        ] {
            if surface.exists && !surface.is_directory() {
                return Err(ProvisionError::refusal(
                    "unsafe_path",
                    format!("account {} path {label}/ is {}", state.name, surface.kind),
                ));
            }
            if !directory_converged(surface, 0o755, uid, gid) {
                commands.push(install_directory(alias, &state.name, path, "0755", label));
            }
        }
    }
    if !commands.is_empty() {
        commands.push(restorecon(alias, &state.name, home));
    }
    Ok(commands)
}

pub(crate) fn execute_mutations<R: Runner, W: io::Write>(
    runner: &mut R,
    commands: &[CommandSpec],
    output: &mut W,
) -> Result<(), ProvisionError> {
    for command in commands {
        debug_assert!(command.mutation);
        let result = invoke("account", runner, command, output)?;
        require_success(command, result)?;
    }
    Ok(())
}
