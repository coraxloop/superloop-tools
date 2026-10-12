use std::io;

use crate::error::ProvisionError;
use crate::runner::{CommandSpec, Runner, failed_command, invoke, require_success};
use crate::state::{AccountState, SurfaceState, account_home, account_paths};

pub(crate) fn sudo_preflight<R: Runner, W: io::Write>(
    alias: &str,
    account: &str,
    runner: &mut R,
    output: &mut W,
) -> Result<(), ProvisionError> {
    let command = CommandSpec::remote(
        alias,
        format!("sudo-preflight-{account}"),
        true,
        [String::from("true")],
        Vec::new(),
        false,
    );
    let completed = invoke("account", runner, &command, output)?;
    require_success(&command, completed).map(|_output| ())
}

fn parse_passwd(account: &str, output: &[u8]) -> Result<(u32, u32, String), ProvisionError> {
    let text = std::str::from_utf8(output).map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("passwd record for {account} is not UTF-8"),
        )
    })?;
    let fields = text.trim_end().split(':').collect::<Vec<_>>();
    if fields.len() != 7 || fields[0] != account {
        return Err(ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid passwd record for {account}"),
        ));
    }
    let uid = fields[2].parse::<u32>().map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid UID in passwd record for {account}"),
        )
    })?;
    let gid = fields[3].parse::<u32>().map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid GID in passwd record for {account}"),
        )
    })?;
    Ok((uid, gid, fields[5].to_owned()))
}

pub(crate) fn mapping_for(
    account: &str,
    output: &[u8],
) -> Result<(Option<String>, Option<String>), ProvisionError> {
    let text = std::str::from_utf8(output).map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("SELinux login table for {account} is not UTF-8"),
        )
    })?;
    let mut mapping = None;
    let mut default_mapping = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(login), Some(selinux_user)) = (fields.next(), fields.next()) else {
            continue;
        };
        if login == account {
            mapping = Some(selinux_user.to_owned());
        } else if login == "__default__" {
            default_mapping = Some(selinux_user.to_owned());
        }
    }
    Ok((mapping, default_mapping))
}

fn probe_surface<R: Runner, W: io::Write>(
    alias: &str,
    account: &str,
    label: &str,
    path: &str,
    runner: &mut R,
    output: &mut W,
) -> Result<SurfaceState, ProvisionError> {
    let symlink = CommandSpec::remote(
        alias,
        format!("probe-{account}-{label}-symlink"),
        true,
        [String::from("test"), String::from("-L"), path.to_owned()],
        Vec::new(),
        false,
    );
    let symlink_result = invoke("account", runner, &symlink, output)?;
    if symlink_result.status == 0 {
        return Ok(SurfaceState {
            exists: true,
            kind: String::from("symbolic link"),
            ..SurfaceState::default()
        });
    }
    if symlink_result.status != 1 || !symlink_result.stderr.is_empty() {
        return Err(failed_command(&symlink, &symlink_result));
    }
    let exists = CommandSpec::remote(
        alias,
        format!("probe-{account}-{label}-exists"),
        true,
        [String::from("test"), String::from("-e"), path.to_owned()],
        Vec::new(),
        false,
    );
    let exists_result = invoke("account", runner, &exists, output)?;
    if exists_result.status == 1 && exists_result.stderr.is_empty() {
        return Ok(SurfaceState::default());
    }
    require_success(&exists, exists_result)?;
    let stat = CommandSpec::remote(
        alias,
        format!("probe-{account}-{label}-stat"),
        true,
        [
            String::from("stat"),
            String::from("--format=%F|%a|%u|%g"),
            path.to_owned(),
        ],
        Vec::new(),
        false,
    );
    let stat_result = require_success(&stat, invoke("account", runner, &stat, output)?)?;
    let text = std::str::from_utf8(&stat_result.stdout).map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("stat output for {account} {label} is not UTF-8"),
        )
    })?;
    let fields = text.trim_end().split('|').collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err(ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid stat output for {account} {label}"),
        ));
    }
    let mode = u32::from_str_radix(fields[1], 8).map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid mode for {account} {label}"),
        )
    })?;
    let uid = fields[2].parse::<u32>().map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid owner for {account} {label}"),
        )
    })?;
    let gid = fields[3].parse::<u32>().map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("invalid group for {account} {label}"),
        )
    })?;
    Ok(SurfaceState {
        exists: true,
        kind: fields[0].to_owned(),
        mode: Some(mode),
        uid: Some(uid),
        gid: Some(gid),
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn probe_account<R: Runner, W: io::Write>(
    alias: &str,
    account: &str,
    runner: &mut R,
    output: &mut W,
) -> Result<AccountState, ProvisionError> {
    let passwd = CommandSpec::remote(
        alias,
        format!("probe-{account}-account"),
        false,
        [
            String::from("getent"),
            String::from("passwd"),
            account.to_owned(),
        ],
        Vec::new(),
        false,
    );
    let passwd_result = invoke("account", runner, &passwd, output)?;
    if matches!(passwd_result.status, 1 | 2)
        && passwd_result.stdout.is_empty()
        && passwd_result.stderr.is_empty()
    {
        return Ok(AccountState {
            name: account.to_owned(),
            ..AccountState::default()
        });
    }
    let passwd_result = require_success(&passwd, passwd_result)?;
    let (uid, gid, home) = parse_passwd(account, &passwd_result.stdout)?;
    let groups_command = CommandSpec::remote(
        alias,
        format!("probe-{account}-groups"),
        false,
        [String::from("id"), String::from("-nG"), account.to_owned()],
        Vec::new(),
        false,
    );
    let groups_result = require_success(
        &groups_command,
        invoke("account", runner, &groups_command, output)?,
    )?;
    let groups = std::str::from_utf8(&groups_result.stdout)
        .map_err(|_error| {
            ProvisionError::runtime(
                "remote_probe_failure",
                format!("group list for {account} is not UTF-8"),
            )
        })?
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mapping_command = CommandSpec::remote(
        alias,
        format!("probe-{account}-selinux-login"),
        true,
        [
            String::from("semanage"),
            String::from("login"),
            String::from("-l"),
        ],
        Vec::new(),
        false,
    );
    let mapping_result = require_success(
        &mapping_command,
        invoke("account", runner, &mapping_command, output)?,
    )?;
    let (mapping, default_mapping) = mapping_for(account, &mapping_result.stdout)?;
    let paths = account_paths(&home);
    let ssh = probe_surface(alias, account, "ssh", &paths[0].1, runner, output)?;
    let authorized_keys = probe_surface(
        alias,
        account,
        "authorized-keys",
        &paths[1].1,
        runner,
        output,
    )?;
    let git = probe_surface(alias, account, "git", &paths[2].1, runner, output)?;
    let loops = probe_surface(alias, account, "loops", &paths[3].1, runner, output)?;
    let correspondence = probe_surface(
        alias,
        account,
        "correspondence",
        &paths[4].1,
        runner,
        output,
    )?;
    let authorized_text = if authorized_keys.is_regular() {
        let command = CommandSpec::remote(
            alias,
            format!("probe-{account}-authorized-keys-content"),
            true,
            [String::from("cat"), paths[1].1.clone()],
            Vec::new(),
            false,
        );
        let result = require_success(&command, invoke("account", runner, &command, output)?)?;
        String::from_utf8(result.stdout).map_err(|_error| {
            ProvisionError::runtime(
                "remote_probe_failure",
                format!("authorized_keys for {account} is not UTF-8"),
            )
        })?
    } else {
        String::new()
    };
    Ok(AccountState {
        name: account.to_owned(),
        exists: true,
        uid: Some(uid),
        gid: Some(gid),
        home: Some(home),
        groups,
        mapping,
        default_mapping,
        ssh,
        authorized_keys,
        git,
        loops,
        correspondence,
        authorized_text,
    })
}

pub(crate) fn uid_owner<R: Runner, W: io::Write>(
    alias: &str,
    uid: u32,
    runner: &mut R,
    output: &mut W,
) -> Result<Option<String>, ProvisionError> {
    let command = CommandSpec::remote(
        alias,
        format!("probe-uid-{uid}"),
        false,
        [
            String::from("getent"),
            String::from("passwd"),
            uid.to_string(),
        ],
        Vec::new(),
        false,
    );
    let result = invoke("account", runner, &command, output)?;
    if matches!(result.status, 1 | 2) && result.stdout.is_empty() && result.stderr.is_empty() {
        return Ok(None);
    }
    let result = require_success(&command, result)?;
    let text = std::str::from_utf8(&result.stdout).map_err(|_error| {
        ProvisionError::runtime(
            "remote_probe_failure",
            format!("passwd record for uid {uid} is not UTF-8"),
        )
    })?;
    Ok(text
        .split(':')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned))
}

pub(crate) fn planned_post_create_probes(alias: &str, account: &str) -> Vec<CommandSpec> {
    let home = account_home(account);
    let mut commands = vec![
        CommandSpec::remote(
            alias,
            format!("probe-{account}-account"),
            false,
            [
                String::from("getent"),
                String::from("passwd"),
                account.to_owned(),
            ],
            Vec::new(),
            false,
        ),
        CommandSpec::remote(
            alias,
            format!("probe-{account}-groups"),
            false,
            [String::from("id"), String::from("-nG"), account.to_owned()],
            Vec::new(),
            false,
        ),
        CommandSpec::remote(
            alias,
            format!("probe-{account}-selinux-login"),
            true,
            [
                String::from("semanage"),
                String::from("login"),
                String::from("-l"),
            ],
            Vec::new(),
            false,
        ),
    ];
    for (label, path) in account_paths(&home) {
        let stem = label
            .trim_end_matches('/')
            .replace('.', "ssh")
            .replace('_', "-");
        for flag in ["-L", "-e"] {
            commands.push(CommandSpec::remote(
                alias,
                format!("probe-{account}-{stem}-{flag}"),
                true,
                [String::from("test"), flag.to_owned(), path.clone()],
                Vec::new(),
                false,
            ));
        }
        commands.push(CommandSpec::remote(
            alias,
            format!("probe-{account}-{stem}-stat-if-present"),
            true,
            [
                String::from("stat"),
                String::from("--format=%F|%a|%u|%g"),
                path,
            ],
            Vec::new(),
            false,
        ));
    }
    commands.push(CommandSpec::remote(
        alias,
        format!("probe-{account}-authorized-keys-content-if-present"),
        true,
        [String::from("cat"), format!("{home}/.ssh/authorized_keys")],
        Vec::new(),
        false,
    ));
    commands
}
