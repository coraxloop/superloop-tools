use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::ProvisionError;

/// Stable help text for the workstation key generator.
pub const LOOP_KEYGEN_HELP: &str = "Usage: account keygen --loop NAME [--dir KEYDIR]\n\
\n\
Mint a loop master key and an independently revocable Codex worker key.\n\
\n\
Options:\n\
  --loop NAME    Loop and requested account name (required)\n\
  --dir KEYDIR   Key directory (default: $HOME/.ssh)\n\
  -h, --help     Show this help\n\
\n\
Required environment (no defaults):\n\
  LOOP_KEYGEN_COORDINATOR    Coordinator name for the handoff\n\
  LOOP_KEYGEN_CLIENT_CONFIG  Absolute client SSH configuration path\n\
  LOOP_KEYGEN_SSH_RECORDS    SSH records for the generated handoff\n\
  LOOP_KEYGEN_ROUTES         Node routes (alias, address, port, optional host key)\n";

/// Stable help text for the guarded server provisioner.
pub const STAFF_PROVISION_HELP: &str = "Usage:\n\
  account check --server BIRD [--ssh-alias ALIAS] ACCOUNT\n\
  account create --server BIRD [--ssh-alias ALIAS] ACCOUNT --class loop|human --uid UID --key PUBKEY_FILE [--key PUBKEY_FILE]... [--showcase ACCOUNT] [--dry-run]\n\
  account admit-key --server BIRD [--ssh-alias ALIAS] ACCOUNT [--mirror-showcase ACCOUNT] [--key PUBKEY_FILE]... [--dry-run]\n\
\n\
Options:\n\
  --server BIRD              Server name; default alias is BIRD-owner\n\
  --ssh-alias ALIAS          Override the owner SSH alias\n\
  --class loop|human         Registry class for create\n\
  --uid UID                  New decimal UID, greater than 1000\n\
  --key PUBKEY_FILE          Public-key input; repeat for multiple files\n\
  --showcase ACCOUNT         Required mirror target for class loop\n\
  --mirror-showcase ACCOUNT  Mirror admitted loop keys to this account\n\
  --dry-run                  Probe and print exact argv without mutations\n\
  -h, --help                 Show this help\n\
\n\
admit-key reads public-key lines from standard input when --key is absent.\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoopOptions {
    pub(crate) loop_name: String,
    pub(crate) directory: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccountClass {
    Loop,
    Human,
}

impl AccountClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Loop => "loop",
            Self::Human => "human",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StaffAction {
    Check {
        account: String,
    },
    Create {
        account: String,
        class: AccountClass,
        uid: u32,
        key_paths: Vec<PathBuf>,
        showcase: Option<String>,
        dry_run: bool,
    },
    Admit {
        account: String,
        mirror_showcase: Option<String>,
        key_paths: Vec<PathBuf>,
        dry_run: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StaffOptions {
    pub(crate) alias: String,
    pub(crate) action: StaffAction,
}

fn valid_account_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_');
    valid_first
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !matches!(name, "root" | "owner" | "administrator")
}

fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn os_arguments<I, A>(arguments: I) -> Result<Vec<String>, ProvisionError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    arguments
        .into_iter()
        .map(Into::into)
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_argument| ProvisionError::usage("arguments must be UTF-8"))
        })
        .collect()
}

pub(crate) fn parse_loop_args<I, A>(arguments: I) -> Result<Option<LoopOptions>, ProvisionError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let arguments = os_arguments(arguments)?;
    if arguments == ["--help"] || arguments == ["-h"] {
        return Ok(None);
    }
    let mut loop_name = None;
    let mut directory = None;
    let mut position = 0;
    while position < arguments.len() {
        let option = &arguments[position];
        position += 1;
        let value = arguments
            .get(position)
            .ok_or_else(|| ProvisionError::usage(format!("missing value for {option}")))?;
        position += 1;
        match option.as_str() {
            "--loop" if loop_name.is_none() => loop_name = Some(value.clone()),
            "--dir" if directory.is_none() => directory = Some(PathBuf::from(value)),
            _ => return Err(ProvisionError::usage(format!("invalid option: {option}"))),
        }
    }
    let loop_name = loop_name.ok_or_else(|| ProvisionError::usage("--loop is required"))?;
    if !valid_account_name(&loop_name) {
        return Err(ProvisionError::usage(format!(
            "invalid loop account name: {loop_name}"
        )));
    }
    let directory = match directory {
        Some(directory) => directory,
        None => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| ProvisionError::usage("HOME is unset; supply --dir"))?,
        )
        .join(".ssh"),
    };
    if directory.to_str().is_none() {
        return Err(ProvisionError::usage("key directory must be UTF-8"));
    }
    Ok(Some(LoopOptions {
        loop_name,
        directory,
    }))
}

fn next_value(
    arguments: &[String],
    position: &mut usize,
    option: &str,
) -> Result<String, ProvisionError> {
    let value = arguments
        .get(*position)
        .ok_or_else(|| ProvisionError::usage(format!("missing value for {option}")))?
        .clone();
    *position += 1;
    Ok(value)
}

fn parse_create(
    arguments: &[String],
    mut position: usize,
    account: String,
) -> Result<StaffAction, ProvisionError> {
    let mut class = None;
    let mut uid = None;
    let mut key_paths = Vec::new();
    let mut showcase = None;
    let mut dry_run = false;
    while position < arguments.len() {
        let option = &arguments[position];
        position += 1;
        match option.as_str() {
            "--class" if class.is_none() => {
                let value = next_value(arguments, &mut position, option)?;
                class = Some(match value.as_str() {
                    "loop" => AccountClass::Loop,
                    "human" => AccountClass::Human,
                    _ => {
                        return Err(ProvisionError::usage(format!(
                            "invalid account class: {value}"
                        )));
                    }
                });
            }
            "--uid" if uid.is_none() => {
                let value = next_value(arguments, &mut position, option)?;
                uid = Some(value.parse::<u32>().map_err(|_error| {
                    ProvisionError::usage(format!("invalid decimal UID: {value}"))
                })?);
            }
            "--key" => key_paths.push(PathBuf::from(next_value(arguments, &mut position, option)?)),
            "--showcase" if showcase.is_none() => {
                showcase = Some(next_value(arguments, &mut position, option)?);
            }
            "--dry-run" if !dry_run => dry_run = true,
            _ => {
                return Err(ProvisionError::usage(format!(
                    "invalid create option: {option}"
                )));
            }
        }
    }
    let class = class.ok_or_else(|| ProvisionError::usage("--class is required"))?;
    let uid = uid.ok_or_else(|| ProvisionError::usage("--uid is required"))?;
    if key_paths.is_empty() {
        return Err(ProvisionError::usage(
            "create requires at least one --key file",
        ));
    }
    if class == AccountClass::Loop && showcase.is_none() {
        return Err(ProvisionError::refusal(
            "showcase_required",
            format!("loop account {account} requires --showcase"),
        ));
    }
    if class == AccountClass::Human && showcase.is_some() {
        return Err(ProvisionError::usage(
            "--showcase is valid only with --class loop",
        ));
    }
    if let Some(showcase_name) = &showcase
        && !valid_account_name(showcase_name)
    {
        return Err(ProvisionError::usage(format!(
            "invalid showcase account name: {showcase_name}"
        )));
    }
    Ok(StaffAction::Create {
        account,
        class,
        uid,
        key_paths,
        showcase,
        dry_run,
    })
}

fn parse_admit(
    arguments: &[String],
    mut position: usize,
    account: String,
) -> Result<StaffAction, ProvisionError> {
    let mut mirror_showcase = None;
    let mut key_paths = Vec::new();
    let mut dry_run = false;
    while position < arguments.len() {
        let option = &arguments[position];
        position += 1;
        match option.as_str() {
            "--mirror-showcase" if mirror_showcase.is_none() => {
                mirror_showcase = Some(next_value(arguments, &mut position, option)?);
            }
            "--key" => key_paths.push(PathBuf::from(next_value(arguments, &mut position, option)?)),
            "--dry-run" if !dry_run => dry_run = true,
            _ => {
                return Err(ProvisionError::usage(format!(
                    "invalid admit-key option: {option}"
                )));
            }
        }
    }
    if let Some(showcase_name) = &mirror_showcase
        && !valid_account_name(showcase_name)
    {
        return Err(ProvisionError::usage(format!(
            "invalid showcase account name: {showcase_name}"
        )));
    }
    Ok(StaffAction::Admit {
        account,
        mirror_showcase,
        key_paths,
        dry_run,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_staff_args<I, A>(arguments: I) -> Result<Option<StaffOptions>, ProvisionError>
where
    I: IntoIterator<Item = A>,
    A: Into<OsString>,
{
    let arguments = os_arguments(arguments)?;
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        return Ok(None);
    }
    let mut server = None;
    let mut alias = None;
    let mut position = 0;
    while position < arguments.len() {
        let option = &arguments[position];
        match option.as_str() {
            "--server" if server.is_none() => {
                position += 1;
                server = Some(next_value(&arguments, &mut position, option)?);
            }
            "--ssh-alias" if alias.is_none() => {
                position += 1;
                alias = Some(next_value(&arguments, &mut position, option)?);
            }
            _ => break,
        }
    }
    let server = server.ok_or_else(|| ProvisionError::usage("--server is required"))?;
    if !valid_alias(&server) {
        return Err(ProvisionError::usage(format!(
            "invalid server name: {server}"
        )));
    }
    let alias = alias.unwrap_or_else(|| format!("{server}-owner"));
    if !valid_alias(&alias) {
        return Err(ProvisionError::usage(format!("invalid SSH alias: {alias}")));
    }
    let subcommand = next_value(&arguments, &mut position, "subcommand")?;
    let account = next_value(&arguments, &mut position, &subcommand)?;
    if !valid_account_name(&account) {
        return Err(ProvisionError::usage(format!(
            "invalid staff account name: {account}"
        )));
    }
    let action = match subcommand.as_str() {
        "check" if position == arguments.len() => StaffAction::Check { account },
        "check" => return Err(ProvisionError::usage("check accepts no trailing options")),
        "create" => parse_create(&arguments, position, account)?,
        "admit-key" => parse_admit(&arguments, position, account)?,
        _ => {
            return Err(ProvisionError::usage(format!(
                "unknown subcommand: {subcommand}"
            )));
        }
    };
    Ok(Some(StaffOptions { alias, action }))
}
