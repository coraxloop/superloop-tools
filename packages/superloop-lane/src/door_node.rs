//! One owner registration for a door node and its deterministic SSH derivatives.

use std::fmt::Write as _;
use std::os::fd::AsFd;
use std::path::Path;

use nix::unistd::Uid;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{error::LaneError, pinned};

const RECORD: &str = "door-node-registration.json";
const LEAVES: [&str; 2] = ["door-ssh_config", "door-known_hosts"];

fn invalid(detail: impl Into<String>) -> LaneError {
    LaneError::input("door-node-registration", detail)
}

fn read(config: &Path, name: &str) -> Result<Option<Vec<u8>>, LaneError> {
    let owner_home = config
        .ancestors()
        .nth(3)
        .ok_or_else(|| invalid("configuration has no owner home"))?;
    pinned::read_private_optional(
        owner_home,
        &config.join(name),
        Uid::effective().as_raw(),
        0o600,
        65_536,
    )
}

fn word<'a>(value: &'a Value, key: &str) -> Result<&'a str, LaneError> {
    value[key]
        .as_str()
        .ok_or_else(|| invalid(format!("{RECORD}: {key} is absent or invalid")))
}

fn token(text: &str, extra: &[u8], limit: usize) -> bool {
    !text.is_empty()
        && text.len() <= limit
        && text.as_bytes()[0].is_ascii_alphanumeric()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
}

fn decode_key(encoded: &str) -> Option<Vec<u8>> {
    let unpadded = encoded.trim_end_matches('=');
    let padding = encoded.len() - unpadded.len();
    if padding > 2 || (padding != 0 && encoded.len() % 4 != 0) || unpadded.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::new();
    let mut pending = 0_u32;
    let mut bits = 0;
    for byte in unpadded.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        pending = (pending << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((pending >> bits) & 255).ok()?);
            pending &= (1 << bits) - 1;
        }
    }
    (pending == 0 && (padding == 0 || padding == (4 - unpadded.len() % 4) % 4)).then_some(bytes)
}

fn key_field<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (length, remaining) = bytes.split_at_checked(4)?;
    let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    let (field, remaining) = remaining.split_at_checked(length)?;
    *bytes = remaining;
    Some(field)
}

fn valid_key(algorithm: &str, encoded: &str) -> bool {
    let Some(decoded) = decode_key(encoded) else {
        return false;
    };
    let mut bytes = decoded.as_slice();
    if key_field(&mut bytes) != Some(algorithm.as_bytes()) {
        return false;
    }
    let valid = match algorithm {
        "ssh-ed25519" => key_field(&mut bytes).is_some_and(|key| key.len() == 32),
        "ssh-rsa" => {
            key_field(&mut bytes).is_some_and(|key| !key.is_empty())
                && key_field(&mut bytes).is_some_and(|key| !key.is_empty())
        }
        _ => algorithm.strip_prefix("ecdsa-sha2-").is_some_and(|curve| {
            key_field(&mut bytes) == Some(curve.as_bytes())
                && key_field(&mut bytes).is_some_and(|point| {
                    point.first() == Some(&4)
                        && point.len()
                            == match curve {
                                "nistp256" => 65,
                                "nistp384" => 97,
                                "nistp521" => 133,
                                _ => 0,
                            }
                })
        }),
    };
    valid && bytes.is_empty()
}

fn validate(value: &Value, loop_name: &str) -> Result<(), LaneError> {
    let keys = [
        "schema", "loop", "alias", "address", "port", "user", "host_key",
    ];
    if value.as_object().is_none_or(|object| {
        object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key))
    }) || value["schema"] != 1
        || value["loop"] != loop_name
    {
        return Err(invalid(format!("{RECORD}: schema, loop or fields differ")));
    }
    for (key, extra, limit) in [
        ("alias", b"-".as_slice(), 80),
        ("user", b"-_.".as_slice(), 80),
    ] {
        if !token(word(value, key)?, extra, limit) {
            return Err(invalid(format!("{RECORD}: {key} is invalid")));
        }
    }
    let address = word(value, "address")?;
    if address.parse::<std::net::IpAddr>().is_err() && !token(address, b"-.", 253) {
        return Err(invalid(format!("{RECORD}: address is invalid")));
    }
    if !value["port"]
        .as_u64()
        .is_some_and(|port| (1..=65_535).contains(&port))
    {
        return Err(invalid(format!("{RECORD}: port is invalid")));
    }
    let key = word(value, "host_key")?;
    let Some((algorithm, encoded)) = key.split_once(' ') else {
        return Err(invalid(format!("{RECORD}: host_key requires TYPE BASE64")));
    };
    if !matches!(
        algorithm,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    ) || encoded.is_empty()
        || encoded.len() > 16_384
        || !valid_key(algorithm, encoded)
    {
        return Err(invalid(format!("{RECORD}: host_key is invalid")));
    }
    Ok(())
}

fn derive(value: &Value, config: &Path) -> Result<[String; 2], LaneError> {
    let alias = word(value, "alias")?;
    let address = word(value, "address")?;
    let user = word(value, "user")?;
    let key = word(value, "host_key")?;
    let port = value["port"]
        .as_u64()
        .ok_or_else(|| invalid("port is invalid"))?;
    let known = config.join(LEAVES[1]);
    let known = known
        .to_str()
        .filter(|path| {
            path.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        })
        .ok_or_else(|| invalid("known-hosts path is not an absolute SSH literal"))?;
    if !config.is_absolute() {
        return Err(invalid("configuration directory is not absolute"));
    }
    let host = if port == 22 {
        address.to_owned()
    } else {
        format!("[{address}]:{port}")
    };
    Ok([
        format!(
            "# Registered host key: {key}\nHost {alias}\n  HostName {address}\n  Port {port}\n  User {user}\n  UserKnownHostsFile {known}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  BatchMode yes\n"
        ),
        format!("{host} {key}\n"),
    ])
}

fn check_alias(config: &Path, value: &Value) -> Result<bool, LaneError> {
    check_alias_bytes(read(config, "door-compute-registration.json")?, value)
}

fn check_alias_bytes(bytes: Option<Vec<u8>>, value: &Value) -> Result<bool, LaneError> {
    let Some(bytes) = bytes else {
        return Ok(false);
    };
    let route: Value =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if route["alias"] != value["alias"] {
        return Err(LaneError::input(
            "door-node-alias",
            "door-compute-registration.json alias differs from door-node-registration.json",
        ));
    }
    Ok(true)
}

/// A measured transport publication; installation holds the configuration lock.
pub(crate) struct Plan {
    pub(crate) actions: Vec<Value>,
    bytes: [String; 2],
}

impl Plan {
    pub(crate) fn changed(&self) -> u64 {
        self.actions
            .iter()
            .filter(|row| row["action"] != "unchanged")
            .count() as u64
    }

    pub(crate) fn apply(&self, config: &Path) -> Result<(), LaneError> {
        for ((name, bytes), action) in LEAVES.iter().zip(&self.bytes).zip(&self.actions) {
            if action["action"] != "unchanged" {
                crate::install_door::publish_node_file(config, name, bytes.as_bytes())?;
            }
        }
        Ok(())
    }
}

fn measured(
    value: &Value,
    config: &Path,
    mut read: impl FnMut(&str) -> Result<Option<Vec<u8>>, LaneError>,
) -> Result<Plan, LaneError> {
    let bytes = derive(value, config)?;
    let actions = LEAVES.iter().zip(&bytes).map(|(name, after)| {
        let before = read(name)?;
        let before = before.map(String::from_utf8).transpose().map_err(|_| invalid(format!("{name}: not UTF-8")))?;
        Ok(json!({"path":config.join(name),"before":before,"after":after,
            "action":if before.as_ref() == Some(after) { "unchanged" } else if before.is_some() { "replace" } else { "create" }}))
    }).collect::<Result<Vec<_>, LaneError>>()?;
    Ok(Plan { actions, bytes })
}

fn present(directory: &impl AsFd, name: &str) -> Result<bool, LaneError> {
    match nix::sys::stat::fstatat(directory, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(invalid(format!("{name}: {error}"))),
    }
}

fn missing(directory: &impl AsFd) -> Result<LaneError, LaneError> {
    let mut files = Vec::new();
    for name in LEAVES {
        if present(directory, name)? {
            files.push(name);
        }
    }
    Ok(if files.is_empty() {
        LaneError::input(
            "door-node-missing",
            format!("{RECORD} is absent; register-door-node is required"),
        )
    } else {
        LaneError::input(
            "door-node-unregistered-files",
            format!(
                "{} without {RECORD}; register-door-node is required",
                files.join(", ")
            ),
        )
    })
}

fn registration(bytes: &[u8], loop_name: &str) -> Result<Value, LaneError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| invalid(format!("{RECORD}: {error}")))?;
    validate(&value, loop_name)?;
    Ok(value)
}

/// Measure the registration and derivatives beneath the installer's held directory.
pub(crate) fn plan(
    directory: &impl AsFd,
    config: &Path,
    loop_name: &str,
    owner: u32,
) -> Result<Option<Plan>, LaneError> {
    let read = |name: &str| crate::door::read_owner_leaf_optional(directory, name, owner);
    let Some(bytes) = read(RECORD)? else {
        let refusal = missing(directory)?;
        if refusal.kind == "door-node-unregistered-files"
            || present(directory, "door-compute-registration.json")?
        {
            return Err(refusal);
        }
        return Ok(None);
    };
    let value = registration(&bytes, loop_name)?;
    check_alias_bytes(read("door-compute-registration.json")?, &value)?;
    measured(&value, config, read).map(Some)
}

/// Compare the transport's pinned bytes with facts read beneath its held directory.
pub(crate) fn verify(
    directory: &impl AsFd,
    config: &Path,
    loop_name: &str,
    alias: &str,
    pin: Option<&[u8]>,
    owner: u32,
) -> Result<(), LaneError> {
    let Some(bytes) = crate::door::read_owner_leaf_optional(directory, RECORD, owner)? else {
        return Err(missing(directory)?);
    };
    let value = registration(&bytes, loop_name)?;
    if value["alias"] != alias {
        return Err(LaneError::input(
            "door-node-alias",
            "door-compute-registration.json alias differs from door-node-registration.json",
        ));
    }
    let derived = derive(&value, config)?;
    let known = crate::door::read_owner_leaf_optional(directory, LEAVES[1], owner)?;
    if pin != Some(derived[0].as_bytes()) || known.as_deref() != Some(derived[1].as_bytes()) {
        return Err(LaneError::input(
            "door-node-derived-drift",
            "door-ssh_config or door-known_hosts differs from door-node-registration.json; run install-door",
        ));
    }
    Ok(())
}

fn arguments(args: &[String]) -> Result<(Value, bool, Option<String>), LaneError> {
    let Some(loop_name) = args.first() else {
        return Err(invalid("register-door-node requires LOOP"));
    };
    loop_home::validate_name(loop_name).map_err(|error| invalid(error.message()))?;
    let mut value = json!({"schema":1,"loop":loop_name});
    let mut dry_run = false;
    let mut digest = None;
    let mut words = args[1..].iter();
    while let Some(flag) = words.next() {
        if flag == "--dry-run" && !dry_run {
            dry_run = true;
            continue;
        }
        let field = match flag.as_str() {
            "--alias" => "alias",
            "--address" => "address",
            "--port" => "port",
            "--user" => "user",
            "--host-key" => "host_key",
            "--expect-digest" if digest.is_none() => "digest",
            _ => return Err(invalid(format!("unknown or repeated argument {flag}"))),
        };
        let text = words
            .next()
            .ok_or_else(|| invalid(format!("{flag} requires a value")))?;
        if field == "digest" {
            digest = Some(text.clone());
            continue;
        }
        if value.get(field).is_some() {
            return Err(invalid(format!("repeated argument {flag}")));
        }
        value[field] = if field == "port" {
            json!(
                text.parse::<u16>()
                    .map_err(|_| invalid("port is invalid"))?
            )
        } else {
            json!(text)
        };
    }
    if dry_run == digest.is_some() {
        return Err(invalid(
            "select exactly one of --dry-run or --expect-digest HEX",
        ));
    }
    validate(&value, loop_name)?;
    Ok((value, dry_run, digest))
}

/// Register public node facts using a preview bound to the measured prior files.
///
/// # Errors
/// Refuses invalid fields, unsafe files, busy configuration or a stale preview digest.
pub fn run(owner_home: &Path, args: &[String]) -> Result<Value, LaneError> {
    let started = std::time::Instant::now();
    let (value, dry_run, expected) = arguments(args)?;
    let loop_name = word(&value, "loop")?;
    let config = owner_home.join(".config/loops").join(loop_name);
    let _lock = crate::install::lock_loop_config(&config, dry_run)?;
    let registry = loop_home::load_registry(&loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    ))
    .map_err(|error| invalid(error.message()))?;
    registry
        .row(loop_name, owner_home)
        .map_err(|error| invalid(error.message()))?;
    check_alias(&config, &value)?;
    let before = read(&config, RECORD)?;
    let before = before
        .map(String::from_utf8)
        .transpose()
        .map_err(|_| invalid("registration is not UTF-8"))?;
    let after =
        serde_json::to_string_pretty(&value).map_err(|error| invalid(error.to_string()))? + "\n";
    let plan = measured(&value, &config, |name| read(&config, name))?;
    let preview = json!({"registration":{"path":config.join(RECORD),"before":before,"after":after},"transport":plan.actions});
    let serialized = serde_json::to_vec(&preview).map_err(|error| invalid(error.to_string()))?;
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(&serialized) {
        write!(digest, "{byte:02x}").map_err(|error| invalid(error.to_string()))?;
    }
    let changed = before.as_ref() != Some(&after);
    if !dry_run {
        if expected.as_deref() != Some(&digest) {
            return Err(LaneError::input(
                "door-node-digest",
                "preview changed; repeat register-door-node --dry-run",
            ));
        }
        if changed {
            crate::install_door::publish_node_file(&config, RECORD, after.as_bytes())?;
        }
    }
    Ok(
        json!({"schema":1,"command":"register-door-node","loop":loop_name,"dry_run":dry_run,
        "changed":changed,"preview":preview,"preview_sha256":digest,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
pub(crate) fn fixture(config: &Path) -> Vec<u8> {
    fixture_for(config, "fixture")
}

#[cfg(test)]
pub(crate) fn fixture_for(config: &Path, alias: &str) -> Vec<u8> {
    use std::os::unix::fs::PermissionsExt as _;
    let value = json!({"schema":1,"loop":"alpha","alias":alias,"address":"192.0.2.1","port":2222,"user":"fixture","host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    let bytes = derive(&value, config).expect("node derivatives");
    for (name, contents) in [
        (RECORD, serde_json::to_vec(&value).expect("node record")),
        (LEAVES[0], bytes[0].as_bytes().to_vec()),
        (LEAVES[1], bytes[1].as_bytes().to_vec()),
    ] {
        let path = config.join(name);
        std::fs::write(&path, contents).expect("fixture file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture mode");
    }
    bytes[0].as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics only if malformed public facts pass registration validation.
    /// ´test:unit:door-node-facts-refuse-injection-and-malformed-keys´
    #[test]
    fn door_node_facts_refuse_injection_and_malformed_keys() {
        let value = json!({"schema":1,"loop":"alpha","alias":"fixture","address":"192.0.2.1","port":22,"user":"account","host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
        validate(&value, "alpha").expect("valid public key");
        for (field, invalid) in [
            ("alias", json!("*")),
            ("address", json!("node\nProxyCommand false")),
            ("user", json!("-option")),
            ("port", json!(0)),
            ("port", json!(65536)),
            ("host_key", json!("ssh-ed25519 AAAA")),
            (
                "host_key",
                json!(
                    "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                ),
            ),
            (
                "host_key",
                json!(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA comment"
                ),
            ),
            ("extra", json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert_eq!(
                validate(&changed, "alpha").expect_err("invalid field").kind,
                "door-node-registration"
            );
        }
    }
}
