use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

pub fn name(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn home_path(relative: &str) -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(relative))
        .ok_or_else(|| io::Error::other("HOME is required"))
}

pub fn milliseconds(variable: &str, default: u64, positive: bool) -> io::Result<Duration> {
    let value = match std::env::var(variable) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| io::Error::other(format!("invalid {variable}")))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(_) => return Err(io::Error::other(format!("invalid {variable}"))),
    };
    if positive && value == 0 {
        return Err(io::Error::other(format!("invalid {variable}")));
    }
    Ok(Duration::from_millis(value))
}

fn matches(pattern: &[u8], value: &[u8]) -> bool {
    match pattern.split_first() {
        None => value.is_empty(),
        Some((b'*', rest)) => {
            matches(rest, value) || (!value.is_empty() && matches(pattern, &value[1..]))
        }
        Some((first, rest)) => value.split_first().is_some_and(|(next, tail)| {
            (*first == b'?' || first.eq_ignore_ascii_case(next)) && matches(rest, tail)
        }),
    }
}

fn declares(
    path: &Path,
    base: &Path,
    alias: &str,
    seen: &mut BTreeSet<PathBuf>,
) -> io::Result<bool> {
    if seen.len() > 64 {
        return Err(io::Error::other("too many SSH includes"));
    }
    if !seen.insert(path.to_path_buf()) {
        return Ok(false);
    }
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for line in source.lines() {
        let mut words = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let key = words.next().unwrap_or_default();
        if key.eq_ignore_ascii_case("host") {
            let patterns: Vec<_> = words.collect();
            let excluded = patterns.iter().any(|p| {
                p.strip_prefix('!')
                    .is_some_and(|p| matches(p.as_bytes(), alias.as_bytes()))
            });
            if !excluded
                && patterns.iter().any(|p| {
                    *p != "*" && !p.starts_with('!') && matches(p.as_bytes(), alias.as_bytes())
                })
            {
                return Ok(true);
            }
        } else if key.eq_ignore_ascii_case("include") {
            for raw in words {
                let include = if let Some(rest) = raw.strip_prefix("~/") {
                    home_path(rest)?
                } else {
                    PathBuf::from(raw)
                };
                let include = if include.is_absolute() {
                    include
                } else {
                    base.join(include)
                };
                let parent = include
                    .parent()
                    .ok_or_else(|| io::Error::other("SSH include parent"))?;
                let pattern = include
                    .file_name()
                    .and_then(|p| p.to_str())
                    .unwrap_or_default();
                if pattern.contains(['*', '?']) {
                    let entries = match fs::read_dir(parent) {
                        Ok(entries) => entries,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    for entry in entries {
                        let entry = entry?;
                        if matches(pattern.as_bytes(), entry.file_name().as_encoded_bytes())
                            && declares(&entry.path(), base, alias, seen)?
                        {
                            return Ok(true);
                        }
                    }
                } else if declares(&include, base, alias, seen)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

pub struct Transport {
    config: PathBuf,
    keys: PathBuf,
}

impl Transport {
    pub fn new(config: Option<PathBuf>, keys: PathBuf, aliases: &[String]) -> io::Result<Self> {
        let config = config.map_or_else(|| home_path(".ssh/config"), Ok)?;
        if !keys.is_absolute() || !fs::metadata(&keys)?.is_file() {
            return Err(io::Error::other(
                "known-hosts must be an absolute regular file",
            ));
        }
        let base = config
            .parent()
            .ok_or_else(|| io::Error::other("SSH config parent"))?;
        for alias in aliases {
            if !name(alias) || !declares(&config, base, alias, &mut BTreeSet::new())? {
                return Err(io::Error::other(format!("unknown ssh alias: {alias}")));
            }
        }
        Ok(Self { config, keys })
    }

    fn command(&self, alias: &str) -> Command {
        let mut command = Command::new("ssh");
        command.arg("-F").arg(&self.config);
        for option in [
            "ConnectTimeout=5",
            "ServerAliveInterval=5",
            "ServerAliveCountMax=1",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
            "GlobalKnownHostsFile=/dev/null",
            "VerifyHostKeyDNS=no",
            "KnownHostsCommand=none",
            "PermitLocalCommand=no",
            "ControlMaster=no",
            "ControlPath=none",
            "ControlPersist=no",
        ] {
            command.arg("-o").arg(option);
        }
        command
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.keys.display()))
            .arg(alias);
        command
    }

    pub fn read(&self, alias: &str, remote: &str, limit: Duration) -> io::Result<Output> {
        let ssh = self.command(alias);
        Command::new("timeout")
            .args(["--foreground", "--kill-after=1s"])
            .arg(format!("{}s", limit.as_secs_f64().max(0.001)))
            .arg(ssh.get_program())
            .args(ssh.get_args())
            .arg(remote)
            .stdin(Stdio::null())
            .output()
    }
}
