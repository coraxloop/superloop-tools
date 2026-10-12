//! Render reviewed node routes as passive owner-installable artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

const HEADING: &str = "## Node routes";
const FIELDS: [&str; 12] = [
    "node",
    "status",
    "hostname",
    "port",
    "host_key_algorithm",
    "host_key",
    "loop",
    "account",
    "worker_alias",
    "session_alias",
    "worker_identity",
    "session_identity",
];
type Result<T> = std::result::Result<T, String>;
pub(super) type Row = BTreeMap<String, String>;

fn cells(line: &str) -> Vec<&str> {
    let line = line.trim();
    let line = line.strip_prefix('|').unwrap_or(line);
    line.strip_suffix('|')
        .unwrap_or(line)
        .split('|')
        .map(str::trim)
        .collect()
}

fn token(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn path_valid(value: &str) -> bool {
    value.starts_with('/')
        && value.split('/').all(|part| {
            part.is_empty()
                || (part != ".."
                    && part != "."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
        })
}

fn validate(row: &Row, line: usize) -> Result<()> {
    for field in FIELDS {
        let value = &row[field];
        let valid = match field {
            "status" => matches!(value.as_str(), "active" | "retired"),
            "port" => value
                .parse::<u16>()
                .is_ok_and(|port| port != 0 && port.to_string() == *value),
            "hostname" => {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b))
            }
            "host_key_algorithm" => matches!(
                value.as_str(),
                "ssh-ed25519"
                    | "ssh-rsa"
                    | "ecdsa-sha2-nistp256"
                    | "ecdsa-sha2-nistp384"
                    | "ecdsa-sha2-nistp521"
            ),
            "host_key" => {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
            }
            "worker_identity" => path_valid(value),
            "session_identity" => value.strip_prefix("~/.ssh").is_some_and(path_valid),
            "worker_alias" => *value == format!("{}-worker", row["node"]),
            _ => token(value),
        };
        if !valid {
            let rule = match field {
                "status" => "active or retired",
                "port" => "a canonical decimal port from 1 to 65535",
                "hostname" => "a nonempty hostname using letters, digits, hyphens, dots or colons",
                "host_key_algorithm" => "a supported SSH host key algorithm",
                "host_key" => "a nonempty base64 host key",
                "worker_identity" => "an absolute path without dot components or unsafe characters",
                "session_identity" => "an entry-relative ~/.ssh path",
                "worker_alias" => "the node token followed by -worker",
                _ => {
                    "a token starting with a letter or digit and containing only letters, digits, hyphens, underscores or dots"
                }
            };
            let form = if value.is_empty() {
                "an empty value"
            } else if value.starts_with('/') {
                if field == "worker_identity" {
                    if value.split('/').any(|part| matches!(part, "." | "..")) {
                        "an absolute path with a dot component"
                    } else {
                        "an absolute path with an unsafe character"
                    }
                } else {
                    "an absolute path"
                }
            } else if field == "session_identity" && !value.starts_with("~/.ssh/") {
                "a path not under ~/.ssh"
            } else {
                "an invalid form"
            };
            return Err(format!(
                "registry-row: {} line {line}: {field} must be {rule} (got {form})",
                row["loop"]
            ));
        }
    }
    Ok(())
}

pub(super) fn registry(source: &str, selected: &str) -> Result<Vec<Row>> {
    registry_rows(source, selected, false)
}

fn registry_heading(line: &str) -> bool {
    if line == HEADING {
        return true;
    }
    let Some(label) = line
        .strip_prefix(HEADING)
        .and_then(|suffix| suffix.strip_prefix(" · `"))
        .and_then(|suffix| suffix.strip_suffix('`'))
    else {
        return false;
    };
    let word = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    let mut parts = label.split(':');
    parts.next().is_some_and(word)
        && parts.next().is_some_and(word)
        && parts.next().is_some_and(|name| name.split('-').all(word))
        && parts.next().is_none()
}

fn registry_row(headers: &[&str], source: &str, line: usize) -> Result<Row> {
    let values = cells(source);
    if values.len() != headers.len() {
        return Err(format!(
            "registry-row: line {line}: field count {}, expected {}",
            values.len(),
            headers.len()
        ));
    }
    let row: Row = headers
        .iter()
        .zip(values)
        .map(|(key, value)| (String::from(*key), String::from(value)))
        .collect();
    for field in ["node", "loop"] {
        if !token(&row[field]) {
            return Err(format!(
                "registry-row: line {line}: {field} must be a present valid token"
            ));
        }
    }
    Ok(row)
}

pub(super) fn registry_rows(source: &str, selected: &str, retired: bool) -> Result<Vec<Row>> {
    let mut lines = source.lines().enumerate();
    if !lines.any(|(_, line)| registry_heading(line)) {
        return Err(String::from("registry-table: missing ## Node routes"));
    }
    let (header_line, header) = lines
        .find(|(_, line)| !line.trim().is_empty())
        .ok_or("registry-table: missing header")?;
    let headers = cells(header);
    if headers.len() != FIELDS.len() {
        return Err(format!(
            "registry-field: line {}: field count {}, expected {}",
            header_line + 1,
            headers.len(),
            FIELDS.len()
        ));
    }
    for field in FIELDS {
        if !headers.contains(&field) {
            return Err(format!(
                "registry-field: line {}: missing {field}",
                header_line + 1
            ));
        }
    }
    let (separator_line, separator) = lines.next().ok_or("registry-table: missing separator")?;
    let separators = cells(separator);
    if separators.len() != headers.len()
        || separators
            .iter()
            .any(|cell| cell.len() < 3 || !cell.bytes().all(|b| b == b'-'))
    {
        return Err(format!(
            "registry-table: invalid separator at line {} (field count {}, expected {})",
            separator_line + 1,
            separators.len(),
            headers.len()
        ));
    }
    let mut rows = Vec::new();
    let mut identities = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    for (index, line) in lines {
        if line.trim().is_empty() || line.starts_with('#') {
            break;
        }
        let row = registry_row(&headers, line, index + 1)?;
        // Every entry point, including render-routes, selects one loop only.
        // A foreign row must be identifiable, but its fields are not this loop's defect.
        if row["loop"] != selected {
            continue;
        }
        validate(&row, index + 1)?;
        if !identities.insert((row["node"].clone(), row["loop"].clone())) {
            return Err(format!(
                "registry-row: {selected} line {}: node/loop must be unique (duplicate node/loop)",
                index + 1
            ));
        }
        for field in ["worker_alias", "session_alias"] {
            if !aliases.insert(row[field].clone()) {
                return Err(format!(
                    "registry-row: {selected} line {}: {field} must be unique (duplicate alias)",
                    index + 1
                ));
            }
        }
        if retired || row["status"] == "active" {
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| left["node"].cmp(&right["node"]));
    if rows.is_empty() {
        return Err(String::from(
            "registry-loop: no active routes for selected loop",
        ));
    }
    let active = rows
        .iter()
        .filter(|row| row["status"] == "active")
        .collect::<Vec<_>>();
    for field in ["account", "worker_identity"] {
        if active
            .first()
            .is_some_and(|first| active.iter().any(|row| row[field] != first[field]))
        {
            return Err(format!(
                "registry-field: selected routes require one {field}"
            ));
        }
    }
    Ok(rows)
}

pub(super) fn stanza(
    row: &Row,
    alias: &str,
    identity: &Path,
    known: &Path,
    policy: &str,
) -> String {
    format!(
        "Host {}\n  HostName {}\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking {policy}\n  UpdateHostKeys no\n\n",
        row[alias],
        row["hostname"],
        row["port"],
        row["account"],
        identity.display(),
        known.display()
    )
}

pub(super) fn known_hosts(rows: &[Row]) -> String {
    let mut known = String::new();
    for row in rows {
        let _written = writeln!(
            known,
            "[{}]:{} {} {}",
            row["hostname"], row["port"], row["host_key_algorithm"], row["host_key"]
        );
        if row["port"] == "22" {
            let _written = writeln!(
                known,
                "{} {} {}",
                row["hostname"], row["host_key_algorithm"], row["host_key"]
            );
        }
    }
    known
}

pub(super) fn render(rows: &[Row], owner: &Path, name: &str) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let known = known_hosts(rows);
    for (artifact, home, alias, identity) in [
        (
            "codex",
            crate::signin_home::lane_home(owner, name),
            "worker_alias",
            "worker_identity",
        ),
        (
            "claude",
            crate::signin_home::claude_home(owner, name),
            "worker_alias",
            "worker_identity",
        ),
        (
            "session",
            PathBuf::from("~/.ssh"),
            "session_alias",
            "session_identity",
        ),
    ] {
        let mut config = if artifact == "codex" {
            super::signin_home::route_header(
                name,
                &rows
                    .iter()
                    .map(|row| row["node"].as_str())
                    .collect::<Vec<_>>(),
            )
        } else {
            String::new()
        };
        let known_file = home.join(if artifact == "session" {
            "known_hosts.clients"
        } else {
            "known_hosts.routes"
        });
        let policy = "yes";
        config.extend(rows.iter().map(|row| {
            let key = if artifact == "codex" {
                home.join("keys")
                    .join(Path::new(&row[identity]).file_name().unwrap_or_default())
            } else {
                PathBuf::from(&row[identity])
            };
            stanza(row, alias, &key, &known_file, policy)
        }));
        files.insert(format!("{artifact}.ssh_config"), config);
        files.insert(format!("{artifact}.known_hosts"), known.clone());
    }
    let config = crate::signin_home::claude_home(owner, name).join("ssh_config");
    let commands: Vec<String> = rows
        .iter()
        .map(|row| format!("ssh -F {} {}", config.display(), row["worker_alias"]))
        .collect();
    let allows: Vec<String> = commands
        .iter()
        .map(|command| format!("Bash({command} *)"))
        .collect();
    files.insert(String::from("claude.owner-settings.json"), format!("{}\n", serde_json::json!({"permissions":{"allow":allows},"sandbox":{"excludedCommands":commands}})));
    files
}

fn publish(output: &Path, files: &BTreeMap<String, String>) -> Result<usize> {
    // The output is an explicitly selected staging directory, never a discovered home.
    if !fs::symlink_metadata(output).is_ok_and(|meta| meta.is_dir()) {
        return Err(String::from(
            "output-directory: supply an existing regular staging directory",
        ));
    }
    for name in files.keys() {
        match fs::symlink_metadata(output.join(name)) {
            Ok(meta) if !meta.is_file() => {
                return Err(format!("output-file: {name}: not a regular file"));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("output-file: {name}: inspection failed"));
            }
            _ => (),
        }
    }
    let mut changed = 0;
    for (name, content) in files {
        let path = output.join(name);
        if fs::read(&path).is_ok_and(|bytes| bytes == content.as_bytes()) {
            continue;
        }
        let mut temporary = tempfile::NamedTempFile::new_in(output)
            .map_err(|_| String::from("output-file: publication failed"))?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| String::from("output-file: publication failed"))?;
        temporary
            .write_all(content.as_bytes())
            .map_err(|_| String::from("output-file: publication failed"))?;
        temporary
            .persist(&path)
            .map_err(|_| String::from("output-file: publication failed"))?;
        changed += 1;
    }
    Ok(changed)
}

fn run(args: &[OsString]) -> Result<serde_json::Value> {
    let mut options = BTreeMap::new();
    for pair in args.chunks(2) {
        let [key, value] = pair else {
            return Err(String::from("arguments: expected option/value pairs"));
        };
        let key = key.to_str().ok_or("arguments: non-UTF-8 option")?;
        if !["--registry", "--loop", "--owner-home", "--output"].contains(&key)
            || options.insert(key, value).is_some()
        {
            return Err(String::from("arguments: unknown or duplicate option"));
        }
    }
    let required = |key| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| format!("arguments: missing {key}"))
    };
    let name = required("--loop")?
        .to_str()
        .filter(|name| token(name))
        .ok_or("arguments: invalid loop")?;
    let owner = required("--owner-home")?
        .to_str()
        .filter(|path| path_valid(path))
        .ok_or("arguments: invalid owner-home")?;
    let source = fs::read_to_string(required("--registry")?)
        .map_err(|_| String::from("registry-read: inspection failed"))?;
    let rows = registry(&source, name)?;
    let output = PathBuf::from(
        required("--output")?
            .to_str()
            .ok_or("arguments: non-UTF-8 output")?,
    );
    let files = render(&rows, Path::new(owner), name);
    let changed = publish(&output, &files)?;
    Ok(
        serde_json::json!({"loop":name,"nodes":rows.len(),"changed":changed,"output":output,"files":files.keys().collect::<Vec<_>>()}),
    )
}

/// Render a strict registry into an explicit staging directory and report changes.
pub fn command(args: &[OsString]) -> std::process::ExitCode {
    superloop_cli_common::install_json_panic_hook("superloop-lane render-routes");
    let started = std::time::Instant::now();
    let result = if std::io::stdout().is_terminal() {
        Err(String::from("arguments: terminal stdout refused"))
    } else {
        run(args)
    };
    let (status, report) = match result {
        Ok(fields) => (
            0,
            writeln!(
                std::io::stdout().lock(),
                "{}",
                serde_json::json!({"schema":1,"command":"superloop-lane render-routes","kind":"result","fields":fields,"wall_ms":started.elapsed().as_millis()})
            ),
        ),
        Err(reason) => {
            let usage = reason.starts_with("arguments:");
            (
                if usage { 2 } else { 1 },
                writeln!(
                    std::io::stderr().lock(),
                    "{}",
                    serde_json::json!({"schema":1,"command":"superloop-lane render-routes","kind":"refusal","class":if usage { "usage" } else { "failure" },"reason":reason})
                ),
            )
        }
    };
    if report.is_err() {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::from(status)
}
