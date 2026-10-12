use crate::driver_launch::run_paths::pin_runs_root;
use crate::planner::{CommandSpec, Custody, EntryPlan, IoMode, shell_word, verify_entry_plan};
use crate::{LoopError, LoopRecord};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

const VERIFY_SCRIPT: &str = "set -e; printf 'user=%s\\0' \"$(/usr/bin/id -un)\"; printf 'uid=%s\\0' \"$(/usr/bin/id -u)\"; printf 'groups=%s\\0' \"$(/usr/bin/id -G)\"; printf 'home=%s\\0' \"$HOME\"; /usr/bin/env -0 | LC_ALL=C /usr/bin/sort -z | /usr/bin/sed -z 's/^/env=/'";

/// Paths and wall read from the namespace-root ensure step's report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnsureReport {
    /// Corrected paths in report order.
    pub corrected: Vec<String>,
    /// Created paths in report order.
    pub created: Vec<String>,
    /// Step wall in microseconds, present only after success.
    pub micros: Option<u64>,
}

impl EnsureReport {
    /// Parse the private step's line forms.
    ///
    /// # Errors
    ///
    /// Returns a runtime failure for malformed or non-UTF-8 report bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoopError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_error| LoopError::runtime("ensure report is not UTF-8"))?;
        let mut report = Self::default();
        for line in text.lines() {
            if let Some(body) = line.strip_prefix("created ") {
                let (path, mode) = body
                    .rsplit_once(' ')
                    .ok_or_else(|| LoopError::runtime("malformed created report line"))?;
                if path.is_empty() || u32::from_str_radix(mode, 8).is_err() {
                    return Err(LoopError::runtime("malformed created report line"));
                }
                report.created.push(path.to_owned());
            } else if let Some(body) = line.strip_prefix("corrected ") {
                let mut tail = body.rsplitn(4, ' ');
                let new_gid = tail.next();
                let old_gid = tail.next();
                let marker = tail.next();
                let body = if marker == Some("gid") {
                    for gid in [old_gid, new_gid] {
                        if !gid.is_some_and(|gid| {
                            !gid.is_empty()
                                && gid.bytes().all(|byte| byte.is_ascii_digit())
                                && gid.parse::<u32>().is_ok()
                        }) {
                            return Err(LoopError::runtime("malformed corrected report line"));
                        }
                    }
                    tail.next()
                        .ok_or_else(|| LoopError::runtime("malformed corrected report line"))?
                } else {
                    body
                };
                let (path_and_old, new) = body
                    .rsplit_once(' ')
                    .ok_or_else(|| LoopError::runtime("malformed corrected report line"))?;
                let (path, old) = path_and_old
                    .rsplit_once(' ')
                    .ok_or_else(|| LoopError::runtime("malformed corrected report line"))?;
                if path.is_empty()
                    || u32::from_str_radix(old, 8).is_err()
                    || u32::from_str_radix(new, 8).is_err()
                {
                    return Err(LoopError::runtime("malformed corrected report line"));
                }
                report.corrected.push(path.to_owned());
            } else if let Some(value) = line.strip_prefix("wall ") {
                if report
                    .micros
                    .replace(
                        value
                            .parse::<u64>()
                            .map_err(|_error| LoopError::runtime("malformed wall report line"))?,
                    )
                    .is_some()
                {
                    return Err(LoopError::runtime("duplicate wall report line"));
                }
            } else {
                return Err(LoopError::runtime("unknown ensure report line"));
            }
        }
        Ok(report)
    }
}

/// The read-only root inspection produced by the private namespace step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootAudit {
    /// Most serious observed home state: zero, three, or four.
    pub status: u8,
    /// Number of rows the ensure step would create.
    pub would_create: usize,
    /// Number of rows whose mode the ensure step would correct.
    pub would_correct: usize,
    /// JSON array of the observed table rows and the additional class root.
    pub rows_json: String,
}

impl RootAudit {
    /// Parse the two-line, privately produced inspection report.
    ///
    /// # Errors
    ///
    /// Returns a runtime failure for a missing or malformed report.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoopError> {
        let source = std::str::from_utf8(bytes)
            .map_err(|_error| LoopError::runtime("root inspection report is not UTF-8"))?;
        let mut lines = source.lines();
        let head = lines
            .next()
            .ok_or_else(|| LoopError::runtime("root inspection report omitted summary"))?;
        let parts = head.split(' ').collect::<Vec<_>>();
        let ["inspection", status, creates, corrects] = parts.as_slice() else {
            return Err(LoopError::runtime(
                "root inspection report has invalid summary",
            ));
        };
        let status = status
            .parse::<u8>()
            .ok()
            .filter(|status| matches!(status, 0 | 3 | 4))
            .ok_or_else(|| LoopError::runtime("root inspection report has invalid status"))?;
        let would_create = creates.parse::<usize>().map_err(|_error| {
            LoopError::runtime("root inspection report has invalid create count")
        })?;
        let would_correct = corrects.parse::<usize>().map_err(|_error| {
            LoopError::runtime("root inspection report has invalid correct count")
        })?;
        let rows_json = lines
            .next()
            .filter(|line| line.starts_with('[') && line.ends_with(']'))
            .ok_or_else(|| LoopError::runtime("root inspection report omitted rows"))?
            .to_owned();
        if lines.next().is_some() {
            return Err(LoopError::runtime("root inspection report has extra lines"));
        }
        let action_count = |action: &str| {
            let marker = format!("\"action\":\"{action}\"");
            rows_json.matches(marker.as_str()).count()
        };
        let refused = action_count("refuse") + action_count("unseen") > 0;
        let decided_status = if refused {
            4
        } else if would_create > 0 || would_correct > 0 {
            3
        } else {
            0
        };
        if would_create != action_count("create")
            || would_correct != action_count("correct")
            || status != decided_status
        {
            return Err(LoopError::runtime(
                "root inspection summary differs from rows",
            ));
        }
        Ok(Self {
            status,
            would_create,
            would_correct,
            rows_json,
        })
    }

    /// Render the report when entering for an inner probe would require preparation.
    #[must_use]
    pub fn skipped_json(
        &self,
        reason: &str,
        account_uid: Option<u32>,
        registry_drift: Option<&[String]>,
    ) -> String {
        let mut output = String::from("{\"account_uid\":");
        if let Some(uid) = account_uid {
            let _written = write!(&mut output, "{uid}");
        } else {
            output.push_str("null");
        }
        output.push_str(",\"env\":null,\"home\":null,\"mounts_left\":null,\"probe\":{\"made\":false,\"reason\":");
        push_json_string(&mut output, reason);
        output.push_str("},\"registry_drift\":");
        if let Some(drift) = registry_drift {
            output.push('[');
            for (index, difference) in drift.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                push_json_string(&mut output, difference);
            }
            output.push(']');
        } else {
            output.push_str("null");
        }
        output.push_str(",\"roots\":");
        output.push_str(&self.rows_json);
        let _written = write!(
            &mut output,
            ",\"runs_root\":null,\"tmp_left\":null,\"uid\":null,\"user\":null,\"would_correct\":{},\"would_create\":{}}}",
            self.would_correct, self.would_create
        );
        output
    }
}

/// Complete repeatable verification observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyRecord {
    /// UID recorded by the owner-run account registry, when present.
    pub account_uid: Option<u32>,
    /// Passwd-derived user name inside the entry.
    pub user: String,
    /// Effective UID inside the entry.
    pub uid: u32,
    /// Supplementary and primary groups measured by the identity probe.
    pub groups: Vec<u32>,
    /// Clean-environment home inside the entry.
    pub home: String,
    /// Sorted environment map inside the entry.
    pub env: BTreeMap<String, String>,
    /// Count of bind mounts remaining in the rootless namespace.
    pub mounts_left: u32,
    /// Env-file fields that differ from the selected registry row, or no file.
    pub registry_drift: Option<Vec<String>>,
    /// Inspected owner and path of the optional durable runs root.
    pub runs_root: Option<RunsRootReport>,
    /// Count of matching temporary directories after entry.
    pub tmp_left: u32,
    /// Read-only state and would-do decisions for all standard roots.
    pub roots: RootAudit,
}

/// The declared durable runs root and its owner identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunsRootReport {
    /// Path as supplied by the registry, without normalization.
    pub path: PathBuf,
    /// Owner UID observed at the root.
    pub uid: u32,
    /// Owner GID observed at the root.
    pub gid: u32,
    /// Checked permission mode at the root.
    pub mode: u32,
}

/// Check every component of a declared runs root and report its owner.
///
/// # Errors
///
/// Returns a status-one failure naming the loop and `runs_root` when a component
/// is absent, linked or not a directory, or the final directory is not owner-owned.
pub fn inspect_runs_root(
    record: &LoopRecord,
    runs_root: Option<&Path>,
) -> Result<Option<RunsRootReport>, LoopError> {
    let owner = (
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
    );
    inspect_runs_root_for_owner(record, runs_root, owner)
}

pub(crate) fn inspect_runs_root_for_owner(
    record: &LoopRecord,
    runs_root: Option<&Path>,
    owner: (u32, u32),
) -> Result<Option<RunsRootReport>, LoopError> {
    let Some(path) = runs_root else {
        return Ok(None);
    };
    let pinned = pin_runs_root(path, owner, true).map_err(|failure| {
        LoopError::runtime(format!(
            "runs_root for loop {} {}: {}",
            record.name,
            failure.reason,
            failure.path.display()
        ))
    })?;
    Ok(Some(RunsRootReport {
        path: path.to_path_buf(),
        uid: pinned.uid,
        gid: pinned.gid,
        mode: pinned.mode,
    }))
}

fn read_optional(path: &Path) -> Result<Option<String>, LoopError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LoopError::runtime(format!(
                "could not read {}: {error}",
                path.display()
            )));
        }
    };
    let mut source = String::new();
    file.read_to_string(&mut source).map_err(|error| {
        LoopError::runtime(format!("could not read {}: {error}", path.display()))
    })?;
    Ok(Some(source))
}

/// Read the account UID as the owner before entry composition changes identity.
///
/// # Errors
///
/// Returns a runtime failure naming a present unreadable or malformed file.
pub fn account_uid(record: &LoopRecord, caller_home: &Path) -> Result<Option<u32>, LoopError> {
    let path = caller_home
        .join(".claude/superloop/accounts")
        .join(&record.name)
        .join("uid");
    let Some(source) = read_optional(&path)? else {
        return Ok(None);
    };
    let value = source.trim();
    let parsed = value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|uid| (1000..=65_535).contains(uid));
    parsed
        .map(Some)
        .ok_or_else(|| LoopError::runtime(format!("malformed account uid: {}", path.display())))
}

fn env_fields(source: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, raw)) = line.split_once('=') {
            let raw = raw.trim();
            let value = if (raw.starts_with('"') && raw.ends_with('"'))
                || (raw.starts_with('\'') && raw.ends_with('\''))
            {
                raw.get(1..raw.len() - 1).unwrap_or("")
            } else {
                raw.split_once(" #").map_or(raw, |(value, _)| value)
            };
            fields.insert(key.trim().to_owned(), value.to_owned());
        }
    }
    fields
}

/// Compare the legacy env file's mapped fields with the selected registry row.
///
/// # Errors
///
/// Returns a runtime failure naming a present unreadable file.
pub fn registry_drift(
    record: &LoopRecord,
    caller_home: &Path,
) -> Result<Option<Vec<String>>, LoopError> {
    let path = caller_home
        .join(".local/share/superloop-tools/loops.d")
        .join(format!("{}.env", record.name));
    let Some(source) = read_optional(&path)? else {
        return Ok(None);
    };
    let fields = env_fields(&source);
    let uid = record.uid.to_string();
    let expected = [
        ("LOOP_NAME", Some(record.name.as_str())),
        ("LOOP_UID", Some(uid.as_str())),
        ("LOOP_CWD", record.launch.to_str()),
        ("LOOP_SID", record.session.as_deref()),
    ];
    let drift = expected
        .into_iter()
        .filter_map(|(key, row)| {
            let env = fields.get(key).map(String::as_str);
            (env != row).then(|| {
                format!(
                    "{key}: env={} row={}",
                    env.unwrap_or("absent"),
                    row.unwrap_or("absent")
                )
            })
        })
        .collect();
    Ok(Some(drift))
}

fn prefixed(podman: &[String], arguments: impl IntoIterator<Item = String>) -> Vec<String> {
    podman.iter().cloned().chain(arguments).collect()
}

pub(crate) fn inspect_roots_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    podman: &[String],
) -> CommandSpec {
    CommandSpec::new(
        "verify-roots",
        prefixed(
            podman,
            [
                String::from("unshare"),
                executable.to_string_lossy().into_owned(),
                String::from("inspect-roots"),
                record.uid.to_string(),
                record.name.clone(),
                caller_home.to_string_lossy().into_owned(),
                report_path.to_string_lossy().into_owned(),
            ],
        ),
        IoMode::Capture,
    )
}

/// Plan the fixed probe as exactly one ordinary loop entry.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_probe_plan(
    record: &LoopRecord,
    executable: &Path,
    caller_home: &Path,
    report_path: &Path,
    custody: Option<&Custody>,
    podman: &[String],
    term: &str,
    lang: &str,
) -> EntryPlan {
    let script = verification_script();
    verify_entry_plan(
        record,
        executable,
        caller_home,
        report_path,
        custody,
        podman,
        &[String::from("/bin/sh"), String::from("-c"), script],
        term,
        lang,
    )
}

pub(crate) fn verification_script() -> String {
    String::from(VERIFY_SCRIPT)
}

/// Plan the post-entry leak counters in podman's rootless namespace.
#[must_use]
pub fn cleanup_probe_plan(record: &LoopRecord, podman: &[String]) -> CommandSpec {
    let script = format!(
        "set -e; h={}; if [ -d \"$h/private\" ]; then h=\"$h/private\"; fi; mounts_left=0; for target in /etc/passwd /etc/group /etc/ssh/ssh_config.d \"$h/.config/custody\" \"$h/.ssh\"; do lines=$(/usr/bin/findmnt -n \"$target\" 2>/dev/null | /usr/bin/wc -l); mounts_left=$((mounts_left + lines)); done; printf 'mounts_left=%s\\n' \"$mounts_left\"; tmp_left=$(/usr/bin/find /tmp -maxdepth 1 -type d -name 'superloop.*' -printf '.\\n' | /usr/bin/wc -l); printf 'tmp_left=%s\\n' \"$tmp_left\"",
        shell_word(&record.home.to_string_lossy()),
    );
    CommandSpec::new(
        "verify-cleanup",
        prefixed(
            podman,
            [
                String::from("unshare"),
                String::from("/bin/sh"),
                String::from("-c"),
                script,
            ],
        ),
        IoMode::Capture,
    )
}

fn parse_number(field: &str, value: Option<&str>) -> Result<u32, LoopError> {
    value
        .ok_or_else(|| LoopError::runtime(format!("verify probe omitted {field}")))?
        .parse::<u32>()
        .map_err(|_error| LoopError::runtime(format!("verify probe returned invalid {field}")))
}

fn parse_lines(source: &[u8]) -> Result<Vec<(&str, &str)>, LoopError> {
    let text = std::str::from_utf8(source)
        .map_err(|_error| LoopError::runtime("verify probe returned non-UTF-8 output"))?;
    text.lines()
        .map(|line| {
            line.split_once('=')
                .ok_or_else(|| LoopError::runtime("verify probe returned a malformed line"))
        })
        .collect()
}

fn parse_probe_lines(source: &[u8]) -> Result<Vec<(&str, &str)>, LoopError> {
    if !source.ends_with(&[0]) {
        return Err(LoopError::runtime("verify probe omitted its final frame"));
    }
    let text = std::str::from_utf8(source)
        .map_err(|_error| LoopError::runtime("verify probe returned non-UTF-8 output"))?;
    text.trim_end_matches('\0')
        .split('\0')
        .map(|frame| {
            frame
                .split_once('=')
                .ok_or_else(|| LoopError::runtime("verify probe returned a malformed frame"))
        })
        .collect()
}

/// Assemble probe streams into the documented verification object.
///
/// # Errors
///
/// Returns a status-one failure when either scripted response is incomplete or malformed.
pub fn assemble_verify(
    entry: &[u8],
    cleanup: &[u8],
    report: &[u8],
    account_uid: Option<u32>,
    registry_drift: Option<Vec<String>>,
) -> Result<VerifyRecord, LoopError> {
    let roots = RootAudit::parse(report)?;
    let entry_lines = parse_probe_lines(entry)?;
    let cleanup_lines = parse_lines(cleanup)?;
    let field = |name: &str| {
        entry_lines
            .iter()
            .find_map(|(key, value)| (*key == name).then_some(*value))
    };
    let user = field("user")
        .ok_or_else(|| LoopError::runtime("verify probe omitted user"))?
        .to_owned();
    let uid = parse_number("uid", field("uid"))?;
    let groups =
        field("groups").ok_or_else(|| LoopError::runtime("verify probe omitted groups"))?;
    if groups.trim().is_empty() {
        return Err(LoopError::runtime("verify probe has empty groups"));
    }
    let groups = groups
        .split_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| LoopError::runtime("verify probe has invalid groups"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let home = field("home")
        .ok_or_else(|| LoopError::runtime("verify probe omitted home"))?
        .to_owned();
    let env = entry_lines
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("env")
                .filter(|suffix| suffix.is_empty())
                .map(|_| *value)
        })
        .filter_map(|assignment| assignment.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let cleanup_field = |name: &str| {
        cleanup_lines
            .iter()
            .find_map(|(key, value)| (*key == name).then_some(*value))
    };
    Ok(VerifyRecord {
        account_uid,
        user,
        uid,
        groups,
        home,
        env,
        mounts_left: parse_number("mounts_left", cleanup_field("mounts_left"))?,
        registry_drift,
        runs_root: None,
        tmp_left: parse_number("tmp_left", cleanup_field("tmp_left"))?,
        roots,
    })
}

pub(crate) fn push_json_string(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push('"');
    for current in value.chars() {
        match current {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            current if current <= '\u{1f}' => {
                let code = usize::try_from(u32::from(current)).unwrap_or(0);
                output.push_str("\\u00");
                output.push(char::from(HEX[code >> 4]));
                output.push(char::from(HEX[code & 0x0f]));
            }
            _ => output.push(current),
        }
    }
    output.push('"');
}

impl VerifyRecord {
    /// Render the compact, deterministically ordered stdout JSON object.
    #[must_use]
    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;

        let mut output = String::from("{\"account_uid\":");
        match self.account_uid {
            Some(uid) => {
                let _write = write!(&mut output, "{uid}");
            }
            None => output.push_str("null"),
        }
        output.push_str(",\"env\":{");
        for (index, (key, value)) in self.env.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            push_json_string(&mut output, key);
            output.push(':');
            push_json_string(&mut output, value);
        }
        output.push_str("},\"groups\":[");
        for (index, gid) in self.groups.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            let _written = write!(&mut output, "{gid}");
        }
        output.push_str("],\"home\":");
        push_json_string(&mut output, &self.home);
        let _write = write!(
            &mut output,
            ",\"mounts_left\":{},\"probe\":{{\"made\":true}},\"registry_drift\":",
            self.mounts_left
        );
        if let Some(drift) = &self.registry_drift {
            output.push('[');
            for (index, difference) in drift.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                push_json_string(&mut output, difference);
            }
            output.push(']');
        } else {
            output.push_str("null");
        }
        output.push_str(",\"roots\":");
        output.push_str(&self.roots.rows_json);
        if let Some(root) = &self.runs_root {
            output.push_str(",\"runs_root\":{\"gid\":");
            let _write = write!(
                &mut output,
                "{},\"mode\":\"{:04o}\",\"path\":",
                root.gid, root.mode
            );
            push_json_string(&mut output, &root.path.to_string_lossy());
            let _write = write!(&mut output, ",\"uid\":{}}}", root.uid);
        }
        let _write = write!(
            &mut output,
            ",\"tmp_left\":{},\"uid\":{},\"user\":",
            self.tmp_left, self.uid
        );
        push_json_string(&mut output, &self.user);
        let _write = write!(
            &mut output,
            ",\"would_correct\":{},\"would_create\":{}",
            self.roots.would_correct, self.roots.would_create
        );
        output.push('}');
        output
    }
}
