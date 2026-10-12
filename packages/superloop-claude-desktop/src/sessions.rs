use crate::{Paths, files};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, FileTimes};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct Copy {
    path: PathBuf,
    data: Value,
    bytes: Vec<u8>,
    modified: SystemTime,
}

impl Copy {
    fn rank(&self) -> (i64, SystemTime) {
        (timestamp(&self.data), self.modified)
    }
}

fn timestamp(data: &Value) -> i64 {
    data.get("lastActivityAt")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}
fn identity(data: &Value) -> &str {
    data.get("cliSessionId")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn union(stores: &[PathBuf]) -> io::Result<(BTreeMap<String, Copy>, usize)> {
    let mut copies: BTreeMap<String, Vec<Copy>> = BTreeMap::new();
    for store in stores {
        for path in files::sessions(store)? {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| io::Error::other("session filename encoding"))?
                .to_owned();
            let bytes = files::read(&path)?;
            let modified = fs::metadata(&path)?.modified()?;
            let data: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if !data.is_object() {
                return Err(io::Error::other("session must be an object"));
            }
            copies.entry(name).or_default().push(Copy {
                path,
                data,
                bytes,
                modified,
            });
        }
    }
    let mut winners = BTreeMap::new();
    let mut forks = 0;
    for (name, copies) in copies {
        let superseded: BTreeSet<_> = copies
            .iter()
            .flat_map(|copy| {
                copy.data
                    .get("priorCliSessionIds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
            })
            .collect();
        let heads: Vec<_> = copies
            .iter()
            .filter(|copy| !superseded.contains(identity(&copy.data)))
            .collect();
        let candidates = if heads.is_empty() {
            copies.iter().collect()
        } else {
            heads
        };
        let winner = candidates
            .into_iter()
            .reduce(|first, next| {
                if next.rank() > first.rank() {
                    next
                } else {
                    first
                }
            })
            .ok_or_else(|| io::Error::other("empty session copies"))?;
        forks += copies
            .iter()
            .filter(|copy| {
                superseded.contains(identity(&copy.data))
                    && timestamp(&copy.data) > timestamp(&winner.data)
            })
            .count();
        winners.insert(name, winner.clone());
    }
    Ok((winners, forks))
}

fn live(paths: &Paths) -> io::Result<BTreeSet<String>> {
    let mut sessions = BTreeSet::new();
    for path in files::list(&paths.registry)? {
        if path.extension().is_none_or(|extension| extension != "json") || !path.is_file() {
            continue;
        }
        let Ok(data) = files::json(&path) else {
            continue;
        };
        if data.get("entrypoint").and_then(Value::as_str) != Some("claude-desktop") {
            continue;
        }
        let Some(pid) = data.get("pid").and_then(Value::as_u64) else {
            continue;
        };
        let Some(session) = data
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let stat = paths.proc_root.join(pid.to_string()).join("stat");
        let Ok(bytes) = files::read(&stat) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let Some((_, fields)) = text.rsplit_once(')') else {
            continue;
        };
        let expected = data
            .get("procStart")
            .filter(|value| !value.is_null() && value.as_u64() != Some(0));
        let matches = expected.is_none_or(|expected| {
            fields.split_whitespace().nth(19).is_some_and(|actual| {
                expected.as_str().map_or_else(
                    || {
                        expected
                            .as_u64()
                            .is_some_and(|expected| actual.parse::<u64>() == Ok(expected))
                    },
                    |expected| expected == actual,
                )
            })
        });
        if matches {
            sessions.insert(session.to_owned());
        }
    }
    Ok(sessions)
}

struct Change {
    source: PathBuf,
    expected: Vec<u8>,
    destination: PathBuf,
    previous: Option<Vec<u8>>,
    description: String,
}

fn describe(current: Option<&Value>, winner: &Copy) -> String {
    let Some(current) = current else {
        return format!("new {}", timestamp(&winner.data));
    };
    let archived = |data: &Value| {
        data.get("isArchived")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let mut details = Vec::new();
    if archived(current) != archived(&winner.data) {
        details.push(
            if archived(&winner.data) {
                "archived"
            } else {
                "unarchived"
            }
            .to_owned(),
        );
    }
    if identity(current) != identity(&winner.data) {
        details.push(format!(
            "transcript {} -> {}",
            identity(current),
            identity(&winner.data)
        ));
    }
    if timestamp(current) != timestamp(&winner.data) {
        details.push(format!("was {}", timestamp(current)));
    } else if details.is_empty() {
        let modified = match winner.modified.duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos().to_string(),
            Err(error) => format!("-{}", error.duration().as_nanos()),
        };
        details.push(format!(
            "metadata rewritten {modified} ns since 1970-01-01T00:00:00Z"
        ));
    }
    details.join(", ")
}

fn changes(
    stores: &[PathBuf],
    winners: &BTreeMap<String, Copy>,
    live: &BTreeSet<String>,
    check: bool,
) -> io::Result<(Vec<Change>, usize)> {
    let mut changes = Vec::new();
    let mut held = 0;
    for store in stores {
        for (name, winner) in winners {
            let destination = store.join(name);
            if destination == winner.path {
                continue;
            }
            let previous = if destination.exists() {
                Some(files::read(&destination)?)
            } else {
                None
            };
            let current = previous
                .as_deref()
                .map(serde_json::from_slice::<Value>)
                .transpose()
                .map_err(io::Error::other)?;
            if previous.as_ref() == Some(&winner.bytes) {
                continue;
            }
            if let Some(current) = &current
                && winner.rank() <= (timestamp(current), fs::metadata(&destination)?.modified()?)
                && identity(&winner.data) == identity(current)
            {
                continue;
            }
            if !check
                && (live.contains(identity(&winner.data))
                    || current
                        .as_ref()
                        .is_some_and(|current| live.contains(identity(current))))
            {
                held += 1;
                continue;
            }
            changes.push(Change {
                source: winner.path.clone(),
                expected: winner.bytes.clone(),
                destination,
                previous,
                description: describe(current.as_ref(), winner),
            });
        }
    }
    Ok((changes, held))
}

fn transcript_exists(paths: &Paths, id: &str) -> io::Result<bool> {
    if id.is_empty() || id.contains(['/', '\0']) {
        return Ok(false);
    }
    for project in files::list(&paths.projects)? {
        if project.is_dir() && project.join(format!("{id}.jsonl")).is_file() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn apply(change: &Change) -> io::Result<()> {
    let source = files::read(&change.source)?;
    if source != change.expected {
        return Err(io::Error::other(
            "source session changed before publication",
        ));
    }
    let metadata = fs::metadata(&change.source)?;
    let now = if change.destination.exists() {
        Some(files::read(&change.destination)?)
    } else {
        None
    };
    if now != change.previous {
        return Err(io::Error::other("session changed before publication"));
    }
    let parent = change
        .destination
        .parent()
        .ok_or_else(|| io::Error::other("session parent"))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(&source)?;
    staged.as_file().set_permissions(metadata.permissions())?;
    staged.as_file().set_times(
        FileTimes::new()
            .set_accessed(metadata.accessed()?)
            .set_modified(metadata.modified()?),
    )?;
    staged.as_file().sync_all()?;
    staged
        .persist(&change.destination)
        .map_err(|error| error.error)?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Apply,
    DryRun,
    Check,
}

pub fn run(
    paths: &Paths,
    mode: Mode,
    allow_live: bool,
    prefer_successor: bool,
    out: &mut impl io::Write,
) -> io::Result<u8> {
    let stores = files::stores(&paths.sessions)?;
    if stores.len() < 2 {
        writeln!(
            out,
            "CCD_SESSIONS_IN_SYNC stores={} pending=0",
            stores.len()
        )?;
        return Ok(0);
    }
    let (winners, forks) = union(&stores)?;
    let live = live(paths)?;
    let running = files::app_running(&paths.lock)?;
    let (changes, held) = changes(&stores, &winners, &live, mode == Mode::Check)?;
    let mut orphans = 0;
    for winner in winners.values() {
        if !identity(&winner.data).is_empty() && !transcript_exists(paths, identity(&winner.data))?
        {
            orphans += 1;
        }
    }
    writeln!(
        out,
        "stores={} union={} changed={} held={held} forks={forks} orphans={orphans} app_running={running} live={}",
        stores.len(),
        winners.len(),
        changes.len(),
        live.len()
    )?;
    if mode == Mode::Check {
        let pending = changes.len() + held + forks;
        writeln!(
            out,
            "CCD_SESSIONS_{} stores={} union={} pending={pending}",
            if pending == 0 { "IN_SYNC" } else { "DIVERGED" },
            stores.len(),
            winners.len()
        )?;
        return Ok(u8::from(pending != 0));
    }
    if forks > 0 && !prefer_successor {
        writeln!(out, "CCD_SESSIONS_FORK forks={forks}")?;
        return Ok(4);
    }
    for change in &changes {
        writeln!(
            out,
            "{}: {}",
            change.destination.display(),
            change.description
        )?;
    }
    if mode == Mode::DryRun {
        writeln!(out, "CCD_SESSIONS_DRY_RUN")?;
        return Ok(0);
    }
    if running && !allow_live {
        writeln!(out, "CCD_SESSIONS_APP_RUNNING")?;
        return Ok(2);
    }
    if changes.is_empty() {
        writeln!(
            out,
            "CCD_SESSIONS_{} pending={held}",
            if held == 0 { "IN_SYNC" } else { "DIVERGED" }
        )?;
        return Ok(if held == 0 { 0 } else { 3 });
    }
    files::backup(&paths.sessions, "claude-code-sessions-backup")?;
    if !allow_live && files::app_running(&paths.lock)? {
        return Err(io::Error::other("application started before publication"));
    }
    for change in &changes {
        apply(change)?;
    }
    writeln!(
        out,
        "CCD_SESSIONS_MERGED stores={} union={} written={} held={held}",
        stores.len(),
        winners.len(),
        changes.len()
    )?;
    Ok(if held == 0 { 0 } else { 3 })
}
