use crate::{Paths, codec, files};
use serde::{
    Deserialize,
    de::{DeserializeOwned, MapAccess, Visitor},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &[u8] = b"_https://claude.ai\0\x01";

fn key(name: &str) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    key
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    let (&kind, bytes) = bytes
        .split_first()
        .ok_or_else(|| io::Error::other("empty storage value"))?;
    let text = match kind {
        1 => bytes.iter().map(|byte| char::from(*byte)).collect(),
        0 if bytes.len().is_multiple_of(2) => String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(io::Error::other)?,
        _ => return Err(io::Error::other("invalid storage encoding")),
    };
    serde_json::from_str(&text).map_err(io::Error::other)
}

// Value's object map sorts keys. Read scope order separately so equal-weight
// scopes keep their input order without changing serde_json's workspace features.
#[derive(Deserialize)]
struct OrderedStore {
    state: OrderedState,
}

#[derive(Deserialize)]
struct OrderedState {
    #[serde(default, rename = "customGroupsByScope")]
    groups: Option<OrderedScopes>,
}

#[derive(Default)]
struct OrderedScopes(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for OrderedScopes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScopesVisitor;
        impl<'de> Visitor<'de> for ScopesVisitor {
            type Value = OrderedScopes;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an ordered scope object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut scopes = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    scopes.push(entry);
                }
                Ok(OrderedScopes(scopes))
            }
        }
        deserializer.deserialize_map(ScopesVisitor)
    }
}

fn encode(value: &Value) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0];
    for unit in serde_json::to_string(value)
        .map_err(io::Error::other)?
        .encode_utf16()
    {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(bytes)
}

fn latest(root: &Path) -> io::Result<(codec::Values, u64, PathBuf, Vec<u8>)> {
    let mut values = codec::Values::new();
    let mut logs = BTreeMap::new();
    for path in files::list(root)? {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("ldb") => {
                for (key, (seq, value)) in codec::table(&files::read(&path)?)? {
                    if values.get(&key).is_none_or(|(old, _)| *old < seq) {
                        values.insert(key, (seq, value));
                    }
                }
            }
            Some("log") => {
                let number = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.parse::<u64>().ok())
                    .ok_or_else(|| io::Error::other("invalid WAL name"))?;
                logs.insert(number, path);
            }
            _ => {}
        }
    }
    let (_, log) = logs.pop_last().ok_or_else(|| io::Error::other("no WAL"))?;
    let bytes = files::read(&log)?;
    let (entries, mut maximum) = codec::log(&bytes)?;
    for (key, (seq, value)) in entries {
        if values.get(&key).is_none_or(|(old, _)| *old < seq) {
            values.insert(key, (seq, value));
        }
    }
    for (seq, _) in values.values() {
        maximum = maximum.max(*seq);
    }
    Ok((values, maximum, log, bytes))
}

fn object(value: &Value) -> io::Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| io::Error::other("expected object"))
}

fn union(scopes: &[(String, Value)], sessions: &BTreeSet<String>) -> io::Result<(Value, usize)> {
    let mut groups = Vec::new();
    let mut seen = BTreeSet::new();
    let mut assignments = Map::new();
    let mut order: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut scopes: Vec<_> = scopes.iter().collect();
    scopes.sort_by_key(|(_, value)| {
        std::cmp::Reverse(
            value
                .get("assignments")
                .and_then(Value::as_object)
                .map_or(0, Map::len),
        )
    });
    for (_, value) in scopes {
        if let Some(items) = value.get("groups") {
            for group in items
                .as_array()
                .ok_or_else(|| io::Error::other("expected groups array"))?
            {
                let id = group
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| io::Error::other("missing group id"))?;
                if seen.insert(id.to_owned()) {
                    groups.push(group.clone());
                }
            }
        }
        if let Some(items) = value.get("assignments") {
            for (key, group) in object(items)? {
                assignments
                    .entry(key.clone())
                    .or_insert_with(|| group.clone());
            }
        }
        if let Some(items) = value.get("order") {
            for (key, list) in object(items)? {
                let target = order.entry(key.clone()).or_default();
                for item in list
                    .as_array()
                    .ok_or_else(|| io::Error::other("expected order array"))?
                {
                    if !target.contains(item) {
                        target.push(item.clone());
                    }
                }
            }
        }
    }
    let initial = assignments.len();
    assignments.retain(|session, group| {
        sessions.contains(
            session
                .split_once(':')
                .map_or(session.as_str(), |(_, session)| session),
        ) && group.as_str().is_some_and(|group| seen.contains(group))
    });
    order.retain(|group, _| seen.contains(group));
    for list in order.values_mut() {
        list.retain(|item| {
            item.as_str()
                .is_some_and(|session| assignments.contains_key(session))
        });
    }
    let dropped = initial - assignments.len();
    Ok((
        json!({"groups": groups, "assignments": assignments, "order": order}),
        dropped,
    ))
}

fn scopes(paths: &Paths) -> io::Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut scopes = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    for org in files::stores(&paths.sessions)? {
        let relative = org
            .strip_prefix(&paths.sessions)
            .map_err(io::Error::other)?;
        scopes.insert(
            relative
                .to_str()
                .ok_or_else(|| io::Error::other("scope encoding"))?
                .to_owned(),
        );
        for path in files::sessions(&org)? {
            sessions.insert(
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .ok_or_else(|| io::Error::other("session encoding"))?
                    .to_owned(),
            );
        }
    }
    Ok((scopes, sessions))
}

struct Plan {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    scopes: usize,
    groups: usize,
    assignments: usize,
    dropped: usize,
}

fn plan(paths: &Paths, values: &codec::Values, migrate: bool) -> io::Result<Plan> {
    let store_key = key("dframe-store");
    let mirror_key = key("LSS-persisted.dframe-group-scopes");
    let raw = values
        .get(&store_key)
        .and_then(|(_, value)| value.as_ref())
        .ok_or_else(|| io::Error::other("dframe-store not found"))?;
    let mut store: Value = decode(raw)?;
    let current_order = decode::<OrderedStore>(raw)?
        .state
        .groups
        .unwrap_or_default();
    let state = store
        .get_mut("state")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| io::Error::other("missing store state"))?;
    let current = state
        .get("customGroupsByScope")
        .filter(|value| !value.is_null())
        .map(object)
        .transpose()?
        .cloned()
        .unwrap_or_default();
    let (mut scopes, sessions) = scopes(paths)?;
    let (merged, dropped) = union(&current_order.0, &sessions)?;
    scopes.extend(current.keys().cloned());
    let groups = merged["groups"].as_array().map_or(0, Vec::len);
    let assignments = merged["assignments"].as_object().map_or(0, Map::len);
    let next: Map<_, _> = scopes
        .iter()
        .map(|scope| (scope.clone(), merged.clone()))
        .collect();
    let changed =
        current != next || (migrate && state.get("pendingLegacyGroupMigration") != Some(&merged));
    let mut entries = Vec::new();
    if groups > 0 && changed {
        state.insert(
            "customGroupsByScope".to_owned(),
            Value::Object(next.clone()),
        );
        if migrate {
            state.insert("pendingLegacyGroupMigration".to_owned(), merged);
        }
        entries.push((store_key, encode(&store)?));
        if let Some(raw) = values
            .get(&mirror_key)
            .and_then(|(_, value)| value.as_ref())
        {
            let mut mirror: Value = decode(raw)?;
            let fields = mirror
                .as_object_mut()
                .ok_or_else(|| io::Error::other("mirror must be an object"))?;
            fields.insert("value".to_owned(), Value::Object(next));
            let now = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_millis(),
            )
            .map_err(io::Error::other)?;
            fields.insert("timestamp".to_owned(), Value::from(now));
            entries.push((mirror_key, encode(&mirror)?));
        }
    }
    Ok(Plan {
        entries,
        scopes: scopes.len(),
        groups,
        assignments,
        dropped,
    })
}

pub fn run(paths: &Paths, dry: bool, migrate: bool, out: &mut impl io::Write) -> io::Result<u8> {
    if files::app_running(&paths.lock)? {
        writeln!(out, "CCD_GROUPS_APP_RUNNING")?;
        return Ok(2);
    }
    let (values, maximum, log, before) = latest(&paths.leveldb)?;
    let plan = plan(paths, &values, migrate)?;
    writeln!(
        out,
        "scopes={} groups={} assignments={} dropped={} changed={}",
        plan.scopes,
        plan.groups,
        plan.assignments,
        plan.dropped,
        plan.entries.len()
    )?;
    if dry || plan.entries.is_empty() {
        writeln!(
            out,
            "CCD_GROUPS_{}",
            if dry { "DRY_RUN" } else { "IN_SYNC" }
        )?;
        return Ok(0);
    }
    let storage = paths
        .leveldb
        .parent()
        .ok_or_else(|| io::Error::other("storage parent"))?;
    files::backup(storage, "local-storage-backup")?;
    if files::app_running(&paths.lock)? || files::read(&log)? != before {
        return Err(io::Error::other(
            "application state changed before publication",
        ));
    }
    let sequence = maximum
        .checked_add(1)
        .ok_or_else(|| io::Error::other("sequence overflow"))?;
    let bytes = codec::append(sequence, &plan.entries, before.len())?;
    let mut output = OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    let (after, end) = codec::log(&files::read(&log)?)?;
    let expected = maximum
        .checked_add(u64::try_from(plan.entries.len()).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::other("sequence overflow"))?;
    if end != expected
        || plan.entries.iter().any(|(key, value)| {
            after.get(key).and_then(|(_, stored)| stored.as_ref()) != Some(value)
        })
    {
        return Err(io::Error::other("WAL verification failed; retain backup"));
    }
    writeln!(
        out,
        "CCD_GROUPS_{} scopes={} groups={} assignments={}",
        if migrate {
            "MIGRATION_STAGED"
        } else {
            "SYNCED"
        },
        plan.scopes,
        plan.groups,
        plan.assignments
    )?;
    Ok(0)
}
