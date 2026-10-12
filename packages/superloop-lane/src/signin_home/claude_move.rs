//! Journal-before-rename migration of a complete owner-side home.

use super::{
    Result,
    claude::{Options, digest},
    claude_fs::Directory,
    claude_rewrite, claude_scan,
};
use nix::fcntl::{RenameFlags, renameat2};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const FILES: [&str; 3] = ["ssh_config", "settings.json", ".claude.json"];

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn read_record(home: &Directory, options: &Options, source: &Path) -> Result<Option<Value>> {
    let Some(bytes) = home.read("move-record.json")? else {
        return Ok(None);
    };
    let record: Value =
        serde_json::from_slice(&bytes).map_err(|_| "claude-home-move-record: invalid JSON")?;
    let identity = home.identity()?;
    if record["schema"] != 1
        || record["source"] != json!(source)
        || record["destination"] != json!(options.home)
        || record["device"] != identity["device"]
        || record["inode"] != identity["inode"]
        || !matches!(record["state"].as_str(), Some("pending" | "complete"))
        || home
            .metadata("move-record.json")?
            .is_none_or(|meta| meta["mode"] != 0o600)
        || record["preview_digest"].as_str().is_none_or(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        || record["files"].as_object().is_none_or(|files| {
            files.len() != FILES.len() || FILES.iter().any(|name| !files.contains_key(*name))
        })
    {
        return Err("claude-home-move-record: identity, shape or mode mismatch".into());
    }
    for name in FILES {
        for field in ["before", "after"] {
            let value = &record["files"][name][field];
            if !value.is_null()
                && value.as_str().is_none_or(|value| {
                    value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(format!("claude-home-move-record: {name}: digest"));
            }
        }
    }
    Ok(Some(record))
}

struct Rewrites {
    before: BTreeMap<&'static str, Option<Vec<u8>>>,
    after: BTreeMap<&'static str, Vec<u8>>,
    files: Value,
    changes: Vec<Value>,
}

fn rewrites(
    home: &Directory,
    record: Option<&Value>,
    paths: &[String],
    destination: &str,
) -> Result<Rewrites> {
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    let mut files = serde_json::Map::new();
    let mut changes = Vec::new();
    for name in FILES {
        let bytes = home.read(name)?;
        let current = bytes.as_ref().map(|bytes| digest(bytes));
        if let Some(record) = record {
            let expected = &record["files"][name];
            if json!(current) != expected["before"] && json!(current) != expected["after"] {
                return Err(format!("claude-home-move-file-changed: {name}"));
            }
            if record["state"] == "complete" && json!(current) != expected["after"] {
                return Err(format!("claude-home-move-file-changed: {name}"));
            }
        }
        let (rewritten, fields) = bytes
            .as_ref()
            .map(|bytes| claude_rewrite::rewrite(name, bytes, paths, destination))
            .transpose()?
            .unwrap_or_default();
        let next = bytes.as_ref().map(|_| digest(&rewritten));
        if let Some(record) = record {
            if json!(next) != record["files"][name]["after"] {
                return Err(format!("claude-home-move-file-changed: {name}"));
            }
            files.insert(name.into(), record["files"][name].clone());
        } else {
            files.insert(name.into(), json!({"before":current,"after":next}));
        }
        if current != next {
            changes.push(json!({"file":name,"before":current,"after":next,"changes":fields}));
            after.insert(name, rewritten);
        }
        before.insert(name, bytes);
    }
    Ok(Rewrites {
        before,
        after,
        files: Value::Object(files),
        changes,
    })
}

fn fault(stage: &str) -> Result<()> {
    if cfg!(debug_assertions)
        && std::env::var("SUPERLOOP_CLAUDE_MOVE_TEST_STOP")
            .ok()
            .as_deref()
            == Some(stage)
    {
        return Err(format!("claude-home-move-interrupted: {stage}"));
    }
    Ok(())
}

fn scan(options: &Options, paths: &[String]) -> Result<usize> {
    let mut paths = paths.to_vec();
    paths.extend(claude_rewrite::spellings(
        &options.owner,
        &options.name,
        "destination",
    ));
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("SUPERLOOP_CLAUDE_MOVE_TEST_PROC") {
        return claude_scan::scan(Path::new(&root), &paths);
    }
    claude_scan::scan(Path::new("/proc"), &paths)
}

fn rename(
    options: &Options,
    source: &Path,
    home: &Directory,
    parent: Option<&Directory>,
) -> Result<()> {
    let source_parent = Directory::open(&options.owner, &options.owner, false)?;
    let created_parent;
    let destination_parent = if let Some(parent) = parent {
        parent
    } else {
        created_parent = Directory::open(
            &options.owner,
            options.home.parent().ok_or("claude-home-move-parent")?,
            true,
        )?;
        &created_parent
    };
    let source_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("claude-home-move-source")?;
    let named = source_parent
        .metadata(source_name)?
        .ok_or("claude-home-move-source-changed")?;
    let identity = home.identity()?;
    if named["device"] != identity["device"] || named["inode"] != identity["inode"] {
        return Err("claude-home-move-source-changed".into());
    }
    renameat2(
        &*source_parent.file,
        source_name,
        &*destination_parent.file,
        "claude",
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| match error {
        nix::errno::Errno::EXDEV => "claude-home-cross-device".to_owned(),
        nix::errno::Errno::EEXIST => "claude-home-destination-occupied".to_owned(),
        _ => format!("claude-home-move-rename: {error}"),
    })?;
    source_parent
        .file
        .sync_all()
        .and_then(|()| destination_parent.file.sync_all())
        .map_err(|error| error.to_string())
}

pub(super) fn run(options: &Options, source: &Path) -> Result<String> {
    if source != options.owner.join(format!(".claude-{}", options.name)) || options.name == "pure" {
        return Err("claude-home-move-source".into());
    }
    let paths = claude_rewrite::spellings(&options.owner, &options.name, "previous");
    let mut environ_unreadable = scan(options, &paths)?;
    let source_exists = exists(source)?;
    let destination_exists = exists(&options.home)?;
    if source_exists && destination_exists {
        return Err("claude-home-destination-occupied".into());
    }
    if !source_exists && !destination_exists {
        return Err("claude-home-move-source-absent".into());
    }
    let parent_path = options.home.parent().ok_or("claude-home-move-parent")?;
    let parent = if exists(parent_path)? {
        Some(Directory::open(&options.owner, parent_path, false)?)
    } else {
        None
    };
    let home = Directory::open(
        &options.owner,
        if source_exists { source } else { &options.home },
        false,
    )?;
    home.check_home()?;
    let credential_metadata = home.metadata(".credentials.json")?;
    let saved = read_record(&home, options, source)?;
    if !source_exists && saved.is_none() {
        return Err("claude-home-destination-occupied".into());
    }
    if source_exists
        && saved
            .as_ref()
            .is_some_and(|record| record["state"] == "complete")
    {
        return Err("claude-home-move-record: complete source".into());
    }
    let destination = options
        .home
        .to_str()
        .ok_or("claude-home-move-path: not UTF-8")?;
    let rewrite = rewrites(&home, saved.as_ref(), &paths, destination)?;
    let identity = home.identity()?;
    let complete = saved
        .as_ref()
        .is_some_and(|record| record["state"] == "complete");
    let plan = json!({"source":source,"destination":options.home,"identity":identity,"rename":source_exists,"files":rewrite.changes,"record":saved,"complete":complete});
    let preview_digest = digest(plan.to_string().as_bytes());
    let changed = rewrite.after.len() + usize::from(source_exists) + usize::from(!complete);
    if !options.dry_run {
        if options
            .digest
            .as_ref()
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
            != Some(&preview_digest)
        {
            return Err("claude-home-digest: repeat --dry-run".into());
        }
        environ_unreadable = scan(options, &paths)?;
        for (name, before) in &rewrite.before {
            if home.read(name)? != *before {
                return Err(format!("claude-home-move-file-changed: {name}"));
            }
        }
        if !complete {
            let mut record = saved.unwrap_or_else(|| json!({"schema":1,"state":"pending","source":source,"device":identity["device"],"inode":identity["inode"],"destination":options.home,"preview_digest":preview_digest,"files":rewrite.files}));
            home.replace("move-record.json", record.to_string().as_bytes())?;
            fault("record")?;
            if source_exists {
                rename(options, source, &home, parent.as_ref())?;
            }
            fault("rename")?;
            for (name, bytes) in &rewrite.after {
                let current = home
                    .read(name)?
                    .ok_or_else(|| format!("claude-home-move-file-changed: {name}"))?;
                if json!(digest(&current)) != record["files"][name]["before"] {
                    return Err(format!("claude-home-move-file-changed: {name}"));
                }
                home.replace(name, bytes)?;
                fault(name)?;
            }
            rewrites(&home, Some(&record), &paths, destination)?;
            record["state"] = json!("complete");
            home.replace("move-record.json", record.to_string().as_bytes())?;
        }
    }
    Ok(json!({"plan":plan,"digest":preview_digest,"changed":changed,"environ_unreadable":environ_unreadable,"sign_in":if credential_metadata.is_some() {"present"} else {"absent"},"credential_metadata":credential_metadata,"old_home_spellings_remaining":0,"outcome":if options.dry_run {"preview"} else {"applied"}}).to_string())
}
