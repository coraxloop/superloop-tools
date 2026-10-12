//! Prepare the owner's registered Claude home without opening its credential.

use super::{Result, claude_fs::Directory};
use crate::routes::{self, Row};
use nix::fcntl::{RenameFlags, renameat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct Options {
    pub owner: PathBuf,
    pub name: String,
    pub home: PathBuf,
    pub dry_run: bool,
    pub digest: Option<String>,
    pub reconcile: bool,
    pub nodes: Option<Vec<String>>,
    pub move_from: Option<PathBuf>,
}

fn options(args: &[String], check: bool) -> Result<Options> {
    if check {
        return Err("claude-home-arguments: use prepare-signin-home --dry-run".into());
    }
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut name = None;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--reconcile" | "--dry-run" => {
                if !flags.insert(word.as_str()) {
                    return Err("claude-home-arguments: duplicate flag".into());
                }
            }
            "--backend" | "--nodes" | "--expect-digest" | "--move-from" => {
                let value = words.next().ok_or("claude-home-arguments: missing value")?;
                if values.insert(word.as_str(), value.clone()).is_some() {
                    return Err("claude-home-arguments: duplicate option".into());
                }
            }
            _ if !word.starts_with('-') && name.is_none() => name = Some(word.clone()),
            _ => return Err("claude-home-arguments: unexpected argument".into()),
        }
    }
    if values.get("--backend").map(String::as_str) != Some("claude") {
        return Err("claude-home-arguments: backend".into());
    }
    let name = name.ok_or("claude-home-arguments: loop required")?;
    loop_home::validate_name(&name).map_err(|error| error.message().to_owned())?;
    let dry_run = flags.contains("--dry-run");
    let digest = values.remove("--expect-digest");
    if dry_run == digest.is_some()
        || digest.as_ref().is_some_and(|value| {
            value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(
            "claude-home-arguments: exactly one of --dry-run or --expect-digest HEX required"
                .into(),
        );
    }
    let nodes = values
        .remove("--nodes")
        .map(|value| value.split(',').map(str::to_owned).collect::<Vec<_>>());
    if nodes.as_ref().is_some_and(|nodes| {
        nodes.iter().any(|node| !super::name_valid(node))
            || nodes.iter().collect::<BTreeSet<_>>().len() != nodes.len()
    }) {
        return Err("registry-node: expected distinct node names".into());
    }
    let owner = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("claude-home-arguments: absolute HOME required")?;
    let move_from = values.remove("--move-from").map(PathBuf::from);
    if move_from.is_some() && (nodes.is_some() || flags.contains("--reconcile")) {
        return Err("claude-home-arguments: move excludes reconcile and nodes".into());
    }
    Ok(Options {
        home: super::claude_home(&owner, &name),
        owner,
        name,
        dry_run,
        digest,
        reconcile: flags.contains("--reconcile"),
        nodes,
        move_from,
    })
}

pub(super) fn digest(bytes: &[u8]) -> String {
    let mut result = String::new();
    for byte in Sha256::digest(bytes) {
        let _written = write!(result, "{byte:02x}");
    }
    result
}

fn selected(options: &Options) -> Result<(Vec<Row>, Vec<Row>)> {
    let source = fs::read_to_string(
        options
            .owner
            .join(".local/share/orchestration-instance/servers.md"),
    )
    .map_err(|_| "registry-read: inspection failed")?;
    let active = routes::registry(&source, &options.name)?;
    let retired = routes::registry_rows(&source, &options.name, true)?
        .into_iter()
        .filter(|row| row["status"] == "retired")
        .collect();
    if let Some(nodes) = &options.nodes {
        for node in nodes {
            if !active.iter().any(|row| row["node"] == *node) {
                return Err(format!("registry-node: {node}: no active row"));
            }
        }
    }
    Ok((active, retired))
}

pub(super) fn rewrite_block(block: &[String], desired: &str) -> Result<String> {
    let desired_lines = desired
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    let mut options = BTreeMap::new();
    for line in desired_lines.iter().skip(1) {
        let words = super::reconcile::words(line)?;
        options.insert(words[0].to_ascii_lowercase(), *line);
    }
    let mut result = block[0].clone();
    let mut seen = BTreeSet::new();
    for line in &block[1..] {
        let words = super::reconcile::words(line)?;
        let key = words
            .first()
            .map(|word| word.to_ascii_lowercase())
            .unwrap_or_default();
        if let Some(desired) = options.get(&key) {
            if words.len() != 2 || !seen.insert(key) {
                return Err("claude-home-ssh: duplicate or malformed option".into());
            }
            writeln!(result, "{desired}").map_err(|error| error.to_string())?;
        } else {
            result.push_str(line);
        }
    }
    for (key, line) in options {
        if !seen.contains(&key) {
            if !result.ends_with('\n') {
                result.push('\n');
            }
            writeln!(result, "{line}").map_err(|error| error.to_string())?;
        }
    }
    Ok(result)
}

fn ssh(before: Option<&[u8]>, rendered: &str, active: &[Row], retired: &[Row]) -> Result<String> {
    let Some(before) = before else {
        return Ok(rendered.to_owned());
    };
    let before = std::str::from_utf8(before).map_err(|_| "claude-home-ssh: not UTF-8")?;
    let blocks = super::reconcile::blocks(before)?;
    let desired = super::reconcile::blocks(rendered)?;
    let mut result = blocks[0].concat();
    let mut seen = BTreeSet::new();
    for block in blocks.iter().skip(1) {
        let names = super::reconcile::words(&block[0])?;
        let selected = active.iter().chain(retired).find(|row| {
            names
                .iter()
                .skip(1)
                .any(|name| name == &row["worker_alias"])
        });
        let Some(row) = selected else {
            result.push_str(&block.concat());
            continue;
        };
        if names.len() != 2 || names[1] != row["worker_alias"] || !seen.insert(row["node"].clone())
        {
            return Err(format!("claude-home-ssh: ambiguous {} stanza", row["node"]));
        }
        if row["status"] == "retired" {
            continue;
        }
        let index = active
            .iter()
            .position(|candidate| candidate["node"] == row["node"])
            .ok_or("claude-home-ssh: selection")?;
        result.push_str(&rewrite_block(block, &desired[index + 1].concat())?);
    }
    for (index, row) in active.iter().enumerate() {
        if !seen.contains(&row["node"]) {
            if !result.is_empty() && !result.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(&desired[index + 1].concat());
        }
    }
    Ok(result)
}

fn findings(
    home: Option<&Directory>,
    settings: Option<&[u8]>,
    expected: &str,
    rows: &[Row],
) -> Result<Value> {
    let mut findings = Vec::new();
    let current = settings
        .map(serde_json::from_slice::<Value>)
        .transpose()
        .map_err(|_| "claude-home-settings: invalid JSON")?;
    let expected: Value = serde_json::from_str(expected).map_err(|error| error.to_string())?;
    if current.is_none() {
        findings.push(json!({"name":"owner-settings-absent"}));
    }
    for (index, row) in rows.iter().enumerate() {
        for pointer in ["/permissions/allow", "/sandbox/excludedCommands"] {
            let rule = &expected
                .pointer(pointer)
                .ok_or("claude-home-settings: rendered field")?[index];
            if !current
                .as_ref()
                .and_then(|value| value.pointer(pointer))
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(rule))
            {
                findings.push(
                    json!({"name":"owner-settings-drift","node":row["node"],"field":pointer}),
                );
            }
        }
    }
    let metadata = |name| {
        home.map(|home| home.metadata(name))
            .transpose()
            .map(Option::flatten)
    };
    let sign_in = metadata(".credentials.json")?;
    let keys = metadata("keys")?;
    if keys
        .as_ref()
        .is_some_and(|value| value["kind"].as_u64() != Some(u64::from(libc::S_IFLNK)))
    {
        findings.push(json!({"name":"keys-not-a-link"}));
    }
    Ok(
        json!({"sign_in":if sign_in.is_some() {"present"} else {"absent"},"credential_metadata":sign_in,"charter_present":metadata("CLAUDE.md")?.is_some(),"keys":keys,"findings":findings,"created_settings_fragment_only":true}),
    )
}

fn create(
    options: &Options,
    files: &BTreeMap<&str, Vec<u8>>,
    parent: Option<&Directory>,
) -> Result<()> {
    let parent_path = options
        .home
        .parent()
        .ok_or("claude-home-path: missing parent")?;
    let created_parent;
    let parent = if let Some(parent) = parent {
        parent
    } else {
        created_parent = Directory::open(&options.owner, parent_path, true)?;
        &created_parent
    };
    let stage = format!(".claude.new.{}", std::process::id());
    mkdirat(&*parent.file, stage.as_str(), Mode::S_IRWXU).map_err(|error| error.to_string())?;
    let staged = parent.child(&stage)?;
    let mut published = false;
    let result = (|| {
        for (name, bytes) in files {
            staged.replace(name, bytes)?;
        }
        renameat2(
            &*parent.file,
            stage.as_str(),
            &*parent.file,
            "claude",
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(|error| format!("claude-home-publication: {error}"))?;
        published = true;
        parent.file.sync_all().map_err(|error| error.to_string())
    })();
    if result.is_err() && !published {
        for name in files.keys() {
            let _removed = unlinkat(&*staged.file, *name, UnlinkatFlags::NoRemoveDir);
        }
        let _removed = unlinkat(&*parent.file, stage.as_str(), UnlinkatFlags::RemoveDir);
    }
    result
}

fn existing_parent(options: &Options) -> Result<Option<Directory>> {
    let path = options
        .home
        .parent()
        .ok_or("claude-home-path: missing parent")?;
    match fs::symlink_metadata(path) {
        Ok(_) => Directory::open(&options.owner, path, false).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn file_previews(
    home: &Path,
    files: &BTreeMap<&str, Vec<u8>>,
    before: &BTreeMap<&str, Option<Vec<u8>>>,
) -> Result<Vec<Value>> {
    files
        .iter()
        .filter(|(name, bytes)| before[*name].as_ref() != Some(*bytes))
        .map(|(name, bytes)| {
            let old = before[name]
                .as_deref()
                .map(std::str::from_utf8)
                .transpose()
                .map_err(|error| error.to_string())?;
            let after = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
            Ok(json!({
                "path":home.join(name), "mode":0o600,
                "before":old, "after":after,
                "action":if old.is_none() { "write" } else { "replace" }
            }))
        })
        .collect()
}

pub(super) fn run(args: &[String], check: bool) -> Result<String> {
    let options = options(args, check)?;
    if let Some(source) = &options.move_from {
        return super::claude_move::run(&options, source);
    }
    let old = options.owner.join(format!(".claude-{}", options.name));
    if fs::symlink_metadata(&old).is_ok() {
        return Err("claude-home-previous-layout: move the previous home first".into());
    }
    let exists = match fs::symlink_metadata(&options.home) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    if options.reconcile && !exists {
        return Err("claude-home-absent".into());
    }
    let parent = existing_parent(&options)?;
    let home = exists
        .then(|| Directory::open(&options.owner, &options.home, false))
        .transpose()?;
    if let Some(home) = &home {
        home.check_home()?;
    }
    let (mut rows, retired) = selected(&options)?;
    let all_routes = routes::render(&rows, &options.owner, &options.name);
    let known_hosts = all_routes["claude.known_hosts"].as_bytes().to_vec();
    if let Some(nodes) = &options.nodes {
        rows.retain(|row| nodes.contains(&row["node"]));
    }
    let rendered = routes::render(&rows, &options.owner, &options.name);
    let read = |name| {
        home.as_ref()
            .map(|home| home.read(name))
            .transpose()
            .map(Option::flatten)
    };
    let before_ssh = read("ssh_config")?;
    let before_known = read("known_hosts.routes")?;
    let settings = read("settings.json")?;
    let mut files = BTreeMap::from([
        (
            "ssh_config",
            ssh(
                before_ssh.as_deref(),
                &rendered["claude.ssh_config"],
                &rows,
                &retired,
            )?
            .into_bytes(),
        ),
        ("known_hosts.routes", known_hosts),
    ]);
    let mut before = BTreeMap::from([
        ("ssh_config", before_ssh),
        ("known_hosts.routes", before_known),
    ]);
    if !exists {
        files.insert(
            "settings.json",
            rendered["claude.owner-settings.json"].as_bytes().to_vec(),
        );
        before.insert("settings.json", None);
    }
    let changes = files.iter().filter(|(name, bytes)| before[*name].as_ref() != Some(*bytes)).map(|(name, bytes)| json!({"path":name,"before":before[name].as_ref().map(|bytes| digest(bytes)),"after":digest(bytes)})).collect::<Vec<_>>();
    let mut plan = json!({"loop":options.name,"home":options.home,"identity":home.as_ref().map(Directory::identity).transpose()?,"create":!exists,"files":changes,"settings_digest":settings.as_ref().map(|bytes| digest(bytes))});
    // Keep issued previews valid by hashing the original digest-only representation.
    let preview_digest = digest(plan.to_string().as_bytes());
    plan["file_digests"] = json!(changes);
    plan["files"] = json!(file_previews(&options.home, &files, &before)?);
    let report = findings(
        home.as_ref(),
        settings.as_deref(),
        &rendered["claude.owner-settings.json"],
        &rows,
    )?;
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
        if let Some(home) = &home {
            for (name, bytes) in &before {
                if home.read(name)? != *bytes {
                    return Err(format!("claude-home-input-changed: {name}"));
                }
            }
            for (name, bytes) in &files {
                if before[name].as_ref() != Some(bytes) {
                    home.replace(name, bytes)?;
                }
            }
        } else {
            create(&options, &files, parent.as_ref())?;
        }
    }
    Ok(json!({"plan":plan,"digest":preview_digest,"changed":changes.len() + usize::from(!exists),"report":report,"outcome":if options.dry_run {"preview"} else {"applied"}}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics only if the worker alias selection or ambiguity contract fails.
    /// ´test:unit:claude-ssh-selects-only-exact-worker-alias´
    #[test]
    fn claude_ssh_selects_only_exact_worker_alias() {
        let rows = vec![Row::from([
            ("node".into(), "node-a".into()),
            ("worker_alias".into(), "node-a-worker".into()),
            ("status".into(), "active".into()),
        ])];
        let desired = "Host node-a-worker\n  HostName new.example\n";
        let unrelated = "Host node-a-loop-b\n\tHostName session.example # retained\n\nHost node-a-other\n  User owner";
        let before = format!("Host node-a-worker\n  HostName old.example\n{unrelated}");
        assert_eq!(
            ssh(Some(before.as_bytes()), desired, &rows, &[]).expect("reconciled"),
            format!("{desired}{unrelated}")
        );
        for ambiguous in [
            "Host node-a-loop-b node-a-worker\n  HostName old.example\n",
            "Host node-a-worker\nHost node-a-worker\n",
        ] {
            assert_eq!(
                ssh(Some(ambiguous.as_bytes()), desired, &rows, &[]).expect_err("ambiguous"),
                "claude-home-ssh: ambiguous node-a stanza"
            );
        }
    }
}
