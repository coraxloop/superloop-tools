//! Digest-bound repair of an existing Codex home; key material is never read.

use super::{Node, Result, Settings, claude::digest, claude_fs::Directory};
use nix::fcntl::{OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, symlinkat, unlinkat};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

fn open(owner: &Path, path: &Path, create: bool) -> Result<Directory> {
    Directory::open(owner, path, create)
        .map_err(|error| error.replace("claude-home-", "codex-home-"))
}

pub(super) fn existing_key(home: &Path, owner: &Path, nodes: &[Node]) -> Result<PathBuf> {
    let directory = open(owner, home, false)?;
    let source = read(&directory, "ssh_config")?.unwrap_or_default();
    let generated = source.lines().any(|line| {
        line.starts_with("# copied from the loop's Claude lane home (")
            || line.starts_with("# selected from the instance routes registry (")
    });
    let blocks = super::reconcile::blocks(&source)?;
    let mut keys = BTreeSet::new();
    for node in nodes {
        let alias = format!("{}-worker", node.name);
        for block in &blocks {
            let Some(line) = block.first() else { continue };
            let names = super::reconcile::words(line)?;
            if names.len() != 2 || !names[0].eq_ignore_ascii_case("host") || names[1] != alias {
                continue;
            }
            for line in &block[1..] {
                let words = super::reconcile::words(line)?;
                if words.len() == 2 && words[0].eq_ignore_ascii_case("identityfile") {
                    let identity = words[1]
                        .strip_prefix("~/")
                        .map_or_else(|| PathBuf::from(&words[1]), |relative| owner.join(relative));
                    let registered = home.parent().ok_or("key home parent")?.join("lanes/keys");
                    // The owner may have already moved and relinked the key into custody.
                    // Inspect that entry before resolving it; external links must refuse.
                    check_key_entry(&identity, &registered)?;
                    let key = super::canonical_key(&words[1], owner);
                    if !identity.starts_with(home)
                        || (!key.starts_with(home) && !key.starts_with(registered) && !generated)
                    {
                        return Err(super::refused("key"));
                    }
                    keys.insert(key);
                }
            }
        }
    }
    if keys.len() != 1 {
        return Err(super::refused("key"));
    }
    keys.into_iter().next().ok_or_else(|| super::refused("key"))
}

fn read(home: &Directory, name: &str) -> Result<Option<String>> {
    let fd = match openat2(
        &*home.file,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(format!("codex-repair-file: {name}: {error}")),
    };
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != super::owner_uid()
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4_194_304
    {
        return Err(format!(
            "codex-repair-file: {name}: owner, type, links, mode or size"
        ));
    }
    let mut result = String::new();
    file.take(4_194_305)
        .read_to_string(&mut result)
        .map_err(|error| error.to_string())?;
    if result.len() > 4_194_304 {
        return Err(format!("codex-repair-file: {name}: size"));
    }
    Ok(Some(result))
}

// Append missing generated lines to their table, leaving every owner byte intact.
// TOML tables cannot be reopened, so additions to an existing table precede the next table.
fn config(current: &str, settings: &Settings) -> Result<(String, Value)> {
    let parsed: toml::Value =
        toml::from_str(current).map_err(|error| format!("config-toml: {error}"))?;
    if parsed.get("sandbox_mode").and_then(toml::Value::as_str) == Some("workspace-write") {
        return Err(
            "config-sandbox-default: owner must resolve sandbox_mode = \"workspace-write\"".into(),
        );
    }
    let expected = super::config(settings);
    let mut result = current.to_owned();
    let mut skipped_comment_lines = Vec::new();
    let roots = parsed
        .get("sandbox_workspace_write")
        .and_then(|table| table.get("writable_roots"));
    for section in expected.trim_end().split("\n\n") {
        let mut lines = section.lines();
        let title = lines.next().ok_or("config-section")?;
        let desired = lines
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        let mut offset = 0;
        let mut start = None;
        let mut end = result.len();
        for line in result.split_inclusive('\n') {
            let trimmed = line.trim();
            if trimmed == title {
                start = Some(offset + line.len());
            } else if start.is_some() && trimmed.starts_with('[') {
                end = offset;
                break;
            }
            offset += line.len();
        }
        let Some(start) = start else {
            if !result.is_empty() && !result.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(title);
            result.push('\n');
            for line in desired {
                if line.trim_start().starts_with('#') {
                    skipped_comment_lines.push(line);
                } else {
                    result.push_str(line);
                    result.push('\n');
                }
            }
            continue;
        };
        let body = &result[start..end];
        let mut addition = String::new();
        for line in desired {
            if line.trim_start().starts_with('#') {
                if !body.lines().any(|old| old == line) {
                    skipped_comment_lines.push(line);
                }
                continue;
            }
            if title == "[sandbox_workspace_write]"
                && line
                    .split_once('=')
                    .is_some_and(|(key, _)| key.trim() == "writable_roots")
                && roots.is_some()
            {
                continue;
            }
            if body.lines().any(|old| old == line) {
                continue;
            }
            if let Some((key, _)) = line.split_once('=')
                && body.lines().any(|old| {
                    old.split_once('=')
                        .is_some_and(|(name, _)| name.trim() == key.trim())
                })
            {
                return Err(format!("config-owner-conflict: {} {}", title, key.trim()));
            }
            addition.push_str(line);
            addition.push('\n');
        }
        if !addition.is_empty() && !result[..end].ends_with('\n') {
            addition.insert(0, '\n');
        }
        result.insert_str(end, &addition);
    }
    let _validated: toml::Value =
        toml::from_str(&result).map_err(|error| format!("config-owner-conflict: {error}"))?;
    Ok((
        result,
        json!({
            "writable_roots": {"owner_line_kept": roots.is_some(),
                "roots": roots.and_then(toml::Value::as_array).map(Vec::len)},
            "skipped_comment_lines": skipped_comment_lines,
        }),
    ))
}

fn ssh(current: &str, settings: &Settings) -> Result<String> {
    let key = super::home_key(settings)?;
    let mut values = vec![
        settings.account.as_str(),
        key.to_str().ok_or("key path encoding")?,
    ];
    for node in &settings.nodes {
        values.extend([node.name.as_str(), node.host.as_str(), node.port.as_str()]);
    }
    if values.iter().any(|value| {
        value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '#'))
    }) {
        return Err("repair requires plain SSH option values".into());
    }
    super::reconcile::rewrite(current, &[], settings, true)
}

struct FilePlan {
    name: &'static str,
    before: Option<String>,
    after: String,
    metadata: Option<Value>,
    config_details: Value,
}

impl FilePlan {
    fn changed(&self) -> bool {
        self.before.as_deref() != Some(self.after.as_str())
    }
    fn report(&self, home: &Path) -> Value {
        let mut report = json!({"path":home.join(self.name),"before":self.before,"after":self.after,
            "before_sha256":self.before.as_ref().map(|s|digest(s.as_bytes())),
            "after_sha256":digest(self.after.as_bytes()),"metadata":self.metadata});
        if let (Some(report), Some(details)) =
            (report.as_object_mut(), self.config_details.as_object())
        {
            report.extend(details.clone());
        }
        report
    }

    fn apply(&self, home: &Directory) -> Result<()> {
        if !self.changed() {
            return Ok(());
        }
        let staged = format!(".repair-{}-{}", self.name, std::process::id());
        let fd = openat2(
            &*home.file,
            staged.as_str(),
            OpenHow::new()
                .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|error| error.to_string())?;
        let result = (|| {
            let mut file = File::from(fd);
            let mode = self
                .metadata
                .as_ref()
                .and_then(|m| m["mode"].as_u64())
                .and_then(|mode| u32::try_from(mode).ok())
                .unwrap_or(0o600);
            file.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|error| error.to_string())?;
            file.write_all(self.after.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| error.to_string())?;
            renameat(&*home.file, staged.as_str(), &*home.file, self.name)
                .map_err(|error| error.to_string())
        })();
        let _removed = unlinkat(&*home.file, staged.as_str(), UnlinkatFlags::NoRemoveDir);
        result
    }
}

pub(super) struct LinkPlan {
    path: PathBuf,
    target: PathBuf,
    before: Option<PathBuf>,
    metadata: Option<Value>,
}

fn metadata(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(
            json!({"device":m.dev(),"inode":m.ino(),"mode":m.mode(),"owner":m.uid(),"links":m.nlink(),"size":m.len(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec()}),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

impl LinkPlan {
    pub(super) fn new(
        path: PathBuf,
        target: PathBuf,
        moving: bool,
        replace_link: bool,
    ) -> Result<Self> {
        let metadata = metadata(&path)?;
        let before = fs::read_link(&path).ok();
        if metadata.is_some()
            && !moving
            && before.as_ref() != Some(&target)
            && !(replace_link && before.is_some())
        {
            return Err(format!("codex-repair-link-conflict: {}", path.display()));
        }
        Ok(Self {
            path,
            target,
            before,
            metadata,
        })
    }
    pub(super) fn changed(&self) -> bool {
        self.before.as_ref() != Some(&self.target)
    }
    pub(super) fn report(&self) -> Value {
        json!({"path":self.path,"target":self.target,"before":self.before,"metadata":self.metadata,
            "before_sha256":self.before.as_ref().map(|p|digest(p.as_os_str().as_encoded_bytes())),
            "after_sha256":digest(self.target.as_os_str().as_encoded_bytes()),"digest_kind":"link-target"})
    }
    pub(super) fn check(&self) -> Result<()> {
        if metadata(&self.path)? != self.metadata || fs::read_link(&self.path).ok() != self.before {
            return Err("charter link changed; repeat --dry-run".into());
        }
        Ok(())
    }

    pub(super) fn publish(&self, directory: &std::fs::File) -> Result<()> {
        self.check()?;
        if !self.changed() {
            return Ok(());
        }
        let name = self.path.file_name().ok_or("link filename")?;
        let stage = format!(".ssh_config.charter-{}", std::process::id());
        symlinkat(&self.target, directory, stage.as_str()).map_err(|error| error.to_string())?;
        let result =
            renameat(directory, stage.as_str(), directory, name).map_err(|error| error.to_string());
        let _removed = unlinkat(directory, stage.as_str(), UnlinkatFlags::NoRemoveDir);
        result?;
        directory.sync_all().map_err(|error| error.to_string())
    }
    fn apply(&self, owner: &Path) -> Result<()> {
        if !self.changed() {
            return Ok(());
        }
        let parent = open(owner, self.path.parent().ok_or("link parent")?, true)?;
        let name = self.path.file_name().ok_or("link filename")?;
        let stage = format!(".repair-link-{}", std::process::id());
        symlinkat(&self.target, &*parent.file, stage.as_str())
            .map_err(|error| error.to_string())?;
        let result = renameat(&*parent.file, stage.as_str(), &*parent.file, name)
            .map_err(|error| error.to_string());
        let _removed = unlinkat(&*parent.file, stage.as_str(), UnlinkatFlags::NoRemoveDir);
        result?;
        parent.file.sync_all().map_err(|error| error.to_string())
    }
}

fn move_key(source: &Path, settings: &Settings, home: &Directory) -> Result<()> {
    let source_parent = source.parent().ok_or("key parent")?;
    let opened = if source_parent == settings.home {
        None
    } else {
        Some(open(&settings.owner, source_parent, false)?)
    };
    let from = opened.as_ref().unwrap_or(home);
    let destination = &settings.key;
    let to = open(
        &settings.owner,
        destination.parent().ok_or("key destination parent")?,
        true,
    )?;
    renameat2(
        &*from.file,
        source.file_name().ok_or("key filename")?,
        &*to.file,
        destination.file_name().ok_or("key destination filename")?,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|error| format!("codex-repair-key-rename: {error}"))?;
    from.file
        .sync_all()
        .and_then(|()| to.file.sync_all())
        .map_err(|error| error.to_string())
}

pub(super) fn explicit_key(value: &str, owner: &Path, home: &Path) -> Result<PathBuf> {
    let entry = value
        .strip_prefix("~/")
        .map_or_else(|| PathBuf::from(value), |relative| owner.join(relative));
    let registered = home.parent().ok_or("key home parent")?.join("lanes/keys");
    check_key_entry(&entry, &registered)?;
    Ok(super::canonical_key(value, owner))
}

fn check_key_entry(entry: &Path, registered: &Path) -> Result<()> {
    let registered_link = fs::read_link(entry).is_ok_and(|target| {
        let target = if target.is_absolute() {
            target
        } else {
            entry
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
        fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.is_file())
            && fs::canonicalize(&target).is_ok_and(|resolved| resolved.starts_with(registered))
    });
    if registered_link {
        Ok(())
    } else {
        check_key(entry)
    }
}

fn key_entry_error(path: &Path, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        super::refused("key")
    } else {
        format!("codex-repair-key: {}: {error}", path.display())
    }
}

fn check_key(key_source: &Path) -> Result<()> {
    let key_metadata =
        fs::symlink_metadata(key_source).map_err(|error| key_entry_error(key_source, &error))?;
    if key_metadata.file_type().is_symlink() {
        let target =
            fs::read_link(key_source).map_err(|error| key_entry_error(key_source, &error))?;
        return Err(format!(
            "codex-repair-key: {} is a link to {}; move the key file into lanes/keys/ by rename and relink, then repair",
            key_source.display(),
            target.display()
        ));
    }
    if !key_metadata.is_file()
        || key_metadata.nlink() != 1
        || key_metadata.uid() != super::owner_uid()
    {
        return Err(format!(
            "codex-repair-key: expected owner-held regular file with one link; path={}, links={}, owner uid={}",
            key_source.display(),
            key_metadata.nlink(),
            key_metadata.uid()
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(mut settings: Settings) -> Result<String> {
    let home = open(&settings.owner, &settings.home, false)?;
    home.check_home()?;
    let home_identity = metadata(&settings.home)?;
    let key_source = settings.key.clone();
    check_key(&key_source)?;
    let moving = key_source.starts_with(&settings.home);
    if moving {
        settings.key = settings
            .owner
            .join(".config/loops")
            .join(&settings.name)
            .join("lanes/keys")
            .join(key_source.file_name().ok_or("key filename")?);
        if metadata(&settings.key)?.is_some() {
            return Err("codex-repair-key-destination: already exists".into());
        }
    }
    let key_identity = metadata(&key_source)?;
    let mut files = Vec::new();
    // The pin file publishes before the strict configuration that names it.
    for name in ["config.toml", "known_hosts.routes", "ssh_config"] {
        let before = read(&home, name)?;
        let current = before.as_deref().unwrap_or_default();
        let (after, config_details) = if name == "config.toml" {
            config(current, &settings)?
        } else if name == "ssh_config" {
            (
                ssh(current, &settings)?,
                super::reconcile::details(current, &settings)?,
            )
        } else {
            (
                crate::routes::known_hosts(&settings.routes),
                json!({"action":if before.is_none() {"write"} else if current != crate::routes::known_hosts(&settings.routes) {"replace"} else {"unchanged"}}),
            )
        };
        files.push(FilePlan {
            name,
            before,
            after,
            metadata: home.metadata(name)?,
            config_details,
        });
    }
    let key_link = super::home_key(&settings)?;
    let mut links = vec![
        LinkPlan::new(
            key_link.clone(),
            settings.key.clone(),
            moving && key_source == key_link,
            true,
        )?,
        LinkPlan::new(
            settings.home.join("AGENTS.md"),
            settings.charter.clone(),
            false,
            false,
        )?,
        LinkPlan::new(
            settings.home.join("auth.json"),
            super::canonical_auth(&settings),
            false,
            false,
        )?,
    ];
    if moving && key_source != key_link {
        links.push(LinkPlan::new(
            key_source.clone(),
            settings.key.clone(),
            true,
            false,
        )?);
    }
    // Validate parents without making directories or opening any key for reading.
    for link in &links {
        let mut parent = link.path.parent().ok_or("link parent")?;
        while metadata(parent)?.is_none() {
            parent = parent.parent().ok_or("link ancestor")?;
        }
        if parent != settings.home {
            let _parent = open(&settings.owner, parent, false)?;
        }
    }
    if moving {
        let mut parent = settings.key.parent().ok_or("key destination parent")?;
        while metadata(parent)?.is_none() {
            parent = parent.parent().ok_or("key destination ancestor")?;
        }
        let _parent = open(&settings.owner, parent, false)?;
    }
    let plan = json!({"charter":settings.charter,"loop":settings.name,"nodes":settings.nodes.iter().map(|n|&n.name).collect::<Vec<_>>(),
        "home":settings.home,"home_identity":home.identity()?,
        "files":files.iter().map(|f|f.report(&settings.home)).collect::<Vec<_>>(),
        "links":links.iter().map(LinkPlan::report).collect::<Vec<_>>(),
        "key":{"source":key_source,"destination":settings.key,"rename":moving,"identity":key_identity,"content_read":false}});
    let digest = digest(plan.to_string().as_bytes());
    let changed = files.iter().filter(|f| f.changed()).count()
        + links.iter().filter(|l| l.changed()).count()
        + usize::from(moving);
    if settings.dry_run {
        return Ok(
            json!({"charter":settings.charter,"plan":plan,"digest":digest,"changed":changed})
                .to_string(),
        );
    }
    if settings.digest.to_ascii_lowercase() != digest {
        return Err("repair digest mismatch; repeat --dry-run".into());
    }
    if metadata(&settings.home)? != home_identity || metadata(&key_source)? != key_identity {
        return Err("repair input changed; repeat --dry-run".into());
    }
    for file in &files {
        if read(&home, file.name)? != file.before || home.metadata(file.name)? != file.metadata {
            return Err("repair input changed; repeat --dry-run".into());
        }
    }
    for link in &links {
        if metadata(&link.path)? != link.metadata {
            return Err("repair link changed; repeat --dry-run".into());
        }
    }
    if moving {
        move_key(&key_source, &settings, &home)?;
    }
    for link in &links {
        // Links in the home use the already-held descriptor, never a second flock.
        if link.path.parent() == Some(settings.home.as_path()) && link.changed() {
            let stage = format!(".repair-link-{}", std::process::id());
            symlinkat(&link.target, &*home.file, stage.as_str())
                .map_err(|error| error.to_string())?;
            let result = renameat(
                &*home.file,
                stage.as_str(),
                &*home.file,
                link.path.file_name().ok_or("link name")?,
            )
            .map_err(|error| error.to_string());
            let _removed = unlinkat(&*home.file, stage.as_str(), UnlinkatFlags::NoRemoveDir);
            result?;
        } else {
            link.apply(&settings.owner)?;
        }
    }
    for file in &files {
        file.apply(&home)?;
    }
    home.file.sync_all().map_err(|error| error.to_string())?;
    Ok(
        json!({"charter":settings.charter,"outcome":"applied","digest":digest,"changed":changed})
            .to_string(),
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::signin_home) fn fixture(owner: &Path) -> Settings {
        Settings {
            name: "alpha".into(),
            owner: owner.into(),
            charter: owner.join("worker-charter.md"),
            home: owner.join("codex"),
            claude_home: owner.join("claude"),
            project: "/project".into(),
            record: None,
            route_refusal: None,
            account: "worker".into(),
            key: owner.join("worker-key"),
            routes: vec![
                [
                    ("node", "node"),
                    ("hostname", "192.0.2.1"),
                    ("port", "22"),
                    ("account", "worker"),
                    ("worker_alias", "node-worker"),
                    ("host_key_algorithm", "ssh-ed25519"),
                    ("host_key", "AAAA"),
                ]
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            ],
            nodes: vec![Node {
                name: "node".into(),
                alias: "node-worker".into(),
                host: "192.0.2.1".into(),
                port: "22".into(),
            }],
            reconcile: false,
            repair: true,
            dry_run: true,
            digest: String::new(),
            missing: Vec::new(),
            varied: Vec::new(),
            varied_lines: Vec::new(),
            locations: Vec::new(),
        }
    }

    /// # Panics
    /// Panics only if the planner violates preservation or idempotence in this fixture.
    /// ´test:unit:codex-repair-config-preserves-owner-lines´
    #[test]
    fn codex_repair_config_preserves_owner_lines() {
        let settings = fixture(Path::new("/owner"));
        let owner = "model = \"owner-model\"\n# owner comment\n";
        let (added, _) = config(owner, &settings).expect("plan");
        assert!(added.starts_with(owner));
        for line in super::super::config(&settings).lines() {
            if !line.starts_with('#') && !line.is_empty() {
                assert!(added.contains(line));
            }
        }
        assert_eq!(config(&added, &settings).expect("repeat").0, added);
        let partial = "[sandbox_workspace_write]\nnetwork_access = true\n[owner]\nvalue = 42\n";
        let (repaired, _) = config(partial, &settings).expect("partial table");
        assert!(repaired.ends_with("trust_level = \"trusted\"\n"));
        assert!(repaired.contains("[owner]\nvalue = 42\n"));
        assert_eq!(repaired.matches("[sandbox_workspace_write]").count(), 1);
    }

    /// Owner roots, including empty and multiline arrays, retain their bytes and report their count.
    /// # Panics
    /// Panics only if planning fails or an owner root array changes or is miscounted.
    /// ´test:unit:codex-repair-config-counts-owner-roots´
    #[test]
    fn codex_repair_config_counts_owner_roots() {
        let settings = fixture(Path::new("/owner"));
        for (array, count) in [
            ("[]", 0),
            ("[\"/one\"]", 1),
            ("[\"/one\", \"/two\"]", 2),
            ("[\n  \"/one\",\n  \"/two\",\n  \"/three\",\n]", 3),
        ] {
            let owner = format!(
                "[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = {array}\n"
            );
            let (after, details) = config(&owner, &settings).expect("owner roots");
            assert!(after.starts_with(&owner));
            assert_eq!(
                details["writable_roots"],
                json!({"owner_line_kept": true, "roots": count})
            );
            assert_eq!(config(&after, &settings).expect("repeat").0, after);
        }
    }

    /// An existing sandbox table without roots gains the generated empty list.
    /// # Panics
    /// Panics only if a missing roots key is not added to the existing table.
    /// ´test:unit:codex-repair-config-adds-missing-roots´
    #[test]
    fn codex_repair_config_adds_missing_roots() {
        let settings = fixture(Path::new("/owner"));
        let owner = "[sandbox_workspace_write]\nnetwork_access = true\n";
        let (after, details) = config(owner, &settings).expect("missing roots");
        assert!(after.starts_with(&format!("{owner}writable_roots = []\n")));
        assert_eq!(details["writable_roots"]["owner_line_kept"], false);
        assert_eq!(after.matches("[sandbox_workspace_write]").count(), 1);
    }

    /// Template comments absent from the owner table are skipped and reported without adding bytes.
    /// # Panics
    /// Panics only if planning adds a template comment or fails to report it as skipped.
    /// ´test:unit:codex-repair-config-skips-template-comments´
    #[test]
    fn codex_repair_config_skips_template_comments() {
        let settings = fixture(Path::new("/owner"));
        let owner = "[sandbox_workspace_write]\nnetwork_access = true\n# owner's roots\nwritable_roots = [\"/lane/.git\"]\n";
        let (repaired, details) = config(owner, &settings).expect("owner roots");
        assert!(repaired.starts_with(owner));
        assert_eq!(repaired.matches('#').count(), 1);
        assert_eq!(
            details["writable_roots"],
            json!({"owner_line_kept": true, "roots": 1})
        );
        let template = super::super::config(&settings);
        let comment = template
            .lines()
            .find(|line| line.starts_with('#'))
            .expect("template comment");
        assert_eq!(details["skipped_comment_lines"], json!([comment]));
        assert!(!repaired.contains(comment));
        assert_eq!(
            config(&repaired, &settings).expect("repeat roots").0,
            repaired
        );
    }

    /// # Panics
    /// Panics only if owner configuration conflicts are accepted or misnamed.
    /// ´test:unit:codex-repair-config-refuses-owner-conflicts´
    #[test]
    fn codex_repair_config_refuses_owner_conflicts() {
        let settings = fixture(Path::new("/owner"));
        assert!(
            config("sandbox_mode = \"workspace-write\"\n", &settings)
                .unwrap_err()
                .starts_with("config-sandbox-default:")
        );
        assert!(
            config(
                "[sandbox_workspace_write]\nwritable_roots = [\"/lane/.git\"]\nnetwork_access = false\n",
                &settings
            )
            .unwrap_err()
            .starts_with("config-owner-conflict:")
        );
    }

    /// # Panics
    /// Panics only if fixture setup fails or key inference accepts an unregistered legacy target.
    /// ´test:unit:codex-repair-key-inference-is-bounded´
    #[test]
    fn codex_repair_key_inference_is_bounded() {
        let root = tempfile::tempdir().expect("fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner mode");
        let settings = fixture(root.path());
        fs::create_dir(&settings.home).expect("home");
        fs::set_permissions(&settings.home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::write(&settings.key, b"opaque fixture").expect("external key");
        let named = settings.home.join("key");
        std::os::unix::fs::symlink(&settings.key, &named).expect("old key link");
        let stanza = format!("Host node-worker\n  IdentityFile {}\n", named.display());
        let ssh = settings.home.join("ssh_config");
        fs::write(&ssh, &stanza).expect("legacy SSH");
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o600)).expect("SSH mode");
        assert!(existing_key(&settings.home, &settings.owner, &settings.nodes).is_err());
        fs::write(&ssh, format!("{}{stanza}", super::super::header(&settings)))
            .expect("generated SSH");
        assert!(existing_key(&settings.home, &settings.owner, &settings.nodes).is_err());
        fs::remove_file(&named).expect("old link");
        fs::write(&named, b"opaque legacy key").expect("regular legacy key");
        fs::write(&ssh, stanza).expect("legacy SSH");
        assert_eq!(
            existing_key(&settings.home, &settings.owner, &settings.nodes)
                .expect("legacy regular key"),
            named
        );
    }

    /// Production inference names live and dangling link targets without reading a mode-000 key.
    /// # Panics
    /// Panics only if fixture setup fails or production inference loses the entry or read-link target.
    /// ´test:unit:codex-repair-key-inference-names-unreadable-link-targets´
    #[test]
    fn codex_repair_key_inference_names_unreadable_link_targets() {
        let root = tempfile::tempdir().expect("fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner mode");
        let settings = fixture(root.path());
        fs::create_dir(&settings.home).expect("home");
        fs::set_permissions(&settings.home, fs::Permissions::from_mode(0o700)).expect("home mode");
        fs::write(&settings.key, b"unreadable key fixture").expect("key");
        fs::set_permissions(&settings.key, fs::Permissions::from_mode(0o000)).expect("key mode");
        let named = settings.home.join("key");
        std::os::unix::fs::symlink(&settings.key, &named).expect("link");
        let ssh = settings.home.join("ssh_config");
        fs::write(
            &ssh,
            format!(
                "{}Host node-worker\n  IdentityFile {}\n",
                super::super::header(&settings),
                named.display()
            ),
        )
        .expect("SSH");
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o600)).expect("SSH mode");
        for dangling in [false, true] {
            if dangling {
                fs::remove_file(&settings.key).expect("remove target");
            }
            let target = fs::read_link(&named).expect("target");
            assert_eq!(
                existing_key(&settings.home, &settings.owner, &settings.nodes).unwrap_err(),
                format!(
                    "codex-repair-key: {} is a link to {}; move the key file into lanes/keys/ by rename and relink, then repair",
                    named.display(),
                    target.display()
                )
            );
        }
    }

    /// Both routes accept absolute and relative links into registered custody and refuse escapes.
    /// # Panics
    /// Panics only if fixture setup fails or inference refuses a registered regular key target.
    /// ´test:unit:codex-repair-key-inference-accepts-registered-custody´
    #[test]
    fn codex_repair_key_inference_accepts_registered_custody() {
        let root = tempfile::tempdir().expect("fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner mode");
        let settings = fixture(root.path());
        fs::create_dir(&settings.home).expect("home");
        fs::set_permissions(&settings.home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let registered = root.path().join("lanes/keys");
        fs::create_dir_all(&registered).expect("custody");
        let target = registered.join("worker-key");
        fs::write(&target, b"registered fixture").expect("key");
        let named = settings.home.join("key");
        let ssh = settings.home.join("ssh_config");
        fs::write(
            &ssh,
            format!("Host node-worker\n  IdentityFile {}\n", named.display()),
        )
        .expect("pre-tool SSH");
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o600)).expect("SSH mode");
        for link in [target.clone(), PathBuf::from("../lanes/keys/worker-key")] {
            std::os::unix::fs::symlink(link, &named).expect("custody link");
            assert_eq!(
                existing_key(&settings.home, &settings.owner, &settings.nodes)
                    .expect("registered key"),
                target
            );
            assert_eq!(
                explicit_key(
                    named.to_str().expect("path"),
                    &settings.owner,
                    &settings.home
                )
                .expect("explicit registered key"),
                target
            );
            fs::remove_file(&named).expect("unlink");
        }
        fs::write(root.path().join("outside"), b"outside fixture").expect("outside key");
        std::os::unix::fs::symlink("../lanes/keys/../../outside", &named).expect("escape link");
        assert!(existing_key(&settings.home, &settings.owner, &settings.nodes).is_err());
        assert!(
            explicit_key(
                named.to_str().expect("path"),
                &settings.owner,
                &settings.home
            )
            .is_err()
        );
    }

    /// Missing entries keep the base remedy on both routes; other entry errors name their path.
    /// # Panics
    /// Panics only if fixture setup fails or an entry error loses its expected context.
    /// ´test:unit:codex-repair-key-entry-errors-name-remedy´
    #[test]
    fn codex_repair_key_entry_errors_name_remedy() {
        let root = tempfile::tempdir().expect("fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner mode");
        let settings = fixture(root.path());
        fs::create_dir(&settings.home).expect("home");
        fs::set_permissions(&settings.home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let ssh = settings.home.join("ssh_config");
        let missing = settings.home.join("missing");
        let parent_file = settings.home.join("file");
        fs::write(&parent_file, b"not a directory").expect("parent file");
        for entry in [missing.clone(), parent_file.join("key")] {
            fs::write(
                &ssh,
                format!("Host node-worker\n  IdentityFile {}\n", entry.display()),
            )
            .expect("SSH");
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o600)).expect("SSH mode");
            let inferred = existing_key(&settings.home, &settings.owner, &settings.nodes)
                .expect_err("entry refusal");
            let explicit = explicit_key(
                entry.to_str().expect("path"),
                &settings.owner,
                &settings.home,
            )
            .expect_err("explicit refusal");
            assert_eq!(inferred, explicit);
            if entry == missing {
                assert_eq!(inferred, super::super::refused("key"));
            } else {
                assert!(inferred.starts_with(&format!("codex-repair-key: {}:", entry.display())));
            }
        }
    }

    /// # Panics
    /// Panics only if the exact-name SSH repair changes unrelated bytes or loses its fixpoint.
    /// ´test:unit:codex-repair-ssh-exact-name-and-header´
    #[test]
    fn codex_repair_ssh_exact_name_and_header() {
        let root = tempfile::tempdir().expect("registry fixture");
        let mut settings = fixture(root.path());
        let registry = root.path().join(".local/share/orchestration-instance");
        fs::create_dir_all(&registry).expect("registry directory");
        fs::write(registry.join("servers.md"), format!("## Node routes\n|node|status|hostname|port|host_key_algorithm|host_key|loop|account|worker_alias|session_alias|worker_identity|session_identity|\n|---|---|---|---|---|---|---|---|---|---|---|---|\n|node|active|192.0.2.1|22|ssh-ed25519|AAAA|alpha|worker|node-worker|node-session|{}/worker-key|~/.ssh/session-key|\n", root.path().display())).expect("registry");
        settings.routes = super::super::selected_routes(root.path(), "alpha", &["node"], "")
            .expect("registry read");
        let loop_stanza = "Host node-alpha\n\tHostName owner.invalid\n  User owner\n\n";
        let tail = "Host other\n  Port 1234\n";
        let source = format!("{loop_stanza}Host node-worker\n  HostName old.invalid\n{tail}");
        let after = ssh(&source, &settings).expect("SSH repair");
        assert!(after.starts_with(&super::super::header(&settings)));
        assert!(after.contains(loop_stanza));
        assert!(after.ends_with(tail));
        assert!(!after.contains("old.invalid"));
        assert!(after.contains("  HostName 192.0.2.1\n"));
        assert_eq!(ssh(&after, &settings).expect("repeat"), after);
        let partial = format!("# copied from the loop's Claude lane home (node);\n{source}");
        let repaired = ssh(&partial, &settings).expect("partial header");
        assert_eq!(
            repaired
                .matches("# selected from the instance routes registry (")
                .count(),
            1
        );
        assert_eq!(ssh(&repaired, &settings).expect("partial repeat"), repaired);
        let appended = ssh(loop_stanza, &settings).expect("absent worker");
        assert!(appended.contains(&format!("{loop_stanza}Host node-worker\n")));
        assert!(ssh("Host node-worker node-alpha\n", &settings).is_err());
        assert!(ssh("Host node-worker\nHost node-worker\n", &settings).is_err());
        let measured = super::super::reconcile::tests::measured(&settings);
        let repaired = ssh(&measured, &settings).expect("measured repair");
        assert_eq!(
            super::super::reconcile::rewrite(&repaired, &[], &settings, true)
                .expect("reconcile after repair"),
            repaired
        );
        assert!(!repaired.contains("gone-"));
        assert!(repaired.contains("# owner registry note\n"));
        assert!(repaired.contains("StrictHostKeyChecking yes\n"));
        let details = super::super::reconcile::details(&measured, &settings).expect("plan details");
        assert_eq!(
            details["removed_stanzas"],
            json!(["gone-one-worker", "gone-two-worker", "gone-three-worker"])
        );
        assert_eq!(details["retained_foreign_stanzas"], json!(["personal"]));
        let (partial, owner) = super::super::reconcile::tests::partial(&settings);
        let repaired = ssh(&partial, &settings).expect("partial header repair");
        assert!(repaired.starts_with(&(super::super::header(&settings) + &owner + "Host ")));
        assert_eq!(
            crate::routes::known_hosts(&settings.routes),
            "[192.0.2.1]:22 ssh-ed25519 AAAA\n192.0.2.1 ssh-ed25519 AAAA\n"
        );
    }

    /// # Panics
    /// Panics only if fixture setup or the digest-bound rename/link repair fails.
    /// ´test:unit:codex-repair-moves-key-and-places-links´
    #[test]
    fn codex_repair_moves_key_and_places_links() {
        let root = tempfile::tempdir().expect("fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("owner mode");
        let mut settings = fixture(root.path());
        fs::create_dir(&settings.home).expect("home");
        fs::set_permissions(&settings.home, fs::Permissions::from_mode(0o700)).expect("mode");
        let config_path = settings.home.join("config.toml");
        fs::write(&config_path, "model = \"owner-model\"\n").expect("owner config");
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640)).expect("config mode");
        fs::create_dir(settings.home.join("keys")).expect("keys");
        fs::set_permissions(
            settings.home.join("keys"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("keys mode");
        settings.key = settings.home.join("keys/worker-key");
        fs::write(&settings.key, b"fixture opaque key").expect("key");
        let inode = fs::metadata(&settings.key).expect("key stat").ino();
        let preview: Value = serde_json::from_str(&run(settings).expect("preview")).expect("JSON");
        let mut settings = fixture(root.path());
        settings.key = settings.home.join("keys/worker-key");
        settings.dry_run = false;
        settings.digest = preview["digest"].as_str().expect("digest").into();
        run(settings).expect("apply");
        assert_eq!(
            fs::metadata(&config_path).expect("config stat").mode() & 0o777,
            0o640
        );
        assert!(
            fs::read_to_string(&config_path)
                .expect("config")
                .starts_with("model = \"owner-model\"\n")
        );
        let target = root
            .path()
            .join(".config/loops/alpha/lanes/keys/worker-key");
        assert_eq!(fs::metadata(&target).expect("moved key").ino(), inode);
        assert_eq!(
            fs::read_link(root.path().join("codex/keys/worker-key")).expect("key link"),
            target
        );
        assert!(fs::read_link(root.path().join("codex/AGENTS.md")).is_ok());
        assert!(fs::read_link(root.path().join("codex/auth.json")).is_ok());
        let mut settings = fixture(root.path());
        settings.key = target;
        let repeated: Value = serde_json::from_str(&run(settings).expect("repeat")).expect("JSON");
        assert_eq!(repeated["changed"], 0);
    }
}
