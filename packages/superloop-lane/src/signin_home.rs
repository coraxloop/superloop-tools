//! Prepare and inspect the loop-owned Codex sign-in source.

mod claude;
mod claude_fs;
mod claude_move;
mod claude_rewrite;
mod claude_scan;
mod reconcile;
mod repair;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::{Path, PathBuf};

use serde_json::json;

type Result<T> = std::result::Result<T, String>;

struct Settings {
    name: String,
    owner: PathBuf,
    home: PathBuf,
    claude_home: PathBuf,
    project: String,
    record: Option<RegistryRecord>,
    account: String,
    key: PathBuf,
    nodes: Vec<Node>,
    routes: Vec<crate::routes::Row>,
    route_refusal: Option<String>,
    reconcile: bool,
    repair: bool,
    dry_run: bool,
    digest: String,
    missing: Vec<String>,
    varied: Vec<String>,
    varied_lines: Vec<VariedLine>,
    locations: Vec<PathBuf>,
}

struct VariedLine {
    label: String,
    expected: String,
    actual: Option<String>,
}

/// The home's first line carrying the varied label's key: after leading whitespace,
/// `writable_roots` or `trust_level` followed by optional whitespace and `=`, or the
/// `[projects."` header prefix, kept whole as spelled; `None` when no line carries the key.
fn varied_line(label: &str, expected: &str, current: &str) -> VariedLine {
    let prefix = match label {
        "config-roots" => "writable_roots",
        "config-project" => "[projects.\"",
        "config-trust" => "trust_level",
        _ => "",
    };
    let actual = current.lines().find(|line| {
        line.trim_start()
            .strip_prefix(prefix)
            .is_some_and(|suffix| label == "config-project" || suffix.trim_start().starts_with('='))
    });
    VariedLine {
        label: label.into(),
        expected: expected.into(),
        actual: actual.map(str::to_owned),
    }
}

struct Node {
    name: String,
    alias: String,
    host: String,
    port: String,
}

fn refused(setting: &str) -> String {
    format!("cannot resolve {setting}; supply --{setting}")
}

fn text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn name_valid(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn ssh_value(source: &str, alias: &str, key: &str) -> String {
    let mut active = false;
    for line in source.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("host"))
        {
            active = words[1..].contains(&alias);
        } else if active
            && words
                .first()
                .is_some_and(|word| word.eq_ignore_ascii_case(key))
        {
            return words.get(1).unwrap_or(&"").to_string();
        }
    }
    String::new()
}

fn aliases(source: &str, node: &str) -> Vec<String> {
    let exact = format!("{node}-worker");
    let mut aliases = Vec::new();
    for line in source.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if words
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("host"))
        {
            for alias in &words[1..] {
                if alias.starts_with(&format!("{node}-")) && !aliases.iter().any(|old| old == alias)
                {
                    aliases.push((*alias).to_owned());
                }
            }
        }
    }
    if aliases.contains(&exact) {
        vec![exact]
    } else {
        aliases
    }
}

fn canonical_key(value: &str, owner: &Path) -> PathBuf {
    let path = value
        .strip_prefix("~/")
        .map_or_else(|| PathBuf::from(value), |rest| owner.join(rest));
    if value.is_empty() {
        PathBuf::new()
    } else {
        fs::canonicalize(path).unwrap_or_default()
    }
}

fn project_from_row(owner: &Path, name: &str) -> String {
    let source = text(
        &owner
            .join(".local/share/superloop-tools/loops.d")
            .join(format!("{name}.env")),
    );
    for line in source.lines() {
        let line = line
            .trim_start()
            .strip_prefix("export ")
            .unwrap_or_else(|| line.trim_start());
        if let Some((key, value)) = line.split_once('=')
            && key.trim() == "LOOP_CWD"
        {
            let value = value.trim();
            return if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].into()
            } else {
                value.into()
            };
        }
    }
    String::new()
}

struct RegistryRecord {
    path: PathBuf,
    bytes: String,
    project: String,
}

impl RegistryRecord {
    fn plan(&self) -> serde_json::Value {
        json!({"path":self.path,"mode":0o600,"before":null,"after":self.bytes,"action":"write"})
    }

    fn write(&self, owner: &Path) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or("registry-record: parent missing")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| format!("registry-record: {}: {error}", self.path.display()))?;
        let directory = crate::pinned::open_protected(owner, parent, owner_uid())
            .map_err(|error| error.line())?;
        let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(
            self.path
                .file_name()
                .ok_or("registry-record: filename missing")?,
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| {
                format!(
                    "registry-record: {}: {error}; repeat preparation",
                    self.path.display()
                )
            })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.write_all(self.bytes.as_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("registry-record: {}: {error}", self.path.display()))
    }
}

fn registry_record(owner: &Path, name: &str) -> Result<Option<RegistryRecord>> {
    let path = owner
        .join(".local/share/superloop-tools/loops.d")
        .join(format!("{name}.env"));
    match fs::symlink_metadata(&path) {
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("registry-record: {}: {error}", path.display())),
    }
    let configuration = loop_home::registry_path(None, owner);
    let row = loop_home::load_registry(&configuration)
        .and_then(|registry| registry.row(name, owner))
        .map_err(|error| {
            format!(
                "registry-record: {name}: {}: {}",
                configuration.display(),
                error.message()
            )
        })?;
    let session = row.session.ok_or_else(|| {
        format!(
            "registry-record: {name}: no session id: {}",
            configuration.display()
        )
    })?;
    let project = row.launch.to_string_lossy().into_owned();
    let home = row.home.to_string_lossy();
    if [name, session.as_str(), project.as_str(), home.as_ref()]
        .iter()
        .any(|value| value.contains(['\n', '\r', '\0']))
    {
        return Err(format!(
            "registry-record: {name}: multiline value: {}",
            configuration.display()
        ));
    }
    let bytes = format!(
        "LOOP_NAME={name}\nLOOP_SID={session}\nLOOP_CWD={project}\nLOOP_UID={}\nLOOP_HOME={home}\n",
        row.uid
    );
    Ok(Some(RegistryRecord {
        path,
        bytes,
        project,
    }))
}

#[allow(clippy::too_many_lines)]
fn settings(args: &[String], verify: bool) -> Result<Settings> {
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut name = None;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--reconcile" | "--repair" | "--dry-run" => {
                if !flags.insert(word.clone()) {
                    return Err("duplicate option".into());
                }
            }
            "--backend" | "--home" | "--claude-home" | "--user" | "--key" | "--project"
            | "--hosts" | "--nodes" | "--expect-digest" => {
                let value = words.next().ok_or("option requires a value")?;
                if values.insert(word.clone(), value.clone()).is_some() {
                    return Err("duplicate option".into());
                }
            }
            _ if !word.starts_with('-') && name.is_none() => {
                name = Some(word.clone());
            }
            _ => return Err(format!("unknown argument: {word}")),
        }
    }
    if values.get("--backend").map(String::as_str) != Some("codex") {
        return Err("--backend codex is required".into());
    }
    let name = name.ok_or("loop name is required")?;
    loop_home::validate_name(&name).map_err(|error| error.message().to_owned())?;
    let owner = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is required")?;
    let value = |key: &str| values.get(key).cloned().unwrap_or_default();
    let home = values
        .get("--home")
        .map_or_else(|| lane_home(&owner, &name), PathBuf::from);
    let claude_home = values
        .get("--claude-home")
        .map_or_else(|| claude_home(&owner, &name), PathBuf::from);
    let reconcile = flags.contains("--reconcile");
    let repair = flags.contains("--repair");
    let dry_run = flags.contains("--dry-run");
    let digest = value("--expect-digest");
    if repair && (reconcile || verify || dry_run != digest.is_empty()) {
        return Err("repair requires exactly one of --dry-run or --expect-digest HEX and excludes reconcile and check".into());
    }
    let invalid_mode = if reconcile || repair {
        verify || dry_run != digest.is_empty()
    } else {
        dry_run || !digest.is_empty()
    };
    if invalid_mode {
        return Err("reconcile requires exactly one of --dry-run or --expect-digest HEX".into());
    }
    if !digest.is_empty() && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("invalid expected digest".into());
    }
    let selected = value("--nodes");
    if selected.is_empty() && values.contains_key("--nodes") {
        return Err("invalid --nodes; expected one or more distinct node names".into());
    }
    if selected.is_empty() && !verify {
        return Err(refused("nodes"));
    }
    let mut names = if selected.is_empty() {
        Vec::new()
    } else {
        selected.split(',').collect::<Vec<_>>()
    };
    if names.iter().any(|name| !name_valid(name))
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
    {
        return Err("invalid --nodes; expected one or more distinct node names".into());
    }
    names.sort_unstable();
    let mut missing = Vec::new();
    let (routes, route_refusal) = match selected_routes(&owner, &name, &names, &value("--hosts"))
        .and_then(|rows| registry_account(rows, values.get("--user")))
    {
        Ok(rows) => (rows, None),
        Err(error) if verify => (Vec::new(), Some(error)),
        Err(error) => return Err(error),
    };
    let nodes = routes
        .iter()
        .map(|row| Node {
            name: row["node"].clone(),
            alias: row["worker_alias"].clone(),
            host: row["hostname"].clone(),
            port: row["port"].clone(),
        })
        .collect::<Vec<_>>();
    let record = if verify || repair {
        None
    } else {
        registry_record(&owner, &name)?
    };
    let project = values.get("--project").cloned().unwrap_or_else(|| {
        if reconcile {
            String::new()
        } else {
            record.as_ref().map_or_else(
                || project_from_row(&owner, &name),
                |record| record.project.clone(),
            )
        }
    });
    let account = values.get("--user").cloned().unwrap_or_else(|| {
        routes
            .first()
            .map(|row| row["account"].clone())
            .unwrap_or_default()
    });
    let key = if repair && !values.contains_key("--key") {
        repair::existing_key(&home, &owner, &nodes)?
    } else if repair {
        repair::explicit_key(&value("--key"), &owner, &home)?
    } else if values.contains_key("--key") {
        canonical_key(&value("--key"), &owner)
    } else {
        routes
            .first()
            .map(|row| canonical_key(&row["worker_identity"], &owner))
            .unwrap_or_default()
    };
    for (needed, label) in [
        (nodes.is_empty(), "nodes"),
        (project.is_empty() && !reconcile, "project"),
        (
            nodes.is_empty()
                || nodes
                    .iter()
                    .any(|node| node.host.is_empty() || node.port.is_empty()),
            "hosts",
        ),
        (account.is_empty(), "user"),
        (key.as_os_str().is_empty() || !key.exists(), "key"),
    ] {
        if needed && route_refusal.is_none() {
            if !verify {
                return Err(refused(label));
            }
            missing.push(if label == "project" {
                format!("project: no LOOP_CWD in ~/.local/share/superloop-tools/loops.d/{name}.env")
            } else {
                label.into()
            });
        }
    }
    Ok(Settings {
        name,
        owner,
        home,
        claude_home,
        project,
        record,
        account,
        key,
        nodes,
        routes,
        route_refusal,
        reconcile,
        repair,
        dry_run,
        digest,
        missing,
        varied: Vec::new(),
        varied_lines: Vec::new(),
        locations: Vec::new(),
    })
}

fn selected_routes(
    owner: &Path,
    name: &str,
    nodes: &[&str],
    hosts: &str,
) -> Result<Vec<crate::routes::Row>> {
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let source = fs::read_to_string(owner.join(".local/share/orchestration-instance/servers.md"))
        .map_err(|_| "registry-read: inspection failed")?;
    let active = crate::routes::registry(&source, name).map_err(|error| {
        if error.starts_with("registry-loop:") {
            format!("registry-node: {}: no active row", nodes[0])
        } else {
            error
        }
    })?;
    let mut rows = Vec::new();
    for node in nodes {
        let row = active
            .iter()
            .find(|row| row["node"] == *node)
            .ok_or_else(|| format!("registry-node: {node}: no active row"))?;
        rows.push(row.clone());
    }
    if !hosts.is_empty() {
        let mut seen = BTreeSet::new();
        for entry in hosts.split(',') {
            let parts = entry.split(':').collect::<Vec<_>>();
            if parts.len() != 3
                || parts.iter().any(|part| part.is_empty())
                || !seen.insert(parts[0])
            {
                return Err(
                    "registry-node: --hosts: expected distinct NAME:HOST:PORT entries".into(),
                );
            }
            let row = rows
                .iter()
                .find(|row| row["node"] == parts[0])
                .ok_or_else(|| {
                    format!(
                        "registry-node: {}: --hosts names an unselected node",
                        parts[0]
                    )
                })?;
            if row["hostname"] != parts[1] || row["port"] != parts[2] {
                return Err(format!(
                    "registry-node: {}: --hosts differs from active row",
                    parts[0]
                ));
            }
        }
        if seen.len() != rows.len() {
            return Err(
                "registry-node: --hosts: expected exactly one entry per selected node".into(),
            );
        }
    }
    rows.sort_by(|left, right| left["node"].cmp(&right["node"]));
    Ok(rows)
}

/// `--user` keeps its grammar but admits no second source: it must repeat the account of every
/// selected active row, since the written stanzas take the account the registry names.
fn registry_account(
    rows: Vec<crate::routes::Row>,
    user: Option<&String>,
) -> Result<Vec<crate::routes::Row>> {
    if let Some(row) = user.and_then(|user| rows.iter().find(|row| row["account"] != *user)) {
        return Err(format!(
            "registry-node: {}: --user differs from active row account",
            row["node"]
        ));
    }
    Ok(rows)
}

fn worker_stanza(settings: &Settings, node: &Node) -> Result<String> {
    route_stanza(settings, node, &home_key(settings)?, &settings.home)
}

/// The Claude lane file's form of the shared stanza: the canonical worker key and the
/// Claude home's own pinned `known_hosts.routes`, as `render-routes` writes it.
fn claude_worker_stanza(settings: &Settings, node: &Node) -> Result<String> {
    route_stanza(settings, node, &settings.key, &settings.claude_home)
}

fn route_stanza(settings: &Settings, node: &Node, identity: &Path, home: &Path) -> Result<String> {
    let mut row = settings
        .routes
        .iter()
        .find(|row| row["node"] == node.name)
        .ok_or_else(|| format!("registry-node: {}: no active row", node.name))?
        .clone();
    row.insert("worker_alias".into(), format!("{}-worker", node.name));
    row.insert("account".into(), settings.account.clone());
    Ok(crate::routes::stanza(
        &row,
        "worker_alias",
        identity,
        &home.join("known_hosts.routes"),
        "yes",
    ))
}

pub(super) fn lane_home(owner: &Path, name: &str) -> PathBuf {
    owner.join(".config/loops").join(name).join("codex")
}

fn charter(owner: &Path) -> PathBuf {
    owner.join(".local/share/superloop-tools/docs/worker-charter.md")
}

fn owner_uid() -> u32 {
    #[cfg(debug_assertions)]
    if let Some(uid) = std::env::var("SUPERLOOP_SIGNIN_TEST_OWNER_UID")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return uid;
    }
    nix::unistd::Uid::effective().as_raw()
}

fn header(settings: &Settings) -> String {
    route_header(
        &settings.name,
        &settings
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
    )
}

pub(super) fn route_header(name: &str, nodes: &[&str]) -> String {
    format!(
        "# Worker-server access for the {} superloop's Codex lanes.\n# Selected estate nodes; the brief scopes which alias a lane may use. Values\n# selected from the instance routes registry ({});\n# registry of record: ~/.local/share/orchestration-instance/servers.md. The key is the loop's own worker\n# key, opening only the loop's own confined account.\n",
        name,
        nodes.join(",")
    )
}

fn home_key(settings: &Settings) -> Result<PathBuf> {
    Ok(settings
        .home
        .join("keys")
        .join(settings.key.file_name().ok_or("key filename missing")?))
}

fn config(settings: &Settings) -> String {
    let project = settings.project.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "[sandbox_workspace_write]\nnetwork_access = true\n# writable_roots: add the lane clone's .git per dispatch (the sandbox excludes .git from writable paths regardless of checkout shape)\nwritable_roots = []\n\n[projects.\"{project}\"]\ntrust_level = \"trusted\"\n"
    )
}

fn link_matches(path: &Path, target: &Path) -> bool {
    path.exists() && fs::read_link(path).is_ok_and(|actual| actual == target)
}

fn canonical_auth(settings: &Settings) -> PathBuf {
    crate::credential::sign_in_dir(&settings.owner, &settings.name).join("auth.json")
}

fn canonical_ready(settings: &Settings) -> Result<bool> {
    loop_home::validate_name(&settings.name).map_err(|error| error.message().to_owned())?;
    let auth = canonical_auth(settings);
    if let Err(error) = fs::symlink_metadata(&auth) {
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(format!("sign-in-source: {error}"))
        };
    }
    let owner = owner_uid();
    #[cfg(debug_assertions)]
    let owner = std::env::var("SUPERLOOP_SIGNIN_TEST_SOURCE_OWNER_UID")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(owner);
    for (path, mode, directory) in [
        (
            crate::credential::sign_in_dir(&settings.owner, &settings.name),
            0o700,
            true,
        ),
        (auth, 0o600, false),
    ] {
        let fd = crate::pinned::open_protected(&settings.owner, &path, owner)
            .map_err(|error| format!("sign-in-source: {}", error.line()))?;
        let metadata = nix::sys::stat::fstat(&fd).map_err(|error| error.to_string())?;
        let kind = metadata.st_mode & libc::S_IFMT;
        if metadata.st_uid != owner
            || metadata.st_mode & 0o7777 != mode
            || kind
                != if directory {
                    libc::S_IFDIR
                } else {
                    libc::S_IFREG
                }
            || (!directory && metadata.st_nlink != 1)
        {
            return Err(format!(
                "sign-in-source: {} owner, mode or type",
                path.display()
            ));
        }
    }
    Ok(true)
}

fn bind_auth(settings: &Settings, home: &Path) -> Result<bool> {
    if !canonical_ready(settings)? {
        return Ok(false);
    }
    let auth = home.join("auth.json");
    let source = canonical_auth(settings);
    match fs::symlink_metadata(&auth) {
        Ok(_) if fs::read_link(&auth).is_ok_and(|target| target == source) => {}
        Ok(_) => {
            return Err(format!(
                "sign-in-link-conflict: {}; retain it until the owner confirms the canonical login and removes the old entry",
                auth.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            symlink(&source, &auth).map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    Ok(true)
}

fn check_location(settings: &mut Settings) {
    let expected = lane_home(&settings.owner, &settings.name);
    let resolved_expected = fs::canonicalize(&settings.owner).map_or_else(
        |_| expected.clone(),
        |owner| lane_home(&owner, &settings.name),
    );
    if settings.home != expected {
        settings.locations.push(settings.home.clone());
    } else if let Ok(actual) = fs::canonicalize(&settings.home)
        && actual != resolved_expected
    {
        settings.locations.push(actual);
    }
    let old = settings.owner.join(format!(".codex-{}", settings.name));
    if fs::symlink_metadata(&old).is_ok() && !settings.locations.contains(&old) {
        settings.locations.push(old);
    }
    if !settings.locations.is_empty() {
        settings.missing.push("location".into());
    }
}

fn verify(mut settings: Settings) -> Result<(u8, String)> {
    if let Some(refusal) = settings.route_refusal.take() {
        settings.missing.push(refusal);
        return Ok(verification_report(&settings));
    }
    check_location(&mut settings);
    if !settings.missing.is_empty() {
        return Ok(verification_report(&settings));
    }
    if !settings.home.is_dir() {
        settings.missing.push("home".into());
        return Ok(verification_report(&settings));
    }
    for (path, label) in [
        (settings.home.clone(), "home-mode-700"),
        (settings.home.join("keys"), "keys-mode-700"),
    ] {
        if !fs::metadata(path).is_ok_and(|m| m.is_dir() && m.mode() & 0o777 == 0o700) {
            settings.missing.push(label.into());
        }
    }
    let auth = settings.home.join("auth.json");
    if fs::symlink_metadata(&auth).is_ok_and(|m| m.is_file()) {
        settings.missing.push("sign-in-link".into());
    } else if !link_matches(&auth, &canonical_auth(&settings)) {
        settings.missing.push("sign-in".into());
    } else if !canonical_ready(&settings).unwrap_or(false) {
        settings.missing.push("sign-in-source".into());
    }
    for (path, target, label) in [
        (
            settings.home.join("AGENTS.md"),
            charter(&settings.owner),
            "AGENTS.md".into(),
        ),
        (
            home_key(&settings)?,
            settings.key.clone(),
            format!(
                "keys/{}",
                settings
                    .key
                    .file_name()
                    .ok_or("key filename missing")?
                    .to_string_lossy()
            ),
        ),
    ] {
        if !link_matches(&path, &target) {
            settings.missing.push(label);
        }
    }
    let current = text(&settings.home.join("config.toml"));
    if current
        .lines()
        .any(|line| line == "sandbox_mode = \"workspace-write\"")
    {
        settings.missing.push("config-sandbox-default".into());
    }
    let expected = config(&settings);
    let labels = [
        "config-workspace-section",
        "config-network",
        "config-roots-comment",
        "config-roots",
        "config-project",
        "config-trust",
    ];
    for (line, label) in expected.lines().filter(|line| !line.is_empty()).zip(labels) {
        if !current.lines().any(|existing| existing == line) {
            if matches!(label, "config-roots" | "config-project" | "config-trust") {
                settings.varied.push(label.into());
                settings
                    .varied_lines
                    .push(varied_line(label, line, &current));
            } else {
                settings.missing.push(label.into());
            }
        }
    }
    verify_ssh(&mut settings)?;
    Ok(verification_report(&settings))
}

fn verify_ssh(settings: &mut Settings) -> Result<()> {
    let current = text(&settings.home.join("ssh_config"));
    if header(settings)
        .lines()
        .any(|line| !current.lines().any(|existing| existing == line))
    {
        settings.missing.push("ssh-header".into());
    }
    let key = home_key(settings)?.to_string_lossy().into_owned();
    let known = settings
        .home
        .join("known_hosts.routes")
        .to_string_lossy()
        .into_owned();
    if text(&settings.home.join("known_hosts.routes"))
        != crate::routes::known_hosts(&settings.routes)
    {
        settings.missing.push("known-hosts".into());
    }
    for node in &settings.nodes {
        for (option, value, label) in [
            ("hostname", node.host.as_str(), "host"),
            ("port", node.port.as_str(), "port"),
            ("user", settings.account.as_str(), "user"),
            ("identityfile", key.as_str(), "key"),
            ("identitiesonly", "yes", "identities"),
            ("userknownhostsfile", known.as_str(), "known-hosts"),
            ("globalknownhostsfile", "/dev/null", "global-hosts"),
            ("stricthostkeychecking", "yes", "host-key"),
            ("updatehostkeys", "no", "update-host-keys"),
        ] {
            if ssh_value(&current, &format!("{}-worker", node.name), option) != value {
                settings.missing.push(format!("ssh-{}-{label}", node.name));
            }
        }
    }
    Ok(())
}

fn verification_report(settings: &Settings) -> (u8, String) {
    let location = if settings.locations.is_empty() {
        String::new()
    } else {
        format!(
            ",\"location\":{}",
            json!(
                settings
                    .locations
                    .iter()
                    .map(|actual| json!({
                        "actual": actual,
                        "expected": lane_home(&settings.owner, &settings.name),
                    }))
                    .collect::<Vec<_>>()
            )
        )
    };
    (
        u8::from(!settings.missing.is_empty()),
        format!(
            "{{\"loop\":{},\"home\":{},\"ok\":{},\"missing\":{},\"varied\":{},\"varied_lines\":{}{location}}}",
            json!(settings.name),
            json!(settings.home),
            settings.missing.is_empty(),
            json!(settings.missing),
            json!(settings.varied),
            json!(
                settings
                    .varied_lines
                    .iter()
                    .map(|line| json!({
                        "label": line.label,
                        "expected": line.expected,
                        "actual": line.actual,
                    }))
                    .collect::<Vec<_>>()
            )
        ),
    )
}

struct StagedHome {
    parent: OwnedFd,
    directory: OwnedFd,
    name: String,
    path: PathBuf,
}

fn staged_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
    let directory = openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )
    .map_err(|error| error.to_string())?;
    let metadata = nix::sys::stat::fstat(&directory).map_err(|error| error.to_string())?;
    if metadata.st_uid != owner_uid()
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err("sign-in-stage-owner-mode-type".into());
    }
    Ok(directory)
}

impl Drop for StagedHome {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.path);
    }
}

fn stage_home(settings: &Settings) -> Result<StagedHome> {
    static NEXT_STAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = settings.home.parent().ok_or("home parent missing")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|error| error.to_string())?;
    let directory = crate::pinned::open_protected(&settings.owner, parent, owner_uid())
        .map_err(|error| error.line())?;
    let metadata = nix::sys::stat::fstat(&directory).map_err(|error| error.to_string())?;
    if metadata.st_uid != owner_uid()
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_mode & 0o022 != 0
    {
        return Err("sign-in-parent-owner-mode-type".into());
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("SUPERLOOP_SIGNIN_TEST_REPLACE_PARENT").is_some() {
        fs::rename(parent, parent.with_extension("pinned")).map_err(|e| e.to_string())?;
        fs::create_dir(parent).map_err(|e| e.to_string())?;
    }
    loop {
        let sequence = NEXT_STAGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("codex.new.{}.{sequence}", std::process::id());
        match nix::sys::stat::mkdirat(&directory, name.as_str(), nix::sys::stat::Mode::S_IRWXU) {
            Ok(()) => {
                let path =
                    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(&name);
                return Ok(StagedHome {
                    directory: staged_directory(&directory, &name)?,
                    parent: directory,
                    name,
                    path,
                });
            }
            Err(nix::errno::Errno::EEXIST) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn create(settings: &Settings) -> Result<String> {
    let staged = stage_home(settings)?;
    nix::sys::stat::mkdirat(&staged.directory, "keys", nix::sys::stat::Mode::S_IRWXU)
        .map_err(|e| e.to_string())?;
    let keys = staged_directory(&staged.directory, "keys")?;
    let mut ssh = header(settings);
    for node in &settings.nodes {
        ssh.push_str(&worker_stanza(settings, node)?);
    }
    for (name, bytes) in [
        ("config.toml", config(settings)),
        ("ssh_config", ssh),
        (
            "known_hosts.routes",
            crate::routes::known_hosts(&settings.routes),
        ),
    ] {
        use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
        let file = openat2(
            &staged.directory,
            name,
            OpenHow::new()
                .flags(
                    OFlag::O_WRONLY
                        | OFlag::O_CREAT
                        | OFlag::O_EXCL
                        | OFlag::O_NOFOLLOW
                        | OFlag::O_CLOEXEC,
                )
                .mode(nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        )
        .map_err(|e| e.to_string())?;
        nix::sys::stat::fchmod(
            &file,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .map_err(|e| e.to_string())?;
        fs::File::from(file)
            .write_all(bytes.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    nix::unistd::symlinkat(
        &settings.key,
        &keys,
        settings.key.file_name().ok_or("key filename missing")?,
    )
    .map_err(|e| e.to_string())?;
    nix::unistd::symlinkat(&charter(&settings.owner), &staged.directory, "AGENTS.md")
        .map_err(|e| e.to_string())?;
    let linked = canonical_ready(settings)?;
    if linked {
        nix::unistd::symlinkat(&canonical_auth(settings), &staged.directory, "auth.json")
            .map_err(|e| e.to_string())?;
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("SUPERLOOP_SIGNIN_TEST_CREATE_FAILURE").is_some() {
        return Err("injected creation failure before publication".into());
    }
    nix::fcntl::renameat2(
        &staged.parent,
        staged.name.as_str(),
        &staged.parent,
        settings.home.file_name().ok_or("home name missing")?,
        nix::fcntl::RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(|e| e.to_string())?;
    let quoted_home = format!(
        "'{}'",
        crate::credential::sign_in_dir(&settings.owner, &settings.name)
            .to_string_lossy()
            .replace('\'', "'\\''")
    );
    let probe =
        std::env::var_os("TMPDIR").map_or_else(|| settings.owner.join(".cache/tmp"), PathBuf::from);
    let quoted_probe = format!("'{}'", probe.to_string_lossy().replace('\'', "'\\''"));
    let _written = writeln!(
        std::io::stderr().lock(),
        "Owner: sign in once in the canonical mode-0700 root with CODEX_HOME={quoted_home} superloop-runtime exec -- login; prepare again to bind the lane home, then probe with the roster's explicit model and effort:\nCODEX_HOME={quoted_home} superloop-runtime exec -- exec -m MODEL -c model_reasoning_effort=EFFORT -C {quoted_probe} --skip-git-repo-check -s read-only 'Reply with the single word OK.' < /dev/null"
    );
    Ok(format!(
        "CODEX-HOME {} READY{}",
        settings.name,
        if linked {
            format!(" sign-in-link={}", canonical_auth(settings).display())
        } else {
            String::new()
        }
    ))
}

/// Dispatch the sign-in preparation and inspection forms from the built lane binary.
#[must_use]
pub fn command(args: &[String], check: bool) -> u8 {
    let result = (|| {
        if args.windows(2).any(|pair| pair == ["--backend", "claude"]) {
            return claude::run(args, check).map(|out| (0, out));
        }
        let settings = settings(args, check)?;
        if check {
            return verify(settings);
        }
        let expected = lane_home(&settings.owner, &settings.name);
        if settings.home != expected {
            return Err(format!(
                "location: {} expected {}; migrate the home at deployment",
                settings.home.display(),
                expected.display()
            ));
        }
        if settings.reconcile {
            return reconcile::run(&settings).map(|out| (0, out));
        }
        if settings.repair {
            return repair::run(settings).map(|out| (0, out));
        }
        if fs::symlink_metadata(&settings.home).is_ok() {
            let meta = fs::symlink_metadata(&settings.home).map_err(|error| error.to_string())?;
            if !meta.is_dir() || meta.uid() != owner_uid() || meta.mode() & 0o7777 != 0o700 {
                return Err("sign-in-home-owner-mode-type".into());
            }
            if let Some(record) = &settings.record {
                record.write(&settings.owner)?;
            }
            if canonical_ready(&settings)? {
                bind_auth(&settings, &settings.home)?;
                return Ok((
                    0,
                    format!(
                        "CODEX-HOME {} SIGN-IN-LINKED sign-in-link={}",
                        settings.name,
                        canonical_auth(&settings).display()
                    ),
                ));
            }
            return Ok((
                3,
                format!("home already exists: {}", settings.home.display()),
            ));
        }
        let out = create(&settings)?;
        if let Some(record) = &settings.record {
            record.write(&settings.owner)?;
        }
        Ok((0, out))
    })();
    match result {
        Ok((status, output)) if status != 3 => {
            if writeln!(std::io::stdout().lock(), "{output}").is_err() {
                1
            } else {
                status
            }
        }
        Ok((status, error)) => {
            let _written = writeln!(
                std::io::stderr().lock(),
                "superloop-lane signin-home: {error}"
            );
            status
        }
        Err(error) => {
            let _written = writeln!(
                std::io::stderr().lock(),
                "superloop-lane signin-home: {error}"
            );
            2
        }
    }
}

pub(crate) fn claude_home(owner: &Path, name: &str) -> PathBuf {
    owner.join(".config/loops").join(name).join("claude")
}

#[cfg(test)]
mod tests {
    use super::varied_line;

    /// # Panics
    /// Panics only if a varied line loses its original spelling or matches another key.
    /// ´test:unit:varied-line-matches-the-key-and-preserves-the-whole-line´
    #[test]
    fn varied_line_matches_the_key_and_preserves_the_whole_line() {
        let actual = "writable_roots = [\"/lane/clone\"] # owner roots";
        let detail = varied_line("config-roots", "writable_roots = []", actual);
        assert_eq!(detail.label, "config-roots");
        assert_eq!(detail.expected, "writable_roots = []");
        assert_eq!(detail.actual.as_deref(), Some(actual));
        let indented = "  writable_roots = [\"/x\"]";
        assert_eq!(
            varied_line("config-roots", "writable_roots = []", indented)
                .actual
                .as_deref(),
            Some(indented)
        );
        assert!(
            varied_line(
                "config-roots",
                "writable_roots = []",
                "writable_roots_extra = []"
            )
            .actual
            .is_none()
        );
        let header = "[projects.\"/lane/clone\"] # owner project";
        assert_eq!(
            varied_line("config-project", "[projects.\"/project\"]", header)
                .actual
                .as_deref(),
            Some(header)
        );
        let trust = "trust_level = \"untrusted\"";
        assert_eq!(
            varied_line("config-trust", "trust_level = \"trusted\"", trust)
                .actual
                .as_deref(),
            Some(trust)
        );
    }
}
