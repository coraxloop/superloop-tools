use super::{Result, Settings, canonical_key, home_key, name_valid};
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, OpenHow, ResolveFlag, openat2, renameat};
use nix::sys::stat::{Mode, fstatat};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;

use serde_json::json;
use sha2::{Digest as _, Sha256};

struct Home {
    path: PathBuf,
    held: Flock<File>,
}

impl Home {
    fn check(&self) -> Result<()> {
        let held = self.held.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|e| e.to_string())?;
        let uid = nix::unistd::Uid::current().as_raw();
        #[cfg(debug_assertions)]
        let uid = if std::env::var_os("SUPERLOOP_SIGNIN_TEST_FOREIGN_OWNER").is_some() {
            uid.wrapping_add(1)
        } else {
            uid
        };
        if !held.is_dir()
            || held.uid() != uid
            || held.mode() & 0o777 != 0o700
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err(format!(
                "reconcile home identity, owner or mode mismatch: {}",
                self.path.display()
            ));
        }
        Ok(())
    }

    fn read(&self, name: &str) -> Result<(Option<fs::Metadata>, Vec<u8>)> {
        self.check()?;
        let refusal = || {
            format!(
                "reconcile requires unlinked regular SSH files: {}",
                self.path.join(name).display()
            )
        };
        let fd = match openat2(
            &*self.held,
            name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) if name == "known_hosts.routes" => {
                return Ok((None, Vec::new()));
            }
            Err(_) => return Err(refusal()),
        };
        let mut file = File::from(fd);
        let metadata = file.metadata().map_err(|_| refusal())?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(refusal());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let named =
            fstatat(&*self.held, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if (metadata.dev(), metadata.ino()) != (named.st_dev, named.st_ino) {
            return Err("SSH input changed while reading".into());
        }
        Ok((Some(metadata), bytes))
    }
}

pub(super) fn words(line: &str) -> Result<Vec<String>> {
    // The reviewed grammar accepts quoted option values but no shell expansion.
    let mut result = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
            continue;
        }
        if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            continue;
        }
        if quote.is_none() && c == '#' {
            break;
        }
        if quote.is_none() && c.is_whitespace() {
            if !word.is_empty() {
                result.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escaped {
        return Err("malformed SSH quoting".into());
    }
    if !word.is_empty() {
        result.push(word);
    }
    Ok(result)
}

pub(super) fn blocks(text: &str) -> Result<Vec<Vec<String>>> {
    let mut blocks = vec![Vec::new()];
    for line in text.split_inclusive('\n') {
        let tokens = words(line)?;
        if tokens.first().is_some_and(|word| {
            word.eq_ignore_ascii_case("match") || word.eq_ignore_ascii_case("include")
        }) {
            return Err("reconcile does not support Match or Include scopes".into());
        }
        if tokens
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("host"))
        {
            blocks.push(Vec::new());
        }
        if let Some(block) = blocks.last_mut() {
            block.push(line.to_owned());
        }
    }
    Ok(blocks)
}

const NODE_HEADERS: [&str; 2] = [
    "# copied from the loop's Claude lane home (",
    "# selected from the instance routes registry (",
];

pub(super) fn header_nodes(text: &str) -> Result<Vec<&str>> {
    let leading = text.split_inclusive('\n').take_while(|line| {
        !line
            .split_whitespace()
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("host"))
    });
    let headers = leading
        .filter_map(|line| {
            NODE_HEADERS.iter().find_map(|prefix| {
                line.trim_end()
                    .strip_prefix(prefix)
                    .and_then(|rest| rest.strip_suffix(");"))
            })
        })
        .collect::<Vec<_>>();
    if headers.len() != 1 {
        return Err("reconcile requires the generated Codex node header".into());
    }
    Ok(headers[0].split(',').collect())
}

fn owner_leading(text: &str, settings: &Settings) -> Result<String> {
    let parts = blocks(text)?;
    let header = super::header(settings);
    let generated = header.lines().collect::<Vec<_>>();
    let marker = |line: &str| {
        NODE_HEADERS
            .iter()
            .any(|prefix| line.trim_end().starts_with(prefix) && line.trim_end().ends_with(");"))
    };
    let markers = parts[0]
        .iter()
        .enumerate()
        .filter(|(_, line)| marker(line))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if markers.len() > 1 {
        return Err("ambiguous generated Codex node header".into());
    }
    let complete = parts[0].windows(generated.len()).position(|window| {
        window.iter().zip(&generated).all(|(line, expected)| {
            line.trim_end() == *expected || (marker(line) && marker(expected))
        })
    });
    let generated_run = match (complete, markers.first()) {
        (Some(start), _) => start..start + generated.len(),
        (None, Some(&at)) => partial_run(&parts[0], at, &generated, marker)?,
        (None, None) => 0..0,
    };
    Ok(parts[0]
        .iter()
        .enumerate()
        .filter(|(index, _)| !generated_run.contains(index))
        .map(|(_, line)| line.clone())
        .collect())
}

/// The generated lines around a lone node marker that the earlier repair left when it inserted
/// only the header lines a file lacked: adjacent lines equal to generated lines in strictly
/// header order on each side of the marker. An owner line that repeats a generated line out of
/// that order (a hand-written title beneath the run, for one) ends the run and stays the owner's.
fn partial_run(
    leading: &[String],
    at: usize,
    generated: &[&str],
    marker: impl Fn(&str) -> bool,
) -> Result<std::ops::Range<usize>> {
    let marker_position = generated
        .iter()
        .position(|line| marker(line))
        .ok_or("generated Codex header lacks its node marker")?;
    let position = |line: &String| {
        generated
            .iter()
            .position(|expected| line.trim_end() == *expected)
    };
    let (mut first, mut bound) = (at, marker_position);
    while let Some(found) = first
        .checked_sub(1)
        .and_then(|index| position(&leading[index]))
    {
        if found >= bound {
            break;
        }
        (first, bound) = (first - 1, found);
    }
    let (mut end, mut bound) = (at + 1, marker_position);
    while let Some(found) = leading.get(end).and_then(position) {
        if found <= bound {
            break;
        }
        (end, bound) = (end + 1, found);
    }
    Ok(first..end)
}

pub(super) fn details(text: &str, settings: &Settings) -> Result<serde_json::Value> {
    let mut removed = Vec::new();
    let mut foreign = Vec::new();
    for block in blocks(text)?.iter().skip(1) {
        let names = words(&block[0])?.into_iter().skip(1).collect::<Vec<_>>();
        if names.len() == 1 && names[0].strip_suffix("-worker").is_some_and(name_valid) {
            if !settings
                .nodes
                .iter()
                .any(|node| names[0] == format!("{}-worker", node.name))
            {
                removed.push(names[0].clone());
            }
        } else {
            foreign.push(names.join(" "));
        }
    }
    let comments = owner_leading(text, settings)?
        .lines()
        .filter(|line| line.trim_start().starts_with('#'))
        .count();
    Ok(
        json!({"removed_stanzas":removed,"retained_foreign_stanzas":foreign,"retained_leading_comment_lines":comments}),
    )
}

fn codex_rewrite(text: &str, settings: &Settings) -> Result<String> {
    let mut result = super::header(settings);
    result.push_str(&owner_leading(text, settings)?);
    let mut seen = BTreeSet::new();
    for block in blocks(text)?.iter().skip(1) {
        let names = words(&block[0])?.into_iter().skip(1).collect::<Vec<_>>();
        let workers = names
            .iter()
            .filter_map(|name| name.strip_suffix("-worker").filter(|node| name_valid(node)))
            .collect::<Vec<_>>();
        if workers.is_empty() {
            result.push_str(&block.concat());
            continue;
        }
        let name = workers[0];
        if names.len() != 1 {
            return Err(format!(
                "cannot reconcile {name} SSH stanza: Host {}",
                names.join(" ")
            ));
        }
        if !seen.insert(name.to_owned()) {
            return Err(format!("ambiguous {name} SSH stanzas: Host {}", names[0]));
        }
        let Some(node) = settings.nodes.iter().find(|node| node.name == name) else {
            continue;
        };
        let desired = super::worker_stanza(settings, node)?;
        let options = desired
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        for line in &block[1..] {
            if words(line)?
                .first()
                .and_then(|word| word.split_once('='))
                .is_some_and(|(key, _)| options.contains(&key.to_ascii_lowercase()))
            {
                return Err("reconcile requires whitespace-separated node options".into());
            }
        }
        result.push_str(&super::claude::rewrite_block(block, &desired)?);
    }
    for node in &settings.nodes {
        if !seen.contains(&node.name) {
            if !result.is_empty() && !result.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(&super::worker_stanza(settings, node)?);
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)]
pub(super) fn rewrite(
    text: &str,
    old_nodes: &[&str],
    settings: &Settings,
    codex: bool,
) -> Result<String> {
    if codex {
        return codex_rewrite(text, settings);
    }
    let mut blocks = blocks(text)?;
    let known = old_nodes
        .iter()
        .copied()
        .chain(settings.nodes.iter().map(|node| node.name.as_str()))
        .collect::<BTreeSet<_>>();
    let mut resolved = BTreeMap::new();
    for node in known {
        let matches = super::aliases(text, node);
        let expected =
            if settings.nodes.iter().any(|selected| selected.name == node) && matches.len() == 1 {
                matches[0].clone()
            } else {
                format!("{node}-worker")
            };
        let mut candidates = Vec::new();
        for (index, block) in blocks.iter().enumerate().skip(1) {
            let names = words(&block[0])?.into_iter().skip(1).collect::<Vec<_>>();
            if names.iter().any(|name| name == &expected) {
                candidates.push((index, names));
            }
        }
        if candidates.len() > 1 {
            return Err(format!(
                "ambiguous {node} SSH stanzas: {}",
                candidates
                    .iter()
                    .map(|(_, names)| format!("Host {}", names.join(" ")))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some((index, names)) = candidates.first() {
            if names.len() != 1 || names[0] != expected || !name_valid(&names[0]) {
                return Err(format!(
                    "cannot reconcile {node} SSH stanza: Host {}",
                    names.join(" ")
                ));
            }
            if resolved.insert(*index, node).is_some() {
                return Err("overlapping node selections".into());
            }
        }
    }
    let identity = settings.key.to_string_lossy().into_owned();
    let mut result = blocks[0].concat();
    let mut found = BTreeSet::new();
    for (index, block) in blocks.iter_mut().enumerate().skip(1) {
        let Some(name) = resolved.get(&index) else {
            result.push_str(&block.concat());
            continue;
        };
        let mut suffix = Vec::new();
        while block.len() > 1
            && block
                .last()
                .is_some_and(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        {
            if let Some(line) = block.pop() {
                suffix.insert(0, line);
            }
        }
        let Some(node) = settings.nodes.iter().find(|node| node.name == *name) else {
            result.push_str(&suffix.concat());
            continue;
        };
        found.insert(node.name.as_str());
        let desired = vec![
            ("hostname", node.host.clone()),
            ("port", node.port.clone()),
            ("user", settings.account.clone()),
            ("identityfile", identity.clone()),
        ];
        let mut seen = BTreeSet::new();
        result.push_str(&block[0]);
        for line in &block[1..] {
            let tokens = words(line)?;
            let option = tokens
                .first()
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if option
                .split_once('=')
                .is_some_and(|(name, _)| desired.iter().any(|(key, _)| *key == name))
            {
                return Err("reconcile requires whitespace-separated node options".into());
            }
            if let Some((key, value)) = desired.iter().find(|(key, _)| *key == option) {
                if !seen.insert(*key) || tokens.len() != 2 {
                    return Err(format!("duplicate or malformed node option: {option}"));
                }
                let same = tokens[1] == *value
                    || (option == "identityfile"
                        && canonical_key(&tokens[1], &settings.owner) == settings.key);
                if same {
                    result.push_str(line);
                } else {
                    writeln!(result, "  {} {value}", tokens[0]).map_err(|e| e.to_string())?;
                }
            } else {
                result.push_str(line);
            }
        }
        for (key, value) in desired {
            if !seen.contains(key) {
                if !result.ends_with('\n') {
                    result.push('\n');
                }
                writeln!(result, "  {key} {value}").map_err(|e| e.to_string())?;
            }
        }
        result.push_str(&suffix.concat());
    }
    for node in &settings.nodes {
        if found.contains(node.name.as_str()) {
            continue;
        }
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&super::claude_worker_stanza(settings, node)?);
    }
    Ok(result)
}

fn lock_home(path: PathBuf) -> Result<Home> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let held = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| e.to_string())?;
    #[cfg(debug_assertions)]
    if std::env::var_os("SUPERLOOP_SIGNIN_TEST_SWAP_HOME")
        .is_some_and(|selected| std::path::Path::new(&selected) == path)
    {
        fs::rename(&path, path.with_extension("held")).map_err(|e| e.to_string())?;
        fs::create_dir(&path).map_err(|e| e.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let home = Home { path, held };
    home.check()?;
    Ok(home)
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(settings: &Settings) -> Result<String> {
    if !super::link_matches(&home_key(settings)?, &settings.key) {
        return Err(super::refused("existing-key"));
    }
    let key = home_key(settings)?.to_string_lossy().into_owned();
    let mut values = vec![settings.account.as_str(), key.as_str()];
    for node in &settings.nodes {
        values.extend([
            node.name.as_str(),
            node.host.as_str(),
            node.port.as_str(),
            node.alias.as_str(),
        ]);
    }
    if values.iter().any(|s| {
        s.chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '#'))
    }) {
        return Err("reconcile requires plain SSH option values".into());
    }
    let paths = [
        std::path::absolute(&settings.home).map_err(|e| e.to_string())?,
        std::path::absolute(&settings.claude_home).map_err(|e| e.to_string())?,
    ];
    if paths[0] == paths[1] {
        return Err("Codex and Claude homes must differ".into());
    }
    let mut order = paths.clone();
    order.sort();
    let locks = order
        .into_iter()
        .map(lock_home)
        .collect::<Result<Vec<_>>>()?;
    let homes = paths
        .iter()
        .map(|path| {
            locks
                .iter()
                .find(|home| home.path == *path)
                .ok_or_else(|| "locked home missing".into())
        })
        .collect::<Result<Vec<_>>>()?;
    let mut leftovers = Vec::new();
    for home in &homes {
        for entry in fs::read_dir(&home.path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".ssh_config.")
            {
                leftovers.push(entry.path().display().to_string());
            }
        }
    }
    if !leftovers.is_empty() {
        leftovers.sort();
        return Err(format!(
            "unfinished reconcile temporary files; inspect and remove before preview: {}",
            leftovers.join(", ")
        ));
    }
    let files_to_write = [
        (homes[0], "ssh_config"),
        (homes[1], "ssh_config"),
        (homes[0], "known_hosts.routes"),
    ];
    let before = files_to_write
        .iter()
        .map(|(home, name)| home.read(name))
        .collect::<Result<Vec<_>>>()?;
    let texts = before
        .iter()
        .map(|(_, bytes)| std::str::from_utf8(bytes).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>>>()?;
    let old_nodes = header_nodes(texts[0])?;
    let mut after = texts[..2]
        .iter()
        .enumerate()
        .map(|(index, text)| rewrite(text, &old_nodes, settings, index == 0))
        .collect::<Result<Vec<_>>>()?;
    after.push(crate::routes::known_hosts(&settings.routes));
    let mut files = files_to_write.iter().enumerate().map(|(index, (home, name))| json!({
        "path":home.path.join(name), "mode":before[index].0.as_ref().map_or(0o600, |m|m.mode() & 0o777),
        "before":before[index].0.as_ref().map(|_|texts[index]), "after":after[index],
        "action":if before[index].0.is_none() { "write" } else if texts[index] != after[index] { "replace" } else { "unchanged" }
    })).collect::<Vec<_>>();
    if let Some(record) = &settings.record {
        files.push(record.plan());
    }
    let plan = json!({"loop":settings.name,"nodes":settings.nodes.iter().map(|node|&node.name).collect::<Vec<_>>(),"files":files,"ssh":details(texts[0], settings)?});
    let mut digest = String::new();
    for byte in Sha256::digest(plan.to_string().as_bytes()) {
        write!(digest, "{byte:02x}").map_err(|e| e.to_string())?;
    }
    let changed = texts
        .iter()
        .zip(&after)
        .filter(|(old, new)| **old != new.as_str())
        .count()
        + usize::from(settings.record.is_some());
    if settings.dry_run {
        return Ok(json!({"plan":plan,"digest":digest,"changed":changed}).to_string());
    }
    if digest != settings.digest.to_ascii_lowercase() {
        return Err("reconcile digest mismatch; repeat --dry-run".into());
    }
    for (index, (home, name)) in files_to_write.iter().enumerate() {
        let (metadata, bytes) = home.read(name)?;
        let identity = |m: &Option<fs::Metadata>| m.as_ref().map(|m| (m.dev(), m.ino(), m.mode()));
        if identity(&metadata) != identity(&before[index].0) || bytes != before[index].1 {
            return Err("SSH input changed while planning; repeat --dry-run".into());
        }
    }
    if let Some(record) = &settings.record {
        record.write(&settings.owner)?;
    }
    let mut staged = Vec::new();
    let result = (|| {
        for (index, (home, _)) in files_to_write.iter().enumerate() {
            if texts[index] == after[index] {
                continue;
            }
            home.check()?;
            let name = format!(".ssh_config.{}-{index}", std::process::id());
            let fd = openat2(
                &*home.held,
                name.as_str(),
                OpenHow::new()
                    .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                    .mode(Mode::S_IRUSR | Mode::S_IWUSR)
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )
            .map_err(|e| e.to_string())?;
            staged.push((index, name));
            let mut file = File::from(fd);
            file.set_permissions(fs::Permissions::from_mode(
                before[index].0.as_ref().map_or(0o600, |m| m.mode() & 0o777),
            ))
            .map_err(|e| e.to_string())?;
            file.write_all(after[index].as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
        for home in &homes {
            home.check()?;
        }
        for wanted in [1, 2, 0] {
            let Some((index, name)) = staged.iter().find(|(index, _)| *index == wanted) else {
                continue;
            };
            let (home, destination) = files_to_write[*index];
            renameat(&*home.held, name.as_str(), &*home.held, destination)
                .map_err(|e| e.to_string())?;
            #[cfg(debug_assertions)]
            if let Some(log) = std::env::var_os("SUPERLOOP_SIGNIN_TEST_KILL_AFTER_RENAME") {
                fs::write(
                    log,
                    home.path.join(destination).to_string_lossy().as_bytes(),
                )
                .map_err(|e| e.to_string())?;
                nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGKILL)
                    .map_err(|e| e.to_string())?;
            }
        }
        for home in &homes {
            home.held.sync_all().map_err(|e| e.to_string())?;
        }
        Ok(format!(
            "{{\"outcome\": \"applied\", \"digest\": \"{digest}\", \"replaced\": {}}}",
            staged.len() + usize::from(settings.record.is_some())
        ))
    })();
    for (index, name) in &staged {
        let _removed = nix::unistd::unlinkat(
            &*files_to_write[*index].0.held,
            name.as_str(),
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        );
    }
    result
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::signin_home) fn measured(settings: &Settings) -> String {
        format!(
            "{}# owner registry note\n# owner access note\nHost gone-one-worker\n  HostName old.invalid\n# gone-one trailing\n\nHost gone-two-worker\n  HostName old.invalid\nHost gone-three-worker\n  HostName old.invalid\nHost node-worker\n  HostName 192.0.2.1\n  StrictHostKeyChecking accept-new\nHost personal\n\tHostName personal.invalid\n# personal trailing\n",
            super::super::header(settings).replace(
                "# selected from the instance routes registry (",
                "# copied from the loop's Claude lane home ("
            )
        )
    }

    /// The shape the earlier repair left on a hand-written home: generated header lines 2 to 5
    /// inserted above the owner's own header, whose first line is the generated title.
    pub(in crate::signin_home) fn partial(settings: &Settings) -> (String, String) {
        let header = measured(settings)
            .lines()
            .take(5)
            .map(|line| format!("{line}\n"))
            .collect::<Vec<_>>();
        let owner = format!(
            "{}# owner registry note\n# owner access note\n# owner path note\n# owner closing note\n",
            header[0]
        );
        let stanzas = measured(settings)
            .split_inclusive('\n')
            .skip(7)
            .collect::<String>();
        (header[1..].concat() + &owner + &stanzas, owner)
    }

    /// # Panics
    /// Panics only if the partial generated header survives or an owner line is removed.
    /// ´test:unit:codex-reconcile-partial-header-keeps-owner-lines´
    #[test]
    fn codex_reconcile_partial_header_keeps_owner_lines() {
        let settings = super::super::repair::tests::fixture(std::path::Path::new("/owner"));
        let (partial, owner) = partial(&settings);
        let rewritten = rewrite(&partial, &[], &settings, true).expect("partial header");
        let leading = rewritten
            .split_inclusive('\n')
            .take_while(|line| !line.starts_with("Host "))
            .collect::<String>();
        assert_eq!(leading, super::super::header(&settings) + &owner);
        assert_eq!(
            details(&partial, &settings).expect("partial count")["retained_leading_comment_lines"],
            5
        );
        assert_eq!(
            rewrite(&rewritten, &[], &settings, true).expect("fixpoint"),
            rewritten
        );
        assert_eq!(
            details(&rewritten, &settings).expect("fixpoint count")["retained_leading_comment_lines"],
            5
        );
        assert!(!rewritten.contains("gone-"));
    }

    /// # Panics
    /// Panics only if fixture setup or digest-bound migration violates the asserted contract.
    /// ´test:unit:codex-reconcile-registry-pins-and-removal-plan´
    #[test]
    fn codex_reconcile_registry_pins_and_removal_plan() {
        let root = tempfile::tempdir().expect("fixture");
        let mut settings = super::super::repair::tests::fixture(root.path());
        for home in [&settings.home, &settings.claude_home] {
            fs::create_dir(home).expect("home");
            fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        }
        fs::create_dir(settings.home.join("keys")).expect("keys");
        fs::write(&settings.key, "synthetic key").expect("key");
        std::os::unix::fs::symlink(&settings.key, home_key(&settings).expect("key path"))
            .expect("key link");
        fs::write(settings.home.join("ssh_config"), measured(&settings)).expect("measured SSH");
        fs::write(
            settings.claude_home.join("ssh_config"),
            "Host node-worker\n  HostName 192.0.2.1\n",
        )
        .expect("sibling SSH");
        let preview: serde_json::Value =
            serde_json::from_str(&run(&settings).expect("preview")).expect("JSON");
        assert_eq!(preview["changed"], 3);
        assert_eq!(
            preview["plan"]["ssh"]["removed_stanzas"],
            json!(["gone-one-worker", "gone-two-worker", "gone-three-worker"])
        );
        assert_eq!(
            preview["plan"]["ssh"]["retained_foreign_stanzas"],
            json!(["personal"])
        );
        assert_eq!(preview["plan"]["ssh"]["retained_leading_comment_lines"], 2);
        assert_eq!(preview["plan"]["files"][2]["action"], "write");
        settings.dry_run = false;
        settings.digest = preview["digest"].as_str().expect("digest").into();
        fs::write(
            settings.home.join("known_hosts.routes"),
            "changed after preview\n",
        )
        .expect("stale input");
        assert!(
            run(&settings)
                .expect_err("stale digest")
                .contains("digest mismatch")
        );
        fs::remove_file(settings.home.join("known_hosts.routes")).expect("restore absence");
        run(&settings).expect("apply");
        let after = fs::read_to_string(settings.home.join("ssh_config")).expect("SSH");
        assert!(!after.contains("gone-"));
        assert!(
            after.ends_with("Host personal\n\tHostName personal.invalid\n# personal trailing\n")
        );
        assert!(after.contains("StrictHostKeyChecking yes\n"));
        assert!(after.contains("GlobalKnownHostsFile /dev/null\n"));
        assert!(after.contains("UpdateHostKeys no\n"));
        assert_eq!(
            fs::read_to_string(settings.home.join("known_hosts.routes")).expect("pins"),
            "[192.0.2.1]:22 ssh-ed25519 AAAA\n192.0.2.1 ssh-ed25519 AAAA\n"
        );
        settings.dry_run = true;
        let repeated: serde_json::Value =
            serde_json::from_str(&run(&settings).expect("repeat")).expect("JSON");
        assert_eq!(repeated["changed"], 0);
        let owner_comment = "# key, opening only the loop's own confined account.\n";
        let duplicate = measured(&settings).replacen("# owner registry note\n", owner_comment, 1);
        let retained =
            rewrite(&duplicate, &[], &settings, true).expect("owner comment repeats header text");
        assert_eq!(retained.matches(owner_comment).count(), 2);
        assert_eq!(
            details(&duplicate, &settings).expect("owner comment count")["retained_leading_comment_lines"],
            2
        );
    }

    /// # Panics
    /// Panics only if the Claude-side rewrite appends a stanza other than the rendered pinned form.
    /// ´test:unit:claude-reconcile-appends-the-pinned-render-stanza´
    #[test]
    fn claude_reconcile_appends_the_pinned_render_stanza() {
        let settings = super::super::repair::tests::fixture(std::path::Path::new("/owner"));
        let owner = "Host personal\n  HostName personal.invalid\n";
        let appended = rewrite(owner, &[], &settings, false).expect("Claude rewrite");
        assert_eq!(
            appended,
            format!(
                "{owner}Host node-worker\n  HostName 192.0.2.1\n  Port 22\n  User worker\n  IdentityFile /owner/worker-key\n  IdentitiesOnly yes\n  UserKnownHostsFile /owner/claude/known_hosts.routes\n  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n  UpdateHostKeys no\n\n"
            )
        );
        assert_eq!(
            rewrite(&appended, &["node"], &settings, false).expect("Claude fixpoint"),
            appended
        );
    }
}
