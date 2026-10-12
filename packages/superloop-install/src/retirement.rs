//! Reviewed staged inventories and narrow home-prefix retirement.

mod filesystem;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;

/// Capture expected bytes from a reviewed staged release, never from live targets.
#[derive(Debug, Parser)]
#[command(name = "superloop-install inventory")]
pub struct InventoryArgs {
    #[arg(long)]
    pub stage: PathBuf,
    #[arg(long)]
    pub prefix: PathBuf,
    #[arg(long)]
    pub repository: String,
    #[arg(long)]
    pub source_commit: String,
    #[arg(long)]
    pub report: PathBuf,
}

/// Retire only reviewed old destinations absent from the newer release.
#[derive(Debug, Parser)]
#[command(name = "superloop-install retire")]
pub struct RetireArgs {
    #[arg(long)]
    pub old_inventory: PathBuf,
    #[arg(long)]
    pub new_inventory: PathBuf,
    #[arg(long)]
    pub prefix: PathBuf,
    #[arg(long)]
    pub destdir: Option<PathBuf>,
    #[arg(long)]
    pub recovery: PathBuf,
    #[arg(long)]
    pub report: PathBuf,
    #[arg(long)]
    pub destination: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    destination: PathBuf,
    sha256: String,
    mode: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: u32,
    repository: String,
    source_commit: String,
    prefix: PathBuf,
    files: Vec<Entry>,
}

#[derive(Debug, Serialize)]
struct Retired {
    destination: PathBuf,
    recovery: PathBuf,
    sha256: String,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: u32,
    repository: String,
    old_source_commit: String,
    new_source_commit: String,
    prefix: PathBuf,
    planned: Vec<Retired>,
    changes: Vec<Retired>,
    already_retired: Vec<Retired>,
    conflict: Option<String>,
}

fn inventory_validate(inventory: &Inventory) -> Result<()> {
    if inventory.schema != 1 || inventory.repository.trim().is_empty() {
        return Err("inventory schema or repository identity is invalid".into());
    }
    if ![40, 64].contains(&inventory.source_commit.len())
        || !inventory
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("inventory source_commit must be a full lowercase Git object ID".into());
    }
    filesystem::absolute(&inventory.prefix)?;
    let mut names = BTreeSet::new();
    for entry in &inventory.files {
        filesystem::relative(&entry.destination)?;
        if !names.insert(&entry.destination) {
            return Err(format!(
                "duplicate inventory destination: {}",
                entry.destination.display()
            ));
        }
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "inventory requires a full SHA-256: {}",
                entry.destination.display()
            ));
        }
        if entry.mode & !0o777 != 0 || entry.mode & 0o022 != 0 {
            return Err(format!(
                "unsafe inventory mode: {}",
                entry.destination.display()
            ));
        }
    }
    Ok(())
}

fn staged_root(stage: &Path, prefix: &Path) -> Result<PathBuf> {
    filesystem::absolute(stage)?;
    filesystem::absolute(prefix)?;
    if stage == Path::new("/") {
        return Err("stage must be a separate staging directory".into());
    }
    Ok(stage.join(
        prefix
            .strip_prefix("/")
            .map_err(|error| error.to_string())?,
    ))
}

fn outside(report: &Path, roots: &[&Path]) -> Result<()> {
    filesystem::absolute(report)?;
    if roots.iter().any(|root| report.starts_with(root)) {
        return Err("report must be outside the managed prefix and recovery bytes".into());
    }
    Ok(())
}

/// Write a durable inventory of regular, exclusively linked staged files.
///
/// # Errors
/// Refuses unsafe paths, links, ownership, concurrent source changes or report publication failure.
pub fn inventory(args: &InventoryArgs) -> Result<usize> {
    let root = staged_root(&args.stage, &args.prefix)?;
    outside(&args.report, &[&root])?;
    let directory = filesystem::directory(&root)?;
    let mut inventory = Inventory {
        schema: 1,
        repository: args.repository.clone(),
        source_commit: args.source_commit.clone(),
        prefix: args.prefix.clone(),
        files: filesystem::inventory(&directory, Path::new(""))?,
    };
    inventory
        .files
        .sort_by(|left, right| left.destination.cmp(&right.destination));
    inventory_validate(&inventory)?;
    filesystem::publish(&args.report, &inventory)?;
    Ok(inventory.files.len())
}

fn read_inventory(path: &Path) -> Result<Inventory> {
    let inventory = serde_json::from_reader(filesystem::read_file(path)?)
        .map_err(|error| format!("read inventory {}: {error}", path.display()))?;
    inventory_validate(&inventory)?;
    Ok(inventory)
}

fn candidates<'a>(
    old: &'a Inventory,
    new: &Inventory,
    requested: &[PathBuf],
) -> Result<Vec<&'a Entry>> {
    let current: BTreeSet<_> = new.files.iter().map(|entry| &entry.destination).collect();
    let old_names: BTreeMap<_, _> = old
        .files
        .iter()
        .map(|entry| (&entry.destination, entry))
        .collect();
    if requested.is_empty() {
        return Ok(old
            .files
            .iter()
            .filter(|entry| !current.contains(&entry.destination))
            .collect());
    }
    let mut selected = BTreeSet::new();
    for name in requested {
        filesystem::relative(name)?;
        if current.contains(name) {
            return Err(format!("new release owns destination: {}", name.display()));
        }
        if !old_names.contains_key(name) || !selected.insert(name) {
            return Err(format!(
                "unknown or duplicate retirement destination: {}",
                name.display()
            ));
        }
    }
    Ok(selected
        .into_iter()
        .filter_map(|name| old_names.get(name).copied())
        .collect())
}

struct Pending<'a> {
    entry: &'a Entry,
    source_parent: File,
    source: File,
    recovery_name: String,
}

fn preflight<'a>(
    root: &File,
    recovery: &File,
    old: &Inventory,
    selected: &[&'a Entry],
    report: &mut Report,
    recovery_path: &Path,
) -> Result<Vec<Pending<'a>>> {
    let mut pending = Vec::new();
    for entry in selected {
        let identity = format!(
            "{}\0{}\0{}",
            old.repository,
            old.source_commit,
            entry.destination.display()
        );
        let recovery_name = format!(
            "{}-{}",
            old.source_commit,
            filesystem::digest(identity.as_bytes())
        );
        report.planned.push(Retired {
            destination: entry.destination.clone(),
            recovery: recovery_path.join(&recovery_name),
            sha256: entry.sha256.clone(),
            outcome: "planned",
        });
        let prior = filesystem::optional_file(recovery, Path::new(&recovery_name))?;
        let parent = filesystem::optional_parent(root, &entry.destination)?;
        let leaf = Path::new(
            entry
                .destination
                .file_name()
                .ok_or("retirement filename missing")?,
        );
        let source = parent
            .as_ref()
            .map(|parent| filesystem::optional_file(parent, leaf))
            .transpose()?
            .flatten();
        match (source, prior) {
            (Some(source), None) => {
                filesystem::verify(&source, entry)?;
                pending.push(Pending {
                    entry,
                    source_parent: parent.ok_or("retirement parent missing")?,
                    source,
                    recovery_name,
                });
            }
            (None, Some(prior)) => {
                filesystem::verify(&prior, entry)?;
                report.already_retired.push(Retired {
                    destination: entry.destination.clone(),
                    recovery: recovery_path.join(recovery_name),
                    sha256: entry.sha256.clone(),
                    outcome: "already-retired",
                });
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "recovery destination already exists while source remains: {}",
                    entry.destination.display()
                ));
            }
            (None, None) => {
                return Err(format!(
                    "retirement source and recovery are both absent: {}",
                    entry.destination.display()
                ));
            }
        }
    }
    Ok(pending)
}

fn apply(
    pending: Vec<Pending<'_>>,
    recovery: &File,
    args: &RetireArgs,
    report: &mut Report,
) -> Result<()> {
    for item in pending {
        let leaf = Path::new(
            item.entry
                .destination
                .file_name()
                .ok_or("retirement filename missing")?,
        );
        filesystem::move_verified(
            &item.source_parent,
            leaf,
            &item.source,
            recovery,
            Path::new(&item.recovery_name),
            item.entry,
        )?;
        report.changes.push(Retired {
            destination: item.entry.destination.clone(),
            recovery: args.recovery.join(item.recovery_name),
            sha256: item.entry.sha256.clone(),
            outcome: "retired",
        });
        filesystem::publish(&args.report, report)?;
    }
    Ok(())
}

/// Move reviewed old files absent from the new release into a caller-only recovery directory.
///
/// # Errors
/// Refuses digest, ownership, link, source identity, new-release ownership and recovery conflicts.
/// A report records completed moves and a later conflict if a concurrent change prevents completion.
pub fn retire(args: &RetireArgs) -> Result<usize> {
    let old = read_inventory(&args.old_inventory)?;
    let new = read_inventory(&args.new_inventory)?;
    if old.prefix != args.prefix || new.prefix != args.prefix || old.repository != new.repository {
        return Err("inventory repository or prefix identity differs".into());
    }
    let root_path = args.destdir.as_ref().map_or_else(
        || Ok(args.prefix.clone()),
        |stage| staged_root(stage, &args.prefix),
    )?;
    outside(&args.recovery, &[&root_path])?;
    outside(&args.report, &[&root_path, &args.recovery])?;
    if args.report == args.old_inventory || args.report == args.new_inventory {
        return Err("retirement report must preserve both reviewed inventories".into());
    }
    let root = filesystem::directory(&root_path)?;
    let recovery = filesystem::recovery(&args.recovery)?;
    let mut report = Report {
        schema: 1,
        repository: old.repository.clone(),
        old_source_commit: old.source_commit.clone(),
        new_source_commit: new.source_commit.clone(),
        prefix: args.prefix.clone(),
        planned: Vec::new(),
        changes: Vec::new(),
        already_retired: Vec::new(),
        conflict: None,
    };
    let result = candidates(&old, &new, &args.destination)
        .and_then(|selected| {
            preflight(
                &root,
                &recovery,
                &old,
                &selected,
                &mut report,
                &args.recovery,
            )
        })
        .and_then(|pending| {
            filesystem::publish(&args.report, &report)?;
            apply(pending, &recovery, args, &mut report)
        });
    if let Err(error) = &result {
        report.conflict = Some(error.clone());
    }
    filesystem::publish(&args.report, &report)?;
    result?;
    Ok(report
        .changes
        .iter()
        .filter(|change| change.outcome == "retired")
        .count())
}
