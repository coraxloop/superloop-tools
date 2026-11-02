// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`the_repository_owner_surface_reconciles_in_both_directions`] | owners | The declared partition attributes every live path exactly once to the 27 manifest owners and the crateless repository owner, with the declared shape exclusions and the imported generic owner added without a partition; its 38 crate-to-crate may-cite rows equal internal path dependencies, its ten edges to the imported generic owner are declaration-authoritative and reach no partition of this tree, seven edges reach the crateless repository owner, and no imported owner receives a manifest edge. # Panics Panics only when this checkout cannot be read or parsed, or when its owner, partition, crate-name, or direct-reach facts diverge from the declaration. |

//! Repository owner-partition and manifest-reach integration tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use superloop_lint::{ExecutionPlan, configuration};

const DEPENDENCY_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// The crateless owner of everything in this tree that no package owns.
const REPOSITORY_OWNER: &str = "TOOLS";

/// The generic repository's owner, resolved from its snapshot under imports.
const IMPORTED_OWNER: &str = "ORCHESTRATION";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest(path: &Path) -> toml::Table {
    let text = fs::read_to_string(path).expect("read manifest");
    toml::from_str(&text).expect("parse manifest")
}

fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
            Component::Prefix(_) | Component::RootDir => {
                panic!("repository dependency paths are relative")
            }
        }
    }

    normalized
}

fn reconcile_partition(plan: &ExecutionPlan) -> BTreeMap<PathBuf, String> {
    let snapshot = plan.snapshot();
    let corpus = plan.topology().corpus();
    let partition = plan.topology().partition();

    assert!(corpus.findings().is_empty(), "{:?}", corpus.findings());
    assert!(
        partition.findings().is_empty(),
        "{:?}",
        partition.findings()
    );
    assert_eq!(partition.counts().excluded, corpus.ignored().len());
    let fixed_ignores: BTreeMap<_, _> = corpus
        .ignored_by()
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "build-target" | "meson-build"))
        .map(|(name, count)| (name.as_str(), *count))
        .collect();
    let mut expected_ignores = BTreeMap::from([("test-fixtures", 5)]);
    if plan.root().join("Cargo.lock").exists() {
        expected_ignores.insert("consumer-lockfile", 1);
    }
    assert_eq!(fixed_ignores, expected_ignores);
    assert_eq!(partition.counts().unaccounted, 0);
    assert_eq!(partition.counts().multiply_accounted, 0);
    assert_eq!(partition.counts().surviving, partition.counts().accounted);
    assert_eq!(corpus.participating().len(), partition.attribution().len());

    let names = snapshot
        .declared_owner_names()
        .expect("declared owner-name derivation");
    let mut owner_by_directory = BTreeMap::new();

    for package in plan.workspace().packages() {
        let owner = names
            .derive(package.name())
            .expect("derivable crate owner")
            .to_string();
        assert!(
            owner_by_directory
                .insert(package.directory().to_path_buf(), owner)
                .is_none()
        );
    }

    let derived_owners: BTreeSet<String> = owner_by_directory.values().cloned().collect();
    let declared_owners: BTreeSet<String> = snapshot.owners().iter().cloned().collect();
    let imported_owners: BTreeSet<String> = snapshot.imports().keys().cloned().collect();
    let mut expected_owners = derived_owners;
    expected_owners.insert(REPOSITORY_OWNER.to_owned());
    assert_eq!(imported_owners, BTreeSet::from([IMPORTED_OWNER.to_owned()]));
    expected_owners.extend(imported_owners);
    assert_eq!(expected_owners, declared_owners);
    assert_eq!(owner_by_directory.len(), 27);
    assert_eq!(plan.workspace().findings().len(), 0);

    let mut path_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (path, owner) in partition.attribution() {
        let native = Path::new(std::str::from_utf8(path.as_bytes()).expect("tracked text path"));
        let expected = owner_by_directory
            .iter()
            .find_map(|(directory, owner)| native.starts_with(directory).then_some(owner))
            .map_or_else(
                || {
                    if native.starts_with("ci") {
                        "SUPERLOOPLINT"
                    } else {
                        REPOSITORY_OWNER
                    }
                },
                String::as_str,
            );

        assert_eq!(owner, expected, "{}", path.display());
        *path_counts.entry(owner.clone()).or_default() += 1;
    }
    assert_eq!(path_counts.len(), 28);
    assert!(path_counts.values().all(|count| *count > 0));

    owner_by_directory
}

fn manifest_reach(
    root: &Path,
    plan: &ExecutionPlan,
    owner_by_directory: &BTreeMap<PathBuf, String>,
) -> BTreeSet<(String, String)> {
    let root_manifest = manifest(&root.join("Cargo.toml"));
    let workspace_dependencies = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .expect("workspace dependencies");
    let internal_by_directory: BTreeMap<PathBuf, String> = owner_by_directory
        .iter()
        .map(|(directory, owner)| (normalize(directory), owner.clone()))
        .collect();
    let mut derived_reach = BTreeSet::new();

    for package in plan.workspace().packages() {
        let source = owner_by_directory
            .get(package.directory())
            .expect("source owner");
        let member_manifest = manifest(&root.join(package.directory()).join("Cargo.toml"));

        for table_name in DEPENDENCY_TABLES {
            let Some(dependencies) = member_manifest
                .get(table_name)
                .and_then(toml::Value::as_table)
            else {
                continue;
            };

            for (dependency_name, dependency) in dependencies {
                let Some(dependency) = dependency.as_table() else {
                    continue;
                };
                let inherited = dependency
                    .get("workspace")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or_default();
                let declared_path = if inherited {
                    workspace_dependencies
                        .get(dependency_name)
                        .and_then(toml::Value::as_table)
                        .and_then(|entry| entry.get("path"))
                        .and_then(toml::Value::as_str)
                        .map(PathBuf::from)
                } else {
                    dependency
                        .get("path")
                        .and_then(toml::Value::as_str)
                        .map(|path| package.directory().join(path))
                };
                let Some(target) = declared_path
                    .as_deref()
                    .map(normalize)
                    .and_then(|path| internal_by_directory.get(&path))
                else {
                    continue;
                };

                if source != target {
                    derived_reach.insert((source.clone(), target.clone()));
                }
            }
        }
    }

    derived_reach
}

/// The declared partition attributes every live path exactly once to the
/// 27 manifest owners and the crateless repository owner, with the declared shape
/// exclusions and the imported generic owner added without a partition;
/// its 38 crate-to-crate may-cite rows equal internal path dependencies,
/// its ten edges to the imported
/// generic owner are declaration-authoritative and reach no partition of this
/// tree, seven edges reach the crateless repository owner, and no imported owner
/// receives a manifest edge.
///
/// # Panics
///
/// Panics only when this checkout cannot be read or parsed, or when its owner,
/// partition, crate-name, or direct-reach facts diverge from the declaration.
///
/// ´claim:owners:the-repository-owner-surface-reconciles-in-both-directions´
/// ´test:integration:the-repository-owner-surface-reconciles-in-both-directions´
#[test]
fn the_repository_owner_surface_reconciles_in_both_directions() {
    let root = repository_root();
    let plan = ExecutionPlan::compile(&root, configuration(&root)).expect("repository plan");
    let snapshot = plan.snapshot();
    let owner_by_directory = reconcile_partition(&plan);
    let derived_reach = manifest_reach(&root, &plan, &owner_by_directory);
    let imported_owners: BTreeSet<String> = snapshot.imports().keys().cloned().collect();

    let declared_reach: BTreeSet<(String, String)> = snapshot
        .may_cite()
        .iter()
        .map(|row| (row.owner.clone(), row.target.clone()))
        .collect();

    let (crateless_reach, crate_reach): (BTreeSet<_>, BTreeSet<_>) = declared_reach
        .iter()
        .cloned()
        .partition(|(_owner, target)| {
            target == REPOSITORY_OWNER || imported_owners.contains(target)
        });
    let imported_reach: BTreeSet<_> = crateless_reach
        .iter()
        .filter(|(_owner, target)| imported_owners.contains(target))
        .cloned()
        .collect();
    let repository_reach: BTreeSet<_> = crateless_reach
        .difference(&imported_reach)
        .cloned()
        .collect();
    let expected_imported_reach = BTreeSet::from([
        ("BUILDSYNC".to_owned(), IMPORTED_OWNER.to_owned()),
        ("SUPERLOOPCHATEXPORT".to_owned(), IMPORTED_OWNER.to_owned()),
        ("SUPERLOOPLANE".to_owned(), IMPORTED_OWNER.to_owned()),
        ("SUPERLOOPCLAUDEHOOK".to_owned(), IMPORTED_OWNER.to_owned()),
        ("LANELIFECYCLE".to_owned(), IMPORTED_OWNER.to_owned()),
        ("SUPERLOOPGATESUBMIT".to_owned(), IMPORTED_OWNER.to_owned()),
        ("SUPERLOOPLINT".to_owned(), IMPORTED_OWNER.to_owned()),
        ("PERMISSIONTRIAGE".to_owned(), IMPORTED_OWNER.to_owned()),
        ("RUNWORKER".to_owned(), IMPORTED_OWNER.to_owned()),
        ("TOOLS".to_owned(), IMPORTED_OWNER.to_owned()),
    ]);

    assert!(
        derived_reach
            .iter()
            .all(|(_owner, target)| !imported_owners.contains(target))
    );
    assert_eq!(derived_reach, crate_reach);
    assert_eq!(imported_reach, expected_imported_reach);
    let expected_repository_reach = BTreeSet::from([
        ("PERMISSIONTRIAGE".to_owned(), REPOSITORY_OWNER.to_owned()),
        (
            "SUPERLOOPCHATEXPORT".to_owned(),
            REPOSITORY_OWNER.to_owned(),
        ),
        ("SUPERLOOPINSTALL".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("SUPERLOOPPACK".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("LOOPHOME".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("EXECUTECOMMAND".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("BUILDSYNC".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("SUPERLOOPLANE".to_owned(), REPOSITORY_OWNER.to_owned()),
        (
            "SUPERLOOPCLAUDEHOOK".to_owned(),
            REPOSITORY_OWNER.to_owned(),
        ),
        (
            "SUPERLOOPGATESUBMIT".to_owned(),
            REPOSITORY_OWNER.to_owned(),
        ),
        ("SUPERLOOPLINT".to_owned(), REPOSITORY_OWNER.to_owned()),
        ("SUPERLOOPLANE".to_owned(), REPOSITORY_OWNER.to_owned()),
    ]);
    assert_eq!(repository_reach, expected_repository_reach);
    assert_eq!(
        declared_reach.len(),
        38 + imported_reach.len() + repository_reach.len()
    );
}
