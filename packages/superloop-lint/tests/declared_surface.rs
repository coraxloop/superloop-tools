// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`the_repository_snapshot_loads_as_one_exact_surface`] | declarations | The repository exposes exactly the fixed and parameter declaration documents, while the imports directory belongs to the registry loader; every envelope parses independently, and the atomic loader accepts their joined snapshot with 35 partitions, 54 may-cite rows and four list rows. The declared environment relation is also the exact relation the imported generic snapshot publishes, with the generic title genres held as extensions. # Panics Panics only when this checkout cannot be read or parsed, or when its declared surface differs from the repository facts asserted here. |

//! Repository declaration-loading integration tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use superloop_lint::{KindRelation, Pair, Rows, configuration};

const DOCUMENTS: [(&str, &str); 10] = [
    (
        "environments.toml",
        "org.superloop-tools.linter.environments",
    ),
    ("lists.toml", "class.linter.lists"),
    ("owners.toml", "org.superloop-tools.linter.owners"),
    ("policies.toml", "org.superloop-tools.linter.policies"),
    (
        "policy-legacy-todos.toml",
        "class.linter.policy.legacy.todos",
    ),
    ("policy-owner-names.toml", "class.linter.policy.owner.names"),
    (
        "policy-public-pack-tools.toml",
        "class.linter.policy.public-pack.values-absent",
    ),
    (
        "policy-references-path-linking.toml",
        "class.linter.policy.references.path-linking",
    ),
    ("policy-spdx.toml", "class.linter.policy.spdx"),
    ("shape.toml", "org.superloop-tools.linter.shape"),
];

/// The generic repository's owner, whose snapshot under the imports directory
/// publishes the kind relation this tree's own must equal.
const IMPORTED_OWNER: &str = "ORCHESTRATION";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The environment pairs of a kind relation's rows, either its adopted
/// environments or its local extensions.
fn relation_pairs(relation: &KindRelation, extensions: bool) -> BTreeSet<(String, String)> {
    let rows = if extensions {
        &relation.extensions
    } else {
        &relation.environments
    };

    rows.iter()
        .map(|row| (row.environment.clone(), row.kind.clone()))
        .collect()
}

/// The repository exposes exactly the fixed and parameter declaration documents,
/// while the imports directory belongs to the registry loader; every envelope
/// parses independently, and the atomic loader accepts their joined snapshot
/// with 35 partitions, 54 may-cite rows and four list rows.
/// The declared environment relation is also the exact relation the imported
/// generic snapshot publishes, with the generic title genres held as extensions.
///
/// # Panics
///
/// Panics only when this checkout cannot be read or parsed, or when its declared
/// surface differs from the repository facts asserted here.
///
/// ´claim:declarations:the-repository-snapshot-loads-as-one-exact-surface´
/// ´test:integration:the-repository-snapshot-loads-as-one-exact-surface´
#[test]
fn the_repository_snapshot_loads_as_one_exact_surface() {
    let root = repository_root();
    let declaration_root = root.join(".linter");
    let expected: BTreeMap<String, String> = DOCUMENTS
        .into_iter()
        .map(|(file, namespace)| (file.to_owned(), namespace.to_owned()))
        .collect();
    let mut found = BTreeMap::new();

    for entry in fs::read_dir(&declaration_root).expect("read declaration directory") {
        let entry = entry.expect("read declaration entry");
        let file = entry
            .file_name()
            .into_string()
            .expect("declaration filename is text");
        if file == "imports" && entry.file_type().expect("declaration entry type").is_dir() {
            continue;
        }
        let text = fs::read_to_string(entry.path()).expect("read declaration");
        let envelope = toml::from_str::<toml::Table>(&text).expect("parse declaration");
        let namespace = envelope
            .get("namespace")
            .and_then(toml::Value::as_str)
            .expect("declaration namespace")
            .to_owned();
        let version: Vec<i64> = envelope
            .get("version")
            .and_then(toml::Value::as_array)
            .expect("declaration version")
            .iter()
            .map(|part| part.as_integer().expect("numeric version part"))
            .collect();

        assert_eq!(version, [1, 0, 0]);
        assert!(found.insert(file, namespace).is_none());
    }

    assert_eq!(found, expected);

    let loaded = configuration(&root);
    assert!(loaded.refusals().is_empty(), "{:?}", loaded.refusals());
    let snapshot = loaded.snapshot().expect("accepted declaration snapshot");

    assert_eq!(snapshot.owners().len(), 28 + snapshot.imports().len());
    assert_eq!(snapshot.partitions().len(), 35);
    assert_eq!(snapshot.may_cite().len(), 54);
    assert_eq!(snapshot.environments().len(), 349);
    assert_eq!(snapshot.environment_extensions().len(), 9);
    let list_keys = snapshot.list_keys();
    let gateway_projections = [
        Pair::singleton("LANEGATEWAY", "projection.test-indexes-current"),
        Pair::singleton("LANEGATEWAY", "projection.test-matrices-current"),
    ];

    assert_eq!(snapshot.policies().len(), 300);
    assert_eq!(list_keys.len(), 300);
    for pair in gateway_projections {
        assert!(snapshot.policies().contains(&pair));
        assert!(list_keys.contains(&pair));
    }
    assert_eq!(snapshot.lists().values().map(Rows::len).sum::<usize>(), 4);

    let imported = snapshot
        .imports()
        .get(IMPORTED_OWNER)
        .expect("imported generic registry");
    let imported_rows = relation_pairs(&imported.kinds, false);
    let declared_rows: BTreeSet<(String, String)> = snapshot
        .environments()
        .iter()
        .map(|row| (row.environment.clone(), row.kind.clone()))
        .collect();
    let imported_reserved: BTreeSet<String> = imported.kinds.reserved.iter().cloned().collect();

    assert_eq!(declared_rows, imported_rows);
    assert_eq!(snapshot.reserved_kinds(), &imported_reserved);

    let extensions: BTreeSet<(String, String)> = snapshot
        .environment_extensions()
        .iter()
        .map(|row| (row.environment.clone(), row.kind.clone()))
        .collect();
    let expected_extensions = [
        ("Constant", "const"),
        ("Document", "guide"),
        ("Document", "plan"),
        ("Document", "proposal"),
        ("Document", "rec"),
        ("Document", "reg"),
        ("Document", "rep"),
        ("Document", "spec"),
        ("To-do", "todo"),
    ]
    .into_iter()
    .map(|(environment, kind)| (environment.to_owned(), kind.to_owned()))
    .collect();

    let imported_extensions = relation_pairs(&imported.kinds, true);

    assert_eq!(extensions, expected_extensions);
    assert_eq!(extensions, imported_extensions);
    assert_eq!(
        snapshot.reserved_extensions(),
        &BTreeSet::from(["const".to_owned(), "todo".to_owned()])
    );
}
