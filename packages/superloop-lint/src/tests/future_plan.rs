// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Test-only specifications salvaged for the future execution-plan bite.
//!
//! These helpers deliberately do not form a production resolver. They preserve
//! the useful union and topology algorithms while the dead resolver is retired,
//! so the later plan compiler has executable specifications without a shadow
//! production route.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`future_plan_unions_namespaces_before_programmes`] | catalogue | Namespace identity is established over the declaration union before any programme is selected, adopted kinds select programmes, and uncatalogued kinds remain inert. |
//! | [`future_plan_bounds_selection_by_owner_then_subtracts`] | catalogue | Topology first bounds a source to its owner's share, then admits by the entry pattern and subtracts the section-wide exclusion. |
//! | [`future_plan_admits_a_non_text_path_by_its_bytes`] | catalogue | A path is the bytes version control recorded, and a rule decides those bytes. The path-byte row admits this name into its share, while the visible-character row leaves it outside by its own declared pattern. |
//! | [`future_plan_detects_overlap_only_on_shared_sources`] | catalogue | Two compiled prefix domains conflict only where their resolved source memberships intersect. |

use std::collections::{BTreeMap, BTreeSet};

use crate::catalogue::program_of;
use crate::declaration::{AbnfPattern, Declaration};
use crate::pattern::BytePath;
use crate::program::{PrefixBound, PrefixNumbers};

/// One test-only ownership bound.
struct Ownership {
    owner: &'static str,
    pattern: AbnfPattern,
}

/// Decode a relative display for an invented corpus.
fn path(display: &str) -> BytePath {
    BytePath::from_bytes(display.as_bytes()).expect("a relative fixture path")
}

/// Index declaration identities over the whole union.
fn namespaces(declarations: &[Declaration]) -> Result<BTreeMap<&str, &Declaration>, String> {
    let mut indexed = BTreeMap::new();

    for declaration in declarations {
        if indexed
            .insert(declaration.namespace(), declaration)
            .is_some()
        {
            return Err(format!(
                "{}: two documents stamp this identity",
                declaration.namespace()
            ));
        }
    }

    Ok(indexed)
}

/// The programmes a declaration's adopted kinds activate.
fn programmes(declaration: &Declaration) -> BTreeSet<&'static str> {
    declaration
        .sets()
        .keys()
        .filter_map(|set| program_of(set))
        .collect()
}

/// Resolve the share of one owner from the compiled ownership rows.
fn share(owner: &str, ownership: &[Ownership], paths: &[BytePath]) -> BTreeSet<BytePath> {
    paths
        .iter()
        .filter(|path| {
            ownership
                .iter()
                .any(|row| row.owner == owner && row.pattern.admits_path(path))
        })
        .cloned()
        .collect()
}

/// Reach one relation inside an already-resolved owner share.
fn reached(
    paths: &[BytePath],
    share: &BTreeSet<BytePath>,
    patterns: &[AbnfPattern],
) -> BTreeSet<BytePath> {
    paths
        .iter()
        .filter(|path| share.contains(*path))
        .filter(|path| patterns.iter().any(|pattern| pattern.admits_path(path)))
        .cloned()
        .collect()
}

/// Admit by the entry and subtract the section's exclusion union.
fn selected(
    paths: &[BytePath],
    owner_share: &BTreeSet<BytePath>,
    include: &[AbnfPattern],
    exclude: &[AbnfPattern],
) -> BTreeSet<BytePath> {
    let admitted = reached(paths, owner_share, include);
    let removed = reached(paths, owner_share, exclude);

    admitted.difference(&removed).cloned().collect()
}

/// Whether two prefix-number runs could read one occurrence.
fn overlaps(
    one: &PrefixNumbers,
    one_sources: &BTreeSet<BytePath>,
    other: &PrefixNumbers,
    other_sources: &BTreeSet<BytePath>,
) -> bool {
    one.overlaps(other) && one_sources.intersection(other_sources).next().is_some()
}

/// Namespace identity is established over the declaration union before any
/// programme is selected, adopted kinds select programmes, and uncatalogued
/// kinds remain inert.
///
/// ´claim:catalogue:future-plan-namespace-union-precedes-programme-selection´
/// ´test:crate:future-plan-unions-namespaces-before-programmes´
#[test]
fn future_plan_unions_namespaces_before_programmes() {
    let adopted = Declaration::decode(
        r#"
namespace = "class.linter.policy.references.divisions"
version = [1, 0, 0]

[set.literals]
information = "Information flows strictly forward"
"#,
    )
    .expect("an adopted fixture");
    let uncatalogued = Declaration::decode(
        r#"
namespace = "example.owner.extension"
version = [1, 0, 0]

[set.uncatalogued-shape]
kept = "not this binary's adoption decision"
"#,
    )
    .expect("an uncatalogued set remains a declaration");

    let declarations = [adopted.clone(), uncatalogued];
    let indexed = namespaces(&declarations).expect("distinct namespace identities");

    assert_eq!(indexed.len(), declarations.len());
    assert_eq!(
        programmes(&adopted),
        BTreeSet::from(["references.literal-set-absent"])
    );
    assert!(programmes(indexed["example.owner.extension"]).is_empty());

    assert_eq!(
        namespaces(&[adopted.clone(), adopted]).expect_err("one identity claimed twice"),
        "class.linter.policy.references.divisions: two documents stamp this identity"
    );
}

/// Topology first bounds a source to its owner's share, then admits by the
/// entry pattern and subtracts the section-wide exclusion.
///
/// ´claim:catalogue:future-plan-selection-is-owner-bounded-and-subtractive´
/// ´test:crate:future-plan-bounds-selection-by-owner-then-subtracts´
#[test]
fn future_plan_bounds_selection_by_owner_then_subtracts() {
    let paths = [
        path("quarry/docs/slate.md"),
        path("quarry/docs/notes/draft.md"),
        path("quarry/src/lode.rs"),
        path("spoil/docs/heap.md"),
    ];
    let ownership = [
        Ownership {
            owner: "QUARRY",
            pattern: AbnfPattern::parse(r#"%s"quarry" [ "/" *VCHAR ]"#).expect("the quarry bound"),
        },
        Ownership {
            owner: "SPOIL",
            pattern: AbnfPattern::parse(r#"%s"spoil" [ "/" *VCHAR ]"#).expect("the spoil bound"),
        },
    ];
    let quarry = share("QUARRY", &ownership, &paths);
    let chosen = selected(
        &paths,
        &quarry,
        &[AbnfPattern::parse(r#"%s"quarry" [ "/" *VCHAR ]"#).expect("the inclusion")],
        &[AbnfPattern::parse(r#"%s"quarry/docs/notes" [ "/" *VCHAR ]"#).expect("the exclusion")],
    );
    let displays: Vec<_> = chosen.iter().map(BytePath::display).collect();

    assert_eq!(
        displays,
        [
            "quarry/docs/slate.md".to_owned(),
            "quarry/src/lode.rs".to_owned()
        ]
    );
}

/// A path is the bytes version control recorded, and a rule decides those
/// bytes. The path-byte row admits this name into its share, while the
/// visible-character row leaves it outside by its own declared pattern.
///
/// ´claim:catalogue:future-plan-decides-a-non-text-path-by-its-bytes´
/// ´test:crate:future-plan-admits-a-non-text-path-by-its-bytes´
#[test]
fn future_plan_admits_a_non_text_path_by_its_bytes() {
    let opaque = BytePath::from_bytes(vec![
        b'q', b'u', b'a', b'r', b'r', b'y', b'/', 0xff, b'.', b'm', b'd',
    ])
    .expect("a relative byte path");
    let paths = [opaque.clone()];
    let ownership = [
        Ownership {
            owner: "BYTES",
            pattern: AbnfPattern::parse(r#"%s"quarry" [ "/" *PATHCHAR ]"#)
                .expect("the path-byte bound"),
        },
        Ownership {
            owner: "VISIBLE",
            pattern: AbnfPattern::parse(r#"%s"quarry" [ "/" *VCHAR ]"#)
                .expect("the visible-character bound"),
        },
    ];

    assert!(share("BYTES", &ownership, &paths).contains(&opaque));
    assert!(!share("VISIBLE", &ownership, &paths).contains(&opaque));
}

/// Two compiled prefix domains conflict only where their resolved source
/// memberships intersect.
///
/// ´claim:catalogue:future-plan-overlap-is-domain-and-membership-intersection´
/// ´test:crate:future-plan-detects-overlap-only-on-shared-sources´
#[test]
fn future_plan_detects_overlap_only_on_shared_sources() {
    let range = PrefixNumbers::new(
        "L-",
        PrefixBound::LeadingRange {
            minimum: 1,
            maximum: 30,
        },
        true,
    );
    let set = PrefixNumbers::new("L-", PrefixBound::LeadingSet(vec![4, 9]), true);
    let prose = BTreeSet::from([path("quarry/docs/slate.md")]);
    let same = BTreeSet::from([path("quarry/docs/slate.md")]);
    let code = BTreeSet::from([path("quarry/src/lode.rs")]);

    assert!(overlaps(&range, &prose, &set, &same));
    assert!(!overlaps(&range, &prose, &set, &code));
}
