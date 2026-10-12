// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Corpus geography: where a share begins, and where a declared surface walks.
//!
//! A census over a corpus has to say where it looks. It used to say so in
//! compiled tables of repository paths, and those tables were a description of
//! somebody else's tree kept inside this binary — which is the arrangement in
//! which a directory is renamed and a tool goes on counting a place that is not
//! there.
//!
//! What replaced them was an experiment: one owner-areas document naming reaches
//! owner-relatively, which every census then resolved against its owner's root.
//! The experiment retired on the ruling that a scan surface is the property of
//! the policy that scans, not of the owner scanned — a policy needing to know
//! what a source is and what a bench is holds that knowledge in its own domain.
//! So a surface now stands in the document of its own policy and spells its
//! places outright, and what is left here is the two questions that survive it.
//!
//! # Partition geography does not declare repository ownership
//!
//! A share's common directory can be derived from its path patterns. That
//! geometry remains useful in fixtures, but it no longer chooses the repository
//! carrier. The owner document explicitly declares `root_owner`; a root-files
//! partition alone cannot substitute for that declaration.
//!
//! # A surface resolves to places, and not to a promise
//!
//! A surface is where a walk starts, and it becomes the places its pattern opens
//! with — including places that are not there, because a surface may name a
//! target directory a package does not carry yet and a reach that quietly forgot
//! it would make the declaration a commitment to create it.
//! A place is a run of whole components over bytes. A partial last component is
//! dropped because the walk is by prefix at component boundaries: a surface
//! opening with `docs/re` walks `docs`. This reach is a locator for the census.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`roots_a_share_where_every_path_it_includes_stands_under`] | areas | An owner's root is the longest run of components every path its partition rows admit stands under, read from the patterns themselves. A share named by one subtree roots at that subtree, a share named by several files under one directory roots at the directory rather than at a file, and a share whose partition rows share no opening roots at the corpus root — which is the true answer for the owner holding the repository's own crate. |
//! | [`opens_a_surface_at_every_place_its_pattern_names`] | areas | A declared surface resolves to the places its pattern opens with, in the order the pattern writes its arms, and a pattern committing to no opening at all is the corpus root entire — which is how a census over the whole repository states its surface without naming one directory of it. The places are taken as written, because a surface stands in the document of the policy that walks it and there is no owner root left to resolve it against. |
//! | [`resolves_an_opening_to_the_place_its_paths_stand_under`] | areas | A surface resolves an opening to whole byte components: a partial final component falls away, a separator preserves the preceding component, and a complete file keeps its own spelling. A non-text byte is retained and displayed reversibly. |

use std::path::PathBuf;

use crate::declaration::AbnfPattern;
use crate::pattern::{BytePath, path_bytes, reversible};

/// The corpus root, as a declaration and a register row both spell it.
pub const CORPUS_ROOT: &str = ".";

/// A corpus root or a run of whole repository-relative path components.
///
/// A component-wise walk can start here without mistaking a partial last
/// component for a directory. The bytes are the same bytes the corpus matches;
/// no native-path or text conversion decides reach.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    /// Every participating path.
    Root,
    /// Whole path components, joined by `/` in their original bytes.
    /// Values built through `from_bytes` obey this rule; a value built directly promises it.
    Run(Vec<u8>),
}

impl Place {
    /// The corpus root.
    #[must_use]
    pub const fn root() -> Self {
        Self::Root
    }

    /// Whether this place reaches the corpus root.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        matches!(self, Self::Root)
    }

    /// The reversible byte display used by declared paths.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Root => CORPUS_ROOT.to_owned(),
            Self::Run(bytes) => reversible(bytes),
        }
    }

    /// Whether a path stands at or below this run of whole components.
    #[must_use]
    pub fn under(&self, path: &BytePath) -> bool {
        match self {
            Self::Root => true,
            Self::Run(bytes) => {
                path.as_bytes() == bytes
                    || path
                        .as_bytes()
                        .strip_prefix(bytes.as_slice())
                        .is_some_and(|tail| tail.first() == Some(&b'/'))
            }
        }
    }

    /// Keep whole components until the first invalid component.
    ///
    /// An opening can contain a separator, an empty component, or traversal
    /// spelling that no corpus path can stand under. Stopping at the first such
    /// component keeps the place a valid locator without inventing a deeper one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut run = Vec::new();
        for component in bytes.split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." || component == b".." {
                break;
            }
            if !run.is_empty() {
                run.push(b'/');
            }
            run.extend_from_slice(component);
        }
        if run.is_empty() {
            Self::Root
        } else {
            Self::Run(run)
        }
    }

    /// The directory containing this place, for a complete file opening.
    #[cfg(test)]
    fn parent(&self) -> Self {
        match self {
            Self::Root => Self::Root,
            Self::Run(bytes) => bytes
                .iter()
                .rposition(|byte| *byte == b'/')
                .map_or(Self::Root, |end| Self::from_bytes(&bytes[..end])),
        }
    }

    /// The longest run of leading components shared with another place.
    #[cfg(test)]
    fn common_prefix(&self, other: &Self) -> Self {
        let (Self::Run(left), Self::Run(right)) = (self, other) else {
            return Self::Root;
        };
        let mut shared = Vec::new();
        for (left, right) in left
            .split(|byte| *byte == b'/')
            .zip(right.split(|byte| *byte == b'/'))
        {
            if left != right {
                break;
            }
            if !shared.is_empty() {
                shared.push(b'/');
            }
            shared.extend_from_slice(left);
        }
        Self::from_bytes(&shared)
    }
}

impl From<PathBuf> for Place {
    /// Read a fixture's native relative spelling as bytes, conservatively using
    /// the corpus root where the platform cannot expose those bytes.
    /// This conversion is safe only for a surface; a leading `.` component ends resolution at the corpus root.
    fn from(path: PathBuf) -> Self {
        path_bytes(&path).map_or_else(Self::root, |bytes| Self::from_bytes(&bytes))
    }
}

/// Resolve an opening to the whole components a component-wise walk can reach.
fn branch_place(branch: &crate::abnf::Branch) -> Place {
    let bytes = branch.bytes();
    if branch.is_complete() || branch.at_boundary() {
        Place::from_bytes(bytes.strip_suffix(b"/").unwrap_or(bytes))
    } else {
        let end = bytes.iter().rposition(|byte| *byte == b'/').unwrap_or(0);
        Place::from_bytes(&bytes[..end])
    }
}

/// The places one declared surface opens with, as the walk reading it meets them.
///
/// A surface stands in the document of the policy whose census walks it, and a
/// policy document has no owner root to resolve against: the corpus writes the
/// places out, and a pattern committing to no opening at all is the corpus root
/// entire — which is how a census over the whole repository is stated without
/// naming one directory of it.
#[must_use]
pub fn places(pattern: &AbnfPattern) -> Vec<Place> {
    pattern.branches().iter().map(branch_place).collect()
}

/// Where a share begins, read from the patterns that say what it includes.
///
/// The answer is the longest run of components every path the owner includes
/// stands under. A complete opening names a file rather than a place, so what it
/// contributes is the directory it stands in; a prefix opening is already the
/// place a reach begins and contributes itself.
#[must_use]
#[cfg(test)]
pub fn partition_root<'a>(patterns: impl IntoIterator<Item = &'a AbnfPattern>) -> Place {
    let mut shared: Option<Place> = None;

    for pattern in patterns {
        for branch in pattern.branches() {
            let place = branch_place(&branch);
            // A complete opening names a file, whose share begins at its directory.
            let place = if branch.is_complete() {
                place.parent()
            } else {
                place
            };
            shared = Some(shared.map_or_else(|| place.clone(), |held| held.common_prefix(&place)));
        }
    }

    shared.unwrap_or_else(Place::root)
}

#[cfg(test)]
mod tests {
    use super::{Place, partition_root, places};
    use crate::declaration::AbnfPattern;
    use crate::pattern::BytePath;

    /// A pattern the declared surface would carry, compiled.
    fn pattern(source: &str) -> AbnfPattern {
        AbnfPattern::parse(source).expect("a pattern of the form")
    }

    fn place(text: &str) -> Place {
        Place::from_bytes(text.as_bytes())
    }

    /// An owner's root is the longest run of components every path its partition
    /// rows admit stands under, read from the patterns themselves. A share named
    /// by one subtree roots at that subtree, a share named by several files under
    /// one directory roots at the directory rather than at a file, and a share
    /// whose partition rows share no opening roots at the corpus root —
    /// which is the true answer for the owner holding the repository's own
    /// crate.
    ///
    /// ´claim:areas:a-root-is-read-off-the-partition´
    /// ´test:unit:roots-a-share-where-every-path-it-includes-stands-under´
    #[test]
    fn roots_a_share_where_every_path_it_includes_stands_under() {
        let subtree = [pattern(r#"%s"packages/project-b" [ "/" *VCHAR ]"#)];

        assert_eq!(partition_root(&subtree), place("packages/project-b"));

        // Several files under one directory root at the directory: a complete
        // opening names a file, and a file is not where a share begins.
        let listed = [pattern(
            r#"%s"contrib/dev-tools/su-exec/" ( %s"LICENSE" / %s"Makefile" / %s"su-exec.c" )"#,
        )];

        assert_eq!(partition_root(&listed), place("contrib/dev-tools/su-exec"));

        // A share reaching several trees and several root files shares no
        // opening at all, so it begins where the repository does.
        let spread = [
            pattern(r#"%s"docs" [ "/" *VCHAR ]"#),
            pattern(r#"%s"src" [ "/" *VCHAR ]"#),
            pattern(r#"%s"AGENTS.md""#),
        ];

        assert_eq!(partition_root(&spread), Place::root());

        // A root is a run of whole components, so two siblings sharing letters
        // root above both rather than inside a name neither carries.
        let siblings = [
            pattern(r#"%s"packages/project-a-config" [ "/" *VCHAR ]"#),
            pattern(r#"%s"packages/project-a-config-probe" [ "/" *VCHAR ]"#),
        ];

        assert_eq!(partition_root(&siblings), place("packages"));

        // An owner including nothing begins nowhere in particular.
        assert_eq!(partition_root([]), Place::root());
    }

    /// A declared surface resolves to the places its pattern opens with, in the
    /// order the pattern writes its arms, and a pattern committing to no opening
    /// at all is the corpus root entire — which is how a census over the whole
    /// repository states its surface without naming one directory of it. The
    /// places are taken as written, because a surface stands in the document of
    /// the policy that walks it and there is no owner root left to resolve it
    /// against.
    ///
    /// ´claim:areas:a-surface-opens-at-the-places-its-pattern-names´
    /// ´test:unit:opens-a-surface-at-every-place-its-pattern-names´
    #[test]
    fn opens_a_surface_at_every_place_its_pattern_names() {
        let member = pattern(r#"%s"packages/project-b/" ( %s"docs" / %s"adr" ) [ "/" *VCHAR ]"#);

        assert_eq!(
            places(&member),
            vec![
                place("packages/project-b/docs"),
                place("packages/project-b/adr")
            ]
        );

        // One tree named alone is one place, spelled where the corpus put it.
        assert_eq!(
            places(&pattern(r#"%s"docs" [ "/" *VCHAR ]"#)),
            vec![place("docs")]
        );

        // A pattern naming no opening is the repository entire.
        assert_eq!(places(&pattern("*VCHAR")), vec![Place::root()]);
    }

    /// A surface resolves an opening to whole byte components: a partial final
    /// component falls away, a separator preserves the preceding component,
    /// and a complete file keeps its own spelling. A non-text byte is retained
    /// and displayed reversibly.
    ///
    /// ´claim:areas:an-opening-becomes-the-place-its-paths-stand-under´
    /// ´test:unit:resolves-an-opening-to-the-place-its-paths-stand-under´
    #[test]
    fn resolves_an_opening_to_the_place_its_paths_stand_under() {
        let partial = pattern(r#"%s"docs/re" *VCHAR"#);
        let boundary = pattern(r#"%s"docs" [ "/" *VCHAR ]"#);
        let file = pattern(r#"%s"docs/readme.md""#);
        let byte_tree = pattern(r#"%xE9 [ "/" *PATHCHAR ]"#);
        let byte_partial = pattern("%xE9 *PATHCHAR");

        assert_eq!(places(&partial), vec![place("docs")]);
        assert_eq!(
            places(&pattern(r#"%s"local" "/" *VCHAR"#)),
            vec![place("local")]
        );
        assert_eq!(places(&boundary), vec![place("docs")]);
        assert_eq!(places(&file), vec![place("docs/readme.md")]);
        assert_eq!(places(&byte_tree), vec![Place::from_bytes(&[0xE9])]);
        assert_eq!(places(&byte_tree)[0].display(), "%E9");
        assert_eq!(places(&byte_partial), vec![Place::root()]);
        assert!(places(&partial)[0].under(&BytePath::from_bytes(b"docs/readme.md").expect("path")));
        assert!(!places(&file)[0].under(&BytePath::from_bytes(b"docs/reader.md").expect("path")));

        assert_eq!(partition_root([&partial]), place("docs"));
        assert_eq!(partition_root([&partial, &file]), place("docs"));
        assert_eq!(partition_root([&byte_tree]), Place::from_bytes(&[0xE9]));
    }
}
