// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! A path name is judged under the encoding its owner declares.
//!
//! The corpus keeps the bytes version control recorded, and every rule decides
//! paths over those bytes. Whether those names should be readable is a house's
//! rule, not a condition for the topology to exist. An owner declares the
//! encoding in which its paths must be well-formed; a house keeping an exception
//! tolerates that path in the policy's path-set list like any other debt.
//!
//! Version control records path bytes, with UTF-8 as the platform convention and arbitrary bytes still possible; a filesystem whose names are not bytes reaches this corpus only through a conversion that already requires UTF-8 text. No step on the way into the corpus converts a name into another encoding, so the policy reads UTF-8 alone. The `encoding` datum remains where a house states its rule and where another encoding could be declared if a path into the corpus ever gives it meaning.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`a_well_formed_name_raises_nothing`] | names | ASCII and UTF-8 names are well-formed in the usual encoding. |
//! | [`a_name_not_well_formed_in_utf_8_is_named_once`] | names | A byte-named path produces one finding with its reversible name and owner. |
//! | [`only_utf_8_is_an_encoding_this_policy_reads`] | names | Only UTF-8 is read as an encoding, and malformed UTF-8 bytes stay malformed. |
//! | [`a_tolerated_path_is_not_raised`] | names | A path in the owner's path-set debt is silent in the check. |
//! | [`an_owner_without_the_activation_is_not_read`] | names | Activation is read per owner: a malformed path under an inactive owner stays silent beside one under an active owner. |
//! | [`violating_paths_is_the_set_the_findings_name`] | names | The audit observes the same one-path identities the check raises. |

use std::collections::{BTreeMap, BTreeSet};

use crate::finding::Finding;
use crate::pattern::BytePath;

/// One encoding an owner can require of the names in its share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Encoding {
    /// UTF-8 is the ordinary answer when no document says otherwise.
    #[default]
    Utf8,
}

impl Encoding {
    /// The spelling an instance document declares and a finding reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
        }
    }

    /// Read one of the encodings this policy understands.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "utf-8" => Some(Self::Utf8),
            _ => None,
        }
    }
}

/// The encodings declared for owners in the optional instance document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NamesParameters {
    /// An absent owner entry reads as UTF-8.
    pub(crate) encodings: BTreeMap<String, Encoding>,
}

impl NamesParameters {
    /// The owner's declared encoding, or UTF-8 where none was written.
    #[must_use]
    pub fn encoding(&self, owner: &str) -> Encoding {
        self.encodings.get(owner).copied().unwrap_or_default()
    }
}

/// Whether raw name bytes are well-formed in the declared encoding.
#[must_use]
pub const fn well_formed(bytes: &[u8], encoding: Encoding) -> bool {
    match encoding {
        Encoding::Utf8 => std::str::from_utf8(bytes).is_ok(),
    }
}

/// One failure per participating path governed by an activated owner's encoding.
#[must_use]
pub fn conform(
    participating: &BTreeSet<BytePath>,
    attribution: &BTreeMap<&BytePath, &str>,
    activated: &BTreeSet<String>,
    parameters: &NamesParameters,
    tolerated: &BTreeSet<&BytePath>,
) -> Vec<Finding> {
    violating_paths(participating, attribution, activated, parameters)
        .into_iter()
        .filter(|path| !tolerated.contains(path))
        .filter_map(|path| {
            let owner = attribution.get(path).copied()?;
            Some(Finding::NonTextName {
                path: path.display(),
                owner: owner.to_owned(),
                encoding: parameters.encoding(owner).as_str(),
            })
        })
        .collect()
}

/// The path-set identities observed before the owner's tolerated list is applied.
#[must_use]
pub fn violating_paths<'a>(
    participating: &'a BTreeSet<BytePath>,
    attribution: &BTreeMap<&BytePath, &str>,
    activated: &BTreeSet<String>,
    parameters: &NamesParameters,
) -> BTreeSet<&'a BytePath> {
    participating
        .iter()
        .filter(|path| {
            let Some(owner) = attribution.get(*path) else {
                return false;
            };
            activated.contains(*owner) && !well_formed(path.as_bytes(), parameters.encoding(owner))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Encoding, NamesParameters, conform, violating_paths, well_formed};
    use crate::finding::Finding;
    use crate::pattern::BytePath;

    fn paths(names: &[&[u8]]) -> BTreeSet<BytePath> {
        names
            .iter()
            .map(|name| BytePath::from_bytes(name.to_vec()).expect("a relative fixture path"))
            .collect()
    }

    fn attributed<'a>(
        paths: &'a BTreeSet<BytePath>,
        owner: &'a str,
    ) -> BTreeMap<&'a BytePath, &'a str> {
        paths.iter().map(|path| (path, owner)).collect()
    }

    fn active() -> BTreeSet<String> {
        BTreeSet::from([String::from("quarry")])
    }

    /// ASCII and UTF-8 names are well-formed in the usual encoding.
    ///
    /// ´claim:names:a-well-formed-name-raises-nothing´
    /// ´test:unit:a-well-formed-name-raises-nothing´
    #[test]
    fn a_well_formed_name_raises_nothing() {
        let participating = paths(&[b"docs/readme", "src/é".as_bytes()]);
        assert_eq!(
            conform(
                &participating,
                &attributed(&participating, "quarry"),
                &active(),
                &NamesParameters::default(),
                &BTreeSet::new()
            ),
            Vec::<Finding>::new()
        );
    }

    /// A byte-named path produces one finding with its reversible name and owner.
    ///
    /// ´claim:names:a-name-not-well-formed-in-utf-8-is-named-once´
    /// ´test:unit:a-name-not-well-formed-in-utf-8-is-named-once´
    #[test]
    fn a_name_not_well_formed_in_utf_8_is_named_once() {
        let participating = paths(&[b"opaque\xff"]);
        let findings = conform(
            &participating,
            &attributed(&participating, "quarry"),
            &active(),
            &NamesParameters::default(),
            &BTreeSet::new(),
        );
        assert_eq!(findings.len(), 1);
        assert!(
            matches!(&findings[0], Finding::NonTextName { path, owner, encoding } if path == "opaque%FF" && owner == "quarry" && *encoding == "utf-8")
        );
        assert_eq!(
            findings[0].to_string(),
            "path name: opaque%FF: governed under quarry and not well-formed utf-8"
        );
    }

    /// Only UTF-8 is read as an encoding, and malformed UTF-8 bytes stay malformed.
    ///
    /// ´claim:names:only-utf-8-is-an-encoding-this-policy-reads´
    /// ´test:unit:only-utf-8-is-an-encoding-this-policy-reads´
    #[test]
    fn only_utf_8_is_an_encoding_this_policy_reads() {
        assert_eq!(Encoding::parse("utf-8"), Some(Encoding::Utf8));
        assert_eq!(Encoding::parse(concat!("utf-16", "le")), None);
        assert_eq!(Encoding::parse(concat!("utf-16", "be")), None);
        assert_eq!(Encoding::parse("latin-1"), None);
        assert!(well_formed("é".as_bytes(), Encoding::Utf8));
        assert!(!well_formed(&[0xe9, 0x00], Encoding::Utf8));
        assert!(!well_formed(&[0xe9], Encoding::Utf8));
    }

    /// A path in the owner's path-set debt is silent in the check.
    ///
    /// ´claim:names:a-tolerated-path-is-not-raised´
    /// ´test:unit:a-tolerated-path-is-not-raised´
    #[test]
    fn a_tolerated_path_is_not_raised() {
        let participating = paths(&[b"opaque\xff"]);
        let tolerated = participating.iter().collect();
        assert_eq!(
            conform(
                &participating,
                &attributed(&participating, "quarry"),
                &active(),
                &NamesParameters::default(),
                &tolerated
            ),
            Vec::<Finding>::new()
        );
    }

    /// Activation is read per owner: a malformed path under an inactive owner stays silent beside one under an active owner.
    ///
    /// ´claim:names:an-owner-without-the-activation-is-not-read´
    /// ´test:unit:an-owner-without-the-activation-is-not-read´
    #[test]
    fn an_owner_without_the_activation_is_not_read() {
        let participating = paths(&[b"opaque\xff", b"docs/\xff"]);
        let attribution = participating
            .iter()
            .map(|path| {
                (
                    path,
                    if path.as_bytes().starts_with(b"docs/") {
                        "docs"
                    } else {
                        "quarry"
                    },
                )
            })
            .collect();
        let findings = conform(
            &participating,
            &attribution,
            &active(),
            &NamesParameters::default(),
            &BTreeSet::new(),
        );
        assert_eq!(findings.len(), 1);
        assert!(
            matches!(&findings[0], Finding::NonTextName { path, owner, .. } if path == "opaque%FF" && owner == "quarry")
        );
    }

    /// The audit observes the same one-path identities the check raises.
    ///
    /// ´claim:names:violating-paths-is-the-set-the-findings-name´
    /// ´test:unit:violating-paths-is-the-set-the-findings-name´
    #[test]
    fn violating_paths_is_the_set_the_findings_name() {
        let participating = paths(&[b"docs/readme", b"opaque\xff"]);
        let attribution = attributed(&participating, "quarry");
        let observed = violating_paths(
            &participating,
            &attribution,
            &active(),
            &NamesParameters::default(),
        );
        let findings = conform(
            &participating,
            &attribution,
            &active(),
            &NamesParameters::default(),
            &BTreeSet::new(),
        );
        let finding_paths: Option<BTreeSet<_>> = findings
            .iter()
            .map(|finding| match finding {
                Finding::NonTextName { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            observed
                .iter()
                .map(|path| path.display())
                .collect::<BTreeSet<_>>(),
            finding_paths.expect("all findings are non-text names")
        );
    }
}
