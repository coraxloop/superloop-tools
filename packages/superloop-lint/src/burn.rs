// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Burn lists: a legacy reference family, censused, and a ratchet that may only
//! shrink.
//!
//! The burn discipline (´[TOOLS-rule:lintcontracts:burn-families]´) requires that
//! every legacy reference family is enumerated exactly and that the enumeration
//! is a ratchet: a new occurrence anywhere is a failure, and a vanished
//! occurrence must leave the enumeration in the same commit. This module is that
//! verification.
//!
//! # Where the enumeration stands
//!
//! It stands in the canonical list document, keyed by owner and program like
//! every other tolerated debt. It used to stand in a generated register document
//! per family, and those registers retired: content that was an argument became a
//! record, content that was a ratchet became these rows, and no declaration
//! points at a file (´[TOOLS-rule:lintcontracts:declarations]´). What the gate compares did not
//! change with them — it is the register-equals-census relation over the same
//! numbers, asked of the list.
//!
//! A family declared over the corpus root is keyed to the root owner rather than
//! to the owner of each file it counts, because the ratchet such a census earns is
//! one repository-wide artifact that no member can repair alone
//! (´[TOOLS-rule:lintcontracts:ownership]´).
//!
//! # Why an enumeration rather than a count
//!
//! A gate could hold the corpus to a total and be simpler. It would also be
//! nearly useless, because a total lets one file lose a reference while another
//! gains one and calls the trade clean — which is exactly the motion a migration
//! must not make. The ratchet is per file, so it holds file by file, and a commit
//! that migrates one document cannot pay for a regression in another.
//!
//! # Why per file and not per occurrence
//!
//! The alternative is a row per occurrence, naming it by line. It is exact, and it
//! churns: an unrelated edit at the top of a document moves every line number
//! below it, and the diff then hides the one change that matters among hundreds
//! that do not. A per-file count is invariant under every edit that does not
//! change what the file references, which is the property a reviewer needs to read
//! the diff at all, and it is still exact enough to ratchet — a file may only be
//! listed at its count or lower, and a file not listed may hold none.
//!
//! Locations are not lost by this: the census knows them, and reports them in the
//! finding that names a violation.
//!
//! # Both directions, and why the stale half matters
//!
//! Growth is the obvious failure. Shrinkage without a list edit is the subtle
//! one, and it is a failure here for the reason outline tracking checks its
//! relation both ways: a ratchet that is allowed to overstate quietly becomes a
//! declaration about a corpus that no longer exists, and the ratchet it is
//! supposed to be turns into a ceiling nobody has measured. So a file whose
//! occurrences have fallen is a failure until the list falls with it, in the same
//! commit that removed them.
//!
//! # The recognizers are the lint's own
//!
//! The shapes a burn list counts are the shapes the migration lint reports, read
//! by the same code. Prose is read by the lint's Markdown reader, so a form in
//! code font or a fenced block is displayed rather than referenced, exactly as
//! the lint has it. Rust sources are read for their comments alone, and the
//! comments are read by the recognizer the lint uses on running text. A census
//! that recognized the forms its own way would eventually disagree with the gate
//! about what a reference is, and a ratchet cannot survive that.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`a_register_row_meets_the_tally_of_a_name_outside_the_plain_set`] | burn | A path containing a space meets its declared count in the reversible display, and growth names that same path when no row declares it. # Panics Panics only if the fixed temporary fixture cannot be written. |
//! | [`a_surface_reaches_the_paths_under_a_partial_opening`] | burn | A surface opening inside a file component starts its census at the containing directory, so both admitted paths beneath that locator are read. # Panics Panics only if the fixed temporary fixture cannot be written. |
//! | [`a_surface_opening_with_bytes_that_are_not_text_reaches_only_its_own_tree`] | burn | A surface opening with a non-text byte keeps that byte as its place and reads only paths beneath its own tree. # Panics Panics only if the fixed temporary fixture cannot be written. |
//!
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::areas::Place;
use crate::catalogue::{CATALOG, Observer, PUBLIC_PACK_BURN_FAMILY, catalogued};
use crate::declaration::AbnfPattern;
use crate::finding::{Finding, Location};
use crate::legacy::{LegacyRule, scan_legacy, scan_regions};
use crate::legacy_profile::{LegacySite, is_production_source, scan_legacy_sites};
use crate::pattern::BytePath;
use crate::plan::CorpusPlan;
use crate::program::{LiteralSet, MarkNumbered, PrefixNumbers};
use crate::residual::{
    Residual, scan_residual_comments, scan_residual_markdown, scan_residual_script,
};
use crate::retired::{Retired, RetiredFamily, scan_retired_markdown, scan_retired_text};
use crate::snapshot::{DIRECTORY, LISTS_FILE, Rows, Snapshot};
use crate::todo::{TodoNotice, scan_todos};
use crate::token::{Region, markdown_regions, rust_regions};

/// The owner this binary is, whose share no census of this binary's own walks.
///
/// It is the one owner identifier compiled here, and it is compiled because it is
/// self-knowledge rather than a fact about the repository: a checker knows which
/// owner it is the same way it knows its own name, and asking a declaration to
/// tell it would be asking the corpus to say who is judging it. Where that share
/// stands is the corpus's to state and is read from the declared partition at
/// runtime, so nothing here knows a directory (´[TOOLS-rule:lintcontracts:declarations]´).
///
/// ´const:indexlinter:self-owner´ (´[ORCHESTRATION-alg:const:text]´)
/// ´const:indexlinter:self-owner-text-x66bcd86b´
const SELF_OWNER: &str = "SUPERLOOPLINT";

/// The run a repository-scoped family's policy carries beside its per-owner sibling.
///
/// Two policies of one program stand in the catalog wherever a family is censused
/// both ways: one per-owner, activated by the owner whose debt it is, and one over
/// the repository, activated by the owner whose share the repository is. The
/// second's identifier is the first's with this run appended, and that is the
/// whole of what tells them apart here — a compiled fact about this binary's own
/// vocabulary, spelling no repository fact at all.
///
/// The run is what makes a corpus-wide census tellable from a per-owner one
/// without asking a declaration which it is, and the ratchet such a census earns
/// belongs to the root owner for exactly that reason
/// (´[TOOLS-rule:lintcontracts:ownership]´).
///
/// ´const:indexlinter:repository-policy-run´ (´[ORCHESTRATION-alg:const:text]´)
/// ´const:indexlinter:repository-policy-run-text-x8f7cd1cc´
const REPOSITORY_RUN: &str = "-repository";

/// How one value from an external burn document is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Match the value at every byte position, including inside a longer token.
    Substring,
    /// Match unless an ASCII letter stands immediately before or after the value.
    Identifier,
}

/// The declared values by match mode, as a burn report summarizes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MatchModeCounts {
    /// Values matched as substrings.
    pub substring: usize,
    /// Values matched at ASCII-letter boundaries.
    pub identifier: usize,
}

/// One non-empty value from an external burn document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurnValue {
    value: String,
    #[serde(rename = "match")]
    mode: MatchMode,
}

impl BurnValue {
    /// Declare one value directly, for a caller constructing an invented census.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty, because an empty matcher would
    /// occur at every byte boundary and cannot express a burn value.
    pub fn new(value: impl Into<String>, mode: MatchMode) -> Result<Self, BurnDocumentDefect> {
        let value = value.into();

        if value.is_empty() {
            return Err(BurnDocumentDefect::Malformed(String::from(
                "values.value: a burn value is a non-empty string",
            )));
        }

        Ok(Self { value, mode })
    }

    /// The bytes this entry searches for, represented as their declared text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// How the value is bounded at a match.
    #[must_use]
    pub const fn mode(&self) -> MatchMode {
        self.mode
    }
}

/// Why an external burn-value document cannot become a recognizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurnDocumentDefect {
    /// The TOML or one of its entries is malformed.
    Malformed(String),
    /// The document declares no entries, which would make verification vacuous.
    Empty,
}

/// The kind of path from which the effective burn values were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnSourceKind {
    /// The repository-relative document named by the policy declaration.
    Repository,
    /// The outside-tree document supplied to public-pack mode.
    External,
}

/// A census omission, stated in the same terms that name the omitted paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exclusion {
    /// The whole attributed share of an owner, wherever its partition rows reach.
    Share(String),
    /// Exactly the paths a policy-local pattern admits.
    Declared(AbnfPattern),
}

impl Exclusion {
    /// Show the owner or the pattern text as the declaration wrote it.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Share(owner) => owner.clone(),
            Self::Declared(pattern) => pattern.source().to_owned(),
        }
    }
}

/// One activated external-value burn family after its policy and values are resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalBurn {
    surface: Vec<Place>,
    excluded: Vec<Exclusion>,
    values: Vec<BurnValue>,
    source: String,
    source_kind: BurnSourceKind,
}

impl ExternalBurn {
    /// Join a policy-local surface to the value document actually used.
    #[must_use]
    pub fn new(
        surface: Vec<Place>,
        excluded: Vec<Exclusion>,
        values: Vec<BurnValue>,
        source: impl Into<String>,
        source_kind: BurnSourceKind,
    ) -> Self {
        Self {
            surface,
            excluded,
            values,
            source: source.into(),
            source_kind,
        }
    }

    /// The path prefixes the family scans.
    #[must_use]
    pub fn surface(&self) -> &[Place] {
        &self.surface
    }

    /// The policy-local patterns omitted from this family alone.
    #[must_use]
    pub fn excluded(&self) -> &[Exclusion] {
        &self.excluded
    }

    /// The non-empty values supplied by the effective document.
    #[must_use]
    pub fn values(&self) -> &[BurnValue] {
        &self.values
    }

    /// The document path actually read, in the spelling the caller supplied.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Whether the effective document was repository-local or outside the tree.
    #[must_use]
    pub const fn source_kind(&self) -> BurnSourceKind {
        self.source_kind
    }

    /// How many values each match mode declares.
    #[must_use]
    pub fn mode_counts(&self) -> MatchModeCounts {
        let mut counts = MatchModeCounts::default();

        for value in &self.values {
            match value.mode() {
                MatchMode::Substring => counts.substring += 1,
                MatchMode::Identifier => counts.identifier += 1,
            }
        }

        counts
    }
}

/// Decode a non-empty external burn-value document.
///
/// # Errors
///
/// Returns a malformed or empty defect rather than admitting a vacuous scan.
pub fn decode_external_values(source: &str) -> Result<Vec<BurnValue>, BurnDocumentDefect> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        values: Vec<BurnValue>,
    }

    let document: Document =
        toml::from_str(source).map_err(|error| BurnDocumentDefect::Malformed(error.to_string()))?;

    if document.values.is_empty() {
        return Err(BurnDocumentDefect::Empty);
    }

    if document.values.iter().any(|entry| entry.value.is_empty()) {
        return Err(BurnDocumentDefect::Malformed(String::from(
            "values.value: a burn value is a non-empty string",
        )));
    }

    Ok(document.values)
}

/// The burn lists this repository adopted.
///
/// Three open the discipline, one per legacy family a migration campaign
/// retires — section references, retired record numbers and superseded tag
/// forms — each enumerated in a register the linter verifies exactly, a ratchet
/// that may only shrink (´[TOOLS-rule:lintcontracts:burn-families]´). A fourth reads
/// the record shape the other three cannot: a number written with no series at
/// all, which is ambiguous between the corpus that keeps its numbers and the
/// local numbering that retired. It is declared beside the lettered family
/// rather than folded into it, because a family is a bounded shape and
/// broadening one to admit a second shape leaves neither bounded
/// (´[TOOLS-rule:lintcontracts:burn-families]´) — and because the two are swept by
/// different judgments, the lettered form by rewriting a citation and the bare
/// one by first finding which record was meant. A fifth counts
/// an inventory profile's remainder rather than a reference family, under the
/// policy ADR-T-016 records
/// (´[TOOLS-rule:lintcontracts:burn-families]´). The remaining two are
/// the families the scenario matrix took with it when it retired, each
/// declaring its own recogniser and surface beside its register — the scenario
/// numbers bounded by range and the division names by enumeration, which are
/// the two bounding devices the family convention licenses
/// (´[TOOLS-rule:lintcontracts:burn-families]´).
///
/// Each declares what it counts and nothing about where. Where a family's census
/// walks is the corpus's to state, and the corpus states it in the document of
/// the policy that activates the census — because if a policy needs to know what
/// a source is and what a bench is, that knowledge belongs to the domain of that
/// policy. So a family is joined to its policy through the catalog and asks that
/// policy's own document for its surface; nothing here knows a directory, a reach
/// name or an owner's geography (´[TOOLS-rule:lintcontracts:burn-families]´).
///
/// ´const:indexlinter:adopted-burn-lists´ (´[ORCHESTRATION-alg:const:form]´)
/// ´const:indexlinter:adopted-burn-lists-form-x34de554d´
const BURN_LISTS: &[Declaration] = &[
    Declaration {
        family: "section-sign references",
        shape: Shape::Legacy(&[LegacyRule::SectionNumber]),
    },
    Declaration {
        family: "retired record numbers",
        shape: Shape::Legacy(&[LegacyRule::RecordNumber]),
    },
    Declaration {
        family: "ambiguous unprefixed record numbers",
        shape: Shape::Legacy(&[LegacyRule::UnprefixedRecordNumber]),
    },
    Declaration {
        family: "superseded tag forms",
        shape: Shape::Legacy(&[LegacyRule::TagForm]),
    },
    Declaration {
        family: "retired scenario numbers",
        shape: Shape::Retired(RetiredFamily::ScenarioNumber),
    },
    Declaration {
        family: "retired division names",
        shape: Shape::Retired(RetiredFamily::DivisionName),
    },
    Declaration {
        family: "residual litter",
        shape: Shape::ResidualLitter,
    },
    Declaration {
        family: "unlabelled to-do notices",
        shape: Shape::UnlabelledTodo,
    },
    Declaration {
        family: "unlabelled legacy implementations",
        shape: Shape::UnlabelledLegacy,
    },
    Declaration {
        family: "section-sign references (repository)",
        shape: Shape::Legacy(&[LegacyRule::SectionNumber]),
    },
    Declaration {
        family: "retired record numbers (repository)",
        shape: Shape::RepositoryRecordNumber,
    },
];

/// What a burn list counts, and therefore which recognizer reads its surfaces.
///
/// The families the migration retires are shapes of the migration lint, read by
/// the lint's own code. The to-do family is not a reference form at all — it is
/// the remainder of an inventory profile, the notices that have not yet been
/// labelled — so it is read by that profile's own census, for the reason given
/// above about recognizers: the register and the gate must count one thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// The reference forms of the migration lint, held to the rules given.
    Legacy(&'static [LegacyRule]),
    /// A reference naming one of the repository's T-series records by number.
    ///
    /// This is track-only: the recognizer records the shape without making the
    /// later adoption decision about whether root prose replaces it with the
    /// record's label-headed identity.
    RepositoryRecordNumber,
    /// The covered notices of ADR-T-016's profile that carry no label.
    UnlabelledTodo,
    /// The marked legacy implementations that carry no derived label.
    UnlabelledLegacy,
    /// The three shapes an earlier sweep, or a retired notation, left standing.
    ///
    /// Read by its own recognizer for the reason the retired families are, and
    /// for one more of its own: two of its three shapes are degraded spellings
    /// of rules the shared migration lint already carries, and widening that
    /// lint to reach them is reserved to the record that retired those forms.
    /// Until that record is amended the family counts and judges nothing, which
    /// is the order the fourth family landed in.
    ResidualLitter,
    /// One of the two identity schemes the retired scenario matrix defined.
    ///
    /// These are read by their own recognizer rather than by the migration
    /// lint's, and the reason is the one the module head gives: no lint rule
    /// judges either shape, so the register is the only counter and cannot come
    /// to disagree with a second one.
    Retired(RetiredFamily),
    /// Literal instance values read across every byte of a declared surface.
    ExternalValues,
}

impl Shape {
    /// The lint rules this shape reads with, which is none outside the lint.
    #[must_use]
    pub const fn rules(&self) -> &'static [LegacyRule] {
        match self {
            Self::Legacy(rules) => rules,
            Self::RepositoryRecordNumber
            | Self::UnlabelledTodo
            | Self::UnlabelledLegacy
            | Self::Retired(_)
            | Self::ResidualLitter
            | Self::ExternalValues => &[],
        }
    }

    /// The file extensions this shape's recognizer can read a code tree for.
    ///
    /// Which kinds of source a shape reads belongs with the shape rather than
    /// with the declaration, for the reason the recognizer does: a family is
    /// read by one reader, and a reader knows the languages it can lex. Every
    /// family but one reads Rust alone. The residual family reads shell scripts
    /// beside it, because one of its occurrences stands in a script's provenance
    /// comment and a census that could not see it would close with that debt
    /// standing.
    #[must_use]
    pub const fn code_extensions(&self) -> &'static [&'static str] {
        match self {
            Self::ResidualLitter => &["rs", "sh"],
            Self::Legacy(_)
            | Self::RepositoryRecordNumber
            | Self::UnlabelledTodo
            | Self::UnlabelledLegacy
            | Self::Retired(_)
            | Self::ExternalValues => &["rs"],
        }
    }

    /// The declared domain a family's surface stands in, where it is not its policy's own.
    ///
    /// A domain is what a document is about, and three of these families are
    /// about something a document already declares: the shapes their recognizers
    /// read are the marked ordinals, the verbatim sentences and the prefix-number
    /// schemes the corpus writes down, and a census of a shape belongs beside the
    /// declaration of that shape rather than in a second document about the same
    /// subject. Which declared payload a recognizer reads is the shape's own
    /// property for the reason the extensions above are — a family is read by one
    /// reader, and a reader knows what it reads for.
    ///
    /// Every other family is about nothing but itself, so its surface stands in
    /// the document its policy identifier names and this answers `None`.
    #[must_use]
    pub const fn domain(&self) -> Option<&'static str> {
        match self {
            Self::Retired(RetiredFamily::ScenarioNumber) => Some("references.scenarios"),
            Self::Retired(RetiredFamily::DivisionName) => Some("references.divisions"),
            Self::ResidualLitter => Some("references.prefix-numbers"),
            Self::Legacy(_)
            | Self::RepositoryRecordNumber
            | Self::UnlabelledTodo
            | Self::UnlabelledLegacy
            | Self::ExternalValues => None,
        }
    }
}

/// One burn list, as the adoption data declare it.
///
/// Two fields and no third. Which shape a family counts and how its recognizer
/// reads a source are this binary's to know — they are the program — while where
/// it looks is the corpus's to state, and the corpus states it in the document of
/// the policy this family is censused under. The join to that policy is the
/// catalog's, so the family name carries it and nothing is written twice.
struct Declaration {
    family: &'static str,
    shape: Shape,
}

/// One policy's declared burn surface: whose geography it stands in, and where its census walks.
///
/// The trees are places rather than names, because a policy document has no owner
/// root to resolve a name against and no second document to resolve it in: the
/// corpus writes out what its census walks, in the domain of the policy that
/// activates it. The owner rides along because a surface is written inside some
/// share and a report saying whose is saying something a reader can check against
/// the partition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Surface {
    owner: String,
    prose: Vec<Place>,
    code: Vec<Place>,
}

impl Surface {
    /// Declare a surface from the owner that wrote it and the trees it walks.
    #[must_use]
    pub fn new(owner: impl Into<String>, prose: Vec<Place>, code: Vec<Place>) -> Self {
        Self {
            owner: owner.into(),
            prose,
            code,
        }
    }

    /// The owner whose share this surface was written in.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The prose trees the census walks.
    #[must_use]
    pub fn prose(&self) -> &[Place] {
        &self.prose
    }

    /// The code trees the census walks.
    #[must_use]
    pub fn code(&self) -> &[Place] {
        &self.code
    }
}

/// The declared values the retiring families' recognizers read for.
///
/// Three payloads rather than one per family, because what a recognizer needs is
/// decided by its shape rather than by its name: the two retired families take a
/// marked ordinal and a literal set, and the residual family takes the whole run
/// of prefix-number schemes at once. Each is the program value the census
/// consumes, built by the loader from the document that declares it, so nothing
/// here knows a mark, a sentence or a prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recognizer {
    marks: Vec<MarkNumbered>,
    literals: Option<LiteralSet>,
    prefix_numbers: Vec<PrefixNumbers>,
}

impl Recognizer {
    /// Read every payload the retiring families need out of one snapshot.
    #[must_use]
    pub fn declared(snapshot: &Snapshot) -> Self {
        Self {
            marks: snapshot
                .numbered_marks()
                .into_iter()
                .map(|(_name, mark)| mark)
                .collect(),
            literals: snapshot.declared_literals(),
            prefix_numbers: snapshot
                .declared_prefix_numbers()
                .into_iter()
                .map(|(_name, numbers)| numbers)
                .collect(),
        }
    }

    /// Declare a payload directly, for a caller standing outside a snapshot.
    #[must_use]
    pub fn new(
        marks: impl IntoIterator<Item = MarkNumbered>,
        literals: Option<LiteralSet>,
        prefix_numbers: impl IntoIterator<Item = PrefixNumbers>,
    ) -> Self {
        Self {
            marks: marks.into_iter().collect(),
            literals,
            prefix_numbers: prefix_numbers.into_iter().collect(),
        }
    }

    /// The marked ordinals the scenario family is read with.
    #[must_use]
    pub fn marks(&self) -> &[MarkNumbered] {
        &self.marks
    }

    /// The literal set the division family is read with.
    #[must_use]
    pub const fn literals(&self) -> Option<&LiteralSet> {
        self.literals.as_ref()
    }

    /// The prefix-number schemes the residual family is read with.
    #[must_use]
    pub fn prefix_numbers(&self) -> &[PrefixNumbers] {
        &self.prefix_numbers
    }
}

/// One burn list: a family, the surfaces it is counted over, and its register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnList {
    family: String,
    shape: Shape,
    prose: Vec<Place>,
    code: Vec<Place>,
    excluded: Vec<Exclusion>,
    recognizer: Recognizer,
    external: Option<ExternalBurn>,
}

impl BurnList {
    /// Declare a burn list over a family and the surfaces it is counted over.
    ///
    /// A list starts excluding nothing. What a census never reads is a statement
    /// the corpus makes about its own trees, so a list built outside a
    /// declaration has no exclusions to inherit and takes them from
    /// [`BurnList::with_excluded`] where it has any.
    #[must_use]
    pub fn new<P: Into<Place>>(
        family: impl Into<String>,
        shape: Shape,
        prose: Vec<P>,
        code: Vec<P>,
    ) -> Self {
        Self {
            family: family.into(),
            shape,
            prose: prose.into_iter().map(Into::into).collect(),
            code: code.into_iter().map(Into::into).collect(),
            excluded: Vec::new(),
            recognizer: Recognizer::default(),
            external: None,
        }
    }

    /// Declare a raw whole-file burn list from policy-local external values.
    #[must_use]
    pub fn external(family: impl Into<String>, declared: ExternalBurn) -> Self {
        Self {
            family: family.into(),
            shape: Shape::ExternalValues,
            prose: Vec::new(),
            code: Vec::new(),
            excluded: declared.excluded().to_vec(),
            recognizer: Recognizer::default(),
            external: Some(declared),
        }
    }

    /// Give the list the shares and patterns its census never reads.
    #[must_use]
    pub fn with_excluded(mut self, excluded: impl IntoIterator<Item = Exclusion>) -> Self {
        self.excluded = excluded.into_iter().collect();

        self
    }

    /// Hand the list the declared values its recognizer reads for.
    #[must_use]
    pub fn reading(mut self, recognizer: Recognizer) -> Self {
        self.recognizer = recognizer;

        self
    }

    /// The declared values this list's recognizer reads for.
    #[must_use]
    pub const fn recognizer(&self) -> &Recognizer {
        &self.recognizer
    }

    /// What this list counts, and therefore which recognizer reads it.
    #[must_use]
    pub const fn shape(&self) -> &Shape {
        &self.shape
    }

    /// The family this list counts, as a register names it.
    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    /// The lint rules whose shapes make up the family, where the lint reads it.
    #[must_use]
    pub const fn rules(&self) -> &[LegacyRule] {
        self.shape.rules()
    }

    /// The prose trees the family is counted over.
    #[must_use]
    pub fn prose(&self) -> &[Place] {
        &self.prose
    }

    /// The Rust trees whose comments the family is counted over.
    #[must_use]
    pub fn code(&self) -> &[Place] {
        &self.code
    }

    /// The shares and declared patterns the census never reads.
    #[must_use]
    pub fn excluded(&self) -> &[Exclusion] {
        &self.excluded
    }

    /// The raw whole-file surface, empty for compiled legacy recognizers.
    #[must_use]
    pub fn surface(&self) -> &[Place] {
        match &self.external {
            Some(external) => external.surface(),
            None => &[],
        }
    }

    /// The resolved external-value input, where this is that family.
    #[must_use]
    pub const fn external_values(&self) -> Option<&ExternalBurn> {
        self.external.as_ref()
    }

    /// Whether a path belongs to an omitted share or a declared pattern.
    fn is_excluded(&self, key: &BytePath, attribution: &BTreeMap<BytePath, String>) -> bool {
        self.excluded.iter().any(|exclusion| match exclusion {
            Exclusion::Share(share) => attribution.get(key).is_some_and(|owner| owner == share),
            Exclusion::Declared(pattern) => pattern.admits_path(key),
        })
    }

    /// Whether this family's census is one repository-wide artifact.
    ///
    /// The answer is read off the declared surfaces rather than declared beside
    /// them: a surface naming the corpus root reaches every owner's share, so the
    /// census it takes is nobody's share in particular. Such a census is one
    /// repository-wide artifact that no member can repair alone, which is exactly
    /// the shape whose verdict belongs to the root owner rather than to the owner
    /// of each file it counts (´[TOOLS-rule:lintcontracts:ownership]´).
    #[must_use]
    pub fn spans_corpus(&self) -> bool {
        self.prose
            .iter()
            .chain(self.code.iter())
            .chain(self.surface())
            .any(Place::is_root)
    }
}

/// Whether the family of this name censuses the corpus rather than one share.
///
/// The lookup stands beside [`BurnList::spans_corpus`] so that a caller holding a
/// family name rather than a censused list can ask the same question, and the two
/// answers cannot drift apart. This one is asked without a tree and therefore
/// without a declaration, so it reads the identifier the catalog gives the
/// family: a repository-scoped policy is the corpus-wide half of a program whose
/// other half is per-owner, and its identifier says so
/// (´[TOOLS-rule:lintcontracts:ownership]´).
#[must_use]
pub fn family_spans_corpus(family: &str) -> bool {
    family == PUBLIC_PACK_BURN_FAMILY
        || policy_of(family).is_some_and(|policy| policy.ends_with(REPOSITORY_RUN))
}

/// The policy a family's census is activated under, as this binary catalogues it.
///
/// One join, asked here and nowhere else. A family is a shape this binary reads
/// and a policy is the vocabulary a declaration activates, and the catalog is the
/// one place the two are tied together — so a family's document, its ratchet and
/// its derived exclusions are all found from the same tie rather than from three
/// tables that could come to disagree.
pub fn policy_of(family: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|policy| matches!(policy.observer, Observer::BurnFamily(named) if named == family))
        .map(|policy| policy.name)
}

/// The domain whose document declares one family's surface.
///
/// It is the family's policy identifier wherever the policy has a document of its
/// own, and the shape's declared domain where the family's subject already has
/// one. Either way it is a name this binary knows about itself, resolved against
/// the corpus's documents rather than against its directories.
fn domain_of(declaration: &Declaration) -> Option<&'static str> {
    declaration
        .shape
        .domain()
        .or_else(|| policy_of(declaration.family))
}

/// The declared surface domain the census activated by a policy walks.
///
/// A family's subject may already have a document, so its surface stands under
/// that subject's domain rather than under the activating policy identifier.
/// Resolve through the family's shape just as the census does; a policy with no
/// burn family has no census domain to report.
#[must_use]
pub fn census_domain_of_policy(policy: &str) -> Option<&'static str> {
    BURN_LISTS
        .iter()
        .find(|declaration| policy_of(declaration.family) == Some(policy))
        .and_then(domain_of)
}

/// The owner a family's ratchet is declared at, where the snapshot activates one.
fn activating_owner(snapshot: &Snapshot, family: &str) -> Option<String> {
    let policy = policy_of(family)?;

    snapshot
        .policies()
        .iter()
        .find(|pair| snapshot.program(pair) == Some(policy))
        .map(|pair| pair.owner.clone())
}

/// The shares no census of this binary reads, derived rather than declared.
///
/// Two rules, and both are policy read against declared data rather than a
/// repository fact written down twice.
///
/// The first is self-exemption. A census never walks the share of the owner that
/// is the checker itself: the linter's own sources carry every shape it retires,
/// as fixtures and as the prose arguing about them, and a census counting those
/// would be a register that grows every time it records a shrinkage. Which owner
/// this binary is, is self-knowledge; whether the partition places that owner is
/// read at runtime. Its share is the set of paths attributed to it, which need
/// not have one directory root.
///
/// The second is sibling-activation exclusion, and it reaches only a
/// repository-scoped family. Such a family is the corpus-wide half of a program
/// whose other half is activated per owner, and an owner that has taken the
/// per-owner half has taken its own debt: counting that share twice would put one
/// occurrence in two ratchets and let a repair in one be paid for by the other.
/// So the corpus-wide census cuts out exactly the shares whose owners activate the
/// sibling, read from the activation document at runtime.
///
/// An owner with no partition row is cut out by neither rule: it has no
/// attributed share to omit. No place is computed for an exclusion, since a
/// partition's opening can reach paths attributed to other owners as well.
fn derived_exclusions(snapshot: &Snapshot, policy: Option<&str>) -> Vec<Exclusion> {
    let mut cut: Vec<Exclusion> = Vec::new();
    let placed = |owner: &str| snapshot.partitions().iter().any(|row| row.owner == owner);

    if let Some(sibling) = policy
        .and_then(|policy| policy.strip_suffix(REPOSITORY_RUN))
        .filter(|sibling| catalogued(sibling).is_some())
    {
        let owners: BTreeSet<&str> = snapshot
            .policies()
            .iter()
            .filter(|pair| pair.policy == sibling && pair.family.is_none())
            .map(|pair| pair.owner.as_str())
            .collect();

        cut.extend(
            owners
                .into_iter()
                .filter(|owner| placed(owner))
                .map(|owner| Exclusion::Share(owner.to_owned())),
        );
    }

    if placed(SELF_OWNER) {
        let own = Exclusion::Share(SELF_OWNER.to_owned());
        if !cut.contains(&own) {
            cut.push(own);
        }
    }

    cut
}

/// The burn lists this repository adopted, each carrying its declared payload.
///
/// What a family counts is compiled meaning and where it counts it is not, so the
/// two meet here: the family names a shape and the reaches it is counted over,
/// and the corpus's own documents say where those reaches are and what to look
/// for inside them.
///
#[must_use]
pub fn index_burn_lists(declared: &Snapshot) -> Vec<BurnList> {
    let recognizer = Recognizer::declared(declared);

    let mut lists: Vec<BurnList> = BURN_LISTS
        .iter()
        .map(|declaration| {
            let surface =
                domain_of(declaration).and_then(|domain| declared.declared_surface(domain));

            let excluded = match surface {
                // A census that walks nothing cuts nothing out of it, so the
                // rules derive against a surface or not at all.
                Some(_) => derived_exclusions(declared, policy_of(declaration.family)),
                None => Vec::new(),
            };

            BurnList::new(
                declaration.family,
                declaration.shape.clone(),
                surface.map_or_else(Vec::new, |surface| surface.prose().to_vec()),
                surface.map_or_else(Vec::new, |surface| surface.code().to_vec()),
            )
            .with_excluded(excluded)
            .reading(recognizer.clone())
        })
        .collect();

    if let Some(external) = declared.external_burn() {
        lists.push(BurnList::external(
            PUBLIC_PACK_BURN_FAMILY,
            external.clone(),
        ));
    }

    lists
}

/// The families a corpus has activated and given no surface to walk.
///
/// An activated census with no declared program surface is a finding rather than a quiet
/// zero. The reason is the reason a stale register row is a failure: a census that
/// reads nothing reports nothing, a ratchet compared against nothing passes, and
/// the corpus is then told its debt is discharged by a walk that never happened.
/// A snapshot that activates no policy is a different case and is not this one:
/// that corpus has asked for no census, and the silence is its own answer.
pub fn undeclared_surfaces(snapshot: &Snapshot) -> Vec<Finding> {
    BURN_LISTS
        .iter()
        .filter_map(|declaration| {
            let policy = policy_of(declaration.family)?;
            let domain = domain_of(declaration)?;

            activating_owner(snapshot, declaration.family)?;

            snapshot
                .declared_surface(domain)
                .is_none()
                .then(|| Finding::UndeclaredBurnSurface {
                    family: declaration.family.to_owned(),
                    policy: policy.to_owned(),
                    document: domain.to_owned(),
                })
        })
        .collect()
}

/// One occurrence of a family, wherever the census found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnOccurrence {
    text: String,
    location: Location,
}

impl BurnOccurrence {
    /// The occurrence as written.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where the occurrence stands.
    #[must_use]
    pub const fn location(&self) -> &Location {
        &self.location
    }
}

/// One file's line of a register: how many occurrences it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BurnRow {
    /// The file, relative to the repository root.
    pub path: String,
    /// How many occurrences of the family stand in it.
    pub count: usize,
}

/// What one burn list's census found.
#[derive(Debug, Clone, Default)]
pub struct BurnCensus {
    occurrences: Vec<BurnOccurrence>,
    rows: Vec<BurnRow>,
    files_scanned: usize,
}

impl BurnCensus {
    /// Every occurrence, ordered by file and position.
    #[must_use]
    pub fn occurrences(&self) -> &[BurnOccurrence] {
        &self.occurrences
    }

    /// One row per file holding at least one occurrence, in path order.
    #[must_use]
    pub fn rows(&self) -> &[BurnRow] {
        &self.rows
    }

    /// How many files the census read.
    #[must_use]
    pub const fn files_scanned(&self) -> usize {
        self.files_scanned
    }

    /// Whether this census found nothing at all to register.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// How many occurrences stand over every surface.
    #[must_use]
    pub fn total(&self) -> usize {
        self.rows.iter().map(|row| row.count).sum()
    }
}

/// One row of a committed register, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRow {
    path: String,
    count: usize,
    kept: Option<String>,
    location: Location,
}

impl RegisterRow {
    /// Declare a ratchet row from the file it bounds and the ceiling it sets.
    ///
    /// The location is where a reader would go to move the ceiling, which under
    /// the ratified grammar is the canonical list rather than a generated view.
    #[must_use]
    pub fn new(path: impl Into<String>, count: usize, location: Location) -> Self {
        Self {
            path: path.into(),
            count,
            kept: None,
            location,
        }
    }

    /// The file the row registers.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The count the row registers.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Why this row's registered occurrences are kept, when declared.
    #[must_use]
    pub fn kept(&self) -> Option<&str> {
        self.kept.as_deref()
    }

    /// Where the row stands in the register.
    #[must_use]
    pub const fn location(&self) -> &Location {
        &self.location
    }
}

/// Take one burn list's census over a repository root.
///
/// The partition's attribution gives a share its exact paths. A partition
/// opening may stand above another owner's paths, so a directory prefix would
/// omit debt that the excluded owner does not own.
#[must_use]
pub fn census(
    root: &Path,
    list: &BurnList,
    corpus: &CorpusPlan,
    attribution: &BTreeMap<BytePath, String>,
) -> (BurnCensus, Vec<Finding>) {
    if let Some(census) = census_external(root, list, corpus, attribution) {
        return census;
    }

    let mut census = BurnCensus::default();
    let mut findings = Vec::new();

    for (key, path) in sources(corpus, list.prose(), "md") {
        if list.is_excluded(&key, attribution) {
            continue;
        }

        let Some(text) = read(root, &path, &mut findings) else {
            continue;
        };

        census.files_scanned += 1;

        match list.shape() {
            Shape::Retired(family) => {
                census
                    .occurrences
                    .extend(retired(&path, &text, *family, list.recognizer()));
            }
            Shape::ResidualLitter => census.occurrences.extend(residual(
                &path,
                &text,
                list.recognizer(),
                scan_residual_markdown,
            )),
            Shape::RepositoryRecordNumber => {
                census.occurrences.extend(repository_record_numbers(
                    &path,
                    &text,
                    &markdown_regions(&text),
                ));
            }
            Shape::Legacy(_) | Shape::UnlabelledTodo => {
                census
                    .occurrences
                    .extend(occurrences(scan_legacy(&path, &text, list.rules())));
            }
            Shape::UnlabelledLegacy | Shape::ExternalValues => {}
        }
    }

    for extension in list.shape().code_extensions() {
        for (key, path) in sources(corpus, list.code(), extension) {
            if list.is_excluded(&key, attribution) {
                continue;
            }

            let Some(text) = read(root, &path, &mut findings) else {
                continue;
            };

            census.files_scanned += 1;

            match list.shape() {
                Shape::Legacy(rules) => census
                    .occurrences
                    .extend(occurrences(scan_comments(&path, &text, rules))),
                Shape::RepositoryRecordNumber => {
                    census.occurrences.extend(repository_record_numbers(
                        &path,
                        &text,
                        &rust_regions(&text),
                    ));
                }
                Shape::UnlabelledTodo => {
                    census.occurrences.extend(unlabelled_todos(&path, &text));
                }
                Shape::UnlabelledLegacy => {
                    census.occurrences.extend(unlabelled_legacy(&path, &text));
                }
                Shape::Retired(family) => census.occurrences.extend(retired_comments(
                    &path,
                    &text,
                    *family,
                    list.recognizer(),
                )),
                Shape::ResidualLitter if *extension == "sh" => {
                    census.occurrences.extend(residual(
                        &path,
                        &text,
                        list.recognizer(),
                        scan_residual_script,
                    ));
                }
                Shape::ResidualLitter => census.occurrences.extend(residual(
                    &path,
                    &text,
                    list.recognizer(),
                    scan_residual_comments,
                )),
                Shape::ExternalValues => {}
            }
        }
    }

    finish_census(&mut census);

    (census, findings)
}

/// Take the raw whole-file census when this list carries external values.
fn census_external(
    root: &Path,
    list: &BurnList,
    corpus: &CorpusPlan,
    attribution: &BTreeMap<BytePath, String>,
) -> Option<(BurnCensus, Vec<Finding>)> {
    let external = list.external_values()?;
    let mut census = BurnCensus::default();
    let mut findings = Vec::new();

    for (key, path) in whole_file_sources(corpus, external.surface()) {
        if list.is_excluded(&key, attribution) {
            continue;
        }

        let Some(bytes) = read_bytes(root, &path, &mut findings) else {
            continue;
        };

        census.files_scanned += 1;
        census
            .occurrences
            .extend(external_occurrences(&path, &bytes, external.values()));
    }

    finish_census(&mut census);

    Some((census, findings))
}

/// Put one census into stable file-and-offset order and derive its path rows.
fn finish_census(census: &mut BurnCensus) {
    census.occurrences.sort_by(|left, right| {
        left.location
            .path()
            .cmp(right.location.path())
            .then_with(|| left.location.offset().cmp(&right.location.offset()))
    });
    census.rows = tally(&census.occurrences);
}

/// Read literal values over arbitrary file bytes.
fn external_occurrences(path: &Path, source: &[u8], values: &[BurnValue]) -> Vec<BurnOccurrence> {
    let mut found = Vec::new();

    for declared in values {
        for offset in superloop_cli_common::burn_match::burn_offsets(
            source,
            declared.value().as_bytes(),
            declared.mode() == MatchMode::Identifier,
        ) {
            found.push(BurnOccurrence {
                text: declared.value().to_owned(),
                location: Location::from_bytes(path, source, offset),
            });
        }
    }

    found
}

/// Read repository record numbers from one surface's referring regions.
///
/// The repository's record series remains canonical. This family observes its
/// number-citation shape without deciding whether the root corpus later retires
/// it, and reads that shape with the same digit-run bound as the legacy
/// record family. The regions decide where referring text stands, so code spans,
/// fenced examples and string literals remain displays or data rather than
/// citations.
fn repository_record_numbers(path: &Path, source: &str, regions: &[Region]) -> Vec<BurnOccurrence> {
    let mut found = Vec::new();

    for region in regions {
        for (offset, prefix) in region.text().match_indices("ADR-T-") {
            let digits = region.text()[offset + prefix.len()..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();

            if digits == 0 {
                continue;
            }

            let end = offset + prefix.len() + digits;

            found.push(BurnOccurrence {
                text: region.text()[offset..end].to_owned(),
                location: Location::new(path, source, region.source_offset(offset)),
            });
        }
    }

    found.sort_by_key(|occurrence| occurrence.location().offset());
    found
}

/// Read one Markdown document for a retired identity family.
fn retired(
    path: &Path,
    source: &str,
    family: RetiredFamily,
    declared: &Recognizer,
) -> Vec<BurnOccurrence> {
    scan_retired_markdown(source, family, declared)
        .into_iter()
        .map(|(text, offset)| BurnOccurrence {
            text,
            location: Location::new(path, source, offset),
        })
        .collect()
}

/// Read one Rust source's comments for a retired identity family.
///
/// Only the comments, for the reason the legacy census reads only comments: a
/// scenario number inside an identifier or a string literal is a name the program
/// carries rather than a reference the corpus makes, and a register counting those
/// could only reach zero by renaming the code.
///
/// The regions come from the tokenization layer, exactly as the legacy census
/// and the residual census take theirs. Reading one comment at a time was a
/// defect of the reading rather than a narrowness of the family: adjacent comment
/// lines are one region there, so a retired identity the corpus wrapped across a
/// line boundary is one occurrence here too, and a census that could not see the
/// corpus's own wrapped spelling would close with that debt still standing
/// (´[TOOLS-rule:lintcontracts:burn-families]´). Offsets are mapped back
/// through the region that produced them, so an occurrence is still reported
/// where its first character really stands.
fn retired_comments(
    path: &Path,
    source: &str,
    family: RetiredFamily,
    declared: &Recognizer,
) -> Vec<BurnOccurrence> {
    let mut found: Vec<Retired> = rust_regions(source)
        .iter()
        .flat_map(|region| {
            scan_retired_text(0, region.text(), family, declared)
                .into_iter()
                .map(|(text, offset)| (text, region.source_offset(offset)))
        })
        .collect();

    found.sort_by_key(|(_text, offset)| *offset);

    found
        .into_iter()
        .map(|(text, offset)| BurnOccurrence {
            text,
            location: Location::new(path, source, offset),
        })
        .collect()
}

/// Read one source for the residual family, by whichever reader suits it.
///
/// The reader is handed in rather than chosen here because the three surfaces
/// the family declares — Markdown prose, Rust commentary and shell commentary —
/// differ only in how the running text is found, and not at all in what is
/// looked for once it is.
fn residual(
    path: &Path,
    source: &str,
    declared: &Recognizer,
    reader: fn(&str, &Recognizer) -> Vec<Residual>,
) -> Vec<BurnOccurrence> {
    reader(source, declared)
        .into_iter()
        .map(|(text, offset)| BurnOccurrence {
            text,
            location: Location::new(path, source, offset),
        })
        .collect()
}

/// Read one Rust source's comments for a family's shapes.
///
/// Only the comments are read. Program text may carry a shape — an identifier
/// holding a record's number, a string literal holding a section locator — and
/// neither is a reference made in the sense the migration retires; a burn list
/// that counted them would never reach zero, because reaching zero would mean
/// renaming the code.
///
/// Adjacent comment lines are one region, so a reference the retired convention
/// wrapped across a line boundary is one reference here too. Reading each
/// comment alone made a census that could not see the corpus's own wrapped
/// spelling, which is a defect of the reading rather than a narrowness of the
/// rules (´[TOOLS-rule:lintcontracts:burn-families]´).
fn scan_comments(path: &Path, source: &str, rules: &[LegacyRule]) -> Vec<Finding> {
    scan_regions(path, source, &rust_regions(source), rules)
}

/// Read one Rust source for the covered notices that carry no label.
///
/// The census is the profile's own, so the register counts exactly what the
/// check would hold to the standard place once the notice is labelled. The text
/// recorded for a growth finding is the marker and the summary, which is what
/// sends a reader to the notice that broke the ratchet.
///
/// The package is not known here and is not needed: whether a notice carries a
/// label is a fact of its own line, and the classification that does need a
/// package decides only which area the label names.
fn unlabelled_todos(path: &Path, source: &str) -> Vec<BurnOccurrence> {
    let (notices, _orphans) = scan_todos("", path, source);

    notices
        .into_iter()
        .filter(TodoNotice::is_unlabelled)
        .map(|notice| BurnOccurrence {
            text: format!("{}: {}", notice.marker(), notice.summary()),
            location: notice.location().clone(),
        })
        .collect()
}

/// Read one production Rust source for marked legacy sites carrying no label.
fn unlabelled_legacy(path: &Path, source: &str) -> Vec<BurnOccurrence> {
    if !is_production_source(path) {
        return Vec::new();
    }

    let (sites, _orphans) = scan_legacy_sites("", path, source);

    sites
        .into_iter()
        .filter(LegacySite::is_unlabelled)
        .map(|site| BurnOccurrence {
            text: format!("LEGACY: {}", site.summary()),
            location: site.location().clone(),
        })
        .collect()
}

/// Reduce the lint's findings to the occurrences a census counts.
fn occurrences(findings: Vec<Finding>) -> Vec<BurnOccurrence> {
    findings
        .into_iter()
        .filter_map(|finding| match finding {
            Finding::LegacySectionReference { text, location }
            | Finding::LegacyTagReference { text, location }
            | Finding::LegacyRecordReference { text, location }
            | Finding::LegacyUnprefixedRecordReference { text, location } => {
                Some(BurnOccurrence { text, location })
            }
            _other => None,
        })
        .collect()
}

/// Count the occurrences of each file, in path order.
///
/// The key uses the declared row's reversible display so a census row meets
/// the same path in the register even when its name contains escaped bytes.
fn tally(occurrences: &[BurnOccurrence]) -> Vec<BurnRow> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();

    for occurrence in occurrences {
        *counts
            .entry(crate::pattern::display_path(occurrence.location.path()))
            .or_default() += 1;
    }

    counts
        .into_iter()
        .map(|(path, count)| BurnRow { path, count })
        .collect()
}

/// Read a file, reporting rather than raising what could not be read.
fn read(root: &Path, relative: &Path, findings: &mut Vec<Finding>) -> Option<String> {
    match fs::read_to_string(root.join(relative)) {
        Ok(text) => Some(text),
        Err(error) => {
            findings.push(Finding::TraversalFailure {
                path: crate::pattern::display_path(relative),
                message: error.to_string(),
            });

            None
        }
    }
}

/// Read arbitrary file bytes, reporting rather than raising what could not be read.
fn read_bytes(root: &Path, relative: &Path, findings: &mut Vec<Finding>) -> Option<Vec<u8>> {
    match fs::read(root.join(relative)) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            findings.push(Finding::TraversalFailure {
                path: crate::pattern::display_path(relative),
                message: error.to_string(),
            });

            None
        }
    }
}

/// Every tracked source below the declared whole-file surface, without duplicates.
fn whole_file_sources(corpus: &CorpusPlan, trees: &[Place]) -> Vec<(BytePath, PathBuf)> {
    corpus
        .natives()
        .iter()
        .filter(|(key, _)| trees.iter().any(|tree| tree.under(key)))
        .map(|(key, native)| (key.clone(), native.clone()))
        .collect()
}

/// Every source of one extension below any declared tree, in path order.
///
/// A tree that is not there contributes nothing and raises nothing: a surface may
/// name a target directory a package does not carry yet, and a census that
/// complained would make declaring the surface a commitment to create it.
fn sources(corpus: &CorpusPlan, trees: &[Place], extension: &str) -> Vec<(BytePath, PathBuf)> {
    corpus
        .natives()
        .iter()
        .filter(|(key, _)| trees.iter().any(|tree| tree.under(key)))
        .filter(|(_, native)| {
            native
                .extension()
                .is_some_and(|found| found.eq_ignore_ascii_case(extension))
        })
        .map(|(key, native)| (key.clone(), native.clone()))
        .collect()
}

/// Verify one burn list's ratchet against its census, in both directions.
///
/// The ratchet is the canonical list, which is what the retired registers left
/// behind them: their content was either an argument, which became a record, or a
/// ratchet, which became these rows (´[TOOLS-rule:lintcontracts:declarations]´). The relation is
/// the one the register-equals-census gate held, over the same numbers.
///
/// Growth is attributed positionally: counts alone cannot say which of a file's
/// occurrences is the new one, so the occurrence named is the first standing
/// beyond what the list accounts for. That is the right occurrence whenever the
/// addition was at or after it, and a nearby one otherwise; either way the reader
/// is sent to the file whose census grew, with the arithmetic beside it.
#[must_use]
pub fn verify(list: &BurnList, census: &BurnCensus, declared: &[RegisterRow]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for row in census.rows() {
        let entry = declared.iter().find(|entry| entry.path == row.path);
        let count = entry.map_or(0, |entry| entry.count);

        if row.count > count {
            findings.push(growth(list, row, count, census));
        }
    }

    for entry in declared {
        let found = census
            .rows()
            .iter()
            .find(|row| row.path == entry.path)
            .map_or(0, |row| row.count);

        if found < entry.count {
            findings.push(Finding::StaleBurnEntry {
                family: list.family().to_owned(),
                path: entry.path.clone(),
                registered: entry.count,
                found,
                location: entry.location.clone(),
            });
        }
    }

    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    findings
}

/// The finding one file's growth raises, naming the occurrence beyond the list.
fn growth(list: &BurnList, row: &BurnRow, registered: usize, census: &BurnCensus) -> Finding {
    let first_new = census
        .occurrences()
        .iter()
        .filter(|occurrence| crate::pattern::display_path(occurrence.location.path()) == row.path)
        .nth(registered);

    Finding::BurnListGrowth {
        family: list.family().to_owned(),
        path: row.path.clone(),
        registered,
        found: row.count,
        text: first_new.map_or_else(String::new, |occurrence| occurrence.text.clone()),
        location: first_new.map(|occurrence| occurrence.location.clone()),
    }
}

/// The ratchet rows a snapshot declares for one family, gathered across its keys.
///
/// A family reaching one owner's share has one key, and a family declared over
/// the corpus root has one too — the root owner's, because the ratchet such a
/// census earns is one repository-wide artifact no member can repair alone
/// (´[TOOLS-rule:lintcontracts:ownership]´). The rows are gathered across every
/// key naming the family's program, so neither shape has to be told apart here.
#[must_use]
pub fn declared_rows(snapshot: &Snapshot, family: &str) -> Vec<RegisterRow> {
    let Some(policy) = CATALOG
        .iter()
        .find(|policy| matches!(policy.observer, Observer::BurnFamily(named) if named == family))
    else {
        return Vec::new();
    };

    let mut rows = Vec::new();

    for (pair, held) in snapshot.lists() {
        if snapshot.program(pair) != Some(policy.name) {
            continue;
        }

        if let Rows::PathCounts(counts) = held {
            rows.extend(counts.iter().map(|count| RegisterRow {
                path: count.path.display(),
                count: usize::try_from(count.maximum).unwrap_or(usize::MAX),
                kept: count.kept.clone(),
                location: Location::new(format!("{DIRECTORY}/{LISTS_FILE}"), "", 0),
            }));
        }
    }

    rows
}

/// Verify every adopted burn list against the ratchet the snapshot declares.
///
/// A declared surface is held to its ratchets entire, and a family the surface
/// never activates is held to the empty ratchet — which is how a family stays at
/// zero.
#[must_use]
#[cfg(test)]
pub fn verify_all(
    root: &Path,
    snapshot: &Snapshot,
    corpus: &CorpusPlan,
    attribution: &BTreeMap<BytePath, String>,
) -> (Vec<(BurnList, BurnCensus)>, Vec<Finding>) {
    let mut taken = Vec::new();
    let mut findings = undeclared_surfaces(snapshot);

    for list in index_burn_lists(snapshot) {
        let (census, census_findings) = census(root, &list, corpus, attribution);
        findings.extend(census_findings);

        findings.extend(verify(
            &list,
            &census,
            &declared_rows(snapshot, list.family()),
        ));

        taken.push((list, census));
    }

    (taken, findings)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::{BurnList, RegisterRow, Shape, census, verify};
    use crate::areas::{self, Place};
    use crate::declaration::AbnfPattern;
    use crate::finding::{Finding, Location};
    use crate::legacy::LegacyRule;
    use crate::plan::CorpusPlan;
    use crate::universe::UniverseKind;

    /// A path containing a space meets its declared count in the reversible
    /// display, and growth names that same path when no row declares it.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed temporary fixture cannot be written.
    ///
    /// ´claim:burn:a-register-row-meets-the-tally-of-a-name-outside-the-plain-set´
    /// ´test:unit:a-register-row-meets-the-tally-of-a-name-outside-the-plain-set´
    #[test]
    fn a_register_row_meets_the_tally_of_a_name_outside_the_plain_set() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(root.path().join("docs")).expect("docs directory");
        fs::write(root.path().join("docs/read me.md"), "As §10.3 requires.\n")
            .expect("prose source");
        let corpus = CorpusPlan::compile(root.path(), UniverseKind::AsWritten, &[]);
        let list = BurnList::new(
            "section references",
            Shape::Legacy(&[LegacyRule::SectionNumber]),
            vec![Place::from_bytes(b"docs")],
            Vec::new(),
        );
        let (taken, findings) = census(root.path(), &list, &corpus, &BTreeMap::new());
        assert_eq!(findings, Vec::new());
        assert_eq!(taken.rows()[0].path, "docs/read%20me.md");

        let row = RegisterRow::new(
            "docs/read%20me.md",
            1,
            Location::new(".linter/lists.toml", "", 0),
        );
        assert_eq!(verify(&list, &taken, &[row]), Vec::new());
        assert!(matches!(
            verify(&list, &taken, &[]).as_slice(),
            [Finding::BurnListGrowth {
                path,
                registered: 0,
                found: 1,
                location: Some(location),
                ..
            }] if path == "docs/read%20me.md" && location.to_string().starts_with("docs/read%20me.md:")
        ));
    }

    /// A surface opening inside a file component starts its census at the
    /// containing directory, so both admitted paths beneath that locator are
    /// read.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed temporary fixture cannot be written.
    ///
    /// ´claim:burn:a-surface-reaches-the-paths-under-a-partial-opening´
    /// ´test:unit:a-surface-reaches-the-paths-under-a-partial-opening´
    #[test]
    fn a_surface_reaches_the_paths_under_a_partial_opening() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(root.path().join("docs")).expect("docs directory");
        fs::write(root.path().join("docs/readme.md"), "See §1.1.\n").expect("first source");
        fs::write(root.path().join("docs/reader.md"), "See §2.2.\n").expect("second source");
        let corpus = CorpusPlan::compile(root.path(), UniverseKind::AsWritten, &[]);
        let pattern = AbnfPattern::parse(r#"%s"docs/re" *VCHAR"#).expect("surface pattern");
        let list = BurnList::new(
            "section references",
            Shape::Legacy(&[LegacyRule::SectionNumber]),
            areas::places(&pattern),
            Vec::new(),
        );
        let (taken, findings) = census(root.path(), &list, &corpus, &BTreeMap::new());
        assert_eq!(findings, Vec::new());
        assert_eq!(taken.files_scanned(), 2);
        assert_eq!(taken.total(), 2);
    }

    /// A surface opening with a non-text byte keeps that byte as its place and
    /// reads only paths beneath its own tree.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed temporary fixture cannot be written.
    ///
    /// ´claim:burn:a-surface-opening-with-bytes-that-are-not-text-reaches-only-its-own-tree´
    /// ´test:unit:a-surface-opening-with-bytes-that-are-not-text-reaches-only-its-own-tree´
    #[cfg(unix)]
    #[test]
    fn a_surface_opening_with_bytes_that_are_not_text_reaches_only_its_own_tree() {
        use std::os::unix::ffi::OsStringExt as _;

        let root = tempfile::tempdir().expect("temporary directory");
        let byte_directory = root.path().join(std::ffi::OsString::from_vec(vec![0xE9]));
        fs::create_dir(&byte_directory).expect("byte directory");
        fs::write(byte_directory.join("a.md"), "See §1.1.\n").expect("byte source");
        fs::create_dir(root.path().join("docs")).expect("docs directory");
        fs::write(root.path().join("docs/b.md"), "See §2.2.\n").expect("other source");
        let corpus = CorpusPlan::compile(root.path(), UniverseKind::AsWritten, &[]);
        let pattern = AbnfPattern::parse(r#"%xE9 [ "/" *PATHCHAR ]"#).expect("surface pattern");
        let list = BurnList::new(
            "section references",
            Shape::Legacy(&[LegacyRule::SectionNumber]),
            areas::places(&pattern),
            Vec::new(),
        );
        let (taken, findings) = census(root.path(), &list, &corpus, &BTreeMap::new());
        assert_eq!(findings, Vec::new());
        assert_eq!(taken.files_scanned(), 1);
        assert_eq!(taken.total(), 1);
        assert_eq!(taken.rows()[0].path, "%E9/a.md");
    }
}
