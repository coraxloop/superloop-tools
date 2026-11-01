// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! The check report, and the top-level check itself.
//!
//! The report is this command's stdout result data under ADR-T-010, so it is one
//! JSON object with no human-oriented text outside the `message` fields carried
//! inside the JSON.
//!
//! The object carries no version of its own. Report shape is not versioned here:
//! a reader takes the members it names and ignores the rest, so a member added
//! is a member a reader that did not ask for it never sees, and a member removed
//! is a reader's own dangling reference rather than a number to migrate against.
//! The command contract's register stands as the changelog of what this object
//! has promised, read by people rather than by programs.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`counts_failures_and_warnings_separately`] | report | Failures and warnings are counted apart from one another, and only a failure spoils the verdict: a corpus carrying one of each reports one of each and is not clean, on account of the failure alone. |
//! | [`serializes_findings_with_their_code`] | report | Every finding serialises with a stable machine-readable code beside its severity and the label it concerns, so a consumer can select the findings it cares about without parsing the human sentence. |
//! | [`counts_every_activations_governed_paths`] | report | Every activated pair is listed with the number of tracked paths the declared partition attributes to its owner, so an activation that governs nothing is told apart from one that measured a share and found nothing in it. |
//! | [`counts_what_each_activations_surface_reaches`] | report | An activation whose policy declares a surface of its own is listed with what that surface reaches over the participating corpus, and an activation whose policy declares none carries no second count, because for it the surface is the share the row already states. |
//! | [`tells_a_vacuous_surface_from_a_satisfied_one`] | report | A policy whose surface names a tree this repository does not have reaches nothing and raises a warning beside a populated share, which is the state a copied declaration is in and the one the share alone cannot tell apart from a satisfied policy. The warning names the policy and census domain without spoiling the clean verdict. |
//! | [`names_a_surface_reaching_nothing_once_per_policy`] | report | Two owners can activate one policy whose surface names an absent tree while a second policy governs their shares. The surface warning names the policy and census domain once, and no empty-share warning is raised. |
//! | [`counts_a_surface_beyond_the_activating_share`] | report | An activated policy reports every participating path its declared surface reaches, including paths attributed to a different owner, so its surface count can exceed the activating owner's share. |
//! | [`resolves_a_surface_through_its_census_domain`] | report | A burn policy whose census reads a surface declared under its subject's domain reports that surface's reach, even when its policy identifier names a different document. |
//! | [`ties_each_finding_to_the_pair_that_produced_it`] | report | A finding is counted against the pair whose policy emitted it and whose owner the partition attributes its location to, and every finding no pair produced is counted once beside the list, so the per-pair figures and the report's own totals reconcile exactly. |
//! | [`ties_a_non_text_name_to_the_pair_that_produced_it`] | report | A non-text name finding without a location is counted against its path-name pair and named owner, leaving no finding outside the activation tally. |
//! | [`an_archive_shaped_surface_governs_nothing_on_a_foreign_tree`] | report | A surface whose partition rows name another tree's paths governs nothing where it is run, and the report says so in the count rather than printing the silence of a corpus that was never reached. |
//! | [`a_check_with_no_activation_reports_it_once`] | report | A declaration that activates no pair raises one warning saying so and naming that cause, because a run that routed nothing anywhere is not the clean verdict it would otherwise print, and a warning never spoils a clean verdict. |
//! | [`a_copied_surface_that_attributes_nothing_names_its_cause`] | report | A surface whose activations stand and whose partition attributes no path to any of their owners raises the same warning under the other cause, which is the state a declaration copied from another repository is in until its rows are rewritten. |
//! | [`an_activation_governing_nothing_beside_others_names_the_pair`] | report | A pair that governs nothing where other pairs govern a share is named on its own, because the whole-check warning cannot see it and the run would otherwise report what it found and say nothing about the activation that reached no file. |

use std::path::Path;

use serde::Serialize;

use crate::burn::{BurnRow, BurnSourceKind, MatchModeCounts};
use crate::claim::ClaimAnalysis;
use crate::constant::ConstantAnalysis;
use crate::coverage::{CoverageCounts, CoverageSummary};
use crate::depend::CitedEdge;
use crate::engine::Analysis;
use crate::finding::{Finding, Severity};
use crate::fix::FixOutcome;
use crate::graph::GraphSummary;
use crate::index::IndexAnalysis;
use crate::label::Label;
use crate::layers::LayerAnalysis;
use crate::legacy_profile::LegacyAnalysis;
use crate::matrix::MatrixAnalysis;
use crate::partition::PartitionCounts;
use crate::plan::{
    AssemblyWritePlan, BurnWritePlan, ExecutionPlan, FixWritePlan, ProjectionWritePlan,
    WriteGuardPlan,
};
use crate::profile::ProfileAnalysis;
#[cfg(test)]
use crate::roster::OwnerNames;
use crate::shape::ShapeSummary;
#[cfg(test)]
use crate::snapshot::Snapshot;
use crate::snapshot::{Configuration, configuration};
use crate::todo::TodoAnalysis;
#[cfg(test)]
use crate::universe::IgnoreRow;

/// One finding, as it appears in the report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedFinding {
    /// Whether the finding blocks the check.
    pub severity: Severity,
    /// A human-readable rendering, carried inside the JSON record.
    pub message: String,
    /// The finding itself, tagged by its code.
    #[serde(flatten)]
    pub finding: Finding,
}

impl From<Finding> for ReportedFinding {
    fn from(finding: Finding) -> Self {
        Self {
            severity: finding.severity(),
            message: finding.to_string(),
            finding,
        }
    }
}

/// The stdout result object of the check command.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// Complete publication classification, absent where no manifest is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_set: Option<superloop_cli_common::public_set::Selection>,
    /// The root the carrier was taken from.
    pub root: String,
    /// Whether the command used the public-pack snapshot contract.
    pub public_pack: bool,
    /// How many carrier sources were scanned.
    pub sources_scanned: usize,
    /// How many mints stand in the carrier.
    pub mints: usize,
    /// How many citations resolved.
    pub citations_resolved: usize,
    /// Citations resolving to a declared unpublished address, a subset of resolved sites.
    pub citations_resolved_unpublished: usize,
    /// How many environment heads validated against the kind registry.
    pub heads_validated: usize,
    /// How many findings block the check.
    pub failures: usize,
    /// How many findings merely advise.
    pub warnings: usize,
    /// Whether the carrier is in good standing.
    pub clean: bool,
    /// Activated rows checked by the repository's own programme, outside this verdict.
    pub deferred: usize,
    /// The owner, policy and checker for every deferred activation.
    pub deferred_policies: Vec<crate::snapshot::DeferredPolicy>,
    /// What the test profile found over the Rust carrier.
    pub profile: ProfileAnalysis,
    /// What the to-do profile found over the Rust carrier.
    pub todo: TodoAnalysis,
    /// What the legacy-implementation profile found over production Rust.
    pub legacy: LegacyAnalysis,
    /// What the claim profile of ADR-T-017 found, and what it counted rather than reported.
    pub claim: ClaimAnalysis,
    /// What the constant profile of ADR-T-018 found over the Rust carrier.
    pub constant: ConstantAnalysis,
    /// What the claim coverage came to: statements written, and intents nobody has kept.
    pub coverage: CoverageCounts,
    /// What the in-file test indexes were found to be.
    pub index: IndexAnalysis,
    /// What the per-folder test matrices were found to be.
    pub matrix: MatrixAnalysis,
    /// What the assembled publications were found to be.
    pub assembly: AssemblyCounts,
    /// What the burn lists were censused at.
    pub burn: BurnCounts,
    /// What the layer owner graph of ADR-T-019 was found to be, and what it refused.
    pub layers: LayerAnalysis,
    /// What the declared configuration was found to be.
    ///
    /// Lower-level verification may omit it only when handed an already-refused
    /// configuration; every compiled command plan carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConfigurationCounts>,
    /// Every finding, ordered by source and position.
    pub findings: Vec<ReportedFinding>,
}

/// What the burn pass found, in counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BurnCounts {
    /// How many burn lists the adoption declares.
    pub declared: usize,
    /// How many sources their censuses read, counted once per list.
    pub files_scanned: usize,
    /// How many occurrences stand over every family.
    pub occurrences: usize,
    /// How many registered occurrences have a kept reason, summed over families.
    pub kept: usize,
    /// How many registered occurrences remain owed, summed over families.
    pub owed: usize,
    /// The per-family censuses, including effective value provenance where applicable.
    pub families: Vec<BurnedFamily>,
}

/// What the assembly pass found, in counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AssemblyCounts {
    /// How many pairs the adoption declares.
    pub declared: usize,
    /// How many of them have no parts directory yet.
    pub dormant: usize,
    /// How many of them were assembled and compared.
    pub verified: usize,
    /// How many parts stood in those assemblies.
    pub parts: usize,
}

/// What each pass over the Rust carrier found, gathered for the report.
///
/// The passes travel together because the report presents them together, and
/// because a constructor taking one argument per pass would grow by one every
/// time a record adds a pass — which is the shape this corpus is in.
#[derive(Debug, Clone, Default)]
pub struct Passes {
    /// What the test profile of ADR-T-015 found.
    pub profile: ProfileAnalysis,
    /// What the to-do profile of ADR-T-016 found.
    pub todo: TodoAnalysis,
    /// What the marked legacy-implementation profile found.
    pub legacy: LegacyAnalysis,
    /// What the claim profile of ADR-T-017 found.
    pub claim: ClaimAnalysis,
    /// What the constant profile of ADR-T-018 found.
    pub constant: ConstantAnalysis,
    /// What the claim coverage came to, in the figures a check report carries.
    pub coverage: CoverageCounts,
    /// What the in-file test indexes were found to be.
    pub index: IndexAnalysis,
    /// What the per-folder test matrices were found to be.
    pub matrix: MatrixAnalysis,
}

/// What the whole-tree verifications found, gathered for the report.
///
/// These four are not passes over the Rust carrier — they read the tree's own
/// documents and manifests — so they travel beside [`Passes`] rather than in it.
/// They travel grouped for the reason that record already gives about the
/// passes: a constructor taking one argument per verification would grow by one
/// every time a record adds a verification, which is the shape this corpus is in.
#[derive(Debug, Clone, Default)]
pub struct Verdicts {
    /// Whether the command used the public-pack snapshot contract.
    pub public_pack: bool,
    /// What the assembled publications were found to be.
    pub assembly: AssemblyCounts,
    /// What the burn lists were censused at.
    pub burn: BurnCounts,
    /// What the layer owner graph of ADR-T-019 was found to be.
    pub layers: LayerAnalysis,
    /// What the declared configuration was found to be, when one stands.
    pub configuration: Option<ConfigurationCounts>,
}

impl CheckReport {
    /// Record the checking boundary without changing the catalogued verdict.
    #[must_use]
    pub fn with_deferred(mut self, policies: &[crate::snapshot::DeferredPolicy]) -> Self {
        self.deferred_policies = policies.to_vec();
        self.deferred = policies.len();
        self
    }

    /// Build a report from an analysis and any findings raised before it.
    #[must_use]
    pub fn new(
        root: &Path,
        analysis: &Analysis,
        passes: Passes,
        verdicts: Verdicts,
        carrier_findings: Vec<Finding>,
    ) -> Self {
        let Verdicts {
            public_pack,
            assembly,
            burn,
            layers,
            configuration,
        } = verdicts;

        let Passes {
            profile,
            todo,
            legacy,
            claim,
            constant,
            coverage,
            index,
            matrix,
        } = passes;

        let findings: Vec<ReportedFinding> = carrier_findings
            .into_iter()
            .chain(analysis.findings().iter().cloned())
            .map(ReportedFinding::from)
            .collect();

        let failures = findings
            .iter()
            .filter(|reported| reported.severity == Severity::Failure)
            .count();

        Self {
            public_set: None,
            root: root.to_string_lossy().into_owned(),
            public_pack,
            sources_scanned: analysis.sources_scanned(),
            mints: analysis.mints(),
            citations_resolved: analysis.citations_resolved(),
            citations_resolved_unpublished: analysis.citations_resolved_unpublished(),
            heads_validated: analysis.heads_validated(),
            failures,
            warnings: findings.len() - failures,
            clean: failures == 0,
            deferred: 0,
            deferred_policies: Vec::new(),
            profile,
            todo,
            legacy,
            claim,
            constant,
            coverage,
            index,
            matrix,
            assembly,
            burn,
            layers,
            configuration,
            findings,
        }
    }
}

/// Run the check over a repository root.
///
/// The passes run in the order the two-pass invariant
/// (ADR-T-014, A calculus of documentation and source labels) fixes: the adoption data are loaded first —
/// and the signature is part of them, so the workspace is read before anything
/// is scanned — then the carriers are harvested, and only then is anything
/// resolved or validated against completed registries.
///
/// Every census of the Rust sources runs before the carrier rather than beside
/// it, because what they find is what the engine seeds the registries with: a
/// document may cite a test, a notice, or a claim, and the mint that citation
/// reaches has to be in hand before the harvest that will resolve against it.
/// The commentary's own citations are gathered in the same sweep, so that one
/// resolution pass sees both surfaces at once.
#[must_use]
pub fn check(root: &Path) -> CheckReport {
    crate::application::check(root)
}

/// Run the check over a repository root against a configuration already read.
///
/// The command reads the configuration itself, because a refused snapshot is a
/// refused precondition and the binary exits before any of this runs. Tests
/// using this lower-level entry point provide a parsed declaration explicitly.
#[must_use]
pub fn check_with(root: &Path, declared: &Configuration) -> CheckReport {
    crate::application::check_with(root, declared)
}

/// Run the check through one already-compiled execution plan.
#[must_use]
pub fn check_with_plan(plan: &ExecutionPlan) -> CheckReport {
    crate::application::check_with_plan(plan)
}

/// What the declared configuration was found to be, in counts.
///
/// The object is optional only for lower-level verification handed a refused
/// configuration. Every compiled command plan carries the parsed snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ConfigurationCounts {
    /// Nested corpora whose own snapshots account for their prose.
    pub nested: Vec<crate::snapshot::NestedCorpus>,
    /// How many owners the declaration registers.
    pub owners: usize,
    /// How many partition rows it carries.
    ///
    /// The member keeps the spelling the surface retired, because a report member
    /// is read by things outside this repository and renaming one changes the
    /// report's shape rather than a declaration. The two spellings part company
    /// here deliberately, and closing the gap is a ruling about the report rather
    /// than a consequence of the one that moved the key.
    pub inclusions: usize,
    /// How many exclusion rules it carries.
    pub excluded: usize,
    /// How many environment-and-kind rows it carries.
    pub environments: usize,
    /// How many owner-and-policy pairs it activates.
    pub pairs: usize,
    /// How many tolerated rows stand over every pair's list.
    pub rows: usize,
    /// What the owner partition over the physical tree came to.
    pub partition: PartitionCounts,
    /// How many activated pairs want a prerequisite pair nobody activated.
    pub missing_dependencies: usize,
    /// What each activated pair reached, by owner and then policy.
    pub activations: Vec<ActivationCounts>,
    /// How many findings this binary ties to no pair.
    ///
    /// Four kinds stand here. A verdict about the declaration itself rather than
    /// about any pair's share — an unaccounted path, a multiply accounted one, a
    /// prerequisite nobody activated. A refusal that precedes attribution
    /// entirely, such as a tree that could not be listed or a source that would
    /// not parse. A finding whose location the partition cannot attribute, which
    /// is the state the partition verdict has already named. And a finding whose
    /// emitting programme the taxonomy does not name on its own, because two
    /// catalogued programmes raise the variant and choosing between them here
    /// would be the invented attribution the declared relation exists to remove.
    /// Counting them keeps the arithmetic honest: the per-pair figures and this
    /// tally together are exactly the findings the report carries.
    pub unattributed_findings: usize,
}

/// What one activated owner-and-policy pair reached.
///
/// An activation that governs nothing prints exactly like one that measured a
/// share and found nothing in it, unless the report says how much each reached.
/// This entry is that statement: the pair as the declaration keys it, the size
/// of the share the declared partition attributes to its owner, what the
/// policy's own surface reaches where it declares one, and how many of the
/// run's findings this binary ties back to the pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ActivationCounts {
    /// The owner whose share the pair governs.
    pub owner: String,
    /// The policy the owner activated.
    pub policy: String,
    /// The set entry naming one deployment, where the key names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// How many tracked paths the declared partition attributes to the owner.
    ///
    /// A path counts when exactly one partition row accounts it and that row
    /// names this owner — the relation a subscription applies to route a
    /// projection, tallied once over the run's own attribution rather than
    /// walked again for every pair.
    pub paths: usize,
    /// How many participating paths the policy's own declared surface reaches,
    /// where its census domain declares one in prose or code.
    ///
    /// The share above is the owner's and the same for every pair the owner
    /// activates, which is what makes a vacuous activation print exactly like a
    /// satisfied one: a policy whose surface names trees this repository does
    /// not have reads nothing and still prints the whole share beside zero
    /// findings. This entry is the other half of that sentence — the paths the
    /// declaration's own surface rows admit — so the two numbers together say
    /// whether an activation measured a corpus or merely stood beside one.
    ///
    /// The reach is not intersected with the owner's share, because the census
    /// it stands for is not either: a policy's surface is declared once, by one
    /// owner, and governs every pair the policy stands at. A surface may
    /// therefore reach further than the share of the owner that activated it,
    /// and the row says so rather than trimming the number to make the two
    /// comparable.
    ///
    /// Absent, rather than equal to the share, where no prose-or-code surface
    /// stands in the policy's census domain. For a policy that declares no
    /// surface at all the surface *is* the owner's share and the count beside
    /// it already answers the question; writing the same number twice would
    /// invite a reader to look for a difference that cannot exist. A family
    /// whose census reads external values states its whole-file surface in
    /// another datum, which this count does not read, so such a row is absent
    /// for that reason instead. Absence is written as nothing, so a consumer
    /// reading the member finds a number exactly where a surface this count
    /// reads was declared.
    ///
    /// The count ranges over the surface's places and not over the files a
    /// census would open: a census also filters by file extension and cuts
    /// out the shares its exclusions derive, both of which are the
    /// programme's business rather than the declaration's, and this block
    /// reports the declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_paths: Option<usize>,
    /// How many of the run's findings this binary ties to the pair.
    pub findings: usize,
}

/// Harvest the cross-owner citations a dependency validation instantiates from.
///
/// A caller that has already analysed the carrier passes its own citations
/// instead; this is for the writing modes, which must answer the same question
/// before they mutate and have no analysis of their own to answer it from.
#[must_use]
pub fn harvest_citations(root: &Path) -> Vec<CitedEdge> {
    crate::application::harvest_citations(root)
}

/// Harvest dependency citations through one already-compiled execution plan.
#[must_use]
pub fn harvest_citations_with_plan(plan: &ExecutionPlan) -> Vec<CitedEdge> {
    crate::application::harvest_citations_with_plan(plan)
}

/// Judge a parsed snapshot against the repository it describes.
///
/// This is the second of the two questions a snapshot faces, and the one that is
/// judged rather than refused: the snapshot is well-formed, and what may be wrong
/// is its description of the tree. A refused declaration answers with no counts
/// and no findings — the refusal is the command's business and it exits before
/// reaching here.
#[must_use]
pub fn verify_configuration(
    root: &Path,
    configuration: &Configuration,
    citations: &[CitedEdge],
) -> (Option<ConfigurationCounts>, Vec<Finding>) {
    crate::application::verify_configuration(root, configuration, citations)
}

/// Judge one execution plan against its materialized corpus.
#[must_use]
pub fn verify_configuration_with_plan(
    plan: &ExecutionPlan,
    citations: &[CitedEdge],
) -> (Option<ConfigurationCounts>, Vec<Finding>) {
    crate::application::verify_configuration_with_plan(plan, citations)
}

/// Judge the common pre-write guard, including cited-owner dependencies.
///
/// The label pass is part of this typed guard rather than a second command-like
/// harvest beside the writer. Its result is consumed immediately and exposes no
/// independent run surface.
#[must_use]
pub fn verify_write_guard(plan: WriteGuardPlan<'_>) -> (Option<ConfigurationCounts>, Vec<Finding>) {
    crate::application::verify_write_guard(plan)
}

/// One burn list, as the burn command reports it.
#[derive(Debug, Clone, Serialize)]
pub struct BurnedFamily {
    /// The family the list counts.
    pub family: String,
    /// How many external values the effective document declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared: Option<usize>,
    /// How the declared values divide between the two match modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<MatchModeCounts>,
    /// The path of the value document actually used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Whether that document was repository-local or an outside-tree input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<BurnSourceKind>,
    /// The prose trees the family was counted over.
    pub prose: Vec<String>,
    /// The Rust trees whose comments the family was counted over.
    pub code: Vec<String>,
    /// The trees the census never read, whatever surfaces were declared.
    pub excluded: Vec<String>,
    /// How many sources the census read.
    pub files_scanned: usize,
    /// How many occurrences stand over the surfaces.
    pub occurrences: usize,
    /// How many files hold at least one.
    pub files_holding: usize,
    /// How many occurrences the declared ratchet accounts for.
    pub registered: usize,
    /// How many registered occurrences have a kept reason.
    pub kept: usize,
    /// How many registered occurrences remain owed: registered minus kept.
    pub owed: usize,
    /// The census, one row per file holding an occurrence.
    pub rows: Vec<BurnRow>,
}

/// The stdout result object of the burn command.
#[derive(Debug, Clone, Serialize)]
pub struct BurnReport {
    /// The root the censuses were taken over.
    pub root: String,
    /// Whether the command used the public-pack snapshot contract.
    pub public_pack: bool,
    /// Whether the command was allowed to write.
    pub write: bool,
    /// Whether the lowering write moved the declared list file; false without it or when the file already held what the write renders.
    pub lowered: bool,
    /// Every adopted burn list, in declaration order.
    pub families: Vec<BurnedFamily>,
    /// How many findings block the command.
    pub failures: usize,
    /// Every finding, ordered by source and position.
    pub findings: Vec<ReportedFinding>,
}

/// Census every adopted burn list and judge it against its declared ceilings.
///
/// Without `write`, the command verifies the declared lists and changes nothing.
/// With it, the command first lowers each declared ceiling to what the census
/// holds. A ceiling that overstated the tree can fall with the occurrences,
/// so that stale entry no longer needs a finding. Growth remains a finding,
/// because lowering cannot raise a ceiling; only append may record growth the
/// tree already holds under an authority-bearing request.
///
/// Direct calls to this reporter form the judgment without writing the lists;
/// their `lowered` field remains false even when `write` filters stale findings.
#[must_use]
pub fn burn(root: &Path, write: bool) -> BurnReport {
    let plan = compatibility_plan(root);
    crate::application::burn_with_write_plan(plan.burn_write(), write)
}

/// Census migration families through one already-compiled execution plan.
#[must_use]
pub fn burn_with_plan(plan: &ExecutionPlan, write: bool) -> BurnReport {
    crate::application::burn_with_plan(plan, write)
}

/// Census migration families through the narrow burn write plan.
#[must_use]
pub fn burn_with_write_plan(plan: BurnWritePlan<'_>, write: bool) -> BurnReport {
    crate::application::burn_with_write_plan(plan, write)
}

/// The stdout result object of the report command.
///
/// The report is informational: it restates what the graph is, and decides
/// nothing. Its exit status therefore never carries the findings class the check
/// owns — see the command's own contract, where the taxonomy is written down.
#[derive(Debug, Clone, Serialize)]
pub struct GraphReport {
    /// The root the carrier was taken from.
    pub root: String,
    /// How many carrier sources were scanned.
    pub sources_scanned: usize,
    /// What the reference graph looks like.
    #[serde(flatten)]
    pub summary: GraphSummary,
    /// Every citation the check found reaching no mint.
    pub dangling: Vec<ReportedFinding>,
}

/// Report the reference graph over a repository root.
///
/// The passes run exactly as the check runs them, because the graph a report
/// describes must be the graph the check decided on; anything else would let a
/// reviewer read one corpus and a gate judge another.
#[must_use]
pub fn report(root: &Path, label: Option<&Label>, hubs: usize) -> GraphReport {
    crate::application::report(root, label, hubs)
}

/// Report the reference graph through one already-compiled execution plan.
#[must_use]
pub fn report_with_plan(plan: &ExecutionPlan, label: Option<&Label>, hubs: usize) -> GraphReport {
    crate::application::report_with_plan(plan, label, hubs)
}

/// The stdout result object of the shape command.
///
/// The report measures and decides nothing, exactly as the graph report does, so
/// its exit status never carries the findings class the check owns.
#[derive(Debug, Clone, Serialize)]
pub struct ShapeReport {
    /// The root the carrier was taken from.
    pub root: String,
    /// How many carrier sources were scanned.
    pub sources_scanned: usize,
    /// What the corpus's documents and environments measure.
    #[serde(flatten)]
    pub summary: ShapeSummary,
}

/// Report the shape of a repository root's documents and environments.
#[must_use]
pub fn shape(root: &Path) -> ShapeReport {
    crate::application::shape(root)
}

/// Report document shape through one already-compiled execution plan.
#[must_use]
pub fn shape_with_plan(plan: &ExecutionPlan) -> ShapeReport {
    crate::application::shape_with_plan(plan)
}

/// The stdout result object of the coverage command.
///
/// The report is informational in the way the graph report is: it restates what
/// the claims came to and decides nothing. An intent nobody has kept and a
/// statement nobody cites are both ordinary, so the command's exit status never
/// carries the findings class the check owns.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    /// The root the claims were counted over.
    pub root: String,
    /// How many carrier sources were scanned for intents.
    pub sources_scanned: usize,
    /// What the claims of the corpus came to.
    #[serde(flatten)]
    pub summary: CoverageSummary,
}

/// Report the claim coverage over a repository root.
///
/// The passes run exactly as the check runs them, for the reason ADR-T-017 gives
/// in as many words: the census the coverage report counts is the same code the
/// check validates against, because a report counting one thing while a gate
/// judged another is a measurement nobody can act on.
///
/// The limit bounds the uncited listing alone. The intents are listed entire,
/// because enumerating the promises nobody has kept is the whole of what this
/// report is for.
#[must_use]
pub fn coverage(root: &Path, uncited: usize) -> CoverageReport {
    crate::application::coverage(root, uncited)
}

/// Report claim coverage through one already-compiled execution plan.
#[must_use]
pub fn coverage_with_plan(plan: &ExecutionPlan, uncited: usize) -> CoverageReport {
    crate::application::coverage_with_plan(plan, uncited)
}

/// One assembled publication, as the assemble command reports it.
#[derive(Debug, Clone, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent flags of one assembly's state, not a state machine"
)]
pub struct AssembledDocument {
    /// The parts directory.
    pub parts: String,
    /// The manifest declaring the order.
    pub manifest: String,
    /// The published document.
    pub target: String,
    /// Whether the parts directory is not there yet.
    pub dormant: bool,
    /// Whether the manifest carries the draft marker.
    ///
    /// A draft assembly forms no freshness verdict and refuses `--write`.
    pub draft: bool,
    /// How many parts were assembled.
    pub assembled: usize,
    /// How many bytes the assembly came to, when one was formed.
    pub bytes: Option<usize>,
    /// Whether the committed publication already carried those exact bytes.
    pub fresh: bool,
    /// Whether this run wrote the publication.
    pub written: bool,
}

/// The stdout result object of the assemble command.
#[derive(Debug, Clone, Serialize)]
pub struct AssembleReport {
    /// The root the assemblies were taken over.
    pub root: String,
    /// Whether the command was allowed to write.
    pub write: bool,
    /// Every adopted assembly, in declaration order.
    pub assemblies: Vec<AssembledDocument>,
    /// How many findings block the command.
    pub failures: usize,
    /// Every finding, ordered by source and position.
    pub findings: Vec<ReportedFinding>,
}

/// Assemble every adopted publication, verifying or writing it.
///
/// Without `write` the command forms no side effect at all: it is the exact-byte
/// freshness comparison of ADR-T-012 and nothing else, which is the mode a gate
/// runs. With it, every publication is rewritten to what its parts say it is, and
/// the freshness findings of that same run are the ones the write repaired.
#[must_use]
pub fn assemble(root: &Path, write: bool) -> AssembleReport {
    let plan = compatibility_plan(root);
    crate::application::assemble_with_write_plan(plan.assembly_write(), write)
}

/// Verify publications through one already-compiled execution plan.
#[must_use]
pub fn assemble_with_plan(plan: &ExecutionPlan, write: bool) -> AssembleReport {
    crate::application::assemble_with_plan(plan, write)
}

/// Verify publications through their typed write subplan.
#[must_use]
pub fn assemble_with_write_plan(plan: AssemblyWritePlan<'_>, write: bool) -> AssembleReport {
    crate::application::assemble_with_write_plan(plan, write)
}

/// What one projection sweep did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProjectionOutcome {
    /// How many surfaces the sweep considered.
    pub considered: usize,
    /// How many were already what their labels say they are.
    pub unchanged: usize,
    /// How many were rewritten to what their labels say.
    pub rewritten: usize,
    /// How many gained a projection they did not have.
    pub bootstrapped: usize,
}

/// The stdout result object of the project command.
///
/// The command takes the check's own taxonomy, because in its default mode it is
/// one: it regenerates both projections and compares them to the committed bytes,
/// writing nothing. With `--write` the projections are rewritten first, and the
/// staleness it repaired is no longer reported.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectReport {
    /// The root the projections were taken over.
    pub root: String,
    /// Whether the command was allowed to write.
    pub write: bool,
    /// What the in-file test indexes came to.
    pub index: ProjectionOutcome,
    /// What the per-folder test matrices came to.
    pub matrix: ProjectionOutcome,
    /// What the constant pins of ADR-T-018 came to.
    pub constant: ProjectionOutcome,
    /// How many findings block the command.
    pub failures: usize,
    /// Every finding, ordered by source and position.
    pub findings: Vec<ReportedFinding>,
}

/// Verify, or regenerate, three generated surfaces: both projections of ADR-T-017 and
/// the constant pins of ADR-T-018.
///
/// The two travel together because the record holds them to one contract: they are
/// computed from the same labels by the same rules, and a run that refreshed one
/// while leaving the other stale would leave a reader two tables disagreeing about
/// one test.
///
/// Without `write` the command forms no side effect at all, which is the mode the
/// check runs. With it, every projection is rewritten to what the labels say it
/// is, the bootstrap included: a source with no index gains one, and a folder with
/// no readme gains one.
#[must_use]
pub fn project(root: &Path, write: bool) -> ProjectReport {
    let plan = compatibility_plan(root);
    crate::application::project_with_write_plan(&plan.projection_write(), write)
}

/// Verify generated projections through one already-compiled execution plan.
#[must_use]
pub fn project_with_plan(plan: &ExecutionPlan, write: bool) -> ProjectReport {
    crate::application::project_with_plan(plan, write)
}

/// Verify or regenerate projections through their narrow write plan.
#[must_use]
pub fn project_with_write_plan(plan: &ProjectionWritePlan<'_>, write: bool) -> ProjectReport {
    crate::application::project_with_write_plan(plan, write)
}

/// Project against an already-read reconciliation.
///
/// The split is the check command's: a caller holding the declaration passes it,
/// and the convenience form reads one. A matrix label opens with the owner
/// spelling its package derives, so a corpus that has not said how its crate
/// names become owner spellings has not said what its matrices are called.
///
/// The snapshot carries the activations and partition the projections are
/// routed by. The optional form exists only for compatibility tests, which
/// compile a complete fictional snapshot when none is supplied.
#[must_use]
#[cfg(test)]
pub fn project_with(
    root: &Path,
    names: Option<&OwnerNames>,
    ignore: &[IgnoreRow],
    snapshot: Option<&Snapshot>,
    write: bool,
) -> ProjectReport {
    crate::application::project_with(root, names, ignore, snapshot, write)
}

/// The stdout result object of the fix command.
#[derive(Debug, Clone, Serialize)]
pub struct FixReport {
    /// The root the sweep was taken over.
    pub root: String,
    /// The profile whose labels were written.
    pub profile: &'static str,
    /// Whether the sweep only reported what it would do.
    pub dry_run: bool,
    /// What the sweep did.
    #[serde(flatten)]
    pub outcome: FixOutcome,
    /// How many findings the sweep raised.
    pub failures: usize,
    /// Every finding, ordered by source and position.
    pub findings: Vec<ReportedFinding>,
}

/// Sweep a repository root, writing the test profile's labels.
#[must_use]
pub fn fix(root: &Path, dry_run: bool) -> FixReport {
    let plan = compatibility_plan(root);
    crate::application::fix_with_write_plan(plan.fix_write(), dry_run)
}

/// Sweep test labels through one already-compiled execution plan.
#[must_use]
pub fn fix_with_plan(plan: &ExecutionPlan, dry_run: bool) -> FixReport {
    crate::application::fix_with_plan(plan, dry_run)
}

/// Sweep test labels through their typed write subplan.
#[must_use]
pub fn fix_with_write_plan(plan: FixWritePlan<'_>, dry_run: bool) -> FixReport {
    crate::application::fix_with_write_plan(plan, dry_run)
}

/// Sweep a repository root, writing the to-do profile's labels.
///
/// The same report as the test profile's sweep, over the second inventory
/// profile's assets, and naming the profile it swept so that a reader of the
/// JSON never has to infer which of the two produced it.
#[must_use]
pub fn fix_todo(root: &Path, dry_run: bool) -> FixReport {
    let plan = compatibility_plan(root);
    crate::application::fix_todo_with_write_plan(plan.fix_write(), dry_run)
}

/// Sweep to-do labels through one already-compiled execution plan.
#[must_use]
pub fn fix_todo_with_plan(plan: &ExecutionPlan, dry_run: bool) -> FixReport {
    crate::application::fix_todo_with_plan(plan, dry_run)
}

/// Sweep to-do labels through their typed write subplan.
#[must_use]
pub fn fix_todo_with_write_plan(plan: FixWritePlan<'_>, dry_run: bool) -> FixReport {
    crate::application::fix_todo_with_write_plan(plan, dry_run)
}

fn compatibility_plan(root: &Path) -> ExecutionPlan {
    ExecutionPlan::compile(root, configuration(root))
        .unwrap_or_else(|error| panic!("the execution plan did not compile: {error:?}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::Value;

    use super::{CheckReport, Passes, Verdicts, check};
    use crate::adoption::{Adoption, index_adoption as build_index_adoption};
    use crate::carrier::Source;
    use crate::code::CodeSurface;
    use crate::declaration::AbnfPattern;
    use crate::engine::analyze;
    use crate::snapshot::{OwnerRow, Pair};
    use crate::test_support::{byte_named_fixture, declare_surface, initialise_and_track};

    /// The activation the routing fixtures are declared under.
    ///
    /// The programme has no prerequisite of its own, so a fixture activating it
    /// declares one thing and is judged on that one thing.
    const MINTS: &str = "labels.mints-well-formed";

    fn index_adoption(
        packages: &[crate::workspace::Package],
        names: Option<&crate::roster::OwnerNames>,
        assemblies: &[crate::assembly::Assembly],
    ) -> Adoption {
        build_index_adoption(
            packages,
            names,
            assemblies,
            crate::registry::fixture_kind_registry(),
            "index",
        )
    }

    fn report_for(sources: &[Source]) -> CheckReport {
        let analysis = analyze(
            &index_adoption(
                &[],
                Some(&crate::roster::OwnerNames::new(
                    "example-",
                    [crate::roster::UnbuiltMember::new(
                        "example-project-c",
                        "packages/project-c",
                    )],
                )),
                &[],
            ),
            sources,
            &CodeSurface::default(),
        );
        CheckReport::new(
            Path::new("."),
            &analysis,
            Passes::default(),
            Verdicts::default(),
            Vec::new(),
        )
    }

    /// Failures and warnings are counted apart from one another, and only a
    /// failure spoils the verdict: a corpus carrying one of each reports one of
    /// each and is not clean, on account of the failure alone.
    ///
    /// ´claim:report:failures-and-warnings-are-counted-apart´
    /// ´test:unit:counts-failures-and-warnings-separately´
    #[test]
    fn counts_failures_and_warnings_separately() {
        let sources = [Source::new(
            "one.md",
            "Cites (`sec:demo:missing`) and nearly (`Sec:demo:head`).\n",
        )];
        let report = report_for(&sources);

        assert_eq!(report.failures, 1);
        assert_eq!(report.warnings, 1);
        assert!(!report.clean);
    }

    /// Every finding serialises with a stable machine-readable code beside its
    /// severity and the label it concerns, so a consumer can select the
    /// findings it cares about without parsing the human sentence.
    ///
    /// ´claim:report:findings-serialise-with-a-stable-code-and-severity´
    /// ´test:unit:serializes-findings-with-their-code´
    #[test]
    fn serializes_findings_with_their_code() {
        let sources = [Source::new("one.md", "Cites (`sec:demo:missing`).\n")];
        let report = report_for(&sources);
        let json = serde_json::to_value(&report).expect("serializable");

        assert!(
            json.get("schema").is_none(),
            "the object states no version of itself"
        );
        assert_eq!(json["findings"][0]["code"], "unresolved_citation");
        assert_eq!(json["findings"][0]["severity"], "failure");
        assert_eq!(json["findings"][0]["label"], "sec:demo:missing");
    }

    /// One package directory accounted to one owner.
    fn owner_row(name: &str, owner: &str, directory: &str) -> OwnerRow {
        OwnerRow {
            name: name.to_owned(),
            owner: owner.to_owned(),
            pattern: AbnfPattern::parse(format!("%s\"{directory}\" [ \"/\" *VCHAR ]"))
                .expect("a well-formed pattern"),
        }
    }

    /// The two-owner fixture partition, one package directory each.
    fn two_owners() -> Vec<OwnerRow> {
        vec![
            owner_row("orchard-package", "ORCHARD", "packages/orchard"),
            owner_row("quince-package", "QUINCE", "packages/quince"),
        ]
    }

    /// Both fixture owners activating the one programme.
    fn both_activate() -> Vec<Pair> {
        vec![
            Pair::singleton("ORCHARD", MINTS),
            Pair::singleton("QUINCE", MINTS),
        ]
    }

    /// Check a tracked fixture tree against a partition and an activation set.
    ///
    /// The declaration is written after the tree is tracked, so the fixture's
    /// own surface is untracked and enters no accounting universe: what the
    /// partition is asked to account is exactly the files the test wrote.
    fn checked(
        files: &[(&str, &str)],
        partitions: &[OwnerRow],
        policies: &[Pair],
    ) -> (CheckReport, Value) {
        let root = tempfile::tempdir().expect("a temporary root");

        for (path, text) in files {
            let path = root.path().join(path);

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a parent directory");
            }

            std::fs::write(path, text).expect("a fixture file");
        }

        initialise_and_track(root.path());
        declare_surface(root.path(), partitions, policies);

        let report = check(root.path());
        let json = serde_json::to_value(&report).expect("serializable");

        (report, json)
    }

    /// Every activated pair is listed with the number of tracked paths the
    /// declared partition attributes to its owner, so an activation that
    /// governs nothing is told apart from one that measured a share and found
    /// nothing in it.
    ///
    /// ´claim:report:every-activation-carries-its-governed-paths´
    /// ´test:unit:counts-every-activations-governed-paths´
    #[test]
    fn counts_every_activations_governed_paths() {
        let (_report, json) = checked(
            &[("packages/orchard/one.md", "## Head · `sec:demo:head`\n")],
            &two_owners(),
            &both_activate(),
        );

        assert_eq!(
            json["configuration"]["activations"],
            serde_json::json!([
                { "owner": "ORCHARD", "policy": MINTS, "paths": 1, "findings": 0 },
                { "owner": "QUINCE", "policy": MINTS, "paths": 0, "findings": 0 },
            ]),
            "an activation that governs nothing is listed beside one that governs a share"
        );
    }

    /// The burn programme whose surface the first fixtures declare.
    const TODOS: &str = "legacy.todos";

    /// A burn programme whose surface stands in its subject's domain.
    const SCENARIOS: &str = "legacy.scenario-numbers";

    /// Check a fixture tree whose declaration also gives one burn programme a
    /// surface of its own.
    ///
    /// The generic fixture writer states an allowance register for every pair,
    /// and the burn programme reads a path-count register instead, so the list
    /// document is rewritten here rather than parameterised there: what this
    /// group of tests is about is the surface, and the register is the price of
    /// activating a programme that has one.
    fn checked_with_surface(
        files: &[(&str, &str)],
        partitions: &[OwnerRow],
        owner: &str,
        policy: &str,
        domain: &str,
        surface: &str,
    ) -> Value {
        let root = tempfile::tempdir().expect("a temporary root");

        for (path, text) in files {
            let path = root.path().join(path);

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a parent directory");
            }

            std::fs::write(path, text).expect("a fixture file");
        }

        initialise_and_track(root.path());

        let policies = vec![
            Pair::singleton(owner, MINTS),
            Pair::singleton(owner, policy),
        ];
        declare_surface(root.path(), partitions, &policies);

        let directory = root.path().join(".linter");
        std::fs::write(
            directory.join("lists.toml"),
            format!(
                "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
                 [{owner}.\"{MINTS}\"]\nallowances = []\n\n\
                 [{owner}.\"{policy}\"]\npath_counts = []\n"
            ),
        )
        .expect("a list document");
        std::fs::write(
            directory.join(format!("policy-{}.toml", domain.replace('.', "-"))),
            format!(
                "namespace = \"class.linter.policy.{domain}\"\n\
                 version = [1, 0, 0]\n\n\
                 [owners.{owner}]\ncode = '%s\"{surface}\" [ \"/\" *PATHCHAR ]'\n"
            ),
        )
        .expect("a policy document");

        let report = check(root.path());

        serde_json::to_value(&report).expect("serializable")
    }

    /// An activation whose policy declares a surface of its own is listed with
    /// what that surface reaches over the participating corpus, and an
    /// activation whose policy declares none carries no second count, because
    /// for it the surface is the share the row already states.
    ///
    /// ´claim:report:every-activation-carries-what-its-surface-reaches´
    /// ´test:unit:counts-what-each-activations-surface-reaches´
    #[test]
    fn counts_what_each_activations_surface_reaches() {
        let json = checked_with_surface(
            &[
                ("packages/orchard/src/one.rs", "fn one() {}\n"),
                ("packages/orchard/two.md", "Nothing stands here.\n"),
            ],
            &two_owners(),
            "ORCHARD",
            TODOS,
            TODOS,
            "packages/orchard/src",
        );

        assert_eq!(
            json["configuration"]["activations"],
            serde_json::json!([
                { "owner": "ORCHARD", "policy": MINTS, "paths": 2, "findings": 0 },
                {
                    "owner": "ORCHARD",
                    "policy": TODOS,
                    "paths": 2,
                    "surface_paths": 1,
                    "findings": 0,
                },
            ]),
            "the surface reaches one of the two paths the corpus carries, and the \
             programme without a surface states no second count at all"
        );
    }

    /// A policy whose surface names a tree this repository does not have
    /// reaches nothing and raises a warning beside a populated share, which is
    /// the state a copied declaration is in and the one the share alone cannot
    /// tell apart from a satisfied policy. The warning names the policy and
    /// census domain without spoiling the clean verdict.
    ///
    /// ´claim:report:a-surface-naming-an-absent-tree-reaches-nothing´
    /// ´test:unit:tells-a-vacuous-surface-from-a-satisfied-one´
    #[test]
    fn tells_a_vacuous_surface_from_a_satisfied_one() {
        let json = checked_with_surface(
            &[
                ("packages/orchard/src/one.rs", "fn one() {}\n"),
                ("packages/orchard/two.md", "Nothing stands here.\n"),
            ],
            &two_owners(),
            "ORCHARD",
            TODOS,
            TODOS,
            "packages/quince/src",
        );

        let activations = json["configuration"]["activations"]
            .as_array()
            .expect("an activations list")
            .clone();

        assert_eq!(activations[1]["policy"], TODOS);
        assert_eq!(
            activations[1]["paths"], 2,
            "the share the partition attributes to the owner is not empty"
        );
        assert_eq!(
            activations[1]["surface_paths"], 0,
            "and the surface the policy declares reaches none of it"
        );
        assert_eq!(codes(&json), vec!["vacuous_surface"]);
        assert_eq!(json["findings"][0]["policy"], TODOS);
        assert_eq!(json["findings"][0]["domain"], TODOS);
        assert_eq!(json["clean"], true);
    }

    /// Two owners can activate one policy whose surface names an absent tree
    /// while a second policy governs their shares. The surface warning names
    /// the policy and census domain once, and no empty-share warning is raised.
    ///
    /// ´claim:report:a-vacuous-surface-is-named-once-per-policy´
    /// ´test:unit:names-a-surface-reaching-nothing-once-per-policy´
    #[test]
    fn names_a_surface_reaching_nothing_once_per_policy() {
        let root = tempfile::tempdir().expect("a temporary root");

        for path in ["packages/orchard/one.md", "packages/quince/two.md"] {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a parent directory"))
                .expect("a fixture directory");
            std::fs::write(path, "Nothing stands here.\n").expect("a fixture file");
        }

        initialise_and_track(root.path());

        let policies = [
            Pair::singleton("ORCHARD", MINTS),
            Pair::singleton("ORCHARD", TODOS),
            Pair::singleton("QUINCE", MINTS),
            Pair::singleton("QUINCE", TODOS),
        ];
        declare_surface(root.path(), &two_owners(), &policies);

        let directory = root.path().join(".linter");
        std::fs::write(
            directory.join("lists.toml"),
            format!(
                "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
                 [ORCHARD.\"{MINTS}\"]\nallowances = []\n\n\
                 [ORCHARD.\"{TODOS}\"]\npath_counts = []\n\n\
                 [QUINCE.\"{MINTS}\"]\nallowances = []\n\n\
                 [QUINCE.\"{TODOS}\"]\npath_counts = []\n"
            ),
        )
        .expect("a list document");
        std::fs::write(
            directory.join("policy-legacy-todos.toml"),
            "namespace = \"class.linter.policy.legacy.todos\"\n\
             version = [1, 0, 0]\n\n\
             [owners.ORCHARD]\ncode = '%s\"packages/quince/absent\" [ \"/\" *PATHCHAR ]'\n",
        )
        .expect("a policy document");

        let report = check(root.path());
        let json = serde_json::to_value(&report).expect("serializable");

        assert_eq!(codes(&json), vec!["vacuous_surface"]);
        assert_eq!(
            json["findings"],
            serde_json::json!([{
                "severity": "warning",
                "message": "activation: legacy.todos: the surface declared for legacy.todos reaches no participating path",
                "code": "vacuous_surface",
                "policy": TODOS,
                "domain": TODOS,
            }])
        );
        assert!(report.clean);
    }

    /// An activated policy reports every participating path its declared
    /// surface reaches, including paths attributed to a different owner, so
    /// its surface count can exceed the activating owner's share.
    ///
    /// ´claim:report:a-surface-reaches-beyond-its-activating-share´
    /// ´test:unit:counts-a-surface-beyond-the-activating-share´
    #[test]
    fn counts_a_surface_beyond_the_activating_share() {
        let json = checked_with_surface(
            &[
                ("packages/orchard/src/one.rs", "fn one() {}\n"),
                ("packages/quince/src/two.rs", "fn two() {}\n"),
            ],
            &two_owners(),
            "ORCHARD",
            TODOS,
            TODOS,
            "packages",
        );

        let activation = &json["configuration"]["activations"][1];
        assert_eq!(activation["policy"], TODOS);
        assert_eq!(activation["paths"], 1);
        assert_eq!(
            activation["surface_paths"], 2,
            "the declared surface also reaches the path attributed to QUINCE"
        );
    }

    /// A burn policy whose census reads a surface declared under its subject's
    /// domain reports that surface's reach, even when its policy identifier
    /// names a different document.
    ///
    /// ´claim:report:a-policy-reports-the-surface-of-its-census-domain´
    /// ´test:unit:resolves-a-surface-through-its-census-domain´
    #[test]
    fn resolves_a_surface_through_its_census_domain() {
        let json = checked_with_surface(
            &[
                ("packages/orchard/src/one.rs", "fn one() {}\n"),
                ("packages/orchard/two.md", "Nothing stands here.\n"),
            ],
            &two_owners(),
            "ORCHARD",
            SCENARIOS,
            "references.scenarios",
            "packages/orchard/src",
        );

        let activation = &json["configuration"]["activations"][1];
        assert_eq!(activation["policy"], SCENARIOS);
        assert_eq!(activation["paths"], 2);
        assert_eq!(activation["surface_paths"], 1);
    }

    /// A finding is counted against the pair whose policy emitted it and whose
    /// owner the partition attributes its location to, and every finding no
    /// pair produced is counted once beside the list, so the per-pair figures
    /// and the report's own totals reconcile exactly.
    ///
    /// ´claim:report:a-finding-is-counted-against-the-pair-that-produced-it´
    /// ´test:unit:ties-each-finding-to-the-pair-that-produced-it´
    #[test]
    fn ties_each_finding_to_the_pair_that_produced_it() {
        let (report, json) = checked(
            &[
                ("packages/orchard/one.md", "Nearly (`Sec:demo:head`).\n"),
                ("packages/quince/two.md", "Nothing stands here.\n"),
            ],
            &two_owners(),
            &both_activate(),
        );

        let activations = json["configuration"]["activations"]
            .as_array()
            .expect("an activations list")
            .clone();

        assert_eq!(activations[0]["owner"], "ORCHARD");
        assert_eq!(
            activations[0]["findings"], 1,
            "the near miss stands in the share the partition attributes to ORCHARD"
        );
        assert_eq!(activations[1]["owner"], "QUINCE");
        assert_eq!(activations[1]["findings"], 0);

        let counted: u64 = activations
            .iter()
            .filter_map(|entry| entry["findings"].as_u64())
            .sum();
        let unattributed = json["configuration"]["unattributed_findings"]
            .as_u64()
            .expect("the tally of findings no pair produced");
        let raised =
            u64::try_from(report.failures + report.warnings).expect("a representable total");

        assert_eq!(
            counted + unattributed,
            raised,
            "every finding is counted exactly once"
        );
    }

    /// A non-text name finding without a location is counted against its path-name pair and named owner, leaving no finding outside the activation tally.
    ///
    /// ´claim:report:a-non-text-name-is-counted-against-its-pair´
    /// ´test:unit:ties-a-non-text-name-to-the-pair-that-produced-it´
    #[test]
    fn ties_a_non_text_name_to_the_pair_that_produced_it() {
        let root = tempfile::tempdir().expect("a temporary root");
        std::fs::create_dir_all(root.path().join("packages/orchard"))
            .expect("the orchard directory");
        std::fs::create_dir_all(root.path().join("packages/quince")).expect("the quince directory");
        std::fs::write(
            root.path().join("packages/orchard/one.md"),
            "Nothing stands here.\n",
        )
        .expect("a text fixture");
        std::fs::write(
            root.path().join("packages/quince/two.md"),
            "Nothing stands here.\n",
        )
        .expect("a text fixture");
        let Some(_opaque) = byte_named_fixture(root.path(), b"packages/orchard/opaque\xff", "")
        else {
            return;
        };
        initialise_and_track(root.path());

        let partitions = [
            OwnerRow {
                pattern: AbnfPattern::parse("%s\"packages/orchard\" [ \"/\" *PATHCHAR ]")
                    .expect("a path-byte pattern"),
                ..owner_row("orchard-package", "ORCHARD", "packages/orchard")
            },
            owner_row("quince-package", "QUINCE", "packages/quince"),
        ];
        let policies = [
            Pair::singleton("ORCHARD", "paths.names-well-formed"),
            Pair::singleton("ORCHARD", MINTS),
            Pair::singleton("QUINCE", MINTS),
        ];
        declare_surface(root.path(), &partitions, &policies);
        std::fs::write(
            root.path().join(".linter/lists.toml"),
            "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n\
             [ORCHARD.\"paths.names-well-formed\"]\npaths = []\n\n\
             [ORCHARD.\"labels.mints-well-formed\"]\nallowances = []\n\n\
             [QUINCE.\"labels.mints-well-formed\"]\nallowances = []\n",
        )
        .expect("a path-set and an allowance list");

        let report = check(root.path());
        let json = serde_json::to_value(&report).expect("serializable");
        let activations = json["configuration"]["activations"]
            .as_array()
            .expect("an activations list");
        let orchard = activations
            .iter()
            .find(|entry| {
                entry["owner"] == "ORCHARD" && entry["policy"] == "paths.names-well-formed"
            })
            .expect("the orchard path-name pair");
        assert_eq!(orchard["findings"], 1);
        assert_eq!(json["configuration"]["unattributed_findings"], 0);
        assert_eq!(report.failures, 1);
        assert_eq!(json["findings"].as_array().expect("the findings").len(), 1);
        assert_eq!(json["findings"][0]["code"], "non_text_name");
    }

    /// A surface whose partition rows name another tree's paths governs nothing
    /// where it is run, and the report says so in the count rather than
    /// printing the silence of a corpus that was never reached.
    ///
    /// ´claim:report:a-foreign-surface-governs-no-path´
    /// ´test:unit:an-archive-shaped-surface-governs-nothing-on-a-foreign-tree´
    #[test]
    fn an_archive_shaped_surface_governs_nothing_on_a_foreign_tree() {
        let (_report, json) = checked(
            &[("src/lib.rs", "")],
            &[
                owner_row("linter-sources", "PROJECTA", "packages/superloop-lint/src"),
                owner_row("linter-tests", "PROJECTA", "packages/superloop-lint/tests"),
            ],
            &[Pair::singleton("PROJECTA", MINTS)],
        );

        assert_eq!(
            json["configuration"]["activations"],
            serde_json::json!([
                { "owner": "PROJECTA", "policy": MINTS, "paths": 0, "findings": 0 },
            ]),
            "a copied surface naming the archive's own paths reaches nothing here"
        );
    }

    /// The finding codes a report carries, in the order it carries them.
    fn codes(json: &Value) -> Vec<String> {
        json["findings"]
            .as_array()
            .map(|findings| {
                findings
                    .iter()
                    .filter_map(|finding| finding["code"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A declaration that activates no pair raises one warning saying so and
    /// naming that cause, because a run that routed nothing anywhere is not the
    /// clean verdict it would otherwise print, and a warning never spoils a
    /// clean verdict.
    ///
    /// ´claim:report:a-check-with-no-activation-says-so´
    /// ´test:unit:a-check-with-no-activation-reports-it-once´
    #[test]
    fn a_check_with_no_activation_reports_it_once() {
        let (report, json) = checked(
            &[("packages/orchard/one.txt", "Nothing stands here.\n")],
            &two_owners(),
            &[],
        );

        assert_eq!(codes(&json), vec!["nothing_governed"]);
        assert_eq!(json["findings"][0]["cause"], "no_activation");
        assert_eq!(json["findings"][0]["severity"], "warning");
        assert_eq!(report.warnings, 1);
        assert!(report.clean, "a warning never spoils a clean verdict");
    }

    /// A surface whose activations stand and whose partition attributes no path
    /// to any of their owners raises the same warning under the other cause,
    /// which is the state a declaration copied from another repository is in
    /// until its rows are rewritten.
    ///
    /// ´claim:report:a-copied-surface-names-the-cause-it-governs-nothing-by´
    /// ´test:unit:a-copied-surface-that-attributes-nothing-names-its-cause´
    #[test]
    fn a_copied_surface_that_attributes_nothing_names_its_cause() {
        let (_report, json) = checked(
            &[("src/lib.rs", "")],
            &[owner_row(
                "linter-sources",
                "PROJECTA",
                "packages/superloop-lint/src",
            )],
            &[Pair::singleton("PROJECTA", MINTS)],
        );
        let findings = json["findings"]
            .as_array()
            .expect("a findings list")
            .clone();
        let vacuity = findings
            .iter()
            .find(|finding| finding["code"] == "nothing_governed")
            .expect("the whole-check vacuity report");

        assert_eq!(vacuity["cause"], "no_attribution");
        assert_eq!(vacuity["severity"], "warning");
    }

    /// A pair that governs nothing where other pairs govern a share is named on
    /// its own, because the whole-check warning cannot see it and the run would
    /// otherwise report what it found and say nothing about the activation that
    /// reached no file.
    ///
    /// ´claim:report:an-activation-governing-nothing-is-named´
    /// ´test:unit:an-activation-governing-nothing-beside-others-names-the-pair´
    #[test]
    fn an_activation_governing_nothing_beside_others_names_the_pair() {
        let (report, json) = checked(
            &[("packages/orchard/one.md", "## Head · `sec:demo:head`\n")],
            &two_owners(),
            &both_activate(),
        );

        assert_eq!(codes(&json), vec!["ungoverned_activation"]);
        assert_eq!(json["findings"][0]["owner"], "QUINCE");
        assert_eq!(json["findings"][0]["policy"], MINTS);
        assert!(
            report.clean,
            "the pair that governs a share is judged still"
        );
    }
}
