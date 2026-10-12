// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Application orchestration behind the stable report protocol.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`declared_package_owners_select_profiles_and_cited_pairs`] | report | Declared package owners satisfy imported dependencies and select profile censuses, even when their names differ from the workspace crate names. A file-list partition attributes the member through its manifest; both fix profiles leave its bytes untouched while inactive and report its declared owner when an active sweep refuses a block documentation comment. # Panics Panics only if the fixed fixture cannot be written or its check fails. |
//! | [`missing_cited_pairs_name_the_declared_root`] | report | Missing prerequisites retain the declared root and citing owner names. # Panics Panics only if the fixed fixture cannot be written or its assertion fails. |
//! | [`a_finding_in_a_file_named_with_a_percent_is_attributed_to_its_pair`] | report | A near miss in a file whose name contains a literal percent is counted against its pair and prints the percent in the reversible display. # Panics Panics only if the fixed temporary fixture cannot be written or read. |
//! | [`a_surface_reach_counts_the_paths_under_a_partial_opening`] | report | A declared surface opening inside a component counts every participating path under its containing directory, including a different file name, because reach locates the census rather than filtering it by admission. # Panics Panics only if the fixed temporary fixture cannot be written or read. |

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::assembly::{Assembly, part_duplicate_mints, verify_assembly, write_assembly};
use crate::burn::{BurnCensus, BurnList, RegisterRow, census, census_domain_of_policy, verify};
use crate::census::take_planned_census;
use crate::claim::analyze_claims;
use crate::code::{CodeSurface, take_planned_code_citations};
use crate::constant::{
    CoveredConstant, analyze_constants, take_planned_constant_census, write_pins,
};
use crate::coverage::{DEFAULT_UNCITED, summarise_coverage};
use crate::depend::{CitedEdge, cited_edges};
use crate::engine::{Analysis, analyze};
use crate::finding::{Finding, Location, Severity, UngovernedCause};
use crate::fix::{fix_profile, fix_todos};
use crate::graph::{dangling, summarise};
use crate::index::{by_source, committed_index, verify_indexes, write_index};
use crate::label::Label;
use crate::layers::verify_layers;
use crate::legacy_profile::{analyze_legacy, cover_legacy, take_planned_legacy_census};
use crate::matrix::{
    MatrixFolder, assets_by_folder, planned_folders, verify_planned_matrices, write_matrix,
};
use crate::plan::{
    AssemblyWritePlan, BurnWritePlan, CorpusPlan, ExecutionPlan, FixWritePlan, PartitionPlan,
    ProjectionWritePlan, WriteGuardPlan,
};
use crate::profile::{CoveredAsset, TEST_KIND, analyze_profile, cover};
use crate::report::{
    ActivationCounts, AssembleReport, AssembledDocument, AssemblyCounts, BurnCounts, BurnReport,
    BurnedFamily, CheckReport, ConfigurationCounts, CoverageReport, FixReport, GraphReport, Passes,
    ProjectReport, ProjectionOutcome, ReportedFinding, ShapeReport, Verdicts,
};
use crate::roster::OwnerNames;
use crate::shape::summarise_shape;
use crate::snapshot::{Configuration, Pair, Rows, Snapshot, configuration};
use crate::spdx::{carriers, conform};
use crate::subscribe::Subscription;
use crate::todo::{TODO_KIND, analyze_todos, cover_todos, take_planned_todo_census};
use crate::workspace::Package;

pub fn check(root: &Path) -> CheckReport {
    let plan = execution_plan(root, configuration(root));
    check_with_plan(&plan)
}

pub fn check_with(root: &Path, declared: &Configuration) -> CheckReport {
    let plan = execution_plan(root, declared.clone());
    check_with_plan(&plan)
}

pub fn check_with_plan(plan: &ExecutionPlan) -> CheckReport {
    let root = plan.root();
    let declared = plan.snapshot();
    let packages = plan.workspace().packages().to_vec();
    let workspace_findings = plan.workspace().findings().to_vec();
    let names = declared.declared_owner_names();
    let adoption = plan.labels().adoption();
    let test_sources =
        plan.profiles()
            .sources_for("profile.tests-conform", plan.activations(), adoption);
    let todo_sources =
        plan.profiles()
            .sources_for("profile.todos-conform", plan.activations(), adoption);
    let (test_census, _census_findings) = take_planned_census(root, &test_sources);
    let (profile, assets, profile_findings) = analyze_profile(&packages, &test_census);

    let (todo_census, todo_census_findings) = take_planned_todo_census(root, &todo_sources);
    let (todo, todo_findings) = analyze_todos(&packages, &todo_census);
    let (legacy_census, legacy_census_findings) =
        take_planned_legacy_census(root, plan.profiles().sources());
    let (legacy, legacy_findings) = analyze_legacy(&legacy_census);
    let (legacy_sites, _legacy_cover_findings) = cover_legacy(&legacy_census);
    let claim_assets = selected_claim_assets(plan, &assets);
    let closed: Vec<_> = claim_assets
        .iter()
        .map(|asset| asset.test().package().to_owned())
        .collect();
    let (claim, claims, claim_findings) = analyze_claims(&claim_assets, &closed);
    let pins = plan
        .activations()
        .subscription(crate::subscribe::CONSTANT_PINS_POLICY);
    let (constant_census, constant_census_findings) =
        take_planned_constant_census(root, plan.profiles().constant_sources());
    let (constant, constants, constant_findings) = analyze_constants(&constant_census, &pins);
    let (code, code_findings) = label_code_surface(plan);
    let code = code.with_legacy(&legacy_sites).with_constants(&constants);

    let (sources, carrier_findings) = plan.labels().read(root);
    let analysis = analyze_for_plan(plan, &sources, &code);

    let coverage =
        summarise_coverage(&analysis, adoption, &claims, claim.covered, DEFAULT_UNCITED).counts();
    let indexes = plan
        .activations()
        .subscription(crate::subscribe::TEST_INDEXES_POLICY);
    let matrices = plan
        .activations()
        .subscription(crate::subscribe::TEST_MATRICES_POLICY);
    let (index, index_findings) = verify_indexes(root, &assets, &indexes);
    let (matrix_folders, matrix_walk_findings) =
        planned_folders(plan.profiles().sources(), names.as_ref(), &matrices);
    let (matrix, matrix_findings) = verify_planned_matrices(root, &matrix_folders, &assets);
    let (assembly, assembly_findings) = verify_assemblies(root, plan.publications());
    let (censused, burn_findings) = verify_migrations(root, plan);
    let (layers, layer_findings) =
        verify_layers(root, &packages, adoption, &analysis, declared.may_cite());
    let (mut configuration, configuration_findings) =
        verify_configuration_with_plan(plan, &cited_edges(adoption, &analysis));

    let mut before: Vec<Finding> = workspace_findings
        .into_iter()
        .chain(carrier_findings)
        .chain(profile_findings)
        .chain(todo_census_findings)
        .chain(todo_findings)
        .chain(legacy_census_findings)
        .chain(legacy_findings)
        .chain(code_findings)
        .chain(claim_findings)
        .chain(constant_census_findings)
        .chain(constant_findings)
        .chain(index_findings)
        .chain(matrix_walk_findings)
        .chain(matrix_findings)
        .chain(assembly_findings)
        .chain(burn_findings)
        .chain(layer_findings)
        .chain(configuration_findings)
        // The vacuity reports are raised here rather than where the configuration
        // is verified, because a writing mode's guard refuses on any finding at
        // all and an advisory that stopped a writer would be a warning deciding
        // an exit code.
        .chain(ungoverned_findings(configuration.as_ref()))
        .collect();

    let (public_set, public_set_findings) = crate::public_set::check(root);
    before.extend(public_set_findings);
    attribute_profile_owners(&mut before, &packages, adoption);

    // The pairs are counted here rather than where the configuration is
    // verified, because the verification runs before the passes it shares a
    // report with: what a pair produced is only known once every finding is in.
    attribute_findings(plan, &analysis, &before, configuration.as_mut());

    let passes = Passes {
        profile,
        todo,
        legacy,
        claim,
        constant,
        coverage,
        index,
        matrix,
    };

    let verdicts = Verdicts {
        public_pack: declared.public_pack(),
        assembly,
        burn: burn_counts(plan, &censused),
        layers,
        configuration,
    };

    let mut report = CheckReport::new(root, &analysis, passes, verdicts, before);
    report.public_set = public_set;
    report
}

// Label resolution still needs code mints and their owned commentary places
// outside an activated inventory profile. Covering supplies that vocabulary;
// only the selected profile runs above judge or count inventory conformance.
fn label_code_surface(plan: &ExecutionPlan) -> (CodeSurface, Vec<Finding>) {
    let packages = plan.workspace().packages();
    let (tests, mut findings) = take_planned_census(plan.root(), plan.profiles().sources());
    let (assets, _) = cover(packages, &tests);
    let (todos, _) = take_planned_todo_census(plan.root(), plan.profiles().sources());
    let (notices, _) = cover_todos(packages, &todos);
    let (_, claims, _) = analyze_claims(&assets, &[]);
    let (citations, code_findings) =
        take_planned_code_citations(plan.root(), plan.profiles().sources(), &assets);
    findings.extend(code_findings);
    (
        CodeSurface::default()
            .with_tests(&assets)
            .with_notices(&notices)
            .with_claims(&claims)
            .with_citations(citations),
        findings,
    )
}

fn selected_claim_assets(plan: &ExecutionPlan, assets: &[CoveredAsset]) -> Vec<CoveredAsset> {
    let sources = plan.profiles().sources_for(
        "profile.claims-conform",
        plan.activations(),
        plan.labels().adoption(),
    );
    assets
        .iter()
        .filter(|asset| {
            sources
                .iter()
                .any(|source| source.path() == asset.test().path())
        })
        .cloned()
        .collect()
}

fn attribute_profile_owners(
    findings: &mut [Finding],
    packages: &[Package],
    adoption: &crate::adoption::Adoption,
) {
    for finding in findings {
        let (Finding::MissingInventoryLabel { owner, .. }
        | Finding::WrongInventoryLabel { owner, .. }
        | Finding::CollidingDerivation { owner, .. }
        | Finding::MisplacedInventoryLabel { owner, .. }
        | Finding::UnderivableAssetName { owner, .. }
        | Finding::UnfixableStandardPlace { owner, .. }
        | Finding::MissingClaimLabel { owner, .. }
        | Finding::DefectiveClaimLine { owner, .. }
        | Finding::DuplicateClaimMint { owner, .. }
        | Finding::UnresolvedClaimCitation { owner, .. }) = finding
        else {
            continue;
        };
        if let Some(package) = packages.iter().find(|package| package.name() == owner) {
            *owner = adoption.owner_of(package.directory()).as_str().to_owned();
        }
    }
}

pub fn harvest_citations(root: &Path) -> Vec<CitedEdge> {
    let Ok(plan) = ExecutionPlan::compile(root, configuration(root)) else {
        return Vec::new();
    };
    harvest_citations_with_plan(&plan)
}

pub fn harvest_citations_with_plan(plan: &ExecutionPlan) -> Vec<CitedEdge> {
    let root = plan.root();
    let adoption = plan.labels().adoption();
    let (sources, _carrier_findings) = plan.labels().read(root);
    let analysis = analyze(adoption, &sources, &CodeSurface::default());

    cited_edges(adoption, &analysis)
}

pub fn verify_configuration(
    root: &Path,
    declared: &Configuration,
    citations: &[CitedEdge],
) -> (Option<ConfigurationCounts>, Vec<crate::finding::Finding>) {
    if declared.snapshot().is_none() {
        return (None, Vec::new());
    }

    let plan = execution_plan(root, declared.clone());
    verify_configuration_with_plan(&plan, citations)
}

pub fn verify_configuration_with_plan(
    plan: &ExecutionPlan,
    citations: &[CitedEdge],
) -> (Option<ConfigurationCounts>, Vec<crate::finding::Finding>) {
    verify_configuration_with_guard(plan.write_guard(), citations)
}

pub fn verify_configuration_with_guard(
    plan: WriteGuardPlan<'_>,
    citations: &[CitedEdge],
) -> (Option<ConfigurationCounts>, Vec<crate::finding::Finding>) {
    let root = plan.root();
    let snapshot = plan.snapshot();

    let corpus = plan.topology().corpus();
    let universe = corpus.base();
    let mut findings = corpus.findings().to_vec();
    let partition_plan = plan.topology().partition();
    let partition = partition_plan.counts().clone();
    let partition_findings = partition_plan.findings();
    let dependency_findings = plan.dependencies().verify(citations);

    let counts = ConfigurationCounts {
        owners: snapshot.owners().len(),
        inclusions: snapshot.partitions().len(),
        excluded: snapshot.shape().ignore().len(),
        environments: snapshot.environments().len(),
        pairs: snapshot.policies().len(),
        rows: snapshot.lists().values().map(Rows::len).sum(),
        partition,
        missing_dependencies: dependency_findings.len(),
        activations: activation_counts(snapshot, snapshot.policies(), partition_plan, corpus),
        unattributed_findings: 0,
    };

    let spdx_selection = plan.content().spdx();
    let governed = spdx_selection.governed();
    let section_findings = spdx_selection.findings();
    let carrier_findings = carriers(root, governed);

    let tolerated = |policy: &str| -> BTreeSet<&crate::pattern::BytePath> {
        snapshot
            .lists()
            .iter()
            .filter(|(pair, _)| pair.policy == policy)
            .filter_map(|(_, rows)| match rows {
                Rows::Paths(paths) => Some(paths.iter()),
                Rows::Allowances(_) | Rows::PathCounts(_) => None,
            })
            .flatten()
            .collect()
    };

    let header_findings = conform(root, snapshot.spdx(), governed, &tolerated(SPDX_POLICY));

    let interchange_selection = plan.content().interchange();
    let enveloped = interchange_selection.governed();
    let envelope_section_findings = interchange_selection.findings();
    let envelope_carrier_findings = crate::interchange::carriers(root, enveloped);
    let envelope_findings =
        crate::interchange::conform(root, enveloped, &tolerated(INTERCHANGE_POLICY));

    let names_findings = crate::names::conform(
        corpus.participating(),
        &partition_plan.attribution_view(),
        &snapshot
            .policies()
            .iter()
            .filter(|pair| pair.policy == NAMES_POLICY)
            .map(|pair| pair.owner.clone())
            .collect(),
        snapshot.names(),
        &tolerated(NAMES_POLICY),
    );

    let ceilings: BTreeMap<&crate::pattern::BytePath, u64> = snapshot
        .lists()
        .iter()
        .filter(|(pair, _)| pair.policy == REFERENCES_POLICY)
        .filter_map(|(_, rows)| match rows {
            Rows::PathCounts(rows) => Some(rows.iter()),
            Rows::Allowances(_) | Rows::Paths(_) => None,
        })
        .flatten()
        .map(|row| (&row.path, row.maximum))
        .collect();

    let reference_selection = plan.content().references();
    let governed = reference_selection.governed();
    let reference_gloss_findings = reference_selection.findings();
    let lexicon = crate::reference::Lexicon::from_tracked(universe);
    let censused = crate::reference::census(root, &lexicon, governed);
    let carrier_kind_findings = crate::reference::carriers(&censused);
    let citation_findings = crate::reference::conform(&censused, &ceilings);

    findings.extend_from_slice(partition_findings);
    findings.extend(dependency_findings);
    findings.extend_from_slice(section_findings);
    findings.extend(carrier_findings);
    findings.extend(header_findings);
    findings.extend_from_slice(envelope_section_findings);
    findings.extend(envelope_carrier_findings);
    findings.extend(envelope_findings);
    findings.extend(names_findings);
    findings.extend_from_slice(reference_gloss_findings);
    findings.extend(carrier_kind_findings);
    findings.extend(citation_findings);

    (Some(counts), findings)
}

/// List every activated pair beside the share its owner is attributed, and
/// beside what its policy's own declared surface reaches over the corpus.
///
/// The share is tallied once over the run's own attribution rather than walked
/// again per pair. The attribution admits a path exactly when one partition row
/// accounts it and names the owner, which is the test a subscription applies to
/// route a projection, so the two views cannot come to disagree; and it is a
/// relation between a path and an owner, so a pair naming one deployment of a
/// programme is attributed the same share as its owner's other pairs.
///
/// The list is sorted by owner, then policy, then deployment, because a report
/// read by a program is read twice, and two runs over one declaration must
/// print one list.
fn activation_counts(
    snapshot: &Snapshot,
    pairs: &[Pair],
    partition: &PartitionPlan,
    corpus: &CorpusPlan,
) -> Vec<ActivationCounts> {
    let mut governed: BTreeMap<&str, usize> = BTreeMap::new();

    for owner in partition.attribution().values() {
        *governed.entry(owner.as_str()).or_default() += 1;
    }

    // One tally per policy rather than per pair: a policy's surface is declared
    // once, by one owner, for every pair the policy stands at, so walking the
    // corpus again for a second pair of the same policy would answer the same
    // question twice.
    let mut reached: BTreeMap<&str, usize> = BTreeMap::new();

    for pair in pairs {
        let policy = pair.policy.as_str();

        if reached.contains_key(policy) {
            continue;
        }

        let Some(domain) = census_domain_of_policy(policy) else {
            continue;
        };

        let Some(surface) = snapshot.declared_surface(domain) else {
            continue;
        };

        let places: Vec<_> = surface.prose().iter().chain(surface.code()).collect();

        // The reach is taken over the participating corpus and is not
        // intersected with any owner's share, because the census the surface
        // governs is not either: it descends the declared trees over the
        // corpus, and one owner declares a policy's surface for every pair the
        // policy stands at. Intersecting here would report a restriction the
        // programme does not apply, which is the invented attribution the
        // declared relation exists to remove — and it would hide the case where
        // a surface reaches further than the share of the owner that activated
        // it, which the declaration is entitled to state.
        // A reach is a locator: a partial opening such as `docs/re` starts at
        // `docs`, so every participating path beneath that place is tallied.
        let count = corpus
            .participating()
            .iter()
            .filter(|key| places.iter().any(|place| place.under(key)))
            .count();

        reached.insert(policy, count);
    }

    let mut activations: Vec<ActivationCounts> = pairs
        .iter()
        .map(|pair| ActivationCounts {
            owner: pair.owner.clone(),
            policy: pair.policy.clone(),
            family: pair.family.clone(),
            paths: governed
                .get(pair.owner.as_str())
                .copied()
                .unwrap_or_default(),
            surface_paths: reached.get(pair.policy.as_str()).copied(),
            findings: 0,
        })
        .collect();

    activations.sort_by(|left, right| {
        (&left.owner, &left.policy, &left.family).cmp(&(&right.owner, &right.policy, &right.family))
    });

    activations
}

/// Report what an activation reaches nothing by: the check, pair, or surface.
///
/// The whole-check report and the per-pair one answer different questions and
/// neither subsumes the other. A declaration where every activation governs
/// nothing has measured no corpus at all, and the cause is what tells its reader
/// which document to open. A declaration where one pair governs nothing beside
/// others that do has measured a corpus, so it reports what it found and would
/// otherwise say nothing whatever about the pair that reached no file — which is
/// the silence that made removing one activation at a time the only way to find
/// out. Both advise and neither fails: what is wrong is a declaration, and a
/// corpus that is mid-adoption is entitled to be told rather than refused.
///
/// A policy's declared surface can reach no participating path even while its
/// owner's share is populated. That is a third report, raised once for the
/// policy rather than once for each pair, because one owner declares its surface
/// for all of them. It names the census domain whose surface document to open.
/// The partition and surface warnings can stand together when both reach
/// nothing: each names a different declaration to repair, and both advise.
///
/// A configuration that was refused reports nothing here, because a declaration
/// nobody could read is a refusal the command has already made rather than a
/// corpus this binary measured and found it governed none of.
fn ungoverned_findings(counts: Option<&ConfigurationCounts>) -> Vec<Finding> {
    let Some(counts) = counts else {
        return Vec::new();
    };

    let mut findings = if counts.activations.iter().all(|entry| entry.paths == 0) {
        let cause = if counts.activations.is_empty() {
            UngovernedCause::NoActivation
        } else {
            UngovernedCause::NoAttribution
        };

        vec![Finding::NothingGoverned { cause }]
    } else {
        counts
            .activations
            .iter()
            .filter(|entry| entry.paths == 0)
            .map(|entry| Finding::UngovernedActivation {
                owner: entry.owner.clone(),
                policy: entry.policy.clone(),
                family: entry.family.clone(),
            })
            .collect()
    };

    let mut named = BTreeSet::new();

    for entry in &counts.activations {
        if entry.surface_paths == Some(0) && named.insert(entry.policy.as_str()) {
            // The row's count was resolved through this same census domain.
            if let Some(domain) = census_domain_of_policy(&entry.policy) {
                findings.push(Finding::VacuousSurface {
                    policy: entry.policy.clone(),
                    domain: domain.to_owned(),
                });
            }
        }
    }

    findings
}

/// The catalogued programme that emitted a finding, where the taxonomy names one.
///
/// A finding records what is wrong rather than which activation was asking, so
/// the programme is derived from the variant and the fields the variant carries.
/// The derivation is only made where it is unambiguous: where two catalogued
/// programmes raise one variant — the publication and specification assemblies,
/// the three inventory profiles that share the derived-label variants, the
/// reference recognizers whose findings name no family — nothing is returned,
/// because choosing between them here would be an attribution nobody declared.
///
/// One source is read at most once. The local and imported citation programmes
/// are told apart by how the occurrence is written, which is a fact about the
/// source; reading it per finding would read one file once per finding standing
/// in it.
pub struct EmittingPolicy<'a> {
    /// The root the located sources stand under.
    root: &'a Path,
    /// Each source read so far, absent where it could not be read.
    sources: BTreeMap<PathBuf, Option<String>>,
}

impl<'a> EmittingPolicy<'a> {
    /// Open the join over one repository root.
    pub const fn new(root: &'a Path) -> Self {
        Self {
            root,
            sources: BTreeMap::new(),
        }
    }

    /// The programme that emitted this finding, where exactly one does.
    pub fn of(&mut self, finding: &Finding) -> Option<&'static str> {
        match finding {
            Finding::NearMiss { .. } | Finding::UnpairedBacktick { .. } => {
                Some("labels.mints-well-formed")
            }
            Finding::UnwarrantedReservedKind { .. } => Some("labels.mints-kind-conform"),
            Finding::DuplicateMint { .. } => Some("labels.mints-unique"),
            Finding::MintlessHead { .. }
            | Finding::HeadlessMint { .. }
            | Finding::UncataloguedHead { .. }
            | Finding::MisclassifiedHead { .. } => Some("labels.heads-conform"),
            Finding::DeadUnpublishedLabel { .. }
            | Finding::UnresolvedCitationWantingImport { .. }
            | Finding::UnresolvedCitationBlockedImport { .. } => {
                Some("labels.citations-local-resolve")
            }
            Finding::UnresolvedCitation { location, .. } => {
                if self.imported(location) {
                    Some("labels.citations-imported-resolve")
                } else {
                    Some("labels.citations-local-resolve")
                }
            }
            Finding::UnregisteredPrefix { .. } => Some("labels.citations-imported-resolve"),
            Finding::SelfQualifiedImport { .. } | Finding::NonParenthesizedImport { .. } => {
                Some("labels.citations-import-form")
            }
            Finding::UnreachedImport { .. } | Finding::PolicyImport { .. } => {
                Some("labels.citations-layer-conform")
            }
            Finding::DanglingGeneratedCitation { .. } | Finding::BareGeneratedOccurrence { .. } => {
                Some("labels.generated-regions-conform")
            }
            Finding::UnfulfilledOutlineEntry { .. }
            | Finding::UnclaimedHead { .. }
            | Finding::DoublyClaimedHead { .. }
            | Finding::UnknownOutlineEntry { .. }
            | Finding::UntrackableDocument { .. }
            | Finding::MalformedTrackingRow { .. }
            | Finding::ParticipatingTrackingCell { .. } => Some("labels.outlines-conform"),
            Finding::ReachDeclarationDivergence { .. }
            | Finding::ReachDeclarationOmission { .. } => Some("owners.reach-conform"),
            Finding::MissingInventoryLabel { .. } | Finding::MisplacedInventoryLabel { .. } => {
                Some("profile.tests-conform")
            }
            Finding::OrphanTodoLabel { .. } => Some("profile.todos-conform"),
            Finding::OrphanLegacyLabel { .. } => Some("profile.legacy-conform"),
            Finding::MissingClaimLabel { .. }
            | Finding::DefectiveClaimLine { .. }
            | Finding::DuplicateClaimMint { .. }
            | Finding::UnresolvedClaimCitation { .. } => Some("profile.claims-conform"),
            Finding::StaleTestIndex { .. } => Some(crate::subscribe::TEST_INDEXES_POLICY),
            Finding::StaleFolderMatrix { .. }
            | Finding::RepeatedFolderMatrix { .. }
            | Finding::WrongMatrixLevel { .. } => Some(crate::subscribe::TEST_MATRICES_POLICY),
            Finding::SpdxMultiplyIncluded { .. }
            | Finding::SpdxUngovernedPath { .. }
            | Finding::SpdxUncataloguedType { .. }
            | Finding::SpdxLinkedPath { .. }
            | Finding::SpdxIdleRow { .. }
            | Finding::SpdxMissingHeader { .. }
            | Finding::SpdxWrongIdentifier { .. }
            | Finding::SpdxRepeatedIdentifier { .. } => Some(SPDX_POLICY),
            Finding::InterchangeMultiplyIncluded { .. }
            | Finding::InterchangeGlossUncovered { .. }
            | Finding::InterchangeLinkedPath { .. }
            | Finding::InterchangeIdleRow { .. }
            | Finding::InterchangeEnvelope { .. } => Some(INTERCHANGE_POLICY),
            Finding::NonTextName { .. } => Some(NAMES_POLICY),
            Finding::FilePathCitation { .. }
            | Finding::FilePathCarrier { .. }
            | Finding::FilePathGlossUncovered { .. }
            | Finding::FilePathGlossMultiplyIncluded { .. }
            | Finding::FilePathIdleGlossRow { .. } => Some(REFERENCES_POLICY),
            Finding::BurnListGrowth { family, .. }
            | Finding::StaleBurnEntry { family, .. }
            | Finding::UndeclaredBurnSurface { family, .. } => crate::burn::policy_of(family),
            _ => None,
        }
    }

    /// Whether the occurrence at a location is written as an import.
    fn imported(&mut self, location: &Location) -> bool {
        let source = self
            .sources
            .entry(location.path().to_path_buf())
            .or_insert_with(|| fs::read_to_string(self.root.join(location.path())).ok());

        source
            .as_ref()
            .and_then(|text| text.get(location.offset()..))
            .and_then(|suffix| suffix.chars().nth(1))
            == Some('[')
    }
}

/// Count every finding against the pair that produced it.
///
/// A finding belongs to a pair when the pair's policy is the programme that
/// emitted it and the pair's owner is the owner whose share it stands in. What
/// neither half answers is counted once as unattributed rather than dropped, so
/// the entries and that tally together are the findings the report carries.
///
/// The carrier's own findings travel beside the analysis's because the report
/// joins the two, and a tally over one of them would report a pair as quiet
/// about defects the run is going to print.
fn attribute_findings(
    plan: &ExecutionPlan,
    analysis: &Analysis,
    raised: &[Finding],
    counts: Option<&mut ConfigurationCounts>,
) {
    let Some(counts) = counts else {
        return;
    };

    let partition = plan.topology().partition();
    let mut join = EmittingPolicy::new(plan.root());

    for finding in raised.iter().chain(analysis.findings()) {
        let attributed = join.of(finding).zip(governing_owner(partition, finding));
        let entry = attributed.and_then(|(policy, owner)| {
            counts.activations.iter_mut().find(|entry| {
                entry.family.is_none() && entry.policy == policy && entry.owner == owner
            })
        });

        match entry {
            Some(entry) => entry.findings += 1,
            None => counts.unattributed_findings += 1,
        }
    }
}

/// The owner whose share a finding stands in.
///
/// A located finding is attributed exactly as its path is: by the declared
/// partition, and by nothing else, so a path the verdict has already named as
/// unaccounted or multiply accounted is attributed to nobody here either. A
/// content policy's findings carry no location — what is wrong is a relation
/// between a path and the section that governs it — and name their owner
/// outright, which is the same owner the partition attributed the path to.
fn governing_owner<'a>(partition: &'a PartitionPlan, finding: &'a Finding) -> Option<&'a str> {
    let Some(location) = finding.primary_location() else {
        return named_owner(finding);
    };

    let path = location.byte_path()?;

    partition.owner(&path)
}

/// The owner a content policy's finding names, where it names one.
fn named_owner(finding: &Finding) -> Option<&str> {
    match finding {
        Finding::SpdxMultiplyIncluded { owner, .. }
        | Finding::SpdxUngovernedPath { owner, .. }
        | Finding::SpdxUncataloguedType { owner, .. }
        | Finding::SpdxLinkedPath { owner, .. }
        | Finding::SpdxIdleRow { owner, .. }
        | Finding::SpdxMissingHeader { owner, .. }
        | Finding::SpdxWrongIdentifier { owner, .. }
        | Finding::InterchangeMultiplyIncluded { owner, .. }
        | Finding::InterchangeGlossUncovered { owner, .. }
        | Finding::InterchangeLinkedPath { owner, .. }
        | Finding::InterchangeIdleRow { owner, .. }
        | Finding::NonTextName { owner, .. }
        | Finding::FilePathCarrier { owner, .. }
        | Finding::FilePathGlossUncovered { owner, .. }
        | Finding::FilePathGlossMultiplyIncluded { owner, .. }
        | Finding::FilePathIdleGlossRow { owner, .. } => Some(owner),
        _ => None,
    }
}

pub fn verify_write_guard(
    plan: WriteGuardPlan<'_>,
) -> (Option<ConfigurationCounts>, Vec<crate::finding::Finding>) {
    let adoption = plan.labels().adoption();
    let (sources, _carrier_findings) = plan.labels().read(plan.root());
    let analysis = analyze(adoption, &sources, &CodeSurface::default());

    verify_configuration_with_guard(plan, &cited_edges(adoption, &analysis))
}

fn verify_assemblies(
    root: &Path,
    publications: &crate::plan::PublicationPlan,
) -> (AssemblyCounts, Vec<Finding>) {
    let mut counts = AssemblyCounts::default();
    let mut findings = Vec::new();

    for run in publications.runs() {
        let assembly = run.assembly();
        counts.declared += 1;

        let (assembled, assembly_findings) = verify_assembly(root, assembly);

        if assembled.dormant {
            counts.dormant += 1;
        } else {
            counts.verified += 1;
            counts.parts += assembled.parts;
        }

        findings.extend(assembly_findings);
    }

    (counts, findings)
}

fn verify_migrations(
    root: &Path,
    plan: &ExecutionPlan,
) -> (Vec<(BurnList, BurnCensus)>, Vec<Finding>) {
    let mut taken = Vec::new();
    let mut findings = plan.migrations().findings().to_vec();

    for run in plan.migrations().runs() {
        let (census, census_findings) = census(
            root,
            run.list(),
            plan.topology().corpus(),
            plan.topology().partition().attribution(),
        );
        findings.extend(census_findings);

        findings.extend(verify(run.list(), &census, run.declared()));

        taken.push((run.list().clone(), census));
    }

    (taken, findings)
}

#[cfg(test)]
pub fn adopted(packages: &[Package], plan: &ExecutionPlan) -> crate::adoption::Adoption {
    let declared = plan.snapshot();
    let names = declared.declared_owner_names();
    crate::adoption::index_adoption(
        packages,
        names.as_ref(),
        plan.publications().assemblies(),
        declared.kind_registry(),
        declared.root_owner(),
    )
    .with_declared_owners(declared.owners(), Some(declared.root_owner()))
}

const SPDX_POLICY: &str = "spdx.headers-conform";
const INTERCHANGE_POLICY: &str = "interchange.envelope-conform";
const NAMES_POLICY: &str = "paths.names-well-formed";
const REFERENCES_POLICY: &str = "references.file-paths-absent";

fn burn_counts(plan: &ExecutionPlan, censused: &[(BurnList, BurnCensus)]) -> BurnCounts {
    let families: Vec<_> = censused
        .iter()
        .map(|(list, census)| {
            let declared = plan
                .migrations()
                .runs()
                .iter()
                .find(|run| run.list().family() == list.family())
                .map_or(&[][..], |run| run.declared());

            reported_burn_family(list, census, declared)
        })
        .collect();

    BurnCounts {
        declared: censused.len(),
        files_scanned: censused
            .iter()
            .map(|(_list, census)| census.files_scanned())
            .sum(),
        occurrences: censused.iter().map(|(_list, census)| census.total()).sum(),
        kept: families.iter().map(|family| family.kept).sum(),
        owed: families.iter().map(|family| family.owed).sum(),
        families,
    }
}

/// Project one census into the stable per-family report shape.
fn reported_burn_family(
    list: &BurnList,
    census: &BurnCensus,
    declared: &[RegisterRow],
) -> BurnedFamily {
    let external = list.external_values();
    let registered: usize = declared.iter().map(RegisterRow::count).sum();
    let kept: usize = declared
        .iter()
        .filter(|row| row.kept().is_some())
        .map(RegisterRow::count)
        .sum();

    BurnedFamily {
        family: list.family().to_owned(),
        declared: external.map(|values| values.values().len()),
        mode: external.map(crate::burn::ExternalBurn::mode_counts),
        source: external.map(|values| values.source().to_owned()),
        source_kind: external.map(crate::burn::ExternalBurn::source_kind),
        prose: displayed(list.prose()),
        code: displayed(list.code()),
        excluded: list
            .excluded()
            .iter()
            .map(crate::burn::Exclusion::display)
            .collect(),
        files_scanned: census.files_scanned(),
        occurrences: census.total(),
        files_holding: census.rows().len(),
        registered,
        kept,
        owed: registered - kept,
        rows: census.rows().to_vec(),
    }
}

pub fn burn_with_plan(plan: &ExecutionPlan, write: bool) -> BurnReport {
    burn_with_write_plan(plan.burn_write(), write)
}

pub fn burn_with_write_plan(plan: BurnWritePlan<'_>, write: bool) -> BurnReport {
    let root = plan.root();
    let mut families = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    for run in plan.migrations().runs() {
        let list = run.list();
        let (taken, census_findings) = census(
            root,
            list,
            plan.control().topology().corpus(),
            plan.control().topology().partition().attribution(),
        );
        findings.extend(census_findings);

        let mut judgment = verify(list, &taken, run.declared());

        if write {
            judgment.retain(|finding| matches!(finding, Finding::BurnListGrowth { .. }));
        }

        findings.append(&mut judgment);

        families.push(reported_burn_family(list, &taken, run.declared()));
    }

    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let reported: Vec<ReportedFinding> = findings.into_iter().map(ReportedFinding::from).collect();
    let failures = reported
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();

    BurnReport {
        root: root.to_string_lossy().into_owned(),
        public_pack: plan.control().snapshot().public_pack(),
        write,
        lowered: false,
        families,
        failures,
        findings: reported,
    }
}

fn displayed(paths: &[crate::areas::Place]) -> Vec<String> {
    paths.iter().map(crate::areas::Place::display).collect()
}

pub fn code_surface(plan: &ExecutionPlan, assets: &[CoveredAsset]) -> CodeSurface {
    let root = plan.root();
    let packages = plan.workspace().packages();
    let (todo_census, _census_findings) = take_planned_todo_census(root, plan.profiles().sources());
    let (notices, _cover_findings) = cover_todos(packages, &todo_census);
    let (legacy_census, _legacy_findings) =
        take_planned_legacy_census(root, plan.profiles().sources());
    let (legacy_sites, _legacy_findings) = cover_legacy(&legacy_census);
    // The wave closure is the check's verdict and no part of the surface: what is
    // taken here is the claims themselves, which stand where they were written
    // whether or not their package is held to writing them.
    let (_claim, claims, _claim_findings) = analyze_claims(assets, &[]);
    let (constant_census, _constant_findings) =
        take_planned_constant_census(root, plan.profiles().constant_sources());
    let pins = plan
        .activations()
        .subscription(crate::subscribe::CONSTANT_PINS_POLICY);
    let (_constant, constants, _constant_defects) = analyze_constants(&constant_census, &pins);
    let (citations, _code_findings) =
        take_planned_code_citations(root, plan.profiles().sources(), assets);

    CodeSurface::default()
        .with_tests(assets)
        .with_notices(&notices)
        .with_legacy(&legacy_sites)
        .with_claims(&claims)
        .with_constants(&constants)
        .with_citations(citations)
}

pub fn report(root: &Path, label: Option<&Label>, hubs: usize) -> GraphReport {
    let plan = execution_plan(root, configuration(root));
    report_with_plan(&plan, label, hubs)
}

fn analyze_for_plan(
    plan: &ExecutionPlan,
    sources: &[crate::carrier::Source],
    code: &CodeSurface,
) -> Analysis {
    let adoption = plan.labels().adoption();
    let reach = crate::layers::derive_reach(plan.root(), plan.workspace().packages(), adoption);
    crate::engine::analyze_with_policy(
        adoption,
        sources,
        code,
        Some(plan.activations().subscription("labels.heads-conform")),
        Some((&reach, plan.snapshot().may_cite())),
    )
}

pub fn report_with_plan(plan: &ExecutionPlan, label: Option<&Label>, hubs: usize) -> GraphReport {
    let root = plan.root();
    let packages = plan.workspace().packages().to_vec();
    let (test_census, _census_findings) = take_planned_census(root, plan.profiles().sources());
    let (assets, _cover_findings) = cover(&packages, &test_census);

    let (sources, _carrier_findings) = plan.labels().read(root);
    let analysis = analyze_for_plan(plan, &sources, &code_surface(plan, &assets));

    GraphReport {
        root: root.to_string_lossy().into_owned(),
        sources_scanned: analysis.sources_scanned(),
        summary: summarise(&analysis, label, hubs),
        dangling: dangling(&analysis)
            .into_iter()
            .map(ReportedFinding::from)
            .collect(),
    }
}

pub fn shape(root: &Path) -> ShapeReport {
    let plan = execution_plan(root, configuration(root));
    shape_with_plan(&plan)
}

pub fn shape_with_plan(plan: &ExecutionPlan) -> ShapeReport {
    let root = plan.root();
    let adoption = plan.labels().adoption();
    let (sources, _carrier_findings) = plan.labels().read(root);

    ShapeReport {
        root: root.to_string_lossy().into_owned(),
        sources_scanned: sources.len(),
        summary: summarise_shape(adoption, &sources),
    }
}

pub fn coverage(root: &Path, uncited: usize) -> CoverageReport {
    let plan = execution_plan(root, configuration(root));
    coverage_with_plan(&plan, uncited)
}

pub fn coverage_with_plan(plan: &ExecutionPlan, uncited: usize) -> CoverageReport {
    let root = plan.root();
    let packages = plan.workspace().packages().to_vec();
    let adoption = plan.labels().adoption();
    let (test_census, _census_findings) = take_planned_census(root, plan.profiles().sources());
    let (assets, _cover_findings) = cover(&packages, &test_census);

    let (sources, _carrier_findings) = plan.labels().read(root);
    let analysis = analyze(adoption, &sources, &code_surface(plan, &assets));

    // The report counts what is written and holds nobody to writing it, so the
    // closed set is the one input this command has no use for.
    let (claim, claims, _claim_findings) = analyze_claims(&assets, &[]);

    CoverageReport {
        root: root.to_string_lossy().into_owned(),
        sources_scanned: analysis.sources_scanned(),
        summary: summarise_coverage(&analysis, adoption, &claims, claim.covered, uncited),
    }
}

pub fn assemble_with_plan(plan: &ExecutionPlan, write: bool) -> AssembleReport {
    assemble_with_write_plan(plan.assembly_write(), write)
}

pub fn assemble_with_write_plan(plan: AssemblyWritePlan<'_>, write: bool) -> AssembleReport {
    let root = plan.root();

    let mut assemblies = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    for run in plan.publications().runs() {
        let assembly = run.assembly();
        let (assembled, mut assembly_findings) = verify_assembly(root, assembly);

        if !assembled.dormant {
            assembly_findings.extend(part_duplicate_mints(root, assembly, run.owner()));
        }

        let fresh =
            !assembled.draft && assembled.text.is_some() && !assembly_findings.iter().any(is_stale);

        if write && assembled.draft && assembled.text.is_some() {
            assembly_findings.push(Finding::DraftAssemblyWrite {
                target: crate::pattern::display_path(assembly.target()),
                parts: crate::pattern::display_path(assembly.parts()),
                manifest: crate::pattern::display_path(assembly.manifest()),
            });
        }

        let written = write
            && !assembled.draft
            && !fresh
            && write_one(
                root,
                assembly,
                assembled.text.as_deref(),
                &mut assembly_findings,
            );

        assemblies.push(AssembledDocument {
            parts: crate::pattern::display_path(assembly.parts()),
            manifest: crate::pattern::display_path(assembly.manifest()),
            target: crate::pattern::display_path(assembly.target()),
            dormant: assembled.dormant,
            draft: assembled.draft,
            assembled: assembled.parts,
            bytes: assembled.text.as_ref().map(String::len),
            fresh,
            written,
        });

        findings.extend(assembly_findings);
    }

    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let reported: Vec<ReportedFinding> = findings.into_iter().map(ReportedFinding::from).collect();
    let failures = reported
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();

    AssembleReport {
        root: root.to_string_lossy().into_owned(),
        write,
        assemblies,
        failures,
        findings: reported,
    }
}

const fn is_stale(finding: &Finding) -> bool {
    matches!(finding, Finding::StaleAssembly { .. })
}

fn write_one(
    root: &Path,
    assembly: &Assembly,
    text: Option<&str>,
    findings: &mut Vec<Finding>,
) -> bool {
    let Some(text) = text else {
        return false;
    };

    match write_assembly(root, assembly, text) {
        Ok(()) => {
            findings.retain(|finding| !is_stale(finding));

            true
        }
        Err(message) => {
            findings.push(Finding::TraversalFailure {
                path: crate::pattern::display_path(assembly.target()),
                message,
            });

            false
        }
    }
}

pub fn project_with_plan(plan: &ExecutionPlan, write: bool) -> ProjectReport {
    let writer = plan.projection_write();

    project_with_write_plan(&writer, write)
}

pub fn project_with_write_plan(plan: &ProjectionWritePlan<'_>, write: bool) -> ProjectReport {
    project_from_plan(plan, plan.names(), write)
}

#[cfg(test)]
pub fn project_with(
    root: &Path,
    names: Option<&crate::roster::OwnerNames>,
    _ignore: &[crate::universe::IgnoreRow],
    declared: Option<&crate::snapshot::Snapshot>,
    write: bool,
) -> ProjectReport {
    let snapshot = declared
        .cloned()
        .unwrap_or_else(crate::test_support::projection_snapshot);
    let configured = Configuration::Present(Box::new(snapshot));
    let plan = execution_plan(root, configured);
    let writer = plan.projection_write();

    project_from_plan(&writer, names, write)
}

fn project_from_plan(
    plan: &ProjectionWritePlan<'_>,
    names: Option<&crate::roster::OwnerNames>,
    write: bool,
) -> ProjectReport {
    let root = plan.root();
    let packages = plan.workspace().packages().to_vec();
    let workspace_findings = plan.workspace().findings().to_vec();
    let (census, census_findings) = take_planned_census(root, plan.profiles().sources());
    let (assets, cover_findings) = cover(&packages, &census);

    let mut findings: Vec<Finding> = workspace_findings
        .into_iter()
        .chain(census_findings)
        .chain(cover_findings)
        .collect();

    let indexes = plan
        .activations()
        .subscription(crate::subscribe::TEST_INDEXES_POLICY);
    let matrices = plan
        .activations()
        .subscription(crate::subscribe::TEST_MATRICES_POLICY);
    let pins = plan
        .activations()
        .subscription(crate::subscribe::CONSTANT_PINS_POLICY);

    let index = sweep_indexes(root, &assets, &indexes, write, &mut findings);
    let matrix = sweep_matrices(plan, &assets, names, &matrices, write, &mut findings);
    let constant = sweep_constants(plan, &pins, write, &mut findings);

    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let reported: Vec<ReportedFinding> = findings.into_iter().map(ReportedFinding::from).collect();
    let failures = reported
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();

    ProjectReport {
        root: root.to_string_lossy().into_owned(),
        write,
        index,
        matrix,
        constant,
        failures,
        findings: reported,
    }
}

fn sweep_constants(
    plan: &ProjectionWritePlan<'_>,
    subscription: &Subscription<'_>,
    write: bool,
    findings: &mut Vec<Finding>,
) -> ProjectionOutcome {
    let root = plan.root();
    let mut outcome = ProjectionOutcome::default();
    let (census, census_findings) =
        take_planned_constant_census(root, plan.profiles().constant_sources());
    let (analysis, covered, constant_findings) = analyze_constants(&census, subscription);

    findings.extend(census_findings);

    let governed: Vec<&CoveredConstant> = covered
        .iter()
        .filter(|constant| subscription.governs(constant.path()))
        .collect();

    outcome.considered = governed.len();
    outcome.unchanged = analysis.pinned;
    outcome.rewritten = analysis.stale_pins;
    outcome.bootstrapped = analysis.missing_pins;

    if !write {
        findings.extend(constant_findings);

        return outcome;
    }

    findings.extend(constant_findings.into_iter().filter(|finding| {
        !matches!(
            finding,
            Finding::MissingConstantPin { .. } | Finding::WrongConstantPin { .. }
        )
    }));

    let mut by_source: BTreeMap<PathBuf, Vec<&CoveredConstant>> = BTreeMap::new();

    for constant in governed {
        by_source
            .entry(constant.path().to_path_buf())
            .or_default()
            .push(constant);
    }

    for (path, constants) in by_source {
        let text = match fs::read_to_string(root.join(&path)) {
            Ok(text) => text,
            Err(error) => {
                findings.push(Finding::TraversalFailure {
                    path: crate::pattern::display_path(&path),
                    message: error.to_string(),
                });
                continue;
            }
        };

        let Some(rewritten) = write_pins(&text, &constants) else {
            continue;
        };

        if let Err(error) = fs::write(root.join(&path), rewritten) {
            findings.push(Finding::TraversalFailure {
                path: crate::pattern::display_path(&path),
                message: error.to_string(),
            });
        }
    }

    outcome
}

fn sweep_indexes(
    root: &Path,
    assets: &[CoveredAsset],
    subscription: &Subscription<'_>,
    write: bool,
    findings: &mut Vec<Finding>,
) -> ProjectionOutcome {
    let mut outcome = ProjectionOutcome::default();

    if !write {
        let (analysis, verification) = verify_indexes(root, assets, subscription);

        findings.extend(verification);
        outcome.considered = analysis.sources_covered;
        outcome.unchanged = analysis.indexed - analysis.stale;
        outcome.rewritten = analysis.stale;
        outcome.bootstrapped = analysis.unindexed;

        return outcome;
    }

    for (path, sources) in by_source(assets) {
        if crate::python::is_python(&path) {
            continue;
        }
        if !subscription.governs(&path) {
            continue;
        }

        outcome.considered += 1;

        let text = match fs::read_to_string(root.join(&path)) {
            Ok(text) => text,
            Err(error) => {
                findings.push(Finding::TraversalFailure {
                    path: crate::pattern::display_path(&path),
                    message: error.to_string(),
                });
                continue;
            }
        };

        let had = committed_index(&text).is_some();

        let Some(rewritten) = write_index(&text, &sources) else {
            outcome.unchanged += 1;
            continue;
        };

        if had {
            outcome.rewritten += 1;
        } else {
            outcome.bootstrapped += 1;
        }

        if let Err(error) = fs::write(root.join(&path), rewritten) {
            findings.push(Finding::TraversalFailure {
                path: crate::pattern::display_path(&path),
                message: error.to_string(),
            });
        }
    }

    outcome
}

fn sweep_matrices(
    plan: &ProjectionWritePlan<'_>,
    assets: &[CoveredAsset],
    names: Option<&OwnerNames>,
    subscription: &Subscription<'_>,
    write: bool,
    findings: &mut Vec<Finding>,
) -> ProjectionOutcome {
    let root = plan.root();
    let mut outcome = ProjectionOutcome::default();
    let (found, walk_findings) = planned_folders(plan.profiles().sources(), names, subscription);
    findings.extend(walk_findings);

    if !write {
        let (analysis, verification) = verify_planned_matrices(root, &found, assets);

        findings.extend(verification);
        outcome.considered = analysis.folders;
        outcome.unchanged = analysis.with_matrix - analysis.stale;
        outcome.rewritten = analysis.stale;
        outcome.bootstrapped = analysis.without_matrix;

        return outcome;
    }

    let by_folder = assets_by_folder(assets);

    for folder in &found {
        outcome.considered += 1;
        write_one_matrix(root, folder, &by_folder, &mut outcome, findings);
    }

    outcome
}

fn write_one_matrix(
    root: &Path,
    folder: &MatrixFolder,
    by_folder: &BTreeMap<PathBuf, Vec<&CoveredAsset>>,
    outcome: &mut ProjectionOutcome,
    findings: &mut Vec<Finding>,
) {
    let readme = folder.readme();
    let existing = fs::read_to_string(root.join(&readme)).ok();
    let owned: Vec<&CoveredAsset> = by_folder
        .get(folder.directory())
        .map_or_else(Vec::new, Clone::clone);

    let Some(written) = write_matrix(existing.as_deref(), folder, &owned) else {
        outcome.unchanged += 1;
        return;
    };

    if existing.is_some() {
        outcome.rewritten += 1;
    } else {
        outcome.bootstrapped += 1;
    }

    if let Err(error) = fs::write(root.join(&readme), written) {
        findings.push(Finding::TraversalFailure {
            path: crate::pattern::display_path(&readme),
            message: error.to_string(),
        });
    }
}

pub fn fix_with_plan(plan: &ExecutionPlan, dry_run: bool) -> FixReport {
    fix_with_write_plan(plan.fix_write(), dry_run)
}

pub fn fix_with_write_plan(plan: FixWritePlan<'_>, dry_run: bool) -> FixReport {
    let root = plan.root();
    let packages = plan.workspace().packages().to_vec();
    let workspace_findings = plan.workspace().findings().to_vec();
    let adoption = plan.guard().labels().adoption();
    let sources =
        plan.profiles()
            .sources_for("profile.tests-conform", plan.activations(), adoption);
    let (census, census_findings) = take_planned_census(root, &sources);
    let (assets, cover_findings) = cover(&packages, &census);
    let (outcome, mut fix_findings) = fix_profile(root, &assets, dry_run);

    let mut findings: Vec<Finding> = workspace_findings
        .into_iter()
        .chain(census_findings)
        .chain(cover_findings)
        .collect();

    findings.append(&mut fix_findings);
    attribute_profile_owners(&mut findings, &packages, adoption);
    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let reported: Vec<ReportedFinding> = findings.into_iter().map(ReportedFinding::from).collect();
    let failures = reported
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();

    FixReport {
        root: root.to_string_lossy().into_owned(),
        profile: TEST_KIND,
        dry_run,
        outcome,
        failures,
        findings: reported,
    }
}

pub fn fix_todo_with_plan(plan: &ExecutionPlan, dry_run: bool) -> FixReport {
    fix_todo_with_write_plan(plan.fix_write(), dry_run)
}

pub fn fix_todo_with_write_plan(plan: FixWritePlan<'_>, dry_run: bool) -> FixReport {
    let root = plan.root();
    let packages = plan.workspace().packages().to_vec();
    let workspace_findings = plan.workspace().findings().to_vec();
    let adoption = plan.guard().labels().adoption();
    let sources =
        plan.profiles()
            .sources_for("profile.todos-conform", plan.activations(), adoption);
    let (census, census_findings) = take_planned_todo_census(root, &sources);
    let (notices, cover_findings) = cover_todos(&packages, &census);
    let (outcome, mut fix_findings) = fix_todos(root, &notices, dry_run);

    let mut findings: Vec<Finding> = workspace_findings
        .into_iter()
        .chain(census_findings)
        .chain(cover_findings)
        .collect();

    findings.append(&mut fix_findings);
    attribute_profile_owners(&mut findings, &packages, adoption);
    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let reported: Vec<ReportedFinding> = findings.into_iter().map(ReportedFinding::from).collect();
    let failures = reported
        .iter()
        .filter(|finding| finding.severity == Severity::Failure)
        .count();

    FixReport {
        root: root.to_string_lossy().into_owned(),
        profile: TODO_KIND,
        dry_run,
        outcome,
        failures,
        findings: reported,
    }
}

fn execution_plan(root: &Path, configuration: Configuration) -> ExecutionPlan {
    ExecutionPlan::compile(root, configuration)
        .unwrap_or_else(|error| panic!("the execution plan did not compile: {error:?}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::check;
    use crate::declaration::AbnfPattern;
    use crate::finding::Finding;
    use crate::snapshot::{OwnerRow, Pair};
    use crate::test_support::{declare_surface, initialise_and_track};

    fn declared_package_fixture(extra: &[Pair], root_unique: bool) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("temporary directory");
        for (path, text) in [
            (
                "Cargo.toml",
                "[package]\nname = \"root-crate\"\nversion = \"0.1.0\"\n[workspace]\nmembers = [\"vendor/member\", \"packages/interchange\"]\n",
            ),
            ("src/lib.rs", "pub fn root() {}\n"),
            ("README.md", "## Root · `sec:demo:root`\n"),
            (
                "vendor/member/Cargo.toml",
                "[package]\nname = \"member-crate\"\nversion = \"0.1.0\"\n",
            ),
            (
                "vendor/member/src/lib.rs",
                "// ´todo:unit:orphan´\n// TODO keep vendor code unchanged\n// TODO !!!\n/** vendor test\nacross two lines */\n#[test]\nfn bare() {}\nmod nested { #[test] fn bare() {} }\n",
            ),
            (
                "packages/interchange/Cargo.toml",
                "[package]\nname = \"interchange-crate\"\nversion = \"0.1.0\"\n",
            ),
            (
                "packages/interchange/src/lib.rs",
                "// (´[ROOT-sec:demo:root]´)\npub fn cite() {}\n",
            ),
        ] {
            let file = root.path().join(path);
            fs::create_dir_all(file.parent().expect("fixture parent")).expect("fixture directory");
            fs::write(file, text).expect("fixture source");
        }
        let partitions: Vec<_> = [
            ("root", "ROOT", "( %s\"Cargo.toml\" / %s\"README.md\" / %s\"src\" [ \"/\" *VCHAR ] / %s\".linter\" [ \"/\" *VCHAR ] )"),
            ("vendor", "VENDOR", "( %s\"vendor/member/Cargo.toml\" / %s\"vendor/member/src/lib.rs\" )"),
            ("interchange", "INTERCHANGE", "%s\"packages/interchange\" [ \"/\" *VCHAR ]"),
        ].into_iter().map(|(name, owner, pattern)| OwnerRow {
            name: name.to_owned(), owner: owner.to_owned(),
            pattern: AbnfPattern::parse(pattern).expect("partition pattern"),
        }).collect();
        let mut policies = Vec::new();
        for owner in ["ROOT", "VENDOR", "INTERCHANGE"] {
            policies.push(Pair::singleton(owner, "labels.mints-well-formed"));
            if owner != "ROOT" || root_unique {
                policies.push(Pair::singleton(owner, "labels.mints-unique"));
                policies.push(Pair::singleton(owner, "labels.citations-local-resolve"));
            }
        }
        policies.push(Pair::singleton(
            "INTERCHANGE",
            "labels.citations-import-form",
        ));
        policies.push(Pair::singleton(
            "INTERCHANGE",
            "labels.citations-imported-resolve",
        ));
        policies.extend_from_slice(extra);
        declare_surface(root.path(), &partitions, &policies);
        fs::write(root.path().join(".linter/environments.toml"),
            "namespace = \"org.example.linter.environments\"\nversion = [1, 0, 0]\nenvironments = [{ environment = \"Section\", kind = \"sec\" }]\n")
            .expect("section environment");
        let owners_path = root.path().join(".linter/owners.toml");
        let owners = fs::read_to_string(&owners_path).expect("owners document");
        fs::write(
            owners_path,
            owners.replace(
                "may_cite = []",
                "may_cite = [{ owner = \"INTERCHANGE\", target = \"ROOT\" }]",
            ),
        )
        .expect("citation reach");
        initialise_and_track(root.path());
        root
    }

    /// Declared package owners satisfy imported dependencies and select profile
    /// censuses, even when their names differ from the workspace crate names.
    /// A file-list partition attributes the member through its manifest; both
    /// fix profiles leave its bytes untouched while inactive and report its
    /// declared owner when an active sweep refuses a block documentation comment.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed fixture cannot be written or its check fails.
    ///
    /// ´claim:report:declared-package-owners-select-profiles-and-cited-pairs´
    /// ´test:unit:declared-package-owners-select-profiles-and-cited-pairs´
    #[test]
    fn declared_package_owners_select_profiles_and_cited_pairs() {
        let root = declared_package_fixture(&[], true);
        let report = check(root.path());
        assert!(report.findings.is_empty(), "{:#?}", report.findings);
        assert_eq!(report.profile.files_scanned, 0);
        assert_eq!(report.todo.files_scanned, 0);
        assert_eq!(report.claim.covered, 0);
        let plan = super::execution_plan(root.path(), crate::snapshot::configuration(root.path()));
        let adoption = plan.labels().adoption();
        let vendor = root.path().join("vendor/member/src/lib.rs");
        let before = fs::read(&vendor).expect("vendor bytes");
        for fixed in [
            super::fix_with_plan(&plan, false),
            super::fix_todo_with_plan(&plan, false),
        ] {
            assert_eq!(fixed.outcome.covered, 0);
            assert_eq!(fixed.outcome.files_changed, 0);
            assert!(fixed.findings.is_empty(), "{:#?}", fixed.findings);
        }
        assert_eq!(fs::read(&vendor).expect("vendor bytes"), before);
        assert_eq!(adoption.owner_of(std::path::Path::new("")).as_str(), "ROOT");
        assert_eq!(
            adoption
                .owner_of(std::path::Path::new("vendor/member"))
                .as_str(),
            "VENDOR"
        );

        let root =
            declared_package_fixture(&[Pair::singleton("VENDOR", "profile.tests-conform")], true);
        let report = check(root.path());
        assert_eq!(report.profile.covered, 2);
        assert_eq!(report.todo.files_scanned, 0);
        assert_eq!(report.claim.covered, 0);

        let plan = super::execution_plan(root.path(), crate::snapshot::configuration(root.path()));
        let fixed = super::fix_with_plan(&plan, true);
        assert_eq!(fixed.outcome.covered, 2);
        assert_eq!(super::fix_todo_with_plan(&plan, true).outcome.covered, 0);
        assert!(fixed.findings.iter().any(|item| matches!(&item.finding,
            Finding::UnfixableStandardPlace { owner, .. } if owner == "VENDOR")));

        let root = declared_package_fixture(
            &[
                Pair::singleton("VENDOR", "profile.tests-conform"),
                Pair::singleton("VENDOR", "profile.todos-conform"),
                Pair::singleton("VENDOR", "profile.claims-conform"),
            ],
            true,
        );
        let report = check(root.path());
        let plan = super::execution_plan(root.path(), crate::snapshot::configuration(root.path()));
        let fixed = super::fix_todo_with_plan(&plan, true);
        assert_eq!(fixed.outcome.covered, 1);
        assert!(fixed.findings.iter().any(|item| matches!(&item.finding,
            Finding::UnderivableAssetName { owner, .. } if owner == "VENDOR")));
        for code in [
            "missing_inventory_label",
            "colliding_derivation",
            "missing_claim_label",
            "orphan_todo_label",
        ] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|item| item.finding.code() == code),
                "missing {code}: {:#?}",
                report.findings
            );
        }
        for item in &report.findings {
            match &item.finding {
                Finding::MissingInventoryLabel { owner, .. }
                | Finding::CollidingDerivation { owner, .. }
                | Finding::MissingClaimLabel { owner, .. } => assert_eq!(owner, "VENDOR"),
                _ => {}
            }
        }
    }

    /// Missing prerequisites retain the declared root and citing owner names.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed fixture cannot be written or its assertion fails.
    ///
    /// ´claim:report:missing-cited-pairs-name-the-declared-root´
    /// ´test:unit:missing-cited-pairs-name-the-declared-root´
    #[test]
    fn missing_cited_pairs_name_the_declared_root() {
        let root = declared_package_fixture(&[], false);
        let report = check(root.path());
        let messages: Vec<_> = report
            .findings
            .iter()
            .map(|item| item.finding.to_string())
            .collect();
        assert!(messages.iter().any(|message| message.contains("INTERCHANGE : labels.citations-imported-resolve: missing cited-owner pair ROOT : labels.mints-unique")), "{messages:#?}");
        assert!(
            messages
                .iter()
                .all(|message| !message.contains("pair index")),
            "{messages:#?}"
        );
    }

    /// A near miss in a file whose name contains a literal percent is counted
    /// against its pair and prints the percent in the reversible display.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed temporary fixture cannot be written or read.
    ///
    /// ´claim:report:a-finding-in-a-file-named-with-a-percent-is-attributed-to-its-pair´
    /// ´test:unit:a-finding-in-a-file-named-with-a-percent-is-attributed-to-its-pair´
    #[test]
    fn a_finding_in_a_file_named_with_a_percent_is_attributed_to_its_pair() {
        let root = tempfile::tempdir().expect("temporary directory");
        for (path, text) in [
            ("packages/orchard/a%41.md", "Nearly (`Sec:demo:head`).\n"),
            ("packages/quince/plain.md", "Nothing stands here.\n"),
        ] {
            let file = root.path().join(path);
            fs::create_dir_all(file.parent().expect("a parent directory"))
                .expect("fixture directory");
            fs::write(file, text).expect("fixture source");
        }
        initialise_and_track(root.path());

        let partitions = [
            OwnerRow {
                name: "orchard-package".to_owned(),
                owner: "ORCHARD".to_owned(),
                pattern: AbnfPattern::parse("%s\"packages/orchard\" [ \"/\" *VCHAR ]")
                    .expect("orchard pattern"),
            },
            OwnerRow {
                name: "quince-package".to_owned(),
                owner: "QUINCE".to_owned(),
                pattern: AbnfPattern::parse("%s\"packages/quince\" [ \"/\" *VCHAR ]")
                    .expect("quince pattern"),
            },
        ];
        let policies = [
            Pair::singleton("ORCHARD", "labels.mints-well-formed"),
            Pair::singleton("QUINCE", "labels.mints-well-formed"),
        ];
        declare_surface(root.path(), &partitions, &policies);

        let report = check(root.path());
        let near_misses: Vec<_> = report
            .findings
            .iter()
            .filter_map(|reported| match &reported.finding {
                Finding::NearMiss { location, .. } => Some(location),
                _ => None,
            })
            .collect();
        assert_eq!(near_misses.len(), 1);
        assert!(
            near_misses[0]
                .to_string()
                .starts_with("packages/orchard/a%2541.md:")
        );

        let json = serde_json::to_value(&report).expect("serializable report");
        let activations = &json["configuration"]["activations"];
        assert_eq!(activations[0]["owner"], "ORCHARD");
        assert_eq!(activations[0]["findings"], 1);
        assert_eq!(activations[1]["owner"], "QUINCE");
        assert_eq!(activations[1]["findings"], 0);
    }

    /// A declared surface opening inside a component counts every participating
    /// path under its containing directory, including a different file name,
    /// because reach locates the census rather than filtering it by admission.
    ///
    /// # Panics
    ///
    /// Panics only if the fixed temporary fixture cannot be written or read.
    ///
    /// ´claim:report:a-surface-reach-counts-the-paths-under-a-partial-opening´
    /// ´test:unit:a-surface-reach-counts-the-paths-under-a-partial-opening´
    #[test]
    fn a_surface_reach_counts_the_paths_under_a_partial_opening() {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(root.path().join("docs")).expect("docs directory");
        for name in ["readme.md", "reader.md", "other.md"] {
            fs::write(root.path().join("docs").join(name), "A source.\n").expect("fixture source");
        }

        let partitions = [OwnerRow {
            name: "all".to_owned(),
            owner: "PROJECTA".to_owned(),
            pattern: AbnfPattern::parse("*PATHCHAR").expect("partition pattern"),
        }];
        let policies = [Pair::singleton("PROJECTA", "legacy.section-references")];
        declare_surface(root.path(), &partitions, &policies);
        fs::write(
            root.path().join(".linter/lists.toml"),
            "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n[PROJECTA.\"legacy.section-references\"]\npath_counts = []\n",
        )
        .expect("list document");
        fs::write(
            root.path()
                .join(".linter/policy-legacy-section-references.toml"),
            "namespace = \"class.linter.policy.legacy.section-references\"\nversion = [1, 0, 0]\n\n[owners.PROJECTA]\nprose = '%s\"docs/re\" *VCHAR'\n",
        )
        .expect("surface document");
        initialise_and_track(root.path());

        let report = check(root.path());
        let json = serde_json::to_value(&report).expect("serializable report");
        let activations = &json["configuration"]["activations"];
        assert_eq!(activations[0]["policy"], "legacy.section-references");
        assert_eq!(activations[0]["surface_paths"], 3);
    }
}
