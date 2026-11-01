// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! # Label-calculus corpus integration tests
//!
//! Every test here runs against a corpus the test itself builds: an invented
//! workspace under a temporary root, or sources named in the test and handed
//! straight to the analysis. None of them locates the checkout they are running
//! in, and the counts they assert are the fixture's own and therefore exact.
//!
//! Whole-tree conformance is not asserted here at all. It is one invocation of
//! the shipped `check` command in the root pipeline, which judges the
//! repository's real declarations; a package that judged them too would be
//! asserting a property of a corpus it is not entitled to know exists
//! (´req:isolation:boundary´).
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`repository_programme_policy_is_deferred`] | cli | Explicit local ownership defers opaque rows and keeps their checker visible. # Panics Panics only if fixture IO fails or the binary violates the deferral contract. |
//! | [`unknown_policy_without_programme_still_refuses`] | cli | A bare unknown activation keeps the existing loader refusal. # Panics Panics only if fixture IO fails or the refusal changes. |
//! | [`catalogued_policy_cannot_claim_programme`] | cli | A published policy cannot be claimed by a local checker. # Panics Panics only if fixture IO fails or a published policy can be deferred. |
//! | [`programme_package_must_be_tracked_directory`] | cli | A programme package must be a tracked repository directory. # Panics Panics only if fixture IO fails or an invalid package is admitted. |
//! | [`programme_binary_must_be_nonempty`] | cli | An empty or whitespace-only binary does not identify a checker. # Panics Panics only if fixture IO fails or an empty binary is admitted. |
//! | [`malformed_programme_refuses`] | cli | A programme is exactly a package and binary string table. # Panics Panics only if fixture IO fails or a malformed declaration is admitted. |
//! | [`deferred_list_requires_supported_shape`] | cli | Deferral admits opaque row tables but still checks their container shape. # Panics Panics only if fixture IO fails or an invalid list shape is admitted. |
//! | [`deferred_policy_does_not_hide_catalogued_failure`] | cli | A deferred policy does not clear failures found by a catalogued policy. # Panics Panics only if fixture IO fails or deferral conceals a failure. |
//! | [`inactive_prose_fails_the_check_command`] | cli | An inactive root's Markdown fails the command until prose activation is declared. # Panics Panics only if fixture IO or command execution fails, or the verdict differs. |
//! | [`macro_doc_attributes_share_the_test_standard_place`] | carrier | A property-test macro's source-written documentation mints the same claim through line comments, separate doc attributes and one multiline attribute. Each form resolves from Markdown through the production entry. # Panics Panics only if fixture IO fails or the production check loses a macro carrier. |
//! | [`invalid_macro_carriers_refuse_by_name`] | carrier | A marked macro body that cannot be read refuses by name, and a misplaced claim remains a placement failure instead of being rescued by its spelling. # Panics Panics only if fixture IO fails or the check accepts an invalid macro carrier. |
//! | [`python_docstrings_participate_in_production_resolution`] | carrier | An owned Python unittest method mints a claim that a Markdown record can cite, and the active profiles count its docstring as a labelled test site. # Panics Panics only if fixture IO fails or the production check violates the contract. |
//! | [`duplicate_python_claims_are_named`] | carrier | A second Python test minting the same claim is refused with the claim's name and both sites instead of disappearing from the label census. # Panics Panics only if fixture IO fails or the production check loses the duplicate. |
//! | [`python_source_boundaries_are_explicit`] | carrier | Python syntax errors refuse by name, while ordinary strings and files outside the owned test-path convention never mint a claim. # Panics Panics only if fixture IO fails or source selection misclassifies the fixture. |
//! | [`an_export_round_trips_through_the_import_loader`] | cli | Export writes every fixture mint with its kind and head, and the import loader reads it back with the same relation. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`two_exports_over_one_tree_are_byte_identical`] | cli | Two exports of one immutable tree have identical bytes, including the source header. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or read. |
//! | [`an_export_refuses_an_unknown_owner`] | cli | An export whose owner is absent refuses as a command failure and writes no document. # Panics Panics only if the temporary fixture cannot be created, written, tracked, or executed. |
//! | [`export_refuses_bad_configuration_and_output_path`] | cli | Export refuses a bad configuration before writing and reports an output failure by its path. # Panics Panics only if the temporary fixture cannot be created, written, tracked, or executed. |
//! | [`export_build_mode_publishes_report_and_stamp`] | cli | Export build mode publishes its JSON report and touches its stamp after writing the registry. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`an_imported_citation_resolves_through_a_registry`] | check | A package's bracketed citation reaches a mint published by another repository when its may-cite row declares the edge. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`a_retired_imported_label_is_unresolved`] | check | Removing an imported label leaves its citation as the ordinary unresolved citation failure. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`an_import_with_different_kinds_is_refused`] | snapshot | A changed kind relation refuses the import before the corpus can be checked. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`format_namespaces_refuse_foreign_identities_before_checking`] | snapshot | Format namespaces admit corpus-owned core envelopes, preserve the declared burn surface, and refuse foreign lists, policy instances and registries with both the offending namespace and the expected identity before checking. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed or parsed, or if the binary violates the namespace contract. |
//! | [`unknown_registry_namespace_and_major_are_refused`] | snapshot | The import loader names an unknown namespace and its expected identity, and distinguishes an unknown major version from a namespace refusal. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`a_malformed_imported_registry_is_refused`] | snapshot | A malformed published document refuses the importing snapshot by the registry's path. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`an_imported_owner_with_a_partition_is_refused`] | snapshot | An imported owner cannot also claim any partition of the importing tree. # Panics Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`every_covered_asset_of_a_fixture_seeds_one_derived_mint`] | check | Every covered asset seeds exactly one derived mint, so the count of derived mints is the count of covered assets and neither an asset nor a mint is lost between the census and the analysis. The relation is one-to-one rather than merely bounded, so a collision that folded two assets into one label would show as a shortfall here. |
//! | [`a_document_citing_a_live_test_resolves_and_a_dead_one_does_not`] | check | Against a census taken from an invented workspace, all four ways of naming a test behave as the calculus says: a citation of a live test resolves, a citation of a name nobody wrote fails, a document of another owner reaches it by importing with the owner's prefix, and writing the label bare mints nothing. |
//! | [`a_cross_owner_citation_without_brackets_fails`] | check | A citation crossing an ownership boundary must say so: written bare it fails, and the failure names the owner that minted the label and spells out the imported form to write instead — delimiters included, since a rendering without them is the one form the grammar reads as nothing. Written that way it resolves. The reader is handed the repair rather than the rule. |
//! | [`a_head_the_registry_denies_fails_the_check`] | head | cites (´claim:head:a-head-whose-kind-contradicts-its-name-is-a-failure´) |
//! | [`head_checks_follow_owner_activation`] | head | Head validation follows each declared owner's activation independently. # Panics Panics only if the fixture cannot be written or the binary violates the activation contract. |
//! | [`an_outline_and_its_document_track_both_ways`] | check | Outline tracking holds end to end and in both directions: a matching pair passes the command, a head the outline claims going missing fails at the claiming row, and a head no row claims fails at the head with the omitting outline named beside it. Each failure points where the repair belongs. |
//! | [`the_report_command_describes_the_graph_without_judging_it`] | cli | The report describes and never judges: an uncited mint and a dangling citation are both listed and the command still exits zero, while the check over the same tree fails that citation. A reverse lookup answers when asked, and a malformed question is a usage failure that prints nothing. |
//! | [`a_small_declared_graph_reports_totals_orphans_dangles_and_hubs`] | graph | The report over a small declared graph is internally consistent: the totals are the mints and citations the sources carry, a citation of a name nobody minted is listed as dangling, the mints nobody cites are the orphans and not every mint is one, the hubs come back ranked by how often they are cited, and within every owner the mints cited and the mints uncited add up to the mints there are. |
//! | [`an_assembled_publication_stales_when_a_part_changes`] | assembly | The assemble and check commands agree through the whole cycle: unpublished parts are stale and the check mode writes nothing, writing settles them in the manifest's order, editing a part stales the publication again, reassembly repairs it, and a further write finds nothing to do. |
//! | [`the_assemble_command_reports_elapsed_micros`] | cli | The assemble command reports its wall time in the result object, matching the judging commands that decide a corpus verdict. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`an_unlisted_part_is_reported_rather_than_dropped`] | assembly | cites (´claim:assembly:a-part-no-row-names-is-reported-and-the-rest-still-assemble´) |
//! | [`a_draft_assembly_forms_no_freshness_verdict_and_refuses_write`] | assembly | A draft assembly is checked for membership but not for freshness, and writing one is refused outright so a partial assembly cannot overwrite the standing publication. An unlisted part still fires while the manifest is a draft, and removing the marker restores the freshness verdict over the very same tree. |
//! | [`the_shape_command_measures_without_judging`] | cli | The shape report measures and never judges: it counts environments, marks which are divisions, distributes the two kinds apart, and exits zero regardless. It compares the corpus with nothing, so an invented tree is reported exactly as the repository is. |
//! | [`a_fixture_census_covers_and_derives_every_test_function`] | census | The census over an invented workspace classifies and derives a label for every test function it holds, with none left underivable, and the invented manifests populate every area the profile supports. What is asserted is completeness rather than magnitude: the classification reaches the whole census, and no area goes unexercised because the fixture forgot to write one. |
//! | [`every_edge_of_a_fixture_reference_graph_lands_on_a_mint`] | graph | Every edge of a reference graph lands on a mint at both ends, and there are several edges to check rather than one: the analysis carries no edge whose endpoint is not a node of the graph it belongs to. |
//! | [`a_fixture_corpus_resolves_across_files`] | check | cites (´claim:check:the-traversal-order-decides-nothing´) |
//! | [`a_fixture_corpus_reports_every_rule_it_breaks`] | check | A corpus breaking every rule at once is told about every one of them, not merely the first: each defect is reported with its own code, and the findings arrive ordered by source and then by position, which is the order a reader would walk the tree in. |
//! | [`displayed_material_never_participates`] | prose | cites (´claim:prose:a-non-participating-region-yields-neither-occurrence-nor-finding´) |
//! | [`the_check_command_emits_json_and_exits_clean`] | cli | The check command emits exactly one JSON object on standard output, carrying the run's counts and stating no version of itself, and exits zero over a clean tree. A caller can parse the result without reading prose. |
//! | [`the_check_command_reports_elapsed_micros`] | cli | The check command reports its wall time in the result object, matching the other judging commands that decide a corpus verdict. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`the_check_command_exits_nonzero_on_findings`] | cli | A tree with findings exits with the documented failure code and still emits its report, so a caller learns both that the run failed and precisely what failed from the same invocation. |
//! | [`a_fixture_package_tree_checks_and_then_fixes_clean`] | cli | Check, sweep, and check again leaves a tree clean and settled: the first check counts what is missing, wrong and already right; the sweep inserts, repairs and leaves alone exactly those; the second check passes; the author's own line survives with the label indented to match; and a further sweep changes nothing. |
//! | [`the_fix_command_writes_nothing_on_a_dry_run`] | fix | cites (´claim:fix:a-dry-run-counts-what-it-would-do-and-writes-nothing´) |
//! | [`the_fix_command_refuses_a_dirty_tree`] | cli | The sweep refuses to run over a tree carrying uncommitted changes and writes nothing, so its edits always arrive as a diff a reviewer can read against a clean baseline. |
//! | [`a_fixture_notice_tree_checks_and_then_fixes_clean`] | cli | cites (´claim:cli:check-then-sweep-then-check-leaves-a-tree-clean-and-settled´) |
//! | [`the_todo_sweep_writes_nothing_on_a_dry_run`] | fix | cites (´claim:fix:a-dry-run-counts-what-it-would-do-and-writes-nothing´) |
//! | [`a_burn_list_fails_on_growth_and_on_a_stale_row`] | burn | The ratchet binds in both directions: the census as found passes, one more reference fails as growth with the new occurrence named, and one fewer fails as a stale row until the list falls with it. A file losing its last reference leaves the list rather than standing at zero. |
//! | [`the_burn_command_emits_json_and_writes_nothing_by_default`] | cli | The burn command reports and writes nothing unless asked: every adopted family is registered at its census, none is rewritten, and the trees excluded from each census are named in the report rather than left to be remembered. |
//! | [`kept_and_owed_counts_sum_across_families`] | cli | A family with kept and unkept rows retains their full registered count while reporting the two parts, and the check report sums each part across two families. # Panics Panics only if the temporary fixture cannot be read, written, executed, or parsed. |
//! | [`the_burn_write_lowers_nothing_from_an_empty_declaration_and_keeps_growth`] | cli | A lowering write over empty declared lists has no ceiling to lower: growth in two files remains a finding for each file, and only append may record it. The declaration and the rest of the tree retain their bytes. |
//! | [`the_burn_command_reports_elapsed_micros`] | cli | The burn command reports its wall time in the result object, matching the judging commands that decide a corpus verdict. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`the_external_document_in_public_pack_mode_is_honored_and_its_path_reported`] | burn | Public-pack mode reads the outside-tree document when the declared local document is absent, reports the supplied path and external source kind, and uses its modes to find public occurrences with their file and line while preserving the policy-local exclusion. |
//! | [`two_runs_over_the_same_tree_produce_payload_identical_reports`] | report | Two superloop-pack checks over the same immutable tree and verifier input emit identical JSON payloads after eliding the wall-time field, so neither filesystem order nor value matching introduces report drift. |
//! | [`a_clean_build_check_publishes_stable_report_bytes`] | cli | A clean build check publishes stable report bytes and an empty, refreshed stamp. # Panics Panics only if the fixture cannot be written or the linter violates the stamp contract. |
//! | [`a_failing_build_check_never_stamps_success`] | cli | A completed check with findings writes a report but never a success stamp. # Panics Panics only if the fixture cannot be written or a failing check stamps success. |
//! | [`a_nonempty_build_stamp_is_preserved_and_refused`] | cli | A stamp carrying foreign bytes is preserved and refused. # Panics Panics only if the fixture cannot be written or a foreign stamp is changed. |
//! | [`incomplete_and_writing_output_pairs_are_usage_errors`] | cli | An incomplete pair and a write paired with check outputs are usage errors. # Panics Panics only if the subprocess cannot run or invalid arguments are admitted. |
//! | [`an_absent_declaration_refuses_without_running_the_command`] | cli | A tree with no declaration directory refuses with an empty stdout before command dispatch and names all five required documents on stderr in their declared order. |
//! | [`a_refused_snapshot_exits_one_with_an_empty_stdout`] | cli | A declaration that is not a snapshot refuses the command entire: the exit is the shared failure class rather than the findings class, and stdout is empty. A command that cannot read its own configuration has no standing to say anything about the corpus, so it says nothing rather than reporting a verdict it could not have formed. |
//! | [`a_dependent_policy_without_label_prerequisites_refuses_loudly`] | cli | A profile activated without the label calculus it reads refuses every command before dispatch. The shared configuration-failure surface keeps stdout empty and names the missing same-owner label prerequisite on stderr, so an incomplete declaration cannot silently run a partial policy. |
//! | [`a_parsed_snapshot_that_disagrees_is_judged_rather_than_refused`] | cli | A snapshot whose declaration is complete but whose partition disagrees with the tree is judged rather than refused: the run happens, the object is complete, and the exit is the findings class with the unaccounted path named in the report. |
//! | [`a_writing_mode_refuses_a_declaration_that_disagrees_with_the_tree`] | cli | Every writing mode refuses to mutate under a declaration that disagrees with the tree. That is stricter than the exit codes alone require and deliberately so: a writer that proceeded would record a conclusion drawn from a question the corpus had not answered, so it exits the failure class with an empty stdout instead. |
//! | [`a_title_minting_the_departed_document_kind_fails_at_the_catalogue`] | head | cites (´claim:head:a-title-validates-on-every-kind-the-relation-rows-its-environment´) |
//! | [`characterizes_no_surface_bytes`] | harness | Every command class refuses with the same empty data streams when the required shape document is absent from an invented root. |
//! | [`characterizes_check_bytes`] | harness | A check over this deliberately undeclared fixture refuses before findings can be ordered. |
//! | [`the_check_reports_a_corpus_finding_once`] | cli | A corpus finding is reported once because reporting it twice doubles a failure count a reader acts on and names the same repair twice. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed. |
//! | [`the_check_reports_a_missing_tracked_path_once`] | cli | A missing tracked Markdown path draws one corpus finding and no reader failure, so one absent file names one repair; restoring its bytes clears it. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed. |
//! | [`the_activation_reach_counts_a_missing_tracked_path`] | cli | A declared census surface counts both tracked paths before and after one leaves the checkout, while check reports the absent file once without calling the surface vacuous. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed. |
//! | [`characterizes_informational_bytes`] | harness | Each informational command refuses before dispatch over this deliberately undeclared fixture. |
//! | [`characterizes_burn_bytes`] | harness | The burn report fixes its census rows and every surrounding report byte. |
//! | [`characterizes_control_bytes`] | harness | The control response file and stdout are one frozen byte sequence. |
//! | [`characterizes_projection_bytes`] | harness | Projection fixes the report and every file the writer owns. |
//! | [`the_project_command_reports_elapsed_micros`] | cli | The project command reports its wall time in the result object, matching the judging commands that decide a corpus verdict. # Panics Panics only when the temporary fixture cannot be created, written, tracked, executed, or parsed. |
//! | [`characterizes_assembly_bytes`] | harness | Assembly fixes both its report and the generated publication. |
//! | [`characterizes_fix_bytes`] | harness | Both fix profiles refuse before writing over deliberately undeclared fixtures, freezing the refusal and the untouched sources. |
//! | [`citation_sites_preserve_resolved_addresses`] | cli | The executable protocol preserves citations before the first mint and exposes no document text. # Panics Panics only if fixture IO fails or the command violates its versioned protocol. |
//! | [`nested_root_containment_uses_tracked_paths`] | cli | Nested containment ignores untracked files but refuses tracked foreign ownership. # Panics Panics only if fixture IO fails or the binary violates the containment contract. |
//! | [`deferred_list_rewrite_preserves_bytes_and_order`] | cli | Rewriting catalogued lists preserves an intervening deferred table's bytes and position. # Panics Panics only if fixture IO fails or a rewrite changes opaque source. |
//! | [`programme_outside_checkout_names_tracked_directory_requirement`] | cli | A programme outside Git names its row and its tracked-directory requirement. # Panics Panics only if fixture IO fails or the refusal loses its feature context. |

use std::borrow::Cow;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use superloop_lint::{
    Adoption, Assembly, BurnList, CodeSurface, ExecutionPlan, Finding, LegacyRule, Location,
    OwnerNames, Package, RegisterRow, RegistryDocument, Shape, Source, analyze, analyze_profile,
    census, configuration, fixture_kind_registry, index_adoption as build_index_adoption,
    take_census, verify, verify_layers,
};

fn exported_fixture() -> RegistryDocument {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/fixture.md",
        "## One · `sec:fixture:one`\n\n## Two · `sec:fixture:two`\n",
    );
    ensure_fixture_surface(root.path());
    track(root.path());
    let out = root.path().join("registry.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["export", "--owner", "PROJECTA", "--root"])
        .arg(root.path())
        .arg("--out")
        .arg(&out)
        .output()
        .expect("export fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    RegistryDocument::parse(&fs::read_to_string(out).expect("read registry"))
        .expect("parse registry")
}

fn carrier_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary corpus");
    let policies = [
        "labels.mints-well-formed",
        "labels.mints-unique",
        "labels.citations-local-resolve",
        "profile.tests-conform",
        "profile.claims-conform",
    ];
    let mut activations = String::from("policies = [\n");
    let mut lists = String::new();
    for policy in policies {
        writeln!(
            activations,
            "{{ owner = \"PROJECTA\", policy = \"{policy}\" }},"
        )
        .expect("string");
        writeln!(lists, "[PROJECTA.\"{policy}\"]\nallowances = []").expect("string");
    }
    activations.push_str("]\n");
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{ name = \"python-tests\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        &activations,
        &lists,
    );
    root
}

fn python_fixture() -> tempfile::TempDir {
    let root = carrier_fixture();
    write(
        root.path(),
        "ci/test_docstring_carrier.py",
        include_str!("../../../ci/test_docstring_carrier.py"),
    );
    write(
        root.path(),
        "docs/python.md",
        "## Python · `sec:carrier:python`\n\nThe method establishes (`claim:carrier:python-method-documentation-is-citable`).\n",
    );
    track(root.path());
    root
}

fn check_carrier(root: &Path) -> (std::process::Output, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root)
        .output()
        .expect("production entry");
    let report = serde_json::from_slice(&output.stdout).expect("check report");
    (output, report)
}

const LOCAL_POLICY: &str = "profile.notice-dispositions-conform";
const LOCAL_PROGRAMME: &str = "{ package = \"packages/local-lint\", binary = \"local-lint\" }";

fn programme_fixture(policy: &str, programme: Option<&str>, list: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary corpus");
    write(
        root.path(),
        "packages/local-lint/checker.txt",
        "repository checker\n",
    );
    write(root.path(), "adr/one.md", "## One · `sec:fixture:one`\n");
    let mut activation = format!("{{ owner = \"PROJECTA\", policy = \"{policy}\"");
    if let Some(programme) = programme {
        write!(activation, ", programme = {programme}").expect("string");
    }
    activation.push_str(" }");
    let policies = if policy == "labels.mints-well-formed" {
        format!("policies = [{activation}]\n")
    } else {
        format!(
            "policies = [{{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }}, {activation}]\n"
        )
    };
    let lists = if policy == "labels.mints-well-formed" {
        format!("[PROJECTA.\"{policy}\"]\n{list}\n")
    } else {
        format!("{DECLARED_LISTS}\n[PROJECTA.\"{policy}\"]\n{list}\n")
    };
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        &policies,
        &lists,
    );
    track(root.path());
    root
}

fn assert_programme_refusal(root: &Path, message: &str) {
    let output = programme_command(root, &["check", "--text"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "{stderr}");
}

/// Explicit local ownership defers opaque rows and keeps their checker visible.
///
/// # Panics
/// Panics only if fixture IO fails or the binary violates the deferral contract.
///
/// ´claim:cli:repository-programme-policy-is-deferred´
/// ´test:integration:repository-programme-policy-is-deferred´
#[test]
fn repository_programme_policy_is_deferred() {
    for field in ["allowances", "path_counts"] {
        let list = format!("{field} = [{{ local_identity = \"opaque\", decision = \"kept\" }}]");
        let root = programme_fixture(LOCAL_POLICY, Some(LOCAL_PROGRAMME), &list);
        let output = programme_command(root.path(), &["check"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(report["clean"], true);
        assert_eq!(report["deferred"], 1);
        assert_eq!(
            report["deferred_policies"],
            serde_json::json!([{
                "owner": "PROJECTA", "policy": LOCAL_POLICY,
                "package": "packages/local-lint", "binary": "local-lint"
            }])
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .matches("deferred to the repository's own programme: 1 rows")
                .count(),
            1
        );
        let output = programme_command(root.path(), &["burn", "--write"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lists: toml::Table = toml::from_str(
            &fs::read_to_string(root.path().join(".linter/lists.toml")).expect("lists"),
        )
        .expect("table");
        assert_eq!(
            lists["PROJECTA"][LOCAL_POLICY][field][0]["local_identity"].as_str(),
            Some("opaque")
        );
        assert_eq!(
            programme_command(root.path(), &["check"]).status.code(),
            Some(0)
        );
    }
}

/// A bare unknown activation keeps the existing loader refusal.
///
/// # Panics
/// Panics only if fixture IO fails or the refusal changes.
///
/// ´claim:cli:unknown-policy-without-programme-still-refuses´
/// ´test:integration:unknown-policy-without-programme-still-refuses´
#[test]
fn unknown_policy_without_programme_still_refuses() {
    let root = programme_fixture(LOCAL_POLICY, None, "allowances = []");
    assert_programme_refusal(
        root.path(),
        &format!(".linter/policies.toml: {LOCAL_POLICY}: this binary catalogues no such policy"),
    );
}

/// A published policy cannot be claimed by a local checker.
///
/// # Panics
/// Panics only if fixture IO fails or a published policy can be deferred.
///
/// ´claim:cli:catalogued-policy-cannot-claim-programme´
/// ´test:integration:catalogued-policy-cannot-claim-programme´
#[test]
fn catalogued_policy_cannot_claim_programme() {
    let root = programme_fixture(
        "labels.mints-well-formed",
        Some(LOCAL_PROGRAMME),
        "allowances = []",
    );
    assert_programme_refusal(
        root.path(),
        "programme cannot claim a policy this binary catalogues",
    );
}

/// A programme package must be a tracked repository directory.
///
/// # Panics
/// Panics only if fixture IO fails or an invalid package is admitted.
///
/// ´claim:cli:programme-package-must-be-tracked-directory´
/// ´test:integration:programme-package-must-be-tracked-directory´
#[test]
fn programme_package_must_be_tracked_directory() {
    for package in [
        "",
        "packages/absent",
        "packages/untracked",
        "packages/local-lint/checker.txt",
        "../outside",
        "/",
        "packages/../packages/local-lint",
    ] {
        let programme = format!("{{ package = {package:?}, binary = \"local-lint\" }}");
        let root = programme_fixture(LOCAL_POLICY, Some(&programme), "allowances = []");
        write(
            root.path(),
            "packages/untracked/checker.txt",
            "not tracked\n",
        );
        assert_programme_refusal(root.path(), "is not a tracked directory of the repository");
    }
}

/// An empty or whitespace-only binary does not identify a checker.
///
/// # Panics
/// Panics only if fixture IO fails or an empty binary is admitted.
///
/// ´claim:cli:programme-binary-must-be-nonempty´
/// ´test:integration:programme-binary-must-be-nonempty´
#[test]
fn programme_binary_must_be_nonempty() {
    for binary in ["", "   "] {
        let programme = format!("{{ package = \"packages/local-lint\", binary = {binary:?} }}");
        let root = programme_fixture(LOCAL_POLICY, Some(&programme), "allowances = []");
        assert_programme_refusal(root.path(), "programme binary must not be empty");
    }
}

/// A programme is exactly a package and binary string table.
///
/// # Panics
/// Panics only if fixture IO fails or a malformed declaration is admitted.
///
/// ´claim:cli:malformed-programme-refuses´
/// ´test:integration:malformed-programme-refuses´
#[test]
fn malformed_programme_refuses() {
    for programme in [
        "\"local-lint\"",
        "[]",
        "{}",
        "{ package = 3, binary = \"local-lint\" }",
        "{ package = \"packages/local-lint\", binary = \"local-lint\", extra = true }",
    ] {
        let root = programme_fixture(LOCAL_POLICY, Some(programme), "allowances = []");
        assert_programme_refusal(root.path(), "malformed programme; expected");
    }
}

/// Deferral admits opaque row tables but still checks their container shape.
///
/// # Panics
/// Panics only if fixture IO fails or an invalid list shape is admitted.
///
/// ´claim:cli:deferred-list-requires-supported-shape´
/// ´test:integration:deferred-list-requires-supported-shape´
#[test]
fn deferred_list_requires_supported_shape() {
    for list in [
        "",
        "paths = []",
        "allowances = 1",
        "allowances = [1]",
        "allowances = []\npath_counts = []",
        "allowances = []\nextra = []",
    ] {
        let root = programme_fixture(LOCAL_POLICY, Some(LOCAL_PROGRAMME), list);
        assert_programme_refusal(
            root.path(),
            "deferred list must be a table with path_counts or allowances rows",
        );
    }
}

/// A deferred policy does not clear failures found by a catalogued policy.
///
/// # Panics
/// Panics only if fixture IO fails or deferral conceals a failure.
///
/// ´claim:cli:deferred-policy-does-not-hide-catalogued-failure´
/// ´test:integration:deferred-policy-does-not-hide-catalogued-failure´
#[test]
fn deferred_policy_does_not_hide_catalogued_failure() {
    let root = programme_fixture(LOCAL_POLICY, Some(LOCAL_PROGRAMME), "allowances = []");
    write(
        root.path(),
        "adr/one.md",
        "Cites (`sec:fixture:missing`).\n",
    );
    let output = programme_command(root.path(), &["check"]);
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(report["clean"], false);
    assert_eq!(report["deferred"], 1);
    assert!(report["failures"].as_u64().expect("failures") > 0);
}

/// An inactive root's Markdown fails the command until prose activation is declared.
///
/// # Panics
/// Panics only if fixture IO or command execution fails, or the verdict differs.
///
/// ´claim:cli:inactive-prose-is-a-failing-configuration-finding´
/// ´test:integration:inactive-prose-fails-the-check-command´
#[test]
fn inactive_prose_fails_the_check_command() {
    let root = tempfile::tempdir().expect("temporary root");
    write(root.path(), "adr/prose.md", "A document.\n");
    for active in [false, true] {
        declare(
            root.path(),
            DECLARED_OWNERS,
            FIXTURE_ENVIRONMENTS,
            if active {
                DECLARED_POLICIES
            } else {
                "policies = []\n"
            },
            if active { DECLARED_LISTS } else { "" },
        );
        track(root.path());
        let (output, report) = check_carrier(root.path());
        assert_eq!(
            output.status.code(),
            Some(if active { 0 } else { 3 }),
            "{report}"
        );
        let findings = report["findings"].as_array().expect("findings");
        let inactive = findings
            .iter()
            .find(|finding| finding["code"] == "inactive_prose_owner");
        if active {
            assert!(inactive.is_none(), "{report}");
            assert_eq!(report["failures"], 0);
        } else {
            let finding = inactive.expect("inactive prose finding");
            assert_eq!(finding["severity"], "failure");
            assert_eq!(finding["owner"], "PROJECTA");
            assert_eq!(finding["sources"], 1);
            assert_eq!(
                finding["message"],
                "owner PROJECTA has 1 Markdown sources but activates no labels.mints-well-formed row; activate labels.mints-well-formed to harvest and check its prose"
            );
        }
    }
}

fn macro_fixture(documentation: &str) -> tempfile::TempDir {
    let root = carrier_fixture();
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\".\"]\n[package]\nname = \"macro-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    );
    write(
        root.path(),
        "src/lib.rs",
        &format!(
            "mod properties {{ proptest::proptest! {{\n#![proptest_config(Config::default())]\n{documentation}\n#[test]\nfn property(value in any::<u8>()) {{ prop_assert_eq!(value, value); }}\n}} }}\n"
        ),
    );
    write(
        root.path(),
        "docs/property.md",
        "## Property · `sec:carrier:property`\n\nThe property establishes (`claim:carrier:macro-property-is-citable`).\n",
    );
    track(root.path());
    root
}

/// A property-test macro's source-written documentation mints the same claim
/// through line comments, separate doc attributes and one multiline attribute.
/// Each form resolves from Markdown through the production entry.
///
/// # Panics
/// Panics only if fixture IO fails or the production check loses a macro carrier.
///
/// ´claim:carrier:macro-doc-attributes-share-the-test-standard-place´
/// ´test:integration:macro-doc-attributes-share-the-test-standard-place´
#[test]
fn macro_doc_attributes_share_the_test_standard_place() {
    for documentation in [
        "/// A property holds.\n///\n/// ´claim:carrier:macro-property-is-citable´\n/// ´test:unit:property´",
        "#[doc = \"A property holds.\"]\n#[doc = \"\"]\n#[doc = \"´claim:carrier:macro-property-is-citable´\"]\n#[doc = \"´test:unit:property´\"]",
        "#[doc = \"A property holds.\\n\\n´claim:carrier:macro-property-is-citable´\\n´test:unit:property´\"]",
    ] {
        let root = macro_fixture(documentation);
        let (output, report) = check_carrier(root.path());
        assert!(output.status.success(), "{report}\n{output:?}");
        assert_eq!(report["profile"]["covered"], 1, "{report}");
        assert_eq!(report["profile"]["labelled"], 1, "{report}");
        assert_eq!(report["claim"]["mints"], 1, "{report}");
        assert_eq!(report["citations_resolved"], 1, "{report}");
        let body = fs::read_to_string(root.path().join("src/lib.rs")).expect("macro source");
        for (target, status, resolved) in [
            ("macro-property-is-citable", 0, 3),
            ("missing-top-level-doc", 3, 1),
        ] {
            write(
                root.path(),
                "src/lib.rs",
                &format!(
                    "#![doc = \"(´claim:carrier:{target}´)\"]\n#[doc = \"(´claim:carrier:{target}´)\"]\npub fn explanation() {{}}\n{body}"
                ),
            );
            let (output, report) = check_carrier(root.path());
            assert_eq!(output.status.code(), Some(status), "{report}");
            assert_eq!(report["citations_resolved"], resolved, "{report}");
            if status != 0 {
                let text = report.to_string();
                assert!(text.contains("unresolved_citation"), "{report}");
                assert!(
                    text.contains("claim:carrier:missing-top-level-doc"),
                    "{report}"
                );
            }
        }
    }
}

/// A marked macro body that cannot be read refuses by name, and a misplaced
/// claim remains a placement failure instead of being rescued by its spelling.
///
/// # Panics
/// Panics only if fixture IO fails or the check accepts an invalid macro carrier.
///
/// ´claim:carrier:invalid-macro-carriers-refuse-by-name´
/// ´test:integration:invalid-macro-carriers-refuse-by-name´
#[test]
fn invalid_macro_carriers_refuse_by_name() {
    let root = macro_fixture(
        "#[doc = \"A property holds.\"]\n#[doc = \"´test:unit:property´\"]\n#[doc = \"´claim:carrier:macro-property-is-citable´\"]",
    );
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert_eq!(report["claim"]["defective"], 1, "{report}");
    write(
        root.path(),
        "src/lib.rs",
        "proptest! { #[test] fn property(value in any::<u8>()) ??? }\n",
    );
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert!(report.to_string().contains("macro-doc-carrier"), "{report}");
}

/// An owned Python unittest method mints a claim that a Markdown record can
/// cite, and the active profiles count its docstring as a labelled test site.
///
/// # Panics
/// Panics only if fixture IO fails or the production check violates the contract.
///
/// ´claim:carrier:python-docstrings-participate-in-production-resolution´
/// ´test:integration:python-docstrings-participate-in-production-resolution´
#[test]
fn python_docstrings_participate_in_production_resolution() {
    let root = python_fixture();
    let (output, report) = check_carrier(root.path());
    assert!(output.status.success(), "{report}\n{output:?}");
    assert_eq!(report["profile"]["covered"], 1, "{report}");
    assert_eq!(report["profile"]["labelled"], 1, "{report}");
    assert_eq!(report["citations_resolved"], 3, "{report}");
    for ending in ["\n", "\r\n", "\r"] {
        let source = format!(
            "# separators: \u{0085}\u{2028}\u{2029}\n\u{000c}# form feed\n{}",
            include_str!("../../../ci/test_docstring_carrier.py")
        )
        .replace('\n', ending);
        write(root.path(), "ci/test_docstring_carrier.py", &source);
        let tests = superloop_lint::scan_source(
            "PROJECTA",
            Path::new("ci/test_docstring_carrier.py"),
            &source,
        )
        .expect("Python AST");
        assert_eq!(tests.len(), 1);
        assert_eq!(
            tests[0].location().offset(),
            source.find("def test_").expect("test offset")
        );
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .env("LC_ALL", "C")
            .args(["check", "--root"])
            .arg(root.path())
            .output()
            .expect("locale-independent production check");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert!(output.status.success(), "{report}");
        assert_eq!(report["profile"]["labelled"], 1, "{report}");
    }
}

/// A second Python test minting the same claim is refused with the claim's
/// name and both sites instead of disappearing from the label census.
///
/// # Panics
/// Panics only if fixture IO fails or the production check loses the duplicate.
///
/// ´claim:carrier:duplicate-python-claims-are-named´
/// ´test:integration:duplicate-python-claims-are-named´
#[test]
fn duplicate_python_claims_are_named() {
    let root = python_fixture();
    let other = include_str!("../../../ci/test_docstring_carrier.py")
        .replace("test_python_claim_is_carried", "test_second_python_claim")
        .replace("test-python-claim-is-carried", "test-second-python-claim");
    write(root.path(), "ci/test_duplicate.py", &other);
    track(root.path());
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    let text = report.to_string();
    assert!(text.contains("duplicate_claim_mint"), "{report}");
    assert!(
        text.contains("claim:carrier:python-method-documentation-is-citable"),
        "{report}"
    );
    assert!(text.contains("ci/test_duplicate.py"), "{report}");

    // Crate identity must not split one partition owner's registry.
    fs::remove_file(root.path().join("ci/test_duplicate.py")).expect("remove duplicate");
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"packages/demo\"]\n",
    );
    write(
        root.path(),
        "packages/demo/Cargo.toml",
        "[package]\nname = \"different-crate-name\"\nversion = \"0.1.0\"\n",
    );
    let rust = "/// A shared claim.\n/// ´claim:carrier:python-method-documentation-is-citable´\n/// ´test:integration:rust-claim´\n#[test]\nfn rust_claim() {}\n";
    write(root.path(), "packages/demo/tests/carrier.rs", rust);
    track(root.path());
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    let text = report.to_string();
    assert!(text.contains("duplicate_claim_mint"), "{report}");
    assert!(
        text.contains("ci/test_docstring_carrier.py")
            && text.contains("packages/demo/tests/carrier.rs"),
        "{report}"
    );

    let python = include_str!("../../../ci/test_docstring_carrier.py").replace(
        "        ´claim:carrier:python-method-documentation-is-citable´",
        "        (´claim:carrier:python-method-documentation-is-citable´)",
    );
    write(root.path(), "ci/test_docstring_carrier.py", &python);
    let (output, report) = check_carrier(root.path());
    assert!(output.status.success(), "{report}");
    assert_eq!(report["claim"]["citations"], 1, "{report}");
    assert_eq!(report["claim"]["unresolved"], 0, "{report}");

    write(
        root.path(),
        "packages/demo/tests/carrier.rs",
        &rust
            .replace("rust_claim", "test_python_claim_is_carried")
            .replace(
                "test:integration:rust-claim",
                "test:integration:test-python-claim-is-carried",
            ),
    );
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert!(
        report.to_string().contains("colliding_derivation"),
        "{report}"
    );
}

/// Python syntax errors refuse by name, while ordinary strings and files
/// outside the owned test-path convention never mint a claim.
///
/// # Panics
/// Panics only if fixture IO fails or source selection misclassifies the fixture.
///
/// ´claim:carrier:python-source-boundaries-are-explicit´
/// ´test:integration:python-source-boundaries-are-explicit´
#[test]
fn python_source_boundaries_are_explicit() {
    let root = python_fixture();
    let fixture = include_str!("../../../ci/test_docstring_carrier.py");
    write(root.path(), "ci/ordinary.py", fixture);
    write(root.path(), "scripts/test_outside.py", fixture);
    write(
        root.path(),
        "ci/test_data.py",
        "data = '''´claim:carrier:not-a-docstring´'''\n",
    );
    track(root.path());
    let (output, report) = check_carrier(root.path());
    assert!(output.status.success(), "{report}");
    write(root.path(), "ci/test_data.py", "def test_broken(:\n");
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert!(report.to_string().contains("python-docstrings"), "{report}");

    write(
        root.path(),
        "ci/test_data.py",
        "def ordinary():\n    '''´claim:carrier:not-a-test´'''\n\ndef outer():\n    def test_nested():\n        pass\n",
    );
    let (output, report) = check_carrier(root.path());
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert_eq!(report["profile"]["covered"], 1, "{report}");
    assert!(
        report.to_string().contains("unwarranted_commentary_mint"),
        "{report}"
    );
    write(
        root.path(),
        "ci/test_data.py",
        "def ordinary():\n    '''An ordinary docstring.'''\n\ndef outer():\n    def test_nested():\n        pass\n",
    );
    let (output, report) = check_carrier(root.path());
    assert!(output.status.success(), "{report}");
    assert_eq!(report["profile"]["covered"], 1, "{report}");

    // Both package-local roots participate, and retain integration classification.
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"packages/demo\"]\n",
    );
    write(
        root.path(),
        "packages/demo/Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    );
    fs::remove_file(root.path().join("ci/test_docstring_carrier.py")).expect("move fixture");
    for path in [
        "tests/test_carrier.py",
        "packages/demo/ci/test_carrier.py",
        "packages/demo/tests/test_carrier.py",
    ] {
        write(root.path(), path, fixture);
        track(root.path());
        let (output, report) = check_carrier(root.path());
        assert!(output.status.success(), "{report}");
        assert_eq!(report["profile"]["covered"], 1, "{report}");
        assert_eq!(report["profile"]["labelled"], 1, "{report}");
        fs::remove_file(root.path().join(path)).expect("move fixture");
    }
    write(root.path(), "ci/test_docstring_carrier.py", fixture);
    track(root.path());
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args([
            "fix",
            "--profile",
            "test",
            "--write",
            "--allow-dirty",
            "--root",
        ])
        .arg(root.path())
        .output()
        .expect("repair entry");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("python-docstrings"),
        "{output:?}"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("ci/test_docstring_carrier.py"))
            .expect("unchanged Python"),
        fixture
    );

    assert_missing_python_refusal(root.path());
}

fn assert_missing_python_refusal(root: &Path) {
    let commands = tempfile::tempdir().expect("isolated command path");
    let git = std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
        .map(|path| path.join("git"))
        .find(|path| path.is_file())
        .expect("git on PATH");
    std::os::unix::fs::symlink(git, commands.path().join("git")).expect("git only");
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .env("PATH", commands.path())
        .args(["check", "--root"])
        .arg(root)
        .output()
        .expect("check without Python");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("python-docstrings: cannot start python3"),
        "{output:?}"
    );
}

fn imported_fixture(document: &RegistryDocument) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    declare(
        root.path(),
        "root_owner = \"ROOT\"\nowners = [\"ROOT\", \"DEMO\", \"PROJECTA\"]\n\
         imports = [{ owner = \"PROJECTA\", registry = \".linter/imports/project-a.toml\" }]\n\
         partitions = [\
           { name = \"fixture-root\", owner = \"ROOT\", pattern = '(%s\"Cargo.toml\" / %s\"README.md\" / %s\"adr\" [ \"/\" *VCHAR ] / %s\"docs\" [ \"/\" *VCHAR ] / %s\"src\" [ \"/\" *VCHAR ] / %s\".linter\" [ \"/\" *VCHAR ])' },\
           { name = \"demo-package\", owner = \"DEMO\", pattern = '%s\"packages/demo\" [ \"/\" *VCHAR ]' }\
         ]\n\
         may_cite = [{ owner = \"DEMO\", target = \"PROJECTA\" }]\n",
        FIXTURE_ENVIRONMENTS,
        "policies = [{ owner = \"DEMO\", policy = \"labels.mints-well-formed\" }]\n",
        "[DEMO.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    write(
        root.path(),
        ".linter/imports/project-a.toml",
        &document.render(),
    );
    write(
        root.path(),
        "packages/demo/docs/note.md",
        "## Note · `sec:demo:note`\n\nThe decision is (`[PROJECTA-sec:fixture:one]`).\n",
    );
    track(root.path());
    root
}

/// Export writes every fixture mint with its kind and head, and the import loader reads it back with the same relation.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:cli:an-export-round-trips-through-the-import-loader´
/// ´test:integration:an-export-round-trips-through-the-import-loader´
#[test]
fn an_export_round_trips_through_the_import_loader() {
    let document = exported_fixture();
    assert_eq!(document.labels.len(), 2);
    assert_eq!(document.labels[0].label, "sec:fixture:one");
    assert_eq!(document.labels[0].head, "One");
    assert_eq!(document.labels[0].kind, "sec");
    assert_eq!(document.labels[0].file, "adr/fixture.md");
    assert_eq!(document.labels[1].label, "sec:fixture:two");
    let root = imported_fixture(&document);
    let imported = configuration(root.path());
    let loaded = imported.snapshot().expect("imported snapshot");
    assert_eq!(
        loaded.imports().get("PROJECTA").expect("imported owner"),
        &document
    );
}

/// Two exports of one immutable tree have identical bytes, including the source header.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or read.
///
/// ´claim:cli:an-export-is-byte-stable-over-one-tree´
/// ´test:integration:two-exports-over-one-tree-are-byte-identical´
#[test]
fn two_exports_over_one_tree_are_byte_identical() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/fixture.md",
        "## One · `sec:fixture:one`\n",
    );
    ensure_fixture_surface(root.path());
    track(root.path());
    let left = root.path().join("left.toml");
    let right = root.path().join("right.toml");
    for out in [&left, &right] {
        let result = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .args(["export", "--owner", "PROJECTA", "--root"])
            .arg(root.path())
            .arg("--out")
            .arg(out)
            .output()
            .expect("export fixture");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(
        fs::read(left).expect("first bytes"),
        fs::read(right).expect("second bytes")
    );
}

/// An export whose owner is absent refuses as a command failure and writes no document.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, or executed.
///
/// ´claim:cli:an-export-refuses-an-unknown-owner´
/// ´test:integration:an-export-refuses-an-unknown-owner´
#[test]
fn an_export_refuses_an_unknown_owner() {
    let root = tempfile::tempdir().expect("temporary directory");
    ensure_fixture_surface(root.path());
    track(root.path());
    let out = root.path().join("unknown.toml");
    let result = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["export", "--owner", "UNSEEN", "--root"])
        .arg(root.path())
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run export");
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stdout, b"");
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("unknown local owner: UNSEEN"));
}

/// Export refuses a bad configuration before writing and reports an output failure by its path.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, or executed.
///
/// ´claim:cli:export-refuses-configuration-and-output-failures´
/// ´test:integration:export-refuses-bad-configuration-and-output-path´
#[test]
fn export_refuses_bad_configuration_and_output_path() {
    let root = tempfile::tempdir().expect("temporary directory");
    let out = root.path().join("labels.toml");
    let absent = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["export", "--owner", "PROJECTA", "--root"])
        .arg(root.path())
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run export");
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(absent.stdout, b"");
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&absent.stderr).contains("owners.toml"));

    ensure_fixture_surface(root.path());
    track(root.path());
    let unwritable = root.path().join("missing/labels.toml");
    let failed = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["export", "--owner", "PROJECTA", "--root"])
        .arg(root.path())
        .arg("--out")
        .arg(&unwritable)
        .output()
        .expect("run export");
    assert_eq!(failed.status.code(), Some(1));
    assert_eq!(failed.stdout, b"");
    assert!(String::from_utf8_lossy(&failed.stderr).contains("cannot write export"));
}

/// Export build mode publishes its JSON report and touches its stamp after writing the registry.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:cli:export-build-mode-publishes-report-and-stamp´
/// ´test:integration:export-build-mode-publishes-report-and-stamp´
#[test]
fn export_build_mode_publishes_report_and_stamp() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/fixture.md",
        "## One · `sec:fixture:one`\n",
    );
    ensure_fixture_surface(root.path());
    track(root.path());
    let out = root.path().join("labels.toml");
    let report = root.path().join("report.json");
    let stamp = root.path().join("stamp");
    let result = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["export", "--owner", "PROJECTA", "--root"])
        .arg(root.path())
        .arg("--out")
        .arg(&out)
        .arg("--write-report")
        .arg(&report)
        .arg("--write-stamp")
        .arg(&stamp)
        .output()
        .expect("run export");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"");
    assert!(out.exists());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(report).expect("report bytes"))
            .expect("JSON report")["labels"],
        1
    );
    assert_eq!(fs::read(stamp).expect("stamp bytes"), b"");
}

/// A package's bracketed citation reaches a mint published by another repository when its may-cite row declares the edge.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:check:an-imported-registry-resolves-a-bracketed-citation´
/// ´test:integration:an-imported-citation-resolves-through-a-registry´
#[test]
fn an_imported_citation_resolves_through_a_registry() {
    let root = imported_fixture(&exported_fixture());
    let plan = plan(root.path());
    let (sources, _findings) = plan.labels().read(root.path());
    let analysis = analyze(plan.labels().adoption(), &sources, &CodeSurface::default());
    assert!(!codes(analysis.findings()).contains(&"unresolved_citation"));
    assert_eq!(analysis.citations_resolved(), 1);
    assert_eq!(analysis.mints(), 1);
    assert_eq!(analysis.code_mints(), 0);
    let (_counts, layers) = verify_layers(
        root.path(),
        plan.workspace().packages(),
        plan.labels().adoption(),
        &analysis,
        plan.snapshot().may_cite(),
    );
    assert!(!codes(&layers).contains(&"unreached_import"));

    let path = root.path().join(".linter/owners.toml");
    let owners = fs::read_to_string(&path).expect("owner declaration");
    fs::write(
        path,
        owners.replace(
            "may_cite = [{ owner = \"DEMO\", target = \"PROJECTA\" }]",
            "may_cite = []",
        ),
    )
    .expect("remove reach");
    let changed_plan = crate::plan(root.path());
    let (sources, _findings) = changed_plan.labels().read(root.path());
    let analysis = analyze(
        changed_plan.labels().adoption(),
        &sources,
        &CodeSurface::default(),
    );
    let (_counts, layers) = verify_layers(
        root.path(),
        changed_plan.workspace().packages(),
        changed_plan.labels().adoption(),
        &analysis,
        changed_plan.snapshot().may_cite(),
    );
    assert!(codes(&layers).contains(&"unreached_import"));
}

/// Removing an imported label leaves its citation as the ordinary unresolved citation failure.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:check:a-retired-imported-label-fails-resolution´
/// ´test:integration:a-retired-imported-label-is-unresolved´
#[test]
fn a_retired_imported_label_is_unresolved() {
    let mut document = exported_fixture();
    document.labels.retain(|row| row.label != "sec:fixture:one");
    let root = imported_fixture(&document);
    let plan = plan(root.path());
    let (sources, _findings) = plan.labels().read(root.path());
    let analysis = analyze(plan.labels().adoption(), &sources, &CodeSurface::default());
    assert!(codes(analysis.findings()).contains(&"unresolved_citation"));
}

/// A changed kind relation refuses the import before the corpus can be checked.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:snapshot:an-import-with-different-kinds-is-refused´
/// ´test:integration:an-import-with-different-kinds-is-refused´
#[test]
fn an_import_with_different_kinds_is_refused() {
    let mut document = exported_fixture();
    document.kinds.reserved.push("alien".to_owned());
    let root = imported_fixture(&document);
    let refusals = configuration(root.path())
        .refusals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(
        refusals
            .iter()
            .any(|line| line.contains("imported kind relation differs from this corpus"))
    );
}

/// Format namespaces admit corpus-owned core envelopes, preserve the declared
/// burn surface, and refuse foreign lists, policy instances and registries with
/// both the offending namespace and the expected identity before checking.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be created, written, tracked,
/// executed or parsed, or if the binary violates the namespace contract.
///
/// ´claim:snapshot:format-namespaces-refuse-foreign-identities-before-checking´
/// ´test:integration:format-namespaces-refuse-foreign-identities-before-checking´
#[test]
fn format_namespaces_refuse_foreign_identities_before_checking() {
    let root = tempfile::tempdir().expect("temporary namespace fixture");
    let check = |root: &Path| {
        Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .env("RUST_LOG", "error")
            .args(["check", "--root"])
            .arg(root)
            .output()
            .expect("run the namespace check")
    };
    declare(
        root.path(),
        "root_owner = \"EXAMPLE\"\nowners = [\"EXAMPLE\"]\npartitions = [{ name = \"all\", owner = \"EXAMPLE\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        "environments = []\n",
        "policies = [{ owner = \"EXAMPLE\", policy = \"legacy.section-references\" }, { owner = \"EXAMPLE\", policy = \"labels.mints-well-formed\" }]\n",
        "[EXAMPLE.\"legacy.section-references\"]\npath_counts = []\n[EXAMPLE.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    let policy = ".linter/policy-legacy-section-references.toml";
    write(
        root.path(),
        policy,
        "namespace = \"class.linter.policy.legacy.section-references\"\nversion = [1, 0, 0]\n\n[owners.EXAMPLE]\nprose = '%s\"note.md\"'\n",
    );
    write(root.path(), "note.md", "See § 12.3 for details.\n");
    track(root.path());
    for kind in ["owners", "environments", "policies", "shape"] {
        let text = fs::read_to_string(root.path().join(format!(".linter/{kind}.toml")))
            .expect("corpus-owned envelope");
        assert!(text.contains(&format!("namespace = \"org.example.linter.{kind}\"")));
    }
    let output = check(root.path());
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("burn report");
    assert_eq!(report["burn"]["files_scanned"], 1);
    assert_eq!(report["burn"]["occurrences"], 1);
    assert_eq!(report["findings"][0]["code"], "burn_list_growth");
    assert_eq!(
        report["configuration"]["activations"]
            .as_array()
            .expect("activation rows")
            .iter()
            .find(|row| row["policy"] == "legacy.section-references")
            .expect("burn activation")["surface_paths"],
        1
    );
    write(root.path(), "note.md", "No section reference remains.\n");
    assert!(check(root.path()).status.success());

    for (file, expected) in [
        (
            ".linter/lists.toml",
            "unknown lists namespace: org.example.linter.lists; expected class.linter.lists",
        ),
        (
            policy,
            "unknown policy namespace: org.example.linter.policy.legacy.section-references; expected prefix class.linter.policy.",
        ),
    ] {
        let original = fs::read_to_string(root.path().join(file)).expect("format envelope");
        write(
            root.path(),
            file,
            &original.replace("class.linter", "org.example.linter"),
        );
        let refused = check(root.path());
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(refused.stdout.as_slice(), b"");
        let message = String::from_utf8_lossy(&refused.stderr);
        assert!(
            message.contains(&format!("{file}: {expected}")),
            "{message}"
        );
        assert_named_refusal(root.path(), &message, &format!("{file}: {expected}"));
        write(root.path(), file, &original);
    }

    let mut registry = exported_fixture();
    registry.namespace = "org.example.linter.labels".to_owned();
    let imported = imported_fixture(&registry);
    let refused = check(imported.path());
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(refused.stdout.as_slice(), b"");
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains(
            "unknown registry namespace: org.example.linter.labels; expected class.linter.labels"
        ),
        "{message}"
    );
}

fn assert_named_refusal(root: &Path, message: &str, expected: &str) {
    let records: Vec<serde_json::Value> = message
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON diagnostic"))
        .collect();
    assert_eq!(records[0]["fields"]["message"], expected);
    assert_eq!(
        records[0]["fields"]["refusal"],
        records[0]["fields"]["message"]
    );
    assert_eq!(
        records[0]["fields"]["kind"],
        "the declared configuration is not a snapshot"
    );
    let text = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .env("RUST_LOG", "off")
        .args(["check", "--text", "--root"])
        .arg(root)
        .output()
        .expect("text refusal");
    assert_eq!(text.status.code(), Some(1));
    assert_eq!(text.stdout, [] as [u8; 0]);
    assert_eq!(
        String::from_utf8(text.stderr).expect("text diagnostics"),
        format!("{expected}\n")
    );
}

/// The import loader names an unknown namespace and its expected identity, and
/// distinguishes an unknown major version from a namespace refusal.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:snapshot:an-unknown-registry-schema-is-refused-by-name´
/// ´test:integration:unknown-registry-namespace-and-major-are-refused´
#[test]
fn unknown_registry_namespace_and_major_are_refused() {
    let mut document = exported_fixture();
    document.namespace = "org.example.linter.labels".to_owned();
    let root = imported_fixture(&document);
    let refusals = configuration(root.path())
        .refusals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(refusals.iter().any(|line| line.contains(
        "unknown registry namespace: org.example.linter.labels; expected class.linter.labels"
    )));

    document.namespace = "class.linter.labels".to_owned();
    document.version[0] = 2;
    write(
        root.path(),
        ".linter/imports/project-a.toml",
        &document.render(),
    );
    let refusals = configuration(root.path())
        .refusals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(
        refusals
            .iter()
            .any(|line| line.contains("unknown registry major version"))
    );
}

/// A malformed published document refuses the importing snapshot by the registry's path.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:snapshot:a-malformed-imported-registry-is-refused´
/// ´test:integration:a-malformed-imported-registry-is-refused´
#[test]
fn a_malformed_imported_registry_is_refused() {
    let root = imported_fixture(&exported_fixture());
    write(
        root.path(),
        ".linter/imports/project-a.toml",
        "labels = [broken\n",
    );
    let refusals = configuration(root.path())
        .refusals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(
        refusals
            .iter()
            .any(|line| line.contains("malformed registry"))
    );
}

/// An imported owner cannot also claim any partition of the importing tree.
///
/// # Panics
/// Panics only if the temporary fixture cannot be created, written, tracked, executed, or parsed.
///
/// ´claim:snapshot:an-imported-owner-cannot-take-a-partition´
/// ´test:integration:an-imported-owner-with-a-partition-is-refused´
#[test]
fn an_imported_owner_with_a_partition_is_refused() {
    let root = imported_fixture(&exported_fixture());
    let path = root.path().join(".linter/owners.toml");
    let owners = fs::read_to_string(&path).expect("owner declaration");
    let owners = owners.replace(
        "partitions = [",
        "partitions = [{ name = \"imported\", owner = \"PROJECTA\", pattern = '%s\"external\"' },",
    );
    fs::write(path, owners).expect("write owner declaration");
    let refusals = configuration(root.path())
        .refusals()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert!(
        refusals
            .iter()
            .any(|line| line.contains("imported owner PROJECTA cannot take a partition"))
    );
}
use sha2::{Digest, Sha256};

#[path = "support/git.rs"]
mod git_fixture;

fn index_adoption(
    packages: &[Package],
    names: Option<&OwnerNames>,
    assemblies: &[Assembly],
) -> Adoption {
    build_index_adoption(
        packages,
        names,
        assemblies,
        fixture_kind_registry(),
        "index",
    )
}

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("parent")).expect("create");
    fs::write(path, text).expect("write");
}

fn codes(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().map(Finding::code).collect()
}

fn plan(root: &Path) -> ExecutionPlan {
    ensure_fixture_surface(root);

    ExecutionPlan::compile(root, configuration(root)).expect("fixture configuration")
}

/// Every covered asset seeds exactly one derived mint, so the count of derived
/// mints is the count of covered assets and neither an asset nor a mint is lost
/// between the census and the analysis. The relation is one-to-one rather than
/// merely bounded, so a collision that folded two assets into one label would
/// show as a shortfall here.
///
/// ´claim:check:every-covered-asset-seeds-exactly-one-derived-mint´
/// ´test:integration:every-covered-asset-of-a-fixture-seeds-one-derived-mint´
#[test]
fn every_covered_asset_of_a_fixture_seeds_one_derived_mint() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    track(root.path());

    let plan = plan(root.path());
    let packages = plan.workspace().packages().to_vec();
    let (census, _census_findings) = take_census(root.path(), plan.profiles().sources());
    let (profile, assets, _profile_findings) = analyze_profile(&packages, &census);

    let analysis = analyze(
        &index_adoption(
            &packages,
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &[],
        &CodeSurface::default().with_tests(&assets),
    );

    assert!(
        profile.covered > 0,
        "the fixture carries covered assets to seed from"
    );
    assert_eq!(
        profile.collision_groups, 0,
        "and no two of them derive one label"
    );
    assert_eq!(
        analysis.derived_mints(),
        profile.covered,
        "every covered asset seeds exactly one mint, since the profile reports no collision"
    );
}

/// Against a census taken from an invented workspace, all four ways of naming a
/// test behave as the calculus says: a citation of a live test resolves, a
/// citation of a name nobody wrote fails, a document of another owner reaches it
/// by importing with the owner's prefix, and writing the label bare mints
/// nothing.
///
/// ´claim:check:citing-a-live-test-resolves-and-citing-a-dead-one-does-not´
/// ´test:integration:a-document-citing-a-live-test-resolves-and-a-dead-one-does-not´
#[test]
fn a_document_citing_a_live_test_resolves_and_a_dead_one_does_not() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    track(root.path());

    let plan = plan(root.path());
    let packages = plan.workspace().packages().to_vec();
    let adoption = index_adoption(
        &packages,
        Some(&superloop_lint::OwnerNames::new(
            "example-",
            [superloop_lint::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let (census, _census_findings) = take_census(root.path(), plan.profiles().sources());
    let (_profile, assets, _profile_findings) = analyze_profile(&packages, &census);

    let witness = assets
        .iter()
        .find(|asset| asset.test().package() == "example-demo")
        .expect("the demo member carries a covered test");
    let label = witness.label().to_string();

    let cited = Source::new(
        "packages/demo/docs/note.md",
        format!("## Head · `sec:demo:note`\n\nThe witness is (`{label}`).\n"),
    );
    let resolved = analyze(
        &adoption,
        &[cited],
        &CodeSurface::default().with_tests(&assets),
    );

    assert_eq!(codes(resolved.findings()), Vec::<&str>::new());
    assert_eq!(
        resolved.citations_resolved(),
        1,
        "the citation is counted as resolved"
    );

    let dead = Source::new(
        "packages/demo/docs/note.md",
        "## Head · `sec:demo:note`\n\nThe witness is (`test:integration:a-test-nobody-ever-wrote`).\n",
    );
    let refused = analyze(
        &adoption,
        &[dead],
        &CodeSurface::default().with_tests(&assets),
    );

    assert_eq!(
        codes(refused.findings()),
        ["unresolved_citation"],
        "a name the census does not carry fails, naming the label and its place"
    );

    let imported = Source::new(
        "adr/001-fixture.md",
        format!("## Head · `sec:fixture:record`\n\nThe witness is (`[DEMO-{label}]`).\n"),
    );
    let reached = analyze(
        &adoption,
        &[imported],
        &CodeSurface::default().with_tests(&assets),
    );

    assert_eq!(codes(reached.findings()), Vec::<&str>::new());
    assert_eq!(
        reached.citations_resolved(),
        1,
        "and a document of the other owner reaches it"
    );

    let authored = Source::new(
        "packages/demo/docs/note.md",
        format!("## Head · `{label}`\n"),
    );
    let unwarranted = analyze(
        &adoption,
        &[authored],
        &CodeSurface::default().with_tests(&assets),
    );

    assert_eq!(
        codes(unwarranted.findings()),
        ["unwarranted_reserved_kind"],
        "while writing the label bare is still no way to mint one"
    );
}

/// A citation crossing an ownership boundary must say so: written bare it fails,
/// and the failure names the owner that minted the label and spells out the
/// imported form to write instead — delimiters included, since a rendering
/// without them is the one form the grammar reads as nothing. Written that way
/// it resolves. The reader is handed the repair rather than the rule.
///
/// ´claim:check:a-citation-crossing-an-ownership-boundary-must-be-imported´
/// ´test:integration:a-cross-owner-citation-without-brackets-fails´
#[test]
fn a_cross_owner_citation_without_brackets_fails() {
    let packages = [
        Package::new("example-project-a", ""),
        Package::new("example-project-b", "packages/project-b"),
    ];
    let adoption = index_adoption(
        &packages,
        Some(&superloop_lint::OwnerNames::new(
            "example-",
            [superloop_lint::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );

    let record = Source::new(
        "adr/014-label-calculus.md",
        "## Syntax · `sec:labels:syntax`\n",
    );
    let bare = Source::new(
        "packages/project-b/docs/note.md",
        "## Note · `sec:projectb:note`\n\nCites (`sec:labels:syntax`) across the boundary.\n",
    );
    let imported = Source::new(
        "packages/project-b/docs/note.md",
        "## Note · `sec:projectb:note`\n\nCites (`[PROJECTA-sec:labels:syntax]`) across the boundary.\n",
    );

    let refused = analyze(&adoption, &[record.clone(), bare], &CodeSurface::default());

    let [
        Finding::UnresolvedCitationWantingImport {
            minting_owner,
            suggestion,
            ..
        },
    ] = refused.findings()
    else {
        panic!(
            "expected the bracket-free crossing to fail, got {:?}",
            refused.findings()
        );
    };

    assert_eq!(minting_owner, "index");
    assert_eq!(suggestion, "(`[PROJECTA-sec:labels:syntax]`)");

    let accepted = analyze(&adoption, &[record, imported], &CodeSurface::default());

    assert_eq!(codes(accepted.findings()), Vec::<&str>::new());
    assert_eq!(accepted.citations_resolved(), 1);
    assert_binary_import_hints();
}

fn import_hint_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("hint fixture");
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/units\", \"crates/reader\"]\n",
    );
    write(
        root.path(),
        "crates/units/Cargo.toml",
        "[package]\nname = \"quantity\"\n",
    );
    write(
        root.path(),
        "crates/reader/Cargo.toml",
        "[package]\nname = \"consumer\"\n",
    );
    write(
        root.path(),
        "crates/units/README.md",
        "## Measure · `sec:units:measure-conversion`\n",
    );
    write(
        root.path(),
        "README.md",
        "(`sec:units:measure-conversion`)\n",
    );
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"UNITS\", \"READER\"]\npartitions = [{ name = \"root\", owner = \"PROJECTA\", pattern = '(%s\"README.md\" / %s\"Cargo.toml\" / %s\".linter\" [ \"/\" *VCHAR ])' }, { name = \"units\", owner = \"UNITS\", pattern = '%s\"crates/units\" [ \"/\" *VCHAR ]' }, { name = \"reader\", owner = \"READER\", pattern = '%s\"crates/reader\" [ \"/\" *VCHAR ]' }]\nmay_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }, { owner = \"UNITS\", policy = \"labels.mints-well-formed\" }, { owner = \"READER\", policy = \"labels.mints-well-formed\" }]\n",
        "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n[UNITS.\"labels.mints-well-formed\"]\nallowances = []\n[READER.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    track(root.path());
    root
}

fn assert_binary_import_hints() {
    let root = import_hint_fixture();
    let (code, report) = run(&["check"], root.path());
    assert_eq!(code, Some(3), "{report}");
    let finding = &report["findings"][0];
    assert_eq!(finding["code"], "unresolved_citation_blocked_import");
    assert_eq!(
        finding["message"],
        "README.md:1:2: citation of sec:units:measure-conversion resolves nowhere in owner PROJECTA; owner UNITS mints it, but root prose cannot import a member owner's private premise; use a prose reference, a root-owned label, or a declared reach edge where the manifest carries the dependency and the citation is admitted by the root-prose policy"
    );
    let (_, graph) = run(&["report"], root.path());
    assert_eq!(graph["dangling"][0]["message"], finding["message"]);
    let owners = fs::read_to_string(root.path().join(".linter/owners.toml")).expect("owners");
    write(
        root.path(),
        ".linter/owners.toml",
        &owners.replace(
            "may_cite = []",
            "may_cite = [{ owner = \"PROJECTA\", target = \"UNITS\" }]",
        ),
    );
    let (_, root_reach) = run(&["check"], root.path());
    assert_eq!(
        root_reach["findings"][0]["message"],
        "README.md:1:2: citation of sec:units:measure-conversion resolves nowhere in owner PROJECTA; owner UNITS mints it, but root prose cannot import a member owner's private premise; use a prose reference, a root-owned label, or a declared reach edge where the manifest carries the dependency and the citation is admitted by the root-prose policy"
    );
    write(root.path(), ".linter/owners.toml", &owners);
    write(root.path(), "README.md", "Root policy.\n");
    write(
        root.path(),
        "crates/reader/README.md",
        "(`sec:units:measure-conversion`)\n",
    );
    track(root.path());
    let (_, unreachable) = run(&["check"], root.path());
    assert_eq!(
        unreachable["findings"][0]["code"],
        "unresolved_citation_blocked_import"
    );
    assert_eq!(
        unreachable["findings"][0]["message"],
        "crates/reader/README.md:1:2: citation of sec:units:measure-conversion resolves nowhere in owner READER; owner UNITS mints it, but the citing owner does not reach the minting owner; use a prose reference, a root-owned label, or a declared reach edge where the manifest carries the dependency and the citation is admitted by the root-prose policy"
    );
    write(
        root.path(),
        "crates/reader/Cargo.toml",
        "[package]\nname = \"consumer\"\n[dependencies]\nquantity = { path = \"../units\" }\n",
    );
    let (_, reachable) = run(&["check"], root.path());
    assert_eq!(
        reachable["findings"][0]["code"],
        "unresolved_citation_wanting_import"
    );
    assert_eq!(
        reachable["findings"][0]["message"],
        "crates/reader/README.md:1:2: citation of sec:units:measure-conversion resolves nowhere in its own owner; owner UNITS mints it, so write (`[UNITS-sec:units:measure-conversion]`)"
    );
    write(
        root.path(),
        "crates/reader/README.md",
        "(`[UNITS-sec:units:measure-conversion]`)\n",
    );
    let (code, repaired) = run(&["check"], root.path());
    assert_eq!(code, Some(0), "{repaired}");
}

/// Head validation reaches the command: a head whose kind the registry denies
/// its name fails the run, reporting the base word and the kinds catalogued for
/// it, and the catalogued pairing passes.
///
/// (´claim:head:a-head-whose-kind-contradicts-its-name-is-a-failure´)
/// ´test:integration:a-head-the-registry-denies-fails-the-check´
#[test]
fn a_head_the_registry_denies_fails_the_check() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "**Theorem (Warrant lapse)** · `def:fixture:warrant-lapse`\n",
    );
    track(root.path());
    ensure_fixture_surface(root.path());
    activate_fixture_heads(root.path(), "PROJECTA");

    let (code, report) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "a head the registry denies is a failure: {report}"
    );
    assert_eq!(report["findings"][0]["code"], "misclassified_head");
    assert_eq!(report["findings"][0]["base"], "Theorem");
    assert_eq!(report["findings"][0]["catalogued"][0], "thm");

    write(
        root.path(),
        "adr/001-one.md",
        "**Meta-theorem (Warrant lapse)** · `metathm:fixture:warrant-lapse`\n",
    );

    let (code, repaired) = run(&["check"], root.path());

    assert_eq!(code, Some(0), "and the catalogued pair passes: {repaired}");
    assert_eq!(repaired["heads_validated"], 1);
}

fn activate_fixture_heads(root: &Path, owner: &str) {
    let path = root.join(".linter/policies.toml");
    let policies = fs::read_to_string(&path).expect("read policies");
    let pairs = format!(
        "policies = [{{ owner = \"{owner}\", policy = \"labels.mints-kind-conform\" }}, {{ owner = \"{owner}\", policy = \"labels.heads-conform\" }},"
    );
    fs::write(path, policies.replace("policies = [", &pairs)).expect("activate heads");
    let path = root.join(".linter/lists.toml");
    let mut lists = fs::read_to_string(&path).expect("read lists");
    writeln!(lists, "\n[{owner}.\"labels.mints-kind-conform\"]\nallowances = []\n[{owner}.\"labels.heads-conform\"]\nallowances = []").expect("write lists");
    fs::write(path, lists).expect("declare head lists");
}

/// Head validation follows each declared owner's activation independently.
///
/// # Panics
/// Panics only if the fixture cannot be written or the binary violates the activation contract.
///
/// ´claim:head:head-checks-follow-owner-activation´
/// ´test:integration:head-checks-follow-owner-activation´
#[test]
fn head_checks_follow_owner_activation() {
    let root = tempfile::tempdir().expect("temporary corpus");
    declare(
        root.path(),
        "root_owner = \"VENDOR\"\nowners = [\"VENDOR\", \"LOCAL\"]\npartitions = [{ name = \"vendor\", owner = \"VENDOR\", pattern = '%s\"vendor\" [ \"/\" *VCHAR ]' }, { name = \"local\", owner = \"LOCAL\", pattern = '(%s\"local.md\" / %s\".linter\" [ \"/\" *VCHAR ])' }]\nmay_cite = []\n",
        "environments = [{ environment = \"Section\", kind = \"sec\" }]\nextensions = []\nreserved_kinds = []\n",
        "policies = [{ owner = \"VENDOR\", policy = \"labels.mints-well-formed\" }, { owner = \"VENDOR\", policy = \"labels.mints-unique\" }, { owner = \"VENDOR\", policy = \"labels.citations-local-resolve\" }, { owner = \"LOCAL\", policy = \"labels.mints-well-formed\" }]\n",
        "[VENDOR.\"labels.mints-well-formed\"]\nallowances = []\n[VENDOR.\"labels.mints-unique\"]\nallowances = []\n[VENDOR.\"labels.citations-local-resolve\"]\nallowances = []\n[LOCAL.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    write(
        root.path(),
        "vendor/README.md",
        "# Vendor · `guide:vendor:readme`\n",
    );
    write(root.path(), "local.md", "# Local · `guide:local:readme`\n");
    activate_fixture_heads(root.path(), "LOCAL");
    track(root.path());
    let (code, report) = run(&["check"], root.path());
    assert_eq!(code, Some(3), "{report}");
    let heads: Vec<_> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|finding| finding["code"] == "uncatalogued_head")
        .collect();
    assert_eq!(heads.len(), 1, "{report}");
    assert_eq!(heads[0]["label"], "guide:local:readme");
    assert_eq!(report["heads_validated"], 1);
    activate_fixture_heads(root.path(), "VENDOR");
    let (_, report) = run(&["check"], root.path());
    assert_eq!(report["heads_validated"], 2);
    assert_eq!(
        report["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter(|finding| finding["code"] == "uncatalogued_head")
            .count(),
        2,
        "{report}"
    );
}

/// The outline half of the tracking fixture, given the rows it declares.
fn outline_document(rows: &str) -> String {
    format!(
        "# The fixture outline\n\n\
         **Convention (Tracking)** · `conv:fixture:tracking`\n\n\
         | Entry | Head | Document |\n| --- | --- | --- |\n{rows}\n\n\
         **Entry (First)** · `entry:fixture:first`\n\n\
         The first environment the tracked document carries.\n\n\
         **Entry (Second)** · `entry:fixture:second`\n\n\
         The second environment the tracked document carries.\n"
    )
}

/// Both rows of the passing fixture pair.
fn both_tracking_rows() -> String {
    concat!(
        "| ``entry:fixture:first`` | ``sec:fixture:first`` | ``docs/tracked.md`` |\n",
        "| ``entry:fixture:second`` | ``sec:fixture:second`` | ``docs/tracked.md`` |",
    )
    .to_owned()
}

/// Outline tracking holds end to end and in both directions: a matching pair
/// passes the command, a head the outline claims going missing fails at the
/// claiming row, and a head no row claims fails at the head with the omitting
/// outline named beside it. Each failure points where the repair belongs.
///
/// ´claim:check:outline-tracking-holds-end-to-end-in-both-directions´
/// ´test:integration:an-outline-and-its-document-track-both-ways´
#[test]
fn an_outline_and_its_document_track_both_ways() {
    let both_heads = "# The tracked document\n\n\
                      ## First · `sec:fixture:first`\n\nProse.\n\n\
                      ## Second · `sec:fixture:second`\n\nProse.\n";

    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "docs/outline.md",
        &outline_document(&both_tracking_rows()),
    );
    write(root.path(), "docs/tracked.md", both_heads);
    track(root.path());

    let (code, tracked) = run(&["check"], root.path());

    assert_eq!(code, Some(0), "the fixture pair tracks: {tracked}");
    assert_eq!(tracked["failures"], 0);

    // Drift one way: the tracked document loses a head the outline claims.
    write(
        root.path(),
        "docs/tracked.md",
        "# The tracked document\n\n## First · `sec:fixture:first`\n\nProse.\n",
    );

    let (code, unfulfilled) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "a head the outline claims went missing: {unfulfilled}"
    );
    assert_eq!(
        unfulfilled["findings"][0]["code"],
        "unfulfilled_outline_entry"
    );
    assert_eq!(unfulfilled["findings"][0]["head"], "sec:fixture:second");
    assert_eq!(
        unfulfilled["findings"][0]["location"]["path"], "docs/outline.md",
        "the claiming row is where the reader repairs it"
    );
    assert_eq!(
        unfulfilled["findings"][0]["document"], "docs/tracked.md",
        "and the document that should have carried it is named beside it"
    );

    // Drift the other way: the document keeps both heads, the outline drops a row.
    write(root.path(), "docs/tracked.md", both_heads);
    write(
        root.path(),
        "docs/outline.md",
        &outline_document(
            "| ``entry:fixture:first`` | ``sec:fixture:first`` | ``docs/tracked.md`` |",
        ),
    );

    let (code, unclaimed) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "a head no entry claims is drift too: {unclaimed}"
    );
    assert_eq!(unclaimed["findings"][0]["code"], "unclaimed_head");
    assert_eq!(unclaimed["findings"][0]["head"], "sec:fixture:second");
    assert_eq!(
        unclaimed["findings"][0]["location"]["path"], "docs/tracked.md",
        "the head stands in the tracked document"
    );
    assert_eq!(
        unclaimed["findings"][0]["declaration"]["path"], "docs/outline.md",
        "and the outline that omits it is the finding's other end"
    );
}

/// The report describes and never judges: an uncited mint and a dangling
/// citation are both listed and the command still exits zero, while the check
/// over the same tree fails that citation. A reverse lookup answers when asked,
/// and a malformed question is a usage failure that prints nothing.
///
/// ´claim:cli:the-report-command-describes-without-judging´
/// ´test:integration:the-report-command-describes-the-graph-without-judging-it´
#[test]
fn the_report_command_describes_the_graph_without_judging_it() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Hub · `sec:fixture:hub`\n\nProse.\n\n\
         ## Leaf · `sec:fixture:leaf`\n\nCites (`sec:fixture:hub`) and (`sec:fixture:missing`).\n",
    );
    track(root.path());

    let (code, report) = run(&["report"], root.path());

    assert_eq!(
        code,
        Some(0),
        "an uncited mint and a dangling citation are both reported, not judged: {report}"
    );
    assert!(
        report.get("schema").is_none(),
        "the graph report states no version of itself"
    );
    assert_eq!(report["mints"], 2);
    assert_eq!(report["citations"], 1);
    assert_eq!(report["orphans"][0]["label"], "sec:fixture:leaf");
    assert_eq!(report["hubs"][0]["label"], "sec:fixture:hub");
    assert_eq!(report["hubs"][0]["citations"], 1);
    assert_eq!(report["dangling"][0]["code"], "unresolved_citation");
    assert!(report["reverse"].is_null(), "no lookup was asked for");

    assert_eq!(
        run(&["check"], root.path()).0,
        Some(3),
        "while the check still fails the same dangling citation"
    );

    let (code, looked_up) = run(&["report", "--cites", "sec:fixture:hub"], root.path());

    assert_eq!(code, Some(0));
    assert_eq!(looked_up["reverse"]["label"], "sec:fixture:hub");
    assert_eq!(
        looked_up["reverse"]["citers"][0]["from"],
        "sec:fixture:leaf"
    );

    let (code, refused) = run(&["report", "--cites", "not a label"], root.path());

    assert_eq!(code, Some(2), "a malformed question is a usage failure");
    assert!(refused.is_null(), "and stdout stays empty");
}

/// The report over a small declared graph is internally consistent: the totals
/// are the mints and citations the sources carry, a citation of a name nobody
/// minted is listed as dangling, the mints nobody cites are the orphans and not
/// every mint is one, the hubs come back ranked by how often they are cited, and
/// within every owner the mints cited and the mints uncited add up to the mints
/// there are.
///
/// ´claim:graph:a-declared-graphs-report-is-internally-consistent´
/// ´test:integration:a-small-declared-graph-reports-totals-orphans-dangles-and-hubs´
#[test]
fn a_small_declared_graph_reports_totals_orphans_dangles_and_hubs() {
    let root = tempfile::tempdir().expect("temporary directory");

    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\".\", \"packages/demo\"]\n\n[package]\nname = \"example-fixture\"\n",
    );
    write(
        root.path(),
        "packages/demo/Cargo.toml",
        "[package]\nname = \"example-demo\"\n",
    );
    write(
        root.path(),
        "adr/001-hub.md",
        "## Hub · `sec:fixture:hub`\n\nProse.\n\n## Second · `sec:fixture:second`\n\nProse.\n",
    );
    write(
        root.path(),
        "adr/002-cites.md",
        "## Cites · `sec:fixture:cites`\n\nCites (`sec:fixture:hub`), then (`sec:fixture:second`), then (`sec:fixture:hub`) again.\n",
    );
    write(
        root.path(),
        "adr/003-dangles.md",
        "## Dangles · `sec:fixture:dangles`\n\nCites (`sec:fixture:gone`), which nobody minted.\n",
    );
    write(
        root.path(),
        "packages/demo/docs/note.md",
        "## Note · `sec:demo:note`\n\nProse.\n",
    );
    track(root.path());
    ensure_fixture_surface(root.path());

    let report = superloop_lint::report(root.path(), None, superloop_lint::DEFAULT_HUBS);

    assert_eq!(report.summary.mints, 5, "the five heads the fixture writes");
    assert_eq!(
        report.dangling.len(),
        1,
        "the one citation nobody minted: {:?}",
        report.dangling
    );
    assert!(
        !report.summary.orphans.is_empty(),
        "some mints are legitimately uncited"
    );
    assert!(
        report.summary.orphans.len() < report.summary.mints,
        "though not all of them: {} of {}",
        report.summary.orphans.len(),
        report.summary.mints
    );
    assert_eq!(
        report.summary.hubs[0].label.to_string(),
        "sec:fixture:hub",
        "the most-cited head leads"
    );
    assert!(
        report
            .summary
            .hubs
            .windows(2)
            .all(|pair| pair[0].citations >= pair[1].citations),
        "the hubs are ranked: {:?}",
        report.summary.hubs
    );

    for cell in report.summary.by_owner.values() {
        assert_eq!(
            cell.mints,
            cell.cited + cell.orphans,
            "every mint is cited or is not"
        );
    }
}

/// The parts directory of the one adopted assembly, and the document it publishes.
const SPEC_PARTS: &str = "packages/project-b/docs/spec";
const SPEC_TARGET: &str = "packages/project-b/docs/spec.md";

/// The fictional kind registry shared by command-level corpus fixtures.
const FIXTURE_ENVIRONMENTS: &str = "reserved_kinds = [\"test\"]\n\
    reserved_extensions = [\"const\", \"legacy\", \"todo\"]\n\n\
    environments = [\n\
      { environment = \"Appendix\", kind = \"app\" },\n\
      { environment = \"Assertion\", kind = \"claim\" },\n\
      { environment = \"Convention\", kind = \"conv\" },\n\
      { environment = \"Document\", kind = \"doc\" },\n\
      { environment = \"Entry\", kind = \"entry\" },\n\
      { environment = \"Invariant\", kind = \"inv\" },\n\
      { environment = \"Meta-theorem\", kind = \"metathm\" },\n\
      { environment = \"Note\", kind = \"rem\" },\n\
      { environment = \"Part\", kind = \"part\" },\n\
      { environment = \"Section\", kind = \"sec\" },\n\
      { environment = \"Table\", kind = \"tab\" },\n\
      { environment = \"Theorem\", kind = \"thm\" },\n\
    ]\n\n\
    extensions = [\n\
      { environment = \"Constant\", kind = \"const\" },\n\
      { environment = \"To-do\", kind = \"todo\" },\n\
    ]\n";

/// One part of the fixture specification.
fn spec_part(name: &str, body: &str) -> String {
    format!(
        "## The {name} part · `sec:fixture:{name}`\n\n**Invariant ({name})** · `inv:fixture:{name}`\n\n{body}\n"
    )
}

/// The fixture manifest, given the rows it lists.
fn spec_manifest(rows: &str) -> String {
    format!(
        "# The specification manifest\n\n\
         **Convention (Assembly)** · `conv:fixture:assembly`\n\n\
         | Part |\n| --- |\n{rows}\n"
    )
}

/// Lay out a parts directory carrying two parts and listing both.
/// The owner file the assembly fixtures are partitioned by.
///
/// Wider than the starting owner file because these fixtures stand under the
/// package tree rather than under the record tree, and every tracked path must
/// be accounted for the partition to be total.
const SPEC_OWNERS: &str = "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
    partitions = [{ name = \"package-trees\", owner = \"PROJECTA\", pattern = '%s\"packages\" [ \"/\" *VCHAR ]' }, \
    { name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }]\n\
    may_cite = []\n";

/// Declare the publication the assembly fixtures assemble.
///
/// The parts and the target used to be compiled into the linter, so a fixture
/// carrying the tree was a fixture the tool already knew how to assemble. They
/// are the corpus's to state now, which is why an assembly fixture declares one:
/// a tree that has not said what it publishes has nothing to publish.
fn declare_spec_publication(root: &Path) {
    declare(
        root,
        SPEC_OWNERS,
        FIXTURE_ENVIRONMENTS,
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    write(
        root,
        ".linter/policy-assembly-publications.toml",
        &format!(
            "namespace = \"class.linter.policy.assembly-publications\"\nversion = [1, 0, 0]\n\n\
             [owners.PROJECTA]\nspec = {{ parts = \"{SPEC_PARTS}\", target = \"{SPEC_TARGET}\" }}\n"
        ),
    );
}

fn spec_fixture(root: &Path) {
    declare_spec_publication(root);

    write(
        root,
        &format!("{SPEC_PARTS}/assembly.md"),
        &spec_manifest("| ``alpha.md`` |\n| ``beta.md`` |"),
    );
    write(
        root,
        &format!("{SPEC_PARTS}/alpha.md"),
        &spec_part("alpha", "The first part."),
    );
    write(
        root,
        &format!("{SPEC_PARTS}/beta.md"),
        &spec_part("beta", "The second part."),
    );
}

/// The assemble and check commands agree through the whole cycle: unpublished
/// parts are stale and the check mode writes nothing, writing settles them in
/// the manifest's order, editing a part stales the publication again,
/// reassembly repairs it, and a further write finds nothing to do.
///
/// ´claim:assembly:the-assemble-and-check-commands-agree-through-publish-stale-and-repair´
/// ´test:integration:an-assembled-publication-stales-when-a-part-changes´
#[test]
#[allow(
    clippy::cognitive_complexity,
    reason = "the test walks one fixture through assemble, stale, and repair in order; splitting it would hide the sequence it exists to pin"
)]
fn an_assembled_publication_stales_when_a_part_changes() {
    let root = tempfile::tempdir().expect("temporary directory");
    spec_fixture(root.path());
    track(root.path());

    let (code, before) = run(&["assemble"], root.path());

    assert_eq!(code, Some(3), "nothing is published yet: {before}");
    assert!(
        before.get("schema").is_none(),
        "the assemble report states no version of itself"
    );
    assert_eq!(before["write"], false);
    assert_eq!(before["assemblies"][0]["dormant"], false);
    assert_eq!(before["assemblies"][0]["assembled"], 2);
    assert_eq!(before["assemblies"][0]["target"], SPEC_TARGET);
    assert_eq!(before["findings"][0]["code"], "stale_assembly");
    assert!(
        !root.path().join(SPEC_TARGET).exists(),
        "and the check mode wrote nothing"
    );

    let (code, written) = run(&["assemble", "--write"], root.path());

    assert_eq!(code, Some(0), "writing settles it: {written}");
    assert_eq!(written["assemblies"][0]["written"], true);

    let published = fs::read_to_string(root.path().join(SPEC_TARGET)).expect("the publication");

    assert!(
        published.starts_with("<!-- Assembled from packages/project-b/docs/spec/ under"),
        "got {published:?}"
    );
    assert!(
        published.find("sec:fixture:alpha") < published.find("sec:fixture:beta"),
        "the manifest's order is the publication's order"
    );

    let (code, fresh) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(0),
        "the parts and their publication agree: {fresh}"
    );
    assert_eq!(fresh["assembly"]["verified"], 1);
    assert_eq!(fresh["assembly"]["dormant"], 0);
    assert_eq!(fresh["assembly"]["parts"], 2);

    // Editing a part stales the publication, and the check is where it shows.
    write(
        root.path(),
        &format!("{SPEC_PARTS}/alpha.md"),
        &spec_part("alpha", "The first part, rewritten."),
    );

    let (code, stale) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "an edited part stales the publication: {stale}"
    );
    assert_eq!(stale["findings"][0]["code"], "stale_assembly");
    assert_eq!(stale["findings"][0]["target"], SPEC_TARGET);

    let (code, repaired) = run(&["assemble", "--write"], root.path());

    assert_eq!(code, Some(0), "and reassembly repairs it: {repaired}");
    assert_eq!(run(&["check"], root.path()).0, Some(0));

    // Assembly is byte-stable: a second write changes nothing and reports fresh.
    let settled = fs::read_to_string(root.path().join(SPEC_TARGET)).expect("the publication");
    let (code, again) = run(&["assemble", "--write"], root.path());

    assert_eq!(code, Some(0));
    assert_eq!(
        again["assemblies"][0]["written"], false,
        "there was nothing to write"
    );
    assert_eq!(again["assemblies"][0]["fresh"], true);
    assert_eq!(
        fs::read_to_string(root.path().join(SPEC_TARGET)).expect("the publication"),
        settled
    );
}

/// The assemble command reports its wall time in the result object, matching the
/// judging commands that decide a corpus verdict.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked,
/// executed, or parsed.
///
/// ´claim:cli:the-assemble-command-reports-elapsed-micros´
/// ´test:integration:the-assemble-command-reports-elapsed-micros´
#[test]
fn the_assemble_command_reports_elapsed_micros() {
    let root = tempfile::tempdir().expect("temporary directory");
    spec_fixture(root.path());
    track(root.path());

    let (code, report) = run(&["assemble"], root.path());

    assert_eq!(code, Some(3), "nothing is published yet: {report}");
    assert_elapsed_micros(&report);
}

/// Through the command as through the library, a part no manifest row names is
/// reported rather than silently dropped from the publication.
///
/// (´claim:assembly:a-part-no-row-names-is-reported-and-the-rest-still-assemble´)
/// ´test:integration:an-unlisted-part-is-reported-rather-than-dropped´
#[test]
fn an_unlisted_part_is_reported_rather_than_dropped() {
    let root = tempfile::tempdir().expect("temporary directory");
    spec_fixture(root.path());
    write(
        root.path(),
        &format!("{SPEC_PARTS}/assembly.md"),
        &spec_manifest("| ``alpha.md`` |"),
    );

    let (code, report) = run(&["assemble"], root.path());

    let codes: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().expect("a code"))
        .collect();

    assert_eq!(
        code,
        Some(3),
        "a part nothing assembles is a finding: {report}"
    );
    assert!(codes.contains(&"unassembled_part"), "got {codes:?}");
}

/// The same fixture manifest, carrying the draft marker before its table.
fn spec_draft_manifest(rows: &str) -> String {
    format!(
        "# The specification manifest\n\n\
         **Draft.**\n\n\
         **Convention (Assembly)** · `conv:fixture:assembly`\n\n\
         | Part |\n| --- |\n{rows}\n"
    )
}

/// A draft assembly is checked for membership but not for freshness, and writing
/// one is refused outright so a partial assembly cannot overwrite the standing
/// publication. An unlisted part still fires while the manifest is a draft, and
/// removing the marker restores the freshness verdict over the very same tree.
///
/// ´claim:assembly:writing-a-draft-assembly-is-refused-and-the-target-left-standing´
/// ´test:integration:a-draft-assembly-forms-no-freshness-verdict-and-refuses-write´
#[test]
fn a_draft_assembly_forms_no_freshness_verdict_and_refuses_write() {
    let root = tempfile::tempdir().expect("temporary directory");
    spec_fixture(root.path());
    write(
        root.path(),
        &format!("{SPEC_PARTS}/assembly.md"),
        &spec_draft_manifest("| ``alpha.md`` |\n| ``beta.md`` |"),
    );
    write(
        root.path(),
        SPEC_TARGET,
        "# The old, unrelated specification\n",
    );
    track(root.path());

    // A draft assembly is checked for membership but forms no freshness verdict,
    // so the standing target — deliberately not what the parts assemble into —
    // is not reported stale.
    let (code, clean) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(0),
        "a draft assembly forms no freshness verdict: {clean}"
    );
    assert_eq!(clean["assembly"]["dormant"], 0, "the rewrite has started");
    assert_eq!(clean["assembly"]["verified"], 1);

    // Writing a draft assembly is refused: it would overwrite the standing
    // target with a partial assembly rather than update it.
    let (code, refused) = run(&["assemble", "--write"], root.path());

    assert_eq!(
        code,
        Some(3),
        "writing a draft assembly is refused: {refused}"
    );
    assert_eq!(refused["assemblies"][0]["draft"], true);
    assert_eq!(refused["assemblies"][0]["written"], false);
    assert!(
        refused["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"] == "draft_assembly_write"),
        "got {refused}"
    );
    assert_eq!(
        fs::read_to_string(root.path().join(SPEC_TARGET)).expect("the old target"),
        "# The old, unrelated specification\n",
        "the standing target was not overwritten"
    );

    // Membership is still checked both ways in draft mode: a part standing in
    // the directory that no row lists is still reported.
    write(
        root.path(),
        &format!("{SPEC_PARTS}/assembly.md"),
        &spec_draft_manifest("| ``alpha.md`` |"),
    );

    let (code, unassembled) = run(&["check"], root.path());
    let codes: Vec<&str> = unassembled["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().expect("a code"))
        .collect();

    assert_eq!(
        code,
        Some(3),
        "an unlisted part still fires in draft mode: {unassembled}"
    );
    assert!(codes.contains(&"unassembled_part"), "got {codes:?}");

    // Removing the marker restores full membership and live freshness: the same
    // old target is now exactly what draft mode was declining to judge.
    write(
        root.path(),
        &format!("{SPEC_PARTS}/assembly.md"),
        &spec_manifest("| ``alpha.md`` |\n| ``beta.md`` |"),
    );

    let (code, stale) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "the marker is gone, so freshness binds again: {stale}"
    );
    assert!(
        stale["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["code"] == "stale_assembly"),
        "got {stale}"
    );
}

/// The shape report measures and never judges: it counts environments, marks
/// which are divisions, distributes the two kinds apart, and exits zero
/// regardless. It compares the corpus with nothing, so an invented tree is
/// reported exactly as the repository is.
///
/// ´claim:cli:the-shape-command-measures-without-judging´
/// ´test:integration:the-shape-command-measures-without-judging´
#[test]
fn the_shape_command_measures_without_judging() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## A division · `sec:fixture:division`\n\n\
         **Invariant (Short)** · `inv:fixture:short`\n\nOne.\n\n\
         **Invariant (Long)** · `inv:fixture:long`\n\n\
         Cites (`inv:fixture:short`) at length, over many more words than its sibling carries.\n",
    );
    track(root.path());

    let (code, report) = run(&["shape"], root.path());

    assert_eq!(code, Some(0), "size is measured and never judged: {report}");
    assert!(
        report.get("schema").is_none(),
        "the shape report states no version of itself"
    );
    assert_eq!(report["documents_measured"], 1);
    assert_eq!(report["environments"], 3);
    assert_eq!(
        report["named"], 2,
        "the division is measured apart from the two named"
    );
    assert_eq!(report["by_document"][0]["document"], "adr/001-one.md");
    assert_eq!(
        report["by_document"][0]["environments"][0]["division"],
        true
    );
    assert_eq!(
        report["words"]["count"], 2,
        "the two named environments are distributed"
    );
    assert_eq!(
        report["division_words"]["count"], 1,
        "and the division in its own"
    );
    assert!(
        report.get("band").is_none()
            && report.get("long").is_none()
            && report.get("short").is_none(),
        "the report carries no yardstick and calls nothing an outlier: {report}"
    );
}

/// The census over an invented workspace classifies and derives a label for
/// every test function it holds, with none left underivable, and the invented
/// manifests populate every area the profile supports. What is asserted is
/// completeness rather than magnitude: the classification reaches the whole
/// census, and no area goes unexercised because the fixture forgot to write one.
///
/// ´claim:census:a-census-covers-and-derives-every-test-function-it-holds´
/// ´test:integration:a-fixture-census-covers-and-derives-every-test-function´
#[test]
fn a_fixture_census_covers_and_derives_every_test_function() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    track(root.path());

    let plan = plan(root.path());
    let packages = plan.workspace().packages().to_vec();
    let (census, findings) = take_census(root.path(), plan.profiles().sources());
    let (analysis, _assets, _profile_findings) = analyze_profile(&packages, &census);

    assert_eq!(
        codes(&findings),
        Vec::<&str>::new(),
        "every invented source parses"
    );
    assert!(
        !census.tests().is_empty(),
        "the fixture holds tests to classify"
    );
    assert_eq!(
        analysis.covered,
        census.tests().len(),
        "every censused test is classified and derived"
    );
    assert_eq!(
        analysis.underivable, 0,
        "every identifier transforms into a label name"
    );

    for area in ["unit", "crate", "integration"] {
        assert!(
            analysis.by_area[area] > 0,
            "the fixture exercises the {area} area, found {}",
            analysis.by_area[area]
        );
    }
}

/// Every edge of a reference graph lands on a mint at both ends, and there are
/// several edges to check rather than one: the analysis carries no edge whose
/// endpoint is not a node of the graph it belongs to.
///
/// ´claim:graph:every-edge-of-a-reference-graph-lands-on-a-mint´
/// ´test:integration:every-edge-of-a-fixture-reference-graph-lands-on-a-mint´
#[test]
fn every_edge_of_a_fixture_reference_graph_lands_on_a_mint() {
    let sources = [
        Source::new(
            "adr/001-one.md",
            "## Hub · `sec:fixture:hub`\n\nProse.\n\n## Second · `sec:fixture:second`\n\nCites (`sec:fixture:hub`).\n",
        ),
        Source::new(
            "adr/002-two.md",
            "## Third · `sec:fixture:third`\n\nCites (`sec:fixture:hub`) and (`sec:fixture:second`).\n",
        ),
    ];

    let analysis = analyze(
        &index_adoption(
            &[],
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &sources,
        &CodeSurface::default(),
    );
    let graph = analysis.graph();

    assert_eq!(
        codes(analysis.findings()),
        Vec::<&str>::new(),
        "the fixture dangles nothing"
    );
    assert_eq!(graph.edge_count(), 3, "three citations, three edges");

    for edge in graph.edge_indices() {
        let (from, to) = graph.edge_endpoints(edge).expect("endpoints");

        assert!(graph.node_weight(from).is_some(), "edge source is a mint");
        assert!(graph.node_weight(to).is_some(), "edge target is a mint");
    }
}

/// Two documents citing each other resolve whichever is read first, with the
/// same counts either way, so mutual reference across files is not an ordering
/// problem.
///
/// (´claim:check:the-traversal-order-decides-nothing´)
/// ´test:integration:a-fixture-corpus-resolves-across-files´
#[test]
fn a_fixture_corpus_resolves_across_files() {
    let minting = Source::new(
        "adr/one.md",
        "## Head · `sec:fixture:head`\n\nProse citing (`sec:fixture:other`).\n",
    );
    let citing = Source::new(
        "adr/two.md",
        "## Other · `sec:fixture:other`\n\nProse citing (`sec:fixture:head`).\n",
    );

    let forward = analyze(
        &index_adoption(
            &[],
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &[minting.clone(), citing.clone()],
        &CodeSurface::default(),
    );
    let backward = analyze(
        &index_adoption(
            &[],
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &[citing, minting],
        &CodeSurface::default(),
    );

    assert_eq!(codes(forward.findings()), Vec::<&str>::new());
    assert_eq!(codes(backward.findings()), Vec::<&str>::new());
    assert_eq!(forward.citations_resolved(), 2);
    assert_eq!(backward.citations_resolved(), 2);
    assert_eq!(forward.mints(), backward.mints());
}

/// A corpus breaking every rule at once is told about every one of them, not
/// merely the first: each defect is reported with its own code, and the findings
/// arrive ordered by source and then by position, which is the order a reader
/// would walk the tree in.
///
/// ´claim:check:every-rule-a-corpus-breaks-is-reported-in-reading-order´
/// ´test:integration:a-fixture-corpus-reports-every-rule-it-breaks´
#[test]
fn a_fixture_corpus_reports_every_rule_it_breaks() {
    let sources = [
        Source::new("adr/one.md", "## Head · `sec:fixture:head`\n"),
        Source::new("adr/two.md", "## Repeat · `sec:fixture:head`\n"),
        Source::new("adr/three.md", "Cites (`sec:fixture:missing`).\n"),
        Source::new("adr/four.md", "## Asset · `test:unit:decode`\n"),
        Source::new("adr/five.md", "Imports (`[SPEC-sec:fixture:head]`).\n"),
        Source::new(
            "adr/six.md",
            "Bare import `[SPEC-sec:fixture:head]` here.\n",
        ),
        Source::new("adr/seven.md", "An unpaired ` backtick.\n"),
        Source::new("adr/eight.md", "Nearly (`Sec:fixture:head`).\n"),
    ];

    let analysis = analyze(
        &index_adoption(
            &[],
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &sources,
        &CodeSurface::default(),
    );

    assert_eq!(
        codes(analysis.findings()),
        [
            // Ordered by source path, then by position within the source.
            "near_miss",                 // adr/eight.md
            "unregistered_prefix",       // adr/five.md
            "unwarranted_reserved_kind", // adr/four.md
            "unpaired_backtick",         // adr/seven.md
            "non_parenthesized_import",  // adr/six.md
            "unresolved_citation",       // adr/three.md
            "duplicate_mint",            // adr/two.md
        ]
    );

    let duplicate = analysis
        .findings()
        .iter()
        .find(|finding| matches!(finding, Finding::DuplicateMint { .. }))
        .expect("a duplicate mint");

    let Finding::DuplicateMint { first, second, .. } = duplicate else {
        panic!("expected a duplicate mint");
    };

    assert_eq!(first.path(), Path::new("adr/one.md"));
    assert_eq!(second.path(), Path::new("adr/two.md"));
}

/// Displayed material never participates, end to end: labels shown in doubled
/// spans or inside a fenced block yield no citation and no finding, while the
/// one head written for real still mints.
///
/// (´claim:prose:a-non-participating-region-yields-neither-occurrence-nor-finding´)
/// ´test:integration:displayed-material-never-participates´
#[test]
fn displayed_material_never_participates() {
    let sources = [Source::new(
        "adr/one.md",
        concat!(
            "## Head · `sec:fixture:head`\n\n",
            "Displayed inline: ``sec:fixture:nowhere`` and (``sec:fixture:nowhere``).\n\n",
            "```text\n",
            "`sec:fixture:nowhere`\n",
            "(`sec:fixture:nowhere`)\n",
            "(`[SPEC-sec:fixture:nowhere]`)\n",
            "```\n",
        ),
    )];

    let analysis = analyze(
        &index_adoption(
            &[],
            Some(&superloop_lint::OwnerNames::new(
                "example-",
                [superloop_lint::UnbuiltMember::new(
                    "example-project-c",
                    "packages/project-c",
                )],
            )),
            &[],
        ),
        &sources,
        &CodeSurface::default(),
    );

    assert_eq!(codes(analysis.findings()), Vec::<&str>::new());
    assert_eq!(analysis.mints(), 1);
    assert_eq!(analysis.citations_resolved(), 0);
}

/// The check command emits exactly one JSON object on standard output, carrying
/// the run's counts and stating no version of itself, and exits zero over a
/// clean tree. A caller can parse the result without reading prose.
///
/// ´claim:cli:the-check-command-emits-one-json-object-and-exits-zero-when-clean´
/// ´test:integration:the-check-command-emits-json-and-exits-clean´
#[test]
fn the_check_command_emits_json_and_exits_clean() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n\nCites (`sec:fixture:head`).\n",
    );
    track(root.path());
    ensure_fixture_surface(root.path());

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root.path())
        .output()
        .expect("run the linter");

    assert_eq!(output.status.code(), Some(0));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");

    assert!(
        report.get("schema").is_none(),
        "the check report states no version of itself"
    );
    assert_eq!(report["clean"], true);
    assert_eq!(report["mints"], 1);
    assert_eq!(report["citations_resolved"], 1);
}

/// The check command reports its wall time in the result object, matching the
/// other judging commands that decide a corpus verdict.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked,
/// executed, or parsed.
///
/// ´claim:cli:the-check-command-reports-elapsed-micros´
/// ´test:integration:the-check-command-reports-elapsed-micros´
#[test]
fn the_check_command_reports_elapsed_micros() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n\nCites (`sec:fixture:head`).\n",
    );
    track(root.path());
    ensure_fixture_surface(root.path());

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root.path())
        .output()
        .expect("run the linter");

    assert_eq!(output.status.code(), Some(0));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");
    assert_elapsed_micros(&report);
}

/// A tree with findings exits with the documented failure code and still emits
/// its report, so a caller learns both that the run failed and precisely what
/// failed from the same invocation.
///
/// ´claim:cli:a-failing-check-exits-with-its-documented-code-and-still-reports´
/// ´test:integration:the-check-command-exits-nonzero-on-findings´
#[test]
fn the_check_command_exits_nonzero_on_findings() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "Cites (`sec:fixture:missing`).\n",
    );
    track(root.path());
    ensure_fixture_surface(root.path());

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root.path())
        .output()
        .expect("run the linter");

    assert_eq!(output.status.code(), Some(3));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");

    assert_eq!(report["clean"], false);
    assert_eq!(report["failures"], 1);
    assert_eq!(report["findings"][0]["code"], "unresolved_citation");
}

/// Build a two-package fixture workspace exercising all three areas.
///
/// One test of each area is unlabelled, one already carries a correct label,
/// and one carries a stale one, so a sweep must insert twice, repair once, and
/// leave one alone.
fn fixture_workspace(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[workspace]\nmembers = [\".\", \"packages/demo\"]\n\n[package]\nname = \"example-fixture\"\n",
    );
    write(
        root,
        "src/lib.rs",
        "#[cfg(test)]\nmod tests {\n    /// Checks it.\n    #[test]\n    fn a_unit_test() {}\n}\n",
    );
    write(
        root,
        "src/tests/mod.rs",
        "/// \u{b4}test:crate:a-stale-name\u{b4}\n#[test]\nfn stale_label_carrier() {}\n",
    );
    write(
        root,
        "packages/demo/Cargo.toml",
        "[package]\nname = \"example-demo\"\n",
    );
    write(
        root,
        "packages/demo/tests/end_to_end.rs",
        "/// \u{b4}test:integration:already-right\u{b4}\n#[test]\nfn already_right() {}\n",
    );
}

/// Run the linter binary and return its exit code and parsed stdout.
fn run(arguments: &[&str], root: &Path) -> (Option<i32>, serde_json::Value) {
    ensure_fixture_surface(root);

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(arguments)
        .arg("--root")
        .arg(root)
        .output()
        .expect("run the linter");

    let parsed = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);

    (output.status.code(), parsed)
}

fn assert_elapsed_micros(report: &serde_json::Value) {
    assert!(
        report["elapsed_micros"].as_u64().is_some(),
        "the report carries a nonnegative elapsed_micros: {report}"
    );
}

/// Activate the profile exercised by a two-package check-and-fix fixture.
fn declare_fixture_profile(root: &Path, policy: &str) {
    ensure_fixture_surface(root);
    let policies =
        fs::read_to_string(root.join(".linter/policies.toml")).expect("fixture policies");
    let lists = fs::read_to_string(root.join(".linter/lists.toml")).expect("fixture lists");
    write(root, ".linter/policies.toml", &policies.replace("policies = [", &format!(
        "policies = [{{ owner = \"PROJECTA\", policy = {policy:?} }}, {{ owner = \"DEMO\", policy = {policy:?} }},"
    )));
    write(
        root,
        ".linter/lists.toml",
        &format!(
            "{lists}\n[PROJECTA.{policy:?}]\nallowances = []\n[DEMO.{policy:?}]\nallowances = []\n"
        ),
    );
}

/// Check, sweep, and check again leaves a tree clean and settled: the first
/// check counts what is missing, wrong and already right; the sweep inserts,
/// repairs and leaves alone exactly those; the second check passes; the author's
/// own line survives with the label indented to match; and a further sweep
/// changes nothing.
///
/// ´claim:cli:check-then-sweep-then-check-leaves-a-tree-clean-and-settled´
/// ´test:integration:a-fixture-package-tree-checks-and-then-fixes-clean´
#[test]
fn a_fixture_package_tree_checks_and_then_fixes_clean() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    track(root.path());
    declare_fixture_profile(root.path(), "profile.tests-conform");

    let (code, before) = run(&["check"], root.path());

    assert_eq!(code, Some(3), "the fixture wants labels");
    assert_eq!(before["profile"]["covered"], 3);
    assert_eq!(before["profile"]["by_area"]["unit"], 1);
    assert_eq!(before["profile"]["by_area"]["crate"], 1);
    assert_eq!(before["profile"]["by_area"]["integration"], 1);
    assert_eq!(
        before["profile"]["labelled"], 1,
        "one test is already right"
    );
    assert_eq!(
        before["profile"]["missing"], 1,
        "one test has no label at all"
    );
    assert_eq!(
        before["profile"]["wrong"], 1,
        "one test attests the wrong label"
    );

    let (code, swept) = run(
        &["fix", "--profile", "test", "--write", "--allow-dirty"],
        root.path(),
    );

    assert_eq!(code, Some(0), "the sweep completes: {swept}");
    assert_eq!(swept["dry_run"], false);
    assert_eq!(swept["inserted"], 1);
    assert_eq!(swept["repaired"], 1);
    assert_eq!(swept["unchanged"], 1);
    assert_eq!(swept["refused"], 0);

    let (code, after) = run(&["check"], root.path());

    assert_eq!(code, Some(0), "the sweep leaves the fixture clean: {after}");
    assert_eq!(after["profile"]["labelled"], 3);
    assert_eq!(after["profile"]["missing"], 0);
    assert_eq!(after["profile"]["wrong"], 0);

    let unit = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");
    assert_eq!(
        unit,
        concat!(
            "#[cfg(test)]\nmod tests {\n",
            "    /// Checks it.\n    ///\n    /// \u{b4}test:unit:a-unit-test\u{b4}\n    #[test]\n    fn a_unit_test() {}\n}\n",
        ),
        "the author's line is preserved and the label indented with the attribute"
    );

    let (code, again) = run(
        &["fix", "--profile", "test", "--write", "--allow-dirty"],
        root.path(),
    );

    assert_eq!(code, Some(0));
    assert_eq!(again["inserted"], 0, "the sweep is idempotent");
    assert_eq!(again["repaired"], 0);
    assert_eq!(again["unchanged"], 3);
}

/// Through the command as through the library, the default dry run reports
/// what it would insert and leaves every file byte-for-byte as it was.
/// The fixture activates its owners' test profile so it belongs to the sweep.
///
/// (´claim:fix:a-dry-run-counts-what-it-would-do-and-writes-nothing´)
/// ´test:integration:the-fix-command-writes-nothing-on-a-dry-run´
#[test]
fn the_fix_command_writes_nothing_on_a_dry_run() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());
    track(root.path());
    declare_fixture_profile(root.path(), "profile.tests-conform");

    let before = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");
    let (code, report) = run(&["fix", "--profile", "test"], root.path());
    let after = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");

    assert_eq!(code, Some(0));
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["inserted"], 1, "it still counts what it would do");
    assert_eq!(before, after, "and leaves every file alone");
}

/// The sweep refuses to run over a tree carrying uncommitted changes and writes
/// nothing, so its edits always arrive as a diff a reviewer can read against a
/// clean baseline.
///
/// ´claim:cli:the-sweep-refuses-a-tree-with-uncommitted-changes´
/// ´test:integration:the-fix-command-refuses-a-dirty-tree´
#[test]
fn the_fix_command_refuses_a_dirty_tree() {
    let root = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(root.path());

    git_fixture::initialise_repository(root.path());

    let before = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");
    let (code, _report) = run(&["fix", "--profile", "test", "--write"], root.path());
    let after = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");

    assert_eq!(code, Some(1), "an unswept tree with changes is refused");
    assert_eq!(before, after, "and nothing is written");
}

/// Build a workspace of deficiency notices exercising the to-do sweep's cases.
///
/// One notice of each area is unlabelled, one already carries its derived label,
/// and one carries a stale one, so a sweep must write twice, rewrite once, and
/// leave one alone. One of the unlabelled notices carries the qualifier this
/// corpus already writes, and one stands after code as a trailing comment.
fn notice_workspace(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[workspace]\nmembers = [\".\", \"packages/demo\"]\n\n[package]\nname = \"example-fixture\"\n",
    );
    write(
        root,
        "src/lib.rs",
        "// TODO(ADR-T-016 2026-08-19): read the policy flag before deciding\n\
         // and then act on what it says.\n\
         pub const LIMIT: usize = 0; // FIXME: raise the limit once measured\n",
    );
    write(
        root,
        "src/tests/mod.rs",
        "// TODO \u{b4}todo:test:a-stale-name\u{b4}: cover the recovery path\n",
    );
    write(
        root,
        "packages/demo/Cargo.toml",
        "[package]\nname = \"example-demo\"\n",
    );
    write(
        root,
        "packages/demo/src/lib.rs",
        "// TODO \u{b4}todo:code:already-right\u{b4}: already right\n",
    );
}

/// The same cycle settles the notice profile: the check counts the labelled, the
/// unlabelled and the wrongly attested; the sweep writes, rewrites and leaves
/// alone exactly those; the qualifier, the continuation line and the code before
/// a trailing marker all stand; and a further sweep changes nothing.
///
/// (´claim:cli:check-then-sweep-then-check-leaves-a-tree-clean-and-settled´)
/// ´test:integration:a-fixture-notice-tree-checks-and-then-fixes-clean´
#[test]
fn a_fixture_notice_tree_checks_and_then_fixes_clean() {
    let root = tempfile::tempdir().expect("temporary directory");
    notice_workspace(root.path());
    track(root.path());
    declare_fixture_profile(root.path(), "profile.todos-conform");

    let (code, before) = run(&["check"], root.path());

    assert_eq!(
        code,
        Some(3),
        "the stale attestation fails from the first commit"
    );
    assert_eq!(before["todo"]["covered"], 4);
    assert_eq!(before["todo"]["by_area"]["code"], 3);
    assert_eq!(before["todo"]["by_area"]["test"], 1);
    assert_eq!(before["todo"]["labelled"], 1, "one notice is already right");
    assert_eq!(
        before["todo"]["unlabelled"], 2,
        "two are the register's family"
    );
    assert_eq!(
        before["todo"]["wrong"], 1,
        "one attests a label it does not derive"
    );

    let (code, swept) = run(
        &["fix", "--profile", "todo", "--write", "--allow-dirty"],
        root.path(),
    );

    assert_eq!(code, Some(0), "the sweep completes: {swept}");
    assert_eq!(swept["profile"], "todo");
    assert_eq!(swept["dry_run"], false);
    assert_eq!(swept["inserted"], 2);
    assert_eq!(swept["repaired"], 1);
    assert_eq!(swept["unchanged"], 1);
    assert_eq!(swept["refused"], 0);

    let (code, after) = run(&["check"], root.path());

    assert_eq!(code, Some(0), "the sweep leaves the fixture clean: {after}");
    assert_eq!(after["todo"]["labelled"], 4);
    assert_eq!(
        after["todo"]["unlabelled"], 0,
        "the register's family is empty"
    );
    assert_eq!(after["todo"]["wrong"], 0);

    let swept_source = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");
    assert_eq!(
        swept_source,
        concat!(
            "// TODO(ADR-T-016 2026-08-19) \u{b4}todo:code:read-the-policy-flag-before-deciding\u{b4}: ",
            "read the policy flag before deciding\n",
            "// and then act on what it says.\n",
            "pub const LIMIT: usize = 0; // FIXME \u{b4}todo:code:raise-the-limit-once-measured\u{b4}: ",
            "raise the limit once measured\n",
        ),
        "the qualifier, the continuation, and the code before a trailing marker all stand"
    );

    let (code, again) = run(
        &["fix", "--profile", "todo", "--write", "--allow-dirty"],
        root.path(),
    );

    assert_eq!(code, Some(0));
    assert_eq!(again["inserted"], 0, "the sweep is idempotent");
    assert_eq!(again["repaired"], 0);
    assert_eq!(again["unchanged"], 4);
    assert_eq!(again["files_changed"], 0);
}

/// The notice sweep reports its mode truthfully: without `--write` it counts
/// what it would change and leaves every file alone, while with `--write` it
/// reports a write and applies the changes.
/// The fixture activates its owners' todo profile so it belongs to the sweep.
///
/// (´claim:fix:a-dry-run-counts-what-it-would-do-and-writes-nothing´)
/// ´test:integration:the-todo-sweep-writes-nothing-on-a-dry-run´
#[test]
fn the_todo_sweep_writes_nothing_on_a_dry_run() {
    let root = tempfile::tempdir().expect("temporary directory");
    notice_workspace(root.path());
    track(root.path());
    declare_fixture_profile(root.path(), "profile.todos-conform");

    let before = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");
    let (code, report) = run(&["fix", "--profile", "todo"], root.path());
    let after = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");

    assert_eq!(code, Some(0));
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["inserted"], 2, "it still counts what it would do");
    assert_eq!(before, after, "and leaves every file alone");

    let (code, report) = run(
        &["fix", "--profile", "todo", "--write", "--allow-dirty"],
        root.path(),
    );
    let written = fs::read_to_string(root.path().join("src/lib.rs")).expect("read");

    assert_eq!(code, Some(0));
    assert_eq!(report["dry_run"], false);
    assert_ne!(before, written, "and the write mode applies its changes");
}

/// The burn list of one fixture tree: prose under its documentation and comments
/// under its sources.
fn fixture_burn_list() -> BurnList {
    BurnList::new(
        "section references",
        Shape::Legacy(&[LegacyRule::SectionNumber]),
        vec![PathBuf::from("docs")],
        vec![PathBuf::from("src")],
    )
}

/// The ratchet a fixture declares, in the rows the canonical list carries.
fn declared(rows: &[(&str, usize)]) -> Vec<RegisterRow> {
    rows.iter()
        .map(|(path, count)| {
            RegisterRow::new(*path, *count, Location::new(".linter/lists.toml", "", 0))
        })
        .collect()
}

/// Census a fixture tree and judge its declared ratchet, as the check does.
fn ratchet(root: &Path, list: &BurnList, rows: &[(&str, usize)]) -> Vec<&'static str> {
    let plan = plan(root);
    let (taken, census_findings) = census(
        root,
        list,
        plan.topology().corpus(),
        plan.topology().partition().attribution(),
    );

    assert_eq!(codes(&census_findings), Vec::<&str>::new());

    codes(&verify(list, &taken, &declared(rows)))
}

/// The ratchet binds in both directions: the census as found passes, one more
/// reference fails as growth with the new occurrence named, and one fewer fails
/// as a stale row until the list falls with it. A file losing its last reference
/// leaves the list rather than standing at zero.
///
/// ´claim:burn:the-ratchet-fails-on-growth-and-on-a-list-that-overstates´
/// ´test:integration:a-burn-list-fails-on-growth-and-on-a-stale-row´
#[test]
fn a_burn_list_fails_on_growth_and_on_a_stale_row() {
    let root = tempfile::tempdir().expect("temporary directory");
    let list = fixture_burn_list();

    write(
        root.path(),
        "docs/note.md",
        "As §10.3 requires, and §6.1 too.\n",
    );
    write(root.path(), "src/lib.rs", "//! Per §4.2.\nfn f() {}\n");
    track(root.path());

    let held = [("docs/note.md", 2), ("src/lib.rs", 1)];

    assert_eq!(
        ratchet(root.path(), &list, &held),
        Vec::<&str>::new(),
        "the census as found is the ratchet, so the gate is clean"
    );

    // Growth: one more reference than the list accounts for.
    write(
        root.path(),
        "docs/note.md",
        "As §10.3 requires, and §6.1 too, and §7.4.\n",
    );
    assert_eq!(
        ratchet(root.path(), &list, &held),
        ["burn_list_growth"],
        "adding a section reference anywhere fails"
    );

    // And the finding names the occurrence that took the file over.
    let plan = plan(root.path());
    let (grown, _findings) = census(
        root.path(),
        &list,
        plan.topology().corpus(),
        plan.topology().partition().attribution(),
    );
    let rendered: Vec<String> = verify(&list, &grown, &declared(&held))
        .iter()
        .map(ToString::to_string)
        .collect();

    assert!(
        rendered
            .iter()
            .any(|finding| finding.contains("§7.4") && finding.contains("docs/note.md")),
        "the growth names the new occurrence: {rendered:#?}"
    );

    // Shrinkage: fewer references than the list accounts for, and the list is
    // stale until it falls with them.
    write(root.path(), "docs/note.md", "As §10.3 requires.\n");
    assert_eq!(
        ratchet(root.path(), &list, &held),
        ["stale_burn_entry"],
        "removing a section reference fails until the list shrinks"
    );

    assert_eq!(
        ratchet(
            root.path(),
            &list,
            &[("docs/note.md", 1), ("src/lib.rs", 1)]
        ),
        Vec::<&str>::new(),
        "and passes once the list shrinks with it"
    );

    // A file that loses its last reference leaves the list outright.
    write(root.path(), "docs/note.md", "No reference at all.\n");
    assert_eq!(
        ratchet(
            root.path(),
            &list,
            &[("docs/note.md", 1), ("src/lib.rs", 1)]
        ),
        ["stale_burn_entry"]
    );
    assert_eq!(
        ratchet(root.path(), &list, &[("src/lib.rs", 1)]),
        Vec::<&str>::new(),
        "the emptied file leaves the list rather than standing at zero"
    );
}

/// The burn command reports and writes nothing unless asked: every adopted
/// family is registered at its census, none is rewritten, and the trees excluded
/// from each census are named in the report rather than left to be remembered.
///
/// ´claim:cli:the-burn-command-reports-and-writes-nothing-by-default´
/// ´test:integration:the-burn-command-emits-json-and-writes-nothing-by-default´
#[test]
fn the_burn_command_emits_json_and_writes_nothing_by_default() {
    let root = tempfile::tempdir().expect("temporary directory");

    // A tree with nothing for any family to count. What is being read here is
    // the report and the mutation, and a census at zero says both without
    // pinning a population: the run either emits its object and leaves the tree
    // alone or it does not.
    // A census looks where the corpus says it does, and it says so in the
    // document of the policy that activates it, so every family's surface is
    // declared here rather than remembered by the binary. What it never reads is
    // derived from the same declaration and written down nowhere: the checker's
    // own share, and for a repository-scoped family the shares whose owners hold
    // the per-owner sibling of its program.
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"PROJECTB\", \"SUPERLOOPLINT\"]\n\
         partitions = [{ name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }, \
         { name = \"project-b-package\", owner = \"PROJECTB\", pattern = '%s\"packages/project-b\" [ \"/\" *VCHAR ]' }, \
         { name = \"linter-package\", owner = \"SUPERLOOPLINT\", pattern = '%s\"packages/superloop-lint\" [ \"/\" *VCHAR ]' }]\n\
         may_cite = []\n",
        "environments = []\n",
        &censused_policies(),
        &censused_lists(),
    );

    for (domain, owner, prose, code) in CENSUS_SURFACES {
        let mut text = format!(
            "namespace = \"class.linter.policy.{domain}\"\nversion = [1, 0, 0]\n\n[owners.{owner}]\n"
        );

        for (key, pattern) in [("prose", prose), ("code", code)] {
            if !pattern.is_empty() {
                let _ignored = writeln!(text, "{key} = '{pattern}'");
            }
        }

        write(
            root.path(),
            &format!(".linter/policy-{}.toml", domain.replace('.', "-")),
            &text,
        );
    }

    let before = tree(root.path());
    let (code, report) = run(&["burn"], root.path());

    assert_eq!(
        code,
        Some(0),
        "a census the ratchet accounts for exits clean: {report}"
    );
    assert!(
        report.get("schema").is_none(),
        "the burn report states no version of itself"
    );
    assert_eq!(report["write"], false);
    assert_eq!(report["lowered"], false);
    assert_eq!(report["failures"], 0);

    let families = report["families"].as_array().expect("families");

    assert!(!families.is_empty(), "every adopted family is reported");

    for family in families {
        assert_eq!(
            family["occurrences"], family["registered"],
            "{} is registered at its census",
            family["family"]
        );
        assert_eq!(family["kept"], 0);
        assert_eq!(family["owed"], family["registered"]);
        assert!(
            !family["excluded"]
                .as_array()
                .expect("exclusions")
                .is_empty(),
            "{} names the trees it does not read rather than leaving them to be remembered",
            family["family"]
        );
    }

    assert_eq!(
        tree(root.path()),
        before,
        "a default run writes not one byte"
    );
}

/// A family with kept and unkept rows retains their full registered count
/// while reporting the two parts, and the check report sums each part across
/// two families.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be read, written, executed, or parsed.
///
/// ´claim:cli:kept-and-owed-counts-sum-across-families´
/// ´test:integration:kept-and-owed-counts-sum-across-families´
#[test]
fn kept_and_owed_counts_sum_across_families() {
    let root = characterization_census_fixture();
    let path = root.path().join(".linter/lists.toml");
    let lists = fs::read_to_string(&path).expect("the lists");
    let lists = lists.replacen(
        "path_counts = [\n  { path = \"packages/project-b/docs/debt.md\", maximum = 1 },\n]",
        "path_counts = [\n  { path = \"packages/project-b/docs/debt.md\", maximum = 1, kept = \"printed text\" },\n  { path = \"packages/project-b/docs/other.md\", maximum = 2 },\n]",
        1,
    );
    let lists = lists.replacen(
        "[PROJECTB.\"legacy.record-references\"]\npath_counts = []",
        "[PROJECTB.\"legacy.record-references\"]\npath_counts = [\n  { path = \"packages/project-b/docs/debt.md\", maximum = 4, kept = \"machine input\" },\n]",
        1,
    );
    fs::write(path, lists).expect("the revised lists");

    let (_code, report) = run(&["check"], root.path());
    let families = report["burn"]["families"]
        .as_array()
        .expect("burn families");
    let first = families
        .iter()
        .find(|family| family["registered"] == 3)
        .expect("the family with two rows");
    assert_eq!(first["kept"], 1);
    assert_eq!(first["owed"], 2);
    assert_eq!(first["registered"].as_u64(), Some(3));
    assert_eq!(first["kept"].as_u64(), Some(1));
    assert_eq!(first["owed"].as_u64(), Some(2));

    let second = families
        .iter()
        .find(|family| family["registered"] == 4)
        .expect("the second family");
    assert_eq!(second["kept"], 4);
    assert_eq!(second["owed"], 0);
    assert_eq!(report["burn"]["kept"], 5);
    assert_eq!(report["burn"]["owed"], 2);

    let (_code, burn) = run(&["burn"], root.path());
    let burn_families = burn["families"].as_array().expect("burn families");
    let burn_first = burn_families
        .iter()
        .find(|family| family["registered"] == 3)
        .expect("the first burn family");
    assert_eq!(burn_first["kept"], 1);
    assert_eq!(burn_first["owed"], 2);
}

/// A lowering write over empty declared lists has no ceiling to lower: growth
/// in two files remains a finding for each file, and only append may record it.
/// The declaration and the rest of the tree retain their bytes.
///
/// ´claim:cli:the-burn-write-lowers-nothing-from-an-empty-declaration-and-keeps-growth´
/// ´test:integration:the-burn-write-lowers-nothing-from-an-empty-declaration-and-keeps-growth´
#[test]
fn the_burn_write_lowers_nothing_from_an_empty_declaration_and_keeps_growth() {
    let root = tempfile::tempdir().expect("temporary directory");
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"PROJECTB\", \"SUPERLOOPLINT\"]\n\
         partitions = [{ name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }, \
         { name = \"project-b-package\", owner = \"PROJECTB\", pattern = '%s\"packages/project-b\" [ \"/\" *VCHAR ]' }, \
         { name = \"linter-package\", owner = \"SUPERLOOPLINT\", pattern = '%s\"packages/superloop-lint\" [ \"/\" *VCHAR ]' }]\n\
         may_cite = []\n",
        "environments = []\n",
        &censused_policies(),
        &censused_lists().replace("\n[", "\n\n["),
    );

    for (domain, owner, prose, code) in CENSUS_SURFACES {
        let mut text = format!(
            "namespace = \"class.linter.policy.{domain}\"\nversion = [1, 0, 0]\n\n[owners.{owner}]\n"
        );

        for (key, pattern) in [("prose", prose), ("code", code)] {
            if !pattern.is_empty() {
                let _ignored = writeln!(text, "{key} = '{pattern}'");
            }
        }

        write(
            root.path(),
            &format!(".linter/policy-{}.toml", domain.replace('.', "-")),
            &text,
        );
    }

    let paths = [
        "packages/project-b/docs/one.md",
        "packages/project-b/docs/two.md",
    ];
    for path in paths {
        write(root.path(), path, "The retired locator is §1.\n");
    }
    track(root.path());

    let lists_path = root.path().join(".linter/lists.toml");
    let before_lists = fs::read(&lists_path).expect("declared lists");
    let before_tree = tree(root.path());
    let (code, report) = run(&["burn", "--write"], root.path());

    assert_eq!(code, Some(3), "growth remains a failure: {report}");
    assert_eq!(report["write"], true);
    assert_eq!(
        report["findings"].as_array().expect("findings").len(),
        paths.len(),
        "no other findings obscure the growth: {report}"
    );

    let growth: Vec<&serde_json::Value> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|finding| {
            finding["code"] == "burn_list_growth" && finding["family"] == "section-sign references"
        })
        .collect();
    assert_eq!(
        growth.len(),
        paths.len(),
        "one finding per holding file: {report}"
    );
    for (finding, path) in growth.iter().zip(paths) {
        assert_eq!(finding["path"], path);
        assert_eq!(finding["registered"], 0);
        assert_eq!(finding["found"], 1);
    }
    assert_eq!(fs::read(&lists_path).expect("declared lists"), before_lists);
    assert_eq!(
        tree(root.path()),
        before_tree,
        "the whole tree keeps its bytes"
    );

    assert_eq!(report["lowered"], false, "report: {report}");
    for finding in growth {
        assert!(
            finding["message"]
                .as_str()
                .expect("growth message")
                .ends_with(
                    "a burn list may only shrink here; growth the tree already holds is recorded through the append mode"
                ),
            "growth names the recording mode: {finding}"
        );
    }
}

/// The burn command reports its wall time in the result object, matching the
/// judging commands that decide a corpus verdict.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked,
/// executed, or parsed.
///
/// ´claim:cli:the-burn-command-reports-elapsed-micros´
/// ´test:integration:the-burn-command-reports-elapsed-micros´
#[test]
fn the_burn_command_reports_elapsed_micros() {
    let root = characterization_census_fixture();

    let (code, report) = run(&["burn"], root.path());

    assert_eq!(code, Some(0), "the census matches its registers: {report}");
    assert_elapsed_micros(&report);
}

/// Public-pack mode reads the outside-tree document when the declared local
/// document is absent, reports the supplied path and external source kind, and
/// uses its modes to find public occurrences with their file and line while
/// preserving the policy-local exclusion.
///
/// ´claim:burn:public-pack-mode-reports-and-uses-its-effective-external-input´
/// ´test:integration:the-external-document-in-public-pack-mode-is-honored-and-its-path-reported´
#[test]
fn the_external_document_in_public_pack_mode_is_honored_and_its_path_reported() {
    let (root, _verifier, input) = public_pack_fixture();
    let output = run_public_pack(root.path(), &input);

    assert_eq!(
        output.status.code(),
        Some(3),
        "the public hits fail the check"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the superloop-pack check report");
    let families = report["burn"]["families"]
        .as_array()
        .expect("the burn family reports");
    let family = families
        .iter()
        .find(|family| family["family"] == "public-pack values")
        .expect("the external-value family");

    assert!(report["public_pack"].as_bool().expect("the mode flag"));
    assert_eq!(family["declared"], 2);
    assert_eq!(family["mode"]["substring"], 1);
    assert_eq!(family["mode"]["identifier"], 1);
    assert_eq!(family["source"], input.to_string_lossy().as_ref());
    assert_eq!(family["source_kind"], "external");
    assert_eq!(
        family["excluded"],
        serde_json::json!([r#"%s"local" [ "/" *VCHAR ]"#])
    );
    assert_eq!(family["occurrences"], 2);
    assert_eq!(family["rows"][0]["path"], "docs/guide.md");
    assert_eq!(family["rows"][0]["count"], 2);

    let growth = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["code"] == "burn_list_growth")
        .expect("the public hit");
    assert_eq!(growth["location"]["path"], "docs/guide.md");
    assert_eq!(growth["location"]["line"], 2);
}

fn report_without_elapsed_suffix(stdout: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(stdout).expect("report stdout is UTF-8");

    assert_eq!(
        text.matches(",\"elapsed_micros\":").count(),
        1,
        "the report has exactly one elapsed_micros key: {text}"
    );

    let text = text.strip_suffix('\n').expect("report ends with newline");
    let body = text.strip_suffix('}').expect("report is a JSON object");
    let (report, elapsed) = body
        .rsplit_once(",\"elapsed_micros\":")
        .expect("elapsed_micros is serialized last");

    assert!(
        !elapsed.is_empty() && elapsed.bytes().all(|byte| byte.is_ascii_digit()),
        "elapsed_micros suffix is decimal digits: {text}"
    );

    let mut without_elapsed = String::with_capacity(report.len() + 2);
    without_elapsed.push_str(report);
    without_elapsed.push_str("}\n");
    without_elapsed.into_bytes()
}

/// Two superloop-pack checks over the same immutable tree and verifier input emit
/// identical JSON payloads after eliding the wall-time field, so neither
/// filesystem order nor value matching introduces report drift.
///
/// ´claim:report:public-pack-reports-are-byte-deterministic´
/// ´test:integration:two-runs-over-the-same-tree-produce-payload-identical-reports´
#[test]
fn two_runs_over_the_same_tree_produce_payload_identical_reports() {
    let (root, _verifier, input) = public_pack_fixture();
    let first = run_public_pack(root.path(), &input);
    let second = run_public_pack(root.path(), &input);

    assert_eq!(first.status.code(), Some(3));
    assert_eq!(second.status.code(), Some(3));

    assert_eq!(
        report_without_elapsed_suffix(&first.stdout),
        report_without_elapsed_suffix(&second.stdout)
    );
}

/// Build an extracted-tree fixture and a separate verifier input.
fn public_pack_fixture() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("temporary public tree");
    let verifier = tempfile::tempdir().expect("temporary verifier directory");
    let input = verifier.path().join("example-burn.toml");

    write(
        root.path(),
        "docs/guide.md",
        "Fictional public guide.\nsagofink-loop is a derived name.\npreexample-loopsuffix is broad.\n",
    );
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"LOCAL\"]\n\
         partitions = [\
           { name = \"public-tree\", owner = \"PROJECTA\", pattern = '(%s\".linter\" [ \"/\" *VCHAR ] / %s\"docs\" [ \"/\" *VCHAR ])' },\
           { name = \"local-overlay\", owner = \"LOCAL\", pattern = '%s\"local\" [ \"/\" *VCHAR ]' }\
         ]\n\
         may_cite = []\n",
        "environments = []\n",
        "policies = [{ owner = \"PROJECTA\", policy = \"public-pack.values-absent\" }]\n",
        "[PROJECTA.\"public-pack.values-absent\"]\npath_counts = []\n",
    );
    write(
        root.path(),
        ".linter/policy-public-pack-values.toml",
        "namespace = \"class.linter.policy.public-pack.values-absent\"\n\
         version = [1, 0, 0]\n\
         \n\
         [owners.PROJECTA]\n\
         surface = \"*VCHAR\"\n\
         values = \"local/linter/example-burn.toml\"\n\
         exclude = '%s\"local\" [ \"/\" *VCHAR ]'\n",
    );
    fs::write(
        &input,
        "values = [\n\
         { value = \"sagofink\", match = \"identifier\" },\n\
         { value = \"example-loop\", match = \"substring\" },\n\
         ]\n",
    )
    .expect("the outside burn-value document");
    track(root.path());

    (root, verifier, input)
}

/// Run a check under the superloop-pack command-contract inputs.
fn run_public_pack(root: &Path, input: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .arg("--public-pack")
        .arg("--burn-input")
        .arg(input)
        .arg("check")
        .arg("--root")
        .arg(root)
        .output()
        .expect("run the superloop-pack check")
}

/// The censused families, by the domain whose document declares each surface.
///
/// Seven stand in project B's share and one is the to-do census over the
/// members, which is the root owner's; the last two are the repository-scoped
/// halves, which name the corpus entire and are the only ones a sibling
/// activation cuts anything out of. Three of the ten stand in a domain named for
/// the shape they read rather than for their own policy, because a census of a
/// shape belongs beside the declaration of that shape.
const CENSUS_SURFACES: [(&str, &str, &str, &str); 11] = [
    (
        "legacy.section-references",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    (
        "legacy.record-references",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    (
        "legacy.unprefixed-record-references",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    ("legacy.tag-references", "PROJECTB", PROJECTB_PROSE, ""),
    (
        "references.scenarios",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    (
        "references.divisions",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    (
        "references.prefix-numbers",
        "PROJECTB",
        PROJECTB_PROSE,
        PROJECTB_CODE,
    ),
    ("legacy.todos", "PROJECTA", "", MEMBER_CODE),
    ("legacy.implementation", "PROJECTB", "", PROJECTB_CODE),
    (
        "legacy.section-references-repository",
        "PROJECTA",
        CORPUS_SURFACE,
        CORPUS_SURFACE,
    ),
    (
        "legacy.record-references-repository",
        "PROJECTA",
        CORPUS_SURFACE,
        CORPUS_SURFACE,
    ),
];

/// The prose tree project B's censuses walk in this fixture.
const PROJECTB_PROSE: &str = r#"%s"packages/project-b/docs" [ "/" *VCHAR ]"#;

/// The code tree project B's censuses walk in this fixture.
const PROJECTB_CODE: &str = r#"%s"packages/project-b/src" [ "/" *VCHAR ]"#;

/// The trees the to-do census walks, which are the members rather than one share.
const MEMBER_CODE: &str = r#"( %s"src" / %s"packages" ) [ "/" *VCHAR ]"#;

/// The corpus entire, which is how a repository-scoped census states its surface.
const CORPUS_SURFACE: &str = "*VCHAR";

/// The activations the ten censuses stand at, each at the owner whose debt it is.
fn censused_policies() -> String {
    let rows: Vec<String> = census_activations()
        .map(|(owner, policy)| format!("{{ owner = \"{owner}\", policy = \"{policy}\" }}"))
        .collect();

    format!(
        "policies = [{{ owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }}, {}]\n",
        rows.join(", ")
    )
}

/// The empty ratchet each of those activations carries, because an activation wants one.
fn censused_lists() -> String {
    census_activations().fold(
        String::from("[PROJECTB.\"labels.mints-well-formed\"]\nallowances = []\n"),
        |mut lists, (owner, policy)| {
            let _ignored = writeln!(lists, "[{owner}.\"{policy}\"]\npath_counts = []");
            lists
        },
    )
}

/// The owner and policy of each censused family, joined as the catalog joins them.
fn census_activations() -> impl Iterator<Item = (&'static str, &'static str)> {
    [
        ("PROJECTB", "legacy.section-references"),
        ("PROJECTB", "legacy.record-references"),
        ("PROJECTB", "legacy.unprefixed-record-references"),
        ("PROJECTB", "legacy.tag-references"),
        ("PROJECTB", "legacy.scenario-numbers"),
        ("PROJECTB", "legacy.division-names"),
        ("PROJECTB", "legacy.residual-litter"),
        ("PROJECTB", "legacy.todos"),
        ("PROJECTB", "legacy.implementation"),
        ("PROJECTA", "legacy.section-references-repository"),
        ("PROJECTA", "legacy.record-references-repository"),
    ]
    .into_iter()
}

/// Every file of a tree with its bytes, for the assertion that a run wrote none.
fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .expect("read the fixture tree")
            .flatten()
        {
            let path = entry.path();

            if path.is_dir() {
                pending.push(path);
            } else {
                let held = fs::read(&path).expect("read a fixture file");

                found.push((path, held));
            }
        }
    }

    found.sort();
    found
}

/// Write the five declared files into a tree's declaration directory.
///
/// The four declarations are written under the envelope allocated for each
/// schema, because the loader requires one of every declared file before it
/// interprets a single declaration. What a caller passes is therefore the
/// declaration it is testing rather than the header every declared file repeats.
fn declare(root: &Path, owners: &str, environments: &str, policies: &str, lists: &str) {
    for (file, schema, text) in [
        ("owners", "owners", owners),
        ("environments", "environments", environments),
        ("policies", "policies", policies),
        ("lists", "lists", lists),
        (
            "shape",
            "shape",
            "universe = \"git-tracked\"\n\nignore = []\n",
        ),
    ] {
        write(
            root,
            &format!(".linter/{file}.toml"),
            &format!(
                "namespace = \"{}.{schema}\"\nversion = [1, 0, 0]\n\n{text}",
                if schema == "lists" || schema.starts_with("policy.") {
                    "class.linter"
                } else {
                    "org.example.linter"
                }
            ),
        );
    }
}

/// Give legacy semantic fixtures an explicit, untracked declaration without
/// changing the tracked corpus they exercise.
fn ensure_fixture_surface(root: &Path) {
    if root.join(".linter").is_dir() {
        return;
    }

    if root.join("packages/demo").is_dir() {
        declare(
            root,
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"DEMO\"]\n\
             partitions = [\
               { name = \"fixture-root\", owner = \"PROJECTA\", pattern = '(%s\"Cargo.toml\" / %s\"README.md\" / %s\"adr\" [ \"/\" *VCHAR ] / %s\"docs\" [ \"/\" *VCHAR ] / %s\"src\" [ \"/\" *VCHAR ])' },\
               { name = \"demo-package\", owner = \"DEMO\", pattern = '%s\"packages/demo\" [ \"/\" *VCHAR ]' }\
             ]\n\
             may_cite = []\n",
            FIXTURE_ENVIRONMENTS,
            "policies = [\
               { owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" },\
               { owner = \"DEMO\", policy = \"labels.mints-well-formed\" }\
             ]\n",
            "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n\n\
             [DEMO.\"labels.mints-well-formed\"]\nallowances = []\n",
        );
    } else {
        declare(
            root,
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
             partitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
             may_cite = []\n",
            FIXTURE_ENVIRONMENTS,
            "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n",
            "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n",
        );
    }
}

/// Make a fixture tree a repository whose tracked corpus is everything in it.
///
/// The partition's accounting universe is the tracked corpus rather than the
/// physical tree, so a fixture that means to be partitioned has to be a
/// repository. An untracked tree has an empty universe, against which every
/// inclusion row is vacuously total and no path can be unaccounted — the
/// opposite of what these fixtures exist to show.
///
/// The index is built directly so neither an external executable nor ambient
/// ignore configuration can decide what the fixture tracks.
fn track(root: &Path) {
    git_fixture::track_all(root);
}

/// The owner file a declared fixture starts from, accounting the whole tree.
const DECLARED_OWNERS: &str = "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
    partitions = [{ name = \"decision-records\", owner = \"PROJECTA\", pattern = '%s\"adr\" [ \"/\" *VCHAR ]' }, \
    { name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }]\n\
    may_cite = []\n";

/// The activation file a declared fixture starts from.
const DECLARED_POLICIES: &str =
    "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n";

/// The list file a declared fixture starts from.
const DECLARED_LISTS: &str = "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n";

fn build_mode_fixture(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary corpus");
    write(root.path(), "adr/001-one.md", source);
    declare(
        root.path(),
        DECLARED_OWNERS,
        FIXTURE_ENVIRONMENTS,
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    track(root.path());
    root
}

fn run_build_check(root: &Path, report: &Path, stamp: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root)
        .arg("--write-report")
        .arg(report)
        .arg("--write-stamp")
        .arg(stamp)
        .output()
        .expect("run build-mode check")
}

/// A clean build check publishes stable report bytes and an empty, refreshed stamp.
///
/// # Panics
///
/// Panics only if the fixture cannot be written or the linter violates the stamp contract.
///
/// ´claim:cli:a-clean-build-check-publishes-stable-report-bytes´
/// ´test:integration:a-clean-build-check-publishes-stable-report-bytes´
#[test]
fn a_clean_build_check_publishes_stable_report_bytes() {
    let root = build_mode_fixture("## Head · `sec:fixture:head`\n\nCites (`sec:fixture:head`).\n");
    let output = tempfile::tempdir().expect("output directory");
    let report = output.path().join("check.json");
    let stamp = output.path().join("check.stamp");
    let first = run_build_check(root.path(), &report, &stamp);
    assert_eq!(first.status.code(), Some(0), "{:?}", first.stderr);
    assert_eq!(first.stdout, b"");
    assert_eq!(fs::metadata(&stamp).expect("stamp").len(), 0);
    let bytes = fs::read(&report).expect("report");
    let modified = fs::metadata(&report)
        .expect("report metadata")
        .modified()
        .expect("mtime");
    std::thread::sleep(std::time::Duration::from_millis(20));
    let second = run_build_check(root.path(), &report, &stamp);
    assert_eq!(second.status.code(), Some(0), "{:?}", second.stderr);
    assert_eq!(second.stdout, b"");
    assert_eq!(fs::read(&report).expect("second report"), bytes);
    assert_eq!(
        fs::metadata(&report)
            .expect("second metadata")
            .modified()
            .expect("mtime"),
        modified
    );
}

/// A completed check with findings writes a report but never a success stamp.
///
/// # Panics
///
/// Panics only if the fixture cannot be written or a failing check stamps success.
///
/// ´claim:cli:a-failing-build-check-never-stamps-success´
/// ´test:integration:a-failing-build-check-never-stamps-success´
#[test]
fn a_failing_build_check_never_stamps_success() {
    let root =
        build_mode_fixture("## Head · `sec:fixture:head`\n\n## Again · `sec:fixture:head`\n");
    let output = tempfile::tempdir().expect("output directory");
    let report = output.path().join("check.json");
    let stamp = output.path().join("check.stamp");
    let result = run_build_check(root.path(), &report, &stamp);
    assert_eq!(result.status.code(), Some(3), "{:?}", result.stderr);
    assert!(report.exists());
    assert!(!stamp.exists());
}

/// A stamp carrying foreign bytes is preserved and refused.
///
/// # Panics
///
/// Panics only if the fixture cannot be written or a foreign stamp is changed.
///
/// ´claim:cli:a-nonempty-build-stamp-is-preserved-and-refused´
/// ´test:integration:a-nonempty-build-stamp-is-preserved-and-refused´
#[test]
fn a_nonempty_build_stamp_is_preserved_and_refused() {
    let root = build_mode_fixture("## Head · `sec:fixture:head`\n");
    let output = tempfile::tempdir().expect("output directory");
    let report = output.path().join("check.json");
    let stamp = output.path().join("check.stamp");
    fs::write(&stamp, b"foreign").expect("foreign stamp");
    let result = run_build_check(root.path(), &report, &stamp);
    assert_eq!(result.status.code(), Some(1), "{:?}", result.stderr);
    assert_eq!(fs::read(&stamp).expect("foreign stamp"), b"foreign");
}

/// An incomplete pair and a write paired with check outputs are usage errors.
///
/// # Panics
///
/// Panics only if the subprocess cannot run or invalid arguments are admitted.
///
/// ´claim:cli:incomplete-and-writing-output-pairs-are-usage-errors´
/// ´test:integration:incomplete-and-writing-output-pairs-are-usage-errors´
#[test]
fn incomplete_and_writing_output_pairs_are_usage_errors() {
    let output = tempfile::tempdir().expect("output directory");
    let report = output.path().join("check.json");
    let lone = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--write-report"])
        .arg(&report)
        .output()
        .expect("lone report");
    assert_eq!(lone.status.code(), Some(2));
    let write = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["project", "--write", "--write-report"])
        .arg(&report)
        .arg("--write-stamp")
        .arg(output.path().join("check.stamp"))
        .output()
        .expect("writing pair");
    assert_eq!(write.status.code(), Some(2));
    assert!(!report.exists());
}

/// A tree with no declaration directory refuses with an empty stdout before
/// command dispatch and names all five required documents on stderr in their
/// declared order.
///
/// ´claim:cli:an-absent-declaration-refuses-without-running-the-command´
/// ´test:integration:an-absent-declaration-refuses-without-running-the-command´
#[test]
fn an_absent_declaration_refuses_without_running_the_command() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n\nCites (`sec:fixture:head`).\n",
    );
    track(root.path());

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root.path())
        .output()
        .expect("run the linter");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"");

    let refusals: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&output.stderr)
        .into_iter()
        .collect::<Result<_, _>>()
        .expect("five refusal records on stderr");

    assert_eq!(refusals.len(), 5);

    for (refusal, file) in refusals.iter().zip([
        "owners.toml",
        "environments.toml",
        "policies.toml",
        "lists.toml",
        "shape.toml",
    ]) {
        assert_eq!(
            refusal["fields"]["refusal"],
            format!(".linter/{file}: the snapshot requires this file")
        );
        assert_eq!(refusal["fields"]["message"], refusal["fields"]["refusal"]);
        assert_eq!(
            refusal["fields"]["kind"],
            "the declared configuration is not a snapshot"
        );
    }
}

/// A declaration that is not a snapshot refuses the command entire: the exit is
/// the shared failure class rather than the findings class, and stdout is
/// empty. A command that cannot read its own configuration has no standing to
/// say anything about the corpus, so it says nothing rather than reporting a
/// verdict it could not have formed.
///
/// ´claim:cli:a-refused-snapshot-exits-one-with-an-empty-stdout´
/// ´test:integration:a-refused-snapshot-exits-one-with-an-empty-stdout´
#[test]
fn a_refused_snapshot_exits_one_with_an_empty_stdout() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n",
    );

    declare(
        root.path(),
        DECLARED_OWNERS,
        "environments = []\n",
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-unheard-of\" }]\n",
        DECLARED_LISTS,
    );

    for command in ["check", "burn", "coverage", "shape"] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .args([command, "--root"])
            .arg(root.path())
            .output()
            .expect("run the linter");

        assert_eq!(output.status.code(), Some(1), "{command}");
        assert!(output.stdout.is_empty(), "{command}");
    }
}

/// A profile activated without the label calculus it reads refuses every
/// command before dispatch. The shared configuration-failure surface keeps
/// stdout empty and names the missing same-owner label prerequisite on stderr,
/// so an incomplete declaration cannot silently run a partial policy.
///
/// ´claim:cli:a-dependent-policy-without-label-prerequisites-refuses-loudly´
/// ´test:integration:a-dependent-policy-without-label-prerequisites-refuses-loudly´
#[test]
fn a_dependent_policy_without_label_prerequisites_refuses_loudly() {
    let root = tempfile::tempdir().expect("temporary directory");

    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
         partitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
         may_cite = []\n",
        "environments = []\n",
        "policies = [{ owner = \"PROJECTA\", policy = \"profile.tests-conform\" }]\n",
        "[PROJECTA.\"profile.tests-conform\"]\nallowances = []\n",
    );
    track(root.path());

    for (name, arguments) in [
        ("check", &["check"][..]),
        ("report", &["report"][..]),
        ("coverage", &["coverage"][..]),
        ("shape", &["shape"][..]),
        ("assemble", &["assemble"][..]),
        ("burn", &["burn"][..]),
        ("project", &["project"][..]),
        ("fix-test", &["fix", "--profile", "test"][..]),
        ("fix-todo", &["fix", "--profile", "todo"][..]),
        (
            "burn-audit",
            &["burn", "--audit", "--output", "response.json"][..],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .env("RUST_LOG", "error")
            .args(arguments)
            .args(["--root"])
            .arg(root.path())
            .output()
            .expect("run the linter");

        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(output.stdout.is_empty(), "{name}: {:?}", output.stdout);

        let stderr = String::from_utf8(output.stderr).expect("JSON diagnostics are UTF-8");
        assert!(
            stderr.contains(
                "policy dependency: PROJECTA : profile.tests-conform: missing same-owner pair PROJECTA : labels.mints-well-formed"
            ),
            "{name}: {stderr}"
        );
    }
}

/// A snapshot whose declaration is complete but whose partition disagrees with
/// the tree is judged rather than refused: the run happens, the object is
/// complete, and the exit is the findings class with the unaccounted path named
/// in the report.
///
/// ´claim:cli:a-parsed-snapshot-that-disagrees-is-judged-rather-than-refused´
/// ´test:integration:a-parsed-snapshot-that-disagrees-is-judged-rather-than-refused´
#[test]
fn a_parsed_snapshot_that_disagrees_is_judged_rather_than_refused() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n",
    );
    write(root.path(), "stray.md", "nothing accounts for this\n");

    declare(
        root.path(),
        DECLARED_OWNERS,
        "environments = []\n",
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    track(root.path());

    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root.path())
        .output()
        .expect("run the linter");

    assert_eq!(output.status.code(), Some(3));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON object on stdout");

    assert_eq!(report["clean"], false);
    assert_eq!(report["configuration"]["pairs"], 1);
    assert_eq!(report["configuration"]["partition"]["unaccounted"], 1);
    assert_eq!(report["configuration"]["missing_dependencies"], 0);

    let raised: Vec<&str> = report["findings"]
        .as_array()
        .expect("an array of findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();

    assert!(raised.contains(&"unaccounted_path"), "{raised:?}");
}

/// Every writing mode refuses to mutate under a declaration that disagrees with
/// the tree. That is stricter than the exit codes alone require and
/// deliberately so: a writer that proceeded would record a conclusion drawn
/// from a question the corpus had not answered, so it exits the failure class
/// with an empty stdout instead.
///
/// ´claim:cli:a-writing-mode-refuses-a-declaration-that-disagrees-with-the-tree´
/// ´test:integration:a-writing-mode-refuses-a-declaration-that-disagrees-with-the-tree´
#[test]
fn a_writing_mode_refuses_a_declaration_that_disagrees_with_the_tree() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "## Head · `sec:fixture:head`\n",
    );
    write(root.path(), "stray.md", "nothing accounts for this\n");

    declare(
        root.path(),
        DECLARED_OWNERS,
        "environments = []\n",
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    track(root.path());

    for command in ["burn", "project", "assemble"] {
        let refused = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .args([command, "--root"])
            .arg(root.path())
            .arg("--write")
            .output()
            .expect("run the linter");

        assert_eq!(refused.status.code(), Some(1), "{command}");
        assert!(refused.stdout.is_empty(), "{command}");

        let read_only = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
            .args([command, "--root"])
            .arg(root.path())
            .output()
            .expect("run the linter");

        assert!(!read_only.stdout.is_empty(), "{command}");
    }
}

/// The nine genre rows are the whole of the Document arrangement, so a title
/// minting the kind that once stood beside them is now answered for at the
/// catalogue like any other head: the name is catalogued, the kind is not
/// catalogued under it, and the nine senses the name does carry are named back.
/// Nothing is written specially for the departed kind — the row that admitted it
/// is simply gone, and its absence is the whole of the judgment.
///
/// (´claim:head:a-title-validates-on-every-kind-the-relation-rows-its-environment´)
/// ´test:integration:a-title-minting-the-departed-document-kind-fails-at-the-catalogue´
#[test]
fn a_title_minting_the_departed_document_kind_fails_at_the_catalogue() {
    const GENRES: &str = "environments = [\
        { environment = \"Document\", kind = \"rec\" }, \
        { environment = \"Document\", kind = \"rep\" }, \
        { environment = \"Document\", kind = \"reg\" }, \
        { environment = \"Document\", kind = \"log\" }, \
        { environment = \"Document\", kind = \"proposal\" }, \
        { environment = \"Document\", kind = \"spec\" }, \
        { environment = \"Document\", kind = \"thesis\" }, \
        { environment = \"Document\", kind = \"plan\" }, \
        { environment = \"Document\", kind = \"guide\" }]\n";

    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-one.md",
        "# A Titled Document · `doc:fixture:document`\n",
    );
    declare(
        root.path(),
        DECLARED_OWNERS,
        GENRES,
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    activate_fixture_heads(root.path(), "PROJECTA");
    track(root.path());

    let (code, report) = run(&["check"], root.path());

    assert_eq!(code, Some(3), "no row admits the departed kind: {report}");
    assert_eq!(report["findings"][0]["code"], "misclassified_head");
    assert_eq!(report["findings"][0]["base"], "Document");

    let catalogued = report["findings"][0]["catalogued"]
        .as_array()
        .expect("the kinds the name does carry")
        .len();

    assert_eq!(
        catalogued, 9,
        "and the name answers with its nine senses: {report}"
    );

    write(
        root.path(),
        "adr/001-one.md",
        "# A Titled Document · `rec:fixture:document`\n",
    );
    track(root.path());

    let (code, repaired) = run(&["check"], root.path());

    assert_eq!(code, Some(0), "while a rowed genre passes: {repaired}");
    assert_eq!(repaired["heads_validated"], 1);
}

/// Run one command from inside its fixture so every reported root is `.`.
fn observable(root: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .env("RUST_LOG", "off")
        .current_dir(root)
        .args(arguments)
        .args(["--root", "."])
        .output()
        .expect("run the characterized command")
}

/// Run one command with caller-supplied standard input from inside its fixture.
///
/// A child is entitled to exit without draining its stdin: only the controlled
/// maintenance modes read a request at all, and a rejected command line leaves the
/// binary before the read. A read end the child has closed therefore says nothing
/// about the characterization — the frozen bytes, the exit code, and the response
/// file are the verdict. Any other write failure is a fault of the harness itself
/// and must be seen.
fn observable_with_input(root: &Path, arguments: &[&str], input: &[u8]) -> std::process::Output {
    use std::io::Write as _;

    let mut child = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .env("RUST_LOG", "off")
        .current_dir(root)
        .args(arguments)
        .args(["--root", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the characterized command");

    let write = child
        .stdin
        .take()
        .expect("piped standard input")
        .write_all(input);
    if let Err(error) = write {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "write the characterized request: {error}"
        );
    }

    child
        .wait_with_output()
        .expect("run the characterized command")
}

/// The lowercase SHA-256 spelling used by every byte oracle.
fn byte_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    digest
}

/// Capture base bytes while blessing, otherwise compare them with the frozen oracle.
fn frozen_bytes(name: &str, bytes: &[u8], expected_len: usize, expected_digest: &str) {
    if let Some(directory) = std::env::var_os("LINTER_CHARACTERIZATION_CAPTURE") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).expect("create the characterization capture directory");
        fs::write(directory.join(name), bytes).expect("capture characterized bytes");
    } else {
        assert_eq!(bytes.len(), expected_len, "{name} byte length");
        assert_eq!(byte_digest(bytes), expected_digest, "{name} byte digest");
    }
}

/// Fix one subprocess's three observable channels.
fn frozen_observable(
    name: &str,
    output: &std::process::Output,
    elide_elapsed: bool,
    expected_status: i32,
    expected_len: usize,
    expected_digest: &str,
) {
    assert_eq!(
        output.status.code(),
        Some(expected_status),
        "{name} status: stdout={:?}, stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert_eq!(output.stderr, b"", "{name} stderr");

    let stdout = if elide_elapsed {
        Cow::Owned(report_without_elapsed_suffix(&output.stdout))
    } else {
        Cow::Borrowed(output.stdout.as_slice())
    };
    frozen_bytes(
        &format!("{name}.stdout"),
        &stdout,
        expected_len,
        expected_digest,
    );
}

/// A two-finding prose tree used to pin ordering as well as the report bytes.
fn characterization_prose_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "adr/001-first.md",
        "Cites (`sec:fixture:first-missing`).\n",
    );
    write(
        root.path(),
        "adr/002-second.md",
        "Cites (`sec:fixture:second-missing`).\n",
    );
    track(root.path());
    root
}

/// Every command class refuses with the same empty data streams when the
/// required shape document is absent from an invented root.
///
/// ´claim:harness:no-surface-refusal-fixes-every-observable-byte´
/// ´test:integration:characterizes-no-surface-bytes´
#[test]
fn characterizes_no_surface_bytes() {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "Cargo.toml",
        "[package]\nname = \"fictional-root\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    );
    write(root.path(), "src/lib.rs", "pub fn invented() {}\n");
    write(root.path(), "README.md", "# Fictional root\n");
    track(root.path());

    for (name, arguments) in [
        ("no-surface-check", &["check"][..]),
        ("no-surface-report", &["report"][..]),
        ("no-surface-coverage", &["coverage"][..]),
        ("no-surface-shape", &["shape"][..]),
        ("no-surface-burn", &["burn"][..]),
        (
            "no-surface-control",
            &["burn", "--audit", "--output", "response.json"][..],
        ),
        ("no-surface-project", &["project"][..]),
        ("no-surface-assemble", &["assemble"][..]),
        ("no-surface-fix-test", &["fix", "--profile", "test"][..]),
        ("no-surface-fix-todo", &["fix", "--profile", "todo"][..]),
    ] {
        let output = observable(root.path(), arguments);
        frozen_observable(
            name,
            &output,
            false,
            1,
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }
}

/// A declared burn surface with one registered occurrence and nine empty families.
fn characterization_census_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    let lists = censused_lists().replacen(
        "path_counts = []",
        "path_counts = [\n  { path = \"packages/project-b/docs/debt.md\", maximum = 1 },\n]",
        1,
    );

    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"PROJECTB\", \"SUPERLOOPLINT\"]\n\
         partitions = [{ name = \"declared-surface\", owner = \"PROJECTA\", pattern = '%s\".linter\" [ \"/\" *VCHAR ]' }, \
         { name = \"project-b-package\", owner = \"PROJECTB\", pattern = '%s\"packages/project-b\" [ \"/\" *VCHAR ]' }, \
         { name = \"linter-package\", owner = \"SUPERLOOPLINT\", pattern = '%s\"packages/superloop-lint\" [ \"/\" *VCHAR ]' }]\n\
         may_cite = []\n",
        "environments = []\n",
        &censused_policies(),
        &lists,
    );

    for (domain, owner, prose, code) in CENSUS_SURFACES {
        let mut text = format!(
            "namespace = \"class.linter.policy.{domain}\"\nversion = [1, 0, 0]\n\n[owners.{owner}]\n"
        );

        for (key, pattern) in [("prose", prose), ("code", code)] {
            if !pattern.is_empty() {
                let _ignored = writeln!(text, "{key} = '{pattern}'");
            }
        }

        write(
            root.path(),
            &format!(".linter/policy-{}.toml", domain.replace('.', "-")),
            &text,
        );
    }

    write(
        root.path(),
        "packages/project-b/docs/debt.md",
        "The retired locator is §1.\n",
    );
    track(root.path());
    root
}

/// A projection fixture with one authored claim, one citing test, and an empty test folder.
fn characterization_projection_fixture() -> tempfile::TempDir {
    let acute = '\u{b4}';
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"packages/demo\"]\n",
    );
    write(
        root.path(),
        "packages/demo/Cargo.toml",
        "[package]\nname = \"example-demo\"\n",
    );
    write(
        root.path(),
        "packages/demo/src/tests/resonance.rs",
        &format!(
            "/// The widths are identical across the sweep.\n///\n\
             /// {acute}claim:resonance:crossover-widths{acute}\n\
             /// {acute}test:crate:widths-are-identical{acute}\n\
             #[test]\nfn widths_are_identical() {{}}\n\n\
             /// ({acute}claim:resonance:crossover-widths{acute})\n\
             /// {acute}test:crate:widths-survive-the-surface{acute}\n\
             #[test]\nfn widths_survive_the_surface() {{}}\n"
        ),
    );
    write(
        root.path(),
        "packages/demo/src/maths/norms.rs",
        "pub fn norm() {}\n",
    );
    declare(
        root.path(),
        "root_owner = \"DEMO\"\nowners = [\"DEMO\"]\n\
         partitions = [{ name = \"fixture\", owner = \"DEMO\", pattern = '*VCHAR' }]\n\
         may_cite = []\n",
        "environments = []\n",
        "policies = [\n\
         { owner = \"DEMO\", policy = \"labels.mints-well-formed\" },\n\
         { owner = \"DEMO\", policy = \"profile.tests-conform\" },\n\
         { owner = \"DEMO\", policy = \"profile.constants-conform\" },\n\
         { owner = \"DEMO\", policy = \"projection.test-indexes-current\" },\n\
         { owner = \"DEMO\", policy = \"projection.test-matrices-current\" },\n\
         { owner = \"DEMO\", policy = \"projection.constant-pins-current\" },\n\
         ]\n",
        "[DEMO.\"labels.mints-well-formed\"]\nallowances = []\n\n\
         [DEMO.\"profile.tests-conform\"]\nallowances = []\n\n\
         [DEMO.\"profile.constants-conform\"]\nallowances = []\n\n\
         [DEMO.\"projection.test-indexes-current\"]\nallowances = []\n\n\
         [DEMO.\"projection.test-matrices-current\"]\nallowances = []\n\n\
         [DEMO.\"projection.constant-pins-current\"]\nallowances = []\n",
    );
    write(
        root.path(),
        ".linter/policy-owner-names.toml",
        "namespace = \"class.linter.policy.owner.names\"\n\
         version = [1, 0, 0]\n\n\
         [set.name-prefix-ignore]\n\
         example = \"example-\"\n",
    );
    track(root.path());
    root
}

/// A check over this deliberately undeclared fixture refuses before findings
/// can be ordered.
///
/// ´claim:harness:check-fixes-every-observable-byte´
/// ´test:integration:characterizes-check-bytes´
#[test]
fn characterizes_check_bytes() {
    let root = characterization_prose_fixture();
    let output = observable(root.path(), &["check"]);
    frozen_observable(
        "check",
        &output,
        false,
        1,
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}

/// A corpus finding is reported once because reporting it twice doubles a failure count a reader acts on and names the same repair twice.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed.
///
/// ´claim:cli:the-check-reports-a-corpus-finding-once´
/// ´test:integration:the-check-reports-a-corpus-finding-once´
#[test]
fn the_check_reports_a_corpus_finding_once() {
    let root = tempfile::tempdir().expect("temporary directory");
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
         partitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
         may_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n",
        "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\nversion = [1, 0, 0]\n\nuniverse = \"tracked-exclusive\"\n\nignore = []\n",
    );
    write(root.path(), "README.md", "# Fixture\n");
    track(root.path());
    write(root.path(), "draft.md", "# Draft\n");

    let (code, report) = run(&["check"], root.path());
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(code, Some(3), "{report}");
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["code"], "untracked_path");
    assert_eq!(findings[0]["path"], "draft.md");
    assert_eq!(report["failures"], 1);

    fs::remove_file(root.path().join("draft.md")).expect("remove untracked file");
    let (code, clean) = run(&["check"], root.path());
    assert_eq!(code, Some(0), "{clean}");
    assert_eq!(clean["findings"], serde_json::json!([]));
    assert_eq!(clean["failures"], 0);
}

/// A missing tracked Markdown path draws one corpus finding and no reader
/// failure, so one absent file names one repair; restoring its bytes clears it.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed.
///
/// ´claim:cli:the-check-reports-a-missing-tracked-path-once´
/// ´test:integration:the-check-reports-a-missing-tracked-path-once´
#[test]
fn the_check_reports_a_missing_tracked_path_once() {
    let root = tempfile::tempdir().expect("temporary directory");
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
         partitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
         may_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }]\n",
        "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\nversion = [1, 0, 0]\n\nuniverse = \"tracked-exclusive\"\n\nignore = []\n",
    );
    write(root.path(), "README.md", "# Fixture\n");
    write(root.path(), "notes.md", "# Notes\n");
    track(root.path());
    fs::remove_file(root.path().join("notes.md")).expect("remove tracked file");

    let (code, report) = run(&["check"], root.path());
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(code, Some(3), "{report}");
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["code"], "missing_tracked_path");
    assert_eq!(findings[0]["path"], "notes.md");
    assert_eq!(report["failures"], 1);

    write(root.path(), "notes.md", "# Notes\n");
    let (code, clean) = run(&["check"], root.path());
    assert_eq!(code, Some(0), "{clean}");
    assert_eq!(clean["findings"], serde_json::json!([]));
    assert_eq!(clean["failures"], 0);
}

/// A declared census surface counts both tracked paths before and after one
/// leaves the checkout, while check reports the absent file once without
/// calling the surface vacuous.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked, executed, inspected, or removed.
///
/// ´claim:cli:the-activation-reach-counts-a-missing-tracked-path´
/// ´test:integration:the-activation-reach-counts-a-missing-tracked-path´
#[test]
fn the_activation_reach_counts_a_missing_tracked_path() {
    let root = tempfile::tempdir().expect("temporary directory");
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\n\
         partitions = [{ name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\n\
         may_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        "policies = [{ owner = \"PROJECTA\", policy = \"labels.mints-well-formed\" }, \
         { owner = \"PROJECTA\", policy = \"legacy.section-references\" }]\n",
        "[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n\n\
         [PROJECTA.\"legacy.section-references\"]\npath_counts = []\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"org.example.linter.shape\"\nversion = [1, 0, 0]\n\nuniverse = \"tracked-exclusive\"\n\nignore = []\n",
    );
    write(
        root.path(),
        ".linter/policy-legacy-section-references.toml",
        "namespace = \"class.linter.policy.legacy.section-references\"\nversion = [1, 0, 0]\n\n[owners.PROJECTA]\nprose = '%s\"docs\" [ \"/\" *VCHAR ]'\n",
    );
    write(root.path(), "README.md", "# Fixture\n");
    write(root.path(), "docs/one.md", "# One\n");
    write(root.path(), "docs/two.md", "# Two\n");
    track(root.path());

    let reach = |report: &serde_json::Value| {
        report["configuration"]["activations"]
            .as_array()
            .expect("activation rows")
            .iter()
            .find(|entry| entry["policy"] == "legacy.section-references")
            .expect("census activation")["surface_paths"]
            .clone()
    };

    let (before_code, before) = run(&["check"], root.path());
    assert_eq!(before_code, Some(0), "{before}");
    assert_eq!(reach(&before), 2, "{before}");

    fs::remove_file(root.path().join("docs/two.md")).expect("remove tracked file");
    let (after_code, after) = run(&["check"], root.path());
    let findings = after["findings"].as_array().expect("findings array");
    assert_eq!(after_code, Some(3), "{after}");
    assert_eq!(reach(&after), reach(&before), "{after}");
    assert_eq!(findings.len(), 1, "{after}");
    assert_eq!(findings[0]["code"], "missing_tracked_path");
    assert_eq!(findings[0]["path"], "docs/two.md");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["code"] == "vacuous_surface")
    );
    assert_eq!(after["failures"], 1);
    assert_eq!(after["warnings"], 0);
}

/// Each informational command refuses before dispatch over this deliberately
/// undeclared fixture.
///
/// ´claim:harness:informational-commands-have-independent-byte-oracles´
/// ´test:integration:characterizes-informational-bytes´
#[test]
fn characterizes_informational_bytes() {
    let root = characterization_prose_fixture();

    for (name, arguments) in [
        ("report", &["report"][..]),
        ("coverage", &["coverage"][..]),
        ("shape", &["shape"][..]),
    ] {
        let output = observable(root.path(), arguments);
        frozen_observable(
            name,
            &output,
            false,
            1,
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }
}

/// The burn report fixes its census rows and every surrounding report byte.
///
/// ´claim:harness:burn-fixes-census-rows-and-report-bytes´
/// ´test:integration:characterizes-burn-bytes´
#[test]
fn characterizes_burn_bytes() {
    let root = characterization_census_fixture();
    let output = observable(root.path(), &["burn"]);
    frozen_observable(
        "burn",
        &output,
        true,
        0,
        2586,
        "e4744f86824bde8b1a5245e3df0e7ee52cff65b48199087bb67d1acb9349327a",
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("burn JSON");
    let families = report["families"].as_array().expect("families");
    assert_eq!(families.len(), CENSUS_SURFACES.len());
    assert_eq!(
        families[0]["rows"][0]["path"],
        "packages/project-b/docs/debt.md"
    );
    assert_eq!(families[0]["rows"][0]["count"], 1);
}

/// The control response file and stdout are one frozen byte sequence.
///
/// ´claim:harness:control-response-and-stdout-are-one-byte-sequence´
/// ´test:integration:characterizes-control-bytes´
#[test]
fn characterizes_control_bytes() {
    let root = characterization_census_fixture();
    let request = r#"{"schema":1,"operation":"audit","targets":[{"owner":"PROJECTA","policy":"legacy.section-references-repository","syntax":"path-count","rows":[],"authority":{"authorized_by":"the owner","ruling":"bite 1 characterization","reason":"freeze the control bytes"}}]}"#;

    let output = observable_with_input(
        root.path(),
        &["burn", "--audit", "--output", "response.json"],
        request.as_bytes(),
    );
    frozen_observable(
        "control",
        &output,
        false,
        0,
        615,
        "c8235967e283a87ae3d84576194026b061c0a0c4d400002d35b608f022839f64",
    );
    let response = fs::read(root.path().join("response.json")).expect("control response");
    assert_eq!(output.stdout, response);
    frozen_bytes(
        "control.response",
        &response,
        615,
        "c8235967e283a87ae3d84576194026b061c0a0c4d400002d35b608f022839f64",
    );
}

/// Projection fixes the report and every file the writer owns.
///
/// ´claim:harness:projection-fixes-report-and-generated-file-bytes´
/// ´test:integration:characterizes-projection-bytes´
#[test]
fn characterizes_projection_bytes() {
    let root = characterization_projection_fixture();
    let output = observable(root.path(), &["project", "--write"]);
    frozen_observable(
        "projection",
        &output,
        true,
        0,
        267,
        "2949efc2ac292b94f923613417fccda0b65f6a4316dd6ecaa05d16cf04049ab3",
    );

    for (relative, expected_len, expected_digest) in [
        (
            "packages/demo/src/tests/resonance.rs",
            568,
            "527194c916b8ff543391d3982e1b475112569ef6486b5d7cb46ad4f4bf33aee6",
        ),
        (
            "packages/demo/src/tests/README.md",
            309,
            "ee72112aaccd94989b66c265be8049ad3e8813d16bb8c55378aace38498315c2",
        ),
        (
            "packages/demo/src/maths/README.md",
            118,
            "74737039afad2661c146aa3d4408dfa9c4d526c5668d46a419197f509877bb58",
        ),
    ] {
        let bytes = fs::read(root.path().join(relative)).expect("generated projection");
        frozen_bytes(
            &format!("projection.{}", relative.replace('/', "-")),
            &bytes,
            expected_len,
            expected_digest,
        );
    }
}

/// The project command reports its wall time in the result object, matching the
/// judging commands that decide a corpus verdict.
///
/// # Panics
///
/// Panics only when the temporary fixture cannot be created, written, tracked,
/// executed, or parsed.
///
/// ´claim:cli:the-project-command-reports-elapsed-micros´
/// ´test:integration:the-project-command-reports-elapsed-micros´
#[test]
fn the_project_command_reports_elapsed_micros() {
    let root = characterization_projection_fixture();

    let (code, report) = run(&["project"], root.path());

    assert_eq!(
        code,
        Some(0),
        "the projection can bootstrap without findings: {report}"
    );
    assert_elapsed_micros(&report);
}

/// Assembly fixes both its report and the generated publication.
///
/// ´claim:harness:assembly-fixes-report-and-publication-bytes´
/// ´test:integration:characterizes-assembly-bytes´
#[test]
fn characterizes_assembly_bytes() {
    let root = tempfile::tempdir().expect("temporary directory");
    spec_fixture(root.path());
    track(root.path());

    let output = observable(root.path(), &["assemble", "--write"]);
    frozen_observable(
        "assembly",
        &output,
        true,
        0,
        291,
        "0500995d583f2c28dd0c00f392ce540510c222940db77a65ce953fe7bd875f89",
    );
    let publication = fs::read(root.path().join(SPEC_TARGET)).expect("assembled publication");
    frozen_bytes(
        "assembly.publication",
        &publication,
        340,
        "0f6a441935116f71ed010e0905682e94ed97853c6b3747d4648d851416b66d7b",
    );
}

/// Both fix profiles refuse before writing over deliberately undeclared
/// fixtures, freezing the refusal and the untouched sources.
///
/// ´claim:harness:fix-profiles-freeze-report-and-source-bytes´
/// ´test:integration:characterizes-fix-bytes´
#[test]
fn characterizes_fix_bytes() {
    let tests = tempfile::tempdir().expect("temporary directory");
    fixture_workspace(tests.path());
    track(tests.path());
    let test_output = observable(
        tests.path(),
        &["fix", "--profile", "test", "--write", "--allow-dirty"],
    );
    frozen_observable(
        "fix-test",
        &test_output,
        false,
        1,
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    for (relative, expected_len, expected_digest) in [
        (
            "src/lib.rs",
            82,
            "c2409ca5eca55ce77741376390328424d5f17546e2c2ab419f496dd38132948e",
        ),
        (
            "src/tests/mod.rs",
            68,
            "c42c104d924cf994a51d33764ddd86ff30881b50874ebf009cf097bc6689551f",
        ),
    ] {
        let bytes = fs::read(tests.path().join(relative)).expect("test profile output");
        frozen_bytes(
            &format!("fix-test.{}", relative.replace('/', "-")),
            &bytes,
            expected_len,
            expected_digest,
        );
    }

    let todos = tempfile::tempdir().expect("temporary directory");
    notice_workspace(todos.path());
    track(todos.path());
    let todo_output = observable(
        todos.path(),
        &["fix", "--profile", "todo", "--write", "--allow-dirty"],
    );
    frozen_observable(
        "fix-todo",
        &todo_output,
        false,
        1,
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    for (relative, expected_len, expected_digest) in [
        (
            "src/lib.rs",
            169,
            "7ea1704b5a2a094e27f646d562400ff652e17f03b85c091e8968188712cebfe8",
        ),
        (
            "src/tests/mod.rs",
            60,
            "abb3e4adc0ddf74d995de2335c31f840e0460037a9f5a79226d24f32955f603a",
        ),
    ] {
        let bytes = fs::read(todos.path().join(relative)).expect("todo profile output");
        frozen_bytes(
            &format!("fix-todo.{}", relative.replace('/', "-")),
            &bytes,
            expected_len,
            expected_digest,
        );
    }
}

/// The executable protocol preserves citations before the first mint and exposes no document text.
///
/// # Panics
/// Panics only if fixture IO fails or the command violates its versioned protocol.
/// ´claim:cli:citation-sites-preserve-resolved-addresses´
/// ´test:integration:citation-sites-preserve-resolved-addresses´
#[test]
fn citation_sites_preserve_resolved_addresses() {
    let root = tempfile::tempdir().expect("fixture");
    write(
        root.path(),
        "adr/fixture.md",
        "(`sec:fixture:one`)\n\n## One · `sec:fixture:one`\n",
    );
    ensure_fixture_surface(root.path());
    track(root.path());
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["citation-sites", "--root"])
        .arg(root.path())
        .output()
        .expect("citation sites");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("protocol");
    assert_eq!(
        report,
        serde_json::json!({
            "namespace":"class.linter.citation-sites", "version":[1,0,0],
            "sites":[{"citing_path":"adr/fixture.md", "target_path":"adr/fixture.md",
                      "surface":"document", "label":"sec:fixture:one", "owner":"PROJECTA", "path_class":null}]
        })
    );
}

/// Nested containment ignores untracked files but refuses tracked foreign ownership.
///
/// # Panics
/// Panics only if fixture IO fails or the binary violates the containment contract.
///
/// ´claim:cli:nested-root-containment-uses-tracked-paths´
/// ´test:integration:nested-root-containment-uses-tracked-paths´
#[test]
fn nested_root_containment_uses_tracked_paths() {
    let root = build_mode_fixture("## One · `sec:fixture:one`\n");
    declare(
        &root.path().join("nested"),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{ name = \"all\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        FIXTURE_ENVIRONMENTS,
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    declare(
        root.path(),
        "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"PROJECTB\"]\npartitions = [{ name = \"project-a\", owner = \"PROJECTA\", pattern = '( %s\".linter/\" / %s\"adr/\" / %s\"nested/.linter/\" ) *VCHAR / %s\".gitignore\"' }, { name = \"scratch\", owner = \"PROJECTB\", pattern = '%s\"nested/scratch/\" *VCHAR' }]\nmay_cite = []\nnested = [{ owner = \"PROJECTA\", root = \"nested\", reason = \"Checked independently\" }]\n",
        FIXTURE_ENVIRONMENTS,
        DECLARED_POLICIES,
        DECLARED_LISTS,
    );
    write(root.path(), ".gitignore", "nested/scratch/\n");
    track(root.path());
    write(root.path(), "nested/scratch/editor.tmp", "untracked\n");
    let output = programme_command(root.path(), &["report"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    track(root.path());
    assert_programme_refusal(
        root.path(),
        "nested[1] (owner PROJECTA, root nested): root must be a normalized relative directory inside the owner's partitions",
    );
}

/// Rewriting catalogued lists preserves an intervening deferred table's bytes and position.
///
/// # Panics
/// Panics only if fixture IO fails or a rewrite changes opaque source.
///
/// ´claim:cli:deferred-list-rewrite-preserves-bytes-and-order´
/// ´test:integration:deferred-list-rewrite-preserves-bytes-and-order´
#[test]
fn deferred_list_rewrite_preserves_bytes_and_order() {
    let root = programme_fixture(LOCAL_POLICY, Some(LOCAL_PROGRAMME), "allowances = []");
    let owners = root.path().join(".linter/owners.toml");
    let text = fs::read_to_string(&owners).expect("owners");
    fs::write(
        &owners,
        text.replace(
            "owners = [\"PROJECTA\"]",
            "owners = [\"PROJECTA\", \"PROJECTB\"]",
        ),
    )
    .expect("second owner");
    let policies = root.path().join(".linter/policies.toml");
    let text = fs::read_to_string(&policies).expect("policies");
    fs::write(
        &policies,
        text.replace(
            "policies = [",
            "policies = [{ owner = \"PROJECTB\", policy = \"labels.mints-well-formed\" }, ",
        ),
    )
    .expect("second catalogued policy");
    let deferred = format!(
        "# Repository programme owns the following bytes.\r\n[PROJECTA.'{LOCAL_POLICY}'] # keep this spelling\r\nallowances = [{{ local_identity = '''opaque\n[PROJECTB.\"labels.mints-well-formed\"]\n''', decision = 'kept' }}]\r\n\r\n"
    );
    let lists = format!(
        "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n\n[PROJECTA.\"labels.mints-well-formed\"]\nallowances=[]\n\n{deferred}[PROJECTB.\"labels.mints-well-formed\"]\nallowances=[]\n"
    );
    let path = root.path().join(".linter/lists.toml");
    fs::write(&path, &lists).expect("interleaved lists");
    let output = programme_command(root.path(), &["burn", "--write"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rewritten = fs::read_to_string(&path).expect("rewritten lists");
    assert_eq!(rewritten, lists.replace("allowances=[]", "allowances = []"));
    assert!(rewritten.contains(&deferred));
    let inline = lists
        .replace(
            "[PROJECTA.\"labels.mints-well-formed\"]\nallowances=[]",
            "[PROJECTA]\n\"labels.mints-well-formed\" = { allowances=[] }",
        )
        .replace(
            "[PROJECTB.\"labels.mints-well-formed\"]\nallowances=[]",
            "[PROJECTB]\n\"labels.mints-well-formed\" = { allowances=[] }",
        );
    fs::write(&path, &inline).expect("inline catalogued lists");
    let output = programme_command(root.path(), &["burn", "--write"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&path).expect("rewritten inline lists"),
        inline.replace("allowances=[]", "allowances = []")
    );
}

/// A programme outside Git names its row and its tracked-directory requirement.
///
/// # Panics
/// Panics only if fixture IO fails or the refusal loses its feature context.
///
/// ´claim:cli:programme-outside-checkout-names-tracked-directory-requirement´
/// ´test:integration:programme-outside-checkout-names-tracked-directory-requirement´
#[test]
fn programme_outside_checkout_names_tracked_directory_requirement() {
    let root = programme_fixture(LOCAL_POLICY, Some(LOCAL_PROGRAMME), "allowances = []");
    fs::remove_dir_all(root.path().join(".git")).expect("remove checkout metadata");
    let output = programme_command(root.path(), &["check", "--text"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, [] as [u8; 0]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "PROJECTA : {LOCAL_POLICY}: programme package \"packages/local-lint\": cannot enumerate the repository's tracked paths required by the tracked-directory check"
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("public-set"), "{stderr}");
}

fn programme_command(root: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .env("RUST_LOG", "info")
        .args(arguments)
        .arg("--root")
        .arg(root)
        .output()
        .expect("run programme fixture")
}
