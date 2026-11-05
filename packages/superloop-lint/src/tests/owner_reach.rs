// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Owner reach, dependency topology, and imported-citation tests.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`does_not_report_owners_without_markdown`] | layers | Owners with no Markdown need no prose activation, even when they own other files. # Panics Panics only if fixture IO or planning fails, or a no-prose owner is reported. |
//! | [`nested_prose_retains_other_policy_coverage`] | layers | Nested prose is exempt only under its declared root and remains in the burn census. # Panics Panics only if fixture IO or planning fails, or the measured scope differs. |
//! | [`refuses_invalid_nested_corpus_declarations`] | layers | A nested declaration must name an owner, a contained directory, a snapshot and a reason. # Panics Panics only if fixture IO fails or a malformed nested declaration is accepted. |
//! | [`reports_every_kind_of_inactive_prose_owner`] | layers | Root, crate-bearing, and crateless owners must activate their Markdown prose. # Panics Panics only if fixture IO or planning fails, or the activation finding differs. |
//! | [`explains_inactive_prose_and_clears_it_on_activation`] | layers | Activating prose restores its mints; an inactive owner without Markdown is harmless. # Panics Panics only if fixture IO or planning fails, or resolution differs from the contract. |
//! | [`resolves_a_prefixed_crateless_owner_before_checking_reach`] | layers | A rendered crateless mint resolves before its declared reach is checked. # Panics Panics only if fixture IO, planning, resolution, or reach differs from the contract. |
//! | [`derives_reach_from_every_dependency_table`] | layers | Reach is read from the manifests and from all three dependency tables — ordinary, development and build — so a dependency declared for tests warrants a citation exactly as one declared for the build does. A `path` key outside a dependency table, such as a library target's, declares no edge. |
//! | [`derives_an_inherited_workspace_path_dependency`] | layers | A member dependency inherited from the workspace derives the edge carried by the root workspace dependency's path. |
//! | [`derives_no_edge_from_an_inherited_dependency_without_a_path`] | layers | A member dependency inherited from a non-path workspace dependency derives no reach edge. |
//! | [`continues_to_derive_a_literal_member_path_dependency`] | layers | A literal path in a member dependency table continues to derive its edge without workspace inheritance. |
//! | [`reach_is_reflexive_and_not_transitive`] | layers | Reach is one declared hop: a corpus reaches itself, reaches what its manifest names, and reaches nothing two hops away. Closing the relation would license imports nobody wrote down. |
//! | [`admits_an_upward_import_from_any_member`] | layers | A member importing a root head is admitted whether or not its manifest names the root crate, because repo-wide policy must be citable by everyone it binds. |
//! | [`admits_an_import_along_a_declared_dependency_edge`] | layers | A package importing a head of a package its manifest depends on is admitted: the warrant is the declared edge, and the law enforces structure rather than denying it. |
//! | [`generated_imports_obey_reach`] | layers | A generated imported citation is judged by the same reach relation as an authored one: without the manifest edge the layer pass refuses the matrix row, and adding the edge repairs the fixture without changing the law. |
//! | [`a_generated_import_instantiates_its_cited_owner_prerequisite`] | depend | A generated imported citation enters the cited-owner relation and therefore instantiates the dependency pair of the owner it names, carrying the register row as the first requiring location. |
//! | [`refuses_a_sideways_import_across_no_edge`] | layers | A package importing a head of a package neither manifest names is refused, naming the citing location, the cited prefix, and the manifest edge whose absence refuses it. |
//! | [`refuses_a_package_import_in_the_root_corpus_prose`] | layers | Repo-wide policy imports no package: the root corpus's prose carrying an import of a package prefix is refused even where the root's manifest reaches that package, because the rule is about the prose rather than about the crate. |
//! | [`admits_an_imported_owner_in_the_root_corpus_prose_along_a_declared_row`] | layers | The root corpus's prose may cite an imported owner's published label when an explicit may-cite row takes on that owner; the registry resolves the citation and reach admits it. # Panics Panics only if the temporary fixture cannot be created, written, loaded, or its imported citation does not resolve and reach its declared owner. |
//! | [`refuses_an_unreached_imported_owner_in_the_root_corpus_prose`] | layers | Without a declared row, the same resolved root-prose citation of an imported owner raises an unreached-import finding, not a policy import. The declared root identity is PROJECTA; the undeclared index identity does not replace the declaration in the finding. # Panics Panics only if the temporary fixture cannot be created, written, loaded, or its imported citation does not raise the expected reach finding. |
//! | [`admits_a_reached_package_import_in_the_root_corpus_code`] | layers | The narrow converse is narrow: the root crate's own commentary may import a package it declares a dependency on, because what the rule closes is policy resting on a private premise, not the crate's code resting on its dependencies. |
//! | [`refuses_an_import_of_a_registered_but_absent_owner`] | layers | A prefix registered against no workspace member is reachable by nobody: no manifest can declare a dependency on a crate the workspace does not build, so an import naming it is refused like any other unreached one. |
//! | [`sees_nothing_at_a_displayed_import`] | layers | A displayed import commits nothing: an import form standing in a fenced block or a double-backtick span never reaches this pass, so a record may exhibit a violating label as evidence without committing one. |
//! | [`reports_a_declared_row_set_that_diverges`] | layers | A declared may-cite row set disagreeing with the manifests fails, naming the owner and both sets, so the declaration is checked rather than believed. |
//! | [`reconciles_structural_root_without_declared_rows`] | layers | Reconciliation supplies self and the crate-bearing root without rows; owners with no remaining manifest edges are complete without a source row. |
//! | [`reports_a_member_the_declaration_heads_no_row_for`] | layers | A crate-bearing owner with a non-structural manifest edge and no source row fails as an omission; supplying self and root must not hide the edge. |
//! | [`passes_over_an_owner_the_workspace_builds_no_member_for`] | layers | A registered owner with no workspace member may declare reach with no manifest edge behind it, so its rows are passed over rather than reported: the registration is the fact and the crate is merely not present yet. |
//! | [`reconciles_nothing_where_the_surface_declares_no_reach`] | layers | A surface declaring no may-cite row at all is dormant rather than divergent: the reach rules still hold, and the reconciliation reports nothing about a relation nobody stated. |
//! | [`derives_no_edge_for_a_package_the_workspace_does_not_build`] | layers | cites (´claim:layers:an-absent-owner-is-reachable-by-nobody´) |
//! | [`keeps_an_edgeless_corpus_in_the_relation`] | layers | cites (´claim:layers:reach-is-one-declared-hop´) |

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::adoption::{Adoption, Owner, index_adoption as build_index_adoption};
use crate::carrier::index_carrier;
use crate::code::{CodeSurface, take_code_citations};
use crate::depend::{cited_edges, retiring_verify};
use crate::engine::analyze;
use crate::finding::Finding;
use crate::layers::{derive_reach, verify_layers};
use crate::snapshot::{Pair, ReachRow};

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

fn packages(root: &Path) -> Vec<crate::workspace::Package> {
    crate::plan::WorkspacePlan::compile(root)
        .packages()
        .to_vec()
}

fn owner(name: &str) -> Owner {
    Owner::new(name)
}

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("a parent")).expect("create");
    fs::write(path, text).expect("write");
}

/// A fixture workspace of a root and three packages.
///
/// The edges are the ones the cases below need and no more: the root
/// depends on alpha ordinarily, alpha on beta for its tests alone, and
/// gamma on nobody. Beta declares a library target path, which is a `path`
/// key standing outside every dependency table and must declare no edge.
fn workspace(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[workspace]\n\
             members = [\".\", \"packages/alpha\", \"packages/beta\", \"packages/gamma\"]\n\n\
             [package]\nname = \"example-project-a\"\n\n\
             [dependencies]\nexample-alpha = { path = \"packages/alpha\" }\n",
    );
    write(
        root,
        "packages/alpha/Cargo.toml",
        "[package]\nname = \"example-alpha\"\n\n\
             [dev-dependencies]\nexample-beta = { path = \"../beta\" }\n",
    );
    write(
        root,
        "packages/beta/Cargo.toml",
        "[package]\nname = \"example-beta\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    );
    write(
        root,
        "packages/gamma/Cargo.toml",
        "[package]\nname = \"example-gamma\"\n",
    );
}

/// The four heads the citations below reach, one per corpus.
fn heads(root: &Path) {
    write(
        root,
        "adr/policy.md",
        "# Policy\n\n## Policy · `sec:root:policy`\n\nRepo-wide.\n",
    );
    write(
        root,
        "packages/alpha/docs/head.md",
        "# Alpha\n\n## Alpha · `sec:alpha:thing`\n\nA head.\n",
    );
    write(
        root,
        "packages/beta/docs/head.md",
        "# Beta\n\n## Beta · `sec:beta:thing`\n\nA head.\n",
    );
    write(
        root,
        "packages/gamma/docs/head.md",
        "# Gamma\n\n## Gamma · `sec:gamma:thing`\n\nA head.\n",
    );
}

/// Write one generated matrix row importing beta's head from a package.
fn generated_beta_import(root: &Path, package: &str) {
    let path = format!("packages/{package}/src/tests/README.md");
    let text = format!(
        "## Crate test matrix · `tab:{package}:crate-test-matrix`\n\n\
         **Table (Crate test matrix)**\n\n\
         |Test|Area|Claim|\n|----|----|-----|\n\
         |(`[BETA-sec:beta:thing]`)|fixture|A generated import.|\n"
    );

    write(root, &path, &text);
}

fn corpus(root: &Path) -> crate::plan::CorpusPlan {
    crate::plan::CorpusPlan::compile(root, crate::universe::UniverseKind::AsWritten, &[])
}

/// Run the whole check path over a fixture root and keep the layer verdicts.
fn judge(root: &Path) -> (Vec<Finding>, crate::LayerAnalysis) {
    let packages = packages(root);
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let (sources, _carrier) = index_carrier(root, &corpus(root)).read();
    let analysis = analyze(&adoption, &sources, &CodeSurface::default());
    let (counts, findings) = verify_layers(root, &packages, &adoption, &analysis, &[]);

    (findings, counts)
}

/// The same, over a surface stating the given may-cite rows.
///
/// The reconciliation cases state the relation whole — self, upward and
/// manifest rows alike — because that is what the owner file writes and
/// therefore what the check compares.
fn judge_declaring(root: &Path, rows: &[(&str, &str)]) -> (Vec<Finding>, crate::LayerAnalysis) {
    let declared: Vec<ReachRow> = rows
        .iter()
        .map(|(owner, target)| ReachRow {
            owner: (*owner).to_owned(),
            target: (*target).to_owned(),
        })
        .collect();

    let packages = packages(root);
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let (sources, _carrier) = index_carrier(root, &corpus(root)).read();
    let analysis = analyze(&adoption, &sources, &CodeSurface::default());
    let (counts, findings) = verify_layers(root, &packages, &adoption, &analysis, &declared);

    (findings, counts)
}

/// The same, with the code surface read too, for the cases about the
/// crate's own commentary.
fn judge_with_code(root: &Path) -> (Vec<Finding>, crate::LayerAnalysis) {
    let packages = packages(root);
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let corpus = corpus(root);
    let (citations, _code_findings) = take_code_citations(root, &packages, &[], &corpus);
    let code = CodeSurface::default().with_citations(citations);
    let (sources, _carrier) = index_carrier(root, &corpus).read();
    let analysis = analyze(&adoption, &sources, &code);
    let (counts, findings) = verify_layers(root, &packages, &adoption, &analysis, &[]);

    (findings, counts)
}

/// Every finding the whole engine raised, for the assertions about what the
/// layer law leaves alone.
fn engine_codes(root: &Path) -> Vec<&'static str> {
    let packages = packages(root);
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let (sources, _carrier) = index_carrier(root, &corpus(root)).read();

    analyze(&adoption, &sources, &CodeSurface::default())
        .findings()
        .iter()
        .map(Finding::code)
        .collect()
}

fn codes(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().map(Finding::code).collect()
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    workspace(root.path());
    heads(root.path());

    root
}

fn imported_root_fixture(declare_row: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\".\"]\n[package]\nname = \"root-crate\"\nversion = \"0.1.0\"\n",
    );
    let may_cite = if declare_row {
        "may_cite = [{ owner = \"PROJECTA\", target = \"GENERIC\" }]"
    } else {
        "may_cite = []"
    };
    write(
        root.path(),
        ".linter/owners.toml",
        &format!(
            "namespace = \"example.linter.owners\"\nversion = [1, 0, 0]\n\n\
             root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\", \"GENERIC\"]\n\
             imports = [{{ owner = \"GENERIC\", registry = \".linter/imports/generic.toml\" }}]\n\
             partitions = [{{ name = \"root\", owner = \"PROJECTA\", pattern = '*VCHAR' }}]\n\
             {may_cite}\n"
        ),
    );
    write(
        root.path(),
        ".linter/environments.toml",
        "namespace = \"example.linter.environments\"\nversion = [1, 0, 0]\n\n\
         environments = [{ environment = \"Section\", kind = \"sec\" }]\n\
         extensions = []\nreserved_kinds = []\nreserved_extensions = []\n",
    );
    write(
        root.path(),
        ".linter/policies.toml",
        "namespace = \"example.linter.policies\"\nversion = [1, 0, 0]\n\npolicies = []\n",
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n",
    );
    write(
        root.path(),
        ".linter/shape.toml",
        "namespace = \"example.linter.shape\"\nversion = [1, 0, 0]\n\n\
         universe = \"as-written\"\nignore = []\n",
    );
    write(
        root.path(),
        ".linter/imports/generic.toml",
        "namespace = \"class.linter.labels\"\nversion = [1, 0, 0]\n\
         labels = [{ label = \"sec:generic:policy\", head = \"Policy\", kind = \"sec\", file = \"docs/policy.md\" }]\n\n\
         [source]\nowner = \"GENERIC\"\ncommit = \"unknown\"\n\n\
         [kinds]\nenvironments = [{ environment = \"Section\", kind = \"sec\" }]\n\
         extensions = []\nreserved = []\nreserved_extensions = []\n",
    );
    write(
        root.path(),
        "adr/cites.md",
        "# Root prose\n\nSee (`[GENERIC-sec:generic:policy]`).\n",
    );
    root
}

fn judge_imported_root(root: &Path) -> (Vec<Finding>, crate::LayerAnalysis, Vec<&'static str>) {
    let loaded = crate::snapshot::configuration(root);
    let snapshot = loaded.snapshot().expect("imported declaration snapshot");
    let packages = packages(root);
    assert_eq!(packages.len(), 1, "the declared root is crate-bearing");
    let adoption = index_adoption(&packages, None, &[])
        .with_declared_owners(snapshot.owners(), Some("PROJECTA"))
        .with_imported(snapshot.imports());
    let (sources, _carrier) = index_carrier(root, &corpus(root)).read();
    let analysis = analyze(&adoption, &sources, &CodeSurface::default());
    assert!(
        crate::depend::cited_edges(&adoption, &analysis).is_empty(),
        "validated external registries require no local activation"
    );
    let engine_codes = analysis.findings().iter().map(Finding::code).collect();
    let (counts, findings) =
        verify_layers(root, &packages, &adoption, &analysis, snapshot.may_cite());
    (findings, counts, engine_codes)
}

fn fixture_reach(root: &Path) -> crate::layers::Reach {
    let packages = packages(root);
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );

    derive_reach(root, &packages, &adoption)
}

fn crateless_owner_fixture(declare_row: bool) -> tempfile::TempDir {
    let root = imported_root_fixture(false);
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/cas\"]\n",
    );
    write(
        root.path(),
        "crates/cas/Cargo.toml",
        "[package]\nname = \"cas\"\nversion = \"0.1.0\"\n",
    );
    let row = if declare_row {
        "{ owner = \"CAS\", target = \"DOCS\" }"
    } else {
        ""
    };
    write(
        root.path(),
        ".linter/owners.toml",
        &format!(
            r#"namespace = "example.linter.owners"
version = [1, 0, 0]
root_owner = "PROJECTA"
owners = ["PROJECTA", "CAS", "DOCS"]
partitions = [
  {{ name = "config", owner = "PROJECTA", pattern = '%s".linter/" *VCHAR' }},
  {{ name = "manifest", owner = "PROJECTA", pattern = '%s"Cargo.toml"' }},
  {{ name = "root-prose", owner = "PROJECTA", pattern = '%s"adr/" *VCHAR' }},
  {{ name = "cas", owner = "CAS", pattern = '%s"crates/cas/" *VCHAR' }},
  {{ name = "docs", owner = "DOCS", pattern = '%s"docs/" *VCHAR' }},
  {{ name = "templates", owner = "DOCS", pattern = '%s"templates/docs/" *VCHAR' }},
]
may_cite = [{row}]
"#
        ),
    );
    write(
        root.path(),
        ".linter/policies.toml",
        r#"namespace = "example.linter.policies"
version = [1, 0, 0]
policies = [
  { owner = "CAS", policy = "labels.mints-well-formed" },
  { owner = "DOCS", policy = "labels.mints-well-formed" },
]
"#,
    );
    write(
        root.path(),
        ".linter/lists.toml",
        "namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n[CAS.\"labels.mints-well-formed\"]\nallowances = []\n[DOCS.\"labels.mints-well-formed\"]\nallowances = []\n",
    );
    write(
        root.path(),
        ".linter/environments.toml",
        "namespace = \"example.linter.environments\"\nversion = [1, 0, 0]\nenvironments = [{ environment = \"Definition\", kind = \"def\" }]\nextensions = []\nreserved_kinds = []\nreserved_extensions = []\n",
    );
    let head = "**Definition (Reuse)** · `def:nrz:reuse-lemma`\n";
    write(root.path(), "docs/design/reuse-concept.md", head);
    write(
        root.path(),
        "templates/docs/design/reuse-concept.md.j2",
        head,
    );
    write(
        root.path(),
        "crates/cas/README.md",
        "See (`[DOCS-def:nrz:reuse-lemma]`).\n",
    );
    root
}

/// Owners with no Markdown need no prose activation, even when they own other files.
///
/// # Panics
/// Panics only if fixture IO or planning fails, or a no-prose owner is reported.
///
/// ´claim:layers:owners-without-markdown-need-no-prose-activation´
/// ´test:crate:does-not-report-owners-without-markdown´
#[test]
fn does_not_report_owners_without_markdown() {
    let root = crateless_owner_fixture(true);
    for path in [
        "adr/cites.md",
        "crates/cas/README.md",
        "docs/design/reuse-concept.md",
    ] {
        fs::remove_file(root.path().join(path)).expect("remove Markdown");
    }
    write(root.path(), "docs/guide.txt", "A non-Markdown document.\n");
    activate_prose(root.path(), &[]);
    let plan = crate::plan::ExecutionPlan::compile(
        root.path(),
        crate::snapshot::configuration(root.path()),
    )
    .expect("no-prose plan");
    assert!(plan.labels().adoption().inactive_prose().is_empty());
    let (_, findings) = crate::application::verify_configuration_with_plan(&plan, &[]);
    assert!(
        !findings
            .iter()
            .any(|finding| matches!(finding, Finding::InactiveProseOwner { .. })),
        "{findings:?}"
    );
}

fn nested_fixture() -> tempfile::TempDir {
    let root = crateless_owner_fixture(true);
    for file in ["owners", "environments", "policies", "lists", "shape"] {
        let text = fs::read_to_string(root.path().join(format!(".linter/{file}.toml")))
            .expect("fixture declaration");
        write(
            root.path(),
            &format!("docs/design/.linter/{file}.toml"),
            &text,
        );
    }
    activate_prose(root.path(), &["CAS", "PROJECTA"]);
    crate::test_support::initialise_and_track(root.path());
    root
}

fn declare_nested(root: &Path, owner: &str, nested_root: &str, reason: &str) {
    let path = root.join(".linter/owners.toml");
    let mut text = fs::read_to_string(&path).expect("owners");
    writeln!(
        text,
        "nested = [{{ owner = {owner:?}, root = {nested_root:?}, reason = {reason:?} }}]"
    )
    .expect("write to string");
    fs::write(path, text).expect("nested declaration");
}

/// Nested prose is exempt only under its declared root and remains in the burn census.
///
/// # Panics
/// Panics only if fixture IO or planning fails, or the measured scope differs.
///
/// ´claim:layers:nested-prose-retains-other-policy-coverage´
/// ´test:crate:nested-prose-retains-other-policy-coverage´
#[test]
fn nested_prose_retains_other_policy_coverage() {
    let root = nested_fixture();
    declare_nested(root.path(), "DOCS", "docs/design", "Checked independently");
    let policies_path = root.path().join(".linter/policies.toml");
    let policies = fs::read_to_string(&policies_path).expect("policies");
    fs::write(
        &policies_path,
        policies.replace(
            "policies = [",
            "policies = [{ owner = \"DOCS\", policy = \"legacy.section-references\" },",
        ),
    )
    .expect("activate burn");
    let lists_path = root.path().join(".linter/lists.toml");
    let mut lists = fs::read_to_string(&lists_path).expect("lists");
    lists.push_str("\n[DOCS.\"legacy.section-references\"]\npath_counts = []\n");
    fs::write(lists_path, lists).expect("burn list");
    write(
        root.path(),
        ".linter/policy-legacy-section-references.toml",
        "namespace = \"class.linter.policy.legacy.section-references\"\nversion = [1, 0, 0]\n[owners.DOCS]\nprose = '%s\"docs/design/\" *VCHAR'\n",
    );
    write(
        root.path(),
        "docs/design/reuse-concept.md",
        "See § 12.3 for details.\n",
    );
    for outside in [false, true] {
        if outside {
            write(
                root.path(),
                "docs/design-other.md",
                "Outside the nested corpus.\n",
            );
        }
        let plan = crate::plan::ExecutionPlan::compile(
            root.path(),
            crate::snapshot::configuration(root.path()),
        )
        .expect("nested plan");
        let (counts, findings) = crate::application::verify_configuration_with_plan(&plan, &[]);
        let inactive: Vec<_> = findings
            .iter()
            .filter(|finding| matches!(finding, Finding::InactiveProseOwner { .. }))
            .collect();
        if outside {
            assert!(
                matches!(inactive.as_slice(), [Finding::InactiveProseOwner { owner, sources: 1 }] if owner == "DOCS")
            );
        } else {
            assert!(inactive.is_empty(), "{findings:?}");
        }
        let report = serde_json::to_value(counts).expect("configuration report");
        assert_eq!(
            report["nested"],
            serde_json::json!([{
                "owner": "DOCS", "root": "docs/design", "reason": "Checked independently"
            }])
        );
        let checked = crate::application::check_with_plan(&plan);
        assert!(
            checked
                .findings
                .iter()
                .any(|finding| matches!(finding.finding, Finding::BurnListGrowth { .. })),
            "nested prose remains visible to the burn policy"
        );
    }
}

/// A nested declaration must name an owner, a contained directory, a snapshot and a reason.
///
/// # Panics
/// Panics only if fixture IO fails or a malformed nested declaration is accepted.
///
/// ´claim:layers:nested-corpus-declarations-require-evidence´
/// ´test:crate:refuses-invalid-nested-corpus-declarations´
#[test]
fn refuses_invalid_nested_corpus_declarations() {
    for (owner, path, reason, missing, condition) in [
        (
            "UNKNOWN",
            "docs/design",
            "Checked",
            false,
            "owner is not registered",
        ),
        (
            "DOCS",
            "../docs/design",
            "Checked",
            false,
            "root must be a normalized relative directory inside the owner's partitions",
        ),
        (
            "DOCS",
            "docs//design",
            "Checked",
            false,
            "root must be a normalized relative directory inside the owner's partitions",
        ),
        (
            "CAS",
            "docs/design",
            "Checked",
            false,
            "root must be a normalized relative directory inside the owner's partitions",
        ),
        (
            "DOCS",
            "docs/design",
            "Checked",
            true,
            "root must hold a loadable .linter/ snapshot",
        ),
        (
            "DOCS",
            "docs/design",
            "  ",
            false,
            "reason must not be empty",
        ),
    ] {
        let root = nested_fixture();
        if missing {
            fs::remove_file(root.path().join("docs/design/.linter/policies.toml"))
                .expect("remove snapshot member");
        }
        declare_nested(root.path(), owner, path, reason);
        let loaded = crate::snapshot::configuration(root.path());
        assert!(loaded.snapshot().is_none());
        let messages: Vec<_> = loaded.refusals().iter().map(ToString::to_string).collect();
        assert_eq!(
            messages,
            [format!(
                ".linter/owners.toml: nested[1] (owner {owner}, root {path}): {condition}"
            )]
        );
    }
}

fn activate_prose(root: &Path, owners: &[&str]) {
    let policies = owners
        .iter()
        .map(|owner| format!("{{ owner = \"{owner}\", policy = \"labels.mints-well-formed\" }}"))
        .collect::<Vec<_>>()
        .join(",\n");
    let lists = owners.iter().fold(String::new(), |mut text, owner| {
        writeln!(
            text,
            "[{owner}.\"labels.mints-well-formed\"]\nallowances = []"
        )
        .expect("write to string");
        text
    });
    write(
        root,
        ".linter/policies.toml",
        &format!(
            "namespace = \"example.linter.policies\"\nversion = [1, 0, 0]\npolicies = [{policies}]\n"
        ),
    );
    write(
        root,
        ".linter/lists.toml",
        &format!("namespace = \"class.linter.lists\"\nversion = [1, 0, 0]\n{lists}"),
    );
}

/// Root, crate-bearing, and crateless owners must activate their Markdown prose.
///
/// # Panics
/// Panics only if fixture IO or planning fails, or the activation finding differs.
///
/// ´claim:layers:every-owner-with-markdown-needs-prose-activation´
/// ´test:crate:reports-every-kind-of-inactive-prose-owner´
#[test]
fn reports_every_kind_of_inactive_prose_owner() {
    for inactive in ["DOCS", "CAS", "PROJECTA"] {
        let root = crateless_owner_fixture(true);
        write(root.path(), "docs/second.md", "Another document.\n");
        let active: Vec<_> = ["DOCS", "CAS", "PROJECTA"]
            .into_iter()
            .filter(|owner| *owner != inactive)
            .collect();
        activate_prose(root.path(), &active);
        let plan = crate::plan::ExecutionPlan::compile(
            root.path(),
            crate::snapshot::configuration(root.path()),
        )
        .expect("fixture plan");
        let (_, findings) = crate::application::verify_configuration_with_plan(&plan, &[]);
        let [finding @ Finding::InactiveProseOwner { owner, sources }] = findings.as_slice() else {
            panic!("one inactive prose owner: {findings:?}");
        };
        let count = if inactive == "DOCS" { 2 } else { 1 };
        assert_eq!(owner, inactive);
        assert_eq!(*sources, count, "templates are not Markdown sources");
        assert!(finding.is_failure());
        assert_eq!(finding.code(), "inactive_prose_owner");
        assert_eq!(
            finding.to_string(),
            format!(
                "owner {inactive} has {count} Markdown sources but activates no labels.mints-well-formed row; activate labels.mints-well-formed to harvest and check its prose"
            )
        );
        assert!(!crate::application::check_with_plan(&plan).clean);
    }
}

/// Activating prose restores its mints; an inactive owner without Markdown is harmless.
///
/// # Panics
/// Panics only if fixture IO or planning fails, or resolution differs from the contract.
///
/// ´claim:layers:inactive-prose-explains-only-an-empty-registry´
/// ´test:crate:explains-inactive-prose-and-clears-it-on-activation´
#[test]
fn explains_inactive_prose_and_clears_it_on_activation() {
    let root = crateless_owner_fixture(true);
    write(root.path(), "adr/cites.md", "Root prose.\n");
    for (active, has_markdown) in [(false, true), (true, true), (false, false)] {
        if !has_markdown {
            fs::remove_file(root.path().join("docs/design/reuse-concept.md")).expect("remove mint");
        }
        let owners = if active {
            vec!["CAS", "PROJECTA", "DOCS"]
        } else {
            vec!["CAS", "PROJECTA"]
        };
        activate_prose(root.path(), &owners);
        let plan = crate::plan::ExecutionPlan::compile(
            root.path(),
            crate::snapshot::configuration(root.path()),
        )
        .expect("fixture plan");
        let (_, findings) = crate::application::verify_configuration_with_plan(&plan, &[]);
        assert_eq!(
            findings.len(),
            usize::from(!active && has_markdown),
            "{findings:?}"
        );
        let (sources, _) = plan.labels().read(root.path());
        let analysis = analyze(plan.labels().adoption(), &sources, &CodeSurface::default());
        if active {
            assert!(analysis.findings().is_empty(), "{:?}", analysis.findings());
            assert_eq!(analysis.citations_resolved(), 1);
        } else {
            let [finding @ Finding::UnresolvedCitation { .. }] = analysis.findings() else {
                panic!("one unresolved import: {:?}", analysis.findings());
            };
            let cause = if has_markdown {
                "; owner DOCS activates no labels.mints-well-formed row, so none of its mints are harvested"
            } else {
                ""
            };
            assert!(finding.to_string().ends_with(&format!(
                "citation of def:nrz:reuse-lemma resolves nowhere in owner DOCS, whose prefix DOCS the citation names{cause}"
            )));
        }
    }
}

/// A rendered crateless mint resolves before its declared reach is checked.
///
/// # Panics
/// Panics only if fixture IO, planning, resolution, or reach differs from the contract.
///
/// ´claim:layers:crateless-mints-resolve-before-reach´
/// ´test:crate:resolves-a-prefixed-crateless-owner-before-checking-reach´
#[test]
fn resolves_a_prefixed_crateless_owner_before_checking_reach() {
    for declare_row in [true, false] {
        let root = crateless_owner_fixture(declare_row);
        let plan = crate::plan::ExecutionPlan::compile(
            root.path(),
            crate::snapshot::configuration(root.path()),
        )
        .expect("crateless fixture plan");
        let adoption = plan.labels().adoption();
        let (sources, findings) = plan.labels().read(root.path());
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(sources.len(), 2, "the template is not a second mint");
        assert_eq!(
            adoption.owner_of(Path::new("docs/design/reuse-concept.md")),
            &owner("DOCS")
        );
        let analysis = analyze(adoption, &sources, &CodeSurface::default());
        assert!(analysis.findings().is_empty(), "{:?}", analysis.findings());
        assert_eq!(analysis.mints(), 1);
        assert_eq!(analysis.citations_resolved(), 1);
        let (_, findings) = verify_layers(
            root.path(),
            plan.workspace().packages(),
            adoption,
            &analysis,
            plan.snapshot().may_cite(),
        );
        let expected = if declare_row {
            vec![]
        } else {
            vec!["unreached_import"]
        };
        assert_eq!(codes(&findings), expected, "{findings:?}");
        write(
            root.path(),
            "docs/design/reuse-concept.md",
            "**Definition (Other)** · `def:nrz:other`\n",
        );
        let (sources, _) = plan.labels().read(root.path());
        let analysis = analyze(adoption, &sources, &CodeSurface::default());
        let [finding @ Finding::UnresolvedCitation { .. }] = analysis.findings() else {
            panic!("one missing imported mint: {:?}", analysis.findings());
        };
        assert!(finding.to_string().ends_with(
            "citation of def:nrz:reuse-lemma resolves nowhere in owner DOCS, whose prefix DOCS the citation names"
        ));
    }
}

/// Reach is read from the manifests and from all three dependency tables —
/// ordinary, development and build — so a dependency declared for tests
/// warrants a citation exactly as one declared for the build does. A `path`
/// key outside a dependency table, such as a library target's, declares no
/// edge.
///
/// ´claim:layers:reach-is-read-from-every-dependency-table´
/// ´test:crate:derives-reach-from-every-dependency-table´
#[test]
fn derives_reach_from_every_dependency_table() {
    let root = fixture();
    let packages = packages(root.path());
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let reach = derive_reach(root.path(), &packages, &adoption);

    assert!(
        reach.reaches(&owner("index"), &owner("example-alpha")),
        "an ordinary edge"
    );
    assert!(
        reach.reaches(&owner("example-alpha"), &owner("example-beta")),
        "a development edge reaches exactly as an ordinary one does"
    );
    assert!(
        !reach.reaches(&owner("example-beta"), &owner("example-gamma")),
        "a library target's path declares no dependency"
    );
    assert_eq!(reach.edge_count(), 2, "two declared edges and no more");
}

/// A member dependency inherited from the workspace derives the edge carried
/// by the root workspace dependency's path.
///
/// ´claim:layers:workspace-inheritance-carries-the-root-path-edge´
/// ´test:crate:derives-an-inherited-workspace-path-dependency´
#[test]
fn derives_an_inherited_workspace_path_dependency() {
    let root = fixture();
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\n\
             members = [\".\", \"packages/alpha\", \"packages/beta\", \"packages/gamma\"]\n\n\
             [workspace.dependencies]\nexample-beta = { path = \"packages/beta\" }\n\n\
             [package]\nname = \"example-project-a\"\n\n\
             [dependencies]\nexample-alpha = { path = \"packages/alpha\" }\n",
    );
    write(
        root.path(),
        "packages/alpha/Cargo.toml",
        "[package]\nname = \"example-alpha\"\n\n\
             [dev-dependencies]\nexample-beta = { workspace = true }\n",
    );

    let reach = fixture_reach(root.path());

    assert!(
        reach.reaches(&owner("example-alpha"), &owner("example-beta")),
        "the inherited root path declares the member edge"
    );
    assert_eq!(reach.edge_count(), 2, "the two path edges and no more");
}

/// A member dependency inherited from a non-path workspace dependency derives
/// no reach edge.
///
/// ´claim:layers:workspace-inheritance-of-a-non-path-dependency-carries-no-edge´
/// ´test:crate:derives-no-edge-from-an-inherited-dependency-without-a-path´
#[test]
fn derives_no_edge_from_an_inherited_dependency_without_a_path() {
    let root = fixture();
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\n\
             members = [\".\", \"packages/alpha\", \"packages/beta\", \"packages/gamma\"]\n\n\
             [workspace.dependencies]\nserde = \"1\"\n\n\
             [package]\nname = \"example-project-a\"\n\n\
             [dependencies]\nexample-alpha = { path = \"packages/alpha\" }\n",
    );
    write(
        root.path(),
        "packages/alpha/Cargo.toml",
        "[package]\nname = \"example-alpha\"\n\n\
             [dev-dependencies]\nserde = { workspace = true }\n",
    );

    let reach = fixture_reach(root.path());

    assert!(
        reach.declared(&owner("example-alpha")).is_empty(),
        "an inherited external dependency declares no edge"
    );
    assert_eq!(reach.edge_count(), 1, "only the root's literal path edge");
}

/// A literal path in a member dependency table continues to derive its edge
/// without workspace inheritance.
///
/// ´claim:layers:a-literal-member-path-dependency-still-carries-its-edge´
/// ´test:crate:continues-to-derive-a-literal-member-path-dependency´
#[test]
fn continues_to_derive_a_literal_member_path_dependency() {
    let root = fixture();
    let reach = fixture_reach(root.path());

    assert!(
        reach.reaches(&owner("example-alpha"), &owner("example-beta")),
        "the member's literal path still declares its edge"
    );
    assert_eq!(
        reach.edge_count(),
        2,
        "the two literal path edges and no more"
    );
}

/// Reach is one declared hop: a corpus reaches itself, reaches what its
/// manifest names, and reaches nothing two hops away. Closing the relation
/// would license imports nobody wrote down.
///
/// ´claim:layers:reach-is-one-declared-hop´
/// ´test:crate:reach-is-reflexive-and-not-transitive´
#[test]
fn reach_is_reflexive_and_not_transitive() {
    let root = fixture();
    let packages = packages(root.path());
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let reach = derive_reach(root.path(), &packages, &adoption);

    assert!(
        reach.reaches(&owner("example-gamma"), &owner("example-gamma")),
        "reflexive"
    );
    assert!(
        !reach.reaches(&owner("index"), &owner("example-beta")),
        "root reaches alpha and alpha reaches beta, and root still does not reach beta"
    );
}

/// A member importing a root head is admitted whether or not its manifest
/// names the root crate, because repo-wide policy must be citable by
/// everyone it binds.
///
/// ´claim:layers:an-upward-import-is-admitted-from-any-member´
/// ´test:crate:admits-an-upward-import-from-any-member´
#[test]
fn admits_an_upward_import_from_any_member() {
    let root = fixture();
    write(
        root.path(),
        "packages/gamma/docs/cites.md",
        "# Gamma cites\n\n## Cites · `sec:gamma:cites`\n\nUnder (`[PROJECTA-sec:root:policy]`).\n",
    );

    let (findings, counts) = judge(root.path());

    assert!(
        findings.is_empty(),
        "no manifest edge is wanted upward: {findings:?}"
    );
    assert_eq!(counts.upward_imports, 1);
    assert_eq!(counts.violations, 0);
}

/// A package importing a head of a package its manifest depends on is
/// admitted: the warrant is the declared edge, and the law enforces
/// structure rather than denying it.
///
/// ´claim:layers:an-import-along-a-declared-edge-is-admitted´
/// ´test:crate:admits-an-import-along-a-declared-dependency-edge´
#[test]
fn admits_an_import_along_a_declared_dependency_edge() {
    let root = fixture();
    write(
        root.path(),
        "packages/alpha/docs/cites.md",
        "# Alpha cites\n\n## Cites · `sec:alpha:cites`\n\nSee (`[BETA-sec:beta:thing]`).\n",
    );

    let (findings, counts) = judge(root.path());

    assert!(
        findings.is_empty(),
        "the declared edge warrants it: {findings:?}"
    );
    assert_eq!(counts.sideways_imports, 1);
    assert_eq!(counts.violations, 0);
}

/// A generated imported citation is judged by the same reach relation as an
/// authored one: without the manifest edge the layer pass refuses the matrix
/// row, and adding the edge repairs the fixture without changing the law.
///
/// ´claim:layers:generated-imports-obey-reach´
/// ´test:crate:generated-imports-obey-reach´
#[test]
fn generated_imports_obey_reach() {
    let root = fixture();
    generated_beta_import(root.path(), "alpha");
    write(
        root.path(),
        "packages/alpha/Cargo.toml",
        "[package]\nname = \"example-alpha\"\n",
    );

    let (findings, counts) = judge(root.path());
    let [Finding::UnreachedImport { location, .. }] = findings.as_slice() else {
        panic!("the mutation must fail the reach law: {findings:?}");
    };

    assert_eq!(
        location.path(),
        Path::new("packages/alpha/src/tests/README.md")
    );
    assert_eq!(
        counts.violations, 1,
        "the generated import is the violation"
    );

    write(
        root.path(),
        "packages/alpha/Cargo.toml",
        "[package]\nname = \"example-alpha\"\n\n\
         [dev-dependencies]\nexample-beta = { path = \"../beta\" }\n",
    );

    let (findings, counts) = judge(root.path());

    assert!(
        findings.is_empty(),
        "the fixture-side edge repairs it: {findings:?}"
    );
    assert_eq!(counts.sideways_imports, 1);
    assert_eq!(counts.violations, 0);
}

/// A generated imported citation enters the cited-owner relation and therefore
/// instantiates the dependency pair of the owner it names, carrying the
/// register row as the first requiring location.
///
/// ´claim:depend:a-generated-import-instantiates-its-cited-owner-prerequisite´
/// ´test:crate:a-generated-import-instantiates-its-cited-owner-prerequisite´
#[test]
fn a_generated_import_instantiates_its_cited_owner_prerequisite() {
    let root = fixture();
    generated_beta_import(root.path(), "alpha");
    let packages = packages(root.path());
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let (sources, _carrier) = index_carrier(root.path(), &corpus(root.path())).read();
    let analysis = analyze(&adoption, &sources, &CodeSurface::default());
    let edges = cited_edges(&adoption, &analysis);

    let [edge] = edges.as_slice() else {
        panic!("one generated cited-owner edge: {edges:?}");
    };

    assert_eq!(edge.owner, "example-alpha");
    assert_eq!(edge.target, "example-beta");
    assert_eq!(
        edge.location.path(),
        Path::new("packages/alpha/src/tests/README.md")
    );

    let pairs = vec![
        Pair::singleton("example-alpha", "labels.citations-imported-resolve"),
        Pair::singleton("example-alpha", "labels.citations-import-form"),
        Pair::singleton("example-alpha", "labels.mints-well-formed"),
    ];
    let findings = retiring_verify(&pairs, &edges, Some("index"));
    let [
        Finding::MissingPolicyDependency {
            scope,
            required_owner,
            required_policy,
            location,
            ..
        },
    ] = findings.as_slice()
    else {
        panic!("one dependency instantiated by the generated import: {findings:?}");
    };

    assert_eq!(*scope, "cited-owner");
    assert_eq!(required_owner, "example-beta");
    assert_eq!(required_policy, "labels.mints-unique");
    assert_eq!(
        location.as_ref().map(crate::finding::Location::path),
        Some(Path::new("packages/alpha/src/tests/README.md"))
    );
}

/// A package importing a head of a package neither manifest names is
/// refused, naming the citing location, the cited prefix, and the manifest
/// edge whose absence refuses it.
///
/// ´claim:layers:a-sideways-import-across-no-edge-is-refused´
/// ´test:crate:refuses-a-sideways-import-across-no-edge´
#[test]
fn refuses_a_sideways_import_across_no_edge() {
    let root = fixture();
    write(
        root.path(),
        "packages/gamma/docs/cites.md",
        "# Gamma cites\n\n## Cites · `sec:gamma:cites`\n\nSee (`[BETA-sec:beta:thing]`).\n",
    );

    let (findings, counts) = judge(root.path());

    let [
        Finding::UnreachedImport {
            citing_owner,
            prefix,
            cited_owner,
            absent_edge,
            location,
        },
    ] = findings.as_slice()
    else {
        panic!("one unreached import: {findings:?}");
    };

    assert_eq!(citing_owner, "example-gamma");
    assert_eq!(prefix.as_str(), "BETA");
    assert_eq!(cited_owner, "example-beta");
    assert!(
        absent_edge.contains("packages/gamma/Cargo.toml") && absent_edge.contains("packages/beta"),
        "the absent edge names both ends: {absent_edge}"
    );
    assert_eq!(location.path(), Path::new("packages/gamma/docs/cites.md"));
    assert_eq!(counts.violations, 1);

    // Resolution is untouched: the refused import still reached its mint.
    assert!(
        !engine_codes(root.path()).contains(&"unresolved_citation"),
        "a refused import still resolves"
    );
}

/// Repo-wide policy imports no package: the root corpus's prose carrying an
/// import of a package prefix is refused even where the root's manifest
/// reaches that package, because the rule is about the prose rather than
/// about the crate.
///
/// ´claim:layers:repo-wide-policy-imports-no-package-prefix´
/// ´test:crate:refuses-a-package-import-in-the-root-corpus-prose´
#[test]
fn refuses_a_package_import_in_the_root_corpus_prose() {
    let root = fixture();
    write(
        root.path(),
        "adr/cites.md",
        "# Policy cites\n\n## Cites · `sec:root:cites`\n\nSee (`[ALPHA-sec:alpha:thing]`).\n",
    );

    let (findings, counts) = judge(root.path());

    let [
        Finding::PolicyImport {
            prefix,
            cited_owner,
            ..
        },
    ] = findings.as_slice()
    else {
        panic!("one policy import: {findings:?}");
    };

    assert_eq!(prefix.as_str(), "ALPHA");
    assert_eq!(cited_owner, "example-alpha");
    assert_eq!(counts.downward_imports, 1);
    assert_eq!(counts.violations, 1);
}

/// The root corpus's prose may cite an imported owner's published label when
/// an explicit may-cite row takes on that owner; the registry resolves the
/// citation and reach admits it.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be created, written, loaded,
/// or its imported citation does not resolve and reach its declared owner.
///
/// ´claim:layers:root-prose-reaches-an-imported-owner-by-declaration´
/// ´test:crate:admits-an-imported-owner-in-the-root-corpus-prose-along-a-declared-row´
#[test]
fn admits_an_imported_owner_in_the_root_corpus_prose_along_a_declared_row() {
    let root = imported_root_fixture(true);
    let (findings, counts, engine_codes) = judge_imported_root(root.path());

    assert!(
        findings.is_empty(),
        "declared reach admits it: {findings:?}"
    );
    assert!(
        !engine_codes.contains(&"unresolved_citation"),
        "the imported registry resolves it: {engine_codes:?}"
    );
    assert_eq!(counts.downward_imports, 1);
    assert_eq!(counts.violations, 0);
}

/// Without a declared row, the same resolved root-prose citation of an
/// imported owner raises an unreached-import finding, not a policy import.
/// The declared root identity is PROJECTA; the undeclared index identity does
/// not replace the declaration in the finding.
///
/// # Panics
///
/// Panics only if the temporary fixture cannot be created, written, loaded,
/// or its imported citation does not raise the expected reach finding.
///
/// ´claim:layers:root-prose-needs-a-row-for-an-imported-owner´
/// ´test:crate:refuses-an-unreached-imported-owner-in-the-root-corpus-prose´
#[test]
fn refuses_an_unreached_imported_owner_in_the_root_corpus_prose() {
    let root = imported_root_fixture(false);
    let (findings, counts, engine_codes) = judge_imported_root(root.path());

    let [
        Finding::UnreachedImport {
            citing_owner,
            prefix,
            cited_owner,
            ..
        },
    ] = findings.as_slice()
    else {
        panic!("one unreached import, not a policy import: {findings:?}");
    };
    assert_eq!(citing_owner, "PROJECTA");
    assert_eq!(prefix.as_str(), "GENERIC");
    assert_eq!(cited_owner, "GENERIC");
    assert!(!engine_codes.contains(&"unresolved_citation"));
    assert_eq!(counts.downward_imports, 1);
    assert_eq!(counts.violations, 1);
}

/// The narrow converse is narrow: the root crate's own commentary may
/// import a package it declares a dependency on, because what the rule
/// closes is policy resting on a private premise, not the crate's code
/// resting on its dependencies.
///
/// ´claim:layers:the-root-crate-s-code-is-held-to-reach-like-any-other´
/// ´test:crate:admits-a-reached-package-import-in-the-root-corpus-code´
#[test]
fn admits_a_reached_package_import_in_the_root_corpus_code() {
    let root = fixture();
    // The root reaches alpha and not beta, so the crate's own commentary is
    // admitted for the one and refused for the other — on the reach rule,
    // never on the policy rule, which reads the prose alone.
    write(
        root.path(),
        "src/lib.rs",
        "//! The root crate.\n\
             //!\n\
             //! Reached: (´[ALPHA-sec:alpha:thing]´).\n",
    );

    let (findings, counts) = judge_with_code(root.path());

    assert!(
        findings.is_empty(),
        "the manifest edge warrants it: {findings:?}"
    );
    assert_eq!(
        counts.downward_imports, 1,
        "it is still the downward direction"
    );
    assert_eq!(counts.violations, 0);
}

/// A prefix registered against no workspace member is reachable by nobody:
/// no manifest can declare a dependency on a crate the workspace does not
/// build, so an import naming it is refused like any other unreached one.
///
/// ´claim:layers:an-absent-owner-is-reachable-by-nobody´
/// ´test:crate:refuses-an-import-of-a-registered-but-absent-owner´
#[test]
fn refuses_an_import_of_a_registered_but_absent_owner() {
    let root = fixture();
    // The pending registration owns the prose beneath its directory
    // although the workspace builds no such crate.
    write(
        root.path(),
        "packages/project-c/docs/head.md",
        "# ProjectC\n\n## ProjectC · `sec:projectc:thing`\n\nA head.\n",
    );
    write(
        root.path(),
        "packages/gamma/docs/cites.md",
        "# Gamma cites\n\n## Cites · `sec:gamma:cites`\n\nSee (`[PROJECTC-sec:projectc:thing]`).\n",
    );

    let (findings, _counts) = judge(root.path());

    let [Finding::UnreachedImport { absent_edge, .. }] = findings.as_slice() else {
        panic!("one unreached import: {findings:?}");
    };

    assert!(
        absent_edge.contains("no workspace member"),
        "the answer is that nothing can declare the dependency: {absent_edge}"
    );
}

/// A displayed import commits nothing: an import form standing in a fenced
/// block or a double-backtick span never reaches this pass, so a record may
/// exhibit a violating label as evidence without committing one.
///
/// ´claim:layers:a-displayed-import-commits-nothing´
/// ´test:crate:sees-nothing-at-a-displayed-import´
#[test]
fn sees_nothing_at_a_displayed_import() {
    let root = fixture();
    write(
        root.path(),
        "adr/shows.md",
        "# Policy shows\n\n## Shows · `sec:root:shows`\n\n\
             Shown inert: (``[ALPHA-sec:alpha:thing]``).\n\n\
             ```text\n(`[BETA-sec:beta:thing]`)\n```\n",
    );

    let (findings, counts) = judge(root.path());

    assert!(
        findings.is_empty(),
        "a display is not an import: {findings:?}"
    );
    assert_eq!(
        counts.downward_imports, 0,
        "and it is counted as nothing at all"
    );
}

/// A declared may-cite row set disagreeing with the manifests fails, naming
/// the owner and both sets, so the declaration is checked rather than
/// believed.
///
/// ´claim:layers:a-divergent-declared-row-set-fails´
/// ´test:crate:reports-a-declared-row-set-that-diverges´
#[test]
fn reports_a_declared_row_set_that_diverges() {
    let root = fixture();

    // Every corpus states the whole of what it may cite, and ALPHA states
    // its self and upward rows without the manifest edge its dev-dependency
    // on beta puts there.
    let (findings, _counts) = judge_declaring(
        root.path(),
        &[
            ("PROJECTA", "PROJECTA"),
            ("PROJECTA", "ALPHA"),
            ("ALPHA", "ALPHA"),
            ("ALPHA", "PROJECTA"),
            ("BETA", "BETA"),
            ("BETA", "PROJECTA"),
            ("GAMMA", "GAMMA"),
            ("GAMMA", "PROJECTA"),
        ],
    );

    let [
        Finding::ReachDeclarationDivergence {
            corpus,
            registered,
            derived,
            ..
        },
    ] = findings.as_slice()
    else {
        panic!("one divergence: {findings:?}");
    };

    assert_eq!(corpus, "ALPHA");
    assert_eq!(registered, &["ALPHA".to_owned(), "PROJECTA".to_owned()]);
    assert_eq!(
        derived,
        &["ALPHA".to_owned(), "BETA".to_owned(), "PROJECTA".to_owned()],
        "the manifest's dev-dependency on beta is admissible and unstated"
    );
}

/// Reconciliation supplies self and the crate-bearing root without rows;
/// owners with no remaining manifest edges are complete without a source row.
///
/// ´claim:layers:reconciliation-supplies-structural-reach´
/// ´test:crate:reconciles-structural-root-without-declared-rows´
#[test]
fn reconciles_structural_root_without_declared_rows() {
    let root = fixture();
    let (findings, _) = judge_declaring(root.path(), &[("PROJECTA", "ALPHA"), ("ALPHA", "BETA")]);
    assert!(findings.is_empty(), "{findings:?}");
}

/// A crate-bearing owner with a non-structural manifest edge and no source
/// row fails as an omission; supplying self and root must not hide the edge.
///
/// ´claim:layers:a-member-the-declaration-omits-fails´
/// ´test:crate:reports-a-member-the-declaration-heads-no-row-for´
#[test]
fn reports_a_member_the_declaration_heads_no_row_for() {
    let root = fixture();
    write(
        root.path(),
        "packages/gamma/Cargo.toml",
        r#"[package]
name = "example-gamma"
version = "0.1.0"
[dependencies]
example-alpha = { path = "../alpha" }
"#,
    );

    // GAMMA has a manifest edge to ALPHA and is stated nowhere. The other
    // owners state their whole relation, leaving only that omission.
    let (findings, _counts) = judge_declaring(
        root.path(),
        &[
            ("PROJECTA", "PROJECTA"),
            ("PROJECTA", "ALPHA"),
            ("ALPHA", "ALPHA"),
            ("ALPHA", "PROJECTA"),
            ("ALPHA", "BETA"),
            ("BETA", "BETA"),
            ("BETA", "PROJECTA"),
        ],
    );

    let [Finding::ReachDeclarationOmission { corpus, .. }] = findings.as_slice() else {
        panic!("one omission: {findings:?}");
    };

    assert_eq!(
        corpus, "GAMMA",
        "the workspace builds it and no row heads it"
    );
}

/// A registered owner with no workspace member may declare reach with no
/// manifest edge behind it, so its rows are passed over rather than
/// reported: the registration is the fact and the crate is merely not
/// present yet.
///
/// ´claim:layers:an-unbuilt-owner-may-declare-reach´
/// ´test:crate:passes-over-an-owner-the-workspace-builds-no-member-for´
#[test]
fn passes_over_an_owner_the_workspace_builds_no_member_for() {
    let root = fixture();

    // PROJECTC is registered against a crate the workspace does not build, and
    // states the two rows a present member would state. Nothing derives
    // them and nothing reports them.
    let (findings, counts) = judge_declaring(
        root.path(),
        &[
            ("PROJECTA", "PROJECTA"),
            ("PROJECTA", "ALPHA"),
            ("ALPHA", "ALPHA"),
            ("ALPHA", "PROJECTA"),
            ("ALPHA", "BETA"),
            ("BETA", "BETA"),
            ("BETA", "PROJECTA"),
            ("GAMMA", "GAMMA"),
            ("GAMMA", "PROJECTA"),
            ("PROJECTC", "PROJECTC"),
            ("PROJECTC", "PROJECTA"),
        ],
    );

    assert!(
        findings.is_empty(),
        "the unbuilt owner's rows are its own: {findings:?}"
    );
    assert_eq!(counts.registered_rows, 11, "and every row is still counted");
}

/// A surface declaring no may-cite row at all is dormant rather than
/// divergent: the reach rules still hold, and the reconciliation reports
/// nothing about a relation nobody stated.
///
/// ´claim:layers:an-unstated-relation-is-dormant´
/// ´test:crate:reconciles-nothing-where-the-surface-declares-no-reach´
#[test]
fn reconciles_nothing_where_the_surface_declares_no_reach() {
    let root = fixture();
    write(
        root.path(),
        "packages/gamma/docs/cites.md",
        "# Gamma cites\n\n## Cites · `sec:gamma:cites`\n\nSee (`[BETA-sec:beta:thing]`).\n",
    );

    let (findings, counts) = judge(root.path());

    assert!(counts.register_dormant, "the surface states no reach");
    assert_eq!(counts.registered_rows, 0);
    assert_eq!(
        codes(&findings),
        ["unreached_import"],
        "and the law still bites"
    );
}

/// A member the workspace does not build owns no row and derives no edge,
/// so a package present on disk without a manifest cannot be reached.
///
/// (´claim:layers:an-absent-owner-is-reachable-by-nobody´)
/// ´test:crate:derives-no-edge-for-a-package-the-workspace-does-not-build´
#[test]
fn derives_no_edge_for_a_package_the_workspace_does_not_build() {
    let root = fixture();
    let packages = packages(root.path());
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let reach = derive_reach(root.path(), &packages, &adoption);

    assert!(reach.crate_name_of(&owner("example-project-c")).is_none());
    assert!(!reach.reaches(&owner("example-alpha"), &owner("example-project-c")));
    assert!(
        reach.reaches(&owner("example-project-c"), reach.root()),
        "an absent owner still reaches the root, as every corpus does"
    );
}

/// A fixture package standing outside every declared dependency keeps the
/// derivation total: an owner with no edges is present in the relation with
/// an empty edge set rather than missing from it.
///
/// (´claim:layers:reach-is-one-declared-hop´)
/// ´test:crate:keeps-an-edgeless-corpus-in-the-relation´
#[test]
fn keeps_an_edgeless_corpus_in_the_relation() {
    let root = fixture();
    let packages = packages(root.path());
    let adoption = index_adoption(
        &packages,
        Some(&crate::roster::OwnerNames::new(
            "example-",
            [crate::roster::UnbuiltMember::new(
                "example-project-c",
                "packages/project-c",
            )],
        )),
        &[],
    );
    let reach = derive_reach(root.path(), &packages, &adoption);

    assert_eq!(reach.corpus_count(), 4, "the root and its three packages");
    assert!(reach.declared(&owner("example-gamma")).is_empty());
    assert_eq!(
        reach.crate_name_of(&owner("index")),
        Some("example-project-a")
    );
}
