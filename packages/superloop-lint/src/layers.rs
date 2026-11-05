// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`a_crateless_prefix_requires_its_declared_edge`] | layers | A crate can resolve a crateless owner's prefix, but the cross-owner citation is reached only when the owner surface declares that edge. Without it the verdict is a reach violation, not an unregistered prefix. |
//! | [`a_crateless_source_reaches_by_its_declared_edge`] | layers | A crateless owner may cite a crate through an explicit may-cite row even though its source endpoint has no manifest in which a dependency could stand. The declaration is authoritative for reconciliation and reach. |
//! | [`keeps_crate_bearing_reconciliation_bidirectional`] | layers | Crate-bearing owners continue to reconcile in both directions against manifests: the exact relation passes, a declaration-only edge diverges, and the existing manifest-only divergence case remains covered elsewhere. When an owner covers two crates, both directories resolve as dependency targets and both manifests contribute edges, independent of member order. Removing an edge from either manifest removes that owner's reach. # Panics Panics only if the fixture cannot be written or its reach assertions fail. |
//! | [`an_absent_edge_names_its_manifest_in_the_reversible_display`] | layers | An absent edge names the citing manifest and cited directory in the reversible byte display; a cited owner without a workspace member keeps the crateless explanation. # Panics Panics only if the temporary fixture cannot be created or written, or its citation cannot be read. |

//! The layer owner graph: reach derived from the manifests, and the two
//! owner-layer rules of the citation law.
//!
//! (´[TOOLS-rule:lintcontracts:ownership]´) supplies the half of the calculus that the calculus deliberately
//! left out. The calculus fixes which citations *resolve*
//! (ADR-T-014, A calculus of documentation and source labels) and says nothing about which
//! imports a corpus ought to admit. This module is the enforcement that record
//! requires (´[TOOLS-rule:lintcontracts:ownership]´): it learns the reach relation,
//! reconciles the may-cite rows the owner surface declares against what the
//! manifests say, and reports every import the law refuses.
//!
//! Reach is one declared hop and nothing else
//! (´[TOOLS-rule:lintcontracts:ownership]´): corpus *A* reaches corpus *B* when
//! *A* is *B*, or when *A*'s manifest declares a workspace-path dependency on
//! *B*, in any dependency table. The relation is derived here from the
//! manifests on disk at check time rather than transcribed into this source, so
//! the graph cannot rot apart from the thing it describes — the same discipline
//! the owner partition already keeps (ADR-T-015, The test label profile),
//! and for the same reason.
//!
//! Two rules read that relation, and their asymmetry is the substance of the
//! two-layer picture. Upward is open: every corpus reaches the root's repo-wide
//! policy whether or not a manifest says so
//! (´[TOOLS-rule:lintcontracts:ownership]´), because policy that binds every
//! member must be citable by every member, and no member declares a dependency
//! on the root crate. Downward is closed: the root corpus's prose carries no
//! import of a package prefix at all
//! (´[TOOLS-rule:lintcontracts:ownership]´), even one its manifest
//! reaches, because a common policy with a private premise is not common.
//! Between the packages the manifest decides
//! (´[TOOLS-rule:lintcontracts:ownership]´).
//!
//! # What this pass does not do
//!
//! It reads prefixes only. The cited label's kind, its area, and the file it
//! mints in are the cited corpus's business, and a rule consulting them would
//! be legislating another owner's naming from outside it — the granularity the
//! owner ruled against (´[TOOLS-rule:lintcontracts:ownership]´).
//!
//! It leaves resolution alone. An import this law refuses still resolves, and
//! reporting it as unresolved would be a false statement about the graph
//! (ADR-T-014, A calculus of documentation and source labels). The engine resolves; this module
//! judges admissibility; the two verdicts stand side by side.
//!
//! And it sees only participating occurrences. The imports it reads are the
//! ones the engine held — which is to say the ones that survived the prose
//! scanner's fenced blocks and double-backtick spans, the generated regions,
//! and the documents the migration has not reached
//! (ADR-T-014, A calculus of documentation and source labels). No second recognizer for the bracket
//! form is written here, because a register counting one thing while a gate
//! judged another is a ratchet that cannot hold
//! (´[TOOLS-rule:lintcontracts:burn-families]´). The three display sites
//! (´[TOOLS-rule:lintcontracts:ownership]´) settles are invisible to this pass for that reason rather than by
//! an exemption list (´[TOOLS-rule:lintcontracts:ownership]´).
//!
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use crate::adoption::{Adoption, Owner};
use crate::engine::{Analysis, ImportSite};
use crate::finding::{Finding, Location};
use crate::occurrence::Syntax;
use crate::snapshot::{DIRECTORY, OWNERS_FILE, ReachRow};
use crate::workspace::Package;

/// The dependency tables a manifest may declare a reach edge in.
///
/// All three, and the enumeration is the convention's own: reach is declared
/// "in any dependency table — ordinary, development, or build"
/// (´[TOOLS-rule:lintcontracts:ownership]´). A dependency declared for tests
/// warrants a citation exactly as one declared for the build does, because what
/// the edge records is that the citing corpus has taken on the cited one, not
/// when it does so.
///
/// ´const:indexlinter:reach-dependency-tables´ (´[ORCHESTRATION-alg:const:form]´)
/// ´const:indexlinter:reach-dependency-tables-form-x84d920a9´
const DEPENDENCY_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// The reach relation over the corpora of a workspace.
///
/// The map holds the declared edges only. Reflexivity and the always-open
/// upward direction are decided by [`Reach::reaches`] rather than stored, so
/// that the stored edges stay exactly what the manifests say and the two rules
/// added on top stay legible as rules.
#[derive(Debug, Clone)]
pub struct Reach {
    edges: BTreeMap<Owner, BTreeSet<Owner>>,
    directories: BTreeMap<Owner, BTreeSet<PathBuf>>,
    names: BTreeMap<Owner, BTreeSet<String>>,
    root: Owner,
}

impl Reach {
    /// Whether the citing corpus reaches the cited one.
    ///
    /// Three ways, and only three. A corpus is itself. Every corpus reaches a
    /// crate-bearing root, by the rule that keeps repo-wide policy readable
    /// from the repository it governs (´[TOOLS-rule:lintcontracts:ownership]´). And
    /// a manifest edge reaches what it declares — one hop, never its closure
    /// (´[TOOLS-rule:lintcontracts:ownership]´). A crateless root has no structural
    /// manifest reach; its explicit declared edges are applied by the verifier.
    #[must_use]
    pub fn reaches(&self, citing: &Owner, cited: &Owner) -> bool {
        citing == cited
            || self.structural_root() == Some(cited)
            || self
                .edges
                .get(citing)
                .is_some_and(|set| set.contains(cited))
    }

    /// The declared edges of one corpus, the corpus itself omitted.
    #[must_use]
    pub fn declared(&self, citing: &Owner) -> BTreeSet<&Owner> {
        self.edges
            .get(citing)
            .map(|set| set.iter().collect())
            .unwrap_or_default()
    }

    /// Everything one corpus may cite, written out.
    ///
    /// The same three ways [`Reach::reaches`] admits a citation, materialized as
    /// a set rather than answered one pair at a time: the corpus itself, the
    /// root, and each manifest edge. This is the form the owner surface writes
    /// the relation in, so it is the form the reconciliation compares against
    /// (´[TOOLS-rule:lintcontracts:ownership]´).
    #[must_use]
    pub fn admissible(&self, citing: &Owner) -> BTreeSet<Owner> {
        let mut reached: BTreeSet<Owner> = BTreeSet::new();

        reached.insert(citing.clone());
        if let Some(root) = self.structural_root() {
            reached.insert(root.clone());
        }

        for target in self.declared(citing) {
            reached.insert(target.clone());
        }

        reached
    }

    /// How many declared edges the derivation found over the whole workspace.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(BTreeSet::len).sum()
    }

    /// How many corpora the relation ranges over.
    #[must_use]
    pub fn corpus_count(&self) -> usize {
        self.directories.len()
    }

    /// The owner the workspace root corpus carries.
    #[must_use]
    pub const fn root(&self) -> &Owner {
        &self.root
    }

    /// The manifest of an owner with exactly one package, otherwise none.
    #[must_use]
    pub fn manifest_of(&self, owner: &Owner) -> Option<PathBuf> {
        self.directory_of(owner)
            .map(|directory| directory.join("Cargo.toml"))
    }

    /// The directory of an owner with exactly one package, otherwise none.
    #[must_use]
    pub fn directory_of(&self, owner: &Owner) -> Option<&Path> {
        self.directories
            .get(owner)
            .filter(|directories| directories.len() == 1)
            .and_then(|directories| directories.first())
            .map(PathBuf::as_path)
    }

    /// The crate name of an owner with exactly one package, otherwise none.
    #[must_use]
    pub fn crate_name_of(&self, owner: &Owner) -> Option<&str> {
        self.names
            .get(owner)
            .filter(|names| names.len() == 1)
            .and_then(|names| names.first())
            .map(String::as_str)
    }

    /// The root reached by every owner without a declared row.
    pub(crate) fn structural_root(&self) -> Option<&Owner> {
        self.is_crate_bearing(&self.root).then_some(&self.root)
    }

    /// Whether a workspace package supplies this owner's manifest.
    fn is_crate_bearing(&self, owner: &Owner) -> bool {
        self.directories.contains_key(owner)
    }
}

/// Derive the reach relation from the workspace manifests.
///
/// Each member's manifest is read for the three dependency tables. An entry
/// carrying a `path` key becomes an edge to whichever member that path resolves
/// to. An entry carrying `workspace = true` is first resolved through the root
/// manifest's `[workspace.dependencies]` table, and becomes an edge when that
/// entry carries a `path`. Resolving the path rather than trusting the
/// dependency's name is deliberate: a dependency may be renamed at its
/// declaration, and the path is what actually names the member. A `path`
/// standing outside a dependency table — a library target's, say — declares no
/// edge, because it is not a dependency.
///
/// A manifest that cannot be read yields no edges and no complaint here: the
/// owner discovery already reported it, and reporting it twice would give one
/// defect two entries.
#[must_use]
pub fn derive_reach(root: &Path, packages: &[Package], adoption: &Adoption) -> Reach {
    let mut directories: BTreeMap<Owner, BTreeSet<PathBuf>> = BTreeMap::new();
    let mut names: BTreeMap<Owner, BTreeSet<String>> = BTreeMap::new();
    let mut by_directory = BTreeMap::new();

    for package in packages {
        let owner = adoption.owner_of(package.directory()).clone();
        directories
            .entry(owner.clone())
            .or_default()
            .insert(package.directory().to_path_buf());
        names
            .entry(owner.clone())
            .or_default()
            .insert(package.name().to_owned());
        by_directory.insert(package.directory().to_path_buf(), owner);
    }

    let workspace_dependencies = std::fs::read_to_string(root.join("Cargo.toml"))
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        .and_then(|manifest| {
            manifest
                .get("workspace")
                .and_then(|workspace| workspace.get("dependencies"))
                .and_then(toml::Value::as_table)
                .cloned()
        })
        .unwrap_or_default();

    let mut edges: BTreeMap<Owner, BTreeSet<Owner>> = BTreeMap::new();

    // Every package contributes; an owner's edge set is their union.
    for (directory, owner) in &by_directory {
        let Ok(text) = std::fs::read_to_string(root.join(directory).join("Cargo.toml")) else {
            continue;
        };
        let Ok(manifest) = toml::from_str::<toml::Table>(&text) else {
            continue;
        };

        let reached = edges.entry(owner.clone()).or_default();

        for table in DEPENDENCY_TABLES {
            let Some(dependencies) = manifest.get(table).and_then(toml::Value::as_table) else {
                continue;
            };

            for (dependency_name, dependency) in dependencies {
                let (base, dependency) =
                    if dependency.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                        let Some(dependency) = workspace_dependencies.get(dependency_name) else {
                            continue;
                        };
                        (Path::new(""), dependency)
                    } else {
                        (directory.as_path(), dependency)
                    };

                let Some(path) = dependency.get("path").and_then(toml::Value::as_str) else {
                    continue;
                };

                let Some(target) = by_directory.get(&join_relative(base, Path::new(path))) else {
                    continue;
                };

                // The member itself is omitted: a manifest may depend on its own
                // directory to turn a feature on for its tests, and a corpus
                // reaching itself is reflexivity rather than a declared edge.
                if target != owner {
                    reached.insert(target.clone());
                }
            }
        }
    }

    Reach {
        edges,
        directories,
        names,
        root: adoption.owner_of(Path::new("")).clone(),
    }
}

/// Join a relative dependency path onto a member directory, resolving `.` and
/// `..` textually.
///
/// The paths in a manifest are relative to that manifest and never escape the
/// workspace, so a textual resolution is exact here and avoids asking the
/// filesystem a question it may answer differently on a symlinked checkout.
fn join_relative(directory: &Path, path: &Path) -> PathBuf {
    let mut resolved: Vec<std::ffi::OsString> = directory
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect();

    for component in path.components() {
        match component {
            Component::Normal(part) => resolved.push(part.to_os_string()),
            Component::ParentDir => {
                resolved.pop();
            }
            _ => {}
        }
    }

    resolved.iter().collect()
}

/// What the layer pass found, in the figures a check report carries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LayerAnalysis {
    /// How many corpora the reach relation ranges over.
    pub corpora: usize,
    /// How many declared manifest edges the derivation found.
    pub edges: usize,
    /// How many may-cite rows the owner surface declares.
    pub registered_rows: usize,
    /// Whether the surface declares no reach at all, so nothing was reconciled.
    pub register_dormant: bool,
    /// Participating imports of a root head, from any corpus but the root.
    pub upward_imports: usize,
    /// Participating imports between non-root owners.
    pub sideways_imports: usize,
    /// Participating imports from the root corpus to another owner.
    pub downward_imports: usize,
    /// How many of those imports the citation law refused.
    pub violations: usize,
}

/// Check a workspace's participating imports against the reach graph.
///
/// The imports come from the engine's own scan, so this pass writes no second
/// recognizer for the bracket form and inherits the participation judgment
/// whole. What is new here is the reach derivation and the two verdicts.
#[must_use]
pub fn verify_layers(
    root: &Path,
    packages: &[Package],
    adoption: &Adoption,
    analysis: &Analysis,
    declared: &[ReachRow],
) -> (LayerAnalysis, Vec<Finding>) {
    let reach = derive_reach(root, packages, adoption);
    let mut findings = if declared.is_empty() {
        Vec::new()
    } else {
        reconcile_declaration(&reach, adoption, declared)
    };

    let mut counts = LayerAnalysis {
        corpora: reach.corpus_count(),
        edges: reach.edge_count(),
        register_dormant: declared.is_empty(),
        registered_rows: declared.len(),
        ..LayerAnalysis::default()
    };

    for import in analysis.imports() {
        let Some(cited) = adoption.owner_of_prefix(import.prefix()).cloned() else {
            // An unregistered prefix names no owner, so no question about reach
            // can be asked of it. The engine already failed it as unregistered.
            continue;
        };

        if cited == *import.citing() {
            // A self-qualified import is already a failure of the calculus, and
            // reach admits every corpus to itself, so this pass has nothing to
            // add.
            continue;
        }

        let citing_is_root = *import.citing() == *reach.root();

        if citing_is_root {
            counts.downward_imports += 1;
        } else if cited == *reach.root() {
            counts.upward_imports += 1;
        } else {
            counts.sideways_imports += 1;
        }

        // Root prose cannot rest on a package's private premise. An imported
        // owner's published policy is common once a declared row takes it on,
        // so the ordinary crateless reach judgment applies to that import.
        if citing_is_root
            && import.syntax() == Syntax::Prose
            && !adoption.imported().contains_key(&cited)
        {
            counts.violations += 1;
            findings.push(Finding::PolicyImport {
                prefix: import.prefix().clone(),
                cited_owner: cited.as_str().to_owned(),
                location: import.location().clone(),
            });
            continue;
        }

        if import_obstacle(
            &reach,
            adoption,
            declared,
            import.citing(),
            &cited,
            import.syntax(),
        )
        .is_none()
        {
            continue;
        }

        counts.violations += 1;
        findings.push(Finding::UnreachedImport {
            citing_owner: import.citing().as_str().to_owned(),
            prefix: import.prefix().clone(),
            cited_owner: cited.as_str().to_owned(),
            absent_edge: absent_edge(&reach, import, &cited),
            location: import.location().clone(),
        });
    }

    (counts, findings)
}

/// Name the manifest edge whose absence refuses an import.
///
/// The repair is what the sentence has to convey, so it names the citing
/// manifest and the directory it would have to declare. Where the cited owner
/// is registered against no workspace member there is no directory to name, and
/// saying so is the whole answer: nothing can declare a dependency on a crate
/// the workspace does not build.
/// Both paths use the reversible byte display of every repository path a reader prints.
fn absent_edge(reach: &Reach, import: &ImportSite, cited: &Owner) -> String {
    if reach
        .directories
        .get(import.citing())
        .is_some_and(|paths| paths.len() > 1)
        || reach
            .directories
            .get(cited)
            .is_some_and(|paths| paths.len() > 1)
    {
        let Some(targets) = reach.directories.get(cited) else {
            return format!(
                "{cited} is registered against no workspace member, so no manifest can declare a dependency on it"
            );
        };
        let manifests = reach
            .directories
            .get(import.citing())
            .into_iter()
            .flatten()
            .map(|path| crate::pattern::display_path(&path.join("Cargo.toml")))
            .collect::<Vec<_>>()
            .join(", ");
        let targets = targets
            .iter()
            .map(|path| crate::pattern::display_path(path))
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "the citing owner's manifests [{manifests}] declare no path dependency on the cited owner's directories [{targets}]"
        );
    }
    let manifest = reach.manifest_of(import.citing()).map_or_else(
        || "the citing corpus's manifest".to_owned(),
        |path| crate::pattern::display_path(&path),
    );

    reach.directory_of(cited).map_or_else(
        || format!("{cited} is registered against no workspace member, so no manifest can declare a dependency on it"),
        |directory| format!("{manifest} declares no path dependency on {}", crate::pattern::display_path(directory)),
    )
}

/// The same reach and root-prose restrictions used to judge an imported citation.
pub fn import_obstacle(
    reach: &Reach,
    adoption: &Adoption,
    rows: &[ReachRow],
    citing: &Owner,
    cited: &Owner,
    syntax: Syntax,
) -> Option<&'static str> {
    if citing == reach.root() && syntax == Syntax::Prose && !adoption.imported().contains_key(cited)
    {
        return Some("root prose cannot import a member owner's private premise");
    }
    if !reach.reaches(citing, cited)
        && !declared_crateless_edge(reach, adoption, rows, citing, cited)
    {
        return Some("the citing owner does not reach the minting owner");
    }
    None
}

/// Whether an explicit row authorizes an edge no pair of manifests can state.
fn declared_crateless_edge(
    reach: &Reach,
    adoption: &Adoption,
    rows: &[ReachRow],
    citing: &Owner,
    cited: &Owner,
) -> bool {
    if reach.is_crate_bearing(citing) && reach.is_crate_bearing(cited) {
        return false;
    }

    let (Some(citing), Some(cited)) = (
        adoption.prefix_of_owner(citing),
        adoption.prefix_of_owner(cited),
    ) else {
        return false;
    };

    rows.iter()
        .any(|row| row.owner == citing.as_str() && row.target == cited.as_str())
}

/// Reconcile the declared may-cite relation against the derived one.
///
/// The manifests keep their authority and the owner surface states the graph,
/// so a disagreement is a defect of the declaration
/// (´[TOOLS-rule:lintcontracts:ownership]´). What is compared is the whole
/// admissibility relation rather than the manifest edges alone: the derivation
/// contributes self reach, the universal upward edge and the workspace-path
/// dependencies, which is exactly the three ways [`Reach::reaches`] admits a
/// citation, so the declaration a reader meets is the relation the check
/// applies and not a subset of it standing in for one.
///
/// Self and a crate-bearing root are structural and cannot be spelled on the
/// declared side. The surface refuses rows restating either permission, and
/// reconciliation supplies both before comparing the remaining manifest edges.
/// A crateless root remains declaration-authoritative like any crateless owner.
///
/// The comparison is made in the prefix spelling, because that is the spelling
/// the owner file writes its rows in. A corpus registered against no prefix can
/// state nothing and is passed over; the engine has already failed it as
/// unregistered, and reporting it here would give one defect two entries.
///
/// A row with a crateless source or target has no possible manifest counterpart
/// and is declaration-authoritative. Reconciliation therefore compares exactly
/// the subrelation whose two endpoints are crate-bearing, while the verifier
/// applies the remaining declared rows directly.
fn reconcile_declaration(reach: &Reach, adoption: &Adoption, rows: &[ReachRow]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let surface = Location::new(Path::new(DIRECTORY).join(OWNERS_FILE), "", 0);

    let mut stated: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();

    for row in rows {
        stated
            .entry(row.owner.as_str())
            .or_default()
            .insert(row.target.as_str());
    }

    for owner in reach.directories.keys() {
        let Some(prefix) = adoption.prefix_of_owner(owner) else {
            continue;
        };

        let derived: BTreeSet<String> = reach
            .admissible(owner)
            .iter()
            .filter_map(|reached| adoption.prefix_of_owner(reached))
            .map(|prefix| prefix.as_str().to_owned())
            .collect();

        let stated_targets = stated.get(prefix.as_str());

        let mut declared: BTreeSet<&str> = stated_targets
            .into_iter()
            .flat_map(|targets| targets.iter().copied())
            .filter(|target| {
                crate::label::Prefix::parse(target)
                    .and_then(|prefix| adoption.owner_of_prefix(&prefix))
                    .is_some_and(|target| reach.is_crate_bearing(target))
            })
            .collect();
        declared.insert(prefix.as_str());
        if let Some(root) = reach
            .structural_root()
            .and_then(|root| adoption.prefix_of_owner(root))
        {
            declared.insert(root.as_str());
        }

        // A rowless owner owes only its non-structural manifest edges.
        if stated_targets.is_none()
            && derived
                .iter()
                .any(|target| !declared.contains(target.as_str()))
        {
            findings.push(Finding::ReachDeclarationOmission {
                corpus: prefix.as_str().to_owned(),
                location: surface.clone(),
            });
            continue;
        }

        if declared != derived.iter().map(String::as_str).collect::<BTreeSet<_>>() {
            findings.push(Finding::ReachDeclarationDivergence {
                corpus: prefix.as_str().to_owned(),
                registered: declared.iter().map(|target| (*target).to_owned()).collect(),
                derived: derived.into_iter().collect(),
                location: surface.clone(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use super::{absent_edge, derive_reach, verify_layers};
    use crate::adoption::{Owner, index_adoption};
    use crate::carrier::index_carrier;
    use crate::code::CodeSurface;
    use crate::engine::analyze;
    use crate::finding::Finding;
    use crate::plan::{CorpusPlan, WorkspacePlan};
    use crate::registry::fixture_kind_registry;
    use crate::roster::OwnerNames;
    use crate::snapshot::ReachRow;
    use crate::universe::UniverseKind;
    use crate::workspace::Package;

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("create");
        fs::write(path, text).expect("write");
    }

    fn workspace(root: &Path) {
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\".\", \"packages/alpha\", \"packages/beta\"]\n\n\
             [package]\nname = \"example-project-a\"\n\n\
             [dependencies]\nexample-alpha = { path = \"packages/alpha\" }\n",
        );
        write(
            root,
            "packages/alpha/Cargo.toml",
            "[package]\nname = \"example-alpha\"\n\n\
             [dependencies]\nexample-beta = { path = \"../beta\" }\n",
        );
        write(
            root,
            "packages/beta/Cargo.toml",
            "[package]\nname = \"example-beta\"\n",
        );
        write(
            root,
            "packages/beta/docs/head.md",
            "# Beta\n\n## Beta · `sec:beta:thing`\n\nA head.\n",
        );
    }

    fn packages(root: &Path) -> Vec<Package> {
        WorkspacePlan::compile(root).packages().to_vec()
    }

    fn corpus(root: &Path) -> CorpusPlan {
        CorpusPlan::compile(root, UniverseKind::AsWritten, &[])
    }

    fn declared_rows(extra: &[(&str, &str)]) -> Vec<ReachRow> {
        [
            ("PROJECTA", "ALPHA"),
            ("ALPHA", "PROJECTA"),
            ("ALPHA", "BETA"),
            ("BETA", "PROJECTA"),
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(|(owner, target)| ReachRow {
            owner: owner.to_owned(),
            target: target.to_owned(),
        })
        .collect()
    }

    fn judge(
        root: &Path,
        rows: &[ReachRow],
        crateless_sources: &[&str],
    ) -> (Vec<Finding>, Vec<&'static str>) {
        let packages = packages(root);
        let declared = vec!["POLICY".to_owned()];
        let path_owners = crateless_sources
            .iter()
            .map(|path| (Path::new(path).to_path_buf(), Owner::new("POLICY")));
        let adoption = index_adoption(
            &packages,
            Some(&OwnerNames::new("example-", [])),
            &[],
            fixture_kind_registry(),
            "index",
        )
        .with_declared_owners(&declared, None)
        .with_path_owners(path_owners);
        let (sources, _carrier_findings) = index_carrier(root, &corpus(root)).read();
        let analysis = analyze(&adoption, &sources, &CodeSurface::default());
        let engine_codes = analysis.findings().iter().map(Finding::code).collect();
        let (_counts, findings) = verify_layers(root, &packages, &adoption, &analysis, rows);

        (findings, engine_codes)
    }

    fn reconcile(root: &Path, rows: &[ReachRow]) -> Vec<Finding> {
        let packages = packages(root);
        let adoption = index_adoption(
            &packages,
            Some(&OwnerNames::new("example-", [])),
            &[],
            fixture_kind_registry(),
            "index",
        );
        let analysis = analyze(&adoption, &[], &CodeSurface::default());
        let (_counts, findings) = verify_layers(root, &packages, &adoption, &analysis, rows);

        findings
    }

    /// A crate can resolve a crateless owner's prefix, but the cross-owner
    /// citation is reached only when the owner surface declares that edge.
    /// Without it the verdict is a reach violation, not an unregistered prefix.
    ///
    /// ´claim:layers:a-crateless-target-requires-its-declared-edge´
    /// ´test:unit:a-crateless-prefix-requires-its-declared-edge´
    #[test]
    fn a_crateless_prefix_requires_its_declared_edge() {
        let root = tempfile::tempdir().expect("temporary directory");
        workspace(root.path());
        write(
            root.path(),
            "docs/policy.md",
            "# Policy\n\n## Policy · `sec:policy:rule`\n\nA crateless head.\n",
        );
        write(
            root.path(),
            "packages/alpha/docs/cites.md",
            "# Alpha cites\n\n## Cites · `sec:alpha:cites`\n\nSee (`[POLICY-sec:policy:rule]`).\n",
        );

        let (missing, engine_codes) = judge(root.path(), &[], &["docs/policy.md"]);
        assert!(
            matches!(missing.as_slice(), [Finding::UnreachedImport { .. }]),
            "the absent edge is a reach violation: {missing:?}"
        );
        assert!(
            !engine_codes.contains(&"unregistered_prefix"),
            "the declared crateless prefix resolves before reach is judged"
        );

        let (admitted, engine_codes) = judge(
            root.path(),
            &declared_rows(&[("ALPHA", "POLICY")]),
            &["docs/policy.md"],
        );
        assert!(
            admitted.is_empty(),
            "the declared edge reaches: {admitted:?}"
        );
        assert!(engine_codes.is_empty(), "the citation resolves cleanly");
    }

    /// A crateless owner may cite a crate through an explicit may-cite row even
    /// though its source endpoint has no manifest in which a dependency could
    /// stand. The declaration is authoritative for reconciliation and reach.
    ///
    /// ´claim:layers:a-crateless-source-reaches-by-declaration´
    /// ´test:unit:a-crateless-source-reaches-by-its-declared-edge´
    #[test]
    fn a_crateless_source_reaches_by_its_declared_edge() {
        let root = tempfile::tempdir().expect("temporary directory");
        workspace(root.path());
        write(
            root.path(),
            "docs/policy-cites.md",
            "# Policy cites\n\n## Cites · `sec:policy:cites`\n\nSee (`[BETA-sec:beta:thing]`).\n",
        );

        let (findings, engine_codes) = judge(
            root.path(),
            &declared_rows(&[("POLICY", "BETA")]),
            &["docs/policy-cites.md"],
        );
        assert!(
            findings.is_empty(),
            "the crateless source needs no manifest counterpart: {findings:?}"
        );
        assert!(engine_codes.is_empty(), "the citation resolves cleanly");
    }

    /// Crate-bearing owners continue to reconcile in both directions against
    /// manifests: the exact relation passes, a declaration-only edge diverges,
    /// and the existing manifest-only divergence case remains covered elsewhere.
    /// When an owner covers two crates, both directories resolve as dependency
    /// targets and both manifests contribute edges, independent of member order.
    /// Removing an edge from either manifest removes that owner's reach.
    ///
    /// # Panics
    ///
    /// Panics only if the fixture cannot be written or its reach assertions fail.
    ///
    /// ´claim:layers:crate-bearing-reconciliation-remains-bidirectional´
    /// ´test:unit:keeps-crate-bearing-reconciliation-bidirectional´
    #[test]
    fn keeps_crate_bearing_reconciliation_bidirectional() {
        let root = tempfile::tempdir().expect("temporary directory");
        workspace(root.path());
        let exact = declared_rows(&[]);

        assert!(
            reconcile(root.path(), &exact).is_empty(),
            "equal package relations pass"
        );

        let divergence = reconcile(root.path(), &declared_rows(&[("BETA", "ALPHA")]));
        let [Finding::ReachDeclarationDivergence { corpus, .. }] = divergence.as_slice() else {
            panic!("one declaration-only divergence: {divergence:?}");
        };
        assert_eq!(corpus, "BETA");

        shared_owner_reach();
    }

    fn shared_owner_reach() {
        let root = tempfile::tempdir().expect("temporary directory");
        write(
            root.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"a\", \"b\", \"c\", \"d\"]\n",
        );
        for (directory, manifest) in [
            (
                "a",
                "[package]\nname = \"first-vendor\"\n[dependencies]\nc = { path = \"../c\" }\n",
            ),
            (
                "b",
                "[package]\nname = \"second-vendor\"\n[dependencies]\nd = { path = \"../d\" }\n",
            ),
            (
                "c",
                "[package]\nname = \"third\"\n[dependencies]\na = { path = \"../a\" }\n",
            ),
            (
                "d",
                "[package]\nname = \"fourth\"\n[dependencies]\nb = { path = \"../b\" }\n",
            ),
        ] {
            write(root.path(), &format!("{directory}/Cargo.toml"), manifest);
        }
        let mut packages = packages(root.path());
        assert_eq!(packages.len(), 4);
        let adoption = index_adoption(&[], None, &[], fixture_kind_registry(), "index")
            .with_declared_owners(
                &[
                    "ROOT".to_owned(),
                    "VENDOR".to_owned(),
                    "THIRD".to_owned(),
                    "FOURTH".to_owned(),
                ],
                Some("ROOT"),
            )
            .with_path_owners(
                [
                    ("a", "VENDOR"),
                    ("b", "VENDOR"),
                    ("c", "THIRD"),
                    ("d", "FOURTH"),
                ]
                .map(|(path, owner)| (Path::new(path).to_path_buf(), Owner::new(owner))),
            );
        let vendor = Owner::new("VENDOR");
        let third = Owner::new("THIRD");
        let fourth = Owner::new("FOURTH");
        let reach = derive_reach(root.path(), &packages, &adoption);
        assert_eq!(reach.declared(&vendor), BTreeSet::from([&third, &fourth]));
        assert!(reach.reaches(&third, &vendor));
        assert!(reach.reaches(&fourth, &vendor));
        assert_eq!(reach.corpus_count(), 3);
        assert_eq!(reach.edge_count(), 4);
        assert!(reach.manifest_of(&vendor).is_none());
        assert!(reach.directory_of(&vendor).is_none());
        assert!(reach.crate_name_of(&vendor).is_none());
        let rows: Vec<_> = [
            ("VENDOR", "THIRD"),
            ("VENDOR", "FOURTH"),
            ("THIRD", "VENDOR"),
            ("FOURTH", "VENDOR"),
        ]
        .map(|(owner, target)| ReachRow {
            owner: owner.to_owned(),
            target: target.to_owned(),
        })
        .into();
        let findings = super::reconcile_declaration(&reach, &adoption, &rows);
        assert!(findings.is_empty(), "the union reconciles: {findings:?}");
        packages.reverse();
        let reversed = derive_reach(root.path(), &packages, &adoption);
        assert_eq!(reach.edges, reversed.edges);
        assert_eq!(reach.directories, reversed.directories);
        assert_eq!(reach.names, reversed.names);
        for (directory, name, target) in [
            ("a", "first-vendor", &third),
            ("b", "second-vendor", &fourth),
        ] {
            write(
                root.path(),
                &format!("{directory}/Cargo.toml"),
                &format!("[package]\nname = \"{name}\"\n"),
            );
            let reduced = derive_reach(root.path(), &packages, &adoption);
            assert!(!reduced.reaches(&vendor, target));
            assert!(super::reconcile_declaration(&reduced, &adoption, &rows).iter().any(|finding|
                matches!(finding, Finding::ReachDeclarationDivergence { corpus, .. } if corpus == "VENDOR")));
        }
    }

    /// An absent edge names the citing manifest and cited directory in the
    /// reversible byte display; a cited owner without a workspace member keeps
    /// the crateless explanation.
    ///
    /// # Panics
    /// Panics only if the temporary fixture cannot be created or written, or
    /// its citation cannot be read.
    ///
    /// ´claim:layers:an-absent-edge-names-its-manifest-in-the-reversible-display´
    /// ´test:unit:an-absent-edge-names-its-manifest-in-the-reversible-display´
    #[test]
    fn an_absent_edge_names_its_manifest_in_the_reversible_display() {
        let root = tempfile::tempdir().expect("temporary directory");
        write(
            root.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\".\", \"packages/my crate\", \"packages/beta\"]\n\n\
             [package]\nname = \"example-project-a\"\n",
        );
        write(
            root.path(),
            "packages/my crate/Cargo.toml",
            "[package]\nname = \"example-my-crate\"\n",
        );
        write(
            root.path(),
            "packages/beta/Cargo.toml",
            "[package]\nname = \"example-beta\"\n",
        );
        write(
            root.path(),
            "packages/beta/docs/head.md",
            "# Beta\n\n## Beta · `sec:beta:thing`\n\nA head.\n",
        );
        write(
            root.path(),
            "packages/my crate/docs/cites.md",
            "# Cites\n\n## Cites · `sec:cites:one`\n\nSee (`[BETA-sec:beta:thing]`).\n",
        );

        let packages = packages(root.path());
        let adoption = index_adoption(
            &packages,
            Some(&OwnerNames::new("example-", [])),
            &[],
            fixture_kind_registry(),
            "index",
        )
        .with_declared_owners(&["POLICY".to_owned()], None);
        let (sources, _carrier_findings) = index_carrier(root.path(), &corpus(root.path())).read();
        let analysis = analyze(&adoption, &sources, &CodeSurface::default());
        let reach = derive_reach(root.path(), &packages, &adoption);
        assert_eq!(analysis.imports().len(), 1);
        let import = &analysis.imports()[0];

        assert_eq!(
            absent_edge(
                &reach,
                import,
                adoption.owner_of(Path::new("packages/beta")),
            ),
            "packages/my%20crate/Cargo.toml declares no path dependency on packages/beta"
        );
        assert_eq!(
            absent_edge(&reach, import, &Owner::new("POLICY")),
            "POLICY is registered against no workspace member, so no manifest can declare a dependency on it"
        );
    }
}
