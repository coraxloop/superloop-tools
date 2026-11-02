// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! A portable, deterministic registry of one owner's labels.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::application::code_surface;
use crate::census::take_planned_census;
use crate::engine::{Surface, analyze};
use crate::head::read_heads;
use crate::label::Label;
use crate::plan::ExecutionPlan;
use crate::profile::cover;
use crate::prose::scan_markdown;
use crate::snapshot::EnvironmentRow;

/// The schema identifier used by a published label registry.
pub const NAMESPACE: &str = "class.linter.labels";

/// Publication metadata holds addresses, ownership and path classes, never prose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnpublishedLabel {
    /// The exact unpublished address.
    pub label: String,
    /// The owner assigned to the excluded definition by the source partition.
    pub owner: String,
    /// The manifest selector excluding the definition, not its text or heading.
    pub path_class: String,
}

/// Generated resolution source for public citations of excluded definitions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnpublishedLabels {
    /// Versioned schema identity.
    pub namespace: String,
    /// Schema version.
    pub version: [u64; 3],
    /// Sorted, unique owner-and-label entries.
    pub labels: Vec<UnpublishedLabel>,
}

/// The public register's stable destination; source trees declare it and cuts project it.
pub const UNPUBLISHED_PATH: &str = "docs/public/unpublished-labels.toml";

impl UnpublishedLabels {
    /// Decode addresses without accepting prose, duplicate entries or unsafe classes.
    ///
    /// # Errors
    /// Refuses an unknown schema, invalid address, owner, class or duplicate row.
    pub fn parse(text: &str) -> Result<Self, String> {
        let document: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        if document.namespace != "class.linter.unpublished-labels" || document.version != [1, 0, 0]
        {
            return Err("unknown unpublished-label register schema".to_owned());
        }
        let mut seen = BTreeSet::new();
        for row in &document.labels {
            if Label::parse(&row.label).is_none()
                || crate::label::Prefix::parse(&row.owner).is_none()
                || !superloop_cli_common::public_set::safe_path(
                    row.path_class.trim_end_matches('/'),
                )
                || !seen.insert((&row.owner, &row.label))
            {
                return Err("invalid or duplicate unpublished-label entry".to_owned());
            }
        }
        Ok(document)
    }
}

/// Resolve the repository with the same carriers and owner rules as a check.
/// Publication uses these sites rather than a second label recognizer.
#[must_use]
pub fn citation_targets(plan: &ExecutionPlan) -> Vec<crate::engine::ResolvedCitation> {
    let (census, _) = take_planned_census(plan.root(), plan.profiles().sources());
    let (assets, _) = cover(plan.workspace().packages(), &census);
    let (sources, _) = plan.labels().read(plan.root());
    analyze(
        plan.labels().adoption(),
        &sources,
        &code_surface(plan, &assets),
    )
    .resolutions()
    .to_vec()
}

/// Versioned executable protocol for resolved citation sites; it carries no heads or prose.
#[derive(Serialize)]
pub struct CitationSites {
    /// Protocol identity.
    pub namespace: &'static str,
    /// Protocol version.
    pub version: [u64; 3],
    /// Resolved occurrences, including occurrences before a document's first mint.
    pub sites: Vec<ResolvedCitationSite>,
}

/// One occurrence and the address to which the check's recognizer resolves it.
#[derive(Serialize)]
pub struct ResolvedCitationSite {
    /// Repository-relative citing file.
    pub citing_path: PathBuf,
    /// Repository-relative definition file or imported registry.
    pub target_path: PathBuf,
    /// Kind of definition.
    pub surface: Surface,
    /// Exact resolved address.
    pub label: String,
    /// Resolved owner partition.
    pub owner: String,
    /// Original exclusion class when the address is already unpublished.
    pub path_class: Option<String>,
}

/// Export the check's resolved sites across an executable boundary.
#[must_use]
pub fn citation_sites_with_plan(plan: &ExecutionPlan) -> CitationSites {
    let sites = citation_targets(plan)
        .into_iter()
        .map(|site| {
            let label = site.target.label.to_string();
            let owner = site.target.owner.as_str().to_owned();
            let path_class = if site.target.surface == Surface::Unpublished {
                plan.snapshot().unpublished().and_then(|(_, document)| {
                    document
                        .labels
                        .iter()
                        .find(|row| row.label == label && row.owner == owner)
                        .map(|row| row.path_class.clone())
                })
            } else {
                None
            };
            ResolvedCitationSite {
                citing_path: site.location.path().to_owned(),
                target_path: site.target.location.path().to_owned(),
                surface: site.target.surface,
                label,
                owner,
                path_class,
            }
        })
        .collect();
    CitationSites {
        namespace: "class.linter.citation-sites",
        version: [1, 0, 0],
        sites,
    }
}

/// One declared environment-to-kind pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindRow {
    /// The environment name.
    pub environment: String,
    /// Its kind token.
    pub kind: String,
}

/// The whole kind relation, including local extensions and reservations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindRelation {
    /// The adopted environment relation.
    pub environments: Vec<KindRow>,
    /// The importing corpus's extension rows.
    pub extensions: Vec<KindRow>,
    /// Kinds reserved by the adopted registry.
    pub reserved: Vec<String>,
    /// Kinds reserved by local extensions.
    pub reserved_extensions: Vec<String>,
}

impl KindRelation {
    /// Project the declarations into a stable relation for export or comparison.
    #[must_use]
    pub fn from_rows(
        environments: &[EnvironmentRow],
        extensions: &[EnvironmentRow],
        reserved: &BTreeSet<String>,
        reserved_extensions: &BTreeSet<String>,
    ) -> Self {
        let mut environments: Vec<_> = environments
            .iter()
            .map(|row| KindRow {
                environment: row.environment.clone(),
                kind: row.kind.clone(),
            })
            .collect();
        let mut extensions: Vec<_> = extensions
            .iter()
            .map(|row| KindRow {
                environment: row.environment.clone(),
                kind: row.kind.clone(),
            })
            .collect();
        environments.sort();
        extensions.sort();
        Self {
            environments,
            extensions,
            reserved: reserved.iter().cloned().collect(),
            reserved_extensions: reserved_extensions.iter().cloned().collect(),
        }
    }

    fn normalize(&mut self) {
        self.environments.sort();
        self.extensions.sort();
        self.reserved.sort();
        self.reserved_extensions.sort();
    }
}

/// Provenance of the registry's labels, independent of the export host.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySource {
    /// The published owner prefix.
    pub owner: String,
    /// Full Git commit, or `unknown` outside a checkout.
    pub commit: String,
}

/// One exported mint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRow {
    /// The exact label.
    pub label: String,
    /// Text of the head under which the label stands.
    pub head: String,
    /// The label's kind token.
    pub kind: String,
    /// Path relative to the exporting repository.
    pub file: String,
}

/// One owner's portable registry document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryDocument {
    /// The schema namespace.
    pub namespace: String,
    /// The schema version.
    pub version: [u64; 3],
    /// Every mint in label order.
    pub labels: Vec<LabelRow>,
    /// The owner and exporting commit.
    pub source: RegistrySource,
    /// The declared kind relation.
    pub kinds: KindRelation,
}

impl RegistryDocument {
    /// Decode and validate a published registry.
    ///
    /// # Errors
    ///
    /// Refuses malformed TOML, an unknown namespace or major version, and
    /// invalid or repeated label rows.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut document: Self =
            toml::from_str(text).map_err(|error| format!("malformed registry: {error}"))?;
        if document.namespace != NAMESPACE {
            return Err(format!(
                "unknown registry namespace: {}; expected {NAMESPACE}",
                document.namespace
            ));
        }
        if document.version[0] != 1 {
            return Err(format!(
                "unknown registry major version: {}",
                document.version[0]
            ));
        }
        if crate::label::Prefix::parse(&document.source.owner).is_none() {
            return Err(format!(
                "malformed registry owner: {}",
                document.source.owner
            ));
        }
        let mut seen = BTreeSet::new();
        for row in &document.labels {
            let Some(label) = Label::parse(&row.label) else {
                return Err(format!("malformed registry label: {}", row.label));
            };
            if !seen.insert(row.label.as_str()) {
                return Err(format!("duplicate registry label: {}", row.label));
            }
            if row.kind != label.kind() || row.head.trim().is_empty() || !relative_file(&row.file) {
                return Err(format!("malformed registry label row: {}", row.label));
            }
        }
        document.kinds.normalize();
        Ok(document)
    }

    /// Render stable TOML with one inline table per label and kind row.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "namespace = {}", quoted(&self.namespace));
        let _ = writeln!(
            out,
            "version = [{}, {}, {}]",
            self.version[0], self.version[1], self.version[2]
        );
        let _ = writeln!(out, "labels = [");
        for row in &self.labels {
            let _ = writeln!(
                out,
                "  {{ label = {}, head = {}, kind = {}, file = {} }},",
                quoted(&row.label),
                quoted(&row.head),
                quoted(&row.kind),
                quoted(&row.file)
            );
        }
        let _ = writeln!(out, "]\n\n[source]");
        let _ = writeln!(out, "owner = {}", quoted(&self.source.owner));
        let _ = writeln!(out, "commit = {}\n", quoted(&self.source.commit));
        let _ = writeln!(out, "[kinds]");
        write_kind_rows(&mut out, "environments", &self.kinds.environments);
        write_kind_rows(&mut out, "extensions", &self.kinds.extensions);
        write_words(&mut out, "reserved", &self.kinds.reserved);
        write_words(
            &mut out,
            "reserved_extensions",
            &self.kinds.reserved_extensions,
        );
        out
    }
}

fn relative_file(file: &str) -> bool {
    let path = Path::new(file);
    !file.is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn quoted(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn write_kind_rows(out: &mut String, name: &str, rows: &[KindRow]) {
    let _ = writeln!(out, "{name} = [");
    for row in rows {
        let _ = writeln!(
            out,
            "  {{ environment = {}, kind = {} }},",
            quoted(&row.environment),
            quoted(&row.kind)
        );
    }
    let _ = writeln!(out, "]");
}

fn write_words(out: &mut String, name: &str, words: &[String]) {
    let _ = write!(out, "{name} = [");
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            let _ = write!(out, ", ");
        }
        let _ = write!(out, "{}", quoted(word));
    }
    let _ = writeln!(out, "]");
}

/// Build the registry of one locally minted owner.
///
/// # Errors
///
/// Refuses an unknown or imported owner.
pub fn export_with_plan(plan: &ExecutionPlan, owner: &str) -> Result<RegistryDocument, String> {
    let snapshot = plan.snapshot();
    if !snapshot.owners().iter().any(|name| name == owner) || snapshot.imports().contains_key(owner)
    {
        return Err(format!("unknown local owner: {owner}"));
    }

    let root = plan.root();
    let (census, _findings) = take_planned_census(root, plan.profiles().sources());
    let (assets, _findings) = cover(plan.workspace().packages(), &census);
    let (sources, _findings) = plan.labels().read(root);
    let analysis = analyze(
        plan.labels().adoption(),
        &sources,
        &code_surface(plan, &assets),
    );
    let mut heads = BTreeMap::new();
    for source in &sources {
        let scan = scan_markdown(source.path(), source.text());
        let (found, _findings) = read_heads(
            source.path(),
            source.text(),
            scan.blocks(),
            scan.occurrences(),
        );
        for head in found {
            heads.insert(
                (source.path().to_path_buf(), head.label().to_string()),
                head.name().as_str().to_owned(),
            );
        }
    }

    let owner_identity = plan.labels().adoption().owner_of_prefix(
        &crate::label::Prefix::parse(owner)
            .ok_or_else(|| format!("unknown local owner: {owner}"))?,
    );
    let mut labels: Vec<LabelRow> = analysis
        .graph()
        .node_weights()
        .filter(|mint| {
            Some(&mint.owner) == owner_identity
                && matches!(mint.surface, Surface::Document | Surface::Code)
        })
        .map(|mint| {
            let file = mint.location.path().to_string_lossy().into_owned();
            let head = heads
                .get(&(mint.location.path().to_path_buf(), mint.label.to_string()))
                .cloned()
                .unwrap_or_else(|| {
                    code_head(
                        root,
                        mint.location.path(),
                        mint.location.line(),
                        mint.label.name(),
                    )
                });
            LabelRow {
                label: mint.label.to_string(),
                head,
                kind: mint.label.kind().to_owned(),
                file,
            }
        })
        .collect();
    labels.sort_by(|left, right| left.label.cmp(&right.label));
    let kinds = KindRelation::from_rows(
        snapshot.environments(),
        snapshot.environment_extensions(),
        snapshot.reserved_kinds(),
        snapshot.reserved_extensions(),
    );
    Ok(RegistryDocument {
        namespace: NAMESPACE.to_owned(),
        version: [1, 0, 0],
        labels,
        source: RegistrySource {
            owner: owner.to_owned(),
            commit: source_commit(root),
        },
        kinds,
    })
}

fn code_head(root: &Path, file: &Path, line: usize, fallback: &str) -> String {
    std::fs::read_to_string(root.join(file))
        .ok()
        .and_then(|text| {
            text.lines()
                .nth(line.saturating_sub(1))
                .map(str::trim)
                .map(str::to_owned)
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn source_commit(root: &Path) -> String {
    let top = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--show-toplevel"])
        .output();
    let Ok(top) = top else {
        return "unknown".to_owned();
    };
    if !top.status.success() {
        return "unknown".to_owned();
    }
    let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim());
    if top.canonicalize().ok() != root.canonicalize().ok() {
        return "unknown".to_owned();
    }
    Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|hash| hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Write a registry document at the requested output path.
///
/// # Errors
///
/// Returns a named output refusal when the path cannot be written.
pub fn write_export(document: &RegistryDocument, out: &Path) -> Result<(), String> {
    std::fs::write(out, document.render())
        .map_err(|error| format!("cannot write export {}: {error}", out.display()))
}

/// Report fields of a completed export command.
#[derive(Serialize)]
pub struct ExportReport {
    /// Published owner.
    pub owner: String,
    /// Output path.
    pub out: String,
    /// Number of labels exported.
    pub labels: usize,
}
