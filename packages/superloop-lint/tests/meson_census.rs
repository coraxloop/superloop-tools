// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Torrust project contributors

//! Meson graph census subprocess fixtures.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`the_graph_census_accepts_an_equal_declaration`] | cli | Equal declared and tracked sets pass the audit. # Panics Panics only if fixture creation fails or an equal graph is refused. |
//! | [`the_graph_census_refuses_an_omitted_tracked_path`] | cli | A tracked path omitted from Meson's lists is a missing graph path. # Panics Panics only if fixture creation fails or the omitted path is accepted. |
//! | [`the_graph_census_refuses_stale_list_paths`] | cli | Stale declarations and exclusions are each rejected. # Panics Panics only if fixture creation fails or a stale list path is accepted. |
//! | [`the_graph_census_refuses_duplicate_and_patterned_declarations`] | cli | Duplicate declarations and pattern overlaps refuse the same list. # Panics Panics only if fixture creation fails or either ambiguity is accepted. |
//! | [`the_graph_census_refuses_an_untracked_checkout_path`] | cli | The tracked-exclusive reader exposes a checkout path omitted by Git. # Panics Panics only if fixture creation fails or an untracked path is accepted. |
//! | [`the_graph_census_refuses_a_tracked_symlink`] | cli | A tracked symlink carries a forbidden index mode. # Panics Panics only if fixture creation fails or a tracked symlink is accepted. |
//! | [`the_graph_census_accepts_required_contract_rows`] | cli | A required contract accepts tracked plain files, a matching pattern and a populated directory while ignoring optional rows. # Panics Panics only if fixture creation or the accepted census and build report fail. |
//! | [`the_graph_census_refuses_missing_required_contract_paths`] | cli | Missing required plain files and directories receive the contract path in a refusal. # Panics Panics only if fixture creation fails or a missing path is accepted. |
//! | [`the_graph_census_refuses_unmatched_required_contract_patterns`] | cli | A required pattern without a tracked regular match is refused at its contract path. # Panics Panics only if fixture creation fails or an unmatched pattern is accepted. |
//! | [`the_graph_census_refuses_invalid_required_contract_patterns`] | cli | Stars outside the last component and multiple stars in one pattern are refused. # Panics Panics only if fixture creation fails or an invalid pattern is accepted. |
//! | [`the_graph_census_refuses_invalid_required_contracts`] | cli | Malformed TOML, missing row fields and unknown contract keys are refused. # Panics Panics only if fixture creation fails or an invalid contract is accepted. |

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: tempfile::TempDir,
    outputs: tempfile::TempDir,
    declared: PathBuf,
    excluded: PathBuf,
}

fn write(root: &Path, path: &str, text: &str) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().expect("parent")).expect("create parent");
    fs::write(target, text).expect("write fixture");
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run fixture git");
    assert!(output.status.success(), "{:?}", output.stderr);
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("corpus");
    let outputs = tempfile::tempdir().expect("outputs");
    write(root.path(), "doc.md", "A document.\n");
    for (name, text) in [
        (
            "owners",
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{ name = \"all\", owner = \"PROJECTA\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        ),
        ("environments", "environments = []\n"),
        ("policies", "policies = []\n"),
        ("lists", ""),
        ("shape", "universe = \"tracked-exclusive\"\nignore = []\n"),
    ] {
        write(
            root.path(),
            &format!(".linter/{name}.toml"),
            &format!(
                "namespace = \"{}.{name}\"\nversion = [1, 0, 0]\n{text}",
                if name == "lists" || name.starts_with("policy.") {
                    "class.linter"
                } else {
                    "org.example.linter"
                }
            ),
        );
    }
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["add", "-f", "-A"]);
    let declared = outputs.path().join("declared.txt");
    let excluded = outputs.path().join("excluded.txt");
    fs::write(
        &declared,
        ".linter/environments.toml\n.linter/lists.toml\n.linter/owners.toml\n.linter/policies.toml\n.linter/shape.toml\ndoc.md\n",
    )
    .expect("declared list");
    fs::write(&excluded, "").expect("excluded list");
    Fixture {
        root,
        outputs,
        declared,
        excluded,
    }
}

fn census(fixture: &Fixture, pattern: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["census", "--root"])
        .arg(fixture.root.path())
        .arg("--declared")
        .arg(&fixture.declared)
        .arg("--excluded")
        .arg(&fixture.excluded)
        .arg("--pattern")
        .arg(pattern)
        .output()
        .expect("run census")
}

fn census_with_required_path(fixture: &Fixture, contract: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["census", "--root"])
        .arg(fixture.root.path())
        .arg("--declared")
        .arg(&fixture.declared)
        .arg("--excluded")
        .arg(&fixture.excluded)
        .args(["--pattern", "^never$", "--required"])
        .arg(contract)
        .output()
        .expect("run census with required list")
}

fn census_with_required(fixture: &Fixture, required: &str) -> Output {
    let contract = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(required);
    census_with_required_path(fixture, &contract)
}

fn assert_refusal(output: &Output, code: &str) {
    assert_eq!(output.status.code(), Some(3), "{:?}", output.stderr);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("census JSON");
    assert_eq!(report["clean"], false);
    assert!(
        report["refusals"]
            .as_array()
            .expect("refusals")
            .iter()
            .any(|row| row["code"] == code),
        "{report}"
    );
}

fn assert_refusal_path(output: &Output, code: &str, path: &str) {
    assert_refusal(output, code);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("census JSON");
    assert!(
        report["refusals"]
            .as_array()
            .expect("refusals")
            .iter()
            .any(|row| row["code"] == code && row["path"] == path),
        "{report}"
    );
}

/// Equal declared and tracked sets pass the audit.
///
/// # Panics
///
/// Panics only if fixture creation fails or an equal graph is refused.
///
/// ´claim:cli:the-graph-census-accepts-an-equal-declaration´
/// ´test:integration:the-graph-census-accepts-an-equal-declaration´
#[test]
fn the_graph_census_accepts_an_equal_declaration() {
    let fixture = fixture();
    let output = census(&fixture, "^never$");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("census JSON");
    assert_eq!(report["tracked"], 6);
    assert_eq!(report["clean"], true);
}

/// A tracked path omitted from Meson's lists is a missing graph path.
///
/// # Panics
///
/// Panics only if fixture creation fails or the omitted path is accepted.
///
/// ´claim:cli:the-graph-census-refuses-an-omitted-tracked-path´
/// ´test:integration:the-graph-census-refuses-an-omitted-tracked-path´
#[test]
fn the_graph_census_refuses_an_omitted_tracked_path() {
    let fixture = fixture();
    let list = fs::read_to_string(&fixture.declared).expect("list");
    fs::write(&fixture.declared, list.replace("doc.md\n", "")).expect("short list");
    assert_refusal(&census(&fixture, "^never$"), "missing_path");
}

/// Stale declarations and exclusions are each rejected.
///
/// # Panics
///
/// Panics only if fixture creation fails or a stale list path is accepted.
///
/// ´claim:cli:the-graph-census-refuses-stale-list-paths´
/// ´test:integration:the-graph-census-refuses-stale-list-paths´
#[test]
fn the_graph_census_refuses_stale_list_paths() {
    let fixture = fixture();
    let mut list = fs::read_to_string(&fixture.declared).expect("list");
    list.push_str("gone.md\n");
    fs::write(&fixture.declared, list).expect("stale declaration");
    fs::write(&fixture.excluded, "another-gone.md\n").expect("stale exclusion");
    let output = census(&fixture, "^never$");
    assert_refusal(&output, "stale_declared_path");
    assert_refusal(&output, "stale_excluded_path");
}

/// Duplicate declarations and pattern overlaps refuse the same list.
///
/// # Panics
///
/// Panics only if fixture creation fails or either ambiguity is accepted.
///
/// ´claim:cli:the-graph-census-refuses-duplicate-and-patterned-declarations´
/// ´test:integration:the-graph-census-refuses-duplicate-and-patterned-declarations´
#[test]
fn the_graph_census_refuses_duplicate_and_patterned_declarations() {
    let fixture = fixture();
    let mut list = fs::read_to_string(&fixture.declared).expect("list");
    list.push_str("doc.md\n");
    fs::write(&fixture.declared, list).expect("duplicate declaration");
    let output = census(&fixture, "^doc[.]md$");
    assert_refusal(&output, "duplicate_declared_path");
    assert_refusal(&output, "declared_pattern_overlap");
}

/// The tracked-exclusive reader exposes a checkout path omitted by Git.
///
/// # Panics
///
/// Panics only if fixture creation fails or an untracked path is accepted.
///
/// ´claim:cli:the-graph-census-refuses-an-untracked-checkout-path´
/// ´test:integration:the-graph-census-refuses-an-untracked-checkout-path´
#[test]
fn the_graph_census_refuses_an_untracked_checkout_path() {
    let fixture = fixture();
    write(fixture.root.path(), "probe.txt", "stray\n");
    assert_refusal(&census(&fixture, "^never$"), "untracked_path");
}

/// A tracked symlink carries a forbidden index mode.
///
/// # Panics
///
/// Panics only if fixture creation fails or a tracked symlink is accepted.
///
/// ´claim:cli:the-graph-census-refuses-a-tracked-symlink´
/// ´test:integration:the-graph-census-refuses-a-tracked-symlink´
#[cfg(unix)]
#[test]
fn the_graph_census_refuses_a_tracked_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = fixture();
    symlink("doc.md", fixture.root.path().join("link")).expect("symlink");
    git(fixture.root.path(), &["add", "-f", "link"]);
    let mut list = fs::read_to_string(&fixture.declared).expect("list");
    list.push_str("link\n");
    fs::write(&fixture.declared, list).expect("declared link");
    assert_refusal(&census(&fixture, "^never$"), "invalid_tracked_mode");
}

/// A required contract accepts tracked plain files, a matching pattern and a
/// populated directory while ignoring optional rows.
///
/// # Panics
///
/// Panics only if fixture creation or the accepted census and build report fail.
///
/// ´claim:cli:the-graph-census-accepts-required-contract-rows´
/// ´test:integration:the-graph-census-accepts-required-contract-rows´
#[test]
fn the_graph_census_accepts_required_contract_rows() {
    let fixture = fixture();
    write(fixture.root.path(), "has space.md", "A spaced path.\n");
    git(fixture.root.path(), &["add", "-f", "has space.md"]);
    let mut declared = fs::read_to_string(&fixture.declared).expect("declared list");
    declared.push_str("has space.md\n");
    fs::write(&fixture.declared, declared).expect("extended declared list");

    let required = census_with_required(&fixture, "census-required-ok.toml");
    assert_eq!(required.status.code(), Some(0), "{:?}", required.stderr);
    let contract =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/census-required-ok.toml");
    let report_path = fixture.outputs.path().join("census.json");
    let stamp_path = fixture.outputs.path().join("census.stamp");
    let build = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["census", "--root"])
        .arg(fixture.root.path())
        .arg("--declared")
        .arg(&fixture.declared)
        .arg("--excluded")
        .arg(&fixture.excluded)
        .args(["--pattern", "^never$", "--required"])
        .arg(contract)
        .arg("--write-report")
        .arg(&report_path)
        .arg("--write-stamp")
        .arg(&stamp_path)
        .output()
        .expect("run census build mode");
    assert_eq!(build.status.code(), Some(0), "{:?}", build.stderr);
    assert_eq!(build.stdout, [] as [u8; 0]);
    assert!(report_path.is_file());
    assert!(stamp_path.is_file());
}

/// Missing required plain files and directories receive the contract path in a refusal.
///
/// # Panics
///
/// Panics only if fixture creation fails or a missing path is accepted.
///
/// ´claim:cli:the-graph-census-refuses-missing-required-contract-paths´
/// ´test:integration:the-graph-census-refuses-missing-required-contract-paths´
#[test]
fn the_graph_census_refuses_missing_required_contract_paths() {
    let fixture = fixture();
    assert_refusal_path(
        &census_with_required(&fixture, "census-required-missing.toml"),
        "missing_required_path",
        "absent.txt",
    );
    assert_refusal_path(
        &census_with_required(&fixture, "census-required-directory-missing.toml"),
        "missing_required_path",
        "gone/",
    );
}

/// A required pattern without a tracked regular match is refused at its contract path.
///
/// # Panics
///
/// Panics only if fixture creation fails or an unmatched pattern is accepted.
///
/// ´claim:cli:the-graph-census-refuses-unmatched-required-contract-patterns´
/// ´test:integration:the-graph-census-refuses-unmatched-required-contract-patterns´
#[test]
fn the_graph_census_refuses_unmatched_required_contract_patterns() {
    let fixture = fixture();
    assert_refusal_path(
        &census_with_required(&fixture, "census-required-unmatched.toml"),
        "unmatched_required_pattern",
        "plans/*.md",
    );
}

/// Stars outside the last component and multiple stars in one pattern are refused.
///
/// # Panics
///
/// Panics only if fixture creation fails or an invalid pattern is accepted.
///
/// ´claim:cli:the-graph-census-refuses-invalid-required-contract-patterns´
/// ´test:integration:the-graph-census-refuses-invalid-required-contract-patterns´
#[test]
fn the_graph_census_refuses_invalid_required_contract_patterns() {
    let fixture = fixture();
    assert_refusal_path(
        &census_with_required(&fixture, "census-required-invalid-pattern.toml"),
        "invalid_required_pattern",
        "plans*/extra.md",
    );
    let contract = fixture.outputs.path().join("multiple-stars.toml");
    fs::write(&contract, "version = [1, 0, 0]\n[[paths]]\npath = \"a**.md\"\npurpose = \"Too many stars.\"\nrequired = true\ntemplate = false\n").expect("multiple star contract");
    assert_refusal_path(
        &census_with_required_path(&fixture, &contract),
        "invalid_required_pattern",
        "a**.md",
    );
}

/// Malformed TOML, missing row fields and unknown contract keys are refused.
///
/// # Panics
///
/// Panics only if fixture creation fails or an invalid contract is accepted.
///
/// ´claim:cli:the-graph-census-refuses-invalid-required-contracts´
/// ´test:integration:the-graph-census-refuses-invalid-required-contracts´
#[test]
fn the_graph_census_refuses_invalid_required_contracts() {
    let fixture = fixture();
    for file in [
        "census-required-malformed-path.toml",
        "census-required-malformed-row.toml",
        "census-required-malformed-toml.toml",
    ] {
        assert_refusal(
            &census_with_required(&fixture, file),
            "invalid_required_list",
        );
    }
    let contract = fixture.outputs.path().join("unknown-key.toml");
    fs::write(&contract, "version = [1, 0, 0]\nunknown = true\n[[paths]]\npath = \"doc.md\"\npurpose = \"Present file.\"\nrequired = true\ntemplate = true\n").expect("unknown top-level key");
    assert_refusal(
        &census_with_required_path(&fixture, &contract),
        "invalid_required_list",
    );
    fs::write(&contract, "version = [1, 0, 0]\n[[paths]]\npath = \"doc.md\"\npurpose = \"Present file.\"\nrequired = true\ntemplate = true\nunknown = true\n").expect("unknown row key");
    assert_refusal(
        &census_with_required_path(&fixture, &contract),
        "invalid_required_list",
    );
}
