//! Publication classification exercised through the installed command boundary.
//!
//! # Test index
//!
//! | Test | Area | Claim |
//! |------|------|-------|
//! | [`publication_classification_is_optional_and_complete`] | integration | A missing manifest is inert; a declared set judges unknown files and dead rows. # Panics Panics only if fixture IO fails or the command violates the classification contract. |

use std::fs;
use std::path::Path;
use std::process::Command;

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("fixture");
    fs::create_dir(root.path().join(".linter")).expect("surface");
    for (name, namespace, body) in [
        (
            "shape",
            "org.example.linter.shape",
            "universe = \"git-tracked\"\nignore = []\n",
        ),
        (
            "owners",
            "org.example.linter.owners",
            "root_owner = \"ROOT\"\nowners = [\"ROOT\"]\npartitions = [{ name = \"all\", owner = \"ROOT\", pattern = '*VCHAR' }]\nmay_cite = []\n",
        ),
        (
            "environments",
            "org.example.linter.environments",
            "environments = []\nextensions = []\nreserved_kinds = []\nreserved_extensions = []\n",
        ),
        ("policies", "org.example.linter.policies", "policies = []\n"),
        ("lists", "class.linter.lists", ""),
    ] {
        fs::write(
            root.path().join(format!(".linter/{name}.toml")),
            format!("namespace = {namespace:?}\nversion = [1, 0, 0]\n{body}"),
        )
        .expect("declaration");
    }
    git(root.path(), &["init", "-q"]);
    git(root.path(), &["add", "."]);
    root
}

fn check(root: &Path) -> (bool, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_superloop-lint"))
        .args(["check", "--root"])
        .arg(root)
        .output()
        .expect("linter");
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "report: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.success(), report)
}

const MANIFEST: &str = r#"namespace = "org.superloop-tools.public-set"
version = [1, 0, 0]
[include]
rows = [{ pattern = "public-set.toml" }, { pattern = "public/" }]
[exclude]
rows = [{ pattern = ".linter/", reason = "Private declaration." }]
[reserved]
rows = [{ pattern = "future/", reason = "Private future material." }]
[public]
name = "fixture-repository"
readme = "public/readme.txt"
licence_code = "LICENSE-CODE"
licence_docs = "LICENSE-DOCS"
"#;

/// A missing manifest is inert; a declared set judges unknown files and dead rows.
///
/// # Panics
/// Panics only if fixture IO fails or the command violates the classification contract.
/// ´claim:integration:publication-classification-is-optional-and-complete´
/// ´test:integration:publication-classification-is-optional-and-complete´
#[test]
fn publication_classification_is_optional_and_complete() {
    let root = fixture();
    let (success, report) = check(root.path());
    assert!(success, "{report}");
    assert!(report.get("public_set").is_none());
    fs::create_dir(root.path().join("public")).expect("public directory");
    fs::write(root.path().join("public/readme.txt"), "public\n").expect("readme");
    fs::write(root.path().join("public-set.toml"), MANIFEST).expect("manifest");
    git(root.path(), &["add", "."]);
    let (success, report) = check(root.path());
    assert!(success, "{report}");
    assert_eq!(
        report["public_set"]["included"]
            .as_array()
            .expect("included")
            .len(),
        2
    );
    for (invalid, detail) in [
        (
            MANIFEST.replace(", reason = \"Private declaration.\"", ""),
            "exclusions require a reason",
        ),
        (format!("unknown = true\n{MANIFEST}"), "unknown field"),
        (
            MANIFEST.replace("org.superloop-tools.public-set", "org.example.public-set"),
            "requires namespace",
        ),
        (
            MANIFEST.replace("version = [1, 0, 0]", "version = [2, 0, 0]"),
            "requires namespace",
        ),
        (
            MANIFEST.replace("LICENSE-DOCS", "LICENSE-CODE"),
            "distinct relative",
        ),
    ]
    .into_iter()
    .chain(["../private", "public/**", "public/[a]"].map(|selector| {
        (
            MANIFEST.replace("pattern = \"public/\"", &format!("pattern = {selector:?}")),
            "invalid public-set row",
        )
    })) {
        fs::write(root.path().join("public-set.toml"), invalid).expect("invalid manifest");
        let (success, report) = check(root.path());
        assert!(!success, "{report}");
        let text = report.to_string();
        assert!(text.contains("\"code\":\"public_set\""), "{text}");
        assert!(text.contains(detail), "{text}");
    }
    fs::write(root.path().join("unknown.txt"), "unknown\n").expect("unknown");
    fs::write(
        root.path().join("public-set.toml"),
        MANIFEST.replace("pattern = \"public/\"", "pattern = \"absent/\""),
    )
    .expect("dead row");
    git(root.path(), &["add", "."]);
    let (success, report) = check(root.path());
    assert!(!success, "{report}");
    let text = report.to_string();
    assert!(
        text.contains("unclassified tracked file: unknown.txt"),
        "{text}"
    );
    assert!(text.contains("dead manifest row: absent/"), "{text}");
    assert!(!text.contains("dead manifest row: future/"), "{text}");
    fs::write(
        root.path().join("public-set.toml"),
        MANIFEST.replace(
            "pattern = \"public/\"",
            "pattern = \"public/\" }, { pattern = \"public/*.txt\"",
        ),
    )
    .expect("overlap");
    let (_, report) = check(root.path());
    assert!(
        report
            .to_string()
            .contains("multiply classified tracked file: public/readme.txt")
    );
    fs::remove_file(root.path().join("public-set.toml")).expect("remove manifest");
    std::os::unix::fs::symlink("missing.toml", root.path().join("public-set.toml"))
        .expect("dangling manifest");
    let (success, report) = check(root.path());
    assert!(!success);
    assert!(
        report
            .to_string()
            .contains("manifest must be a regular file")
    );
}
