//! Built-binary replay metadata, deterministic mapping and no-write refusals.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Original Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_COMMITTER_NAME", "Original Committer")
        .env("GIT_COMMITTER_EMAIL", "committer@example.com")
        .env("GIT_AUTHOR_DATE", "946684700 +0530")
        .env("GIT_COMMITTER_DATE", "946684800 -0730")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn line(root: &Path, args: &[&str]) -> String {
    String::from_utf8(git(root, args))
        .expect("git text")
        .trim_end()
        .into()
}

fn pack(source: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-pack"));
    command.current_dir(source);
    command
}

const MANIFEST: &str = r#"namespace = "org.superloop-tools.public-set"
version = [1, 0, 0]
[include]
rows = [{pattern = "public-set.toml"}, {pattern = ".linter/"}, {pattern = "LICENSE-CODE", reserved = true}, {pattern = "LICENSE-DOCS", reserved = true}, {pattern = "docs/"}, {pattern = "public/"}]
[exclude]
rows = [{pattern = "private.txt", reason = "Private fixture."}]
[public]
name = "replay-fixture"
readme = "docs/readme.txt"
licence_code = "LICENSE-CODE"
licence_docs = "LICENSE-DOCS"
"#;

struct Fixture {
    _temporary: tempfile::TempDir,
    source: PathBuf,
    out: PathBuf,
    second: PathBuf,
    burn: PathBuf,
    scratch: PathBuf,
    public_root: String,
    base: String,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("fixture");
        let source = temporary.path().join("source");
        let out = temporary.path().join("public");
        let second = temporary.path().join("second");
        let burn = temporary.path().join("burn.toml");
        let scratch = temporary.path().join("scratch");
        fs::create_dir_all(source.join("docs")).expect("docs");
        fs::create_dir_all(source.join("public")).expect("public");
        fs::create_dir(&scratch).expect("scratch");
        declare_linter(&source);
        for (path, content) in [
            ("public-set.toml", MANIFEST),
            ("LICENSE-CODE", "Code licence\n"),
            ("LICENSE-DOCS", "Document licence\n"),
            ("docs/readme.txt", "Public readme\n"),
            ("public/file.txt", "ordinary\n"),
            ("private.txt", "private\n"),
        ] {
            fs::write(source.join(path), content).expect("fixture bytes");
        }
        fs::write(
            &burn,
            "[[values]]\nvalue = \"forbidden-value\"\nmatch = \"substring\"\n",
        )
        .expect("burn register");
        git(&source, &["init", "-q", "--initial-branch=main"]);
        git(&source, &["add", "."]);
        git(
            &source,
            &["commit", "-q", "--no-gpg-sign", "-m", "Initial fixture"],
        );
        git(&source, &["tag", "base"]);
        let base = line(&source, &["rev-parse", "HEAD"]);
        let result = pack(&source)
            .args([
                "cut",
                "--tag",
                "base",
                "--manifest",
                "public-set.toml",
                "--author",
                "Publisher <publisher@example.com>",
                "--out",
            ])
            .arg(&out)
            .arg("--burn-register")
            .arg(&burn)
            .arg("--linter")
            .arg(
                std::env::var_os("PUBLIC_PACK_TEST_LINTER")
                    .expect("PUBLIC_PACK_TEST_LINTER must name the built real linter"),
            )
            .output()
            .expect("cut");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        git(&out, &["checkout", "-q", "-b", "development"]);
        let public_root = line(&out, &["rev-parse", "HEAD"]);
        git(
            temporary.path(),
            &[
                "clone",
                "--no-local",
                out.to_str().expect("out"),
                second.to_str().expect("second"),
            ],
        );
        Self {
            _temporary: temporary,
            source,
            out,
            second,
            burn,
            scratch,
            public_root,
            base,
        }
    }

    fn commit(&self, path: &str, content: &str, message: &str) -> String {
        fs::write(self.source.join(path), content).expect("change");
        git(&self.source, &["add", "."]);
        git(
            &self.source,
            &[
                "commit",
                "-q",
                "--no-gpg-sign",
                "--cleanup=verbatim",
                "-m",
                message,
            ],
        );
        line(&self.source, &["rev-parse", "HEAD"])
    }

    fn replay(&self, out: &Path) -> Command {
        let linter = std::env::var_os("PUBLIC_PACK_TEST_LINTER")
            .expect("PUBLIC_PACK_TEST_LINTER must name the built real linter");
        let mut command = pack(&self.source);
        command
            .args([
                "replay",
                "--since",
                &self.base,
                "--tag",
                "HEAD",
                "--manifest",
                "public-set.toml",
                "--public-root",
                &self.public_root,
                "--out",
            ])
            .arg(out)
            .arg("--previous")
            .arg(out)
            .arg("--burn-register")
            .arg(&self.burn)
            .arg("--linter")
            .arg(linter)
            .env("TMPDIR", &self.scratch);
        command
    }

    fn unchanged_refusal(&self, expected: &str) {
        let refs = git(&self.out, &["show-ref"]);
        let objects = git(&self.out, &["count-objects", "-v"]);
        let contents = git(&self.out, &["status", "--porcelain=v1", "--ignored"]);
        let output = self.replay(&self.out).output().expect("replay");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(3), "{text}");
        assert!(text.contains(expected), "{text}");
        assert_eq!(git(&self.out, &["show-ref"]), refs);
        assert_eq!(git(&self.out, &["count-objects", "-v"]), objects);
        assert_eq!(
            git(&self.out, &["status", "--porcelain=v1", "--ignored"]),
            contents
        );
        assert_eq!(fs::read_dir(&self.scratch).expect("scratch").count(), 0);
    }
}

fn report(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("report text");
    serde_json::from_str(text.lines().next().expect("report line")).expect("JSON")
}

/// Original metadata survives a deterministic replay and excluded-only commits skip.
///
/// # Panics
/// Panics only if fixture IO fails or replay violates its metadata contract.
/// ´test:integration:replay-preserves-metadata-readme-and-deterministic-mapping´
#[test]
fn replay_preserves_metadata_readme_and_deterministic_mapping() {
    let fixture = Fixture::new();
    fixture.commit("private.txt", "excluded change\n", "Excluded only\n");
    let readme = fixture.commit(
        "docs/readme.txt",
        "New public readme\n",
        "Readme subject\n\nbody  \n\n",
    );
    let ordinary = fixture.commit(
        "public/file.txt",
        "ordinary change\n",
        "Ordinary subject\n\nmessage bytes  \n\n",
    );
    let first = report(fixture.replay(&fixture.out).output().expect("replay"));
    let second = report(fixture.replay(&fixture.second).output().expect("replay"));
    assert_eq!(first["mapping"], second["mapping"]);
    assert_eq!(first["final_tip"], second["final_tip"]);
    assert_eq!(first["mapping"][0]["outcome"], "skipped");
    assert_eq!(first["mapping"][0]["public_commit"], fixture.public_root);
    for (index, source) in [(1, readme), (2, ordinary)] {
        let public = first["mapping"][index]["public_commit"]
            .as_str()
            .expect("mapped commit");
        let original = git(&fixture.source, &["cat-file", "commit", &source]);
        let written = git(&fixture.out, &["cat-file", "commit", public]);
        for prefix in [b"author ".as_slice(), b"committer ".as_slice()] {
            assert_eq!(
                original
                    .split(|byte| *byte == b'\n')
                    .find(|row| row.starts_with(prefix)),
                written
                    .split(|byte| *byte == b'\n')
                    .find(|row| row.starts_with(prefix))
            );
        }
        let message = |bytes: Vec<u8>| {
            let start = bytes
                .windows(2)
                .position(|pair| pair == b"\n\n")
                .expect("message");
            bytes[start + 2..].to_vec()
        };
        assert_eq!(message(original), message(written));
    }
    assert_eq!(
        fs::read(fixture.out.join("README.md")).expect("README"),
        b"New public readme\n"
    );
    assert_eq!(line(&fixture.out, &["rev-list", "--count", "HEAD"]), "3");
    assert_eq!(line(&fixture.out, &["status", "--porcelain"]), "");
    assert_eq!(fs::read_dir(&fixture.scratch).expect("scratch").count(), 0);
}

/// Burn checks include messages even when a source commit would be skipped.
///
/// # Panics
/// Panics only if fixture IO fails or a refusal writes output or leaks a value.
/// ´test:integration:private-message-refuses-before-output-writes´
#[test]
fn private_message_refuses_before_output_writes() {
    let fixture = Fixture::new();
    fixture.commit("public/file.txt", "safe change\n", "Safe change\n");
    fixture.commit("private.txt", "excluded change\n", "forbidden-value\n");
    fixture.unchanged_refusal("source ordinal 2 field message match kind substring");
    let output = fixture.replay(&fixture.out).output().expect("replay");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("forbidden-value"));
}

/// Merge ranges never partially replay their linear prefix.
///
/// # Panics
/// Panics only if fixture IO fails or a merge is accepted.
/// ´test:integration:merge-range-refuses-before-output-writes´
#[test]
fn merge_range_refuses_before_output_writes() {
    let fixture = Fixture::new();
    git(&fixture.source, &["checkout", "-q", "-b", "side"]);
    fixture.commit("private.txt", "side\n", "Side\n");
    git(&fixture.source, &["checkout", "-q", "main"]);
    fixture.commit("public/file.txt", "main\n", "Main\n");
    git(
        &fixture.source,
        &[
            "merge",
            "--no-gpg-sign",
            "--no-ff",
            "-m",
            "Merge fixture",
            "side",
        ],
    );
    fixture.unchanged_refusal("merge or root commit");
}

/// Source, output and required input guards refuse without changing objects or refs.
///
/// # Panics
/// Panics only if fixture IO fails or an invalid replay is accepted.
/// ´test:integration:replay-required-inputs-and-destination-are-guarded´
#[test]
fn replay_required_inputs_and_destination_are_guarded() {
    let mut fixture = Fixture::new();
    fixture.unchanged_refusal("nothing to replay");
    fixture.commit("public/file.txt", "changed\n", "Change\n");
    git(&fixture.out, &["checkout", "-q", "main"]);
    fixture.unchanged_refusal("checked out on development");
    git(&fixture.out, &["checkout", "-q", "development"]);
    fs::write(fixture.out.join("dirty"), "dirty").expect("dirty");
    fixture.unchanged_refusal("must be clean");
    fs::remove_file(fixture.out.join("dirty")).expect("clean");
    let original_root = fixture.public_root.clone();
    git(
        &fixture.out,
        &[
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-m",
            "Wrong root",
        ],
    );
    fixture.unchanged_refusal("public-root mismatch: expected");
    git(&fixture.out, &["reset", "--hard", &original_root]);
    fs::remove_file(&fixture.burn).expect("remove register");
    fixture.unchanged_refusal("unreadable unpublished-label burn register");
    fs::write(
        &fixture.burn,
        "[[values]]\nvalue = \"forbidden-value\"\nmatch = \"substring\"\n",
    )
    .expect("register");
    git(&fixture.source, &["rm", "LICENSE-CODE"]);
    git(
        &fixture.source,
        &["commit", "--no-gpg-sign", "-m", "Missing licence"],
    );
    fixture.unchanged_refusal("licence");
    fixture.base = line(&fixture.source, &["rev-parse", "HEAD"]);
    fixture.unchanged_refusal("nothing to replay");
}

/// Final policy spans older manifest schemas and a README source introduced later.
///
/// # Panics
/// Panics only if fixture IO fails or historical projection violates its contract.
/// ´test:integration:final-policy-spans-manifest-schema-and-readme-introduction´
#[test]
fn final_policy_spans_manifest_schema_and_readme_introduction() {
    let fixture = Fixture::new();
    let final_manifest = MANIFEST.replace(
        "{pattern = \"private.txt\", reason = \"Private fixture.\"}",
        "{pattern = \"private.txt\", reason = \"Private fixture.\"}, {pattern = \"README.md\", reason = \"Replaced by public source.\"}",
    );
    let historical_manifest = final_manifest.replace("name = \"replay-fixture\"\n", "");
    fs::remove_file(fixture.source.join("docs/readme.txt")).expect("remove source");
    fs::write(fixture.source.join("README.md"), "Early root README\n").expect("root README");
    fixture.commit(
        "public-set.toml",
        &historical_manifest,
        "Older manifest schema\n",
    );
    fixture.commit(
        "public/file.txt",
        "early public change\n",
        "Before README source\n",
    );
    fixture.commit(
        "docs/readme.txt",
        "Replacement README\n",
        "Introduce README source\n",
    );
    fixture.commit(
        "public-set.toml",
        &final_manifest,
        "Final manifest policy\n",
    );
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    assert_eq!(result["readme_fallback_commits"], 2);
    for (index, expected) in [
        "Early root README\n",
        "Early root README\n",
        "Replacement README\n",
        "Replacement README\n",
    ]
    .iter()
    .enumerate()
    {
        let row = &result["mapping"][index];
        assert_eq!(row["readme_fallback"], index < 2);
        let oid = row["public_commit"].as_str().expect("mapped commit");
        assert_eq!(
            git(&fixture.out, &["show", &format!("{oid}:README.md")]),
            expected.as_bytes()
        );
    }
    assert_eq!(result["mapping"][3]["outcome"], "skipped");
}

/// Accepted base drift is carried by the first commit and recorded explicitly.
///
/// # Panics
/// Panics only if fixture IO fails or drift handling violates its contract.
/// ´test:integration:generated-drift-requires-acceptance´
#[test]
fn generated_drift_requires_acceptance() {
    let mut fixture = Fixture::new();
    fixture.commit("private.txt", "excluded change\n", "Excluded only\n");
    fs::write(fixture.out.join("README.md"), "Old generated README\n").expect("drift");
    git(&fixture.out, &["add", "."]);
    git(
        &fixture.out,
        &["commit", "--no-gpg-sign", "-m", "Published drift"],
    );
    fixture.public_root = line(&fixture.out, &["rev-parse", "HEAD"]);
    fixture.unchanged_refusal("generated drift: README.md");
    let result = report(
        fixture
            .replay(&fixture.out)
            .arg("--accept-generated-drift")
            .output()
            .expect("replay"),
    );
    assert_eq!(result["generated_drift"], serde_json::json!(["README.md"]));
    assert_eq!(result["mapping"][0]["outcome"], "replayed");
    assert_eq!(
        fs::read(fixture.out.join("README.md")).expect("README"),
        b"Public readme\n"
    );
}

/// Historical owners and final selection policy are read from their own commits.
///
/// # Panics
/// Panics only if fixture IO fails or replay reads policy from the wrong commit.
/// ´test:integration:historical-owners-and-final-policy-bound-each-projection´
#[test]
fn historical_owners_and_final_policy_bound_each_projection() {
    let fixture = Fixture::new();
    let owners = fs::read_to_string(fixture.source.join(".linter/owners.toml")).expect("owners");
    fixture.commit("public/file.txt", "ordinary first\n", "First public edit\n");
    fixture.commit(
        ".linter/owners.toml",
        &owners.replace("name = \"fixture\"", "name = \"renamed\""),
        "Rename partition\n",
    );
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    let first = result["mapping"][0]["public_commit"]
        .as_str()
        .expect("first");
    assert!(
        line(
            &fixture.out,
            &["show", &format!("{first}:.linter/owners.toml")]
        )
        .contains("name = \"fixture\"")
    );
    assert!(
        fs::read_to_string(fixture.out.join(".linter/owners.toml"))
            .expect("owners")
            .contains("name = \"renamed\"")
    );

    let mut fixture = Fixture::new();
    fixture.commit("public/retired.txt", "Once public\n", "Historical file\n");
    let policy = MANIFEST.replace("{pattern = \"public/\"}", "{pattern = \"public/file.txt\"}")
        .replace("[exclude]\nrows = [", "[exclude]\nrows = [{pattern = \"public/retired.txt\", reason = \"Retired public path.\"}, ");
    fixture.commit("public-set.toml", &policy, "Retire historical file\n");
    // The projected base inventory is unchanged: selectors become exact public rows.
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    assert_eq!(result["mapping"][0]["outcome"], "skipped");
    assert!(!fixture.out.join("public/retired.txt").exists());
    fixture.base = line(&fixture.source, &["rev-parse", "HEAD"]);
    fixture.unchanged_refusal("nothing to replay");
}

/// Blob, path and author burns and unsupported entries all refuse in preflight.
///
/// # Panics
/// Panics only if fixture IO fails or a forbidden candidate changes public history.
/// ´test:integration:projected-fields-and-unsupported-entries-refuse-before-output-writes´
#[test]
fn projected_fields_and_unsupported_entries_refuse_before_output_writes() {
    for (path, content, field) in [
        ("public/file.txt", "forbidden-value\n", "blob"),
        ("public/forbidden-value.txt", "safe\n", "path"),
    ] {
        let fixture = Fixture::new();
        fixture.commit(path, content, "Candidate\n");
        fixture.unchanged_refusal(&format!(
            "source ordinal 1 field {field} match kind substring"
        ));
    }
    let fixture = Fixture::new();
    git(
        &fixture.source,
        &[
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "--author",
            "forbidden-value <author@example.com>",
            "-m",
            "Candidate",
        ],
    );
    fixture.unchanged_refusal("source ordinal 1 field author.name match kind substring");
    let fixture = Fixture::new();
    git(
        &fixture.source,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            &fixture.base,
            "public/submodule",
        ],
    );
    git(
        &fixture.source,
        &["commit", "--no-gpg-sign", "-m", "Unsupported entry"],
    );
    fs::create_dir(fixture.source.join("public/submodule")).expect("unpopulated submodule");
    // A populated submodule is unnecessary: the index records the unsupported mode.
    fixture.unchanged_refusal("public projection refused");
}

/// Citation resolution uses each historical definition rather than the tip's text.
///
/// # Panics
/// Panics only if fixture IO fails or historical citation snapshots are incorrect.
/// ´test:integration:historical-citations-use-their-own-commit´
#[test]
fn historical_citations_use_their_own_commit() {
    let fixture = Fixture::new();
    let manifest = MANIFEST.replace(
        "[exclude]\nrows = [",
        "[exclude]\nrows = [{pattern = \"private.md\", reason = \"Private definition.\"}, ",
    );
    fs::write(fixture.source.join("public-set.toml"), manifest).expect("manifest");
    fs::write(
        fixture.source.join("private.md"),
        "# Private definition · `sec:private:earlier`\n",
    )
    .expect("private definition");
    fixture.commit(
        "docs/guide.md",
        "# Public guide · `guide:replay:public-guide`\n\nSee (`sec:private:earlier`).\n",
        "Earlier citation\n",
    );
    fs::write(
        fixture.source.join("private.md"),
        "# Private definition · `sec:private:later`\n",
    )
    .expect("later definition");
    fixture.commit(
        "docs/guide.md",
        "# Public guide · `guide:replay:public-guide`\n\nSee (`sec:private:later`).\n",
        "Later citation\n",
    );
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    let first = result["mapping"][0]["public_commit"]
        .as_str()
        .expect("first");
    let register = line(
        &fixture.out,
        &[
            "show",
            &format!("{first}:docs/public/unpublished-labels.toml"),
        ],
    );
    assert!(register.contains("sec:private:earlier"), "{register}");
    assert!(!register.contains("sec:private:later"), "{register}");
    let register = fs::read_to_string(fixture.out.join("docs/public/unpublished-labels.toml"))
        .expect("register");
    assert!(register.contains("sec:private:later"), "{register}");
    assert!(!fixture.out.join("private.md").exists());
}

fn declare_linter(source: &Path) {
    let declaration = source.join(".linter");
    fs::create_dir(&declaration).expect("declaration");
    for (name, body) in [
        (
            "owners",
            "root_owner = \"PROJECTA\"\nowners = [\"PROJECTA\"]\npartitions = [{name = \"fixture\", owner = \"PROJECTA\", pattern = '*VCHAR'}]\nmay_cite = []\n",
        ),
        ("environments", "environments = []\n"),
        ("shape", "universe = \"git-tracked\"\nignore = []\n"),
        (
            "policies",
            "policies = [{owner = \"PROJECTA\", policy = \"public-pack.values-absent\"}, {owner = \"PROJECTA\", policy = \"labels.mints-well-formed\"}]\n",
        ),
        (
            "lists",
            "[PROJECTA.\"public-pack.values-absent\"]\npath_counts = []\n[PROJECTA.\"labels.mints-well-formed\"]\nallowances = []\n",
        ),
    ] {
        let namespace = if name == "lists" {
            "class.linter"
        } else {
            "org.example.linter"
        };
        fs::write(
            declaration.join(format!("{name}.toml")),
            format!("namespace = \"{namespace}.{name}\"\nversion = [1, 0, 0]\n{body}"),
        )
        .expect("declaration bytes");
    }
    fs::write(declaration.join("policy-public-pack-values.toml"), "namespace = \"class.linter.policy.public-pack.values-absent\"\nversion = [1, 0, 0]\n[owners.PROJECTA]\nactivation = \"public-pack\"\nsurface = \"*VCHAR\"\nvalues = \"local/burn-register.toml\"\nexclude = '%s\"local\" [ \"/\" *VCHAR ]'\n").expect("burn policy");
}
