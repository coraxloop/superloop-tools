//! Built-binary cut and replay contracts, deterministic mapping and no-write refusals.

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
unpublished = "docs/public/unpublished-labels.toml"
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
        let result: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
        let summary = text
            .lines()
            .find(|line| line.starts_with("replay outcome="))
            .expect("summary");
        let (_, entries) = summary
            .rsplit_once(" pre-existing=")
            .expect("summary evidence");
        let entries: serde_json::Value = serde_json::from_str(entries).expect("match evidence");
        assert_eq!(entries, result["pre-existing"]);
        let validation = &result["validation"];
        assert!(
            validation["current"]["check"]
                .as_str()
                .is_some_and(|check| !check.is_empty()),
            "{text}"
        );
        let saved = Path::new(
            validation["report_path"]
                .as_str()
                .expect("private report path"),
        );
        assert!(saved.starts_with(&self.scratch));
        let saved = fs::read_to_string(saved).expect("retained private report");
        assert!(saved.contains(expected));
        assert!(!saved.contains("forbidden-value"));
    }
}

/// Unparseable public metadata retains an input context and leaves the output untouched.
///
/// # Panics
/// Panics only if fixture IO fails or the refusal context is incorrect.
/// ´test:integration:public-root-metadata-refusal-context´
#[test]
fn public_root_metadata_refusal_context() {
    let mut fixture = Fixture::new();
    fixture.commit("public/file.txt", "changed\n", "Public edit\n");
    let original = git(&fixture.out, &["cat-file", "commit", &fixture.public_root]);
    let malformed = String::from_utf8(original).expect("commit text").replacen(
        "\n\n",
        "\nunsupported metadata\n\n",
        1,
    );
    let input = fixture.scratch.join("commit");
    fs::write(&input, malformed).expect("malformed commit");
    fixture.public_root = line(
        &fixture.out,
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            input.to_str().expect("input"),
        ],
    );
    git(&fixture.out, &["reset", "--hard", &fixture.public_root]);
    fixture.unchanged_refusal("unsupported commit header");
    fixture.unchanged_refusal("check=inputs source ordinal=0");
    fixture.unchanged_refusal("field=public root metadata");
    fixture.unchanged_refusal(&format!("commit={}", fixture.public_root));
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
        assert_eq!(
            first["mapping"][index]["old_author"],
            first["mapping"][index]["new_author"]
        );
        assert_eq!(
            first["mapping"][index]["old_committer"],
            first["mapping"][index]["new_committer"]
        );
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

/// An explicit author maps both identities while preserving each source date.
///
/// # Panics
/// Panics only if fixture IO fails or mapped commits lose metadata or determinism.
/// ´test:integration:replay-maps-author-and-committer-with-original-dates´
#[test]
fn replay_maps_author_and_committer_with_original_dates() {
    let fixture = Fixture::new();
    fixture.commit("private.txt", "excluded change\n", "Excluded only\n");
    fixture.commit("public/file.txt", "first change\n", "First change\n");
    fixture.commit("docs/readme.txt", "readme change\n", "Second change\n");
    let run = |out: &Path| {
        report(
            fixture
                .replay(out)
                .args(["--author", "Loop Author <loop@example.net>"])
                .output()
                .expect("mapped replay"),
        )
    };
    let first = run(&fixture.out);
    let second = run(&fixture.second);
    assert_eq!(first["mapping"], second["mapping"]);
    assert_eq!(first["final_tip"], second["final_tip"]);
    assert_eq!(first["mapping"][0]["outcome"], "skipped");
    assert!(first["mapping"][0]["new_author"].is_null());
    assert!(first["mapping"][0]["new_committer"].is_null());
    for entry in first["mapping"].as_array().expect("mapping").iter().skip(1) {
        assert_eq!(entry["old_author"]["name"], "Original Author");
        assert_eq!(entry["old_committer"]["name"], "Original Committer");
        let written = String::from_utf8(git(
            &fixture.out,
            &[
                "cat-file",
                "commit",
                entry["public_commit"].as_str().expect("commit"),
            ],
        ))
        .expect("commit bytes");
        for (field, prefix) in [("author", "author "), ("committer", "committer ")] {
            let old = &entry[format!("old_{field}")];
            let new = &entry[format!("new_{field}")];
            assert_eq!(new["name"], "Loop Author");
            assert_eq!(new["email"], "loop@example.net");
            assert_eq!(old["timestamp"], new["timestamp"]);
            assert_eq!(old["timezone"], new["timezone"]);
            let expected = format!(
                "{prefix}Loop Author <loop@example.net> {} {}",
                old["timestamp"].as_str().expect("timestamp"),
                old["timezone"].as_str().expect("timezone")
            );
            assert!(written.lines().any(|line| line == expected));
        }
    }
}

/// Mapping cannot hide source burns or introduce a burned identity, and invalid input refuses.
///
/// # Panics
/// Panics only if fixture IO fails or a refused author mapping writes public output.
/// ´test:integration:replay-author-mapping-retains-source-burn-checks´
#[test]
fn replay_author_mapping_retains_source_burn_checks() {
    for (message, source_author, author, check, field) in [
        (
            "forbidden-value\n",
            None,
            "Loop Author <loop@example.net>",
            "metadata scan",
            "message",
        ),
        (
            "Safe message\n",
            Some("forbidden-value <source@example.net>"),
            "Loop Author <loop@example.net>",
            "metadata scan",
            "author.name",
        ),
        (
            "Safe message\n",
            None,
            "forbidden-value <loop@example.net>",
            "mapped metadata scan",
            "author.name",
        ),
        (
            "Safe message\n",
            None,
            "invalid",
            "inputs",
            "author override",
        ),
    ] {
        let fixture = Fixture::new();
        fixture.commit("public/file.txt", "safe change\n", message);
        if let Some(source_author) = source_author {
            git(
                &fixture.source,
                &[
                    "commit",
                    "--amend",
                    "--no-gpg-sign",
                    "--author",
                    source_author,
                    "-m",
                    message,
                ],
            );
        }
        let refs = git(&fixture.out, &["show-ref"]);
        let objects = git(&fixture.out, &["count-objects", "-v"]);
        let output = fixture
            .replay(&fixture.out)
            .args(["--author", author])
            .output()
            .expect("refused replay");
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(3), "{text}");
        assert!(!text.contains("forbidden-value"));
        let result: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
        assert_eq!(result["validation"]["current"]["check"], check);
        assert_eq!(result["validation"]["current"]["field"], field);
        assert_eq!(git(&fixture.out, &["show-ref"]), refs);
        assert_eq!(git(&fixture.out, &["count-objects", "-v"]), objects);
        assert_eq!(line(&fixture.out, &["status", "--porcelain"]), "");
    }
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
    let text = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
    let context = &result["validation"]["current"];
    assert_eq!(context["check"], "metadata scan");
    assert_eq!(context["ordinal"], 2);
    assert_eq!(
        context["commit"],
        line(&fixture.source, &["rev-parse", "HEAD"])
    );
    assert_eq!(context["field"], "message");
    assert_eq!(context["matcher_kind"], "substring");
    assert_eq!(context["register_kind"], "values");
}

/// Root values remain pre-existing in changed blobs; new values and paths refuse.
///
/// # Panics
/// Panics only if fixture IO fails or replay misclassifies a burn match.
/// ´test:integration:replay-classifies-pre-existing-blobs´
#[test]
fn replay_classifies_pre_existing_blobs() {
    let fixture = Fixture::new();
    fs::write(
        &fixture.burn,
        "[[values]]\nvalue = \"ordinary\"\nmatch = \"identifier\"\n",
    )
    .expect("updated register");
    let first = fixture.commit("private.txt", "changed\n", "Excluded change\n");
    let changed = fixture.commit(
        "public/file.txt",
        "ordinary changed\n",
        "Changed public file\n",
    );
    fixture.commit("public/file.txt", "repaired\n", "Repair\n");
    let output = fixture.replay(&fixture.out).output().expect("replay");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    let summary = text
        .lines()
        .find(|line| line.starts_with("replay since="))
        .expect("summary");
    assert!(summary.contains("pre-existing=["));
    assert!(summary.contains(&first));
    assert!(summary.contains("public/file.txt"));
    assert!(!summary.contains("ordinary"));
    let result = report(output);
    let entries = result["pre-existing"].as_array().expect("matches");
    assert_eq!(entries.len(), 2);
    let matched = &entries[0];
    assert_eq!(matched["ordinal"], 1);
    assert_eq!(matched["commit"], first);
    assert_eq!(matched["path"], "public/file.txt");
    assert_eq!(matched["field"], "blob");
    assert_eq!(matched["matcher_kind"], "identifier");
    assert_eq!(matched["register_kind"], "values");
    assert_eq!(entries[1]["ordinal"], 2);
    assert_eq!(entries[1]["commit"], changed);
    assert_eq!(entries[1]["path"], "public/file.txt");
    assert_eq!(entries[1]["matcher_kind"], "identifier");
    assert_eq!(entries[1]["register_kind"], "values");

    for (path, bytes, value) in [
        ("public/file.txt", "ordinary introduced\n", "introduced"),
        ("public/new.txt", "ordinary\n", "ordinary"),
        ("public/file.txt", "ord\n", "ord"),
    ] {
        let fixture = Fixture::new();
        fs::write(
            &fixture.burn,
            format!("[[values]]\nvalue = \"ordinary\"\nmatch = \"identifier\"\n[[values]]\nvalue = \"{value}\"\nmatch = \"identifier\"\n"),
        )
        .expect("updated register");
        fixture.commit(path, bytes, "Candidate\n");
        fixture.unchanged_refusal("source ordinal 1 field blob match kind identifier");
    }
}

/// Each metadata field is compared with the corresponding parentless public root field.
///
/// # Panics
/// Panics only if fixture IO fails or replay misclassifies metadata.
/// ´test:integration:replay-classifies-pre-existing-metadata´
#[test]
fn replay_classifies_pre_existing_metadata() {
    let mut fixture = Fixture::new();
    git(
        &fixture.out,
        &[
            "commit",
            "--amend",
            "--no-gpg-sign",
            "--reset-author",
            "-m",
            "Shared message",
        ],
    );
    fixture.public_root = line(&fixture.out, &["rev-parse", "HEAD"]);
    assert_eq!(line(&fixture.out, &["rev-list", "--count", "HEAD"]), "1");
    fs::write(&fixture.burn, "[[values]]\nvalue = \"Original\"\nmatch = \"identifier\"\n[[values]]\nvalue = \"example.com\"\nmatch = \"substring\"\n[[values]]\nvalue = \"Shared message\"\nmatch = \"substring\"\n")
        .expect("updated register");
    let first = fixture.commit("public/file.txt", "safe change\n", "Shared message\n");
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    let entries = result["pre-existing"].as_array().expect("matches");
    assert_eq!(entries.len(), 5);
    for (matched, field) in entries.iter().zip([
        "message",
        "author.name",
        "author.email",
        "committer.name",
        "committer.email",
    ]) {
        assert_eq!(matched["ordinal"], 1);
        assert_eq!(matched["commit"], first);
        assert_eq!(matched["field"], field);
        assert_eq!(matched["register_kind"], "values");
        assert!(matched["path"].is_null());
    }
    git(&fixture.out, &["reset", "--hard", &fixture.public_root]);
    fixture.commit(
        "public/file.txt",
        "another safe change\n",
        "Shared message changed\n",
    );
    git(
        &fixture.source,
        &[
            "commit",
            "--amend",
            "--no-gpg-sign",
            "--author",
            "Original Changed <changed@example.com>",
            "-m",
            "Shared message changed",
        ],
    );
    let result = report(
        fixture
            .replay(&fixture.out)
            .output()
            .expect("changed metadata replay"),
    );
    assert_eq!(
        result["pre-existing"].as_array().expect("matches").len(),
        10
    );
    git(&fixture.out, &["reset", "--hard", &fixture.public_root]);
    fs::write(
        &fixture.burn,
        "[[values]]\nvalue = \"introduced-message\"\nmatch = \"substring\"\n",
    )
    .expect("updated register");
    fixture.commit(
        "public/file.txt",
        "last safe change\n",
        "introduced-message\n",
    );
    fixture.unchanged_refusal("source ordinal 3 field message match kind substring");
}

/// Refusals identify manifest, README and projection checks and retain their evidence.
///
/// # Panics
/// Panics only if fixture IO fails or diagnostic context is missing.
/// ´test:integration:replay-refusal-checks-retain-private-evidence´
#[test]
fn replay_refusal_checks_retain_private_evidence() {
    for (path, content, check, field) in [
        (
            "public-set.toml",
            "invalid manifest",
            "manifest",
            "final policy",
        ),
        ("public/file.txt", "forbidden-value", "burn scan", "blob"),
    ] {
        let fixture = Fixture::new();
        let oid = fixture.commit(path, content, "Candidate\n");
        let output = fixture.replay(&fixture.out).output().expect("replay");
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8_lossy(&output.stdout);
        let result: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
        let context = &result["validation"]["current"];
        assert_eq!(context["check"], check, "{text}");
        assert_eq!(context["commit"], oid, "{text}");
        assert_eq!(context["field"], field, "{text}");
        assert_eq!(context["path"], path, "{text}");
        assert!(text.contains("source ordinal="));
        assert!(!text.contains("forbidden-value"));
    }
    let fixture = Fixture::new();
    git(&fixture.source, &["rm", "docs/readme.txt"]);
    git(
        &fixture.source,
        &["commit", "--no-gpg-sign", "-m", "Missing README"],
    );
    fixture.unchanged_refusal("check=licence/README validation");
    fixture.unchanged_refusal("path=docs/readme.txt");

    let fixture = Fixture::new();
    fixture.commit(".linter/owners.toml", "invalid owners", "Invalid owners\n");
    fixture.unchanged_refusal("citation-sites linter refused");
    fixture.unchanged_refusal("field=citation-sites");
}

/// Unclassified paths are redacted before diagnostic evidence is persisted.
///
/// # Panics
/// Panics only if fixture IO fails or diagnostics expose a registered value.
/// ´test:integration:unclassified-path-diagnostics-redact-register-values´
#[test]
fn unclassified_path_diagnostics_redact_register_values() {
    let fixture = Fixture::new();
    fixture.commit(
        "forbidden-value.txt",
        "safe content\n",
        "Unclassified path\n",
    );
    fixture.unchanged_refusal("path=sha256:");
    let output = fixture.replay(&fixture.out).output().expect("replay");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("forbidden-value"));
    let result: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
    let context = &result["validation"]["current"];
    assert_eq!(context["check"], "manifest");
    assert!(
        context["path"]
            .as_str()
            .expect("path")
            .starts_with("sha256:")
    );
    let saved = fs::read_to_string(
        result["validation"]["report_path"]
            .as_str()
            .expect("report path"),
    )
    .expect("private report");
    assert!(!saved.contains("forbidden-value"));
    assert!(saved.contains("sha256:"));
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
    fixture.unchanged_refusal("check=range");
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
    fixture.unchanged_refusal("path=LICENSE-CODE");
    fixture.base = line(&fixture.source, &["rev-parse", "HEAD"]);
    fixture.unchanged_refusal("nothing to replay");
}

/// Missing historical README inputs refuse even when a later source exists.
///
/// # Panics
/// Panics only if fixture IO fails or historical projection violates its contract.
/// ´test:integration:historical-readme-must-exist-at-each-commit´
#[test]
fn historical_readme_must_exist_at_each_commit() {
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
    fixture.unchanged_refusal("check=licence/README validation source ordinal=1");
    fixture.unchanged_refusal("path=docs/readme.txt");
}

/// Historical public READMEs survive a final switch away from an internal root README.
///
/// # Panics
/// Panics only if fixture IO fails or replay publishes the private historical root.
/// ´test:integration:historical-manifest-bounds-readme-transition´
#[test]
fn historical_manifest_bounds_readme_transition() {
    let fixture = Fixture::new();
    let historical = MANIFEST.replace("name = \"replay-fixture\"\n", "").replace(
        "[exclude]\nrows = [",
        "[exclude]\nrows = [{pattern = \"README.md\", reason = \"Internal overview.\"}, ",
    );
    fs::write(fixture.source.join("README.md"), "forbidden-value\n").expect("internal README");
    fixture.commit("public-set.toml", &historical, "Historical policy\n");
    fixture.commit("public/file.txt", "public change\n", "Public edit\n");
    let final_policy = MANIFEST
        .replace("readme = \"docs/readme.txt\"", "readme = \"README.md\"")
        .replace(
            "[include]\nrows = [",
            "[include]\nrows = [{pattern = \"README.md\"}, ",
        );
    fs::write(fixture.source.join("README.md"), "New public README\n").expect("public README");
    fs::remove_file(fixture.source.join("docs/readme.txt")).expect("consumed README source");
    fixture.commit("public-set.toml", &final_policy, "Switch public README\n");
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    assert_eq!(result["mapping"][0]["outcome"], "skipped");
    for row in result["mapping"]
        .as_array()
        .expect("mapping")
        .iter()
        .take(2)
    {
        let oid = row["public_commit"].as_str().expect("public commit");
        assert_eq!(
            git(&fixture.out, &["show", &format!("{oid}:README.md")]),
            b"Public readme\n"
        );
    }
    assert_eq!(
        fs::read(fixture.out.join("README.md")).expect("README"),
        b"New public README\n"
    );
}

/// A declared historical publication name survives a later name change.
///
/// # Panics
/// Panics only if fixture IO fails or replay overwrites a declared name.
/// ´test:integration:historical-publication-name-is-preserved´
#[test]
fn historical_publication_name_is_preserved() {
    let fixture = Fixture::new();
    fixture.commit("public/file.txt", "public change\n", "Public edit\n");
    fixture.commit(
        "public-set.toml",
        &MANIFEST.replace("replay-fixture", "renamed-fixture"),
        "Rename publication\n",
    );
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    let oid = result["mapping"][0]["public_commit"]
        .as_str()
        .expect("commit");
    let historical = git(&fixture.out, &["show", &format!("{oid}:public-set.toml")]);
    assert!(
        String::from_utf8(historical)
            .expect("manifest")
            .contains("name = \"replay-fixture\"")
    );
    let final_manifest = fs::read_to_string(fixture.out.join("public-set.toml")).expect("manifest");
    assert!(final_manifest.contains("name = \"renamed-fixture\""));
}

/// Missing manifests and unclassified historical paths cannot borrow a later policy.
///
/// # Panics
/// Panics only if fixture IO fails or a missing historical input is accepted.
/// ´test:integration:historical-manifest-inputs-are-required´
#[test]
fn historical_manifest_inputs_are_required() {
    let fixture = Fixture::new();
    git(&fixture.source, &["rm", "public-set.toml"]);
    git(
        &fixture.source,
        &["commit", "--no-gpg-sign", "-m", "Missing manifest"],
    );
    fixture.commit("public-set.toml", MANIFEST, "Restore manifest\n");
    fixture.unchanged_refusal("historical manifest missing or unreadable");
    fixture.unchanged_refusal("check=manifest source ordinal=1");

    let fixture = Fixture::new();
    fixture.commit(
        "unclassified.txt",
        "unclassified\n",
        "Unknown historical path\n",
    );
    let final_policy = MANIFEST.replace(
        "[exclude]\nrows = [",
        "[exclude]\nrows = [{pattern = \"unclassified.txt\", reason = \"Private.\"}, ",
    );
    fixture.commit("public-set.toml", &final_policy, "Classify at tip\n");
    fixture.unchanged_refusal("historical policy cannot classify tree");
    fixture.unchanged_refusal("path=unclassified.txt");
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
    fixture.unchanged_refusal("check=drift guard");
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
    fixture.unchanged_refusal("unsupported public tree entry");
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

/// A final declaration does not backfill a historical manifest's missing register declaration.
///
/// # Panics
/// Panics only if fixture IO fails or historical register admission differs from its declaration.
/// ´test:integration:historical-register-declaration-does-not-fall-back´
#[test]
fn historical_register_declaration_does_not_fall_back() {
    for declared_history in [false, true] {
        let fixture = Fixture::new();
        let declared = MANIFEST.replace(
            "[exclude]\nrows = [",
            "[exclude]\nrows = [{pattern = \"private.md\", reason = \"Private definition.\"}, ",
        );
        let historical = if declared_history {
            declared.clone()
        } else {
            declared.replace(
                "unpublished = \"docs/public/unpublished-labels.toml\"\n",
                "",
            )
        };
        fs::write(fixture.source.join("public-set.toml"), historical).expect("historical manifest");
        fs::write(
            fixture.source.join("private.md"),
            "# Private definition · `sec:private:earlier`\n",
        )
        .expect("private definition");
        let guide =
            "# Public guide · `guide:replay:public-guide`\n\nSee (`sec:private:earlier`).\n";
        fixture.commit("docs/guide.md", guide, "Historical citation\n");
        fs::write(
            fixture.source.join("docs/guide.md"),
            format!("{guide}\nFinal text.\n"),
        )
        .expect("final guide");
        fixture.commit("public-set.toml", &declared, "Declare final register\n");
        if declared_history {
            let result = report(fixture.replay(&fixture.out).output().expect("replay"));
            let first = result["mapping"][0]["public_commit"]
                .as_str()
                .expect("first");
            assert!(
                line(
                    &fixture.out,
                    &[
                        "show",
                        &format!("{first}:docs/public/unpublished-labels.toml")
                    ]
                )
                .contains("sec:private:earlier")
            );
        } else {
            fixture.unchanged_refusal("check=projection source ordinal=1");
        }
    }
}

/// Final-bound omissions still produce audited historical citation snapshots.
///
/// # Panics
/// Panics only if fixture IO fails or a removed public target is resurrected.
/// ´test:integration:final-bound-omissions-retain-historical-citation-evidence´
#[test]
fn final_bound_omissions_retain_historical_citation_evidence() {
    let fixture = Fixture::new();
    fs::write(
        fixture.source.join("public/target.md"),
        "# Target · `sec:fixture:retired`\n",
    )
    .expect("target");
    fixture.commit(
        "public/guide.md",
        "# Guide · `guide:fixture:public`\n\nSee (`sec:fixture:retired`).\n",
        "Public reference\n",
    );
    let policy = MANIFEST
        .replace(
            "{pattern = \"public/\"}",
            "{pattern = \"public/file.txt\"}, {pattern = \"public/guide.md\"}",
        )
        .replace(
            "[exclude]\nrows = [",
            "[exclude]\nrows = [{pattern = \"public/target.md\", reason = \"Retired.\"}, ",
        );
    fs::write(
        fixture.source.join("public/guide.md"),
        "# Guide · `guide:fixture:public`\n",
    )
    .expect("clean final guide");
    fixture.commit("public-set.toml", &policy, "Retire target and reference\n");
    let result = report(fixture.replay(&fixture.out).output().expect("replay"));
    let first = result["mapping"][0]["public_commit"]
        .as_str()
        .expect("first");
    assert_eq!(
        line(
            &fixture.out,
            &["ls-tree", "--name-only", first, "--", "public/target.md"]
        ),
        ""
    );
    assert!(
        line(
            &fixture.out,
            &[
                "show",
                &format!("{first}:docs/public/unpublished-labels.toml")
            ]
        )
        .contains("sec:fixture:retired")
    );
    assert!(
        !fs::read_to_string(fixture.out.join("docs/public/unpublished-labels.toml"))
            .expect("final snapshot")
            .contains("sec:fixture:retired")
    );
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

/// Register planning and owner rewriting use tag blobs despite worktree changes after preflight.
///
/// # Panics
/// Panics only if fixture IO fails or worktree bytes alter the committed public projection.
/// ´test:integration:register-planning-uses-tag-blobs-after-preflight´
#[test]
fn register_planning_uses_tag_blobs_after_preflight() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    fs::create_dir(fixture.source.join("hidden")).expect("hidden definitions");
    let manifest = MANIFEST.replace("reason = \"Private fixture.\"}]", "reason = \"Private fixture.\"}, {pattern = \"hidden/\", reason = \"Hidden fixture declarations.\"}]");
    fixture.commit(
        "hidden/definition.md",
        "# Hidden · `sec:fixture:hidden`\n",
        "Hidden definition\n",
    );
    fixture.commit(
        "docs/citation.md",
        "# Public · `sec:fixture:public`\n\nSee (`sec:fixture:hidden`).\n",
        "Public citation\n",
    );
    fixture.commit(
        "public-set.toml",
        &manifest,
        "Classify hidden definitions\n",
    );
    let control = fixture.scratch.join("tag-control");
    let result = manifest_cut(&fixture, &control);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let register = "docs/public/unpublished-labels.toml";
    assert!(
        fs::read_to_string(control.join(register))
            .expect("control register")
            .contains("sec:fixture:hidden")
    );
    let wrapper = fixture.scratch.join("change-worktree");
    fs::write(&wrapper, "#!/bin/sh\n[ \"$3\" != \"$SOURCE_ROOT\" ] || exit 90\nprintf 'invalid [' > \"$SOURCE_ROOT/.linter/owners.toml\"\nprintf changed > \"$SOURCE_ROOT/hidden/definition.md\"\nprintf changed > \"$SOURCE_ROOT/docs/citation.md\"\nexec \"$REAL_LINTER\" \"$@\"\n").expect("wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).expect("wrapper mode");
    let out = fixture.scratch.join("tag-projection");
    let output = manifest_cut_command(&fixture, &out)
        .arg("--linter")
        .arg(&wrapper)
        .env("SOURCE_ROOT", &fixture.source)
        .env(
            "REAL_LINTER",
            std::env::var_os("PUBLIC_PACK_TEST_LINTER").expect("real linter"),
        )
        .output()
        .expect("cut during worktree mutation");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        fs::read_to_string(fixture.source.join(".linter/owners.toml")).expect("mutated source"),
        "invalid ["
    );
    assert_eq!(
        fs::read(out.join(register)).expect("register"),
        fs::read(control.join(register)).expect("control register")
    );
    assert_eq!(
        fs::read(out.join(".linter/owners.toml")).expect("snapshot"),
        fs::read(control.join(".linter/owners.toml")).expect("control snapshot")
    );
    assert_eq!(
        line(&out, &["rev-parse", "HEAD^{tree}"]),
        line(&control, &["rev-parse", "HEAD^{tree}"])
    );
}

/// The manifest chooses the generated register destination and the snapshot follows it.
///
/// # Panics
/// Panics only if fixture IO fails or the cut loses the declared register binding.
/// ´test:integration:manifest-register-destination-binds-the-snapshot´
#[test]
fn manifest_register_destination_binds_the_snapshot() {
    let fixture = Fixture::new();
    let path = "docs/public/citation-register.toml";
    let manifest = MANIFEST.replace("docs/public/unpublished-labels.toml", path);
    fixture.commit("public-set.toml", &manifest, "Declare custom register\n");
    let out = fixture.scratch.join("custom-cut");
    let result = manifest_cut(&fixture, &out);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(out.join(path).is_file());
    assert!(!out.join("docs/public/unpublished-labels.toml").exists());
    let owners: toml::Value =
        toml::from_str(&fs::read_to_string(out.join(".linter/owners.toml")).expect("owners"))
            .expect("owner TOML");
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(out.join("public-set.toml")).expect("manifest"))
            .expect("manifest TOML");
    assert_eq!(owners["unpublished"].as_str(), Some(path));
    assert_eq!(manifest["public"]["unpublished"].as_str(), Some(path));
    let check = Command::new(std::env::var_os("PUBLIC_PACK_TEST_LINTER").expect("real linter"))
        .args(["check", "--root"])
        .arg(&out)
        .arg("--public-pack")
        .arg("--burn-input")
        .arg(&fixture.burn)
        .output()
        .expect("check generated snapshot");
    assert!(
        check.status.success(),
        "{} {}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    report(
        fixture
            .replay(&fixture.out)
            .output()
            .expect("replay custom destination"),
    );
    assert!(fixture.out.join(path).is_file());
    assert!(
        !fixture
            .out
            .join("docs/public/unpublished-labels.toml")
            .exists()
    );
}

/// A silent manifest emits no register and refuses source register declarations or excluded definitions.
///
/// # Panics
/// Panics only if fixture IO fails or an undeclared register is generated or required evidence is lost.
/// ´test:integration:manifest-register-absence-is-explicit´
#[test]
fn manifest_register_absence_is_explicit() {
    let fixture = Fixture::new();
    let manifest = MANIFEST.replace(
        "unpublished = \"docs/public/unpublished-labels.toml\"\n",
        "",
    );
    fixture.commit("public-set.toml", &manifest, "No register\n");
    let out = fixture.scratch.join("no-register");
    let result = manifest_cut(&fixture, &out);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(!out.join("docs/public/unpublished-labels.toml").exists());
    let owners: toml::Value =
        toml::from_str(&fs::read_to_string(out.join(".linter/owners.toml")).expect("owners"))
            .expect("owner TOML");
    assert!(owners.get("unpublished").is_none());
    let owner_path = fixture.source.join(".linter/owners.toml");
    let original_owners = fs::read_to_string(&owner_path).expect("source owners");
    for (register, policy) in [
        ("docs/source-register.toml", manifest.clone()),
        (
            "private-register.toml",
            manifest.replace(
                "[exclude]\nrows = [",
                "[exclude]\nrows = [{pattern = \"private-register.toml\", reason = \"Private register.\"}, ",
            ),
        ),
    ] {
        fs::write(
            &owner_path,
            format!("unpublished = {register:?}\n{original_owners}"),
        )
        .expect("source register declaration");
        fs::write(
            fixture.source.join(register),
            "namespace = \"class.linter.unpublished-labels\"\nversion = [1, 0, 0]\nlabels = []\n",
        )
        .expect("source register");
        fixture.commit("public-set.toml", &policy, "Source register without manifest declaration\n");
        let refused = fixture.scratch.join(format!("source-register-refused-{}", register.starts_with("docs/")));
        let result = manifest_cut(&fixture, &refused);
        assert_eq!(result.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&result.stdout)
            .contains("owner snapshot unpublished field requires public.unpublished"));
        assert!(!refused.exists());
        fs::remove_file(fixture.source.join(register)).expect("remove source register");
    }
    fs::write(&owner_path, original_owners).expect("restore owners");
    fs::write(
        fixture.source.join("public-set.toml"),
        manifest.replace(
            "[exclude]\nrows = [",
            "[exclude]\nrows = [{pattern = \"private.md\", reason = \"Private definition.\"}, ",
        ),
    )
    .expect("exclude definition");
    fs::write(
        fixture.source.join("private.md"),
        "# Private · `sec:private:definition`\n",
    )
    .expect("private mint");
    fixture.commit(
        "docs/guide.md",
        "# Guide · `guide:public:guide`\n\nSee (`sec:private:definition`).\n",
        "Require register\n",
    );
    let refused = fixture.scratch.join("refused-cut");
    let result = manifest_cut(&fixture, &refused);
    assert_eq!(result.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .contains("excluded-definition citations require public.unpublished")
    );
    assert!(!refused.exists());
}

/// Register paths cannot replace selected ordinary files, manifests, or directory entries.
///
/// # Panics
/// Panics only if fixture IO fails or a conflicting register destination is admitted.
/// ´test:integration:manifest-register-collisions-refuse-before-publication´
#[test]
fn manifest_register_collisions_refuse_before_publication() {
    for (path, reason) in [
        ("public/file.txt", "overwrite a selected non-register file"),
        ("public/link", "must replace a regular register file"),
        (
            "public/file.txt/labels.toml",
            "conflicts with a selected path",
        ),
        ("public", "conflicts with a selected path"),
        ("public-set.toml", "cannot replace the manifest"),
    ] {
        let fixture = Fixture::new();
        if path == "public/link" {
            std::os::unix::fs::symlink("file.txt", fixture.source.join(path))
                .expect("selected symlink");
        }
        fixture.commit(
            "public-set.toml",
            &MANIFEST.replace("docs/public/unpublished-labels.toml", path),
            "Conflicting register\n",
        );
        let out = fixture.scratch.join("refused-cut");
        let result = manifest_cut(&fixture, &out);
        assert_eq!(result.status.code(), Some(3), "{path}");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains(reason),
            "{path}: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert!(!out.exists());
    }
}

fn manifest_cut(fixture: &Fixture, out: &Path) -> Output {
    manifest_cut_command(fixture, out)
        .arg("--linter")
        .arg(std::env::var_os("PUBLIC_PACK_TEST_LINTER").expect("real linter"))
        .output()
        .expect("manifest cut")
}

fn manifest_cut_command(fixture: &Fixture, out: &Path) -> Command {
    let tag = format!(
        "manifest-{}",
        out.file_name()
            .expect("output name")
            .to_str()
            .expect("UTF-8")
    );
    git(&fixture.source, &["tag", &tag]);
    let mut command = pack(&fixture.source);
    command
        .args([
            "cut",
            "--tag",
            &tag,
            "--manifest",
            "public-set.toml",
            "--author",
            "Publisher <publisher@example.com>",
            "--out",
        ])
        .arg(out)
        .arg("--burn-register")
        .arg(&fixture.burn);
    command
}

fn citation_probe(fixture: &Fixture) -> String {
    let output = Command::new(std::env::var_os("PUBLIC_PACK_TEST_LINTER").expect("real linter"))
        .args(["citation-sites", "--root"])
        .arg(&fixture.source)
        .output()
        .expect("citation probe");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("citation protocol text");
    let observed: serde_json::Value =
        serde_json::from_str(&text).expect("recorded citation protocol");
    assert!(observed.is_object());
    text
}

fn citation_transport(fixture: &Fixture, payload: &str, status: u8) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = fixture.scratch.join("citation-transport");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n[ \"$#\" -eq 3 ] && [ \"$1\" = citation-sites ] && [ \"$2\" = --root ] && [ -d \"$3/.git\" ] || exit 90\ncat <<'CITATION_FIXTURE'\n{}\nCITATION_FIXTURE\nprintf '%s\\n' fixture-linter-stderr >&2\nexit {status}\n",
            payload.trim_end()
        ),
    )
    .expect("fixture transport");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("executable transport");
    path
}

fn cut_route_refusal(fixture: &Fixture, linter: Option<&Path>, expected: &str) -> String {
    let out = fixture.scratch.join("refused-route");
    let mut command = manifest_cut_command(fixture, &out);
    command.env("TMPDIR", &fixture.scratch);
    if let Some(linter) = linter {
        command.arg("--linter").arg(linter);
    }
    let refs = git(&fixture.source, &["show-ref"]);
    let state = git(&fixture.source, &["status", "--porcelain=v1", "--ignored"]);
    let output = command.output().expect("cut refusal");
    let text = String::from_utf8(output.stdout).expect("cut report");
    assert_eq!(output.status.code(), Some(3), "{text}");
    assert!(text.contains(expected), "{text}");
    assert!(!out.exists());
    assert_eq!(git(&fixture.source, &["show-ref"]), refs);
    assert_eq!(
        git(&fixture.source, &["status", "--porcelain=v1", "--ignored"]),
        state
    );
    text
}

/// A cut requiring citation sites refuses an absent linter before publication.
///
/// # Panics
/// Panics only if fixture IO fails or the built cut accepts a missing linter or changes output.
/// ´test:integration:cut-route-refuses-missing-linter´
#[test]
fn cut_route_refuses_missing_linter() {
    let fixture = Fixture::new();
    cut_route_refusal(&fixture, None, "unpublished labels require --linter");
}

/// A failed citation executable retains its stdout and stderr and refuses before publication.
///
/// # Panics
/// Panics only if fixture IO fails or the cut loses diagnostics or changes output on refusal.
/// ´test:integration:cut-route-refuses-failed-linter´
#[test]
fn cut_route_refuses_failed_linter() {
    let fixture = Fixture::new();
    let observed = citation_probe(&fixture);
    let linter = citation_transport(&fixture, &observed, 7);
    let report = cut_route_refusal(&fixture, Some(&linter), "citation-sites linter refused");
    let path = report
        .lines()
        .find_map(|line| {
            line.strip_prefix("cut outcome=")
                .and_then(|line| line.split_once("diagnostic scratch=").map(|(_, path)| path))
        })
        .expect("retained diagnostic path");
    assert!(Path::new(path).starts_with(&fixture.scratch), "{report}");
    assert_eq!(
        fs::read_to_string(Path::new(path).join("citation-sites.stdout")).expect("stdout"),
        format!("{}\n", observed.trim_end())
    );
    assert_eq!(
        fs::read_to_string(Path::new(path).join("citation-sites.stderr")).expect("stderr"),
        "fixture-linter-stderr\n"
    );
}

/// A successful executable with truncated measured citation JSON refuses before publication.
///
/// # Panics
/// Panics only if fixture IO fails or malformed protocol bytes are accepted or change output.
/// ´test:integration:cut-route-refuses-malformed-json´
#[test]
fn cut_route_refuses_malformed_json() {
    let fixture = Fixture::new();
    let observed = citation_probe(&fixture);
    let observed = observed.trim_end();
    assert!(observed.ends_with('}'));
    let linter = citation_transport(&fixture, &observed[..observed.len() - 1], 0);
    cut_route_refusal(&fixture, Some(&linter), "invalid citation-sites JSON");
}

/// A hung citation executable refuses at the production deadline without publication.
///
/// # Panics
/// Panics only if fixture IO fails, the bound is outlived, or diagnostics or output change.
/// ´test:integration:cut-route-refuses-a-hung-linter´
#[test]
fn cut_route_refuses_a_hung_linter() {
    let fixture = Fixture::new();
    let observed = citation_probe(&fixture);
    let linter = citation_transport(&fixture, &observed, 0);
    let script = fs::read_to_string(&linter).expect("transport script");
    fs::write(&linter, script.replace("exit 0\n", "exec /bin/sleep 300\n"))
        .expect("hung transport");
    let started = std::time::Instant::now();
    let report = cut_route_refusal(
        &fixture,
        Some(&linter),
        "citation-sites linter timed out after 120 s",
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(180),
        "deadline did not bound invocation"
    );
    let diagnostic = report
        .lines()
        .find_map(|line| {
            line.strip_prefix("cut outcome=")
                .and_then(|line| line.split_once("diagnostic scratch=").map(|(_, path)| path))
        })
        .expect("retained diagnostics");
    assert!(
        Path::new(diagnostic).starts_with(&fixture.scratch),
        "{report}"
    );
    assert_eq!(
        fs::read_to_string(Path::new(diagnostic).join("citation-sites.stdout")).expect("stdout"),
        format!("{}\n", observed.trim_end())
    );
    assert_eq!(
        fs::read_to_string(Path::new(diagnostic).join("citation-sites.stderr")).expect("stderr"),
        "fixture-linter-stderr\n"
    );
}

/// Unknown citation namespaces and versions refuse even when the executable returns valid JSON.
///
/// # Panics
/// Panics only if fixture IO fails or an unknown protocol is accepted or changes output.
/// ´test:integration:cut-route-refuses-unknown-protocol´
#[test]
fn cut_route_refuses_unknown_protocol() {
    for field in ["namespace", "version"] {
        let fixture = Fixture::new();
        let observed = citation_probe(&fixture);
        let mut document: serde_json::Value =
            serde_json::from_str(&observed).expect("measured JSON");
        document[field] = if field == "namespace" {
            serde_json::json!("class.fixture.unknown-citation-sites")
        } else {
            serde_json::json!([99, 0, 0])
        };
        let linter = citation_transport(&fixture, &document.to_string(), 0);
        cut_route_refusal(&fixture, Some(&linter), "unknown citation-sites protocol");
    }
}

/// A generated register cannot be declared without a selected owner snapshot.
///
/// # Panics
/// Panics only if fixture IO fails or a register without its owner snapshot is published.
/// ´test:integration:manifest-register-requires-a-selected-snapshot´
#[test]
fn manifest_register_requires_a_selected_snapshot() {
    let fixture = Fixture::new();
    let manifest = MANIFEST.replace("{pattern = \".linter/\"}, ", "").replace(
        "[exclude]\nrows = [",
        "[exclude]\nrows = [{pattern = \".linter/\", reason = \"Omit snapshot.\"}, ",
    );
    fixture.commit("public-set.toml", &manifest, "Exclude snapshot\n");
    let out = fixture.scratch.join("no-snapshot");
    let result = manifest_cut(&fixture, &out);
    assert_eq!(result.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .contains("public.unpublished requires a selected owner snapshot")
    );
    assert!(!out.exists());
}

/// A replay cannot silently drop a register required by its historical snapshot.
///
/// # Panics
/// Panics only if fixture IO fails or a final bound removes a required register.
/// ´test:integration:manifest-register-obeys-the-final-bound´
#[test]
fn manifest_register_obeys_the_final_bound() {
    let fixture = Fixture::new();
    let manifest = MANIFEST.replace("{pattern = \"docs/\"}", "{pattern = \"docs/readme.txt\"}");
    fixture.commit("public-set.toml", &manifest, "Exclude generated register\n");
    fixture.unchanged_refusal("field=public.unpublished path=docs/public/unpublished-labels.toml");
}

/// Replay audit evidence names the manifest's register path for a refused unpublished label.
///
/// # Panics
/// Panics only if fixture IO fails or the audit reports a different register path.
/// ´test:integration:manifest-register-audit-names-the-declared-path´
#[test]
fn manifest_register_audit_names_the_declared_path() {
    let fixture = Fixture::new();
    let path = "docs/public/custom-labels.toml";
    let manifest = MANIFEST
        .replace("docs/public/unpublished-labels.toml", path)
        .replace(
            "[exclude]\nrows = [",
            "[exclude]\nrows = [{pattern = \"private.md\", reason = \"Private definition.\"}, ",
        );
    fs::write(fixture.source.join("public-set.toml"), manifest).expect("manifest");
    fs::write(
        fixture.source.join("private.md"),
        "# Private · `sec:private:forbidden-value`\n",
    )
    .expect("private mint");
    fixture.commit(
        "docs/guide.md",
        "# Guide · `guide:public:guide`\n\nSee (`sec:private:forbidden-value`).\n",
        "Audited citation\n",
    );
    let output = fixture
        .replay(&fixture.out)
        .output()
        .expect("replay refusal");
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout).expect("report text");
    let report: serde_json::Value =
        serde_json::from_str(text.lines().next().expect("report")).expect("JSON");
    let current = &report["validation"]["current"];
    assert_eq!(current["check"], "burn scan");
    assert_eq!(current["field"], "unpublished.label");
    assert_eq!(current["path"], path);
    assert_eq!(current["matcher_kind"], "substring");
    assert_eq!(
        line(&fixture.out, &["rev-parse", "HEAD"]),
        fixture.public_root
    );
}
