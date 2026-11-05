//! The public cut's history, selection, reproducibility and refusal contract.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .env("GIT_AUTHOR_DATE", "946684700 +0000")
        .env("GIT_COMMITTER_DATE", "946684800 +0000")
        .current_dir(root)
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git text")
        .trim_end()
        .to_owned()
}

const MANIFEST: &str = r#"namespace = "org.superloop-tools.public-set"
version = [1, 0, 0]
[include]
rows = [{ pattern = "public-set.toml" }, { pattern = "CHANGELOG.md", reserved = true }, { pattern = "LICENSE-CODE", reserved = true }, { pattern = "LICENSE-DOCS", reserved = true }, { pattern = "docs/" }, { pattern = "public/" }]
[exclude]
rows = [{ pattern = "private.txt", reason = "Private fixture." }]
[reserved]
rows = [{ pattern = "future-private/", reason = "Reserved private fixture." }]
[public]
name = "fixture-repository"
readme = "docs/readme.txt"
licence_code = "LICENSE-CODE"
licence_docs = "LICENSE-DOCS"
"#;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("fixture");
    fs::create_dir(root.path().join("source")).expect("source");
    let source = root.path().join("source");
    fs::create_dir(source.join("docs")).expect("docs");
    fs::create_dir(source.join("public")).expect("public");
    for (path, content) in [
        ("public-set.toml", MANIFEST),
        (
            "CHANGELOG.md",
            "# Changelog\n\n## [Unreleased]\n\n## [0.1.1] - 2026-10-13\n\n### Fixed\n\n- Later fixture.\n\n## [0.1.0] - 2026-10-12\n\n### Added\n\n- First fixture.\n\n[Unreleased]: https://example.com/compare/v0.1.0...HEAD\n[0.1.0]: https://example.com/releases/v0.1.0\n\n",
        ),
        ("LICENSE-CODE", "fixture code licence\n"),
        ("LICENSE-DOCS", "fixture documents licence\n"),
        ("docs/readme.txt", "public readme\n"),
        ("public/tool", "#!/bin/sh\nexit 0\n"),
        ("private.txt", "PRIVATE CONTENT\n"),
    ] {
        fs::write(source.join(path), content).expect("fixture bytes");
    }
    fs::set_permissions(
        source.join("public/tool"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("executable");
    symlink("tool", source.join("public/link")).expect("link");
    git(&source, &["init", "-q", "--initial-branch=main"]);
    git(&source, &["config", "user.name", "Source Fixture"]);
    git(&source, &["config", "user.email", "source@example.com"]);
    git(&source, &["config", "tag.gpgsign", "false"]);
    git(&source, &["add", "."]);
    git(
        &source,
        &[
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "Private source history",
        ],
    );
    git(&source, &["tag", "source-v1"]);
    root
}

fn cut(source: &Path, out: &Path, previous: Option<&Path>, with_author: bool) -> Output {
    cut_with_date(source, out, previous, with_author, None)
}

fn cut_with_date(
    source: &Path,
    out: &Path,
    previous: Option<&Path>,
    with_author: bool,
    date: Option<&str>,
) -> Output {
    cut_with_public_tag(source, out, previous, with_author, date, None)
}

fn cut_with_public_tag(
    source: &Path,
    out: &Path,
    previous: Option<&Path>,
    with_author: bool,
    date: Option<&str>,
    public_tag: Option<&str>,
) -> Output {
    cut_command(source, out, previous, with_author, date, public_tag)
        .output()
        .expect("cut binary")
}

fn cut_command(
    source: &Path,
    out: &Path,
    previous: Option<&Path>,
    with_author: bool,
    date: Option<&str>,
    public_tag: Option<&str>,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_superloop-pack"));
    command
        .current_dir(source)
        .args([
            "cut",
            "--tag",
            "source-v1",
            "--manifest",
            "public-set.toml",
            "--out",
        ])
        .arg(out);
    if with_author {
        command.args(["--author", "Fixture Author <fixture@example.com>"]);
    }
    if let Some(previous) = previous {
        command.arg("--previous").arg(previous);
    }
    if let Some(date) = date {
        command.args(["--date", date]);
    }
    if let Some(tag) = public_tag {
        command.args(["--public-tag", tag]);
    }
    command
}

/// Public messages preserve overrides and reproduce commit and tag objects.
///
/// # Panics
/// Panics only if fixture IO fails or a publication message violates its contract.
/// ´claim:integration:publication-messages-are-verbatim-and-reproducible´
/// ´test:integration:publication-messages-are-verbatim-and-reproducible´
#[test]
fn publication_messages_are_verbatim_and_reproducible() {
    let root = fixture();
    let source = root.path().join("source");
    for (index, (public_tag, message, expected)) in [
        (None, None, "feat(release): publish the source set\n"),
        (Some("v0.1.0"), None, "feat(release): publish v0.1.0\n"),
        (
            None,
            Some(" custom subject \n\nbody  \n\n"),
            " custom subject \n\nbody  \n",
        ),
        (
            Some("v0.1.0"),
            Some(" custom subject \n\nbody  \n\n"),
            " custom subject \n\nbody  \n",
        ),
    ]
    .iter()
    .enumerate()
    {
        let first = root.path().join(format!("message-{index}"));
        let recut = root.path().join(format!("message-recut-{index}"));
        for out in [&first, &recut] {
            let mut command = cut_command(&source, out, None, true, None, *public_tag);
            if let Some(message) = message {
                command.args(["--message", message]);
            }
            let report = success(command.output().expect("cut binary"));
            assert!(report.contains(if message.is_some() {
                " message_override=yes"
            } else {
                " message_override=no"
            }));
            let object = Command::new("git")
                .current_dir(out)
                .args(["cat-file", "commit", "HEAD"])
                .output()
                .expect("commit object");
            assert!(object.status.success());
            let object = String::from_utf8(object.stdout).expect("commit text");
            assert_eq!(object.split_once("\n\n").expect("message").1, *expected);
        }
        assert_eq!(
            git(&first, &["rev-parse", "HEAD"]),
            git(&recut, &["rev-parse", "HEAD"])
        );
        if let Some(tag) = public_tag {
            assert_eq!(
                git(&first, &["rev-parse", tag]),
                git(&recut, &["rev-parse", tag])
            );
        }
    }
    for message in ["", "\n\n", " \t\n"] {
        let out = root.path().join("empty-message");
        let output = cut_command(&source, &out, None, true, None, None)
            .args(["--message", message])
            .output()
            .expect("cut binary");
        assert!(!output.status.success());
        assert!(!out.exists());
    }
}

/// Public tags bind the publishing identity and date reproducibly to each commit.
///
/// # Panics
/// Panics only if fixture IO fails or a public tag violates its contract.
/// ´claim:integration:public-tags-bind-reproducible-public-commits´
/// ´test:integration:public-tags-bind-reproducible-public-commits´
#[test]
fn public_tags_bind_reproducible_public_commits() {
    let root = fixture();
    let source = root.path().join("source");
    for (index, date) in [None, Some("2026-10-12T16:11:22Z")].iter().enumerate() {
        let first = root.path().join(format!("tagged-{index}"));
        let recut = root.path().join(format!("recut-{index}"));
        for out in [&first, &recut] {
            let report = success(cut_with_public_tag(
                &source,
                out,
                None,
                true,
                *date,
                Some("v0.1.0"),
            ));
            assert!(report.contains(" public_tag=v0.1.0"));
            assert_eq!(
                git(out, &["rev-parse", "v0.1.0^{}"]),
                git(out, &["rev-parse", "HEAD"])
            );
            let tag = git(out, &["cat-file", "-p", "v0.1.0"]);
            assert!(tag.contains("tagger Fixture Author <fixture@example.com>"));
            assert!(tag.ends_with("fixture-repository v0.1.0\n\n### Added\n\n- First fixture."));
            assert!(!tag.contains("BEGIN PGP SIGNATURE"));
            assert_eq!(
                git(out, &["tag", "-l", "--format=%(taggerdate:raw)", "v0.1.0"]),
                git(out, &["show", "-s", "--date=raw", "--format=%cd", "HEAD"])
            );
            assert_eq!(
                git(out, &["tag", "-l", "--format=%(taggerdate:unix)", "v0.1.0"])
                    .parse::<i64>()
                    .expect("tag epoch"),
                git(out, &["show", "-s", "--format=%ct", "HEAD"])
                    .parse::<i64>()
                    .expect("commit epoch")
            );
        }
        assert_eq!(
            git(&first, &["rev-parse", "v0.1.0"]),
            git(&recut, &["rev-parse", "v0.1.0"])
        );
        success(cut_with_public_tag(
            &source,
            &first,
            Some(&first),
            true,
            *date,
            Some("v0.1.1"),
        ));
        assert_eq!(
            git(&first, &["rev-parse", "v0.1.1^{}"]),
            git(&first, &["rev-parse", "HEAD"])
        );
        assert!(
            !cut_with_public_tag(&source, &first, Some(&first), true, *date, Some("v0.1.1"))
                .status
                .success()
        );
    }
    for tag in ["", "bad..name", "bad name", "bad.lock", "bad/name/"] {
        let out = root.path().join("invalid-tag");
        assert!(
            !cut_with_public_tag(&source, &out, None, true, None, Some(tag))
                .status
                .success()
        );
        assert!(!out.exists());
    }
}

/// Tag notes select one released section and overrides preserve their exact bytes.
///
/// # Panics
/// Panics only if fixture IO fails or tag notes violate their contract.
/// ´test:integration:tag-notes-select-release-sections-and-preserve-overrides´
#[test]
fn tag_notes_select_release_sections_and_preserve_overrides() {
    let root = fixture();
    let source = root.path().join("source");
    let first = root.path().join("notes");
    success(cut_with_public_tag(
        &source,
        &first,
        None,
        true,
        None,
        Some("0.1.1"),
    ));
    assert_eq!(
        git(&first, &["tag", "-l", "--format=%(contents)", "0.1.1"]),
        "fixture-repository 0.1.1\n\n### Fixed\n\n- Later fixture."
    );
    let footer = root.path().join("footer-notes");
    success(cut_with_public_tag(
        &source,
        &footer,
        None,
        true,
        None,
        Some("v0.1.0"),
    ));
    let object = Command::new("git")
        .current_dir(&footer)
        .args(["cat-file", "tag", "v0.1.0"])
        .output()
        .expect("tag object");
    assert!(object.status.success());
    let object = String::from_utf8(object.stdout).expect("tag text");
    assert_eq!(
        object.split_once("\n\n").expect("tag message").1,
        "fixture-repository v0.1.0\n\n### Added\n\n- First fixture.\n"
    );
    let absent = root.path().join("absent");
    let output = cut_with_public_tag(&source, &absent, None, true, None, Some("v9.0.0"));
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("CHANGELOG.md requires heading ## [9.0.0] - DATE")
    );
    assert!(!absent.exists());
    git(&source, &["rm", "CHANGELOG.md"]);
    git(
        &source,
        &["commit", "--no-gpg-sign", "-m", "Remove fixture notes"],
    );
    git(&source, &["tag", "-f", "source-v1"]);
    let output = cut_with_public_tag(&source, &absent, None, true, None, Some("v0.1.0"));
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("CHANGELOG.md requires heading ## [0.1.0] - DATE")
    );
    assert!(!absent.exists());
    let recut = root.path().join("override-recut");
    let message = " custom tag subject \n\n# preserved comment\nbody  \n\n";
    for out in [&absent, &recut] {
        let output = cut_command(&source, out, None, true, None, Some("v0.1.0"))
            .args(["--tag-message", message])
            .output()
            .expect("cut binary");
        assert!(success(output).contains(" tag_message_override=yes"));
        let object = Command::new("git")
            .current_dir(out)
            .args(["cat-file", "tag", "v0.1.0"])
            .output()
            .expect("tag object");
        assert!(object.status.success());
        let object = String::from_utf8(object.stdout).expect("tag text");
        assert_eq!(object.split_once("\n\n").expect("tag message").1, message);
    }
    assert_eq!(
        git(&absent, &["rev-parse", "v0.1.0"]),
        git(&recut, &["rev-parse", "v0.1.0"])
    );
}

/// Empty release sections and blank tag overrides refuse publication.
///
/// # Panics
/// Panics only if fixture IO fails or invalid release notes are accepted.
/// ´test:integration:empty-release-notes-refuse-publication´
#[test]
fn empty_release_notes_refuse_publication() {
    let root = fixture();
    let source = root.path().join("source");
    let absent = root.path().join("absent");
    for body in ["", " \t\n", "\n[0.1.0]: https://example.com/release\n"] {
        fs::write(
            source.join("CHANGELOG.md"),
            format!("# Changelog\n\n## [0.1.0] - 2026-10-12\n{body}\n## [Older]\n"),
        )
        .expect("empty notes");
        git(&source, &["add", "CHANGELOG.md"]);
        git(
            &source,
            &["commit", "--no-gpg-sign", "-m", "Empty fixture notes"],
        );
        git(&source, &["tag", "-f", "source-v1"]);
        let output = cut_with_public_tag(&source, &absent, None, true, None, Some("v0.1.0"));
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("CHANGELOG.md requires non-empty body for heading ## [0.1.0] - DATE")
        );
        assert!(!absent.exists());
    }
    for message in ["", " \t\n"] {
        let output = cut_command(&source, &absent, None, true, None, Some("v0.1.0"))
            .args(["--tag-message", message])
            .output()
            .expect("cut binary");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("tag-message must be non-empty and contain no NUL")
        );
        assert!(!absent.exists());
    }
}

/// Explicit dates set both identities' timestamps and preserve deterministic recuts.
///
/// # Panics
/// Panics only if fixture IO fails or publication violates its date contract.
/// ´claim:integration:publication-dates-apply-to-roots-and-later-commits´
/// ´test:integration:publication-dates-apply-to-roots-and-later-commits´
#[test]
fn publication_dates_apply_to_roots_and_later_commits() {
    let root = fixture();
    let source = root.path().join("source");
    let first = root.path().join("dated-first");
    let second = root.path().join("dated-second");
    let date = "2026-10-12T16:11:22Z";
    let report = success(cut_with_date(&source, &first, None, true, Some(date)));
    assert!(report.contains(&format!(
        " date={} ",
        git(&first, &["show", "-s", "--format=%aI"])
    )));
    assert_eq!(
        git(&first, &["show", "-s", "--date=raw", "--format=%ad|%cd"]),
        "1791821482 +0000|1791821482 +0000"
    );
    success(cut_with_date(&source, &second, None, true, Some(date)));
    for format in ["--format=%H", "--format=%T"] {
        assert_eq!(
            git(&first, &["show", "-s", format]),
            git(&second, &["show", "-s", format])
        );
    }
    assert_eq!(
        git(&first, &["show", "-s", "--format=%at %ct"])
            .split_whitespace()
            .map(|value| value.parse::<i64>().expect("epoch seconds"))
            .collect::<Vec<_>>(),
        [1_791_821_482; 2]
    );
    let parent = git(&first, &["rev-parse", "HEAD"]);
    let later = "2026-10-13T17:12:23.456+02:30";
    success(cut_with_date(
        &source,
        &first,
        Some(&first),
        true,
        Some(later),
    ));
    assert_eq!(git(&first, &["rev-parse", "HEAD^"]), parent);
    assert_eq!(
        git(&first, &["show", "-s", "--date=raw", "--format=%ad|%cd"]),
        "1791902543 +0230|1791902543 +0230"
    );
    assert_eq!(
        git(&first, &["show", "-s", "--format=%at %ct"])
            .split_whitespace()
            .map(|value| value.parse::<i64>().expect("epoch seconds"))
            .collect::<Vec<_>>(),
        [1_791_902_543; 2]
    );
}

/// Malformed dates refuse before publishing a destination.
///
/// # Panics
/// Panics only if fixture IO fails or an invalid date reaches publication.
/// ´claim:integration:invalid-publication-dates-refuse-before-creating-output´
/// ´test:integration:invalid-publication-dates-refuse-before-creating-output´
#[test]
fn invalid_publication_dates_refuse_before_creating_output() {
    let root = fixture();
    let source = root.path().join("source");
    let out = root.path().join("invalid-date");
    for date in [
        "",
        "yesterday",
        "2026-10-12T16:11:22",
        "2026-02-29T16:11:22Z",
        "2026-13-12T16:11:22Z",
        "2026-10-12T24:11:22Z",
        "2026-10-12T16:11:22+24:00",
        "2026-10-12T16:11:22+00:60",
        "2026-10-12T16:11:22.Z",
        "2026-10-12T16:11:22Zextra",
    ] {
        let output = cut_with_date(&source, &out, None, true, Some(date));
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("date requires RFC 3339 with an explicit offset or Z")
        );
        assert!(!out.exists());
    }
}

fn success(output: Output) -> String {
    let text = String::from_utf8(output.stdout).expect("cut text");
    assert!(
        output.status.success(),
        "{text}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(text.matches("RUN-REPORT").count(), 1);
    text
}

/// A cut has one public root, stable tree bytes and modes, and explicit publication identity.
///
/// # Panics
/// Panics only if fixture IO fails or the cut violates its tree or history contract.
/// ´claim:integration:cuts-reproduce-the-public-tree-and-append-only-public-history´
/// ´test:integration:cuts-reproduce-the-public-tree-and-append-only-public-history´
#[test]
fn cuts_reproduce_the_public_tree_and_append_only_public_history() {
    let root = fixture();
    let source = root.path().join("source");
    let first = root.path().join("first");
    let second = root.path().join("second");
    let report = success(cut(&source, &first, None, true));
    assert!(report.contains("cut files=7 "), "{report}");
    assert!(report.contains(&format!(
        "source_commit={}",
        git(&source, &["rev-parse", "HEAD"])
    )));
    assert_eq!(git(&first, &["rev-list", "--count", "HEAD"]), "1");
    let source_time = git(&source, &["show", "-s", "--format=%ct"]);
    assert_eq!(
        git(&first, &["show", "-s", "--format=%at|%ct"]),
        format!("{source_time}|{source_time}")
    );
    assert_eq!(
        git(&first, &["show", "-s", "--format=%an <%ae>|%cn <%ce>"]),
        "Fixture Author <fixture@example.com>|Fixture Author <fixture@example.com>"
    );
    assert_eq!(
        git(&first, &["ls-tree", "-r", "--name-only", "HEAD"]),
        "CHANGELOG.md\nLICENSE-CODE\nLICENSE-DOCS\nREADME.md\npublic-set.toml\npublic/link\npublic/tool"
    );
    for path in ["LICENSE-CODE", "LICENSE-DOCS", "public/link", "public/tool"] {
        assert_eq!(
            git(&first, &["ls-tree", "HEAD", "--", path]),
            git(&source, &["ls-tree", "HEAD", "--", path])
        );
    }
    let public_manifest =
        fs::read_to_string(first.join("public-set.toml")).expect("public manifest");
    assert!(public_manifest.contains("Exclusion is a source-side matter"));
    assert!(public_manifest.contains("future-private/"));
    assert_eq!(
        fs::read_to_string(source.join("public-set.toml")).expect("source manifest"),
        MANIFEST
    );
    let manifest = superloop_cli_common::public_set::Manifest::parse(&public_manifest)
        .expect("public manifest schema");
    let paths = git(&first, &["ls-files"])
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let selection = manifest.select(&paths);
    assert!(selection.issues.is_empty(), "{:?}", selection.issues);
    assert_eq!(selection.excluded, 0);
    assert_eq!(selection.included, paths);
    assert_eq!(
        git(&first, &["rev-parse", "HEAD:README.md"]),
        git(&source, &["rev-parse", "HEAD:docs/readme.txt"])
    );
    let message = git(&first, &["show", "-s", "--format=%B"]);
    assert_eq!(message, "feat(release): publish the source set");
    assert_eq!(
        fs::read(first.join("README.md")).expect("readme"),
        b"public readme\n"
    );
    assert_eq!(
        fs::read_link(first.join("public/link")).expect("link"),
        Path::new("tool")
    );
    assert_eq!(
        fs::metadata(first.join("public/tool"))
            .expect("mode")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(!first.join("private.txt").exists());
    assert!(!git(&first, &["cat-file", "commit", "HEAD"]).contains("gpgsig"));
    let tree = git(&first, &["show", "-s", "--format=%T"]);
    fs::create_dir(&second).expect("empty output directory");
    success(cut(&source, &second, None, true));
    assert_eq!(tree, git(&second, &["show", "-s", "--format=%T"]));
    assert_eq!(
        git(&first, &["ls-tree", "-r", "HEAD"]),
        git(&second, &["ls-tree", "-r", "HEAD"])
    );
    let previous = git(&first, &["rev-parse", "HEAD"]);
    success(cut(&source, &first, Some(&first), true));
    assert_eq!(git(&first, &["rev-list", "--count", "HEAD"]), "2");
    assert_eq!(git(&first, &["rev-parse", "HEAD^"]), previous);
    assert_eq!(git(&first, &["show", "-s", "--format=%T"]), tree);
    assert_eq!(git(&first, &["status", "--porcelain"]), "");
}

/// Missing identity, missing licence, mismatched output and dirty input refuse before publication.
///
/// # Panics
/// Panics only if fixture IO fails or a refusal changes the publication destination.
/// ´claim:integration:required-inputs-and-existing-publication-are-guarded´
/// ´test:integration:required-inputs-and-existing-publication-are-guarded´
#[test]
fn required_inputs_and_existing_publication_are_guarded() {
    for input in ["LICENSE-CODE", "LICENSE-DOCS", "public-set.toml"] {
        refuses_consumed_input(input);
    }
    let root = fixture();
    let source = root.path().join("source");
    let out = root.path().join("out");
    assert_eq!(cut(&source, &out, None, false).status.code(), Some(2));
    assert!(!out.exists());
    git(
        &source,
        &[
            "commit",
            "--allow-empty",
            "-q",
            "--no-gpg-sign",
            "-m",
            "After tag",
        ],
    );
    let output = cut(&source, &out, None, true);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stdout).contains("clean checkout of tag required"));
    assert!(!out.exists());
    git(&source, &["reset", "--hard", "source-v1"]);
    fs::create_dir(&out).expect("initial output");
    fs::write(out.join("retain.txt"), "retain me").expect("existing output bytes");
    let output = cut(&source, &out, None, true);
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stdout).contains("empty"));
    assert_eq!(
        fs::read(out.join("retain.txt")).expect("retained"),
        b"retain me"
    );
    assert!(!out.join(".git").exists());
    fs::remove_file(out.join("retain.txt")).expect("remove fixture bytes");
    fs::remove_dir(&out).expect("remove fixture directory");
    fs::write(source.join("private.txt"), "dirty").expect("dirty source");
    assert_eq!(cut(&source, &out, None, true).status.code(), Some(3));
    assert!(!out.exists());
    git(&source, &["checkout", "--", "private.txt"]);
    success(cut(&source, &out, None, true));
    let before = git(&out, &["rev-parse", "HEAD"]);
    let other = root.path().join("other");
    fs::create_dir(&other).expect("other");
    let output = cut(&source, &other, Some(&out), true);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("previous must name the same directory")
    );
    assert_eq!(git(&out, &["rev-parse", "HEAD"]), before);
    fs::write(out.join("untracked"), "retain me").expect("dirty output");
    assert_eq!(cut(&source, &out, Some(&out), true).status.code(), Some(3));
    assert_eq!(
        fs::read(out.join("untracked")).expect("retained"),
        b"retain me"
    );
    for licence in ["LICENSE-CODE", "LICENSE-DOCS"] {
        let missing_root = fixture();
        let source = missing_root.path().join("source");
        git(&source, &["rm", licence]);
        git(
            &source,
            &["commit", "-q", "--no-gpg-sign", "-m", "Licence absent"],
        );
        git(&source, &["tag", "-f", "source-v1"]);
        let missing = missing_root.path().join("missing");
        let output = cut(&source, &missing, None, true);
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("{licence} is absent from the public set"))
        );
        assert!(!missing.exists());
    }
}

/// A publication must declare its repository name even with a tag-message override.
///
/// # Panics
/// Panics only if fixture IO fails or an unnamed publication is accepted.
/// ´test:integration:missing-public-name-refuses-publication´
#[test]
fn missing_public_name_refuses_publication() {
    let root = fixture();
    let source = root.path().join("source");
    fs::write(
        source.join("public-set.toml"),
        MANIFEST.replace("name = \"fixture-repository\"\n", ""),
    )
    .expect("unnamed manifest");
    git(&source, &["add", "public-set.toml"]);
    git(
        &source,
        &["commit", "-q", "--no-gpg-sign", "-m", "Missing name"],
    );
    git(&source, &["tag", "-f", "source-v1"]);
    let out = root.path().join("out");
    for override_message in [None, Some("Explicit notes")] {
        let mut command = cut_command(&source, &out, None, true, None, Some("v0.1.0"));
        if let Some(message) = override_message {
            command.args(["--tag-message", message]);
        }
        let output = command.output().expect("cut binary");
        assert_eq!(output.status.code(), Some(3));
        assert!(String::from_utf8_lossy(&output.stdout).contains("missing field `name`"));
        assert!(!out.exists());
    }
}

/// Blank names and control characters cannot become annotated tag subjects.
///
/// # Panics
/// Panics only if fixture IO fails or an invalid publication name is accepted.
/// ´test:integration:invalid-public-names-refuse-publication´
#[test]
fn invalid_public_names_refuse_publication() {
    for name in [
        "",
        "   ",
        "fixture\\nrepository",
        "fixture\\trepository",
        "fixture\\u007Frepository",
    ] {
        let root = fixture();
        let source = root.path().join("source");
        fs::write(
            source.join("public-set.toml"),
            MANIFEST.replace(
                "name = \"fixture-repository\"",
                &format!("name = \"{name}\""),
            ),
        )
        .expect("invalid name manifest");
        git(&source, &["add", "public-set.toml"]);
        git(
            &source,
            &["commit", "-q", "--no-gpg-sign", "-m", "Invalid name"],
        );
        git(&source, &["tag", "-f", "source-v1"]);
        let out = root.path().join("out");
        let output = cut_with_public_tag(&source, &out, None, true, None, Some("v0.1.0"));
        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("public-set requires a non-empty single-line public.name")
        );
        assert!(!out.exists());
    }
}

/// Root README replacement requires an explicit reasoned exclusion.
///
/// # Panics
/// Panics only if fixture IO fails or README selection violates its contract.
/// ´test:integration:root-readme-replacement-requires-exclusion´
#[test]
fn root_readme_replacement_requires_exclusion() {
    for selector in ["README.md", "README.*"] {
        let root = fixture();
        let source = root.path().join("source");
        let out = root.path().join("out");
        fs::write(source.join("README.md"), "private root README\n").expect("root README");
        for excluded in [false, true] {
            let manifest = if excluded {
                MANIFEST.replace(
                    "[exclude]\nrows = [",
                    &format!("[exclude]\nrows = [{{ pattern = \"{selector}\", reason = \"Public README replaces it.\" }}, "),
                )
            } else {
                MANIFEST.replace(
                    "[include]\nrows = [",
                    &format!("[include]\nrows = [{{ pattern = \"{selector}\" }}, "),
                )
            };
            fs::write(source.join("public-set.toml"), manifest).expect("README selection");
            git(&source, &["add", "."]);
            git(
                &source,
                &["commit", "-q", "--no-gpg-sign", "-m", "README selection"],
            );
            git(&source, &["tag", "-f", "source-v1"]);
            let output = cut(&source, &out, None, true);
            if excluded {
                success(output);
                assert_eq!(
                    fs::read(out.join("README.md")).expect("public README"),
                    b"public readme\n"
                );
            } else {
                assert_eq!(output.status.code(), Some(3));
                let report = String::from_utf8_lossy(&output.stdout);
                assert!(report.contains(&format!("include selector {selector}")));
                assert!(report.contains("change the row to an exclusion with a reason"));
                assert!(!out.exists());
            }
        }
    }
}

fn refuses_consumed_input(input: &str) {
    let root = fixture();
    let source = root.path().join("source");
    fs::write(
        source.join("public-set.toml"),
        MANIFEST.replace("docs/readme.txt", input),
    )
    .expect("conflicting README source");
    git(&source, &["add", "public-set.toml"]);
    git(
        &source,
        &["commit", "-q", "--no-gpg-sign", "-m", "Conflicting README"],
    );
    git(&source, &["tag", "-f", "source-v1"]);
    let out = root.path().join("out");
    let output = cut(&source, &out, None, true);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("public README source must differ from manifest and licence paths")
    );
    assert!(!out.exists());
}
