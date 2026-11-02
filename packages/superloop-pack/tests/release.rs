//! Built-command deployment releases and refusal atomicity.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .env("GNUPGHOME", root.join(".git/gnupg"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+02:00")
        .env("GIT_COMMITTER_DATE", "2000-01-02T00:00:00+02:00")
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

fn commit(root: &Path, message: &str) {
    git(root, &["add", "."]);
    git(root, &["commit", "--no-gpg-sign", "-qm", message]);
}

fn fixture(version: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("fixture");
    let root = directory.path();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.name", "Fixture"]);
    git(root, &["config", "user.email", "fixture@example.com"]);
    git(root, &["config", "tag.gpgsign", "false"]);
    git(root, &["config", "commit.gpgsign", "false"]);
    let home = root.join(".git/gnupg");
    fs::create_dir(&home).expect("GPG home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("GPG home mode");
    fs::write(
        root.join("Cargo.toml"),
        "[workspace.package]\nversion = '0.1.0'\n",
    )
    .expect("cargo");
    fs::write(
        root.join("public-set.toml"),
        "[public]\nname = 'fixture-tools'\n",
    )
    .expect("manifest");
    fs::write(root.join("CHANGELOG.md"), "# Changelog\n").expect("notes");
    commit(root, "root");
    git(root, &["checkout", "-qb", "development"]);
    fs::write(
        root.join("Cargo.toml"),
        format!("[workspace.package]\nversion = '{version}'\n"),
    )
    .expect("bump");
    commit(root, "version bump");
    fs::write(root.join("CHANGELOG.md"), format!("# Changelog\n\n## [Unreleased]\n\n## [{version}] - 2026-11-01\n\n### Added\n\n- Release fixture.\n\n[link]: https://example.com\n\n## [0.1.0] - 2026-01-01\n\n- Old notes.\n")).expect("notes");
    commit(root, "release notes");
    directory
}

fn release(root: &Path, version: &str, extra: &[&str]) -> Output {
    let main = git(root, &["rev-parse", "main"]);
    let development = git(root, &["rev-parse", "development"]);
    let mut args = extra.to_vec();
    if !extra.contains(&"--check") && !extra.contains(&"--dry-run") {
        if !extra.contains(&"--expected-main") {
            args.extend(["--expected-main", &main]);
        }
        if !extra.contains(&"--expected-development") {
            args.extend(["--expected-development", &development]);
        }
    }
    release_unpinned(root, version, &args)
}

fn release_unpinned(root: &Path, version: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_superloop-pack"))
        .env("GNUPGHOME", root.join(".git/gnupg"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["release", "--repository"])
        .arg(root)
        .args([
            "--version",
            version,
            "--manifest",
            "public-set.toml",
            "--author",
            "Publisher <publisher@example.com>",
        ])
        .args(extra)
        .output()
        .expect("release binary")
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("report")
}

fn snapshot(root: &Path) -> (String, String) {
    (
        git(root, &["show-ref"]),
        git(root, &["count-objects", "-v"]),
    )
}

fn refusal(root: &Path, version: &str, args: &[&str], reason: &str) -> String {
    assert_refusal(root, reason, || release(root, version, args))
}

fn assert_refusal(root: &Path, reason: &str, apply: impl FnOnce() -> Output) -> String {
    let before = snapshot(root);
    let output = apply();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(reason),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(snapshot(root), before, "refusal changed refs or objects");
    String::from_utf8(output.stdout).expect("refusal text")
}

fn verify_release(version: &str, date: Option<&str>) {
    let fixture = fixture(version);
    let root = fixture.path();
    git(root, &["config", "core.sharedRepository", "group"]);
    let main = git(root, &["rev-parse", "main"]);
    let development = git(root, &["rev-parse", "development"]);
    let tree = git(root, &["rev-parse", &format!("{}^{{tree}}", "development")]);
    let extra: Vec<_> = date.map_or_else(Vec::new, |date| vec!["--date", date]);
    let report = success(release(root, version, &extra));
    assert!(report.contains("version_source=\"Cargo.toml:workspace.package.version\""));
    let released = git(root, &["rev-parse", "main"]);
    assert_eq!(git(root, &["rev-parse", "development"]), released);
    assert_eq!(
        git(root, &["show", "-s", "--format=%P", "main"]),
        format!("{main} {development}")
    );
    assert_eq!(
        git(root, &["rev-parse", &format!("{}^{{tree}}", "main")]),
        tree
    );
    assert_eq!(
        git(
            root,
            &["show", "-s", "--format=%an <%ae>|%cn <%ce>", "main"]
        ),
        "Publisher <publisher@example.com>|Publisher <publisher@example.com>"
    );
    let expected_date = date.unwrap_or("2000-01-02T00:00:00+02:00");
    assert_eq!(
        git(root, &["show", "-s", "--format=%aI|%cI", "main"]),
        format!("{expected_date}|{expected_date}")
    );
    let tag = format!("v{version}");
    assert_eq!(
        git(root, &["rev-parse", &format!("{tag}^{{commit}}")]),
        released
    );
    let tag_object = git(root, &["cat-file", "tag", &tag]);
    for oid in [&released, &git(root, &["rev-parse", &tag])] {
        let path = root.join(".git/objects").join(&oid[..2]).join(&oid[2..]);
        let mode = fs::metadata(path)
            .expect("loose object")
            .permissions()
            .mode();
        assert_eq!(mode & 0o222, 0, "Git objects must be read-only");
        assert_ne!(mode & 0o040, 0, "shared objects must be group readable");
    }
    assert!(tag_object.ends_with(&format!(
        "fixture-tools {tag}\n\n### Added\n\n- Release fixture."
    )));
    assert!(tag_object.contains("tagger Publisher <publisher@example.com>"));
    assert!(!tag_object.contains("[link]"));
    assert!(report.contains(&format!(
        "body_bytes={}",
        "### Added\n\n- Release fixture.\n".len()
    )));
    assert!(report.contains(&format!(
        "refspecs refs/heads/main refs/heads/development refs/tags/{tag}"
    )));
}

/// Patch releases preserve the deployed tree and explicit metadata.
///
/// # Panics
/// Panics only if the fixture or release contract fails.
/// ´test:integration:patch-release´
#[test]
fn patch_release() {
    verify_release("0.1.1", Some("2026-11-01T12:34:56+03:00"));
}

/// Minor releases default both dates to the development committer time.
///
/// # Panics
/// Panics only if the fixture or release contract fails.
/// ´test:integration:minor-release´
#[test]
fn minor_release() {
    verify_release("0.2.0", None);
}

/// Documents releases read the declared version from committed development.
///
/// # Panics
/// Panics only if fixture IO or the release contract fails.
/// ´test:integration:documents-release-version´
#[test]
fn documents_release_version() {
    for mode in ["--check", "--dry-run", "apply"] {
        let fixture = fixture("0.1.1");
        let root = fixture.path();
        fs::remove_file(root.join("Cargo.toml")).expect("remove cargo");
        fs::write(
            root.join("public-set.toml"),
            "version = [1, 0, 0]\n[public]\nname = 'fixture-documents'\nversion = '0.1.1'\n",
        )
        .expect("manifest version");
        commit(root, "documents version");
        // Main still carries Cargo.toml: only development determines the source.
        git(root, &["checkout", "-q", "main"]);
        let before = snapshot(root);
        let args = if mode == "apply" { vec![] } else { vec![mode] };
        let report = success(release(root, "0.1.1", &args));
        assert!(report.contains("version_source=\"public-set.toml:public.version\""));
        if mode == "apply" {
            assert_eq!(
                git(root, &["rev-parse", "main"]),
                git(root, &["rev-parse", "development"])
            );
            assert!(git(root, &["cat-file", "tag", "v0.1.1"]).contains("fixture-documents v0.1.1"));
        } else {
            assert_eq!(snapshot(root), before);
        }
    }
}

/// Documents version refusals preserve refs and objects and identify the source.
///
/// # Panics
/// Panics only if fixture IO or refusal atomicity fails.
/// ´test:integration:documents-version-refusals´
#[test]
fn documents_version_refusals() {
    for (declaration, reason) in [
        ("version = '0.2.0'\n", "version-mismatch"),
        ("", "version-missing"),
        ("version = [1, 2, 3]\n", "reason=version "),
    ] {
        let fixture = fixture("0.1.1");
        let root = fixture.path();
        fs::remove_file(root.join("Cargo.toml")).expect("remove cargo");
        fs::write(
            root.join("public-set.toml"),
            format!("version = [1, 0, 0]\n[public]\nname = 'fixture-documents'\n{declaration}"),
        )
        .expect("manifest");
        commit(root, "documents version");
        let report = refusal(root, "0.1.1", &[], reason);
        assert!(report.contains("public-set.toml:public.version"));
    }
}

/// Cargo is authoritative and a declared public version must agree with it.
///
/// # Panics
/// Panics only if fixture IO or source precedence fails.
/// ´test:integration:cargo-version-precedence´
#[test]
fn cargo_version_precedence() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    success(release(root, "0.1.1", &["--check"]));
    fs::write(
        root.join("public-set.toml"),
        "[public]\nname = 'fixture-tools'\nversion = '0.1.1'\n",
    )
    .expect("manifest");
    commit(root, "matching manifest version");
    let report = success(release(root, "0.1.1", &["--check"]));
    assert!(report.contains("version_source=\"Cargo.toml:workspace.package.version\""));
    fs::write(
        root.join("public-set.toml"),
        "[public]\nname = 'fixture-tools'\nversion = '0.2.0'\n",
    )
    .expect("manifest");
    commit(root, "different manifest version");
    for mode in [vec!["--check"], vec!["--dry-run"], vec![]] {
        for requested in ["0.1.1", "0.2.0"] {
            let report = refusal(root, requested, &mode, "version-mismatch");
            assert!(report.contains("public-set.toml:public.version=0.2.0"));
            assert!(report.contains("Cargo.toml:workspace.package.version=0.1.1"));
        }
    }
    fs::write(root.join("Cargo.toml"), "invalid toml [").expect("invalid cargo");
    commit(root, "malformed cargo");
    refusal(root, "0.2.0", &[], "reason=version ");
}

/// A second release cannot create a duplicate merge.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:nothing-to-release´
#[test]
fn nothing_to_release() {
    let fixture = fixture("0.1.1");
    success(release(fixture.path(), "0.1.1", &[]));
    refusal(fixture.path(), "0.1.1", &[], "nothing-to-release");
}

/// Missing or empty notes refuse before writing, including with an override.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:missing-notes´
#[test]
fn missing_notes() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    for notes in [
        "# Changelog\n",
        "## [0.1.1]\n\n[link]: https://example.com\n",
    ] {
        fs::write(root.join("NOTES.md"), notes).expect("notes");
        commit(root, "invalid notes");
        let text = refusal(root, "0.1.1", &["--changelog", "NOTES.md"], "reason=notes");
        assert!(text.contains("selected changelog requires"));
        assert!(text.contains("## [0.1.1] (optionally - DATE)"));
        assert!(!text.contains("CHANGELOG.md"));
        refusal(
            root,
            "0.1.1",
            &["--changelog", "NOTES.md", "--tag-message", "override"],
            "reason=notes",
        );
    }
}

/// The requested version must match the pinned tree.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:version-mismatch´
#[test]
fn version_mismatch() {
    let fixture = fixture("0.1.1");
    refusal(fixture.path(), "0.2.0", &[], "version-mismatch");
}

/// An existing version tag is never replaced.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:existing-tag´
#[test]
fn existing_tag() {
    let fixture = fixture("0.1.1");
    git(fixture.path(), &["tag", "v0.1.1", "main"]);
    refusal(fixture.path(), "0.1.1", &[], "existing-tag");
}

/// Untracked and tracked work must be clean before release.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:dirty-tree´
#[test]
fn dirty_tree() {
    let fixture = fixture("0.1.1");
    fs::write(fixture.path().join("dirty"), "work").expect("dirty");
    refusal(fixture.path(), "0.1.1", &[], "dirty-tree");
}

/// Diverged main cannot be hidden by the development tree.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:main-not-ancestor´
#[test]
fn main_not_ancestor() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    git(root, &["checkout", "-q", "main"]);
    fs::write(root.join("divergence"), "main").expect("divergence");
    commit(root, "diverge");
    git(root, &["checkout", "-q", "development"]);
    refusal(root, "0.1.1", &[], "main-not-ancestor");
}

/// A deployment pin becomes stale when an import advances development.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:stale-development´
#[test]
fn stale_development() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    let main = git(root, &["rev-parse", "main"]);
    let development = git(root, &["rev-parse", "development"]);
    let before = snapshot(root);
    success(release(root, "0.1.1", &["--check"]));
    assert_eq!(snapshot(root), before);
    let lock = root.join(".git/refs/heads/development.lock");
    fs::write(&lock, "concurrent importer").expect("import lock");
    refusal(root, "0.1.1", &[], "stale-refs");
    fs::remove_file(lock).expect("unlock");
    fs::write(root.join("import"), "new development").expect("import");
    commit(root, "new import");
    refusal(
        root,
        "0.1.1",
        &[
            "--expected-main",
            &main,
            "--expected-development",
            &development,
        ],
        "stale-development",
    );
}

/// Dry run computes the same objects as apply without storing any objects.
///
/// # Panics
/// Panics only if the fixture or release contract fails.
/// ´test:integration:dry-run-no-writes´
#[test]
fn dry_run_no_writes() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    // Read from D even when the clean checkout is main; custom changelog is pinned too.
    git(root, &["mv", "CHANGELOG.md", "NOTES.md"]);
    fs::write(root.join("NOTES.md"), "## [0.1.1]\n\n- Undated notes.\n").expect("notes");
    commit(root, "custom notes");
    git(root, &["checkout", "-q", "main"]);
    let before = snapshot(root);
    let preview = success(release(
        root,
        "0.1.1",
        &["--dry-run", "--changelog", "NOTES.md"],
    ));
    assert_eq!(snapshot(root), before);
    let actual = success(release(root, "0.1.1", &["--changelog", "NOTES.md"]));
    assert_eq!(
        preview
            .lines()
            .next()
            .expect("preview")
            .replace("prepared", "locally-committed"),
        actual.lines().next().expect("actual")
    );
}

/// Explicit notes preserve every byte including trailing blank lines.
///
/// # Panics
/// Panics only if the fixture or release contract fails.
/// ´test:integration:tag-message-verbatim´
#[test]
fn tag_message_verbatim() {
    let fixture = fixture("0.1.1");
    let message = "Custom title\n\nExact notes.\n\n";
    success(release(
        fixture.path(),
        "0.1.1",
        &["--tag-message", message],
    ));
    // cat-file text helper trims; use the object size to prove the trailing bytes.
    let text = git(fixture.path(), &["cat-file", "tag", "v0.1.1"]);
    assert!(text.ends_with(message.trim_end()));
    let size: usize = git(fixture.path(), &["cat-file", "-s", "v0.1.1"])
        .parse()
        .expect("size");
    assert_eq!(size, text.len() + 2);
}

/// Apply requires both deployment pins, while previews can discover them.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:unpinned´
#[test]
fn unpinned() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    let main = git(root, &["rev-parse", "main"]);
    let development = git(root, &["rev-parse", "development"]);
    for args in [
        vec![],
        vec!["--expected-main", &main],
        vec!["--expected-development", &development],
    ] {
        assert_refusal(root, "reason=unpinned", || {
            release_unpinned(root, "0.1.1", &args)
        });
    }
    for mode in ["--check", "--dry-run"] {
        let before = snapshot(root);
        success(release_unpinned(root, "0.1.1", &[mode]));
        assert_eq!(snapshot(root), before);
    }
}

/// Release versions use canonical three-component numeric spelling.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:version´
#[test]
fn version() {
    let fixture = fixture("0.1.1");
    refusal(fixture.path(), "00.1.1", &[], "reason=version ");
}

/// The pinned manifest must name its public repository.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:manifest-name´
#[test]
fn manifest_name() {
    let fixture = fixture("0.1.1");
    fs::write(fixture.path().join("public-set.toml"), "[public]\n").expect("manifest");
    commit(fixture.path(), "remove name");
    refusal(fixture.path(), "0.1.1", &[], "reason=manifest-name");
}

/// A moved main refuses even when development still matches its pin.
///
/// # Panics
/// Panics only if the fixture or refusal contract fails.
/// ´test:integration:stale-main´
#[test]
fn stale_main() {
    let fixture = fixture("0.1.1");
    let root = fixture.path();
    let main = git(root, &["rev-parse", "main"]);
    git(
        root,
        &["update-ref", "refs/heads/main", "development~1", &main],
    );
    refusal(
        root,
        "0.1.1",
        &["--expected-main", &main],
        "reason=stale-main",
    );
}

struct SigningHome(PathBuf);

impl Drop for SigningHome {
    fn drop(&mut self) {
        // Both operations must run even during unwinding or after partial key creation.
        for args in [vec!["--kill", "gpg-agent"], vec!["--remove-socketdir"]] {
            let result = Command::new("gpgconf")
                .env("GNUPGHOME", &self.0)
                .args(args)
                .status();
            if !result.is_ok_and(|status| status.success()) {
                eprintln!("fixture GPG cleanup failed for {}", self.0.display());
            }
        }
    }
}

fn signing_key(root: &Path) -> String {
    let output = Command::new("gpg")
        .env("GNUPGHOME", root.join(".git/gnupg"))
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Release fixture <release@example.com>",
            "ed25519",
            "sign",
            "0",
        ])
        .output()
        .expect("generate throwaway key");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("gpg")
        .env("GNUPGHOME", root.join(".git/gnupg"))
        .args(["--batch", "--with-colons", "--list-secret-keys"])
        .output()
        .expect("list throwaway key");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("key listing");
    let key = text
        .lines()
        .find(|line| line.starts_with("fpr:"))
        .and_then(|line| line.split(':').nth(9))
        .expect("fingerprint")
        .to_owned();
    git(root, &["config", "user.signingkey", &key]);
    let signer = root.join(".git/test-signer");
    fs::write(
        &signer,
        "#!/bin/sh\nprintf 'invoked\\n' >> \"$GNUPGHOME/invocations\"\nexec gpg \"$@\"\n",
    )
    .expect("signer");
    fs::set_permissions(&signer, fs::Permissions::from_mode(0o700)).expect("signer mode");
    git(
        root,
        &[
            "config",
            "gpg.program",
            signer.to_str().expect("signer path"),
        ],
    );
    key
}

/// Each switch independently signs its object with the configured program and key.
///
/// # Panics
/// Panics only if isolated key generation or release verification fails.
/// ´test:integration:release-signing´
#[test]
fn release_signing() {
    for (commit_signing, tag_signing, signing) in [
        (true, true, "commit,tag"),
        (true, false, "commit"),
        (false, true, "tag"),
    ] {
        let fixture = fixture("0.1.1");
        let root = fixture.path();
        let _home = SigningHome(root.join(".git/gnupg"));
        let key = signing_key(root);
        git(
            root,
            &["config", "commit.gpgsign", &commit_signing.to_string()],
        );
        git(root, &["config", "tag.gpgsign", &tag_signing.to_string()]);
        let before = snapshot(root);
        for mode in ["--check", "--dry-run"] {
            let preview = success(release(root, "0.1.1", &[mode]));
            assert!(preview.contains(&format!("signing={signing} signing_key=null")));
            assert_eq!(snapshot(root), before);
            assert!(!root.join(".git/gnupg/invocations").exists());
        }
        let report = success(release(root, "0.1.1", &[]));
        assert!(report.contains(&format!("signing={signing} signing_key=\"{key}\"")));
        assert!(report.contains(&format!("R={} ", git(root, &["rev-parse", "main"]))));
        assert!(report.contains(&format!(
            "tag_object={} ",
            git(root, &["rev-parse", "v0.1.1"])
        )));
        assert_eq!(
            git(root, &["rev-parse", "main"]),
            git(root, &["rev-parse", "development"])
        );
        assert_eq!(
            git(root, &["rev-parse", "main"]),
            git(root, &["rev-parse", &format!("{}^{{commit}}", "v0.1.1")])
        );
        let commit = git(root, &["cat-file", "commit", "main"]);
        let tag = git(root, &["cat-file", "tag", "v0.1.1"]);
        assert_eq!(
            commit.contains("\ngpgsig -----BEGIN PGP SIGNATURE-----"),
            commit_signing
        );
        assert_eq!(tag.contains("\n-----BEGIN PGP SIGNATURE-----"), tag_signing);
        let calls = fs::read_to_string(root.join(".git/gnupg/invocations")).expect("signer calls");
        assert_eq!(
            calls.lines().count(),
            usize::from(commit_signing) + usize::from(tag_signing)
        );
        if commit_signing {
            git(root, &["verify-commit", "main"]);
        }
        if tag_signing {
            git(root, &["verify-tag", "v0.1.1"]);
        }
    }
}

/// Signer failure, including empty successful output, never promotes objects or refs.
///
/// # Panics
/// Panics only if fixture setup or refusal atomicity fails.
/// ´test:integration:release-signing-failure´
#[test]
fn release_signing_failure() {
    for switch in ["commit.gpgsign", "tag.gpgsign"] {
        for status in ["0", "1"] {
            let fixture = fixture("0.1.1");
            let root = fixture.path();
            git(root, &["config", switch, "true"]);
            git(root, &["config", "user.signingkey", "fixture-only"]);
            let signer = root.join(".git/failing-signer");
            fs::write(
                &signer,
                format!("#!/bin/sh\necho fixture-signer-failed >&2\nexit {status}\n"),
            )
            .expect("failing signer");
            fs::set_permissions(&signer, fs::Permissions::from_mode(0o700)).expect("signer mode");
            git(
                root,
                &[
                    "config",
                    "gpg.program",
                    signer.to_str().expect("signer path"),
                ],
            );
            success(release(root, "0.1.1", &["--check"]));
            let report = refusal(root, "0.1.1", &[], "reason=signing");
            assert!(report.contains("fixture-signer-failed"));
        }
    }
}
