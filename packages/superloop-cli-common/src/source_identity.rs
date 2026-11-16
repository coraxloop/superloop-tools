//! Build-time source evidence under the existing clean-HEAD release rule.
//!
//! Full Git object digests bind candidate source to the independently reviewed
//! public revision; a candidate supplier cannot replace that retained reference.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Source evidence compiled into a program, never read from a runtime sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentity {
    /// Explicitly checked public commit, or the public checkout's HEAD.
    pub commit: Option<String>,
    /// Tree of the checked public commit, independent of its history.
    pub tree: Option<String>,
    /// Release, candidate, dirty, or unknown.
    pub state: &'static str,
    /// Explicit tag resolving to the clean, unoverlaid checkout HEAD.
    pub release_tag: Option<String>,
}

fn git(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot inspect build source: {error}"))?;
    if !output.status.success() {
        return Err("cannot inspect build source with Git".to_owned());
    }
    Ok(output.stdout)
}

fn text(root: &Path, arguments: &[&str]) -> Result<String, String> {
    String::from_utf8(git(root, arguments)?)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "build source identity is not UTF-8".to_owned())
}

/// Apply the release predicate used by the installer and Meson's release tag:
/// an explicit tag resolves to the requested commit and to a clean checkout HEAD.
///
/// # Errors
/// Refuses absent, mismatched or dirty release identity.
pub fn verify_release(root: &Path, tag: &str, commit: &str) -> Result<(), String> {
    if tag.is_empty() || commit.is_empty() {
        return Err("release tag and commit must be explicit".to_owned());
    }
    let head = text(root, &["rev-parse", "HEAD"])?;
    let tagged = text(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/tags/{tag}^{{commit}}"),
        ],
    )?;
    let dirty = git(root, &["status", "--porcelain", "--untracked-files=all"])?;
    if head != commit || tagged != commit || !dirty.is_empty() {
        return Err("release tag must name the clean checkout HEAD".to_owned());
    }
    Ok(())
}

/// Git metadata that invalidates compiled source observations, including worktrees.
///
/// Watch indexed and existing nonignored inputs, not generated directories.
/// A newly created untracked file is observed at the next build-script run;
/// it does not change the identity of an already-built executable.
/// Missing Git history leaves only the source directory to watch.
#[must_use]
pub fn watch_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )
    .ok()
    .and_then(|bytes| String::from_utf8(bytes).ok())
    .map_or_else(
        || vec![root.to_owned()],
        |files| {
            files
                .split('\0')
                .filter(|path| !path.is_empty())
                .map(|path| root.join(path))
                .collect::<Vec<_>>()
        },
    );
    for name in ["HEAD", "index", "refs", "packed-refs"] {
        if let Ok(path) = text(root, &["rev-parse", "--git-path", name]) {
            let path = PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            if path.exists() {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn verify_overlay(root: &Path, commit: &str, head: &str) -> Result<(), String> {
    let overlay = git(
        root,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            commit,
            head,
            "--",
        ],
    )?;
    let entries: Vec<_> = overlay
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect();
    if !entries.len().is_multiple_of(2)
        || entries
            .as_chunks::<2>()
            .0
            .iter()
            .any(|entry| !matches!(*entry, [b"A", b"Cargo.lock"] | [b"M", b"public-set.toml"]))
    {
        return Err(
            "build overlay differs outside Cargo.lock added and public-set.toml modified"
                .to_owned(),
        );
    }
    Ok(())
}

/// Observe source state and check an explicitly handed-over public commit.
///
/// The closed private overlay permits only adding Cargo.lock and modifying the
/// public-set manifest. Parent position is never evidence of public identity.
///
/// # Errors
/// In a source checkout, refuses an invalid explicit source, a private source
/// guess, an extra overlay path, or a mismatched release request. Archives without
/// that history remain unknown; supplied metadata cannot lend them a source name.
pub fn observe(
    root: &Path,
    public_commit: Option<&str>,
    release_tag: Option<&str>,
) -> Result<SourceIdentity, String> {
    let unknown = || SourceIdentity {
        commit: None,
        tree: None,
        state: "unknown",
        release_tag: None,
    };
    let top = text(root, &["rev-parse", "--show-toplevel"]);
    if !matches!((top.as_ref().ok().and_then(|value| std::fs::canonicalize(value).ok()), std::fs::canonicalize(root).ok()), (Some(top), Some(root)) if top == root)
    {
        return Ok(unknown());
    }
    let Ok(head) = text(root, &["rev-parse", "HEAD"]) else {
        let dirty = git(root, &["status", "--porcelain", "--untracked-files=all"])
            .is_ok_and(|status| !status.is_empty());
        return Ok(SourceIdentity {
            state: if dirty { "dirty" } else { "unknown" },
            ..unknown()
        });
    };
    let selected = public_commit.unwrap_or(&head);
    if !matches!(selected.len(), 40 | 64) || !selected.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("public source commit must be a full Git object ID".to_owned());
    }
    let commit = text(
        root,
        &["rev-parse", "--verify", &format!("{selected}^{{commit}}")],
    )?;
    let dirty = !git(root, &["status", "--porcelain", "--untracked-files=all"])?.is_empty();
    if let Some(release) = release_tag {
        verify_release(root, release, &head)?;
    }
    let locked = git(
        root,
        &["ls-tree", "--name-only", &commit, "--", "Cargo.lock"],
    )?;
    if !locked.is_empty() {
        return if public_commit.is_some() {
            Err(
                "public source commit contains the private Cargo.lock; do not guess a merge parent"
                    .to_owned(),
            )
        } else {
            Ok(SourceIdentity {
                state: if dirty { "dirty" } else { "unknown" },
                ..unknown()
            })
        };
    }
    verify_overlay(root, &commit, &head)?;
    let mut state = if dirty { "dirty" } else { "candidate" };
    let tag = if let Some(release) = release_tag
        && commit == head
    {
        state = "release";
        Some(release.to_owned())
    } else {
        None
    };
    Ok(SourceIdentity {
        tree: Some(text(
            root,
            &["rev-parse", "--verify", &format!("{commit}^{{tree}}")],
        )?),
        commit: Some(commit),
        state,
        release_tag: tag,
    })
}

#[cfg(test)]
mod tests {
    use super::{git, observe, text, verify_release, watch_paths};
    use std::path::Path;

    fn commit(root: &Path, message: &str) -> String {
        git(root, &["add", "."]).unwrap();
        git(
            root,
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                message,
            ],
        )
        .unwrap();
        text(root, &["rev-parse", "HEAD"]).unwrap()
    }

    fn repository() -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "public"]).unwrap();
        std::fs::write(root.path().join("README.md"), "Public source.\n").unwrap();
        std::fs::write(root.path().join("public-set.toml"), "public\n").unwrap();
        let head = commit(root.path(), "public source");
        (root, head)
    }

    /// Public trees distinguish source content from commit history and artifacts.
    ///
    /// # Panics
    /// Panics only if fixture Git operations fail or source evidence drifts.
    ///
    /// ´claim:identity:public-tree-compares-source-content´
    /// ´test:unit:public-tree-compares-source-content´
    #[test]
    fn public_tree_compares_source_content() {
        let (root, first) = repository();
        let a = observe(root.path(), None, None).unwrap();
        let second = commit(root.path(), "same tree, different history");
        let b = observe(root.path(), None, None).unwrap();
        assert_ne!(first, second);
        assert_eq!(a.tree, b.tree);
        assert_eq!(
            a.tree.as_deref(),
            Some(
                text(root.path(), &["rev-parse", "HEAD^{tree}"])
                    .unwrap()
                    .as_str()
            )
        );
        std::fs::write(root.path().join("README.md"), "Different public source.\n").unwrap();
        commit(root.path(), "different source");
        let c = observe(root.path(), None, None).unwrap();
        assert_ne!(a.tree, c.tree);
        std::fs::write(root.path().join("Cargo.lock"), "private lock\n").unwrap();
        commit(root.path(), "private overlay");
        let unknown = observe(root.path(), None, None).unwrap();
        assert_eq!(unknown.tree, None);
        let public = c.commit.unwrap();
        assert_eq!(
            observe(root.path(), Some(&public), None).unwrap().tree,
            c.tree
        );
    }

    /// Ignored build output neither dirties source nor retriggers its observer.
    ///
    /// # Panics
    /// Panics only if fixture IO fails or generated output becomes a source input.
    ///
    /// ´claim:identity:generated-output-is-not-a-source-watch´
    /// ´test:unit:generated-output-is-not-a-source-watch´
    #[test]
    fn generated_output_is_not_a_source_watch() {
        let (root, _) = repository();
        std::fs::write(root.path().join(".gitignore"), "/build/\n").unwrap();
        commit(root.path(), "declared build directory");
        std::fs::create_dir(root.path().join("build")).unwrap();
        std::fs::write(root.path().join("build/build.ninja"), "generated\n").unwrap();
        let paths = watch_paths(root.path());
        assert!(!paths.contains(&root.path().to_owned()));
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with(root.path().join("build")))
        );
        assert!(paths.contains(&root.path().join("README.md")));
        assert_eq!(observe(root.path(), None, None).unwrap().state, "candidate");
        std::fs::write(root.path().join("README.md"), "edited\n").unwrap();
        assert_eq!(observe(root.path(), None, None).unwrap().state, "dirty");
        std::fs::write(root.path().join("new-source.rs"), "new source\n").unwrap();
        assert!(watch_paths(root.path()).contains(&root.path().join("new-source.rs")));
    }

    /// A release is an explicit tag at the clean checkout HEAD, never a build profile.
    ///
    /// # Panics
    /// Panics only when fixture Git operations fail or release qualification drifts.
    ///
    /// ´claim:identity:release-is-the-existing-clean-head-rule´
    /// ´test:unit:release-is-the-existing-clean-head-rule´
    #[test]
    fn release_is_the_existing_clean_head_rule() {
        let (root, head) = repository();
        assert_eq!(observe(root.path(), None, None).unwrap().state, "candidate");
        git(root.path(), &["tag", "fixture-0.5.0"]).unwrap();
        let source = observe(root.path(), None, Some("fixture-0.5.0")).unwrap();
        assert_eq!(source.state, "release");
        assert_eq!(source.release_tag.as_deref(), Some("fixture-0.5.0"));
        assert_eq!(source.commit.as_deref(), Some(head.as_str()));
        std::fs::write(root.path().join("README.md"), "Dirty source.\n").unwrap();
        assert!(verify_release(root.path(), "fixture-0.5.0", &head).is_err());
        let dirty = observe(root.path(), None, None).unwrap();
        assert_eq!(dirty.state, "dirty");
        assert_eq!(dirty.commit.as_deref(), Some(head.as_str()));
        assert!(dirty.release_tag.is_none());
    }

    /// An explicitly named public commit survives a private merge while its
    /// lock-bearing first parent cannot be guessed as public provenance.
    ///
    /// # Panics
    /// Panics only when fixture Git operations fail or an unchecked parent qualifies.
    ///
    /// ´claim:identity:private-overlay-requires-the-explicit-public-source´
    /// ´test:unit:private-overlay-requires-the-explicit-public-source´
    #[test]
    fn private_overlay_requires_the_explicit_public_source() {
        let (root, base) = repository();
        git(root.path(), &["checkout", "-b", "private"]).unwrap();
        std::fs::write(root.path().join("Cargo.lock"), "private fixture lock\n").unwrap();
        std::fs::write(root.path().join("public-set.toml"), "private overlay\n").unwrap();
        let private = commit(root.path(), "private inputs");
        git(root.path(), &["checkout", "public"]).unwrap();
        let public = commit(root.path(), "public successor");
        assert_ne!(base, public);
        git(root.path(), &["checkout", "private"]).unwrap();
        git(
            root.path(),
            &[
                "-c",
                "commit.gpgsign=false",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "merge",
                "--no-ff",
                "--no-edit",
                "public",
            ],
        )
        .unwrap();
        assert_eq!(
            text(root.path(), &["rev-parse", "HEAD^1"]).unwrap(),
            private
        );
        assert_eq!(text(root.path(), &["rev-parse", "HEAD^2"]).unwrap(), public);
        let source = observe(root.path(), Some(&public), None).unwrap();
        assert_eq!(source.commit.as_deref(), Some(public.as_str()));
        assert_eq!(source.state, "candidate");
        assert!(source.release_tag.is_none());
        assert!(
            observe(root.path(), Some(&private), None)
                .unwrap_err()
                .contains("private Cargo.lock")
        );
        assert_eq!(observe(root.path(), None, None).unwrap().state, "unknown");
        git(root.path(), &["tag", "estate-fixture"]).unwrap();
        let tagged = observe(root.path(), Some(&public), Some("estate-fixture")).unwrap();
        assert_eq!(tagged.state, "candidate");
        assert!(tagged.release_tag.is_none());
        std::fs::write(
            root.path().join("unexpected.rs"),
            "additional committed source\n",
        )
        .unwrap();
        commit(root.path(), "extra overlay path");
        assert!(
            observe(root.path(), Some(&public), None)
                .unwrap_err()
                .contains("outside")
        );
    }

    /// Source archives do not borrow an enclosing repository's commit, and an
    /// unverifiable explicit source claim stays unknown rather than becoming fact.
    ///
    /// # Panics
    /// Panics only when fixture IO fails or an archive acquires unverified provenance.
    ///
    /// ´claim:identity:archives-do-not-borrow-an-enclosing-commit´
    /// ´test:unit:archives-do-not-borrow-an-enclosing-commit´
    #[test]
    fn archives_do_not_borrow_an_enclosing_commit() {
        let (root, head) = repository();
        let archive = root.path().join("archive");
        std::fs::create_dir(&archive).unwrap();
        let source = observe(&archive, None, None).unwrap();
        assert_eq!(source.state, "unknown");
        assert!(source.commit.is_none());
        assert_eq!(
            observe(&archive, Some(&head), None).unwrap().state,
            "unknown"
        );
        assert!(
            observe(&archive, Some(&head), None)
                .unwrap()
                .commit
                .is_none()
        );
        assert!(observe(root.path(), Some("HEAD"), None).is_err());
        let unborn = tempfile::tempdir().unwrap();
        git(unborn.path(), &["init", "-b", "public"]).unwrap();
        std::fs::write(unborn.path().join("source.rs"), "uncommitted source\n").unwrap();
        let source = observe(unborn.path(), None, None).unwrap();
        assert_eq!(source.state, "dirty");
        assert!(source.commit.is_none());
    }
}
