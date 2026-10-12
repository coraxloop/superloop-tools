use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::super::folder::{Folder, Kind, digest_of};
use super::super::output::{JOURNAL, MANIFEST, parse_root_manifest};
use super::super::owner::{Owned, journal_claims};
use super::super::render::{RenderError, write_loops_index};
use super::super::templates::{STYLESHEET, with_templates};
use super::fixture_projects;
use super::render::{attempt, copy_tree, manifest_at, render};

fn files_in(output: &Path) -> BTreeSet<String> {
    Folder::open(output)
        .expect("folder")
        .list(true)
        .expect("list")
        .into_iter()
        .filter(|entry| entry.kind == Kind::File)
        .map(|entry| entry.path)
        .collect()
}

fn gamma() -> std::path::PathBuf {
    fixture_projects().join("-home-alpha-dev-gamma")
}

/// ´test:crate:the-manifest-records-every-file-the-run-produced-with-its-digest´
#[test]
fn the_manifest_records_every_file_the_run_produced_with_its_digest() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    render(&gamma(), &output, 16_384);
    let manifest = manifest_at(&output);
    let listed: BTreeSet<String> = manifest
        .files
        .iter()
        .map(|owned| owned.path.clone())
        .collect();
    let mut present = files_in(&output);
    assert!(present.remove(MANIFEST));
    assert_eq!(listed, present);
    for owned in &manifest.files {
        let bytes = fs::read(output.join(&owned.path)).expect("file");
        assert_eq!(owned.sha256, digest_of(&bytes), "{}", owned.path);
    }
    for fixed in [
        "chat-export.css",
        "chat-export.js",
        "index.html",
        "pages.html",
        "c2/pages.html",
        "latest.html",
    ] {
        assert!(listed.contains(fixed), "{fixed}");
    }
}

/// ´test:crate:a-page-the-last-run-owns-and-this-run-does-not-make-is-removed´
#[test]
fn a_page_the_last_run_owns_and_this_run_does_not_make_is_removed() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    copy_tree(&gamma(), &project);
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let branch = "branches/SESSION-ID-B-01.html";
    assert!(
        manifest_at(&output)
            .files
            .iter()
            .any(|owned| owned.path == branch)
    );
    fs::remove_file(project.join("SESSION-ID-B.jsonl")).expect("drop the branch file");
    let after = render(&project, &output, 16_384);
    assert_eq!((after.files_removed, after.files_foreign), (1, 0));
    assert!(!output.join(branch).exists());
}

/// ´test:crate:a-folder-without-a-manifest-is-written-into-and-nothing-is-removed´
#[test]
fn a_folder_without_a_manifest_is_written_into_and_nothing_is_removed() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    fs::create_dir_all(output.join("old")).expect("folder");
    fs::write(output.join("reader-notes.md"), "mine").expect("note");
    fs::write(output.join("old/SESSION-ID-A.html"), "old page").expect("old page");
    let outcome = render(&gamma(), &output, 16_384);
    assert_eq!(
        (
            outcome.pages_rendered,
            outcome.files_removed,
            outcome.files_foreign
        ),
        (9, 0, 2)
    );
    assert_eq!(
        outcome.foreign,
        ["old/SESSION-ID-A.html", "reader-notes.md"]
    );
    assert_eq!(
        fs::read_to_string(output.join("reader-notes.md")).expect("kept"),
        "mine"
    );
    assert!(output.join("p0001.html").is_file());
}

/// ´test:crate:a-foreign-entry-where-the-run-writes-refuses-the-loop´
#[test]
fn a_foreign_entry_where_the_run_writes_refuses_the_loop() {
    for name in ["index.html", "branches", "c2"] {
        let root = tempfile::tempdir().expect("temporary directory");
        let output = root.path().join("gamma");
        fs::create_dir_all(&output).expect("folder");
        fs::write(output.join(name), "mine").expect("foreign file");
        let refused = attempt(&gamma(), &output, 16_384);
        assert!(
            matches!(&refused, Err(RenderError::Foreign(path)) if path == name),
            "{refused:?}"
        );
        assert_eq!(fs::read_to_string(output.join(name)).expect("kept"), "mine");
        assert_eq!(files_in(&output).len(), 1, "{name}");
    }
}

/// ´test:crate:a-forged-manifest-owns-only-generated-names-with-their-recorded-bytes´
#[test]
fn a_forged_manifest_owns_only_generated_names_with_their_recorded_bytes() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    render(&gamma(), &output, 16_384);
    let mut manifest = manifest_at(&output);
    let forge = |path: &str, bytes: &[u8]| Owned {
        path: path.to_owned(),
        sha256: digest_of(bytes),
    };
    fs::write(output.join("reader-notes.md"), "mine").expect("reader's file");
    fs::write(output.join("p0099.html"), "reader's page").expect("reader's page");
    fs::write(output.join("p0098.html"), "old page").expect("old page");
    manifest.files.push(forge("reader-notes.md", b"mine"));
    manifest.files.push(forge("p0099.html", b"other bytes"));
    manifest.files.push(forge("p0098.html", b"old page"));
    fs::write(
        output.join(MANIFEST),
        serde_json::to_vec(&manifest).expect("json"),
    )
    .expect("forge");
    let outcome = render(&gamma(), &output, 16_384);
    assert_eq!((outcome.files_removed, outcome.files_foreign), (1, 2));
    assert_eq!(outcome.foreign, ["p0099.html", "reader-notes.md"]);
    assert_eq!(
        fs::read_to_string(output.join("reader-notes.md")).expect("kept"),
        "mine"
    );
    assert_eq!(
        fs::read_to_string(output.join("p0099.html")).expect("kept"),
        "reader's page"
    );
    assert!(!output.join("p0098.html").exists());
    fs::write(output.join("index.html"), "edited by a reader").expect("edit");
    let refused = attempt(&gamma(), &output, 16_384);
    assert!(
        matches!(&refused, Err(RenderError::Foreign(path)) if path == "index.html"),
        "{refused:?}"
    );
    assert_eq!(
        fs::read_to_string(output.join("index.html")).expect("kept"),
        "edited by a reader"
    );
}

/// ´test:crate:a-manifest-without-digests-owns-nothing´
#[test]
fn a_manifest_without_digests_owns_nothing() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    render(&gamma(), &output, 16_384);
    let manifest = manifest_at(&output);
    let mut old = serde_json::to_value(&manifest).expect("json");
    old["schema"] = 1.into();
    old["files"] = manifest
        .files
        .iter()
        .map(|owned| owned.path.clone())
        .collect::<Vec<_>>()
        .into();
    fs::write(
        output.join(MANIFEST),
        serde_json::to_vec(&old).expect("json"),
    )
    .expect("old form");
    let before = files_in(&output);
    let page = fs::read(output.join("p0001.html")).expect("page");
    let refused = attempt(&gamma(), &output, 16_384);
    assert!(
        matches!(refused, Err(RenderError::Foreign(_))),
        "{refused:?}"
    );
    assert_eq!(files_in(&output), before);
    assert_eq!(fs::read(output.join("p0001.html")).expect("page"), page);
}

/// ´test:crate:an-interrupted-journal-append-keeps-every-complete-record´
#[test]
fn an_interrupted_journal_append_keeps_every_complete_record() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    let agents = output.join("agents");
    fs::create_dir_all(&agents).expect("agents folder");
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o555)).expect("read-only");
    let stopped = attempt(&gamma(), &output, 16_384);
    assert!(matches!(stopped, Err(RenderError::Io(_))), "{stopped:?}");
    assert!(output.join("p0001.html").is_file(), "a page written first");
    let journal = output.join(JOURNAL);
    let complete = fs::read(&journal).expect("journal");
    let claimed = journal_claims(&complete).expect("the journal's form");
    assert!(claimed.files.iter().any(|owned| owned.path == "p0001.html"));
    let mut interrupted = complete.clone();
    interrupted.extend_from_slice(&claimed.files[0].sha256.as_bytes()[..20]);
    fs::write(&journal, &interrupted).expect("an append cut before its line feed");
    let kept = journal_claims(&interrupted).expect("the complete records");
    assert_eq!(kept, claimed);
    let again = attempt(&gamma(), &output, 16_384);
    assert!(matches!(again, Err(RenderError::Io(_))), "{again:?}");
    let appended = fs::read(&journal).expect("journal");
    assert!(appended.len() > complete.len() && appended.starts_with(&complete));
    assert!(appended.ends_with(b"\n"));
    assert!(journal_claims(&appended).is_some_and(|read| read.files.len() > claimed.files.len()));
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o755)).expect("writable again");
    let clean = render(&gamma(), &output, 16_384);
    assert_eq!((clean.files_foreign, clean.files_removed), (0, 0));
    assert!(!journal.exists());
}

/// ´test:crate:the-loops-index-writes-over-only-its-own-files´
#[test]
fn the_loops_index_writes_over_only_its_own_files() {
    let environment = with_templates().expect("templates");
    let empty = tempfile::tempdir().expect("temporary directory");
    let folder = Folder::open(empty.path()).expect("root");
    let first = write_loops_index(&environment, &folder, &[]).expect("root");
    assert!(first.written && first.refused.is_empty());
    let root_manifest = |path: &Path| {
        parse_root_manifest(&fs::read(path.join("chat-export-root.json")).expect("root manifest"))
            .expect("parse")
            .files
            .into_iter()
            .map(|owned| owned.path)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        root_manifest(empty.path()),
        ["chat-export.css", "index.html"]
    );
    let second = write_loops_index(&environment, &folder, &[]).expect("root");
    assert!(!second.written && second.refused.is_empty());
    let foreign = tempfile::tempdir().expect("temporary directory");
    fs::write(foreign.path().join("index.html"), "mine").expect("foreign index");
    fs::write(foreign.path().join("chat-export.css"), STYLESHEET).expect("unowned stylesheet");
    let folder = Folder::open(foreign.path()).expect("root");
    let refused = write_loops_index(&environment, &folder, &[]).expect("root");
    assert_eq!(refused.refused, ["chat-export.css", "index.html"]);
    assert_eq!(
        fs::read_to_string(foreign.path().join("index.html")).expect("kept"),
        "mine"
    );
    assert_eq!(root_manifest(foreign.path()), Vec::<String>::new());
}
