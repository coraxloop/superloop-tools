use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

use super::super::input::{Project, Reached};
use super::super::load::Heads;
use super::super::output::SCHEMA;
use super::super::plan::{PAGE_BUDGET, plan};
use super::super::tree::Tree;
use super::super::view::read_bodies;
use super::render::{manifest_at, render};
use super::{discover, id, paths};

fn record(number: u64) -> String {
    format!(
        r#"{{"type":"user","uuid":"{}","message":{{"content":"hello"}},"timestamp":"2026-01-01T00:00:00Z"}}"#,
        id(number)
    ) + "\n"
}

/// ´test:crate:links-and-pipes-in-the-input-tree-are-left-unread-and-counted´
#[test]
fn links_and_pipes_in_the_input_tree_are_left_unread_and_counted() {
    let root = tempfile::tempdir().expect("temporary directory");
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir_all(elsewhere.join("subagents")).expect("another project's agents");
    fs::write(elsewhere.join("subagents/agent-x.jsonl"), record(9)).expect("its agent");
    fs::write(elsewhere.join("OTHER.jsonl"), record(8)).expect("its session");
    let project = root.path().join("project");
    fs::create_dir_all(project.join("SESSION-ID")).expect("session folder");
    fs::create_dir_all(project.join("SESSION-B/subagents")).expect("agents' folder");
    fs::write(project.join("SESSION-ID.jsonl"), record(1)).expect("session");
    symlink(elsewhere.join("OTHER.jsonl"), project.join("LINKED.jsonl"))
        .expect("linked transcript");
    mkfifo(&project.join("PIPE.jsonl"), Mode::S_IRUSR | Mode::S_IWUSR).expect("pipe");
    symlink(
        elsewhere.join("subagents"),
        project.join("SESSION-ID/subagents"),
    )
    .expect("linked agents' folder");
    symlink(
        elsewhere.join("subagents/agent-x.jsonl"),
        project.join("SESSION-B/subagents/agent-y.jsonl"),
    )
    .expect("linked agent file");
    symlink(&elsewhere, project.join("SESSION-L")).expect("linked session folder");
    let source = discover(&project);
    assert_eq!(paths(&source.sessions), [project.join("SESSION-ID.jsonl")]);
    assert_eq!(source.agents.len(), 0);
    assert_eq!(
        source.skipped,
        [
            project.join("LINKED.jsonl"),
            project.join("PIPE.jsonl"),
            project.join("SESSION-L"),
            project.join("SESSION-B/subagents/agent-y.jsonl"),
            project.join("SESSION-ID/subagents"),
        ]
    );
    let heads = Heads::load(&source).expect("load");
    assert_eq!((heads.files.len(), heads.report().skipped), (1, 5));
    fs::remove_file(project.join("SESSION-ID.jsonl")).expect("remove");
    symlink(
        elsewhere.join("OTHER.jsonl"),
        project.join("SESSION-ID.jsonl"),
    )
    .expect("a link where the session was listed");
    let heads = Heads::load(&source).expect("load");
    assert_eq!(heads.files.len(), 0);
    assert_eq!(
        heads.skipped.last(),
        Some(&project.join("SESSION-ID.jsonl"))
    );
    symlink(&project, root.path().join("linked-project")).expect("linked project folder");
    assert!(matches!(
        Project::open(root.path(), OsStr::new("linked-project")),
        Ok(Reached::Refused)
    ));
    assert!(matches!(
        Project::open(root.path(), OsStr::new("absent")),
        Ok(Reached::Absent)
    ));
}

/// ´test:crate:a-transcript-replaced-after-its-scan-is-not-read-for-a-page´
#[test]
fn a_transcript_replaced_after_its_scan_is_not_read_for_a_page() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let session = project.join("SESSION-ID.jsonl");
    fs::write(&session, record(1) + &record(2)).expect("session");
    let source = discover(&project);
    let changed = |heads: &Heads| {
        read_bodies(heads, &[0], 64)
            .expect_err("not the file scanned")
            .kind()
    };
    let heads = Heads::load(&source).expect("load");
    assert_eq!(
        read_bodies(&heads, &[0, 1], 64).expect("read").values.len(),
        2
    );
    let fresh = project.join("fresh");
    fs::write(&fresh, fs::read(&session).expect("bytes")).expect("the same bytes");
    fs::rename(&fresh, &session).expect("another file at the name");
    assert_eq!(changed(&heads), ErrorKind::InvalidData);
    let heads = Heads::load(&source).expect("load again");
    assert_eq!(read_bodies(&heads, &[1], 64).expect("read").values.len(), 1);
    fs::write(&session, record(1)).expect("cut short in place");
    assert_eq!(changed(&heads), ErrorKind::InvalidData);
    let heads = Heads::load(&source).expect("load again");
    let kept = root.path().join("kept.jsonl");
    fs::write(&kept, record(1)).expect("kept elsewhere");
    fs::remove_file(&session).expect("remove");
    symlink(&kept, &session).expect("a link at the name");
    assert_eq!(changed(&heads), ErrorKind::InvalidData);
    fs::remove_file(&session).expect("remove");
    mkfifo(&session, Mode::S_IRUSR | Mode::S_IWUSR).expect("a pipe at the name");
    assert_eq!(changed(&heads), ErrorKind::InvalidData);
}

/// A session of a prompt and a response whose text is `answer`.
fn answered(answer: &str) -> String {
    let prompt = record(1);
    let response = format!(
        r#"{{"type":"assistant","uuid":"{}","parentUuid":"{}","message":{{"id":"MESSAGE-ID-1","content":[{{"type":"text","text":"{answer}"}}]}},"timestamp":"2026-01-01T00:00:01Z"}}"#,
        id(2),
        id(1)
    ) + "\n";
    prompt + &response
}

/// ´test:crate:a-record-changed-to-text-of-the-same-length-renders-its-page-again´
#[test]
fn a_record_changed_to_text_of_the_same_length_renders_its_page_again() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let session = project.join("SESSION-ID.jsonl");
    fs::write(&session, answered("The first answer.")).expect("session");
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let page = output.join("p0001.html");
    assert!(
        fs::read_to_string(&page)
            .expect("page")
            .contains("The first answer.")
    );
    let before = fs::read(&session).expect("bytes");
    fs::write(&session, answered("The fixed answer.")).expect("same length, other text");
    assert_eq!(fs::read(&session).expect("bytes").len(), before.len());
    let again = render(&project, &output, 16_384);
    assert_eq!(again.pages_rendered, 1);
    let html = fs::read_to_string(&page).expect("page");
    assert!(html.contains("The fixed answer.") && !html.contains("The first answer."));
    let unchanged = render(&project, &output, 16_384);
    assert_eq!((unchanged.pages_rendered, unchanged.files_written), (0, 0));
}

/// ´test:crate:a-record-changed-between-its-scan-and-its-page-is-refused-by-its-digest´
#[test]
fn a_record_changed_between_its_scan_and_its_page_is_refused_by_its_digest() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let session = project.join("SESSION-ID.jsonl");
    fs::write(&session, answered("The first answer.")).expect("session");
    let heads = Heads::load(&discover(&project)).expect("load");
    assert_eq!(
        read_bodies(&heads, &[0, 1], 64).expect("read").values.len(),
        2
    );
    fs::write(&session, answered("The fixed answer.")).expect("changed in place");
    assert!(
        heads.files[0].reopen().is_ok(),
        "the same file, as long as it was"
    );
    assert_eq!(
        read_bodies(&heads, &[0], 64)
            .expect("the prompt is unchanged")
            .values
            .len(),
        1
    );
    let error = read_bodies(&heads, &[1], 64).expect_err("the response changed");
    assert_eq!(error.kind(), ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("changed under the run"),
        "{error}"
    );
}

/// ´test:crate:a-change-no-page-shows-changes-the-plan-digest-and-not-the-page-key´
#[test]
fn a_change_no_page_shows_changes_the_plan_digest_and_not_the_page_key() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let session = project.join("SESSION-ID.jsonl");
    let output = root.path().join("output");
    let digest = || {
        let heads = Heads::load(&discover(&project)).expect("load");
        let tree = Tree::build(&heads);
        plan(&heads, &tree, &[], PAGE_BUDGET).remove(0).digest
    };
    fs::write(&session, answered("The first answer.")).expect("session");
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 1);
    let (key, before) = (manifest_at(&output).pages[0].key.clone(), digest());
    let unshown = answered("The first answer.").replace(
        r#""timestamp":"2026-01-01T00:00:01Z""#,
        r#""timestamp":"2026-01-01T00:00:01Z","cwd":"~/dev/alpha""#,
    );
    fs::write(&session, unshown).expect("a field no page shows");
    assert_ne!(digest(), before);
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 0);
    assert_eq!(manifest_at(&output).pages[0].key, key);
}

/// ´test:crate:pages-whose-records-differ-only-in-their-bytes-have-different-whole-keys´
#[test]
fn pages_whose_records_differ_only_in_their_bytes_have_different_whole_keys() {
    let root = tempfile::tempdir().expect("temporary directory");
    let answers = [
        "The first answer.",
        "The fixed answer.",
        "The first answer.",
    ];
    let keys: Vec<(String, [u8; 32])> = answers
        .iter()
        .enumerate()
        .map(|(index, answer)| {
            let project = root.path().join(format!("project-{index}"));
            fs::create_dir_all(&project).expect("project");
            fs::write(project.join("SESSION-ID.jsonl"), answered(answer)).expect("session");
            let heads = Heads::load(&discover(&project)).expect("load");
            let tree = Tree::build(&heads);
            let page = plan(&heads, &tree, &[], PAGE_BUDGET).remove(0);
            let output = root.path().join(format!("output-{index}"));
            render(&project, &output, 16_384);
            let manifest = manifest_at(&output);
            assert_eq!(manifest.schema, SCHEMA);
            assert_eq!(manifest.templates.len(), 64);
            (manifest.pages[0].key.clone(), page.digest)
        })
        .collect();
    for (key, _) in &keys {
        assert_eq!(key.len(), 64, "{key}");
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()), "{key}");
    }
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[0].0, keys[1].0);
    assert_ne!(keys[0].1, keys[1].1);
    assert_eq!(keys[0], keys[2]);
}
