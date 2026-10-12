use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use super::super::agents::{attach, load_agents};
use super::super::folder::Folder;
use super::super::load::Heads;
use super::super::output::{MANIFEST, Manifest, PageEntry, parse_manifest, previous_keys};
use super::super::plan::{PAGE_BUDGET, PageKind, plan};
use super::super::render::{
    Header, Outcome, PageContext, RenderError, Settings, keyed, render_loop,
};
use super::super::templates::with_templates;
use super::super::tree::Tree;
use super::super::view::{Block, Link, PromptView, TurnView};
use super::conserve::{conservation, records_planned};
use super::paging::{PROMPT, line, padded};
use super::{discover, fixture_projects, id};

pub(super) fn render(project: &Path, output: &Path, limit: usize) -> Outcome {
    attempt(project, output, limit).expect("render")
}

pub(super) fn attempt(project: &Path, output: &Path, limit: usize) -> Result<Outcome, RenderError> {
    attempt_paged(project, output, limit, PAGE_BUDGET)
}

pub(super) fn attempt_paged(
    project: &Path,
    output: &Path,
    limit: usize,
    budget: u64,
) -> Result<Outcome, RenderError> {
    let source = discover(project);
    let heads = Heads::load(&source).expect("load");
    let (mut agents, _) = load_agents(&source.agents).expect("agents");
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    let pages = plan(&heads, &tree, &agents, budget);
    let environment = with_templates().expect("templates");
    fs::create_dir_all(output).expect("output folder");
    let folder = Folder::open(output)?;
    let settings = Settings {
        name: "gamma",
        project,
        folder: &folder,
        limit,
        program: "superloop-chat-export test",
    };
    render_loop(&environment, &heads, &tree, &agents, &pages, &settings)
}

/// The manifest a render left in `output`.
pub(super) fn manifest_at(output: &Path) -> Manifest {
    parse_manifest(&fs::read(output.join(MANIFEST)).expect("manifest")).expect("parse manifest")
}

pub(super) fn html_files(root: &Path) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).expect("list") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "html")
            {
                let name = path
                    .strip_prefix(root)
                    .expect("inside")
                    .to_string_lossy()
                    .into_owned();
                files.insert(name, fs::read_to_string(&path).expect("read"));
            }
        }
    }
    files
}

pub(super) fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("directory");
    for entry in fs::read_dir(from).expect("list") {
        let path = entry.expect("entry").path();
        let target = to.join(path.file_name().expect("name"));
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).expect("copy");
        }
    }
}

fn gamma_rendered() -> (tempfile::TempDir, PathBuf, BTreeMap<String, String>) {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    let files = html_files(&output);
    (root, output, files)
}

fn anchor(number: u64) -> String {
    format!(r#"id="r-{}""#, id(number))
}

/// ´test:crate:every-record-is-anchored-exactly-once-across-the-pages´
#[test]
fn every_record_is_anchored_exactly_once_across_the_pages() {
    let (_root, output, files) = gamma_rendered();
    let project = fixture_projects().join("-home-alpha-dev-gamma");
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.records,
            found.records_shown_once,
            found.calls_shown_once
        ),
        (found.records_shown_once, 38, found.calls)
    );
    assert_eq!(records_planned(&project, PAGE_BUDGET), (38, 38));
    let every: Vec<u64> = (0x501..=0x509)
        .chain(0x510..=0x519)
        .chain(0x520..=0x525)
        .chain([
            0x5b1, 0x5b2, 0x5d1, 0x5d2, 0x5e1, 0x5e2, 0xa01, 0xa02, 0xa03, 0xa04, 0xb01, 0xb02,
            0xc01,
        ])
        .collect();
    for number in every {
        let count: usize = files
            .values()
            .map(|html| html.matches(&anchor(number)).count())
            .sum();
        assert_eq!(count, 1, "record {number:x}");
    }
    let anchors: usize = files
        .values()
        .map(|html| html.matches(r#"id="r-"#).count())
        .sum();
    assert_eq!(anchors, 25 + 6 + 7);
}

/// ´test:crate:no-record-is-shown-before-its-parent´
#[test]
fn no_record_is_shown_before_its_parent() {
    let (_root, _output, files) = gamma_rendered();
    let source = discover(&fixture_projects().join("-home-alpha-dev-gamma"));
    let heads = Heads::load(&source).expect("load");
    let tree = Tree::build(&heads);
    let pages = plan(&heads, &tree, &[], PAGE_BUDGET);
    let mut position = BTreeMap::new();
    for (index, page) in pages.iter().enumerate() {
        let html = &files[&page.path];
        for (offset, (at, _)) in html.match_indices(r#"id="r-"#).enumerate() {
            let id = &html[at + 6..at + 42];
            position.insert(id.to_owned(), (index, offset));
        }
    }
    let mut checked = 0;
    for (node, parent) in tree.links.parent.iter().enumerate() {
        let Some(parent) = parent else { continue };
        let child = &position[&heads.nodes[node].id.to_string()];
        let parent = &position[&heads.nodes[*parent].id.to_string()];
        assert!(parent < child, "{:?}", heads.nodes[node].id);
        checked += 1;
    }
    assert_eq!(checked, 29);
}

/// ´test:crate:pages-link-previous-next-index-and-latest´
#[test]
fn pages_link_previous_next_index_and_latest() {
    let (_root, _output, files) = gamma_rendered();
    let first = &files["p0001.html"];
    assert!(first.contains(r#"<span class="disabled">Previous</span>"#));
    assert!(first.contains(r#"<a rel="next" href="p0002.html">Next</a>"#));
    let middle = &files["p0002.html"];
    assert!(middle.contains(r#"<a rel="prev" href="p0001.html">Previous</a>"#));
    assert!(middle.contains(r#"<a rel="next" href="p0003.html">Next</a>"#));
    let last = &files["p0004.html"];
    assert!(last.contains(r#"<span class="disabled">Next</span>"#));
    for html in [first, middle, last] {
        assert!(html.contains(r#"<a href="index.html">Loop index</a>"#));
        assert!(html.contains(&format!("<a {}>All loops</a>", href("../index.html"))));
        assert!(html.contains(r#"<a href="latest.html">Latest</a>"#));
        assert!(html.contains(r#"<details class="pages" open>"#));
        assert!(html.contains(r#"<iframe src="pages.html" name="page-"#));
        assert!(html.contains(r#"href="chat-export.css""#));
    }
    let second = &files["c2/p0001.html"];
    assert!(second.contains(&format!("<a {}>All loops</a>", href("../../index.html"))));
    assert!(second.contains(r#"<iframe src="pages.html" name="page-1""#));
    assert!(files["latest.html"].contains("url=c2&#x2f;p0001.html"));
    let index = &files["index.html"];
    let fourth = index.find(r#"href="p0004.html""#).expect("page 4 listed");
    let first_row = index.find(r#"href="p0001.html""#).expect("page 1 listed");
    assert!(fourth < first_row, "newest first");
    assert!(index.contains("Summarise the notes."));
    assert!(index.contains("manual, 1200 tokens"));
    assert!(files["pages.html"].contains(r#"target="_top""#));
}

/// (´req:chatexport:lists-open´) (´req:chatexport:current-page-row´)
/// (´req:chatexport:opening-keeps-place´) (´req:chatexport:one-list-per-conversation´)
/// ´test:crate:each-main-page-opens-its-lists-and-names-one-shared-row´
#[test]
fn each_main_page_opens_its_lists_and_names_one_shared_row() {
    let (_root, output, files) = gamma_rendered();
    let manifest = manifest_at(&output);
    let main: Vec<&PageEntry> = manifest
        .pages
        .iter()
        .filter(|page| page.kind == PageKind::Main)
        .collect();
    assert_eq!(main.len(), 5);
    let lists: Vec<&str> = files
        .keys()
        .filter(|path| path.ends_with("pages.html"))
        .map(String::as_str)
        .collect();
    assert_eq!(lists, ["c2/pages.html", "pages.html"]);
    for page in main {
        let html = &files[&page.path];
        let stem = Path::new(&page.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("page stem");
        let number: usize = stem
            .strip_prefix('p')
            .expect("main page")
            .parse()
            .expect("number");
        let list = page.path.rsplit_once('/').map_or_else(
            || "pages.html".to_owned(),
            |(directory, _)| format!("{directory}/pages.html"),
        );
        let frame = format!(
            "<details class=\"pages\" open><summary>Pages · Current page {number}</summary><iframe src=\"pages.html\" name=\"page-{number}\" title=\"Pages of this conversation, current page {number}\" loading=\"lazy\"></iframe></details>"
        );
        assert_eq!(html.matches("<details class=\"pages\" open>").count(), 2);
        assert_eq!(html.matches(&frame).count(), 2);
        assert_eq!(html.matches("src=\"pages.html\"").count(), 2);
        assert_eq!(html.matches("name=\"page-").count(), 2);
        assert!(!html.contains("pages.html#"));
        if html.contains("<details class=\"prompts\"") {
            assert!(html.contains("<details class=\"prompts\" open>"));
        }
        let rows = &files[&list];
        assert_eq!(rows.matches(&format!("id=\"page-{number}\"")).count(), 1);
        assert_eq!(
            rows.matches(" id=\"page-").count(),
            manifest
                .pages
                .iter()
                .filter(
                    |entry| entry.kind == PageKind::Main && entry.conversation == page.conversation
                )
                .count()
        );
    }
    for page in manifest
        .pages
        .iter()
        .filter(|page| page.kind == PageKind::Branch)
    {
        assert!(!files[&page.path].contains("#page-"));
        assert!(!files[&page.path].contains("name=\"page-"));
    }
    let script = super::super::templates::SCRIPT;
    assert_eq!(script.matches("window.name").count(), 1);
    assert!(script.contains("/^page-[1-9][0-9]*$/"));
    assert!(script.contains("document.getElementById(name)"));
    assert!(script.contains("setAttribute(\"aria-current\", \"page\")"));
    assert!(script.contains("scroller.scrollTop"));
    assert!(!script.contains("tr:target"));
    assert!(!script.contains("scrollIntoView"));
    assert!(super::super::templates::STYLESHEET.contains("main.list table.pages tr.current-page"));
    let again = render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    assert_eq!(again.pages_rendered, 0);
    assert_eq!(again.files_written, 0);
    assert_eq!(html_files(&output), files);
    let mut previous = manifest_at(&output);
    previous.templates = "previous templates and assets".to_owned();
    fs::write(
        output.join(MANIFEST),
        serde_json::to_vec_pretty(&previous).expect("old manifest"),
    )
    .expect("old manifest on disk");
    let refreshed = render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    assert_eq!(refreshed.pages_rendered, manifest.pages.len());
    assert_eq!(html_files(&output), files);
    let stable = render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    assert_eq!(stable.pages_rendered, 0);
    assert_eq!(stable.files_written, 0);
}

/// (´req:chatexport:current-page-row´) (´req:chatexport:opening-keeps-place´)
/// ´test:crate:a-standalone-page-list-cannot-inherit-a-current-page´
#[test]
fn a_standalone_page_list_cannot_inherit_a_current_page() {
    let (_root, _output, files) = gamma_rendered();
    for list in ["pages.html", "c2/pages.html"] {
        let html = &files[list];
        assert!(!html.contains("name=\"page-"));
        assert!(!html.contains("aria-current=\"page\""));
        assert!(!html.contains("class=\"current-page\""));
        assert!(!html.contains("Current page"));
    }
    let script = super::super::templates::SCRIPT;
    let top = script
        .find("if (window.self === window.top) return;")
        .expect("top guard");
    let shape = script.find("/^page-[1-9][0-9]*$/").expect("name shape");
    let frame = script
        .find("frame = window.frameElement;")
        .expect("optional frame evidence");
    let fallback = script.find("frame = null;").expect("file origin fallback");
    let validation = script.find("if (frame) {").expect("available frame check");
    let place = script
        .find("frame.matches(\"nav.pager > details.pages > iframe\")")
        .expect("generated frame position");
    let address = script
        .find("frame.getAttribute(\"src\") !== \"pages.html\"")
        .expect("shared list address");
    let name = script
        .find("frame.getAttribute(\"name\") !== name")
        .expect("frame's own name");
    let row = script
        .find("document.getElementById(name)")
        .expect("row lookup");
    let mark = script
        .find("row.classList.add(\"current-page\")")
        .expect("row mark");
    let scroll = script.find("scroller.scrollTop +=").expect("frame scroll");
    assert_eq!(script.matches("window.frameElement").count(), 1);
    assert_eq!(script.matches("document.getElementById(name)").count(), 1);
    assert!(top < shape && shape < frame && frame < fallback);
    assert!(fallback < validation && validation < place);
    assert!(place < address && address < name && name < row);
    assert!(row < mark && mark < scroll);
}

/// (´req:chatexport:lists-open´)
/// ´test:crate:a-page-with-no-prompts-has-no-prompt-disclosure´
#[test]
fn a_page_with_no_prompts_has_no_prompt_disclosure() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir(&project).expect("project");
    fs::write(
        project.join("SESSION-ID-N.jsonl"),
        format!(
            r#"{{"uuid":"{}","parentUuid":null,"timestamp":"2026-05-01T10:00:00.000Z","type":"assistant","message":{{"id":"MESSAGE-ID-N","content":[{{"type":"text","text":"An answer without a prompt."}}]}}}}"#,
            id(0x900)
        ) + "\n",
    )
    .expect("session");
    let output = root.path().join("output");
    render(&project, &output, 16_384);
    let html = fs::read_to_string(output.join("p0001.html")).expect("main page");
    assert_eq!(html.matches("<details class=\"pages\" open>").count(), 2);
    assert!(html.contains("<summary>Pages · Current page 1</summary>"));
    assert!(!html.contains("<details class=\"prompts\""));
}

/// ´test:crate:owner-messages-show-their-form-and-the-queued-marker´
#[test]
fn owner_messages_show_their_form_and_the_queued_marker() {
    let (_root, _output, files) = gamma_rendered();
    let last = &files["p0004.html"];
    let queued = last.find(&anchor(0x524)).expect("queued message");
    assert!(last[queued..].contains("Sent while the agent was working"));
    assert!(last.contains("Also check the dates."));
    assert!(last.contains("From another session"));
    let first = &files["p0001.html"];
    assert!(first.contains("Owner, command"));
    assert!(first.contains("No result was recorded."));
    assert!(first.contains("Read two files at once."));
    assert!(files["p0002.html"].contains("Compaction, manual, 1200 tokens before, 300 after"));
}

/// ´test:crate:agent-and-branch-pages-link-both-ways´
#[test]
fn agent_and_branch_pages_link_both_ways() {
    let (_root, _output, files) = gamma_rendered();
    let first = &files["p0001.html"];
    assert!(first.contains(&format!(
        "{}>Subagent: Read the notes</a>",
        href("agents/0123456789abcdef0-01.html")
    )));
    let call = |number: u64| format!("call-{}-0", id(number));
    assert!(first.contains(&format!(r#"id="{}""#, call(0x508))));
    assert!(first.contains(&href("branches/SESSION-ID-B-01.html")));
    let agent = &files["agents/0123456789abcdef0-01.html"];
    assert!(agent.contains(&href(&format!("../p0001.html#{}", call(0x508)))));
    assert!(agent.contains(&format!(
        "{}>Subagent: Count the lines</a>",
        href("0123456789abcdef1-01.html")
    )));
    let nested = &files["agents/0123456789abcdef1-01.html"];
    assert!(nested.contains(&href(&format!("0123456789abcdef0-01.html#{}", call(0xa02)))));
    assert!(
        files["agents/0123456789abcdef2-01.html"].contains("No loaded transcript holds the call")
    );
    let branch = &files["branches/SESSION-ID-B-01.html"];
    assert!(branch.contains(&href(&format!("../p0001.html#r-{}", id(0x505)))));
}

/// An `href` attribute as the escaping environment writes it: every `/` of a
/// path becomes a character reference, which browsers read back as `/`.
fn href(path: &str) -> String {
    format!(r#"href="{}""#, path.replace('/', "&#x2f;"))
}

/// ´test:crate:hostile-text-is-escaped-in-every-field´
#[test]
fn hostile_text_is_escaped_in_every_field() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("hostile");
    render(
        &fixture_projects().join("-home-alpha-dev-hostile"),
        &output,
        16_384,
    );
    let files = html_files(&output);
    let all: String = files.values().cloned().collect();
    assert!(!all.contains("<script>alert"));
    assert!(!all.contains("<img"));
    for field in [
        "title",
        "prompt",
        "thinking",
        "response",
        "name",
        "time",
        "result",
        "kind",
        "note",
        "queued",
        "peer",
        "command",
        "trigger",
        "summary",
        "subtype",
        "system",
        "agent",
        "type",
        "description",
    ] {
        assert!(
            all.contains(&format!("alert(&quot;{field}&quot;)")),
            "{field}"
        );
    }
    // A tool's input is shown as JSON, which puts a backslash before a quote.
    assert!(all.contains(r"alert(\&quot;input\&quot;)"));
    // A call's id is printed nowhere: its anchor and the links to it are made
    // from its place.
    assert!(!all.contains("alert(&quot;id&quot;)") && !all.contains("alert%28%22id"));
}

/// ´test:crate:blocks-cut-at-a-character-boundary-and-count-what-they-omit´
#[test]
fn blocks_cut_at_a_character_boundary_and_count_what_they_omit() {
    assert_eq!(
        Block::cut("abcdef", 4),
        Block {
            text: "abcd".to_owned(),
            omitted: 2
        }
    );
    assert_eq!(Block::cut("abc", 4).omitted, 0);
    let cut = Block::cut("aé€b", 3);
    assert_eq!((cut.text.as_str(), cut.omitted), ("aé", 4));
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        8,
    );
    let first = fs::read_to_string(output.join("p0001.html")).expect("page");
    assert!(first.contains("Summaris<span class=\"omitted\">[12 bytes omitted]</span>"));
}

fn entry(path: &str, kind: PageKind, conversation: Option<usize>, key: &str) -> PageEntry {
    PageEntry {
        path: path.to_owned(),
        kind,
        conversation,
        records: [0, 0],
        key: key.to_owned(),
    }
}

fn manifest(pages: Vec<PageEntry>) -> Manifest {
    Manifest {
        schema: 1,
        program: "superloop-chat-export 1".to_owned(),
        templates: "t".to_owned(),
        max_block_bytes: 10,
        pages,
        ..Manifest::default()
    }
}

/// ´test:crate:the-manifest-decides-which-pages-to-render´
#[test]
fn the_manifest_decides_which_pages_to_render() {
    let pages = |keys: [&str; 5]| {
        manifest(vec![
            entry("p1", PageKind::Main, Some(0), keys[0]),
            entry("p2", PageKind::Main, Some(0), keys[1]),
            entry("p3", PageKind::Main, Some(0), keys[2]),
            entry("b1", PageKind::Branch, Some(0), keys[3]),
            entry("a1", PageKind::Agent, None, keys[4]),
        ])
    };
    let before = pages(["1", "2", "3", "4", "5"]);
    assert!(previous_keys(None, &before).is_none());
    let keys = previous_keys(Some(&before), &before).expect("comparable");
    assert_eq!(
        ["p1", "p2", "p3", "b1", "a1"].map(|path| keys.get(path).copied()),
        [Some("1"), Some("2"), Some("3"), Some("4"), Some("5")]
    );
    let mut program = before.clone();
    program.program = "superloop-chat-export 2".to_owned();
    assert!(previous_keys(Some(&before), &program).is_none());
    let mut templates = before.clone();
    templates.templates = "u".to_owned();
    assert!(previous_keys(Some(&before), &templates).is_none());
    let mut limit = before.clone();
    limit.max_block_bytes = 11;
    assert!(previous_keys(Some(&before), &limit).is_none());
}

/// ´test:crate:a-foreign-file-survives-two-runs-and-is-counted´
#[test]
fn a_foreign_file_survives_two_runs_and_is_counted() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    let project = fixture_projects().join("-home-alpha-dev-gamma");
    let first = render(&project, &output, 16_384);
    assert_eq!(
        (
            first.pages_rendered,
            first.files_removed,
            first.files_foreign
        ),
        (9, 0, 0)
    );
    let produced = first.files_written;
    fs::write(output.join("SESSION-ID-OLD.html"), "old").expect("foreign page");
    fs::create_dir_all(output.join("c9")).expect("foreign directory");
    fs::write(output.join("c9/p0001.html"), "note").expect("foreign page");
    for _ in 0..2 {
        assert_eq!(
            render(&project, &output, 16_384),
            Outcome {
                pages_rendered: 0,
                files_written: 0,
                files_unchanged: produced,
                files_removed: 0,
                files_foreign: 2,
                foreign: vec!["SESSION-ID-OLD.html".to_owned(), "c9/p0001.html".to_owned()],
            }
        );
    }
    assert_eq!(
        fs::read_to_string(output.join("SESSION-ID-OLD.html")).expect("kept"),
        "old"
    );
    assert_eq!(
        fs::read_to_string(output.join("c9/p0001.html")).expect("kept"),
        "note"
    );
    let listed = manifest_at(&output).files;
    assert_eq!(
        listed.len() + 1,
        produced,
        "every produced file but the manifest"
    );
    for foreign in ["SESSION-ID-OLD.html", "c9/p0001.html"] {
        assert!(
            !listed.iter().any(|owned| owned.path == foreign),
            "{foreign}"
        );
    }
}

/// ´test:crate:an-appended-transcript-renders-from-the-first-changed-page´
#[test]
fn an_appended_transcript_renders_from_the_first_changed_page() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    copy_tree(&fixture_projects().join("-home-alpha-dev-gamma"), &project);
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let session = project.join("SESSION-ID-D.jsonl");
    let mut text = fs::read_to_string(&session).expect("session");
    writeln!(
        text,
        r#"{{"parentUuid":"{}","type":"assistant","message":{{"id":"MESSAGE-ID-D2","content":[{{"type":"text","text":"One more line."}}]}},"uuid":"{}","timestamp":"2026-02-01T12:00:02.000Z","sessionId":"SESSION-ID-D"}}"#,
        id(0x5d2),
        id(0x5d3)
    )
    .expect("write to a string");
    fs::write(&session, text).expect("append");
    let appended = render(&project, &output, 16_384);
    assert_eq!(appended.pages_rendered, 1);
    assert!(
        fs::read_to_string(output.join("p0004.html"))
            .expect("page")
            .contains("One more line.")
    );
    let manifest_path = output.join(MANIFEST);
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("parse");
    manifest.program = "superloop-chat-export 0.0.0".to_owned();
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("serialise"),
    )
    .expect("write");
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 9);
}

/// ´test:crate:every-value-a-page-template-receives-is-in-its-key´
#[test]
fn every_value_a_page_template_receives_is_in_its_key() {
    fn leaves(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(members) => {
                for (name, member) in members {
                    leaves(member, &format!("{path}/{name}"), found);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    leaves(item, &format!("{path}/{index}"), found);
                }
            }
            _ => found.push(path.to_owned()),
        }
    }
    let header = Header {
        template: "page.html",
        loop_name: "gamma".to_owned(),
        heading: "Conversation 1 · page 1".to_owned(),
        ..Header::default()
    };
    let context = PageContext {
        header: &header,
        prompts_summary: "1 prompt on this page".to_owned(),
        prompts: vec![PromptView {
            href: "#r-1".to_owned(),
            time: "10:00 UTC".to_owned(),
            line: "Read the notes".to_owned(),
        }],
        turns: vec![TurnView {
            items: Vec::new(),
            forks: vec![Link {
                href: "branches/x-01.html".to_owned(),
                label: "A branch".to_owned(),
            }],
            before: None,
            after: None,
        }],
    };
    let (_, value) = keyed(&context).expect("key");
    let rendered = serde_json::to_value(&value).expect("the rendered value");
    assert_eq!(
        rendered,
        serde_json::to_value(&context).expect("the context"),
        "the template renders the whole context"
    );
    let (key, _) = keyed(&rendered).expect("key");
    assert_eq!(key.len(), 64);
    let mut paths = Vec::new();
    leaves(&rendered, "", &mut paths);
    for nested in ["/turns/0/forks/0/label", "/prompts/0/line", "/nav/previous"] {
        assert!(paths.iter().any(|path| path == nested), "{nested}");
    }
    let mut seen = BTreeSet::from([key]);
    for path in &paths {
        let mut changed = rendered.clone();
        *changed.pointer_mut(path).expect("leaf") =
            serde_json::Value::from(format!("changed {path}"));
        let (other, _) = keyed(&changed).expect("key");
        assert!(seen.insert(other), "{path} is not in the key");
    }
}

/// The key a run stored for the page at `path` of the loop rendered into
/// `output`.
fn stored_key(output: &Path, path: &str) -> String {
    manifest_at(output)
        .pages
        .into_iter()
        .find(|page| page.path == path)
        .map(|page| page.key)
        .expect("a page of that path")
}

/// ´test:crate:an-agent-page-renders-again-when-only-its-metadata-changes´
#[test]
fn an_agent_page_renders_again_when_only_its_metadata_changes() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    let call = r#""type":"assistant","message":{"id":"MESSAGE-ID-C","content":[{"type":"tool_use","id":"TOOL-A","name":"Task","input":{}}]}"#;
    fs::write(
        project.join("SESSION-ID.jsonl"),
        line(0x900, None, PROMPT) + &line(0x901, Some(0x900), call),
    )
    .expect("session");
    fs::write(subagents.join("agent-a.jsonl"), line(0xa00, None, PROMPT)).expect("thread");
    let meta = |kind: &str, task: &str| {
        fs::write(
            subagents.join("agent-a.meta.json"),
            format!(r#"{{"agentType":"{kind}","description":"{task}","toolUseId":"TOOL-A"}}"#),
        )
        .expect("meta");
    };
    let (agent, calling) = ("agents/a-01.html", "p0001.html");
    let output = root.path().join("gamma");
    meta("general-purpose", "Read the notes");
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 2);
    let (agent_key, calling_key) = (stored_key(&output, agent), stored_key(&output, calling));
    let calling_bytes = fs::read(output.join(calling)).expect("calling page");
    meta("Explore", "Read the notes");
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 1);
    assert_ne!(stored_key(&output, agent), agent_key);
    assert_eq!(stored_key(&output, calling), calling_key);
    let html = fs::read_to_string(output.join(agent)).expect("agent page");
    assert!(html.contains("<dd>Explore</dd>") && !html.contains("general-purpose"));
    assert_eq!(
        fs::read(output.join(calling)).expect("calling page"),
        calling_bytes
    );
    meta("Explore", "Read the other notes");
    assert_eq!(render(&project, &output, 16_384).pages_rendered, 2);
    assert_ne!(stored_key(&output, calling), calling_key);
    assert!(
        fs::read_to_string(output.join(agent))
            .expect("agent page")
            .contains("<dd>Read the other notes</dd>")
    );
    assert!(
        fs::read_to_string(output.join(calling))
            .expect("calling page")
            .contains("Subagent: Read the other notes")
    );
}

/// ´test:crate:a-result-shown-apart-links-to-its-call-by-place-whatever-its-id´
#[test]
fn a_result_shown_apart_links_to_its_call_by_place_whatever_its_id() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    fs::write(project.join("SESSION-ID.jsonl"), line(0x900, None, PROMPT)).expect("session");
    let thread = |call_id: &str| {
        let call = padded(1_200, 0xa01, 0xa00, |pad| {
            format!(
                r#""type":"assistant","message":{{"id":"MESSAGE-ID-C","content":[{{"type":"tool_use","id":"{call_id}","name":"Task","input":{{"text":"{pad}"}}}}]}}"#
            )
        });
        let result = padded(700, 0xa02, 0xa01, |pad| {
            format!(
                r#""type":"user","sourceToolAssistantUUID":"{}","message":{{"content":[{{"type":"tool_result","content":"{pad}"}}]}}"#,
                id(0xa01)
            )
        });
        line(0xa00, None, PROMPT) + &call + &result
    };
    let (first, second) = ("agents/a-01.html", "agents/a-02.html");
    let output = root.path().join("gamma");
    fs::write(subagents.join("agent-a.jsonl"), thread("TOOL-AAAA")).expect("thread");
    attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    let call = format!("call-{}-0", id(0xa01));
    let apart = fs::read_to_string(output.join(second)).expect("second page");
    assert!(
        apart.contains(&format!(r#"href="a-01.html#{call}""#)),
        "{apart}"
    );
    let keys = (stored_key(&output, first), stored_key(&output, second));
    fs::write(subagents.join("agent-a.jsonl"), thread("TOOL-BBBB")).expect("the call's id changed");
    let again = attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    assert_eq!(again.pages_rendered, 0);
    assert_eq!(
        (stored_key(&output, first), stored_key(&output, second)),
        keys
    );
    let apart = fs::read_to_string(output.join(second)).expect("second page");
    assert!(
        apart.contains(&format!(r#"href="a-01.html#{call}""#)),
        "{apart}"
    );
    let calling = fs::read_to_string(output.join(first)).expect("first page");
    assert!(calling.contains(&format!(r#"id="{call}""#)) && !calling.contains("TOOL-BBBB"));
}

/// ´test:crate:a-page-renders-again-when-the-next-page-no-longer-continues-its-turn´
#[test]
fn a_page_renders_again_when_the_next_page_no_longer_continues_its_turn() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    fs::write(project.join("SESSION-ID.jsonl"), line(0x900, None, PROMPT)).expect("session");
    let call = padded(1_200, 0xa01, 0xa00, |pad| {
        format!(
            r#""type":"assistant","message":{{"id":"MESSAGE-ID-C","content":[{{"type":"tool_use","id":"TOOL-X","name":"Task","input":{{"text":"{pad}"}}}}]}}"#
        )
    });
    let result = padded(700, 0xa02, 0xa01, |pad| {
        format!(
            r#""type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"TOOL-X","content":"{pad}"}}]}}"#
        )
    });
    let prompt = padded(700, 0xa02, 0xa01, |pad| {
        format!(r#""type":"user","message":{{"content":"{pad}"}}"#)
    });
    let opening = line(0xa00, None, PROMPT) + &call;
    let (first, marker) = ("agents/a-01.html", "This turn goes on to the next page");
    let output = root.path().join("gamma");
    fs::write(subagents.join("agent-a.jsonl"), opening.clone() + &result).expect("thread");
    attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    assert!(
        fs::read_to_string(output.join(first))
            .expect("first page")
            .contains(marker)
    );
    let key = stored_key(&output, first);
    fs::write(subagents.join("agent-a.jsonl"), opening + &prompt).expect("a new turn next");
    let again = attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    assert_eq!(again.pages_rendered, 2);
    assert_ne!(stored_key(&output, first), key);
    assert!(
        !fs::read_to_string(output.join(first))
            .expect("first page")
            .contains(marker)
    );
}

/// ´test:crate:a-calls-result-is-told-where-it-lies´
#[test]
fn a_calls_result_is_told_where_it_lies() {
    let call = |id: &str, message: &str| {
        format!(
            r#""type":"assistant","message":{{"id":"{message}","content":[{{"type":"tool_use","id":"{id}","name":"Read","input":{{}}}}]}}"#
        )
    };
    let result = |id: &str| {
        format!(
            r#""type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"{id}","content":"Read done."}}]}}"#
        )
    };
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    fs::write(
        project.join("SESSION-ID.jsonl"),
        [
            line(0x900, None, PROMPT),
            line(0x901, Some(0x900), &call("TOOL-A", "MESSAGE-ID-A")),
            line(
                0x902,
                Some(0x901),
                r#""type":"system","content":"Hook ran.""#,
            ),
            line(0x903, Some(0x902), &result("TOOL-A")),
            line(
                0x904,
                Some(0x903),
                &call("TOOL-B", "MESSAGE-ID-B").replace(
                    "}]}",
                    r#"},{"type":"tool_use","id":"TOOL-D","name":"Read","input":{}}]}"#,
                ),
            ),
            line(0x908, Some(0x904), &result("TOOL-D")),
            line(0x905, Some(0x908), &call("TOOL-C", "MESSAGE-ID-C")),
            line(0x906, Some(0x905), PROMPT),
            line(0x907, Some(0x906), &result("TOOL-C")),
        ]
        .concat(),
    )
    .expect("session");
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let page = fs::read_to_string(output.join("p0001.html")).expect("page");
    let moved = |answer: u64| {
        format!(
            r##"<p class="moved">Its result is shown <a href="#result-{}-0">further down this page</a>.</p>"##,
            id(answer)
        )
    };
    let call = |record: u64, block: u32| format!("call-{}-{block}", id(record));
    assert!(page.contains(&moved(0x903)), "{page}");
    assert!(
        page.contains(&format!(
            r##"Result of <a href="#{}">Read</a>"##,
            call(0x901, 0)
        )),
        "{page}"
    );
    assert!(page.contains(&moved(0x907)), "{page}");
    assert!(
        page.contains(&format!(
            r##"Result of <a href="#{}">Read</a>"##,
            call(0x905, 0)
        )),
        "{page}"
    );
    assert_eq!(page.matches("No result was recorded.").count(), 1, "{page}");
    let absent = page
        .find("No result was recorded.")
        .expect("the absent result");
    let told = |record: u64, block: u32| {
        page.find(&format!(r#"id="{}""#, call(record, block)))
            .expect("the call")
    };
    assert!(told(0x904, 0) < absent && absent < told(0x904, 1), "{page}");
    let beside = &page[told(0x904, 1)..told(0x905, 0)];
    assert!(
        beside.contains(&format!(
            r#"<div class="result" id="result-{}-0">"#,
            id(0x908)
        )),
        "{beside}"
    );
    assert_eq!(conservation(&project, &output).faults, Vec::<String>::new());
}

/// ´test:crate:a-result-on-a-later-part-and-its-call-link-to-each-other´
#[test]
fn a_result_on_a_later_part_and_its_call_link_to_each_other() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    fs::write(project.join("SESSION-ID.jsonl"), line(0x900, None, PROMPT)).expect("session");
    let long_call = padded(1_200, 0xa01, 0xa00, |pad| {
        format!(
            r#""type":"assistant","message":{{"id":"MESSAGE-ID-L","content":[{{"type":"tool_use","id":"TOOL-L","name":"Read","input":{{"text":"{pad}"}}}}]}}"#
        )
    });
    let long_result = padded(700, 0xa02, 0xa01, |pad| {
        format!(
            r#""type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"TOOL-L","content":"{pad}"}}]}}"#
        )
    });
    fs::write(
        subagents.join("agent-a.jsonl"),
        line(0xa00, None, PROMPT) + &long_call + &long_result,
    )
    .expect("thread");
    let output = root.path().join("gamma");
    attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    let first = fs::read_to_string(output.join("agents/a-01.html")).expect("first part");
    let second = fs::read_to_string(output.join("agents/a-02.html")).expect("second part");
    assert!(
        first.contains(&format!(
            r#"<p class="moved">Its result is shown <a href="a-02.html#result-{}-0">on part 2</a>.</p>"#,
            id(0xa02)
        )),
        "{first}"
    );
    assert!(!first.contains("No result was recorded."), "{first}");
    assert!(
        second.contains(&format!(
            r#"Result of <a href="a-01.html#call-{}-0">the call on part 1</a>"#,
            id(0xa01)
        )),
        "{second}"
    );
    let index = fs::read_to_string(output.join("index.html")).expect("index");
    assert!(
        index.contains(r#"<li><a href="agents&#x2f;a-01.html">Subagent: a</a></li>"#),
        "{index}"
    );
    assert!(index.contains("except the 1 listed here"), "{index}");
}
