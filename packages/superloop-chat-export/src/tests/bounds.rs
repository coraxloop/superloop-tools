use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, ErrorKind};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use nix::sys::stat::Mode;
use serde_json::Value;

use super::super::agents::{MAX_META_BYTES, MetaFile, attach, load_agents};
use super::super::folder::{Folder, create_apart, staging_name, temporaries_drawn};
use super::super::load::{FileScan, Heads};
use super::super::names::{generated, is_segment, url_segment};
use super::super::output::JOURNAL;
use super::super::plan::{PAGE_BUDGET, plan};
use super::super::pool;
use super::super::render::{RenderError, Settings, render_loop};
use super::super::templates::with_templates;
use super::super::tree::Tree;
use super::super::view::{STRUCTURE_BYTES, read_bodies};
use super::render::{attempt, attempt_paged, html_files, manifest_at, render};
use super::{discover, fixture_projects, id, paths};

/// ´test:crate:names-follow-one-grammar-and-links-need-no-escaping´
#[test]
fn names_follow_one_grammar_and_links_need_no_escaping() {
    for name in ["alpha", "a", "loop-2", "Loop_3.x", "0123456789abcdef0"] {
        assert!(is_segment(name), "{name}");
        assert_eq!(url_segment(name), name);
    }
    let long = "a".repeat(65);
    for name in [
        "",
        ".hidden",
        "-flag",
        "_under",
        "javascript:alert(1)",
        "..",
        "a/b",
        "q?x",
        "frag#x",
        "space d",
        "tab\tx",
        "é",
        long.as_str(),
    ] {
        assert!(!is_segment(name), "{name:?}");
    }
    assert_eq!(url_segment("a:b/c?d#e"), "a%3Ab%2Fc%3Fd%23e");
    for path in [
        "p0001.html",
        "p10000.html",
        "pages.html",
        "c2/p0001.html",
        "c12/pages.html",
        "branches/SESSION-ID-B-01.html",
        "c2/branches/abc-10.html",
        "agents/0123456789abcdef0-01.html",
        "agents/a-01-02.html",
        "chat-export-manifest.json",
        "chat-export-journal.txt",
    ] {
        assert!(generated(path), "{path}");
    }
    for path in [
        "p001.html",
        "reader-notes.md",
        "c1/p0001.html",
        "c02/p0001.html",
        "c2/agents/x.html",
        "branches/-01.html",
        "branches/x-1.html",
        "agents/0123456789abcdef0.html",
        "agents/x-1.html",
        "agents/../index.html",
        "../index.html",
        ".chat-export-1-2/3.tmp",
    ] {
        assert!(!generated(path), "{path}");
    }
}

/// ´test:crate:a-symbolic-link-redirects-no-write´
#[test]
fn a_symbolic_link_redirects_no_write() {
    let root = tempfile::tempdir().expect("temporary directory");
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("index.html"), "outside").expect("outside file");
    let chats = root.path().join("chats");
    fs::create_dir_all(&chats).expect("chats");
    symlink(&outside, chats.join("gamma")).expect("link as the loop folder");
    let folder = Folder::open(&chats).expect("chats");
    let error = folder.child("gamma").expect_err("a link is no loop folder");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(Folder::open(&chats.join("gamma")).is_err());
    let output = root.path().join("gamma");
    render(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    fs::remove_dir_all(output.join("c2")).expect("clear c2");
    symlink(&outside, output.join("c2")).expect("link as a parent component");
    let refused = attempt(
        &fixture_projects().join("-home-alpha-dev-gamma"),
        &output,
        16_384,
    );
    assert!(
        matches!(&refused, Err(RenderError::Foreign(path)) if path == "c2"),
        "{refused:?}"
    );
    let loop_folder = Folder::open(&output).expect("loop folder");
    assert!(
        loop_folder
            .write("c2/p0001.html", b"through the link")
            .is_err()
    );
    let next = temporaries_drawn();
    for number in next..next + 64 {
        symlink(&outside, output.join(staging_name(number))).expect("link at a staging name");
    }
    symlink(outside.join("index.html"), output.join("latest.html.new"))
        .expect("link at the destination");
    loop_folder
        .write("latest.html.new", b"written")
        .expect("write past the links");
    assert_eq!(
        fs::read_to_string(outside.join("index.html")).expect("outside"),
        "outside"
    );
    assert!(
        !fs::symlink_metadata(output.join("latest.html.new"))
            .expect("entry")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_dir(&outside).expect("outside").count(), 1);
    let staging: Vec<_> = fs::read_dir(&output)
        .expect("output")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".chat-export-")
        })
        .collect();
    assert_eq!(
        staging.len(),
        1,
        "one staging folder while the folder is open"
    );
    let mode = staging[0]
        .metadata()
        .expect("staging folder")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    drop(loop_folder);
    assert!(
        !staging[0].path().exists(),
        "the staging folder goes with the folder"
    );
}

/// ´test:crate:an-over-long-line-is-skipped-and-counted-without-being-held´
#[test]
fn an_over_long_line_is_skipped_and_counted_without_being_held() {
    let record = |number: u64| {
        format!(
            r#"{{"type":"user","uuid":"{}","message":{{"content":"hello"}},"timestamp":"2026-01-01T00:00:00Z"}}"#,
            id(number)
        ) + "\n"
    };
    let long = format!(
        r#"{{"type":"user","uuid":"{}","message":{{"content":"{}"}}}}"#,
        id(2),
        "x".repeat(4096)
    ) + "\n";
    let text = record(1) + &long + &record(3);
    let scan = FileScan::read_within(Cursor::new(text.as_bytes()), 512).expect("scan");
    assert_eq!(
        (scan.oversized, scan.malformed, scan.lines.len()),
        (1, 0, 2)
    );
    let third = &scan.lines[1];
    assert_eq!(third.id, id(3));
    let start = usize::try_from(third.loc.offset).expect("offset");
    assert_eq!(&text[start..start + record(3).len()], record(3));
}

/// ´test:crate:many-files-are-scanned-a-bounded-number-at-once´
#[test]
fn many_files_are_scanned_a_bounded_number_at_once() {
    let running = AtomicUsize::new(0);
    let most = AtomicUsize::new(0);
    let done = pool::run(200, pool::SCAN_THREADS, &|index| {
        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
        most.fetch_max(now, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(1));
        running.fetch_sub(1, Ordering::SeqCst);
        index
    });
    assert_eq!(done, (0..200).collect::<Vec<_>>());
    assert!(most.load(Ordering::SeqCst) <= pool::SCAN_THREADS);
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    for number in 0..120_u64 {
        let mut text = String::new();
        writeln!(
            text,
            r#"{{"type":"user","uuid":"{}","message":{{"content":"file {number}"}},"timestamp":"2026-01-01T00:00:{:02}Z"}}"#,
            id(0x1000 + number),
            number % 60
        )
        .expect("write");
        fs::write(project.join(format!("SESSION-{number:03}.jsonl")), text).expect("session");
    }
    fs::write(project.join("bad name!.jsonl"), "{}\n").expect("ignored session");
    let source = discover(&project);
    assert_eq!((source.sessions.len(), source.ignored.len()), (120, 1));
    let heads = Heads::load(&source).expect("load");
    let report = heads.report();
    assert_eq!(
        (report.files, report.records, report.ignored),
        (120, 120, 1)
    );
}

/// ´test:crate:a-run-that-fails-midway-leaves-nothing-the-next-run-refuses´
#[test]
fn a_run_that_fails_midway_leaves_nothing_the_next_run_refuses() {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("gamma");
    let agents = output.join("agents");
    fs::create_dir_all(&agents).expect("agents folder");
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o555)).expect("read-only");
    let project = fixture_projects().join("-home-alpha-dev-gamma");
    let failed = attempt(&project, &output, 16_384);
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o755)).expect("writable again");
    assert!(matches!(failed, Err(RenderError::Io(_))), "{failed:?}");
    assert!(
        output.join("p0001.html").is_file(),
        "pages written before the failure"
    );
    assert!(output.join(JOURNAL).is_file(), "the journal records them");
    let leftovers = fs::read_dir(&output)
        .expect("output")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .count();
    assert_eq!(leftovers, 0);
    let second = render(&project, &output, 16_384);
    assert_eq!((second.files_foreign, second.files_removed), (0, 0));
    assert!(!output.join(JOURNAL).exists());
    assert!(output.join("agents/0123456789abcdef0-01.html").is_file());
}

/// A transcript line: record `number` under `parent` at second `second`, with
/// `rest` giving its type and message.
fn line(number: u64, parent: Option<u64>, second: u64, rest: &str) -> String {
    let parent = parent.map_or_else(|| "null".to_owned(), |parent| format!("\"{}\"", id(parent)));
    format!(
        r#"{{"uuid":"{}","parentUuid":{parent},{rest},"timestamp":"2026-05-01T10:00:{second:02}.000Z"}}"#,
        id(number)
    ) + "\n"
}

const PROMPT: &str = r#""type":"user","message":{"content":"Next step."}"#;

fn call(message: &str, call: &str) -> String {
    format!(
        r#""type":"assistant","message":{{"id":"{message}","content":[{{"type":"tool_use","id":"{call}","name":"Task","input":{{}}}}]}}"#
    )
}

fn answer(text: &str) -> String {
    format!(
        r#""type":"assistant","message":{{"id":"MESSAGE-ID-{text}","content":[{{"type":"text","text":"{text}"}}]}}"#
    )
}

/// ´test:crate:an-agent-meta-file-is-read-only-as-a-bounded-regular-file´
#[test]
fn an_agent_meta_file_is_read_only_as_a_bounded_regular_file() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    fs::write(
        project.join("SESSION-ID.jsonl"),
        line(0x900, None, 0, PROMPT),
    )
    .expect("session");
    let meta = r#"{"agentType":"general-purpose","toolUseId":"TOOL-A"}"#;
    for (number, name) in
        (0x910_u64..).zip(["absent", "folder", "large", "linked", "pipe", "regular"])
    {
        let mut thread = line(number, None, 1, PROMPT);
        if name == "regular" {
            thread += "not a record\n";
        }
        fs::write(subagents.join(format!("agent-{name}.jsonl")), thread).expect("thread");
    }
    let at = |name: &str| subagents.join(format!("agent-{name}.meta.json"));
    fs::write(at("regular"), meta).expect("meta");
    fs::create_dir(at("folder")).expect("a folder at the meta name");
    let padding = usize::try_from(MAX_META_BYTES).expect("limit") + 1 - meta.len();
    fs::write(at("large"), format!("{meta}{}", " ".repeat(padding))).expect("large meta");
    let elsewhere = root.path().join("elsewhere.json");
    fs::write(&elsewhere, meta).expect("meta elsewhere");
    symlink(&elsewhere, at("linked")).expect("link at the meta name");
    nix::unistd::mkfifo(&at("pipe"), Mode::S_IRUSR | Mode::S_IWUSR).expect("pipe at the meta name");
    let source = discover(&project);
    let heads = Heads::load(&source).expect("load");
    let (agents, _) = load_agents(&source.agents).expect("agents");
    let found: BTreeMap<&str, MetaFile> = agents
        .iter()
        .map(|agent| (agent.id.as_str(), agent.meta_file))
        .collect();
    assert_eq!(
        found,
        BTreeMap::from([
            ("absent", MetaFile::Absent),
            ("folder", MetaFile::Skipped),
            ("large", MetaFile::Skipped),
            ("linked", MetaFile::Skipped),
            ("pipe", MetaFile::Skipped),
            ("regular", MetaFile::Read),
        ])
    );
    let regular = agents.iter().find(|agent| agent.id == "regular");
    assert_eq!(
        regular.and_then(|agent| agent.meta.tool_use_id.as_deref()),
        Some("TOOL-A")
    );
    let report = heads.report().with_agents(&agents, 0);
    assert_eq!((report.meta_skipped, report.malformed), (4, 1));
    assert!(
        report
            .to_string()
            .ends_with("malformed=1 oversized=0 ignored=0 skipped=0 meta_skipped=4")
    );
}

/// ´test:crate:an-agent-thread-is-paged-by-the-page-budget´
#[test]
fn an_agent_thread_is_paged_by_the_page_budget() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    let session = line(0x900, None, 0, PROMPT)
        + &line(0x901, Some(0x900), 1, &call("MESSAGE-ID-S", "TOOL-A"));
    fs::write(project.join("SESSION-ID.jsonl"), session).expect("session");
    let mut thread = String::new();
    for turn in 0..3_u64 {
        let prompt = 0x910 + 2 * turn;
        let parent = turn.checked_sub(1).map(|before| 0x911 + 2 * before);
        thread += &line(prompt, parent, 2 + 2 * turn, PROMPT);
        let reply = if turn == 2 {
            call("MESSAGE-ID-N", "TOOL-N")
        } else {
            answer(&format!("Step{turn}"))
        };
        thread += &line(prompt + 1, Some(prompt), 3 + 2 * turn, &reply);
    }
    fs::write(subagents.join("agent-thread.jsonl"), thread).expect("thread");
    fs::write(
        subagents.join("agent-thread.meta.json"),
        r#"{"agentType":"general-purpose","toolUseId":"TOOL-A"}"#,
    )
    .expect("meta");
    fs::write(
        subagents.join("agent-nested.jsonl"),
        line(0x920, None, 9, PROMPT),
    )
    .expect("nested");
    fs::write(
        subagents.join("agent-nested.meta.json"),
        r#"{"agentType":"Explore","toolUseId":"TOOL-N"}"#,
    )
    .expect("meta");
    let output = root.path().join("gamma");
    // Each turn of two records reaches a budget of 300 bytes and fits in
    // twice it, so each is a page of its own.
    attempt_paged(&project, &output, 16_384, 300).expect("render");
    let files = html_files(&output);
    let pages: Vec<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|path| path.starts_with("agents/"))
        .collect();
    assert_eq!(
        pages,
        [
            "agents/nested-01.html",
            "agents/thread-01.html",
            "agents/thread-02.html",
            "agents/thread-03.html"
        ]
    );
    assert!(files["p0001.html"].contains("thread-01.html"));
    let (first, middle, last) = (
        &files["agents/thread-01.html"],
        &files["agents/thread-02.html"],
        &files["agents/thread-03.html"],
    );
    assert!(first.contains(r#"<a rel="next" href="thread-02.html">Next</a>"#));
    assert!(middle.contains(r#"<a rel="prev" href="thread-01.html">Previous</a>"#));
    assert!(middle.contains(r#"<a rel="next" href="thread-03.html">Next</a>"#));
    assert!(middle.contains("Subagent general-purpose · part 2"));
    assert!(last.contains(r#"<span class="disabled">Next</span>"#));
    for number in 0x910..0x916 {
        let anchor = format!(r#"id="r-{}""#, id(number));
        let shown = [first, middle, last]
            .iter()
            .map(|page| page.matches(&anchor).count())
            .sum::<usize>();
        assert_eq!(shown, 1, "{anchor}");
    }
    assert!(
        files["agents/nested-01.html"].contains(&format!("thread-03.html#call-{}-0", id(0x915)))
    );
    assert!(!files["agents/nested-01.html"].contains("part 1"));
}

/// ´test:crate:a-record-keeps-no-string-beyond-the-block-limit-and-no-name-beyond-its-bound´
#[test]
fn a_record_keeps_no_string_beyond_the_block_limit_and_no_name_beyond_its_bound() {
    /// The longest member name and the longest string other than a `type`
    /// or `subtype` value under `value`.
    fn longest(value: &Value) -> (usize, usize) {
        match value {
            Value::String(text) => (0, text.len()),
            Value::Array(items) => items
                .iter()
                .map(longest)
                .fold((0, 0), |(a, b), (c, d)| (a.max(c), b.max(d))),
            Value::Object(members) => members
                .iter()
                .map(|(name, member)| {
                    let (names, texts) = longest(member);
                    let texts = if matches!(name.as_str(), "type" | "subtype") {
                        0
                    } else {
                        texts
                    };
                    (names.max(name.len()), texts)
                })
                .fold((0, 0), |(a, b), (c, d)| (a.max(c), b.max(d))),
            _ => (0, 0),
        }
    }
    let root = tempfile::tempdir().expect("temporary directory");
    let path = root.path().join("SESSION-ID.jsonl");
    let (name, text, repeated) = ("n".repeat(300), "t".repeat(100), "r".repeat(100));
    let input = format!(r#"{{"{name}":"{text}","a":"b","a":"{repeated}"}}"#);
    let rest = format!(
        r#""type":"assistant","message":{{"id":"MESSAGE-ID-L","content":[{{"type":"tool_use","id":"TOOL-L","name":"Bash","input":{input}}}]}}"#
    );
    fs::write(&path, line(0x900, None, 0, &rest)).expect("session");
    let heads = Heads::load(&discover(root.path())).expect("heads");
    let bodies = read_bodies(&heads, &[0], 16).expect("read back");
    let record = &bodies.values[&0];
    assert_eq!(longest(record), (STRUCTURE_BYTES, 16), "{record}");
    assert_eq!(
        record.pointer("/message/content/0/type"),
        Some(&Value::from("tool_use"))
    );
    assert_eq!(record.get("type"), Some(&Value::from("assistant")));
    let kept = record
        .pointer("/message/content/0/input")
        .expect("the call's input");
    let mut expected = serde_json::Map::new();
    expected.insert("n".repeat(STRUCTURE_BYTES), Value::from("t".repeat(16)));
    expected.insert("a".to_owned(), Value::from("b"));
    assert_eq!(kept, &Value::Object(expected));
    assert_eq!(bodies.dropped(kept), (300 - STRUCTURE_BYTES) + (100 - 16));
}

/// ´test:crate:two-subagent-files-of-one-id-render-one-thread-and-the-other-is-named´
#[test]
fn two_subagent_files_of_one_id_render_one_thread_and_the_other_is_named() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    for session in ["SESSION-ID", "SESSION-ID-2"] {
        fs::create_dir_all(project.join(session).join("subagents")).expect("subagents");
    }
    fs::write(
        project.join("SESSION-ID.jsonl"),
        line(0x900, None, 0, PROMPT),
    )
    .expect("session");
    let first = project.join("SESSION-ID/subagents/agent-a.jsonl");
    let bare = project.join("SESSION-ID/subagents/a.jsonl");
    let again = project.join("SESSION-ID-2/subagents/agent-a.jsonl");
    for (path, number, text) in [
        (&bare, 0x910, "Bare"),
        (&first, 0x920, "First"),
        (&again, 0x930, "Again"),
    ] {
        fs::write(path, line(number, None, 1, &answer(text))).expect("thread");
    }
    let source = discover(&project);
    assert_eq!(paths(&source.agents), std::slice::from_ref(&first));
    assert_eq!(source.ignored, [bare]);
    assert_eq!(source.repeated, [(again, first)]);
    assert_eq!(Heads::load(&source).expect("load").report().ignored, 2);
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let files = html_files(&output);
    let threads: Vec<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|path| path.starts_with("agents/"))
        .collect();
    assert_eq!(threads, ["agents/a-01.html"]);
    let thread = &files["agents/a-01.html"];
    assert!(thread.contains("First") && !thread.contains("Again") && !thread.contains("Bare"));
    let listed = manifest_at(&output).files;
    let distinct: BTreeSet<&str> = listed.iter().map(|owned| owned.path.as_str()).collect();
    assert_eq!(distinct.len(), listed.len());
    let heads = Heads::load(&source).expect("load");
    let (mut agents, _) = load_agents(&source.agents).expect("agents");
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    let mut pages = plan(&heads, &tree, &agents, PAGE_BUDGET);
    pages.push(pages[0].clone());
    let twice = root.path().join("twice");
    fs::create_dir_all(&twice).expect("folder");
    let folder = Folder::open(&twice).expect("folder");
    let settings = Settings {
        name: "gamma",
        project: &project,
        folder: &folder,
        limit: 16_384,
        program: "superloop-chat-export test",
    };
    let environment = with_templates().expect("templates");
    let refused = render_loop(&environment, &heads, &tree, &agents, &pages, &settings);
    assert!(
        matches!(&refused, Err(RenderError::Io(error)) if error.kind() == ErrorKind::InvalidData),
        "{refused:?}"
    );
    assert_eq!(fs::read_dir(&twice).expect("folder").count(), 0);
}

/// ´test:crate:the-plan-dump-is-created-in-the-folder-it-checked´
#[test]
fn the_plan_dump_is_created_in_the_folder_it_checked() {
    let root = tempfile::tempdir().expect("temporary directory");
    let (projects, chats, elsewhere) = (
        root.path().join("projects"),
        root.path().join("chats"),
        root.path().join("elsewhere"),
    );
    for folder in [projects.join("deep"), chats.join("sub"), elsewhere.clone()] {
        fs::create_dir_all(folder).expect("folder");
    }
    let apart = [
        (projects.as_path(), "projects"),
        (chats.as_path(), "output"),
    ];
    let dump = elsewhere.join("plan.jsonl");
    create_apart(&dump, &apart).expect("a folder apart from both");
    assert!(dump.is_file());
    let exists = create_apart(&dump, &apart).expect_err("an existing file");
    assert_eq!(exists.kind(), ErrorKind::AlreadyExists);
    symlink(projects.join("deep"), root.path().join("link")).expect("link to a projects folder");
    let refused = |path: &Path, role: &str| {
        let error = create_apart(path, &apart).expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
        assert!(error.to_string().contains(role), "{error}");
    };
    refused(&root.path().join("link/plan.jsonl"), "projects");
    refused(&chats.join("sub/../plan.jsonl"), "output");
    refused(&chats.join("plan.jsonl"), "output");
    symlink(
        projects.join("deep/plan.jsonl"),
        elsewhere.join("linked.jsonl"),
    )
    .expect("link at the dump's name");
    assert!(create_apart(&elsewhere.join("linked.jsonl"), &apart).is_err());
    assert_eq!(
        fs::read_dir(projects.join("deep")).expect("deep").count(),
        0
    );
    assert_eq!(fs::read_dir(&chats).expect("chats").count(), 1);
}
