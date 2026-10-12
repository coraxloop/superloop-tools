use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use super::head::{Kind, RecordId, parse_timestamp};
use super::input::Project;
use super::load::{FileScan, Heads, LoadReport, LoopSource, SourceFile};
use super::registry::{parse_env, project_slug};
use super::templates;

mod aids;
mod bounds;
mod conserve;
mod forms;
mod input;
mod markdown;
mod ownership;
mod paging;
mod render;
mod tree;

const LINEAR: &[u8] =
    include_bytes!("../../tests/fixtures/projects/-home-alpha-dev-alpha/SESSION-ID-LINEAR.jsonl");
const REPEAT: &[u8] =
    include_bytes!("../../tests/fixtures/projects/-home-alpha-dev-alpha/SESSION-ID-REPEAT.jsonl");
const ORDER: &[u8] =
    include_bytes!("../../tests/fixtures/projects/-home-alpha-dev-alpha/SESSION-ID-ORDER.jsonl");
const UNKNOWN: &[u8] =
    include_bytes!("../../tests/fixtures/projects/-home-alpha-dev-alpha/SESSION-ID-UNKNOWN.jsonl");

fn id(number: u64) -> RecordId {
    RecordId::parse(&format!("00000000-0000-4000-8000-{number:012x}")).expect("fixture id")
}

fn source(stem: &str, bytes: &[u8]) -> SourceFile {
    SourceFile {
        path: PathBuf::from(format!("{stem}.jsonl")),
        stem: stem.to_owned(),
        bytes: bytes.len() as u64,
        modified: None,
        scan: FileScan::read(Cursor::new(bytes)).expect("in-memory read"),
        origin: None,
    }
}

/// The transcript files of the project folder at `path`.
fn discover(path: &Path) -> LoopSource {
    LoopSource::discover(&Project::at(path).expect("project folder")).expect("discover")
}

/// The paths of `files`.
fn paths(files: &[super::input::InputFile]) -> Vec<PathBuf> {
    files.iter().map(|file| file.path.clone()).collect()
}

fn load(files: &[(&str, &[u8])]) -> Heads {
    Heads::merge(
        files
            .iter()
            .map(|(stem, bytes)| source(stem, bytes))
            .collect(),
    )
    .expect("merge")
}

fn kinds(heads: &Heads) -> Vec<Kind> {
    heads.nodes.iter().map(|node| node.kind).collect()
}

fn fixture_projects() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/projects")
}

/// ´test:crate:record-ids-parse-canonical-text-in-either-case-and-refuse-the-rest´
#[test]
fn record_ids_parse_canonical_text_in_either_case_and_refuse_the_rest() {
    let lower = RecordId::parse("0123abcd-4567-89ef-0123-456789abcdef").expect("lower case");
    let upper = RecordId::parse("0123ABCD-4567-89EF-0123-456789ABCDEF").expect("upper case");
    assert_eq!(lower, upper);
    assert_eq!(lower.to_string(), "0123abcd-4567-89ef-0123-456789abcdef");
    for text in [
        "",
        "0123abcd456789ef0123456789abcdef",
        "0123abcd-4567-89ef-0123-456789abcde",
        "0123abcd-4567-89ef-0123-456789abcdeff",
        "0123abcd_4567-89ef-0123-456789abcdef",
        "0123abcg-4567-89ef-0123-456789abcdef",
        "SESSION-ID",
    ] {
        assert_eq!(RecordId::parse(text), None, "{text}");
    }
}

/// ´test:crate:timestamps-parse-the-harness-utc-form-to-epoch-milliseconds´
#[test]
fn timestamps_parse_the_harness_utc_form_to_epoch_milliseconds() {
    assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_timestamp("1970-01-01T00:00:01.5Z"), Some(1500));
    assert_eq!(parse_timestamp("1969-12-31T23:59:59.000Z"), Some(-1000));
    assert_eq!(
        parse_timestamp("2000-03-01T00:00:00.000Z"),
        Some(951_868_800_000)
    );
    assert_eq!(
        parse_timestamp("2024-02-29T12:00:00.123456Z"),
        Some(1_709_208_000_123)
    );
    for text in [
        "",
        "2024-02-29 12:00:00Z",
        "2024-13-01T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00.Z",
        "2024-01-01T00:00:00",
    ] {
        assert_eq!(parse_timestamp(text), None, "{text}");
    }
}

/// ´test:crate:heads-classify-prompts-commands-notes-and-tool-traffic´
#[test]
fn heads_classify_prompts_commands_notes_and_tool_traffic() {
    let heads = load(&[("SESSION-ID-LINEAR", LINEAR)]);
    assert_eq!(
        kinds(&heads),
        [
            Kind::Prompt,
            Kind::Thinking,
            Kind::ToolUse,
            Kind::ToolUse,
            Kind::ToolResult,
            Kind::ToolResult,
            Kind::QueuedPrompt,
            Kind::Peer,
            Kind::UserNote,
            Kind::Response,
            Kind::SystemNote,
            Kind::Command,
            Kind::UserNote,
            Kind::Prompt,
        ]
    );
    let openers: Vec<_> = heads
        .nodes
        .iter()
        .filter(|node| node.kind.opens_turn())
        .map(|node| node.id)
        .collect();
    assert_eq!(openers, [id(0x1), id(0x7), id(0x14)]);
}

/// ´test:crate:the-first-pass-keeps-titles-counts-times-and-byte-spans´
#[test]
fn the_first_pass_keeps_titles_counts_times_and_byte_spans() {
    let heads = load(&[("SESSION-ID-LINEAR", LINEAR)]);
    let scan = &heads.files[0].scan;
    assert_eq!(
        (
            scan.lines_read,
            scan.id_lines,
            scan.distinct,
            scan.malformed
        ),
        (18, 14, 14, 0)
    );
    assert_eq!(
        scan.first_timestamp.as_deref(),
        Some("2026-01-01T09:00:00.000Z")
    );
    assert_eq!(heads.title(), Some("Linear fixture"));
    let first = &heads.nodes[0];
    assert_eq!((first.id, first.parent), (id(0x1), None));
    assert_eq!(first.timestamp, parse_timestamp("2026-01-01T09:00:00.500Z"));
    for node in &heads.nodes {
        let start = usize::try_from(node.loc.offset).expect("offset");
        let end = start + usize::try_from(node.loc.len).expect("length");
        let line: serde_json::Value =
            serde_json::from_slice(&LINEAR[start..end]).expect("span is one record");
        assert_eq!(line["uuid"].as_str(), Some(node.id.to_string().as_str()));
    }
}

/// ´test:crate:the-first-copy-of-a-repeated-record-is-the-node´
#[test]
fn the_first_copy_of_a_repeated_record_is_the_node() {
    let heads = load(&[("SESSION-ID-REPEAT", REPEAT)]);
    assert_eq!(heads.nodes.len(), 5);
    assert_eq!(heads.copies_dropped, 4);
    let node = |number| &heads.nodes[heads.index[&id(number)] as usize];
    assert_eq!(node(0x103).parent, Some(id(0x102)));
    let result = node(0x104);
    let start = usize::try_from(result.loc.offset).expect("offset");
    let line = &REPEAT[start..start + result.loc.len as usize];
    assert!(
        String::from_utf8_lossy(line)
            .contains(r#""toolUseResult":{"stdout":"full output of the command""#)
    );
    assert_eq!(node(0x105).parent, Some(id(0x104)));
    assert_eq!(heads.title(), Some("Repeat fixture"));
}

/// ´test:crate:records-written-before-their-parent-keep-write-order´
#[test]
fn records_written_before_their_parent_keep_write_order() {
    let heads = load(&[("SESSION-ID-ORDER", ORDER)]);
    let order: Vec<_> = heads
        .nodes
        .iter()
        .map(|node| (node.id, node.parent))
        .collect();
    assert_eq!(
        order,
        [
            (id(0x201), None),
            (id(0x202), Some(id(0x203))),
            (id(0x203), Some(id(0x201))),
            (id(0x204), Some(id(0x202))),
        ]
    );
}

/// ´test:crate:unknown-kinds-load-and-malformed-lines-are-counted´
#[test]
fn unknown_kinds_load_and_malformed_lines_are_counted() {
    let heads = load(&[("SESSION-ID-UNKNOWN", UNKNOWN)]);
    let scan = &heads.files[0].scan;
    assert_eq!((scan.lines_read, scan.id_lines, scan.malformed), (10, 5, 5));
    let loaded: Vec<_> = heads
        .nodes
        .iter()
        .map(|node| (node.id, node.kind))
        .collect();
    assert_eq!(
        loaded,
        [
            (id(0x301), Kind::Other),
            (id(0x302), Kind::Response),
            (id(0x303), Kind::Attachment),
            (id(0x307), Kind::UserNote),
            (id(0x3ab), Kind::Prompt),
        ]
    );
    assert_eq!(heads.nodes[4].parent, Some(id(0x303)));
}

/// ´test:crate:files-merge-in-first-timestamp-order-the-larger-first-among-equals´
#[test]
fn files_merge_in_first_timestamp_order_the_larger_first_among_equals() {
    let line = |number: u64, parent: &str| {
        format!(
            r#"{{"type":"user","uuid":"{}","parentUuid":{parent},"timestamp":"2026-01-05T00:00:00.000Z","message":{{"content":"Words."}}}}"#,
            id(number)
        )
    };
    let original = [
        line(0x401, "null"),
        line(0x402, &format!(r#""{}""#, id(0x401))),
        line(0x404, &format!(r#""{}""#, id(0x402))),
    ]
    .join("\n");
    let copy = [line(0x401, "null"), line(0x402, "null")].join("\n");
    let later = format!(
        r#"{{"type":"user","uuid":"{}","timestamp":"2026-01-06T00:00:00.000Z","message":{{"content":"Later."}}}}"#,
        id(0x403)
    );
    let heads = load(&[
        ("A-LATER", later.as_bytes()),
        ("B-COPY", copy.as_bytes()),
        ("C-ORIGINAL", original.as_bytes()),
    ]);
    let stems: Vec<_> = heads.files.iter().map(|file| file.stem.as_str()).collect();
    assert_eq!(stems, ["C-ORIGINAL", "B-COPY", "A-LATER"]);
    assert_eq!(heads.nodes[1].parent, Some(id(0x401)));
    assert_eq!(heads.nodes[1].loc.file, 0);
    assert_eq!(heads.nodes[3].id, id(0x403));
    assert_eq!(heads.copies_dropped, 2);
}

/// ´test:crate:the-registry-maps-names-to-working-directories-and-slugs-them´
#[test]
fn the_registry_maps_names_to_working_directories_and_slugs_them() {
    let values = parse_env(
        "# comment\nLOOP_NAME = 'alpha'\nno separator\nLOOP_CWD=\"/home/alpha/dev/alpha\"\n",
    );
    assert_eq!(values.get("LOOP_NAME").map(String::as_str), Some("alpha"));
    assert_eq!(
        values.get("LOOP_CWD").map(String::as_str),
        Some("/home/alpha/dev/alpha")
    );
    assert_eq!(values.len(), 2);
    assert_eq!(
        project_slug("/home/alpha/dev/alpha"),
        "-home-alpha-dev-alpha"
    );
    assert_eq!(project_slug("~/dev/al.pha é"), "--dev-al-pha--");
}

/// ´test:crate:discovery-lists-session-files-and-subagent-files´
#[test]
fn discovery_lists_session_files_and_subagent_files() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path();
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents directory");
    fs::create_dir_all(project.join("SESSION-ID/tool-results")).expect("tool-results directory");
    fs::create_dir_all(project.join("NOTES")).expect("unrelated directory");
    for path in [
        project.join("SESSION-ID.jsonl"),
        project.join("notes.txt"),
        subagents.join("agent-0123456789abcdef0.jsonl"),
        subagents.join("agent-0123456789abcdef0.meta.json"),
        project.join("SESSION-ID/tool-results/output.txt"),
        project.join("NOTES/SESSION-ID.jsonl.md"),
    ] {
        fs::write(path, "").expect("fixture file");
    }
    let source = discover(project);
    assert_eq!(paths(&source.sessions), [project.join("SESSION-ID.jsonl")]);
    assert_eq!(
        paths(&source.agents),
        [subagents.join("agent-0123456789abcdef0.jsonl")]
    );
}

/// ´test:crate:templates-escape-every-value-and-know-no-safe-filter´
#[test]
fn templates_escape_every_value_and_know_no_safe_filter() {
    let environment = templates::environment();
    let hostile = "<script>alert(1)</script> & \"quoted\"";
    let rendered = environment
        .render_str("<p>{{ text }}</p>", minijinja::context! { text => hostile })
        .expect("render");
    assert!(
        rendered.starts_with("<p>&lt;script&gt;alert(1)&lt;"),
        "{rendered}"
    );
    assert!(rendered.contains(" &amp; &quot;quoted&quot;"), "{rendered}");
    assert_eq!(rendered.matches('<').count(), 2, "{rendered}");
    assert!(
        environment
            .render_str("{{ text|safe }}", minijinja::context! { text => hostile })
            .is_err()
    );
}

/// ´test:crate:a-loop-loads-from-its-project-directory´
#[test]
fn a_loop_loads_from_its_project_directory() {
    let source = discover(&fixture_projects().join("-home-alpha-dev-alpha"));
    let heads = Heads::load(&source).expect("load");
    let report = heads.report();
    assert_eq!(
        report,
        LoadReport {
            files: 4,
            records: 28,
            copies_dropped: 4,
            malformed: 5,
            oversized: 0,
            ignored: 0,
            skipped: 0,
            meta_skipped: 0,
        }
    );
    assert_eq!(
        report.to_string(),
        "files=4 records=28 copies_dropped=4 malformed=5 oversized=0 ignored=0 skipped=0 meta_skipped=0"
    );
    let stems: Vec<_> = heads.files.iter().map(|file| file.stem.as_str()).collect();
    assert_eq!(
        stems,
        [
            "SESSION-ID-LINEAR",
            "SESSION-ID-REPEAT",
            "SESSION-ID-ORDER",
            "SESSION-ID-UNKNOWN"
        ]
    );
    assert!(
        heads
            .files
            .iter()
            .all(|file| file.bytes > 0 && file.modified.is_some())
    );
}
