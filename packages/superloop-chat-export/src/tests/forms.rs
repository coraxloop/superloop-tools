use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use super::super::head::{Kind, RawHead};
use super::super::templates::SCRIPT;
use super::id;
use super::render::{html_files, render};

/// Renders one synthetic session whose records follow each other, one second
/// apart from 10:00:00, each record given as its fields after the shared ones.
fn rendered_session(records: &[String]) -> (tempfile::TempDir, BTreeMap<String, String>) {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let mut text = String::new();
    for (index, rest) in (0_u64..).zip(records) {
        let parent = index.checked_sub(1).map_or_else(
            || "null".to_owned(),
            |previous| format!(r#""{}""#, id(0x900 + previous)),
        );
        writeln!(
            text,
            r#"{{"uuid":"{}","parentUuid":{parent},"timestamp":"2026-05-01T10:00:{index:02}.000Z","sessionId":"SESSION-ID-S",{rest}}}"#,
            id(0x900 + index)
        )
        .expect("write");
    }
    fs::write(project.join("SESSION-ID-S.jsonl"), text).expect("session");
    let output = root.path().join("out");
    render(&project, &output, 16_384);
    let files = html_files(&output);
    (root, files)
}

fn user(content: &str) -> String {
    format!(
        r#""type":"user","message":{{"content":{}}}"#,
        serde_json::to_string(content).expect("json")
    )
}

fn kind(record: &str) -> Kind {
    let line = format!("{{{record}}}");
    serde_json::from_str::<RawHead<'_>>(&line)
        .expect("record head")
        .kind()
}

/// ´test:crate:harness-forms-are-classified-by-name´
#[test]
fn harness_forms_are_classified_by_name() {
    for (content, expected) in [
        (
            "<local-command-stdout>ok</local-command-stdout>",
            Kind::UserNote,
        ),
        (
            "<local-command-stderr>no</local-command-stderr>",
            Kind::UserNote,
        ),
        (
            "<local-command-caveat>Caveat</local-command-caveat>",
            Kind::UserNote,
        ),
        (
            "<bash-stdout>ok</bash-stdout><bash-stderr></bash-stderr>",
            Kind::UserNote,
        ),
        (
            "<system-reminder>Remember.</system-reminder>",
            Kind::UserNote,
        ),
        (
            "<task-notification>done</task-notification>",
            Kind::UserNote,
        ),
        ("<command-name>/compact</command-name>", Kind::Command),
        (
            "<command-message>compact</command-message>\n<command-name>/compact</command-name>",
            Kind::Command,
        ),
        ("<div>my own markup</div> please", Kind::Prompt),
        ("<script>alert(1)</script>", Kind::Prompt),
        ("<b>bold</b> request", Kind::Prompt),
        ("<Local-command-stdout>ok", Kind::Prompt),
        ("plain words", Kind::Prompt),
        ("  \n", Kind::UserNote),
    ] {
        assert_eq!(kind(&user(content)), expected, "{content}");
    }
    let blocks = r#""type":"user","message":{"content":[{"type":"text","text":"<system-reminder>x</system-reminder>"}]}"#;
    assert_eq!(kind(blocks), Kind::UserNote);
    let owner = r#""type":"user","message":{"content":[{"type":"text","text":"<table> of results, please"}]}"#;
    assert_eq!(kind(owner), Kind::Prompt);
}

/// ´test:crate:a-command-shows-as-typed-with-its-output-folded´
#[test]
fn a_command_shows_as_typed_with_its_output_folded() {
    let caveat = r#""type":"user","isMeta":true,"message":{"content":"<local-command-caveat>Caveat: written by local commands.</local-command-caveat>"}"#;
    let response = r###""type":"assistant","message":{"id":"MESSAGE-ID-S1","content":[{"type":"text","text":"## Done **now**\n\n| a | b |\n|---|---|\n| 1 | 2 |"}]}"###;
    let (_root, files) = rendered_session(&[
        user("<b>Tidy</b> the notes."),
        response.to_owned(),
        caveat.to_owned(),
        user(
            "<command-name>/compact</command-name>\n<command-message>compact</command-message>\n<command-args>keep the tests</command-args>",
        ),
        user("<local-command-stdout>Compacted <b>fine</b></local-command-stdout>"),
    ]);
    let page = &files["p0001.html"];
    assert!(page.contains("<div class=\"text\">&#x2f;compact keep the tests</div>"));
    assert!(page.contains("<time>10:00:03 UTC</time> &#x2f;compact keep the tests</a>"));
    assert!(page.contains("<time>10:00:00 UTC</time> &lt;b&gt;Tidy&lt;&#x2f;b&gt; the notes.</a>"));
    assert!(!page.contains("command-name") && !page.contains("local-command-stdout"));
    assert!(page.contains(
        "<details class=\"run notes\">\n<summary>1 note · command caveat · 10:00:02 UTC</summary>"
    ));
    assert!(page.contains(
        "<details class=\"run notes\">\n<summary>1 note · command output · 10:00:04 UTC</summary>"
    ));
    assert!(page.contains("<div class=\"text\">Compacted &lt;b&gt;fine&lt;&#x2f;b&gt;</div>"));
    assert!(page.contains("<details class=\"response\" open>\n<summary>Done now</summary>"));
    assert!(page.contains("<h4>Done <strong>now</strong></h4>"));
    assert!(page.contains("<summary>2 prompts on this page</summary>"));
}

/// ´test:crate:a-notes-summary-counts-attachments-and-names-six-labels´
#[test]
fn a_notes_summary_counts_attachments_and_names_six_labels() {
    let attachment = |kind: &str| {
        format!(r#""type":"attachment","attachment":{{"type":"{kind}","content":"x"}}"#)
    };
    let system = |subtype: &str| format!(r#""type":"system","subtype":"{subtype}","content":"x""#);
    let meta = r#""type":"user","isMeta":true,"message":{"content":"Loaded a skill."}"#;
    let origin = r#""type":"user","origin":{"kind":"task-notification"},"message":{"content":"A task ended."}"#;
    let response = r#""type":"assistant","message":{"id":"MESSAGE-ID-S2","content":[{"type":"text","text":"Noted."}]}"#;
    let (_root, files) = rendered_session(&[
        user("Collect the notes."),
        attachment("date"),
        attachment("skill_listing"),
        system("s1"),
        attachment("date"),
        system("s2"),
        system("s3"),
        system("s4"),
        system("s5"),
        meta.to_owned(),
        system("s6"),
        origin.to_owned(),
        response.to_owned(),
        attachment("date"),
    ]);
    let page = &files["p0001.html"];
    assert!(page.contains(
        "<summary>11 notes · 3 attachments, system · s1, system · s2, system · s3, system · s4, system · s5 and 3 more · 10:00:01 UTC – 10:00:11 UTC</summary>"
    ));
    assert!(page.contains("<strong>harness message</strong>"));
    assert!(page.contains("<strong>task notification</strong>"));
    assert!(page.contains("<summary>1 note · attachment · date · 10:00:13 UTC</summary>"));
}

/// ´test:crate:the-script-guards-the-decode-of-the-fragment´
#[test]
fn the_script_guards_the_decode_of_the_fragment() {
    assert_eq!(SCRIPT.matches("decodeURIComponent(").count(), 1);
    let decode = SCRIPT.find("decodeURIComponent(").expect("decode");
    let guard = SCRIPT[..decode].rfind("try {").expect("try");
    assert_eq!(SCRIPT[guard..decode].lines().count(), 2);
    assert!(SCRIPT[decode..].contains("} catch (malformed) {"));
    assert!(SCRIPT[..guard].contains("let id = location.hash.slice(1);"));
}
