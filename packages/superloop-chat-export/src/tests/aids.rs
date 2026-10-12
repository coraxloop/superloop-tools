use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use super::super::agents::{attach, load_agents};
use super::super::load::Heads;
use super::super::plan::{PAGE_BUDGET, PageKind, plan};
use super::super::templates::SCRIPT;
use super::super::tree::{Item, Tree};
use super::super::view::Stamp;
use super::render::{html_files, render};
use super::{discover, fixture_projects, id};

fn rendered(project: &Path) -> (tempfile::TempDir, BTreeMap<String, String>) {
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("out");
    render(project, &output, 16_384);
    let files = html_files(&output);
    (root, files)
}

fn summaries(html: &str) -> Vec<&str> {
    html.split("<summary>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</summary>").map(|(summary, _)| summary))
        .collect()
}

/// ´test:crate:a-run-folds-under-a-summary-of-what-it-holds´
#[test]
fn a_run_folds_under_a_summary_of_what_it_holds() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    let first = &files["p0001.html"];
    assert!(first.contains(
        "<details class=\"run\">\n<summary>3 calls · Read, Bash, Agent · 1 agent thread · 10:00:03 UTC – 10:00:08 UTC</summary>"
    ));
    assert!(first.contains(
        "<details class=\"run\">\n<summary>1 call · Bash · 1 note · 10:00:10 UTC – 10:00:11 UTC</summary>"
    ));
    assert!(!first.contains("<details class=\"run\" open"));
}

/// ´test:crate:a-run-names-six-tools-then-counts-the-rest´
#[test]
fn a_run_names_six_tools_then_counts_the_rest() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(project.join("SESSION-ID-S/subagents")).expect("directories");
    let tools = ["Bash", "Read", "Edit", "Write", "Grep", "Glob", "Agent"];
    let mut text = String::new();
    let record = |number: u64, parent: Option<u64>, second: u64, rest: &str| {
        let parent = parent.map_or_else(
            || "null".to_owned(),
            |parent| format!(r#""{}""#, id(parent)),
        );
        format!(
            r#"{{"uuid":"{}","parentUuid":{parent},"timestamp":"2026-05-01T10:00:{second:02}.000Z","sessionId":"SESSION-ID-S",{rest}}}"#,
            id(number)
        )
    };
    writeln!(
        text,
        "{}",
        record(
            0x800,
            None,
            0,
            r#""type":"user","message":{"content":"Use every tool."}"#
        )
    )
    .expect("write");
    for (index, tool) in (0_u64..).zip(tools) {
        let call = format!(
            r#""type":"assistant","message":{{"id":"MESSAGE-ID-S","content":[{{"type":"tool_use","id":"TOOL-{index}","name":"{tool}","input":{{}}}}]}}"#
        );
        let parent = if index == 0 { 0x800 } else { 0x80f + index };
        writeln!(
            text,
            "{}",
            record(0x810 + index, Some(parent), 1 + index, &call)
        )
        .expect("write");
    }
    for index in 0_u64..7 {
        let error = if index == 2 {
            r#","is_error":true"#
        } else {
            ""
        };
        let result = format!(
            r#""type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"TOOL-{index}","content":"done"{error}}}]}}"#
        );
        writeln!(
            text,
            "{}",
            record(0x820 + index, Some(0x810 + index), 10 + index, &result)
        )
        .expect("write");
    }
    fs::write(project.join("SESSION-ID-S.jsonl"), text).expect("session");
    fs::write(
        project.join("SESSION-ID-S/subagents/agent-0123456789abcdef7.jsonl"),
        format!(
            r#"{{"uuid":"{}","parentUuid":null,"type":"user","isSidechain":true,"message":{{"content":"Work."}},"timestamp":"2026-05-01T10:00:08.000Z"}}"#,
            id(0x830)
        ) + "\n",
    )
    .expect("agent");
    fs::write(
        project.join("SESSION-ID-S/subagents/agent-0123456789abcdef7.meta.json"),
        r#"{"agentType":"general-purpose","description":"Work","toolUseId":"TOOL-6"}"#,
    )
    .expect("meta");
    let (_root, files) = rendered(&project);
    assert!(files["p0001.html"].contains(
        "<summary>7 calls · Bash, Read, Edit, Write, Grep, Glob and 1 more · 1 error · 1 agent thread · 10:00:01 UTC – 10:00:16 UTC</summary>"
    ));
}

/// ´test:crate:a-response-folds-open-under-its-first-line-of-text´
#[test]
fn a_response_folds_open_under_its_first_line_of_text() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    let first = &files["p0001.html"];
    // The response's first record is thinking; the line comes from its text.
    assert!(first.contains("<details class=\"response\" open>\n<summary>Reading them.</summary>"));
    assert!(first.contains(
        "<details class=\"thinking\"><summary>Thinking, 23 bytes</summary><div class=\"text\">Read two files at once.</div></details>"
    ));
    assert!(first.contains("<summary>The notes have twelve lines.</summary>"));
}

/// ´test:crate:owner-messages-lie-outside-every-disclosure´
#[test]
fn owner_messages_lie_outside_every_disclosure() {
    for fixture in [
        "-home-alpha-dev-gamma",
        "-home-alpha-dev-hostile",
        "-home-alpha-dev-alpha",
    ] {
        let (_root, files) = rendered(&fixture_projects().join(fixture));
        let mut owners = 0;
        for html in files.values() {
            let mut depth = 0_i32;
            for (at, _) in html.match_indices('<') {
                let tag = &html[at..];
                if tag.starts_with("<details") {
                    depth += 1;
                } else if tag.starts_with("</details>") {
                    depth -= 1;
                } else if tag.starts_with("<article class=\"record owner") {
                    assert_eq!(depth, 0, "{fixture}");
                    owners += 1;
                }
            }
            assert_eq!(depth, 0);
        }
        assert!(owners > 0, "{fixture}");
    }
}

/// ´test:crate:the-prompt-list-counts-and-links-the-owner-messages´
#[test]
fn the_prompt_list_counts_and_links_the_owner_messages() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    let last = &files["p0004.html"];
    assert!(
        last.contains(
            "<details class=\"prompts\" open>\n<summary>2 prompts on this page</summary>"
        )
    );
    assert!(last.contains(&format!(
        "<li><a href=\"#r-{}\"><time>10:06:30 UTC</time> Also check the dates.</a></li>",
        id(0x524)
    )));
    assert!(last.contains(&format!("href=\"#r-{}\"", id(0x5d1))));
    assert!(files["p0002.html"].contains("<summary>1 prompt on this page</summary>"));
    assert!(files["p0001.html"].contains("<summary>2 prompts on this page</summary>"));
    let prompts = last.find("details class=\"prompts\"").expect("prompt list");
    assert!(prompts < last.find("<main>").expect("main"));
}

/// ´test:crate:the-mode-button-is-in-the-html-and-hidden´
#[test]
fn the_mode_button_is_in_the_html_and_hidden() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    for (name, html) in &files {
        if name.starts_with("p0") || name.starts_with("agents/") || name.starts_with("branches/") {
            let button = "<button type=\"button\" class=\"mode\" hidden>Prompts only</button>";
            assert_eq!(html.matches(button).count(), 2, "{name}");
            let script = html.find("<script src=\"").expect("script");
            assert!(script < html.find("<body>").expect("body"), "{name}");
            assert!(!html.contains(" defer>"), "{name}");
        }
    }
}

/// ´test:crate:the-script-reads-one-storage-key-and-builds-no-markup´
#[test]
fn the_script_reads_one_storage_key_and_builds_no_markup() {
    assert_eq!(SCRIPT.matches("\"chat-export.mode\"").count(), 1);
    assert_eq!(SCRIPT.matches("localStorage").count(), 2);
    for refused in [
        "innerHTML",
        "outerHTML",
        "eval(",
        "fetch(",
        "XMLHttpRequest",
        "setTimeout",
        "setInterval",
        "document.write",
    ] {
        assert!(!SCRIPT.contains(refused), "{refused}");
    }
}

/// ´test:crate:summaries-escape-the-hostile-fixture´
#[test]
fn summaries_escape_the_hostile_fixture() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-hostile"));
    let all: Vec<&str> = files.values().flat_map(|html| summaries(html)).collect();
    let run = all
        .iter()
        .find(|summary| summary.contains("alert(&quot;name&quot;)"))
        .expect("a run summary naming the hostile tool");
    assert!(
        run.contains("&lt;script&gt;") && run.contains("1 error"),
        "{run}"
    );
    assert!(
        all.iter()
            .any(|summary| summary.contains("alert(&quot;response&quot;)"))
    );
    assert!(all.iter().all(|summary| !summary.contains('<')));
    let lists: String = files
        .values()
        .filter_map(|html| {
            let start = html.find("<details class=\"prompts\" open>")?;
            let length = html[start..].find("</details>")?;
            Some(html[start..start + length].to_owned())
        })
        .collect();
    for field in ["prompt", "queued", "command"] {
        assert!(
            lists.contains(&format!("alert(&quot;{field}&quot;)")),
            "{field}"
        );
    }
    assert!(!lists.contains("<script"));
}

/// ´test:crate:runs-and-responses-are-disclosures-as-the-plan-counts´
#[test]
fn runs_and_responses_are_disclosures_as_the_plan_counts() {
    let project = fixture_projects().join("-home-alpha-dev-gamma");
    let (_root, files) = rendered(&project);
    let source = discover(&project);
    let heads = Heads::load(&source).expect("load");
    let (mut agents, _) = load_agents(&source.agents).expect("agents");
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    for page in plan(&heads, &tree, &agents, PAGE_BUDGET) {
        let turns = match (page.kind, page.conversation, page.branch) {
            (PageKind::Main, Some(conversation), _) => {
                &tree.conversations[conversation].turns[page.turns.clone()]
            }
            (PageKind::Branch, Some(conversation), Some(branch)) => {
                &tree.conversations[conversation].branches[branch].turns[page.turns.clone()]
            }
            _ => continue,
        };
        let items: Vec<&Item> = turns.iter().flat_map(|turn| &turn.items).collect();
        let runs = items
            .iter()
            .filter(|item| matches!(item, Item::ToolRun(_) | Item::Notes(_)))
            .count();
        let responses = items
            .iter()
            .filter(|item| matches!(item, Item::Response { .. }))
            .count();
        let html = &files[&page.path];
        assert_eq!(
            html.matches("<details class=\"run").count(),
            runs,
            "{}",
            page.path
        );
        assert_eq!(
            html.matches("<details class=\"response\" open>").count(),
            responses,
            "{}",
            page.path
        );
    }
}

/// ´test:crate:record-times-show-a-date-and-time-with-the-instant-in-datetime´
#[test]
fn record_times_show_a_date_and_time_with_the_instant_in_datetime() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    let first = &files["p0001.html"];
    assert!(first.contains(
        "<strong>Read</strong> <time datetime=\"2026-02-01T10:00:03.000Z\">2026-02-01 10:00:03 UTC</time>"
    ));
    assert!(!first.contains(">2026-02-01T"));
    let stamp = Stamp::of("2026-02-01T23:59:59.999Z");
    assert_eq!(
        (stamp.instant.as_deref(), stamp.shown.as_str()),
        (Some("2026-02-01T23:59:59.999Z"), "2026-02-01 23:59:59 UTC")
    );
    let (_root, hostile) = rendered(&fixture_projects().join("-home-alpha-dev-hostile"));
    let all: String = hostile.values().cloned().collect();
    assert!(all.contains(
        "<time>unparsed timestamp: &lt;script&gt;alert(&quot;time&quot;)&lt;&#x2f;script&gt;</time>"
    ));
    for text in [
        "2026-02-01T10:00:00",
        "2026-02-01T12:00:00+02:00",
        "2026-02-29T10:00:00Z",
        "2026-02-31T10:00:00Z",
        "2026-04-31T10:00:00Z",
        "2026-02-01T10:00:60Z",
    ] {
        let stamp = Stamp::of(text);
        assert_eq!(stamp.instant, None);
        assert_eq!(stamp.shown, format!("unparsed timestamp: {text}"));
    }
}

/// ´test:crate:main-pages-and-page-lists-lead-with-the-span´
#[test]
fn main_pages_and_page_lists_lead_with_the_span() {
    let (_root, files) = rendered(&fixture_projects().join("-home-alpha-dev-gamma"));
    let first = &files["p0001.html"];
    assert!(first.contains("<title>gamma · 2026-02-01 10:00 UTC – 10:01 UTC</title>"));
    assert!(first.contains(
        "<h1>gamma · 2026-02-01 10:00 UTC – 10:01 UTC</h1>\n<p class=\"span\">Conversation 1 · page 1</p>"
    ));
    assert!(files["pages.html"].contains(
        "<td><a href=\"p0001.html\" target=\"_top\">2026-02-01 10:00 UTC – 10:01 UTC</a></td><td>1</td>"
    ));
    assert!(files["index.html"].contains("<th>Span</th><th>Page</th>"));
}
