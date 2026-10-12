use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use super::super::load::Heads;
use super::super::plan::{page_turns, plan};
use super::super::tree::{Answers, Item, Tree};
use super::super::view::{Links, PageView, read_bodies};
use super::conserve::{conservation, records_planned};
use super::render::{attempt_paged, html_files};
use super::{discover, id};

pub(super) const PROMPT: &str = r#""type":"user","message":{"content":"Next step."}"#;

/// A transcript line: record `number` under `parent`, with `rest` giving its
/// type and message.
pub(super) fn line(number: u64, parent: Option<u64>, rest: &str) -> String {
    let parent = parent.map_or_else(|| "null".to_owned(), |parent| format!("\"{}\"", id(parent)));
    format!(
        r#"{{"uuid":"{}","parentUuid":{parent},{rest},"timestamp":"2026-05-01T10:00:00.000Z"}}"#,
        id(number)
    ) + "\n"
}

/// A transcript line of exactly `length` bytes, its message built by `rest`
/// around the padding that makes it so.
pub(super) fn padded(
    length: usize,
    number: u64,
    parent: u64,
    rest: impl Fn(&str) -> String,
) -> String {
    let bare = line(number, Some(parent), &rest("")).len();
    line(number, Some(parent), &rest(&"x".repeat(length - bare)))
}

/// One turn: an opening prompt, then `pairs` calls of 1,200 bytes each
/// answered by a result of 700 bytes, the last call with the id `last`.
fn long_turn(first: u64, pairs: u64, last: &str) -> String {
    let mut text = line(first, None, PROMPT);
    let mut parent = first;
    for pair in 0..pairs {
        let call = first + 1 + 2 * pair;
        let id = if pair + 1 == pairs {
            last.to_owned()
        } else {
            format!("TOOL-{first:x}-{pair}")
        };
        text += &padded(1_200, call, parent, |pad| {
            format!(
                r#""type":"assistant","message":{{"id":"MESSAGE-ID-{call:x}","content":[{{"type":"tool_use","id":"{id}","name":"Task","input":{{"text":"{pad}"}}}}]}}"#
            )
        });
        text += &padded(700, call + 1, call, |pad| {
            format!(
                r#""type":"user","message":{{"content":[{{"type":"tool_result","tool_use_id":"{id}","content":"{pad}"}}]}}"#
            )
        });
        parent = call + 1;
    }
    text
}

/// The ids every page of `files` gives its elements, by page.
fn anchors(files: &BTreeMap<String, String>) -> BTreeMap<&str, BTreeSet<&str>> {
    files
        .iter()
        .map(|(path, html)| {
            let ids = html
                .split(" id=\"")
                .skip(1)
                .filter_map(|rest| rest.split('"').next())
                .collect();
            (path.as_str(), ids)
        })
        .collect()
}

/// `target` relative to the page at `from`, both under the loop's folder; none
/// when it leaves the folder.
fn joined(from: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            ".." => {
                parts.pop()?;
            }
            "." | "" => {}
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// Resolves every link with a fragment on every page to an element of the
/// page it names, returning how many it resolved.
fn resolve_links(files: &BTreeMap<String, String>) -> usize {
    let anchors = anchors(files);
    let mut resolved = 0;
    for (path, html) in files {
        for href in html
            .split(" href=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
        {
            let href = href.replace("&#x2f;", "/");
            let Some((target, fragment)) = href.split_once('#') else {
                continue;
            };
            let target = if target.is_empty() {
                path.clone()
            } else if let Some(target) = joined(path, target) {
                target
            } else {
                continue;
            };
            let ids = anchors
                .get(target.as_str())
                .unwrap_or_else(|| panic!("{path}: {href} names no page"));
            assert!(ids.contains(fragment), "{path}: {href}");
            resolved += 1;
        }
    }
    resolved
}

/// ´test:crate:a-turn-past-the-page-limit-is-cut-at-records-with-its-links-resolved´
#[test]
fn a_turn_past_the_page_limit_is_cut_at_records_with_its_links_resolved() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    let end = line(
        0x911,
        Some(0x910),
        &format!(
            r#""type":"assistant","message":{{"id":"MESSAGE-ID-END","content":[{{"type":"text","text":"{}"}}]}}"#,
            "y".repeat(20_000)
        ),
    );
    fs::write(
        project.join("SESSION-ID.jsonl"),
        long_turn(0x900, 8, "TOOL-A") + &end,
    )
    .expect("session");
    fs::write(
        subagents.join("agent-thread.jsonl"),
        long_turn(0xa00, 8, "TOOL-N"),
    )
    .expect("thread");
    fs::write(
        subagents.join("agent-thread.meta.json"),
        r#"{"agentType":"general-purpose","toolUseId":"TOOL-A"}"#,
    )
    .expect("meta");
    fs::write(
        subagents.join("agent-nested.jsonl"),
        line(0xb00, None, PROMPT),
    )
    .expect("nested");
    fs::write(
        subagents.join("agent-nested.meta.json"),
        r#"{"agentType":"Explore","toolUseId":"TOOL-N"}"#,
    )
    .expect("meta");
    let output = root.path().join("gamma");
    attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    let files = html_files(&output);
    let count = |prefix: &str| files.keys().filter(|path| path.starts_with(prefix)).count();
    assert_eq!((count("p0"), count("agents/thread-")), (10, 9));
    for number in (0x900..=0x911).chain(0xa00..=0xa10).chain([0xb00]) {
        let anchor = format!(r#" id="r-{}""#, id(number));
        let shown: usize = files
            .values()
            .map(|html| html.matches(&anchor).count())
            .sum();
        assert_eq!(shown, 1, "{anchor}");
    }
    let owners: usize = files
        .iter()
        .filter(|(path, _)| path.starts_with("p0"))
        .map(|(_, html)| html.matches("<article class=\"record owner").count())
        .sum();
    assert_eq!(owners, 1);
    assert!(files["p0001.html"].contains("This turn goes on to the next page"));
    assert!(files["p0002.html"].contains("This turn began on the previous page"));
    let call = |number: u64| format!("#call-{}-0", id(number));
    assert!(files["p0002.html"].contains(&format!(r#"href="p0001.html{}""#, call(0x901))));
    assert!(files["p0010.html"].contains("bytes omitted"));
    assert!(!files["p0010.html"].contains("This turn goes on to the next page"));
    assert!(
        files["agents/thread-02.html"]
            .contains(&format!(r#"href="thread-01.html{}""#, call(0xa01)))
    );
    assert!(files["agents/thread-01.html"].contains(&format!("..&#x2f;p0008.html{}", call(0x90f))));
    assert!(files["agents/nested-01.html"].contains(&format!("thread-08.html{}", call(0xa0f))));
    assert!(resolve_links(&files) >= 16);
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!((found.calls, found.results, found.unanswered), (16, 16, 0));
    assert_eq!(
        records_planned(&project, 1_000),
        (found.records, found.records)
    );
}

/// ´test:crate:a-page-of-a-long-run-visits-only-its-own-records´
#[test]
fn a_page_of_a_long_run_visits_only_its_own_records() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    fs::write(
        project.join("SESSION-ID.jsonl"),
        long_turn(0x900, 300, "TOOL-LAST"),
    )
    .expect("session");
    let heads = Heads::load(&discover(&project)).expect("load");
    let tree = Tree::build(&heads);
    let turn = &tree.conversations[0].turns[0];
    assert_eq!(tree.conversations[0].turns.len(), 1);
    assert!(matches!(&turn.items[1], Item::ToolRun(run) if run.groups.len() == 300));
    let pages = plan(&heads, &tree, &[], 1_000);
    assert!(pages.len() > 250, "{}", pages.len());
    let sequence = &tree.conversations[0].main;
    let (agents, forks) = (BTreeMap::new(), BTreeMap::new());
    let (results, calls) = (BTreeMap::new(), BTreeMap::new());
    let pairing = Answers::of(&heads);
    for page in &pages {
        let records = page.positions.len();
        let bodies =
            read_bodies(&heads, &sequence[page.positions.clone()], 16_384).expect("bodies");
        let links = Links {
            agents: &agents,
            forks: &forks,
            parents: &tree.links.parent,
            results: &results,
            calls: &calls,
            pairing: &pairing,
        };
        let mut view = PageView::new(&heads, &bodies, links, 16_384);
        let turns = view.turns(sequence, page_turns(&tree, &[], page), &page.positions);
        assert_eq!(turns.len(), 1, "{}", page.path);
        assert_eq!(view.shown(), records, "{}", page.path);
        assert!(
            view.examined() <= 2 * records,
            "{}: {} places examined for {records} records of a run of {}",
            page.path,
            view.examined(),
            turn.positions.len()
        );
    }
}
