//! Conservation of records, calls and results from the transcripts to the
//! plan and the rendered pages, checked apart from the program's own pairing:
//! the transcripts are read here as JSON lines, every tool-use block is a call
//! known by its record and its index among the record's tool-use blocks, a
//! result block names the calls carrying the id it names (or, for a block
//! naming none, the one call of the record it names as its source), and the
//! pages are read as text. The checks hold whatever order the program pairs
//! a repeated id in: a call's result is one its call names, no result is
//! claimed twice, and no more calls of one id are told no result was recorded
//! than that id has calls beyond its results.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use super::super::agents::{AgentThread, attach, load_agents};
use super::super::load::Heads;
use super::super::plan::{PAGE_BUDGET, PagePlan, page_sequence, plan, write_dump};
use super::super::templates::{SCRIPT, with_templates};
use super::super::tree::Tree;
use super::super::view::{self, MIN_BLOCK_BYTES};
use super::paging::{PROMPT, line, padded};
use super::render::{attempt, attempt_paged, html_files, render};
use super::{discover, fixture_projects};

/// A call as the transcript holds it: one tool-use block.
struct Call {
    record: String,
    index: usize,
    id: Option<String>,
}

impl Call {
    fn anchor(&self) -> String {
        format!("call-{}-{}", self.record, self.index)
    }
}

/// A tool result block as the transcript holds it.
struct Block {
    record: String,
    index: usize,
    call: Option<String>,
    source: Option<String>,
}

impl Block {
    fn anchor(&self) -> String {
        format!("result-{}-{}", self.record, self.index)
    }
}

/// What a project's transcripts hold, read line by line.
#[derive(Default)]
struct Transcript {
    records: BTreeSet<String>,
    calls: Vec<Call>,
    /// How many tool-use blocks each record holds, with an id or without.
    blocks_of: BTreeMap<String, usize>,
    /// How many calls carry each id.
    carriers: BTreeMap<String, usize>,
    blocks: Vec<Block>,
}

impl Transcript {
    fn read(project: &Path) -> Self {
        let mut files = Vec::new();
        for entry in fs::read_dir(project).expect("project").flatten() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "jsonl")
            {
                files.push(path);
            } else if let Ok(agents) = fs::read_dir(path.join("subagents")) {
                files.extend(agents.flatten().map(|agent| agent.path()).filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "jsonl")
                }));
            }
        }
        let mut transcript = Self::default();
        for file in files {
            let text = fs::read_to_string(&file).expect("transcript");
            for record in text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
            {
                transcript.add(&record);
            }
        }
        transcript
    }

    fn add(&mut self, record: &Value) {
        let Some(id) = record.get("uuid").and_then(Value::as_str) else {
            return;
        };
        if !self.records.insert(id.to_owned()) {
            return;
        }
        let blocks = record
            .pointer("/message/content")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let of_type = |kind: &'static str| {
            blocks
                .iter()
                .filter(move |block| block.get("type").and_then(Value::as_str) == Some(kind))
        };
        match record.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                for (index, block) in of_type("tool_use").enumerate() {
                    let call = block.get("id").and_then(Value::as_str).map(str::to_owned);
                    if let Some(call) = &call {
                        *self.carriers.entry(call.clone()).or_default() += 1;
                    }
                    self.calls.push(Call {
                        record: id.to_owned(),
                        index,
                        id: call,
                    });
                    *self.blocks_of.entry(id.to_owned()).or_default() += 1;
                }
            }
            Some("user") => {
                let source = record
                    .get("sourceToolAssistantUUID")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                for (index, block) in of_type("tool_result").enumerate() {
                    self.blocks.push(Block {
                        record: id.to_owned(),
                        index,
                        call: block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        source: source.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    /// What a call is named by: its id, or its place when it has none.
    fn call_key(call: &Call) -> String {
        call.id
            .as_ref()
            .map_or_else(|| format!("at {}", call.anchor()), |id| format!("id {id}"))
    }

    /// The key of the calls a block names: those carrying the id it names,
    /// or for a block naming none the one call of its source record; none
    /// when no call answers to it.
    fn block_key(&self, block: &Block) -> Option<String> {
        block.call.as_ref().map_or_else(
            || {
                let source = block.source.as_deref()?;
                if self.blocks_of.get(source) != Some(&1) {
                    return None;
                }
                self.calls
                    .iter()
                    .find(|call| call.record == source)
                    .map(Self::call_key)
            },
            |id| self.carriers.contains_key(id).then(|| format!("id {id}")),
        )
    }
}

/// How the transcripts' records, calls and results reach the pages.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Conservation {
    pub(super) records: usize,
    pub(super) records_shown_once: usize,
    pub(super) calls: usize,
    pub(super) calls_without_an_id: usize,
    pub(super) ids_carried_by_more_than_one_call: usize,
    pub(super) calls_shown_once: usize,
    pub(super) results: usize,
    pub(super) results_shown_once: usize,
    /// Calls shown with their result beneath them.
    pub(super) answered_beside: usize,
    /// Calls whose result is shown apart on the same page.
    pub(super) answered_on_the_page: usize,
    /// Calls whose result is shown on another page.
    pub(super) answered_elsewhere: usize,
    /// Calls told that the transcript holds no result.
    pub(super) unanswered: usize,
    pub(super) results_without_a_known_call: usize,
    /// Links between a call and its result resolved to the other half.
    pub(super) links_resolved: usize,
    pub(super) faults: Vec<String>,
}

/// Every element id on each page, with how often it occurs.
fn anchors(files: &BTreeMap<String, String>) -> BTreeMap<&str, BTreeMap<&str, usize>> {
    files
        .iter()
        .map(|(path, html)| {
            let mut ids: BTreeMap<&str, usize> = BTreeMap::new();
            for rest in html.split(" id=\"").skip(1) {
                if let Some(id) = rest.split('"').next() {
                    *ids.entry(id).or_default() += 1;
                }
            }
            (path.as_str(), ids)
        })
        .collect()
}

/// The page and anchor a link on the page at `from` names, its fragment
/// decoded as the page's script decodes it.
fn resolve(from: &str, href: &str) -> Option<(String, String)> {
    let href = href.replace("&#x2f;", "/");
    let (target, fragment) = href.split_once('#')?;
    let fragment = percent_decoded(fragment)?;
    if target.is_empty() {
        return Some((from.to_owned(), fragment));
    }
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
    Some((parts.join("/"), fragment))
}

/// A fragment decoded as `decodeURIComponent` decodes it; none when it is not
/// UTF-8 once decoded.
fn percent_decoded(fragment: &str) -> Option<String> {
    let bytes = fragment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// The text of the `<article>` element around `at` in `html`.
fn article_around(html: &str, at: usize) -> &str {
    let start = html[..at].rfind("<article").unwrap_or(0);
    let end = html[at..]
        .find("</article>")
        .map_or(html.len(), |end| at + end);
    &html[start..end]
}

/// The first href after `marker` in `text`.
fn href_after<'t>(text: &'t str, marker: &str) -> Option<&'t str> {
    let rest = &text[text.find(marker)? + marker.len()..];
    let rest = &rest[rest.find("href=\"")? + "href=\"".len()..];
    rest.split('"').next()
}

/// What the pages say of the calls of one key.
#[derive(Default)]
struct Told {
    calls: usize,
    results: usize,
    unanswered: usize,
}

/// Checks that every record of the project's transcripts is shown once on the
/// rendered pages under `output`, every call and every result block once,
/// every call's stated status agrees with where the transcript's results for
/// it lie, and every link between a call and its result resolves to the other
/// half of the same exchange.
pub(super) fn conservation(project: &Path, output: &Path) -> Conservation {
    let transcript = Transcript::read(project);
    let files = html_files(output);
    let anchors = anchors(&files);
    let once = |id: &str| {
        anchors
            .values()
            .filter_map(|ids| ids.get(id))
            .copied()
            .collect::<Vec<_>>()
            == [1]
    };
    let mut found = Conservation {
        records: transcript.records.len(),
        records_shown_once: transcript
            .records
            .iter()
            .filter(|record| once(&format!("r-{record}")))
            .count(),
        calls: transcript.calls.len(),
        calls_without_an_id: transcript
            .calls
            .iter()
            .filter(|call| call.id.is_none())
            .count(),
        ids_carried_by_more_than_one_call: transcript
            .carriers
            .values()
            .filter(|&&count| count > 1)
            .count(),
        results: transcript.blocks.len(),
        ..Conservation::default()
    };
    let mut told: BTreeMap<String, Told> = BTreeMap::new();
    let mut keys: BTreeMap<String, Option<String>> = BTreeMap::new();
    for block in &transcript.blocks {
        found.results_shown_once += usize::from(once(&block.anchor()));
        let key = transcript.block_key(block);
        match &key {
            Some(key) => told.entry(key.clone()).or_default().results += 1,
            None => found.results_without_a_known_call += 1,
        }
        keys.insert(block.anchor(), key);
    }
    let pages = Pages {
        files: &files,
        anchors: &anchors,
        keys: &keys,
    };
    let mut claimed = BTreeSet::new();
    for call in &transcript.calls {
        found.calls_shown_once += usize::from(once(&call.anchor()));
        let key = Transcript::call_key(call);
        told.entry(key.clone()).or_default().calls += 1;
        let shared = call
            .id
            .as_ref()
            .is_some_and(|id| transcript.carriers[id] > 1);
        match pages.check_call(call, &key, shared, &mut found) {
            Status::Claims(claim) => {
                if !claimed.insert(claim.clone()) {
                    found.faults.push(format!("{claim}: claimed by two calls"));
                }
            }
            Status::Unanswered => told.entry(key).or_default().unanswered += 1,
            Status::Faulty => {}
        }
    }
    for (key, told) in &told {
        if told.unanswered > told.calls - told.results.min(told.calls) {
            found.faults.push(format!(
                "{key}: {} of {} calls told no result was recorded while {} results name them",
                told.unanswered, told.calls, told.results
            ));
        }
    }
    for block in &transcript.blocks {
        pages.check_result(&transcript, block, &mut found);
    }
    for (what, shown, all) in [
        ("records", found.records_shown_once, found.records),
        ("calls", found.calls_shown_once, found.calls),
        ("results", found.results_shown_once, found.results),
    ] {
        if shown != all {
            found
                .faults
                .push(format!("{shown} of {all} {what} shown exactly once"));
        }
    }
    found
}

/// What the page holding a call states of its result.
enum Status {
    /// A result block beneath the call or linked from it, which the call
    /// claims.
    Claims(String),
    /// That no result was recorded.
    Unanswered,
    /// Something a fault records.
    Faulty,
}

/// The rendered pages, their element ids, and the key of the calls each
/// result block names, by the block's anchor.
struct Pages<'p> {
    files: &'p BTreeMap<String, String>,
    anchors: &'p BTreeMap<&'p str, BTreeMap<&'p str, usize>>,
    keys: &'p BTreeMap<String, Option<String>>,
}

impl Pages<'_> {
    /// The page holding the element `anchor`, its text and where the anchor
    /// stands in it.
    fn find(&self, anchor: &str) -> Option<(&str, &str, usize)> {
        let marker = format!(" id=\"{anchor}\"");
        self.files.iter().find_map(|(page, html)| {
            html.find(&marker)
                .map(|at| (page.as_str(), html.as_str(), at))
        })
    }

    /// Whether the element `anchor` stands on the page at `page`.
    fn stands(&self, page: &str, anchor: &str) -> bool {
        self.anchors
            .get(page)
            .is_some_and(|ids| ids.contains_key(anchor))
    }

    /// Whether the result block of `anchor` names the calls of `key`.
    fn names(&self, anchor: &str, key: &str) -> bool {
        self.keys
            .get(anchor)
            .is_some_and(|named| named.as_deref() == Some(key))
    }

    /// Checks the status the page holding `call` states for it: a result
    /// beneath it or a link to one, each a block naming the call, or no
    /// result recorded.
    fn check_call(&self, call: &Call, key: &str, shared: bool, found: &mut Conservation) -> Status {
        let anchor = call.anchor();
        let Some((page, html, at)) = self.find(&anchor) else {
            found
                .faults
                .push(format!("{anchor}: no page shows the call"));
            return Status::Faulty;
        };
        let exchange = article_around(html, at);
        if exchange.contains("Its call id is not unique in this transcript") != shared {
            found.faults.push(format!(
                "{anchor}: says its id is unique when it is not, or not when it is"
            ));
        }
        let beside = exchange
            .find("<div class=\"result")
            .and_then(|at| exchange[at..].split(" id=\"").nth(1))
            .and_then(|rest| rest.split('"').next());
        if let Some(beside) = beside {
            if self.names(beside, key) {
                found.answered_beside += 1;
                return Status::Claims(beside.to_owned());
            }
            found.faults.push(format!(
                "{anchor}: shows {beside} beneath it, not a result of it"
            ));
        } else if let Some(href) = href_after(exchange, "<p class=\"moved\">") {
            match resolve(page, href) {
                Some((target, fragment))
                    if self.names(&fragment, key) && self.stands(&target, &fragment) =>
                {
                    if target == page {
                        found.answered_on_the_page += 1;
                    } else {
                        found.answered_elsewhere += 1;
                    }
                    found.links_resolved += 1;
                    return Status::Claims(fragment);
                }
                _ => found.faults.push(format!(
                    "{anchor}: its result link {href} names no result of it"
                )),
            }
        } else if exchange.contains("<p class=\"unanswered\">No result was recorded.</p>") {
            found.unanswered += 1;
            return Status::Unanswered;
        } else {
            found.faults.push(format!("{anchor}: no status stated"));
        }
        Status::Faulty
    }

    /// Checks that a result block shown apart from its call links to a call
    /// it names, or says that its call is not identified when it names none.
    fn check_result(&self, transcript: &Transcript, block: &Block, found: &mut Conservation) {
        let anchor = block.anchor();
        let Some((page, html, at)) = self.find(&anchor) else {
            return;
        };
        let article = article_around(html, at);
        if !article.starts_with("<article class=\"record result") {
            return;
        }
        let key = transcript.block_key(block);
        match (href_after(article, "<header"), &key) {
            (Some(href), Some(key)) => {
                let called = resolve(page, href).filter(|(target, fragment)| {
                    self.stands(target, fragment)
                        && transcript.calls.iter().any(|call| {
                            call.anchor() == *fragment && Transcript::call_key(call) == *key
                        })
                });
                if called.is_some() {
                    found.links_resolved += 1;
                } else {
                    found.faults.push(format!(
                        "{anchor}: its call link {href} names no call of it"
                    ));
                }
            }
            (None, None) if article.contains("of a call the transcript does not identify") => {}
            (href, key) => found.faults.push(format!(
                "{anchor}: links to {href:?} while the transcript names {key:?}"
            )),
        }
    }
}

/// How many records the loader accepts from `project`, and how many of them
/// the plan at `budget` places on exactly one page, once.
pub(super) fn records_planned(project: &Path, budget: u64) -> (usize, usize) {
    let Planned {
        heads,
        agents,
        tree,
        pages,
    } = planned(project, budget);
    let mut placed: BTreeMap<(Option<usize>, usize), usize> = BTreeMap::new();
    for page in &pages {
        let sequence = page_sequence(&tree, &agents, page);
        for &node in sequence.get(page.positions.clone()).unwrap_or_default() {
            *placed.entry((page.agent, node)).or_default() += 1;
        }
    }
    let loaded = heads.nodes.len()
        + agents
            .iter()
            .map(|agent| agent.heads.nodes.len())
            .sum::<usize>();
    let once = placed.values().filter(|&&count| count == 1).count();
    (loaded, once)
}

/// A project loaded and planned as a render loads and plans it.
struct Planned {
    heads: Heads,
    agents: Vec<AgentThread>,
    tree: Tree,
    pages: Vec<PagePlan>,
}

fn planned(project: &Path, budget: u64) -> Planned {
    let source = discover(project);
    let heads = Heads::load(&source).expect("load");
    let (mut agents, _) = load_agents(&source.agents).expect("agents");
    attach(&mut agents, &heads);
    let tree = Tree::build(&heads);
    let pages = plan(&heads, &tree, &agents, budget);
    Planned {
        heads,
        agents,
        tree,
        pages,
    }
}

/// How many call and result block anchors the plan dump gives the pages of
/// `project` at `budget`, and how many of them stand exactly once on the page
/// rendered under `output` that the dump names.
pub(super) fn plan_anchors(project: &Path, output: &Path, budget: u64) -> (usize, usize) {
    let Planned {
        heads,
        agents,
        tree,
        pages,
    } = planned(project, budget);
    let mut dump = Vec::new();
    write_dump(&mut dump, &heads, &tree, &agents, &pages).expect("dump");
    let files = html_files(output);
    let anchors = anchors(&files);
    let (mut listed, mut once) = (0, 0);
    for line in String::from_utf8(dump).expect("the dump").lines() {
        let page: Value = serde_json::from_str(line).expect("a page of the dump");
        let path = page["page"].as_str().expect("the page's path");
        for key in ["calls", "results"] {
            for anchor in page[key].as_array().into_iter().flatten() {
                listed += 1;
                let count = anchors
                    .get(path)
                    .and_then(|ids| ids.get(anchor.as_str().unwrap_or_default()));
                once += usize::from(count == Some(&1));
            }
        }
    }
    (listed, once)
}

/// An assistant record making a call of each entry of `ids`, carrying that
/// id or none, each call's input naming its index, the first padded with
/// `pad`.
fn calls(message: &str, ids: &[Option<&str>], pad: &str) -> String {
    let blocks: Vec<String> = ids
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let id = call.map_or_else(String::new, |call| format!(r#""id":"{call}","#));
            let text = if index == 0 { pad } else { "" };
            format!(
                r#"{{"type":"tool_use",{id}"name":"Read","input":{{"text":"input {index}{text}"}}}}"#
            )
        })
        .collect();
    format!(
        r#""type":"assistant","message":{{"id":"{message}","content":[{}]}}"#,
        blocks.join(",")
    )
}

/// A user record holding a result block for each entry of `answers`, naming
/// that call id or none, with its source record when there is one; the first
/// block's text padded with `pad`.
fn results(answers: &[Option<&str>], source: Option<u64>, pad: &str) -> String {
    let blocks: Vec<String> = answers
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let named = call.map_or_else(String::new, |call| format!(r#""tool_use_id":"{call}","#));
            let text = format!(
                "Read {} done.{}",
                call.unwrap_or("?"),
                if index == 0 { pad } else { "" }
            );
            format!(r#"{{"type":"tool_result",{named}"content":"{text}"}}"#)
        })
        .collect();
    let source = source.map_or_else(String::new, |source| {
        format!(r#""sourceToolAssistantUUID":"{}","#, super::id(source))
    });
    format!(
        r#""type":"user",{source}"message":{{"content":[{}]}}"#,
        blocks.join(",")
    )
}

/// The anchor of the call at `block` of record `record`.
fn call_at(record: u64, block: u32) -> String {
    format!("call-{}-{block}", super::id(record))
}

/// The article of the call at `block` of record `record` on `page`.
fn call_article(page: &str, record: u64, block: u32) -> &str {
    let at = page
        .find(&format!(r#"id="{}""#, call_at(record, block)))
        .expect("the call");
    article_around(page, at)
}

/// A session of `lines` rendered at the default budget, with the text of its
/// one page.
fn rendered(
    lines: &[String],
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
) {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    fs::write(project.join("SESSION-ID.jsonl"), lines.concat()).expect("session");
    let output = root.path().join("gamma");
    render(&project, &output, 16_384);
    let page = fs::read_to_string(output.join("p0001.html")).expect("page");
    (root, project, output, page)
}

/// ´test:crate:parallel-calls-answered-by-two-records-show-every-result-once´
#[test]
fn parallel_calls_answered_by_two_records_show_every_result_once() {
    let (_root, project, output, page) = rendered(&[
        line(0x900, None, PROMPT),
        line(
            0x901,
            Some(0x900),
            &calls(
                "MESSAGE-ID-A",
                &[Some("TOOL-A"), Some("TOOL-B"), Some("TOOL-C")],
                "",
            ),
        ),
        line(
            0x902,
            Some(0x901),
            &results(&[Some("TOOL-A"), Some("TOOL-B")], Some(0x901), ""),
        ),
        line(
            0x903,
            Some(0x902),
            &results(&[Some("TOOL-C")], Some(0x901), ""),
        ),
    ]);
    for (call, block, record, answer) in [
        ("TOOL-A", 0, 0x902, 0),
        ("TOOL-B", 1, 0x902, 1),
        ("TOOL-C", 2, 0x903, 0),
    ] {
        assert_eq!(
            page.matches(&format!("Read {call} done.")).count(),
            1,
            "{page}"
        );
        assert!(
            call_article(&page, 0x901, block).contains(&format!(
                r#"<div class="result" id="result-{}-{answer}">"#,
                super::id(record)
            )),
            "{call}: {page}"
        );
    }
    assert!(!page.contains("class=\"moved\"") && !page.contains("class=\"unanswered\""));
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.calls,
            found.results,
            found.answered_beside,
            found.links_resolved
        ),
        (3, 3, 3, 0)
    );
    assert_eq!(records_planned(&project, PAGE_BUDGET), (4, 4));
    assert_eq!(plan_anchors(&project, &output, PAGE_BUDGET), (6, 6));
}

/// ´test:crate:a-parallel-call-without-a-result-takes-no-other-calls-result´
#[test]
fn a_parallel_call_without_a_result_takes_no_other_calls_result() {
    let (_root, project, output, page) = rendered(&[
        line(0x900, None, PROMPT),
        line(
            0x901,
            Some(0x900),
            &calls(
                "MESSAGE-ID-A",
                &[Some("TOOL-A"), Some("TOOL-B"), Some("TOOL-C")],
                "",
            ),
        ),
        line(
            0x902,
            Some(0x901),
            &results(&[Some("TOOL-A"), Some("TOOL-B")], Some(0x901), ""),
        ),
        line(
            0x904,
            Some(0x902),
            &calls("MESSAGE-ID-G", &[Some("TOOL-G"), Some("TOOL-H")], ""),
        ),
        line(
            0x905,
            Some(0x904),
            &results(&[Some("TOOL-G")], Some(0x904), ""),
        ),
        line(0x906, Some(0x905), PROMPT),
        line(
            0x907,
            Some(0x906),
            &results(&[Some("TOOL-H")], Some(0x904), ""),
        ),
    ]);
    assert_eq!(page.matches("No result was recorded.").count(), 1, "{page}");
    assert!(
        call_article(&page, 0x901, 2).contains("No result was recorded."),
        "{page}"
    );
    assert!(
        call_article(&page, 0x904, 1).contains(&format!(
            r##"Its result is shown <a href="#result-{}-0">further down this page</a>."##,
            super::id(0x907)
        )),
        "{page}"
    );
    let at = page
        .find(&format!(r#"id="result-{}-0""#, super::id(0x907)))
        .expect("the later result");
    assert!(
        article_around(&page, at).contains(&format!(
            r##"Result of <a href="#{}">Read</a>"##,
            call_at(0x904, 1)
        )),
        "{page}"
    );
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.answered_beside,
            found.answered_on_the_page,
            found.unanswered,
            found.links_resolved
        ),
        (3, 1, 1, 2)
    );
    assert_eq!(records_planned(&project, PAGE_BUDGET), (7, 7));
    assert_eq!(plan_anchors(&project, &output, PAGE_BUDGET), (9, 9));
}

/// ´test:crate:parallel-calls-split-across-a-page-boundary-link-both-ways´
#[test]
fn parallel_calls_split_across_a_page_boundary_link_both_ways() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    let subagents = project.join("SESSION-ID/subagents");
    fs::create_dir_all(&subagents).expect("subagents");
    fs::write(project.join("SESSION-ID.jsonl"), line(0x900, None, PROMPT)).expect("session");
    let thread = line(0xa00, None, PROMPT)
        + &padded(1_200, 0xa01, 0xa00, |pad| {
            calls(
                "MESSAGE-ID-L",
                &[Some("TOOL-A"), Some("TOOL-B"), Some("TOOL-C")],
                pad,
            )
        })
        + &padded(700, 0xa02, 0xa01, |pad| {
            results(&[Some("TOOL-A"), Some("TOOL-B")], None, pad)
        })
        + &padded(600, 0xa03, 0xa02, |pad| {
            results(&[Some("TOOL-C")], None, pad)
        });
    fs::write(subagents.join("agent-a.jsonl"), thread).expect("thread");
    let output = root.path().join("gamma");
    attempt_paged(&project, &output, 16_384, 1_000).expect("render");
    let first = fs::read_to_string(output.join("agents/a-01.html")).expect("first part");
    let second = fs::read_to_string(output.join("agents/a-02.html")).expect("second part");
    for (call, block, record, answer) in [
        ("TOOL-A", 0, 0xa02, 0),
        ("TOOL-B", 1, 0xa02, 1),
        ("TOOL-C", 2, 0xa03, 0),
    ] {
        assert!(
            call_article(&first, 0xa01, block).contains(&format!(
                r#"Its result is shown <a href="a-02.html#result-{}-{answer}">on part 2</a>."#,
                super::id(record)
            )),
            "{call}: {first}"
        );
        let at = second
            .find(&format!(r#"id="result-{}-{answer}""#, super::id(record)))
            .expect("the result");
        assert!(
            article_around(&second, at).contains(&format!(
                r#"Result of <a href="a-01.html#{}">the call on part 1</a>"#,
                call_at(0xa01, block)
            )),
            "{call}: {second}"
        );
        assert_eq!(second.matches(&format!("Read {call} done.")).count(), 1);
    }
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!((found.answered_elsewhere, found.links_resolved), (3, 6));
    assert_eq!(records_planned(&project, 1_000), (5, 5));
    assert_eq!(plan_anchors(&project, &output, 1_000), (6, 6));
}

/// ´test:crate:a-result-naming-no-call-answers-only-a-sole-call-of-its-source´
#[test]
fn a_result_naming_no_call_answers_only_a_sole_call_of_its_source() {
    let (_root, project, output, page) = rendered(&[
        line(0x900, None, PROMPT),
        line(
            0x901,
            Some(0x900),
            &calls("MESSAGE-ID-D", &[Some("TOOL-D"), Some("TOOL-E")], ""),
        ),
        line(0x902, Some(0x901), &results(&[None], Some(0x901), "")),
        line(
            0x903,
            Some(0x902),
            &calls("MESSAGE-ID-F", &[Some("TOOL-F")], ""),
        ),
        line(0x904, Some(0x903), &results(&[None], Some(0x903), "")),
    ]);
    for block in [0, 1] {
        assert!(
            call_article(&page, 0x901, block).contains("No result was recorded."),
            "{page}"
        );
    }
    let at = page
        .find(&format!(r#"id="result-{}-0""#, super::id(0x902)))
        .expect("the undetermined result");
    assert!(
        article_around(&page, at).contains("Result of a call the transcript does not identify"),
        "{page}"
    );
    assert!(
        call_article(&page, 0x903, 0).contains(&format!(
            r#"<div class="result" id="result-{}-0">"#,
            super::id(0x904)
        )),
        "{page}"
    );
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.unanswered,
            found.answered_beside,
            found.results_without_a_known_call
        ),
        (2, 1, 1)
    );
    assert_eq!(records_planned(&project, PAGE_BUDGET), (5, 5));
    assert_eq!(plan_anchors(&project, &output, PAGE_BUDGET), (5, 5));
}

/// ´test:crate:a-call-without-an-id-beside-a-named-call-is-shown-and-a-bare-result-answers-neither´
#[test]
fn a_call_without_an_id_beside_a_named_call_is_shown_and_a_bare_result_answers_neither() {
    let (_root, project, output, page) = rendered(&[
        line(0x900, None, PROMPT),
        line(
            0x901,
            Some(0x900),
            &calls("MESSAGE-ID-A", &[Some("TOOL-A"), None], ""),
        ),
        line(0x902, Some(0x901), &results(&[None], Some(0x901), "")),
        line(
            0x903,
            Some(0x902),
            &results(&[Some("TOOL-A")], Some(0x901), ""),
        ),
    ]);
    let (named, unnamed) = (call_article(&page, 0x901, 0), call_article(&page, 0x901, 1));
    assert!(
        named.contains("input 0") && !named.contains("input 1"),
        "{page}"
    );
    assert!(
        unnamed.contains("input 1") && !unnamed.contains("input 0"),
        "{page}"
    );
    assert!(unnamed.contains("No result was recorded."), "{page}");
    assert!(
        named.contains(&format!(
            r##"Its result is shown <a href="#result-{}-0">further down this page</a>."##,
            super::id(0x903)
        )),
        "{page}"
    );
    let at = page
        .find(&format!(r#"id="result-{}-0""#, super::id(0x902)))
        .expect("the bare result");
    assert!(
        article_around(&page, at).contains("Result of a call the transcript does not identify"),
        "{page}"
    );
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.calls,
            found.calls_without_an_id,
            found.unanswered,
            found.answered_on_the_page,
            found.results_without_a_known_call
        ),
        (2, 1, 1, 1, 1)
    );
    assert_eq!(plan_anchors(&project, &output, PAGE_BUDGET), (4, 4));
}

/// ´test:crate:two-calls-sharing-an-id-show-their-own-inputs-and-take-the-nearest-result´
#[test]
fn two_calls_sharing_an_id_show_their_own_inputs_and_take_the_nearest_result() {
    let shared = calls("MESSAGE-ID-X", &[Some("TOOL-X"), Some("TOOL-X")], "");
    let once = [
        line(0x900, None, PROMPT),
        line(0x901, Some(0x900), &shared),
        line(0x902, Some(0x901), &results(&[Some("TOOL-X")], None, "")),
    ];
    let (_root, project, output, page) = rendered(&once);
    let (first, second) = (call_article(&page, 0x901, 0), call_article(&page, 0x901, 1));
    assert!(
        first.contains("input 0") && !first.contains("input 1"),
        "{page}"
    );
    assert!(
        second.contains("input 1") && !second.contains("input 0"),
        "{page}"
    );
    for article in [first, second] {
        assert!(
            article.contains("Its call id is not unique in this transcript"),
            "{page}"
        );
    }
    assert!(first.contains("No result was recorded."), "{page}");
    assert!(
        second.contains(&format!(
            r#"<div class="result" id="result-{}-0">"#,
            super::id(0x902)
        )),
        "{page}"
    );
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.ids_carried_by_more_than_one_call,
            found.answered_beside,
            found.unanswered
        ),
        (1, 1, 1)
    );
    let twice = [
        once.as_slice(),
        &[line(
            0x903,
            Some(0x902),
            &results(&[Some("TOOL-X")], None, ""),
        )],
    ]
    .concat();
    let (_root, project, output, page) = rendered(&twice);
    assert!(
        call_article(&page, 0x901, 0).contains(&format!(
            r##"Its result is shown <a href="#result-{}-0">further down this page</a>."##,
            super::id(0x903)
        )),
        "{page}"
    );
    let at = page
        .find(&format!(r#"id="result-{}-0""#, super::id(0x903)))
        .expect("the second result");
    assert!(
        article_around(&page, at).contains(&format!(
            r##"Result of <a href="#{}">Read</a>"##,
            call_at(0x901, 0)
        )),
        "{page}"
    );
    let found = conservation(&project, &output);
    assert_eq!(found.faults, Vec::<String>::new());
    assert_eq!(
        (
            found.answered_beside,
            found.answered_on_the_page,
            found.unanswered
        ),
        (1, 1, 0)
    );
}

/// ´test:crate:an-anchor-with-a-space-and-a-percent-sign-is-found-as-the-script-finds-it´
#[test]
fn an_anchor_with_a_space_and_a_percent_sign_is_found_as_the_script_finds_it() {
    let anchor = "call-A B%";
    let environment = with_templates().expect("templates");
    let html = environment
        .render_str(
            r#"<div id="{{ anchor }}"></div><a href="{{ href }}">call</a>"#,
            minijinja::context! { anchor => anchor, href => view::href("", anchor) },
        )
        .expect("render");
    assert!(SCRIPT.contains("location.hash.slice(1)") && SCRIPT.contains("decodeURIComponent(id)"));
    let href = href_after(&html, "<a").expect("the link");
    assert_eq!(href, "#call-A%20B%25");
    let (page, found) = resolve("p0001.html", href).expect("a fragment");
    assert_eq!((page.as_str(), found.as_str()), ("p0001.html", anchor));
    assert!(html.contains(&format!(r#"<div id="{found}">"#)), "{html}");
    assert_eq!(
        view::href("agents/a-01.html", anchor),
        "agents/a-01.html#call-A%20B%25"
    );
    // Page anchors carry canonical record UUIDs and block indices, never a raw
    // call id or other free-form transcript text; therefore the hostile
    // fixture's anchors contain only ASCII letters, digits and hyphens.
    let root = tempfile::tempdir().expect("temporary directory");
    let output = root.path().join("hostile");
    attempt(
        &fixture_projects().join("-home-alpha-dev-hostile"),
        &output,
        16_384,
    )
    .expect("render");
    for (path, html) in html_files(&output) {
        for id in html
            .split(" id=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
        {
            assert!(
                id.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                "{path}: {id}"
            );
        }
    }
}

/// ´test:crate:a-result-at-the-least-block-limit-keeps-its-structure-and-counts-what-it-omits´
#[test]
fn a_result_at_the_least_block_limit_keeps_its_structure_and_counts_what_it_omits() {
    let root = tempfile::tempdir().expect("temporary directory");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    let pad = "R".repeat(200);
    fs::write(
        project.join("SESSION-ID.jsonl"),
        [
            line(0x900, None, PROMPT),
            line(
                0x901,
                Some(0x900),
                &calls("MESSAGE-ID-A", &[Some("TOOL-A")], ""),
            ),
            line(0x902, Some(0x901), &results(&[Some("TOOL-A")], None, &pad)),
        ]
        .concat(),
    )
    .expect("session");
    let full = "Read TOOL-A done.".len() + pad.len();
    for limit in [MIN_BLOCK_BYTES, 1] {
        let output = root.path().join(format!("limit-{limit}"));
        attempt(&project, &output, limit).expect("render");
        let page = fs::read_to_string(output.join("p0001.html")).expect("page");
        let beside = call_article(&page, 0x901, 0);
        assert!(
            beside.contains(&format!(
                r#"<div class="result" id="result-{}-0">"#,
                super::id(0x902)
            )),
            "{limit}: {page}"
        );
        let kept = &"Read TOOL-A done."[..limit.min(17)];
        assert!(
            beside.contains(&format!(
                r#"{kept}{}<span class="omitted">[{} bytes omitted]</span>"#,
                &pad[..limit.saturating_sub(17)],
                full - limit
            )),
            "{limit}: {page}"
        );
        assert_eq!(conservation(&project, &output).faults, Vec::<String>::new());
    }
}
