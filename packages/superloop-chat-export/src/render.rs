//! Rendering a loop: its pages, its index, its page lists, its assets and the
//! manifest that lets the next run skip what did not change.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use minijinja::Environment;
use serde::Serialize;
use serde_json::Value;

use crate::agents::{AgentThread, Spawn};
use crate::folder::{Fields, Folder, hex};
use crate::head::{Kind, format_timestamp};
use crate::load::{Heads, SourceFile};
use crate::names;
use crate::output::{
    JOURNAL, LoopSummary, MANIFEST, Manifest, PageEntry, ROOT_JOURNAL, ROOT_MANIFEST, ROOT_SCHEMA,
    RootManifest, SCHEMA, SourceEntry, parse_manifest, parse_root_manifest, previous_keys,
};
use crate::owner::{Claims, Holdings, Journal, Owned, claim, commit, journal_claims};
use crate::plan::{PageKind, PagePlan, page_sequence, page_turns};
use crate::pool;
use crate::templates::{SCRIPT, STYLESHEET};
use crate::tree::{Answer, Answers, CallPlace, Item, Place, Tree, Turn};
use crate::view::{self, LINE_CHARS, Link, Links, PageView, PromptView, TurnView, read_bodies};

/// What a loop's render needs besides its tree and plan.
pub struct Settings<'a> {
    pub name: &'a str,
    /// The loop's project directory, which source paths are relative to.
    pub project: &'a Path,
    /// The loop's output folder, opened without following links.
    pub folder: &'a Folder,
    /// The most bytes of one text block a page shows.
    pub limit: usize,
    /// The program and version, recorded in the manifest.
    pub program: &'a str,
}

/// The stylesheet's file name, in each loop's folder and at the output root.
const STYLESHEET_FILE: &str = "chat-export.css";

/// The script's file name in each loop's folder.
const SCRIPT_FILE: &str = "chat-export.js";

/// How many foreign files' names an outcome keeps for the reader.
const FOREIGN_NAMES: usize = 5;

/// What a loop's render did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub pages_rendered: usize,
    pub files_written: usize,
    pub files_unchanged: usize,
    pub files_removed: usize,
    /// The files in the loop's folder that no manifest lists, left in place.
    pub files_foreign: usize,
    /// The first few of those files, by path.
    pub foreign: Vec<String>,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "pages_rendered={} files_written={} files_unchanged={} files_removed={} files_foreign={}",
            self.pages_rendered,
            self.files_written,
            self.files_unchanged,
            self.files_removed,
            self.files_foreign
        )
    }
}

/// Why a loop was not rendered.
#[derive(Debug)]
pub enum RenderError {
    /// A file stands in the loop's folder where the run writes one of its own,
    /// and no manifest lists it: the loop is refused and nothing is written.
    Foreign(String),
    /// A transcript, a template or a file that cannot be read or written.
    Io(io::Error),
}

impl From<io::Error> for RenderError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Foreign(path) => write!(formatter, "{path} is not listed by any manifest"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

/// The files every run writes into a loop's folder beside its pages and its
/// own records.
fn fixed_files(conversations: usize) -> impl Iterator<Item = String> {
    [STYLESHEET_FILE, SCRIPT_FILE, "index.html", "latest.html"]
        .into_iter()
        .map(str::to_owned)
        .chain(
            (0..conversations).map(|number| format!("{}pages.html", conversation_prefix(number))),
        )
}

/// The claims of a folder's manifest and journal, and the length of the
/// journal's complete lines when it reads as the program's own.
fn claims_of(
    folder: &Folder,
    manifest: Option<&[Owned]>,
    journal: &'static str,
) -> io::Result<(Claims, Option<u64>)> {
    let mut claims = Claims::new();
    if let Some(files) = manifest {
        claim(&mut claims, files);
    }
    let journal = folder
        .read(journal)?
        .and_then(|bytes| journal_claims(&bytes));
    if let Some(journal) = &journal {
        claim(&mut claims, &journal.files);
    }
    Ok((claims, journal.map(|journal| journal.complete)))
}

fn other(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

/// A path relative to the page at `from`, both relative to the loop's output
/// directory.
fn relative(from: &str, target: &str) -> String {
    let mut directories: Vec<&str> = from.split('/').collect();
    directories.pop();
    let parts: Vec<&str> = target.split('/').collect();
    let target_directories = &parts[..parts.len() - 1];
    let common = directories
        .iter()
        .zip(target_directories)
        .take_while(|(from, to)| from == to)
        .count();
    "../".repeat(directories.len() - common) + &parts[common..].join("/")
}

/// The span of a page or a conversation to the minute, naming a day once when
/// both ends fall on it.
fn span(first: Option<i64>, last: Option<i64>) -> String {
    match (first, last) {
        (Some(first), Some(last)) if first / 60_000 != last / 60_000 => {
            let (from, to) = (format_timestamp(first), format_timestamp(last));
            match (from.split_once(' '), to.split_once(' ')) {
                (Some((day, _)), Some((same, time))) if day == same => format!("{from} – {time}"),
                _ => format!("{from} – {to}"),
            }
        }
        (Some(time), _) | (None, Some(time)) => format_timestamp(time),
        (None, None) => String::new(),
    }
}

fn conversation_prefix(conversation: usize) -> String {
    if conversation == 0 {
        String::new()
    } else {
        format!("c{}/", conversation + 1)
    }
}

/// Runs `work` over `jobs` on the render pool, keeping job order; every job
/// runs, and the first error is returned after all have.
fn in_parallel<T: Send>(
    jobs: &[usize],
    work: &(impl Fn(usize) -> io::Result<T> + Sync),
) -> io::Result<Vec<T>> {
    pool::run(jobs.len(), pool::RENDER_THREADS, &|index| work(jobs[index]))
        .into_iter()
        .collect()
}

/// Where each page's records live and what each page links to.
struct Places {
    /// The agent page each spawning call links to, with its label.
    agents: HashMap<String, (String, String)>,
    /// The branch pages that fork at each node.
    forks: HashMap<usize, Vec<(String, String)>>,
    /// Each page's previous and next page and its back link.
    previous: Vec<Option<String>>,
    next: Vec<Option<String>>,
    back: Vec<Option<(String, String)>>,
    list: Vec<Option<String>>,
    /// The page holding each record of a conversation's main sequence or
    /// branch.
    page_of: HashMap<usize, usize>,
    /// The page holding each record of each agent thread, by thread.
    agent_page_of: HashMap<(usize, usize), usize>,
}

impl Places {
    /// The page holding the record `node` of `page`'s sequence.
    fn page_holding(&self, page: &PagePlan, node: usize) -> Option<usize> {
        page.agent.map_or_else(
            || self.page_of.get(&node).copied(),
            |agent| self.agent_page_of.get(&(agent, node)).copied(),
        )
    }
}

/// How a page names another page when it links to it: a conversation's page
/// by its number, a branch's or a thread's by its part.
fn page_label(page: &PagePlan) -> String {
    match page.kind {
        PageKind::Main => format!("page {}", page.number),
        PageKind::Branch | PageKind::Agent => format!("part {}", page.number),
    }
}

/// The heads and the parents a page's records are read and linked by: the
/// loop's, or its agent thread's own.
fn page_heads<'a>(
    heads: &'a Heads,
    tree: &'a Tree,
    agents: &'a [AgentThread],
    page: &PagePlan,
) -> (&'a Heads, &'a [Option<usize>]) {
    page.agent
        .map_or((heads, tree.links.parent.as_slice()), |agent| {
            (&agents[agent].heads, agents[agent].parents.as_slice())
        })
}

/// The first page of each agent thread, by the call that spawned it, with the
/// label its link shows.
fn spawn_links(
    agents: &[AgentThread],
    pages: &[PagePlan],
    first_page: &HashMap<usize, usize>,
) -> HashMap<String, (String, String)> {
    agents
        .iter()
        .enumerate()
        .filter_map(|(index, agent)| {
            let call = agent.meta.tool_use_id.clone()?;
            let first = &pages[*first_page.get(&index)?];
            let what = agent
                .meta
                .description
                .clone()
                .or_else(|| agent.meta.agent_type.clone())
                .unwrap_or_else(|| agent.id.clone());
            Some((call, (first.path.clone(), format!("Subagent: {what}"))))
        })
        .collect()
}

/// The link, from the loop's root, to the call carrying the id `call` in the
/// record `node` of `records`, on the page `at` that holds it.
fn spawning_link(records: &Heads, node: usize, call: &str, at: &PagePlan) -> String {
    let head = &records.nodes[node];
    let block = head
        .calls
        .iter()
        .position(|id| id.as_deref() == Some(call))
        .unwrap_or_default();
    let anchor = view::call_anchor(
        &head.id.to_string(),
        u32::try_from(block).unwrap_or(u32::MAX),
    );
    view::href(&at.path, &anchor)
}

fn places(heads: &Heads, tree: &Tree, agents: &[AgentThread], pages: &[PagePlan]) -> Places {
    let mut page_of = HashMap::new();
    let mut agent_page_of = HashMap::new();
    let mut first_agent_page = HashMap::new();
    for (index, page) in pages.iter().enumerate() {
        let nodes = page_sequence(tree, agents, page)
            .get(page.positions.clone())
            .unwrap_or_default();
        if let Some(agent) = page.agent {
            first_agent_page.entry(agent).or_insert(index);
            agent_page_of.extend(nodes.iter().map(|&node| ((agent, node), index)));
        } else {
            page_of.extend(nodes.iter().map(|&node| (node, index)));
        }
    }
    let agent_pages = spawn_links(agents, pages, &first_agent_page);
    let mut forks: HashMap<usize, Vec<(String, String)>> = HashMap::new();
    let mut previous = vec![None; pages.len()];
    let mut next = vec![None; pages.len()];
    let mut back = vec![None; pages.len()];
    let mut list = vec![None; pages.len()];
    for (index, page) in pages.iter().enumerate() {
        let same_sequence = |other: &PagePlan| {
            other.kind == page.kind
                && other.conversation == page.conversation
                && other.branch == page.branch
                && other.agent == page.agent
        };
        if index > 0 && same_sequence(&pages[index - 1]) {
            previous[index] = Some(pages[index - 1].path.clone());
        }
        if pages.get(index + 1).is_some_and(same_sequence) {
            next[index] = Some(pages[index + 1].path.clone());
        }
        if let Some(conversation) = page.conversation {
            list[index] = Some(format!("{}pages.html", conversation_prefix(conversation)));
        }
        match (page.kind, page.conversation, page.branch, page.agent) {
            (PageKind::Branch, Some(conversation), Some(branch), _) => {
                let branch = &tree.conversations[conversation].branches[branch];
                if let Some(fork) = branch.fork {
                    if page.number == 1 {
                        let stem = &heads.files[branch.file].stem;
                        forks.entry(fork).or_default().push((
                            page.path.clone(),
                            format!("A branch continues from here in {stem}"),
                        ));
                    }
                    back[index] = page_of.get(&fork).map(|&at| {
                        (
                            view::href(&pages[at].path, &format!("r-{}", heads.nodes[fork].id)),
                            format!("page {} of the conversation", pages[at].number),
                        )
                    });
                }
            }
            (PageKind::Agent, _, _, Some(agent)) => {
                let agent = &agents[agent];
                let call = agent.meta.tool_use_id.as_deref().unwrap_or_default();
                let spawning = |records: &Heads, node: usize, at: &PagePlan| {
                    spawning_link(records, node, call, at)
                };
                back[index] = match agent.spawn {
                    Spawn::Main { node } => page_of.get(&node).map(|&at| {
                        (
                            spawning(heads, node, &pages[at]),
                            format!("a call on page {}", pages[at].number),
                        )
                    }),
                    Spawn::Agent { parent, node } => {
                        agent_page_of.get(&(parent, node)).map(|&at| {
                            (
                                spawning(&agents[parent].heads, node, &pages[at]),
                                "a call in another subagent's thread".to_owned(),
                            )
                        })
                    }
                    Spawn::Unattached => None,
                };
            }
            _ => {}
        }
    }
    Places {
        agents: agent_pages,
        forks,
        previous,
        next,
        back,
        list,
        page_of,
        agent_page_of,
    }
}

/// The records a page shows and the tree over them.
struct Content<'a> {
    heads: &'a Heads,
    parents: &'a [Option<usize>],
    sequence: &'a [usize],
    turns: &'a [Turn],
    nodes: std::ops::Range<usize>,
}

fn content<'a>(
    heads: &'a Heads,
    tree: &'a Tree,
    agents: &'a [AgentThread],
    page: &PagePlan,
) -> Content<'a> {
    let (heads, parents) = page_heads(heads, tree, agents, page);
    Content {
        heads,
        parents,
        sequence: page_sequence(tree, agents, page),
        turns: page_turns(tree, agents, page),
        nodes: page.positions.clone(),
    }
}

/// A page's navigation links, relative to the page.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Nav {
    pub(crate) loops: String,
    pub(crate) index: String,
    pub(crate) previous: Option<String>,
    pub(crate) next: Option<String>,
    pub(crate) latest: String,
    pub(crate) pages: Option<String>,
    pub(crate) current_page: Option<usize>,
}

/// What a page's template prints besides the views of its records.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Header {
    pub(crate) template: &'static str,
    pub(crate) loop_name: String,
    pub(crate) heading: String,
    pub(crate) span: String,
    pub(crate) assets: String,
    pub(crate) nav: Nav,
    pub(crate) back: Option<Link>,
    pub(crate) agent_type: Option<String>,
    pub(crate) description: Option<String>,
}

/// The links a page takes from outside its own records: its header and the
/// links its records print.
#[derive(Debug)]
struct Frame {
    header: Header,
    /// The links of the subagents the page's calls spawned, by call id.
    agents: BTreeMap<String, Link>,
    /// The branches that fork at the page's records, by record id.
    forks: BTreeMap<String, Vec<Link>>,
    /// Where the result block answering each of the page's calls lies, by
    /// the call's fragment, so each of a record's calls has its own.
    results: BTreeMap<String, Link>,
    /// The call each result block the page shows answers, when that call lies
    /// on another page, by the block's fragment.
    calls: BTreeMap<String, Link>,
    /// The page the page's first turn began on, when the page continues it.
    before: Option<Link>,
    /// The page the page's last turn goes on to, when the page cuts it.
    after: Option<Link>,
}

/// What a page's template receives: its header and the views of its records.
#[derive(Serialize)]
pub(crate) struct PageContext<'a> {
    #[serde(flatten)]
    pub(crate) header: &'a Header,
    pub(crate) prompts_summary: String,
    pub(crate) prompts: Vec<PromptView>,
    pub(crate) turns: Vec<TurnView>,
}

/// The value a page's template renders and the key that decides whether it
/// renders again, made from one value: the key is the SHA-256 digest, stored
/// whole as hex, of that value written as JSON, and the template renders the
/// same value, so the key covers everything the template receives, the
/// nested views of the records included.
///
/// # Errors
///
/// Returns the error of a value that cannot be written as JSON.
pub(crate) fn keyed(context: &impl Serialize) -> io::Result<(String, minijinja::Value)> {
    let value = minijinja::Value::from_serialize(context);
    let mut key = Fields::new("superloop-chat-export page key");
    key.field(&serde_json::to_vec(&value).map_err(other)?);
    Ok((hex(&key.finish()), value))
}

struct Job<'a> {
    environment: &'a Environment<'static>,
    heads: &'a Heads,
    tree: &'a Tree,
    agents: &'a [AgentThread],
    pages: &'a [PagePlan],
    places: &'a Places,
    settings: &'a Settings<'a>,
    /// Which records answer which calls, over the loop's records.
    answers: &'a Answers,
    /// The same over each agent thread's records.
    agent_answers: &'a [Answers],
}

impl Job<'_> {
    /// The frame of the page at `index`: its header and the links its
    /// records print, found from the places of its own records.
    fn frame(&self, index: usize) -> Frame {
        let page = &self.pages[index];
        let shown = content(self.heads, self.tree, self.agents, page);
        let nodes = &shown.sequence[shown.nodes.clone()];
        let here = |target: &str| relative(&page.path, target);
        let link = |(href, label): &(String, String)| Link {
            href: here(href),
            label: label.clone(),
        };
        let id = |node: usize| shown.heads.nodes[node].id.to_string();
        let mut agents = BTreeMap::new();
        let mut forks = BTreeMap::new();
        for &node in nodes {
            for call in shown.heads.nodes[node].calls.iter().flatten() {
                if let Some(spawned) = self.places.agents.get(&**call) {
                    agents.insert(call.to_string(), link(spawned));
                }
            }
            if page.agent.is_none()
                && let Some(branches) = self.places.forks.get(&node)
            {
                forks.insert(id(node), branches.iter().map(link).collect());
            }
        }
        let (results, calls) = self.across(index, &shown);
        let before = shown
            .turns
            .first()
            .filter(|turn| turn.positions.start < page.positions.start)
            .and(self.places.previous[index].as_deref())
            .map(|previous| Link {
                href: here(previous),
                label: "This turn began on the previous page".to_owned(),
            });
        let after = shown
            .turns
            .last()
            .filter(|turn| turn.positions.end > page.positions.end)
            .and(self.places.next[index].as_deref())
            .map(|next| Link {
                href: here(next),
                label: "This turn goes on to the next page".to_owned(),
            });
        Frame {
            header: self.header(index),
            agents,
            forks,
            results,
            calls,
            before,
            after,
        }
    }

    /// Which result blocks answer which calls over the heads of the page at
    /// `index`: the loop's, or its agent thread's.
    fn pairing(&self, index: usize) -> &Answers {
        self.pages[index]
            .agent
            .map_or(self.answers, |agent| &self.agent_answers[agent])
    }

    /// The links between calls and their result blocks that the page at
    /// `index` prints, found from the places of its own records: where the
    /// block answering each of its calls lies, and the call of each result
    /// block it shows when that call lies on another page.
    fn across(
        &self,
        index: usize,
        shown: &Content<'_>,
    ) -> (BTreeMap<String, Link>, BTreeMap<String, Link>) {
        let page = &self.pages[index];
        let answers = self.pairing(index);
        let id = |node: usize| shown.heads.nodes[node].id.to_string();
        let call_key = |call: CallPlace| view::call_anchor(&id(call.record), call.block);
        let result_key = |answer: Answer| view::result_anchor(&id(answer.record), answer.block);
        let position: HashMap<usize, usize> = page
            .positions
            .clone()
            .map(|position| (shown.sequence[position], position))
            .collect();
        let locate = |node: usize, anchor: String, from: usize, what: &str| {
            if let Some(&at) = position.get(&node) {
                let way = if at > from { "down" } else { "up" };
                return Link {
                    href: view::href("", &anchor),
                    label: format!("{what}further {way} this page"),
                };
            }
            self.places.page_holding(page, node).map_or_else(
                || Link {
                    href: String::new(),
                    label: format!("{what}elsewhere"),
                },
                |at| Link {
                    href: view::href(&relative(&page.path, &self.pages[at].path), &anchor),
                    label: format!("{what}on {}", page_label(&self.pages[at])),
                },
            )
        };
        let (mut results, mut calls) = (BTreeMap::new(), BTreeMap::new());
        for turn in shown.turns {
            let pairs = turn.pairs_in(&page.positions);
            for slot in turn.slots_in(&page.positions) {
                let Item::ToolRun(run) = &turn.items[slot.item as usize] else {
                    continue;
                };
                let record = match slot.place {
                    Place::Call(group, index) => {
                        let exchange = &run.groups[group as usize].exchanges[index as usize];
                        if let Some(answer) = answers.of_exchange(exchange) {
                            let target =
                                locate(answer.record, result_key(answer), slot.position, "");
                            results.insert(call_key(exchange.place()), target);
                        }
                        continue;
                    }
                    Place::Result(group, index) => run.groups[group as usize].exchanges
                        [index as usize]
                        .result
                        .map(|answer| answer.record),
                    Place::Note(note) => run.notes.get(note as usize).copied(),
                    Place::Node(_) => None,
                };
                let Some(record) = record else { continue };
                for block in 0..shown.heads.nodes[record].results.len() {
                    let answer = Answer {
                        record,
                        block: u32::try_from(block).unwrap_or(u32::MAX),
                    };
                    let call = pairs
                        .get(&answer)
                        .map(|exchange| exchange.place())
                        .or_else(|| answers.call_of(shown.heads, answer));
                    if let Some(call) = call.filter(|call| !position.contains_key(&call.record)) {
                        let target =
                            locate(call.record, call_key(call), slot.position, "the call ");
                        calls.insert(result_key(answer), target);
                    }
                }
            }
        }
        (results, calls)
    }

    /// What the template of the page at `index` prints besides the views of
    /// its records.
    fn header(&self, index: usize) -> Header {
        let page = &self.pages[index];
        let here = |target: &str| relative(&page.path, target);
        let agent = page.agent.map(|agent| &self.agents[agent]);
        let (template, heading) = self.heading(index);
        Header {
            template,
            loop_name: self.settings.name.to_owned(),
            heading,
            span: span(page.first_timestamp, page.last_timestamp),
            assets: here(""),
            nav: Nav {
                loops: here("../index.html"),
                index: here("index.html"),
                previous: self.places.previous[index].as_deref().map(here),
                next: self.places.next[index].as_deref().map(here),
                latest: here("latest.html"),
                pages: self.places.list[index].as_deref().map(here),
                current_page: (page.kind == PageKind::Main).then_some(page.number),
            },
            back: self.places.back[index].as_ref().map(|(href, label)| Link {
                href: here(href),
                label: label.clone(),
            }),
            agent_type: agent.and_then(|agent| agent.meta.agent_type.clone()),
            description: agent.and_then(|agent| agent.meta.description.clone()),
        }
    }

    /// The page at `index`: its key, and its HTML unless `kept` says the
    /// page on disk was rendered from a value of that key. The key and the
    /// HTML come from one value, the whole of what the template receives.
    ///
    /// # Errors
    ///
    /// Returns the error of a record that cannot be read or a template that
    /// does not render.
    fn page(
        &self,
        index: usize,
        kept: &dyn Fn(&str) -> bool,
    ) -> io::Result<(String, Option<String>)> {
        let page = &self.pages[index];
        let frame = self.frame(index);
        let shown = content(self.heads, self.tree, self.agents, page);
        let nodes = &shown.sequence[shown.nodes.clone()];
        let bodies = read_bodies(shown.heads, nodes, self.settings.limit)?;
        let links = Links {
            agents: &frame.agents,
            forks: &frame.forks,
            parents: shown.parents,
            results: &frame.results,
            calls: &frame.calls,
            pairing: self.pairing(index),
        };
        let mut turns = PageView::new(shown.heads, &bodies, links, self.settings.limit).turns(
            shown.sequence,
            shown.turns,
            &page.positions,
        );
        if let Some(view) = turns.first_mut() {
            view.before.clone_from(&frame.before);
        }
        if let Some(view) = turns.last_mut() {
            view.after.clone_from(&frame.after);
        }
        let prompts = view::prompts(&turns);
        let context = PageContext {
            header: &frame.header,
            prompts_summary: view::counted(prompts.len(), "prompt", "prompts") + " on this page",
            prompts,
            turns,
        };
        let (key, value) = keyed(&context)?;
        if kept(&key) {
            return Ok((key, None));
        }
        let html = self
            .environment
            .get_template(frame.header.template)
            .and_then(|template| template.render(&value))
            .map_err(other)?;
        Ok((key, Some(html)))
    }

    /// The template and heading of a page; a thread of several pages names
    /// the part.
    fn heading(&self, index: usize) -> (&'static str, String) {
        let page = &self.pages[index];
        match (page.kind, page.agent) {
            (PageKind::Agent, Some(agent)) => {
                let kind = self.agents[agent]
                    .meta
                    .agent_type
                    .as_deref()
                    .unwrap_or("thread");
                let parted =
                    self.places.previous[index].is_some() || self.places.next[index].is_some();
                let heading = if parted {
                    format!("Subagent {kind} · part {}", page.number)
                } else {
                    format!("Subagent {kind}")
                };
                ("agent.html", heading)
            }
            (PageKind::Branch, _) => (
                "branch.html",
                format!(
                    "Branch from {} · part {}",
                    page.branch
                        .zip(page.conversation)
                        .map(|(branch, conversation)| {
                            let file = self.tree.conversations[conversation].branches[branch].file;
                            self.heads.files[file].stem.as_str()
                        })
                        .unwrap_or_default(),
                    page.number
                ),
            ),
            _ => (
                "page.html",
                format!(
                    "Conversation {} · page {}",
                    page.conversation.unwrap_or_default() + 1,
                    page.number
                ),
            ),
        }
    }
}

#[derive(Serialize)]
struct Row {
    number: usize,
    href: String,
    span: String,
    compaction: String,
    prompts: usize,
    first_prompt: String,
}

#[derive(Serialize)]
struct BranchRow {
    href: String,
    label: String,
    fork: Link,
}

#[derive(Serialize)]
struct ConversationRows {
    number: usize,
    pages: usize,
    prompts: usize,
    span: String,
    rows: Vec<Row>,
    branches: Vec<BranchRow>,
}

fn owner_text(body: &Value) -> String {
    let content = body
        .pointer("/attachment/prompt")
        .or_else(|| body.pointer("/message/content"));
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .find_map(|block| block.get("text").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned(),
        _ => String::new(),
    }
}

/// The owner messages of the turns that open on `page`, in order; a turn the
/// page continues opened on the page before it.
fn page_owners<'t>(turns: &'t [Turn], page: &'t PagePlan) -> impl Iterator<Item = usize> + 't {
    turns
        .iter()
        .filter(|turn| page.positions.contains(&turn.positions.start))
        .filter_map(|turn| turn.owner)
}

/// The rows of a loop's index and of each conversation's page list, newest
/// first, with hrefs relative to `from`.
fn conversation_rows(
    heads: &Heads,
    tree: &Tree,
    pages: &[PagePlan],
    places: &Places,
    bodies: &HashMap<usize, Value>,
    from: &str,
) -> Vec<ConversationRows> {
    tree.conversations
        .iter()
        .enumerate()
        .map(|(index, conversation)| {
            let main: Vec<&PagePlan> = pages
                .iter()
                .filter(|page| page.kind == PageKind::Main && page.conversation == Some(index))
                .collect();
            let mut rows: Vec<Row> = main
                .iter()
                .map(|page| {
                    let turns = &conversation.turns[page.turns.clone()];
                    let segment = page.segment.map(|segment| &conversation.segments[segment]);
                    let compaction = segment
                        .filter(|segment| segment.positions.start == page.positions.start)
                        .and_then(|segment| segment.compaction.as_ref())
                        .map(|compaction| {
                            let trigger = compaction.trigger.as_deref().unwrap_or("compaction");
                            compaction.pre_tokens.map_or_else(
                                || trigger.to_owned(),
                                |tokens| format!("{trigger}, {tokens} tokens"),
                            )
                        })
                        .unwrap_or_default();
                    let first_prompt = page_owners(turns, page)
                        .next()
                        .and_then(|node| bodies.get(&node))
                        .map(|body| view::first_line(&owner_text(body), LINE_CHARS))
                        .unwrap_or_default();
                    Row {
                        number: page.number,
                        href: relative(from, &page.path),
                        span: span(page.first_timestamp, page.last_timestamp),
                        compaction,
                        prompts: page_owners(turns, page).count(),
                        first_prompt,
                    }
                })
                .collect();
            rows.reverse();
            let branches = conversation
                .branches
                .iter()
                .enumerate()
                .filter_map(|(branch_index, branch)| {
                    let at = pages.iter().position(|page| {
                        page.kind == PageKind::Branch
                            && page.conversation == Some(index)
                            && page.branch == Some(branch_index)
                    })?;
                    let (href, label) = places.back[at].clone().unwrap_or_default();
                    Some(BranchRow {
                        href: relative(from, &pages[at].path),
                        label: format!(
                            "{} ({} records)",
                            heads.files[branch.file].stem,
                            branch.nodes.len()
                        ),
                        fork: Link {
                            href: relative(from, &href),
                            label,
                        },
                    })
                })
                .collect();
            ConversationRows {
                number: index + 1,
                pages: main.len(),
                prompts: conversation
                    .turns
                    .iter()
                    .filter(|turn| turn.owner.is_some())
                    .count(),
                span: span(
                    main.first().and_then(|page| page.first_timestamp),
                    main.iter().filter_map(|page| page.last_timestamp).max(),
                ),
                rows,
                branches,
            }
        })
        .collect()
}

fn modified_ns(file: &SourceFile) -> u64 {
    file.modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn source_entry(project: &Path, file: &SourceFile) -> SourceEntry {
    SourceEntry {
        path: file
            .path
            .strip_prefix(project)
            .unwrap_or(&file.path)
            .to_string_lossy()
            .into_owned(),
        bytes: file.bytes,
        modified_ns: modified_ns(file),
    }
}

/// The manifest of a loop's render: what its pages are rendered from. The
/// pages' keys and the files it records are added once the run knows them.
fn loop_manifest(
    heads: &Heads,
    tree: &Tree,
    agents: &[AgentThread],
    pages: &[PagePlan],
    settings: &Settings<'_>,
) -> Manifest {
    Manifest {
        schema: SCHEMA,
        program: settings.program.to_owned(),
        templates: crate::templates::digest(),
        max_block_bytes: settings.limit as u64,
        summary: LoopSummary {
            title: heads.title().map(str::to_owned),
            conversations: tree.conversations.len(),
            pages: pages.len(),
            last: pages.iter().filter_map(|page| page.last_timestamp).max(),
        },
        sources: heads
            .files
            .iter()
            .chain(agents.iter().map(AgentThread::file))
            .map(|file| source_entry(settings.project, file))
            .collect(),
        pages: Vec::new(),
        files: Vec::new(),
    }
}

/// What a folder holds before a run writes into it, as its records decide.
struct Survey {
    /// The folder's manifest, when it is of this program's schema, with its
    /// bytes.
    previous: Option<(Manifest, Vec<u8>)>,
    /// The length of the complete lines of a journal of this program's form
    /// that stands in the folder.
    journal: Option<u64>,
    holdings: Holdings,
}

/// Reads a loop folder's records and sorts what it holds, refusing the loop
/// when a foreign entry stands where the run writes.
fn survey(folder: &Folder, produced: &BTreeSet<String>) -> Result<Survey, RenderError> {
    let previous = folder
        .read(MANIFEST)?
        .and_then(|bytes| parse_manifest(&bytes).map(|manifest| (manifest, bytes)));
    let (claims, journal) = claims_of(
        folder,
        previous
            .as_ref()
            .map(|(manifest, _)| manifest.files.as_slice()),
        JOURNAL,
    )?;
    let mut records = Vec::new();
    if previous.is_some() {
        records.push(MANIFEST);
    }
    if journal.is_some() {
        records.push(JOURNAL);
    }
    let holdings = Holdings::of(folder, true, &claims, &records, names::generated)?;
    let mut needed = produced.clone();
    needed.extend([MANIFEST.to_owned(), JOURNAL.to_owned()]);
    if let Some(path) = holdings.in_the_way(&needed) {
        return Err(RenderError::Foreign(path));
    }
    Ok(Survey {
        previous,
        journal,
        holdings,
    })
}

/// Every path a loop's run writes, refusing a plan that derives one path
/// twice before anything is written.
fn produced_paths(
    pages: &[PagePlan],
    conversations: usize,
) -> Result<BTreeSet<String>, RenderError> {
    let mut produced = BTreeSet::new();
    for path in pages
        .iter()
        .map(|page| page.path.clone())
        .chain(fixed_files(conversations))
    {
        if let Some(path) = produced.replace(path) {
            return Err(RenderError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("two pages of the plan derive the path {path}"),
            )));
        }
    }
    Ok(produced)
}

/// Renders a loop's pages, index, page lists, latest page and assets into its
/// output folder, and writes its manifest.
///
/// Every file the run writes is first recorded in the folder's journal with
/// the digest of its new bytes, then written through a temporary file; the
/// run removes the files it owns and no longer produces, writes its manifest
/// with every produced file's digest, and removes the journal. A file the
/// program does not own is foreign: it is left in place and counted, and one
/// that stands where the run writes refuses the loop before anything is
/// written.
///
/// # Errors
///
/// Returns [`RenderError::Foreign`] for a foreign entry in the way, and the
/// error of a transcript that cannot be read, a template that does not render,
/// or a file that cannot be written or removed.
pub fn render_loop(
    environment: &Environment<'static>,
    heads: &Heads,
    tree: &Tree,
    agents: &[AgentThread],
    pages: &[PagePlan],
    settings: &Settings<'_>,
) -> Result<Outcome, RenderError> {
    let folder = settings.folder;
    let produced = produced_paths(pages, tree.conversations.len())?;
    let places = places(heads, tree, agents, pages);
    let survey = survey(folder, &produced)?;
    let holdings = &survey.holdings;
    let (answers, agent_answers) = (
        Answers::of(heads),
        agents
            .iter()
            .map(|agent| Answers::of(&agent.heads))
            .collect::<Vec<_>>(),
    );
    let job = Job {
        environment,
        heads,
        tree,
        agents,
        pages,
        places: &places,
        settings,
        answers: &answers,
        agent_answers: &agent_answers,
    };
    let mut manifest = loop_manifest(heads, tree, agents, pages, settings);
    let keys = previous_keys(
        survey.previous.as_ref().map(|(manifest, _)| manifest),
        &manifest,
    );
    let journal = Journal::new(folder, JOURNAL, survey.journal.unwrap_or_default());
    let done = render_pages(&job, &journal, holdings, keys.as_ref())?;
    let mut outcome = Outcome::default();
    let mut digests: HashMap<String, String> = HashMap::new();
    let mut count = |outcome: &mut Outcome, path: &str, (digest, wrote): (String, bool)| {
        if wrote {
            outcome.files_written += 1;
        } else {
            outcome.files_unchanged += 1;
        }
        digests.insert(path.to_owned(), digest);
    };
    let mut entries = Vec::with_capacity(pages.len());
    for (page, (key, committed)) in pages.iter().zip(done) {
        let result = committed.map_or_else(
            || {
                let digest = holdings.owned.get(&page.path).cloned().unwrap_or_default();
                (digest, false)
            },
            |committed| {
                outcome.pages_rendered += 1;
                committed
            },
        );
        count(&mut outcome, &page.path, result);
        entries.push(PageEntry {
            path: page.path.clone(),
            kind: page.kind,
            conversation: page.conversation,
            records: [page.positions.start, page.positions.end],
            key,
        });
    }
    manifest.pages = entries;
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (STYLESHEET_FILE.to_owned(), STYLESHEET.as_bytes().to_vec()),
        (SCRIPT_FILE.to_owned(), SCRIPT.as_bytes().to_vec()),
    ];
    files.extend(index_files(
        environment,
        heads,
        tree,
        agents,
        pages,
        &places,
        settings,
    )?);
    for (path, bytes) in &files {
        let done = commit(folder, &journal, holdings, path, bytes)?;
        count(&mut outcome, path, done);
    }
    manifest.files = produced
        .iter()
        .map(|path| Owned {
            path: path.clone(),
            sha256: digests.get(path).cloned().unwrap_or_default(),
        })
        .collect();
    settle(folder, &survey, &produced, &manifest, &mut outcome)?;
    journal.close(survey.journal.is_some())?;
    outcome.files_foreign = holdings.foreign.len();
    outcome.foreign = holdings
        .foreign
        .iter()
        .take(FOREIGN_NAMES)
        .cloned()
        .collect();
    Ok(outcome)
}

/// A page's key, with its digest and whether the run wrote it when the run
/// rendered it.
type Rendered = (String, Option<(String, bool)>);

/// Each page's key, with the digest of each page the run rendered and whether
/// it wrote it: a page renders unless its file is an owned file and the
/// earlier run's key for it is its key now.
fn render_pages(
    job: &Job<'_>,
    journal: &Journal<'_>,
    holdings: &Holdings,
    keys: Option<&HashMap<&str, &str>>,
) -> io::Result<Vec<Rendered>> {
    let all: Vec<usize> = (0..job.pages.len()).collect();
    in_parallel(&all, &|index| {
        let path = &job.pages[index].path;
        let kept = |key: &str| {
            holdings.owned.contains_key(path)
                && keys.is_some_and(|keys| keys.get(path.as_str()) == Some(&key))
        };
        let (key, html) = job.page(index, &kept)?;
        let committed = html
            .map(|html| {
                commit(
                    job.settings.folder,
                    journal,
                    holdings,
                    path,
                    html.as_bytes(),
                )
            })
            .transpose()?;
        Ok((key, committed))
    })
}

/// Removes the owned files the run no longer produces, then writes the
/// manifest unless the folder already holds exactly its bytes.
fn settle(
    folder: &Folder,
    survey: &Survey,
    produced: &BTreeSet<String>,
    manifest: &Manifest,
    outcome: &mut Outcome,
) -> io::Result<()> {
    let stale: Vec<&String> = survey
        .holdings
        .owned
        .keys()
        .filter(|path| !produced.contains(*path))
        .collect();
    for path in &stale {
        folder.remove(path)?;
    }
    outcome.files_removed = stale.len();
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(other)?;
    bytes.push(b'\n');
    if survey
        .previous
        .as_ref()
        .is_some_and(|(_, old)| *old == bytes)
    {
        outcome.files_unchanged += 1;
    } else {
        folder.write(MANIFEST, &bytes)?;
        outcome.files_written += 1;
    }
    Ok(())
}

/// The first page of each agent thread that no page's call links to, with the
/// label a spawning call's link would show: a thread whose spawning call lies
/// on no page, or that names no call, is reached from the loop's index.
fn unattached(agents: &[AgentThread], pages: &[PagePlan], places: &Places) -> Vec<Link> {
    let mut seen = BTreeSet::new();
    pages
        .iter()
        .enumerate()
        .filter_map(|(index, page)| Some((index, page, page.agent?)))
        .filter(|&(_, _, agent)| seen.insert(agent))
        .filter(|&(index, page, agent)| {
            let linked = agents[agent]
                .meta
                .tool_use_id
                .as_deref()
                .and_then(|call| places.agents.get(call))
                .is_some_and(|(path, _)| *path == page.path);
            !(linked && places.back[index].is_some())
        })
        .map(|(_, page, agent)| {
            let meta = &agents[agent].meta;
            let what = meta
                .description
                .clone()
                .or_else(|| meta.agent_type.clone())
                .unwrap_or_else(|| agents[agent].id.clone());
            Link {
                href: page.path.clone(),
                label: format!("Subagent: {what}"),
            }
        })
        .collect()
}

fn index_files(
    environment: &Environment<'static>,
    heads: &Heads,
    tree: &Tree,
    agents: &[AgentThread],
    pages: &[PagePlan],
    places: &Places,
    settings: &Settings<'_>,
) -> io::Result<Vec<(String, Vec<u8>)>> {
    let firsts: Vec<usize> = pages
        .iter()
        .filter(|page| page.kind == PageKind::Main)
        .filter_map(|page| {
            let conversation = &tree.conversations[page.conversation?];
            page_owners(&conversation.turns[page.turns.clone()], page).next()
        })
        .filter(|&node| matches!(heads.nodes[node].kind, Kind::Prompt | Kind::QueuedPrompt))
        .collect();
    let bodies = read_bodies(heads, &firsts, settings.limit)?;
    let render = |name: &str, context: &minijinja::Value| -> io::Result<Vec<u8>> {
        environment
            .get_template(name)
            .and_then(|template| template.render(context))
            .map(String::into_bytes)
            .map_err(other)
    };
    let mut files = Vec::new();
    let conversations = conversation_rows(heads, tree, pages, places, &bodies.values, "index.html");
    let unattached = unattached(agents, pages, places);
    let index = minijinja::context! {
        loop_name => settings.name,
        title => heads.title(),
        assets => "",
        loops => "../index.html",
        conversations => conversations,
        agents => agents.len(),
        unattached_count => unattached.len(),
        unattached => unattached,
    };
    files.push(("index.html".to_owned(), render("index.html", &index)?));
    for (number, _) in tree.conversations.iter().enumerate() {
        let path = format!("{}pages.html", conversation_prefix(number));
        let mut rows = conversation_rows(heads, tree, pages, places, &bodies.values, &path);
        let conversation = rows.swap_remove(number);
        let list = minijinja::context! {
            loop_name => settings.name,
            assets => relative(&path, ""),
            target => "_top",
            conversation => conversation,
        };
        files.push((path, render("pages.html", &list)?));
    }
    let newest = pages
        .iter()
        .filter(|page| page.kind == PageKind::Main)
        .max_by_key(|page| (page.last_timestamp, page.conversation, page.number))
        .map_or_else(|| "index.html".to_owned(), |page| page.path.clone());
    let latest = minijinja::context! { loop_name => settings.name, target => newest };
    files.push(("latest.html".to_owned(), render("latest.html", &latest)?));
    Ok(files)
}

/// What writing the output root did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootOutcome {
    /// Whether any file of the root was written.
    pub written: bool,
    /// The entries left in place because they stand where the root's files
    /// are written and the program does not own them.
    pub refused: Vec<String>,
}

/// Writes each of the root's files over nothing the program does not own,
/// then the root's manifest over what it wrote, under the same journal rule
/// as a loop's folder.
fn write_root_files(chats: &Folder, files: [(&str, &[u8]); 2]) -> io::Result<RootOutcome> {
    let previous = chats
        .read(ROOT_MANIFEST)?
        .and_then(|bytes| parse_root_manifest(&bytes).map(|manifest| (manifest, bytes)));
    let (claims, journal_complete) = claims_of(
        chats,
        previous
            .as_ref()
            .map(|(manifest, _)| manifest.files.as_slice()),
        ROOT_JOURNAL,
    )?;
    let mut records = Vec::new();
    if previous.is_some() {
        records.push(ROOT_MANIFEST);
    }
    if journal_complete.is_some() {
        records.push(ROOT_JOURNAL);
    }
    let holdings = Holdings::of(chats, false, &claims, &records, |path| {
        files.iter().any(|(name, _)| *name == path)
    })?;
    let mut outcome = RootOutcome::default();
    let own_records = BTreeSet::from([ROOT_MANIFEST.to_owned(), ROOT_JOURNAL.to_owned()]);
    if let Some(path) = holdings.in_the_way(&own_records) {
        outcome.refused.push(path);
        return Ok(outcome);
    }
    let journal = Journal::new(chats, ROOT_JOURNAL, journal_complete.unwrap_or_default());
    let mut kept = Vec::new();
    for (name, bytes) in files {
        if let Some(path) = holdings.in_the_way(&BTreeSet::from([name.to_owned()])) {
            outcome.refused.push(path);
            continue;
        }
        let (digest, wrote) = commit(chats, &journal, &holdings, name, bytes)?;
        outcome.written |= wrote;
        kept.push(Owned {
            path: name.to_owned(),
            sha256: digest,
        });
    }
    let manifest = RootManifest {
        schema: ROOT_SCHEMA,
        files: kept,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(other)?;
    bytes.push(b'\n');
    if previous.as_ref().is_none_or(|(_, old)| *old != bytes) {
        chats.write(ROOT_MANIFEST, &bytes)?;
        outcome.written = true;
    }
    journal.close(journal_complete.is_some())?;
    Ok(outcome)
}

/// Writes the loops index at the root of the output directory, with the
/// stylesheet it shares with the loops' pages.
///
/// The index lists the named loops whose names are segments of the grammar,
/// each from its manifest, and neither file is written over a file the
/// program does not own.
///
/// # Errors
///
/// Returns the error of the index, stylesheet or manifest file that cannot be
/// written.
pub fn write_loops_index(
    environment: &Environment<'static>,
    chats: &Folder,
    loop_names: &[String],
) -> io::Result<RootOutcome> {
    #[derive(Serialize)]
    struct LoopRow {
        name: String,
        href: String,
        latest: String,
        title: String,
        conversations: usize,
        pages: usize,
        last: String,
    }
    let loops: Vec<LoopRow> = loop_names
        .iter()
        .filter(|name| names::is_segment(name))
        .filter_map(|name| {
            let bytes = chats.read(&format!("{name}/{MANIFEST}")).ok()??;
            let manifest = parse_manifest(&bytes)?;
            let segment = names::url_segment(name);
            Some(LoopRow {
                name: name.clone(),
                href: format!("{segment}/index.html"),
                latest: format!("{segment}/latest.html"),
                title: manifest.summary.title.unwrap_or_default(),
                conversations: manifest.summary.conversations,
                pages: manifest.summary.pages,
                last: manifest
                    .summary
                    .last
                    .map(format_timestamp)
                    .unwrap_or_default(),
            })
        })
        .collect();
    let html = environment
        .get_template("loops.html")
        .and_then(|template| template.render(minijinja::context! { loops => loops }))
        .map_err(other)?;
    write_root_files(
        chats,
        [
            (STYLESHEET_FILE, STYLESHEET.as_bytes()),
            ("index.html", html.as_bytes()),
        ],
    )
}
