//! The page plan: every page the render step will write, with the records it
//! covers and a digest of what it was planned from.
//!
//! A conversation's main pages follow its segments; within a segment a page
//! takes records until they reach the budget and closes where the next turn
//! opens, and it never takes a record that would carry it past twice the
//! budget, so a turn too large for one page is cut at a record boundary.
//! Whether a page closes rests only on the records before it and the next one,
//! so appending records only extends the last page or adds pages after it.
//! Each branch file and each subagent thread has pages of its own, by the same
//! rule.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::ops::Range;

use serde::Serialize;

use crate::agents::{AgentThread, Spawn};
use crate::folder::{Fields, hex};
use crate::head::Kind;
use crate::load::{Head, Heads};
use crate::tree::{Answers, Exchange, Item, LinkCounts, Place, Tree, Turn};
use crate::view::{call_anchor, result_anchor};

/// The source bytes after which a page closes at the next turn; a page holds
/// at most twice this, or one record larger than that.
pub const PAGE_BUDGET: u64 = 2 * 1024 * 1024;

/// Which kind of page a plan entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PageKind {
    Main,
    Branch,
    Agent,
}

/// One page the render step will write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagePlan {
    pub kind: PageKind,
    /// The page's path under the loop's output directory.
    pub path: String,
    pub conversation: Option<usize>,
    pub segment: Option<usize>,
    pub branch: Option<usize>,
    pub agent: Option<usize>,
    /// The page's number among its conversation's main pages, its branch's
    /// pages or its agent thread's pages.
    pub number: usize,
    /// The positions of the page's records in its sequence: the
    /// conversation's main sequence, the branch's records or the agent
    /// thread's order.
    pub positions: Range<usize>,
    /// Indices into the sequence's turns of the turns the page's records lie
    /// in; a turn the page cuts is shared with the page beside it.
    pub turns: Range<usize>,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
    pub bytes: u64,
    /// The SHA-256 digest of the page's path and of each record's id,
    /// location and the digest of its bytes, so a record whose bytes change,
    /// whatever their length, changes this digest. The page's key is another
    /// digest, of the value its template renders, which changes when what
    /// the page shows changes.
    pub digest: [u8; 32],
}

/// What one page takes of its sequence: the records at `positions`, lying in
/// the turns at `turns`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub turns: Range<usize>,
    pub positions: Range<usize>,
}

/// Groups a sequence's records into pages.
///
/// `size` gives the source bytes of the record at each position. A page takes
/// records until they reach `budget` and closes where the next turn opens, so
/// a turn stays whole while it fits; it never takes a record that would carry
/// it past `limit`, so a turn that would is cut there, at a record boundary,
/// and a record larger than the limit stands on a page of its own.
#[must_use]
pub fn pack(turns: &[Turn], size: &dyn Fn(usize) -> u64, budget: u64, limit: u64) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut open: Option<Part> = None;
    let mut bytes: u64 = 0;
    for (index, turn) in turns.iter().enumerate() {
        if bytes >= budget
            && let Some(part) = open.take()
        {
            parts.push(part);
            bytes = 0;
        }
        for position in turn.positions.clone() {
            let record = size(position);
            if bytes.saturating_add(record) > limit
                && let Some(part) = open.take()
            {
                parts.push(part);
                bytes = 0;
            }
            let part = open.get_or_insert(Part {
                turns: index..index,
                positions: position..position,
            });
            part.turns.end = index + 1;
            part.positions.end = position + 1;
            bytes = bytes.saturating_add(record);
        }
    }
    parts.extend(open);
    parts
}

/// The source bytes of each record of `sequence`, by position.
fn record_sizes<'a>(heads: &'a Heads, sequence: &'a [usize]) -> impl Fn(usize) -> u64 + 'a {
    move |position| u64::from(heads.nodes[sequence[position]].loc.len)
}

/// The digest of a page's plan: its path, then how many records it holds and,
/// for each in order, its id, its file's stem, the offset and length of its
/// line and the SHA-256 digest of the line's bytes.
fn plan_digest<'h>(
    path: &str,
    records: impl ExactSizeIterator<Item = &'h Head>,
    heads: &Heads,
) -> [u8; 32] {
    let mut digest = Fields::new("superloop-chat-export page plan");
    digest.field(path.as_bytes());
    digest.count(records.len());
    for head in records {
        digest.field(head.id.as_bytes());
        digest.field(heads.files[usize::from(head.loc.file)].stem.as_bytes());
        digest.field(&head.loc.offset.to_le_bytes());
        digest.field(&head.loc.len.to_le_bytes());
        digest.field(&head.digest);
    }
    digest.finish()
}

struct Sequence<'a> {
    kind: PageKind,
    conversation: Option<usize>,
    branch: Option<usize>,
    agent: Option<usize>,
    nodes: &'a [usize],
}

fn node_page(
    heads: &Heads,
    sequence: &Sequence<'_>,
    path: String,
    segment: Option<usize>,
    number: usize,
    Part { turns, positions }: Part,
) -> PagePlan {
    let nodes = &sequence.nodes[positions.clone()];
    let digest = plan_digest(&path, nodes.iter().map(|&node| &heads.nodes[node]), heads);
    let mut bytes = 0;
    let mut first_timestamp = None;
    let mut last_timestamp = None;
    for &node in nodes {
        let head = &heads.nodes[node];
        bytes += u64::from(head.loc.len);
        if let Some(timestamp) = head.timestamp {
            first_timestamp = first_timestamp.or(Some(timestamp));
            last_timestamp =
                Some(last_timestamp.map_or(timestamp, |last: i64| last.max(timestamp)));
        }
    }
    PagePlan {
        kind: sequence.kind,
        path,
        conversation: sequence.conversation,
        segment,
        branch: sequence.branch,
        agent: sequence.agent,
        number,
        positions,
        turns,
        first_timestamp,
        last_timestamp,
        bytes,
        digest,
    }
}

/// An agent thread's pages, `agents/ID-NN.html` as a branch file's are
/// `branches/STEM-NN.html`, packed from the thread's order as a conversation's
/// are; a thread without records has one empty page, so the call that spawned
/// it has a page to link to.
fn agent_pages(index: usize, agent: &AgentThread, budget: u64) -> Vec<PagePlan> {
    let sequence = Sequence {
        kind: PageKind::Agent,
        conversation: None,
        branch: None,
        agent: Some(index),
        nodes: &agent.order,
    };
    let path = |number: usize| format!("agents/{}-{number:02}.html", agent.id);
    let size = record_sizes(&agent.heads, &agent.order);
    let parts = pack(&agent.turns, &size, budget, budget.saturating_mul(2));
    if parts.is_empty() {
        let digest = plan_digest(&path(1), std::iter::empty(), &agent.heads);
        return vec![PagePlan {
            kind: PageKind::Agent,
            path: path(1),
            conversation: None,
            segment: None,
            branch: None,
            agent: Some(index),
            number: 1,
            positions: 0..0,
            turns: 0..0,
            first_timestamp: None,
            last_timestamp: None,
            bytes: 0,
            digest,
        }];
    }
    parts
        .into_iter()
        .enumerate()
        .map(|(number, part)| {
            node_page(
                &agent.heads,
                &sequence,
                path(number + 1),
                None,
                number + 1,
                part,
            )
        })
        .collect()
}

/// Plans every page of a loop.
///
/// Those are each conversation's main pages by segment and part, its branch
/// files' pages, and each subagent thread's pages, each page closing at the
/// first turn past `budget` and holding at most twice it.
#[must_use]
pub fn plan(heads: &Heads, tree: &Tree, agents: &[AgentThread], budget: u64) -> Vec<PagePlan> {
    let limit = budget.saturating_mul(2);
    let mut pages = Vec::new();
    for (index, conversation) in tree.conversations.iter().enumerate() {
        let prefix = if index == 0 {
            String::new()
        } else {
            format!("c{}/", index + 1)
        };
        let main = Sequence {
            kind: PageKind::Main,
            conversation: Some(index),
            branch: None,
            agent: None,
            nodes: &conversation.main,
        };
        let size = record_sizes(heads, &conversation.main);
        let mut number = 0;
        for (segment_index, segment) in conversation.segments.iter().enumerate() {
            let turns = &conversation.turns[segment.turns.clone()];
            for part in pack(turns, &size, budget, limit) {
                number += 1;
                let turns =
                    segment.turns.start + part.turns.start..segment.turns.start + part.turns.end;
                let path = format!("{prefix}p{number:04}.html");
                pages.push(node_page(
                    heads,
                    &main,
                    path,
                    Some(segment_index),
                    number,
                    Part {
                        turns,
                        positions: part.positions,
                    },
                ));
            }
        }
        for (branch_index, branch) in conversation.branches.iter().enumerate() {
            let sequence = Sequence {
                kind: PageKind::Branch,
                conversation: Some(index),
                branch: Some(branch_index),
                agent: None,
                nodes: &branch.nodes,
            };
            let stem = &heads.files[branch.file].stem;
            let size = record_sizes(heads, &branch.nodes);
            let parts = pack(&branch.turns, &size, budget, limit);
            for (number, part) in parts.into_iter().enumerate() {
                let path = format!("{prefix}branches/{stem}-{:02}.html", number + 1);
                pages.push(node_page(heads, &sequence, path, None, number + 1, part));
            }
        }
    }
    for (index, agent) in agents.iter().enumerate() {
        pages.extend(agent_pages(index, agent, budget));
    }
    pages
}

/// The sequence a page's positions index: its conversation's main sequence,
/// its branch's records or its agent thread's order.
#[must_use]
pub fn page_sequence<'a>(
    tree: &'a Tree,
    agents: &'a [AgentThread],
    page: &PagePlan,
) -> &'a [usize] {
    match (page.kind, page.conversation, page.branch, page.agent) {
        (PageKind::Main, Some(conversation), _, _) => &tree.conversations[conversation].main,
        (PageKind::Branch, Some(conversation), Some(branch), _) => {
            &tree.conversations[conversation].branches[branch].nodes
        }
        (PageKind::Agent, _, _, Some(agent)) => &agents[agent].order,
        _ => &[],
    }
}

/// The turns a page shows.
#[must_use]
pub fn page_turns<'a>(tree: &'a Tree, agents: &'a [AgentThread], page: &PagePlan) -> &'a [Turn] {
    let turns: &[Turn] = match (page.kind, page.conversation, page.branch, page.agent) {
        (PageKind::Main, Some(conversation), _, _) => &tree.conversations[conversation].turns,
        (PageKind::Branch, Some(conversation), Some(branch), _) => {
            &tree.conversations[conversation].branches[branch].turns
        }
        (PageKind::Agent, _, _, Some(agent)) => &agents[agent].turns,
        _ => &[],
    };
    turns.get(page.turns.clone()).unwrap_or_default()
}

/// The tree's and the plan's counts, written as `key=value` fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub conversations: usize,
    pub segments: usize,
    pub turns: usize,
    pub prompts: usize,
    pub pages: usize,
    pub branches: usize,
    pub agents: usize,
    pub agents_nested: usize,
    pub agents_unattached: usize,
    pub held_back: usize,
    pub missing_logical_parents: usize,
    pub links: LinkCounts,
    pub exchanges: usize,
    pub groups: usize,
    pub unanswered: usize,
}

fn count_items(summary: &mut Summary, turns: &[Turn], answers: &Answers) {
    for turn in turns {
        summary.turns += 1;
        summary.prompts += usize::from(turn.owner.is_some());
        for item in &turn.items {
            if let Item::ToolRun(run) = item {
                summary.groups += run.groups.len();
                for group in &run.groups {
                    summary.exchanges += group.exchanges.len();
                    summary.unanswered += group
                        .exchanges
                        .iter()
                        .filter(|exchange| answers.of_exchange(exchange).is_none())
                        .count();
                }
            }
        }
    }
}

impl Summary {
    /// Counts a loop's conversations, turns, exchanges, agents and pages; an
    /// exchange is unanswered when no record of the loop answers its call.
    #[must_use]
    pub fn of(heads: &Heads, tree: &Tree, agents: &[AgentThread], pages: &[PagePlan]) -> Self {
        let answers = Answers::of(heads);
        let mut summary = Self {
            conversations: tree.conversations.len(),
            pages: pages.len(),
            agents: agents.len(),
            held_back: tree.held_back,
            missing_logical_parents: tree.links.missing_logical_parents,
            links: tree.links.counts,
            ..Self::default()
        };
        for conversation in &tree.conversations {
            summary.segments += conversation.segments.len();
            summary.branches += conversation.branches.len();
            count_items(&mut summary, &conversation.turns, &answers);
            for branch in &conversation.branches {
                count_items(&mut summary, &branch.turns, &answers);
            }
        }
        for agent in agents {
            match agent.spawn {
                Spawn::Main { .. } => {}
                Spawn::Agent { .. } => summary.agents_nested += 1,
                Spawn::Unattached => summary.agents_unattached += 1,
            }
        }
        summary
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let links = &self.links;
        write!(
            formatter,
            "conversations={} segments={} turns={} prompts={} pages={} branches={} agents={} agents_nested={} agents_unattached={} held_back={} missing_logical_parents={} links=parent:{},logical:{},tail:{},previous:{},root:{},dangling:{} exchanges={} groups={} unanswered={}",
            self.conversations,
            self.segments,
            self.turns,
            self.prompts,
            self.pages,
            self.branches,
            self.agents,
            self.agents_nested,
            self.agents_unattached,
            self.held_back,
            self.missing_logical_parents,
            links.parent,
            links.logical_parent,
            links.preserved_tail,
            links.previous_record,
            links.roots,
            links.dangling,
            self.exchanges,
            self.groups,
            self.unanswered
        )
    }
}

#[derive(Serialize)]
struct DumpPage<'a> {
    page: &'a str,
    kind: PageKind,
    conversation: Option<usize>,
    segment: Option<usize>,
    digest: String,
    bytes: u64,
    nodes: Vec<(String, Option<String>)>,
    agent: Option<&'a str>,
    records: usize,
    spawn: Option<&'static str>,
    /// The page's tool runs and harness-note runs, each one disclosure.
    runs: usize,
    /// The page's responses, each one disclosure.
    responses: usize,
    /// The page's calls that no result block answers.
    unanswered: usize,
    /// The anchor of every call the page holds.
    calls: Vec<String>,
    /// The anchor of every tool result block the page holds.
    results: Vec<String>,
}

/// The calls at `positions`, in order of position.
fn calls_at<'t>(turns: &'t [Turn], positions: &Range<usize>) -> Vec<&'t Exchange> {
    turns
        .iter()
        .flat_map(|turn| {
            turn.slots_in(positions).iter().filter_map(|slot| {
                match (slot.place, &turn.items[slot.item as usize]) {
                    (Place::Call(group, index), Item::ToolRun(run)) => {
                        Some(&run.groups[group as usize].exchanges[index as usize])
                    }
                    _ => None,
                }
            })
        })
        .collect()
}

/// How many runs and responses a page's turns hold.
fn disclosures(turns: &[Turn], positions: &Range<usize>) -> (usize, usize) {
    let (mut runs, mut responses) = (0, 0);
    for turn in turns {
        let mut items: Vec<u32> = turn
            .slots_in(positions)
            .iter()
            .map(|slot| slot.item)
            .collect();
        items.sort_unstable();
        items.dedup();
        for item in items {
            match &turn.items[item as usize] {
                Item::ToolRun(_) | Item::Notes(_) => runs += 1,
                Item::Response { .. } => responses += 1,
                Item::Owner { .. } | Item::Compaction { .. } | Item::Peer(_) => {}
            }
        }
    }
    (runs, responses)
}

/// Writes the plan as JSON lines, for checking the plan outside the program.
///
/// Each page's line carries the id of every record the page shows and its
/// parent's id, an agent page's records linked within its thread.
///
/// # Errors
///
/// Returns the writer's error.
pub fn write_dump(
    out: &mut impl Write,
    heads: &Heads,
    tree: &Tree,
    agents: &[AgentThread],
    pages: &[PagePlan],
) -> io::Result<()> {
    let loop_answers = Answers::of(heads);
    let mut agent_answers: HashMap<usize, Answers> = HashMap::new();
    for page in pages {
        let answers = page.agent.map_or(&loop_answers, |agent| {
            &*agent_answers
                .entry(agent)
                .or_insert_with(|| Answers::of(&agents[agent].heads))
        });
        let exchanges = calls_at(page_turns(tree, agents, page), &page.positions);
        let unanswered = exchanges
            .iter()
            .filter(|exchange| answers.of_exchange(exchange).is_none())
            .count();
        let agent = page.agent.map(|index| &agents[index]);
        let (records, parents) = agent.map_or((heads, tree.links.parent.as_slice()), |agent| {
            (&agent.heads, agent.parents.as_slice())
        });
        let shown = page_sequence(tree, agents, page)
            .get(page.positions.clone())
            .unwrap_or_default();
        let calls = exchanges
            .iter()
            .map(|exchange| {
                call_anchor(&records.nodes[exchange.call].id.to_string(), exchange.block)
            })
            .collect();
        let results = shown
            .iter()
            .filter(|&&node| records.nodes[node].kind == Kind::ToolResult)
            .flat_map(|&node| {
                let id = records.nodes[node].id.to_string();
                (0..records.nodes[node].results.len())
                    .map(move |block| result_anchor(&id, u32::try_from(block).unwrap_or(u32::MAX)))
            })
            .collect();
        let nodes = shown
            .iter()
            .map(|&node| {
                let parent = parents[node].map(|up| records.nodes[up].id.to_string());
                (records.nodes[node].id.to_string(), parent)
            })
            .collect();
        let (runs, responses) = disclosures(page_turns(tree, agents, page), &page.positions);
        let dump = DumpPage {
            runs,
            responses,
            unanswered,
            calls,
            results,
            page: &page.path,
            kind: page.kind,
            conversation: page.conversation,
            segment: page.segment,
            digest: hex(&page.digest),
            bytes: page.bytes,
            nodes,
            agent: agent.map(|agent| agent.id.as_str()),
            records: page.positions.len(),
            spawn: agent.map(|agent| match agent.spawn {
                Spawn::Main { .. } => "main",
                Spawn::Agent { .. } => "agent",
                Spawn::Unattached => "unattached",
            }),
        };
        serde_json::to_writer(&mut *out, &dump)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}
