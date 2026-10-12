//! The conversation tree built from the first pass's heads.
//!
//! Every node takes its first copy's parent; a compaction boundary without
//! one falls back to its logical parent, then to the tail of the segment its
//! compaction preserved, then to the record written just before it. Nodes are
//! ordered by write order, a record written before its parent held back until
//! the parent is placed, and the connected components are the loop's
//! conversations.

use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::ops::Range;

use crate::head::{Compaction, Kind};
use crate::load::Heads;

/// How a node found its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// Its `parentUuid` names a record the loop holds.
    Parent,
    /// A compaction boundary's `logicalParentUuid`.
    LogicalParent,
    /// A boundary whose logical parent is absent: the tail of the segment its
    /// compaction preserved.
    PreservedTail,
    /// A boundary with neither: the record written just before it in its file.
    PreviousRecord,
    /// No parent: the first record of a conversation.
    Root,
    /// A `parentUuid` naming a record no file holds; the node starts a
    /// conversation of its own.
    Dangling,
}

/// How many nodes each link rule placed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkCounts {
    pub parent: usize,
    pub logical_parent: usize,
    pub preserved_tail: usize,
    pub previous_record: usize,
    pub roots: usize,
    pub dangling: usize,
}

/// The parent of every node under the link rules, how each was found, and the
/// boundaries whose logical parent the loop does not hold.
#[derive(Debug, Default)]
pub struct Links {
    pub parent: Vec<Option<usize>>,
    pub rule: Vec<Link>,
    pub counts: LinkCounts,
    pub missing_logical_parents: usize,
}

/// Applies the link rules to every node.
#[must_use]
pub fn link(heads: &Heads) -> Links {
    let lookup = |id: Option<crate::head::RecordId>| {
        id.and_then(|id| heads.index.get(&id).map(|&node| node as usize))
    };
    let mut links = Links::default();
    for node in &heads.nodes {
        let boundary = node.kind == Kind::Boundary;
        if boundary && lookup(node.logical_parent).is_none() {
            links.missing_logical_parents += 1;
        }
        let (parent, rule) = match lookup(node.parent) {
            Some(parent) => (Some(parent), Link::Parent),
            None if node.parent.is_some() => (None, Link::Dangling),
            None if !boundary => (None, Link::Root),
            None => [
                (node.logical_parent, Link::LogicalParent),
                (node.preserved_tail, Link::PreservedTail),
                (node.previous, Link::PreviousRecord),
            ]
            .into_iter()
            .find_map(|(id, rule)| lookup(id).map(|parent| (Some(parent), rule)))
            .unwrap_or((None, Link::Root)),
        };
        let counter = match rule {
            Link::Parent => &mut links.counts.parent,
            Link::LogicalParent => &mut links.counts.logical_parent,
            Link::PreservedTail => &mut links.counts.preserved_tail,
            Link::PreviousRecord => &mut links.counts.previous_record,
            Link::Root => &mut links.counts.roots,
            Link::Dangling => &mut links.counts.dangling,
        };
        *counter += 1;
        links.parent.push(parent);
        links.rule.push(rule);
    }
    links
}

/// The stable topological order and how many nodes it held back.
///
/// Among the nodes whose parent is placed, the one written first comes next,
/// so the order is write order wherever every parent was written first, and a
/// node written before an ancestor is held back until that ancestor is placed.
#[must_use]
pub fn topological_order(parent: &[Option<usize>]) -> (Vec<usize>, usize) {
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); parent.len()];
    let mut ready = BinaryHeap::new();
    for (node, &up) in parent.iter().enumerate() {
        match up {
            Some(up) if up != node => children[up].push(node),
            _ => ready.push(Reverse(node)),
        }
    }
    let mut placed = vec![false; parent.len()];
    let mut order = Vec::with_capacity(parent.len());
    while let Some(Reverse(node)) = ready.pop() {
        placed[node] = true;
        order.push(node);
        ready.extend(children[node].iter().map(|&child| Reverse(child)));
    }
    // A cycle's members are never ready; place them in write order.
    order.extend((0..parent.len()).filter(|&node| !placed[node]));
    let mut latest_ancestor = vec![0; parent.len()];
    let mut held_back = 0;
    for &node in &order {
        if let Some(up) = parent[node].filter(|&up| up != node) {
            latest_ancestor[node] = latest_ancestor[up].max(up);
        }
        held_back += usize::from(latest_ancestor[node] > node);
    }
    (order, held_back)
}

/// What a session file is to its conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileRole {
    /// On the chain of files that leads to the conversation's latest record.
    Spine,
    /// Records of its own that leave the spine at a fork point.
    Branch { fork: Option<usize> },
    /// No record of its own: a copy of another file's records.
    Copy,
}

/// One session file seen from its conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileView {
    pub file: usize,
    pub role: FileRole,
    pub own: usize,
}

/// How the owner's message came.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerForm {
    Typed,
    Queued,
    Command,
}

/// One tool result block: the record that holds it and its index among that
/// record's result blocks. A record may hold the results of several calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Answer {
    pub record: usize,
    pub block: u32,
}

/// A call's place, which is its identity: the record that makes it and the
/// index of its tool-use block among the record's tool-use blocks. Its id is
/// a property it may have, and two calls may carry one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallPlace {
    pub record: usize,
    pub block: u32,
}

/// A tool call, one tool-use block, with the result block that answers it,
/// if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub call: usize,
    /// The index of the call's block among its record's tool-use blocks.
    pub block: u32,
    pub call_id: Option<Box<str>>,
    pub result: Option<Answer>,
}

impl Exchange {
    /// The exchange's call.
    #[must_use]
    pub const fn place(&self) -> CallPlace {
        CallPlace {
            record: self.call,
            block: self.block,
        }
    }
}

/// How many calls a record makes: one for each of its tool-use blocks.
#[must_use]
pub const fn calls_made(head: &crate::load::Head) -> usize {
    head.calls.len()
}

/// The one call a result block without a call id answers, if any.
///
/// It is the call of the record the result names as its source, when that
/// record makes exactly one call, counting every tool-use block with an id
/// or without; none otherwise, since a record of several calls leaves the
/// block's call undetermined.
#[must_use]
pub fn sole_call(heads: &Heads, result: &crate::load::Head) -> Option<CallPlace> {
    let source = result.source_call.and_then(|id| heads.index.get(&id))?;
    let record = *source as usize;
    (calls_made(&heads.nodes[record]) == 1).then_some(CallPlace { record, block: 0 })
}

/// The nearest call of `open`, the calls carrying one id in the order of the
/// heads, that no block answers yet, taken from it.
fn nearest_open(
    open: &mut Vec<CallPlace>,
    answered: &HashMap<CallPlace, Answer>,
) -> Option<CallPlace> {
    while let Some(call) = open.pop() {
        if !answered.contains_key(&call) {
            return Some(call);
        }
    }
    None
}

/// Which result blocks answer which calls across one set of heads.
///
/// The heads are a loop's or a thread's, taken in their order: a result
/// block naming a call id answers the nearest earlier call carrying that id
/// that no block answers yet, and a block that names none answers the one
/// call of its source record, when that record makes exactly one and no
/// block answers it yet. Only tool result records answer calls. A turn shows
/// a call with the block that answers it when the turn holds both, and a
/// block written in a later turn answers its call all the same.
#[derive(Debug, Default)]
pub struct Answers {
    /// The result block answering each call.
    answer_of: HashMap<CallPlace, Answer>,
    /// The call each answering block answers.
    call_of: HashMap<Answer, CallPlace>,
    /// The calls carrying each id, in the order of the heads.
    carriers: HashMap<Box<str>, Vec<CallPlace>>,
}

impl Answers {
    /// The answers among `heads`.
    #[must_use]
    pub fn of(heads: &Heads) -> Self {
        let mut answers = Self::default();
        let mut open: HashMap<&str, Vec<CallPlace>> = HashMap::new();
        for (node, head) in heads.nodes.iter().enumerate() {
            for (block, id) in head.calls.iter().enumerate() {
                if let Some(id) = id {
                    let call = CallPlace {
                        record: node,
                        block: small(block),
                    };
                    answers.carriers.entry(id.clone()).or_default().push(call);
                    open.entry(&**id).or_default().push(call);
                }
            }
            if head.kind != Kind::ToolResult {
                continue;
            }
            for (block, id) in head.results.iter().enumerate() {
                let answer = Answer {
                    record: node,
                    block: small(block),
                };
                let call = id.as_ref().map_or_else(
                    || sole_call(heads, head).filter(|call| !answers.answer_of.contains_key(call)),
                    |id| {
                        open.get_mut(&**id)
                            .and_then(|calls| nearest_open(calls, &answers.answer_of))
                    },
                );
                if let Some(call) = call {
                    answers.answer_of.insert(call, answer);
                    answers.call_of.insert(answer, call);
                }
            }
        }
        answers
    }

    /// The result block answering `exchange`'s call; none when the
    /// transcript holds no result for it.
    #[must_use]
    pub fn of_exchange(&self, exchange: &Exchange) -> Option<Answer> {
        exchange
            .result
            .or_else(|| self.answer_of.get(&exchange.place()).copied())
    }

    /// The call `answer` answers, when it answers one.
    #[must_use]
    pub fn answered(&self, answer: Answer) -> Option<CallPlace> {
        self.call_of.get(&answer).copied()
    }

    /// The call a result block is shown as the result of: the call it
    /// answers, else, for a block every call of whose id is already
    /// answered, the nearest earlier call carrying that id, and for a block
    /// without an id the one call of its source record; none when the
    /// transcript determines no call for it.
    #[must_use]
    pub fn call_of(&self, heads: &Heads, answer: Answer) -> Option<CallPlace> {
        if let Some(call) = self.answered(answer) {
            return Some(call);
        }
        let head = &heads.nodes[answer.record];
        head.results
            .get(answer.block as usize)?
            .as_ref()
            .map_or_else(
                || sole_call(heads, head),
                |id| {
                    self.carriers
                        .get(id)?
                        .iter()
                        .rev()
                        .find(|call| call.record < answer.record)
                        .copied()
                },
            )
    }

    /// Whether more than one call carries `id`.
    #[must_use]
    pub fn shared(&self, id: &str) -> bool {
        self.carriers.get(id).is_some_and(|calls| calls.len() > 1)
    }
}

/// The calls of one API message, made together.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Group {
    pub exchanges: Vec<Exchange>,
}

/// Tool traffic between two open items: the call groups and the harness
/// traffic folded with them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolRun {
    pub groups: Vec<Group>,
    pub notes: Vec<usize>,
}

/// One thing a turn shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Owner {
        node: usize,
        form: OwnerForm,
    },
    Response {
        nodes: Vec<usize>,
    },
    ToolRun(ToolRun),
    Notes(Vec<usize>),
    Compaction {
        boundary: Option<usize>,
        summary: Option<usize>,
    },
    Peer(usize),
}

/// Where an item shows one of its records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Place {
    /// The record at this index of the item's own records: an owner's or a
    /// peer's message (0), a compaction's boundary (0) or summary (1), or one
    /// of a response's or a stretch of notes' records.
    Node(u32),
    /// The call of a tool run's exchange, by group and exchange.
    Call(u32, u32),
    /// The result of a tool run's exchange, by group and exchange.
    Result(u32, u32),
    /// A tool run's note, by its index among the run's notes.
    Note(u32),
}

/// One record's place in a turn: its position in the sequence, the index of
/// the item that shows it and its place there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub position: usize,
    pub item: u32,
    pub place: Place,
}

/// An index that a turn's items and records keep far below `u32::MAX`, since
/// a loop addresses fewer records than that.
fn small(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

impl Item {
    /// Every record the item shows, with its place.
    #[must_use]
    pub fn places(&self) -> Vec<(Place, usize)> {
        match self {
            Self::Owner { node, .. } | Self::Peer(node) => vec![(Place::Node(0), *node)],
            Self::Response { nodes } | Self::Notes(nodes) => nodes
                .iter()
                .enumerate()
                .map(|(index, &node)| (Place::Node(small(index)), node))
                .collect(),
            Self::ToolRun(run) => {
                let mut places = Vec::new();
                for (group, exchanges) in run.groups.iter().enumerate() {
                    for (index, exchange) in exchanges.exchanges.iter().enumerate() {
                        let (group, index) = (small(group), small(index));
                        places.push((Place::Call(group, index), exchange.call));
                        places.extend(
                            exchange
                                .result
                                .map(|result| (Place::Result(group, index), result.record)),
                        );
                    }
                }
                places.extend(
                    run.notes
                        .iter()
                        .enumerate()
                        .map(|(index, &node)| (Place::Note(small(index)), node)),
                );
                places
            }
            Self::Compaction { boundary, summary } => boundary
                .map(|node| (Place::Node(0), node))
                .into_iter()
                .chain(summary.map(|node| (Place::Node(1), node)))
                .collect(),
        }
    }
}

/// An owner message and everything done in answer to it; a segment's records
/// before its first owner message form a turn without one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Turn {
    /// Positions in the sequence the turn belongs to.
    pub positions: Range<usize>,
    pub owner: Option<usize>,
    pub items: Vec<Item>,
    pub bytes: u64,
    /// Every record's place in the turn's items, in order of position, so a
    /// page that holds part of the turn finds its own records without
    /// scanning the rest.
    pub slots: Vec<Slot>,
}

impl Turn {
    /// The slots of the records at `positions`, in order of position.
    #[must_use]
    pub fn slots_in(&self, positions: &Range<usize>) -> &[Slot] {
        let start = self
            .slots
            .partition_point(|slot| slot.position < positions.start);
        let end = self
            .slots
            .partition_point(|slot| slot.position < positions.end);
        &self.slots[start..end.max(start)]
    }

    /// The exchange each result block at `positions` is paired with in this
    /// turn, by block.
    #[must_use]
    pub fn pairs_in(&self, positions: &Range<usize>) -> HashMap<Answer, &Exchange> {
        self.slots_in(positions)
            .iter()
            .filter_map(|slot| match (slot.place, &self.items[slot.item as usize]) {
                (Place::Result(group, index), Item::ToolRun(run)) => {
                    let exchange = &run.groups[group as usize].exchanges[index as usize];
                    Some((exchange.result?, exchange))
                }
                _ => None,
            })
            .collect()
    }
}

/// A stretch of the main sequence between two compaction boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub positions: Range<usize>,
    pub turns: Range<usize>,
    pub boundary: Option<usize>,
    pub compaction: Option<Compaction>,
}

/// A branch file's own records, in write order, and where they leave the spine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub file: usize,
    pub fork: Option<usize>,
    pub nodes: Vec<usize>,
    pub turns: Vec<Turn>,
}

/// One connected component of a loop's records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub files: Vec<FileView>,
    /// The spine files' records in write order, each after its parent.
    pub main: Vec<usize>,
    pub segments: Vec<Segment>,
    pub turns: Vec<Turn>,
    pub branches: Vec<Branch>,
    pub first_timestamp: Option<i64>,
}

/// The records of a loop grouped into conversations.
#[derive(Debug, Default)]
pub struct Tree {
    pub links: Links,
    pub held_back: usize,
    pub conversations: Vec<Conversation>,
    /// The conversation each node belongs to.
    pub conversation_of: Vec<usize>,
}

impl Tree {
    /// Links the nodes, orders them and splits them into conversations.
    #[must_use]
    pub fn build(heads: &Heads) -> Self {
        let links = link(heads);
        let (order, held_back) = topological_order(&links.parent);
        let mut component = vec![usize::MAX; heads.nodes.len()];
        let mut roots = Vec::new();
        for &node in &order {
            component[node] = match links.parent[node] {
                Some(up) if component[up] != usize::MAX => component[up],
                _ => {
                    roots.push(node);
                    roots.len() - 1
                }
            };
        }
        let mut members: Vec<Vec<usize>> = vec![Vec::new(); roots.len()];
        for &node in &order {
            members[component[node]].push(node);
        }
        let first_timestamp = |nodes: &[usize]| {
            nodes
                .iter()
                .filter_map(|&node| heads.nodes[node].timestamp)
                .min()
        };
        let mut ranked: Vec<usize> = (0..members.len()).collect();
        ranked.sort_by_key(|&index| {
            let timestamp = first_timestamp(&members[index]);
            (
                timestamp.is_none(),
                timestamp,
                members[index].first().copied(),
            )
        });
        let mut conversation_of = vec![0; heads.nodes.len()];
        let mut conversations = Vec::with_capacity(ranked.len());
        let answers = Answers::of(heads);
        for (position, &index) in ranked.iter().enumerate() {
            for &node in &members[index] {
                conversation_of[node] = position;
            }
        }
        for (position, &index) in ranked.iter().enumerate() {
            conversations.push(Conversation::build(
                heads,
                &answers,
                &links.parent,
                &members[index],
                position,
                &conversation_of,
            ));
        }
        Self {
            links,
            held_back,
            conversations,
            conversation_of,
        }
    }
}

fn file_roles(
    heads: &Heads,
    parent: &[Option<usize>],
    nodes: &[usize],
    conversation: usize,
    conversation_of: &[usize],
) -> Vec<FileView> {
    let mut own: HashMap<usize, usize> = HashMap::new();
    let mut attach: HashMap<usize, usize> = HashMap::new();
    for &node in nodes {
        let file = usize::from(heads.nodes[node].loc.file);
        *own.entry(file).or_default() += 1;
        if let Some(up) = parent[node]
            && usize::from(heads.nodes[up].loc.file) != file
            && let Entry::Vacant(slot) = attach.entry(file)
        {
            slot.insert(up);
        }
    }
    let latest = nodes
        .iter()
        .copied()
        .enumerate()
        .max_by_key(|&(position, node)| (heads.nodes[node].timestamp, position))
        .map(|(_, node)| usize::from(heads.nodes[node].loc.file));
    let mut spine = Vec::new();
    let mut file = latest;
    while let Some(current) = file {
        if spine.contains(&current) {
            break;
        }
        spine.push(current);
        file = attach
            .get(&current)
            .map(|&fork| usize::from(heads.nodes[fork].loc.file));
    }
    let mut views = Vec::new();
    for (position, source) in heads.files.iter().enumerate() {
        let count = own.get(&position).copied().unwrap_or(0);
        let belongs = count > 0
            || source
                .scan
                .first_record
                .and_then(|id| heads.index.get(&id))
                .is_some_and(|&node| conversation_of[node as usize] == conversation);
        if !belongs {
            continue;
        }
        let role = if count == 0 {
            FileRole::Copy
        } else if spine.contains(&position) {
            FileRole::Spine
        } else {
            FileRole::Branch {
                fork: attach.get(&position).copied(),
            }
        };
        views.push(FileView {
            file: position,
            role,
            own: count,
        });
    }
    views
}

impl Conversation {
    fn build(
        heads: &Heads,
        answers: &Answers,
        parent: &[Option<usize>],
        nodes: &[usize],
        conversation: usize,
        conversation_of: &[usize],
    ) -> Self {
        let files = file_roles(heads, parent, nodes, conversation, conversation_of);
        let branch_files: Vec<(usize, Option<usize>)> = files
            .iter()
            .filter_map(|view| match view.role {
                FileRole::Branch { fork } => Some((view.file, fork)),
                FileRole::Spine | FileRole::Copy => None,
            })
            .collect();
        let is_branch = |node: usize| {
            let file = usize::from(heads.nodes[node].loc.file);
            branch_files.iter().any(|&(branch, _)| branch == file)
        };
        let main: Vec<usize> = nodes
            .iter()
            .copied()
            .filter(|&node| !is_branch(node))
            .collect();
        let (segments, turns) = segments_and_turns(heads, answers, &main);
        let branches = branch_files
            .into_iter()
            .map(|(file, fork)| {
                let own: Vec<usize> = nodes
                    .iter()
                    .copied()
                    .filter(|&node| usize::from(heads.nodes[node].loc.file) == file)
                    .collect();
                let turns = turns_of(heads, answers, &own, 0..own.len());
                Branch {
                    file,
                    fork,
                    nodes: own,
                    turns,
                }
            })
            .collect();
        Self {
            files,
            first_timestamp: nodes
                .iter()
                .filter_map(|&node| heads.nodes[node].timestamp)
                .min(),
            main,
            segments,
            turns,
            branches,
        }
    }
}

/// Cuts a sequence at each compaction boundary and splits each segment into
/// turns.
#[must_use]
pub fn segments_and_turns(
    heads: &Heads,
    answers: &Answers,
    sequence: &[usize],
) -> (Vec<Segment>, Vec<Turn>) {
    let mut starts: Vec<usize> = sequence
        .iter()
        .enumerate()
        .filter(|&(_, &node)| heads.nodes[node].kind == Kind::Boundary)
        .map(|(position, _)| position)
        .collect();
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    let mut segments = Vec::with_capacity(starts.len());
    let mut turns = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(sequence.len());
        if start == end {
            continue;
        }
        let boundary =
            Some(sequence[start]).filter(|&node| heads.nodes[node].kind == Kind::Boundary);
        let first_turn = turns.len();
        turns.extend(turns_of(heads, answers, sequence, start..end));
        segments.push(Segment {
            positions: start..end,
            turns: first_turn..turns.len(),
            boundary,
            compaction: boundary.and_then(|node| heads.nodes[node].compaction.as_deref().cloned()),
        });
    }
    (segments, turns)
}

/// Splits a stretch of a sequence into turns at each opening owner message.
#[must_use]
pub fn turns_of(
    heads: &Heads,
    answers: &Answers,
    sequence: &[usize],
    positions: Range<usize>,
) -> Vec<Turn> {
    let mut turns = Vec::new();
    let mut start = positions.start;
    for position in positions.clone() {
        if position > start && heads.nodes[sequence[position]].kind.opens_turn() {
            turns.push(TurnBuilder::build(
                heads,
                answers,
                sequence,
                start..position,
            ));
            start = position;
        }
    }
    if start < positions.end {
        turns.push(TurnBuilder::build(
            heads,
            answers,
            sequence,
            start..positions.end,
        ));
    }
    turns
}

/// Builds a turn's items in one pass over its records.
struct TurnBuilder<'h> {
    heads: &'h Heads,
    answers: &'h Answers,
    items: Vec<Item>,
    run: Option<usize>,
    thinking: Vec<usize>,
    /// Where each call of the turn stands among its items: item, group and
    /// exchange.
    calls: HashMap<CallPlace, (usize, usize, usize)>,
}

impl<'h> TurnBuilder<'h> {
    fn build(
        heads: &'h Heads,
        answers: &'h Answers,
        sequence: &[usize],
        positions: Range<usize>,
    ) -> Turn {
        let mut builder = Self {
            heads,
            answers,
            items: Vec::new(),
            run: None,
            thinking: Vec::new(),
            calls: HashMap::new(),
        };
        let mut owner = None;
        let mut bytes = 0;
        for &node in &sequence[positions.clone()] {
            bytes += u64::from(heads.nodes[node].loc.len);
            if owner.is_none() && heads.nodes[node].kind.opens_turn() {
                owner = Some(node);
            }
            builder.push(node);
        }
        builder.flush_thinking();
        let items: Vec<Item> = builder
            .items
            .into_iter()
            .map(|item| match item {
                Item::ToolRun(run)
                    if run.groups.is_empty()
                        && run
                            .notes
                            .iter()
                            .all(|&note| heads.nodes[note].kind != Kind::ToolResult) =>
                {
                    Item::Notes(run.notes)
                }
                other => other,
            })
            .collect();
        let position_of: HashMap<usize, usize> = positions
            .clone()
            .map(|position| (sequence[position], position))
            .collect();
        let mut slots: Vec<Slot> = items
            .iter()
            .enumerate()
            .flat_map(|(index, item)| {
                let position_of = &position_of;
                item.places().into_iter().filter_map(move |(place, node)| {
                    Some(Slot {
                        position: *position_of.get(&node)?,
                        item: small(index),
                        place,
                    })
                })
            })
            .collect();
        slots.sort_by_key(|slot| slot.position);
        Turn {
            positions,
            owner,
            items,
            bytes,
            slots,
        }
    }

    fn message(&self, node: usize) -> Option<&'h str> {
        self.heads.nodes[node].message.as_deref()
    }

    fn open(&mut self, item: Item) {
        self.flush_thinking();
        self.run = None;
        self.items.push(item);
    }

    fn run_mut(&mut self) -> &mut ToolRun {
        let index = *self.run.get_or_insert_with(|| {
            self.items.push(Item::ToolRun(ToolRun::default()));
            self.items.len() - 1
        });
        match &mut self.items[index] {
            Item::ToolRun(run) => run,
            _ => unreachable!("the open run index names a tool run"),
        }
    }

    fn flush_thinking(&mut self) {
        if !self.thinking.is_empty() {
            let thinking = std::mem::take(&mut self.thinking);
            self.run_mut().notes.extend(thinking);
        }
    }

    fn push(&mut self, node: usize) {
        match self.heads.nodes[node].kind {
            Kind::Prompt => self.open(Item::Owner {
                node,
                form: OwnerForm::Typed,
            }),
            Kind::QueuedPrompt => self.open(Item::Owner {
                node,
                form: OwnerForm::Queued,
            }),
            Kind::Command => self.open(Item::Owner {
                node,
                form: OwnerForm::Command,
            }),
            Kind::Peer => self.open(Item::Peer(node)),
            Kind::Boundary => self.open(Item::Compaction {
                boundary: Some(node),
                summary: None,
            }),
            Kind::CompactSummary => self.summary(node),
            Kind::Response => self.response(node),
            Kind::Thinking => self.thinking.push(node),
            Kind::ToolUse => {
                self.flush_thinking();
                self.call(node);
            }
            Kind::ToolResult => {
                self.flush_thinking();
                self.result(node);
            }
            Kind::UserNote | Kind::SystemNote | Kind::Attachment | Kind::Other => {
                self.flush_thinking();
                self.run_mut().notes.push(node);
            }
        }
    }

    fn summary(&mut self, node: usize) {
        if self.run.is_none()
            && let Some(Item::Compaction { summary, .. }) = self.items.last_mut()
            && summary.is_none()
        {
            *summary = Some(node);
            return;
        }
        self.open(Item::Compaction {
            boundary: None,
            summary: Some(node),
        });
    }

    fn response(&mut self, node: usize) {
        let message = self.message(node);
        let continues = self.run.is_none()
            && matches!(self.items.last(), Some(Item::Response { nodes })
                if nodes.last().is_some_and(|&last| message.is_some() && self.message(last) == message));
        let (same, other): (Vec<usize>, Vec<usize>) = std::mem::take(&mut self.thinking)
            .into_iter()
            .partition(|&thinking| message.is_some() && self.message(thinking) == message);
        self.thinking = other;
        if continues {
            if let Some(Item::Response { nodes }) = self.items.last_mut() {
                nodes.extend(same);
                nodes.push(node);
            }
        } else {
            self.flush_thinking();
            self.run = None;
            let mut nodes = same;
            nodes.push(node);
            self.items.push(Item::Response { nodes });
        }
        if !self.heads.nodes[node].calls.is_empty() {
            self.call(node);
        }
    }

    fn call(&mut self, node: usize) {
        let heads = self.heads;
        let message = self.message(node);
        let run = self.run.unwrap_or(usize::MAX);
        let same_group = run != usize::MAX
            && match &self.items[run] {
                Item::ToolRun(tool_run) => tool_run.groups.last().is_some_and(|group| {
                    group.exchanges.last().is_some_and(|exchange| {
                        message.is_some() && self.message(exchange.call) == message
                    })
                }),
                _ => false,
            };
        let tool_run = self.run_mut();
        if !same_group {
            tool_run.groups.push(Group::default());
        }
        let group_index = tool_run.groups.len() - 1;
        let group = &mut tool_run.groups[group_index];
        let mut placed = Vec::new();
        for (block, id) in heads.nodes[node].calls.iter().enumerate() {
            let exchange = Exchange {
                call: node,
                block: small(block),
                call_id: id.clone(),
                result: None,
            };
            placed.push((exchange.place(), group.exchanges.len()));
            group.exchanges.push(exchange);
        }
        let run = self.run.unwrap_or_default();
        for (call, exchange) in placed {
            self.calls.insert(call, (run, group_index, exchange));
        }
    }

    fn exchange_mut(
        &mut self,
        (item, group, exchange): (usize, usize, usize),
    ) -> Option<&mut Exchange> {
        match self.items.get_mut(item) {
            Some(Item::ToolRun(run)) => run.groups.get_mut(group)?.exchanges.get_mut(exchange),
            _ => None,
        }
    }

    /// Places each of a result record's blocks with the call of this turn it
    /// answers, as the loop's pairing decides. A record none of whose blocks
    /// answers a call of this turn is placed as a note of the run, and its
    /// blocks are shown there.
    fn result(&mut self, node: usize) {
        let answers = self.answers;
        let mut paired = false;
        for block in 0..self.heads.nodes[node].results.len() {
            let answer = Answer {
                record: node,
                block: small(block),
            };
            let at = answers
                .answered(answer)
                .and_then(|call| self.calls.get(&call).copied());
            if let Some(exchange) = at.and_then(|at| self.exchange_mut(at)) {
                exchange.result = Some(answer);
                paired = true;
            }
        }
        if !paired {
            self.run_mut().notes.push(node);
        }
    }
}
