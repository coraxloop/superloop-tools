//! Subagent threads: one transcript file per agent under a session's
//! `subagents/` directory, with a meta file beside it naming the tool call
//! that spawned it.
//!
//! A thread's heads are read with the session files and put in order once;
//! its records stay on disk until a page needs them.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;

use serde::Deserialize;

use crate::input::{InputFile, Reached};
use crate::load::{Heads, SourceFile, agent_id, scan_file};
use crate::pool;
use crate::tree::{Answers, Turn, link, topological_order, turns_of};

/// The most bytes an agent's meta file is read to; a larger one is skipped.
pub const MAX_META_BYTES: u64 = 1 << 20;

/// What an agent's meta file records about it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AgentMeta {
    pub agent_type: Option<String>,
    pub description: Option<String>,
    pub tool_use_id: Option<String>,
    pub spawn_depth: Option<u64>,
    pub parent_agent_id: Option<String>,
}

/// Where an agent was spawned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spawn {
    /// By a call on a session's own line: the node of that call.
    Main { node: usize },
    /// By a call in another agent's thread: that agent and the call's node in
    /// its thread.
    Agent { parent: usize, node: usize },
    /// By a call no loaded transcript holds.
    Unattached,
}

/// What became of an agent's meta file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaFile {
    /// Read and parsed.
    Read,
    /// Nothing stands at its name.
    Absent,
    /// Left unread or unused: not a regular file, a symbolic link among them,
    /// larger than [`MAX_META_BYTES`], unreadable, or not a meta record.
    Skipped,
}

/// One subagent's transcript, its meta and where it attaches.
#[derive(Debug)]
pub struct AgentThread {
    pub id: String,
    /// The thread's records, from its one transcript file.
    pub heads: Heads,
    /// Each record's parent within the thread.
    pub parents: Vec<Option<usize>>,
    /// The thread's records in the stable topological order of their links.
    pub order: Vec<usize>,
    /// The turns over that order.
    pub turns: Vec<Turn>,
    pub meta: AgentMeta,
    pub meta_file: MetaFile,
    pub spawn: Spawn,
}

impl AgentThread {
    /// The thread's transcript file.
    #[must_use]
    pub fn file(&self) -> &SourceFile {
        &self.heads.files[0]
    }
}

/// Reads an agent's meta file: reached like its transcript, without following
/// a link, and used only when it is a regular file of at most
/// [`MAX_META_BYTES`] that parses.
fn read_meta(input: &InputFile) -> (AgentMeta, MetaFile) {
    let skipped = (AgentMeta::default(), MetaFile::Skipped);
    let file = match input.open() {
        Ok(Reached::Found(file)) => file,
        Ok(Reached::Absent) => return (AgentMeta::default(), MetaFile::Absent),
        Ok(Reached::Refused) | Err(_) => return skipped,
    };
    let mut bytes = Vec::new();
    let within = file
        .take(MAX_META_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_ok_and(|read| u64::try_from(read).is_ok_and(|read| read <= MAX_META_BYTES));
    match serde_json::from_slice::<AgentMeta>(&bytes) {
        Ok(meta) if within => (meta, MetaFile::Read),
        _ => skipped,
    }
}

fn load_one(input: &InputFile) -> io::Result<Option<AgentThread>> {
    let Some(file) = scan_file(input)? else {
        return Ok(None);
    };
    let id = agent_id(&input.path).unwrap_or(&file.stem).to_owned();
    let (meta, meta_file) = read_meta(&input.beside(&format!("{}.meta.json", file.stem)));
    let heads = Heads::merge(vec![file])?;
    let parents = link(&heads).parent;
    let (order, _) = topological_order(&parents);
    let turns = turns_of(&heads, &Answers::of(&heads), &order, 0..order.len());
    Ok(Some(AgentThread {
        id,
        heads,
        parents,
        order,
        turns,
        meta,
        meta_file,
        spawn: Spawn::Unattached,
    }))
}

/// Reads every agent file's heads and meta on the scan pool, in the order the
/// files are given, with the paths of those no longer regular files reached
/// without a link when they were opened.
///
/// # Errors
///
/// Returns the first error opening or reading an agent file.
pub fn load_agents(inputs: &[InputFile]) -> io::Result<(Vec<AgentThread>, Vec<PathBuf>)> {
    let loaded = pool::run(inputs.len(), pool::SCAN_THREADS, &|index| {
        load_one(&inputs[index])
    });
    let mut threads = Vec::new();
    let mut skipped = Vec::new();
    for (input, thread) in inputs.iter().zip(loaded) {
        match thread? {
            Some(thread) => threads.push(thread),
            None => skipped.push(input.path.clone()),
        }
    }
    Ok((threads, skipped))
}

/// Attaches each agent to the call that spawned it: a call on a session's
/// line, else a call in another agent's thread.
pub fn attach(agents: &mut [AgentThread], heads: &Heads) {
    let mut main_calls: HashMap<&str, usize> = HashMap::new();
    for (node, head) in heads.nodes.iter().enumerate() {
        for call in head.calls.iter().flatten() {
            main_calls.entry(&**call).or_insert(node);
        }
    }
    let mut agent_calls: HashMap<&str, (usize, usize)> = HashMap::new();
    for (index, agent) in agents.iter().enumerate() {
        for (node, line) in agent.heads.nodes.iter().enumerate() {
            for call in line.calls.iter().flatten() {
                agent_calls.entry(&**call).or_insert((index, node));
            }
        }
    }
    let spawns: Vec<Spawn> = agents
        .iter()
        .enumerate()
        .map(|(index, agent)| {
            let Some(call) = agent.meta.tool_use_id.as_deref() else {
                return Spawn::Unattached;
            };
            if let Some(&node) = main_calls.get(call) {
                Spawn::Main { node }
            } else if let Some(&(parent, node)) = agent_calls
                .get(call)
                .filter(|&&(parent, _)| parent != index)
            {
                Spawn::Agent { parent, node }
            } else {
                Spawn::Unattached
            }
        })
        .collect();
    for (agent, spawn) in agents.iter_mut().zip(spawns) {
        agent.spawn = spawn;
    }
}
