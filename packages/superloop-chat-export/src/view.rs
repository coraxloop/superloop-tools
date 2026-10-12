//! What a page shows: the records a page covers, read back from their files
//! by their byte spans, turned into plain values the templates print.
//!
//! Every record of a page is anchored exactly once, and every text is cut in
//! Rust to the block limit, with the number of bytes it omitted: a record is
//! read back as a stream with each string cut as it is decoded, so a page
//! holds no more of a string than the limit.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use serde::Serialize;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::head::{
    Kind, format_clock, format_instant, format_timestamp, harness_form, opening_tag,
    parse_timestamp,
};
use crate::load::Heads;
use crate::markdown::{self, Markup};
use crate::tree::{Answer, Answers, CallPlace, Exchange, Item, OwnerForm, Place, ToolRun, Turn};

/// The exchange each result block on a page is paired with in its turn.
type Pairs<'t> = HashMap<Answer, &'t Exchange>;

/// A text cut to the block limit, with the bytes the cut left out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Block {
    pub text: String,
    pub omitted: usize,
}

impl Block {
    /// Cuts `text` to at most `limit` bytes at a character boundary.
    #[must_use]
    pub fn cut(text: &str, limit: usize) -> Self {
        if text.len() <= limit {
            return Self {
                text: text.to_owned(),
                omitted: 0,
            };
        }
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            text: text[..end].to_owned(),
            omitted: text.len() - end,
        }
    }

    /// Cuts `text`, a text of `full` bytes of which reading may already have
    /// dropped some, and counts every byte not shown.
    #[must_use]
    pub fn counted(text: &str, full: usize, limit: usize) -> Self {
        let shown = Self::cut(text, limit);
        Self {
            omitted: full.saturating_sub(shown.text.len()),
            text: shown.text,
        }
    }
}

/// A Markdown text cut to the block limit before it is parsed and written as
/// HTML, with the bytes the cut left out and the plain text of its first
/// block.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Rendered {
    pub html: Markup,
    pub omitted: usize,
    #[serde(skip)]
    pub lead: String,
}

impl Rendered {
    /// Cuts `text` to at most `limit` bytes and renders what is left; a code
    /// fence the cut leaves open closes at the block's end.
    #[must_use]
    pub fn cut(text: &str, limit: usize) -> Self {
        Self::counted(text, text.len(), limit)
    }

    /// Cuts and renders `text`, a text of `full` bytes of which reading may
    /// already have dropped some.
    #[must_use]
    pub fn counted(text: &str, full: usize, limit: usize) -> Self {
        let block = Block::counted(text, full, limit);
        Self {
            html: markdown::render(&block.text),
            omitted: block.omitted,
            lead: markdown::first_block(&block.text),
        }
    }
}

/// When a record was written: the transcript's instant for a `time` element's
/// `datetime`, and the date and time of day a reader scans.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stamp {
    /// The transcript's timestamp, when it is an instant.
    pub instant: Option<String>,
    /// The instant as `YYYY-MM-DD HH:MM:SS UTC`, or the transcript's text
    /// labelled `unparsed timestamp: TEXT` when that is no instant.
    pub shown: String,
}

impl Stamp {
    /// The stamp of a transcript's timestamp text.
    #[must_use]
    pub fn of(text: &str) -> Self {
        parse_timestamp(text).map_or_else(
            || Self {
                instant: None,
                shown: format!("unparsed timestamp: {text}"),
            },
            |millis| Self {
                instant: Some(text.to_owned()),
                shown: format_instant(millis),
            },
        )
    }
}

/// A link a page prints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    pub href: String,
    pub label: String,
}

/// One record of a response: its thinking and its text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PartView {
    pub anchor: Option<String>,
    pub time: Stamp,
    pub thinking: Vec<ThinkingView>,
    pub text: Vec<Rendered>,
}

/// A thinking block with its full size, shown folded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThinkingView {
    pub size: String,
    pub text: Block,
}

/// One of the owner's messages on a page, for the page's list of prompts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PromptView {
    pub href: String,
    pub time: String,
    pub line: String,
}

/// The length of a text's first line a summary or a list shows.
pub const LINE_CHARS: usize = 120;

/// The first non-empty line of `text`, cut to `chars` characters with an
/// ellipsis when cut.
#[must_use]
pub fn first_line(text: &str, chars: usize) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    match line.char_indices().nth(chars) {
        Some((end, _)) => format!("{}…", &line[..end]),
        None => line.to_owned(),
    }
}

/// A count with its noun, singular for one: `1 call`, `3 calls`.
#[must_use]
pub fn counted(count: usize, singular: &str, plural: &str) -> String {
    let mut digits = count.to_string();
    let mut grouped = String::new();
    while digits.len() > 3 {
        let tail = digits.split_off(digits.len() - 3);
        grouped = format!(",{tail}{grouped}");
    }
    format!(
        "{digits}{grouped} {}",
        if count == 1 { singular } else { plural }
    )
}

/// Names in order of first use: up to six, then how many more.
fn capped(names: &[String]) -> String {
    let shown = names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
    match names.len().saturating_sub(6) {
        0 => shown,
        more => format!("{shown} and {more} more"),
    }
}

/// The span of a set of instants: a clock time, a range of clock times on one
/// day, or a range of dates and times.
fn span_label(times: impl Iterator<Item = i64>) -> Option<String> {
    let (mut first, mut last) = (None, None);
    for time in times {
        first = Some(first.map_or(time, |first: i64| first.min(time)));
        last = Some(last.map_or(time, |last: i64| last.max(time)));
    }
    let (first, last) = (first?, last?);
    Some(if first / 1000 == last / 1000 {
        format_clock(first)
    } else if first.div_euclid(86_400_000) == last.div_euclid(86_400_000) {
        format!("{} – {}", format_clock(first), format_clock(last))
    } else {
        format!("{} – {}", format_timestamp(first), format_timestamp(last))
    })
}

/// A tool call with its input and the result that answered it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExchangeView {
    pub anchor: Option<String>,
    /// The call's own anchor, made from its place.
    pub call_anchor: String,
    /// Whether another call of the transcript carries the call's id.
    pub shared: bool,
    pub time: Stamp,
    pub name: String,
    pub input: Block,
    /// The result shown with its call.
    pub result: Option<ResultView>,
    /// Where the call's result is shown instead, when the transcript holds
    /// one that is not shown with the call.
    pub moved: Option<Link>,
    pub agent: Option<Link>,
}

/// One tool result block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResultView {
    /// The block's own anchor, which a call's link to its result names.
    pub id: String,
    /// The record's anchor, on the first of its blocks the page shows.
    pub anchor: Option<String>,
    pub time: Stamp,
    pub text: Block,
    pub error: bool,
}

/// A record of harness traffic, or thinking outside a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NoteView {
    pub anchor: Option<String>,
    pub time: Stamp,
    pub label: String,
    pub text: Block,
}

/// The summary a compaction wrote, rendered from its Markdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SummaryView {
    pub anchor: Option<String>,
    pub time: Stamp,
    pub text: Rendered,
}

/// A compaction boundary with what it records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BoundaryView {
    pub anchor: Option<String>,
    pub time: Stamp,
    pub trigger: String,
    pub pre_tokens: String,
    pub post_tokens: String,
}

/// One item of a turn, tagged by `kind` for the templates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ItemView {
    Owner {
        anchor: Option<String>,
        time: Stamp,
        clock: String,
        form: &'static str,
        text: Block,
    },
    Response {
        summary: String,
        parts: Vec<PartView>,
    },
    Run {
        summary: String,
        entries: Vec<RunEntry>,
    },
    Notes {
        summary: String,
        notes: Vec<NoteView>,
    },
    Compaction {
        boundary: Option<BoundaryView>,
        summary: Option<SummaryView>,
    },
    Peer {
        anchor: Option<String>,
        time: Stamp,
        text: Block,
    },
}

/// One entry of a tool run, in plan order, tagged by `entry`.
///
/// An entry is the calls of one message with the results that answer them, a
/// note, or a result block shown apart from its call, because its parent
/// comes later, its call lies in another turn or on another page, or the
/// transcript determines no call for it, when `call` is none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "entry", rename_all = "lowercase")]
pub enum RunEntry {
    Group {
        exchanges: Vec<ExchangeView>,
    },
    Note {
        note: NoteView,
    },
    Result {
        call: Option<Link>,
        result: ResultView,
    },
}

/// A run's summary line: its calls, the tools in order of first use, its
/// errors, the agent threads it spawned, its notes and its span.
fn run_summary(entries: &[RunEntry], span: Option<String>) -> String {
    let mut names: Vec<String> = Vec::new();
    let (mut calls, mut results, mut errors, mut agents, mut notes) = (0, 0, 0, 0, 0);
    for entry in entries {
        match entry {
            RunEntry::Group { exchanges } => {
                for exchange in exchanges {
                    calls += 1;
                    if !names.contains(&exchange.name) {
                        names.push(exchange.name.clone());
                    }
                    errors +=
                        usize::from(exchange.result.as_ref().is_some_and(|result| result.error));
                    agents += usize::from(exchange.agent.is_some());
                }
            }
            RunEntry::Result { result, .. } => {
                results += 1;
                errors += usize::from(result.error);
            }
            RunEntry::Note { .. } => notes += 1,
        }
    }
    let mut parts = vec![if calls == 0 && results > 0 {
        counted(results, "result", "results")
    } else {
        counted(calls, "call", "calls")
    }];
    if !names.is_empty() {
        parts.push(capped(&names));
    }
    if errors > 0 {
        parts.push(counted(errors, "error", "errors"));
    }
    if agents > 0 {
        parts.push(counted(agents, "agent thread", "agent threads"));
    }
    if notes > 0 {
        parts.push(counted(notes, "note", "notes"));
    }
    parts.extend(span);
    parts.join(" · ")
}

/// The labels of a stretch of notes in order of first use, with attachments of
/// more than one kind counted under one word.
fn note_labels(views: &[NoteView]) -> Vec<String> {
    let attachment = |label: &str| label.starts_with("attachment · ");
    let kinds: HashSet<&str> = views
        .iter()
        .map(|view| view.label.as_str())
        .filter(|label| attachment(label))
        .collect();
    let attachments = views.iter().filter(|view| attachment(&view.label)).count();
    let mut labels: Vec<String> = Vec::new();
    for view in views {
        let label = if kinds.len() > 1 && attachment(&view.label) {
            counted(attachments, "attachment", "attachments")
        } else {
            view.label.clone()
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

/// The owner's messages of a page's turns, for the list under its header.
#[must_use]
pub fn prompts(turns: &[TurnView]) -> Vec<PromptView> {
    turns
        .iter()
        .flat_map(|turn| &turn.items)
        .filter_map(|item| match item {
            ItemView::Owner {
                anchor: Some(anchor),
                clock,
                text,
                ..
            } => Some(PromptView {
                href: href("", anchor),
                time: clock.clone(),
                line: first_line(&text.text, LINE_CHARS),
            }),
            _ => None,
        })
        .collect()
}

/// A turn as a page shows it, with the branches that fork inside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TurnView {
    pub items: Vec<ItemView>,
    pub forks: Vec<Link>,
    /// The page the turn began on, when this page continues it.
    pub before: Option<Link>,
    /// The page the turn goes on to, when this page cuts it.
    pub after: Option<Link>,
}

/// The records of a page, read back with every string and member name longer
/// than the block limit cut to it, and the full byte length of each text the
/// reading cut, by the address of the text it kept.
#[derive(Debug, Default)]
pub struct Bodies {
    pub values: HashMap<usize, Value>,
    cuts: HashMap<usize, usize>,
}

impl Bodies {
    /// The full byte length of a string of these records.
    #[must_use]
    pub fn full(&self, text: &str) -> usize {
        self.cuts
            .get(&text.as_ptr().addr())
            .copied()
            .unwrap_or(text.len())
    }

    /// The bytes the reading cut from the strings and member names under
    /// `value`.
    #[must_use]
    pub fn dropped(&self, value: &Value) -> usize {
        match value {
            Value::String(text) => self.full(text) - text.len(),
            Value::Array(items) => items.iter().map(|item| self.dropped(item)).sum(),
            Value::Object(members) => members
                .iter()
                .map(|(name, member)| self.full(name) - name.len() + self.dropped(member))
                .sum(),
            _ => 0,
        }
    }
}

/// The least block limit the command line admits: a text cut to it keeps
/// its opening words and says how many bytes it omits, and a time or a
/// record id, which are shorter, is never cut.
pub const MIN_BLOCK_BYTES: usize = 64;

/// The most bytes of a member name, or of a `type` or `subtype` value, that a
/// page keeps, whatever the block limit.
///
/// These name and tell apart the content the view looks up, so the block
/// limit cuts only what is displayed, never what finds it.
pub const STRUCTURE_BYTES: usize = 256;

/// Decodes a JSON value with every string longer than `limit` bytes cut to
/// it, and every member name and every `type` or `subtype` value cut only
/// past the larger of `limit` and [`STRUCTURE_BYTES`], recording each cut
/// text's kept address and full length; a name repeated within one object
/// keeps its first member and the others are read through without being
/// kept.
#[derive(Clone, Copy)]
struct Trim<'c> {
    limit: usize,
    cuts: &'c RefCell<Vec<(usize, usize)>>,
}

impl Trim<'_> {
    /// The same decoding with the limit of names and discriminators.
    fn structural(self) -> Self {
        Self {
            limit: self.limit.max(STRUCTURE_BYTES),
            cuts: self.cuts,
        }
    }

    /// `text` cut to the limit at a character boundary, with its full length
    /// when it was cut.
    fn kept(self, text: &str) -> (String, Option<usize>) {
        if text.len() <= self.limit {
            return (text.to_owned(), None);
        }
        let mut end = self.limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        (text[..end].to_owned(), Some(text.len()))
    }

    /// Records that `kept`, which the value holds, was cut from `full` bytes.
    fn record(self, kept: &str, full: Option<usize>) {
        if let Some(full) = full
            && !kept.is_empty()
        {
            self.cuts.borrow_mut().push((kept.as_ptr().addr(), full));
        }
    }

    fn string(self, text: &str) -> Value {
        let (kept, full) = self.kept(text);
        self.record(&kept, full);
        Value::String(kept)
    }
}

/// Decodes a member name cut like a string, its cut recorded only once the
/// object keeps the name.
struct Name<'c>(Trim<'c>);

impl<'de> DeserializeSeed<'de> for Name<'_> {
    type Value = (String, Option<usize>);

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Name<'_> {
    type Value = (String, Option<usize>);

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a member name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(self.0.kept(value))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() <= self.0.limit {
            Ok((value, None))
        } else {
            Ok(self.0.kept(&value))
        }
    }
}

impl<'de> DeserializeSeed<'de> for Trim<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Trim<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(self.string(value))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() <= self.limit {
            Ok(Value::String(value))
        } else {
            Ok(self.string(&value))
        }
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = items.next_element_seed(self)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some((name, full)) = members.next_key_seed(Name(self.structural()))? {
            if object.contains_key(&name) {
                members.next_value::<de::IgnoredAny>()?;
                continue;
            }
            let value = if matches!(name.as_str(), "type" | "subtype") {
                members.next_value_seed(self.structural())?
            } else {
                members.next_value_seed(self)?
            };
            self.record(&name, full);
            object.insert(name, value);
        }
        Ok(Value::Object(object))
    }
}

/// A reader that takes the SHA-256 digest of the bytes it passes on.
struct Digesting<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for Digesting<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

/// Reads the records of `nodes` from their files by their byte spans.
///
/// Each file is reached again the way its scan reached it and checked to be
/// the file the scan read, each record is decoded as a stream with every
/// string and member name cut to `limit` bytes as it is read, and the bytes
/// of its span are checked against the digest the scan took of them.
///
/// # Errors
///
/// Returns the error of a file that cannot be opened or read, and an
/// `InvalidData` error for a file that is no longer the one its scan read or
/// a record whose bytes are no longer those the scan read.
pub fn read_bodies(heads: &Heads, nodes: &[usize], limit: usize) -> io::Result<Bodies> {
    let mut files: HashMap<u16, File> = HashMap::new();
    let mut bodies = Bodies::default();
    for &node in nodes {
        let loc = heads.nodes[node].loc;
        let file = match files.entry(loc.file) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(heads.files[usize::from(loc.file)].reopen()?)
            }
        };
        file.seek(SeekFrom::Start(loc.offset))?;
        let span = Digesting {
            inner: Read::take(&*file, u64::from(loc.len)),
            hasher: Sha256::new(),
        };
        let mut reader = BufReader::with_capacity(8192, span);
        let cuts = RefCell::new(Vec::new());
        let value = {
            let mut decoder = serde_json::Deserializer::from_reader(&mut reader);
            Trim { limit, cuts: &cuts }
                .deserialize(&mut decoder)
                .ok()
                .filter(|_| decoder.end().is_ok())
        };
        io::copy(&mut reader, &mut io::sink())?;
        let read: [u8; 32] = reader.into_inner().hasher.finalize().into();
        if read != heads.nodes[node].digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} changed under the run: a record's bytes are not those its scan read",
                    heads.files[usize::from(loc.file)].path.display()
                ),
            ));
        }
        if let Some(value) = value {
            bodies.cuts.extend(cuts.into_inner());
            bodies.values.insert(node, value);
        } else {
            bodies.values.insert(node, Value::Null);
        }
    }
    Ok(bodies)
}

/// What a page's items link to outside the page.
pub struct Links<'a> {
    /// The page holding each agent's thread, by the call that spawned it.
    pub agents: &'a BTreeMap<String, Link>,
    /// The branches that fork at each of the page's records, by record id.
    pub forks: &'a BTreeMap<String, Vec<Link>>,
    /// Each node's parent.
    pub parents: &'a [Option<usize>],
    /// The link to the result block answering each call this page shows, by
    /// the call's anchor ([`call_anchor`]), used when the block is not shown
    /// with the call.
    pub results: &'a BTreeMap<String, Link>,
    /// The link to the call each result block this page shows apart
    /// answers, when that call lies on another page, by the block's anchor
    /// ([`result_anchor`]).
    pub calls: &'a BTreeMap<String, Link>,
    /// Which result blocks answer which calls across the page's heads.
    pub pairing: &'a Answers,
}

/// A call's anchor, made from its place.
///
/// It is its record's id and the index of its block among the record's
/// tool-use blocks, so every call has its own and the anchor holds nothing
/// the transcript's call id carries.
#[must_use]
pub fn call_anchor(record: &str, block: u32) -> String {
    format!("call-{record}-{block}")
}

/// A link to the element of `anchor` on the page at `page`.
///
/// The page is relative to the linking page, and empty for that page itself.
/// The anchor is an element's `id` as it is, and the link's fragment is the
/// anchor percent-encoded, so the page's script finds the element again by
/// decoding the fragment.
#[must_use]
pub fn href(page: &str, anchor: &str) -> String {
    format!("{page}#{}", crate::names::url_segment(anchor))
}

/// A result block's anchor, made from its place: its record's id and the
/// block's index among the record's result blocks, so every block has its
/// own.
#[must_use]
pub fn result_anchor(record: &str, block: u32) -> String {
    format!("result-{record}-{block}")
}

/// Builds the views of a page's turns.
pub struct PageView<'a> {
    pub heads: &'a Heads,
    pub bodies: &'a Bodies,
    pub links: Links<'a>,
    pub limit: usize,
    anchored: HashSet<usize>,
    /// The result blocks the page has shown, so each is shown once.
    blocks: HashSet<Answer>,
    positions: HashMap<usize, usize>,
    examined: usize,
}

/// A text with the full byte length of what it was read from.
type Measured = (String, usize);

/// Joins measured parts with a blank line between them.
fn joined(parts: Vec<Measured>) -> Measured {
    let full =
        parts.iter().map(|(_, full)| full).sum::<usize>() + 2 * parts.len().saturating_sub(1);
    let text = parts
        .into_iter()
        .map(|(text, _)| text)
        .collect::<Vec<_>>()
        .join("\n\n");
    (text, full)
}

fn text_of(value: &Value, bodies: &Bodies) -> Measured {
    let measured = |text: &str| (text.to_owned(), bodies.full(text));
    match value {
        Value::String(text) => measured(text),
        Value::Array(blocks) => joined(
            blocks
                .iter()
                .filter_map(|block| match block {
                    Value::String(text) => Some(measured(text)),
                    Value::Object(block) => match block.get("type").and_then(Value::as_str) {
                        Some("text") => block.get("text").and_then(Value::as_str).map(measured),
                        Some(other) => {
                            let label = format!("[{other}]");
                            let full = label.len();
                            Some((label, full))
                        }
                        None => None,
                    },
                    _ => None,
                })
                .collect(),
        ),
        Value::Null => (String::new(), 0),
        other => {
            let text = other.to_string();
            let full = text.len() + bodies.dropped(other);
            (text, full)
        }
    }
}

/// The text of `value` as reading kept it, for labels and first lines.
fn plain_text(value: &Value) -> String {
    text_of(value, &Bodies::default()).0
}

fn blocks(body: &Value) -> &[Value] {
    body.pointer("/message/content")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn of_type<'v>(body: &'v Value, kind: &'v str) -> impl Iterator<Item = &'v Value> + 'v {
    blocks(body)
        .iter()
        .filter(move |block| block.get("type").and_then(Value::as_str) == Some(kind))
}

/// The fields of a harness record that say nothing about what happened.
const BOOKKEEPING: [&str; 14] = [
    "cwd",
    "entrypoint",
    "gitBranch",
    "isMeta",
    "isSidechain",
    "parentUuid",
    "sessionId",
    "slug",
    "timestamp",
    "type",
    "userType",
    "uuid",
    "version",
    "agentId",
];

fn note_text(body: &Value, bodies: &Bodies) -> Measured {
    let fields = body
        .get("attachment")
        .filter(|attachment| attachment.is_object())
        .unwrap_or(body);
    for key in [
        "content",
        "text",
        "prompt",
        "stdout",
        "snippet",
        "displayPath",
    ] {
        if let Some(Value::String(text)) = fields.get(key) {
            return (text.clone(), bodies.full(text));
        }
    }
    if let Some(content) = body.pointer("/message/content") {
        let (text, full) = text_of(content, bodies);
        let before = text.len();
        let inside = inside_harness_form(text);
        let full = full - (before - inside.len());
        return (inside, full);
    }
    let shown: serde_json::Map<String, Value> = fields
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(key, _)| !BOOKKEEPING.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let dropped: usize = fields
        .as_object()
        .map(|fields| {
            fields
                .iter()
                .filter(|(key, _)| !BOOKKEEPING.contains(&key.as_str()))
                .map(|(_, value)| bodies.dropped(value))
                .sum()
        })
        .unwrap_or_default();
    let text = serde_json::to_string_pretty(&shown).unwrap_or_default();
    let full = text.len() + dropped;
    (text, full)
}

/// The inside of a text that is one element of a harness form, which its
/// label already names; any other text as it is.
fn inside_harness_form(text: String) -> String {
    let Some(tag) = opening_tag(&text).filter(|_| harness_form(&text).is_some()) else {
        return text;
    };
    let close = format!("</{tag}>");
    let inside = text
        .trim()
        .strip_prefix(&format!("<{tag}>"))
        .and_then(|rest| rest.strip_suffix(&close))
        .filter(|inside| !inside.contains(&close))
        .map(|inside| inside.trim().to_owned());
    inside.unwrap_or(text)
}

/// What a user record the harness classed as a note is: the harness form its
/// text opens with, the origin that sent it, or a message the harness wrote.
fn user_note_label(body: &Value) -> String {
    let text = body
        .pointer("/message/content")
        .map(plain_text)
        .unwrap_or_default();
    if let Some(label) = harness_form(&text) {
        return label.to_owned();
    }
    if let Some(origin) = body
        .pointer("/origin/kind")
        .and_then(Value::as_str)
        .filter(|kind| *kind != "human")
    {
        return origin.replace(['-', '_'], " ");
    }
    if text.trim().is_empty() {
        "user record without text".to_owned()
    } else {
        "harness message".to_owned()
    }
}

/// The text inside the first `tag` element of `text`, trimmed, when there is
/// any.
fn tagged<'t>(text: &'t str, tag: &str) -> Option<&'t str> {
    let open = format!("<{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&format!("</{tag}>"))? + start;
    Some(text[start..end].trim()).filter(|inside| !inside.is_empty())
}

/// A slash command as the owner typed it: its name, then its arguments when
/// there are any, read from the harness's command tags.
fn command_line(text: &str) -> String {
    let name = tagged(text, "command-name").map(str::to_owned).or_else(|| {
        tagged(text, "command-message").map(|message| {
            if message.starts_with('/') {
                message.to_owned()
            } else {
                format!("/{message}")
            }
        })
    });
    match (name, tagged(text, "command-args")) {
        (Some(name), Some(arguments)) => format!("{name} {arguments}"),
        (Some(name), None) => name,
        (None, _) => text.to_owned(),
    }
}

fn note_label(body: &Value) -> String {
    let record = body.get("type").and_then(Value::as_str).unwrap_or("record");
    if record == "user" {
        return user_note_label(body);
    }
    let sub = body
        .pointer("/attachment/type")
        .or_else(|| body.get("subtype"))
        .and_then(Value::as_str);
    sub.map_or_else(|| record.to_owned(), |sub| format!("{record} · {sub}"))
}

impl<'a> PageView<'a> {
    /// A view over one page's records.
    #[must_use]
    pub fn new(heads: &'a Heads, bodies: &'a Bodies, links: Links<'a>, limit: usize) -> Self {
        Self {
            heads,
            bodies,
            links,
            limit,
            anchored: HashSet::new(),
            blocks: HashSet::new(),
            positions: HashMap::new(),
            examined: 0,
        }
    }

    fn body(&self, node: usize) -> &'a Value {
        self.bodies.values.get(&node).unwrap_or(&Value::Null)
    }

    /// The node's anchor the first time the page shows it, and none after.
    fn anchor(&mut self, node: usize) -> Option<String> {
        self.anchored
            .insert(node)
            .then(|| format!("r-{}", self.heads.nodes[node].id))
    }

    fn time(&self, node: usize) -> Stamp {
        Stamp::of(
            self.body(node)
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    }

    fn cut(&self, (text, full): Measured) -> Block {
        Block::counted(&text, full, self.limit)
    }

    fn text(&self, value: Option<&Value>) -> Measured {
        text_of(value.unwrap_or(&Value::Null), self.bodies)
    }

    fn note(&mut self, node: usize) -> NoteView {
        let body = self.body(node);
        let (label, text) = if self.heads.nodes[node].kind == Kind::Thinking {
            let thinking = of_type(body, "thinking")
                .filter_map(|block| block.get("thinking").and_then(Value::as_str))
                .map(|text| (text.to_owned(), self.bodies.full(text)))
                .collect();
            ("thinking".to_owned(), joined(thinking))
        } else {
            (note_label(body), note_text(body, self.bodies))
        };
        NoteView {
            anchor: self.anchor(node),
            time: self.time(node),
            label,
            text: self.cut(text),
        }
    }

    fn owner(&mut self, node: usize, form: OwnerForm) -> ItemView {
        let body = self.body(node);
        let (form, text) = match form {
            OwnerForm::Typed => ("typed", self.text(body.pointer("/message/content"))),
            OwnerForm::Command => {
                let command = command_line(&self.text(body.pointer("/message/content")).0);
                let full = command.len();
                ("command", (command, full))
            }
            OwnerForm::Queued => ("queued", self.text(body.pointer("/attachment/prompt"))),
        };
        ItemView::Owner {
            anchor: self.anchor(node),
            time: self.time(node),
            clock: self.heads.nodes[node]
                .timestamp
                .map(format_clock)
                .unwrap_or_default(),
            form,
            text: self.cut(text),
        }
    }

    fn part(&mut self, node: usize) -> PartView {
        let body = self.body(node);
        let thinking = of_type(body, "thinking")
            .filter_map(|block| block.get("thinking").and_then(Value::as_str))
            .map(|text| {
                let full = self.bodies.full(text);
                ThinkingView {
                    size: counted(full, "byte", "bytes"),
                    text: Block::counted(text, full, self.limit),
                }
            })
            .collect();
        let mut text: Vec<Rendered> = of_type(body, "text")
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .map(|text| Rendered::counted(text, self.bodies.full(text), self.limit))
            .collect();
        if let Some(Value::String(plain)) = body.pointer("/message/content") {
            text.push(Rendered::counted(
                plain,
                self.bodies.full(plain),
                self.limit,
            ));
        }
        PartView {
            anchor: self.anchor(node),
            time: self.time(node),
            thinking,
            text,
        }
    }

    /// The call's own tool-use block, found by its place.
    fn call_block(&self, call: CallPlace) -> Option<&'a Value> {
        of_type(self.body(call.record), "tool_use").nth(call.block as usize)
    }

    fn call_name(&self, call: CallPlace) -> String {
        self.call_block(call)
            .and_then(|block| block.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("tool")
            .to_owned()
    }

    /// A call's anchor.
    fn call_anchor(&self, call: CallPlace) -> String {
        call_anchor(&self.heads.nodes[call.record].id.to_string(), call.block)
    }

    /// A result block's anchor.
    fn result_anchor(&self, answer: Answer) -> String {
        result_anchor(
            &self.heads.nodes[answer.record].id.to_string(),
            answer.block,
        )
    }

    /// The view of one result block, which the page now shows.
    fn result_view(&mut self, answer: Answer) -> ResultView {
        self.blocks.insert(answer);
        let block = of_type(self.body(answer.record), "tool_result").nth(answer.block as usize);
        let text = self.text(block.and_then(|block| block.get("content")));
        let error = block
            .and_then(|block| block.get("is_error"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ResultView {
            id: self.result_anchor(answer),
            anchor: self.anchor(answer.record),
            time: self.time(answer.record),
            text: self.cut(text),
            error,
        }
    }

    /// The call a result block answers: the exchange its turn paired it
    /// with, else the call the transcript determines for it across the
    /// heads; none when it determines none.
    fn call_of(&self, pairs: &Pairs<'_>, answer: Answer) -> Option<CallPlace> {
        pairs
            .get(&answer)
            .map(|exchange| exchange.place())
            .or_else(|| self.links.pairing.call_of(self.heads, answer))
    }

    /// The link from a result block shown apart to its call: to the call's
    /// anchor on this page, or on the page that holds it; none when the
    /// transcript determines no call for the block.
    fn call_link(&self, pairs: &Pairs<'_>, answer: Answer) -> Option<Link> {
        let call = self.call_of(pairs, answer)?;
        if self.on_page(call.record) {
            return Some(Link {
                href: href("", &self.call_anchor(call)),
                label: self.call_name(call),
            });
        }
        let found = self.links.calls.get(&self.result_anchor(answer)).cloned();
        Some(found.unwrap_or_else(|| Link {
            href: String::new(),
            label: "its call".to_owned(),
        }))
    }

    /// The result blocks of `record` the page has not shown yet, each shown
    /// apart from its call with a link to it, in the order of the blocks.
    fn result_entries(&mut self, record: usize, pairs: &Pairs<'_>) -> Vec<RunEntry> {
        (0..self.heads.nodes[record].results.len())
            .map(|block| Answer {
                record,
                block: u32::try_from(block).unwrap_or(u32::MAX),
            })
            .filter(|answer| !self.blocks.contains(answer))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|answer| RunEntry::Result {
                call: self.call_link(pairs, answer),
                result: self.result_view(answer),
            })
            .collect()
    }

    /// The view of a call, with the result block `joined` shown beneath it,
    /// or else where its result lies, or that the transcript holds none.
    fn exchange(&mut self, exchange: &Exchange, joined: Option<Answer>) -> ExchangeView {
        let call = exchange.place();
        let input = self
            .call_block(call)
            .and_then(|block| block.get("input"))
            .map(|input| {
                let text = serde_json::to_string_pretty(input).unwrap_or_default();
                let full = text.len() + self.bodies.dropped(input);
                (text, full)
            })
            .unwrap_or_default();
        let id = exchange.call_id.as_deref();
        let agent = id.and_then(|id| self.links.agents.get(id)).cloned();
        let moved = joined
            .is_none()
            .then(|| self.links.results.get(&self.call_anchor(call)).cloned())
            .flatten();
        ExchangeView {
            anchor: self.anchor(exchange.call),
            call_anchor: self.call_anchor(call),
            shared: id.is_some_and(|id| self.links.pairing.shared(id)),
            time: self.time(exchange.call),
            name: self.call_name(call),
            input: self.cut(input),
            result: joined.map(|answer| self.result_view(answer)),
            moved,
            agent,
        }
    }

    /// Whether `node` is one of this page's records.
    fn on_page(&self, node: usize) -> bool {
        self.positions.contains_key(&node)
    }

    /// A tool run's entries at `places`, the places of its records this page
    /// holds, in plan order; none when there are none. A call's result block
    /// joins its call when the block's record is on the page, not yet shown,
    /// and its parent is already shown; every other block of a result record
    /// is shown at the record's place with a link to its call, on the page
    /// that holds the call, so no record comes before its parent and every
    /// block is shown once. Only the page's own places are visited, however
    /// long the run.
    fn run(&mut self, run: &ToolRun, places: &[Place], pairs: &Pairs<'_>) -> Option<ItemView> {
        if places.is_empty() {
            return None;
        }
        let exchange_at =
            |group: u32, index: u32| &run.groups[group as usize].exchanges[index as usize];
        let nodes = places.iter().filter_map(|&place| match place {
            Place::Call(group, index) => Some(exchange_at(group, index).call),
            Place::Result(group, index) => exchange_at(group, index).result.map(|a| a.record),
            Place::Note(index) => run.notes.get(index as usize).copied(),
            Place::Node(_) => None,
        });
        let span = span_label(nodes.filter_map(|node| self.heads.nodes[node].timestamp));
        let mut entries: Vec<RunEntry> = Vec::new();
        let mut open_group = None;
        for &place in places {
            match place {
                Place::Call(group, index) => {
                    let exchange = exchange_at(group, index);
                    let node = exchange.call;
                    let joined = exchange.result.filter(|answer| {
                        self.on_page(answer.record)
                            && !self.blocks.contains(answer)
                            && self
                                .links
                                .parents
                                .get(answer.record)
                                .copied()
                                .flatten()
                                .is_none_or(|parent| {
                                    parent == node || self.anchored.contains(&parent)
                                })
                    });
                    let view = self.exchange(exchange, joined);
                    match entries.last_mut() {
                        Some(RunEntry::Group { exchanges }) if open_group == Some(group) => {
                            exchanges.push(view);
                        }
                        _ => entries.push(RunEntry::Group {
                            exchanges: vec![view],
                        }),
                    }
                    open_group = Some(group);
                }
                Place::Result(group, index) => {
                    if let Some(answer) = exchange_at(group, index).result {
                        let shown = self.result_entries(answer.record, pairs);
                        if !shown.is_empty() {
                            entries.extend(shown);
                            open_group = None;
                        }
                    }
                }
                Place::Note(index) => {
                    let Some(&node) = run.notes.get(index as usize) else {
                        continue;
                    };
                    if self.heads.nodes[node].kind == Kind::ToolResult {
                        entries.extend(self.result_entries(node, pairs));
                    } else {
                        let view = self.note(node);
                        entries.push(RunEntry::Note { note: view });
                    }
                    open_group = None;
                }
                Place::Node(_) => {}
            }
        }
        Some(ItemView::Run {
            summary: run_summary(&entries, span),
            entries,
        })
    }

    fn notes(&mut self, nodes: &[usize]) -> ItemView {
        let views: Vec<NoteView> = nodes.iter().map(|&node| self.note(node)).collect();
        let mut summary = vec![
            counted(views.len(), "note", "notes"),
            capped(&note_labels(&views)),
        ];
        summary.extend(span_label(
            nodes
                .iter()
                .filter_map(|&node| self.heads.nodes[node].timestamp),
        ));
        ItemView::Notes {
            summary: summary.join(" · "),
            notes: views,
        }
    }

    fn response(&mut self, nodes: &[usize]) -> ItemView {
        let parts: Vec<PartView> = nodes.iter().map(|&node| self.part(node)).collect();
        let summary = parts
            .iter()
            .flat_map(|part| &part.text)
            .map(|block| first_line(&block.lead, LINE_CHARS))
            .find(|line| !line.is_empty())
            .unwrap_or_else(|| "A response without text".to_owned());
        ItemView::Response { summary, parts }
    }

    fn boundary(&mut self, node: usize) -> BoundaryView {
        let compaction = self.heads.nodes[node].compaction.as_deref();
        let count = |value: Option<u64>| value.map_or_else(String::new, |value| value.to_string());
        BoundaryView {
            anchor: self.anchor(node),
            time: self.time(node),
            trigger: compaction
                .and_then(|compaction| compaction.trigger.clone())
                .unwrap_or_default(),
            pre_tokens: count(compaction.and_then(|compaction| compaction.pre_tokens)),
            post_tokens: count(compaction.and_then(|compaction| compaction.post_tokens)),
        }
    }

    /// The view of the part of `item` at `places`, the places of its records
    /// this page holds; none when there are none.
    fn item(&mut self, item: &Item, places: &[Place], pairs: &Pairs<'_>) -> Option<ItemView> {
        let own = |nodes: &[usize]| -> Vec<usize> {
            places
                .iter()
                .filter_map(|&place| match place {
                    Place::Node(index) => nodes.get(index as usize).copied(),
                    _ => None,
                })
                .collect()
        };
        let has = |index: u32| places.contains(&Place::Node(index));
        match item {
            Item::Owner { node, form } => has(0).then(|| self.owner(*node, *form)),
            Item::Response { nodes } => {
                let nodes = own(nodes);
                (!nodes.is_empty()).then(|| self.response(&nodes))
            }
            Item::ToolRun(run) => self.run(run, places, pairs),
            Item::Notes(nodes) => {
                let nodes = own(nodes);
                (!nodes.is_empty()).then(|| self.notes(&nodes))
            }
            Item::Compaction { boundary, summary } => {
                let boundary = boundary.filter(|_| has(0));
                let summary = summary.filter(|_| has(1));
                (boundary.is_some() || summary.is_some()).then(|| ItemView::Compaction {
                    boundary: boundary.map(|node| self.boundary(node)),
                    summary: summary.map(|node| {
                        let (text, full) = note_text(self.body(node), self.bodies);
                        SummaryView {
                            anchor: self.anchor(node),
                            time: self.time(node),
                            text: Rendered::counted(&text, full, self.limit),
                        }
                    }),
                })
            }
            Item::Peer(node) => has(0).then(|| {
                let body = self.body(*node);
                let text = self.text(
                    body.pointer("/attachment/prompt")
                        .or_else(|| body.pointer("/message/content")),
                );
                ItemView::Peer {
                    anchor: self.anchor(*node),
                    time: self.time(*node),
                    text: self.cut(text),
                }
            }),
        }
    }

    /// The views of `turns`, whose records lie in `sequence`, showing only the
    /// records at `page`, the positions the page holds: a turn the page cuts
    /// shows the part of it that lies on the page, found from the turn's slots
    /// without visiting the rest of it.
    pub fn turns(
        &mut self,
        sequence: &[usize],
        turns: &[Turn],
        page: &std::ops::Range<usize>,
    ) -> Vec<TurnView> {
        self.positions = page
            .clone()
            .map(|position| (sequence[position], position))
            .collect();
        self.examined += self.positions.len();
        turns
            .iter()
            .map(|turn| {
                let slots = turn.slots_in(page);
                self.examined += slots.len();
                let mut places: BTreeMap<u32, Vec<Place>> = BTreeMap::new();
                for slot in slots {
                    places.entry(slot.item).or_default().push(slot.place);
                }
                let pairs = turn.pairs_in(page);
                let items = places
                    .iter()
                    .filter_map(|(&item, places)| {
                        self.item(&turn.items[item as usize], places, &pairs)
                    })
                    .collect();
                let shown = turn.positions.start.max(page.start)..turn.positions.end.min(page.end);
                let forks = sequence
                    .get(shown)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|&node| {
                        self.links.forks.get(&self.heads.nodes[node].id.to_string())
                    })
                    .flatten()
                    .cloned()
                    .collect();
                TurnView {
                    items,
                    forks,
                    before: None,
                    after: None,
                }
            })
            .collect()
    }

    /// The nodes of `sequence` this view has shown so far.
    #[must_use]
    pub fn shown(&self) -> usize {
        self.anchored.len()
    }

    /// How many positions and record places this view has visited: the page's
    /// own records and their places, never the rest of a turn the page cuts.
    #[must_use]
    pub const fn examined(&self) -> usize {
        self.examined
    }
}
