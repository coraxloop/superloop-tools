//! The first pass over a loop's transcript files.
//!
//! Every line is read once and only its head is kept, with the location of
//! each record's first copy, so a page can later re-read exactly the records it
//! renders.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest as _, Sha256};

use crate::agents::{AgentThread, MetaFile};
use crate::head::{Compaction, Kind, RawHead, RecordId, parse_timestamp};
use crate::input::{EntryKind, InputFile, Project, Reached};
use crate::names::is_segment;
use crate::pool;

/// The most bytes of one transcript line the first pass holds; a longer line
/// is read through without being kept, and counted.
pub const MAX_LINE_BYTES: usize = 64 << 20;

/// Reads one line into `line`, keeping at most `limit` bytes of it: a longer
/// line is read through and dropped. Returns the bytes the line took in the
/// file, and whether it was dropped.
fn next_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    limit: usize,
) -> io::Result<(usize, bool)> {
    line.clear();
    let (mut taken, mut dropped) = (0, false);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((taken, dropped));
        }
        let end = available.iter().position(|&byte| byte == b'\n');
        let chunk = &available[..end.map_or(available.len(), |at| at + 1)];
        let length = chunk.len();
        if !dropped {
            if line.len() + length > limit {
                dropped = true;
                line.clear();
                line.shrink_to_fit();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        reader.consume(length);
        taken += length;
        if end.is_some() {
            return Ok((taken, dropped));
        }
    }
}

/// Where a record's first copy lives: the file's position in load order and
/// the byte span of its line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loc {
    pub file: u16,
    pub offset: u64,
    pub len: u32,
}

/// One distinct record as the first pass keeps it; its parent and content are
/// the first copy's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub id: RecordId,
    pub parent: Option<RecordId>,
    pub logical_parent: Option<RecordId>,
    pub preserved_tail: Option<RecordId>,
    pub kind: Kind,
    pub sidechain: bool,
    pub timestamp: Option<i64>,
    /// The API message an assistant record belongs to.
    pub message: Option<Box<str>>,
    /// The id each of the record's tool-use blocks carries, in the order of
    /// the blocks, none for a block that carries none; each block is a call,
    /// known by the record and its index among them.
    pub calls: Box<[Option<Box<str>>]>,
    /// The call id each of the record's tool result blocks names, in the
    /// order of the blocks, none for a block that names no call.
    pub results: Box<[Option<Box<str>>]>,
    /// The call record a tool result names as its source.
    pub source_call: Option<RecordId>,
    /// What a compaction boundary records.
    pub compaction: Option<Box<Compaction>>,
    /// For a compaction boundary, the record written just before it in its
    /// file.
    pub previous: Option<RecordId>,
    pub loc: Loc,
    /// The SHA-256 digest of the record's line as the first pass read it,
    /// which a page's key covers and a page's reading checks.
    pub digest: [u8; 32],
}

/// What one pass over one transcript file found.
#[derive(Debug, Default)]
pub struct FileScan {
    /// The file's record lines in write order, copies included, each located
    /// in the file this scan read (file position 0).
    pub lines: Vec<Head>,
    /// The first timestamp written in the file, as text.
    pub first_timestamp: Option<String>,
    /// The first record id written in the file, which places a file with no
    /// records of its own in a conversation.
    pub first_record: Option<RecordId>,
    /// Non-blank lines read.
    pub lines_read: u64,
    /// Lines that carry a record id.
    pub id_lines: u64,
    /// Distinct record ids among them.
    pub distinct: u64,
    /// Lines that are not a JSON object with well-typed known fields and
    /// well-formed record ids.
    pub malformed: u64,
    /// Lines longer than the line limit, read through without being kept.
    pub oversized: u64,
    /// The last `custom-title` the file records.
    pub custom_title: Option<String>,
    /// The last `ai-title` the file records.
    pub ai_title: Option<String>,
}

fn record_id(text: Option<&str>) -> Result<Option<RecordId>, ()> {
    text.map_or(Ok(None), |text| RecordId::parse(text).map(Some).ok_or(()))
}

impl FileScan {
    /// Reads one transcript file's lines, keeping heads and byte spans.
    ///
    /// # Errors
    ///
    /// Returns the reader's error; a line that does not parse is counted, not
    /// an error.
    pub fn read(reader: impl BufRead) -> io::Result<Self> {
        Self::read_within(reader, MAX_LINE_BYTES)
    }

    /// Reads one transcript file's lines, holding at most `limit` bytes of a
    /// line: a longer one is read through, counted and skipped.
    ///
    /// # Errors
    ///
    /// Returns the reader's error; a line that does not parse is counted, not
    /// an error.
    pub fn read_within(mut reader: impl BufRead, limit: usize) -> io::Result<Self> {
        let mut scan = Self::default();
        let mut seen = std::collections::HashSet::new();
        let mut buffer = Vec::new();
        let mut offset = 0_u64;
        loop {
            let (read, dropped) = next_line(&mut reader, &mut buffer, limit)?;
            if read == 0 {
                break;
            }
            let start = offset;
            offset += read as u64;
            if dropped {
                scan.oversized += 1;
                continue;
            }
            if buffer.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            scan.lines_read += 1;
            let Ok(head) = serde_json::from_slice::<RawHead<'_>>(&buffer) else {
                scan.malformed += 1;
                continue;
            };
            if scan.first_timestamp.is_none() {
                scan.first_timestamp = head.timestamp.as_deref().map(str::to_owned);
            }
            match head.record_type.as_deref() {
                Some("custom-title") if head.custom_title.is_some() => {
                    scan.custom_title = head.custom_title.as_deref().map(str::to_owned);
                }
                Some("ai-title") if head.ai_title.is_some() => {
                    scan.ai_title = head.ai_title.as_deref().map(str::to_owned);
                }
                _ => {}
            }
            let Some(uuid) = head.uuid.as_deref() else {
                continue;
            };
            let links = (
                record_id(Some(uuid)),
                record_id(head.parent_uuid.as_deref()),
                record_id(head.logical_parent_uuid.as_deref()),
                record_id(
                    head.compact_metadata
                        .as_ref()
                        .and_then(|metadata| metadata.preserved_segment.as_ref())
                        .and_then(|segment| segment.tail_uuid.as_deref()),
                ),
            );
            let (Ok(Some(id)), Ok(parent), Ok(logical_parent), Ok(preserved_tail)) = links else {
                scan.malformed += 1;
                continue;
            };
            let Ok(len) = u32::try_from(read) else {
                scan.malformed += 1;
                continue;
            };
            scan.id_lines += 1;
            scan.first_record.get_or_insert(id);
            if seen.insert(id) {
                scan.distinct += 1;
            }
            let previous = scan.lines.last().map(|line| line.id);
            let loc = Loc {
                file: 0,
                offset: start,
                len,
            };
            let mut kept = into_head(
                head,
                id,
                [parent, logical_parent, preserved_tail],
                previous,
                loc,
            );
            kept.digest = Sha256::digest(&buffer).into();
            scan.lines.push(kept);
        }
        Ok(scan)
    }
}

/// Keeps what the tree needs of one parsed record line.
fn into_head(
    head: RawHead<'_>,
    id: RecordId,
    [parent, logical_parent, preserved_tail]: [Option<RecordId>; 3],
    previous: Option<RecordId>,
    loc: Loc,
) -> Head {
    let kind = head.kind();
    let compaction = head.compaction().map(Box::new);
    let source_call = head
        .source_tool_assistant_uuid
        .as_deref()
        .and_then(RecordId::parse);
    let (message, calls, results) = head.message.map_or_else(
        || (None, Box::default(), Box::default()),
        |message| {
            let boxed = |ids: Vec<Option<String>>| -> Box<[Option<Box<str>>]> {
                ids.into_iter()
                    .map(|id| id.map(String::into_boxed_str))
                    .collect()
            };
            (
                message.id.map(|id| id.into_owned().into_boxed_str()),
                boxed(message.content.calls),
                boxed(message.content.results),
            )
        },
    );
    Head {
        id,
        parent,
        logical_parent,
        preserved_tail,
        kind,
        sidechain: head.is_sidechain == Some(true),
        timestamp: head.timestamp.as_deref().and_then(parse_timestamp),
        message,
        calls,
        results,
        source_call,
        previous: previous.filter(|_| kind == Kind::Boundary),
        compaction,
        loc,
        digest: [0; 32],
    }
}

/// One transcript file of a loop, in load order.
#[derive(Debug)]
pub struct SourceFile {
    pub path: PathBuf,
    pub stem: String,
    pub bytes: u64,
    pub modified: Option<SystemTime>,
    pub scan: FileScan,
    /// Where the scan read the file, and the device and inode it read; none
    /// for a scan made in memory.
    pub origin: Option<Origin>,
}

/// The file a scan read: how to reach it again, and its identity.
#[derive(Clone, Debug)]
pub struct Origin {
    pub input: InputFile,
    pub device: u64,
    pub inode: u64,
}

impl SourceFile {
    /// Opens the file again the way the scan reached it, as the file the scan
    /// read: the same device and inode, no shorter than it was.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidData` error when the file is gone, is no longer a
    /// regular file reached without a link, or is another file or shorter
    /// than the one scanned, and the error of a file that cannot be opened.
    pub fn reopen(&self) -> io::Result<File> {
        let changed = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} is no longer the file its scan read",
                    self.path.display()
                ),
            )
        };
        let origin = self.origin.as_ref().ok_or_else(changed)?;
        let Reached::Found(file) = origin.input.open()? else {
            return Err(changed());
        };
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != (origin.device, origin.inode)
            || metadata.len() < self.bytes
        {
            return Err(changed());
        }
        Ok(file)
    }
}

/// The transcript files of one loop's project folder: the session files at
/// its top level and the subagent files in each session folder's agents'
/// folder.
#[derive(Debug, Default)]
pub struct LoopSource {
    pub sessions: Vec<InputFile>,
    pub agents: Vec<InputFile>,
    /// Transcript files whose names give no segment of the name grammar,
    /// left unread because their names would become file names and links.
    pub ignored: Vec<PathBuf>,
    /// Subagent files whose id an earlier file in path order gives, left
    /// unread, each with the file whose thread is rendered under that id.
    pub repeated: Vec<(PathBuf, PathBuf)>,
    /// Entries left unread for their kind: a link anywhere in the project
    /// folder, anything but a regular file at a transcript's name, and
    /// anything but a folder at an agents' folder's name.
    pub skipped: Vec<PathBuf>,
}

/// Whether a session file's stem is a segment.
fn session_named(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(is_segment)
}

/// A subagent file's id: its name is `agent-ID.jsonl` with ID a segment.
#[must_use]
pub fn agent_id(path: &Path) -> Option<&str> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix("agent-"))
        .filter(|id| is_segment(id))
}

fn is_transcript(name: &OsStr) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension == "jsonl")
}

impl LoopSource {
    /// Lists a project folder's session files and subagent files, each in
    /// path order, reaching every folder and entry through the project
    /// folder's descriptor without following a link; of the subagent files
    /// that give one id, the first is the thread and the others are left
    /// unread, so no two threads share a page name.
    ///
    /// # Errors
    ///
    /// Returns the error of a folder that cannot be opened or listed.
    pub fn discover(project: &Project) -> io::Result<Self> {
        let mut source = Self::default();
        let Reached::Found(entries) = project.list(&[])? else {
            return Ok(source);
        };
        let mut folders = Vec::new();
        for (name, kind) in entries {
            let path = project.path.join(&name);
            match kind {
                EntryKind::File if is_transcript(&name) => {
                    if session_named(&path) {
                        source.sessions.push(project.file(vec![name]));
                    } else {
                        source.ignored.push(path);
                    }
                }
                EntryKind::Directory => folders.push(name),
                EntryKind::Link => source.skipped.push(path),
                EntryKind::Other if is_transcript(&name) => source.skipped.push(path),
                EntryKind::File | EntryKind::Other => {}
            }
        }
        let mut ids: HashMap<String, usize> = HashMap::new();
        for folder in folders {
            let subagents = vec![folder, OsString::from("subagents")];
            let folder_path = subagents
                .iter()
                .fold(project.path.clone(), |path, name| path.join(name));
            let entries = match project.list(&subagents)? {
                Reached::Found(entries) => entries,
                Reached::Absent => continue,
                Reached::Refused => {
                    source.skipped.push(folder_path);
                    continue;
                }
            };
            for (name, kind) in entries {
                let path = folder_path.join(&name);
                if !is_transcript(&name) {
                    continue;
                }
                if kind != EntryKind::File {
                    source.skipped.push(path);
                    continue;
                }
                let Some(id) = agent_id(&path).map(str::to_owned) else {
                    source.ignored.push(path);
                    continue;
                };
                match ids.entry(id) {
                    Entry::Occupied(first) => {
                        let first = source.agents[*first.get()].path.clone();
                        source.repeated.push((path, first));
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(source.agents.len());
                        let mut names = subagents.clone();
                        names.push(name);
                        source.agents.push(project.file(names));
                    }
                }
            }
        }
        Ok(source)
    }
}

/// The first pass over a loop's session files: the distinct records in write
/// order, each at its first copy, over the files in load order.
#[derive(Debug, Default)]
pub struct Heads {
    pub files: Vec<SourceFile>,
    pub nodes: Vec<Head>,
    pub index: HashMap<RecordId, u32>,
    /// Record lines beyond the first copy of their id.
    pub copies_dropped: u64,
    /// Subagent transcript files found beside the sessions.
    pub agent_files: usize,
    /// Transcript files left unread for their names: outside the grammar, or
    /// a subagent id an earlier file gives.
    pub ignored_files: usize,
    /// Entries left unread for their kind, when the source was listed or when
    /// a session file was opened.
    pub skipped: Vec<PathBuf>,
}

/// Scans one transcript file, keeping its path, size, modification time and
/// identity; none when it is no longer a regular file reached without a link.
///
/// # Errors
///
/// Returns the error of a file that cannot be opened or read.
pub fn scan_file(input: &InputFile) -> io::Result<Option<SourceFile>> {
    let Reached::Found(file) = input.open()? else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    let scan = FileScan::read(BufReader::with_capacity(1 << 20, file))?;
    Ok(Some(SourceFile {
        path: input.path.clone(),
        stem: input.stem(),
        bytes: metadata.len(),
        modified: metadata.modified().ok(),
        scan,
        origin: Some(Origin {
            input: input.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }),
    }))
}

impl Heads {
    /// Scans every session file of a loop on the scan pool, then merges them.
    ///
    /// # Errors
    ///
    /// Returns the first error opening or reading a session file.
    pub fn load(source: &LoopSource) -> io::Result<Self> {
        let scanned = pool::run(source.sessions.len(), pool::SCAN_THREADS, &|index| {
            scan_file(&source.sessions[index])
        });
        let mut files = Vec::new();
        let mut skipped = source.skipped.clone();
        for (input, file) in source.sessions.iter().zip(scanned) {
            match file? {
                Some(file) => files.push(file),
                None => skipped.push(input.path.clone()),
            }
        }
        let mut heads = Self::merge(files)?;
        heads.agent_files = source.agents.len();
        heads.ignored_files = source.ignored.len() + source.repeated.len();
        heads.skipped = skipped;
        Ok(heads)
    }

    /// Orders the files by their first timestamp, a file with more distinct
    /// records first among equals (an original before its prefix copies), then
    /// by name, and keeps each id's first copy in that order.
    ///
    /// # Errors
    ///
    /// Returns an error when a loop has more files or records than a location
    /// can address.
    pub fn merge(mut files: Vec<SourceFile>) -> io::Result<Self> {
        files.sort_by(|left, right| {
            let key = |file: &SourceFile| {
                (
                    file.scan.first_timestamp.is_none(),
                    file.scan.first_timestamp.clone(),
                    Reverse(file.scan.distinct),
                )
            };
            key(left)
                .cmp(&key(right))
                .then_with(|| left.stem.cmp(&right.stem))
        });
        let too_many =
            || io::Error::other("more transcript files or records than one loop can address");
        let mut heads = Self::default();
        for (position, file) in files.iter_mut().enumerate() {
            let file_index = u16::try_from(position).map_err(|_| too_many())?;
            for line in std::mem::take(&mut file.scan.lines) {
                let next = u32::try_from(heads.nodes.len()).map_err(|_| too_many())?;
                match heads.index.entry(line.id) {
                    Entry::Occupied(_) => heads.copies_dropped += 1,
                    Entry::Vacant(slot) => {
                        slot.insert(next);
                        let loc = Loc {
                            file: file_index,
                            ..line.loc
                        };
                        heads.nodes.push(Head { loc, ..line });
                    }
                }
            }
        }
        heads.files = files;
        Ok(heads)
    }

    /// The loop's title: the last custom title of the last file that has one,
    /// else its last generated title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        let custom = self
            .files
            .iter()
            .rev()
            .find_map(|file| file.scan.custom_title.as_deref());
        custom.or_else(|| {
            self.files
                .iter()
                .rev()
                .find_map(|file| file.scan.ai_title.as_deref())
        })
    }

    /// The counts the first pass over the session files can give, for the
    /// report line.
    #[must_use]
    pub fn report(&self) -> LoadReport {
        LoadReport {
            files: self.files.len(),
            records: self.nodes.len(),
            copies_dropped: self.copies_dropped,
            malformed: self.files.iter().map(|file| file.scan.malformed).sum(),
            oversized: self.files.iter().map(|file| file.scan.oversized).sum(),
            ignored: self.ignored_files,
            skipped: self.skipped.len(),
            meta_skipped: 0,
        }
    }
}

/// The first pass's counts, written as `key=value` fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadReport {
    pub files: usize,
    pub records: usize,
    pub copies_dropped: u64,
    /// Lines of every transcript file that do not parse, skipped.
    pub malformed: u64,
    /// Lines of every transcript file over the line limit, skipped.
    pub oversized: u64,
    /// Transcript files left unread for their names.
    pub ignored: usize,
    /// Entries of the input tree left unread for their kind.
    pub skipped: usize,
    /// Subagent meta files present and left unread or unused.
    pub meta_skipped: usize,
}

impl LoadReport {
    /// Adds the subagent files' skipped lines, the subagent files left unread
    /// for their kind when they were opened, and their skipped meta files.
    #[must_use]
    pub fn with_agents(mut self, agents: &[AgentThread], skipped: usize) -> Self {
        for agent in agents {
            let scan = &agent.file().scan;
            self.malformed += scan.malformed;
            self.oversized += scan.oversized;
            self.meta_skipped += usize::from(agent.meta_file == MetaFile::Skipped);
        }
        self.skipped += skipped;
        self
    }
}

impl fmt::Display for LoadReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "files={} records={} copies_dropped={} malformed={} oversized={} ignored={} skipped={} meta_skipped={}",
            self.files,
            self.records,
            self.copies_dropped,
            self.malformed,
            self.oversized,
            self.ignored,
            self.skipped,
            self.meta_skipped
        )
    }
}
