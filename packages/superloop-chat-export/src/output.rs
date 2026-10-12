//! The records a run leaves beside its pages.
//!
//! A loop's manifest lets the next run skip the pages whose inputs did not
//! change and records every file the run produced with the digest of the
//! bytes written; the output root keeps a smaller one for the loops index and
//! its stylesheet. What those records can authorise is decided in `owner`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::owner::Owned;
use crate::plan::PageKind;

/// The manifest's file name in a loop's output directory.
pub const MANIFEST: &str = "chat-export-manifest.json";

/// The journal's file name in a loop's output directory.
pub const JOURNAL: &str = "chat-export-journal.txt";

/// The loop manifest's schema version: 3 keys each page and the templates by
/// SHA-256 digests stored whole, and records every file with its digest.
pub const SCHEMA: u32 = 3;

/// The root manifest's schema version: 2 records the root's files with their
/// digests.
pub const ROOT_SCHEMA: u32 = 2;

/// The file name of the output root's manifest.
pub const ROOT_MANIFEST: &str = "chat-export-root.json";

/// The file name of the output root's journal.
pub const ROOT_JOURNAL: &str = "chat-export-root-journal.txt";

/// What a loop's pages were rendered from, and what the run wrote.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub schema: u32,
    /// The program and version that rendered the pages.
    pub program: String,
    /// The SHA-256 digest of the templates and assets, as hex.
    pub templates: String,
    pub max_block_bytes: u64,
    pub summary: LoopSummary,
    pub sources: Vec<SourceEntry>,
    pub pages: Vec<PageEntry>,
    /// Every file the run produced in the loop's folder, with the digest of
    /// the bytes written.
    pub files: Vec<Owned>,
}

/// What the run wrote at the output root: the loops index and its stylesheet.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct RootManifest {
    pub schema: u32,
    pub files: Vec<Owned>,
}

/// What the loops index shows of a loop.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct LoopSummary {
    pub title: Option<String>,
    pub conversations: usize,
    pub pages: usize,
    /// The latest record's instant, in milliseconds since the Unix epoch.
    pub last: Option<i64>,
}

/// One transcript file the pages were planned from.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct SourceEntry {
    /// The path relative to the loop's project directory.
    pub path: String,
    pub bytes: u64,
    pub modified_ns: u64,
}

/// One rendered page and the key of what it was rendered from.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PageEntry {
    pub path: String,
    pub kind: PageKind,
    pub conversation: Option<usize>,
    /// The first and past-the-last positions of its records in its sequence.
    pub records: [usize; 2],
    /// The SHA-256 digest, as hex, of the whole value the page's template
    /// rendered, written as JSON: the header and the views of its records,
    /// every text, link and anchor the page shows among them. A later run
    /// keeps the page on disk only when its value has this key.
    pub key: String,
}

/// A loop manifest of this schema from `bytes`; any other bytes are none.
#[must_use]
pub fn parse_manifest(bytes: &[u8]) -> Option<Manifest> {
    serde_json::from_slice::<Manifest>(bytes)
        .ok()
        .filter(|manifest| manifest.schema == SCHEMA)
}

/// A root manifest of this schema from `bytes`; any other bytes are none.
#[must_use]
pub fn parse_root_manifest(bytes: &[u8]) -> Option<RootManifest> {
    serde_json::from_slice::<RootManifest>(bytes)
        .ok()
        .filter(|manifest| manifest.schema == ROOT_SCHEMA)
}

/// The keys of an earlier run's pages by path; none when every page must
/// render.
///
/// The keys are given when that run's manifest is of this schema and was made
/// by this program with these templates and this block limit, so that a page
/// whose key is unchanged and whose file is an owned file need not render
/// again.
#[must_use]
pub fn previous_keys<'m>(
    previous: Option<&'m Manifest>,
    current: &Manifest,
) -> Option<HashMap<&'m str, &'m str>> {
    let previous = previous.filter(|previous| {
        previous.schema == current.schema
            && previous.program == current.program
            && previous.templates == current.templates
            && previous.max_block_bytes == current.max_block_bytes
    })?;
    Some(
        previous
            .pages
            .iter()
            .map(|page| (page.path.as_str(), page.key.as_str()))
            .collect(),
    )
}
