//! What the program owns in a folder it writes.
//!
//! A manifest cannot prove who wrote it, so it never authorises by itself: a
//! file is the program's only when its path is of the grammar the program
//! generates, a manifest or a journal records it with the SHA-256 digest of
//! the bytes written, and its bytes on disk still have that digest. Every
//! other file is foreign: left in place, counted and named. The most a forged
//! record can do is let the program remove or replace a file that has a
//! generated name and exactly the bytes the forger recorded.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, Write};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::folder::{Folder, Kind};
use crate::pool;

/// One file a manifest records: its path and the SHA-256 digest, as
/// lower-case hex, of the bytes the run wrote there.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Owned {
    pub path: String,
    pub sha256: String,
}

/// The digests the records claim for each path.
pub type Claims = HashMap<String, Vec<String>>;

/// Adds `files` to `claims`.
pub fn claim(claims: &mut Claims, files: &[Owned]) {
    for file in files {
        claims
            .entry(file.path.clone())
            .or_default()
            .push(file.sha256.clone());
    }
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A journal read back: the claims of its complete lines and their length in
/// bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JournalClaims {
    pub files: Vec<Owned>,
    pub complete: u64,
}

/// A journal's claims, one `DIGEST PATH` line per file a run began to write.
///
/// A run records a file before it writes it, so a last line without its line
/// feed is a record the run was writing when it stopped, before it wrote that
/// file: it claims nothing and is dropped, and every complete line is kept.
/// None when a complete line is not of that form.
#[must_use]
pub fn journal_claims(bytes: &[u8]) -> Option<JournalClaims> {
    let complete = bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |end| end + 1);
    let text = std::str::from_utf8(&bytes[..complete]).ok()?;
    let files = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (digest, path) = line.split_once(' ')?;
            is_digest(digest).then(|| Owned {
                path: path.to_owned(),
                sha256: digest.to_owned(),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(JournalClaims {
        files,
        complete: u64::try_from(complete).ok()?,
    })
}

/// What a folder holds before a run writes, sorted by ownership.
#[derive(Debug, Default)]
pub struct Holdings {
    /// The files a claim still describes, with their digest.
    pub owned: BTreeMap<String, String>,
    /// Every other file, link or special file, by path.
    pub foreign: BTreeSet<String>,
    /// The directories, by path.
    pub directories: BTreeSet<String>,
}

impl Holdings {
    /// Sorts what `folder` holds, all the way down when `deep` is set. The
    /// names in `records` are the program's manifest and journal, read and
    /// found to be of its own form; any other file is owned only when
    /// `generated` accepts its path, `claims` list it and its bytes have a
    /// claimed digest.
    ///
    /// # Errors
    ///
    /// Returns the error of a directory that cannot be listed or a file that
    /// cannot be read.
    pub fn of(
        folder: &Folder,
        deep: bool,
        claims: &Claims,
        records: &[&str],
        generated: impl Fn(&str) -> bool,
    ) -> io::Result<Self> {
        let mut holdings = Self::default();
        let mut candidates = Vec::new();
        for entry in folder.list(deep)? {
            match entry.kind {
                Kind::Directory => {
                    holdings.directories.insert(entry.path);
                }
                Kind::File if records.contains(&entry.path.as_str()) => {}
                Kind::File if generated(&entry.path) && claims.contains_key(&entry.path) => {
                    candidates.push(entry.path);
                }
                Kind::File | Kind::Other => {
                    holdings.foreign.insert(entry.path);
                }
            }
        }
        let digests = pool::run(candidates.len(), pool::SCAN_THREADS, &|index| {
            folder.digest(&candidates[index])
        });
        for (path, digest) in candidates.into_iter().zip(digests) {
            match digest? {
                Some(digest) if claims[&path].contains(&digest) => {
                    holdings.owned.insert(path, digest);
                }
                _ => {
                    holdings.foreign.insert(path);
                }
            }
        }
        Ok(holdings)
    }

    /// The first foreign entry in the way of a path in `needed`: at that path,
    /// at a folder it lies in, or a directory standing where it is a file.
    #[must_use]
    pub fn in_the_way(&self, needed: &BTreeSet<String>) -> Option<String> {
        needed.iter().find_map(|path| {
            let parents = path.match_indices('/').map(|(at, _)| &path[..at]);
            std::iter::once(path.as_str())
                .chain(parents)
                .find(|at| self.foreign.contains(*at))
                .or_else(|| self.directories.contains(path).then_some(path.as_str()))
                .map(str::to_owned)
        })
    }
}

/// The journal of a run, which the run removes once its manifest is written.
///
/// Every file the run writes is recorded with the digest of its new bytes
/// before it is renamed into place, so a run that stops anywhere leaves
/// nothing the next run cannot own.
pub struct Journal<'f> {
    folder: &'f Folder,
    name: &'static str,
    /// The length of the complete lines a journal left by an earlier run
    /// holds, which the run keeps and appends after.
    complete: u64,
    file: Mutex<Option<File>>,
}

impl<'f> Journal<'f> {
    /// A journal at `name` in `folder`, opened for appending at its first
    /// record after the `complete` bytes of lines an earlier run left there.
    #[must_use]
    pub const fn new(folder: &'f Folder, name: &'static str, complete: u64) -> Self {
        Self {
            folder,
            name,
            complete,
            file: Mutex::new(None),
        }
    }

    /// Records that the run is about to write `digest` bytes to `path`; the
    /// first record first cuts an earlier run's unfinished last line away.
    ///
    /// # Errors
    ///
    /// Returns the error of a journal that cannot be opened or written.
    pub fn record(&self, path: &str, digest: &str) -> io::Result<()> {
        let mut slot = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            let file = self.folder.append(self.name)?;
            file.set_len(self.complete)?;
            *slot = Some(file);
        }
        let written = slot.as_mut().map_or(Ok(()), |file| {
            writeln!(file, "{digest} {path}").and_then(|()| file.flush())
        });
        drop(slot);
        written
    }

    /// Removes the journal, the run's manifest now recording what it wrote.
    ///
    /// # Errors
    ///
    /// Returns the error of a journal that cannot be removed.
    pub fn close(self, present: bool) -> io::Result<()> {
        let opened = self
            .file
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if opened || present {
            self.folder.remove(self.name)?;
        }
        Ok(())
    }
}

/// Writes `bytes` to `path` unless the owned file there already has their
/// digest, recording the write in `journal` first. Returns the digest and
/// whether it wrote.
///
/// # Errors
///
/// Returns the error of the journal or of the write.
pub fn commit(
    folder: &Folder,
    journal: &Journal<'_>,
    holdings: &Holdings,
    path: &str,
    bytes: &[u8],
) -> io::Result<(String, bool)> {
    let digest = crate::folder::digest_of(bytes);
    if holdings.owned.get(path) == Some(&digest) {
        return Ok((digest, false));
    }
    journal.record(path, &digest)?;
    folder.write(path, bytes)?;
    Ok((digest, true))
}
