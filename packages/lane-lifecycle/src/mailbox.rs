//! Mailbox names are observed through pinned directories; letter bytes stay in the worker home.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::libc;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{atomic_write, iso8601_utc};

const LETTERS_FILE: &str = "letters.jsonl";
const WATCH_MASK: u32 = libc::IN_CREATE | libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO;

struct Mailbox {
    name: &'static str,
    directory: File,
    watch: i32,
}

struct RecordedHome {
    directory: File,
    path: std::path::PathBuf,
    worker: u32,
    loop_group: u32,
}

#[derive(Clone, Copy, Debug)]
struct FileVersion {
    device: u64,
    inode: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileVersion {
    fn same_file(self, inode: u64, ctime: i64, ctime_nsec: i64) -> bool {
        (self.inode, self.ctime, self.ctime_nsec) == (inode, ctime, ctime_nsec)
    }

    fn json(self) -> Value {
        json!({"device":self.device,"inode":self.inode,"ctime":self.ctime,"ctime_nsec":self.ctime_nsec})
    }
}

#[derive(Clone, Copy)]
struct Observation {
    bytes: u64,
    revision: u64,
    complete: bool,
    version: Option<FileVersion>,
}

type MailboxEntry = (Vec<u8>, u64, &'static str, FileVersion);

/// A round's outside observer, with prior observations recovered from durable lines.
pub struct MailboxWatcher {
    boxes: [Mailbox; 2],
    inotify: Option<OwnedFd>,
    records: Vec<Value>,
    observed: BTreeMap<(String, String), Observation>,
    replay_pending: BTreeSet<String>,
    round: String,
    needs_rearm: bool,
    observation_state: Option<&'static str>,
    run_dir: std::path::PathBuf,
}

impl MailboxWatcher {
    /// Resolve and pin the mailboxes recorded for this round.
    ///
    /// # Errors
    /// Returns an error for inaccessible or invalid plans, mailbox custody or journals.
    pub fn for_round(run_dir: &Path, round: &str) -> io::Result<Option<Self>> {
        let Some(home) = recorded_home(run_dir)? else {
            return Ok(None);
        };
        Self::new_pinned(
            &home.directory,
            run_dir,
            round,
            Some((&home.path, home.worker, home.loop_group)),
        )
        .map(Some)
    }

    #[cfg(test)]
    fn new(home: &Path, run_dir: &Path, round: &str) -> io::Result<Self> {
        let home = open_absolute_directory(home)?;
        Self::new_pinned(&home, run_dir, round, None)
    }

    fn new_pinned(
        home: &File,
        run_dir: &Path,
        round: &str,
        expected: Option<(&Path, u32, u32)>,
    ) -> io::Result<Self> {
        let local = open_child_directory(home, ".local")?;
        let inbox = open_child_directory(&local, "inbox")?;
        let outbox = if let Some((path, worker, loop_group)) = expected {
            open_verified_outbox(&local, path, worker, loop_group)?
        } else {
            open_child_directory(&local, "outbox")?
        };
        let mut boxes = [
            Mailbox {
                name: "inbox",
                directory: inbox,
                watch: -1,
            },
            Mailbox {
                name: "outbox",
                directory: outbox,
                watch: -1,
            },
        ];
        let inotify = install_watches(&mut boxes);
        let records = read_records(&run_dir.join(LETTERS_FILE))?;
        let mut observed: BTreeMap<(String, String), Observation> = BTreeMap::new();
        let mut replay_pending = BTreeSet::new();
        for record in &records {
            let box_name = field(record, "box")?;
            let name = field(record, "name")?;
            let bytes = record["bytes"].as_u64().ok_or_else(invalid_record)?;
            let revision = record["revision"].as_u64().ok_or_else(invalid_record)?;
            let complete = field(record, "state")? == "complete";
            let version = file_version(record)?;
            let key = (box_name.to_owned(), name.to_owned());
            let valid = match observed.get(&key) {
                None => revision == 1,
                Some(prior) if prior.revision == revision => {
                    !prior.complete
                        && complete
                        && prior.bytes == bytes
                        && prior.version.zip(version).is_some_and(|(prior, current)| {
                            prior.same_file(current.inode, current.ctime, current.ctime_nsec)
                        })
                }
                Some(prior) => prior.revision.checked_add(1) == Some(revision),
            };
            if !valid {
                return Err(invalid_record());
            }
            observed.insert(
                key,
                Observation {
                    bytes,
                    revision,
                    complete,
                    version,
                },
            );
            if record["emitted"] == false {
                replay_pending.insert(field(record, "id")?.to_owned());
            }
        }
        Ok(Self {
            boxes,
            inotify,
            records,
            observed,
            replay_pending,
            round: round.to_owned(),
            needs_rearm: false,
            observation_state: None,
            run_dir: run_dir.to_path_buf(),
        })
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record["round"] == self.round)
            .count()
    }

    /// Scan the held mailboxes and publish newly measured observations.
    ///
    /// # Errors
    /// Returns an error if scanning, journal publication or output fails.
    pub fn poll<W: io::Write>(&mut self, output: &mut W) -> io::Result<()> {
        self.scan(output, false)
    }

    /// The child has exited or been reaped, so its outbox names are complete.
    ///
    /// # Errors
    /// Returns an error if the final scan, journal publication or output fails.
    pub fn finish<W: io::Write>(&mut self, output: &mut W) -> io::Result<()> {
        self.scan(output, true)
    }

    fn scan<W: io::Write>(&mut self, output: &mut W, final_scan: bool) -> io::Result<()> {
        self.record_observation_state()?;
        self.emit_pending(output)?;
        let _observed_close = self.drain_events()?;
        if self.needs_rearm {
            self.inotify = install_watches(&mut self.boxes);
            self.needs_rearm = false;
            self.record_observation_state()?;
        }
        for mailbox in &self.boxes {
            for (name, bytes, kind, version) in list_entries(&mailbox.directory)? {
                let escaped = escape_name(&name);
                let key = (mailbox.name.to_owned(), escaped.clone());
                let previous = self.observed.get(&key).copied();
                let complete = (mailbox.name == "inbox" && kind == "file")
                    || (final_scan && mailbox.name == "outbox");
                if previous.is_some_and(|prior| {
                    prior.bytes == bytes
                        && prior.version.is_some_and(|prior| {
                            prior.same_file(version.inode, version.ctime, version.ctime_nsec)
                        })
                        && (prior.complete || !complete)
                }) {
                    continue;
                }
                let revision = match previous {
                    Some(prior)
                        if prior.bytes == bytes
                            && prior.version.is_some_and(|prior| {
                                prior.same_file(version.inode, version.ctime, version.ctime_nsec)
                            }) =>
                    {
                        prior.revision
                    }
                    Some(prior) => prior.revision.checked_add(1).ok_or_else(invalid_record)?,
                    None => 1,
                };
                let state = if complete { "complete" } else { "observed" };
                let elapsed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let at = format!(
                    "{}.{:09}Z",
                    iso8601_utc(elapsed.as_secs()).trim_end_matches('Z'),
                    elapsed.subsec_nanos()
                );
                let identity = json!([mailbox.name, escaped, revision, at]);
                let id = hex_identity(&identity)?;
                let line = format!(
                    "LETTER box={} name={escaped} bytes={bytes} at={at} state={state} revision={revision} id={id}\n",
                    mailbox.name
                );
                let record = json!({"round":&self.round,"box":mailbox.name,"name":escaped,
                    "bytes":bytes,"at":at,"kind":kind,"state":state,"revision":revision,"line":line,"identity":identity,"id":id,"emitted":false,"file_version":version.json()});
                let mut candidate = self.records.clone();
                candidate.push(record);
                write_records(&self.run_dir.join(LETTERS_FILE), &candidate)?;
                self.records = candidate;
                self.observed.insert(
                    key,
                    Observation {
                        bytes,
                        revision,
                        complete,
                        version: Some(version),
                    },
                );
            }
        }
        self.emit_pending(output)?;
        Ok(())
    }

    fn record_observation_state(&mut self) -> io::Result<()> {
        let mode = "inbox-complete-outbox-sight-final-complete";
        if self.observation_state != Some(mode) {
            atomic_write(
                &self.run_dir.join("mailbox-state.json"),
                format!("{{\"observation\":\"{mode}\"}}\n").as_bytes(),
            )?;
            self.observation_state = Some(mode);
        }
        Ok(())
    }

    fn emit_pending<W: io::Write>(&mut self, output: &mut W) -> io::Result<()> {
        for index in 0..self.records.len() {
            if self.records[index]["emitted"] == true {
                continue;
            }
            let line = field(&self.records[index], "line")?;
            let id = field(&self.records[index], "id")?.to_owned();
            if self.replay_pending.contains(&id) {
                let replay = line.trim_end_matches('\n');
                writeln!(output, "{replay} replay=1")?;
            } else {
                output.write_all(line.as_bytes())?;
            }
            output.flush()?;
            let mut candidate = self.records.clone();
            candidate[index]["emitted"] = json!(true);
            write_records(&self.run_dir.join(LETTERS_FILE), &candidate)?;
            self.records = candidate;
            self.replay_pending.remove(&id);
        }
        Ok(())
    }

    fn drain_events(&mut self) -> io::Result<BTreeSet<(String, String)>> {
        let mut ready = BTreeSet::new();
        let Some(fd) = self.inotify.as_ref().map(std::os::fd::AsRawFd::as_raw_fd) else {
            return Ok(ready);
        };
        let mut buffer = [0_u8; 4096];
        loop {
            // SAFETY: the buffer is writable and the descriptor belongs to this watcher.
            #[allow(unsafe_code)]
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                return Err(error);
            }
            if count == 0 {
                break;
            }
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::inotify_event>() <= count.cast_unsigned() {
                // SAFETY: the complete event header is inside the returned byte count.
                #[allow(unsafe_code)]
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer[offset..].as_ptr().cast::<libc::inotify_event>(),
                    )
                };
                let start = offset + std::mem::size_of::<libc::inotify_event>();
                let end = start.saturating_add(event.len as usize);
                if end > count.cast_unsigned() {
                    break;
                }
                let bytes = &buffer[start..end];
                let name = bytes.split(|byte| *byte == 0).next().unwrap_or_default();
                self.handle_event(event.wd, event.mask, name, &mut ready);
                offset = end;
            }
        }
        Ok(ready)
    }

    fn handle_event(
        &mut self,
        watch: i32,
        mask: u32,
        name: &[u8],
        ready: &mut BTreeSet<(String, String)>,
    ) {
        if mask & libc::IN_Q_OVERFLOW != 0 {
            ready.clear();
            self.needs_rearm = true;
            return;
        }
        if name.is_empty() || name[0] == b'.' {
            return;
        }
        if mask & WATCH_MASK != 0
            && let Some(mailbox) = self.boxes.iter().find(|mailbox| mailbox.watch == watch)
        {
            let key = (mailbox.name.to_owned(), escape_name(name));
            if mask & (libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO) != 0 {
                ready.insert(key);
            }
        }
    }
}

fn recorded_home(run_dir: &Path) -> io::Result<Option<RecordedHome>> {
    for directory in [Some(run_dir), run_dir.parent()].into_iter().flatten() {
        let pinned = open_absolute_directory(directory)?;
        let plan_name = CString::new("plan.json").expect("static name has no NUL");
        // SAFETY: the pinned directory and terminated name remain valid for the call.
        #[allow(unsafe_code)]
        let raw = unsafe {
            libc::openat(
                pinned.as_raw_fd(),
                plan_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                continue;
            }
            return Err(error);
        }
        // SAFETY: successful openat transferred one descriptor.
        #[allow(unsafe_code)]
        let plan = unsafe { File::from_raw_fd(raw) };
        let meta = plan.metadata()?;
        if !meta.is_file()
            || meta.uid() != effective_uid()
            || meta.mode() & 0o7777 != 0o600
            || meta.len() > 65_536
        {
            return Err(invalid_record());
        }
        let mut bytes = Vec::new();
        plan.take(65_537).read_to_end(&mut bytes)?;
        let document: Value = serde_json::from_slice(&bytes).map_err(|_| invalid_record())?;
        if document["driver_dir"] != directory.display().to_string() {
            return Err(invalid_record());
        }
        let home_path = document["home"].as_str().ok_or_else(invalid_record)?;
        let expected = document["paths"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["path"] == home_path))
            .ok_or_else(invalid_record)?;
        let home = open_absolute_directory(Path::new(home_path))?;
        let actual = home.metadata()?;
        if expected["uid"] != actual.uid()
            || expected["gid"] != actual.gid()
            || expected["mode"] != format!("{:04o}", actual.mode() & 0o7777)
        {
            return Err(invalid_record());
        }
        let worker = document["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .ok_or_else(invalid_record)?;
        return Ok(Some(RecordedHome {
            directory: home,
            path: Path::new(home_path).to_path_buf(),
            worker,
            loop_group: actual.gid(),
        }));
    }
    Ok(None)
}

fn open_verified_outbox(
    local: &File,
    path: &Path,
    worker: u32,
    loop_group: u32,
) -> io::Result<File> {
    let name = CString::new("outbox").expect("static name has no NUL");
    // SAFETY: O_PATH pins the named directory without requiring its read permission.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            local.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "mailbox-access: {}: {}",
                path.join(".local/outbox").display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: successful openat transferred one descriptor.
    #[allow(unsafe_code)]
    let pinned = unsafe { File::from_raw_fd(raw) };
    let stat = pinned.metadata()?;
    let mode = stat.mode() & 0o7777;
    if !stat.is_dir() || stat.uid() != worker || stat.gid() != loop_group || mode != 0o750 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "mailbox-access: {} owner={} group={} mode={mode:04o}; expected owner={worker} group={loop_group} mode=0750",
                path.join(".local/outbox").display(),
                stat.uid(),
                stat.gid()
            ),
        ));
    }
    let dot = CString::new(".").expect("static name has no NUL");
    // SAFETY: the pinned outbox and terminated dot remain valid for this call.
    #[allow(unsafe_code)]
    let readable = unsafe {
        libc::openat(
            pinned.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if readable < 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "mailbox-access: {}: {}",
                path.join(".local/outbox").display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: successful openat transferred one descriptor.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(readable) })
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no pointer argument and no side effects.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "letter-record: malformed durable line",
    )
}

fn field<'a>(record: &'a Value, name: &str) -> io::Result<&'a str> {
    record[name].as_str().ok_or_else(invalid_record)
}

fn file_version(row: &Value) -> io::Result<Option<FileVersion>> {
    row.get("file_version")
        .map(|version| {
            Ok(FileVersion {
                device: version["device"].as_u64().ok_or_else(invalid_record)?,
                inode: version["inode"].as_u64().ok_or_else(invalid_record)?,
                ctime: version["ctime"].as_i64().ok_or_else(invalid_record)?,
                ctime_nsec: version["ctime_nsec"]
                    .as_i64()
                    .filter(|n| (0..1_000_000_000).contains(n))
                    .ok_or_else(invalid_record)?,
            })
        })
        .transpose()
}

/// Compare a journal row with a held file's inode and nanosecond change time.
///
/// Device numbers are data, not identity. Legacy rows without a file version match.
///
/// # Errors
/// Returns invalid data when the row contains a malformed file version.
pub fn reply_version_matches(
    row: &Value,
    inode: u64,
    ctime: i64,
    ctime_nsec: i64,
) -> io::Result<bool> {
    Ok(file_version(row)?.is_none_or(|version| version.same_file(inode, ctime, ctime_nsec)))
}

/// The first observation of the current file version and its public receipt key.
pub struct ReplyObservation {
    pub row: Value,
    pub key: String,
}

/// Resolve current replies from chronological journal rows, ignoring staging names.
///
/// Completion-only rows retain the observation that first recorded that file version.
/// Legacy rows without file versions retain the key only on an adjacent, same-size
/// observed-to-complete transition; a new measured version starts a new identity.
///
/// # Errors
/// Returns invalid data for malformed outbox observations or file versions.
pub fn reply_observations(rows: &[Value]) -> io::Result<BTreeMap<String, ReplyObservation>> {
    let mut latest: BTreeMap<String, &Value> = BTreeMap::new();
    let mut replies = BTreeMap::new();
    for row in rows {
        if row["box"] != "outbox" || row["kind"] != "file" {
            continue;
        }
        let name = field(row, "name")?;
        if name.starts_with('.') {
            continue;
        }
        let revision = row["revision"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(invalid_record)?;
        let at = field(row, "at")?;
        if parse_utc_instant(at).is_none() {
            return Err(invalid_record());
        }
        let bytes = row["bytes"].as_u64().ok_or_else(invalid_record)?;
        let version = file_version(row)?;
        if row["identity"] != json!(["outbox", name, revision, at]) {
            return Err(invalid_record());
        }
        let key = reply_observation_key(&row["identity"])?;
        let unchanged = if let Some(previous) = latest.get(name) {
            let prior_version = file_version(previous)?;
            previous["bytes"] == bytes
                && match (prior_version, version) {
                    (Some(_), Some(current)) => reply_version_matches(
                        previous,
                        current.inode,
                        current.ctime,
                        current.ctime_nsec,
                    )?,
                    (None, None) => {
                        previous["state"] == "observed"
                            && row["state"] == "complete"
                            && previous["revision"].as_u64().and_then(|n| n.checked_add(1))
                                == Some(revision)
                    }
                    _ => false,
                }
        } else {
            false
        };
        if !unchanged {
            replies.insert(
                name.to_owned(),
                ReplyObservation {
                    row: row.clone(),
                    key,
                },
            );
        }
        latest.insert(name.to_owned(), row);
    }
    Ok(replies)
}

/// A selected reply and the journal directory that owns its receipt.
pub struct RunReplyObservation {
    pub journal: PathBuf,
    pub observation: ReplyObservation,
}

/// Select replies across a run's journals independently of discovery order.
///
/// Each journal first retains the observation of the current file version. Across
/// journals the greatest (instant, revision, journal directory) wins, including
/// ties and backward clock steps. Receipt access stays with the selected journal.
///
/// # Errors
/// Returns invalid data for a malformed observation in any supplied journal.
pub fn run_reply_observations(
    journals: &BTreeMap<PathBuf, Vec<Value>>,
) -> io::Result<BTreeMap<String, RunReplyObservation>> {
    let mut selected: BTreeMap<String, RunReplyObservation> = BTreeMap::new();
    for (journal, rows) in journals {
        for (name, observation) in reply_observations(rows)? {
            let rank = |row: &Value| {
                (
                    row["at"].as_str().unwrap_or_default().to_owned(),
                    row["revision"].as_u64().unwrap_or_default(),
                )
            };
            let newer = selected.get(&name).is_none_or(|prior| {
                (rank(&observation.row), journal) > (rank(&prior.observation.row), &prior.journal)
            });
            if newer {
                selected.insert(
                    name,
                    RunReplyObservation {
                        journal: journal.clone(),
                        observation,
                    },
                );
            }
        }
    }
    Ok(selected)
}

/// Hash the journal identity's compact JSON serialization for a public receipt name.
///
/// # Errors
/// Returns invalid data unless this is an outbox identity with a nonzero revision.
pub fn reply_observation_key(identity: &Value) -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let parts = identity
        .as_array()
        .filter(|parts| parts.len() == 4)
        .ok_or_else(invalid_record)?;
    if parts[0] != "outbox"
        || parts[1].as_str().is_none_or(str::is_empty)
        || parts[2].as_u64().is_none_or(|revision| revision == 0)
        || parts[3].as_str().is_none_or(str::is_empty)
    {
        return Err(invalid_record());
    }
    let bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect())
}

fn hex_identity(identity: &Value) -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(encoded)
}

fn read_records(path: &Path) -> io::Result<Vec<Value>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut file) => {
            file.read_to_end(&mut bytes)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(invalid_record());
    }
    let records: Vec<Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| invalid_record()))
        .collect::<io::Result<_>>()?;
    for record in &records {
        let box_name = field(record, "box")?;
        let name = field(record, "name")?;
        let at = field(record, "at")?;
        let bytes = record["bytes"].as_u64().ok_or_else(invalid_record)?;
        let revision = record["revision"].as_u64().ok_or_else(invalid_record)?;
        let state = field(record, "state")?;
        if revision == 0
            || !["observed", "complete"].contains(&state)
            || record["emitted"].as_bool().is_none()
            || record["identity"] != json!([box_name, name, revision, at])
            || field(record, "id")? != hex_identity(&record["identity"])?
            || record["bytes"] != bytes
        {
            return Err(invalid_record());
        }
    }
    Ok(records)
}

fn write_records(path: &Path, records: &[Value]) -> io::Result<()> {
    let mut bytes = Vec::new();
    for record in records {
        serde_json::to_writer(&mut bytes, record).map_err(io::Error::other)?;
        bytes.push(b'\n');
    }
    atomic_write(path, &bytes)
}

fn open_absolute_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid_record());
    }
    let root = CString::new("/").expect("static path has no NUL");
    // SAFETY: the terminated root path remains valid for the call.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open transferred one descriptor.
    #[allow(unsafe_code)]
    let mut pinned = unsafe { File::from_raw_fd(raw) };
    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err(invalid_record());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| invalid_record())?;
        // SAFETY: the parent descriptor and terminated component remain valid.
        #[allow(unsafe_code)]
        let raw = unsafe {
            libc::openat(
                pinned.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat transferred one descriptor.
        #[allow(unsafe_code)]
        let next = unsafe { File::from_raw_fd(raw) };
        pinned = next;
    }
    let dot = CString::new(".").expect("static component has no NUL");
    // SAFETY: the pinned directory and terminated component remain valid.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            pinned.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred one descriptor.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn open_child_directory(parent: &File, name: &str) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| invalid_record())?;
    // SAFETY: the pinned parent and terminated child name remain valid.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred one descriptor.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn install_watches(boxes: &mut [Mailbox; 2]) -> Option<OwnedFd> {
    // SAFETY: inotify creates one owned descriptor, closed by OwnedFd on every path.
    #[allow(unsafe_code)]
    let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if raw < 0 {
        return None;
    }
    // SAFETY: the successful syscall transferred ownership of this descriptor.
    #[allow(unsafe_code)]
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    for mailbox in boxes {
        let path = CString::new(format!("/proc/self/fd/{}", mailbox.directory.as_raw_fd())).ok()?;
        // SAFETY: the path is terminated and the inotify descriptor is live.
        #[allow(unsafe_code)]
        let watch = unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), WATCH_MASK) };
        if watch < 0 {
            return None;
        }
        mailbox.watch = watch;
    }
    Some(fd)
}

fn list_entries(directory: &File) -> io::Result<Vec<MailboxEntry>> {
    // SAFETY: duplicating the pinned directory gives fdopendir its own descriptor to close.
    #[allow(unsafe_code)]
    let duplicated = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fdopendir takes ownership of the successful duplicate.
    #[allow(unsafe_code)]
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        // SAFETY: fdopendir did not take ownership on failure.
        #[allow(unsafe_code)]
        unsafe {
            libc::close(duplicated);
        }
        return Err(io::Error::last_os_error());
    }
    // A duplicate shares the directory offset, so every rescan starts at the beginning.
    #[allow(unsafe_code)]
    unsafe {
        libc::rewinddir(stream);
    }
    let mut entries = Vec::new();
    loop {
        // SAFETY: errno and the DIR pointer belong to this single scanning thread.
        #[allow(unsafe_code)]
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                // SAFETY: stream is live and owned here.
                #[allow(unsafe_code)]
                unsafe {
                    libc::closedir(stream);
                }
                return Err(error);
            }
            break;
        }
        // SAFETY: readdir gives a terminated d_name valid until the next call.
        #[allow(unsafe_code)]
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name.first() == Some(&b'.') {
            continue;
        }
        let name_c = CString::new(name).map_err(|_| invalid_record())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstatat reads metadata for this name relative to the pinned directory.
        #[allow(unsafe_code)]
        let status = unsafe {
            libc::fstatat(
                libc::dirfd(stream),
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if status < 0 {
            // SAFETY: stream is live and owned here.
            #[allow(unsafe_code)]
            unsafe {
                libc::closedir(stream);
            }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatat initialized the full stat value.
        #[allow(unsafe_code)]
        let stat = unsafe { stat.assume_init() };
        let kind = match stat.st_mode & libc::S_IFMT {
            libc::S_IFLNK => "link",
            libc::S_IFREG => "file",
            _ => continue,
        };
        entries.push((
            name.to_vec(),
            u64::try_from(stat.st_size).unwrap_or(0),
            kind,
            FileVersion {
                device: stat.st_dev,
                inode: stat.st_ino,
                ctime: stat.st_ctime,
                ctime_nsec: stat.st_ctime_nsec,
            },
        ));
    }
    // SAFETY: stream is live and owned here.
    #[allow(unsafe_code)]
    let close = unsafe { libc::closedir(stream) };
    if close < 0 {
        return Err(io::Error::last_os_error());
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

/// Escape every byte outside the small safe field alphabet, preserving exact names.
#[must_use]
pub fn escape_name(name: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = String::new();
    for &byte in name {
        if byte.is_ascii_alphanumeric() || b"._-".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push('%');
            escaped.push(char::from(HEX[usize::from(byte >> 4)]));
            escaped.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    escaped
}

/// Parse a UTC instant, accepting Z or +00:00 and an optional decimal fraction.
/// Returns None for malformed instants or dates outside 1970 through 9999.
#[must_use]
pub fn parse_utc_instant(value: &str) -> Option<u64> {
    if !value.is_ascii() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let suffix = &value[19..];
    let fraction = suffix.strip_prefix('.');
    let zone = if let Some(fraction) = fraction {
        let end = fraction.find(|ch: char| !ch.is_ascii_digit())?;
        if end == 0 {
            return None;
        }
        &fraction[end..]
    } else {
        suffix
    };
    if zone != "Z" && zone != "+00:00" {
        return None;
    }
    let year = instant_decimal(&value[..4])?;
    let month = instant_decimal(&value[5..7])?;
    let day = instant_decimal(&value[8..10])?;
    let hour = instant_decimal(&value[11..13])?;
    let minute = instant_decimal(&value[14..16])?;
    let second = instant_decimal(&value[17..19])?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        28 + u64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let index = usize::try_from(month - 1).ok()?;
    if day == 0 || day > month_days[index] {
        return None;
    }
    let prior_months: u64 = month_days[..index].iter().sum();
    let days = days_before_year(year) - days_before_year(1970) + prior_months + day - 1;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

const fn days_before_year(year: u64) -> u64 {
    let last = year - 1;
    last * 365 + last / 4 - last / 100 + last / 400
}

fn instant_decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "lane-mailbox-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir(&path).expect("fixture");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.0);
        }
    }

    /// ´claim:lifecycle:reply-observation-key-binds-the-journal-array´
    /// ´test:unit:reply-observation-key-binds-the-journal-array´
    #[test]
    fn reply_observation_key_binds_the_journal_array() {
        let identity = json!(["outbox", "reply.md", 1, "2026-01-01T00:00:01Z"]);
        let first = reply_observation_key(&identity).expect("observation key");
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let parsed: Value =
            serde_json::from_slice(&serde_json::to_vec(&identity).expect("journal serialization"))
                .expect("journal parse");
        assert_eq!(reply_observation_key(&parsed).expect("same key"), first);
        assert_ne!(
            reply_observation_key(&json!(["outbox", "reply.md", 2, "2026-01-01T00:00:02Z"]))
                .expect("new revision"),
            first
        );
        for bad in [
            json!(null),
            json!([]),
            json!(["inbox", "reply.md", 1, "now"]),
            json!(["outbox", "", 1, "now"]),
            json!(["outbox", "reply.md", 0, "now"]),
            json!(["outbox", "reply.md", 1, ""]),
        ] {
            assert!(reply_observation_key(&bad).is_err());
        }
    }

    /// ´claim:lifecycle:shared-reply-version-predicate-retains-legacy-and-ignores-device´
    /// ´test:unit:shared-reply-version-predicate-retains-legacy-and-ignores-device´
    #[test]
    fn shared_reply_version_predicate_retains_legacy_and_ignores_device() {
        assert!(reply_version_matches(&json!({}), 2, 3, 4).expect("legacy row"));
        let mut row = json!({"file_version":{"device":1,"inode":2,"ctime":3,"ctime_nsec":4}});
        assert!(reply_version_matches(&row, 2, 3, 4).expect("same version"));
        row["file_version"]["device"] = json!(9);
        assert!(reply_version_matches(&row, 2, 3, 4).expect("renumbered device"));
        for (inode, ctime, ctime_nsec) in [(7, 3, 4), (2, 7, 4), (2, 3, 7)] {
            assert!(
                !reply_version_matches(&row, inode, ctime, ctime_nsec).expect("changed version")
            );
        }
        row["file_version"]["ctime_nsec"] = json!(-1);
        assert!(reply_version_matches(&row, 2, 3, 4).is_err());
    }

    /// ´claim:lifecycle:reply-version-key-keeps-completion-and-rejects-malformed-versions´
    /// ´test:unit:reply-version-key-keeps-completion-and-rejects-malformed-versions´
    #[test]
    fn reply_version_key_keeps_completion_and_rejects_malformed_versions() {
        let first = json!({"box":"outbox","kind":"file","name":"reply.md","bytes":5,
            "state":"observed","revision":1,"at":"2026-01-01T00:00:01Z",
            "identity":["outbox","reply.md",1,"2026-01-01T00:00:01Z"]});
        let mut complete = first.clone();
        complete["state"] = json!("complete");
        complete["revision"] = json!(2);
        complete["identity"][2] = json!(2);
        let records =
            reply_observations(&[first.clone(), complete.clone()]).expect("legacy completion");
        assert_eq!(records["reply.md"].row, first);
        complete["file_version"] = json!({"device":1,"inode":2,"ctime":3,"ctime_nsec":4});
        let records =
            reply_observations(&[first.clone(), complete.clone()]).expect("new measured version");
        assert_eq!(records["reply.md"].row, complete);
        for (field, bad) in [
            ("file_version", json!({})),
            ("bytes", json!(null)),
            ("revision", json!(0)),
            ("identity", json!([])),
        ] {
            let mut row = first.clone();
            row[field] = bad;
            assert!(reply_observations(&[row]).is_err());
        }
        for (field, bad) in [
            ("device", json!(-1)),
            ("inode", json!(null)),
            ("ctime", json!("invalid")),
            ("ctime_nsec", json!(-1)),
            ("ctime_nsec", json!(1_000_000_000)),
        ] {
            let mut row = complete.clone();
            row["file_version"][field] = bad;
            assert!(reply_observations(&[row]).is_err());
        }
    }

    /// ´claim:lifecycle:real-watcher-observes-same-size-replacement-after-completion´
    /// ´test:unit:real-watcher-observes-same-size-replacement-after-completion´
    #[test]
    fn real_watcher_observes_same_size_replacement_after_completion() {
        let fixture = Fixture::new("same-size-version");
        let local = fixture.path().join(".local");
        std::fs::create_dir_all(local.join("inbox")).expect("inbox");
        let outbox = local.join("outbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        std::fs::write(outbox.join("reply.md"), b"first").expect("reply");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "work").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("observe");
        let first = reply_observations(&read_records(&run.join(LETTERS_FILE)).expect("journal"))
            .expect("key")["reply.md"]
            .key
            .clone();
        watcher.finish(&mut Vec::new()).expect("complete");
        drop(watcher);
        let mut watcher =
            MailboxWatcher::new(fixture.path(), &run, "work").expect("restart restores versions");
        watcher.poll(&mut Vec::new()).expect("no duplicate");
        let complete = read_records(&run.join(LETTERS_FILE)).expect("complete journal");
        assert_eq!(complete.len(), 2);
        assert_eq!(
            reply_observations(&complete).expect("completion key")["reply.md"].key,
            first
        );
        std::fs::write(outbox.join(".tmp-reply"), b"other").expect("same size replacement");
        std::fs::rename(outbox.join(".tmp-reply"), outbox.join("reply.md"))
            .expect("atomic publication");
        watcher.poll(&mut Vec::new()).expect("replacement");
        let records = read_records(&run.join(LETTERS_FILE)).expect("replacement journal");
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["revision"], 2);
        assert_ne!(records[0]["file_version"], records[2]["file_version"]);
        assert_ne!(
            reply_observations(&records).expect("replacement key")["reply.md"].key,
            first
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(outbox.join("reply.md"), b"third").expect("same inode same size write");
        watcher.poll(&mut Vec::new()).expect("ctime change");
        let updated = read_records(&run.join(LETTERS_FILE)).expect("ctime journal");
        assert_eq!(updated.len(), 4);
        assert_eq!(updated[3]["revision"], 3);
        assert_eq!(
            updated[2]["file_version"]["inode"],
            updated[3]["file_version"]["inode"]
        );
        assert_ne!(updated[2]["file_version"], updated[3]["file_version"]);
        assert_ne!(
            reply_observations(&updated).expect("ctime key")["reply.md"].key,
            reply_observations(&records).expect("prior key")["reply.md"].key
        );
    }

    /// ´claim:lifecycle:watcher-restart-ignores-recorded-device-number´
    /// ´test:unit:watcher-restart-ignores-recorded-device-number´
    #[test]
    fn watcher_restart_ignores_recorded_device_number() {
        let fixture = Fixture::new("device-renumbering");
        let local = fixture.path().join(".local");
        for mailbox in ["inbox", "outbox"] {
            std::fs::create_dir_all(local.join(mailbox)).expect("mailbox");
            std::fs::write(local.join(mailbox).join("letter.md"), b"letter").expect("letter");
        }
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "work").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("first observations");
        drop(watcher);
        let journal = run.join(LETTERS_FILE);
        let mut records = read_records(&journal).expect("journal");
        let key = reply_observations(&records).expect("first key")["letter.md"]
            .key
            .clone();
        for row in &mut records {
            row["file_version"]["device"] =
                json!(row["file_version"]["device"].as_u64().expect("device") ^ 1);
        }
        write_records(&journal, &records).expect("previous mount's devices");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "work").expect("restart");
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("same versions");
        assert_eq!(output, Vec::<u8>::new());
        assert_eq!(read_records(&journal).expect("no new row"), records);
        assert_eq!(
            reply_observations(&records).expect("unchanged key")["letter.md"].key,
            key
        );
        watcher
            .finish(&mut Vec::new())
            .expect("completion with current device");
        let completed = read_records(&journal).expect("completion row");
        assert_eq!(completed.len(), 3);
        assert_ne!(
            completed[1]["file_version"]["device"],
            completed[2]["file_version"]["device"]
        );
        assert_eq!(
            reply_observations(&completed).expect("resolver ignores device")["letter.md"].key,
            key
        );
    }

    /// ´claim:lifecycle:legacy-mailbox-rows-are-reobserved-once´
    /// ´test:unit:legacy-mailbox-rows-are-reobserved-once´
    #[test]
    fn legacy_mailbox_rows_are_reobserved_once() {
        let fixture = Fixture::new("legacy-version");
        let local = fixture.path().join(".local");
        std::fs::create_dir_all(local.join("inbox")).expect("inbox");
        std::fs::create_dir(local.join("outbox")).expect("outbox");
        std::fs::write(local.join("outbox/reply.md"), b"reply").expect("reply");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "work").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("observe");
        drop(watcher);
        let journal = run.join(LETTERS_FILE);
        let mut rows = read_records(&journal).expect("rows");
        rows[0]
            .as_object_mut()
            .expect("object")
            .remove("file_version");
        let old_key = reply_observations(&rows).expect("legacy key")["reply.md"]
            .key
            .clone();
        write_records(&journal, &rows).expect("legacy journal");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "work").expect("new watcher");
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("first measured version");
        assert_eq!(String::from_utf8(output).expect("line").lines().count(), 1);
        let measured = read_records(&journal).expect("measured journal");
        assert_eq!(measured.len(), 2);
        assert_ne!(
            reply_observations(&measured).expect("measured key")["reply.md"].key,
            old_key
        );
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("already measured");
        assert_eq!(output, Vec::<u8>::new());
    }

    /// ´claim:lifecycle:escaped-names-keep-one-parseable-line-and-exact-bytes´
    /// ´test:unit:escaped-names-keep-one-parseable-line-and-exact-bytes´
    #[test]
    fn escaped_names_keep_one_parseable_line_and_exact_bytes() {
        for name in [
            b"a\nb".as_slice(),
            b"a b",
            b"a%b",
            b"a=b",
            b"a\x01b",
            b"a\xffb",
        ] {
            let escaped = escape_name(name);
            assert!(!escaped.contains(['\n', ' ', '=']));
            let line = format!(
                "LETTER box=inbox name={escaped} bytes=2 at=2026-10-07T00:00:00Z state=complete revision=1 id=ABC\n"
            );
            assert_eq!(line.lines().count(), 1);
            assert_eq!(line.split_ascii_whitespace().count(), 8);
            assert_eq!(
                line.split_ascii_whitespace().nth(2),
                Some(format!("name={escaped}").as_str())
            );
            let mut recovered = Vec::new();
            let mut bytes = escaped.as_bytes().iter().copied();
            while let Some(byte) = bytes.next() {
                if byte == b'%' {
                    let high = bytes.next().expect("high digit");
                    let low = bytes.next().expect("low digit");
                    recovered.push(
                        u8::try_from(char::from(high).to_digit(16).expect("hex")).expect("nibble")
                            * 16
                            + u8::try_from(char::from(low).to_digit(16).expect("hex"))
                                .expect("nibble"),
                    );
                } else {
                    recovered.push(byte);
                }
            }
            assert_eq!(recovered, name);
        }
    }

    /// ´claim:lifecycle:scan-does-not-follow-mailbox-link-and-restart-deduplicates´
    /// ´test:unit:scan-does-not-follow-mailbox-link-and-restart-deduplicates´
    #[test]
    fn scan_does_not_follow_mailbox_link_and_restart_deduplicates() {
        let fixture = std::env::temp_dir().join(format!(
            "lane-mailbox-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&fixture).expect("fixture");
        let local = fixture.join(".local");
        std::fs::create_dir_all(local.join("inbox")).expect("inbox");
        std::fs::create_dir_all(local.join("outbox")).expect("outbox");
        std::fs::write(fixture.join("secret"), b"private bytes").expect("target");
        std::os::unix::fs::symlink(fixture.join("secret"), local.join("inbox/link.md"))
            .expect("link");
        std::fs::write(local.join("inbox/dispatch.md"), b"brief").expect("letter");
        let run = fixture.join("run");
        std::fs::create_dir(&run).expect("run");
        let mut first = MailboxWatcher::new(&fixture, &run, "dispatch").expect("watcher");
        let mut output = Vec::new();
        first.poll(&mut output).expect("first scan");
        let records = read_records(&run.join(LETTERS_FILE)).expect("records");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .find(|record| record["name"] == "link.md")
                .expect("link")["kind"],
            "link"
        );
        assert_eq!(
            records
                .iter()
                .find(|record| record["name"] == "link.md")
                .expect("link")["bytes"],
            fixture.join("secret").as_os_str().len()
        );
        let mut restarted = MailboxWatcher::new(&fixture, &run, "dispatch").expect("restart");
        let mut after = Vec::new();
        restarted.poll(&mut after).expect("reconcile");
        assert_eq!(after, Vec::<u8>::new());
        assert_eq!(
            std::fs::read(fixture.join("secret")).expect("unchanged"),
            b"private bytes"
        );
        std::fs::remove_dir_all(&fixture).expect("remove fixture");
    }

    /// ´claim:lifecycle:close-rename-and-restart-rescan-observe-completed-names´
    /// ´test:unit:close-rename-and-restart-rescan-observe-completed-names´
    #[test]
    fn close_rename_and_restart_rescan_observe_completed_names() {
        let fixture = std::env::temp_dir().join(format!(
            "lane-mailbox-events-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let inbox = fixture.join(".local/inbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(fixture.join(".local/outbox")).expect("outbox");
        let run = fixture.join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(&fixture, &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("initial scan");
        let staging = inbox.join(".placing-closed");
        let mut open = std::fs::File::create(&staging).expect("open staging file");
        open.write_all(b"one").expect("write file");
        let mut premature = Vec::new();
        watcher.poll(&mut premature).expect("open scan one");
        watcher.poll(&mut premature).expect("open scan two");
        assert_eq!(premature, Vec::<u8>::new());
        drop(open);
        std::fs::rename(staging, inbox.join("closed.md")).expect("publish letter");
        let mut close_lines = Vec::new();
        watcher.poll(&mut close_lines).expect("close event");
        assert!(
            String::from_utf8(close_lines)
                .expect("line")
                .contains("name=closed.md bytes=3")
        );
        std::fs::write(fixture.join("staged"), b"two").expect("staged file");
        std::fs::rename(fixture.join("staged"), inbox.join("renamed.md")).expect("rename");
        let mut rename_lines = Vec::new();
        watcher.poll(&mut rename_lines).expect("rename event");
        let renamed = String::from_utf8(rename_lines).expect("line");
        assert!(renamed.contains("name=renamed.md bytes=3"));
        assert!(renamed.contains("state=complete"));
        watcher.inotify = None;
        std::fs::write(fixture.join(".local/outbox/rescanned.md"), b"three")
            .expect("fallback file");
        let mut fallback = Vec::new();
        watcher.poll(&mut fallback).expect("first fallback scan");
        assert!(String::from_utf8_lossy(&fallback).contains("state=observed revision=1"));
        fallback.clear();
        watcher.poll(&mut fallback).expect("second fallback scan");
        assert_eq!(fallback, Vec::<u8>::new());
        watcher.finish(&mut fallback).expect("child exited");
        assert!(String::from_utf8_lossy(&fallback).contains("name=rescanned.md bytes=5"));
        assert!(String::from_utf8_lossy(&fallback).contains("state=complete revision=1"));
        let mut restarted = MailboxWatcher::new(&fixture, &run, "dispatch").expect("restart");
        let mut after = Vec::new();
        restarted.poll(&mut after).expect("restart rescan");
        assert_eq!(after, Vec::<u8>::new());
        std::fs::remove_dir_all(fixture).expect("remove fixture");
    }

    /// ´claim:lifecycle:quick-outbox-writer-is-observed-then-completed-at-round-end´
    /// ´test:unit:quick-outbox-writer-is-observed-then-completed-at-round-end´
    #[test]
    fn quick_outbox_writer_is_observed_then_completed_at_round_end() {
        let fixture = Fixture::new("quick-outbox");
        let inbox = fixture.path().join(".local/inbox");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher =
            MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher before child");
        watcher.poll(&mut Vec::new()).expect("pre-child scan");
        let mut writer = std::fs::File::create(outbox.join("dispatch.md")).expect("quick writer");
        writer.write_all(b"first").expect("first write");
        let mut lines = Vec::new();
        watcher.poll(&mut lines).expect("first active scan");
        assert!(String::from_utf8_lossy(&lines).contains("bytes=5"));
        assert!(String::from_utf8_lossy(&lines).contains("state=observed revision=1"));
        lines.clear();
        watcher.poll(&mut lines).expect("second active scan");
        assert_eq!(lines, Vec::<u8>::new());
        writer.write_all(b" second").expect("growth before close");
        watcher.poll(&mut lines).expect("growth scan");
        assert!(String::from_utf8_lossy(&lines).contains("bytes=12"));
        assert!(String::from_utf8_lossy(&lines).contains("state=observed revision=2"));
        lines.clear();
        drop(writer);
        watcher.poll(&mut lines).expect("close scan");
        assert_eq!(lines, Vec::<u8>::new());
        watcher.poll(&mut Vec::new()).expect("steady scan");
        let mut complete = Vec::new();
        watcher.finish(&mut complete).expect("child exited");
        assert!(String::from_utf8_lossy(&complete).contains("state=complete revision=2"));
        let records = read_records(&run.join(LETTERS_FILE)).expect("production journal");
        assert_eq!(records.len(), 3);
        assert_eq!(records[1]["bytes"], records[2]["bytes"]);
        assert_eq!(records[1]["file_version"], records[2]["file_version"]);
        assert_ne!(records[1]["id"], records[2]["id"]);
        let selected = run_reply_observations(&BTreeMap::from([(run, records)]))
            .expect("shared watcher and read-reply selection");
        let reply = &selected["dispatch.md"].observation.row;
        assert_eq!(reply["revision"], 2);
        assert_eq!(reply["state"], "observed");
    }

    /// ´claim:lifecycle:coalesced-opens-revise-observation-and-complete-at-round-end´
    /// ´test:unit:coalesced-opens-revise-observation-and-complete-at-round-end´
    #[test]
    fn coalesced_opens_revise_observation_and_complete_at_round_end() {
        let fixture = Fixture::new("overlapping-writers");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(fixture.path().join(".local/inbox")).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("pre-child scan");
        let mut first = std::fs::File::create(outbox.join("review-1.md")).expect("first writer");
        let mut second = std::fs::OpenOptions::new()
            .append(true)
            .open(outbox.join("review-1.md"))
            .expect("second writer");
        first.write_all(b"first").expect("first write");
        let _ignored = watcher.drain_events().expect("coalesced or missed opens");
        drop(first);
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("first close");
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=1"));
        second.write_all(b" second").expect("later growth");
        output.clear();
        watcher
            .poll(&mut output)
            .expect("growth through second writer");
        assert!(String::from_utf8_lossy(&output).contains("bytes=12"));
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=2"));
        drop(second);
        output.clear();
        watcher.poll(&mut output).expect("last close");
        assert_eq!(output, Vec::<u8>::new());
        watcher.finish(&mut output).expect("worker exited");
        assert!(String::from_utf8_lossy(&output).contains("state=complete revision=2"));
        assert_eq!(watcher.count(), 3);
    }

    /// ´claim:lifecycle:reader-close-does-not-complete-an-open-writer´
    /// ´test:unit:reader-close-does-not-complete-an-open-writer´
    #[test]
    fn reader_close_does_not_complete_an_open_writer() {
        let fixture = Fixture::new("reader-overlap");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(fixture.path().join(".local/inbox")).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("pre-child scan");
        let mut writer = std::fs::File::create(outbox.join("review-1.md")).expect("writer");
        writer.write_all(b"first").expect("first write");
        let reader = std::fs::File::open(outbox.join("review-1.md")).expect("reader");
        let mut first = Vec::new();
        watcher.poll(&mut first).expect("both opens");
        assert!(String::from_utf8_lossy(&first).contains("state=observed revision=1"));
        drop(reader);
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("reader close-nowrite");
        assert_eq!(output, Vec::<u8>::new());
        writer.write_all(b" second").expect("writer continues");
        watcher.poll(&mut output).expect("writer remains open");
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=2"));
        output.clear();
        drop(writer);
        watcher.poll(&mut output).expect("writer close-write");
        assert_eq!(output, Vec::<u8>::new());
        output.clear();
        watcher.finish(&mut output).expect("worker exited");
        assert!(String::from_utf8_lossy(&output).contains("state=complete"));
    }

    /// ´claim:lifecycle:reopened-writer-revises-earlier-close-observation´
    /// ´test:unit:reopened-writer-revises-earlier-close-observation´
    #[test]
    fn reopened_writer_revises_earlier_close_observation() {
        let fixture = Fixture::new("reopened-writer");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(fixture.path().join(".local/inbox")).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("pre-child scan");
        std::fs::write(outbox.join("review-1.md"), b"first").expect("first close");
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(outbox.join("review-1.md"))
            .expect("reopen");
        let mut observed = Vec::new();
        watcher.poll(&mut observed).expect("old close and new open");
        assert!(String::from_utf8_lossy(&observed).contains("state=observed revision=1"));
        writer.write_all(b" second").expect("growth");
        observed.clear();
        watcher
            .poll(&mut observed)
            .expect("old close and new modify");
        assert!(String::from_utf8_lossy(&observed).contains("state=observed revision=2"));
        drop(writer);
        observed.clear();
        watcher.poll(&mut observed).expect("final close");
        assert_eq!(observed, Vec::<u8>::new());
        watcher.finish(&mut observed).expect("worker exited");
        assert!(String::from_utf8_lossy(&observed).contains("state=complete revision=2"));
    }

    /// ´claim:lifecycle:unemitted-durable-letter-replays-after-restart´
    /// ´test:unit:unemitted-durable-letter-replays-after-restart´
    #[test]
    fn unemitted_durable_letter_replays_after_restart() {
        struct RefusingOutput;
        impl io::Write for RefusingOutput {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("output interrupted"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let fixture = Fixture::new("emitted");
        let inbox = fixture.path().join(".local/inbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(fixture.path().join(".local/outbox")).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        std::fs::write(inbox.join("dispatch.md"), b"brief").expect("letter");
        let mut first = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        first
            .poll(&mut RefusingOutput)
            .expect_err("line write fails after record");
        let records = read_records(&run.join(LETTERS_FILE)).expect("durable record");
        assert_eq!(records[0]["emitted"], false);
        let mut restarted = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("restart");
        let mut output = Vec::new();
        restarted.poll(&mut output).expect("reemit");
        assert!(String::from_utf8_lossy(&output).contains(" replay=1\n"));
        assert_eq!(
            read_records(&run.join(LETTERS_FILE)).expect("record")[0]["emitted"],
            true
        );
        let mut after = Vec::new();
        restarted.poll(&mut after).expect("steady");
        assert_eq!(after, Vec::<u8>::new());
    }

    /// ´claim:lifecycle:flushed-letter-restart-replays-with-one-durable-identity´
    /// ´test:unit:flushed-letter-restart-replays-with-one-durable-identity´
    #[test]
    fn flushed_letter_restart_replays_with_one_durable_identity() {
        #[derive(Default)]
        struct FlushInterrupted(Vec<u8>);
        impl io::Write for FlushInterrupted {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("interrupted after stdout write"))
            }
        }
        let fixture = Fixture::new("flush-interrupted");
        let inbox = fixture.path().join(".local/inbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(fixture.path().join(".local/outbox")).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        std::fs::write(inbox.join("dispatch.md"), b"brief").expect("letter");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        let mut first = FlushInterrupted::default();
        watcher.poll(&mut first).expect_err("flush interrupted");
        assert!(String::from_utf8_lossy(&first.0).contains(" id="));
        let mut restarted = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("restart");
        let mut replay = Vec::new();
        restarted.poll(&mut replay).expect("replay");
        assert!(String::from_utf8_lossy(&replay).contains(" replay=1\n"));
        assert_eq!(
            read_records(&run.join(LETTERS_FILE))
                .expect("durable")
                .len(),
            1
        );
        let mut after = Vec::new();
        restarted.poll(&mut after).expect("steady");
        assert_eq!(after, Vec::<u8>::new());
    }

    /// ´claim:lifecycle:overflow-rearm-never-completes-an-unseen-open-writer´
    /// ´test:unit:overflow-rearm-never-completes-an-unseen-open-writer´
    #[test]
    fn overflow_rearm_never_completes_an_unseen_open_writer() {
        let fixture = Fixture::new("overflow");
        let inbox = fixture.path().join(".local/inbox");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("initial scan");
        let mut writer = std::fs::File::create(outbox.join("missed.md")).expect("letter");
        writer.write_all(b"partial").expect("first write");
        let _ignored = watcher
            .drain_events()
            .expect("discard simulated lost events");
        watcher.handle_event(-1, libc::IN_Q_OVERFLOW, b"", &mut BTreeSet::new());
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("overflow rescan");
        assert!(String::from_utf8_lossy(&output).contains("name=missed.md bytes=7"));
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=1"));
        output.clear();
        watcher.poll(&mut output).expect("second overflow rescan");
        assert_eq!(output, Vec::<u8>::new());
        writer.write_all(b" complete").expect("later growth");
        watcher.poll(&mut output).expect("growth remains pending");
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=2"));
        output.clear();
        std::os::unix::fs::symlink("target", inbox.join("link.md")).expect("new link");
        let mut link = Vec::new();
        watcher.poll(&mut link).expect("link scan without close");
        assert!(String::from_utf8_lossy(&link).contains("name=link.md"));
        assert!(String::from_utf8_lossy(&link).contains("state=observed"));
        assert!(!String::from_utf8_lossy(&link).contains("name=missed.md"));
        drop(writer);
        let mut finished = Vec::new();
        watcher.finish(&mut finished).expect("child exited");
        assert!(String::from_utf8_lossy(&finished).contains("name=missed.md bytes=16"));
        assert!(
            read_records(&run.join(LETTERS_FILE))
                .expect("records")
                .iter()
                .any(|record| record["kind"] == "link")
        );
    }

    /// ´claim:lifecycle:fallback-open-writer-is-observed-and-revised-before-final-scan´
    /// ´test:unit:fallback-open-writer-is-observed-and-revised-before-final-scan´
    #[test]
    fn fallback_open_writer_is_observed_and_revised_before_final_scan() {
        let fixture = Fixture::new("fallback-open");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir_all(fixture.path().join(".local/inbox")).expect("inbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("pre-child scan");
        watcher.inotify = None;
        let mut writer = std::fs::File::create(outbox.join("review-1.md")).expect("writer");
        writer.write_all(b"partial").expect("first write");
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("first fallback scan");
        assert!(String::from_utf8_lossy(&output).contains("bytes=7"));
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=1"));
        output.clear();
        watcher.poll(&mut output).expect("second fallback scan");
        assert_eq!(output, Vec::<u8>::new());
        writer.write_all(b" complete").expect("later growth");
        watcher
            .poll(&mut output)
            .expect("growth changes the observation");
        assert!(String::from_utf8_lossy(&output).contains("bytes=16"));
        assert!(String::from_utf8_lossy(&output).contains("state=observed revision=2"));
        assert_eq!(watcher.count(), 2);
        assert_eq!(
            std::fs::read_to_string(run.join("mailbox-state.json")).expect("watcher state"),
            "{\"observation\":\"inbox-complete-outbox-sight-final-complete\"}\n"
        );
        drop(writer);
        output.clear();
        watcher.finish(&mut output).expect("child exited");
        assert!(String::from_utf8_lossy(&output).contains("name=review-1.md bytes=16"));
        assert!(String::from_utf8_lossy(&output).contains("state=complete revision=2"));
        assert_eq!(watcher.count(), 3);
    }

    /// ´claim:lifecycle:mailbox-directories-are-not-regular-letters´
    /// ´test:unit:mailbox-directories-are-not-regular-letters´
    #[test]
    fn mailbox_directories_are_not_regular_letters() {
        let fixture = Fixture::new("nonregular");
        for box_name in ["inbox", "outbox"] {
            let directory = fixture.path().join(".local").join(box_name);
            std::fs::create_dir_all(directory.join("review.md"))
                .expect("directory named as letter");
        }
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "review").expect("watcher");
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("in-round scan");
        watcher.finish(&mut output).expect("final scan");
        assert_eq!(output, Vec::<u8>::new());
        assert_eq!(
            read_records(&run.join(LETTERS_FILE)).expect("records"),
            Vec::<Value>::new()
        );
    }

    /// ´claim:lifecycle:inbox-sight-completes-after-fallback-and-lost-rename´
    /// ´test:unit:inbox-sight-completes-after-fallback-and-lost-rename´
    #[test]
    fn inbox_sight_completes_after_fallback_and_lost_rename() {
        for lost_rename in [false, true] {
            let fixture = Fixture::new("inbox-sight");
            let inbox = fixture.path().join(".local/inbox");
            std::fs::create_dir_all(&inbox).expect("inbox");
            std::fs::create_dir(fixture.path().join(".local/outbox")).expect("outbox");
            let run = fixture.path().join("run");
            std::fs::create_dir(&run).expect("run");
            let mut watcher = MailboxWatcher::new(fixture.path(), &run, "review").expect("watcher");
            watcher.poll(&mut Vec::new()).expect("first scan");
            if !lost_rename {
                watcher.inotify = None;
            }
            let staging = inbox.join(".placing-review");
            std::fs::write(&staging, b"letter").expect("staging");
            std::fs::rename(&staging, inbox.join("review-1.md")).expect("publication");
            if lost_rename {
                let _lost = watcher.drain_events().expect("lost rename event");
                watcher.handle_event(-1, libc::IN_Q_OVERFLOW, b"", &mut BTreeSet::new());
            }
            let mut output = Vec::new();
            watcher.poll(&mut output).expect("sight scan");
            let line = String::from_utf8(output).expect("line");
            assert!(line.contains("name=review-1.md bytes=6"));
            assert!(line.contains("state=complete revision=1"));
            assert_eq!(watcher.count(), 1);
        }
    }

    /// ´claim:lifecycle:outbox-rename-while-open-remains-an-observation´
    /// ´test:unit:outbox-rename-while-open-remains-an-observation´
    #[test]
    fn outbox_rename_while_open_remains_an_observation() {
        let fixture = Fixture::new("outbox-rename");
        std::fs::create_dir_all(fixture.path().join(".local/inbox")).expect("inbox");
        let outbox = fixture.path().join(".local/outbox");
        std::fs::create_dir(&outbox).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "review").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("first scan");
        let staging = outbox.join(".draft");
        let mut writer = std::fs::File::create(&staging).expect("worker writer");
        writer.write_all(b"part").expect("first bytes");
        std::fs::rename(&staging, outbox.join("review-1.md")).expect("worker rename");
        let mut first = Vec::new();
        watcher.poll(&mut first).expect("rename observation");
        assert!(String::from_utf8_lossy(&first).contains("bytes=4"));
        assert!(String::from_utf8_lossy(&first).contains("state=observed revision=1"));
        writer.write_all(b" complete").expect("later bytes");
        let mut revised = Vec::new();
        watcher.poll(&mut revised).expect("growth observation");
        assert!(String::from_utf8_lossy(&revised).contains("bytes=13"));
        assert!(String::from_utf8_lossy(&revised).contains("state=observed revision=2"));
        drop(writer);
        let mut complete = Vec::new();
        watcher.finish(&mut complete).expect("child exited");
        assert!(String::from_utf8_lossy(&complete).contains("state=complete revision=2"));
    }

    /// ´claim:lifecycle:hidden-staging-file-at-child-exit-is-not-a-letter´
    /// ´test:unit:hidden-staging-file-at-child-exit-is-not-a-letter´
    #[test]
    fn hidden_staging_file_at_child_exit_is_not_a_letter() {
        let fixture = Fixture::new("staging");
        let inbox = fixture.path().join(".local/inbox");
        std::fs::create_dir_all(&inbox).expect("inbox");
        std::fs::create_dir(fixture.path().join(".local/outbox")).expect("outbox");
        let run = fixture.path().join("run");
        std::fs::create_dir(&run).expect("run");
        let mut watcher = MailboxWatcher::new(fixture.path(), &run, "dispatch").expect("watcher");
        watcher.poll(&mut Vec::new()).expect("before child");
        let staged = inbox.join(".placing-1");
        let mut writer = std::fs::File::create(&staged).expect("owner staging file");
        writer.write_all(b"partial").expect("partial letter");
        let mut output = Vec::new();
        watcher.finish(&mut output).expect("worker child exited");
        assert_eq!(output, Vec::<u8>::new());
        assert_eq!(
            read_records(&run.join(LETTERS_FILE)).expect("records"),
            Vec::<Value>::new()
        );
        writer
            .write_all(b" complete")
            .expect("complete owner write");
        drop(writer);
        std::fs::rename(staged, inbox.join("review-1.md")).expect("owner publication");
        watcher.poll(&mut output).expect("rename publication");
        assert!(String::from_utf8_lossy(&output).contains("name=review-1.md bytes=16"));
        assert!(String::from_utf8_lossy(&output).contains("state=complete"));
        assert_eq!(watcher.count(), 1);
    }

    /// ´claim:lifecycle:mailbox-ancestor-links-refuse-before-listing´
    /// ´test:unit:mailbox-ancestor-links-refuse-before-listing´
    #[test]
    fn mailbox_ancestor_links_refuse_before_listing() {
        for level in ["local", "inbox", "outbox"] {
            let fixture = Fixture::new(level);
            let actual = fixture.path().join("actual");
            std::fs::create_dir_all(actual.join("inbox")).expect("inbox");
            std::fs::create_dir(actual.join("outbox")).expect("outbox");
            if level == "local" {
                std::os::unix::fs::symlink(&actual, fixture.path().join(".local"))
                    .expect("linked local");
            } else {
                let local = fixture.path().join(".local");
                std::fs::create_dir(&local).expect("local");
                if level == "inbox" {
                    std::os::unix::fs::symlink(actual.join("inbox"), local.join("inbox"))
                        .expect("linked inbox");
                    std::fs::create_dir(local.join("outbox")).expect("outbox");
                } else {
                    std::fs::create_dir(local.join("inbox")).expect("inbox");
                    std::os::unix::fs::symlink(actual.join("outbox"), local.join("outbox"))
                        .expect("linked outbox");
                }
            }
            let run = fixture.path().join("run");
            std::fs::create_dir(&run).expect("run");
            assert!(MailboxWatcher::new(fixture.path(), &run, "dispatch").is_err());
        }
    }

    /// ´claim:lifecycle:recorded-plan-selects-host-home-through-pinned-directories´
    /// ´test:unit:recorded-plan-selects-host-home-through-pinned-directories´
    #[test]
    fn recorded_plan_selects_host_home_through_pinned_directories() {
        let fixture = Fixture::new("plan");
        let home = fixture.path().join("home-R");
        std::fs::create_dir_all(home.join(".local/inbox")).expect("inbox");
        std::fs::create_dir(home.join(".local/outbox")).expect("outbox");
        std::fs::set_permissions(
            home.join(".local/outbox"),
            std::fs::Permissions::from_mode(0o750),
        )
        .expect("outbox mode");
        std::fs::write(home.join(".local/inbox/dispatch.md"), b"brief").expect("letter");
        let run = fixture.path().join("runs/R");
        std::fs::create_dir_all(&run).expect("driver directory");
        let meta = std::fs::metadata(&home).expect("home metadata");
        let plan = json!({"driver_dir":run,"home":home,"worker_uid":effective_uid(),"paths":[{"path":home,"uid":meta.uid(),"gid":meta.gid(),"mode":format!("{:04o}",meta.mode() & 0o7777)}]});
        std::fs::write(
            run.join("plan.json"),
            serde_json::to_vec(&plan).expect("plan"),
        )
        .expect("recorded plan");
        std::fs::set_permissions(
            run.join("plan.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("plan mode");
        let step = run.join("20261007T043545Z-dispatch");
        std::fs::create_dir(&step).expect("step directory");
        let mut watcher = MailboxWatcher::for_round(&step, "dispatch")
            .expect("plan read")
            .expect("boxed watcher");
        let mut output = Vec::new();
        watcher.poll(&mut output).expect("observed letter");
        assert!(String::from_utf8_lossy(&output).contains("name=dispatch.md"));
        std::fs::set_permissions(
            home.join(".local/outbox"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("old outbox mode");
        let old = MailboxWatcher::for_round(&step, "dispatch")
            .err()
            .expect("old mode refuses");
        assert!(old.to_string().contains("mailbox-access:"));
        assert!(old.to_string().contains("mode=0700"));
        std::fs::set_permissions(
            home.join(".local/outbox"),
            std::fs::Permissions::from_mode(0o750),
        )
        .expect("restore outbox mode");
        let linked = fixture.path().join("linked-home");
        std::os::unix::fs::symlink(&home, &linked).expect("home link");
        let mut changed = plan;
        changed["home"] = json!(linked);
        std::fs::write(
            run.join("plan.json"),
            serde_json::to_vec(&changed).expect("plan"),
        )
        .expect("changed plan");
        assert!(MailboxWatcher::for_round(&step, "dispatch").is_err());
    }

    /// ´claim:lifecycle:group-listable-outbox-exposes-names-and-sizes-with-private-files´
    /// ´test:unit:group-listable-outbox-exposes-names-and-sizes-with-private-files´
    #[test]
    fn group_listable_outbox_exposes_names_and_sizes_with_private_files() {
        let fixture = Fixture::new("group-outbox");
        let local = fixture.path().join(".local");
        std::fs::create_dir(&local).expect("local");
        let outbox = local.join("outbox");
        std::fs::create_dir(&outbox).expect("outbox");
        std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(0o750))
            .expect("group-listable directory");
        let reply = outbox.join("dispatch.md");
        std::fs::write(&reply, b"private reply").expect("reply");
        std::fs::set_permissions(&reply, std::fs::Permissions::from_mode(0o600))
            .expect("private reply mode");
        let pinned = open_absolute_directory(fixture.path()).expect("home descriptor");
        let local = open_child_directory(&pinned, ".local").expect("local descriptor");
        let directory = open_verified_outbox(
            &local,
            fixture.path(),
            effective_uid(),
            pinned.metadata().expect("home metadata").gid(),
        )
        .expect("directory metadata");
        assert_eq!(
            list_entries(&directory)
                .expect("names and sizes")
                .into_iter()
                .map(|(name, bytes, kind, _)| (name, bytes, kind))
                .collect::<Vec<_>>(),
            vec![(b"dispatch.md".to_vec(), 13, "file")]
        );
        let directory_mode = std::fs::metadata(&outbox).expect("outbox metadata").mode() & 0o777;
        let file_mode = std::fs::metadata(&reply).expect("reply metadata").mode() & 0o777;
        assert_eq!(directory_mode & 0o070, 0o050);
        assert_eq!(file_mode & 0o070, 0);
    }
    /// ´claim:lifecycle:run-reply-selection-orders-instant-revision-and-directory´
    /// ´test:unit:run-reply-selection-orders-instant-revision-and-directory´
    #[test]
    fn run_reply_selection_orders_instant_revision_and_directory() {
        let make = |revision, at| {
            json!({"box":"outbox","kind":"file","name":"reply.md",
            "revision":revision,"at":at,"bytes":5,"state":"observed",
            "identity":["outbox","reply.md",revision,at]})
        };
        let mut journals = BTreeMap::from([
            (
                PathBuf::from("first"),
                vec![make(2, "2026-01-01T00:00:02Z")],
            ),
            (
                PathBuf::from("second"),
                vec![make(1, "2026-01-01T00:00:02Z")],
            ),
        ]);
        let select = |journals: &BTreeMap<PathBuf, Vec<Value>>| {
            run_reply_observations(journals)
                .expect("selection")
                .remove("reply.md")
                .expect("reply")
        };
        assert_eq!(select(&journals).journal, PathBuf::from("first"));
        journals.get_mut(Path::new("second")).expect("second")[0] = make(2, "2026-01-01T00:00:02Z");
        assert_eq!(select(&journals).journal, PathBuf::from("second"));
        journals.get_mut(Path::new("second")).expect("second")[0] = make(3, "2026-01-01T00:00:01Z");
        assert_eq!(select(&journals).journal, PathBuf::from("first"));
        journals.get_mut(Path::new("second")).expect("second")[0]["at"] = json!("invalid");
        assert!(run_reply_observations(&journals).is_err());
    }
}
