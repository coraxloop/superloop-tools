//! Reconcile public journal observations with receipt names, without opening reply bodies.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use lane_lifecycle::{escape_mailbox_name, run_reply_observations};
use serde_json::Value;

const MAX_RECORD: u64 = 16_777_216;
const ANNOUNCED_RECORD: &str = ".announced-replies.json";

/// Local announcement history; receipts remain the authority for unread replies.
pub(crate) struct Announcements {
    entries: BTreeMap<String, u64>,
    dirty: bool,
    directory: File,
    path: PathBuf,
}

impl Announcements {
    pub(crate) fn read(run: &Path) -> Result<Self, OutboxError> {
        let path = run.join(ANNOUNCED_RECORD);
        let parent = File::open(run).map_err(|e| failure(&path, "outbox-record", &e))?;
        let Some(record) = document_at(&parent, ANNOUNCED_RECORD, &path)? else {
            return Ok(Self {
                entries: BTreeMap::new(),
                dirty: false,
                directory: parent,
                path,
            });
        };
        let invalid = || failure(&path, "outbox-record", "invalid announced reply set");
        if record.as_object().is_none_or(|object| object.len() != 2)
            || record["schema"].as_u64() != Some(1)
        {
            return Err(invalid());
        }
        let rows = record["replies"].as_array().ok_or_else(invalid)?;
        let mut entries = BTreeMap::new();
        for row in rows {
            if row.as_object().is_none_or(|object| object.len() != 2) {
                return Err(invalid());
            }
            let name = row["name"]
                .as_str()
                .filter(|name| published_name(name))
                .ok_or_else(invalid)?;
            let revision = row["revision"]
                .as_u64()
                .filter(|revision| *revision > 0)
                .ok_or_else(invalid)?;
            if entries.insert(name.to_owned(), revision).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self {
            entries,
            dirty: false,
            directory: parent,
            path,
        })
    }

    pub(crate) fn contains(&self, reply: &ReplyNotice) -> bool {
        self.entries.get(&reply.name) == Some(&reply.revision)
    }

    pub(crate) fn reconcile(
        &mut self,
        replies: &[ReplyNotice],
        save: bool,
    ) -> Result<bool, OutboxError> {
        let names: BTreeSet<_> = replies.iter().map(|reply| &reply.name).collect();
        let before = self.entries.len();
        self.entries.retain(|name, _| names.contains(name));
        let removed = self.entries.len() != before;
        self.dirty |= removed;
        if removed && save {
            self.write()?;
        }
        Ok(removed)
    }

    pub(crate) fn announced(&mut self, replies: &[ReplyNotice]) -> Result<(), OutboxError> {
        if !self.dirty
            && replies.len() == self.entries.len()
            && replies.iter().all(|reply| self.contains(reply))
        {
            return Ok(());
        }
        self.entries = replies
            .iter()
            .map(|reply| (reply.name.clone(), reply.revision))
            .collect();
        self.write()
    }

    fn write(&self) -> Result<(), OutboxError> {
        let rows: Vec<_> = self
            .entries
            .iter()
            .map(|(name, revision)| serde_json::json!({"name":name,"revision":revision}))
            .collect();
        let bytes = serde_json::to_vec(&serde_json::json!({"schema":1,"replies":rows}))
            .map_err(|e| failure(&self.path, "outbox-record", &e))?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err(failure(
                &self.path,
                "outbox-record",
                "announced reply set exceeds bound",
            ));
        }
        self.publish(|file| file.write_all(&bytes))
    }

    fn publish(&self, write: impl FnOnce(&mut File) -> io::Result<()>) -> Result<(), OutboxError> {
        let refuse = |error| failure(&self.path, "outbox-record", &error);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| failure(&self.path, "outbox-record", &e))?
            .as_nanos();
        let temporary = CString::new(format!(
            ".announced-replies-{}-{stamp}.tmp",
            std::process::id()
        ))
        .map_err(|e| failure(&self.path, "outbox-record", &e))?;
        let directory = self.directory.as_raw_fd();
        // SAFETY: the held directory and terminated name remain live; O_EXCL
        // creates a new file and a successful open transfers one descriptor.
        #[allow(unsafe_code)]
        let raw = unsafe {
            libc::openat(
                directory,
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(refuse(io::Error::last_os_error()));
        }
        // SAFETY: raw is the newly owned descriptor from the successful openat.
        #[allow(unsafe_code)]
        let mut file = unsafe { File::from_raw_fd(raw) };
        let result = write(&mut file)
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                // SAFETY: both names are terminated and directory remains held.
                #[allow(unsafe_code)]
                let renamed = unsafe {
                    libc::renameat(
                        directory,
                        temporary.as_ptr(),
                        directory,
                        c".announced-replies.json".as_ptr(),
                    )
                };
                if renamed < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    self.directory.sync_all()
                }
            });
        if result.is_err() {
            // SAFETY: this removes only our exclusive temporary name from the
            // held directory; after a successful rename that name is absent.
            #[allow(unsafe_code)]
            let _ignored = unsafe { libc::unlinkat(directory, temporary.as_ptr(), 0) };
        }
        result.map_err(refuse)
    }
}

/// An unread observation, not a completion or a claim about unseen filesystem changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyNotice {
    pub name: String,
    pub at: String,
    pub revision: u64,
}

impl fmt::Display for ReplyNotice {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "NEW MESSAGE name={} at={} revision={}",
            self.name, self.at, self.revision
        )
    }
}

/// A named failure to inspect the host-visible mailbox evidence.
#[derive(Debug)]
pub struct OutboxError {
    pub kind: &'static str,
    pub path: PathBuf,
    pub reason: String,
}

impl fmt::Display for OutboxError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{} path={} reason={}",
            self.kind,
            escape_mailbox_name(self.path.as_os_str().as_bytes()),
            escape_mailbox_name(self.reason.as_bytes())
        )
    }
}
impl std::error::Error for OutboxError {}

fn failure(path: &Path, kind: &'static str, reason: &(impl ToString + ?Sized)) -> OutboxError {
    OutboxError {
        kind,
        path: path.into(),
        reason: reason.to_string(),
    }
}

/// Fixed-size, saturating counters for this call's outbox scans (not waiting).
#[derive(Default, Debug, Clone)]
pub(crate) struct Cost {
    scans: u64,
    journal_bytes: u64,
    receipt_names: u64,
    wall: std::time::Duration,
}
impl Cost {
    pub(crate) fn value(&self) -> Value {
        serde_json::json!({"scans":self.scans,"journal_bytes":self.journal_bytes,
            "receipt_names":self.receipt_names,
            "scan_wall_ms":u64::try_from(self.wall.as_millis()).unwrap_or(u64::MAX)})
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    content: Option<(u64, i64, i64)>,
}
struct Watch {
    parent: File,
    name: std::ffi::OsString,
    path: PathBuf,
    content: bool,
    before: Option<Stamp>,
}
impl Watch {
    fn sample(&self, identity: &HostIdentity) -> Result<Option<Stamp>, OutboxError> {
        identity.search(&self.parent, &self.path)?;
        let Some(file) = open_at(&self.parent, &self.name, libc::O_PATH, &self.path)? else {
            return Ok(None);
        };
        let meta = file
            .metadata()
            .map_err(|e| failure(&self.path, "outbox-access", &e))?;
        Ok(Some(Stamp {
            inode: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            content: self
                .content
                .then(|| (meta.len(), meta.mtime(), meta.mtime_nsec())),
        }))
    }
}

#[derive(Default)]
pub(crate) struct Scanner {
    watches: Vec<Watch>,
    ready: bool,
    replies: Vec<ReplyNotice>,
    pub(crate) cost: Cost,
}
impl Scanner {
    pub(crate) fn poll(&mut self, run: &Path) -> Result<Vec<ReplyNotice>, OutboxError> {
        let identity = HostIdentity::current().map_err(|e| failure(run, "outbox-access", &e))?;
        if self.ready {
            let mut changed = false;
            for watch in &self.watches {
                if watch.sample(&identity)? != watch.before {
                    changed = true;
                    break;
                }
            }
            if !changed {
                return Ok(self.replies.clone());
            }
        }
        self.ready = false;
        self.watches.clear();
        let started = std::time::Instant::now();
        self.cost.scans = self.cost.scans.saturating_add(1);
        let result = scan(run, &identity, &mut self.watches, &mut self.cost);
        self.cost.wall = self.cost.wall.saturating_add(started.elapsed());
        self.replies = result?;
        self.ready = true;
        Ok(self.replies.clone())
    }
}

fn watch_at(
    watches: &mut Vec<Watch>,
    parent: &File,
    name: &std::ffi::OsStr,
    path: &Path,
    content: bool,
    identity: &HostIdentity,
) -> Result<(), OutboxError> {
    let mut watch = Watch {
        parent: parent
            .try_clone()
            .map_err(|e| failure(path, "outbox-path", &e))?,
        name: name.to_owned(),
        path: path.to_owned(),
        content,
        before: None,
    };
    watch.before = watch.sample(identity)?;
    watches.push(watch);
    Ok(())
}

struct HostIdentity {
    uid: u32,
    groups: Vec<u32>,
}
impl HostIdentity {
    fn current() -> io::Result<Self> {
        #[cfg(test)]
        injected_fault("identity")?;
        #[cfg(test)]
        if let Some(uid) = TEST_CALLER.with(std::cell::Cell::get) {
            return Ok(Self {
                uid,
                groups: vec![uid],
            });
        }
        // SAFETY: these identity queries take no pointers.
        #[allow(unsafe_code)]
        let (uid, gid, count) = unsafe {
            (
                libc::geteuid(),
                libc::getegid(),
                libc::getgroups(0, std::ptr::null_mut()),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut groups = vec![0; usize::try_from(count).map_err(io::Error::other)?];
        // SAFETY: the vector holds count writable gid slots.
        #[allow(unsafe_code)]
        let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
        if actual < 0 {
            return Err(io::Error::last_os_error());
        }
        groups.truncate(usize::try_from(actual).map_err(io::Error::other)?);
        groups.push(gid);
        Ok(Self { uid, groups })
    }
    fn search(&self, file: &File, path: &Path) -> Result<(), OutboxError> {
        #[cfg(test)]
        if TEST_SCOPE.with(|scope| {
            scope
                .borrow()
                .as_ref()
                .is_some_and(|root| !path.starts_with(root))
        }) {
            return Ok(());
        }
        let meta = file
            .metadata()
            .map_err(|e| failure(path, "outbox-access", &e))?;
        let (owner, group) = directory_identity(&meta);
        let bit = if owner == self.uid {
            0o100
        } else if self.groups.contains(&group) {
            0o010
        } else {
            0o001
        };
        if !meta.is_dir() || meta.mode() & bit == 0 {
            return Err(failure(
                path,
                "outbox-search",
                &format!(
                    "uid={} owner={} group={} mode={:04o} missing-search-bit={bit:04o} required-directory-owner={owner}",
                    self.uid,
                    owner,
                    group,
                    meta.mode() & 0o7777
                ),
            ));
        }
        Ok(())
    }
}

fn directory_identity(meta: &std::fs::Metadata) -> (u32, u32) {
    #[cfg(test)]
    if let Some(identity) =
        TEST_OWNERS.with(|owners| owners.borrow().get(&(meta.dev(), meta.ino())).copied())
    {
        return identity;
    }
    (meta.uid(), meta.gid())
}

fn open_at(
    parent: &File,
    name: &std::ffi::OsStr,
    flags: i32,
    path: &Path,
) -> Result<Option<File>, OutboxError> {
    let name = CString::new(name.as_bytes()).map_err(|e| failure(path, "outbox-path", &e))?;
    // SAFETY: parent and terminated name remain live; successful openat transfers one fd.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(failure(path, "outbox-path", &error));
    }
    // SAFETY: raw is a newly owned descriptor.
    #[allow(unsafe_code)]
    Ok(Some(unsafe { File::from_raw_fd(raw) }))
}

fn absolute(path: &Path) -> Result<PathBuf, OutboxError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| failure(path, "outbox-path", &e))?
            .join(path)
    };
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(failure(&path, "outbox-path", "parent traversal"));
    }
    Ok(path.components().collect())
}

fn pin(path: &Path, identity: &HostIdentity) -> Result<Vec<(PathBuf, File)>, OutboxError> {
    let mut file = File::open("/").map_err(|e| failure(path, "outbox-path", &e))?;
    let mut current = PathBuf::from("/");
    identity.search(&file, &current)?;
    let mut held = vec![(
        current.clone(),
        file.try_clone()
            .map_err(|e| failure(path, "outbox-path", &e))?,
    )];
    for component in path.components() {
        if let Component::Normal(name) = component {
            current.push(name);
            file = open_at(&file, name, libc::O_PATH | libc::O_DIRECTORY, &current)?
                .ok_or_else(|| failure(&current, "outbox-path", "directory absent"))?;
            identity.search(&file, &current).map_err(|mut error| {
                let caller_owns_parent = held
                    .last()
                    .and_then(|(_, parent)| parent.metadata().ok())
                    .is_some_and(|meta| directory_identity(&meta).0 == identity.uid);
                if error.kind == "outbox-search"
                    && caller_owns_parent
                    && (current == path || path.parent() == Some(current.as_path()))
                    && file
                        .metadata()
                        .is_ok_and(|meta| directory_identity(&meta).0 != identity.uid)
                {
                    error
                        .reason
                        .push_str(" use-run-identity=loop-via-superloop");
                }
                error
            })?;
            held.push((
                current.clone(),
                file.try_clone()
                    .map_err(|e| failure(path, "outbox-path", &e))?,
            ));
        }
    }
    Ok(held)
}

fn bytes_at(parent: &File, name: &str, path: &Path) -> Result<Option<Vec<u8>>, OutboxError> {
    let Some(file) = open_at(parent, name.as_ref(), libc::O_RDONLY, path)? else {
        return Ok(None);
    };
    let meta = file
        .metadata()
        .map_err(|e| failure(path, "outbox-record", &e))?;
    if !meta.is_file() || meta.len() > MAX_RECORD {
        return Err(failure(
            path,
            "outbox-record",
            "not a bounded regular record",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| failure(path, "outbox-record", &e))?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(failure(path, "outbox-record", "record grew beyond bound"));
    }
    Ok(Some(bytes))
}

fn document_at(parent: &File, name: &str, path: &Path) -> Result<Option<Value>, OutboxError> {
    bytes_at(parent, name, path)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| failure(path, "outbox-record", &e)))
        .transpose()
}

fn receipt_names(
    round: &File,
    path: &Path,
    identity: &HostIdentity,
    cost: &mut Cost,
) -> Result<BTreeSet<String>, OutboxError> {
    let path = path.join(".reply-receipts");
    let Some(directory) = open_at(
        round,
        ".reply-receipts".as_ref(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        &path,
    )?
    else {
        return Ok(BTreeSet::new());
    };
    identity.search(&directory, &path)?;
    names(&directory, cost).map_err(|e| failure(&path, "outbox-receipts", &e))
}

fn names(directory: &File, cost: &mut Cost) -> io::Result<BTreeSet<String>> {
    collect_names(directory, false, cost)
}

fn collect_names(directory: &File, rounds: bool, cost: &mut Cost) -> io::Result<BTreeSet<String>> {
    #[cfg(test)]
    injected_fault(if rounds { "round-list" } else { "receipt-list" })?;
    // SAFETY: fdopendir owns only its duplicate, never the caller's descriptor.
    #[allow(unsafe_code)]
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(unsafe_code)]
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir did not consume the duplicate on failure.
        #[allow(unsafe_code)]
        unsafe {
            libc::close(duplicate);
        }
        return Err(error);
    }
    let mut found = BTreeSet::new();
    let result = loop {
        // SAFETY: this thread owns stream and its errno slot.
        #[allow(unsafe_code)]
        let entry = unsafe {
            *libc::__errno_location() = 0;
            libc::readdir(stream)
        };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(found)
            } else {
                Err(error)
            };
        }
        // SAFETY: d_name is terminated and valid until the next readdir.
        #[allow(unsafe_code)]
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if !rounds && name != b"." && name != b".." {
            cost.receipt_names = cost.receipt_names.saturating_add(1);
        }
        let candidate = if rounds {
            !name.starts_with(b".") && std::str::from_utf8(name).is_ok()
        } else {
            name.len() == 69
                && name.ends_with(b".json")
                && name[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        };
        if candidate {
            let word = CString::new(name).map_err(io::Error::other)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the descriptor is held and stat has writable storage.
            #[allow(unsafe_code)]
            let status = unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    word.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if status == 0 {
                // SAFETY: successful fstatat initialized stat.
                #[allow(unsafe_code)]
                let stat = unsafe { stat.assume_init() };
                if (rounds && stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
                    || (!rounds
                        && stat.st_mode & libc::S_IFMT == libc::S_IFREG
                        && stat.st_mode & 0o7777 == 0o600)
                {
                    found.insert(String::from_utf8_lossy(name).into_owned());
                }
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    break Err(error);
                }
            }
        }
    };
    // SAFETY: close the owned stream, also closing the duplicate.
    #[allow(unsafe_code)]
    unsafe {
        libc::closedir(stream);
    }
    result
}

fn published_name(name: &str) -> bool {
    let mut decoded = Vec::new();
    let mut bytes = name.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(pair) = bytes.next().zip(bytes.next()) else {
                return false;
            };
            let Some(a) = char::from(pair.0).to_digit(16) else {
                return false;
            };
            let Some(b) = char::from(pair.1).to_digit(16) else {
                return false;
            };
            let Ok(byte) = u8::try_from(a * 16 + b) else {
                return false;
            };
            decoded.push(byte);
        } else {
            decoded.push(byte);
        }
    }
    !decoded.is_empty()
        && decoded.len() <= 255
        && !decoded.starts_with(b".")
        && !decoded.contains(&b'/')
        && !decoded.contains(&0)
        && escape_mailbox_name(&decoded) == name
}

/// List every journal-observed reply lacking an observation receipt on this call.
///
/// # Errors
/// Names an inaccessible ancestor, unsafe path or malformed bounded record.
pub fn unread_replies(run: &Path) -> Result<Vec<ReplyNotice>, OutboxError> {
    Scanner::default().poll(run)
}

fn select_plan(
    pinned: &[(PathBuf, File)],
    identity: &HostIdentity,
    watches: &mut Vec<Watch>,
) -> Result<Option<usize>, OutboxError> {
    for pair in pinned.windows(2) {
        let (path, _) = &pair[1];
        watch_at(
            watches,
            &pair[0].1,
            path.file_name().unwrap_or_default(),
            path,
            false,
            identity,
        )?;
        // Bind the sample to the ancestor actually held by the scan, even if its
        // name changed between pinning and the metadata probe.
        let meta = pair[1]
            .1
            .metadata()
            .map_err(|e| failure(path, "outbox-access", &e))?;
        if let Some(watch) = watches.last_mut() {
            watch.before = Some(Stamp {
                inode: meta.ino(),
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                content: None,
            });
        }
    }
    let mut selected = None;
    for index in (0..pinned.len()).rev().take(2) {
        let (directory, held) = &pinned[index];
        watch_at(
            watches,
            held,
            "plan.json".as_ref(),
            &directory.join("plan.json"),
            true,
            identity,
        )?;
        if let Some(plan) = document_at(held, "plan.json", &directory.join("plan.json"))? {
            if plan["home"].as_str().is_none_or(str::is_empty) {
                return Ok(None);
            }
            if plan["driver_dir"].as_str() != directory.to_str() {
                return Err(failure(
                    directory,
                    "outbox-plan",
                    "recorded driver directory differs",
                ));
            }
            selected = Some(index);
            break;
        }
    }
    Ok(selected)
}

fn scan(
    run: &Path,
    identity: &HostIdentity,
    watches: &mut Vec<Watch>,
    cost: &mut Cost,
) -> Result<Vec<ReplyNotice>, OutboxError> {
    let run = absolute(run)?;
    let pinned = pin(&run, identity)?;
    let selected = select_plan(&pinned, identity, watches)?;
    let Some(index) = selected else {
        return Ok(Vec::new());
    };
    let (root, held_root) = &pinned[index];
    // The reservation is owner-private command input. A loop's watcher discovers
    // journals only beneath its pinned durable run, including a shim's root journal.
    let readable = open_at(
        held_root,
        std::ffi::OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        root,
    )?
    .ok_or_else(|| failure(root, "outbox-path", "run absent"))?;
    watch_at(watches, held_root, ".".as_ref(), root, true, identity)?;
    let children =
        collect_names(&readable, true, cost).map_err(|e| failure(root, "outbox-rounds", &e))?;
    let mut evidence = Evidence::default();
    observations(held_root, root, identity, &mut evidence, watches, cost)?;
    for name in children {
        let path = root.join(&name);
        watch_at(watches, held_root, name.as_ref(), &path, false, identity)?;
        let Some(held) = open_at(
            held_root,
            std::ffi::OsStr::new(&name),
            libc::O_PATH | libc::O_DIRECTORY,
            &path,
        )?
        else {
            continue;
        };
        identity.search(&held, &path)?;
        observations(&held, &path, identity, &mut evidence, watches, cost)?;
    }
    let latest = run_reply_observations(&evidence.journals)
        .map_err(|e| failure(root, "outbox-journal", &e))?;
    let mut replies: Vec<_> = latest
        .into_iter()
        .filter_map(|(name, selected)| {
            let received = evidence
                .receipts
                .get(&selected.journal)
                .is_some_and(|names| names.contains(&format!("{}.json", selected.observation.key)));
            (!received).then(|| ReplyNotice {
                name,
                at: selected.observation.row["at"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                revision: selected.observation.row["revision"]
                    .as_u64()
                    .unwrap_or_default(),
            })
        })
        .collect();
    replies.sort_by(|a, b| (&a.at, &a.name).cmp(&(&b.at, &b.name)));
    Ok(replies)
}

#[derive(Default)]
struct Evidence {
    journals: BTreeMap<PathBuf, Vec<Value>>,
    receipts: BTreeMap<PathBuf, BTreeSet<String>>,
}

fn observations(
    round: &File,
    path: &Path,
    identity: &HostIdentity,
    evidence: &mut Evidence,
    watches: &mut Vec<Watch>,
    cost: &mut Cost,
) -> Result<(), OutboxError> {
    for name in ["letters.jsonl", ".reply-receipts"] {
        watch_at(
            watches,
            round,
            name.as_ref(),
            &path.join(name),
            true,
            identity,
        )?;
    }
    let journal_path = path.join("letters.jsonl");
    let Some(bytes) = bytes_at(round, "letters.jsonl", &journal_path)? else {
        return Ok(());
    };
    let mut rows = Vec::new();
    // Ignore a torn final line; only newline-terminated observations are records.
    for line in bytes
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| line.ends_with(b"\n"))
    {
        cost.journal_bytes = cost.journal_bytes.saturating_add(line.len() as u64);
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| failure(&journal_path, "outbox-journal", &e))?;
        if row["box"] != "outbox" || row["kind"] != "file" {
            continue;
        }
        let name = row["name"]
            .as_str()
            .ok_or_else(|| failure(&journal_path, "outbox-journal", "name absent"))?;
        if name.starts_with('.') {
            continue;
        }
        if !published_name(name) {
            return Err(failure(
                &journal_path,
                "outbox-name",
                &format!("invalid published name {name}"),
            ));
        }
        let at = row["at"]
            .as_str()
            .filter(|at| super::parse_utc_instant(at).is_some())
            .ok_or_else(|| {
                failure(
                    &journal_path,
                    "outbox-journal",
                    "invalid observation instant",
                )
            })?;
        let revision = row["revision"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| failure(&journal_path, "outbox-journal", "invalid revision"))?;
        if row["identity"] != serde_json::json!(["outbox", name, revision, at]) {
            return Err(failure(
                &journal_path,
                "outbox-journal",
                "observation identity differs",
            ));
        }
        rows.push(row);
    }
    evidence.journals.insert(path.to_owned(), rows);
    evidence
        .receipts
        .insert(path.to_owned(), receipt_names(round, path, identity, cost)?);
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
thread_local! {
    static TEST_CALLER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    static TEST_SCOPE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_OWNERS: std::cell::RefCell<BTreeMap<(u64, u64), (u32, u32)>> = const { std::cell::RefCell::new(BTreeMap::new()) };
    static FAULT: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}

#[cfg(test)]
fn injected_fault(point: &str) -> io::Result<()> {
    FAULT.with(|fault| {
        if fault.get() == point {
            fault.set("");
            Err(io::Error::from_raw_os_error(libc::EIO))
        } else {
            Ok(())
        }
    })
}
