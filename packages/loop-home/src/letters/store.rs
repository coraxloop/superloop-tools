use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek as _, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::{OFlag, RenameFlags, renameat2};
use nix::sys::stat::{FileStat, SFlag, fstat};
#[cfg(not(test))]
use nix::unistd::{Gid, fchown};
use nix::unistd::{UnlinkatFlags, unlinkat};

use super::record::{LetterRecord, MAX_BODY, MAX_HEADER, hex, malformed, parse_name};
use super::{beneath, io_error, open_beneath, path_error, unsafe_path};
use crate::{LoopError, LoopRecord};

pub(super) struct Context {
    pub loops: OwnedFd,
    pub rows: Vec<LoopRecord>,
    pub uid: u32,
    pub gid: u32,
    pub root_uid: u32,
}

#[cfg(test)]
thread_local! {
    pub(super) static IDENTITIES: std::cell::RefCell<std::collections::BTreeMap<(u64, u64), (u32, u32)>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    pub(super) static RACE: std::cell::RefCell<Option<(&'static str, Race)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type Race = Box<dyn FnOnce()>;

#[cfg(test)]
pub(super) fn race(phase: &str) {
    let hook = RACE.with(|race| {
        let mut race = race.borrow_mut();
        if race
            .as_ref()
            .is_some_and(|(expected, _)| *expected == phase)
        {
            race.take()
        } else {
            None
        }
    });
    if let Some((_, hook)) = hook {
        hook();
    }
}

pub(super) fn stat(fd: &OwnedFd) -> Result<FileStat, LoopError> {
    let observed = fstat(fd).map_err(io_error)?;
    #[cfg(test)]
    let observed = {
        let mut observed = observed;
        IDENTITIES.with(|identities| {
            if let Some(&(uid, gid)) = identities.borrow().get(&(observed.st_dev, observed.st_ino))
            {
                observed.st_uid = uid;
                observed.st_gid = gid;
            }
        });
        observed
    };
    Ok(observed)
}

pub(super) fn random_suffix() -> Result<String, LoopError> {
    let mut bytes = [0; 16];
    system_random(&mut bytes)?;
    Ok(hex(&bytes))
}

#[allow(unsafe_code)]
fn system_random(bytes: &mut [u8]) -> Result<(), LoopError> {
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: getrandom writes at most the remaining slice length into its live buffer.
        let count = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io_error(error));
        }
        if count == 0 {
            return Err(io_error("random source returned zero bytes"));
        }
        filled += usize::try_from(count).map_err(io_error)?;
    }
    Ok(())
}

pub(super) fn directory(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<OwnedFd, LoopError> {
    let fd = beneath(
        parent,
        Path::new(name),
        OFlag::O_PATH | OFlag::O_DIRECTORY,
        0,
    )?;
    let observed = stat(&fd)?;
    if observed.st_uid != uid || observed.st_gid != gid || observed.st_mode & 0o7777 != mode {
        return Err(LoopError::refusal(format!(
            "letters inbox owner, group or mode mismatch: {name}; observed uid={} gid={} mode={:04o}; expected directory uid={uid} gid={gid} mode={mode:04o}",
            observed.st_uid,
            observed.st_gid,
            observed.st_mode & 0o7777
        )));
    }
    Ok(fd)
}

impl Context {
    pub(super) fn row(&self, name: &str) -> Result<&LoopRecord, LoopError> {
        self.rows
            .iter()
            .find(|row| row.name == name)
            .ok_or_else(|| LoopError::refusal(format!("letters unknown loop: {name}")))
    }

    pub(super) fn me(&self) -> Result<&LoopRecord, LoopError> {
        self.rows
            .iter()
            .find(|row| row.uid == self.uid)
            .ok_or_else(|| LoopError::refusal("letters sender uid matches no registry row"))
    }

    pub(super) fn inbox(&self, row: &LoopRecord) -> Result<OwnedFd, LoopError> {
        let root = beneath(
            &self.loops,
            Path::new(&row.name),
            OFlag::O_PATH | OFlag::O_DIRECTORY,
            0,
        )?;
        let observed = stat(&root)?;
        if observed.st_uid != self.root_uid || observed.st_mode & 0o7777 != 0o711 {
            return Err(unsafe_path("unsafe loop root"));
        }
        directory(&root, "inbox", row.uid, self.gid, 0o710)
    }
}

fn sync_directory(fd: &OwnedFd) -> Result<(), LoopError> {
    // O_PATH anchors cannot fsync; opening '.' stays relative to the held descriptor.
    // A peer cannot open new/ for reading, so publication uses the file's sync only.
    let readable = beneath(fd, Path::new("."), OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)?;
    File::from(readable).sync_all().map_err(io_error)
}

fn file_record(
    context: &Context,
    dir: &OwnedFd,
    name: &str,
) -> Result<Option<(OwnedFd, LetterRecord)>, LoopError> {
    let (named_sender, instant) = parse_name(name)?;
    let fd = match open_beneath(dir, Path::new(name), OFlag::O_RDONLY | OFlag::O_NONBLOCK, 0) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(path_error(Path::new(name), error)),
    };
    let observed = stat(&fd)?;
    let sender = context
        .rows
        .iter()
        .find(|row| row.uid == observed.st_uid)
        .ok_or_else(|| {
            LoopError::refusal(format!(
                "letters sender uid matches no registry row: {name}"
            ))
        })?;
    if SFlag::from_bits_truncate(observed.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG
        || observed.st_mode & 0o7777 != 0o440
        || observed.st_gid != context.gid
        || observed.st_nlink != 1
    {
        return Err(LoopError::refusal(format!(
            "letters malformed file metadata: {name}"
        )));
    }
    if observed.st_size < 0 || observed.st_size.cast_unsigned() > (MAX_BODY + MAX_HEADER) as u64 {
        return Err(LoopError::refusal(format!(
            "letters oversized letter: {name}"
        )));
    }
    let mut bytes = Vec::new();
    File::from(nix::unistd::dup(&fd).map_err(io_error)?)
        .take((MAX_BODY + MAX_HEADER + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let record = LetterRecord::decode(&bytes)
        .map_err(|error| LoopError::refusal(format!("{}: {name}", error.message())))?;
    if record.sender != sender.name || named_sender != sender.name {
        return Err(LoopError::refusal(format!(
            "letters claimed sender differs from owner uid: {name}"
        )));
    }
    if record.receiver != context.me()?.name || record.posted_ns != instant {
        return Err(LoopError::refusal(format!(
            "letters malformed receiver or posting instant: {name}"
        )));
    }
    #[cfg(test)]
    race("read");
    let after = stat(&fd)?;
    if after.st_size != observed.st_size
        || after.st_mtime != observed.st_mtime
        || after.st_mtime_nsec != observed.st_mtime_nsec
        || after.st_ctime != observed.st_ctime
        || after.st_ctime_nsec != observed.st_ctime_nsec
    {
        return Err(unsafe_path("letter changed while reading"));
    }
    Ok(Some((fd, record)))
}

fn publish(
    context: &Context,
    receiver: &LoopRecord,
    name: &str,
    bytes: &[u8],
) -> Result<(), LoopError> {
    let inbox = context.inbox(receiver)?;
    let new = directory(&inbox, "new", receiver.uid, context.gid, 0o1730)?;
    let temporary = format!(".tmp-{}", random_suffix()?);
    let fd = beneath(
        &new,
        Path::new(&temporary),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
        0o440,
    )?;
    let result = (|| {
        #[cfg(not(test))]
        fchown(&fd, None, Some(Gid::from_raw(context.gid))).map_err(io_error)?;
        #[cfg(test)]
        {
            // The fixture changes provenance observations, never OS credentials.
            let real = fstat(&fd).map_err(io_error)?;
            IDENTITIES.with(|identities| {
                identities
                    .borrow_mut()
                    .insert((real.st_dev, real.st_ino), (context.uid, context.gid));
            });
        }
        let mut file = File::from(nix::unistd::dup(&fd).map_err(io_error)?);
        file.set_permissions(std::fs::Permissions::from_mode(0o440))
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        #[cfg(test)]
        race("written");
        file.rewind().map_err(io_error)?;
        let mut verified = Vec::new();
        file.take((MAX_BODY + MAX_HEADER + 1) as u64)
            .read_to_end(&mut verified)
            .map_err(io_error)?;
        let observed = stat(&fd)?;
        if verified != bytes
            || (observed.st_uid, observed.st_gid) != (context.uid, context.gid)
            || observed.st_mode & 0o7777 != 0o440
            || observed.st_nlink != 1
        {
            return Err(unsafe_path("temporary letter failed verification"));
        }
        #[cfg(test)]
        race("verified");
        let pinned_name = beneath(&new, Path::new(&temporary), OFlag::O_PATH, 0)?;
        let named = stat(&pinned_name)?;
        if named.st_dev != observed.st_dev || named.st_ino != observed.st_ino {
            return Err(unsafe_path("temporary letter was replaced"));
        }
        renameat2(
            &new,
            temporary.as_str(),
            &new,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(io_error)
    })();
    if result.is_err() {
        let _removed = unlinkat(&new, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

fn post(
    context: &Context,
    arguments: &[String],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), LoopError> {
    let [receiver, flag, subject, options @ ..] = arguments else {
        return Err(usage());
    };
    if flag != "--subject"
        || !matches!(options, [] | [_])
        || options.first().is_some_and(|s| s != "--dry-run")
    {
        return Err(usage());
    }
    let sender = context.me()?;
    let receiver = context.row(receiver)?;
    if sender.uid == receiver.uid {
        return Err(LoopError::refusal("letters self-post refused"));
    }
    let inbox = context.inbox(receiver)?;
    let _new = directory(&inbox, "new", receiver.uid, context.gid, 0o1730)?;
    let mut body = Vec::new();
    input
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut body)
        .map_err(io_error)?;
    let posted_ns = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io_error)?
            .as_nanos(),
    )
    .map_err(io_error)?;
    let name = format!("{}.{posted_ns:020}.{}", sender.name, random_suffix()?);
    parse_name(&name)?;
    let record = LetterRecord {
        sender: sender.name.clone(),
        receiver: receiver.name.clone(),
        subject: subject.clone(),
        posted_ns,
        body,
    };
    let bytes = record.encode()?;
    let dry = !options.is_empty();
    if !dry {
        publish(context, receiver, &name, &bytes)?;
    }
    writeln!(output, "LETTERS post name={name} actions=1 dry_run={dry}").map_err(io_error)?;
    if dry {
        output.write_all(&bytes).map_err(io_error)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn directory_names(fd: &OwnedFd) -> Result<Vec<OsString>, LoopError> {
    use std::os::fd::IntoRawFd as _;

    let duplicate = nix::unistd::dup(fd).map_err(io_error)?;
    // SAFETY: fdopendir owns the duplicate on success; every exit closes it.
    // Each readdir name is copied before the next call or closedir.
    let names = unsafe {
        let raw = duplicate.into_raw_fd();
        let directory = libc::fdopendir(raw);
        if directory.is_null() {
            let error = std::io::Error::last_os_error();
            libc::close(raw);
            return Err(io_error(error));
        }
        // dup shares the directory offset. Every poll starts at the beginning of
        // this held directory, including after an earlier scan reached EOF.
        libc::rewinddir(directory);
        let mut names = Vec::new();
        loop {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(directory);
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                libc::closedir(directory);
                if error.raw_os_error() != Some(0) {
                    return Err(io_error(error));
                }
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()).to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        names
    };
    Ok(names.into_iter().map(OsString::from_vec).collect())
}

pub(super) struct ObservedEntry {
    pub identity: (OsString, u64, u64),
    pub instant: u64,
    pub line: String,
}

pub(super) enum Observation {
    Letter(ObservedEntry),
    Refused(ObservedEntry),
}

impl Observation {
    pub const fn entry(&self) -> &ObservedEntry {
        match self {
            Self::Letter(entry) | Self::Refused(entry) => entry,
        }
    }
}

fn escaped_name(name: &std::ffi::OsStr) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::new();
    for byte in name.as_encoded_bytes() {
        if *byte == b' ' || *byte == b'=' {
            let _written = write!(escaped, "\\x{byte:02x}");
        } else {
            escaped.extend(std::ascii::escape_default(*byte).map(char::from));
        }
    }
    escaped
}

pub(super) fn readable_directory(dir: &OwnedFd) -> Result<OwnedFd, LoopError> {
    beneath(dir, Path::new("."), OFlag::O_RDONLY | OFlag::O_DIRECTORY, 0)
}

fn entry_identity(dir: &OwnedFd, name: &Path) -> Result<Option<FileStat>, LoopError> {
    match open_beneath(dir, name, OFlag::O_PATH | OFlag::O_NOFOLLOW, 0) {
        Ok(fd) => stat(&fd).map(Some),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(path_error(name, error)),
    }
}

pub(super) fn observations(
    context: &Context,
    dir: &OwnedFd,
    box_name: &str,
    peer: Option<&str>,
) -> Result<Vec<Observation>, LoopError> {
    let mut entries = Vec::new();
    for name in directory_names(dir)? {
        if name.as_encoded_bytes().starts_with(b".tmp-") {
            continue;
        }
        #[cfg(test)]
        race("listing");
        let Some(before) = entry_identity(dir, Path::new(&name))? else {
            continue;
        };
        let result: Result<_, LoopError> = (|| {
            let text = name.to_str().ok_or_else(malformed)?;
            let (sender, instant) = parse_name(text)?;
            if peer.is_some_and(|peer| peer != sender) {
                return Ok(None);
            }
            let Some((fd, record)) = file_record(context, dir, text)? else {
                return Ok(None);
            };
            let observed = stat(&fd)?;
            if (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino) {
                return Ok(None);
            }
            Ok(Some((
                instant,
                super::letter_metadata(box_name, text, &record.encode()?)?,
            )))
        })();
        let refused = result.as_ref().is_err_and(|error| error.status() == 2);
        let (instant, line) = match result {
            Ok(Some(entry)) => entry,
            Ok(None) => continue,
            Err(error) if error.status() == 2 => (
                0,
                format!(
                    "{box_name}/{} refused reason=\"{}\"",
                    escaped_name(&name),
                    error.message().escape_debug()
                ),
            ),
            Err(error) => return Err(error),
        };
        #[cfg(test)]
        race("observing");
        let Some(after) = entry_identity(dir, Path::new(&name))? else {
            continue;
        };
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) {
            continue;
        }
        let entry = ObservedEntry {
            identity: (name, before.st_dev, before.st_ino),
            instant,
            line,
        };
        entries.push(if refused {
            Observation::Refused(entry)
        } else {
            Observation::Letter(entry)
        });
    }
    entries.sort_by(|a, b| {
        let (a, b) = (a.entry(), b.entry());
        (a.instant, &a.identity.0, &a.line).cmp(&(b.instant, &b.identity.0, &b.line))
    });
    Ok(entries)
}

fn list(context: &Context, arguments: &[String], output: &mut impl Write) -> Result<(), LoopError> {
    let peer = match arguments {
        [] => None,
        [flag, peer] if flag == "--peer" => Some(context.row(peer)?.name.as_str()),
        _ => return Err(usage()),
    };
    let me = context.me()?;
    let inbox = context.inbox(me)?;
    let mut entries = Vec::new();
    for (box_name, gid, mode) in [("new", context.gid, 0o1730), ("cur", me.uid, 0o700)] {
        let dir = directory(&inbox, box_name, me.uid, gid, mode)?;
        let readable = readable_directory(&dir)?;
        entries.extend(observations(context, &readable, box_name, peer)?);
    }
    entries.sort_by(|a, b| {
        let (a, b) = (a.entry(), b.entry());
        (a.instant, &a.identity.0, &a.line).cmp(&(b.instant, &b.identity.0, &b.line))
    });
    for entry in entries {
        writeln!(output, "{}", entry.entry().line).map_err(io_error)?;
    }
    Ok(())
}

fn read(
    context: &Context,
    arguments: &[String],
    output: &mut impl Write,
) -> Result<usize, LoopError> {
    let [name, options @ ..] = arguments else {
        return Err(usage());
    };
    let mut body = false;
    let mut dry = false;
    for option in options {
        match option.as_str() {
            "--body" if !body => body = true,
            "--dry-run" if !dry => dry = true,
            _ => return Err(usage()),
        }
    }
    let printed_name = name;
    let (box_name, name) = match (name.strip_prefix("new/"), name.strip_prefix("cur/")) {
        (Some(name), _) => (Some("new"), name),
        (None, Some(name)) => (Some("cur"), name),
        (None, None) => (None, name.as_str()),
    };
    validate_read_name(printed_name, box_name, name)?;
    let me = context.me()?;
    let inbox = context.inbox(me)?;
    let cur = directory(&inbox, "cur", me.uid, me.uid, 0o700)?;
    let new = directory(&inbox, "new", me.uid, context.gid, 0o1730)?;
    let present = if box_name == Some("new") {
        Err(nix::errno::Errno::ENOENT)
    } else {
        nix::fcntl::openat2(
            &cur,
            name,
            nix::fcntl::OpenHow::new()
                .flags(OFlag::O_PATH | OFlag::O_CLOEXEC)
                .resolve(
                    nix::fcntl::ResolveFlag::RESOLVE_BENEATH
                        | nix::fcntl::ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
    };
    let mut in_cur = match present {
        Ok(_fd) => true,
        Err(nix::errno::Errno::ENOENT) => false,
        Err(error) => return Err(path_error(Path::new(name), error)),
    };
    if !in_cur && box_name == Some("cur") {
        return absent(output, printed_name);
    }
    #[cfg(test)]
    race("opening");
    let (fd, record) = match file_record(context, if in_cur { &cur } else { &new }, name)? {
        Some(letter) => letter,
        None if in_cur => return Err(io_error(format!("current letter disappeared: {name}"))),
        None => match file_record(context, &cur, name)? {
            Some(letter) => {
                in_cur = true;
                letter
            }
            None => return absent(output, printed_name),
        },
    };
    if !in_cur && !dry {
        #[cfg(test)]
        race("taking");
        match renameat2(&new, name, &cur, name, RenameFlags::RENAME_NOREPLACE) {
            Ok(()) => (),
            Err(nix::errno::Errno::ENOENT) => in_cur = true,
            Err(error) => return Err(io_error(error)),
        }
        let taken = match open_beneath(&cur, Path::new(name), OFlag::O_PATH, 0) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) if in_cur => return absent(output, printed_name),
            Err(error) => return Err(path_error(Path::new(name), error)),
        };
        let before = stat(&fd)?;
        let after = stat(&taken)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(unsafe_path("letter replaced during take"));
        }
        if !in_cur {
            sync_directory(&new)?;
            sync_directory(&cur)?;
        }
    }
    if dry {
        writeln!(
            output,
            "LETTERS read name={printed_name} actions={} dry_run=true",
            usize::from(!in_cur)
        )
        .map_err(io_error)?;
    }
    let bytes = if body { record.body } else { record.encode()? };
    output.write_all(&bytes).map_err(io_error)?;
    Ok(usize::from(!in_cur))
}

fn validate_read_name(
    printed_name: &str,
    box_name: Option<&str>,
    name: &str,
) -> Result<(), LoopError> {
    if let Some((_, rest)) = printed_name.split_once('/')
        && box_name.is_none()
        && !rest.contains('/')
    {
        return Err(malformed_read_name(printed_name, "invalid box prefix"));
    }
    if name.contains('/') {
        return Err(malformed_read_name(
            printed_name,
            "unexpected path separator",
        ));
    }
    parse_name(name)
        .map_err(|_| malformed_read_name(printed_name, "invalid letter name grammar"))?;
    Ok(())
}

fn malformed_read_name(name: &str, defect: &str) -> LoopError {
    LoopError::refusal(format!(
        "letters malformed letter name={} ({defect})",
        escaped_name(std::ffi::OsStr::new(name))
    ))
}

fn absent(output: &mut impl Write, name: &str) -> Result<usize, LoopError> {
    writeln!(output, "LETTERS read name={name} absent").map_err(io_error)?;
    Ok(0)
}

pub(super) fn usage() -> LoopError {
    LoopError::refusal(
        "usage: letters post RECEIVER --subject TEXT [--dry-run] | list [--peer PEER] | read NAME [--body] [--dry-run] | follow [--peer PEER] [--interval SECONDS] [--once | --next [--wall SECONDS] [--exclude NAME]...]",
    )
}

pub(super) fn command_with_report(
    context: &Context,
    arguments: &[String],
    input: &mut impl Read,
    output: &mut impl Write,
    report: &mut impl Write,
) -> Result<usize, LoopError> {
    let [verb, arguments @ ..] = arguments else {
        return Err(usage());
    };
    match verb.as_str() {
        "post" => post(context, arguments, input, output).map(|()| 1),
        "list" => list(context, arguments, output).map(|()| 0),
        "read" => read(context, arguments, output),
        "follow" => super::follow::run(context, arguments, output, report).map(|()| 0),
        _ => Err(usage()),
    }
}

#[cfg(test)]
pub(super) fn command(
    context: &Context,
    arguments: &[String],
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<usize, LoopError> {
    command_with_report(context, arguments, input, output, &mut std::io::sink())
}
