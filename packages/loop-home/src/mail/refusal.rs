//! Protected refusal bindings; a suffix alone never excludes a submitted entry.
use super::instant::Instant;
use super::journal::{Identity, Journal, MailError, RECORD_MAX_BYTES, Result, digest};
use super::{io, store};
use nix::fcntl::{OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, UnlinkatFlags, fchown, unlinkat};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sidecar {
    version: u32,
    filename: Option<String>,
    filename_hex: String,
    bytes: Option<u64>,
    digest: Option<String>,
    code: String,
    reason: String,
    observed: Instant,
    delivery: Option<Instant>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    sender: String,
    source_hex: String,
    sidecar: String,
    identity: Identity,
    digest: String,
    source_digest: Option<String>,
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _written = write!(&mut text, "{byte:02x}");
        text
    })
}
fn key(sender: &str, name: &OsStr) -> String {
    format!(
        "refusal-{}.toml",
        digest(&[sender.as_bytes(), b"\0", name.as_bytes()].concat())
    )
}
fn sidecar(name: &OsStr) -> String {
    name.to_str()
        .filter(|name| name.len() + 12 <= 255)
        .map_or_else(
            || format!("refusal-{}.reason.toml", digest(name.as_bytes())),
            |name| format!("{name}.reason.toml"),
        )
}
pub(super) fn code(error: &MailError) -> &'static str {
    match error {
        MailError::Capacity => "service-capacity",
        MailError::Io(_) | MailError::ClockWait => "io-failure",
        MailError::Invalid(reason) => match reason.split(':').next().unwrap_or("") {
            "invalid-name" => "invalid-name",
            "invalid-file" => "invalid-file",
            "oversize" => "oversize",
            "unknown-recipient" => "unknown-recipient",
            "retired-worker" => "retired-worker",
            "outside-estate" => "outside-estate",
            "not-whitelisted" => "not-whitelisted",
            "invalid-directory" => "invalid-directory",
            "unsafe-storage" => "unsafe-storage",
            "changed-source" => "changed-source",
            _ => "io-failure",
        },
    }
}
fn matches_name(parent: &File, name: &str, binding: &Binding) -> Result<bool> {
    let file = match io::child(parent, Path::new(name), false) {
        Ok(file) => file,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let info = file.metadata()?;
    Ok(info.uid() == nix::unistd::geteuid().as_raw()
        && info.mode() & 0o222 == 0o200
        && info.dev() == binding.identity.device
        && info.ino() == binding.identity.inode
        && digest(&io::bounded(&file, RECORD_MAX_BYTES)?) == binding.digest)
}
/// Only a service-owned inode with a protected exact binding is a sidecar.
pub(super) fn recognized(
    journal: &Journal,
    outbox: &File,
    sender: &str,
    name: &OsStr,
) -> Result<bool> {
    for entry in store::names(journal.publication_root())?
        .into_iter()
        .filter(|name| name.starts_with("refusal-"))
    {
        let binding: Binding = store::read(journal.publication_root(), &entry, RECORD_MAX_BYTES)?;
        if binding.sender == sender
            && name == OsStr::new(&binding.sidecar)
            && matches_name(outbox, &binding.sidecar, &binding)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn exists(parent: &File, name: &str) -> Result<bool> {
    match nix::sys::stat::fstatat(parent, name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(nix::errno::Errno::ENOENT) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn temporary(key: &str) -> String {
    format!("reason-{}", digest(key.as_bytes()))
}

/// Claim before deleting: an actor swap is restored without overwriting its entry.
/// The protected binding also makes interrupted cleanup restartable.
pub(super) fn clear(
    journal: &Journal,
    outbox: &File,
    staging: &File,
    sender: &str,
    name: &OsStr,
) -> Result<()> {
    let key = key(sender, name);
    let binding: Binding = match store::read(journal.publication_root(), &key, RECORD_MAX_BYTES) {
        Ok(binding) => binding,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let claimed = format!("reap-{}", digest(key.as_bytes()));
    if !exists(staging, &claimed)? && exists(outbox, &binding.sidecar)? {
        if !matches_name(outbox, &binding.sidecar, &binding)? {
            return Err(MailError::Invalid(
                "unsafe-storage: refusal sidecar replaced by actor",
            ));
        }
        renameat2(
            outbox,
            binding.sidecar.as_str(),
            staging,
            claimed.as_str(),
            RenameFlags::RENAME_NOREPLACE,
        )?;
        outbox.sync_all()?;
        staging.sync_all()?;
    }
    if exists(staging, &claimed)? {
        if !matches_name(staging, &claimed, &binding)? {
            renameat2(
                staging,
                claimed.as_str(),
                outbox,
                binding.sidecar.as_str(),
                RenameFlags::RENAME_NOREPLACE,
            )?;
            outbox.sync_all()?;
            staging.sync_all()?;
            return Err(MailError::Invalid(
                "unsafe-storage: sidecar changed during cleanup",
            ));
        }
        unlinkat(staging, claimed.as_str(), UnlinkatFlags::NoRemoveDir)?;
        staging.sync_all()?;
    }
    let temporary = temporary(&key);
    if exists(staging, &temporary)? {
        if !matches_name(staging, &temporary, &binding)? {
            return Err(MailError::Invalid(
                "unsafe-storage: refusal staging mismatch",
            ));
        }
        unlinkat(staging, temporary.as_str(), UnlinkatFlags::NoRemoveDir)?;
        staging.sync_all()?;
    }
    store::remove(journal.publication_root(), &key)
}

fn raw_name(value: &str) -> Result<std::ffi::OsString> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MailError::Invalid("refusal filename encoding"));
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| MailError::Invalid("refusal filename encoding"))
        })
        .collect::<Result<Vec<_>>>()?;
    if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'/') {
        return Err(MailError::Invalid("refusal filename component"));
    }
    Ok(OsStr::from_bytes(&bytes).to_owned())
}

/// Reconcile withdrawn/changed sources and service-only unpublished projections.
pub(super) fn maintain(
    journal: &Journal,
    outbox: &File,
    staging: &File,
    sender: &str,
) -> Result<()> {
    let pending = journal
        .records()?
        .into_iter()
        .filter(|record| record.sender == sender && record.completed.is_none())
        .map(|record| record.outgoing)
        .collect::<std::collections::BTreeSet<_>>();
    let mut temporaries = std::collections::BTreeSet::new();
    for key in store::names(journal.publication_root())?
        .into_iter()
        .filter(|name| name.starts_with("refusal-"))
    {
        let binding: Binding = store::read(journal.publication_root(), &key, RECORD_MAX_BYTES)?;
        if binding.sender != sender {
            continue;
        }
        let name = raw_name(&binding.source_hex)?;
        if binding.version != 1
            || key != self::key(sender, &name)
            || binding.sidecar != sidecar(&name)
        {
            return Err(MailError::Invalid("refusal binding mismatch"));
        }
        let source = io::child(outbox, Path::new(&name), false);
        let absent = matches!(&source,Err(MailError::Io(error)) if error.kind()==std::io::ErrorKind::NotFound);
        let changed = source
            .as_ref()
            .ok()
            .and_then(|file| io::bounded(file, super::journal::MAX_LETTER_BYTES).ok())
            .is_some_and(|bytes| {
                binding
                    .source_digest
                    .as_ref()
                    .is_some_and(|prior| *prior != digest(&bytes))
            });
        if !name.to_str().is_some_and(|name| pending.contains(name)) && (absent || changed) {
            clear(journal, outbox, staging, sender, &name)?;
        } else {
            temporaries.insert(temporary(&key));
        }
    }
    for name in io::names(staging)? {
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("reason-") && !temporaries.contains(name) {
            let file = io::child(staging, Path::new(name), false)?;
            let info = file.metadata()?;
            if info.uid() != nix::unistd::geteuid().as_raw() || !info.is_file() || info.nlink() != 1
            {
                return Err(MailError::Invalid(
                    "unsafe-storage: unbound refusal staging",
                ));
            }
            unlinkat(staging, name, UnlinkatFlags::NoRemoveDir)?;
            staging.sync_all()?;
        }
    }
    Ok(())
}

pub(super) struct Projection<'a> {
    pub sender: &'a str,
    pub name: &'a OsStr,
    pub group: u32,
    pub observation: Option<(u64, String)>,
    pub code: &'a str,
    pub reason: &'a str,
    pub now: Instant,
    pub delivery: Option<Instant>,
    pub staging_bytes: u64,
}
/// Binding is durable before the one publication rename; its exact staged inode
/// is the only sidecar this operation may complete after interruption.
pub(super) fn project(
    journal: &Journal,
    outbox: &File,
    staging: &File,
    projection: Projection<'_>,
) -> Result<()> {
    clear(journal, outbox, staging, projection.sender, projection.name)?;
    maintain(journal, outbox, staging, projection.sender)?;
    let name = sidecar(projection.name);
    if io::child(outbox, Path::new(&name), false).is_ok() {
        return Err(MailError::Invalid(
            "unsafe-storage: sidecar destination collision",
        ));
    }
    let reason = Sidecar {
        version: 1,
        filename: projection.name.to_str().map(str::to_owned),
        filename_hex: hex(projection.name.as_bytes()),
        bytes: projection.observation.as_ref().map(|value| value.0),
        digest: projection.observation.as_ref().map(|value| value.1.clone()),
        code: projection.code.into(),
        reason: projection.reason.into(),
        observed: projection.now,
        delivery: projection.delivery,
    };
    let bytes = store::encode(&reason)?;
    if bytes.len() as u64 > RECORD_MAX_BYTES
        || projection.staging_bytes.saturating_add(bytes.len() as u64)
            > super::journal::STAGING_MAX_BYTES
        || store::size(journal.publication_root())?
            .saturating_add(RECORD_MAX_BYTES + 2 * super::journal::SUMMARY_MAX_BYTES)
            > super::journal::JOURNAL_MAX_BYTES
    {
        return Err(MailError::Capacity);
    }
    let key = key(projection.sender, projection.name);
    let temporary = temporary(&key);
    let mut file = File::from(openat2(
        staging,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::S_IRUSR | Mode::S_IWUSR)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    #[cfg(test)]
    boundary(1)?;
    fchown(&file, None, Some(Gid::from_raw(projection.group)))?;
    fchmod(&file, Mode::from_bits_truncate(0o640))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    staging.sync_all()?;
    #[cfg(test)]
    boundary(2)?;
    let info = file.metadata()?;
    let binding = Binding {
        version: 1,
        sender: projection.sender.into(),
        source_hex: hex(projection.name.as_bytes()),
        sidecar: name.clone(),
        identity: Identity {
            device: info.dev(),
            inode: info.ino(),
        },
        digest: digest(&bytes),
        source_digest: reason.digest,
    };
    store::write(
        journal.publication_root(),
        journal.publication_root(),
        &key,
        &binding,
        false,
    )?;
    #[cfg(test)]
    boundary(3)?;
    renameat2(
        staging,
        temporary.as_str(),
        outbox,
        name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    )?;
    #[cfg(test)]
    boundary(4)?;
    outbox.sync_all()?;
    staging.sync_all()?;
    #[cfg(test)]
    boundary(5)?;
    Ok(())
}

#[cfg(test)]
thread_local! { pub(super) static STOP: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
fn boundary(point: u8) -> Result<()> {
    if STOP.with(|stop| stop.get() == point) {
        return Err(MailError::Invalid("fixture interruption"));
    }
    Ok(())
}
