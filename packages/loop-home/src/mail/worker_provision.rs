//! Namespace-root coordination of retained worker identity receipts and mailbox birth.
use super::birth::{self, Identity};
use super::configuration_store::ConfigurationStore;
use super::journal::{MailError, Result};
use super::{acl, io, provision};
use crate::allocations::Allocations;
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::Mode;
use nix::sys::stat::fchmod;
use nix::unistd::{Gid, Uid, fchown};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    identity: Identity,
    retired: bool,
}
fn receipt_name(identity: &Identity) -> String {
    format!(
        "name-{}.toml",
        super::journal::digest(identity.name.as_bytes())
    )
}
/// Implementation bound for protected receipt metadata, not a lexical name bound.
const MAX_RECEIPT_BYTES: u64 = 4096;

fn admit(prior: Option<&Receipt>, identity: &Identity, phase: &str) -> Result<()> {
    if let Some(saved) = prior {
        if saved.retired && phase != "retire" {
            return Err(MailError::Invalid(
                "retired-worker: this worker birth name is retired; prepare a fresh worker lifetime",
            ));
        }
        if saved.identity != *identity {
            return Err(invalid());
        }
    }
    Ok(())
}
const fn invalid() -> MailError {
    MailError::Invalid("unsafe-storage: worker birth receipt")
}
fn failure(error: impl std::fmt::Display) -> MailError {
    MailError::Io(std::io::Error::other(error.to_string()))
}
fn unavailable(loop_name: &str, identity: &Identity, error: MailError) -> MailError {
    match error {
        MailError::Io(error) => MailError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "unavailable endpoint {loop_name}+{}: {error}",
                identity.name
            ),
        )),
        error => error,
    }
}
fn metadata(file: &File, owner: u32, mode: u32, directory: bool) -> Result<()> {
    let info = file.metadata()?;
    if info.uid() != owner
        || info.mode() & 0o7777 != mode
        || (directory && !info.is_dir())
        || (!directory && (!info.is_file() || info.nlink() != 1))
    {
        return Err(invalid());
    }
    Ok(())
}
fn read_receipts(root: &File, owner: u32) -> Result<Vec<Receipt>> {
    metadata(root, owner, 0o700, true)?;
    let mut receipts = Vec::new();
    let mut names = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut uids = BTreeSet::new();
    for name in io::names(root)? {
        let name = name.to_str().ok_or_else(invalid)?;
        if name.starts_with(".birth-") {
            continue;
        }
        let file = io::child(root, Path::new(name), false)?;
        metadata(&file, owner, 0o600, false)?;
        let bytes = io::bounded(&file, MAX_RECEIPT_BYTES)?;
        let receipt: Receipt = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let identity = &receipt.identity;
        crate::registry::validate_name(&identity.name).map_err(failure)?;
        if name != receipt_name(identity)
            || !(1000..=65535).contains(&identity.uid)
            || identity.uid == 65534
            || identity.reservation.is_empty()
            || !names.insert(identity.name.clone())
            || !references.insert(identity.reservation.clone())
            || (!receipt.retired && !uids.insert(identity.uid))
        {
            return Err(invalid());
        }
        receipts.push(receipt);
    }
    Ok(receipts)
}
fn registered(home: &Path, name: &str) -> Result<crate::LoopRecord> {
    crate::registry::validate_name(name).map_err(failure)?;
    let canonical = home.join(".config/loops/registry.toml");
    let row = crate::load_registry(&canonical)
        .map_err(failure)?
        .row(name, home)
        .map_err(failure)?;
    let selected = crate::registry_path(std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(), home);
    if selected != canonical {
        let selected = crate::load_registry(&selected)
            .map_err(failure)?
            .row(name, home)
            .map_err(failure)?;
        if selected.uid != row.uid || selected.home != row.home {
            return Err(MailError::Invalid(
                "invalid-directory: worker birth registry differs from service registry",
            ));
        }
    }
    Ok(row)
}

fn history(home: &Path, receipts: &[Receipt], owner: u32) -> Result<()> {
    let workers = match io::absolute(&home.join("workers"), true) {
        Ok(workers) => workers,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if workers.metadata()?.uid() != owner {
        return Err(MailError::Invalid(
            "invalid-directory: worker-run execution homes under workers/ require relocation to worker-homes/",
        ));
    }
    metadata(&workers, owner, acl::preserved_mode(&workers, 0o711), true)?;
    let expected = receipts
        .iter()
        .map(|receipt| receipt.identity.name.as_str())
        .collect::<BTreeSet<_>>();
    for name in io::names(&workers)? {
        if !name.to_str().is_some_and(|name| expected.contains(name)) {
            return Err(MailError::Invalid(
                "invalid-directory: worker history requires reconciliation",
            ));
        }
    }
    Ok(())
}

/// Read lifetime UID reservations from the protected registered loop home.
///
/// # Errors
/// Refuses unsafe receipts or worker homes whose lifetime history needs reconciliation.
pub fn reserved_uids(home: &Path, loop_name: &str) -> Result<BTreeSet<u32>> {
    let row = registered(home, loop_name)?;
    let owner = io::search_directory(home)?.metadata()?.uid();
    let root = match io::absolute(&row.home.join(".mail-births"), true) {
        Ok(root) => root,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            history(&row.home, &[], owner)?;
            return Ok(BTreeSet::new());
        }
        Err(error) => return Err(error),
    };
    let lock =
        Flock::lock(root, FlockArg::LockShared).map_err(|(_, error)| MailError::from(error))?;
    let receipts = read_receipts(&lock, owner)?;
    history(&row.home, &receipts, owner)?;
    Ok(receipts
        .into_iter()
        .filter(|receipt| !receipt.retired)
        .map(|receipt| receipt.identity.uid)
        .collect())
}

fn receipt(root: &File, identity: &Identity) -> Result<()> {
    write_receipt(root, identity, false)
}
fn write_receipt(root: &File, identity: &Identity, retired: bool) -> Result<()> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let bytes = toml::to_string(&Receipt {
        identity: identity.clone(),
        retired,
    })
    .map_err(|_| invalid())?;
    let (temporary, mut file) = loop {
        let temporary = format!(
            ".birth-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        match openat2(
            root,
            temporary.as_str(),
            OpenHow::new()
                .flags(OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
                .mode(Mode::from_bits_truncate(0o600))
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(file) => break (temporary, File::from(file)),
            Err(nix::errno::Errno::EEXIST) => {}
            Err(error) => return Err(error.into()),
        }
    };
    file.write_all(bytes.as_bytes())?;
    file.sync_all()?;
    renameat2(
        root,
        temporary.as_str(),
        root,
        receipt_name(identity).as_str(),
        if retired {
            RenameFlags::empty()
        } else {
            RenameFlags::RENAME_NOREPLACE
        },
    )?;
    root.sync_all()?;
    Ok(())
}
fn configure(
    row: &crate::LoopRecord,
    service: u32,
    group: u32,
    phase: &str,
    identity: &Identity,
) -> Result<()> {
    let arguments = [
        "_mail-worker-state".into(),
        ".".into(),
        OsString::from(service.to_string()),
        phase.into(),
        OsString::from(&identity.name),
        OsString::from(identity.uid.to_string()),
        OsString::from(&identity.reservation),
    ];
    provision::spawn_identity(row.uid, group, Some(&row.home.join("private")), &arguments)
}

fn existing(parent: &File, name: &str) -> Result<Option<File>> {
    match io::child(parent, Path::new(name), true) {
        Ok(file) => Ok(Some(file)),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn verify_folders(
    worker: &File,
    identity: &Identity,
    service: u32,
    group: u32,
    verify_only: bool,
) -> Result<()> {
    metadata(worker, 0, 0o711, true)?;
    if worker.metadata()?.gid() != 0 {
        return Err(invalid());
    }
    acl::transport(worker)?;
    // A published endpoint with missing state requires recovery, not fresh creation.
    io::child(worker, Path::new("mail"), true)?;
    if verify_only {
        provision::verify_tree(worker, "mail", identity.uid, service, group)?;
    } else {
        provision::tree(worker, "mail", identity.uid, service, group)?;
    }
    let staging = io::child(worker, Path::new(".mail-staging"), true)?;
    metadata(&staging, service, 0o700, true)?;
    if staging.metadata()?.gid() != service {
        return Err(invalid());
    }
    acl::transport(&staging)
}

fn folders(
    parent: &File,
    identity: &Identity,
    service: u32,
    group: u32,
    phase: &str,
) -> Result<()> {
    let (staging, _) = provision::directory(parent, ".mail-worker-staging", 0, 0, 0o700)?;
    let mut workers = existing(parent, "workers")?;
    if workers.as_ref().is_some_and(|root| {
        root.metadata()
            .is_ok_and(|info| info.mode() & 0o7777 == 0o700)
    }) {
        workers = Some(provision::staged_directory(parent, "workers", 0, 0, 0o711)?.0);
    }
    if let Some(workers) = &workers {
        let info = workers.metadata()?;
        if info.uid() != 0
            || info.gid() != 0
            || info.mode() & 0o7777 != acl::preserved_mode(workers, 0o711)
        {
            return Err(invalid());
        }
        acl::grant_ancestor(workers, service, 5, 0o711)?;
    }
    let published = match &workers {
        Some(workers) => existing(workers, &identity.name)?,
        None => None,
    };
    if let Some(worker) = published {
        verify_folders(&worker, identity, service, group, false)?;
    } else {
        let (worker, _) = provision::staged_directory(&staging, &identity.name, 0, 0, 0o711)?;
        let complete = existing(&worker, "mail")?.is_some();
        provision::tree(
            &worker,
            if complete {
                "mail"
            } else {
                ".mail-provisioning"
            },
            identity.uid,
            service,
            group,
        )?;
        provision::staged_directory(&worker, ".mail-staging", service, service, 0o700)?;
        if phase == "finish" {
            if !complete {
                renameat2(
                    &worker,
                    ".mail-provisioning",
                    &worker,
                    "mail",
                    RenameFlags::RENAME_NOREPLACE,
                )?;
                worker.sync_all()?;
            }
            let workers = match workers {
                Some(workers) => workers,
                None => provision::directory(parent, "workers", 0, 0, 0o711)?.0,
            };
            acl::grant_ancestor(&workers, service, 5, 0o711)?;
            renameat2(
                &staging,
                identity.name.as_str(),
                &workers,
                identity.name.as_str(),
                RenameFlags::RENAME_NOREPLACE,
            )?;
            staging.sync_all()?;
            workers.sync_all()?;
        }
    }
    Ok(())
}

pub(super) fn worker_quiet(proc_root: &Path, uid: u32) -> Result<()> {
    for entry in std::fs::read_dir(proc_root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let status = match std::fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let uids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or_else(invalid)?;
        for value in uids.split_whitespace() {
            if value.parse::<u32>().map_err(|_| invalid())? == uid {
                return Err(MailError::Invalid(
                    "unsafe-storage: worker processes must be drained before retirement",
                ));
            }
        }
    }
    Ok(())
}

fn take_custody(file: &File, service: u32) -> Result<()> {
    // Revoke the reusable mailbox group as well as the former actor UID.
    acl::remove_grants(file)?;
    fchown(
        file,
        Some(Uid::from_raw(service)),
        Some(Gid::from_raw(service)),
    )?;
    fchmod(file, Mode::from_bits_truncate(0o700))?;
    file.sync_all()?;
    Ok(())
}
fn retire_folders(parent: &File, identity: &Identity, service: u32) -> Result<()> {
    for root in ["workers", ".mail-worker-staging"] {
        let Some(root) = existing(parent, root)? else {
            continue;
        };
        let Some(worker) = existing(&root, &identity.name)? else {
            continue;
        };
        metadata(&worker, 0, 0o711, true)?;
        for name in ["mail", ".mail-provisioning"] {
            let Some(mail) = existing(&worker, name)? else {
                continue;
            };
            if mail.metadata()?.uid() != service {
                return Err(invalid());
            }
            take_custody(&mail, service)?;
            for folder in ["draft", "outbox", "read"] {
                let Some(folder) = existing(&mail, folder)? else {
                    continue;
                };
                if ![identity.uid, service].contains(&folder.metadata()?.uid()) {
                    return Err(invalid());
                }
                take_custody(&folder, service)?;
            }
            mail.sync_all()?;
        }
        worker.sync_all()?;
    }
    Ok(())
}

/// Inspect the protected terminal receipt before resuming a historical migration mapping.
///
/// # Errors
/// A name bound to another identity or an unsafe receipt refuses the mapping.
pub(super) fn retired_identity(home: &Path, loop_name: &str, identity: &Identity) -> Result<bool> {
    let row = registered(home, loop_name)?;
    let Some(root) = existing(&io::absolute(&row.home, true)?, ".mail-births")? else {
        return Ok(false);
    };
    let lock =
        Flock::lock(root, FlockArg::LockShared).map_err(|(_, error)| MailError::from(error))?;
    for receipt in read_receipts(&lock, 0)? {
        if receipt.identity.name == identity.name {
            if receipt.identity != *identity {
                return Err(invalid());
            }
            return Ok(receipt.retired);
        }
    }
    Ok(false)
}
/// Recheck both terminal receipt and loop-owned configuration through the common entry.
///
/// # Errors
/// The namespace root cannot substitute an unchecked configuration projection.
pub(super) fn verify_retired(home: &Path, loop_name: &str, identity: &Identity) -> Result<()> {
    if !Uid::effective().is_root() || !retired_identity(home, loop_name, identity)? {
        return Err(invalid());
    }
    let row = registered(home, loop_name)?;
    let allocations =
        Allocations::read(&home.join(".config/loops/allocations.toml")).map_err(failure)?;
    let service = allocations.mail_uid().ok_or_else(invalid)?;
    let group = allocations.mail_group(loop_name, None).map_err(failure)?;
    configure(&row, service, group, "verify-retired", identity)
}

/// Reserve, finish or retire one immutable worker lifetime through the loop identity.
///
/// The launcher invokes reserve before creating the worker home and finish only
/// after the home is complete. Retirement retains every receipt and mailbox.
///
/// # Errors
/// Requires namespace root, a validated identity grant and unchanged protected custody.
pub fn coordinate(home: &Path, loop_name: &str, identity: &Identity, phase: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        return Err(MailError::Invalid(
            "unsafe-storage: namespace-root worker birth required",
        ));
    }
    if !matches!(
        phase,
        "reserve" | "finish" | "retire" | "verify" | "verify-only"
    ) {
        return Err(invalid());
    }
    crate::registry::validate_name(&identity.name)
        .map_err(|_| MailError::Invalid("invalid-name: worker birth name"))?;
    let row = registered(home, loop_name)?;
    if existing(&io::absolute(&row.home, true)?, ".mail-migration-hold")?.is_some() {
        return Err(MailError::Invalid(
            "invalid-directory: retained migration history requires namespace reconciliation before worker birth",
        ));
    }
    let allocations =
        Allocations::read(&home.join(".config/loops/allocations.toml")).map_err(failure)?;
    if !allocations
        .get(loop_name)
        .is_some_and(|block| block.contains(identity.uid))
        || identity.reservation.is_empty()
    {
        return Err(invalid());
    }
    let service = allocations.mail_uid().ok_or_else(invalid)?;
    let group = allocations
        .mail_group(loop_name, Some(identity.uid))
        .map_err(failure)?;
    let loop_group = allocations.mail_group(loop_name, None).map_err(failure)?;
    let parent = io::absolute(&row.home, true)?;
    let info = parent.metadata()?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let births = birth_directory(&parent, phase == "verify-only")?;
    let lock = Flock::lock(births, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))?;
    let receipts = read_receipts(&lock, 0)?;
    let prior = receipts
        .iter()
        .find(|saved| saved.identity.name == identity.name);
    admit(prior, identity, phase)?;
    if prior.is_none() {
        if phase != "reserve"
            || receipts.iter().any(|saved| {
                (!saved.retired && saved.identity.uid == identity.uid)
                    || saved.identity.reservation == identity.reservation
            })
        {
            return Err(invalid());
        }
        if let Some(workers) = existing(&parent, "workers")? {
            let expected = receipts
                .iter()
                .map(|receipt| receipt.identity.name.as_str())
                .collect::<BTreeSet<_>>();
            for name in io::names(&workers)? {
                if !name.to_str().is_some_and(|name| expected.contains(name)) {
                    return Err(MailError::Invalid(
                        "invalid-directory: worker history requires reconciliation",
                    ));
                }
            }
        }
        // A missing protected receipt cannot impersonate an older binding whose
        // loop-owned configuration survives. Check before creating any new receipt.
        configure(&row, service, loop_group, "unreserved", identity)?;
        receipt(&lock, identity)?;
    }
    if phase == "retire" {
        if prior.is_some_and(|receipt| receipt.retired) {
            return Ok(());
        }
        // The receipt stays allocated across every interruption until both custody
        // and the loop-owned binding durably record the terminal transition.
        worker_quiet(Path::new("/proc"), identity.uid)?;
        retire_folders(&parent, identity, service)?;
        configure(&row, service, loop_group, "retire", identity)?;
        release_pins(home, loop_name, identity, service)?;
        return write_receipt(&lock, identity, true);
    }
    if matches!(phase, "verify" | "verify-only") {
        verify_active_folders(
            &parent,
            loop_name,
            identity,
            service,
            group,
            phase == "verify-only",
        )?;
        return configure(&row, service, loop_group, phase, identity);
    }
    configure(&row, service, loop_group, "reserve", identity)?;
    folders(&parent, identity, service, group, phase)
        .map_err(|error| unavailable(loop_name, identity, error))?;
    if phase == "finish" {
        configure(&row, service, loop_group, "activate", identity)?;
    }
    Ok(())
}

fn verify_active_folders(
    parent: &File,
    loop_name: &str,
    identity: &Identity,
    service: u32,
    group: u32,
    verify_only: bool,
) -> Result<()> {
    let workers = io::child(parent, Path::new("workers"), true)?;
    let worker = io::child(&workers, Path::new(&identity.name), true)
        .map_err(|error| unavailable(loop_name, identity, error))?;
    metadata(&workers, 0, acl::preserved_mode(&workers, 0o711), true)?;
    if workers.metadata()?.gid() != 0 {
        return Err(invalid());
    }
    if verify_only {
        acl::verify_ancestor(&workers, service, 5, 0o711)?;
    } else {
        acl::grant_ancestor(&workers, service, 5, 0o711)?;
    }
    verify_folders(&worker, identity, service, group, verify_only)
}

fn birth_directory(parent: &File, verify_only: bool) -> Result<File> {
    if verify_only {
        let births = io::child(parent, Path::new(".mail-births"), true)?;
        metadata(&births, 0, 0o700, true)?;
        if births.metadata()?.gid() != 0 {
            return Err(invalid());
        }
        Ok(births)
    } else {
        Ok(provision::directory(parent, ".mail-births", 0, 0, 0o700)?.0)
    }
}

/// Keep the protected lifetime locked across service verification and pin publication.
///
/// # Errors
/// Requires namespace root and an unchanged active receipt, folder and binding.
pub(super) fn hold_active(
    home: &Path,
    loop_name: &str,
    identity: &Identity,
    verify_only: bool,
) -> Result<Flock<File>> {
    coordinate(
        home,
        loop_name,
        identity,
        if verify_only { "verify-only" } else { "verify" },
    )?;
    let row = registered(home, loop_name)?;
    let parent = io::absolute(&row.home, true)?;
    let births = io::child(&parent, Path::new(".mail-births"), true)?;
    metadata(&births, 0, 0o700, true)?;
    let guard = Flock::lock(births, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))?;
    if !read_receipts(&guard, 0)?
        .iter()
        .any(|receipt| receipt.identity == *identity && !receipt.retired)
    {
        return Err(invalid());
    }
    let allocations =
        Allocations::read(&home.join(".config/loops/allocations.toml")).map_err(failure)?;
    let service = allocations.mail_uid().ok_or_else(invalid)?;
    configure(
        &row,
        service,
        allocations.mail_group(loop_name, None).map_err(failure)?,
        if verify_only { "verify-only" } else { "verify" },
        identity,
    )?;
    Ok(guard)
}
fn release_pins(home: &Path, loop_name: &str, identity: &Identity, service: u32) -> Result<()> {
    let args = [
        OsString::from("_mail-worker-pins"),
        home.as_os_str().to_owned(),
        OsString::from(service.to_string()),
        OsString::from(loop_name),
        OsString::from(&identity.name),
        OsString::from(identity.uid.to_string()),
        OsString::from(&identity.reservation),
    ];
    provision::spawn_identity(service, service, None, &args)
}

fn retire_execution(home: &Path, loop_name: &str, lane: &str, identity: &Identity) -> Result<()> {
    if !Uid::effective().is_root() || !super::valid_identity_name(lane) {
        return Err(invalid());
    }
    let prefix = format!("worker-run:{lane}:{}:", identity.uid);
    if !identity
        .reservation
        .strip_prefix(&prefix)
        .is_some_and(|claim| !claim.is_empty() && claim.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid());
    }
    let row = registered(home, loop_name)?;
    let parent = io::absolute(&row.home, true)?;
    let info = parent.metadata()?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err(invalid());
    }
    let births = io::child(&parent, Path::new(".mail-births"), true)?;
    metadata(&births, 0, 0o700, true)?;
    let lock = Flock::lock(births, FlockArg::LockExclusive)
        .map_err(|(_, error)| MailError::from(error))?;
    if !read_receipts(&lock, 0)?
        .iter()
        .any(|receipt| receipt.identity == *identity)
    {
        return Err(invalid());
    }
    worker_quiet(Path::new("/proc"), identity.uid)?;
    archive_execution(&parent, lane, identity, row.uid)
}
fn archive_execution(parent: &File, lane: &str, identity: &Identity, loop_uid: u32) -> Result<()> {
    let owner = Uid::effective().as_raw();
    let Some(homes) = existing(parent, "worker-homes")? else {
        return Ok(());
    };
    metadata(&homes, loop_uid, 0o710, true)?;
    let source = existing(&homes, lane)?;
    let (history, _) = provision::directory(
        parent,
        ".worker-history",
        owner,
        Gid::effective().as_raw(),
        0o700,
    )?;
    let prior = existing(&history, &identity.name)?;
    if let Some(prior) = prior {
        metadata(&prior, owner, 0o700, true)?;
        if source.is_some() {
            return Err(MailError::Invalid(
                "changed-source: retired execution home and active lane both exist",
            ));
        }
        return Ok(());
    }
    let Some(source) = source else { return Ok(()) };
    let info = source.metadata()?;
    if !(info.uid() == loop_uid && info.mode() & 0o7777 == 0o750
        || info.uid() == owner && info.mode() & 0o7777 == 0o700)
    {
        return Err(invalid());
    }
    take_custody(&source, owner)?;
    renameat2(
        &homes,
        lane,
        &history,
        identity.name.as_str(),
        RenameFlags::RENAME_NOREPLACE,
    )?;
    homes.sync_all()?;
    history.sync_all()?;
    let moved = io::child(&history, Path::new(&identity.name), true)?;
    let after = moved.metadata()?;
    if (after.dev(), after.ino()) != (info.dev(), info.ino()) {
        return Err(MailError::Invalid(
            "changed-source: execution home changed during retirement",
        ));
    }
    metadata(&moved, owner, 0o700, true)
}

fn text(value: &std::ffi::OsStr) -> Result<&str> {
    value.to_str().ok_or_else(invalid)
}

/// Dispatch the private namespace and loop-identity halves without activating a service.
pub fn entry(arguments: &[OsString], report: &mut dyn std::io::Write) -> u8 {
    let result = (|| {
        let [mode, path, scope, phase, name, uid, reservation] = arguments else {
            return Err(invalid());
        };
        let identity = Identity {
            name: text(name)?.into(),
            uid: text(uid)?.parse().map_err(|_| invalid())?,
            reservation: text(reservation)?.into(),
        };
        let path = PathBuf::from(path);
        let phase = text(phase)?;
        if mode == "_mail-worker-home" {
            return retire_execution(&path, text(scope)?, phase, &identity);
        }
        if mode == "_mail-worker-birth" {
            return coordinate(&path, text(scope)?, &identity, phase);
        }
        if mode == "_mail-worker-pins" {
            let service = text(scope)?.parse::<u32>().map_err(|_| invalid())?;
            if Uid::effective().as_raw() != service
                || super::command::settings(&path)?.uid != service
            {
                return Err(invalid());
            }
            crate::registry::validate_name(phase).map_err(failure)?;
            return super::journal::release_reservation_family(
                &io::absolute(&path.join(".var/loops/.mail-service"), true)?,
                &identity.pin_family(phase),
            );
        }
        if mode != "_mail-worker-state" {
            return Err(invalid());
        }
        let service = text(scope)?.parse::<u32>().map_err(|_| invalid())?;
        if !(1000..=65535).contains(&service)
            || service == 65534
            || service == Uid::effective().as_raw()
        {
            return Err(invalid());
        }
        let mut store = if phase == "verify-only" {
            ConfigurationStore::open_existing(&path, service)?
        } else {
            ConfigurationStore::open(&path, service)?
        };
        match phase {
            "reserve" => birth::reserve(&mut store, &identity),
            "activate" => birth::activate(&mut store, &identity),
            "retire" => birth::retire(&mut store, &identity),
            "verify" | "verify-only" => birth::verify(&store, &identity),
            "verify-retired" => birth::verify_retired(&store, &identity),
            "unreserved" => birth::unreserved(&store, &identity),
            _ => Err(invalid()),
        }
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _written = writeln!(report, "{error}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// ´claim:loophome:birth-preview-never-ensures-missing-or-drifted-receipts´
    /// ´test:unit:birth-preview-never-ensures-missing-or-drifted-receipts´
    #[test]
    fn birth_preview_never_ensures_missing_or_drifted_receipts() {
        let root = std::env::temp_dir().join(format!("birth-preview-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let parent = File::open(&root).expect("parent");
        assert!(birth_directory(&parent, true).is_err());
        let path = root.join(".mail-births");
        assert!(!path.exists());
        std::fs::create_dir(&path).expect("drifted directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        let before = std::fs::metadata(&path).expect("metadata");
        assert!(birth_directory(&parent, true).is_err());
        let after = std::fs::metadata(&path).expect("metadata");
        assert_eq!(
            (
                before.uid(),
                before.gid(),
                before.mode(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.uid(),
                after.gid(),
                after.mode(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    /// ´claim:loophome:closed-execution-home-is-sealed-before-uid-release´
    /// ´test:unit:closed-execution-home-is-sealed-before-uid-release´
    #[test]
    fn closed_execution_home_is_sealed_before_uid_release() {
        let root =
            std::env::temp_dir().join(format!("execution-retirement-{}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture");
        let parent = File::open(&root).expect("parent");
        let owner = Uid::effective().as_raw();
        let group = Gid::effective().as_raw();
        let (homes, _) =
            provision::directory(&parent, "worker-homes", owner, group, 0o710).expect("homes");
        let (lane, _) = provision::directory(&homes, "lane", owner, group, 0o750).expect("lane");
        std::fs::write(root.join("worker-homes/lane/evidence"), [0, 255]).expect("retained bytes");
        drop(lane);
        let identity = Identity::for_reservation(owner, "worker-run:lane:1:1".into());
        archive_execution(&parent, "lane", &identity, owner).expect("retirement");
        archive_execution(&parent, "lane", &identity, owner).expect("retry");
        let retained = root.join(".worker-history").join(&identity.name);
        assert_eq!(
            std::fs::read(retained.join("evidence")).expect("bytes"),
            [0, 255]
        );
        assert_eq!(
            std::fs::metadata(&retained).expect("custody").mode() & 0o7777,
            0o700
        );
        assert!(!root.join("worker-homes/lane").exists());
        provision::directory(&homes, "lane", owner, group, 0o750).expect("next preparation");
        assert!(archive_execution(&parent, "lane", &identity, owner).is_err());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    /// ´claim:loophome:retired-birth-collision-names-the-refusal´
    /// ´test:unit:retired-birth-collision-names-the-refusal´
    #[test]
    fn retired_birth_collision_names_the_refusal() {
        let identity = Identity::for_reservation(4000, "worker-run:lane:4000:1".into());
        let receipt = Receipt {
            identity: identity.clone(),
            retired: true,
        };
        assert!(
            admit(Some(&receipt), &identity, "reserve")
                .expect_err("retired name")
                .to_string()
                .starts_with("retired-worker:")
        );
        admit(Some(&receipt), &identity, "retire").expect("terminal retry");
    }

    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    struct Fixture {
        root: PathBuf,
        loop_home: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "worker-history-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
            for path in [
                ".config",
                ".config/loops",
                ".var",
                ".var/loops",
                ".var/loops/alpha",
            ] {
                fs::create_dir(root.join(path)).expect("ancestor");
                fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o711))
                    .expect("ancestor mode");
            }
            fs::write(root.join(".config/loops/registry.toml"),"namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{name='alpha',uid=41001,launch='dev/alpha'}]\n").expect("registry");
            let loop_home = root.join(".var/loops/alpha");
            Self { root, loop_home }
        }
        fn receipts(&self) -> File {
            let path = self.loop_home.join(".mail-births");
            fs::create_dir(&path).expect("receipt root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("receipt mode");
            File::open(path).expect("root descriptor")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.root);
        }
    }

    /// ´claim:loophome:worker-uid-history-survives-before-any-run-table-or-worker-home´
    /// ´test:unit:worker-uid-history-survives-before-any-run-table-or-worker-home´
    #[test]
    fn worker_uid_history_survives_before_any_run_table_or_worker_home() {
        let fixture = Fixture::new();
        assert!(
            reserved_uids(&fixture.root, "alpha")
                .expect("fresh history")
                .is_empty()
        );
        let root = fixture.receipts();
        let identity = Identity {
            name: "worker-3000".into(),
            uid: 3000,
            reservation: "lane:3000".into(),
        };
        receipt(&root, &identity).expect("durable reservation");
        drop(root);
        assert_eq!(
            reserved_uids(&fixture.root, "alpha").expect("retained lifetime"),
            BTreeSet::from([3000])
        );
        assert!(!fixture.loop_home.join("workers").exists());
    }

    /// ´claim:loophome:worker-history-loss-never-releases-a-provisioned-identity´
    /// ´test:unit:worker-history-loss-never-releases-a-provisioned-identity´
    #[test]
    fn worker_history_loss_never_releases_a_provisioned_identity() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.loop_home.join("workers")).expect("workers");
        fs::set_permissions(
            fixture.loop_home.join("workers"),
            fs::Permissions::from_mode(0o711),
        )
        .expect("workers mode");
        fs::create_dir(fixture.loop_home.join("workers/retained")).expect("known lifetime");
        assert!(reserved_uids(&fixture.root, "alpha").is_err());
        drop(fixture.receipts());
        assert!(reserved_uids(&fixture.root, "alpha").is_err());
    }

    /// ´claim:loophome:worker-history-rejects-widened-and-duplicate-bindings´
    /// ´test:unit:worker-history-rejects-widened-and-duplicate-bindings´
    #[test]
    fn worker_history_rejects_widened_and_duplicate_bindings() {
        let fixture = Fixture::new();
        let root = fixture.receipts();
        let identity = Identity {
            name: "one".into(),
            uid: 3000,
            reservation: "one".into(),
        };
        receipt(&root, &identity).expect("first");
        fs::set_permissions(
            fixture
                .loop_home
                .join(".mail-births")
                .join(receipt_name(&identity)),
            fs::Permissions::from_mode(0o644),
        )
        .expect("widened");
        assert!(reserved_uids(&fixture.root, "alpha").is_err());
        fs::set_permissions(
            fixture
                .loop_home
                .join(".mail-births")
                .join(receipt_name(&identity)),
            fs::Permissions::from_mode(0o600),
        )
        .expect("restored");
        receipt(
            &root,
            &Identity {
                uid: 3001,
                ..identity
            },
        )
        .expect_err("name receipt cannot be replaced");
    }
    /// ´claim:loophome:retirement-releases-only-terminal-receipts-and-retains-names´
    /// ´test:unit:retirement-releases-only-terminal-receipts-and-retains-names´
    #[test]
    fn retirement_releases_only_terminal_receipts_and_retains_names() {
        let fixture = Fixture::new();
        let root = fixture.receipts();
        let first = Identity::for_reservation(3000, "lane:first".into());
        receipt(&root, &first).expect("reserve");
        assert!(
            reserved_uids(&fixture.root, "alpha")
                .expect("live")
                .contains(&3000)
        );
        write_receipt(&root, &first, true).expect("custody and configuration completed");
        assert!(
            reserved_uids(&fixture.root, "alpha")
                .expect("retired")
                .is_empty()
        );
        let second = Identity::for_reservation(3000, "lane:second".into());
        receipt(&root, &second).expect("new name on released UID");
        assert!(
            reserved_uids(&fixture.root, "alpha")
                .expect("reused")
                .contains(&3000)
        );
        assert!(receipt(&root, &first).is_err());
        let records = read_receipts(&root, Uid::effective().as_raw()).expect("history");
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .any(|receipt| receipt.retired && receipt.identity == first)
        );
    }

    /// ´claim:loophome:terminal-custody-revokes-reusable-group-and-actor-grants´
    /// ´test:unit:terminal-custody-revokes-reusable-group-and-actor-grants´
    #[test]
    fn terminal_custody_revokes_reusable_group_and_actor_grants() {
        let fixture = Fixture::new();
        let folder = fixture.receipts();
        let service = Uid::effective().as_raw();
        acl::grant_outbox(&folder, service + 1).expect("actor grant");
        acl::grant_draft_default(&folder, service + 1).expect("default grant");
        take_custody(&folder, service).expect("terminal custody");
        metadata(&folder, service, 0o700, true).expect("service-only search");
        acl::transport(&folder).expect("no reusable group or actor ACL");
        take_custody(&folder, service).expect("interruption retry");
    }

    /// ´claim:loophome:retirement-refuses-processes-retaining-any-worker-uid´
    /// ´test:unit:retirement-refuses-processes-retaining-any-worker-uid´
    #[test]
    fn retirement_refuses_processes_retaining_any_worker_uid() {
        let fixture = Fixture::new();
        let process = fixture.root.join("123");
        fs::create_dir(&process).expect("process");
        fs::write(process.join("status"), "Uid:\t1000\t3000\t1000\t1000\n").expect("status");
        assert!(worker_quiet(&fixture.root, 3000).is_err());
        fs::write(process.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").expect("released");
        worker_quiet(&fixture.root, 3000).expect("quiet UID");
    }

    /// ´claim:loophome:receipt-reads-stop-at-the-implementation-bound´
    /// ´test:unit:receipt-reads-stop-at-the-implementation-bound´
    #[test]
    fn receipt_reads_stop_at_the_implementation_bound() {
        let fixture = Fixture::new();
        let root = fixture.receipts();
        let identity = Identity::for_reservation(3000, "bounded".into());
        receipt(&root, &identity).expect("receipt");
        let path = fixture
            .loop_home
            .join(".mail-births")
            .join(receipt_name(&identity));
        let mut bytes = fs::read(&path).expect("bytes");
        bytes.push(b'#');
        bytes.resize(
            usize::try_from(MAX_RECEIPT_BYTES).expect("receipt bound fits address space"),
            b' ',
        );
        fs::write(&path, &bytes).expect("inclusive bound");
        read_receipts(&root, Uid::effective().as_raw()).expect("bounded receipt");
        bytes.push(b' ');
        fs::write(&path, &bytes).expect("overflow");
        assert!(
            read_receipts(&root, Uid::effective().as_raw())
                .expect_err("bound")
                .to_string()
                .starts_with("oversize:")
        );
    }

    /// ´claim:loophome:legacy-worker-layout-names-its-required-relocation´
    /// ´test:unit:legacy-worker-layout-names-its-required-relocation´
    #[test]
    fn legacy_worker_layout_names_its_required_relocation() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.loop_home.join("workers")).expect("legacy tree");
        let error = history(&fixture.loop_home, &[], Uid::effective().as_raw() + 1)
            .expect_err("loop-owned legacy root");
        assert!(error.to_string().contains(
            "worker-run execution homes under workers/ require relocation to worker-homes/"
        ));
    }

    /// ´claim:loophome:unrepresentable-worker-endpoints-do-not-change-name-grammar´
    /// ´test:unit:unrepresentable-worker-endpoints-do-not-change-name-grammar´
    #[test]
    fn unrepresentable_worker_endpoints_do_not_change_name_grammar() {
        let fixture = Fixture::new();
        let identity = Identity {
            name: "a".repeat(512),
            uid: 3000,
            reservation: "long".into(),
        };
        crate::registry::validate_name(&identity.name).expect("lexically valid");
        let parent = File::open(&fixture.loop_home).expect("endpoint parent");
        let error = existing(&parent, &identity.name).expect_err("filesystem component limit");
        let error = unavailable("alpha", &identity, error);
        assert!(
            error
                .to_string()
                .starts_with("io-failure: unavailable endpoint alpha+")
        );
        assert!(crate::registry::validate_name(&identity.name).is_ok());
    }
}
