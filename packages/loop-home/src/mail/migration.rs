//! Restartable opaque-byte movement; cutover coordination supplies closed inventory.
use super::{
    io,
    journal::{MailError, Result, digest},
};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::UnlinkatFlags;
use nix::unistd::{Gid, Uid, fchown, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

const MANIFEST: &str = "manifest.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub path: PathBuf,
    pub read: PathBuf,
    pub expected: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Object {
    device: u64,
    inode: u64,
    bytes: u64,
    digest: String,
    uid: u32,
    gid: u32,
    mode: u32,
    attributes: super::migration_metadata::Attributes,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Item {
    name: Vec<u8>,
    source: Object,
    backup: String,
    backed_up: bool,
    restored: Option<Object>,
    prepared: Option<Object>,
    removed: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Store {
    source: Source,
    absent: bool,
    device: u64,
    inode: u64,
    provenance: String,
    destination: Option<(u64, u64)>,
    read_identity: (u64, u64, u32, u32),
    items: Vec<Item>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    stores: Vec<Store>,
    backed_up: bool,
    verified: bool,
    rolled_back: bool,
}
const fn refuse(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn regular(file: &File) -> Result<()> {
    if !file.metadata()?.is_file() {
        return Err(refuse("invalid-file: migration source is not regular"));
    }
    Ok(())
}
fn object(file: &mut File) -> Result<Object> {
    regular(file)?;
    let before = file.metadata()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut count = 0_u64;
    let mut block = [0_u8; 16384];
    loop {
        let size = file.read(&mut block)?;
        if size == 0 {
            break;
        }
        hash.update(&block[..size]);
        count += size as u64;
    }
    let attributes = super::migration_metadata::read(file)?;
    let after = file.metadata()?;
    if before.len() != count
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(refuse(
            "changed-source: migration source changed while hashing",
        ));
    }
    Ok(Object {
        device: before.dev(),
        inode: before.ino(),
        bytes: count,
        digest: hash
            .finalize()
            .iter()
            .flat_map(|byte| {
                let hex = b"0123456789abcdef";
                [
                    char::from(hex[usize::from(byte >> 4)]),
                    char::from(hex[usize::from(byte & 15)]),
                ]
            })
            .collect(),
        uid: before.uid(),
        gid: before.gid(),
        mode: before.mode() & 0o7777,
        attributes,
    })
}
fn same_bytes(a: &Object, b: &Object) -> bool {
    a.bytes == b.bytes && a.digest == b.digest
}
fn same_object(a: &Object, b: &Object) -> bool {
    a.device == b.device && a.inode == b.inode && same_bytes(a, b)
}
fn create(parent: &File, name: &Path) -> Result<File> {
    Ok(File::from(openat2(
        parent,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?))
}
fn copy(source: &mut File, destination: &mut File) -> Result<Object> {
    let wanted = object(source)?;
    source.seek(SeekFrom::Start(0))?;
    std::io::copy(source, destination)?;
    destination.sync_all()?;
    let actual = object(destination)?;
    if !same_bytes(&wanted, &actual) || !same_object(&wanted, &object(source)?) {
        return Err(refuse(
            "changed-source: migration copy differs from opened source",
        ));
    }
    Ok(actual)
}
fn persist(root: &File, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|_| refuse("invalid-directory: migration serialization"))?;
    let temporary = format!(".manifest-{}", digest(&bytes));
    let mut file = match create(root, Path::new(&temporary)) {
        Ok(file) => file,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut held = File::from(openat2(
                root,
                temporary.as_str(),
                OpenHow::new()
                    .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )?);
            let info = held.metadata()?;
            let partial = io::bounded(&held, bytes.len() as u64)?;
            if info.uid() != Uid::effective().as_raw()
                || info.nlink() != 1
                || info.mode() & 0o7777 != 0o600
                || !bytes.starts_with(&partial)
            {
                return Err(refuse(
                    "unsafe-storage: migration manifest scratch conflict",
                ));
            }
            held.set_len(0)?;
            held.seek(SeekFrom::Start(0))?;
            held
        }
        Err(error) => return Err(error),
    };
    file.write_all(&bytes)?;
    file.sync_all()?;
    renameat2(
        root,
        temporary.as_str(),
        root,
        MANIFEST,
        RenameFlags::empty(),
    )?;
    root.sync_all()?;
    Ok(())
}
fn load(root: &File) -> Result<Manifest> {
    let file = io::child(root, Path::new(MANIFEST), false)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != Uid::effective().as_raw()
        || info.mode() & 0o7777 != 0o600
    {
        return Err(refuse("unsafe-storage: migration manifest custody"));
    }
    // The manifest is migration-owned recovery state, not loop-writable input.
    // Streaming decoding adds no history-count limit to the mail specification.
    let result: Manifest = serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|_| refuse("invalid-directory: migration manifest schema"))?;
    if result.version != 1 {
        return Err(refuse("invalid-directory: migration manifest version"));
    }
    Ok(result)
}
fn source(store: &Store) -> Result<File> {
    let source = io::absolute(&store.source.path, true)?;
    let info = source.metadata()?;
    if (info.dev(), info.ino()) != (store.device, store.inode) {
        return Err(refuse("changed-source: migration store replaced"));
    }
    Ok(source)
}
fn read_history(store: &Store) -> Result<File> {
    let file = io::absolute(&store.source.read, true)?;
    let info = file.metadata()?;
    if (info.dev(), info.ino(), info.uid(), info.gid()) != store.read_identity {
        return Err(refuse("changed-source: migration read directory replaced"));
    }
    Ok(file)
}
fn name(item: &Item) -> Result<std::ffi::OsString> {
    if item.name.is_empty()
        || item.name == b"."
        || item.name == b".."
        || item.name.contains(&b'/')
        || item.name.contains(&0)
    {
        return Err(refuse("invalid-directory: migration basename"));
    }
    Ok(std::ffi::OsString::from_vec(item.name.clone()))
}
fn custody(root: &File) -> Result<Flock<File>> {
    let info = root.metadata()?;
    if !info.is_dir() || info.uid() != Uid::effective().as_raw() || info.mode() & 0o7777 != 0o700 {
        return Err(refuse("unsafe-storage: migration state custody"));
    }
    Flock::lock(
        io::child(root, Path::new("."), true)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|_| refuse("changed-source: another migration owns the state"))
}
fn backup(root: &File, manifest: &mut Manifest) -> Result<()> {
    for store_index in 0..manifest.stores.len() {
        if manifest.stores[store_index].absent {
            continue;
        }
        let directory = source(&manifest.stores[store_index])?;
        for item_index in 0..manifest.stores[store_index].items.len() {
            let item = manifest.stores[store_index].items[item_index].clone();
            let mut original = io::child(&directory, Path::new(&name(&item)?), false)?;
            if !same_object(&item.source, &object(&mut original)?) {
                return Err(refuse("changed-source: migration inventory differs"));
            }
            if item.backed_up {
                let mut saved = io::child(root, Path::new(&item.backup), false)?;
                if !same_bytes(&item.source, &object(&mut saved)?) {
                    return Err(refuse("unsafe-storage: migration backup changed"));
                }
                continue;
            }
            let mut saved = match create(root, Path::new(&item.backup)) {
                Ok(file) => file,
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = File::from(openat2(
                        root,
                        item.backup.as_str(),
                        OpenHow::new()
                            .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                            .resolve(
                                ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS,
                            ),
                    )?);
                    regular(&file)?;
                    let info = file.metadata()?;
                    if info.uid() != Uid::effective().as_raw()
                        || info.nlink() != 1
                        || info.mode() & 0o7777 != 0o600
                    {
                        return Err(refuse("unsafe-storage: migration backup scratch custody"));
                    }
                    file.set_len(0)?;
                    file
                }
                Err(error) => return Err(error),
            };
            if !same_bytes(&item.source, &copy(&mut original, &mut saved)?) {
                return Err(refuse("changed-source: migration backup differs"));
            }
            root.sync_all()?;
            manifest.stores[store_index].items[item_index].backed_up = true;
            persist(root, manifest)?;
        }
    }
    manifest.backed_up = true;
    persist(root, manifest)
}
fn disjoint(left: &File, right: &File) -> Result<()> {
    if super::migration_tree::is_ancestor(left, right)?
        || super::migration_tree::is_ancestor(right, left)?
    {
        return Err(refuse("unsafe-storage: migration stores overlap"));
    }
    Ok(())
}
/// Snapshot every byte before allowing movement; optional absence is explicit.
///
/// # Errors
/// Refuses missing expected stores, changed source custody or conflicting inventory.
#[allow(clippy::too_many_lines)] // Inventory is frozen before any source becomes movable.
pub fn prepare(root: &File, sources: Vec<Source>) -> Result<()> {
    let _lock = custody(root)?;
    if io::names(root)?.iter().any(|name| name == MANIFEST) {
        let mut manifest = load(root)?;
        let expected = serde_json::to_vec(&sources)
            .map_err(|_| refuse("invalid-directory: migration sources"))?;
        let actual = serde_json::to_vec(
            &manifest
                .stores
                .iter()
                .map(|store| &store.source)
                .collect::<Vec<_>>(),
        )
        .map_err(|_| refuse("invalid-directory: migration sources"))?;
        if expected != actual || manifest.rolled_back {
            return Err(refuse("changed-source: migration inventory differs"));
        }
        return if manifest.backed_up {
            Ok(())
        } else {
            backup(root, &mut manifest)
        };
    }
    if io::names(root)?
        .iter()
        .any(|name| !name.as_bytes().starts_with(b".manifest-"))
    {
        return Err(refuse("unsafe-storage: unrecorded migration state"));
    }
    let mut manifest = Manifest {
        version: 1,
        stores: Vec::new(),
        backed_up: false,
        verified: false,
        rolled_back: false,
    };
    let mut unique = std::collections::BTreeSet::new();
    let mut source_directories = Vec::new();
    let mut read_directories = Vec::new();
    for (index, specification) in sources.into_iter().enumerate() {
        if !unique.insert(specification.path.clone()) {
            return Err(refuse("invalid-directory: duplicate migration source"));
        }
        let read = io::absolute(&specification.read, true)?;
        disjoint(root, &read)?;
        for source in &source_directories {
            disjoint(source, &read)?;
        }
        read_directories.push(read.try_clone()?);
        let root_info = root.metadata()?;
        let transaction = digest(format!("{}:{}", root_info.dev(), root_info.ino()).as_bytes());
        let mut store = Store {
            source: specification,
            absent: false,
            device: 0,
            inode: 0,
            provenance: format!("legacy-{}-{index:08}", &transaction[..16]),
            destination: None,
            read_identity: (
                read.metadata()?.dev(),
                read.metadata()?.ino(),
                read.metadata()?.uid(),
                read.metadata()?.gid(),
            ),
            items: Vec::new(),
        };
        let directory = match io::absolute(&store.source.path, true) {
            Ok(file) => file,
            Err(MailError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && !store.source.expected =>
            {
                store.absent = true;
                manifest.stores.push(store);
                continue;
            }
            Err(error) => return Err(error),
        };
        disjoint(root, &directory)?;
        for other in source_directories.iter().chain(&read_directories) {
            disjoint(other, &directory)?;
        }
        source_directories.push(directory.try_clone()?);
        let info = directory.metadata()?;
        store.device = info.dev();
        store.inode = info.ino();
        let mut names = io::names(&directory)?;
        names.sort();
        for entry in names {
            let mut file = io::child(&directory, Path::new(&entry), false)?;
            store.items.push(Item {
                name: entry.as_bytes().to_vec(),
                source: object(&mut file)?,
                backup: format!("backup-{index:08}-{:08}", store.items.len()),
                backed_up: false,
                restored: None,
                prepared: None,
                removed: false,
            });
        }
        manifest.stores.push(store);
    }
    persist(root, &manifest)?;
    backup(root, &mut manifest)
}
fn temporary_name(store: &Store, index: usize, purpose: &str) -> String {
    // Legacy basenames are opaque; no private scratch spelling may reserve one.
    for attempt in 0_u64.. {
        let name = format!(".migration-{purpose}-{index:08}-{attempt:08}");
        if !store.items.iter().any(|item| item.name == name.as_bytes()) {
            return name;
        }
    }
    unreachable!("a finite in-memory inventory cannot occupy every scratch name")
}
/// Publish a recorded destination before removing its source; retries use inode witnesses.
///
/// # Errors
/// Refuses source replacement, an unrelated destination or incomplete backup.
pub fn apply(root: &File) -> Result<()> {
    apply_with(root, |_| Ok(()))
}
#[allow(clippy::too_many_lines)]
fn apply_with(root: &File, mut stop: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let _lock = custody(root)?;
    let mut manifest = load(root)?;
    if !manifest.backed_up {
        return Err(refuse("unsafe-storage: migration backup incomplete"));
    }
    if manifest.rolled_back {
        return Err(refuse("invalid-directory: migration is rolled back"));
    }
    for store_index in 0..manifest.stores.len() {
        if manifest.stores[store_index].absent {
            continue;
        }
        let source = source(&manifest.stores[store_index])?;
        let read = read_history(&manifest.stores[store_index])?;
        let provenance = manifest.stores[store_index].provenance.clone();
        match mkdirat(&read, provenance.as_str(), Mode::from_bits_truncate(0o700)) {
            Ok(()) => read.sync_all()?,
            Err(nix::errno::Errno::EEXIST) => (),
            Err(error) => return Err(error.into()),
        }
        let destination = io::child(&read, Path::new(&provenance), true)?;
        let metadata = destination.metadata()?;
        let identity = (metadata.dev(), metadata.ino());
        if let Some(expected) = manifest.stores[store_index].destination {
            if expected != identity {
                return Err(refuse(
                    "changed-source: migration provenance directory replaced",
                ));
            }
        } else {
            if metadata.uid() != Uid::effective().as_raw()
                || metadata.mode() & 0o7777 != 0o700
                || !io::names(&destination)?.is_empty()
            {
                return Err(refuse(
                    "unsafe-storage: migration provenance is not empty private scratch",
                ));
            }
            manifest.stores[store_index].destination = Some(identity);
            persist(root, &manifest)?;
        }
        for item_index in 0..manifest.stores[store_index].items.len() {
            let item = manifest.stores[store_index].items[item_index].clone();
            let basename = name(&item)?;
            let temporary = temporary_name(&manifest.stores[store_index], item_index, "publish");
            if item.prepared.is_none() {
                let mut original = io::child(&source, Path::new(&basename), false)?;
                if !same_object(&item.source, &object(&mut original)?) {
                    return Err(refuse("changed-source: migration source replaced"));
                }
                let mut backup = io::child(root, Path::new(&item.backup), false)?;
                if !same_bytes(&item.source, &object(&mut backup)?) {
                    return Err(refuse("unsafe-storage: migration backup changed"));
                }
                // An unrecorded scratch holds no committed witness. The source and
                // complete backup still exist, so an interrupted copy can restart.
                match io::child(&destination, Path::new(&temporary), false) {
                    Ok(file) => {
                        let info = file.metadata()?;
                        if !info.is_file()
                            || info.uid() != Uid::effective().as_raw()
                            || info.nlink() != 1
                            || info.mode() & 0o7777 != 0o600
                        {
                            return Err(refuse("unsafe-storage: migration scratch custody"));
                        }
                        unlinkat(&destination, temporary.as_str(), UnlinkatFlags::NoRemoveDir)?;
                        destination.sync_all()?;
                    }
                    Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error),
                }
                let mut staged = create(&destination, Path::new(&temporary))?;
                let prepared = copy(&mut backup, &mut staged)?;
                destination.sync_all()?;
                stop("staged-copy")?;
                manifest.stores[store_index].items[item_index].prepared = Some(prepared);
                persist(root, &manifest)?;
                stop("publication-intent")?;
            }
            let prepared = manifest.stores[store_index].items[item_index]
                .prepared
                .as_ref()
                .expect("prepared item");
            match io::child(&destination, Path::new(&basename), false) {
                Ok(mut file) => {
                    if !same_object(prepared, &object(&mut file)?) {
                        return Err(refuse("unsafe-storage: unrelated migration destination"));
                    }
                }
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut staged = io::child(&destination, Path::new(&temporary), false)?;
                    if !same_object(prepared, &object(&mut staged)?) {
                        return Err(refuse("unsafe-storage: migration prepared file changed"));
                    }
                    renameat2(
                        &destination,
                        temporary.as_str(),
                        &destination,
                        basename.as_os_str(),
                        RenameFlags::RENAME_NOREPLACE,
                    )?;
                    destination.sync_all()?;
                    stop("published")?;
                }
                Err(error) => return Err(error),
            }
            match io::child(&source, Path::new(&basename), false) {
                Ok(mut file) => {
                    if !same_object(&item.source, &object(&mut file)?) {
                        return Err(refuse(
                            "changed-source: migration source differs before removal",
                        ));
                    }
                    unlinkat(&source, basename.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
                    source.sync_all()?;
                    stop("source-removed")?;
                }
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            manifest.stores[store_index].items[item_index].removed = true;
            persist(root, &manifest)?;
            stop("removal-recorded")?;
        }
    }
    Ok(())
}
/// Verify the complete move set, then grant the read-history actor its retained bytes.
///
/// # Errors
/// Refuses unexpected source entries, changed witnesses or unlisted destination files.
pub fn verify(root: &File) -> Result<()> {
    let _lock = custody(root)?;
    let mut manifest = load(root)?;
    if !manifest.backed_up || manifest.rolled_back {
        return Err(refuse("invalid-directory: migration cannot verify"));
    }
    for store in &manifest.stores {
        if store.absent {
            match io::absolute(&store.source.path, true) {
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                _ => return Err(refuse("changed-source: absent migration store appeared")),
            }
        }
        let source = source(store)?;
        if !io::names(&source)?.is_empty() {
            return Err(refuse("changed-source: migration source is not empty"));
        }
        let read = read_history(store)?;
        let actor = read.metadata()?;
        let destination = io::child(&read, Path::new(&store.provenance), true)?;
        let info = destination.metadata()?;
        if store.destination != Some((info.dev(), info.ino())) {
            return Err(refuse(
                "changed-source: migration provenance directory replaced",
            ));
        }
        let mut expected = store.items.iter().map(name).collect::<Result<Vec<_>>>()?;
        expected.sort();
        let mut actual = io::names(&destination)?;
        actual.sort();
        if expected != actual {
            return Err(refuse(
                "invalid-directory: migration destination inventory differs",
            ));
        }
        for item in &store.items {
            let mut file = io::child(&destination, Path::new(&name(item)?), false)?;
            let observed = object(&mut file)?;
            if !item.removed
                || !item
                    .prepared
                    .as_ref()
                    .is_some_and(|prepared| same_object(prepared, &observed))
            {
                return Err(refuse(
                    "changed-source: migration destination witness differs",
                ));
            }
            fchown(
                &file,
                Some(Uid::from_raw(actor.uid())),
                Some(Gid::from_raw(actor.gid())),
            )?;
            file.sync_all()?;
        }
        fchown(
            &destination,
            Some(Uid::from_raw(actor.uid())),
            Some(Gid::from_raw(actor.gid())),
        )?;
        destination.sync_all()?;
        read.sync_all()?;
    }
    manifest.verified = true;
    persist(root, &manifest)
}
/// Restore opaque source bytes before activation; the coordinator owns process/history rollback.
///
/// # Errors
/// Refuses changed backups, unrelated restored files or destinations without recorded witnesses.
pub fn rollback(root: &File) -> Result<()> {
    rollback_with(root, |_| Ok(()))
}
#[allow(clippy::too_many_lines)]
fn rollback_with(root: &File, mut stop: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let _lock = custody(root)?;
    let mut manifest = load(root)?;
    if manifest.rolled_back {
        return Ok(());
    }
    // Validate every backup before changing either side of the migration.
    for store in &manifest.stores {
        for item in &store.items {
            let mut saved = io::child(root, Path::new(&item.backup), false)?;
            if !item.backed_up || !same_bytes(&item.source, &object(&mut saved)?) {
                return Err(refuse("unsafe-storage: migration rollback backup differs"));
            }
        }
    }
    for store in &manifest.stores {
        if let Some(expected) = store.destination {
            let read = read_history(store)?;
            let destination = io::child(&read, Path::new(&store.provenance), true)?;
            let info = destination.metadata()?;
            if (info.dev(), info.ino()) != expected {
                return Err(refuse(
                    "changed-source: rollback provenance directory replaced",
                ));
            }
            for item in &store.items {
                if let Some(prepared) = &item.prepared {
                    match io::child(&destination, Path::new(&name(item)?), false) {
                        Ok(mut file) => {
                            if !same_object(prepared, &object(&mut file)?) {
                                return Err(refuse(
                                    "changed-source: rollback destination conflicts",
                                ));
                            }
                        }
                        Err(MailError::Io(error))
                            if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
    for store_index in 0..manifest.stores.len() {
        if manifest.stores[store_index].absent {
            continue;
        }
        let source = source(&manifest.stores[store_index])?;
        for item_index in 0..manifest.stores[store_index].items.len() {
            let item = manifest.stores[store_index].items[item_index].clone();
            let basename = name(&item)?;
            match io::child(&source, Path::new(&basename), false) {
                Ok(mut file) => {
                    let observed = object(&mut file)?;
                    if !same_object(&item.source, &observed)
                        && !item
                            .restored
                            .as_ref()
                            .is_some_and(|restored| same_object(restored, &observed))
                    {
                        return Err(refuse(
                            "changed-source: migration rollback source conflicts",
                        ));
                    }
                }
                Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    let temporary =
                        temporary_name(&manifest.stores[store_index], item_index, "restore");
                    if item.restored.is_none() {
                        match io::child(&source, Path::new(&temporary), false) {
                            Ok(file) => {
                                let info = file.metadata()?;
                                if !info.is_file()
                                    || info.uid() != Uid::effective().as_raw()
                                    || info.nlink() != 1
                                    || info.mode() & 0o7777 != 0o600
                                {
                                    return Err(refuse("unsafe-storage: rollback scratch custody"));
                                }
                                unlinkat(&source, temporary.as_str(), UnlinkatFlags::NoRemoveDir)?;
                                source.sync_all()?;
                            }
                            Err(MailError::Io(error))
                                if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                        let mut saved = io::child(root, Path::new(&item.backup), false)?;
                        let mut staged = create(&source, Path::new(&temporary))?;
                        let restored = copy(&mut saved, &mut staged)?;
                        source.sync_all()?;
                        stop("restore-copy")?;
                        manifest.stores[store_index].items[item_index].restored = Some(restored);
                        persist(root, &manifest)?;
                        stop("restore-intent")?;
                    }
                    let mut staged = io::child(&source, Path::new(&temporary), false)?;
                    let expected = manifest.stores[store_index].items[item_index]
                        .restored
                        .as_ref()
                        .ok_or_else(|| refuse("invalid-directory: missing rollback intent"))?;
                    if !same_object(expected, &object(&mut staged)?) {
                        return Err(refuse("changed-source: rollback scratch differs"));
                    }
                    fchown(
                        &staged,
                        Some(Uid::from_raw(item.source.uid)),
                        Some(Gid::from_raw(item.source.gid)),
                    )?;
                    nix::sys::stat::fchmod(&staged, Mode::from_bits_truncate(item.source.mode))?;
                    super::migration_metadata::restore(&staged, &item.source.attributes)?;
                    staged.sync_all()?;
                    renameat2(
                        &source,
                        temporary.as_str(),
                        &source,
                        basename.as_os_str(),
                        RenameFlags::RENAME_NOREPLACE,
                    )?;
                    source.sync_all()?;
                    stop("restore-published")?;
                }
                Err(error) => return Err(error),
            }
            if let Some(prepared) = item.prepared {
                let read = read_history(&manifest.stores[store_index])?;
                let destination = io::child(
                    &read,
                    Path::new(&manifest.stores[store_index].provenance),
                    true,
                )?;
                match io::child(&destination, Path::new(&basename), false) {
                    Ok(mut file) => {
                        if !same_object(&prepared, &object(&mut file)?) {
                            return Err(refuse("changed-source: rollback destination conflicts"));
                        }
                        unlinkat(
                            &destination,
                            basename.as_os_str(),
                            UnlinkatFlags::NoRemoveDir,
                        )?;
                        destination.sync_all()?;
                        stop("rollback-destination-removed")?;
                    }
                    Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error),
                }
            }
        }
    }
    manifest.verified = false;
    manifest.rolled_back = true;
    persist(root, &manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "mail-migrate-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("fixture");
            for part in ["state", "new", "cur", "read", "driver"] {
                fs::create_dir(root.join(part)).expect("directory");
            }
            fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700))
                .expect("state custody");
            Self { root }
        }
        fn state(&self) -> File {
            File::open(self.root.join("state")).expect("state")
        }
        fn sources(&self) -> Vec<Source> {
            ["new", "cur"]
                .map(|part| Source {
                    path: self.root.join(part),
                    read: self.root.join("read"),
                    expected: true,
                })
                .to_vec()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.root);
        }
    }

    /// ´claim:loophome:migration-preserves-opaque-duplicate-basenames-and-driver-evidence´
    /// ´test:unit:migration-preserves-opaque-duplicate-basenames-and-driver-evidence´
    #[test]
    fn migration_preserves_opaque_duplicate_basenames_and_driver_evidence() {
        let fixture = Fixture::new();
        let raw = std::ffi::OsString::from_vec(vec![b'x', 0xff]);
        fs::write(fixture.root.join("new").join(&raw), [0, 255, 10]).expect("binary");
        fs::write(fixture.root.join("cur").join(&raw), b"old envelope\n\nbody").expect("history");
        fs::write(fixture.root.join("driver/step-work.txt"), b"retained step").expect("step");
        fs::write(fixture.root.join("driver/brief.txt"), b"brief").expect("brief");
        let state = fixture.state();
        prepare(&state, fixture.sources()).expect("backup");
        apply(&state).expect("move");
        verify(&state).expect("verify");
        apply(&state).expect("retry");
        verify(&state).expect("verify retry");
        let manifest = load(&state).expect("manifest");
        assert_ne!(manifest.stores[0].provenance, manifest.stores[1].provenance);
        for store in &manifest.stores {
            let bytes =
                fs::read(store.source.read.join(&store.provenance).join(&raw)).expect("history");
            assert_eq!(digest(&bytes), store.items[0].source.digest);
        }
        assert_eq!(
            fs::read(fixture.root.join("driver/step-work.txt")).expect("step"),
            b"retained step"
        );
        assert_eq!(
            fs::read(fixture.root.join("driver/brief.txt")).expect("brief"),
            b"brief"
        );
        rollback(&state).expect("rollback");
        rollback(&state).expect("rollback retry");
        assert_eq!(
            fs::read(fixture.root.join("new").join(&raw)).expect("binary restored"),
            [0, 255, 10]
        );
        assert_eq!(
            fs::read(fixture.root.join("cur").join(&raw)).expect("history restored"),
            b"old envelope\n\nbody"
        );
    }
    /// ´claim:loophome:migration-scratch-never-reserves-an-opaque-basename´
    /// ´test:unit:migration-scratch-never-reserves-an-opaque-basename´
    #[test]
    fn migration_scratch_never_reserves_an_opaque_basename() {
        let fixture = Fixture::new();
        let names = [
            ".migration-00000001",
            ".migration-publish-00000000-00000000",
            ".migration-publish-00000001-00000000",
            ".migration-restore-00000000-00000000",
            "z",
        ];
        for (index, name) in names.iter().enumerate() {
            fs::write(fixture.root.join("new").join(name), index.to_string())
                .expect("opaque basename");
        }
        let state = fixture.state();
        prepare(&state, fixture.sources()).expect("backup");
        apply(&state).expect("publish");
        verify(&state).expect("verify every original basename");
        let manifest = load(&state).expect("manifest");
        for (index, name) in names.iter().enumerate() {
            assert_eq!(
                fs::read_to_string(
                    fixture
                        .root
                        .join("read")
                        .join(&manifest.stores[0].provenance)
                        .join(name)
                )
                .expect("preserved basename"),
                index.to_string()
            );
        }
        rollback(&state).expect("restore every original basename");
        for (index, name) in names.iter().enumerate() {
            assert_eq!(
                fs::read_to_string(fixture.root.join("new").join(name)).expect("restored basename"),
                index.to_string()
            );
        }
    }
    /// ´claim:loophome:migration-refuses-forged-destination-and-new-source-entries´
    /// ´test:unit:migration-refuses-forged-destination-and-new-source-entries´
    #[test]
    fn migration_refuses_forged_destination_and_new_source_entries() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("new/a"), b"same").expect("source");
        let state = fixture.state();
        prepare(&state, fixture.sources()).expect("backup");
        apply(&state).expect("move");
        let manifest = load(&state).expect("manifest");
        let path = fixture
            .root
            .join("read")
            .join(&manifest.stores[0].provenance)
            .join("a");
        fs::rename(&path, path.with_extension("held")).expect("hold genuine inode");
        fs::write(&path, b"same").expect("forged same bytes");
        assert!(apply(&state).is_err());
        assert!(verify(&state).is_err());
        assert!(rollback(&state).is_err());
    }
    /// ´claim:loophome:migration-restarts-every-publication-witness-without-duplicate-history´
    /// ´test:unit:migration-restarts-every-publication-witness-without-duplicate-history´
    #[test]
    fn migration_restarts_every_publication_witness_without_duplicate_history() {
        for boundary in 0..10 {
            let fixture = Fixture::new();
            fs::write(fixture.root.join("new/a"), b"first opaque record").expect("first");
            fs::write(fixture.root.join("cur/a"), [0, 1, 255]).expect("second");
            let state = fixture.state();
            prepare(&state, fixture.sources()).expect("backup");
            let mut seen = 0;
            let result = apply_with(&state, |_| {
                let stop = seen == boundary;
                seen += 1;
                if stop {
                    Err(refuse("io-failure: fixture interruption"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "boundary {boundary}");
            apply(&state).expect("recover published or staged witness");
            verify(&state).expect("complete inventory after recovery");
            let manifest = load(&state).expect("manifest");
            for store in &manifest.stores {
                assert_eq!(
                    io::names(&source(store).expect("source")).expect("names"),
                    [] as [std::ffi::OsString; 0]
                );
                assert_eq!(
                    io::names(
                        &io::absolute(&store.source.read.join(&store.provenance), true)
                            .expect("history")
                    )
                    .expect("names")
                    .len(),
                    1
                );
            }
            rollback(&state).expect("preactivation byte rollback");
            assert_eq!(
                fs::read(fixture.root.join("new/a")).expect("first restored"),
                b"first opaque record"
            );
            assert_eq!(
                fs::read(fixture.root.join("cur/a")).expect("second restored"),
                [0, 1, 255]
            );
        }
    }

    /// ´claim:loophome:migration-rollback-restarts-before-and-after-source-restoration´
    /// ´test:unit:migration-rollback-restarts-before-and-after-source-restoration´
    #[test]
    fn migration_rollback_restarts_before_and_after_source_restoration() {
        for boundary in 0..4 {
            let fixture = Fixture::new();
            fs::write(fixture.root.join("new/a"), b"opaque source").expect("source");
            fs::set_permissions(
                fixture.root.join("new/a"),
                fs::Permissions::from_mode(0o640),
            )
            .expect("source mode");
            let state = fixture.state();
            prepare(&state, fixture.sources()).expect("backup");
            apply(&state).expect("move");
            verify(&state).expect("verify bytes");
            let mut seen = 0;
            assert!(
                rollback_with(&state, |_| {
                    let stop = seen == boundary;
                    seen += 1;
                    if stop {
                        Err(refuse("io-failure: fixture interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            rollback(&state).expect("restart rollback");
            assert_eq!(
                fs::read(fixture.root.join("new/a")).expect("restored"),
                b"opaque source"
            );
            assert_eq!(
                fs::metadata(fixture.root.join("new/a"))
                    .expect("mode")
                    .mode()
                    & 0o7777,
                0o640
            );
        }
    }

    /// ´claim:loophome:migration-rollback-restores-source-extended-attributes´
    /// ´test:unit:migration-rollback-restores-source-extended-attributes´
    #[test]
    fn migration_rollback_restores_source_extended_attributes() {
        let fixture = Fixture::new();
        let path = fixture.root.join("new/a");
        fs::write(&path, b"history").expect("source");
        let file = File::open(&path).expect("opened source");
        super::super::acl::install(&file, Uid::effective().as_raw() + 1, false)
            .expect("source service ACL");
        let mut expected = super::super::migration_metadata::read(&file).expect("ACL");
        expected.push((b"user.migration-fixture".to_vec(), vec![0, 255, 1]));
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        super::super::migration_metadata::restore(&file, &expected).expect("source attributes");
        let state = fixture.state();
        prepare(&state, fixture.sources()).expect("backup");
        apply(&state).expect("move");
        verify(&state).expect("history");
        rollback(&state).expect("restore source");
        assert_eq!(
            super::super::migration_metadata::read(&File::open(&path).expect("restored"))
                .expect("restored attributes"),
            expected
        );
    }

    /// ´claim:loophome:migration-distinguishes-optional-absence-from-missing-expected-store´
    /// ´test:unit:migration-distinguishes-optional-absence-from-missing-expected-store´
    #[test]
    fn migration_distinguishes_optional_absence_from_missing_expected_store() {
        let fixture = Fixture::new();
        let state = fixture.state();
        let source = Source {
            path: fixture.root.join("absent"),
            read: fixture.root.join("read"),
            expected: true,
        };
        assert!(prepare(&state, vec![source.clone()]).is_err());
        prepare(
            &state,
            vec![Source {
                expected: false,
                ..source
            }],
        )
        .expect("optional absence");
        apply(&state).expect("nothing to move");
        verify(&state).expect("absent remains absent");
        fs::create_dir(fixture.root.join("absent")).expect("store appears");
        assert!(verify(&state).is_err());
    }
}
