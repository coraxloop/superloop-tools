//! Close a quiet worker-run slot and relocate its independently backed-up tree.
use super::{
    io,
    journal::{MailError, Result, digest},
    migration_tree, provision,
};
use nix::fcntl::{Flock, FlockArg, OFlag, OpenHow, RenameFlags, ResolveFlag, openat2, renameat2};
use nix::sys::stat::Mode;
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
enum DestinationOrigin {
    Absent,
    Existing,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    loop_root: PathBuf,
    loop_uid: u32,
    lane: String,
    uid: u32,
    source: (u64, u64),
    tree_digest: String,
    workers_attributes: super::migration_metadata::Attributes,
    destination_origin: DestinationOrigin,
    table: Vec<u8>,
    closed: Vec<u8>,
    moved: bool,
    rolling_back: bool,
    rolled_back: bool,
}
const fn invalid(reason: &'static str) -> MailError {
    MailError::Invalid(reason)
}
fn owned(file: &File, uid: u32, mode: u32) -> Result<()> {
    let info = file.metadata()?;
    if info.uid() != uid || info.mode() & 0o7777 != mode {
        return Err(invalid("unsafe-storage: legacy relocation custody"));
    }
    Ok(())
}
fn write(parent: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let temporary = format!(".migration-{}", digest(name.as_bytes()));
    let mut file = File::from(openat2(
        parent,
        temporary.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    let info = file.metadata()?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != Uid::effective().as_raw()
        || !([0o600, mode].contains(&(info.mode() & 0o7777)))
    {
        return Err(invalid("unsafe-storage: relocation scratch custody"));
    }
    nix::sys::stat::fchmod(&file, Mode::from_bits_truncate(0o600))?;
    file.set_len(0)?;
    file.write_all(bytes)?;
    nix::sys::stat::fchmod(&file, Mode::from_bits_truncate(mode))?;
    file.sync_all()?;
    renameat2(
        parent,
        temporary.as_str(),
        parent,
        name,
        RenameFlags::empty(),
    )?;
    parent.sync_all()?;
    Ok(())
}
fn save(state: &File, record: &Record) -> Result<()> {
    write(
        state,
        "relocation.json",
        &serde_json::to_vec(record)
            .map_err(|_| invalid("invalid-directory: relocation serialization"))?,
        0o600,
    )
}
fn load(state: &File) -> Result<Record> {
    let file = io::child(state, Path::new("relocation.json"), false)?;
    owned(&file, Uid::effective().as_raw(), 0o600)?;
    if !file.metadata()?.is_file() || file.metadata()?.nlink() != 1 {
        return Err(invalid("unsafe-storage: relocation record type"));
    }
    let record: Record = serde_json::from_reader(file)
        .map_err(|_| invalid("invalid-directory: relocation record schema"))?;
    if record.version != 1 {
        return Err(invalid("invalid-directory: relocation record version"));
    }
    Ok(record)
}
fn table(runs: &File) -> Result<Vec<u8>> {
    let file = io::child(runs, Path::new("table.tsv"), false)?;
    let info = file.metadata()?;
    if info.uid() != Uid::effective().as_raw() || info.mode() & 0o022 != 0 {
        return Err(invalid("unsafe-storage: worker-run table custody"));
    }
    io::bounded(&file, u64::MAX)
}
fn close_table(bytes: &[u8], lane: &str, uid: u32) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid("invalid-directory: worker-run table encoding"))?;
    if !text.ends_with('\n') {
        return Err(invalid("invalid-directory: worker-run table is partial"));
    }
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| invalid("invalid-directory: worker-run table header"))?;
    let columns = match header {
        "uid\tlane\tdriver\tcommit\tstarted" => 5,
        "uid\tlane\tdriver\tcommit\tstarted\tclaimed" => 6,
        _ => return Err(invalid("invalid-directory: worker-run table header")),
    };
    let mut result = format!("{header}\n");
    let mut found = false;
    let mut names = std::collections::BTreeSet::new();
    let mut uids = std::collections::BTreeSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != columns
            || (columns == 6
                && (fields[5].is_empty() || !fields[5].bytes().all(|byte| byte.is_ascii_digit())))
        {
            return Err(invalid("invalid-directory: worker-run table row"));
        }
        let number = fields[0]
            .parse::<u32>()
            .map_err(|_| invalid("invalid-directory: worker-run table uid"))?;
        if !names.insert(fields[1]) || !uids.insert(number) {
            return Err(invalid("invalid-directory: worker-run table duplicate"));
        }
        if fields[1] == lane {
            if number != uid {
                return Err(invalid("changed-source: legacy lane UID differs"));
            }
            found = true;
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    if !found {
        return Err(invalid(
            "invalid-directory: legacy lane has no retained table binding",
        ));
    }
    Ok(result.into_bytes())
}
struct TableGuard<'a> {
    runs: &'a File,
    held: Flock<File>,
}
impl Drop for TableGuard<'_> {
    fn drop(&mut self) {
        if let Ok(named) = io::child(self.runs, Path::new("table.lock"), false)
            && let (Ok(named), Ok(held)) = (named.metadata(), self.held.metadata())
            && (named.dev(), named.ino()) == (held.dev(), held.ino())
        {
            let _removed = unlinkat(self.runs, "table.lock", UnlinkatFlags::NoRemoveDir);
            let _synced = self.runs.sync_all();
        }
    }
}
fn table_lock<'a>(runs: &'a File, state: &File) -> Result<TableGuard<'a>> {
    let info = state.metadata()?;
    let token = format!("mail-migration {}:{}\n", info.dev(), info.ino());
    let file = match io::child(runs, Path::new("table.lock"), false) {
        Ok(file) => file,
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let temporary = format!(".migration-lock-{}", digest(token.as_bytes()));
            let mut file = File::from(openat2(
                runs,
                temporary.as_str(),
                OpenHow::new()
                    .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                    .mode(Mode::from_bits_truncate(0o600))
                    .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
            )?);
            owned(&file, Uid::effective().as_raw(), 0o600)?;
            if !file.metadata()?.is_file() || file.metadata()?.nlink() != 1 {
                return Err(invalid("unsafe-storage: migration table-lock scratch"));
            }
            file.set_len(0)?;
            file.write_all(token.as_bytes())?;
            file.sync_all()?;
            renameat2(
                runs,
                temporary.as_str(),
                runs,
                "table.lock",
                RenameFlags::RENAME_NOREPLACE,
            )?;
            runs.sync_all()?;
            io::child(runs, Path::new("table.lock"), false)?
        }
        Err(error) => return Err(error),
    };
    let info = file.metadata()?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != Uid::effective().as_raw()
        || info.mode() & 0o022 != 0
    {
        return Err(invalid("unsafe-storage: worker-run table lock custody"));
    }
    if io::bounded(&file, 256)? != token.as_bytes() {
        return Err(invalid(
            "changed-source: worker-run table is locked by another operation",
        ));
    }
    owned(&file, Uid::effective().as_raw(), 0o600)?;
    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|_| invalid("changed-source: worker-run table lock is live"))?;
    Ok(TableGuard { runs, held })
}
fn lifetime(runs: &File, lane: &str) -> Result<Flock<File>> {
    let name = format!(".lifetime-{lane}.lock");
    let file = File::from(openat2(
        runs,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .mode(Mode::from_bits_truncate(0o600))
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    )?);
    owned(&file, Uid::effective().as_raw(), 0o600)?;
    if !file.metadata()?.is_file() || file.metadata()?.nlink() != 1 {
        return Err(invalid("unsafe-storage: legacy lifetime lock"));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|_| invalid("changed-source: legacy worker lifetime is busy"))
}
fn state_lock(state: &File) -> Result<Flock<File>> {
    owned(state, Uid::effective().as_raw(), 0o700)?;
    Flock::lock(
        io::child(state, Path::new("."), true)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|_| invalid("changed-source: legacy relocation is busy"))
}
/// Close a quiet legacy lane, retain an independent backup, and move its tree once.
///
/// # Errors
/// Refuses missing bindings, active workers, unsafe history or an occupied destination.
pub fn relocate(state: &File, loop_root: &Path, loop_uid: u32, lane: &str, uid: u32) -> Result<()> {
    relocate_with(
        state,
        loop_root,
        loop_uid,
        lane,
        uid,
        Path::new("/proc"),
        |_| Ok(()),
    )
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn relocate_with(
    state: &File,
    loop_root: &Path,
    loop_uid: u32,
    lane: &str,
    uid: u32,
    proc_root: &Path,
    mut stop: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    if lane.is_empty()
        || [".", ".."].contains(&lane)
        || lane.bytes().any(|byte| b"/\0\t\r\n".contains(&byte))
    {
        return Err(invalid("invalid-directory: legacy lane component"));
    }
    let _state = state_lock(state)?;
    let root = io::absolute(loop_root, true)?;
    let runs = io::child(&root, Path::new("runs"), true)?;
    owned(&runs, Uid::effective().as_raw(), 0o755)?;
    let _lifetime = lifetime(&runs, lane)?;
    let _table = table_lock(&runs, state)?;
    let mut record = match load(state) {
        Ok(record) => {
            if record.loop_root != loop_root
                || record.loop_uid != loop_uid
                || record.lane != lane
                || record.uid != uid
                || record.rolling_back
                || record.rolled_back
            {
                return Err(invalid("changed-source: relocation request differs"));
            }
            record
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let workers = io::child(&root, Path::new("workers"), true)?;
            owned(&workers, loop_uid, 0o710)?;
            let source = io::child(&workers, Path::new(lane), true)?;
            let info = source.metadata()?;
            let original = table(&runs)?;
            let record = Record {
                version: 1,
                loop_root: loop_root.to_owned(),
                loop_uid,
                lane: lane.into(),
                uid,
                source: (info.dev(), info.ino()),
                tree_digest: migration_tree::fingerprint(&source)?,
                workers_attributes: super::migration_metadata::read(&workers)?,
                destination_origin: if optional(&loop_root.join("worker-homes"))?.is_none() {
                    DestinationOrigin::Absent
                } else {
                    DestinationOrigin::Existing
                },
                closed: close_table(&original, lane, uid)?,
                table: original,
                moved: false,
                rolling_back: false,
                rolled_back: false,
            };
            save(state, &record)?;
            record
        }
        Err(error) => return Err(error),
    };
    super::worker_provision::worker_quiet(proc_root, uid)?;
    let (backup, _) = provision::directory(
        state,
        "backup",
        Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        0o700,
    )?;
    let (destination, _) = provision::directory(&root, "worker-homes", loop_uid, loop_uid, 0o710)?;
    let source_path = loop_root.join("workers").join(lane);
    let source = match io::absolute(&source_path, true) {
        Ok(source) => {
            let info = source.metadata()?;
            if (info.dev(), info.ino()) != record.source {
                return Err(invalid("changed-source: legacy source tree replaced"));
            }
            if migration_tree::backup(&source, &backup)?.digest != record.tree_digest {
                return Err(invalid(
                    "changed-source: legacy tree changed after inventory",
                ));
            }
            Some(source)
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let target = io::child(&destination, Path::new(lane), true)?;
            let info = target.metadata()?;
            if (info.dev(), info.ino()) != record.source {
                return Err(invalid("changed-source: relocated tree identity differs"));
            }
            migration_tree::verify_backup(&backup)?;
            None
        }
        Err(error) => return Err(error),
    };
    stop("backup")?;
    let current = table(&runs)?;
    if record.moved {
        match close_table(&current, lane, uid) {
            Err(MailError::Invalid(
                "invalid-directory: legacy lane has no retained table binding",
            )) => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(invalid(
                    "changed-source: relocated lane acquired a new table binding",
                ));
            }
        }
    } else if current == record.table {
        write(&runs, "table.tsv", &record.closed, 0o644)?;
    } else if current != record.closed {
        return Err(invalid(
            "changed-source: worker-run table changed before closure",
        ));
    }
    stop("table-closed")?;
    super::worker_provision::worker_quiet(proc_root, uid)?;
    if source.is_some() {
        let workers = io::child(&root, Path::new("workers"), true)?;
        owned(&workers, loop_uid, 0o710)?;
        renameat2(
            &workers,
            lane,
            &destination,
            lane,
            RenameFlags::RENAME_NOREPLACE,
        )?;
        workers.sync_all()?;
        destination.sync_all()?;
    }
    stop("tree-moved")?;
    let target = io::child(&destination, Path::new(lane), true)?;
    let proof = migration_tree::verify_backup(&backup)?;
    if migration_tree::fingerprint(&target)? != proof.digest {
        return Err(invalid(
            "changed-source: relocated tree differs from backup",
        ));
    }
    match io::child(&root, Path::new("workers"), true) {
        Ok(workers) => {
            owned(&workers, loop_uid, 0o710)?;
            if io::names(&workers)?.is_empty() {
                unlinkat(&root, "workers", UnlinkatFlags::RemoveDir)?;
                root.sync_all()?;
            }
        }
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    stop("legacy-root-removed")?;
    record.moved = true;
    save(state, &record)?;
    stop("relocation-recorded")?;
    Ok(())
}

/// Restore a quiet legacy tree and its original table binding before activation.
///
/// The coordinator holds the estate and reverses relocations in manifest reverse
/// order. Provisioned mail history must be reconciled before legacy restoration.
///
/// # Errors
/// Refuses changed trees, changed tables, live workers or retained mail history.
pub fn rollback(state: &File) -> Result<()> {
    rollback_with(state, Path::new("/proc"), |_| Ok(()))
}
#[allow(clippy::too_many_lines)]
fn rollback_with(
    state: &File,
    proc_root: &Path,
    mut stop: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let _state = state_lock(state)?;
    let mut record = load(state)?;
    let root = io::absolute(&record.loop_root, true)?;
    let runs = io::child(&root, Path::new("runs"), true)?;
    owned(&runs, Uid::effective().as_raw(), 0o755)?;
    let _lifetime = lifetime(&runs, &record.lane)?;
    let _table = table_lock(&runs, state)?;
    super::worker_provision::worker_quiet(proc_root, record.uid)?;
    let current = table(&runs)?;
    if record.rolled_back {
        // Earlier reverse moves may have restored additional rows. Verify this
        // lifetime without rewriting their rows; the coordinator checks the full original table.
        close_table(&current, &record.lane, record.uid)?;
        let row = |bytes: &[u8]| -> Result<Vec<u8>> {
            std::str::from_utf8(bytes)
                .map_err(|_| invalid("invalid-directory: restored table encoding"))?
                .lines()
                .find(|line| line.split('\t').nth(1) == Some(record.lane.as_str()))
                .map(|line| line.as_bytes().to_vec())
                .ok_or_else(|| invalid("invalid-directory: restored lane binding absent"))
        };
        let tree = io::absolute(&record.loop_root.join("workers").join(&record.lane), true)?;
        let info = tree.metadata()?;
        if row(&current)? != row(&record.table)?
            || (info.dev(), info.ino()) != record.source
            || migration_tree::fingerprint(&tree)? != record.tree_digest
            || optional(&record.loop_root.join("worker-homes").join(&record.lane))?.is_some()
        {
            return Err(invalid(
                "changed-source: restored lifetime differs from its rollback witness",
            ));
        }
        return Ok(());
    }
    if current != record.closed && current != record.table {
        return Err(invalid(
            "changed-source: reverse later relocations before restoring this table",
        ));
    }
    let (backup, _) = provision::directory(
        state,
        "backup",
        Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        0o700,
    )?;
    let old_path = record.loop_root.join("workers").join(&record.lane);
    let new_path = record.loop_root.join("worker-homes").join(&record.lane);
    let old = optional(&old_path)?;
    let new = optional(&new_path)?;
    if old.is_some() && new.is_some() {
        return Err(invalid(
            "changed-source: legacy and relocated trees both exist",
        ));
    }
    let tree = old.as_ref().or(new.as_ref()).ok_or_else(|| {
        invalid(
            "io-failure: legacy tree missing; restore its retained backup through reconciliation",
        )
    })?;
    let info = tree.metadata()?;
    if (info.dev(), info.ino()) != record.source
        || migration_tree::fingerprint(tree)? != record.tree_digest
    {
        return Err(invalid("changed-source: legacy rollback tree differs"));
    }
    if migration_tree::backup(tree, &backup)?.digest != record.tree_digest {
        return Err(invalid("unsafe-storage: legacy rollback backup differs"));
    }
    if let Some(workers) = optional(&record.loop_root.join("workers"))?
        && owned(&workers, record.loop_uid, 0o710).is_err()
    {
        return Err(invalid(
            "invalid-directory: retained mail namespace requires reconciliation before legacy restoration",
        ));
    }
    record.rolling_back = true;
    save(state, &record)?;
    stop("rollback-intent")?;
    let (workers, _) =
        provision::directory(&root, "workers", record.loop_uid, record.loop_uid, 0o710)?;
    if new.is_some() {
        let destination = io::child(&root, Path::new("worker-homes"), true)?;
        owned(&destination, record.loop_uid, 0o710)?;
        renameat2(
            &destination,
            record.lane.as_str(),
            &workers,
            record.lane.as_str(),
            RenameFlags::RENAME_NOREPLACE,
        )?;
        destination.sync_all()?;
        workers.sync_all()?;
    }
    super::migration_metadata::restore(&workers, &record.workers_attributes)?;
    workers.sync_all()?;
    stop("legacy-tree-restored")?;
    let restored = io::child(&workers, Path::new(&record.lane), true)?;
    if migration_tree::fingerprint(&restored)? != record.tree_digest {
        return Err(invalid("changed-source: restored legacy tree differs"));
    }
    super::worker_provision::worker_quiet(proc_root, record.uid)?;
    write(&runs, "table.tsv", &record.table, 0o644)?;
    stop("legacy-table-restored")?;
    if matches!(record.destination_origin, DestinationOrigin::Absent)
        && let Some(destination) = optional(&record.loop_root.join("worker-homes"))?
    {
        owned(&destination, record.loop_uid, 0o710)?;
        if !io::names(&destination)?.is_empty() {
            return Err(invalid(
                "changed-source: reverse later execution-home moves before removing their namespace",
            ));
        }
        unlinkat(&root, "worker-homes", UnlinkatFlags::RemoveDir)?;
        root.sync_all()?;
    }
    record.rolled_back = true;
    save(state, &record)?;
    stop("rollback-recorded")?;
    Ok(())
}
/// Verify the complete table after reversing every move for a loop.
///
/// # Errors
/// Use the first relocation's state; any additional or changed row refuses completion.
pub fn verify_restored_table(state: &File) -> Result<()> {
    let _state = state_lock(state)?;
    let record = load(state)?;
    if !record.rolled_back {
        return Err(invalid("changed-source: relocation rollback is incomplete"));
    }
    let root = io::absolute(&record.loop_root.join("runs"), true)?;
    let _table = table_lock(&root, state)?;
    if table(&root)? != record.table {
        return Err(invalid(
            "changed-source: restored worker-run table differs from its original inventory",
        ));
    }
    Ok(())
}
fn optional(path: &Path) -> Result<Option<File>> {
    match io::absolute(path, true) {
        Ok(file) => Ok(Some(file)),
        Err(MailError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    /// ´claim:loophome:legacy-worker-relocation-restarts-every-closure-boundary´
    /// ´test:unit:legacy-worker-relocation-restarts-every-closure-boundary´
    #[test]
    fn legacy_worker_relocation_restarts_every_closure_boundary() {
        for boundary in 0..5 {
            let root = std::env::temp_dir()
                .join(format!("mail-relocation-{}-{boundary}", std::process::id()));
            fs::create_dir(&root).expect("fixture");
            let home = root.join("loop");
            let state = root.join("state");
            let proc_root = root.join("proc");
            for path in [&home, &state, &proc_root] {
                fs::create_dir(path).expect("directory");
            }
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("state");
            fs::create_dir(home.join("runs")).expect("runs");
            fs::set_permissions(home.join("runs"), fs::Permissions::from_mode(0o755))
                .expect("runs mode");
            fs::create_dir(home.join("workers")).expect("workers");
            fs::set_permissions(home.join("workers"), fs::Permissions::from_mode(0o710))
                .expect("workers mode");
            fs::create_dir(home.join("workers/legacy")).expect("legacy tree");
            fs::write(home.join("workers/legacy/body"), [0, 255]).expect("body");
            symlink("body", home.join("workers/legacy/link")).expect("link");
            let uid = Uid::effective().as_raw();
            fs::write(
                home.join("runs/table.tsv"),
                format!("uid\tlane\tdriver\tcommit\tstarted\n{uid}\tlegacy\t\t\t\n"),
            )
            .expect("table");
            fs::set_permissions(
                home.join("runs/table.tsv"),
                fs::Permissions::from_mode(0o644),
            )
            .expect("table mode");
            let state_fd = File::open(&state).expect("state descriptor");
            let mut seen = 0;
            assert!(
                relocate_with(&state_fd, &home, uid, "legacy", uid, &proc_root, |_| {
                    let stop = seen == boundary;
                    seen += 1;
                    if stop {
                        Err(invalid("io-failure: fixture interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            relocate_with(&state_fd, &home, uid, "legacy", uid, &proc_root, |_| Ok(()))
                .expect("restart relocation");
            assert_eq!(
                fs::read(home.join("worker-homes/legacy/body")).expect("retained body"),
                [0, 255]
            );
            assert_eq!(
                fs::read_to_string(home.join("runs/table.tsv")).expect("closed table"),
                "uid\tlane\tdriver\tcommit\tstarted\n"
            );
            assert!(!home.join("workers").exists());
            assert!(load(&state_fd).expect("manifest").moved);
            let mut seen = 0;
            assert!(
                rollback_with(&state_fd, &proc_root, |_| {
                    let interrupted = seen == boundary % 4;
                    seen += 1;
                    if interrupted {
                        Err(invalid("io-failure: fixture interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            assert!(
                relocate_with(&state_fd, &home, uid, "legacy", uid, &proc_root, |_| Ok(()))
                    .is_err()
            );
            rollback_with(&state_fd, &proc_root, |_| Ok(())).expect("restart rollback");
            assert_eq!(
                fs::read(home.join("workers/legacy/body")).expect("restored body"),
                [0, 255]
            );
            assert_eq!(
                fs::read_to_string(home.join("runs/table.tsv")).expect("restored table"),
                format!("uid\tlane\tdriver\tcommit\tstarted\n{uid}\tlegacy\t\t\t\n")
            );
            assert!(!home.join("worker-homes/legacy").exists());
            assert!(load(&state_fd).expect("rollback manifest").rolled_back);
            fs::remove_dir_all(root).expect("cleanup");
        }
    }
    /// ´claim:loophome:legacy-relocation-reverse-order-retry-preserves-all-table-bindings´
    /// ´test:unit:legacy-relocation-reverse-order-retry-preserves-all-table-bindings´
    #[test]
    fn legacy_relocation_reverse_order_retry_preserves_all_table_bindings() {
        let root = std::env::temp_dir().join(format!("migration-multiple-{}", std::process::id()));
        fs::create_dir(&root).expect("root");
        let home = root.join("loop");
        fs::create_dir(&home).expect("loop");
        let uid = Uid::effective().as_raw();
        let proc_root = root.join("proc");
        fs::create_dir(&proc_root).expect("synthetic quiet process table");
        for name in ["runs", "workers"] {
            fs::create_dir(home.join(name)).expect("directory");
            fs::set_permissions(
                home.join(name),
                fs::Permissions::from_mode(if name == "runs" { 0o755 } else { 0o710 }),
            )
            .expect("mode");
        }
        let original = format!(
            "uid\tlane\tdriver\tcommit\tstarted\n{uid}\tone\t\t\t\n{}\ttwo\t\t\t\n",
            uid + 1
        );
        fs::write(home.join("runs/table.tsv"), &original).expect("table");
        fs::set_permissions(
            home.join("runs/table.tsv"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("table mode");
        for name in ["one", "two"] {
            let path = home.join("workers").join(name);
            fs::create_dir(&path).expect("worker tree");
            fs::write(path.join("body"), name.as_bytes()).expect("body");
        }
        let mut states = Vec::new();
        for (index, name) in ["one", "two"].iter().enumerate() {
            let path = root.join(name);
            fs::create_dir(&path).expect("state");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("state custody");
            states.push(File::open(path).expect("state descriptor"));
            relocate_with(
                &states[index],
                &home,
                uid,
                name,
                uid + u32::try_from(index).expect("index"),
                &proc_root,
                |_| Ok(()),
            )
            .expect("relocate");
        }
        for state in states.iter().rev() {
            rollback_with(state, &proc_root, |_| Ok(())).expect("reverse");
        }
        for state in states.iter().rev() {
            rollback_with(state, &proc_root, |_| Ok(()))
                .expect("repeat after earlier rows restored");
        }
        verify_restored_table(&states[0]).expect("whole original table");
        assert_eq!(
            fs::read_to_string(home.join("runs/table.tsv")).expect("table"),
            original
        );
        assert!(!home.join("worker-homes").exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
