use nix::fcntl::{Flock, FlockArg, RenameFlags, renameat2};
use nix::sys::statvfs::fstatvfs;
use nix::unistd::{Gid, chown};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_CONFIG_BYTES: u64 = 65_536;
const MAX_RECORD_BYTES: usize = 262_144;
const MAX_PAGE_BYTES: usize = 1_048_576;
const MAX_PAGE_ROWS: usize = 16;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    node_id: String,
    incarnation_id: String,
    configuration_revision: String,
    reader_gid: u32,
    volumes: Vec<VolumeConfig>,
    accounts: Vec<AccountConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeConfig {
    id: String,
    mount_path: PathBuf,
    query_path: PathBuf,
    identity: FilesystemIdentity,
    capacity_scope: CapacityScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemIdentity {
    major_minor: String,
    filesystem_type: String,
    source: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CapacityScope {
    Filesystem,
    ProjectScoped,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountConfig {
    account_id: String,
    uid: u32,
    storage_class: String,
    volume_id: String,
    project_id: Option<u32>,
    collection_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Interval {
    started_utc_ns: u64,
    finished_utc_ns: u64,
    boot_id: String,
    elapsed_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadingError {
    volume_id: String,
    kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VolumeSample {
    id: String,
    mount_path: PathBuf,
    query_path: PathBuf,
    expected_identity: FilesystemIdentity,
    observed_identity: Option<FilesystemIdentity>,
    interval: Interval,
    status: String,
    error: Option<String>,
    total_bytes: Option<u64>,
    free_bytes: Option<u64>,
    available_bytes: Option<u64>,
    total_inodes: Option<u64>,
    free_inodes: Option<u64>,
    available_inodes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountSample {
    account_id: String,
    uid: u32,
    storage_class: String,
    volume_id: String,
    project_id: Option<u32>,
    collection_enabled: bool,
    coverage: String,
    interval: Interval,
    status: String,
    charged_bytes: Option<u64>,
    charged_inodes: Option<u64>,
    limit_bytes: Option<u64>,
    limit_inodes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    schema: u32,
    node_id: String,
    incarnation_id: String,
    state_nonce: String,
    sequence: u64,
    scheduled_date: String,
    interval: Interval,
    configuration_revision: String,
    status: String,
    errors: Vec<ReadingError>,
    volumes: Vec<VolumeSample>,
    accounts: Vec<AccountSample>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    sequence: u64,
    scheduled_date: String,
}

#[derive(Serialize)]
struct Export {
    schema: u32,
    state_nonce: String,
    after_sequence: u64,
    next_after_sequence: u64,
    has_more: bool,
    samples: Vec<Sample>,
    unfinished_attempts: Vec<Attempt>,
}

#[derive(Clone, Copy)]
struct Counters {
    fragment_size: u64,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    files_available: u64,
}

trait Reader {
    type Handle;
    fn open(&self, query: &Path) -> io::Result<Self::Handle>;
    fn identity(
        &self,
        handle: &Self::Handle,
        mount: &Path,
        query: &Path,
    ) -> io::Result<FilesystemIdentity>;
    fn project_inherits(&self, handle: &Self::Handle) -> io::Result<bool>;
    fn counters(&self, handle: &Self::Handle) -> io::Result<Counters>;
}

struct KernelReader;

#[repr(C)]
#[derive(Default)]
struct FsXattr {
    xflags: u32,
    extsize: u32,
    nextents: u32,
    project_id: u32,
    cowextsize: u32,
    pad: [u8; 8],
}

// Linux _IOR('X', 31, struct fsxattr): 28 output bytes.
const FS_IOC_FSGETXATTR: libc::c_ulong = 0x801c_581f;
const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;

#[allow(unsafe_code)]
fn project_inherits_from_fd(handle: &File) -> io::Result<bool> {
    let mut attrs = FsXattr::default();
    // SAFETY: the open directory remains live, and attrs has the kernel fsxattr layout.
    let result = unsafe { libc::ioctl(handle.as_raw_fd(), FS_IOC_FSGETXATTR, &raw mut attrs) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(attrs.xflags & FS_XFLAG_PROJINHERIT != 0)
}

impl KernelReader {
    fn identity_from_mountinfo(
        raw: &str,
        handle: &File,
        mount: &Path,
        query: &Path,
    ) -> io::Result<FilesystemIdentity> {
        let mount_name = mount
            .to_str()
            .ok_or_else(|| bad("mount path is not UTF-8"))?;
        let query_name = query
            .to_str()
            .ok_or_else(|| bad("query path is not UTF-8"))?;
        let mut selected: Option<(usize, String, FilesystemIdentity)> = None;
        for line in raw.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                continue;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let tail: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 5 || tail.len() < 2 {
                continue;
            }
            let point = fields[4];
            if query_name == point
                || (query_name.starts_with(point)
                    && query_name.as_bytes().get(point.len()) == Some(&b'/'))
            {
                let identity = FilesystemIdentity {
                    major_minor: fields[2].to_owned(),
                    filesystem_type: tail[0].to_owned(),
                    source: tail[1].to_owned(),
                };
                if selected
                    .as_ref()
                    .is_none_or(|(length, _, _)| point.len() >= *length)
                {
                    selected = Some((point.len(), point.to_owned(), identity));
                }
            }
        }
        let (_, point, identity) = selected.ok_or_else(|| bad("mount absent"))?;
        if point != mount_name {
            return Err(bad("mount absent or query path is on another mount"));
        }
        let device = handle.metadata()?.dev();
        let actual = format!(
            "{}:{}",
            nix::sys::stat::major(device),
            nix::sys::stat::minor(device)
        );
        if actual != identity.major_minor {
            return Err(bad("query descriptor device differs from mount"));
        }
        Ok(identity)
    }
}

impl Reader for KernelReader {
    type Handle = File;

    fn open(&self, query: &Path) -> io::Result<Self::Handle> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(query)
    }

    fn identity(
        &self,
        handle: &Self::Handle,
        mount: &Path,
        query: &Path,
    ) -> io::Result<FilesystemIdentity> {
        let raw = fs::read_to_string("/proc/self/mountinfo")?;
        Self::identity_from_mountinfo(&raw, handle, mount, query)
    }

    fn project_inherits(&self, handle: &Self::Handle) -> io::Result<bool> {
        project_inherits_from_fd(handle)
    }

    fn counters(&self, handle: &Self::Handle) -> io::Result<Counters> {
        let stat = fstatvfs(handle).map_err(io::Error::other)?;
        Ok(Counters {
            fragment_size: stat.fragment_size(),
            blocks: stat.blocks(),
            blocks_free: stat.blocks_free(),
            blocks_available: stat.blocks_available(),
            files: stat.files(),
            files_free: stat.files_free(),
            files_available: stat.files_available(),
        })
    }
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn load_config(path: &Path) -> io::Result<Config> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| bad(&format!("configuration-custody: open failed: {error}")))?;
    let metadata = file.metadata()?;
    check_config_custody(&metadata, 0)?;
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(bad("configuration exceeds byte bound"));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(bad("configuration exceeds byte bound"));
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    validate_config(&config)?;
    Ok(config)
}

fn check_config_custody(metadata: &fs::Metadata, owner: u32) -> io::Result<()> {
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(bad(
            "configuration-custody: expected owner and no group or other write access",
        ));
    }
    Ok(())
}

fn validate_config(config: &Config) -> io::Result<()> {
    if config.schema != 1
        || !valid_name(&config.node_id)
        || !valid_name(&config.incarnation_id)
        || !valid_name(&config.configuration_revision)
        || config.volumes.is_empty()
        || config.volumes.len() > 16
        || config.accounts.len() > 512
    {
        return Err(bad("configuration identity or count invalid"));
    }
    let mut ids = HashSet::new();
    for volume in &config.volumes {
        if !valid_name(&volume.id)
            || !ids.insert(volume.id.as_str())
            || !volume.mount_path.is_absolute()
            || !volume.query_path.is_absolute()
            || !volume.query_path.starts_with(&volume.mount_path)
            || volume.identity.major_minor.is_empty()
            || volume.identity.filesystem_type.is_empty()
            || volume.identity.source.is_empty()
        {
            return Err(bad("configuration volume invalid"));
        }
    }
    let mut rows = HashSet::new();
    for account in &config.accounts {
        if !valid_name(&account.account_id)
            || !valid_name(&account.storage_class)
            || !ids.contains(account.volume_id.as_str())
            || !rows.insert((account.uid, account.storage_class.as_str()))
        {
            return Err(bad("configuration account row invalid"));
        }
    }
    Ok(())
}

fn now_ns() -> io::Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    u64::try_from(duration.as_nanos()).map_err(io::Error::other)
}

// Civil date conversion from days since the Unix epoch; no locale or local-time clock participates.
fn utc_date(epoch_ns: u64) -> io::Result<String> {
    let days = i64::try_from(epoch_ns / 1_000_000_000 / 86_400).map_err(io::Error::other)?;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

fn interval(start: u64, boot_id: &str, clock: Instant) -> io::Result<Interval> {
    Ok(Interval {
        started_utc_ns: start,
        finished_utc_ns: now_ns()?,
        boot_id: boot_id.to_owned(),
        elapsed_ns: u64::try_from(clock.elapsed().as_nanos()).map_err(io::Error::other)?,
    })
}

fn read_volume<R: Reader>(
    config: &VolumeConfig,
    reader: &R,
    boot_id: &str,
) -> io::Result<VolumeSample> {
    let started = now_ns()?;
    let clock = Instant::now();
    let handle = reader.open(&config.query_path);
    let observed = match &handle {
        Ok(handle) => reader.identity(handle, &config.mount_path, &config.query_path),
        Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
    };
    let mut row = VolumeSample {
        id: config.id.clone(),
        mount_path: config.mount_path.clone(),
        query_path: config.query_path.clone(),
        expected_identity: config.identity.clone(),
        observed_identity: observed.as_ref().ok().cloned(),
        interval: interval(started, boot_id, clock)?,
        status: "failed".to_owned(),
        error: None,
        total_bytes: None,
        free_bytes: None,
        available_bytes: None,
        total_inodes: None,
        free_inodes: None,
        available_inodes: None,
    };
    let result = match observed {
        Err(error) if error.to_string().contains("mount absent") => Err("mount_absent"),
        Err(error) if error.to_string().contains("descriptor device differs") => {
            Err("identity_mismatch")
        }
        Err(_) => Err("identity_read_failed"),
        Ok(identity) if identity != config.identity => Err("identity_mismatch"),
        Ok(_) => match handle.as_ref().map_err(|_| "identity_read_failed") {
            Err(kind) => Err(kind),
            Ok(handle) => match reader.project_inherits(handle) {
                Err(_) => Err("project_attribute_unavailable"),
                Ok(true) => Err("project_scoped_query"),
                Ok(false) if matches!(config.capacity_scope, CapacityScope::ProjectScoped) => {
                    Err("project_scoped_query")
                }
                Ok(false) => read_counters(reader, handle, &mut row),
            },
        },
    };
    if let Err(kind) = result {
        row.error = Some(kind.to_owned());
        row.status = if kind == "project_scoped_query" {
            "unmeasured".to_owned()
        } else {
            "failed".to_owned()
        };
    }
    row.interval = interval(started, boot_id, clock)?;
    Ok(row)
}

fn read_counters<R: Reader>(
    reader: &R,
    handle: &R::Handle,
    row: &mut VolumeSample,
) -> Result<(), &'static str> {
    match reader.counters(handle) {
        Err(_) => Err("counter_read_failed"),
        Ok(counters) => {
            let bytes = (
                counters.blocks.checked_mul(counters.fragment_size),
                counters.blocks_free.checked_mul(counters.fragment_size),
                counters
                    .blocks_available
                    .checked_mul(counters.fragment_size),
            );
            match bytes {
                (Some(total), Some(free), Some(available))
                    if available <= free && free <= total =>
                {
                    row.total_bytes = Some(total);
                    row.free_bytes = Some(free);
                    row.available_bytes = Some(available);
                    row.total_inodes = Some(counters.files);
                    row.free_inodes = Some(counters.files_free);
                    row.available_inodes = Some(counters.files_available);
                    "complete".clone_into(&mut row.status);
                    Ok(())
                }
                _ => Err("counter_invalid"),
            }
        }
    }
}

fn ensure_dir(path: &Path, mode: u32, gid: u32) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(bad("record path is not a directory"));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(bad("record directory owner differs from sampler"));
    }
    if metadata.gid() != gid {
        chown(path, None, Some(Gid::from_raw(gid))).map_err(io::Error::other)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn publish(path: &Path, bytes: &[u8], mode: u32, reader_gid: Option<u32>) -> io::Result<()> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(bad("record exceeds byte bound"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| bad("record has no directory"))?;
    let temporary = parent.join(format!(".{}.{}.tmp", std::process::id(), now_ns()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    if let Some(gid) = reader_gid {
        chown(&temporary, None, Some(Gid::from_raw(gid))).map_err(io::Error::other)?;
    }
    let dir = File::open(parent)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        renameat2(
            &dir,
            temporary
                .file_name()
                .ok_or_else(|| bad("temporary name absent"))?,
            &dir,
            path.file_name().ok_or_else(|| bad("record name absent"))?,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(io::Error::other)?;
        dir.sync_all()
    })();
    let _removed = fs::remove_file(&temporary);
    result
}

fn read_nonce(state: &Path) -> io::Result<String> {
    let path = state.join("state-nonce");
    if fs::metadata(&path)?.len() > 64 {
        return Err(bad("state nonce exceeds byte bound"));
    }
    let text = fs::read_to_string(path)?;
    let nonce = text.trim_end_matches('\n');
    let valid = nonce.len() == 36
        && nonce.bytes().enumerate().all(|(position, byte)| {
            if matches!(position, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err(bad("state nonce invalid"));
    }
    Ok(nonce.to_owned())
}

fn create_nonce(
    state: &Path,
    attempts: &Path,
    samples: &Path,
    reader_gid: u32,
) -> io::Result<String> {
    match read_nonce(state) {
        Ok(nonce) => return Ok(nonce),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if fs::read_dir(attempts)?.next().is_some() || fs::read_dir(samples)?.next().is_some() {
        return Err(bad("state nonce absent beside existing custody"));
    }
    let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    let nonce = nonce.trim_end_matches('\n');
    if nonce.len() != 36 {
        return Err(bad("kernel nonce invalid"));
    }
    publish(
        &state.join("state-nonce"),
        nonce.as_bytes(),
        0o640,
        Some(reader_gid),
    )?;
    read_nonce(state)
}

fn next_sequence(attempts: &Path) -> io::Result<u64> {
    let mut maximum = 0;
    for entry in fs::read_dir(attempts)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        let attempt: Attempt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        maximum = maximum.max(attempt.sequence);
    }
    maximum
        .checked_add(1)
        .ok_or_else(|| bad("sequence exhausted"))
}

fn latest_date(attempts: &Path) -> io::Result<Option<String>> {
    let mut latest: Option<String> = None;
    for entry in fs::read_dir(attempts)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Some(date) = name.strip_suffix(".json") else {
            return Err(bad("attempt name invalid"));
        };
        if latest.as_deref().is_none_or(|prior| date > prior) {
            latest = Some(date.to_owned());
        }
    }
    Ok(latest)
}

fn sample_once<R: Reader>(
    config: &Config,
    state: &Path,
    reader: &R,
    started: u64,
    boot_id: &str,
) -> io::Result<Sample> {
    validate_config(config)?;
    let date = utc_date(started)?;
    ensure_dir(state, 0o750, config.reader_gid)?;
    let attempts = state.join("attempts");
    let samples = state.join("samples");
    ensure_dir(&attempts, 0o750, config.reader_gid)?;
    ensure_dir(&samples, 0o750, config.reader_gid)?;
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("sample.lock"))?;
    let _lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| io::Error::other(format!("sample busy: {error}")))?;
    let state_nonce = create_nonce(state, &attempts, &samples, config.reader_gid)?;
    if latest_date(&attempts)?
        .as_deref()
        .is_some_and(|last| date.as_str() <= last)
    {
        return Err(bad("daily slot already reserved or clock moved backwards"));
    }
    let sequence = next_sequence(&attempts)?;
    let attempt = Attempt {
        sequence,
        scheduled_date: date.clone(),
    };
    publish(
        &attempts.join(format!("{date}.json")),
        &serde_json::to_vec(&attempt).map_err(io::Error::other)?,
        0o640,
        Some(config.reader_gid),
    )?;
    let clock = Instant::now();
    let mut volumes = Vec::with_capacity(config.volumes.len());
    let mut errors = Vec::new();
    for volume in &config.volumes {
        let row = read_volume(volume, reader, boot_id)?;
        if let Some(kind) = &row.error {
            errors.push(ReadingError {
                volume_id: volume.id.clone(),
                kind: kind.clone(),
            });
        }
        volumes.push(row);
    }
    let observation = interval(started, boot_id, clock)?;
    let accounts = config
        .accounts
        .iter()
        .map(|account| AccountSample {
            account_id: account.account_id.clone(),
            uid: account.uid,
            storage_class: account.storage_class.clone(),
            volume_id: account.volume_id.clone(),
            project_id: account.project_id,
            collection_enabled: account.collection_enabled,
            coverage: "unmarked".to_owned(),
            interval: observation.clone(),
            status: "not_measured".to_owned(),
            charged_bytes: None,
            charged_inodes: None,
            limit_bytes: None,
            limit_inodes: None,
        })
        .collect();
    let status = if errors.is_empty() {
        "complete"
    } else if errors.len() == volumes.len() {
        "failed"
    } else {
        "partial"
    };
    let record = Sample {
        schema: 1,
        node_id: config.node_id.clone(),
        incarnation_id: config.incarnation_id.clone(),
        state_nonce,
        sequence,
        scheduled_date: date,
        interval: observation,
        configuration_revision: config.configuration_revision.clone(),
        status: status.to_owned(),
        errors,
        volumes,
        accounts,
    };
    publish(
        &samples.join(format!("{sequence:020}.json")),
        &serde_json::to_vec(&record).map_err(io::Error::other)?,
        0o640,
        Some(config.reader_gid),
    )?;
    Ok(record)
}

fn selected_attempts(
    attempts: &Path,
    after: u64,
    limit: usize,
) -> io::Result<BTreeMap<u64, Attempt>> {
    let mut selected = BTreeMap::new();
    for entry in fs::read_dir(attempts)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Some(date) = name.strip_suffix(".json") else {
            return Err(bad("attempt name invalid"));
        };
        let path = entry.path();
        if fs::metadata(&path)?.len() > 1024 {
            return Err(bad("attempt exceeds byte bound"));
        }
        let bytes = fs::read(path)?;
        if bytes.len() > 1024 {
            return Err(bad("attempt exceeds byte bound"));
        }
        let attempt: Attempt = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if attempt.scheduled_date != date || attempt.sequence == 0 {
            return Err(bad("attempt identity invalid"));
        }
        if attempt.sequence > after {
            if selected.insert(attempt.sequence, attempt).is_some() {
                return Err(bad("duplicate attempt sequence"));
            }
            if selected.len() > limit + 1 {
                selected.pop_last();
            }
        }
    }
    Ok(selected)
}

fn export(state: &Path, after: u64, limit: usize) -> io::Result<Vec<u8>> {
    if !(1..=MAX_PAGE_ROWS).contains(&limit) {
        return Err(bad("page limit outside 1..16"));
    }
    let state_nonce = read_nonce(state)?;
    let samples = state.join("samples");
    let selected = selected_attempts(&state.join("attempts"), after, limit)?;
    let mut rows = Vec::new();
    let mut unfinished = Vec::new();
    let mut next = after;
    let mut has_more = false;
    for (sequence, attempt) in selected {
        if rows.len() + unfinished.len() == limit {
            has_more = true;
            break;
        }
        let path = samples.join(format!("{sequence:020}.json"));
        let sample = match fs::metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
            Ok(metadata) => {
                if metadata.len() > MAX_RECORD_BYTES as u64 {
                    return Err(bad("sample exceeds byte bound"));
                }
                let bytes = fs::read(path)?;
                if bytes.len() > MAX_RECORD_BYTES {
                    return Err(bad("sample exceeds byte bound"));
                }
                let sample: Sample = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                if sample.schema != 1
                    || sample.sequence != sequence
                    || sample.scheduled_date != attempt.scheduled_date
                    || sample.state_nonce != state_nonce
                {
                    return Err(bad("sample identity invalid"));
                }
                Some(sample)
            }
        };
        let mut trial_rows = rows.clone();
        let mut trial_unfinished = unfinished.clone();
        if let Some(sample) = &sample {
            trial_rows.push(sample.clone());
        } else {
            trial_unfinished.push(attempt.clone());
        }
        let trial_page = serde_json::to_vec(&Export {
            schema: 1,
            state_nonce: state_nonce.clone(),
            after_sequence: after,
            next_after_sequence: sequence,
            has_more: true,
            samples: trial_rows,
            unfinished_attempts: trial_unfinished,
        })
        .map_err(io::Error::other)?;
        if trial_page.len() > MAX_PAGE_BYTES {
            if rows.is_empty() && unfinished.is_empty() {
                return Err(bad("entry exceeds export byte bound"));
            }
            has_more = true;
            break;
        }
        if let Some(sample) = sample {
            rows.push(sample);
        } else {
            unfinished.push(attempt);
        }
        next = sequence;
    }
    let page = serde_json::to_vec(&Export {
        schema: 1,
        state_nonce,
        after_sequence: after,
        next_after_sequence: next,
        has_more,
        samples: rows,
        unfinished_attempts: unfinished,
    })
    .map_err(io::Error::other)?;
    if page.len() > MAX_PAGE_BYTES {
        return Err(bad("export exceeds byte bound"));
    }
    Ok(page)
}

pub fn sample(config: &Path, state: &Path) -> io::Result<serde_json::Value> {
    let config = load_config(config)?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let record = sample_once(&config, state, &KernelReader, now_ns()?, boot_id.trim())?;
    serde_json::to_value(record).map_err(io::Error::other)
}

pub fn export_page(state: &Path, after: u64, limit: usize) -> io::Result<Vec<u8>> {
    export(state, after, limit)
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
