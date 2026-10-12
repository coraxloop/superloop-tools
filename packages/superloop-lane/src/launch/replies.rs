//! Deliver a pinned worker reply, then acknowledge exactly the delivered version.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{Read as _, Seek as _, SeekFrom, Write};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{checkout, follow};
use crate::{build, error::LaneError, home};

/// Receipts contain metadata only; their names are hashes of exact reply identities.
pub const RECEIPTS: &str = ".reply-receipts";
const MAX_REPLY: u64 = 1_000_000;
const MAX_JOURNAL: u64 = 16_777_216;

mod exercise;
pub use exercise::measure as exercise;

/// One public read, optionally previewed without publishing a receipt.
#[derive(Debug)]
pub struct Request {
    pub loop_name: String,
    pub run: String,
    pub name: String,
    pub dry_run: bool,
    pub range: Option<(u64, u64)>,
}

impl Request {
    /// Parse the public command's words, excluding its command name.
    ///
    /// # Errors
    /// Refuses an incomplete form, extra words, or an unpublished name.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let dry_run = args.last().is_some_and(|word| word == "--dry-run");
        let args = if dry_run {
            &args[..args.len() - 1]
        } else {
            args
        };
        let (words, range) = match args {
            [a, b, c] => ([a, b, c], None),
            [a, b, c, offset_flag, offset, length_flag, length]
                if offset_flag == "--offset" && length_flag == "--length" =>
            {
                ([a, b, c], Some(parse_range(offset, length)?))
            }
            _ => {
                return Err(refusal(
                    "read-reply-usage",
                    "read-reply LOOP RUN NAME [--offset N --length M] [--dry-run]",
                ));
            }
        };
        loop_home::validate_name(words[0])
            .map_err(|error| refusal("loop-name", error.message()))?;
        if !crate::valid_run_name(words[1]) {
            return Err(refusal("run-name", "invalid run name"));
        }
        decode_name(words[2])?;
        Ok(Self {
            loop_name: words[0].clone(),
            run: words[1].clone(),
            name: words[2].clone(),
            dry_run,
            range,
        })
    }
}

fn parse_range(offset: &str, length: &str) -> Result<(u64, u64), LaneError> {
    let number = |word: &str| {
        if word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(refusal(
                "read-reply-range",
                "offset and length must be unsigned decimal bytes",
            ));
        }
        word.parse::<u64>()
            .map_err(|_| refusal("read-reply-range", "offset or length exceeds u64"))
    };
    let offset = number(offset)?;
    let length = number(length)?;
    if !(1..=MAX_REPLY).contains(&length) {
        return Err(refusal(
            "read-reply-range",
            "length must contain 1 through 1000000 bytes",
        ));
    }
    if offset.checked_add(length).is_none() {
        return Err(refusal("read-reply-range", "offset + length overflows u64"));
    }
    Ok((offset, length))
}

/// The single private protocol, used for inspection, preparation and receipt publication.
#[derive(Debug)]
pub struct PrivateRequest {
    pub owner_home: PathBuf,
    pub request: Request,
    pub reservation: String,
    pub expected: Option<String>,
    pub inspect: bool,
}

impl PrivateRequest {
    /// Parse exactly the form built by `private_argv`.
    ///
    /// # Errors
    /// Refuses malformed flags, names, or receipt identities.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let (args, range) = match args.len() {
            10 => (args, None),
            14 if args[10] == "--offset" && args[12] == "--length" => {
                (&args[..10], Some(parse_range(&args[11], &args[13])?))
            }
            _ => return Err(refusal("read-reply-private", "incomplete private form")),
        };
        let [
            command,
            loop_name,
            run,
            name,
            home_flag,
            owner_home,
            record_flag,
            reservation,
            phase,
            expected,
        ] = args
        else {
            return Err(refusal("read-reply-private", "incomplete private form"));
        };
        if command != "_read-reply-private"
            || home_flag != "--owner-home"
            || record_flag != "--record-identity"
            || !Path::new(owner_home).is_absolute()
            || !((matches!(phase.as_str(), "--prepare" | "--inspect") && expected == "-")
                || (phase == "--receipt" && digest_word(expected)))
        {
            return Err(refusal("read-reply-private", "malformed private form"));
        }
        if range.is_some() && phase != "--prepare" {
            return Err(refusal(
                "read-reply-private",
                "range reads prepare bytes only; no receipt or inspection",
            ));
        }
        let mut request = Request::parse(&[loop_name.clone(), run.clone(), name.clone()])?;
        request.range = range;
        Ok(Self {
            owner_home: PathBuf::from(owner_home),
            request,
            reservation: reservation.clone(),
            expected: (phase == "--receipt").then(|| expected.clone()),
            inspect: phase == "--inspect",
        })
    }
}

/// Build the private helper's words; all phases use this one builder.
///
/// # Errors
/// Refuses an owner home that is not a lossless path word.
pub fn private_argv(
    owner_home: &Path,
    request: &Request,
    reservation: &str,
    phase: &str,
    expected: Option<&str>,
) -> Result<Vec<String>, LaneError> {
    let mut argv = vec![
        "_read-reply-private".into(),
        request.loop_name.clone(),
        request.run.clone(),
        request.name.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "owner-home")?,
        "--record-identity".into(),
        reservation.into(),
        phase.into(),
        expected.unwrap_or("-").into(),
    ];
    if let Some((offset, length)) = request.range {
        argv.extend([
            "--offset".into(),
            offset.to_string(),
            "--length".into(),
            length.to_string(),
        ]);
    }
    Ok(argv)
}

fn inspection_argv(
    owner_home: &Path,
    request: &Request,
    reservation: &str,
) -> Result<Vec<String>, LaneError> {
    private_argv(owner_home, request, reservation, "--inspect", None)
}

/// Deliver the reply before asking the helper to publish its exact-version receipt.
///
/// # Errors
/// Refuses an unplanned run, unsafe reply, changed identity, or failed output.
pub fn run(
    owner_home: &Path,
    request: &Request,
    output: &mut impl Write,
    records: &mut impl Write,
) -> Result<(), LaneError> {
    let reader = BoundReader::open(owner_home, request)?;
    deliver(request, output, records, |expected| {
        reader.invoke(request, expected, false)
    })
}

struct BoundReader {
    owner_home: PathBuf,
    root: PathBuf,
    pinned_home: OwnedFd,
    runs: OwnedFd,
    environment: std::collections::BTreeMap<String, String>,
    program: String,
    exe: String,
    reservation: String,
}

impl BoundReader {
    fn open(owner_home: &Path, request: &Request) -> Result<Self, LaneError> {
        let owner = Uid::effective().as_raw();
        let (plan, settings) =
            crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (owner, 0))?;
        let root = settings
            .runs_root
            .as_deref()
            .ok_or_else(|| refusal("read-reply-unplanned", "run has no recorded root"))?;
        let runs = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
        let (record, reservation) = checkout::read_record_bound(&runs, &request.run, owner)
            .map_err(|error| refusal("read-reply-unplanned", error.line()))?;
        follow::validate_record(&plan, &record, &request.loop_name, &request.run)?;
        let program = record["plan"]["runtime_argv"][0]
            .as_str()
            .ok_or_else(|| refusal("read-reply-unplanned", "recorded runtime is absent"))?;
        let exe = std::env::current_exe().map_err(runtime)?;
        let exe = crate::pinned::owner_executable_word(&exe, owner)?;
        let pinned_home = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
        let environment = super::launch_environment(owner_home)?;
        Ok(Self {
            owner_home: owner_home.to_path_buf(),
            root: root.to_path_buf(),
            pinned_home,
            runs,
            environment,
            program: program.to_owned(),
            exe,
            reservation,
        })
    }

    fn invoke(
        &self,
        request: &Request,
        expected: Option<&str>,
        inspect: bool,
    ) -> Result<Value, LaneError> {
        let mut argv = vec!["unshare".into(), self.exe.clone()];
        argv.extend(if inspect {
            inspection_argv(&self.owner_home, request, &self.reservation)?
        } else {
            private_argv(
                &self.owner_home,
                request,
                &self.reservation,
                if expected.is_some() {
                    "--receipt"
                } else {
                    "--prepare"
                },
                expected,
            )?
        });
        let spec = build::child(
            Path::new(&self.program),
            argv,
            &self.environment,
            &self.owner_home,
            60,
            "read-reply-helper",
        )
        .with_private_launch(&self.pinned_home, &self.root, &self.runs, None)?;
        helper_response(&build::run_child(&spec, None)?)
    }
}

fn helper_response(response: &build::ChildResult) -> Result<Value, LaneError> {
    if !response.status.success() {
        let detail = String::from_utf8_lossy(&response.stderr).into_owned();
        return Err(if response.status.code() == Some(2) {
            refusal("read-reply-helper", detail)
        } else {
            LaneError::operation("read-reply-helper", detail)
        });
    }
    serde_json::from_slice(&response.stdout)
        .map_err(|_| refusal("read-reply-helper", "invalid private response"))
}

fn deliver(
    request: &Request,
    output: &mut impl Write,
    records: &mut impl Write,
    mut invoke: impl FnMut(Option<&str>) -> Result<Value, LaneError>,
) -> Result<(), LaneError> {
    let prepared = invoke(None)?;
    let body = unhex(
        prepared["body_hex"]
            .as_str()
            .ok_or_else(|| refusal("read-reply-helper", "reply bytes absent"))?,
    )?;
    let identity = prepared["identity"]
        .as_str()
        .filter(|word| digest_word(word))
        .ok_or_else(|| refusal("read-reply-helper", "reply identity absent"))?;
    let reply = &prepared["reply"];
    if let Some((offset, length)) = request.range {
        if reply["offset"].as_u64() != Some(offset)
            || reply["length"].as_u64() != Some(length)
            || body.len() as u64 != length
            || reply["bytes"]
                .as_u64()
                .is_none_or(|total| offset.checked_add(length).is_none_or(|end| end > total))
            || reply["digest"] != hex(&Sha256::digest(&body))
        {
            return Err(refusal(
                "read-reply-helper",
                "range response differs from requested bytes",
            ));
        }
        output
            .write_all(&body)
            .and_then(|()| output.flush())
            .map_err(runtime)?;
        writeln!(records, "READ-REPLY name={} total_bytes={} offset={} length={} revision={} at={} digest={} identity={} receipts=none actions=0 dry_run={}",
            request.name, reply["bytes"], offset, length, reply["revision"], reply["at"].as_str().unwrap_or("invalid"), reply["digest"].as_str().unwrap_or("invalid"), identity, request.dry_run)
            .and_then(|()| records.flush()).map_err(runtime)?;
        return Ok(());
    }
    output
        .write_all(&body)
        .and_then(|()| output.flush())
        .map_err(runtime)?;
    let reply = &prepared["reply"];
    writeln!(records, "READ-REPLY name={} bytes={} revision={} at={} digest={} identity={} receipts={} actions=1 dry_run={}",
        request.name, reply["bytes"], reply["revision"], reply["at"].as_str().unwrap_or("invalid"),
        reply["digest"].as_str().unwrap_or("invalid"), identity, RECEIPTS, request.dry_run)
        .and_then(|()| records.flush()).map_err(runtime)?;
    if !request.dry_run && invoke(Some(identity))?["identity"] != prepared["identity"] {
        return Err(refusal(
            "read-reply-changed",
            "receipt identity differs from delivered reply",
        ));
    }
    Ok(())
}

/// Execute a request only after the entry has bound the inherited descriptors.
///
/// # Errors
/// Refuses a non-owner helper, replaced reservation, or unsafe mailbox input.
pub fn private(request: &PrivateRequest) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() || !home::private_is_active() {
        return Err(refusal(
            "read-reply-private",
            "bound namespace owner is required",
        ));
    }
    private_bound(request, 0, true)
}

fn private_bound(
    request: &PrivateRequest,
    owner: u32,
    drop_identity: bool,
) -> Result<Value, LaneError> {
    if home::private_home().as_deref() != Some(request.owner_home.as_path()) {
        return Err(refusal(
            "read-reply-private",
            "owner home differs from inherited anchor",
        ));
    }
    let (root, runs) = home::private_runs()?;
    let (record, identity) = checkout::read_record_bound(&runs, &request.request.run, owner)
        .map_err(|error| refusal("read-reply-unplanned", error.line()))?;
    if identity != request.reservation {
        return Err(refusal(
            "read-reply-changed",
            "reservation changed after the public read",
        ));
    }
    let recorded_home = record["plan"]["home"]
        .as_str()
        .ok_or_else(|| refusal("read-reply-unplanned", "run has no recorded home"))?;
    let recorded_driver = record["plan"]["driver_dir"].as_str().ok_or_else(|| {
        refusal(
            "read-reply-unplanned",
            "run has no recorded driver directory",
        )
    })?;
    if Path::new(recorded_driver) != root.join(&request.request.run) {
        return Err(refusal(
            "read-reply-unplanned",
            "driver directory differs from inherited run root",
        ));
    }
    let plan = crate::plan::Plan {
        home: PathBuf::from(recorded_home),
        driver_dir: PathBuf::from(recorded_driver),
        letter: PathBuf::new(),
        document: record["plan"].clone(),
    };
    follow::validate_record(
        &plan,
        &record,
        &request.request.loop_name,
        &request.request.run,
    )?;
    if request.inspect {
        return exercise::inspect(&plan, &record, &runs, &root, owner, &request.request.name);
    }
    let context = Context::open_range(
        &plan,
        &record,
        &runs,
        &root,
        owner,
        &request.request.name,
        request.request.range,
    )?;
    context.execute(request.expected.as_deref(), drop_identity)
}

struct Context {
    range: Option<(u64, u64)>,
    outbox: File,
    journal_dir: File,
    file: File,
    before: Metadata,
    loop_uid: u32,
    worker_uid: u32,
    name: String,
    raw_name: Vec<u8>,
    observation: Value,
    observation_key: String,
}

struct RunObservations {
    directories: BTreeMap<PathBuf, File>,
    selected: BTreeMap<String, lane_lifecycle::RunReplyObservation>,
}

fn run_observations(
    plan: &crate::plan::Plan,
    record: &Value,
    runs: &OwnedFd,
    root: &Path,
    loop_uid: u32,
) -> Result<RunObservations, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| refusal("read-reply-unplanned", "recorded rounds absent"))?;
    let mut directories = BTreeMap::new();
    let mut journals = BTreeMap::new();
    for round in rounds {
        let directory = follow::recorded_directory(plan, round)?;
        if directories.contains_key(&directory) {
            continue;
        }
        let held = pin_journal_round(runs, root, &directory, loop_uid)?;
        if let Some(rows) = journal_rows(&held, loop_uid)? {
            journals.insert(directory.clone(), rows);
        }
        directories.insert(directory, held);
    }
    let selected = lane_lifecycle::run_reply_observations(&journals)
        .map_err(|_| refusal("read-reply-journal", "invalid observation identity"))?;
    Ok(RunObservations {
        directories,
        selected,
    })
}

impl Context {
    fn open(
        plan: &crate::plan::Plan,
        record: &Value,
        runs: &OwnedFd,
        root: &Path,
        owner: u32,
        name: &str,
    ) -> Result<Self, LaneError> {
        Self::open_range(plan, record, runs, root, owner, name, None)
    }

    fn open_range(
        plan: &crate::plan::Plan,
        record: &Value,
        runs: &OwnedFd,
        root: &Path,
        owner: u32,
        name: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Self, LaneError> {
        let raw_name = decode_name(name)?;
        let loop_uid = super::recorded_loop_uid(record)?;
        let worker_uid = record["worker_uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .filter(|uid| *uid != loop_uid)
            .ok_or_else(|| {
                refusal(
                    "read-reply-owner",
                    "worker identity is absent or equals reader",
                )
            })?;
        let home = File::from(home::pin_parent(&plan.home, owner)?);
        let local = open_at(&home, b".local", true)?;
        check_directory(&local, owner, None, "worker local root")?;
        let outbox = open_at(&local, b"outbox", true)?;
        check_directory(&outbox, worker_uid, Some((loop_uid, 0o750)), "outbox")?;
        let file = open_at(&outbox, &raw_name, false)?;
        let before = file.metadata().map_err(runtime)?;
        check_reply(&before, worker_uid, range)?;
        let mut observations = run_observations(plan, record, runs, root, loop_uid)?;
        if let Some(selected) = observations.selected.remove(name) {
            let journal_dir = observations
                .directories
                .remove(&selected.journal)
                .ok_or_else(|| refusal("read-reply-journal", "selected journal absent"))?;
            let selected = selected.observation;
            let observation = selected.row;
            let version_matches = lane_lifecycle::reply_version_matches(
                &observation,
                before.ino(),
                before.ctime(),
                before.ctime_nsec(),
            )
            .map_err(|_| refusal("read-reply-journal", "invalid file version"))?;
            if observation["bytes"].as_u64() != Some(before.len()) || !version_matches {
                return Err(refusal(
                    "read-reply-unobserved",
                    "reply differs from its latest journal observation",
                ));
            }
            return Ok(Self {
                range,
                outbox,
                journal_dir,
                file,
                before,
                loop_uid,
                worker_uid,
                name: name.into(),
                raw_name,
                observation,
                observation_key: selected.key,
            });
        }
        Err(refusal(
            "read-reply-unobserved",
            "published reply has no recorded observation",
        ))
    }

    fn execute(mut self, expected: Option<&str>, drop_identity: bool) -> Result<Value, LaneError> {
        if self.range.is_some() && expected.is_some() {
            return Err(refusal(
                "read-reply-private",
                "range reads cannot publish whole-reply receipts",
            ));
        }
        let (offset, length) = self.range.unwrap_or((0, self.before.len()));
        self.file.seek(SeekFrom::Start(offset)).map_err(runtime)?;
        let mut body = Vec::new();
        std::io::Read::by_ref(&mut self.file)
            .take(length)
            .read_to_end(&mut body)
            .map_err(runtime)?;
        self.unchanged()?;
        if body.len() as u64 != length {
            return Err(refusal("read-reply-changed", "reply changed during read"));
        }
        let digest = hex(&Sha256::digest(&body));
        let mut reply = json!({"name":self.name,"bytes":self.before.len(),"revision":self.observation["revision"],
            "at":self.observation["at"],"digest":digest,"file":version(&self.before)});
        if self.range.is_some() {
            reply["offset"] = json!(offset);
            reply["length"] = json!(length);
        }
        let identity = reply_identity(&reply);
        self.unchanged()?;
        if let Some(expected) = expected {
            if expected != identity {
                return Err(refusal(
                    "read-reply-changed",
                    "reply changed after delivery; no receipt written",
                ));
            }
            if drop_identity {
                become_reader(self.loop_uid)?;
            }
            publish_receipt(
                &self.journal_dir,
                self.loop_uid,
                &self.observation_key,
                &identity,
                &reply,
            )?;
        }
        Ok(
            json!({"identity":identity,"reply":reply,"body_hex":if expected.is_none() { hex(&body) } else { String::new() },"loop_uid":self.loop_uid}),
        )
    }

    fn unchanged(&self) -> Result<(), LaneError> {
        let held = self.file.metadata().map_err(runtime)?;
        let current = open_at(&self.outbox, &self.raw_name, false)?
            .metadata()
            .map_err(runtime)?;
        if comparable_version(&held) != comparable_version(&self.before)
            || comparable_version(&current) != comparable_version(&self.before)
        {
            return Err(refusal("read-reply-changed", "reply changed during read"));
        }
        check_reply(&held, self.worker_uid, self.range)?;
        Ok(())
    }
}

fn journal_rows(journal_dir: &File, loop_uid: u32) -> Result<Option<Vec<Value>>, LaneError> {
    let journal = match open_at(journal_dir, b"letters.jsonl", false) {
        Ok(file) => file,
        Err(error) if error.kind == "read-reply-absent" => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = journal.metadata().map_err(runtime)?;
    if !meta.is_file()
        || observed_uid(&meta) != loop_uid
        || meta.mode() & 0o022 != 0
        || meta.len() > MAX_JOURNAL
    {
        return Err(refusal(
            "read-reply-journal",
            "journal type, owner, mode or size differs",
        ));
    }
    let mut bytes = Vec::new();
    journal
        .take(MAX_JOURNAL + 1)
        .read_to_end(&mut bytes)
        .map_err(runtime)?;
    if bytes.len() as u64 > MAX_JOURNAL || (!bytes.is_empty() && !bytes.ends_with(b"\n")) {
        return Err(refusal(
            "read-reply-journal",
            "journal is oversized or incomplete",
        ));
    }
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row: Value = serde_json::from_slice(line)
            .map_err(|_| refusal("read-reply-journal", "malformed journal record"))?;
        rows.push(row);
    }
    Ok(Some(rows))
}

fn version(meta: &Metadata) -> Value {
    // mtime/ctime are Unix seconds since 1970-01-01T00:00:00Z; the *_ns fields
    // are nanosecond fractions within those seconds, not independent epochs.
    json!({"device":meta.dev(),"inode":meta.ino(),"bytes":meta.len(),"mtime":meta.mtime(),"mtime_ns":meta.mtime_nsec(),"ctime":meta.ctime(),"ctime_ns":meta.ctime_nsec()})
}

fn comparable_version(meta: &Metadata) -> Value {
    let mut value = version(meta);
    remove_device(&mut value);
    value
}

fn remove_device(version: &mut Value) {
    if let Some(fields) = version.as_object_mut() {
        fields.remove("device");
    }
}

fn reply_identity(reply: &Value) -> String {
    let mut comparable = reply.clone();
    remove_device(&mut comparable["file"]);
    hex(&Sha256::digest(comparable.to_string().as_bytes()))
}

fn same_receipt(saved: &[u8], expected: &[u8]) -> bool {
    let (Ok(mut saved), Ok(mut expected)) = (
        serde_json::from_slice::<Value>(saved),
        serde_json::from_slice::<Value>(expected),
    ) else {
        return false;
    };
    // Device numbers remain evidence, but are not durable file identities across mounts.
    if let Some(file) = saved
        .get_mut("reply")
        .and_then(|reply| reply.get_mut("file"))
    {
        remove_device(file);
    }
    if let Some(file) = expected
        .get_mut("reply")
        .and_then(|reply| reply.get_mut("file"))
    {
        remove_device(file);
    }
    saved == expected
}

fn check_reply(meta: &Metadata, worker: u32, range: Option<(u64, u64)>) -> Result<(), LaneError> {
    if !meta.is_file()
        || observed_uid(meta) != worker
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(refusal(
            "read-reply-owner",
            "reply must be one regular worker-owned file at 0600",
        ));
    }
    if let Some((offset, length)) = range {
        if !(1..=MAX_REPLY).contains(&length)
            || offset
                .checked_add(length)
                .is_none_or(|end| end > meta.len())
        {
            return Err(refusal(
                "read-reply-range",
                "range must fit wholly inside the reply with length 1 through 1000000 bytes",
            ));
        }
    } else if meta.len() == 0 || meta.len() > MAX_REPLY {
        return Err(refusal(
            "read-reply-size",
            "reply must contain 1 through 1000000 bytes; use --offset N --length M for a bounded range without a receipt",
        ));
    }
    Ok(())
}

fn pin_journal_round(
    runs: &OwnedFd,
    root: &Path,
    directory: &Path,
    loop_uid: u32,
) -> Result<File, LaneError> {
    #[cfg(not(test))]
    let journal_dir = File::from(home::pin_loop_round_at(runs, root, directory, loop_uid)?);
    #[cfg(test)]
    let journal_dir = File::from(home::pin_loop_round_at_with(
        runs,
        root,
        directory,
        loop_uid,
        |fd, _| {
            let meta = File::from(nix::unistd::dup(fd).map_err(runtime)?)
                .metadata()
                .map_err(runtime)?;
            Ok((observed_uid(&meta), meta.mode() & 0o7777))
        },
    )?);
    Ok(journal_dir)
}

fn become_reader(uid: u32) -> Result<(), LaneError> {
    #[cfg(test)]
    if FIXTURE_WRITER.with(|writer| writer.get().is_some()) {
        FIXTURE_WRITER.with(|writer| writer.set(Some(uid)));
        return Ok(());
    }
    nix::unistd::setgroups(&[]).map_err(runtime)?;
    nix::unistd::setresgid(Gid::from_raw(uid), Gid::from_raw(uid), Gid::from_raw(uid))
        .map_err(runtime)?;
    nix::unistd::setresuid(Uid::from_raw(uid), Uid::from_raw(uid), Uid::from_raw(uid))
        .map_err(runtime)?;
    Ok(())
}

fn check_directory(
    file: &File,
    owner: u32,
    exact: Option<(u32, u32)>,
    name: &str,
) -> Result<(), LaneError> {
    let meta = file.metadata().map_err(runtime)?;
    if !meta.is_dir()
        || observed_uid(&meta) != owner
        || meta.mode() & 0o022 != 0
        || exact
            .is_some_and(|(gid, mode)| observed_gid(&meta) != gid || meta.mode() & 0o7777 != mode)
    {
        return Err(refusal(
            "read-reply-custody",
            format!(
                "{name}: owner={} group={} mode={:04o}; expected owner={owner} group/mode={exact:?}",
                observed_uid(&meta),
                observed_gid(&meta),
                meta.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

fn open_at(parent: &File, name: &[u8], directory: bool) -> Result<File, LaneError> {
    let word = CString::new(name).map_err(|_| refusal("read-reply-name", "NUL in name"))?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: the held parent and terminated child name remain valid for openat.
    #[allow(unsafe_code)]
    let fd = unsafe { libc::openat(parent.as_raw_fd(), word.as_ptr(), flags) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(refusal(
            if error.kind() == std::io::ErrorKind::NotFound {
                "read-reply-absent"
            } else {
                "read-reply-path"
            },
            format!(
                "name={}: {error}",
                lane_lifecycle::escape_mailbox_name(name)
            ),
        ));
    }
    // SAFETY: successful openat transfers ownership of this descriptor.
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn receipt_directory(parent: &File, owner: u32) -> Result<File, LaneError> {
    let directory = CString::new(RECEIPTS).map_err(runtime)?;
    // SAFETY: mkdirat uses the held journal parent and a terminated constant name.
    #[allow(unsafe_code)]
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), directory.as_ptr(), 0o755) };
    if created < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
        return Err(runtime(std::io::Error::last_os_error()));
    }
    let receipts = open_at(parent, RECEIPTS.as_bytes(), true)?;
    if created == 0 {
        #[cfg(test)]
        map_created(&receipts);
        nix::sys::stat::fchmod(&receipts, nix::sys::stat::Mode::from_bits_truncate(0o755))
            .map_err(runtime)?;
    }
    check_directory(&receipts, owner, Some((owner, 0o755)), RECEIPTS)?;
    Ok(receipts)
}

fn existing_receipt(
    receipts: &File,
    owner: u32,
    name: &[u8],
    bytes: &[u8],
) -> Result<bool, LaneError> {
    let existing = match open_at(receipts, name, false) {
        Ok(file) => Some(file),
        Err(error) if error.kind == "read-reply-absent" => None,
        Err(error) => return Err(error),
    };
    if let Some(mut existing) = existing {
        let meta = existing.metadata().map_err(runtime)?;
        let mut saved = Vec::new();
        if !meta.is_file()
            || observed_uid(&meta) != owner
            || meta.mode() & 0o7777 != 0o600
            || meta.len() > 8192
        {
            return Err(refusal(
                "read-reply-receipt",
                "existing receipt custody differs",
            ));
        }
        existing.read_to_end(&mut saved).map_err(runtime)?;
        if !same_receipt(&saved, bytes) {
            return Err(refusal(
                "read-reply-changed",
                "existing receipt identity differs from delivered version",
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

fn publish_receipt(
    parent: &File,
    owner: u32,
    observation_key: &str,
    identity: &str,
    reply: &Value,
) -> Result<(), LaneError> {
    let receipts = receipt_directory(parent, owner)?;
    let final_name = format!("{observation_key}.json");
    let bytes = format!(
        "{}\n",
        json!({"schema":1,"observation":observation_key,"identity":identity,"reply":reply})
    );
    if existing_receipt(&receipts, owner, final_name.as_bytes(), bytes.as_bytes())? {
        return Ok(());
    }
    let temporary =
        CString::new(format!(".tmp-{}-{identity}", std::process::id())).map_err(runtime)?;
    // SAFETY: all creation and publication operations are beneath the held receipts directory.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::openat(
            receipts.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(runtime(std::io::Error::last_os_error()));
    }
    // SAFETY: successful openat transfers one descriptor.
    #[allow(unsafe_code)]
    let mut file = unsafe { File::from_raw_fd(raw) };
    #[cfg(test)]
    map_created(&file);
    let final_word = CString::new(final_name).map_err(runtime)?;
    let mut published = false;
    let result = (|| {
        #[cfg(test)]
        receipt_fault("write")?;
        file.write_all(bytes.as_bytes()).map_err(runtime)?;
        nix::sys::stat::fchmod(&file, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .map_err(runtime)?;
        #[cfg(test)]
        receipt_fault("sync")?;
        file.sync_all().map_err(runtime)?;
        #[cfg(test)]
        corrupt_staged_receipt(&file)?;
        let metadata = file.metadata().map_err(runtime)?;
        let staged = open_at(&receipts, temporary.as_bytes(), false)?
            .metadata()
            .map_err(runtime)?;
        #[cfg(test)]
        receipt_fault("verify")?;
        if !metadata.is_file()
            || observed_uid(&metadata) != owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != bytes.len() as u64
            || version(&metadata) != version(&staged)
        {
            return Err(refusal(
                "read-reply-receipt",
                "staged receipt identity differs",
            ));
        }
        #[cfg(test)]
        receipt_fault("rename")?;
        // SAFETY: both names are terminated and both anchors are the held receipts directory.
        #[allow(unsafe_code)]
        let renamed = unsafe {
            libc::renameat2(
                receipts.as_raw_fd(),
                temporary.as_ptr(),
                receipts.as_raw_fd(),
                final_word.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if renamed < 0 {
            return Err(runtime(std::io::Error::last_os_error()));
        }
        published = true;
        #[cfg(test)]
        receipt_fault("directory-sync")?;
        receipts
            .sync_all()
            .and_then(|()| parent.sync_all())
            .map_err(runtime)
    })();
    if result.is_err() {
        if published
            && let Ok(current) = open_at(&receipts, final_word.as_bytes(), false)
            && let (Ok(current), Ok(held)) = (current.metadata(), file.metadata())
            && current.dev() == held.dev()
            && current.ino() == held.ino()
        {
            // SAFETY: rollback removes only the exact inode this call published.
            #[allow(unsafe_code)]
            unsafe {
                libc::unlinkat(receipts.as_raw_fd(), final_word.as_ptr(), 0);
            }
            let _sync = receipts.sync_all();
        }
        // SAFETY: remove only our temporary name beneath its original held directory.
        #[allow(unsafe_code)]
        unsafe {
            libc::unlinkat(receipts.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn decode_name(name: &str) -> Result<Vec<u8>, LaneError> {
    let mut raw = Vec::new();
    let mut words = name.as_bytes().iter().copied();
    while let Some(byte) = words.next() {
        if byte == b'%' {
            let pair = words
                .next()
                .zip(words.next())
                .and_then(|(a, b)| hex_digit(a).zip(hex_digit(b)));
            let Some((a, b)) = pair else {
                return Err(refusal("read-reply-name", "malformed escaped reply name"));
            };
            raw.push(a * 16 + b);
        } else {
            raw.push(byte);
        }
    }
    if raw.is_empty()
        || raw.len() > 255
        || raw.starts_with(b".")
        || raw.contains(&b'/')
        || raw.contains(&0)
        || lane_lifecycle::escape_mailbox_name(&raw) != name
    {
        return Err(refusal(
            "read-reply-name",
            format!(
                "name={} is not a published escaped reply name",
                lane_lifecycle::escape_mailbox_name(name.as_bytes())
            ),
        ));
    }
    Ok(raw)
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|n| u8::try_from(n).ok())
}
fn digest_word(word: &str) -> bool {
    word.len() == 64
        && word
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
fn unhex(word: &str) -> Result<Vec<u8>, LaneError> {
    if !word.len().is_multiple_of(2) || word.len() as u64 > MAX_REPLY * 2 {
        return Err(refusal("read-reply-helper", "invalid encoded reply size"));
    }
    word.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            hex_digit(pair[0])
                .zip(hex_digit(pair[1]))
                .map(|(a, b)| a * 16 + b)
                .ok_or_else(|| refusal("read-reply-helper", "invalid encoded reply"))
        })
        .collect()
}
fn refusal(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}
fn runtime(error: impl std::fmt::Display) -> LaneError {
    LaneError::operation("read-reply-io", error.to_string())
}

fn observed_uid(meta: &Metadata) -> u32 {
    #[cfg(test)]
    if let Some(uid) = TEST_OWNERS.with(|owners| {
        owners
            .borrow()
            .get(&(meta.dev(), meta.ino()))
            .map(|(uid, _, _)| *uid)
    }) {
        return uid;
    }
    meta.uid()
}
fn observed_gid(meta: &Metadata) -> u32 {
    #[cfg(test)]
    if let Some(gid) = TEST_OWNERS.with(|owners| {
        owners
            .borrow()
            .get(&(meta.dev(), meta.ino()))
            .map(|(_, gid, _)| *gid)
    }) {
        return gid;
    }
    meta.gid()
}

#[cfg(test)]
thread_local! { static FIXTURE_WRITER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
fn map_created(file: &File) {
    if let Some(uid) = FIXTURE_WRITER.with(std::cell::Cell::get) {
        let meta = file.metadata().expect("fixture created inode");
        TEST_OWNERS.with(|owners| {
            owners.borrow_mut().insert(
                (meta.dev(), meta.ino()),
                (uid, uid, file.try_clone().expect("hold fixture inode")),
            )
        });
    }
}

#[cfg(test)]
type FixtureOwners = std::collections::BTreeMap<(u64, u64), (u32, u32, File)>;
#[cfg(test)]
thread_local! { static TEST_OWNERS: std::cell::RefCell<FixtureOwners> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) }; }

#[cfg(test)]
thread_local! { static RECEIPT_FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
fn corrupt_staged_receipt(file: &File) -> Result<(), LaneError> {
    if RECEIPT_FAULT.with(|fault| fault.get() == Some("staged-mismatch")) {
        RECEIPT_FAULT.with(|fault| fault.set(None));
        nix::sys::stat::fchmod(file, nix::sys::stat::Mode::from_bits_truncate(0o644))
            .map_err(runtime)?;
    }
    Ok(())
}

#[cfg(test)]
fn receipt_fault(stage: &str) -> Result<(), LaneError> {
    if RECEIPT_FAULT.with(|fault| fault.get() == Some(stage)) {
        RECEIPT_FAULT.with(|fault| fault.set(None));
        return Err(runtime(format!("fixture receipt {stage} failure")));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
