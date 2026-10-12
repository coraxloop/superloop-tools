//! Move a finished run and its custody aside only after absence is established.

use super::*;
use crate::door::retirement as node;

#[path = "retire_proof.rs"]
pub(super) mod proof;

#[path = "retire_absences.rs"]
pub(crate) mod absences;
#[path = "retire_node.rs"]
pub(crate) mod node_record;
#[path = "retire_node_rewrite.rs"]
pub mod node_rewrite;
#[cfg(test)]
#[path = "retire_node_tests.rs"]
mod node_tests;
#[path = "retire_rewrite.rs"]
pub(crate) mod rewrite;

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI modifiers, checked by the parser.
pub struct RetireRequest {
    pub loop_name: String,
    pub run: Option<String>,
    pub generations: bool,
    pub dry_run: bool,
    pub confirm_uncertain: bool,
    pub confirm_missing_lease: bool,
    pub confirm_missing_harvest_fields: bool,
    pub rewrite: bool,
    pub node: bool,
    pub expect_digest: Option<String>,
}

impl RetireRequest {
    /// Parse the run or generation retirement form.
    ///
    /// # Errors
    ///
    /// Refuses missing names, an invalid run, or unknown options.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        if args.first().is_some_and(|word| word == "rewrite") {
            if args.get(1).is_some_and(|word| word == "rewrite") {
                return Err(LaneError::input(
                    "retire-usage",
                    "rewrite cannot be repeated",
                ));
            }
            let mut request = Self::parse(&args[1..])?;
            if request.rewrite
                || request.generations
                || request.node
                || request.confirm_uncertain
                || request.confirm_missing_lease
                || request.confirm_missing_harvest_fields
                || (!request.dry_run && request.expect_digest.is_none())
            {
                return Err(LaneError::input(
                    "retire-usage",
                    "retire rewrite LOOP RUN {--dry-run|--expect-digest HEX}",
                ));
            }
            request.rewrite = true;
            return Ok(request);
        }
        let [loop_name, rest @ ..] = args else {
            return Err(LaneError::input(
                "retire-usage",
                "retire LOOP RUN [--confirm-uncertain] [--confirm-missing-lease] [--confirm-missing-harvest-fields] [--dry-run|--expect-digest HEX]|retire LOOP RUN --node [--dry-run|--expect-digest HEX] or retire LOOP --generations [--dry-run]",
            ));
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        let mut rest = rest.to_vec();
        let expect_digest =
            if let Some(index) = rest.iter().position(|word| word == "--expect-digest") {
                if index + 2 != rest.len()
                    || rest[index + 1].len() != 64
                    || !rest[index + 1].bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(LaneError::input(
                        "retire-usage",
                        "--expect-digest requires the preview_sha256",
                    ));
                }
                let digest = rest.pop();
                rest.pop();
                digest
            } else {
                None
            };
        let node = rest.iter().any(|word| word == "--node");
        if node {
            if rest.get(1).map(String::as_str) != Some("--node") {
                return Err(LaneError::input(
                    "retire-usage",
                    "use retire LOOP RUN --node [--dry-run|--expect-digest HEX]",
                ));
            }
            rest.remove(1);
        }
        let dry_run = rest.iter().any(|word| word == "--dry-run");
        let generations = rest.iter().any(|word| word == "--generations");
        let confirm_uncertain = rest.iter().any(|word| word == "--confirm-uncertain");
        let confirm_missing_lease = take_confirmation(&mut rest, "--confirm-missing-lease")?;
        let confirm_missing_harvest_fields =
            take_confirmation(&mut rest, "--confirm-missing-harvest-fields")?;
        let valid = if generations {
            rest == ["--generations"] || rest == ["--generations", "--dry-run"]
        } else {
            (rest.len() == 1
                || rest.len() == 2
                    && ["--dry-run", "--confirm-uncertain"].contains(&rest[1].as_str())
                || rest.len() == 3 && rest[1] == "--confirm-uncertain" && rest[2] == "--dry-run")
                && valid_run_name(&rest[0])
        };
        if !valid
            || (node && (generations || confirm_uncertain))
            || (expect_digest.is_some() && (dry_run || generations))
            || ((confirm_missing_lease || confirm_missing_harvest_fields) && (node || generations))
        {
            return Err(LaneError::input(
                "retire-usage",
                "retire LOOP RUN [--confirm-uncertain] [--confirm-missing-lease] [--confirm-missing-harvest-fields] [--dry-run|--expect-digest HEX]|retire LOOP RUN --node [--dry-run|--expect-digest HEX] or retire LOOP --generations [--dry-run]",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: (!generations).then(|| rest[0].clone()),
            generations,
            dry_run,
            confirm_uncertain,
            confirm_missing_lease,
            confirm_missing_harvest_fields,
            rewrite: false,
            node,
            expect_digest,
        })
    }
}

fn take_confirmation(words: &mut Vec<String>, flag: &str) -> Result<bool, LaneError> {
    let count = words.iter().filter(|word| word.as_str() == flag).count();
    if count > 1 {
        return Err(LaneError::input(
            "retire-usage",
            format!("{flag} is repeated"),
        ));
    }
    words.retain(|word| word != flag);
    Ok(count == 1)
}

/// Retire one run or unreferenced generations through the loop's owner locks.
///
/// # Errors
///
/// Refuses a live or uncertain presence and any changed protected input.
pub fn run(owner_home: &Path, request: &RetireRequest) -> Result<Value, LaneError> {
    let begun = Instant::now();
    run_with(owner_home, request, None, node::DEADLINE).map_err(|mut error| {
        use std::fmt::Write as _;
        if error.kind == "harvest-record" && error.detail == "collection shape differs" {
            let _written = write!(
                error.detail,
                "; preview retire rewrite {} {} --dry-run",
                request.loop_name,
                request.run.as_deref().unwrap_or_default()
            );
        }
        if error.kind == "harvest-record"
            && ["agreement field is absent", "collection field is absent"]
                .contains(&error.detail.as_str())
        {
            let mut preview = request.clone();
            preview.confirm_missing_harvest_fields = true;
            preview.dry_run = true;
            preview.expect_digest = None;
            match run_with(owner_home, &preview, None, node::DEADLINE) {
                Ok(_) => {
                    let _written = write!(
                        error.detail,
                        "; preview retire {} {}{}{} --confirm-missing-harvest-fields --dry-run",
                        request.loop_name,
                        request.run.as_deref().unwrap_or_default(),
                        if request.confirm_missing_lease {
                            " --confirm-missing-lease"
                        } else {
                            ""
                        },
                        if request.confirm_uncertain {
                            " --confirm-uncertain"
                        } else {
                            ""
                        }
                    );
                }
                Err(blocked) => {
                    let _written = write!(
                        error.detail,
                        "; confirmation preview refused: {}",
                        blocked.line()
                    );
                }
            }
        }
        let _written = write!(
            error.detail,
            "; wall_seconds={:.6}",
            begun.elapsed().as_secs_f64()
        );
        error
    })
}

#[allow(clippy::too_many_lines)]
fn run_with(
    owner_home: &Path,
    request: &RetireRequest,
    runner: Option<&dyn node::Runner>,
    budget: Duration,
) -> Result<Value, LaneError> {
    let begun = Instant::now();
    if request.generations {
        return retire_generations(owner_home, request, begun);
    }
    let loop_dir = owner_home.join(".config/loops").join(&request.loop_name);
    let _configuration = crate::install::lock_loop_config(&loop_dir, true)?;
    let settings = Settings::read_beneath(&loop_dir.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, &request.loop_name)?;
    let root = settings.runs_root.as_deref().ok_or_else(|| {
        LaneError::input("retire-grant", "runs_root is absent from loop settings")
    })?;
    let owner = Uid::effective().as_raw();
    let runs_guard = lock_runs_root(root, true, owner)?;
    if request.rewrite {
        return rewrite::run(owner_home, root, request, begun);
    }
    if request.confirm_missing_lease || request.confirm_missing_harvest_fields {
        return absences::run(owner_home, root, request, runner, budget, begun, runs_guard);
    }
    let run = request
        .run
        .as_deref()
        .ok_or_else(|| LaneError::input("retire-usage", "run name is absent"))?;
    let _lease = lock_retirement_lease(root, run, owner, &request.loop_name)?;
    if request.node {
        drop(runs_guard);
        return node_record::complete(owner_home, root, request, runner, budget, begun);
    }
    let reservation = reservation_path(root, run);
    let record = read_reservation(&reservation)
        .map_err(retire_error)?
        .ok_or_else(|| {
            LaneError::input(
                "retire-record",
                format!("{} is absent", reservation.display()),
            )
        })?;
    validate_retirement_record(&record, request, run)?;
    let (base, count) = worker_range(owner_home, &request.loop_name)?;
    let uid = record["worker_uid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value >= base && *value < base + count)
        .ok_or_else(|| {
            LaneError::input("retire-uid", "worker UID is outside the loop allocation")
        })?;
    let driver = root.join(run);
    let home = owner_home
        .join(".cache/tmp")
        .join(format!("lane-{}-{run}", request.loop_name));
    if record["plan"]["driver_dir"] != driver.display().to_string()
        || record["plan"]["home"] != home.display().to_string()
    {
        return Err(LaneError::input(
            "retire-record",
            "recorded paths differ from this run",
        ));
    }
    let program = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("retire-record", "recorded container program is absent"))?;
    node_record::read(&record)?;
    let node_plan = node_record::plan_for_record(owner_home, &request.loop_name, run, &record)?;
    let pending = node_record::pending(&node_plan.value);
    refuse_pending_collection(&record)?;
    refuse_import_evidence(&record)?;
    let mailbox = lock_retirement_mailbox(root, run, owner, request.dry_run)?;
    let store = crate::requests::store::Store::open(owner_home, &request.loop_name, false)?;
    let requests_guard = store.retirement_guard(run, &*runs_guard, request.dry_run)?;
    let reconciled = super::reaping::retirement_reconciliation(&record, owner_home)?;
    let fresh_proof = proof::needed(&record).then_some(&reconciled["retirement_absence_proof"]);
    let mut result = retire_record_confirmed_with(
        owner_home,
        root,
        run,
        &home,
        &reconciled,
        fresh_proof,
        (reconciled != record).then_some(&record),
        request.dry_run,
        request.confirm_uncertain,
        Some(&pending),
        request.expect_digest.as_deref(),
        true,
        crate::container_helper::process_presence,
        || container_absent_for_run(Path::new(program), owner_home, &request.loop_name, run),
    )
    .map_err(retire_error)?;
    drop(mailbox);
    drop(requests_guard);
    drop(runs_guard);
    if !request.dry_run {
        let path = Path::new(
            result["record"]
                .as_str()
                .ok_or_else(|| LaneError::input("retire-record", "retired path absent"))?,
        );
        result["node_retirement"] = node_record::finish(path, &node_plan, runner, budget)?;
    }
    Ok(
        json!({"schema":1,"command":"retire","loop":request.loop_name,"run":run,"dry_run":request.dry_run,"preview_sha256":result["preview_sha256"],"worker_uid_released":if request.dry_run { Value::Null } else { json!(uid) },"retirement":result,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

fn validate_retirement_record(
    record: &Value,
    request: &RetireRequest,
    run: &str,
) -> Result<(), LaneError> {
    if record.get("retirement_absence_plan").is_some() {
        return Err(LaneError::input(
            "retire-absence",
            "resume with the recorded confirmation flags and --dry-run, then --expect-digest",
        ));
    }
    if record["loop"] != request.loop_name || record["run"] != run {
        return Err(LaneError::input(
            "retire-record",
            "reservation names another run",
        ));
    }
    Ok(())
}

fn retire_error(error: LaneError) -> LaneError {
    if ["uid-table", "launch-recover"].contains(&error.kind) {
        LaneError {
            status: error.status,
            kind: "retire-record",
            detail: error.detail,
        }
    } else {
        error
    }
}

pub(super) fn lock_retirement_lease(
    root: &Path,
    run: &str,
    owner: u32,
    loop_name: &str,
) -> Result<Flock<fs::File>, LaneError> {
    probe_retirement_lease(root, run, owner)?.ok_or_else(|| LaneError::input(
        "retire-lease", format!("preparation lease is absent; preview retire {loop_name} {run} --confirm-missing-lease --dry-run"),
    ))
}

pub(super) fn probe_retirement_lease(
    root: &Path,
    run: &str,
    owner: u32,
) -> Result<Option<Flock<fs::File>>, LaneError> {
    let parent = home::pin_parent(root, owner)?;
    let name = format!(".prepare-{run}.lock");
    let path = root.join(&name);
    let file = match openat2(
        &parent,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fs::File::from(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "retire-lease",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("retire-lease", error.to_string()))?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o600 {
        return Err(LaneError::input(
            "retire-lease",
            format!("{} is not an owner lease at mode 0600", path.display()),
        ));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map(Some)
        .map_err(|(_file, error)| {
            LaneError::input("retire-busy", format!("{}: {error}", path.display()))
        })
}

pub(super) fn lock_retirement_mailbox(
    root: &Path,
    run: &str,
    owner: u32,
    dry_run: bool,
) -> Result<Option<Flock<fs::File>>, LaneError> {
    if !dry_run {
        return lock_mailbox(root, run, owner).map(Some);
    }
    let parent = home::pin_parent(root, owner)?;
    let name = format!(".letter-{run}.lock");
    let path = root.join(&name);
    let file = match openat2(
        &parent,
        name.as_str(),
        OpenHow::new()
            .flags(OFlag::O_RDWR | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fs::File::from(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => {
            return Err(LaneError::input(
                "letter-lock",
                format!("{}: {error}", path.display()),
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| LaneError::input("letter-lock", error.to_string()))?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o600 {
        return Err(LaneError::input(
            "letter-lock",
            "mailbox lock has foreign owner or mode",
        ));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map(Some)
        .map_err(|(_file, error)| {
            LaneError::input(
                "retire-busy",
                format!("mailbox lock {}: {error}", path.display()),
            )
        })
}

pub(super) fn never_started_preparation(record: &Value) -> bool {
    record["phase"] == "preparing" && never_started_shape(record)
}

fn never_started_shape(record: &Value) -> bool {
    record["helper_spawn_state"] == "not-started"
        && [
            "driver_entry_pid",
            "driver_entry_start",
            "helper_pid",
            "helper_start",
            "helper_parent_pid",
            "helper_parent_start",
        ]
        .iter()
        .all(|key| record[*key].is_null())
        && ["driver_end", "helper_end"]
            .iter()
            .all(|key| record[*key].is_null() || record[*key] == json!({"state":"not-started"}))
}

#[allow(clippy::too_many_lines)]
pub(super) fn checked_presence(
    owner_home: &Path,
    record: &Value,
    confirmed_uncertain: bool,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Value, LaneError> {
    checked_presence_with_proof(owner_home, record, confirmed_uncertain, None, presence)
}

fn checked_presence_with_proof(
    owner_home: &Path,
    record: &Value,
    confirmed_uncertain: bool,
    fresh_proof: Option<&Value>,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
) -> Result<Value, LaneError> {
    checked_presence_with_observer(
        owner_home,
        record,
        confirmed_uncertain,
        fresh_proof,
        presence,
        || Ok(None),
    )
}

#[allow(clippy::too_many_lines)]
pub(super) fn checked_presence_with_observer(
    owner_home: &Path,
    record: &Value,
    confirmed_uncertain: bool,
    fresh_proof: Option<&Value>,
    mut presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    mut observer_absence: impl FnMut() -> Result<Option<Value>, LaneError>,
) -> Result<Value, LaneError> {
    if let Some(proof) = fresh_proof {
        proof::validate(proof)?;
    } else if !record["retirement_absence_proof"].is_null() {
        return Err(LaneError::input(
            "retire-uncertain",
            "saved absence proof requires a fresh retire measurement",
        ));
    }
    if (record["settlement_uncertain"] == true && !confirmed_uncertain)
        || (!record["settlement_uncertain"].is_null()
            && !record["settlement_uncertain"].is_boolean())
    {
        return Err(LaneError::input(
            "retire-uncertain",
            "settlement uncertainty is recorded",
        ));
    }
    let observer_state = record["observer_state"]
        .as_str()
        .ok_or_else(|| LaneError::input("retire-uncertain", "observer state is not recorded"))?;
    if !["not-started", "starting", "running", "failed", "ended"].contains(&observer_state) {
        return Err(LaneError::input(
            "retire-uncertain",
            "observer state is invalid",
        ));
    }
    let identities = [
        ("launcher", launcher_identity(record)?),
        ("driver", driver_identity(record)?),
        ("helper", helper_identity(record)?),
        ("observer", observer_identity(record)?),
    ];
    // A preparing reservation can establish non-spawn without inventing failed ends.
    // Launcher absence is measured first; the work scope, probes and container must also be absent.
    let unstarted_preparation = never_started_preparation(record)
        || (record["phase"] == "failed"
            && record["reconciliation"]["retirement"] == "never-started-preparation"
            && record["pre_driver_failure"].is_string()
            && record["pre_driver_failure"] == record["reconciliation"]["cause"]
            && record["driver_end"] == json!({"state":"not-started"})
            && record["helper_end"] == json!({"state":"not-started"})
            && never_started_shape(record));
    let mut checked = serde_json::Map::new();
    for (name, identity) in identities {
        if let Some((pid, start)) = identity {
            match presence(pid, start) {
                crate::container_helper::ProcessPresence::Absent => {
                    checked.insert(
                        name.into(),
                        json!({"pid":pid,"start":start,"presence":"absent"}),
                    );
                }
                crate::container_helper::ProcessPresence::Present => {
                    return Err(LaneError::input(
                        "retire-busy",
                        format!("{name} is still present"),
                    ));
                }
                crate::container_helper::ProcessPresence::Unknown => {
                    return Err(LaneError::input(
                        "retire-uncertain",
                        format!("{name} presence is unreadable"),
                    ));
                }
            }
        } else {
            let proved = fresh_proof.is_some()
                || match name {
                    "driver" => {
                        unstarted_preparation
                            || (record["pre_driver_failure"].is_string()
                                && record["driver_end"]["state"] == "not-started")
                    }
                    "helper" => {
                        if unstarted_preparation {
                            true
                        } else if record["pre_driver_failure"].is_string() {
                            if record["helper_spawn_state"] == "not-started"
                                && record["helper_end"]["state"] == "not-started"
                            {
                                true
                            } else if let Some((pid, start)) = helper_parent_identity(record)? {
                                match presence(pid, start) {
                                    crate::container_helper::ProcessPresence::Absent => true,
                                    crate::container_helper::ProcessPresence::Present => {
                                        return Err(LaneError::input(
                                            "retire-busy",
                                            "helper parent is still present",
                                        ));
                                    }
                                    crate::container_helper::ProcessPresence::Unknown => {
                                        return Err(LaneError::input(
                                            "retire-uncertain",
                                            "helper parent presence is unreadable",
                                        ));
                                    }
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    "observer" => absent_unrecorded_observer(
                        owner_home,
                        record,
                        observer_state,
                        unstarted_preparation,
                    )?,
                    _ => false,
                };
            if !proved {
                if name == "observer"
                    && let Some(evidence) = observer_absence()?
                {
                    checked.insert(
                        name.into(),
                        json!({"presence":"absence-proved-without-identity","evidence":evidence}),
                    );
                    continue;
                }
                return Err(LaneError::input(
                    "retire-uncertain",
                    format!("{name} has no recorded identity or absence proof"),
                ));
            }
            checked.insert(
                name.into(),
                json!({"presence":"absence-proved-without-identity"}),
            );
        }
    }
    if let Some((pid, start)) = helper_parent_identity(record)? {
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Absent => {
                checked.insert(
                    "helper_parent".into(),
                    json!({"pid":pid,"start":start,"presence":"absent"}),
                );
            }
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "retire-busy",
                    "helper parent is still present",
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "retire-uncertain",
                    "helper parent presence is unreadable",
                ));
            }
        }
    } else {
        let evidence = helper_parent_absence_evidence(record)
            .or_else(|| fresh_proof.is_some().then_some("measured-absence"))
            .ok_or_else(|| {
                LaneError::input(
                    "retire-uncertain",
                    "helper parent has no recorded identity or completed end",
                )
            })?;
        checked.insert(
            "helper_parent".into(),
            json!({"presence":"absence-proved-without-identity","evidence":evidence}),
        );
    }
    let starts = match &record["probe_starts"] {
        Value::Null => Vec::new(),
        Value::Array(items) => items.clone(),
        _ => {
            return Err(LaneError::input(
                "retire-uncertain",
                "probe journal is invalid",
            ));
        }
    };
    let mut probes = Vec::new();
    for entry in starts {
        let phase = entry["phase"].as_str().unwrap_or("unknown");
        let role = entry["role"].as_str().unwrap_or("unknown");
        let (Some(pid), Some(start)) = (
            entry["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok()),
            entry["start_tick"].as_u64(),
        ) else {
            return Err(LaneError::input(
                "retire-uncertain",
                format!("{phase}/{role} probe process identity is absent"),
            ));
        };
        match presence(pid, start) {
            crate::container_helper::ProcessPresence::Present => {
                return Err(LaneError::input(
                    "retire-busy",
                    format!("{phase}/{role} probe process is present"),
                ));
            }
            crate::container_helper::ProcessPresence::Unknown => {
                return Err(LaneError::input(
                    "retire-uncertain",
                    format!("{phase}/{role} probe process absence is uncertain"),
                ));
            }
            crate::container_helper::ProcessPresence::Absent => {
                probes.push(
                    json!({"phase":phase,"role":role,"pid":pid,"start":start,"presence":"absent"}),
                );
            }
        }
    }
    checked.insert("probe_starts".into(), json!(probes));
    if unstarted_preparation && fresh_proof.is_none() {
        checked.insert(
            "run_scope".into(),
            super::reaping::retirement_scope(record)?,
        );
    }
    Ok(Value::Object(checked))
}

fn absent_unrecorded_observer(
    owner_home: &Path,
    record: &Value,
    state: &str,
    unstarted_preparation: bool,
) -> Result<bool, LaneError> {
    if unstarted_preparation
        && state == "not-started"
        && (record["observer_end"].is_null()
            || record["observer_end"] == json!({"state":"not-started"}))
    {
        let Some(path) = recorded_observer_socket(record)? else {
            return Ok(record["plan"]["vendor_mode"].is_null());
        };
        let slot = crate::SocketSlot::pinned(&path, Uid::effective().as_raw())?;
        return slot
            .metadata()
            .map(|metadata| metadata.is_none())
            .map_err(|error| {
                LaneError::input("retire-uncertain", format!("{}: {error}", path.display()))
            });
    }
    if state == "not-started"
        && record["plan"]["vendor_mode"].is_null()
        && record["observer_end"]["state"] == "not-started"
    {
        if ["failed", "settled"].contains(&record["phase"].as_str().unwrap_or_default()) {
            return Ok(true);
        }
        return match super::repin_door::settled_boundary(record, |record| {
            super::driver_report::read(owner_home, record)
        }) {
            Ok((_, _, boundary)) => Ok(boundary == "interrupted-settlement"),
            Err(error) if error.kind == "repin-door-state" => Ok(false),
            Err(error) => Err(retirement_report_error(error)),
        };
    }
    if state != "failed"
        || !record["observer_end"]["status"].is_string()
        || !record["observer_end"]["stop"].is_null()
        || !["removed", "absent"].contains(
            &record["observer_end"]["socket"]["state"]
                .as_str()
                .unwrap_or_default(),
        )
    {
        return Ok(false);
    }
    let Some(path) = recorded_observer_socket(record)? else {
        return Ok(false);
    };
    let slot = crate::SocketSlot::pinned(&path, Uid::effective().as_raw())?;
    Ok(slot
        .metadata()
        .map_err(|error| {
            LaneError::input("retire-uncertain", format!("{}: {error}", path.display()))
        })?
        .is_none())
}

fn retirement_report_error(mut error: LaneError) -> LaneError {
    error.kind = match error.kind {
        "repin-door-uncertain" => "retire-uncertain",
        "repin-door-live" => "retire-busy",
        other => other,
    };
    error
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[cfg(test)]
pub(crate) fn retire_record_with(
    root: &Path,
    run: &str,
    worker_home: &Path,
    saved: &Value,
    dry_run: bool,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    container_absent: impl FnMut() -> Result<bool, LaneError>,
) -> Result<Value, LaneError> {
    let _reader = super::driver_report::FixtureReader::enter();
    retire_record_confirmed_with(
        root,
        root,
        run,
        worker_home,
        saved,
        None,
        None,
        dry_run,
        false,
        None,
        None,
        false,
        presence,
        container_absent,
    )
}

fn confirmed_uncertainty(saved: &Value, confirm: bool) -> Result<bool, LaneError> {
    let journal = &saved["current_retirement"];
    let retry = ["retiring", "retired"].contains(&saved["phase"].as_str().unwrap_or_default())
        && journal["prior_phase"] == "failed"
        && journal["uncertain"] == true
        && journal["confirmation"]["flag"] == "--confirm-uncertain"
        && journal["confirmation"]["owner_uid"] == Uid::effective().as_raw()
        && journal["reaping"] == saved["reaping"]
        && journal["reaping_recovery"] == saved["reaping_recovery"];
    if saved["settlement_uncertain"] == true && ((confirm && saved["phase"] == "failed") || retry) {
        return Ok(true);
    }
    if confirm {
        return Err(LaneError::input(
            "retire-uncertain",
            "confirmation requires a failed run with recorded boolean settlement uncertainty",
        ));
    }
    Ok(false)
}

fn validate_retirement_paths(record: &Value) -> Result<(), LaneError> {
    let journal = &record["current_retirement"];
    let root = record["plan"]["driver_dir"]
        .as_str()
        .and_then(|path| Path::new(path).parent())
        .ok_or_else(|| LaneError::input("retire-record", "recorded runs root is absent"))?;
    let target = journal["reservation_path"]["target"]
        .as_str()
        .ok_or_else(|| LaneError::input("retire-record", "reservation target is absent"))?;
    if Path::new(target).parent() != Some(root) {
        return Err(LaneError::input(
            "retire-record",
            "reservation target is outside runs root",
        ));
    }
    let paths = journal["planned_paths"]
        .as_array()
        .ok_or_else(|| LaneError::input("retire-record", "planned retirement paths are absent"))?;
    for pair in paths
        .iter()
        .chain(std::iter::once(&journal["reservation_path"]))
    {
        let source = Path::new(
            pair["source"]
                .as_str()
                .ok_or_else(|| LaneError::input("retire-record", "retirement source is absent"))?,
        );
        let target = Path::new(
            pair["target"]
                .as_str()
                .ok_or_else(|| LaneError::input("retire-record", "retirement target is absent"))?,
        );
        if source.parent() != target.parent()
            || !target
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".retired-"))
        {
            return Err(LaneError::input(
                "retire-record",
                "retirement target is outside its source directory",
            ));
        }
        let from = absences::metadata(source)?;
        let to = absences::metadata(target)?;
        if from["present"] == to["present"] {
            return Err(LaneError::input(
                "retire-record",
                format!(
                    "{} and {} have an incomplete retirement",
                    source.display(),
                    target.display()
                ),
            ));
        }
    }
    if let Some(path) = journal["observer_socket"].as_str() {
        let slot = crate::SocketSlot::pinned(Path::new(path), Uid::effective().as_raw())?;
        if let Some(meta) = slot
            .metadata()
            .map_err(|error| LaneError::input("retire-socket", error.to_string()))?
        {
            if journal["observer_socket_present"] != true {
                return Err(LaneError::input(
                    "retire-record",
                    format!("{path} appeared after the retirement record"),
                ));
            }
            if meta.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || meta.st_uid != Uid::effective().as_raw()
            {
                return Err(LaneError::input(
                    "retire-record",
                    format!("{path} is not the old owner socket"),
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn retire_record_confirmed_with(
    owner_home: &Path,
    root: &Path,
    run: &str,
    worker_home: &Path,
    saved: &Value,
    fresh_proof: Option<&Value>,
    before_reconciliation: Option<&Value>,
    dry_run: bool,
    confirm_uncertain: bool,
    node_retirement: Option<&Value>,
    expect_digest: Option<&str>,
    mailbox_held: bool,
    presence: impl FnMut(u32, u64) -> crate::container_helper::ProcessPresence,
    mut container_absent: impl FnMut() -> Result<bool, LaneError>,
) -> Result<Value, LaneError> {
    let _mailbox = if mailbox_held {
        None
    } else {
        lock_retirement_mailbox(root, run, Uid::effective().as_raw(), dry_run)?
    };
    refuse_pending_collection(saved)?;
    refuse_import_evidence(saved)?;
    if ![
        "preparing",
        "started",
        "settled",
        "failed",
        "retiring",
        "retired",
    ]
    .contains(&saved["phase"].as_str().unwrap_or_default())
    {
        return Err(LaneError::input(
            "retire-record",
            "reservation phase is not retireable",
        ));
    }
    let uncertain = confirmed_uncertainty(saved, confirm_uncertain)?;
    let mut presence_record = saved.clone();
    if ["retiring", "retired"].contains(&saved["phase"].as_str().unwrap_or_default()) {
        presence_record["phase"] = saved["current_retirement"]["prior_phase"].clone();
    }
    let identities = checked_presence_with_proof(
        owner_home,
        &presence_record,
        uncertain,
        fresh_proof,
        presence,
    )?;
    if !container_absent().map_err(|error| LaneError::input("retire-uncertain", error.line()))? {
        return Err(LaneError::input(
            "retire-busy",
            "labelled container is still present",
        ));
    }
    let reservation = reservation_path(root, run);
    let driver = root.join(run);
    let mut record = saved.clone();
    if record["phase"] != "retiring" && record["phase"] != "retired" {
        let identity = protected_identity_dir(&driver)?;
        let observed = root.join(format!(".observed-{run}.txt"));
        let helper = crate::container_helper::socket_path(&driver)?;
        let control = crate::container_helper::control_socket_path(&driver)?;
        let mut sources = vec![
            driver.clone(),
            worker_home.to_path_buf(),
            identity,
            observed,
            helper,
            control,
        ];
        for attempt in 1..=4 {
            sources.push(protected_identifier_path(&driver, attempt)?);
        }
        let held_reports: OwnedFd = fs::File::open(root)
            .map_err(|error| LaneError::input("retire-record", error.to_string()))?
            .into();
        let owner = Uid::effective().as_raw();
        if super::report::present(&held_reports, run, None, owner)? {
            sources.push(root.join(super::report::name(run, None)?));
        }
        let mut report_steps = BTreeSet::new();
        for round in record["rounds"].as_array().into_iter().flatten().skip(1) {
            let step = round["step"]
                .as_str()
                .ok_or_else(|| LaneError::input("retire-record", "recorded round has no step"))?;
            super::letters::valid_step(step)?;
            if report_steps.insert(step)
                && super::report::present(&held_reports, run, Some(step), owner)?
            {
                sources.push(root.join(super::report::name(run, Some(step))?));
            }
        }
        let mut paths = Vec::new();
        let first_report_index = 10;
        for (index, source) in sources.iter().enumerate() {
            let retirement_index = if index < first_report_index {
                index
            } else {
                21 + index - first_report_index
            };
            if let Some(pair) = planned_retirement(source, run, retirement_index)? {
                paths.push(pair);
            }
        }
        let record_pair = planned_retirement(&reservation, run, 20)?.ok_or_else(|| {
            LaneError::input("retire-record", "reservation disappeared before retirement")
        })?;
        let observer_socket = recorded_observer_socket(&record)?;
        let observer_present = if let Some(path) = observer_socket.as_ref() {
            crate::SocketSlot::pinned(path, Uid::effective().as_raw())?
                .metadata()
                .map_err(|error| LaneError::input("retire-socket", error.to_string()))?
                .is_some()
        } else {
            false
        };
        record["current_retirement"] = json!({"state":"retiring-run","prior_phase":saved["phase"],"worker_uid":saved["worker_uid"],"planned_paths":paths,"reservation_path":record_pair,"observer_socket":observer_socket,"observer_socket_present":observer_present,"identities":identities,"container_presence":"absent-by-label"});
        if let Some(proof) = fresh_proof {
            record["current_retirement"]["settlement"] = proof.clone();
        }
        if let Some(accepted) = saved["current_retirement"].get("accepted_absences") {
            record["current_retirement"]["accepted_absences"] = accepted.clone();
        }
        if uncertain {
            record["current_retirement"]["uncertain"] = json!(true);
            record["current_retirement"]["confirmation"] =
                json!({"flag":"--confirm-uncertain","owner_uid":Uid::effective().as_raw()});
            record["current_retirement"]["reaping"] = saved["reaping"].clone();
            record["current_retirement"]["reaping_recovery"] = saved["reaping_recovery"].clone();
        }
        record["phase"] = json!("retiring");
    } else if record["current_retirement"]["state"] != "retiring-run"
        && record["current_retirement"]["state"] != "retired-run"
    {
        return Err(LaneError::input(
            "retire-record",
            "retirement journal is invalid",
        ));
    }
    if !record
        .as_object()
        .is_some_and(|object| object.contains_key("node_retirement"))
        && let Some(node) = node_retirement
    {
        record["node_retirement"] = node.clone();
    }
    let digest = node_record::preview(
        saved,
        &record["current_retirement"],
        node_retirement.map(|node| &node["plan"]),
        false,
    );
    validate_retirement_paths(&record)?;
    let mut current = if mailbox_held
        && dry_run
        && before_reconciliation.is_none()
        && saved["current_retirement"]["accepted_absences"].is_object()
    {
        saved.clone()
    } else {
        read_reservation(&reservation)?.ok_or_else(|| {
            LaneError::input(
                "retire-record",
                "reservation vanished before phase transition",
            )
        })?
    };
    if let Some(before) = before_reconciliation {
        if &current != before {
            return Err(LaneError::input(
                "retire-digest",
                "reservation changed before named reconciliation",
            ));
        }
        // Keep the measured pre-write custody journal: publishing replaces the
        // reservation inode, but that replacement is this named transition only.
        if dry_run || fresh_proof.is_some() {
            current = saved.clone();
        } else {
            publish_reservation(&reservation, saved)?;
            current = read_reservation(&reservation)?.ok_or_else(|| {
                LaneError::input("retire-record", "reconciled reservation vanished")
            })?;
        }
    }
    refuse_pending_collection(&current)?;
    refuse_import_evidence(&current)?;
    node_record::check_digest(
        expect_digest,
        &node_record::preview(
            &current,
            &record["current_retirement"],
            node_retirement.map(|node| &node["plan"]),
            false,
        ),
    )?;
    if current["phase"] != saved["phase"]
        || current["loop"] != saved["loop"]
        || current["run"] != saved["run"]
        || current["plan"] != saved["plan"]
        || current["worker_uid"] != saved["worker_uid"]
        || current["settlement_uncertain"] != saved["settlement_uncertain"]
        || current["reaping"] != saved["reaping"]
        || current["reaping_recovery"] != saved["reaping_recovery"]
        || current.get("node_retirement") != saved.get("node_retirement")
    {
        return Err(LaneError::input(
            "retire-record",
            "reservation identity or phase changed before retirement",
        ));
    }
    if dry_run {
        return Ok(
            json!({"state":"would-retire","journal":record["current_retirement"],"identities":identities,"container_presence":"absent-by-label","worker_uid":saved["worker_uid"],"node_retirement":record["node_retirement"],"preview_sha256":digest}),
        );
    }
    if saved["phase"] != "retiring" && saved["phase"] != "retired" {
        current["current_retirement"] = record["current_retirement"].clone();
        if let Some(node) = record.get("node_retirement") {
            current["node_retirement"] = node.clone();
        }
        current["phase"] = json!("retiring");
        record = current;
        publish_reservation(&reservation, &record)?;
    } else {
        record = current;
        if record.get("node_retirement").is_none()
            && let Some(node) = node_retirement
        {
            record["node_retirement"] = node.clone();
            publish_reservation(&reservation, &record)?;
        }
    }
    if record["current_retirement"]["observer_socket_disposition"].is_null() {
        let socket = remove_retired_observer_socket(&record)?;
        record["current_retirement"]["observer_socket_disposition"] = socket;
        publish_reservation(&reservation, &record)?;
    }
    let moved = apply_retirement_paths(&record)?;
    record["current_retirement"]["retired_paths"] = json!(moved);
    record["current_retirement"]["state"] = json!("retired-run");
    record["phase"] = json!("retired");
    publish_reservation(&reservation, &record)?;
    let target = Path::new(
        record["current_retirement"]["reservation_path"]["target"]
            .as_str()
            .ok_or_else(|| LaneError::input("retire-record", "reservation target is absent"))?,
    );
    if target.parent() != Some(root)
        || !target
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(".retired-"))
    {
        return Err(LaneError::input(
            "retire-record",
            "reservation target is outside runs root",
        ));
    }
    fs::rename(&reservation, target).map_err(|error| {
        LaneError::operation(
            "retire-record",
            format!("{}: {error}", reservation.display()),
        )
    })?;
    fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| LaneError::operation("retire-record", error.to_string()))?;
    Ok(
        json!({"state":"retired","journal":record["current_retirement"],"record":target,"worker_uid":record["worker_uid"],"preview_sha256":digest}),
    )
}

pub(super) fn refuse_pending_collection(record: &Value) -> Result<(), LaneError> {
    let (_, collection) = super::harvest::harvest_fields(record)?;
    if collection.is_some_and(|collection| collection["state"] == "removing") {
        return Err(LaneError::input(
            "retire-collection-pending",
            "harvest removal is pending recovery",
        ));
    }
    Ok(())
}

pub(super) fn refuse_import_evidence(record: &Value) -> Result<(), LaneError> {
    let marks = super::imports::validated(record)?;
    if let Some(mark) = marks.first() {
        let object = mark["object"]
            .as_str()
            .ok_or_else(|| LaneError::input("import-record", "marked object is absent"))?;
        return Err(LaneError::input(
            "retire-import-evidence",
            format!(
                "checkpoint {} carries marked object {}",
                mark["checkpoint_index"], object
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn retire_generations(
    owner_home: &Path,
    request: &RetireRequest,
    begun: Instant,
) -> Result<Value, LaneError> {
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| LaneError::input("registry-row", error.message()))?;
    let mut rows = registry.rows(owner_home);
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    let mut guards = Vec::new();
    let mut protected = std::collections::BTreeSet::new();
    let mut current_template = None;
    for row in &rows {
        let directory = owner_home.join(".config/loops").join(&row.name);
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(LaneError::input(
                    "retire-generations",
                    format!("{}: {error}", directory.display()),
                ));
            }
            Ok(_) => {}
        }
        guards.push(crate::install::lock_loop_config(
            &directory,
            request.dry_run,
        )?);
        let settings = Settings::read_beneath(&directory.join("workers.toml"), owner_home)?;
        settings.validate_grant(owner_home, &row.name)?;
        if let Some(digest) = settings.image_digest.as_deref() {
            protected.insert(digest.to_owned());
        }
        if let Some(template) = settings.template_dir.as_ref() {
            if row.name == request.loop_name {
                current_template = Some(template.clone());
            }
            let manifest = template.join("manifest");
            let bytes = fs::read(&manifest).map_err(|error| {
                LaneError::input(
                    "retire-manifest",
                    format!("{}: {error}", manifest.display()),
                )
            })?;
            if bytes.len() > 65_536 {
                return Err(LaneError::input(
                    "retire-manifest",
                    format!("{} is oversized", manifest.display()),
                ));
            }
            let record: Value = serde_json::from_slice(&bytes)
                .map_err(|error| LaneError::input("retire-manifest", error.to_string()))?;
            let digest = record["image_digest"].as_str().ok_or_else(|| {
                LaneError::input("retire-manifest", "installed manifest has no image digest")
            })?;
            protected.insert(digest.to_owned());
        }
        if let Some(generation) =
            crate::install::read_generation(&directory.join("install-generation.json"))?
        {
            let digest = generation["image_digest"].as_str().ok_or_else(|| {
                LaneError::input(
                    "retire-generations",
                    "installed generation has no image digest",
                )
            })?;
            protected.insert(digest.to_owned());
        }
        if let Some(root) = settings.runs_root.as_deref() {
            let _runs = lock_runs_root(root, false, Uid::effective().as_raw())?;
            for entry in fs::read_dir(root)
                .map_err(|error| LaneError::input("retire-generations", error.to_string()))?
            {
                let entry = entry
                    .map_err(|error| LaneError::input("retire-generations", error.to_string()))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".reservation-") && name.ends_with(".json") {
                    let reservation = read_reservation(&entry.path())?.ok_or_else(|| {
                        LaneError::input("retire-generations", "reservation vanished during census")
                    })?;
                    let digest = reservation["plan"]["image_digest"]
                        .as_str()
                        .ok_or_else(|| {
                            LaneError::input(
                                "retire-generations",
                                format!("{} has no image digest", entry.path().display()),
                            )
                        })?;
                    protected.insert(digest.to_owned());
                }
            }
        }
    }
    // Keep every loop lock alive through the inventory and mutations.
    let _held_lock_count = guards.len();
    let templates = template_retirement_candidates(
        owner_home,
        &request.loop_name,
        &protected,
        current_template.as_deref(),
    )?;
    let podman = Path::new("/usr/bin/podman");
    crate::pinned::owner_executable(podman, Uid::effective().as_raw())?;
    let environment = build::podman_environment(owner_home)?;
    let inventory = build::run_checked(
        podman,
        vec![
            "images".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.ID}} {{.Repository}}:{{.Tag}}".into(),
        ],
        &environment,
        owner_home,
        30,
        "retire-images",
    )?;
    let images = image_retirement_candidates(&inventory, &protected)?;
    let candidates = json!({"templates":templates,"images":images});
    if request.dry_run {
        return Ok(
            json!({"schema":1,"command":"retire","loop":request.loop_name,"generations":true,"dry_run":true,"candidates":candidates,"changed":false,"wall_seconds":begun.elapsed().as_secs_f64()}),
        );
    }
    let journal = json!({"current_retirement":{"planned_paths":templates}});
    let moved = apply_retirement_paths(&journal).map_err(retire_error)?;
    let changed = !moved.is_empty();
    Ok(
        json!({"schema":1,"command":"retire","loop":request.loop_name,"generations":true,"dry_run":false,"candidates":candidates,"retired_templates":moved,"retired_images":[],"changed":changed,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

fn template_retirement_candidates(
    owner_home: &Path,
    loop_name: &str,
    protected: &std::collections::BTreeSet<String>,
    current_template: Option<&Path>,
) -> Result<Vec<Value>, LaneError> {
    let mut templates = Vec::new();
    for vendor in [build::payload::CODEX, build::payload::CLAUDE] {
        let template_root = owner_home
            .join(".var/loops")
            .join(loop_name)
            .join("runner-templates")
            .join(vendor.name);
        if !template_root.exists() {
            continue;
        }
        let _template_parent = home::pin_parent(&template_root, Uid::effective().as_raw())?;
        let template_entries = match fs::read_dir(&template_root) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(LaneError::input("retire-generations", error.to_string())),
        };
        for entry in template_entries.into_iter().flatten() {
            let entry =
                entry.map_err(|error| LaneError::input("retire-generations", error.to_string()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                continue;
            }
            let digest = format!("sha256:{name}");
            if protected.contains(&digest) || current_template == Some(entry.path().as_path()) {
                continue;
            }
            let manifest = entry.path().join("manifest");
            let bytes = fs::read(&manifest).map_err(|error| {
                LaneError::input(
                    "retire-manifest",
                    format!("{}: {error}", manifest.display()),
                )
            })?;
            if bytes.len() > 65_536 {
                return Err(LaneError::input(
                    "retire-manifest",
                    format!("{} is oversized", manifest.display()),
                ));
            }
            let record: Value = serde_json::from_slice(&bytes)
                .map_err(|error| LaneError::input("retire-manifest", error.to_string()))?;
            if record["image_digest"] != digest {
                return Err(LaneError::input(
                    "retire-manifest",
                    format!("{} names another image", manifest.display()),
                ));
            }
            if let Some(pair) = planned_retirement(
                &entry.path(),
                &format!("generation-{loop_name}"),
                templates.len(),
            )? {
                templates.push(pair);
            }
        }
    }
    Ok(templates)
}

fn image_retirement_candidates(
    inventory: &str,
    protected: &std::collections::BTreeSet<String>,
) -> Result<Vec<Value>, LaneError> {
    let mut candidates = Vec::new();
    for line in inventory.lines() {
        let mut words = line.split_whitespace();
        let (Some(digest), Some(tag), None) = (words.next(), words.next(), words.next()) else {
            return Err(LaneError::input(
                "retire-images",
                "image inventory line is malformed",
            ));
        };
        if ![build::payload::CODEX, build::payload::CLAUDE]
            .iter()
            .any(|vendor| tag.starts_with(&format!("localhost/superloop-lane-{}:", vendor.name)))
        {
            continue;
        }
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(LaneError::input(
                "retire-images",
                "image ID is not a sha256 digest",
            ));
        };
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(LaneError::input(
                "retire-images",
                "image ID has invalid hex",
            ));
        }
        if !protected.contains(digest) {
            candidates.push(json!({"image_digest":digest,"tag":tag,"remove_command":{"program":"/usr/bin/podman","argv":["rmi",tag]}}));
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    /// ´test:unit:retire-observer-branch-reads-report-and-keeps-retire-refusals´
    #[test]
    fn retire_observer_branch_reads_report_and_keeps_retire_refusals() {
        let directory = tempfile::tempdir().expect("report directory");
        let mut record = crate::launch::repin_door::tests::captured_record(false);
        record["driver_entry_pid"] = json!(u32::MAX);
        record["driver_entry_start"] = json!(1);
        record["rounds"][0]["driver_dir"] = json!(directory.path());
        let step = record["active_round"].as_str().expect("step");
        let report = directory.path().join("run-report.txt");
        fs::write(
            &report,
            format!(
                "RUN-REPORT lane={step} exit=1 verdict=FAILED dir={}\n",
                directory.path().display()
            ),
        )
        .expect("report");
        let _reader = crate::launch::driver_report::FixtureReader::enter();
        assert!(
            absent_unrecorded_observer(directory.path(), &record, "not-started", false)
                .expect("report proof")
        );
        fs::write(&report, [0xff]).expect("unreadable report text");
        assert_eq!(
            absent_unrecorded_observer(directory.path(), &record, "not-started", false)
                .expect_err("uncertain report")
                .kind,
            "retire-uncertain"
        );
        for (before, after) in [
            ("repin-door-uncertain", "retire-uncertain"),
            ("repin-door-live", "retire-busy"),
            ("driver-report-private", "driver-report-private"),
        ] {
            let error = retirement_report_error(LaneError::input(before, "retained detail"));
            assert_eq!(
                (error.kind, error.detail.as_str()),
                (after, "retained detail")
            );
        }
    }

    use super::*;

    /// ´test:unit:retire-refuses-marked-preserved-import-evidence´
    #[test]
    fn retire_refuses_marked_preserved_import_evidence() {
        let object = "802da01e".repeat(5);
        let checkpoint = json!({"index":1,"instant_unix_ns":1,"round_after":"a","files":[],"bares":[{"name":"tools","declared":true,"seed":null,"lane_ref":"present","object":object}]});
        let record = json!({"imports":[{"checkpoint_index":1,"repo":"tools","object":object,"instant_unix_ns":2}],"checkpoints":[checkpoint]});
        let error = refuse_import_evidence(&record).expect_err("marked import blocks retirement");
        assert_eq!(error.kind, "retire-import-evidence");
        assert_eq!(
            error.line(),
            format!("retire-import-evidence: checkpoint 1 carries marked object {object}")
        );
        assert_eq!(error.status, 2);
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Value) {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture mode");
        let root = fixture.path().join("runs");
        fs::create_dir(&root).expect("runs root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver directory");
        let home = fixture.path().join("home-R");
        fs::create_dir(&home).expect("worker home");
        let identity = protected_identity_dir(&driver).expect("identity path");
        fs::create_dir(&identity).expect("protected identity");
        let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":home,"driver_dir":driver,"runtime_argv":["/usr/bin/podman"]},"launcher_pid":321,"launcher_start":88,"helper_pid":322,"helper_start":89,"helper_parent_pid":325,"helper_parent_start":92,"driver_entry_pid":323,"driver_entry_start":90,"observer_pid":324,"observer_start":91,"observer_state":"running"});
        publish_reservation(&reservation_path(&root, "R"), &record).expect("reservation");
        (fixture, root, home, record)
    }

    /// ´test:unit:retire-refuses-pending-collection-before-moving-paths´
    #[test]
    fn retire_refuses_pending_collection_before_moving_paths() {
        let (_fixture, root, home, mut record) = fixture();
        record["harvest_agreement"] = json!({"checkpoint_index":1,"preserved_object":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","gate_object":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instant_unix_ns":1});
        record["collection"] = json!({"checkpoint_index":1,"state":"removing","instant_unix_ns":2,"planned":["."],"writable_collected_first":null,"remaining":null,"refusal":null,"component":null,"token":"a".repeat(32),"parent_identity":{"device":1,"inode":2},"home_identity":{"device":1,"inode":3}});
        let refusal = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            true,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect_err("pending collection");
        assert_eq!(refusal.kind, "retire-collection-pending");
        assert!(home.exists());
    }

    pub(super) fn public_fixture() -> (tempfile::TempDir, PathBuf, RetireRequest) {
        // Public path checks require a sticky, root-owned ancestor above the fixture owner.
        let fixture = tempfile::Builder::new()
            .tempdir_in("/tmp")
            .expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("loop config");
        for path in [
            home.join(".config"),
            home.join(".config/loops"),
            config.clone(),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("config mode");
        }
        let root = home.join("runs");
        fs::create_dir(&root).expect("runs root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("runs mode");
        let registry = home.join(".config/loops/registry.toml");
        fs::write(&registry, format!("namespace = \"org.superloop-tools.loophome.registry\"\nversion = [1, 0, 0]\nloops = [{{ name = \"alpha\", uid = 41001, launch = \"src\", runs_root = \"{}\" }}]\n", root.display())).expect("registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).expect("registry mode");
        let allocations = home.join(".config/loops/allocations.toml");
        fs::write(&allocations, "[alpha]\nuids = { base = 3000, count = 2 }\n")
            .expect("allocations");
        fs::set_permissions(&allocations, fs::Permissions::from_mode(0o600))
            .expect("allocation mode");
        let settings = config.join("workers.toml");
        fs::write(&settings, format!("runs_root = \"{}\"\nentry_bin = \"/usr/bin/true\"\ndriver_argv = [\"/usr/bin/true\"]\nimage_digest = \"sha256:{}\"\ntemplate_dir = \"{}\"\nsocket_dir = \"{}\"\nresources = {{ memory_bytes = 2147483648, pids_max = 128, cpu_shares = 512 }}\n", root.display(), "a".repeat(64), home.join("template").display(), home.join("sockets").display())).expect("settings");
        fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).expect("settings mode");
        let request = RetireRequest {
            loop_name: "alpha".into(),
            run: Some("R".into()),
            generations: false,
            dry_run: true,
            confirm_uncertain: false,
            confirm_missing_lease: false,
            confirm_missing_harvest_fields: false,
            rewrite: false,
            node: false,
            expect_digest: None,
        };
        (fixture, root, request)
    }

    /// ´test:unit:ordinary-retirement-admits-measured-never-started-preparation´
    #[test]
    fn ordinary_retirement_admits_measured_never_started_preparation() {
        let (fixture, root, mut request) = public_fixture();
        let runtime = fixture.path().join("container-fixture");
        crate::fixture_exec::write_executable(
            &runtime,
            b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nexit 0\n",
        )
        .expect("absent container");
        let mut record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},"launcher_pid":u32::MAX,"launcher_start":1,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[]});
        let scope = super::super::reaping::RetirementScopeFixture::new(&mut record);
        let path = reservation_path(&root, "R");
        publish_reservation(&path, &record).expect("current preparation");
        drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("existing lease"));
        assert!(!request.confirm_missing_lease);
        assert!(!request.confirm_missing_harvest_fields);
        assert!(!request.confirm_uncertain);
        let preview = run(fixture.path(), &request).expect("ordinary preparation preview");
        assert_eq!(preview["retirement"]["state"], "would-retire");
        assert!(preview["worker_uid_released"].is_null());
        assert_eq!(
            read_reservation(&path).expect("reader").expect("unchanged"),
            record
        );
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        fs::write(scope.path.join("cgroup.events"), "populated 1\n").expect("new private work");
        assert_eq!(
            run(fixture.path(), &request)
                .expect_err("apply remeasures scope")
                .kind,
            "retire-busy"
        );
        assert!(path.exists());
        fs::write(scope.path.join("cgroup.events"), "populated 0\n").expect("work ended");
        fs::remove_dir_all(&scope.path).expect("scope collected after preview");
        assert_eq!(
            run(fixture.path(), &request)
                .expect_err("changed scope measurement")
                .kind,
            "retire-digest"
        );
        request.dry_run = true;
        request.expect_digest = None;
        let preview = run(fixture.path(), &request).expect("preview named failed record");
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let done = run(fixture.path(), &request).expect("ordinary preparation retirement");
        assert_eq!(done["retirement"]["state"], "retired");
        assert_eq!(done["worker_uid_released"], 3000);
        let archive = Path::new(done["retirement"]["record"].as_str().expect("archive"));
        let retired = read_reservation(archive)
            .expect("reader")
            .expect("retired record");
        assert_eq!(retired["current_retirement"]["prior_phase"], "failed");
        assert!(retired["current_retirement"]["accepted_absences"].is_null());
        assert!(!path.exists());
    }

    /// ´test:unit:ordinary-retirement-admits-an-absent-recorded-work-scope´
    #[test]
    fn ordinary_retirement_admits_an_absent_recorded_work_scope() {
        let (fixture, root, mut request) = public_fixture();
        let runtime = fixture.path().join("container-fixture");
        crate::fixture_exec::write_executable(
            &runtime,
            b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nexit 0\n",
        )
        .expect("absent container");
        let mut record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},"launcher_pid":u32::MAX,"launcher_start":1,"observer_state":"not-started","helper_spawn_state":"not-started","probe_starts":[]});
        let scope = super::super::reaping::RetirementScopeFixture::new(&mut record);
        fs::remove_dir_all(&scope.path).expect("collected recorded work directory");
        let path = reservation_path(&root, "R");
        publish_reservation(&path, &record).expect("never-started preparation");
        drop(lock_run_preparation(&root, "R", Uid::effective().as_raw()).expect("lease"));
        let preview = run(fixture.path(), &request).expect("absent scope preview");
        assert_eq!(preview["retirement"]["state"], "would-retire");
        assert_eq!(
            preview["retirement"]["identities"]["run_scope"]["state"],
            "collected"
        );
        assert_eq!(
            read_reservation(&path).expect("reader").expect("unchanged"),
            record
        );
        request.dry_run = false;
        request.expect_digest = preview["preview_sha256"].as_str().map(str::to_owned);
        let done = run(fixture.path(), &request).expect("absent scope apply");
        assert_eq!(done["retirement"]["state"], "retired");
        assert_eq!(done["worker_uid_released"], 3000);
        let archive = Path::new(done["retirement"]["record"].as_str().expect("archive"));
        let retired = read_reservation(archive).expect("reader").expect("retired");
        assert_eq!(retired["phase"], "retired");
        assert_eq!(retired["run_scope"], record["run_scope"]);
        assert_eq!(
            retired["current_retirement"]["identities"]["run_scope"]["state"],
            "collected"
        );
        assert!(!path.exists());
    }

    /// ´test:unit:public-confirmed-retirement-preserves-uncertainty-and-refuses-live-identities´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn public_confirmed_retirement_preserves_uncertainty_and_refuses_live_identities() {
        for worker in [3000, 3001] {
            let (fixture, root, mut request) = public_fixture();
            let owner = Uid::effective().as_raw();
            assert_ne!(owner, worker);
            let lease = lock_run_preparation(&root, "R", owner).expect("create lease");
            drop(lease);
            let runtime = fixture.path().join("container-fixture");
            crate::fixture_exec::write_executable(
                &runtime,
                b"#!/bin/sh\n[ \"$1\" = ps ] || exit 9\nexit 0\n",
            )
            .expect("absent runtime");
            let mut record = json!({"schema":1,"phase":"failed","loop":"alpha","run":"R","worker_uid":worker,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},"launcher_pid":u32::MAX,"launcher_start":1,"driver_entry_pid":u32::MAX,"driver_entry_start":1,"helper_pid":u32::MAX,"helper_start":1,"helper_parent_pid":u32::MAX,"helper_parent_start":1,"observer_pid":u32::MAX,"observer_start":1,"observer_state":"ended","settlement_uncertain":true,"reaping":{"state":"unmeasured"},"reaping_recovery":{"state":"collected","error":"prior recovery refused"}});
            let path = reservation_path(&root, "R");
            publish_reservation(&path, &record).expect("failed record");
            let store = crate::requests::store::Store::open(fixture.path(), "alpha", false)
                .expect("request store");
            fs::create_dir(root.join(".launch-R")).expect("request custody");
            fs::set_permissions(root.join(".launch-R"), fs::Permissions::from_mode(0o700))
                .expect("private custody");
            store
                .file(crate::requests::tests::waiting(
                    "R",
                    "1a",
                    worker,
                    crate::requests::Mode::Audit,
                ))
                .expect("waiting request");
            let pending = run(fixture.path(), &request).expect_err("waiting custody cannot retire");
            assert_eq!(pending.kind, "retire-requests-pending");
            assert!(pending.detail.contains("R:1a"));
            assert!(pending.detail.contains("requests triage"));
            store.triage("R", &[json!({"id":"R:1a","action":"adjudicate","treatment":"refuse","reason":"finished"})], "superloop", "2").expect("adjudicate before retirement");
            assert_eq!(
                run(fixture.path(), &request)
                    .expect_err("confirmation absent")
                    .kind,
                "retire-uncertain"
            );
            request.confirm_uncertain = true;
            let pid = std::process::id();
            let start = crate::container_helper::process_start(pid).expect("live start");
            for (pid_key, start_key) in [
                ("launcher_pid", "launcher_start"),
                ("driver_entry_pid", "driver_entry_start"),
                ("helper_pid", "helper_start"),
                ("helper_parent_pid", "helper_parent_start"),
                ("observer_pid", "observer_start"),
            ] {
                let mut live = record.clone();
                live[pid_key] = json!(pid);
                live[start_key] = json!(start);
                publish_reservation(&path, &live).expect("live identity");
                assert_eq!(
                    run(fixture.path(), &request)
                        .expect_err("identity alive")
                        .kind,
                    "retire-busy"
                );
            }
            let mut malformed = record.clone();
            malformed["settlement_uncertain"] = json!("true");
            publish_reservation(&path, &malformed).expect("malformed uncertainty");
            assert_eq!(
                run(fixture.path(), &request)
                    .expect_err("malformed uncertainty")
                    .kind,
                "retire-uncertain"
            );
            publish_reservation(&path, &record).expect("restore");
            crate::fixture_exec::write_executable(
                &runtime,
                b"#!/bin/sh\nprintf 'container-id\\n'\n",
            )
            .expect("present runtime");
            let busy = run(fixture.path(), &request).expect_err("container present");
            assert_eq!(busy.kind, "retire-busy");
            assert!(
                busy.detail
                    .starts_with("labelled container is still present; wall_seconds=")
            );
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n")
                .expect("absent runtime");
            let preview = run(fixture.path(), &request).expect("confirmed preview");
            assert!(!root.join(".letter-R.lock").exists());
            let held = lock_mailbox(&root, "R", owner).expect("letter writer");
            let busy = run(fixture.path(), &request).expect_err("held mailbox refuses preview");
            assert_eq!(busy.kind, "retire-busy");
            assert!(busy.detail.contains("mailbox lock"));
            drop(held);
            assert_eq!(preview["retirement"]["journal"]["uncertain"], true);
            assert_eq!(
                preview["retirement"]["journal"]["reaping_recovery"],
                record["reaping_recovery"]
            );
            if worker == 3001 {
                record["phase"] = json!("retiring");
                record["current_retirement"] = preview["retirement"]["journal"].clone();
                publish_reservation(&path, &record).expect("interrupted retirement journal");
                request.confirm_uncertain = false;
            }
            request.dry_run = false;
            let retired = run(fixture.path(), &request).expect("retry retains confirmation");
            assert_eq!(retired["worker_uid_released"], worker);
            assert_eq!(retired["retirement"]["journal"]["uncertain"], true);
            assert_eq!(
                retired["retirement"]["journal"]["reaping"],
                record["reaping"]
            );
            let saved = read_reservation(Path::new(
                retired["retirement"]["record"]
                    .as_str()
                    .expect("retired path"),
            ))
            .expect("retired reader")
            .expect("retired record");
            assert_eq!(saved["settlement_uncertain"], true);
            assert_eq!(saved["reaping_recovery"], record["reaping_recovery"]);
        }
    }

    /// ´test:unit:retire-confirmation-is-only-a-run-option´
    #[test]
    fn retire_confirmation_is_only_a_run_option() {
        for words in [
            vec!["alpha", "R", "--confirm-uncertain"],
            vec!["alpha", "R", "--confirm-uncertain", "--dry-run"],
        ] {
            assert!(
                RetireRequest::parse(&words.into_iter().map(str::to_owned).collect::<Vec<_>>())
                    .expect("confirmed run")
                    .confirm_uncertain
            );
        }
        assert!(
            RetireRequest::parse(
                &["alpha", "--generations", "--confirm-uncertain"].map(str::to_owned)
            )
            .is_err()
        );
    }

    /// ´test:unit:public-retire-requires-probe-process-absence-before-label-query´
    #[test]
    fn public_retire_requires_probe_process_absence_before_label_query() {
        let (fixture, root, mut request) = public_fixture();
        let lease = root.join(".prepare-R.lock");
        fs::write(&lease, "").expect("lease");
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("lease mode");
        let owner = Uid::effective().as_raw();
        let worker = if owner == 3000 { 3001 } else { 3000 };
        assert_ne!(owner, worker);
        let pid = std::process::id();
        let tick = crate::container_helper::process_start(pid).expect("current process tick");
        let mut record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":worker,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":["/usr/bin/true"]},"launcher_pid":u32::MAX,"launcher_start":1,"driver_entry_pid":u32::MAX,"driver_entry_start":1,"helper_pid":u32::MAX,"helper_start":1,"observer_pid":u32::MAX,"observer_start":1,"observer_state":"ended","probe_starts":[{"phase":"deferred","role":"worker","pid":pid,"start_tick":tick,"state":"running"}]});
        let reservation = reservation_path(&root, "R");
        publish_reservation(&reservation, &record).expect("reservation");
        let error = run(fixture.path(), &request).expect_err("live deferred probe");
        assert_eq!(error.kind, "retire-busy", "{}", error.line());
        assert!(error.detail.contains("deferred/worker"));
        assert!(reservation.exists());

        record["probe_starts"][0]
            .as_object_mut()
            .expect("probe")
            .remove("start_tick");
        publish_reservation(&reservation, &record).expect("incomplete journal");
        let error = run(fixture.path(), &request).expect_err("unreadable probe identity");
        assert_eq!(error.kind, "retire-uncertain", "{}", error.line());
        assert!(error.detail.contains("deferred/worker"));

        record["probe_starts"][0]["pid"] = json!(u32::MAX);
        record["probe_starts"][0]["start_tick"] = json!(1);
        publish_reservation(&reservation, &record).expect("absent probe");
        let preview = run(fixture.path(), &request).expect("empty two-label query");
        assert_eq!(
            preview["retirement"]["identities"]["probe_starts"][0]["presence"],
            "absent"
        );
        request.dry_run = false;
        let changed = run(fixture.path(), &request).expect("retire absent probe");
        assert_eq!(changed["retirement"]["state"], "retired");
        assert_eq!(changed["worker_uid_released"], worker);
    }

    /// ´test:unit:retire-refuses-unreadable-journaled-probe-before-container-query´
    #[test]
    fn retire_refuses_unreadable_journaled_probe_before_container_query() {
        let (_fixture, root, home, mut record) = fixture();
        record["probe_starts"] =
            json!([{"phase":"deferred","role":"sibling","pid":u32::MAX,"start_tick":1}]);
        let error = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            true,
            |pid, _| {
                if pid == u32::MAX {
                    crate::container_helper::ProcessPresence::Unknown
                } else {
                    crate::container_helper::ProcessPresence::Absent
                }
            },
            || panic!("unreadable process refuses before container query"),
        )
        .expect_err("unreadable deferred probe");
        assert_eq!(error.kind, "retire-uncertain");
        assert!(error.detail.contains("deferred/sibling"));
    }

    /// ´test:unit:public-retire-refuses-unrecorded-preparation-child´
    #[test]
    fn public_retire_refuses_unrecorded_preparation_child() {
        let (fixture, root, request) = public_fixture();
        let lease = root.join(".prepare-R.lock");
        fs::write(&lease, "").expect("lease");
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("lease mode");
        let record = json!({"schema":1,"phase":"preparing","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":["/usr/bin/true"]},"observer_state":"not-started"});
        let reservation = reservation_path(&root, "R");
        publish_reservation(&reservation, &record).expect("reservation");
        let error = run(fixture.path(), &request).expect_err("unidentified preparation child");
        assert_eq!(error.kind, "retire-uncertain", "{}", error.line());
        assert!(error.detail.contains("launcher"));
        assert!(reservation.exists());
    }

    /// ´test:unit:public-retire-refuses-unidentified-observer´
    #[test]
    fn public_retire_refuses_unidentified_observer() {
        let (fixture, root, request) = public_fixture();
        let lease = root.join(".prepare-R.lock");
        fs::write(&lease, "").expect("lease");
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).expect("lease mode");
        let record = json!({"schema":1,"phase":"failed","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":["/usr/bin/true"]},"launcher_pid":321,"launcher_start":88,"observer_state":"failed","observer_end":{"state":"uncertain","socket":{"state":"uncertain"}},"settlement_uncertain":false,"pre_driver_failure":"proxy-start","driver_end":{"state":"not-started"},"helper_end":{"state":"not-started"},"helper_spawn_state":"not-started"});
        let reservation = reservation_path(&root, "R");
        publish_reservation(&reservation, &record).expect("reservation");
        let error = run(fixture.path(), &request).expect_err("unidentified observer");
        assert_eq!(error.kind, "retire-uncertain", "{}", error.line());
        assert!(error.detail.contains("observer"));
        assert!(reservation.exists());
        let mut uncertain = record;
        uncertain["settlement_uncertain"] = json!(true);
        publish_reservation(&reservation, &uncertain).expect("uncertain reservation");
        let error = run(fixture.path(), &request).expect_err("uncertain settlement");
        assert_eq!(error.kind, "retire-uncertain");
        assert!(error.detail.contains("settlement"));
    }

    /// ´test:unit:public-retire-coexists-with-live-configuration-readers´
    #[test]
    fn public_retire_coexists_with_live_configuration_readers() {
        for worker in [3000_u32, 3001] {
            let (fixture, root, mut request) = public_fixture();
            let owner = Uid::effective().as_raw();
            assert_ne!(owner, worker);
            let config = fixture.path().join(".config/loops/alpha");
            let runtime = fixture.path().join("runtime");
            crate::fixture_exec::write_executable(&runtime, b"#!/bin/sh\nexit 0\n")
                .expect("runtime");
            drop(lock_run_preparation(&root, "R", owner).expect("lease"));
            let mut record = json!({"schema":1,"phase":"settled","loop":"alpha","run":"R",
                "worker_uid":worker,"imports":[],"harvest_agreement":null,"collection":null,
                "plan":{"home":fixture.path().join(".cache/tmp/lane-alpha-R"),"driver_dir":root.join("R"),"runtime_argv":[runtime]},
                "launcher_pid":u32::MAX-worker,"launcher_start":worker,"driver_entry_pid":u32::MAX-worker,"driver_entry_start":worker,
                "helper_pid":u32::MAX-worker,"helper_start":worker,"observer_state":"not-started","observer_end":{"state":"not-started"}});
            publish_reservation(&reservation_path(&root, "R"), &record).expect("settled run");
            record["run"] = json!("S");
            record["plan"]["driver_dir"] = json!(root.join("S"));
            record["plan"]["home"] = json!(fixture.path().join(".cache/tmp/lane-alpha-S"));
            record["launcher_pid"] = json!(std::process::id());
            record["launcher_start"] = json!(
                crate::container_helper::process_start(std::process::id()).expect("live identity")
            );
            drop(lock_run_preparation(&root, "S", owner).expect("live lease file"));
            record["worker_uid"] = json!(6001 - worker);
            publish_reservation(&reservation_path(&root, "S"), &record)
                .expect("distinct live worker");
            let live_before =
                fs::read(reservation_path(&root, "S")).expect("live reservation bytes");
            std::thread::scope(|scope| {
                let (ready, arrived) = std::sync::mpsc::channel();
                let mut releases = Vec::new();
                for _ in 0..2 {
                    let (release, wait) = std::sync::mpsc::channel::<()>();
                    releases.push(release);
                    let ready = ready.clone();
                    let config = &config;
                    scope.spawn(move || {
                        let _live = crate::install::lock_loop_config(config, true)
                            .expect("production launcher shared read guard");
                        ready.send(()).expect("announce holder");
                        let _released = wait.recv();
                    });
                }
                arrived.recv().expect("first live holder");
                arrived.recv().expect("second live holder");
                let error = crate::install::lock_loop_config(&config, false)
                    .map(|_| ())
                    .expect_err("exclusive install refused");
                assert_eq!(error.kind, "install-busy");
                request.dry_run = false;
                let result = run(fixture.path(), &request).expect("retire beside live launchers");
                assert_eq!(result["retirement"]["state"], "retired");
                assert_eq!(result["worker_uid_released"], worker);
                assert_eq!(
                    fs::read(reservation_path(&root, "S")).expect("retained live reservation"),
                    live_before
                );
                request.run = Some("S".into());
                let error = run(fixture.path(), &request).expect_err("live launcher refuses");
                assert_eq!(error.kind, "retire-busy");
                assert!(error.detail.contains("launcher is still present"));
                assert!(error.detail.contains("wall_seconds="));
                assert_eq!(
                    fs::read(reservation_path(&root, "S")).expect("refused live reservation"),
                    live_before
                );
                drop(releases);
            });
        }
    }

    /// ´test:unit:public-retire-dry-run-never-creates-a-missing-lease´
    #[test]
    fn public_retire_dry_run_never_creates_a_missing_lease() {
        let (fixture, root, request) = public_fixture();
        let lease = root.join(".prepare-R.lock");
        let error = run(fixture.path(), &request).expect_err("missing lease");
        assert_eq!(error.kind, "retire-lease", "{}", error.line());
        assert!(
            error
                .detail
                .contains("retire alpha R --confirm-missing-lease --dry-run")
        );
        assert!(!lease.exists());
        assert!(!root.join(".letter-R.lock").exists());
    }

    /// ´test:unit:retire-old-started-record-dry-run-and-uid-release´
    #[test]
    fn retire_old_started_record_dry_run_and_uid_release() {
        let (_fixture, root, home, record) = fixture();
        let preview = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            true,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("dry retirement");
        assert_eq!(preview["state"], "would-retire");
        assert_eq!(preview["worker_uid"], 3000);
        assert!(reservation_path(&root, "R").exists());
        assert!(root.join("R").exists());
        let changed = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("retirement");
        assert_eq!(changed["state"], "retired");
        assert_eq!(
            changed["journal"]["planned_paths"],
            preview["journal"]["planned_paths"]
        );
        assert!(!reservation_path(&root, "R").exists());
        let retained = Path::new(changed["record"].as_str().expect("retired record"));
        assert_eq!(
            read_reservation(retained)
                .expect("read retired")
                .expect("record")["phase"],
            "retired"
        );
        assert_eq!(
            select_free_uid(&root, "next", 3000, 2).expect("freed uid"),
            3000
        );
    }

    /// ´test:unit:retire-moves-each-recorded-launch-report-with-its-reservation´
    #[test]
    fn retire_moves_each_recorded_launch_report_with_its_reservation() {
        let (_fixture, root, home, mut record) = fixture();
        record["rounds"] = json!([{"step":"dispatch"}, {"step":"review"}, {"step":"final"}]);
        publish_reservation(&reservation_path(&root, "R"), &record).expect("round names");
        let names = [
            super::report::name("R", None).expect("first report"),
            super::report::name("R", Some("review")).expect("review report"),
            super::report::name("R", Some("final")).expect("final report"),
        ];
        let held: OwnedFd = fs::File::open(&root).expect("runs root").into();
        let initial = json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":"/home/run","driver_dir":"/runs/R","round_dir":"/runs/R/first-dispatch","preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"evidence":"driver directory outside home","wall_seconds":1.0});
        super::report::publish(&held, "R", None, &initial).expect("first report file");
        for step in ["review", "final"] {
            let resumed = json!({"schema":1,"command":"launch","dry_run":false,"round":step,"round_dir":"/runs/R/first-dispatch","budget_seconds":3600,"letter":"letter.md","letter_reconciliation":[],"thread_id":"thread","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"wall_seconds":2.0});
            super::report::publish(&held, "R", Some(step), &resumed).expect("resumed report file");
        }
        let archive = super::report::archive_preview(&held, "R", None).expect("archive name");
        let archive_path = root.join(archive["target"].as_str().expect("target"));
        let archive_bytes = fs::read(root.join(&names[0])).expect("report bytes");
        super::report::publish_replacing(&held, "R", None, &initial, Some(&initial))
            .expect("historical archive");
        let preview = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            true,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("retirement preview");
        let planned = preview["journal"]["planned_paths"]
            .as_array()
            .expect("paths");
        for name in &names {
            assert!(
                planned
                    .iter()
                    .any(|pair| pair["source"] == root.join(name).display().to_string())
            );
        }
        retire_record_with(
            &root,
            "R",
            &home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("retirement");
        for name in &names {
            assert!(!root.join(name).exists(), "report moved: {name}");
        }
        assert_eq!(
            fs::read(archive_path).expect("archive retained in runs root"),
            archive_bytes
        );
    }

    /// ´test:unit:twelve-retired-reports-are-attributed-to-census-record´
    #[test]
    fn twelve_retired_reports_are_attributed_to_census_record() {
        let (fixture, root, _) = public_fixture();
        let worker_home = fixture.path().join("home-R");
        fs::create_dir(&worker_home).expect("worker home");
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver directory");
        fs::create_dir(protected_identity_dir(&driver).expect("identity path"))
            .expect("identity directory");
        let steps = (0..11)
            .map(|index| format!("review{index}"))
            .collect::<Vec<_>>();
        let mut rounds = vec![json!({"step":"dispatch"})];
        rounds.extend(steps.iter().map(|step| json!({"step":step})));
        let record = json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"imports":[],"harvest_agreement":null,"collection":null,"rounds":rounds,"plan":{"home":worker_home,"driver_dir":driver,"runtime_argv":["/usr/bin/podman"]},"launcher_pid":321,"launcher_start":88,"helper_pid":322,"helper_start":89,"helper_parent_pid":325,"helper_parent_start":92,"driver_entry_pid":323,"driver_entry_start":90,"observer_pid":324,"observer_start":91,"observer_state":"running"});
        publish_reservation(&reservation_path(&root, "R"), &record).expect("reservation");
        let held: OwnedFd = fs::File::open(&root).expect("runs root").into();
        let first = json!({"schema":1,"command":"launch","dry_run":false,"observe":false,"enforcing":true,"observed":null,"home":"/home/run","driver_dir":"/runs/R","round_dir":"/runs/R/first-dispatch","preparation":"ready","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"evidence":"driver directory outside home","wall_seconds":1.0});
        super::report::publish(&held, "R", None, &first).expect("first report");
        for step in &steps {
            let resumed = json!({"schema":1,"command":"launch","dry_run":false,"round":step,"round_dir":"/runs/R/first-dispatch","budget_seconds":3600,"letter":"letter.md","letter_reconciliation":[],"thread_id":"thread","credential_publication":{"source_inode":42,"published_unix_ns":100},"driver_report":"driver","settlement":{},"wall_seconds":2.0});
            super::report::publish(&held, "R", Some(step), &resumed).expect("round report");
        }
        let changed = retire_record_with(
            &root,
            "R",
            &worker_home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("retirement");
        let paths = changed["journal"]["planned_paths"]
            .as_array()
            .expect("planned paths");
        assert_eq!(
            paths
                .iter()
                .filter(|pair| pair["source"]
                    .as_str()
                    .is_some_and(|source| source.contains(".report=")))
                .count(),
            12
        );
        assert!(paths.iter().all(|pair| {
            pair["target"]
                .as_str()
                .is_none_or(|target| !target.contains(".retired-R-20-"))
        }));
        admission::set(fixture.path(), "alpha", true).expect("paused admission");
        let census =
            super::census::run(fixture.path(), "alpha").expect("census after reports retire");
        assert_eq!(census["retired_records"].as_array().map(Vec::len), Some(1));
        assert_eq!(census["retired_records"][0]["run"], "R");
        let attributed = census["retired_records"][0]["journaled_names"]
            .as_array()
            .expect("retired names");
        let skipped = census["skipped_names"].as_array().expect("skipped names");
        for target in paths.iter().filter(|pair| {
            pair["source"]
                .as_str()
                .is_some_and(|source| source.contains(".report="))
        }) {
            let path = target["target"].as_str().expect("retired target");
            let name = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .expect("retired report name");
            assert!(attributed.contains(&json!(name)), "attributed: {name}");
            assert!(!skipped.contains(&json!(name)), "not skipped: {name}");
        }
    }

    /// ´test:unit:retirement-keeps-letter-placed-after-its-read´
    #[test]
    fn retirement_keeps_letter_placed_after_its_read() {
        let (_fixture, root, home, stale) = fixture();
        let inbox = home.join(".local/inbox");
        fs::create_dir_all(&inbox).expect("inbox");
        fs::write(inbox.join("review.md"), b"four").expect("placed letter");
        let mut placed = stale.clone();
        placed["letters"] = json!([{"step":"review","name":"review.md","state":"placed","bytes":4,"sha256":"fixture","placed_at_unix_ns":1}]);
        publish_reservation(&reservation_path(&root, "R"), &placed)
            .expect("placement after retirement read");
        let result = retire_record_with(
            &root,
            "R",
            &home,
            &stale,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(true),
        )
        .expect("locked retirement");
        let retired = read_reservation(Path::new(
            result["record"].as_str().expect("retired record"),
        ))
        .expect("read")
        .expect("record");
        assert_eq!(retired["letters"], placed["letters"]);
        assert_eq!(retired["phase"], "retired");
        let moved_home = result["journal"]["planned_paths"]
            .as_array()
            .expect("planned paths")
            .iter()
            .find(|pair| pair["source"] == home.display().to_string())
            .expect("home move");
        assert!(
            Path::new(moved_home["target"].as_str().expect("target"))
                .join(".local/inbox/review.md")
                .exists()
        );
        assert!(!home.exists());
    }

    /// ´test:unit:retire-refuses-live-unknown-and-labelled-container´
    #[test]
    fn retire_refuses_live_unknown_and_labelled_container() {
        let (_fixture, root, home, record) = fixture();
        for (state, kind) in [
            (
                crate::container_helper::ProcessPresence::Present,
                "retire-busy",
            ),
            (
                crate::container_helper::ProcessPresence::Unknown,
                "retire-uncertain",
            ),
        ] {
            let error = retire_record_with(
                &root,
                "R",
                &home,
                &record,
                true,
                |_, _| state,
                || panic!("process refusal precedes container lookup"),
            )
            .expect_err("presence refusal");
            assert_eq!(error.kind, kind);
        }
        let error = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            false,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || Ok(false),
        )
        .expect_err("labelled container remains");
        assert_eq!(error.kind, "retire-busy");
        assert!(reservation_path(&root, "R").exists());
    }

    /// ´test:unit:retire-pre-spawn-failure-after-launcher-identity´
    #[test]
    fn retire_pre_spawn_failure_after_launcher_identity() {
        let (_fixture, root, home, mut record) = fixture();
        for field in [
            "helper_pid",
            "helper_start",
            "helper_parent_pid",
            "helper_parent_start",
            "driver_entry_pid",
            "driver_entry_start",
            "observer_pid",
            "observer_start",
        ] {
            record.as_object_mut().expect("record").remove(field);
        }
        record["phase"] = json!("preparing");
        record["observer_state"] = json!("not-started");
        record["helper_spawn_state"] = json!("not-started");
        let reservation = reservation_path(&root, "R");
        publish_reservation(&reservation, &record).expect("preparation");
        super::super::record_failed_pre_driver(
            &reservation,
            &mut None,
            &LaneError::operation("driver-program", "pin refused before helper spawn"),
            Uid::effective().as_raw(),
            false,
        )
        .expect("record pre-spawn failure");
        let record = read_reservation(&reservation)
            .expect("read")
            .expect("record");
        assert_eq!(record["helper_end"]["state"], "not-started");
        let result = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            false,
            |pid, start| {
                assert_eq!((pid, start), (321, 88));
                crate::container_helper::ProcessPresence::Absent
            },
            || Ok(true),
        )
        .expect("pre-spawn failure retires");
        assert_eq!(result["state"], "retired");
        assert!(!reservation.exists());
    }

    /// ´test:unit:retire-helper-before-identity-requires-measured-parent-absence´
    #[test]
    fn retire_helper_before_identity_requires_measured_parent_absence() {
        let (_fixture, root, _home, mut record) = fixture();
        for field in [
            "helper_pid",
            "helper_start",
            "driver_entry_pid",
            "driver_entry_start",
        ] {
            record.as_object_mut().expect("record").remove(field);
        }
        record["phase"] = json!("preparing");
        record["helper_spawn_state"] = json!("running");
        let reservation = reservation_path(&root, "R");
        publish_reservation(&reservation, &record).expect("preparation");
        super::super::record_failed_pre_driver(
            &reservation,
            &mut None,
            &LaneError::operation("helper-start", "refused before identity"),
            Uid::effective().as_raw(),
            false,
        )
        .expect("record helper failure");
        let mut record = read_reservation(&reservation)
            .expect("read")
            .expect("record");
        assert_eq!(record["helper_end"]["state"], "failed");
        for (parent, expected) in [
            (
                crate::container_helper::ProcessPresence::Present,
                "retire-busy",
            ),
            (
                crate::container_helper::ProcessPresence::Unknown,
                "retire-uncertain",
            ),
        ] {
            let error = checked_presence(Path::new("/"), &record, false, |pid, _| {
                if pid == 325 {
                    parent
                } else {
                    crate::container_helper::ProcessPresence::Absent
                }
            })
            .expect_err("parent not proved absent");
            assert_eq!(error.kind, expected);
            assert!(error.detail.contains("helper parent"));
        }
        let evidence = checked_presence(Path::new("/"), &record, false, |_, _| {
            crate::container_helper::ProcessPresence::Absent
        })
        .expect("measured parent absence");
        assert_eq!(evidence["helper_parent"]["presence"], "absent");
        record
            .as_object_mut()
            .expect("record")
            .remove("helper_parent_pid");
        record
            .as_object_mut()
            .expect("record")
            .remove("helper_parent_start");
        assert_eq!(
            checked_presence(Path::new("/"), &record, false, |_, _| {
                crate::container_helper::ProcessPresence::Absent
            })
            .expect_err("no parent identity")
            .kind,
            "retire-uncertain"
        );
    }

    /// ´test:unit:retire-does-not-trust-saved-absence-proofs´
    #[test]
    fn retire_does_not_trust_saved_absence_proofs() {
        let (_fixture, _root, _home, mut record) = fixture();
        record["launcher_pid"] = Value::Null;
        record["launcher_start"] = Value::Null;
        record["retirement_absence_proof"] = json!({"schema":1,"state":"absent","phase":"started"});
        let error = checked_presence(Path::new("/"), &record, false, |_, _| {
            crate::container_helper::ProcessPresence::Absent
        })
        .expect_err("rewrite and repin readers cannot reuse a saved proof");
        assert_eq!(error.kind, "retire-uncertain");
        for invalid in [
            json!({"schema":2,"state":"absent","phase":"started"}),
            json!({"schema":1,"state":"absent"}),
            json!({"schema":1,"state":"absent","phase":"settled"}),
        ] {
            let error = checked_presence_with_proof(
                Path::new("/"),
                &record,
                false,
                Some(&invalid),
                |_, _| crate::container_helper::ProcessPresence::Absent,
            )
            .expect_err("invalid proof shape");
            assert_eq!(error.kind, "retire-uncertain");
        }
    }

    /// ´test:unit:retire-probes-parent-when-inner-helper-is-absent´
    #[test]
    fn retire_probes_parent_when_inner_helper_is_absent() {
        let (_fixture, root, home, mut record) = fixture();
        record["helper_parent_pid"] = json!(325);
        record["helper_parent_start"] = json!(92);
        for (parent, kind) in [
            (
                crate::container_helper::ProcessPresence::Present,
                "retire-busy",
            ),
            (
                crate::container_helper::ProcessPresence::Unknown,
                "retire-uncertain",
            ),
        ] {
            let error = retire_record_with(
                &root,
                "R",
                &home,
                &record,
                true,
                |pid, _| {
                    if pid == 325 {
                        parent
                    } else {
                        crate::container_helper::ProcessPresence::Absent
                    }
                },
                || panic!("parent refusal precedes container lookup"),
            )
            .expect_err("parent presence refuses");
            assert_eq!(error.kind, kind);
        }
    }

    /// ´test:unit:retire-refuses-started-run-with-unrecorded-parent´
    #[test]
    fn retire_refuses_started_run_with_unrecorded_parent() {
        let (_fixture, root, home, mut record) = fixture();
        record
            .as_object_mut()
            .expect("record")
            .remove("helper_parent_pid");
        record
            .as_object_mut()
            .expect("record")
            .remove("helper_parent_start");
        let error = retire_record_with(
            &root,
            "R",
            &home,
            &record,
            true,
            |_, _| crate::container_helper::ProcessPresence::Absent,
            || panic!("uncertain parent precedes container lookup"),
        )
        .expect_err("missing parent proof refuses");
        assert_eq!(error.kind, "retire-uncertain");
        assert!(error.detail.contains("helper parent"));
    }

    /// ´test:unit:generation-inventory-keeps-referenced-digests´
    #[test]
    fn generation_inventory_keeps_referenced_digests() {
        let first = format!("sha256:{}", "a".repeat(64));
        let second = format!("sha256:{}", "b".repeat(64));
        let inventory = format!(
            "{first} localhost/superloop-lane-codex:held\n{first} localhost/superloop-lane-claude:held\n{second} localhost/superloop-lane-codex:old\n{second} localhost/superloop-lane-claude:old\n"
        );
        let protected = std::collections::BTreeSet::from([first]);
        let candidates =
            image_retirement_candidates(&inventory, &protected).expect("generation inventory");
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0]["image_digest"], second);
        assert_eq!(
            candidates[0]["remove_command"]["argv"],
            json!(["rmi", "localhost/superloop-lane-codex:old"])
        );
        assert_eq!(
            candidates[1]["remove_command"]["argv"],
            json!(["rmi", "localhost/superloop-lane-claude:old"])
        );
    }

    /// ´test:unit:template-inventory-retains-both-vendors-for-referenced-image´
    #[test]
    fn template_inventory_retains_both_vendors_for_referenced_image() {
        let fixture = tempfile::Builder::new()
            .tempdir_in("/tmp")
            .expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let hash = "a".repeat(64);
        let digest = format!("sha256:{hash}");
        for vendor in ["codex", "claude"] {
            let root = home
                .join(".var/loops/alpha/runner-templates")
                .join(vendor)
                .join(&hash);
            fs::create_dir_all(&root).expect("template directories");
            for ancestor in root.ancestors().take_while(|path| *path != home) {
                fs::set_permissions(ancestor, fs::Permissions::from_mode(0o700))
                    .expect("protected template ancestor");
            }
            fs::write(
                root.join("manifest"),
                serde_json::to_vec(&json!({"image_digest":digest})).expect("manifest JSON"),
            )
            .expect("manifest");
        }
        let protected = std::collections::BTreeSet::from([digest]);
        assert_eq!(
            template_retirement_candidates(home, "alpha", &protected, None)
                .expect("protected inventory"),
            [] as [Value; 0]
        );
        let unreferenced = std::collections::BTreeSet::new();
        let candidates = template_retirement_candidates(home, "alpha", &unreferenced, None)
            .expect("unreferenced inventory");
        assert_eq!(candidates.len(), 2);
        for vendor in ["codex", "claude"] {
            assert!(candidates.iter().any(|pair| pair["source"]
                == json!(home.join(".var/loops/alpha/runner-templates").join(vendor).join(&hash))));
        }
        let claude = home
            .join(".var/loops/alpha/runner-templates/claude")
            .join(&hash);
        assert_eq!(
            template_retirement_candidates(home, "alpha", &unreferenced, Some(&claude))
                .expect("current template")
                .len(),
            1
        );
        fs::write(claude.join("manifest"), b"{\"image_digest\":\"wrong\"}").expect("changed image");
        assert_eq!(
            template_retirement_candidates(home, "alpha", &unreferenced, None)
                .expect_err("manifest binding")
                .kind,
            "retire-manifest"
        );
    }
}
