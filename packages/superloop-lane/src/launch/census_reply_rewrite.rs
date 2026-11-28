//! Digest-bound conversion of retained round rows, without changing ordinary readers.

use super::super::read_reservation_for_conversion as read_reservation;
use super::*;
use std::os::unix::fs::DirBuilderExt as _;
use std::time::Instant;

const PENDING: &str = ".census-replies-pending.json";
const COMPLETE_DIR: &str = ".census-replies-complete";

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("reply-row-rewrite", detail)
}

fn command(loop_name: &str, digest: Option<&str>) -> String {
    digest.map_or_else(
        || format!("superloop-lane census rewrite-replies {loop_name} --dry-run"),
        |digest| {
            format!("superloop-lane census rewrite-replies {loop_name} --expect-digest {digest}")
        },
    )
}

fn parse(args: &[String]) -> Result<(&str, Option<&str>), LaneError> {
    let (loop_name, expected) = match args {
        [loop_name, flag] if flag == "--dry-run" => (loop_name.as_str(), None),
        [loop_name, flag, digest]
            if flag == "--expect-digest"
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            (loop_name.as_str(), Some(digest.as_str()))
        }
        _ => {
            return Err(refusal(
                "census rewrite-replies LOOP {--dry-run|--expect-digest HEX}",
            ));
        }
    };
    loop_home::validate_name(loop_name).map_err(|error| refusal(error.message()))?;
    Ok((loop_name, expected))
}

fn completed_name(digest: &str) -> PathBuf {
    Path::new(COMPLETE_DIR).join(format!("{digest}.json"))
}

fn completed_dir(root: &Path, owner: u32, create: bool) -> Result<Option<PathBuf>, LaneError> {
    let path = root.join(COMPLETE_DIR);
    if create && !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| refusal(format!("completed journal directory: {error}")))?;
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(refusal(format!("completed journal directory: {error}"))),
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(refusal(format!(
            "{} must be an owner-only directory; repair its custody",
            path.display()
        )));
    }
    Ok(Some(path))
}

fn protected_json(path: &Path) -> Result<Option<Value>, LaneError> {
    let Some(bytes) = retire::absences::read_bytes(path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| refusal(format!("{}: {error}", path.display())))
}

pub(super) fn validate_journal<'a>(
    journal: &'a Value,
    loop_name: &str,
) -> Result<(&'a Value, &'a str), LaneError> {
    let plan = &journal["plan"];
    let digest = journal["preview_sha256"]
        .as_str()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| refusal("rewrite journal has no full preview digest"))?;
    if journal["schema"] != 1
        || journal["loop"] != loop_name
        || !["pending", "complete"].contains(&journal["phase"].as_str().unwrap_or_default())
        || plan["schema"] != 1
        || plan["loop"] != loop_name
        || plan["command"] != "census rewrite-replies"
        || !plan["files"].is_array()
        || crate::door::retirement::digest(plan) != digest
    {
        return Err(refusal(
            "rewrite journal binding differs; restore its protected evidence",
        ));
    }
    Ok((plan, digest))
}

fn record_names(root: &Path) -> Result<Vec<(String, PathBuf, bool)>, LaneError> {
    Ok(root_entries(root)?
        .into_iter()
        .filter_map(|(name, path)| {
            let retired = retired_name(&name);
            if (name.starts_with(".reservation-") && name.strip_suffix(".json").is_some())
                || retired
            {
                Some((name, path, retired))
            } else {
                None
            }
        })
        .collect())
}

fn eligible(record: &Value, run: &str, retired: bool, loop_name: &str) -> Result<(), LaneError> {
    eligible_with_presence(record, run, retired, loop_name, identity)
}

fn eligible_with_presence(
    record: &Value,
    run: &str,
    retired: bool,
    loop_name: &str,
    presence_of: impl Fn(Result<Option<(u32, u64)>, LaneError>) -> Result<Value, LaneError>,
) -> Result<(), LaneError> {
    if record["loop"] != loop_name || record["run"] != run {
        return Err(refusal(format!(
            "run {run}: reservation identity differs; repeat {}",
            command(loop_name, None)
        )));
    }
    if retired {
        if record["phase"] != "retired" {
            return Err(refusal(format!(
                "run {run}: archive is not retired; repeat {}",
                command(loop_name, None)
            )));
        }
    } else {
        if record.get("retirement_absence_plan").is_some() {
            let flags = record["retirement_absence_plan"]["flags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            let options = if flags.is_empty() {
                String::new()
            } else {
                format!(" {flags}")
            };
            return Err(refusal(format!(
                "run {run}: finish its pending retire with superloop-lane retire {loop_name} {run}{options} --dry-run, then --expect-digest HEX from its preview; repeat {}",
                command(loop_name, None)
            )));
        }
        if !["settled", "failed", "started"].contains(&record["phase"].as_str().unwrap_or_default())
        {
            return Err(refusal(format!(
                "run {run}: round is live or uncertain; follow the census's preparation or retirement command, then repeat {}",
                command(loop_name, None)
            )));
        }
        if super::started_without_writer_identity(record)
            && record["rounds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|round| designation_member(round) == DesignationMember::Absent)
        {
            let remedy = match reaping::check_unsettled_driver(record) {
                Ok(reaping::UnsettledDriverCheck::Absent) => format!(
                    "preview retirement with superloop-lane retire {loop_name} {run} --dry-run, apply its digest, then repeat {}",
                    command(loop_name, None)
                ),
                Ok(reaping::UnsettledDriverCheck::Unreadable(error)) => format!(
                    "report evidence cannot be read ({error}); retirement cannot establish absence and no command of this program converts it; retain its recovery evidence for owner repair"
                ),
                Err(error) => format!(
                    "retirement refuses this run ({error}) and strict launch recovery needs a converted row; no command of this program converts it; retain its recovery evidence for owner repair"
                ),
            };
            return Err(refusal(format!(
                "run {run}: a started writer identity was not recorded; {remedy}"
            )));
        }
        for observed in [
            launcher_identity(record),
            driver_identity(record),
            helper_identity(record),
            helper_parent_identity(record),
            observer_identity(record),
        ] {
            let presence = presence_of(observed)?["presence"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if presence == "present" || presence == "unknown" {
                let remedy = if presence == "unknown" {
                    "its presence cannot be measured; inspect the process evidence before repeating"
                        .to_owned()
                } else {
                    "wait for its exit before repeating".to_owned()
                };
                return Err(refusal(format!(
                    "run {run}: {presence} round writer; {remedy} {}",
                    command(loop_name, None)
                )));
            }
        }
    }
    for round in record["rounds"].as_array().into_iter().flatten() {
        if designation_member(round) == DesignationMember::Invalid {
            return Err(refusal(format!(
                "run {run}: malformed or unknown reply designation; repair the protected row, then repeat {}",
                command(loop_name, None)
            )));
        }
    }
    Ok(())
}

fn inventory(root: &Path, loop_name: &str, owner: u32) -> Result<Value, LaneError> {
    let names = record_names(root)?;
    let mut files = Vec::new();
    let mut retained_bytes = 0_u64;
    let mut changed_rows = 0_usize;
    let mut runs = std::collections::BTreeSet::new();
    for (name, path, retired) in names {
        let run = if retired {
            read_reservation(&path)?.and_then(|record| record["run"].as_str().map(str::to_owned))
        } else {
            name.strip_prefix(".reservation-")
                .and_then(|part| part.strip_suffix(".json"))
                .map(str::to_owned)
        }
        .filter(|run| valid_run_name(run))
        .ok_or_else(|| refusal(format!("{} has no valid run", path.display())))?;
        runs.insert(run.clone());
        let bytes = retire::absences::read_bytes(&path)?.ok_or_else(|| {
            refusal(format!(
                "run {run}: record vanished; repeat {}",
                command(loop_name, None)
            ))
        })?;
        let record = read_reservation(&path)?.ok_or_else(|| {
            refusal(format!(
                "run {run}: record vanished; repeat {}",
                command(loop_name, None)
            ))
        })?;
        eligible(&record, &run, retired, loop_name)?;
        let mut target = record;
        let mut changed = 0;
        for round in target["rounds"].as_array_mut().into_iter().flatten() {
            if designation_member(round) == DesignationMember::Absent {
                round["reply_designation"] = json!({"state":"unmeasured"});
                changed += 1;
            }
        }
        let target_bytes = if changed == 0 {
            bytes.clone()
        } else {
            serde_json::to_vec(&target).map_err(|error| refusal(error.to_string()))?
        };
        if target_bytes.len() as u64 > MAX_RESERVATION_BYTES {
            return Err(refusal(format!(
                "run {run}: target is {} bytes over reservation bound {MAX_RESERVATION_BYTES}; reduce the record through its owner, then repeat {}",
                target_bytes.len(),
                command(loop_name, None)
            )));
        }
        retained_bytes += bytes.len() as u64;
        changed_rows += changed;
        files.push(json!({"path":path,"run":run,"retired":retired,
            "before_sha256":retire::absences::hash(&bytes),"before_bytes":bytes.len(),
            "target_sha256":retire::absences::hash(&target_bytes),"target_bytes":target_bytes.len(),
            "changed_rows":changed}));
    }
    let mut blocker_counts = DesignationCounts::default();
    for (name, path) in root_entries(root)? {
        blocker_counts.rewrite(&name, &path, root, loop_name)?;
    }
    if blocker_counts.pending_census_rewrites
        + blocker_counts.pending_retirement_rewrites
        + blocker_counts.pending_node_retirement_rewrites
        > 0
    {
        let blocker = blocker_counts
            .blockers
            .first()
            .ok_or_else(|| refusal("rewrite blocker has no run"))?;
        let preview = blocker["next_command"].as_str().unwrap_or("its preview");
        let apply = blocker["apply_command"]
            .as_str()
            .map_or_else(String::new, |command| {
                format!(", then {command} with the preview digest")
            });
        return Err(refusal(format!(
            "run {}: pending {}; finish {preview}{apply}, then repeat {}",
            blocker["run"].as_str().unwrap_or("unknown"),
            blocker["kind"].as_str().unwrap_or("rewrite"),
            command(loop_name, None)
        )));
    }
    let retained_records = files.len();
    Ok(
        json!({"schema":1,"command":"census rewrite-replies","loop":loop_name,"owner_uid":owner,
        "files":files,"runs":runs,"retained_records":retained_records,"retained_bytes":retained_bytes,
        "changed_rows":changed_rows}),
    )
}

fn check_manifest(root: &Path, loop_name: &str, plan: &Value) -> Result<(), LaneError> {
    let names = record_names(root)?;
    let files = plan["files"]
        .as_array()
        .ok_or_else(|| refusal("journal has no files"))?;
    if names.len() != files.len() {
        return Err(refusal(format!(
            "inventory changed; repeat {}",
            command(loop_name, None)
        )));
    }
    for ((_, path, retired), file) in names.into_iter().zip(files) {
        let run = file["run"]
            .as_str()
            .ok_or_else(|| refusal("journal row has no run"))?;
        if file["path"] != path.to_string_lossy().as_ref() || file["retired"] != retired {
            return Err(refusal(format!(
                "run {run}: inventory path changed; repeat {}",
                command(loop_name, None)
            )));
        }
        let bytes = retire::absences::read_bytes(&path)?.ok_or_else(|| {
            refusal(format!(
                "run {run}: record vanished; repeat {}",
                command(loop_name, None)
            ))
        })?;
        let actual = retire::absences::hash(&bytes);
        if actual != file["before_sha256"] && actual != file["target_sha256"] {
            return Err(refusal(format!(
                "run {run}: bytes changed since preview; repeat {}",
                command(loop_name, None)
            )));
        }
        let record = read_reservation(&path)?.ok_or_else(|| {
            refusal(format!(
                "run {run}: record vanished; repeat {}",
                command(loop_name, None)
            ))
        })?;
        eligible(&record, run, retired, loop_name)?;
        if actual == file["before_sha256"] {
            let mut target = record;
            for round in target["rounds"].as_array_mut().into_iter().flatten() {
                if designation_member(round) == DesignationMember::Absent {
                    round["reply_designation"] = json!({"state":"unmeasured"});
                }
            }
            let target_bytes = if file["changed_rows"] == 0 {
                bytes.clone()
            } else {
                serde_json::to_vec(&target).map_err(|error| refusal(error.to_string()))?
            };
            if retire::absences::hash(&target_bytes) != file["target_sha256"]
                || target_bytes.len() as u64 != file["target_bytes"].as_u64().unwrap_or_default()
                || bytes.len() as u64 != file["before_bytes"].as_u64().unwrap_or_default()
            {
                return Err(refusal(format!(
                    "run {run}: bound target differs; repeat {}",
                    command(loop_name, None)
                )));
            }
        }
    }
    Ok(())
}

fn check_journal_bound(
    journal: &Value,
    plan: &Value,
    loop_name: &str,
    bound: u64,
) -> Result<(), LaneError> {
    if serde_json::to_vec(journal)
        .map_err(|error| refusal(error.to_string()))?
        .len() as u64
        <= bound
    {
        return Ok(());
    }
    let runs = plan["runs"].as_array().map_or_else(String::new, |runs| {
        runs.iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    });
    Err(refusal(format!(
        "runs {runs}: journal exceeds {bound} bytes; reduce the retained inventory before repeating {}",
        command(loop_name, None)
    )))
}

/// Preview or apply the protected, whole-loop round-row conversion.
///
/// # Errors
/// Refuses changed inputs, live writers, pending rewrites, malformed members or unsafe custody.
pub fn run(owner_home: &Path, args: &[String]) -> Result<Value, LaneError> {
    run_with_journal_bound(owner_home, args, MAX_RESERVATION_BYTES)
}

#[allow(clippy::too_many_lines)]
fn run_with_journal_bound(
    owner_home: &Path,
    args: &[String],
    journal_bound: u64,
) -> Result<Value, LaneError> {
    let begun = Instant::now();
    let (loop_name, expected) = parse(args)?;
    let config = owner_home.join(".config/loops").join(loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let owner = Uid::effective().as_raw();
    if admission::read(&config, owner)?["state"] != "paused" {
        return Err(refusal(format!(
            "pause {loop_name} with superloop-lane pause {loop_name}, then repeat {}",
            command(loop_name, None)
        )));
    }
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| refusal("runs_root is absent"))?;
    let _runs = lock_runs_root(root, true, owner)?;
    let pending_path = root.join(PENDING);
    let pending = protected_json(&pending_path)?;
    if let Some(journal) = &pending {
        let (_, digest) = validate_journal(journal, loop_name)?;
        if expected.is_some_and(|expected| expected != digest) {
            return Err(refusal(format!(
                "a conversion is pending; resume {}",
                command(loop_name, Some(digest))
            )));
        }
    }
    if let Some(digest) = expected
        && let Some(complete_dir) = completed_dir(root, owner, false)?
    {
        let complete_path = complete_dir.join(format!("{digest}.json"));
        if let Some(completed) = protected_json(&complete_path)? {
            let (plan, found) = validate_journal(&completed, loop_name)?;
            if completed["phase"] != "complete" || found != digest {
                return Err(refusal(format!(
                    "completed journal {digest} differs; restore its protected evidence"
                )));
            }
            return Ok(
                json!({"schema":1,"command":"census rewrite-replies","dry_run":false,
                "complete":true,"already_complete":true,"resuming":false,"plan":plan,
                "preview_sha256":digest,"wall_seconds":begun.elapsed().as_secs_f64()}),
            );
        }
    }
    let (plan, digest, resuming) = if let Some(journal) = &pending {
        let (plan, digest) = validate_journal(journal, loop_name)?;
        (plan.clone(), digest.to_owned(), true)
    } else {
        let plan = inventory(root, loop_name, owner)?;
        let digest = crate::door::retirement::digest(&plan);
        (plan, digest, false)
    };
    let mut run_locks = Vec::new();
    for run in plan["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if let Some(lease) = retire::probe_retirement_lease(root, run, owner)? {
            run_locks.push(lease);
        }
        if let Some(mailbox) = retire::lock_retirement_mailbox(root, run, owner, true)? {
            run_locks.push(mailbox);
        }
    }
    check_manifest(root, loop_name, &plan)?;
    if !resuming && plan["changed_rows"] == 0 {
        return Ok(
            json!({"schema":1,"command":"census rewrite-replies","dry_run":expected.is_none(),
            "complete":expected.is_some(),"already_complete":expected.is_some(),"resuming":false,
            "plan":plan,"preview_sha256":digest,"wall_seconds":begun.elapsed().as_secs_f64()}),
        );
    }
    let mut journal = json!({"schema":1,"phase":"pending","loop":loop_name,
        "plan":plan,"preview_sha256":digest,"published":0});
    journal["published"] = json!(plan["files"].as_array().map_or(0, Vec::len));
    check_journal_bound(&journal, &plan, loop_name, journal_bound)?;
    journal["published"] = json!(0);
    if let Some(expected) = expected {
        if expected != digest {
            let runs = plan["runs"].as_array().map_or_else(String::new, |runs| {
                runs.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            return Err(refusal(format!(
                "runs {runs}: inventory changed since preview; repeat {}",
                command(loop_name, None)
            )));
        }
        if pending.is_none() {
            publish_reservation(&pending_path, &journal)?;
        }
        let files = plan["files"]
            .as_array()
            .ok_or_else(|| refusal("plan has no files"))?;
        for (index, file) in files.iter().enumerate() {
            let path = Path::new(
                file["path"]
                    .as_str()
                    .ok_or_else(|| refusal("plan path absent"))?,
            );
            let bytes =
                retire::absences::read_bytes(path)?.ok_or_else(|| refusal("record vanished"))?;
            let actual = retire::absences::hash(&bytes);
            if actual != file["before_sha256"] && actual != file["target_sha256"] {
                return Err(refusal(format!(
                    "run {}: bytes changed during publication; resume {} after owner repair",
                    file["run"].as_str().unwrap_or("unknown"),
                    command(loop_name, Some(&digest))
                )));
            }
            if actual == file["before_sha256"] && file["before_sha256"] != file["target_sha256"] {
                let mut target =
                    read_reservation(path)?.ok_or_else(|| refusal("record vanished"))?;
                for round in target["rounds"].as_array_mut().into_iter().flatten() {
                    if designation_member(round) == DesignationMember::Absent {
                        round["reply_designation"] = json!({"state":"unmeasured"});
                    }
                }
                publish_reservation(path, &target)?;
            }
            journal["published"] = json!(index + 1);
            publish_reservation(&pending_path, &journal)?;
        }
        journal["phase"] = json!("complete");
        publish_reservation(&pending_path, &journal)?;
        completed_dir(root, owner, true)?;
        fs::rename(&pending_path, root.join(completed_name(&digest)))
            .map_err(|error| refusal(format!("completed journal rename: {error}")))?;
        fs::File::open(root.join(COMPLETE_DIR))
            .and_then(|directory| directory.sync_all())
            .map_err(|error| refusal(format!("completed journal directory sync: {error}")))?;
        fs::File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| refusal(format!("completed journal sync: {error}")))?;
    }
    drop(run_locks);
    Ok(
        json!({"schema":1,"command":"census rewrite-replies","dry_run":expected.is_none(),
        "complete":expected.is_some(),"already_complete":false,"resuming":resuming,
        "plan":plan,"preview_sha256":digest,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        let home = fixture.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
        let config = home.join(".config/loops/alpha");
        fs::create_dir_all(&config).expect("configuration");
        for directory in [
            home.join(".config"),
            home.join(".config/loops"),
            config.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("configuration mode");
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
        publish_reservation(&reservation_path(&root, "R"),
            &json!({"schema":1,"phase":"settled","loop":"alpha","run":"R","worker_uid":3000,
                "observer_state":"not-started","rounds":[{"step":"dispatch"},{"step":"close","reply_designation":{"state":"unmeasured"}}],"plan":{}}))
            .expect("live reservation");
        let retired = root.join(".retired-S-20-1-2");
        publish_reservation(&retired,
            &json!({"schema":1,"phase":"retired","loop":"alpha","run":"S","worker_uid":3001,
                "observer_state":"not-started","rounds":[{"step":"dispatch"}],
                "current_retirement":{"reservation_path":{"target":retired},"planned_paths":[]},"plan":{}}))
            .expect("retired reservation");
        admission::set(home, "alpha", true).expect("paused admission");
        (fixture, root)
    }

    fn preview(home: &Path) -> Value {
        run(home, &["alpha".into(), "--dry-run".into()]).expect("preview")
    }

    fn apply(home: &Path, digest: &str) -> Value {
        run(
            home,
            &["alpha".into(), "--expect-digest".into(), digest.into()],
        )
        .expect("apply")
    }

    fn digest(report: &Value) -> &str {
        report["preview_sha256"].as_str().expect("digest")
    }

    /// ´test:unit:preview-apply-and-second-conversion´
    #[test]
    #[allow(clippy::too_many_lines)] // One fixture checks preview custody, history, and a second conversion.
    fn preview_apply_and_second_conversion() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        let live = reservation_path(&root, "R");
        let retired = root.join(".retired-S-20-1-2");
        let mut retired_record = read_reservation(&retired)
            .expect("read archive")
            .expect("archive");
        retired_record["retirement_absence_plan"] =
            json!({"before":{"rounds":[{"step":"historical"}]}});
        let historical = retired_record["retirement_absence_plan"].clone();
        publish_reservation(&retired, &retired_record).expect("historical plan");
        let before = [
            fs::read(&live).expect("live bytes"),
            fs::read(&retired).expect("retired bytes"),
        ];
        let names_before = root_entries(&root).expect("root names");
        let report = preview(home);
        assert_eq!(report["plan"]["changed_rows"], 2);
        assert_eq!(report["plan"]["retained_records"], 2);
        assert!(
            report["plan"]["retained_bytes"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        assert!(report["wall_seconds"].as_f64().is_some());
        assert_eq!(fs::read(&live).expect("unchanged live"), before[0]);
        assert_eq!(fs::read(&retired).expect("unchanged retired"), before[1]);
        assert_eq!(root_entries(&root).expect("root names"), names_before);
        assert!(!root.join(PENDING).exists());
        let first = digest(&report).to_owned();
        let applied = apply(home, &first);
        assert_eq!(applied["complete"], true);
        assert_eq!(
            read_reservation(&live).expect("read").expect("record")["rounds"][0]["reply_designation"],
            json!({"state":"unmeasured"})
        );
        assert_eq!(
            read_reservation(&retired).expect("read").expect("record")["rounds"][0]["reply_designation"],
            json!({"state":"unmeasured"})
        );
        assert_eq!(
            read_reservation(&retired).expect("read").expect("record")["retirement_absence_plan"],
            historical
        );
        assert!(root.join(completed_name(&first)).exists());
        assert_eq!(
            fs::read_dir(root.join(COMPLETE_DIR))
                .expect("completed directory")
                .count(),
            1
        );
        let completed_bytes =
            fs::read(root.join(completed_name(&first))).expect("completed journal");
        assert!(!root.join(PENDING).exists());
        assert_eq!(apply(home, &first)["already_complete"], true);
        fs::write(
            root.join(completed_name(&first)),
            b"{corrupt historical evidence",
        )
        .expect("corrupt completed journal");
        assert!(
            run(
                home,
                &["alpha".into(), "--expect-digest".into(), first.clone()]
            )
            .expect_err("completed digest needs its evidence")
            .line()
            .contains(COMPLETE_DIR)
        );
        let mut old_writer = read_reservation(&live).expect("read").expect("record");
        old_writer["rounds"]
            .as_array_mut()
            .expect("rounds")
            .push(json!({"step":"late"}));
        publish_reservation(&live, &old_writer).expect("old writer row");
        let second = preview(home);
        assert_eq!(second["plan"]["changed_rows"], 1);
        assert_ne!(digest(&second), first);
        publish_reservation(
            &root.join(PENDING),
            &json!({"schema":1,"phase":"pending","loop":"alpha",
                "plan":second["plan"],"preview_sha256":digest(&second),"published":0}),
        )
        .expect("second pending conversion");
        let replay = run(
            home,
            &["alpha".into(), "--expect-digest".into(), first.clone()],
        )
        .expect_err("older completed digest must not hide pending conversion");
        assert!(
            replay
                .line()
                .contains(&command("alpha", Some(digest(&second))))
        );
        apply(home, digest(&second));
        assert!(root.join(completed_name(&first)).exists());
        assert_ne!(completed_bytes, b"{corrupt historical evidence");
        assert_eq!(
            fs::read(root.join(completed_name(&first))).expect("historical journal"),
            b"{corrupt historical evidence"
        );
        assert!(root.join(completed_name(digest(&second))).exists());
        assert_eq!(
            fs::read_dir(root.join(COMPLETE_DIR))
                .expect("completed directory")
                .count(),
            2
        );
        let readiness =
            super::super::run(home, "alpha").expect("census")["reply_designation_readiness"]
                .clone();
        assert_eq!(
            readiness["rows_without_member"],
            json!({"live":0,"retired":0})
        );
        assert_eq!(readiness["retained_records"], 2);
        assert!(readiness["retained_bytes"].as_u64().unwrap_or_default() > 0);
    }

    /// ´test:unit:resumes-after-one-publication´
    #[test]
    fn resumes_after_one_publication() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        let report = preview(home);
        let digest = digest(&report);
        publish_reservation(
            &root.join(PENDING),
            &json!({"schema":1,"phase":"pending",
            "loop":"alpha","plan":report["plan"],"preview_sha256":digest,"published":0}),
        )
        .expect("pending journal");
        assert!(
            run(
                home,
                &["alpha".into(), "--expect-digest".into(), "0".repeat(64)]
            )
            .expect_err("another digest")
            .line()
            .contains(&command("alpha", Some(digest)))
        );
        let live = reservation_path(&root, "R");
        let mut record = read_reservation(&live).expect("read").expect("record");
        let original = record.clone();
        record["note"] = json!("changed after preview");
        publish_reservation(&live, &record).expect("changed bytes");
        assert!(
            run(
                home,
                &["alpha".into(), "--expect-digest".into(), digest.into()]
            )
            .expect_err("changed pending bytes")
            .line()
            .contains("run R: bytes changed since preview")
        );
        record = original;
        record["rounds"][0]["reply_designation"] = json!({"state":"unmeasured"});
        publish_reservation(&live, &record).expect("first publication");
        let result = apply(home, digest);
        assert_eq!(result["resuming"], true);
        assert!(!root.join(PENDING).exists());
        assert!(root.join(completed_name(digest)).exists());
    }

    /// ´test:unit:refuses-changed-and-blocked-inventory´
    #[test]
    fn refuses_changed_and_blocked_inventory() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        let report = preview(home);
        let live = reservation_path(&root, "R");
        let mut changed = read_reservation(&live).expect("read").expect("record");
        changed["note"] = json!("changed");
        publish_reservation(&live, &changed).expect("change");
        assert!(
            run(
                home,
                &[
                    "alpha".into(),
                    "--expect-digest".into(),
                    digest(&report).into()
                ]
            )
            .expect_err("stale digest")
            .line()
            .contains("repeat")
        );
        changed["rounds"][0]["reply_designation"] = Value::Null;
        publish_reservation(&live, &changed).expect("invalid member");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("invalid member")
                .line()
                .contains("malformed or unknown")
        );
        changed["rounds"][0]["reply_designation"] =
            json!({"state":"issued","outgoing":"reply.letter"});
        publish_reservation(&live, &changed).expect("unknown member");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("unknown member")
                .line()
                .contains("malformed or unknown")
        );
        changed["rounds"][0]
            .as_object_mut()
            .expect("round")
            .remove("reply_designation");
        changed["phase"] = json!("started");
        for role in ["launcher", "driver_entry", "helper"] {
            changed[format!("{role}_pid")] = json!(u32::MAX);
            changed[format!("{role}_start")] = json!(1);
        }
        publish_reservation(&live, &changed).expect("dead started round");
        assert!(run(home, &["alpha".into(), "--dry-run".into()]).is_ok());
        changed["phase"] = json!("preparing");
        publish_reservation(&live, &changed).expect("uncertain round");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("uncertain round")
                .line()
                .contains("live or uncertain")
        );
        changed["phase"] = json!("retiring");
        changed["retirement_absence_plan"] =
            json!({"before":{},"flags":["--confirm-missing-lease"]});
        publish_reservation(&live, &changed).expect("absence plan");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("absence plan")
                .line()
                .contains("superloop-lane retire alpha R --confirm-missing-lease --dry-run")
        );
    }

    /// ´test:unit:refuses-admission-process-and-pending-rewrites´
    #[test]
    fn refuses_admission_process_and_pending_rewrites() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        admission::set(home, "alpha", false).expect("running admission");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("admission")
                .line()
                .contains("superloop-lane pause alpha")
        );
        admission::set(home, "alpha", true).expect("pause again");
        let live = reservation_path(&root, "R");
        let mut record = read_reservation(&live).expect("read").expect("record");
        assert!(
            eligible_with_presence(&record, "R", false, "alpha", |_| {
                Ok(json!({"presence":"unknown"}))
            })
            .expect_err("unknown writer")
            .line()
            .contains("unknown round writer")
        );
        record["launcher_pid"] = json!(std::process::id());
        record["launcher_start"] =
            json!(crate::container_helper::process_start(std::process::id()).expect("start"));
        publish_reservation(&live, &record).expect("live launcher");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("live launcher")
                .line()
                .contains("present round writer")
        );
        record
            .as_object_mut()
            .expect("record")
            .remove("launcher_pid");
        record
            .as_object_mut()
            .expect("record")
            .remove("launcher_start");
        publish_reservation(&live, &record).expect("idle launcher");
        for (name, plan, remedy) in [
            (
                ".census-rewrite-R.json",
                json!({"before":{}}),
                "superloop-lane census rewrite alpha R --dry-run",
            ),
            (
                ".retire-rewrite-R.json",
                json!({"before":{}}),
                "superloop-lane retire rewrite alpha R --dry-run",
            ),
            (
                ".retire-node-rewrite.json",
                json!({"files":[{"path":live}]}),
                "superloop-lane retire rewrite-node alpha --dry-run",
            ),
        ] {
            let journal = root.join(name);
            publish_reservation(&journal, &json!({"schema":1,"phase":"pending","plan":plan}))
                .expect("pending old rewrite");
            let error =
                run(home, &["alpha".into(), "--dry-run".into()]).expect_err("pending rewrite");
            assert!(error.line().contains("run R: pending"));
            assert!(error.line().contains(remedy));
            assert!(error.line().contains("--expect-digest HEX"));
            fs::remove_file(journal).expect("clear old rewrite");
        }
    }

    /// ´test:unit:converts-near-bound-and-empty-inventories´
    #[test]
    fn converts_near_bound_and_empty_inventories() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        let live = reservation_path(&root, "R");
        let mut record = read_reservation(&live).expect("read").expect("record");
        let bound = usize::try_from(MAX_RESERVATION_BYTES).expect("bound fits usize");
        record["padding"] = json!("x".repeat(bound - 1024));
        publish_reservation(&live, &record).expect("near bound record");
        let report = preview(home);
        assert!(
            report["plan"]["retained_bytes"]
                .as_u64()
                .unwrap_or_default()
                > MAX_RESERVATION_BYTES - 1024
        );
        apply(home, digest(&report));
        fs::remove_file(&live).expect("remove live");
        fs::remove_file(root.join(".retired-S-20-1-2")).expect("remove archive");
        let empty = preview(home);
        assert_eq!(empty["plan"]["retained_records"], 0);
        assert_eq!(empty["plan"]["changed_rows"], 0);
        assert_eq!(apply(home, digest(&empty))["already_complete"], true);
        assert!(!root.join(PENDING).exists());
    }

    /// ´test:unit:refuses-overbound-target´
    #[test]
    fn refuses_overbound_target() {
        let (fixture, root) = fixture();
        let home = fixture.path();
        let live = reservation_path(&root, "R");
        let mut record = read_reservation(&live).expect("read").expect("record");
        let bound = usize::try_from(MAX_RESERVATION_BYTES).expect("bound fits usize");
        record["padding"] = json!("x".repeat(bound - 1024));
        let size = serde_json::to_vec(&record).expect("bytes").len();
        record["padding"] = json!("x".repeat(bound - 1024 + (bound - size - 5)));
        publish_reservation(&live, &record).expect("bounded original");
        assert!(
            run(home, &["alpha".into(), "--dry-run".into()])
                .expect_err("target bound")
                .line()
                .contains("over reservation bound")
        );
    }

    /// ´test:unit:refuses-overbound-journal´
    #[test]
    fn refuses_overbound_journal() {
        let plan = json!({"runs":["R"]});
        let journal = json!({"padding":"x".repeat(usize::try_from(MAX_RESERVATION_BYTES).expect("bound fits usize"))});
        assert!(
            check_journal_bound(&journal, &plan, "alpha", MAX_RESERVATION_BYTES)
                .expect_err("journal bound")
                .line()
                .contains("runs R: journal exceeds")
        );
        let (fixture, _) = fixture();
        let error =
            run_with_journal_bound(fixture.path(), &["alpha".into(), "--dry-run".into()], 1)
                .expect_err("run checks its journal before publishing");
        assert!(error.line().contains("journal exceeds 1 bytes"));
    }
}
