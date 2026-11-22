//! Read protected reservations without traversing loop-owned run directories.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DesignationMember {
    Absent,
    Valid,
    Invalid,
}

fn designation_member(round: &Value) -> DesignationMember {
    let Some(member) = round.get("reply_designation") else {
        return DesignationMember::Absent;
    };
    if member.as_object().is_some_and(|fields| fields.len() == 1) && member["state"] == "unmeasured"
    {
        DesignationMember::Valid
    } else {
        DesignationMember::Invalid
    }
}

fn root_entries(root: &Path) -> Result<Vec<(String, PathBuf)>, LaneError> {
    let mut entries = fs::read_dir(root)
        .map_err(|error| LaneError::input("census-root", format!("{}: {error}", root.display())))?
        .map(|entry| {
            entry.map(|entry| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| LaneError::input("census-root", error.to_string()))?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

#[derive(Default)]
struct DesignationCounts {
    live_without_member: usize,
    retired_without_member: usize,
    live_invalid_member: usize,
    retired_invalid_member: usize,
    retained_records: usize,
    retained_bytes: u64,
    pending_rollback_before_images: usize,
    stranded_rollback_before_images: usize,
    pending_absence_plans: usize,
    pending_census_rewrites: usize,
    pending_retirement_rewrites: usize,
    pending_node_retirement_rewrites: usize,
    pending_reply_rewrites: usize,
    blockers: Vec<Value>,
    rollback_evidence: Vec<Value>,
}

impl DesignationCounts {
    fn row(&mut self, record: &Value, retired: bool, loop_name: &str) {
        let run = record["run"].as_str().unwrap_or_default();
        let mut absent = 0;
        let mut invalid = 0;
        for round in record["rounds"].as_array().into_iter().flatten() {
            match designation_member(round) {
                DesignationMember::Absent => absent += 1,
                DesignationMember::Invalid => invalid += 1,
                DesignationMember::Valid => {}
            }
        }
        if retired {
            self.retired_without_member += absent;
            self.retired_invalid_member += invalid;
        } else {
            self.live_without_member += absent;
            self.live_invalid_member += invalid;
        }
        if absent > 0 {
            self.blockers.push(json!({"kind":"rounds-without-member","run":run,
                "retired":retired,"count":absent,
                "next_command":format!("superloop-lane census rewrite-replies {loop_name} --dry-run"),
                "apply_command":format!("superloop-lane census rewrite-replies {loop_name} --expect-digest HEX"),
                "then":"Replace HEX with preview_sha256 from the dry run."}));
        }
        if invalid > 0 {
            self.blockers.push(json!({"kind":"rounds-with-invalid-member","run":run,
                "retired":retired,"count":invalid,"next_command":null,
                "clears_by":"Repair the invalid protected row with its owner; conversion refuses it."}));
        }
        if !retired && record.get("round_rollback").is_some() {
            if record.get("dispatch_intent").is_some() {
                self.stranded_rollback_before_images += 1;
                self.rollback_evidence.push(json!({"kind":"rollback-after-dispatch-intent",
                    "run":run,"next_command":null,
                    "clears_by":"No restore command exists after dispatch intent; retain the run for owner repair."}));
            } else {
                self.pending_rollback_before_images += 1;
                self.rollback_evidence.push(json!({"kind":"pending-round-rollback",
                    "run":run,"next_command":null,
                    "clears_by":"A live launch may restore before intent or consume the image at spawn receipt. A crash leaves no standalone restore command; retain the run for owner repair."}));
            }
        }
        if !retired && record.get("retirement_absence_plan").is_some() {
            self.pending_absence_plans += 1;
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
            self.blockers.push(json!({"kind":"pending-absence-plan","run":run,
                "next_command":format!("superloop-lane retire {loop_name} {run}{options} --dry-run"),
                "apply_command":format!("superloop-lane retire {loop_name} {run}{options} --expect-digest HEX"),
                "then":"Replace HEX with the preview_sha256 from the dry run."}));
        }
    }

    #[allow(clippy::case_sensitive_file_extension_comparisons)] // Protected journal names are exact.
    #[allow(clippy::too_many_lines)] // Three recorded journal forms have distinct recovery routes.
    fn rewrite(
        &mut self,
        name: &str,
        path: &Path,
        root: &Path,
        loop_name: &str,
    ) -> Result<bool, LaneError> {
        if name == ".census-replies-pending.json" {
            let bytes = super::retire::absences::read_bytes(path)?.ok_or_else(|| {
                LaneError::input("census-record", format!("{} vanished", path.display()))
            })?;
            let journal: Value = serde_json::from_slice(&bytes).map_err(|error| {
                LaneError::input("census-record", format!("{}: {error}", path.display()))
            })?;
            let (plan, digest) = reply_rewrite::validate_journal(&journal, loop_name)?;
            if journal["phase"] == "pending" {
                self.pending_reply_rewrites += 1;
                for run in plan["runs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    self.blockers.push(json!({"kind":"pending-reply-row-rewrite","run":run,
                        "next_command":format!("superloop-lane census rewrite-replies {loop_name} --expect-digest {digest}")}));
                }
            }
            return Ok(true);
        }
        let kind = if name.starts_with(".census-rewrite-") && name.ends_with(".json") {
            0
        } else if name.starts_with(".retire-rewrite-") && name.ends_with(".json") {
            1
        } else if name == ".retire-node-rewrite.json" {
            2
        } else {
            return Ok(false);
        };
        let bytes = super::retire::absences::read_bytes(path)?.ok_or_else(|| {
            LaneError::input("census-record", format!("{} vanished", path.display()))
        })?;
        let journal: Value = serde_json::from_slice(&bytes).map_err(|error| {
            LaneError::input("census-record", format!("{}: {error}", path.display()))
        })?;
        match journal["phase"].as_str() {
            Some("pending") => match kind {
                0 | 1 => {
                    let run = name
                        .strip_prefix(if kind == 0 {
                            ".census-rewrite-"
                        } else {
                            ".retire-rewrite-"
                        })
                        .and_then(|name| name.strip_suffix(".json"))
                        .filter(|run| valid_run_name(run))
                        .ok_or_else(|| {
                            LaneError::input(
                                "census-record",
                                format!("{} has no valid run", path.display()),
                            )
                        })?;
                    let (kind_name, preview, apply) = if kind == 0 {
                        self.pending_census_rewrites += 1;
                        (
                            "pending-census-rewrite",
                            format!("superloop-lane census rewrite {loop_name} {run} --dry-run"),
                            format!(
                                "superloop-lane census rewrite {loop_name} {run} --expect-digest HEX"
                            ),
                        )
                    } else {
                        self.pending_retirement_rewrites += 1;
                        (
                            "pending-retirement-rewrite",
                            format!("superloop-lane retire rewrite {loop_name} {run} --dry-run"),
                            format!(
                                "superloop-lane retire rewrite {loop_name} {run} --expect-digest HEX"
                            ),
                        )
                    };
                    self.blockers.push(json!({"kind":kind_name,"run":run,
                        "next_command":preview,
                        "apply_command":apply,
                        "then":"Replace HEX with the preview_sha256 from the dry run."}));
                }
                _ => {
                    self.pending_node_retirement_rewrites += 1;
                    let entries = match journal["schema"].as_u64() {
                        Some(1) => journal["plan"]["files"].as_array(),
                        Some(2) => journal["manifest"].as_array(),
                        _ => None,
                    };
                    let manifest = entries.ok_or_else(|| {
                        LaneError::input(
                            "census-record",
                            format!("{} has no rewrite file inventory", path.display()),
                        )
                    })?;
                    let mut runs = std::collections::BTreeSet::new();
                    for entry in manifest {
                        let recorded = entry["path"].as_str().map(Path::new).ok_or_else(|| {
                            LaneError::input(
                                "census-record",
                                format!("{} has an unnamed rewrite row", path.display()),
                            )
                        })?;
                        if recorded.parent() != Some(root) {
                            return Err(LaneError::input(
                                "census-record",
                                "node rewrite path escapes runs root",
                            ));
                        }
                        let row =
                            super::read_reservation_checked(recorded, false)?.ok_or_else(|| {
                                LaneError::input(
                                    "census-record",
                                    format!("{} vanished", recorded.display()),
                                )
                            })?;
                        let run = row["run"]
                            .as_str()
                            .filter(|run| valid_run_name(run))
                            .ok_or_else(|| {
                                LaneError::input("census-record", "node rewrite row has no run")
                            })?;
                        runs.insert(run.to_owned());
                    }
                    for run in runs {
                        self.blockers.push(json!({"kind":"pending-node-retirement-rewrite",
                            "run":run,"next_command":format!("superloop-lane retire rewrite-node {loop_name} --dry-run"),
                            "apply_command":format!("superloop-lane retire rewrite-node {loop_name} --expect-digest HEX"),
                            "then":"Replace HEX with the preview_sha256 from the dry run."}));
                    }
                }
            },
            Some("complete") => {}
            _ => {
                return Err(LaneError::input(
                    "census-record",
                    format!("{} has an unknown rewrite phase", path.display()),
                ));
            }
        }
        Ok(true)
    }

    fn report(mut self) -> Value {
        self.blockers.sort_by(|left, right| {
            (
                left["run"].as_str(),
                left["kind"].as_str(),
                left["index"].as_u64(),
            )
                .cmp(&(
                    right["run"].as_str(),
                    right["kind"].as_str(),
                    right["index"].as_u64(),
                ))
        });
        json!({
            "rows_without_member":{"live":self.live_without_member,"retired":self.retired_without_member},
            "rows_with_invalid_member":{"live":self.live_invalid_member,"retired":self.retired_invalid_member},
            "retained_records":self.retained_records,"retained_bytes":self.retained_bytes,
            "pending_rollback_before_images":self.pending_rollback_before_images,
            "stranded_rollback_before_images":self.stranded_rollback_before_images,
            "rollback_evidence":self.rollback_evidence,
            "pending_absence_plans":self.pending_absence_plans,
            "pending_rewrite_transactions":{
                "census":self.pending_census_rewrites,
                "retirement":self.pending_retirement_rewrites,
                "node_retirement":self.pending_node_retirement_rewrites,
                "reply_rows":self.pending_reply_rewrites,
            },
            "blockers":self.blockers
        })
    }
}

#[path = "census_reply_rewrite.rs"]
pub mod reply_rewrite;
#[path = "census_rewrite.rs"]
pub mod rewrite;

fn identity(result: Result<Option<(u32, u64)>, LaneError>) -> Result<Value, LaneError> {
    let recorded = result.map_err(|error| LaneError::input("census-record", error.line()))?;
    Ok(match recorded {
        Some((pid, start)) => {
            let presence = match crate::container_helper::process_presence(pid, start) {
                crate::container_helper::ProcessPresence::Present => "present",
                crate::container_helper::ProcessPresence::Absent => "absent",
                crate::container_helper::ProcessPresence::Unknown => "unknown",
            };
            json!({"pid":pid,"start":start,"presence":presence})
        }
        None => json!({"presence":"not-recorded"}),
    })
}

fn journaled_names(
    record: &Value,
    root: &Path,
    root_names: &std::collections::BTreeSet<String>,
    retired: bool,
) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for journal in std::iter::once(&record["current_retirement"])
        .chain(std::iter::once(&record["dead_preparation_retired"]))
        .chain(record["retry_retirements"].as_array().into_iter().flatten())
    {
        if let Some(paths) = journal["planned_paths"].as_array() {
            for pair in paths {
                if let Some(target) = pair["target"].as_str() {
                    let path = Path::new(target);
                    if path.parent() == Some(root)
                        && let Some(name) = path.file_name().and_then(|name| name.to_str())
                    {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
    }
    if retired && let Some(run) = record["run"].as_str() {
        let lease = format!(".prepare-{run}.lock");
        if root_names.contains(&lease) {
            names.insert(lease);
        }
    }
    names.into_iter().collect()
}

fn row(
    name: &str,
    record: &Value,
    path: &Path,
    root: &Path,
    root_names: &std::collections::BTreeSet<String>,
    retired: bool,
    credential_refresh: &Value,
) -> Result<Value, LaneError> {
    if record["loop"] != name || !record["run"].is_string() {
        return Err(LaneError::input(
            "census-record",
            format!("{} names another loop or has no run", path.display()),
        ));
    }
    Ok(json!({
        "run":record["run"],
        "phase":record["phase"],
        "worker_uid":record["worker_uid"],
        "door_scope":record["door_scope"],
        "door_pin_history":record["door_pin_history"],
        "round_door_pins":super::repin_door::round_pins(record)?,
        "record":path,
        "identities":{
            "launcher":identity(launcher_identity(record))?,
            "driver":identity(driver_identity(record))?,
            "helper":identity(helper_identity(record))?,
            "helper_parent":identity(helper_parent_identity(record))?,
            "observer":identity(observer_identity(record))?,
        },
        "settlement_uncertain":record["settlement_uncertain"],
        "accepted_absences":record["current_retirement"]["accepted_absences"],
        "credential_refresh":credential_refresh,
        "node_retirement":if retired || record.get("node_retirement").is_some() { super::retire::node_record::read(record)? } else { Value::Null },
        "journaled_names":journaled_names(record, root, root_names, retired),
    }))
}

pub(super) fn retired_name(name: &str) -> bool {
    retired_base_name(name)
        || name.rsplit_once('.').is_some_and(|(base, suffix)| {
            !suffix.starts_with('0')
                && !suffix.is_empty()
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
                && retired_base_name(base)
        })
}

fn retired_base_name(name: &str) -> bool {
    let Some((prefix, inode)) = name.rsplit_once('-') else {
        return false;
    };
    let Some((prefix, device)) = prefix.rsplit_once('-') else {
        return false;
    };
    prefix
        .strip_prefix(".retired-")
        .and_then(|part| part.strip_suffix("-20"))
        .is_some_and(valid_run_name)
        && !device.is_empty()
        && device.bytes().all(|byte| byte.is_ascii_digit())
        && !inode.is_empty()
        && inode.bytes().all(|byte| byte.is_ascii_digit())
}

fn credential_refresh(
    runs: &std::os::fd::OwnedFd,
    run: &str,
    owner: u32,
) -> Result<Value, LaneError> {
    Ok(
        crate::credential::read_evidence(runs, run, owner)?.map_or_else(
            || unavailable("absent", "missing-file"),
            |evidence| match evidence {
                crate::credential::EvidenceObservation::Current(document) => measurement(&document),
                crate::credential::EvidenceObservation::Historical(document) => {
                    let reason = if document.get("run_refusals").is_some() {
                        "historical-envelope:four-key-run-refusals"
                    } else {
                        "historical-envelope:five-key-refusal"
                    };
                    let mut result = unavailable("unmeasured", reason);
                    result["evidence_state"] = document["state"].clone();
                    result["refused"] = document["kind"].clone();
                    result
                }
            },
        ),
    )
}

fn unavailable(state: &str, reason: &str) -> Value {
    json!({"state":state,"reason":reason,"expires_unix":null,"refresh_due_unix":null,
        "evidence_state":null,"refused":null})
}

fn measurement(evidence: &Value) -> Value {
    if let Some(provenance) = evidence.get("credential_rewrite") {
        return historical_measurement(evidence, &provenance["original"]);
    }
    let mut result = unavailable("measured", "measured");
    result["evidence_state"] = evidence["state"].clone();
    result["refused"] = evidence["kind"].clone();
    if evidence.get("expires_unix") == Some(&Value::Null)
        && evidence.get("refresh_due_unix") == Some(&Value::Null)
        && evidence["state"] == "refused"
        && evidence["kind"]
            .as_str()
            .is_some_and(|kind| !kind.is_empty())
    {
        result["state"] = json!("unmeasured");
        result["reason"] = json!("helper-could-not-measure");
        return result;
    }
    let mut reasons = Vec::new();
    let mut missing = false;
    let mut invalid = false;
    for field in ["expires_unix", "refresh_due_unix"] {
        match evidence.get(field) {
            None => {
                missing = true;
                reasons.push(format!("missing-field:{field}"));
            }
            Some(value) if value.as_u64().is_some() => result[field] = value.clone(),
            Some(_) => {
                invalid = true;
                reasons.push(format!("invalid-field:{field}"));
            }
        }
    }
    if let Some(expires) = result["expires_unix"].as_u64() {
        if expires < 600 {
            result["expires_unix"] = Value::Null;
            invalid = true;
            reasons.push("expiry-precedes-refresh-lead".to_owned());
        }
        if let Some(due) = result["refresh_due_unix"].as_u64()
            && expires.checked_sub(600) != Some(due)
        {
            result["refresh_due_unix"] = Value::Null;
            invalid = true;
            reasons.push("refresh-due-disagrees".to_owned());
        }
    }
    if invalid || missing {
        result["state"] = json!(if invalid { "invalid" } else { "absent" });
        result["reason"] = json!(reasons.join(","));
    }
    result
}

fn historical_measurement(evidence: &Value, original: &Value) -> Value {
    let mut result = unavailable("unmeasured", "historical-helper-did-not-measure");
    result["evidence_state"] = original["state"].clone();
    result["refused"] = original["kind"].clone();
    let mut reasons = Vec::new();
    let mut invalid = false;
    for field in ["expires_unix", "refresh_due_unix"] {
        match evidence.get(field) {
            None => reasons.push(format!("missing-field:{field}")),
            Some(Value::Null) => {}
            Some(_) => {
                invalid = true;
                reasons.push(format!("historical-unmeasured-field:{field}"));
            }
        }
    }
    if !reasons.is_empty() {
        result["state"] = json!(if invalid { "invalid" } else { "absent" });
        result["reason"] = json!(reasons.join(","));
    }
    result
}

/// Report every protected reservation and retired reservation for a loop.
///
/// # Errors
///
/// Refuses an unsafe or malformed protected record and an unreadable runs root.
#[allow(clippy::too_many_lines)]
pub fn run(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    run_with(owner_home, loop_name, false)
}
/// Inventory protected home generations for the held mail cutover.
///
/// # Errors
/// Refuses unsafe or inconsistent protected history under the ordinary census locks.
pub fn mail_migration(owner_home: &Path, loop_name: &str) -> Result<Value, LaneError> {
    run_with(owner_home, loop_name, true)
}
#[allow(clippy::too_many_lines)]
fn run_with(owner_home: &Path, loop_name: &str, migration: bool) -> Result<Value, LaneError> {
    loop_home::validate_name(loop_name)
        .map_err(|error| LaneError::input("loop-name", error.message()))?;
    let begun = Instant::now();
    let config = owner_home.join(".config/loops").join(loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let owner = Uid::effective().as_raw();
    let admission = admission::read(&config, owner)?;
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, loop_name)?;
    let root = settings.runs_root.as_deref().ok_or_else(|| {
        LaneError::input("census-grant", "runs_root is absent from loop settings")
    })?;
    let runs = lock_runs_root(root, false, owner)?;
    let (base, count) = worker_range(owner_home, loop_name)?;
    let mut migration_rows = Vec::new();
    let mut reservations = Vec::new();
    let mut retired = Vec::new();
    let mut designation_counts = DesignationCounts::default();
    let mut skipped_names = Vec::new();
    let entries = root_entries(root)?;
    let root_names = entries
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (name, path) in entries {
        if let Some(run) = name
            .strip_prefix(".reservation-")
            .and_then(|part| part.strip_suffix(".json"))
        {
            if !valid_run_name(run) {
                return Err(LaneError::input(
                    "census-record",
                    format!("{} has an invalid run name", path.display()),
                ));
            }
            let record = read_reservation(&path)
                .map_err(|error| LaneError::input("census-record", error.line()))?
                .ok_or_else(|| {
                    LaneError::input("census-record", format!("{} vanished", path.display()))
                })?;
            if record["run"] != run {
                return Err(LaneError::input(
                    "census-record",
                    format!("{} names another run", path.display()),
                ));
            }
            designation_counts.retained_records += 1;
            designation_counts.retained_bytes += fs::metadata(&path)
                .map_err(|error| LaneError::input("census-record", error.to_string()))?
                .len();
            if migration {
                migration_rows.push(super::migration_inventory::row(
                    owner_home, root, loop_name, &path, &record,
                )?);
            }
            designation_counts.row(&record, false, loop_name);
            let due = credential_refresh(&runs, run, owner)?;
            reservations.push(row(
                loop_name,
                &record,
                &path,
                root,
                &root_names,
                false,
                &due,
            )?);
        } else if retired_name(&name) {
            let record = read_reservation(&path)
                .map_err(|error| LaneError::input("census-record", error.line()))?
                .ok_or_else(|| {
                    LaneError::input("census-record", format!("{} vanished", path.display()))
                })?;
            if record["phase"] != "retired"
                || record["current_retirement"]["reservation_path"]["target"]
                    != path.to_string_lossy().as_ref()
            {
                return Err(LaneError::input(
                    "census-record",
                    format!("{} is not a recorded retirement", path.display()),
                ));
            }
            designation_counts.retained_records += 1;
            designation_counts.retained_bytes += fs::metadata(&path)
                .map_err(|error| LaneError::input("census-record", error.to_string()))?
                .len();
            if migration {
                migration_rows.push(super::migration_inventory::row(
                    owner_home, root, loop_name, &path, &record,
                )?);
            }
            designation_counts.row(&record, true, loop_name);
            let due = unavailable("unmeasured", "retired");
            retired.push(row(
                loop_name,
                &record,
                &path,
                root,
                &root_names,
                true,
                &due,
            )?);
        } else {
            designation_counts.rewrite(&name, &path, root, loop_name)?;
            skipped_names.push(name);
        }
    }
    reservations.sort_by(|left, right| left["run"].as_str().cmp(&right["run"].as_str()));
    retired.sort_by(|left, right| left["record"].as_str().cmp(&right["record"].as_str()));
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for row in reservations.iter().chain(&retired) {
        if let Some(names) = row["journaled_names"].as_array() {
            for name in names.iter().filter_map(Value::as_str) {
                *counts.entry(name.to_owned()).or_default() += 1;
            }
        }
    }
    for row in reservations.iter_mut().chain(&mut retired) {
        let ambiguous = row["journaled_names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|name| counts.get(*name).is_some_and(|count| *count > 1))
            .collect::<Vec<_>>();
        row["ambiguous_journaled_names"] = json!(ambiguous);
    }
    let attributed = reservations
        .iter()
        .chain(&retired)
        .filter_map(|row| row["journaled_names"].as_array())
        .flatten()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    skipped_names.retain(|name| !attributed.contains(name.as_str()));
    skipped_names.sort();
    let mut result = json!({"schema":1,"command":"census","loop":loop_name,"admission":admission,"allocation":{"base":base,"count":count},"reservations":reservations,"retired_records":retired,"skipped_names":skipped_names,"reply_designation_readiness":designation_counts.report(),"wall_seconds":begun.elapsed().as_secs_f64()});
    if migration {
        result["mail_migration"] = json!({"records":migration_rows,"unattributed_names":skipped_names,"activation_verified":false});
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:census-retired-names-accept-collision-suffixes´
    #[test]
    fn census_retired_names_accept_collision_suffixes() {
        for name in [
            ".retired-run-with-dashes-20-1-2",
            ".retired-run-with-dashes-20-1-2.1",
            ".retired-run-with-dashes-20-1-2.12",
            ".retired-X-20-20-1-2.1",
        ] {
            assert!(retired_name(name), "{name}");
        }
        for name in [
            ".retired-R-21-1-2.1",
            ".retired-R-20-1-2.0",
            ".retired-R-20-1-2.01",
            ".retired-R-20-1-2.x",
            ".retired-R-20-1-2.",
            ".retired-R-20-1-2-1",
            ".retired-X-20-0-1-2",
            ".retired-X-20-21-1-2",
            ".retired-X-20-0-1-2.1",
            ".retired-X-20-21-1-2.1",
        ] {
            assert!(!retired_name(name), "{name}");
        }
    }

    struct RestoreDriver(std::path::PathBuf);

    impl Drop for RestoreDriver {
        fn drop(&mut self) {
            drop(fs::set_permissions(
                &self.0,
                fs::Permissions::from_mode(0o700),
            ));
        }
    }

    /// ´test:unit:census-reads-owner-records-with-unreadable-driver´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn census_reads_owner_records_with_unreadable_driver() {
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
        assert_ne!(Uid::effective().as_raw(), 41001);
        let driver = root.join("R");
        fs::create_dir(&driver).expect("driver");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o000)).expect("driver mode");
        let _restore = RestoreDriver(driver);
        let protected = root.join(".launch-R");
        fs::create_dir(&protected).expect("protected evidence directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("protected evidence mode");
        let evidence = crate::credential::evidence_for_check(
            &Ok(crate::credential::fixture_report(1_900_000_000)),
            true,
            crate::settings::BoxBackend::Codex,
        )
        .expect("first check evidence");
        crate::credential::publish_evidence(&root.join("R"), &evidence).expect("fixture evidence");
        let pid = std::process::id();
        let start = crate::container_helper::process_start(pid).expect("process start");
        let recovered = root.join(".retired-R-0-4-5");
        fs::create_dir(&recovered).expect("launch recovery path");
        let retried = root.join(".retired-R-0-6-7");
        fs::create_dir(&retried).expect("later retry path");
        publish_reservation(&reservation_path(&root, "R"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"R","worker_uid":3000,"launcher_pid":pid,"launcher_start":start,"observer_state":"not-started","rounds":[{"step":"dispatch"},{"step":"review","reply_designation":{"state":"unmeasured"}},{"step":"close"}],"round_rollback":{"nonce":"a".repeat(64),"before":"{}"},"retirement_absence_plan":{"before":{},"flags":["--confirm-missing-lease"]},"dead_preparation_retired":{"state":"retired-dead-preparation","planned_paths":[{"source":root.join("R"),"target":recovered}]},"retry_retirements":[{"state":"retired-dead-preparation","planned_paths":[{"source":root.join("R"),"target":retried}]}],"plan":{}})).expect("reservation");
        publish_reservation(&reservation_path(&root, "T"), &json!({"schema":1,"phase":"started","loop":"alpha","run":"T","worker_uid":3001,"observer_state":"not-started","rounds":[{"step":"dispatch","reply_designation":{"state":"unmeasured"}}],"round_rollback":{"nonce":"b".repeat(64),"before":"{}"},"dispatch_intent":{"nonce":"b".repeat(64)},"plan":{}})).expect("stranded rollback");
        let retired_path = root.join(".retired-S-20-1-2");
        let retired_driver = root.join(".retired-S-0-1-2");
        fs::create_dir(&retired_driver).expect("retired driver");
        let lease = root.join(".prepare-S.lock");
        std::os::unix::fs::symlink("missing-target", &lease)
            .expect("lease name without readable target");
        fs::write(root.join(".prepare-orphan.lock"), b"").expect("orphan lease");
        publish_reservation(&retired_path, &json!({"schema":1,"phase":"retired","loop":"alpha","run":"S","worker_uid":3001,"observer_state":"not-started","rounds":[{"step":"dispatch","reply_designation":{"state":"unmeasured"}},{"step":"close"}],"current_retirement":{"reservation_path":{"target":retired_path},"planned_paths":[{"source":root.join("S"),"target":retired_driver},{"source":root.join("shared"),"target":retried}]},"plan":{}})).expect("retired record");
        for (name, phase) in [
            (".census-rewrite-R.json", "pending"),
            (".retire-rewrite-R.json", "pending"),
            (".retire-node-rewrite.json", "pending"),
            (".census-rewrite-S.json", "complete"),
        ] {
            publish_reservation(
                &root.join(name),
                &json!({"schema":1,"phase":phase,"plan":if name == ".retire-node-rewrite.json" {
                    json!({"files":[{"path":reservation_path(&root, "R")},{"path":reservation_path(&root, "T")}]})
                } else {json!({"before":{}})}}),
            )
            .expect("rewrite journal");
        }
        let before = fs::read(reservation_path(&root, "R")).expect("before census");
        admission::set(home, "alpha", true).expect("paused admission");
        let report = run(home, "alpha").expect("census");
        assert_eq!(
            fs::read(reservation_path(&root, "R")).expect("after census"),
            before
        );
        assert_eq!(
            report["reply_designation_readiness"]["rows_without_member"],
            json!({"live":2,"retired":1})
        );
        assert_eq!(
            report["reply_designation_readiness"]["pending_rollback_before_images"],
            1
        );
        assert_eq!(
            report["reply_designation_readiness"]["stranded_rollback_before_images"],
            1
        );
        assert_eq!(report["reply_designation_readiness"]["retained_records"], 3);
        assert!(
            report["reply_designation_readiness"]["retained_bytes"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        assert_eq!(
            report["reply_designation_readiness"]["pending_absence_plans"],
            1
        );
        assert_eq!(
            report["reply_designation_readiness"]["pending_rewrite_transactions"],
            json!({"census":1,"retirement":1,"node_retirement":1,"reply_rows":0})
        );
        let blockers = report["reply_designation_readiness"]["blockers"]
            .as_array()
            .expect("blockers");
        for (kind, run, command) in [
            (
                "pending-absence-plan",
                "R",
                "superloop-lane retire alpha R --confirm-missing-lease --dry-run",
            ),
            (
                "pending-census-rewrite",
                "R",
                "superloop-lane census rewrite alpha R --dry-run",
            ),
            (
                "pending-retirement-rewrite",
                "R",
                "superloop-lane retire rewrite alpha R --dry-run",
            ),
            (
                "pending-node-retirement-rewrite",
                "R",
                "superloop-lane retire rewrite-node alpha --dry-run",
            ),
            (
                "pending-node-retirement-rewrite",
                "T",
                "superloop-lane retire rewrite-node alpha --dry-run",
            ),
        ] {
            assert!(
                blockers.iter().any(|row| row["kind"] == kind
                    && row["run"] == run
                    && row["next_command"] == command
                    && row["apply_command"] == command.replace("--dry-run", "--expect-digest HEX")),
                "missing {kind} for {run}"
            );
        }
        assert!(
            report["reply_designation_readiness"]["rollback_evidence"]
                .as_array()
                .expect("rollback evidence")
                .iter()
                .any(|row| row["kind"] == "rollback-after-dispatch-intent" && row["run"] == "T")
        );
        assert_eq!(
            blockers
                .iter()
                .filter(|row| row["kind"] == "rounds-without-member"
                    && row["run"] == "R"
                    && row["count"] == 2)
                .count(),
            1
        );
        assert_eq!(
            blockers
                .iter()
                .filter(|row| row["kind"] == "rounds-without-member"
                    && row["run"] == "S"
                    && row["count"] == 1)
                .count(),
            1
        );
        assert_eq!(report["admission"]["state"], "paused");
        assert_eq!(
            report["reservations"][0]["identities"]["launcher"]["presence"],
            "present"
        );
        assert_eq!(report["retired_records"][0]["run"], "S");
        assert_eq!(
            report["reservations"][0]["credential_refresh"],
            json!({"state":"measured","reason":"measured","expires_unix":1_900_000_000_u64,
                "refresh_due_unix":1_899_999_400_u64,"evidence_state":"current","refused":null})
        );
        assert_eq!(
            report["retired_records"][0]["credential_refresh"],
            unavailable("unmeasured", "retired")
        );
        assert_eq!(
            report["reservations"][0]["journaled_names"],
            json!([".retired-R-0-4-5", ".retired-R-0-6-7"])
        );
        assert_eq!(
            report["retired_records"][0]["journaled_names"],
            json!([".prepare-S.lock", ".retired-R-0-6-7", ".retired-S-0-1-2"])
        );
        assert_eq!(
            report["reservations"][0]["ambiguous_journaled_names"],
            json!([".retired-R-0-6-7"])
        );
        assert_eq!(
            report["retired_records"][0]["ambiguous_journaled_names"],
            json!([".retired-R-0-6-7"])
        );
        assert!(
            report["skipped_names"]
                .as_array()
                .expect("skipped")
                .contains(&json!(".prepare-orphan.lock"))
        );
        assert!(
            report["skipped_names"]
                .as_array()
                .expect("skipped")
                .iter()
                .any(|name| name == "R")
        );
        publish_reservation(
            &root.join(".retire-node-rewrite.json"),
            &json!({
                "schema":2,"phase":"pending","plan":{"files":[]},
                "manifest":[{"path":reservation_path(&root,"R")},
                    {"path":reservation_path(&root,"T")}]}
            ),
        )
        .expect("schema 2 rewrite journal");
        let schema_two = run(home, "alpha").expect("schema 2 census");
        assert_eq!(
            schema_two["reply_designation_readiness"]["pending_rewrite_transactions"]["node_retirement"],
            1
        );
        assert_eq!(
            schema_two["reply_designation_readiness"]["blockers"]
                .as_array()
                .expect("blockers")
                .iter()
                .filter(|row| row["kind"] == "pending-node-retirement-rewrite")
                .count(),
            2
        );
        let reused_retired = root.join(".retired-R-20-3-4");
        publish_reservation(&reused_retired, &json!({"schema":1,"phase":"retired","loop":"alpha","run":"R","worker_uid":3001,"observer_state":"not-started","current_retirement":{"reservation_path":{"target":reused_retired},"planned_paths":[]},"plan":{}})).expect("retired reuse record");
        let overlap_report = run(home, "alpha").expect("reused live run census");
        let retired_r = overlap_report["retired_records"]
            .as_array()
            .expect("retired rows")
            .iter()
            .find(|row| row["run"] == "R")
            .expect("retired R");
        assert_eq!(
            retired_r["credential_refresh"],
            unavailable("unmeasured", "retired")
        );
        assert_eq!(
            overlap_report["reservations"][0]["credential_refresh"]["expires_unix"],
            1_900_000_000_u64
        );
        let mut vendor_report = crate::credential::fixture_report(1_900_000_000);
        vendor_report.authority_failure = Some(LaneError::input(
            "credential-refresh",
            "fixture vendor refusal",
        ));
        let vendor_evidence = crate::credential::evidence_for_check(
            &Ok(vendor_report),
            false,
            crate::settings::BoxBackend::Codex,
        )
        .expect("vendor refusal evidence");
        crate::credential::publish_evidence(&root.join("R"), &vendor_evidence)
            .expect("vendor refusal publication");
        let vendor_report = run(home, "alpha").expect("vendor refusal census");
        assert_eq!(
            vendor_report["reservations"][0]["credential_refresh"],
            json!({"state":"measured","reason":"measured","expires_unix":1_900_000_000_u64,
                "refresh_due_unix":1_899_999_400_u64,"evidence_state":"refused","refused":"credential-refresh"})
        );
        let source_error = LaneError::input("credential-sign-in", "source cannot be read");
        let failure_evidence = crate::credential::evidence_for_check(
            &Err(source_error),
            false,
            crate::settings::BoxBackend::Codex,
        )
        .expect("failed check evidence");
        crate::credential::publish_evidence(&root.join("R"), &failure_evidence)
            .expect("failed check replaces measurement");
        let failed_check_report = run(home, "alpha").expect("refused check census");
        assert_eq!(
            failed_check_report["reservations"][0]["credential_refresh"],
            json!({"state":"unmeasured","reason":"helper-could-not-measure","expires_unix":null,
                "refresh_due_unix":null,"evidence_state":"refused","refused":"credential-sign-in"})
        );
        assert_eq!(
            failed_check_report["retired_records"]
                .as_array()
                .expect("retired rows")
                .iter()
                .find(|row| row["run"] == "R")
                .expect("retired R")["credential_refresh"],
            unavailable("unmeasured", "retired")
        );
        fs::write(protected.join("credential-refresh.json"), json!({"schema":1,"host":crate::credential::REFRESH_HOST,"state":"published","run_refusals":[]}).to_string()).expect("base evidence shape");
        let historical = run(home, "alpha").expect("historical evidence census");
        assert_eq!(
            historical["reservations"][0]["credential_refresh"],
            json!({
                "state":"unmeasured","reason":"historical-envelope:four-key-run-refusals",
                "expires_unix":null,"refresh_due_unix":null,"evidence_state":"published","refused":null
            })
        );
        let rewrite = root.join(".retire-rewrite-R.json");
        publish_reservation(&rewrite, &json!({"schema":1,"phase":"unknown"}))
            .expect("unknown phase journal");
        assert_eq!(
            run(home, "alpha").expect_err("unknown phase refuses").kind,
            "census-record"
        );
        fs::write(&rewrite, b"malformed").expect("corrupt journal");
        assert_eq!(
            run(home, "alpha")
                .expect_err("malformed journal refuses")
                .kind,
            "census-record"
        );
    }
}
