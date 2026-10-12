//! Report run, home, preservation and retention evidence without changing a run.

use super::{
    LaneError, Path, Plan, Settings, Value, checkpoint, harvest, imports, json, layout, retire,
};
use crate::home;
use nix::fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{FileStat, SFlag, fstat, fstatat};
use nix::unistd::Uid;
use std::io::Read as _;
use std::os::fd::OwnedFd;

fn claim(verdict: &str, reason: &str) -> Value {
    json!({"verdict":verdict,"reason":reason})
}

fn required_verdict(claims: &Value) -> &'static str {
    let Some(claims) = claims.as_object() else {
        return "fail";
    };
    if claims.values().any(|claim| {
        !matches!(
            claim["verdict"].as_str(),
            Some("pass" | "fail" | "unmeasured" | "unknown")
        ) || claim["verdict"] == "fail"
    }) {
        "fail"
    } else if claims
        .values()
        .any(|claim| claim["verdict"] == "unmeasured")
    {
        "unmeasured"
    } else if claims.values().any(|claim| claim["verdict"] == "unknown") {
        "unknown"
    } else {
        "pass"
    }
}

fn home_absent(home_path: &Path) -> Result<bool, LaneError> {
    let parent = home_path
        .parent()
        .ok_or_else(|| LaneError::input("exercise-harvest", "home parent is absent"))?;
    let held = home::pin_parent(parent, Uid::effective().as_raw())?;
    let name = home_path
        .file_name()
        .ok_or_else(|| LaneError::input("exercise-harvest", "home name is absent"))?;
    match openat2(
        &held,
        name,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Err(nix::errno::Errno::ENOENT) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(LaneError::input(
            "exercise-harvest",
            format!("home absence probe refused: {error}"),
        )),
    }
}

pub(super) fn home_descriptor(home_path: &Path) -> Result<Option<OwnedFd>, LaneError> {
    let parent = home_path
        .parent()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "home parent is absent"))?;
    let held = home::pin_parent(parent, Uid::effective().as_raw())?;
    let name = home_path
        .file_name()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "home name is absent"))?;
    match openat2(
        &held,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(nix::errno::Errno::ENOENT) => Ok(None),
        Err(error) => Err(LaneError::input(
            "exercise-home-layout",
            format!("home descriptor refused: {error}"),
        )),
    }
}

fn framed_claim(verdict: &str, reason: &str) -> Value {
    json!({"verdict":verdict,"reason":reason,"frame":"private-namespace"})
}

fn plan_component<'a>(paths: &'a [Value], path: &Path) -> Result<&'a Value, LaneError> {
    let name = path.to_str().ok_or_else(|| {
        LaneError::input("exercise-home-layout-record", "plan component is not UTF-8")
    })?;
    paths
        .iter()
        .find(|row| row.get("path").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| {
            LaneError::input(
                "exercise-home-layout-record",
                format!("plan component {name} has no row"),
            )
        })
}

fn metadata_values(
    actual_uid: u32,
    actual_mode_bits: u32,
    actual_kind: SFlag,
    expected: &Value,
    relative: &Path,
    worker: u64,
) -> Result<Value, LaneError> {
    let uid = expected.get("uid").and_then(Value::as_u64).ok_or_else(|| {
        LaneError::input(
            "exercise-home-layout-record",
            "plan component uid is absent",
        )
    })?;
    let mode = expected
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LaneError::input(
                "exercise-home-layout-record",
                "plan component mode is absent",
            )
        })?;
    let kind = expected
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LaneError::input(
                "exercise-home-layout-record",
                "plan component kind is absent",
            )
        })?;
    let actual_mode = format!("{actual_mode_bits:04o}");
    let kind_name = if actual_kind == SFlag::S_IFDIR {
        "directory"
    } else if actual_kind == SFlag::S_IFREG {
        "file"
    } else if actual_kind == SFlag::S_IFLNK {
        "link"
    } else {
        "other"
    };
    let expected_directory = kind == "directory"
        || kind == "mountpoint"
            && relative != Path::new(".codex/config.toml")
            && relative != Path::new(".codex/AGENTS.md");
    let kind_matches = if expected_directory {
        actual_kind == SFlag::S_IFDIR
    } else {
        actual_kind == SFlag::S_IFREG
    };
    let owner_class = if uid == worker {
        "worker"
    } else if uid == 0 {
        "owner"
    } else {
        "other"
    };
    let matches = u64::from(actual_uid) == uid && actual_mode == mode && kind_matches;
    Ok(
        json!({"verdict":if matches {"pass"} else {"fail"},"uid":actual_uid,"mode":actual_mode,"kind":kind_name,"owner_class":owner_class,"frame":"private-namespace","reason":if matches {"descriptor metadata matches the plan in the private namespace".to_owned()} else {format!("{}: plan uid {uid}, mode {mode}, kind {kind}; observed uid {actual_uid}, mode {actual_mode}, kind {kind_name}",relative.display())}}),
    )
}

fn metadata_observation(
    stat: &FileStat,
    expected: &Value,
    relative: &Path,
    worker: u64,
) -> Result<Value, LaneError> {
    metadata_values(
        stat.st_uid,
        stat.st_mode & 0o7777,
        SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT,
        expected,
        relative,
        worker,
    )
}

fn observe_path(
    home_fd: &OwnedFd,
    relative: &Path,
    home_path: &Path,
    paths: &[Value],
    worker: u64,
) -> Result<Value, LaneError> {
    let mut current = nix::unistd::dup(home_fd).map_err(|error| {
        LaneError::input("exercise-home-layout", format!("home descriptor: {error}"))
    })?;
    if relative.as_os_str().is_empty() {
        let stat = fstat(&current)
            .map_err(|error| LaneError::input("exercise-home-layout", error.to_string()))?;
        return metadata_observation(&stat, plan_component(paths, home_path)?, relative, worker);
    }
    let mut walked = std::path::PathBuf::new();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Ok(framed_claim("fail", "plan path has a non-normal component"));
        };
        walked.push(name);
        let expected = plan_component(paths, &home_path.join(&walked))?;
        let stat = match fstatat(&current, *name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) => {
                return Ok(framed_claim(
                    "fail",
                    &format!(
                        "{}: parent-relative metadata refused: {error}",
                        walked.display()
                    ),
                ));
            }
        };
        let observed = metadata_observation(&stat, expected, &walked, worker)?;
        if observed["verdict"] == "fail" || index + 1 == components.len() {
            return Ok(observed);
        }
        let opened = match openat2(
            &current,
            *name,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
                .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
        ) {
            Ok(fd) => fd,
            Err(error) => {
                let mut refused = observed;
                refused["verdict"] = json!("fail");
                refused["reason"] = json!(format!(
                    "{}: matched component could not be entered: {error}",
                    walked.display()
                ));
                return Ok(refused);
            }
        };
        let pinned = fstat(&opened)
            .map_err(|error| LaneError::input("exercise-home-layout", error.to_string()))?;
        if pinned.st_dev != stat.st_dev
            || pinned.st_ino != stat.st_ino
            || pinned.st_uid != stat.st_uid
            || pinned.st_mode != stat.st_mode
        {
            let mut changed = observed;
            changed["verdict"] = json!("fail");
            changed["reason"] = json!(format!("{} changed before descent", walked.display()));
            return Ok(changed);
        }
        current = opened;
    }
    Ok(framed_claim("fail", "plan path has no component"))
}

pub(super) fn private_path_metadata(
    record: &Value,
    plan: &Plan,
    home_fd: &OwnedFd,
) -> Result<Value, LaneError> {
    let paths = record
        .get("plan")
        .and_then(|plan| plan.get("paths"))
        .and_then(Value::as_array)
        .ok_or_else(|| LaneError::input("exercise-home-layout-record", "plan paths are absent"))?;
    let worker = record
        .get("worker_uid")
        .and_then(Value::as_u64)
        .ok_or_else(|| LaneError::input("exercise-home-layout-record", "worker uid is absent"))?;
    let mut measured = Vec::with_capacity(paths.len());
    for row in paths {
        let name = row.get("path").and_then(Value::as_str).ok_or_else(|| {
            LaneError::input("exercise-home-layout-record", "plan path is absent")
        })?;
        let observation = if let Ok(relative) = Path::new(name).strip_prefix(&plan.home) {
            observe_path(home_fd, relative, &plan.home, paths, worker)?
        } else {
            framed_claim("unknown", "path is outside the home layout boundary")
        };
        measured.push(json!({"path":name,"observation":observation}));
    }
    Ok(json!(measured))
}

fn routing_claim(home_fd: &OwnedFd) -> Value {
    let ssh = match openat2(
        home_fd,
        ".ssh",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(error) => return claim("fail", &format!("routing directory refused: {error}")),
    };
    match checkpoint::directory_names(&ssh, Path::new(".ssh")) {
        Ok(names) if names == ["config"] => claim(
            "pass",
            "routing directory contains only config and no private-key name",
        ),
        Ok(names) => claim(
            "fail",
            &format!("routing directory names differ: {names:?}"),
        ),
        Err(error) => claim("fail", &error.line()),
    }
}

fn signing_claim(home_fd: &OwnedFd) -> Value {
    let file = match openat2(
        home_fd,
        ".gitconfig",
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(error) => return claim("fail", &format!("Git configuration refused: {error}")),
    };
    let mut bytes = Vec::new();
    if let Err(error) = std::fs::File::from(file).take(4097).read_to_end(&mut bytes) {
        return claim("fail", &format!("Git configuration read refused: {error}"));
    }
    if bytes
        == b"[commit]\n\tgpgsign = false\n[user]\n\tname = Lane Worker\n\temail = worker@invalid\n"
    {
        claim("pass", "pinned Git configuration disables signing")
    } else {
        claim(
            "fail",
            "pinned Git configuration differs from the launcher input",
        )
    }
}

fn run_identity(
    record: &Value,
    plan: &Plan,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    let rounds = record["rounds"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-run-identity", "round list is absent"))?;
    let thread = record["thread_id"].as_str();
    let mut steps = Vec::new();
    let mut failed = None;
    let mut first_directory = None;
    for round in rounds {
        let step = round["step"]
            .as_str()
            .ok_or_else(|| LaneError::input("exercise-run-identity", "round step is absent"))?;
        let directory = round["driver_dir"].as_str();
        if round["phase"] != "settled" {
            failed = Some(format!("{step} is not a settled round"));
        }
        if directory.is_none() {
            failed = Some(format!("{step} has no driver directory"));
        }
        if let Some(directory) = directory
            && !Path::new(directory).starts_with(&plan.driver_dir)
        {
            failed = Some(format!("{step} changed driver directory to {directory}"));
        }
        if let Some(directory) = directory {
            if let Some(first) = first_directory {
                if directory != first {
                    failed = Some(format!(
                        "{step} changed driver directory from {first} to {directory}"
                    ));
                }
            } else {
                first_directory = Some(directory);
            }
        }
        steps.push(
            json!({"step":step,"phase":round["phase"],"driver_dir":directory,"thread_id":thread}),
        );
    }
    let rotation = record.get("rotation").cloned().unwrap_or(Value::Null);
    if rotation.is_object() {
        super::rotation::validate_rotation_record(&rotation)?;
    }
    if rotation.is_object() && rotation["old_run"] != run && rotation["new_run"] != run {
        failed = Some(String::from("rotation record does not name this run"));
    }
    let identity = failed.map_or_else(
        || {
            if thread.is_none() && !rotation.is_object() {
                claim(
                    "fail",
                    "run has neither a resumed thread nor a rotation record",
                )
            } else {
                claim(
                    "pass",
                    "one recorded home, driver directory and thread or rotation",
                )
            }
        },
        |reason| claim("fail", &reason),
    );
    let verdict = identity["verdict"].clone();
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"run-identity","home":plan.home,"driver_dir":plan.driver_dir,"steps":steps,"thread_id":thread,"rotation":rotation,"claims":{"identity":identity,"host_thread_canary":claim("unmeasured","host must compare the resumed thread with the run record")},"verdict":verdict,"changed":false}),
    )
}

fn harvest(
    record: &Value,
    plan: &Plan,
    loop_name: &str,
    run: &str,
    measurement: Option<&Value>,
) -> Result<Value, LaneError> {
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(record)?;
    let (agreement, collection) = harvest::harvest_fields(record)?;
    let checkpoint = checkpoints.last();
    let preserved_object = checkpoint
        .zip(
            agreement
                .as_ref()
                .and_then(|agreement| agreement["gate_object"].as_str()),
        )
        .map(|(checkpoint, gate)| harvest::checkpoint_object(checkpoint, gate))
        .transpose()?;
    let index = checkpoint.and_then(|checkpoint| checkpoint["index"].as_u64());
    let agreement_ok = agreement.as_ref().is_some_and(|agreement| {
        agreement["preserved_object"].as_str() == preserved_object.as_deref()
            && agreement["checkpoint_index"].as_u64() == index
            && agreement["preserved_object"] == agreement["gate_object"]
    });
    let collection_ok = collection.as_ref().is_some_and(|collection| {
        collection["state"] == "collected" && collection["checkpoint_index"].as_u64() == index
    });
    let absent = home_absent(&plan.home)?;
    let files = checkpoint
        .and_then(|checkpoint| checkpoint["files"].as_array())
        .cloned()
        .unwrap_or_default();
    let bares = checkpoint
        .and_then(|checkpoint| checkpoint["bares"].as_array())
        .cloned()
        .unwrap_or_default();
    let designated = files.iter().all(|file| {
        file["path"].as_str().is_some_and(|name| {
            ["inbox/", "outbox/", "sources/"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
    });
    let byte_audit = read_audit_claim(measurement, checkpoint)?;
    let seeds = bares
        .iter()
        .map(|bare| json!({"name":bare["name"],"seed":bare["seed"],"lane_object":bare["object"]}))
        .collect::<Vec<_>>();
    let seeded = bares
        .iter()
        .any(|bare| bare["lane_ref"] != "absent" && !bare["seed"].is_null());
    let descent_rows = measurement.and_then(|value| value["seed_descent"].as_array());
    let descent = if !seeded {
        claim("pass", "checkpoint declares no seed object")
    } else if byte_audit["verdict"] != "pass" || descent_rows.is_none() {
        claim("unmeasured", "private seed ancestry audit is incomplete")
    } else if descent_rows.is_some_and(|rows| {
        rows.iter().all(|row| {
            row["lane_object"].is_null() || row["seed"].is_null() || row["descends"] == true
        })
    }) {
        claim(
            "pass",
            "each preserved lane object descends from its declared seed",
        )
    } else {
        claim(
            "fail",
            "a preserved lane object does not descend from its seed",
        )
    };
    let claims = json!({"object_agreement":if agreement_ok {claim("pass","gate and latest preserved checkpoint name one object")} else {claim("fail","complete gate agreement is absent or differs")},"preserved_outputs":if checkpoint.is_some() && designated && bares.iter().any(|bare| bare["lane_ref"] != "absent") {claim("pass","complete checkpoint records designated mailboxes and a shipped bare")} else {claim("fail","complete designated checkpoint is absent")},"collected_after_preservation":if collection_ok && absent {claim("pass","collection record follows checkpoint agreement and home is absent")} else {claim("fail","complete collection or absent home is missing")},"preserved_byte_audit":byte_audit,"seed_descent":descent});
    let verdict = required_verdict(&claims);
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"harvest","home":plan.home,"checkpoint_index":index,"preserved_object":preserved_object,"agreement":agreement,"collection":collection,"preserved_files":files,"preserved_bares":bares,"seeds":seeds,"home_absent":absent,"claims":claims,"verdict":verdict,"changed":false}),
    )
}

/// Recheck every preserved bare and its recorded files from the private frame.
///
/// # Errors
///
/// Refuses malformed checkpoint evidence before reporting an observation.
pub(super) fn audit_preserved(
    record: &Value,
    plan: &Plan,
    settings: &Settings,
    root_fd: &OwnedFd,
    run: &str,
) -> Result<Value, LaneError> {
    let loop_uid = super::recorded_loop_uid(record)?;
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(record)?;
    let Some(checkpoint) = checkpoints.last() else {
        return Ok(
            json!({"frame":"private-namespace","checkpoint_index":null,"files":[],"bares":[],"seed_descent":[],"verdict":"fail","reason":"complete checkpoint is absent"}),
        );
    };
    let index = checkpoint["index"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-harvest-record", "checkpoint index is absent"))?;
    let files = checkpoint["files"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-harvest-record", "file list is absent"))?;
    let bares = checkpoint["bares"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-harvest-record", "bare list is absent"))?;
    let result = (|| {
        if !bares.iter().any(|bare| bare["lane_ref"] != "absent") {
            return Err(LaneError::input(
                "exercise-harvest",
                "checkpoint has no shipped bare to audit",
            ));
        }
        let root = settings
            .runs_root
            .as_deref()
            .ok_or_else(|| LaneError::input("exercise-harvest", "runs root is absent"))?;
        let round_fd = home::pin_loop_round_at(root_fd, root, &plan.driver_dir, loop_uid)?;
        let mut ancestry_rows = Vec::new();
        for bare in bares {
            let name = bare["name"]
                .as_str()
                .ok_or_else(|| LaneError::input("exercise-harvest", "bare name is absent"))?;
            if bare["lane_ref"] == "absent" {
                ancestry_rows.push(
                    json!({"name":name,"seed":bare["seed"],"lane_object":null,"descends":null}),
                );
                continue;
            }
            let object = bare["object"]
                .as_str()
                .ok_or_else(|| LaneError::input("exercise-harvest", "bare object is absent"))?;
            let verified = checkpoint::verify_preserved_copy(
                &round_fd,
                &plan.driver_dir,
                index,
                files,
                name,
                run,
                object,
                loop_uid,
            )?;
            let seed = bare["seed"].as_str();
            if let Some(seed) = seed {
                checkpoint::verify_seed_ref(&verified.fd, &verified.path, name, run, seed)?;
            }
            let descends = seed
                .map(|seed| checkpoint::seed_descends(&verified, seed, object))
                .transpose()?;
            ancestry_rows
                .push(json!({"name":name,"seed":seed,"lane_object":object,"descends":descends}));
        }
        Ok(ancestry_rows)
    })();
    let (verdict, reason, seed_descent) = match result {
        Ok(rows) => (
            "pass",
            String::from("current preserved bytes and bare objects match checkpoint"),
            rows,
        ),
        Err(error) => ("fail", error.line(), Vec::new()),
    };
    Ok(
        json!({"frame":"private-namespace","checkpoint_index":index,"files":files,"bares":bares,"seed_descent":seed_descent,"verdict":verdict,"reason":reason}),
    )
}

fn read_audit_claim(
    measurement: Option<&Value>,
    checkpoint: Option<&Value>,
) -> Result<Value, LaneError> {
    let Some(measurement) = measurement else {
        let reason = if checkpoint.is_some() {
            "preserved bytes were not audited in the private namespace"
        } else {
            "complete checkpoint is absent"
        };
        return Ok(json!({"verdict":"unmeasured","reason":reason,"frame":"unknown"}));
    };
    let fields = measurement.as_object().ok_or_else(|| {
        LaneError::input("exercise-harvest-record", "private audit is not an object")
    })?;
    let index = checkpoint.and_then(|checkpoint| checkpoint["index"].as_u64());
    let expected_index = index.map_or(Value::Null, |value| json!(value));
    let files = checkpoint.map_or_else(|| json!([]), |checkpoint| checkpoint["files"].clone());
    let bares = checkpoint.map_or_else(|| json!([]), |checkpoint| checkpoint["bares"].clone());
    let verdict = fields.get("verdict").and_then(Value::as_str);
    let reason = fields.get("reason").and_then(Value::as_str);
    let descent = fields.get("seed_descent").and_then(Value::as_array);
    let descent_valid = descent.is_some_and(|rows| {
        verdict == Some("fail") && rows.is_empty()
            || rows.len() == bares.as_array().map_or(0, Vec::len)
                && rows
                    .iter()
                    .zip(bares.as_array().into_iter().flatten())
                    .all(|(row, bare)| {
                        row["name"] == bare["name"]
                            && row["seed"] == bare["seed"]
                            && row["lane_object"] == bare["object"]
                            && (if bare["seed"].is_null() || bare["lane_ref"] == "absent" {
                                row["descends"].is_null()
                            } else {
                                row["descends"].is_boolean()
                            })
                    })
    });
    if fields.len() != 7
        || fields.get("frame").and_then(Value::as_str) != Some("private-namespace")
        || fields.get("checkpoint_index") != Some(&expected_index)
        || fields.get("files") != Some(&files)
        || fields.get("bares") != Some(&bares)
        || !descent_valid
        || !matches!(verdict, Some("pass" | "fail"))
        || reason.is_none_or(str::is_empty)
        || verdict == Some("pass")
            && (checkpoint.is_none()
                || bares
                    .as_array()
                    .is_none_or(|bares| !bares.iter().any(|bare| bare["lane_ref"] != "absent")))
    {
        return Err(LaneError::input(
            "exercise-harvest-record",
            "private audit frame or checkpoint evidence differs",
        ));
    }
    Ok(json!({"verdict":verdict,"reason":reason,"frame":"private-namespace"}))
}

#[allow(clippy::too_many_lines)]
fn home_layout(
    record: &Value,
    plan: &Plan,
    loop_name: &str,
    run: &str,
    measurement: &Value,
) -> Result<Value, LaneError> {
    let home_fd = home_descriptor(&plan.home)?;
    home_layout_with_descriptor(record, plan, loop_name, run, measurement, home_fd.as_ref())
}

fn valid_canary_row(row: &Value, key: &str, area: &str) -> bool {
    let observation = &row["observation"];
    let state = observation["state"].as_str();
    let recovery = &row["recovery"];
    let recovery_valid = recovery.as_object().is_some_and(|fields| {
        fields.len() == 4
            && ["name", "state", "residue", "reason"]
                .iter()
                .all(|name| fields.contains_key(*name))
    }) && recovery["name"]
        .as_str()
        .is_some_and(|name| name.ends_with(layout::CANARY))
        && recovery["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
        && match recovery["state"].as_str() {
            Some("absent" | "removed") => recovery["residue"] == false,
            Some("refused") => recovery["residue"].is_boolean() || recovery["residue"].is_null(),
            _ => false,
        };
    let standard_shape = if matches!(state, Some("refused" | "created-removed")) {
        observation.as_object().is_some_and(|fields| {
            fields.len() == 5
                && ["state", "errno", "created", "removed", "residue"]
                    .iter()
                    .all(|name| fields.contains_key(*name))
        }) && observation["created"].as_bool().is_some()
            && observation["removed"].as_bool().is_some()
            && observation["residue"].as_bool().is_some()
            && if state == Some("refused") {
                observation["created"] == false
                    && observation["removed"] == false
                    && observation["residue"] == false
                    && observation["errno"].as_str().is_some()
            } else {
                observation["created"] == true
                    && observation["removed"] == true
                    && observation["residue"] == false
                    && observation["errno"].is_null()
            }
    } else {
        observation.as_object().is_some_and(|fields| {
            [
                "state",
                "created",
                "removed",
                "residue",
                "residue_name",
                "residue_probe",
            ]
            .iter()
            .all(|name| fields.contains_key(*name))
        }) && (observation["created"].is_boolean() || observation["created"].is_null())
            && observation["removed"] == false
            && (observation["residue"].is_boolean() || observation["residue"].is_null())
            && observation["residue_name"] == recovery["name"]
            && observation["residue_probe"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty())
    };
    let supports_pass = (if key == "protected" {
        state == Some("refused")
            && matches!(
                observation["errno"].as_str(),
                Some("EACCES" | "EPERM" | "EROFS")
            )
    } else {
        state == Some("created-removed") && observation["residue"] == false
    }) && matches!(recovery["state"].as_str(), Some("absent" | "removed"));
    row.as_object().is_some_and(|fields| fields.len() == 4)
        && row["area"] == area
        && state.is_some()
        && recovery_valid
        && standard_shape
        && matches!(row["verdict"].as_str(), Some("pass" | "fail"))
        && (row["verdict"] == "pass") == supports_pass
}

#[allow(clippy::too_many_lines)]
fn validate_home_measurement(measurement: &Value, worker: u64) -> Result<(), LaneError> {
    let fields = measurement.as_object().ok_or_else(|| {
        LaneError::input(
            "exercise-home-layout-record",
            "private result is not an object",
        )
    })?;
    let state = fields.get("state").and_then(Value::as_str).ok_or_else(|| {
        LaneError::input(
            "exercise-home-layout-record",
            "private result state is absent",
        )
    })?;
    match state {
        "unmeasured" => {
            if fields.len() != 2
                || fields
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
            {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    "unmeasured result has missing or contradictory claims",
                ));
            }
        }
        "measured" => {
            if fields.len() != 7
                || fields.get("worker_uid").and_then(Value::as_u64) != Some(worker)
                || fields.get("path_frame").and_then(Value::as_str) != Some("private-namespace")
            {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    "measured result has missing keys or another worker",
                ));
            }
            let paths = fields
                .get("path_metadata")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    LaneError::input("exercise-home-layout-record", "path metadata is absent")
                })?;
            if paths.iter().any(|row| {
                row.as_object().is_none_or(|fields| fields.len() != 2)
                    || row.get("path").and_then(Value::as_str).is_none()
                    || row.get("observation").is_none_or(|observation| {
                        observation.get("frame").and_then(Value::as_str)
                            != Some("private-namespace")
                            || !matches!(
                                observation.get("verdict").and_then(Value::as_str),
                                Some("pass" | "fail" | "unknown")
                            )
                            || observation.get("reason").and_then(Value::as_str).is_none()
                            || observation.get("verdict").and_then(Value::as_str) == Some("pass")
                                && (observation.get("uid").and_then(Value::as_u64).is_none()
                                    || observation.get("mode").and_then(Value::as_str).is_none()
                                    || observation.get("kind").and_then(Value::as_str).is_none()
                                    || observation
                                        .get("owner_class")
                                        .and_then(Value::as_str)
                                        .is_none())
                    })
            }) {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    "path metadata is malformed or lacks its private frame",
                ));
            }
            for (key, expected) in [
                (
                    "protected",
                    &["fixed-input", "routing", "sign-in-source", "preserved"][..],
                ),
                ("writable", &["scratch", "outbox"][..]),
            ] {
                let rows = fields.get(key).and_then(Value::as_array).ok_or_else(|| {
                    LaneError::input(
                        "exercise-home-layout-record",
                        format!("{key} claim is absent"),
                    )
                })?;
                if rows.len() != expected.len()
                    || rows
                        .iter()
                        .zip(expected)
                        .any(|(row, area)| !valid_canary_row(row, key, area))
                {
                    return Err(LaneError::input(
                        "exercise-home-layout-record",
                        format!("{key} claims are malformed or contradictory"),
                    ));
                }
            }
            let no_copy = fields.get("no_copy").ok_or_else(|| {
                LaneError::input("exercise-home-layout-record", "no_copy claim is absent")
            })?;
            let no_copy_verdict = no_copy.get("verdict").and_then(Value::as_str);
            if !matches!(no_copy_verdict, Some("pass" | "fail"))
                || no_copy.get("reason").and_then(Value::as_str).is_none()
                || (no_copy_verdict == Some("pass")
                    && (!no_copy
                        .get("extra_paths")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                        || no_copy.get("method").and_then(Value::as_str).is_none()))
                || (no_copy_verdict == Some("fail")
                    && no_copy
                        .get("extra_paths")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty))
            {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    "no_copy claim is malformed",
                ));
            }
        }
        _ => {
            return Err(LaneError::input(
                "exercise-home-layout-record",
                "private result state is unknown",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn home_layout_with_descriptor(
    record: &Value,
    plan: &Plan,
    loop_name: &str,
    run: &str,
    measurement: &Value,
    home_fd: Option<&OwnedFd>,
) -> Result<Value, LaneError> {
    let paths = record["plan"]["paths"]
        .as_array()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "plan paths are absent"))?;
    let worker = record["worker_uid"]
        .as_u64()
        .ok_or_else(|| LaneError::input("exercise-home-layout", "worker UID is absent"))?;
    u32::try_from(worker)
        .map_err(|_| LaneError::input("exercise-home-layout", "worker UID is out of range"))?;
    validate_home_measurement(measurement, worker)?;
    let measured = measurement["state"] == "measured";
    let private_paths = if measured {
        let rows = measurement["path_metadata"].as_array().ok_or_else(|| {
            LaneError::input("exercise-home-layout-record", "path metadata is absent")
        })?;
        if rows.len() != paths.len() {
            return Err(LaneError::input(
                "exercise-home-layout-record",
                "path metadata count differs from the plan",
            ));
        }
        Some(rows)
    } else {
        None
    };
    let mut rows = Vec::new();
    let mut path_failed = false;
    for (index, path) in paths.iter().enumerate() {
        let name = path["path"]
            .as_str()
            .ok_or_else(|| LaneError::input("exercise-home-layout", "plan path name is absent"))?;
        let uid = path["uid"]
            .as_u64()
            .ok_or_else(|| LaneError::input("exercise-home-layout", "plan path owner is absent"))?;
        let mode = path["mode"]
            .as_str()
            .ok_or_else(|| LaneError::input("exercise-home-layout", "plan path mode is absent"))?;
        let kind = path.get("kind").and_then(Value::as_str).ok_or_else(|| {
            LaneError::input("exercise-home-layout-record", "plan path kind is absent")
        })?;
        if !matches!(kind, "directory" | "file" | "mountpoint") {
            return Err(LaneError::input(
                "exercise-home-layout-record",
                format!("plan path kind differs at {name}"),
            ));
        }
        let relative = Path::new(name).strip_prefix(&plan.home).ok();
        let harvest_class = if relative.is_none() {
            "driver-evidence"
        } else if [".local/inbox", ".local/outbox", ".local/sources"]
            .iter()
            .any(|part| {
                relative.is_some_and(|path| path == Path::new(part) || path.starts_with(part))
            })
        {
            "preserve"
        } else if relative
            .is_some_and(|path| path == Path::new(".local/bin") || path.starts_with(".local/bin"))
        {
            "launcher-input"
        } else {
            "exclude"
        };
        let observation = if let Some(private_paths) = private_paths {
            let private = &private_paths[index];
            if private.get("path").and_then(Value::as_str) != Some(name) {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    format!("private path metadata differs at {name}"),
                ));
            }
            let observation = private.get("observation").ok_or_else(|| {
                LaneError::input("exercise-home-layout-record", "path observation is absent")
            })?;
            if relative.is_some() && observation["verdict"] == "unknown"
                || relative.is_none() && observation["verdict"] != "unknown"
            {
                return Err(LaneError::input(
                    "exercise-home-layout-record",
                    format!("private path boundary differs at {name}"),
                ));
            }
            if relative.is_some() && observation["verdict"] == "pass" {
                let expected_class = if uid == worker { "worker" } else { "owner" };
                let expected_kind = if kind == "directory"
                    || kind == "mountpoint"
                        && relative != Some(Path::new(".codex/config.toml"))
                        && relative != Some(Path::new(".codex/AGENTS.md"))
                {
                    "directory"
                } else {
                    "file"
                };
                if observation["uid"] != uid
                    || observation["mode"] != mode
                    || observation["kind"] != expected_kind
                    || observation["owner_class"] != expected_class
                {
                    return Err(LaneError::input(
                        "exercise-home-layout-record",
                        format!("private path pass contradicts plan at {name}"),
                    ));
                }
            }
            observation.clone()
        } else if relative.is_some() {
            claim(
                "unmeasured",
                measurement["reason"]
                    .as_str()
                    .unwrap_or("private measurement is unavailable"),
            )
        } else {
            claim("unknown", "path is outside the home layout boundary")
        };
        if observation["verdict"] == "fail" {
            path_failed = true;
        }
        rows.push(json!({"path":name,"uid":uid,"mode":mode,"harvest_class":harvest_class,"observation":observation}));
    }
    let designated = [".local/inbox", ".local/outbox", ".local/sources"];
    let present = designated.iter().all(|name| {
        rows.iter()
            .any(|row| row["path"] == plan.home.join(name).display().to_string())
    });
    let routing = home_fd.map_or_else(|| claim("unmeasured", "home was collected"), routing_claim);
    let signing = home_fd.map_or_else(|| claim("unmeasured", "home was collected"), signing_claim);
    let (_, mut checkpoints, _) = checkpoint::checkpoint_fields(record)?;
    let checkpoint = checkpoints.pop();
    let boundary = checkpoint.map_or_else(
        || {
            claim(
                "unknown",
                "no checkpoint exists to audit the harvest boundary",
            )
        },
        |checkpoint| {
            if checkpoint["files"].as_array().is_some_and(|files| {
                files.iter().all(|file| {
                    file["path"].as_str().is_some_and(|name| {
                        ["inbox/", "outbox/", "sources/"]
                            .iter()
                            .any(|prefix| name.starts_with(prefix))
                    })
                })
            }) {
                claim(
                    "pass",
                    "checkpoint names only designated local output files",
                )
            } else {
                claim(
                    "fail",
                    "checkpoint includes an omitted or extra harvested path",
                )
            }
        },
    );
    let mut path_claim = if !present || path_failed {
        claim("fail", "a designated path or observed metadata differs")
    } else if !measured {
        claim(
            "unmeasured",
            "private namespace metadata could not be observed",
        )
    } else {
        claim(
            "pass",
            "designated paths and private namespace metadata match the plan",
        )
    };
    path_claim["frame"] = json!("private-namespace");
    let reason = measurement["reason"]
        .as_str()
        .unwrap_or("measurement is unavailable");
    let measured_claim = |rows: &Value, success: &str| {
        if !measured {
            claim("unmeasured", reason)
        } else if rows
            .as_array()
            .is_some_and(|rows| !rows.is_empty() && rows.iter().all(|row| row["verdict"] == "pass"))
        {
            claim("pass", success)
        } else {
            claim("fail", "a worker canary differed from the planned access")
        }
    };
    let protected = measured_claim(
        &measurement["protected"],
        "worker writes to fixed inputs, sign-in source and preservation refused",
    );
    let writable = measured_claim(
        &measurement["writable"],
        "worker scratch and outbox writes succeeded and their canaries were removed",
    );
    let no_copy = if measured {
        measurement["no_copy"].clone()
    } else {
        claim("unmeasured", reason)
    };
    let canaries = if measured {
        measurement.clone()
    } else {
        let row = |area: &str, path: &str| json!({"area":area,"observation":{"state":"unmeasured","reason":reason},"recovery":{"name":format!("{path}/{}", layout::CANARY),"state":"unmeasured","residue":null,"reason":reason},"verdict":"unmeasured"});
        json!({"state":"unmeasured","reason":reason,"protected":[row("fixed-input",".local/inbox"),row("routing",".ssh"),row("sign-in-source",&format!(".config/loops/{loop_name}/lanes/codex")),row("preserved",&format!("{run}/preserved"))],"writable":[row("scratch",".cache/work"),row("outbox",".local/outbox")]})
    };
    let claims = json!({"path_plan":path_claim,"ssh_routing_no_key":routing,"signing_disabled":signing,"protected_write_denied":protected,"scratch_outbox_write_accepted":writable,"no_sign_in_or_session_copy":no_copy,"identity_canary":if worker == 0 {claim("fail","owner and worker UIDs are equal")} else {claim("pass","owner and worker UIDs differ in the private plan")},"harvest_boundary":boundary});
    let verdict = required_verdict(&claims);
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"home-layout","worker_uid":worker,"paths":rows,"canaries":canaries,"claims":claims,"verdict":verdict,"changed":false}),
    )
}

fn rotation(
    record: &Value,
    settings: &Settings,
    loop_name: &str,
    run: &str,
) -> Result<Value, LaneError> {
    let marks = imports::validated(record)?;
    let kept = settings.retention == "keep";
    let evidence = !marks.is_empty();
    let refusal = if evidence {
        retire::refuse_pending_collection(record)
            .and_then(|()| retire::refuse_import_evidence(record))
            .err()
    } else {
        None
    };
    let observed = refusal
        .as_ref()
        .is_some_and(|error| error.kind == "retire-import-evidence");
    if record["rotation"].is_object() {
        super::rotation::validate_rotation_record(&record["rotation"])?;
    }
    let context = record["rotation"]["context"].clone();
    Ok(
        json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"rotation","retention":settings.retention,"import_marks":marks,"context":context,"claims":{"default_keep":if kept {claim("pass","retention is keep") } else {claim("fail","retention differs from keep")},"import_evidence_prune_refusal":if observed {claim("pass","retire guard refused marked import evidence under the mailbox lock") } else if evidence {claim("fail","retire guard did not refuse marked import evidence") } else {claim("unmeasured","mark an imported checkpoint to measure the retire guard")},"use_window_threshold_stop_time":claim("unknown","context state is unknown or host measurement is absent")},"verdict":if !kept || evidence && !observed {"fail"} else if observed {"pass"} else {"unmeasured"},"changed":false}),
    )
}

/// Measure a named acceptance case from protected evidence.
///
/// # Errors
///
/// Refuses malformed records or an unknown case.
#[allow(clippy::too_many_arguments)]
pub(in crate::launch) fn measure(
    _owner_home: &Path,
    plan: &Plan,
    settings: &Settings,
    record: &Value,
    loop_name: &str,
    run: &str,
    case: &str,
    measurement: Option<&Value>,
    _root_fd: &OwnedFd,
) -> Result<Value, LaneError> {
    match case {
        "harvest" => harvest(record, plan, loop_name, run, measurement),
        "run-identity" => run_identity(record, plan, loop_name, run),
        "home-layout" => home_layout(
            record,
            plan,
            loop_name,
            run,
            measurement
                .ok_or_else(|| LaneError::input("exercise-home-layout", "measurement is absent"))?,
        ),
        "rotation" => rotation(record, settings, loop_name, run),
        _ => Err(LaneError::input("exercise-case", "case is unknown")),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::Command;

    fn fixture_command(command: &mut Command) -> Vec<u8> {
        let output = command.output().expect("fixture command");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn secure_fixture(path: &Path) {
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("fixture mode");
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("fixture directory") {
                secure_fixture(&entry.expect("fixture entry").path());
            }
        }
    }

    fn fixture_manifest(root: &Path, directory: &Path, files: &mut Vec<Value>) {
        for entry in std::fs::read_dir(directory).expect("fixture directory") {
            let entry = entry.expect("fixture entry");
            let path = entry.path();
            if entry.file_type().expect("fixture type").is_dir() {
                fixture_manifest(root, &path, files);
            } else {
                let digest = fixture_command(Command::new("/usr/bin/sha256sum").arg(&path));
                let sha256 = std::str::from_utf8(&digest[..64]).expect("digest");
                files.push(json!({"path":path.strip_prefix(root).expect("relative").to_str().expect("UTF-8"),"size":entry.metadata().expect("metadata").len(),"sha256":sha256}));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn collected_preserved_fixture() -> (tempfile::TempDir, Plan, Settings, Value, PathBuf) {
        let fixture = tempfile::TempDir::new_in("/tmp").expect("fixture");
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700))
            .expect("fixture owner mode");
        let root = fixture.path().join("runs");
        let driver = root.join("R");
        let preserved = driver.join("preserved/1");
        let sources = preserved.join("sources");
        std::fs::create_dir_all(&sources).expect("preserved sources");
        std::fs::create_dir(preserved.join("inbox")).expect("inbox");
        std::fs::create_dir(preserved.join("outbox")).expect("outbox");
        let bare = sources.join("tools.git");
        fixture_command(
            Command::new("/usr/bin/git")
                .args(["init", "-q", "--bare"])
                .arg(&bare),
        );
        let work = fixture.path().join("work");
        fixture_command(Command::new("/usr/bin/git").args(["init", "-q"]).arg(&work));
        std::fs::write(work.join("note"), b"preserved commit\n").expect("note");
        fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .args(["add", "note"]),
        );
        fixture_command(Command::new("/usr/bin/git").arg("-C").arg(&work).args([
            "-c",
            "user.name=Worker",
            "-c",
            "user.email=worker@invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ]));
        let seed = String::from_utf8(fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .args(["rev-parse", "HEAD"]),
        ))
        .expect("seed object");
        std::fs::write(work.join("note"), b"preserved lane commit\n").expect("lane note");
        fixture_command(Command::new("/usr/bin/git").arg("-C").arg(&work).args([
            "-c",
            "user.name=Worker",
            "-c",
            "user.email=worker@invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qam",
            "lane",
        ]));
        fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .arg("push")
                .arg(&bare)
                .arg("HEAD:refs/heads/lane/R"),
        );
        fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .arg("push")
                .arg(&bare)
                .arg(format!("{}:refs/seeds/tools", seed.trim())),
        );
        fixture_command(Command::new("/usr/bin/git").arg("-C").arg(&bare).args([
            "symbolic-ref",
            "HEAD",
            "refs/heads/lane/R",
        ]));
        let object = String::from_utf8(fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .args(["rev-parse", "HEAD"]),
        ))
        .expect("object");
        secure_fixture(&root);
        let mut files = Vec::new();
        fixture_manifest(&preserved, &preserved, &mut files);
        let object = object.trim();
        let mut plan = plan();
        plan.home = fixture.path().join("lane-alpha-R");
        plan.driver_dir = driver;
        let settings = Settings {
            runs_root: Some(root),
            backend_argv: std::collections::BTreeMap::new(),
            driver_argv: Vec::new(),
            entry_bin: None,
            driver_bin: None,
            image_digest: None,
            template_dir: None,
            resources: None,
            socket_dir: None,
            vendor_hosts: std::collections::BTreeMap::new(),
            sandbox_mode: String::new(),
            context_threshold: None,
            retention: String::from("keep"),
            source: String::new(),
        };
        let loop_uid = Uid::effective().as_raw();
        let namespace_owner = u32::from(loop_uid == 0);
        assert_ne!(namespace_owner, loop_uid);
        let paths = json!([
            {"path":plan.home,"uid":namespace_owner,"gid":loop_uid,"kind":"directory","mode":"0750"},
            {"path":plan.driver_dir,"uid":loop_uid,"gid":loop_uid,"kind":"directory","mode":"0700"}
        ]);
        let record = json!({"loop":"alpha","run":"R","phase":"settled","plan":{"home":plan.home,"driver_dir":plan.driver_dir,"paths":paths},"checkpoints":[{"index":1,"instant_unix_ns":1,"round_after":"dispatch","files":files,"bares":[{"name":"tools","declared":true,"seed":seed.trim(),"lane_ref":"present","object":object}]}],"checkpoint_attempts":[],"attempts_omitted":0,"harvest_agreement":{"checkpoint_index":1,"preserved_object":object,"gate_object":object,"instant_unix_ns":2},"collection":{"checkpoint_index":1,"state":"collected","instant_unix_ns":3,"planned":["."],"writable_collected_first":null,"remaining":[],"refusal":null,"component":null,"token":"a".repeat(32),"parent_identity":{"device":1,"inode":1},"home_identity":{"device":1,"inode":2}}});
        (fixture, plan, settings, record, bare)
    }

    pub fn mixed_preserved_fixture() -> (tempfile::TempDir, Plan, Settings, Value, PathBuf) {
        let (fixture, plan, settings, mut record, shipped) = collected_preserved_fixture();
        let snapshot = plan.driver_dir.join("preserved/1");
        let unborn = snapshot.join("sources/unborn.git");
        fixture_command(
            Command::new("/usr/bin/git")
                .args(["init", "-q", "--bare"])
                .arg(&unborn),
        );
        secure_fixture(settings.runs_root.as_deref().expect("runs root"));
        let mut files = Vec::new();
        fixture_manifest(&snapshot, &snapshot, &mut files);
        record["checkpoints"][0]["files"] = json!(files);
        record["checkpoints"][0]["bares"]
            .as_array_mut()
            .expect("bare rows")
            .push(json!({"name":"unborn","declared":true,"seed":null,"lane_ref":"absent","object":null}));
        (fixture, plan, settings, record, shipped)
    }

    fn plan() -> Plan {
        Plan {
            home: PathBuf::from("~/lane-alpha-R"),
            driver_dir: PathBuf::from("~/runs/R"),
            letter: PathBuf::from("~/lane-alpha-R/.local/inbox/dispatch.md"),
            document: json!({}),
        }
    }

    /// ´test:unit:run-identity-names-a-changed-driver-directory´
    #[test]
    fn run_identity_names_a_changed_driver_directory() {
        let record = json!({"thread_id":"thread-1","rounds":[{"step":"dispatch","phase":"settled","driver_dir":"~/runs/R/dispatch"},{"step":"review","phase":"settled","driver_dir":"~/runs/other/review"}]});
        let report = run_identity(&record, &plan(), "alpha", "R").expect("identity report");
        assert_eq!(report["verdict"], "fail");
        assert!(
            report["claims"]["identity"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("review changed driver directory"))
        );
        let drift = json!({"thread_id":"thread-1","rounds":[{"step":"dispatch","phase":"settled","driver_dir":"~/runs/R/dispatch"},{"step":"review","phase":"settled","driver_dir":"~/runs/R/review"}]});
        assert_eq!(
            run_identity(&drift, &plan(), "alpha", "R").expect("same-root drift")["verdict"],
            "fail"
        );
        let same = json!({"thread_id":"thread-1","rounds":[{"step":"dispatch","phase":"settled","driver_dir":"~/runs/R/dispatch"},{"step":"review","phase":"settled","driver_dir":"~/runs/R/dispatch"}]});
        assert_eq!(
            run_identity(&same, &plan(), "alpha", "R").expect("stable identity")["verdict"],
            "pass"
        );
    }

    /// ´test:unit:home-layout-collected-run-names-unmeasured-canaries´
    #[test]
    fn home_layout_collected_run_names_unmeasured_canaries() {
        let fixture = tempfile::tempdir().expect("fixture");
        let mut plan = plan();
        plan.home = fixture.path().join("lane-alpha-R");
        let worker = Uid::effective().as_raw() + 1;
        let paths: Vec<_> = [".local/inbox", ".local/outbox", ".local/sources"]
            .iter()
            .map(|name| json!({"path":plan.home.join(name),"uid":worker,"mode":"0750","kind":"directory"}))
            .collect();
        let record = json!({"worker_uid":worker,"plan":{"paths":paths},"checkpoints":[],"checkpoint_attempts":[],"attempts_omitted":0});
        let measurement = json!({"state":"unmeasured","reason":"home was collected"});
        let report = home_layout_with_descriptor(&record, &plan, "alpha", "R", &measurement, None)
            .expect("collected report");
        assert_eq!(report["verdict"], "unmeasured");
        assert_eq!(
            report["claims"]["protected_write_denied"]["verdict"],
            "unmeasured"
        );
        assert_eq!(
            report["claims"]["protected_write_denied"]["reason"],
            "home was collected"
        );
        assert_eq!(
            report["claims"]["scratch_outbox_write_accepted"]["verdict"],
            "unmeasured"
        );
        assert_eq!(
            report["canaries"]["protected"]
                .as_array()
                .expect("planned protected canaries")
                .len(),
            4
        );
        assert_eq!(
            report["canaries"]["writable"]
                .as_array()
                .expect("planned writable canaries")
                .len(),
            2
        );
        for (key, expected) in [
            (
                "protected",
                &[
                    ("fixed-input", ".local/inbox"),
                    ("routing", ".ssh"),
                    ("sign-in-source", ".config/loops/alpha/lanes/codex"),
                    ("preserved", "R/preserved"),
                ][..],
            ),
            (
                "writable",
                &[("scratch", ".cache/work"), ("outbox", ".local/outbox")][..],
            ),
        ] {
            for (row, (area, path)) in report["canaries"][key]
                .as_array()
                .expect("planned canary rows")
                .iter()
                .zip(expected)
            {
                assert_eq!(row["area"], *area);
                assert_eq!(
                    row["recovery"]["name"],
                    format!("{path}/{}", layout::CANARY)
                );
                assert_eq!(row["observation"]["state"], "unmeasured");
                assert_eq!(row["observation"]["reason"], "home was collected");
                assert_eq!(row["recovery"]["state"], "unmeasured");
                assert_eq!(row["recovery"]["reason"], "home was collected");
                assert_eq!(row["verdict"], "unmeasured");
            }
        }
    }

    /// ´test:unit:harvest-case-private-audit-verifies-collected-preservation´
    #[test]
    fn harvest_case_private_audit_verifies_collected_preservation() {
        let (_fixture, plan, settings, record, bare) = collected_preserved_fixture();
        let root_fd: OwnedFd = std::fs::File::open(settings.runs_root.as_ref().expect("root"))
            .expect("held runs root")
            .into();
        let loop_uid = record["plan"]["paths"][1]["uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .expect("fixture loop UID");
        let namespace_owner = record["plan"]["paths"][0]["uid"]
            .as_u64()
            .and_then(|uid| u32::try_from(uid).ok())
            .expect("fixture namespace owner");
        assert_ne!(namespace_owner, loop_uid);
        assert_eq!(
            super::super::recorded_loop_uid(&record).expect("shared loop identity"),
            loop_uid
        );
        let mut wrong_owner_row = record.clone();
        wrong_owner_row["plan"]["paths"][1]["uid"] = json!(namespace_owner);
        assert_eq!(
            super::super::recorded_loop_uid(&wrong_owner_row)
                .expect_err("driver owner must agree with home group")
                .kind,
            "loop-identity"
        );
        let error = audit_preserved(&wrong_owner_row, &plan, &settings, &root_fd, "R")
            .expect_err("private harvest audit refuses conflicting owner row");
        assert_eq!(error.kind, "loop-identity");
        assert_eq!(error.status, 2);
        assert_eq!(
            home::pin_loop_round_at(
                &root_fd,
                settings.runs_root.as_deref().expect("runs root"),
                &plan.driver_dir,
                namespace_owner,
            )
            .expect_err("namespace owner must not pin the loop directory")
            .kind,
            "unsafe-path"
        );
        let audited =
            audit_preserved(&record, &plan, &settings, &root_fd, "R").expect("private-frame audit");
        assert_eq!(audited["frame"], "private-namespace");
        assert_eq!(audited["verdict"], "pass", "{audited}");
        let report =
            harvest(&record, &plan, "alpha", "R", Some(&audited)).expect("collected harvest case");
        assert_eq!(report["verdict"], "pass");
        assert_eq!(report["claims"]["seed_descent"]["verdict"], "pass");
        assert_eq!(
            report["seeds"][0]["seed"],
            record["checkpoints"][0]["bares"][0]["seed"]
        );
        assert_eq!(
            report["claims"]["preserved_byte_audit"]["frame"],
            "private-namespace"
        );
        let old = harvest(&record, &plan, "alpha", "R", None).expect("old unmeasured case");
        assert_eq!(
            old["claims"]["preserved_byte_audit"]["verdict"],
            "unmeasured"
        );
        let description = bare.join("description");
        let mut changed_bytes = std::fs::read(&description).expect("preserved description");
        changed_bytes[0] ^= 1;
        std::fs::write(&description, changed_bytes).expect("change preserved byte");
        let changed = audit_preserved(&record, &plan, &settings, &root_fd, "R")
            .expect("changed private-frame audit");
        assert_eq!(changed["verdict"], "fail");
        assert!(
            changed["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("description")),
            "{changed}"
        );
        let failed =
            harvest(&record, &plan, "alpha", "R", Some(&changed)).expect("changed harvest case");
        assert_eq!(failed["verdict"], "fail");
        let mut host = audited.clone();
        host["frame"] = json!("host");
        assert_eq!(
            harvest(&record, &plan, "alpha", "R", Some(&host))
                .expect_err("host-framed pass")
                .kind,
            "exercise-harvest-record"
        );
        let mut contrary = audited;
        contrary["files"] = json!([]);
        assert_eq!(
            harvest(&record, &plan, "alpha", "R", Some(&contrary))
                .expect_err("pass contradicts checkpoint")
                .kind,
            "exercise-harvest-record"
        );
    }

    /// ´test:unit:harvest-mixed-shipped-and-unborn-bares-skips-unborn-copy´
    #[test]
    fn harvest_mixed_shipped_and_unborn_bares_skips_unborn_copy() {
        let (_fixture, plan, settings, mut record, _bare) = collected_preserved_fixture();
        let preserved = plan.driver_dir.join("preserved/1");
        let unborn = preserved.join("sources/unborn.git");
        fixture_command(
            Command::new("/usr/bin/git")
                .args(["init", "-q", "--bare"])
                .arg(&unborn),
        );
        fixture_command(Command::new("/usr/bin/git").arg("-C").arg(&unborn).args([
            "symbolic-ref",
            "HEAD",
            "refs/heads/lane/R",
        ]));
        secure_fixture(settings.runs_root.as_deref().expect("runs root"));
        let mut files = Vec::new();
        fixture_manifest(&preserved, &preserved, &mut files);
        record["checkpoints"][0]["files"] = json!(files);
        record["checkpoints"][0]["bares"]
            .as_array_mut()
            .expect("bare rows")
            .push(json!({"name":"unborn","declared":true,"seed":null,"lane_ref":"absent","object":null}));
        let gate = record["checkpoints"][0]["bares"][0]["object"]
            .as_str()
            .expect("shipped object")
            .to_owned();
        assert_eq!(
            harvest::checkpoint_object(&record["checkpoints"][0], &gate)
                .expect("shipped bare selects gate object"),
            gate
        );
        let root_fd: OwnedFd = std::fs::File::open(settings.runs_root.as_ref().expect("root"))
            .expect("held runs root")
            .into();
        let audited = audit_preserved(&record, &plan, &settings, &root_fd, "R")
            .expect("audit shipped bare and skip unborn bare");
        assert_eq!(audited["verdict"], "pass", "{audited}");
        assert_eq!(audited["seed_descent"][1]["lane_object"], Value::Null);
        let report =
            harvest(&record, &plan, "alpha", "R", Some(&audited)).expect("mixed-bare harvest case");
        assert_eq!(report["verdict"], "pass", "{report}");
        record["checkpoints"][0]["bares"][0]["lane_ref"] = json!("absent");
        record["checkpoints"][0]["bares"][0]["object"] = Value::Null;
        assert_eq!(
            harvest::checkpoint_object(&record["checkpoints"][0], &gate)
                .expect_err("no shipped bare cannot be harvested")
                .kind,
            "harvest-checkpoint"
        );
    }

    /// ´test:unit:harvest-case-reports-foreign-seed-as-failed-descent´
    #[test]
    #[allow(clippy::literal_string_with_formatting_args)]
    fn harvest_case_reports_foreign_seed_as_failed_descent() {
        let (fixture, plan, settings, mut record, bare) = collected_preserved_fixture();
        let work = fixture.path().join("work");
        let tree = String::from_utf8(fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .args(["rev-parse", "HEAD^{tree}"]),
        ))
        .expect("tree object");
        let foreign = String::from_utf8(fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .args(["commit-tree", tree.trim(), "-m", "foreign"])
                .env("GIT_AUTHOR_NAME", "Fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@invalid")
                .env("GIT_COMMITTER_NAME", "Fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@invalid"),
        ))
        .expect("foreign object");
        fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .arg("push")
                .arg(&bare)
                .arg(format!("{}:refs/heads/foreign", foreign.trim())),
        );
        fixture_command(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&work)
                .arg("push")
                .arg(&bare)
                .arg(format!("+{}:refs/seeds/tools", foreign.trim())),
        );
        record["checkpoints"][0]["bares"][0]["seed"] = json!(foreign.trim());
        let preserved = plan.driver_dir.join("preserved/1");
        secure_fixture(&preserved);
        let mut files = Vec::new();
        fixture_manifest(&preserved, &preserved, &mut files);
        record["checkpoints"][0]["files"] = json!(files);
        let root_fd: OwnedFd = std::fs::File::open(settings.runs_root.as_ref().expect("root"))
            .expect("held runs root")
            .into();
        let audited =
            audit_preserved(&record, &plan, &settings, &root_fd, "R").expect("private seed audit");
        assert_eq!(audited["verdict"], "pass", "{audited}");
        assert_eq!(audited["seed_descent"][0]["descends"], false);
        let report =
            harvest(&record, &plan, "alpha", "R", Some(&audited)).expect("foreign seed report");
        assert_eq!(report["claims"]["seed_descent"]["verdict"], "fail");
        assert_eq!(report["verdict"], "fail");
    }

    /// ´test:unit:production-plan-private-metadata-compares-owner-and-worker-in-one-frame´
    #[test]
    #[allow(clippy::too_many_lines)]
    fn production_plan_private_metadata_compares_owner_and_worker_in_one_frame() {
        let fixture = tempfile::tempdir().expect("fixture");
        let settings = Settings {
            sandbox_mode: String::from("danger-full-access"),
            runs_root: None,
            backend_argv: std::collections::BTreeMap::from([(
                "codex".into(),
                vec!["/usr/libexec/superloop/codex".into()],
            )]),
            driver_argv: Vec::new(),
            entry_bin: Some(fixture.path().join("entry")),
            driver_bin: Some(fixture.path().join("driver")),
            image_digest: Some(format!("sha256:{}", "a".repeat(64))),
            template_dir: Some(fixture.path().join("templates")),
            resources: Some(crate::settings::Resources {
                memory_bytes: 2_147_483_648,
                pids_max: 128,
                cpu_shares: 512,
            }),
            socket_dir: Some(fixture.path().join("sockets")),
            vendor_hosts: std::collections::BTreeMap::new(),
            context_threshold: None,
            retention: String::from("keep"),
            source: String::new(),
        };
        let registry = json!({"name":"alpha","uid":2001,"runs_root":fixture.path()});
        let plan = Plan::build(
            fixture.path(),
            "alpha",
            "R",
            &settings,
            &registry,
            loop_home::registry::WorkerBlock {
                base: 3000,
                count: 2,
            },
            (0, 0),
        )
        .expect("production planner");
        let paths = plan.document["paths"].as_array().expect("planned paths");
        let mut private_paths = Vec::new();
        let mut owner_rows = 0;
        let mut worker_rows = 0;
        for row in paths {
            let name = row["path"].as_str().expect("plan path");
            let observation = Path::new(name).strip_prefix(&plan.home).map_or_else(
                |_| framed_claim("unknown", "path is outside the home layout boundary"),
                |relative| {
                    let uid = row["uid"].as_u64().expect("plan uid");
                    if uid == 0 {
                        owner_rows += 1;
                    } else if uid == 3000 {
                        worker_rows += 1;
                    }
                    let mode = u32::from_str_radix(row["mode"].as_str().expect("mode"), 8)
                        .expect("octal mode");
                    let kind = if row["kind"] == "directory"
                        || row["kind"] == "mountpoint"
                            && relative != Path::new(".codex/config.toml")
                            && relative != Path::new(".codex/AGENTS.md")
                    {
                        SFlag::S_IFDIR
                    } else {
                        SFlag::S_IFREG
                    };
                    metadata_values(
                        u32::try_from(uid).expect("uid"),
                        mode,
                        kind,
                        row,
                        relative,
                        3000,
                    )
                    .expect("private namespace comparison")
                },
            );
            private_paths.push(json!({"path":name,"observation":observation}));
        }
        assert!(owner_rows > 0 && worker_rows > 0);
        let canary_row = |area: &str, path: &str, writable: bool| {
            let observation = if writable {
                json!({"state":"created-removed","errno":null,"created":true,"removed":true,"residue":false})
            } else {
                json!({"state":"refused","errno":"EACCES","created":false,"removed":false,"residue":false})
            };
            json!({"area":area,"observation":observation,"recovery":{"name":format!("{path}/{}", layout::CANARY),"state":"absent","residue":false,"reason":"name absent"},"verdict":"pass"})
        };
        let protected = [
            ("fixed-input", ".local/inbox"),
            ("routing", ".ssh"),
            ("sign-in-source", ".config/loops/alpha/lanes/codex"),
            ("preserved", "R/preserved"),
        ]
        .iter()
        .map(|(area, path)| canary_row(area, path, false))
        .collect::<Vec<_>>();
        let writable = [("scratch", ".cache/work"), ("outbox", ".local/outbox")]
            .iter()
            .map(|(area, path)| canary_row(area, path, true))
            .collect::<Vec<_>>();
        let mut measurement = json!({"state":"measured","worker_uid":3000,"protected":protected,"writable":writable,"no_copy":{"verdict":"pass","reason":"planned","extra_paths":[],"method":"names-only"},"path_frame":"private-namespace","path_metadata":private_paths});
        let record = json!({"worker_uid":3000,"plan":{"paths":paths},"checkpoints":[],"checkpoint_attempts":[],"attempts_omitted":0});
        let passing = home_layout_with_descriptor(&record, &plan, "alpha", "R", &measurement, None)
            .expect("production plan report");
        assert_eq!(passing["claims"]["path_plan"]["verdict"], "pass");
        assert_eq!(passing["claims"]["path_plan"]["frame"], "private-namespace");
        assert_eq!(
            crate::launch::exercise::case_status(&passing).expect("unmeasured case status"),
            1
        );
        assert_eq!(
            crate::launch::exercise::case_status(&json!({"verdict":"pass"}))
                .expect("passing case status"),
            0
        );
        let source = plan.home.join(".local/sources").display().to_string();
        let changed = measurement["path_metadata"]
            .as_array_mut()
            .expect("private rows")
            .iter_mut()
            .find(|row| row["path"] == source)
            .expect("worker source row");
        let expected = paths
            .iter()
            .find(|row| row["path"] == source)
            .expect("planned source row");
        changed["observation"] = metadata_values(
            3000,
            0o755,
            SFlag::S_IFDIR,
            expected,
            Path::new(".local/sources"),
            3000,
        )
        .expect("changed mode comparison");
        let changed_observation = changed["observation"].clone();
        let failed = home_layout_with_descriptor(&record, &plan, "alpha", "R", &measurement, None)
            .expect("changed mode report");
        assert_eq!(failed["claims"]["path_plan"]["verdict"], "fail");
        assert_eq!(failed["verdict"], "fail");
        assert_eq!(
            crate::launch::exercise::case_status(&failed).expect("mode drift status"),
            1
        );
        assert_eq!(changed_observation["owner_class"], "worker");
        assert!(
            changed_observation["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(".local/sources"))
        );
    }

    /// ´test:unit:worker-owned-parent-metadata-is-observed-without-following-leaves´
    #[test]
    fn worker_owned_parent_metadata_is_observed_without_following_leaves() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let fixture = tempfile::tempdir().expect("fixture");
        let home_path = fixture.path().join("lane-alpha-R");
        let work = home_path.join(".cache/work");
        std::fs::create_dir_all(&work).expect("worker directory");
        let probe = work.join("probe");
        std::fs::write(&probe, b"metadata only").expect("worker file");
        for path in [&home_path, &home_path.join(".cache"), &work] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("directory mode");
        }
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o600))
            .expect("worker file mode");
        let uid = Uid::effective().as_raw();
        let paths = [
            json!({"path":home_path,"uid":uid,"mode":"0700","kind":"directory"}),
            json!({"path":home_path.join(".cache"),"uid":uid,"mode":"0700","kind":"directory"}),
            json!({"path":work,"uid":uid,"mode":"0700","kind":"directory"}),
            json!({"path":probe,"uid":uid,"mode":"0600","kind":"file"}),
        ];
        let fd: OwnedFd = std::fs::File::open(&home_path).expect("held home").into();
        let observed = observe_path(
            &fd,
            Path::new(".cache/work/probe"),
            &home_path,
            &paths,
            u64::from(uid),
        )
        .expect("parent-relative observation");
        assert_eq!(observed["verdict"], "pass");
        assert_eq!(observed["owner_class"], "worker");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o640))
            .expect("changed worker mode");
        let changed = observe_path(
            &fd,
            Path::new(".cache/work/probe"),
            &home_path,
            &paths,
            u64::from(uid),
        )
        .expect("changed metadata");
        assert_eq!(changed["verdict"], "fail");
        assert_eq!(changed["mode"], "0640");
        symlink(&probe, work.join("linked")).expect("linked leaf");
        let linked_paths = [
            paths[0].clone(),
            paths[1].clone(),
            paths[2].clone(),
            json!({"path":work.join("linked"),"uid":uid,"mode":"0600","kind":"file"}),
        ];
        let linked = observe_path(
            &fd,
            Path::new(".cache/work/linked"),
            &home_path,
            &linked_paths,
            u64::from(uid),
        )
        .expect("linked leaf observation");
        assert_eq!(linked["verdict"], "fail");
        assert_eq!(linked["kind"], "link");
    }

    /// ´test:unit:home-layout-private-result-requires-present-consistent-claims´
    #[test]
    fn home_layout_private_result_requires_present_consistent_claims() {
        let mut measured = json!({"state":"measured","worker_uid":3000,"protected":[{"area":"fixed-input","observation":{"state":"refused","errno":"EACCES","created":false,"removed":false,"residue":false},"verdict":"pass"},{"area":"routing","observation":{"state":"refused","errno":"EACCES","created":false,"removed":false,"residue":false},"verdict":"pass"},{"area":"sign-in-source","observation":{"state":"refused","errno":"EACCES","created":false,"removed":false,"residue":false},"verdict":"pass"},{"area":"preserved","observation":{"state":"refused","errno":"EACCES","created":false,"removed":false,"residue":false},"verdict":"pass"}],"writable":[{"area":"scratch","observation":{"state":"created-removed","errno":null,"created":true,"removed":true,"residue":false},"verdict":"pass"},{"area":"outbox","observation":{"state":"created-removed","errno":null,"created":true,"removed":true,"residue":false},"verdict":"pass"}],"no_copy":{"verdict":"pass","reason":"planned","extra_paths":[],"method":"names-only"},"path_frame":"private-namespace","path_metadata":[]});
        for (kind, paths) in [
            (
                "protected",
                &[
                    ".local/inbox",
                    ".ssh",
                    ".config/loops/alpha/lanes/codex",
                    "R/preserved",
                ][..],
            ),
            ("writable", &[".cache/work", ".local/outbox"][..]),
        ] {
            for (row, path) in measured[kind]
                .as_array_mut()
                .expect("rows")
                .iter_mut()
                .zip(paths)
            {
                row["recovery"] = json!({"name":format!("{path}/{}", layout::CANARY),"state":"absent","residue":false,"reason":"name absent"});
            }
        }
        validate_home_measurement(&measured, 3000).expect("complete private result");
        let mut missing = measured.clone();
        missing.as_object_mut().expect("object").remove("no_copy");
        let missing_error = validate_home_measurement(&missing, 3000).expect_err("missing claim");
        assert_eq!(missing_error.kind, "exercise-home-layout-record");
        assert_eq!(missing_error.status, 2);
        let mut removed_false = measured.clone();
        removed_false["writable"][0]["observation"]["removed"] = json!(false);
        assert_eq!(
            validate_home_measurement(&removed_false, 3000)
                .expect_err("removal contradiction")
                .kind,
            "exercise-home-layout-record"
        );
        let mut created_true = measured.clone();
        created_true["protected"][0]["observation"]["created"] = json!(true);
        assert_eq!(
            validate_home_measurement(&created_true, 3000)
                .expect_err("creation contradiction")
                .kind,
            "exercise-home-layout-record"
        );
        let mut missing_residue = measured.clone();
        missing_residue["writable"][0]["observation"] =
            json!({"state":"worker-refused","status":1});
        missing_residue["writable"][0]["verdict"] = json!("fail");
        assert_eq!(
            validate_home_measurement(&missing_residue, 3000)
                .expect_err("missing failure residue")
                .kind,
            "exercise-home-layout-record"
        );
        let mut observed_residue = measured.clone();
        observed_residue["writable"][0]["observation"] = json!({"state":"worker-refused","status":null,"created":null,"removed":false,"residue":true,"residue_name":format!(".cache/work/{}", layout::CANARY),"residue_probe":"worker regular file"});
        observed_residue["writable"][0]["verdict"] = json!("fail");
        validate_home_measurement(&observed_residue, 3000).expect("observed failure residue");
        let mut contrary = measured;
        contrary["protected"][0]["observation"]["state"] = json!("created-removed");
        assert_eq!(
            validate_home_measurement(&contrary, 3000)
                .expect_err("contrary claim")
                .kind,
            "exercise-home-layout-record"
        );
    }

    /// ´test:unit:harvest-case-cannot-pass-without-preserved-byte-audit´
    #[test]
    fn harvest_case_cannot_pass_without_preserved_byte_audit() {
        let claims = json!({"object_agreement":claim("pass","matched"),"preserved_outputs":claim("pass","listed"),"collected_after_preservation":claim("pass","absent"),"preserved_byte_audit":claim("unmeasured","pending audit")});
        assert_eq!(required_verdict(&claims), "unmeasured");
        let failed = json!({"object_agreement":claim("fail","mismatch"),"preserved_byte_audit":claim("unmeasured","pending audit")});
        assert_eq!(required_verdict(&failed), "fail");
    }
}
