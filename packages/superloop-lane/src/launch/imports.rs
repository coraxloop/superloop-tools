//! Keep the preserved checkpoint and checkout evidence that explains an import.

use super::*;

const MAX_IMPORTS: usize = 64;

#[derive(Debug)]
pub struct MarkImportedRequest {
    pub loop_name: String,
    pub run: String,
    pub object: String,
}

/// Build the private import words used by the public command.
///
/// # Errors
///
/// Refuses an owner home that cannot be passed as a path word.
pub fn private_import_argv(
    request: &MarkImportedRequest,
    owner_home: &Path,
) -> Result<Vec<String>, LaneError> {
    Ok(vec![
        "_mark-imported".into(),
        request.loop_name.clone(),
        request.run.clone(),
        "--object".into(),
        request.object.clone(),
        "--owner-home".into(),
        crate::pinned::path_word(owner_home, "import-home")?,
    ])
}

fn valid_object(object: &str) -> bool {
    [40, 64].contains(&object.len())
        && object
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl MarkImportedRequest {
    /// Parse one import-evidence mark.
    ///
    /// # Errors
    ///
    /// Refuses an absent or malformed name or object.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let [loop_name, run, flag, object] = args else {
            return Err(LaneError::input(
                "mark-imported-usage",
                "mark-imported LOOP RUN --object HEX",
            ));
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| LaneError::input("loop-name", error.message()))?;
        if !valid_run_name(run) || flag != "--object" || !valid_object(object) {
            return Err(LaneError::input(
                "mark-imported-usage",
                "mark-imported LOOP RUN --object HEX",
            ));
        }
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            object: object.clone(),
        })
    }
}

/// Read import marks and verify that each still names a preserved checkpoint entry.
///
/// # Errors
///
/// Refuses an absent or malformed journal or a mark without checkpoint evidence.
pub(super) fn validated(record: &Value) -> Result<Vec<Value>, LaneError> {
    let imports = record
        .get("imports")
        .ok_or_else(|| {
            LaneError::input(
                "import-record",
                "required imports key is absent; reservation predates import records",
            )
        })?
        .as_array()
        .ok_or_else(|| LaneError::input("import-record", "imports key is malformed"))?;
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(record)?;
    if imports.len() > MAX_IMPORTS {
        return Err(LaneError::input(
            "import-record",
            "import journal exceeds bound",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in imports {
        let Some(fields) = entry.as_object() else {
            return Err(LaneError::input(
                "import-record",
                "import entry is malformed",
            ));
        };
        if fields.len() != 4
            || fields
                .get("checkpoint_index")
                .and_then(Value::as_u64)
                .is_none()
            || fields
                .get("object")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_object(value))
            || fields
                .get("repo")
                .and_then(Value::as_str)
                .is_none_or(|value| !valid_run_name(value))
            || fields
                .get("instant_unix_ns")
                .and_then(Value::as_u64)
                .is_none()
        {
            return Err(LaneError::input(
                "import-record",
                "import entry has another shape",
            ));
        }
        if !seen.insert((entry["checkpoint_index"].as_u64(), entry["repo"].as_str())) {
            return Err(LaneError::input(
                "import-record",
                "import entry is repeated",
            ));
        }
        if !checkpoints.iter().any(|checkpoint| {
            checkpoint["index"] == entry["checkpoint_index"]
                && checkpoint["bares"].as_array().is_some_and(|bares| {
                    bares.iter().any(|bare| {
                        bare["name"] == entry["repo"] && bare["object"] == entry["object"]
                    })
                })
        }) {
            return Err(LaneError::input(
                "import-record",
                "marked object lacks its checkpoint entry",
            ));
        }
    }
    Ok(imports.clone())
}

/// Enter the owner namespace with pinned home and runs-root descriptors.
///
/// # Errors
///
/// Refuses an unsafe root, failed private mark, or malformed private report.
pub fn run(owner_home: &Path, request: &MarkImportedRequest) -> Result<Value, LaneError> {
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("import-grant", "runs_root is absent"))?;
    let podman = plan.document["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| LaneError::input("import-record", "container program is absent"))?;
    let owner = Uid::effective().as_raw();
    crate::pinned::owner_executable(Path::new(podman), owner)?;
    let home_fd = home::verify_host_prefix_from(Path::new("/"), owner_home, owner, 0)?;
    let runs_fd = home::verify_host_launch_root(Path::new("/"), owner_home, root, owner, 0)?;
    let exe = std::env::current_exe()
        .map_err(|error| LaneError::operation("import-program", error.to_string()))?;
    crate::pinned::owner_executable(&exe, owner)?;
    let mut argv = vec![
        "unshare".into(),
        crate::pinned::path_word(&exe, "import-program")?,
    ];
    argv.extend(private_import_argv(request, owner_home)?);
    let output = build::run_checked_with_private_launch(
        Path::new(podman),
        argv,
        &launch_environment(owner_home)?,
        owner_home,
        300,
        "import-private",
        &home_fd,
        root,
        &runs_fd,
        None,
    )
    .map_err(|error| {
        for kind in [
            "import-record",
            "import-checkpoint",
            "import-evidence",
            "import-duplicate",
            "import-size",
            "import-round",
            "checkout-checkpoint",
        ] {
            if error.detail.contains(&format!("{kind}:")) {
                return LaneError::input(kind, error.detail);
            }
        }
        error
    })?;
    serde_json::from_str(&output)
        .map_err(|error| LaneError::operation("import-private", error.to_string()))
}

/// Verify the copied bare and publish one bounded import mark under the mailbox lock.
///
/// # Errors
///
/// Refuses a missing checkpoint, changed copy, or unexplainable checkout history.
#[allow(clippy::too_many_lines)]
pub fn private_run(owner_home: &Path, request: &MarkImportedRequest) -> Result<Value, LaneError> {
    if !Uid::effective().is_root() {
        return Err(LaneError::input(
            "namespace-owner",
            "rootless namespace root is required",
        ));
    }
    let (plan, settings) =
        crate::load_plan_for_record(owner_home, &request.loop_name, &request.run, (0, 0))?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| LaneError::input("import-grant", "runs_root is absent"))?;
    let owner = Uid::effective().as_raw();
    let root_fd = home::pin_parent(root, owner)?;
    let _mailbox = lock_mailbox_at(&root_fd, &request.run, owner)?;
    let mut record = checkout::read_record(&root_fd, &request.run, owner)
        .map_err(|error| LaneError::input("import-record", error.line()))?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
        || record["plan"]["home"] != plan.home.display().to_string()
    {
        return Err(LaneError::input(
            "import-record",
            "reservation names another run",
        ));
    }
    if record["phase"] != "settled" {
        return Err(LaneError::input(
            "import-round",
            "run is not settled for import marking",
        ));
    }
    let mut imports = validated(&record)?;
    let (_, checkpoints, _) = checkpoint::checkpoint_fields(&record)?;
    let (checkpoint, bare) = checkpoints
        .iter()
        .rev()
        .find_map(|checkpoint| {
            checkpoint["bares"]
                .as_array()?
                .iter()
                .find(|bare| bare["object"] == request.object)
                .map(|bare| (checkpoint, bare))
        })
        .ok_or_else(|| {
            LaneError::input("import-checkpoint", "object has no preserved checkpoint")
        })?;
    let index = checkpoint["index"]
        .as_u64()
        .ok_or_else(|| LaneError::input("import-record", "checkpoint index is malformed"))?;
    let repo = bare["name"]
        .as_str()
        .ok_or_else(|| LaneError::input("import-record", "bare name is malformed"))?;
    if imports
        .iter()
        .any(|entry| entry["checkpoint_index"] == index && entry["repo"] == repo)
    {
        return Err(LaneError::input(
            "import-duplicate",
            "checkpoint bare is already marked",
        ));
    }
    if imports.len() >= MAX_IMPORTS {
        return Err(LaneError::input("import-size", "import journal is full"));
    }
    let checkouts = record["checkouts"]
        .as_array()
        .ok_or_else(|| LaneError::input("import-record", "checkout journal is malformed"))?;
    if record["checkouts_omitted"].as_u64().is_none() {
        return Err(LaneError::input(
            "import-record",
            "checkout omission count is malformed",
        ));
    }
    if record["checkouts_omitted"].as_u64() != Some(0)
        && !checkouts
            .iter()
            .any(|entry| entry["checkpoint_index"] == index && entry["repo"] == repo)
    {
        return Err(LaneError::input(
            "import-evidence",
            "an omitted checkout might be needed to explain this import",
        ));
    }
    let loop_uid = super::recorded_loop_uid(&record)?;
    let run_fd = home::pin_loop_round_at(&root_fd, root, &plan.driver_dir, loop_uid)?;
    let files = checkpoint["files"]
        .as_array()
        .ok_or_else(|| LaneError::input("import-record", "checkpoint file list is malformed"))?;
    checkpoint::verify_preserved_copy(
        &run_fd,
        &plan.driver_dir,
        index,
        files,
        repo,
        &request.run,
        &request.object,
        loop_uid,
    )?;
    let instant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| LaneError::operation("import-clock", error.to_string()))?
        .as_nanos();
    imports.push(json!({"checkpoint_index":index,"repo":repo,"object":request.object,"instant_unix_ns":instant}));
    record["imports"] = json!(imports);
    let token = checkpoint::random_token()?;
    checkout::publish_record(&root_fd, &request.run, &record, &token)
        .map_err(|error| LaneError::operation("import-record", error.line()))?;
    Ok(
        json!({"schema":1,"command":"mark-imported","loop":request.loop_name,"run":request.run,"checkpoint_index":index,"repo":repo,"object":request.object}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ´test:unit:import-marks-require-an-exact-checkpoint-entry´
    #[test]
    fn import_marks_require_an_exact_checkpoint_entry() {
        let checkpoint = json!({"index":1,"instant_unix_ns":1,"round_after":"a","files":[],"bares":[{"name":"tools","declared":true,"seed":null,"lane_ref":"present","object":"a".repeat(40)}]});
        let mut record = json!({"imports":[{"checkpoint_index":1,"repo":"tools","object":"a".repeat(40),"instant_unix_ns":2}],"checkpoints":[checkpoint]});
        assert_eq!(validated(&record).expect("matched evidence").len(), 1);
        record["imports"][0]["object"] = json!("b".repeat(40));
        assert_eq!(
            validated(&record).expect_err("mismatch").kind,
            "import-record"
        );
        record.as_object_mut().expect("record").remove("imports");
        let absent = validated(&record).expect_err("absent journal");
        assert_eq!(absent.kind, "import-record");
        assert!(absent.detail.contains("imports"));
        assert!(absent.detail.contains("predates"));
    }
}
