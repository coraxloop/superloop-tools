//! Owner-selected door authority for an existing boxed run.

use super::*;

const HISTORY: usize = 64;
const ROUTE_REMEDY: &str = "a work scope needs the loop's compute route: place door-compute-registration.json beside door-key in the loop configuration as proto:superlooplane:registered-ssh-transport describes, then repeat a dry-run preview";

fn refusal(kind: &'static str, detail: impl Into<String>) -> LaneError {
    LaneError::input(kind, detail)
}

fn route_refusal(detail: &str) -> LaneError {
    refusal("door-scope-route", format!("{detail}; {ROUTE_REMEDY}"))
}

#[derive(Clone, Debug)]
pub struct Request {
    pub loop_name: String,
    pub run: String,
    pub target: crate::door::Scope,
    pub expected: Option<String>,
}

impl Request {
    /// Parse the preview or digest-bound changing form.
    /// # Errors
    /// Refuses invalid names, scope, digest or option combinations.
    pub fn parse(args: &[String]) -> Result<Self, LaneError> {
        let (loop_name, run, scope, expected) = match args {
            [loop_name, run, to, scope, flag] if to == "--to" && flag == "--dry-run" => {
                (loop_name, run, scope, None)
            }
            [loop_name, run, to, scope, flag, digest]
                if to == "--to"
                    && flag == "--expect-digest"
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
            {
                (loop_name, run, scope, Some(digest.clone()))
            }
            _ => {
                return Err(refusal(
                    "door-scope-usage",
                    "set-door-scope LOOP RUN --to {work|review} {--dry-run|--expect-digest HEX}",
                ));
            }
        };
        loop_home::validate_name(loop_name)
            .map_err(|error| refusal("door-scope-loop", error.message()))?;
        if !valid_run_name(run) {
            return Err(refusal("door-scope-run", "run is not a plain name"));
        }
        let target = match scope.as_str() {
            "work" => crate::door::Scope::Work,
            "review" => crate::door::Scope::Review,
            _ => {
                return Err(refusal(
                    "door-scope-target",
                    "target must be work or review",
                ));
            }
        };
        Ok(Self {
            loop_name: loop_name.clone(),
            run: run.clone(),
            target,
            expected,
        })
    }
}

fn current_scope(record: &Value) -> Result<&str, LaneError> {
    record["door_scope"]
        .as_str()
        .filter(|scope| matches!(*scope, "work" | "review"))
        .ok_or_else(|| refusal("door-scope-record", "recorded scope is absent or invalid"))
}

fn history(record: &Value) -> Result<(Vec<Value>, u64), LaneError> {
    let rows = match record.get("door_scope_history") {
        None => Vec::new(),
        Some(Value::Array(rows)) if rows.len() <= HISTORY => rows.clone(),
        _ => {
            return Err(refusal(
                "door-scope-history",
                "scope history is malformed or over bound",
            ));
        }
    };
    if rows.iter().any(|row| {
        row["member"] != "door_scope"
            || !matches!(row["from"].as_str(), Some("work" | "review"))
            || !matches!(row["to"].as_str(), Some("work" | "review"))
            || row["at_unix_ns"].as_u64().is_none()
            || row["command"] != "set-door-scope"
            || row["preview_sha256"].as_str().is_none_or(|digest| {
                digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    }) {
        return Err(refusal(
            "door-scope-history",
            "scope history entry is malformed",
        ));
    }
    let omitted = match record.get("door_scope_history_omitted") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| refusal("door-scope-history", "omitted count is malformed"))?,
    };
    Ok((rows, omitted))
}

fn eligible(
    record: &Value,
    request: &Request,
    row: &loop_home::LoopRecord,
    root: &Path,
    owner: u32,
) -> Result<(), LaneError> {
    if record["loop"] != request.loop_name || record["run"] != request.run {
        return Err(refusal(
            "door-scope-record",
            "reservation names another run",
        ));
    }
    let worker = record["worker_uid"]
        .as_u64()
        .and_then(|uid| u32::try_from(uid).ok())
        .ok_or_else(|| refusal("door-scope-record", "worker identity is absent"))?;
    let scope = match current_scope(record)? {
        "work" => crate::door::Scope::Work,
        _ => crate::door::Scope::Review,
    };
    crate::door::Registration::from_row(
        &json!({"name":row.name,"uid":row.uid}),
        &request.loop_name,
        &request.run,
        worker,
        scope,
    )
    .map_err(|error| refusal("door-scope-record", error.line()))?;
    if record["plan"]["door"].as_object().is_none()
        || record["plan"]["door"]["mirror_ref"] != format!("refs/heads/lane/{}", request.run)
    {
        return Err(refusal(
            "door-scope-no-door",
            "run has no exact recorded door route",
        ));
    }
    if record["current_retirement"].is_object() {
        return Err(refusal(
            "door-scope-retiring",
            "current retirement is recorded; scope cannot change",
        ));
    }
    match record["phase"].as_str() {
        Some("started" | "settled" | "failed") => {}
        Some("preparing") => {
            let detail = match retire::probe_retirement_lease(root, &request.run, owner) {
                Err(error) if error.kind == "retire-busy" =>
                    "a launch holds the preparation lease; wait for it to finish (which can take minutes), then repeat set-door-scope --dry-run".to_owned(),
                Ok(Some(_)) => format!(
                    "the preparation lease is unheld; there is no standalone restore command; preview retirement with superloop-lane retire {} {} --dry-run (follow any confirmation flags it names); see prob:lanes:a-refused-resumed-launch-leaves-a-round-row-no-route-admits",
                    request.loop_name, request.run
                ),
                Ok(None) => format!(
                    "the preparation lease is absent; preview retirement with superloop-lane retire {} {} --confirm-missing-lease --dry-run (follow any other confirmation flags it names); see prob:lanes:a-refused-resumed-launch-leaves-a-round-row-no-route-admits",
                    request.loop_name, request.run
                ),
                Err(error) => format!(
                    "preparation lease cannot be measured ({error}); do not infer that launch has stopped; inspect superloop-lane census {} before retrying",
                    request.loop_name
                ),
            };
            return Err(refusal("door-scope-preparing", detail));
        }
        Some("retiring" | "retired") => {
            return Err(refusal("door-scope-retiring", "run is retiring or retired"));
        }
        _ => {
            return Err(refusal(
                "door-scope-state",
                "run phase is absent or invalid",
            ));
        }
    }
    if record["rotation_intent"].is_object()
        || (record["rotation"].is_object() && record["rotation"]["old_run"] == request.run)
    {
        return Err(refusal(
            "door-scope-rotated",
            "rotation intent or link exists; set the successor's scope",
        ));
    }
    history(record)?;
    Ok(())
}

fn plan(request: &Request, bytes: &[u8], from: &str) -> Value {
    json!({"schema":1,"command":"set-door-scope","loop":request.loop_name,"run":request.run,
        "from":from,"to":request.target.name(),
        "before_sha256":retire::absences::hash(bytes),"before_bytes":bytes.len()})
}

fn no_pending_rewrite(root: &Path, request: &Request) -> Result<(), LaneError> {
    if let Some(rewrite) =
        census::pending_record_rewrites(root, &request.loop_name, &request.run)?.first()
    {
        return Err(refusal(
            "door-scope-pending-rewrite",
            format!(
                "{} holds run {}; resume with {}",
                rewrite["kind"].as_str().unwrap_or("pending rewrite"),
                request.run,
                rewrite["next_command"]
                    .as_str()
                    .unwrap_or("its recorded command")
            ),
        ));
    }
    Ok(())
}

/// Preview or apply the loop owner's change of one protected run's door scope.
/// # Errors
/// Refuses an unsafe run, a conflicting phase, stale digest or oversized record.
#[allow(clippy::too_many_lines)] // One lock scope and publication keep the preview and apply transaction together.
pub fn run(owner_home: &Path, request: &Request) -> Result<Value, LaneError> {
    let started = Instant::now();
    let owner = Uid::effective().as_raw();
    let config = owner_home.join(".config/loops").join(&request.loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let registry_path = loop_home::registry_path(
        std::env::var_os("ENTER_LOOP_REGISTRY").as_deref(),
        owner_home,
    );
    let registry = loop_home::load_registry(&registry_path)
        .map_err(|error| refusal("door-scope-registry", error.message()))?;
    let row = registry
        .row(&request.loop_name, owner_home)
        .map_err(|error| refusal("door-scope-registry", error.message()))?;
    let root = registry
        .runs_root(&request.loop_name)
        .ok_or_else(|| refusal("door-scope-registry", "runs_root is absent"))?;
    let _runs = lock_runs_root(root, false, owner)?;
    let _mailbox = if request.expected.is_some() {
        Some(lock_mailbox(root, &request.run, owner)?)
    } else {
        None
    };
    let path = reservation_path(root, &request.run);
    let (record, bytes) = read_reservation_raw(&path, true)?
        .ok_or_else(|| refusal("door-scope-record", "reservation is absent"))?;
    no_pending_rewrite(root, request)?;
    eligible(&record, request, &row, root, owner)?;
    let prerequisites = work_prerequisites(request, &config, owner)?;
    let from = current_scope(&record)?.to_owned();
    let (mut entries, mut omitted) = history(&record)?;
    if let Some(expected) = request.expected.as_deref()
        && from == request.target.name()
        && entries
            .last()
            .is_some_and(|entry| entry["preview_sha256"] == expected)
    {
        return Ok(
            json!({"schema":1,"command":"set-door-scope","loop":request.loop_name,
            "run":request.run,"from":entries.last().map_or(Value::Null, |entry| entry["from"].clone()),
            "to":request.target.name(),"dry_run":false,"changed":false,"applied":true,
            "replayed":true,"preview_sha256":expected,"history_entry":entries.last(),
            "history_omitted":omitted,"worker_notice":"Tell the worker by letter; it learns this scope at its next door request.",
            "work_prerequisites":prerequisites,"wall_seconds":started.elapsed().as_secs_f64()}),
        );
    }
    let proposal = plan(request, &bytes, &from);
    let digest = crate::door::retirement::digest(&proposal);
    if let Some(expected) = request.expected.as_deref()
        && expected != digest
    {
        return Err(refusal(
            "door-scope-digest",
            "preview digest differs; repeat set-door-scope --dry-run",
        ));
    }
    let changing = from != request.target.name();
    let entry = if changing {
        json!({"member":"door_scope","from":from,"to":request.target.name(),
            "at_unix_ns":if request.expected.is_some() {json!(letters::unix_ns()?)} else {Value::Null},
            "command":"set-door-scope","preview_sha256":digest})
    } else {
        Value::Null
    };
    if changing {
        entries.push(entry.clone());
        if entries.len() > HISTORY {
            entries.remove(0);
            omitted = omitted.saturating_add(1);
        }
        let mut after = record;
        after["door_scope"] = json!(request.target.name());
        after["door_scope_history"] = json!(entries);
        after["door_scope_history_omitted"] = json!(omitted);
        if request.expected.is_none() {
            after["door_scope_history"]
                .as_array_mut()
                .and_then(|history| history.last_mut())
                .ok_or_else(|| refusal("door-scope-history", "planned entry is absent"))?["at_unix_ns"] =
                json!(u64::MAX);
        }
        let size = serde_json::to_vec(&after)
            .map_err(|error| refusal("door-scope-record", error.to_string()))?
            .len() as u64;
        if size > MAX_RESERVATION_BYTES {
            return Err(refusal(
                "door-scope-size",
                format!("target is {size} bytes over reservation bound {MAX_RESERVATION_BYTES}"),
            ));
        }
        if request.expected.is_some() {
            publish_reservation(&path, &after)?;
        }
    }
    Ok(
        json!({"schema":1,"command":"set-door-scope","loop":request.loop_name,"run":request.run,
        "from":from,"to":request.target.name(),"dry_run":request.expected.is_none(),
        "changed":request.expected.is_some() && changing,
        "applied":request.expected.is_some(),"replayed":false,"preview_sha256":digest,
        "history_entry":entry,"history_omitted":omitted,
        "worker_notice":"Tell the worker by letter; it learns this scope at its next door request.",
        "work_prerequisites":prerequisites,"wall_seconds":started.elapsed().as_secs_f64()}),
    )
}

fn work_prerequisites(request: &Request, config: &Path, owner: u32) -> Result<Value, LaneError> {
    if request.target != crate::door::Scope::Work {
        return Ok(json!([]));
    }
    let route = work_route(config, &request.loop_name, owner)?;
    let alias = route["alias"]
        .as_str()
        .ok_or_else(|| refusal("door-scope-route", "alias is absent"))?;
    let mirror_root = route["mirror_root"]
        .as_str()
        .ok_or_else(|| refusal("door-scope-route", "mirror root is absent"))?;
    let mirror = format!("{mirror_root}/{}.git", request.run);
    let reference = format!("refs/heads/lane/{}", request.run);
    let remote = format!("{alias}:{mirror}");
    Ok(json!([
        format!(
            "On registered node alias {alias}, the loop arranges the bare mirror at {mirror} by hand; set-door-scope creates nothing there."
        ),
        format!(
            "The run ref is {reference}; after the mirror exists, the worker's first push can create it."
        ),
        format!(
            "Tell the worker to run git remote add lane-{} {remote} in its clone, then git push lane-{} HEAD:{reference}; the loop arranges that remote by letter, and set-door-scope creates nothing in the clone.",
            request.run, request.run
        )
    ]))
}

pub(super) fn work_route(config: &Path, loop_name: &str, owner: u32) -> Result<Value, LaneError> {
    let held = File::open(config)
        .map_err(|error| route_refusal(&format!("{}: {error}", config.display())))?;
    crate::door::registered_route(&held, config, loop_name, owner)
        .map_err(|error| route_refusal(&error.line()))
}
