//! Explicit conversion of listed helper evidence predecessors, never a read fallback.

use super::super::*;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

fn refusal(detail: impl Into<String>) -> LaneError {
    LaneError::input("credential-evidence-rewrite", detail)
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

pub(crate) fn historical_shape(value: &Value) -> bool {
    if value["schema"] != 1 || value["host"] != crate::credential::REFRESH_HOST {
        return false;
    }
    if exact(value, &["schema", "host", "state", "kind", "detail"]) {
        return value["state"] == "refused"
            && value["kind"].as_str().is_some_and(|kind| !kind.is_empty())
            && value["detail"].is_string();
    }
    if !exact(value, &["schema", "host", "state", "run_refusals"]) {
        return false;
    }
    let Some(rows) = value["run_refusals"].as_array() else {
        return false;
    };
    let state_matches = match value["state"].as_str() {
        Some("published") => rows.is_empty(),
        Some("partial" | "refused") => !rows.is_empty(),
        _ => false,
    };
    state_matches
        && rows.iter().all(|row| {
            exact(row, &["run", "kind", "detail"])
                && row["run"].as_str().is_some_and(valid_run_name)
                && row["kind"].as_str().is_some_and(|kind| !kind.is_empty())
                && row["detail"].is_string()
        })
}

fn hash(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _written = write!(result, "{byte:02x}");
    }
    result
}

fn convert(bytes: &[u8]) -> Result<Value, LaneError> {
    let original: Value = serde_json::from_slice(bytes).map_err(|_| {
        refusal("restore valid original evidence; malformed JSON cannot be rewritten")
    })?;
    if !historical_shape(&original) {
        return Err(refusal(
            "only the listed historical helper envelopes can be rewritten; restore valid original evidence for unknown or corrupt envelopes",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refusal("original evidence is not UTF-8"))?;
    let target = json!({
        "schema":1,"host":crate::credential::REFRESH_HOST,"state":"refused",
        "expires_unix":null,"refresh_due_unix":null,
        "run_refusals":original.get("run_refusals").cloned().unwrap_or_else(|| json!([])),
        "run_refusals_omitted":0,
        "kind":"credential-evidence-historical",
        "detail":"historical helper evidence did not measure expiry; original evidence is retained in credential_rewrite",
        "credential_rewrite":{"schema":1,"conversion":"helper-expiry-unmeasured",
            "original":original,"original_bytes":text,"before_sha256":hash(bytes),"token_observed":false}
    });
    if target.to_string().len() > 65_536 {
        return Err(refusal(
            "rewritten evidence exceeds the evidence reader bound",
        ));
    }
    Ok(target)
}

pub(crate) fn validate_provenance(document: &Value) -> Result<(), LaneError> {
    let Some(provenance) = document.get("credential_rewrite") else {
        return Ok(());
    };
    let bytes = provenance["original_bytes"]
        .as_str()
        .ok_or_else(|| refusal("rewrite provenance has no original bytes"))?;
    let mut expected = convert(bytes.as_bytes())?;
    // Temporal defects remain census observations even on explicitly rewritten evidence.
    for field in ["expires_unix", "refresh_due_unix"] {
        if let Some(value) = document.get(field) {
            expected[field] = value.clone();
        } else if let Some(object) = expected.as_object_mut() {
            object.remove(field);
        }
    }
    if expected != *document {
        return Err(refusal(
            "rewrite provenance or target differs from the listed conversion",
        ));
    }
    Ok(())
}

struct Request<'a> {
    loop_name: &'a str,
    run: &'a str,
    expected: Option<&'a str>,
}

fn parse(args: &[String]) -> Result<Request<'_>, LaneError> {
    let (loop_name, run, expected) = match args {
        [name, run, flag] if flag == "--dry-run" => (name, run, None),
        [name, run, flag, digest]
            if flag == "--expect-digest"
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            (name, run, Some(digest.as_str()))
        }
        _ => {
            return Err(refusal(
                "census rewrite LOOP RUN {--dry-run|--expect-digest HEX}",
            ));
        }
    };
    loop_home::validate_name(loop_name).map_err(|error| refusal(error.message()))?;
    if !valid_run_name(run) {
        return Err(refusal("invalid run name"));
    }
    Ok(Request {
        loop_name,
        run,
        expected,
    })
}

fn eligible(
    owner_home: &Path,
    root: &Path,
    request: &Request<'_>,
    record: &Value,
) -> Result<(), LaneError> {
    let (base, count) = worker_range(owner_home, request.loop_name)?;
    let uid = record["worker_uid"]
        .as_u64()
        .ok_or_else(|| refusal("worker identity absent"))?;
    if record["loop"] != request.loop_name
        || record["run"] != request.run
        || !["settled", "failed"].contains(&record["phase"].as_str().unwrap_or_default())
        || uid < u64::from(base)
        || uid >= u64::from(base) + u64::from(count)
        || record["plan"]["driver_dir"] != root.join(request.run).to_string_lossy().as_ref()
        || record["plan"]["home"]
            != owner_home
                .join(".cache/tmp")
                .join(format!("lane-{}-{}", request.loop_name, request.run))
                .to_string_lossy()
                .as_ref()
    {
        return Err(refusal(
            "rewrite requires this loop's settled or failed reservation and allocated worker identity",
        ));
    }
    retire::checked_presence(
        owner_home,
        record,
        false,
        crate::container_helper::process_presence,
    )?;
    let runtime = record["plan"]["runtime_argv"][0]
        .as_str()
        .ok_or_else(|| refusal("runtime absent"))?;
    if !container_absent_for_run(
        Path::new(runtime),
        owner_home,
        request.loop_name,
        request.run,
    )? {
        return Err(refusal("labelled container is still present"));
    }
    Ok(())
}

fn read_bytes(runs: &OwnedFd, name: &str, owner: u32) -> Result<Option<Vec<u8>>, LaneError> {
    let fd = match openat2(
        runs,
        name,
        OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(refusal(format!("{name}: {error}"))),
    };
    let file = fs::File::from(fd);
    let meta = file
        .metadata()
        .map_err(|error| refusal(error.to_string()))?;
    if !meta.is_file()
        || meta.uid() != owner
        || meta.mode() & 0o7777 != 0o600
        || meta.len() > MAX_RESERVATION_BYTES
    {
        return Err(refusal(
            "rewrite input is not bounded owner-private custody",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RESERVATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refusal(error.to_string()))?;
    if bytes.len() as u64 > MAX_RESERVATION_BYTES {
        return Err(refusal("rewrite input exceeds reader bound"));
    }
    Ok(Some(bytes))
}

fn plan(
    request: &Request<'_>,
    owner: u32,
    reservation_hash: &str,
    bytes: &[u8],
) -> Result<Value, LaneError> {
    let after = convert(bytes)?;
    Ok(
        json!({"schema":1,"command":"census rewrite","owner_uid":owner,
        "loop":request.loop_name,"run":request.run,"reservation_sha256":reservation_hash,
        "before":after["credential_rewrite"]["original"],
        "before_bytes":after["credential_rewrite"]["original_bytes"],
        "before_sha256":hash(bytes),"after":after}),
    )
}

fn bound_plan(
    request: &Request<'_>,
    owner: u32,
    reservation_hash: &str,
    bytes: &[u8],
    journal: Option<&Value>,
) -> Result<Value, LaneError> {
    let Some(journal) = journal else {
        return plan(request, owner, reservation_hash, bytes);
    };
    if !exact(journal, &["schema", "phase", "plan", "preview_sha256"])
        || journal["schema"] != 1
        || !["pending", "complete"].contains(&journal["phase"].as_str().unwrap_or_default())
    {
        return Err(refusal("rewrite journal envelope differs"));
    }
    let original = journal["plan"]["before_bytes"]
        .as_str()
        .ok_or_else(|| refusal("journal original bytes absent"))?;
    let expected = plan(request, owner, reservation_hash, original.as_bytes())?;
    if expected != journal["plan"]
        || crate::door::retirement::digest(&expected) != journal["preview_sha256"]
    {
        return Err(refusal("rewrite journal binding differs"));
    }
    let target = expected["after"].to_string();
    if bytes != target.as_bytes()
        && (journal["phase"] == "complete" || bytes != original.as_bytes())
    {
        return Err(refusal(
            "record changed since the bound plan; restore original or exact target bytes",
        ));
    }
    Ok(expected)
}

/// Rewrite only the enumerated historical credential evidence after absence proof.
///
/// # Errors
/// Refuses unsafe custody, live or unknown writers, unknown shapes and changed bytes.
pub fn run(owner_home: &Path, args: &[String]) -> Result<Value, LaneError> {
    let begun = Instant::now();
    let request = parse(args)?;
    let config = owner_home.join(".config/loops").join(request.loop_name);
    let _configuration = crate::install::lock_loop_config(&config, true)?;
    let settings = Settings::read_beneath(&config.join("workers.toml"), owner_home)?;
    settings.validate_grant(owner_home, request.loop_name)?;
    let root = settings
        .runs_root
        .as_deref()
        .ok_or_else(|| refusal("runs_root is absent"))?;
    let owner = Uid::effective().as_raw();
    let runs = lock_runs_root(root, true, owner)?;
    let _lease = retire::lock_retirement_lease(root, request.run, owner, request.loop_name)?;
    let _mailbox =
        retire::lock_retirement_mailbox(root, request.run, owner, request.expected.is_none())?;
    let record = read_reservation(&reservation_path(root, request.run))?
        .ok_or_else(|| refusal("reservation absent"))?;
    eligible(owner_home, root, &request, &record)?;
    let reservation_name = format!(".reservation-{}.json", request.run);
    let reservation = read_bytes(&runs, &reservation_name, owner)?
        .ok_or_else(|| refusal("reservation vanished"))?;
    if serde_json::from_slice::<Value>(&reservation)
        .map_err(|_| refusal("reservation malformed"))?
        != record
    {
        return Err(refusal("reservation changed during absence proof"));
    }
    let bytes = crate::credential::read_evidence_bytes(&runs, request.run, owner)?
        .ok_or_else(|| refusal("evidence absent"))?;
    let journal_name = format!(".census-rewrite-{}.json", request.run);
    let prior = read_bytes(&runs, &journal_name, owner)?;
    let journal = prior
        .as_ref()
        .map(|bytes| serde_json::from_slice::<Value>(bytes))
        .transpose()
        .map_err(|_| refusal("rewrite journal is malformed"))?;
    let plan = bound_plan(
        &request,
        owner,
        &hash(&reservation),
        &bytes,
        journal.as_ref(),
    )?;
    let digest = crate::door::retirement::digest(&plan);
    let resuming = journal
        .as_ref()
        .is_some_and(|value| value["phase"] == "pending");
    if let Some(expected) = request.expected {
        if expected != digest {
            return Err(refusal(
                "plan differs; repeat census rewrite with --dry-run",
            ));
        }
        if crate::credential::read_evidence_bytes(&runs, request.run, owner)?.as_deref()
            != Some(bytes.as_slice())
            || read_bytes(&runs, &reservation_name, owner)?.as_deref()
                != Some(reservation.as_slice())
            || read_bytes(&runs, &journal_name, owner)? != prior
        {
            return Err(refusal("rewrite input changed before publication"));
        }
        if journal
            .as_ref()
            .is_none_or(|value| value["phase"] != "complete")
        {
            let mut pending =
                json!({"schema":1,"phase":"pending","plan":plan,"preview_sha256":digest});
            publish_reservation(&root.join(&journal_name), &pending)?;
            crate::credential::publish_evidence(&root.join(request.run), &plan["after"])?;
            pending["phase"] = json!("complete");
            publish_reservation(&root.join(&journal_name), &pending)?;
        }
    }
    Ok(
        json!({"schema":1,"command":"census rewrite","dry_run":request.expected.is_none(),
        "complete":request.expected.is_some(),"resuming":resuming,"plan":plan,
        "preview_sha256":digest,"wall_seconds":begun.elapsed().as_secs_f64()}),
    )
}
