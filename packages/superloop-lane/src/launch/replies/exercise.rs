//! Exercise the real reader protocol without claiming an owner write is a worker publication.

use super::*;

type Invoke<'a> = dyn FnMut(&Request, Option<&str>, bool) -> Result<Value, LaneError> + 'a;

fn claim(verdict: &str, reason: impl Into<String>) -> Value {
    json!({"verdict":verdict,"reason":reason.into()})
}

/// Read and receipt one observed reply on a planned run, reporting each measured step.
///
/// # Errors
/// Refuses malformed loop or run names; unavailable evidence is reported as unmeasured.
pub fn measure(owner_home: &Path, loop_name: &str, run: &str) -> Result<Value, LaneError> {
    let request = Request::parse(&[loop_name.into(), run.into(), "-".into()])?;
    let reader = BoundReader::open(owner_home, &request);
    Ok(measure_with(
        loop_name,
        run,
        &mut |request, expected, inspect| match &reader {
            Ok(reader) => reader.invoke(request, expected, inspect),
            Err(error) => Err(refusal("exercise-reply-receipts", error.line())),
        },
        &mut || {
            Err(
                "no worker-side publication callback; replacement by rename was not attempted"
                    .into(),
            )
        },
    ))
}

pub(super) fn inspect(
    plan: &crate::plan::Plan,
    record: &Value,
    runs: &OwnedFd,
    root: &Path,
    owner: u32,
    name: &str,
) -> Result<Value, LaneError> {
    let name = if name == "-" {
        let loop_uid = super::super::recorded_loop_uid(record)?;
        run_observations(plan, record, runs, root, loop_uid)?
            .selected
            .into_keys()
            .next()
            .ok_or_else(|| refusal("read-reply-unobserved", "no observed outbox reply"))?
    } else {
        name.to_owned()
    };
    // Context performs the reader's shared observation and file-version checks.
    let context = Context::open(plan, record, runs, root, owner, &name)?;
    let key = context.observation_key.clone();
    let receipts = match open_at(&context.journal_dir, RECEIPTS.as_bytes(), true) {
        Ok(directory) => {
            check_directory(
                &directory,
                context.loop_uid,
                Some((context.loop_uid, 0o755)),
                RECEIPTS,
            )?;
            let fd: OwnedFd = directory.into();
            let mut names = super::super::checkpoint::directory_names(&fd, Path::new(RECEIPTS))?;
            names.retain(|name| !name.starts_with(".tmp-"));
            names.sort();
            Some(names)
        }
        Err(error) if error.kind == "read-reply-absent" => None,
        Err(error) => return Err(error),
    };
    let mut value = context.execute(None, false)?;
    value["name"] = json!(name);
    value["observation_key"] = json!(key);
    value["receipt_directory"] = json!(receipts.is_some());
    value["receipts"] = json!(receipts.unwrap_or_default());
    Ok(value)
}

fn read(
    request: &Request,
    invoke: &mut Invoke<'_>,
    changed: &mut Option<bool>,
    already_receipted: bool,
) -> Result<(Vec<u8>, Vec<u8>), LaneError> {
    let mut body = Vec::new();
    let mut record = Vec::new();
    deliver(request, &mut body, &mut record, |expected| {
        let response = invoke(request, expected, false).inspect_err(|_| {
            if expected.is_some() && *changed != Some(true) {
                // A lost helper response cannot prove whether its rename happened.
                *changed = None;
            }
        })?;
        if expected.is_some() {
            note_change(changed, !already_receipted);
        }
        Ok(response)
    })?;
    Ok((body, record))
}

const fn note_change(changed: &mut Option<bool>, observed: bool) {
    if observed {
        *changed = Some(true);
    }
}

fn count(snapshot: &Value) -> usize {
    snapshot["receipts"].as_array().map_or(0, Vec::len)
}

fn has_receipt(snapshot: &Value) -> bool {
    let name = format!(
        "{}.json",
        snapshot["observation_key"].as_str().unwrap_or("invalid")
    );
    snapshot["receipts"]
        .as_array()
        .is_some_and(|names| names.contains(&json!(name)))
}

pub(super) fn measure_with(
    loop_name: &str,
    run: &str,
    invoke: &mut Invoke<'_>,
    replace: &mut dyn FnMut() -> Result<(), String>,
) -> Value {
    let mut claims = json!({});
    for name in [
        "dry_run",
        "repeat_read",
        "replacement",
        "staging_refusal",
        "missing_refusal",
    ] {
        claims[name] = claim("unmeasured", "prior step did not finish");
    }
    let mut request = Request {
        loop_name: loop_name.into(),
        run: run.into(),
        name: "-".into(),
        dry_run: true,
        range: None,
    };
    let mut changed = Some(false);
    let mut active_step = None;
    let outcome = sequence(
        &mut request,
        invoke,
        replace,
        &mut claims,
        &mut changed,
        &mut active_step,
    );
    if let (Err(error), Some(step)) = (&outcome, active_step) {
        claims[step] = claim("fail", error.line());
    }
    let verdict = if claims
        .as_object()
        .is_some_and(|claims| claims.values().any(|c| c["verdict"] == "fail"))
    {
        "fail"
    } else if outcome.is_err()
        || claims
            .as_object()
            .is_some_and(|claims| claims.values().any(|c| c["verdict"] != "pass"))
    {
        "unmeasured"
    } else {
        "pass"
    };
    json!({"schema":1,"command":"exercise","loop":loop_name,"run":run,"case":"reply-receipts",
        "name":request.name,"claims":claims,"verdict":verdict,"changed":changed,
        "reason":outcome.err().map(|error| error.line())})
}

fn sequence(
    request: &mut Request,
    invoke: &mut Invoke<'_>,
    replace: &mut dyn FnMut() -> Result<(), String>,
    claims: &mut Value,
    changed: &mut Option<bool>,
    active_step: &mut Option<&'static str>,
) -> Result<(), LaneError> {
    let before = invoke(request, None, true)?;
    *active_step = Some("dry_run");
    request.name = before["name"]
        .as_str()
        .ok_or_else(|| refusal("exercise-reply-receipts", "inspection omitted name"))?
        .into();
    let expected = unhex(before["body_hex"].as_str().unwrap_or("invalid"))?;
    let (preview, _) = read(request, invoke, changed, has_receipt(&before))?;
    let after = invoke(request, None, true)?;
    note_change(
        changed,
        before["receipts"] != after["receipts"]
            || before["receipt_directory"] != after["receipt_directory"],
    );
    claims["dry_run"] = if preview != expected
        || before["receipts"] != after["receipts"]
        || before["receipt_directory"] != after["receipt_directory"]
    {
        claim("fail", "dry run body or receipt state differs")
    } else if before["receipt_directory"] == true {
        claim(
            "unmeasured",
            "receipt directory already existed; absence cannot be demonstrated",
        )
    } else {
        claim(
            "pass",
            "full body returned; receipt directory remains absent",
        )
    };
    claims["dry_run"]["bytes"] = json!(preview.len());
    claims["dry_run"]["receipt_directory_before"] = before["receipt_directory"].clone();
    claims["dry_run"]["receipt_directory_after"] = after["receipt_directory"].clone();
    *active_step = Some("repeat_read");
    request.dry_run = false;
    let first = read(request, invoke, changed, has_receipt(&before))?;
    let second = read(request, invoke, changed, true)?;
    let after = invoke(request, None, true)?;
    note_change(changed, before["receipts"] != after["receipts"]);
    claims["repeat_read"] = if first != second || first.0 != expected || !has_receipt(&after) {
        claim(
            "fail",
            "changing reads differ in body or record, or matching receipt is absent",
        )
    } else if count(&before) > 0 {
        claim(
            "unmeasured",
            "pre-existing receipts prevent the exactly-one-receipt baseline",
        )
    } else if count(&after) != 1 {
        claim("fail", "changing reads did not leave exactly one receipt")
    } else {
        claim(
            "pass",
            "two identical bodies and records; exactly one matching receipt",
        )
    };
    claims["repeat_read"]["record"] = json!(String::from_utf8_lossy(&first.1));
    claims["repeat_read"]["receipts_before"] = before["receipts"].clone();
    claims["repeat_read"]["receipts_after"] = after["receipts"].clone();
    *active_step = Some("replacement");
    if let Err(reason) = replace() {
        claims["replacement"] = claim("unmeasured", reason);
    } else {
        *changed = Some(true);
        let replacement = invoke(request, None, true)?;
        let delivered = read(request, invoke, changed, has_receipt(&replacement))?;
        let final_state = invoke(request, None, true)?;
        let expected = unhex(replacement["body_hex"].as_str().unwrap_or("invalid"))?;
        claims["replacement"] = if replacement["identity"] != after["identity"]
            && replacement["observation_key"] != after["observation_key"]
            && delivered.0 == expected
            && has_receipt(&final_state)
            && count(&final_state) == count(&after) + 1
            && count(&final_state) == 2
        {
            claim(
                "pass",
                "renamed replacement has a new identity and a second receipt",
            )
        } else {
            claim(
                "fail",
                "replacement identity, body or receipt count differs",
            )
        };
    }
    refusal_claims(request, invoke, claims, &after, changed, active_step)
}

fn refusal_claims(
    request: &Request,
    invoke: &mut Invoke<'_>,
    claims: &mut Value,
    observed: &Value,
    changed: &mut Option<bool>,
    active_step: &mut Option<&'static str>,
) -> Result<(), LaneError> {
    for (step, name, kind) in [
        (
            "staging_refusal",
            ".tmp-exercise-reply".to_owned(),
            "read-reply-name",
        ),
        (
            "missing_refusal",
            format!(
                "exercise-missing-{}.md",
                observed["observation_key"].as_str().unwrap_or("invalid")
            ),
            "read-reply-absent",
        ),
    ] {
        *active_step = Some(step);
        let before = invoke(request, None, true)?;
        let parsed =
            Request::parse(&[request.loop_name.clone(), request.run.clone(), name.clone()]);
        let prior_changed = *changed;
        let result = parsed.and_then(|candidate| read(&candidate, invoke, changed, false));
        let after = invoke(request, None, true)?;
        // This inspection settles whether even a failed receipt call changed custody.
        *changed = prior_changed;
        note_change(
            changed,
            before["receipts"] != after["receipts"]
                || before["receipt_directory"] != after["receipt_directory"],
        );
        claims[step] = match result {
            Err(error)
                if error.line().contains(kind) && before["receipts"] == after["receipts"] =>
            {
                let mut value = claim("pass", error.line());
                value["name"] = json!(name);
                value
            }
            _ => claim("fail", format!("expected {kind} with no added receipt")),
        };
    }
    Ok(())
}
