//! Authenticated direct entry; command execution remains with its caller.

mod agent;
mod judgement;
mod policy;
mod store;

#[cfg(test)]
mod protocol_tests;

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use execute_command::escalation::{Answer, ReferralTarget, ReviewAnswer, validate_answer};
use execute_command::record::{
    Claim, Completion, ConditionalCommit, Intent, Load, OutcomeRecord, Persistence,
    PersistenceResult, Refusal, Snapshot, Transition, UncertainCommit,
};
use execute_command::request::{
    Binding, HygieneObservation, Judgement, Request, Rung, Text, VerdictStatus,
};
use execute_command::triage::{Scope, referral};
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use store::Store;

#[derive(Debug)]
struct Error {
    rule: String,
    detail: String,
}

impl Error {
    fn named(rule: &str, detail: &str) -> Self {
        Self {
            rule: rule.into(),
            detail: detail.into(),
        }
    }
    fn shape() -> Self {
        Self::named(
            "execute-command-request-shape",
            "use the schema-one command envelope",
        )
    }
    fn record() -> Self {
        Self::named(
            "execute-command-record-shape",
            "command-requests.jsonl requires its current schema-one snapshot; no predecessor reader exists",
        )
    }
    fn storage(error: impl std::fmt::Display) -> Self {
        Self::named("execute-command-persistence-storage", &error.to_string())
    }
}

fn text(value: &str) -> Result<Text, Error> {
    value.to_owned().try_into().map_err(|_| Error::shape())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    schema: u32,
    loop_name: String,
    root: PathBuf,
    device: u64,
    inode: u64,
    principal: String,
    registration: String,
    snapshot_digest: String,
    role: String,
    cwd: String,
    scope: Option<String>,
}

pub fn dispatch(args: &[OsString]) -> Option<u8> {
    if args.first().is_none_or(|arg| arg != "command") {
        return None;
    }
    Some(match run(&args[1..]) {
        Ok(value) => u8::from(writeln!(std::io::stdout().lock(), "{value}").is_err()),
        Err(error) => {
            let _written = writeln!(
                std::io::stderr().lock(),
                "{}",
                json!({"schema":1,"rule":error.rule,"detail":error.detail})
            );
            2
        }
    })
}

fn exact(value: &Value, fields: &[&str]) -> Result<(), Error> {
    if value["schema"] == 1
        && value.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
        })
    {
        Ok(())
    } else {
        Err(Error::shape())
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, Error> {
    serde_json::from_value(value.clone()).map_err(|_| Error::shape())
}

fn digest(value: &impl Serialize) -> Result<String, Error> {
    let value = serde_json::to_value(value).map_err(|_| Error::shape())?;
    Ok(request_core::request_id(
        &serde_json::to_vec(&value).map_err(|_| Error::shape())?,
    ))
}

fn binding_valid(request: &Request) -> bool {
    let Ok(mut source) = serde_json::to_value(request) else {
        return false;
    };
    let Some(object) = source.as_object_mut() else {
        return false;
    };
    object.remove("binding");
    digest(&source).is_ok_and(|digest| digest == request.binding().request_id.as_str())
        && digest(request.context())
            .is_ok_and(|digest| digest == request.binding().context_digest.as_str())
}

fn durable<T>(result: PersistenceResult<T>) -> Result<T, Error> {
    match result {
        PersistenceResult::Durable(value) => Ok(value),
        PersistenceResult::Refused(refusal) => Err(Error::named(
            refusal.name(),
            "operation refused without a new execution grant",
        )),
        PersistenceResult::CommitUncertain(uncertain) => Err(Error::named(
            "execute-command-read-before-retry",
            &format!(
                "read status with resolve={} before retry; a resolved claim never grants another effect",
                uncertain.operation_id.as_str()
            ),
        )),
    }
}

fn response(snapshot: &Snapshot, review: Option<&Text>, fresh_claim: bool) -> Value {
    json!({"schema":1,"verdict":snapshot.verdict,"revision":snapshot.revision.0,"review":review,
        "claim":snapshot.claim.as_ref().map(|claim| json!({"operation_id":claim.operation_id,"claimant":claim.claimant,"revision":claim.revision.0})),
        "fresh_claim":fresh_claim,"outcome":snapshot.outcome})
}

fn status(loaded: execute_command::record::Loaded, review: Option<&Text>) -> Result<Value, Error> {
    let mut value = if let Some(snapshot) = &loaded.snapshot {
        response(snapshot, review, false)
    } else if loaded.resolution.is_some() {
        json!({"schema":1,"verdict":null,"revision":null,"review":null,"claim":null,"fresh_claim":false,"outcome":null})
    } else {
        return Err(Error::named(
            Refusal::Conflict.name(),
            "command request is absent",
        ));
    };
    value["resolution"] = loaded.resolution.map_or(Value::Null, |(operation, resolution)| json!({"operation_id":operation.operation_id,"committed":resolution == execute_command::record::Resolution::Committed}));
    Ok(value)
}

fn run(args: &[OsString]) -> Result<Value, Error> {
    let [action, loop_name] = args else {
        return Err(Error::shape());
    };
    let action = action.to_str().ok_or_else(Error::shape)?;
    let loop_name = loop_name.to_str().ok_or_else(Error::shape)?;
    let input = read_input(action)?;
    let request = if action == "judge" {
        let request =
            Request::from_json(&serde_json::to_vec(&input["request"]).map_err(|_| Error::shape())?)
                .map_err(|_| Error::shape())?;
        if !binding_valid(&request) {
            return Err(Error::shape());
        }
        Some(request)
    } else {
        None
    };
    let (authority, policy, directory) = policy::read(loop_name)?;
    execute(action, &input, request, &authority, &policy, &directory)
}

fn execute(
    action: &str,
    input: &Value,
    request: Option<Request>,
    authority: &Authority,
    policy: &execute_command::snapshot::PolicySnapshot,
    directory: &File,
) -> Result<Value, Error> {
    if action == "status" && input["binding"].is_null() {
        if !input["resolve"].is_null() {
            return Err(Error::shape());
        }
        return Ok(json!({"schema":1,"verdict":null,"context":authority}));
    }
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(Error::storage)?
            .as_nanos(),
    )
    .map_err(Error::storage)?;
    let mut store = Store::open(directory, authority, now)?;
    let binding = match action {
        "judge" => request.as_ref().ok_or_else(Error::shape)?.binding().clone(),
        "answer" => decode::<Answer>(&input["answer"])?.binding,
        _ => decode::<Binding>(&input["binding"])?,
    };
    let load = if action == "status" && !input["resolve"].is_null() {
        Load::Resolve(UncertainCommit {
            binding: binding.clone(),
            operation_id: decode(&input["resolve"])?,
            expected: None,
        })
    } else {
        Load::Current(binding.clone())
    };
    let loaded = durable(store.load(load))?;
    if matches!(action, "answer" | "claim") {
        store.require_current_policy(&binding)?;
    }
    if action == "status" {
        return status(loaded, store.review(&binding).as_ref());
    }
    if action == "judge" {
        let request = request.ok_or_else(Error::shape)?;
        if let Some(snapshot) = loaded.snapshot {
            if store.request(&binding)? != &input["request"] {
                return Err(Error::named(
                    Refusal::Conflict.name(),
                    "request identity is occupied",
                ));
            }
            return Ok(response(&snapshot, store.review(&binding).as_ref(), false));
        }
        judge(&mut store, authority, policy, &request, &input["request"])?;
    } else {
        let snapshot = loaded
            .snapshot
            .ok_or_else(|| Error::named(Refusal::Conflict.name(), "command request is absent"))?;
        match action {
            "answer" => answer(&mut store, authority, &snapshot, &decode(&input["answer"])?)?,
            "claim" => claim(&mut store, authority, snapshot, now / 1_000_000)?,
            "complete" => complete(&mut store, snapshot, &binding, &input["outcome"])?,
            _ => return Err(Error::shape()),
        }
    }
    let snapshot = durable(store.load(Load::Current(binding.clone())))?
        .snapshot
        .ok_or_else(Error::record)?;
    Ok(response(
        &snapshot,
        store.review(&binding).as_ref(),
        action == "claim",
    ))
}

fn answer(
    store: &mut Store<'_>,
    authority: &Authority,
    snapshot: &Snapshot,
    answer: &Answer,
) -> Result<(), Error> {
    if authority.role != "orchestrator" || answer.adjudicator.as_str() != authority.principal {
        return Err(Error::named(
            Refusal::Authority.name(),
            "only the authenticated loop main session may answer",
        ));
    }
    if snapshot.verdict.judgement != Judgement::Refer {
        return Err(Error::named(
            Refusal::InvalidTransition.name(),
            "this judgement already has a terminal answer",
        ));
    }
    let escalation = snapshot
        .verdict
        .escalation
        .as_ref()
        .filter(|escalation| escalation.target == ReferralTarget::LoopReview)
        .ok_or_else(|| {
            Error::named(
                "execute-command-route-unprovisioned",
                "this request has no provisioned loop-review route",
            )
        })?;
    let review = store.review(&answer.binding);
    validate_answer(escalation, answer, review.as_ref()).map_err(|_| {
        Error::named(
            "execute-command-escalation-shape",
            "answer binding or current review differs",
        )
    })?;
    let mut verdict = snapshot.verdict.clone();
    verdict.judgement = if answer.answer == ReviewAnswer::Approve {
        Judgement::Allow
    } else {
        Judgement::Refuse
    };
    verdict.tier = Rung::LoopReview;
    verdict.reason = answer.reason.clone();
    if verdict.judgement == Judgement::Allow {
        verdict.correction = None;
        verdict.escalation = None;
    }
    store.prepare_answer(answer.clone());
    durable(
        store.commit(
            ConditionalCommit::new(
                text(&format!("answer:{}", answer.binding.request_id.as_str()))?,
                Some(snapshot.revision),
                verdict,
            )
            .map_err(|_| Error::shape())?,
        ),
    )?;
    Ok(())
}

fn claim(
    store: &mut Store<'_>,
    authority: &Authority,
    mut snapshot: Snapshot,
    now_ms: u64,
) -> Result<(), Error> {
    if snapshot.claim.is_some() {
        return Err(Error::named(
            Refusal::ClaimUsed.name(),
            "the recorded claim grants no second effect",
        ));
    }
    let request = Request::from_json(
        &serde_json::to_vec(store.request(&snapshot.verdict.binding)?)
            .map_err(|_| Error::record())?,
    )
    .map_err(|_| Error::record())?;
    if request.context().deadline_unix_ms <= now_ms {
        return Err(Error::named(
            Refusal::InvalidTransition.name(),
            "the command attention deadline has elapsed",
        ));
    }
    let binding = snapshot.verdict.binding.clone();
    let intent_id = text(&format!("intent:{}", binding.request_id.as_str()))?;
    if snapshot.intent.is_none() {
        let revision = durable(store.intent(Intent {
            transition: Transition {
                binding: binding.clone(),
                operation_id: intent_id.clone(),
                expected: snapshot.revision,
            },
            effect_digest: binding.request_id.clone(),
        }))?;
        snapshot.revision = revision;
    }
    durable(store.claim(Claim {
        transition: Transition {
            binding: binding.clone(),
            operation_id: text(&format!("claim:{}", binding.request_id.as_str()))?,
            expected: snapshot.revision,
        },
        intent_operation_id: intent_id,
        claimant: text(&authority.principal)?,
    }))?;
    Ok(())
}

fn read_input(action: &str) -> Result<Value, Error> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take((execute_command::request::MAX_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(Error::storage)?;
    if input.len() > execute_command::request::MAX_ENVELOPE_BYTES {
        return Err(Error::shape());
    }
    let input: Value = serde_json::from_slice(&input).map_err(|_| Error::shape())?;
    validate_input(action, &input)?;
    Ok(input)
}

fn validate_input(action: &str, input: &Value) -> Result<(), Error> {
    let fields: &[&str] = match action {
        "judge" => &["schema", "request"],
        "answer" => &["schema", "answer"],
        "claim" => &["schema", "binding"],
        "complete" => &["schema", "binding", "outcome"],
        "status" => &["schema", "binding", "resolve"],
        _ => return Err(Error::shape()),
    };
    exact(input, fields)
}

fn judge(
    store: &mut Store<'_>,
    authority: &Authority,
    policy: &execute_command::snapshot::PolicySnapshot,
    request: &Request,
    source: &Value,
) -> Result<(), Error> {
    let binding = request.binding();
    if request.context().requester.as_str() != authority.principal
        || request.context().registration.as_str() != authority.registration
        || request.context().loop_id.as_str() != authority.loop_name
        || request.context().cwd.as_str() != authority.cwd
    {
        return Err(Error::named(
            Refusal::Authority.name(),
            "request context differs from authenticated identity or current directory",
        ));
    }
    let verdict = judgement::judge(policy, request)?;
    store.prepare_source(source.clone());
    durable(
        store.commit(
            ConditionalCommit::new(
                text(&format!("judge:{}", binding.request_id.as_str()))?,
                None,
                verdict,
            )
            .map_err(|_| Error::shape())?,
        ),
    )?;
    Ok(())
}

fn complete(
    store: &mut Store<'_>,
    snapshot: Snapshot,
    binding: &Binding,
    input: &Value,
) -> Result<(), Error> {
    let receipt = snapshot.claim.ok_or_else(|| {
        Error::named(
            Refusal::InvalidTransition.name(),
            "completion requires a durable claim",
        )
    })?;
    let outcome: OutcomeRecord = decode(input)?;
    let transition = Transition {
        binding: binding.clone(),
        operation_id: text(&format!("complete:{}", binding.request_id.as_str()))?,
        expected: receipt.revision,
    };
    durable(
        store.complete(Completion::new(transition, receipt, outcome).map_err(|_| Error::record())?),
    )?;
    Ok(())
}
