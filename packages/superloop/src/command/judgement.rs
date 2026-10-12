//! Apply trusted snapshot observations to the common command rules.

use super::*;
use execute_command::policy::DoorMode;
use execute_command::request::{Command, LearnedGroup, MatchEvaluation, MatchKey, Verdict};
use execute_command::snapshot::PolicySnapshot;

pub(super) fn key(request: &Request) -> Result<MatchKey, Error> {
    if let Command::Argv { argv } = request.command()
        && execute_command::checks::compute::validate_words(argv).is_ok()
    {
        return Ok(MatchKey {
            class: text("compute")?,
            operation: text("compute")?,
            shape_key: text(&execute_command::checks::compute::shape(argv))?,
        });
    }
    Ok(MatchKey {
        class: text("command")?,
        operation: text("execute")?,
        shape_key: text(&digest(request.command())?)?,
    })
}

fn mode(policy: &PolicySnapshot, class: &str) -> Result<DoorMode, Error> {
    let parse = |value: Option<&str>| {
        DoorMode::from_record(value)
            .map_err(|error| Error::named(error.0, "republish the owner's mode settings"))
    };
    let floor = parse(policy.registry.value["floor"].as_str())?;
    let ledger = &policy.modes.value["ledger"];
    let current = |settings: &Value| -> Result<DoorMode, Error> {
        match settings.as_array().and_then(|settings| settings.last()) {
            Some(setting) => parse(setting["mode"].as_str()),
            None => execute_command::policy::initial_setting(None, floor)
                .map_err(|error| {
                    Error::named(error.0, "derive absent settings from the registered floor")
                })?
                .map(|setting| setting.mode)
                .ok_or_else(Error::shape),
        }
    };
    let classes = ledger["classes"].as_array().ok_or_else(Error::shape)?;
    let class_settings = classes
        .iter()
        .find(|row| row["class"] == class)
        .map_or(&Value::Null, |row| &row["settings"]);
    Ok(execute_command::policy::effective_mode(
        current(class_settings)?,
        current(&ledger["loop_settings"])?,
        floor,
        policy.modes.value["effective"][class]["correction_pending"] == true,
    ))
}

pub(super) fn judge(policy: &PolicySnapshot, request: &Request) -> Result<Verdict, Error> {
    let key = key(request)?;
    let selected = mode(policy, key.class.as_str())?;
    let hygiene = execute_command::checks::hygiene(
        request,
        &HygieneObservation::Shell {
            timeout_ms: None,
            declared_background: None,
        },
        "estate",
    )
    .map_err(|_| Error::shape())?;
    if let Some(verdict) = hygiene {
        return Ok(verdict);
    }
    let key_text = json!([
        key.class.as_str(),
        key.operation.as_str(),
        key.shape_key.as_str()
    ])
    .to_string();
    let group = &policy.learned.value["groups"][&key_text];
    let learned = if group.is_null() {
        None
    } else {
        Some(LearnedGroup {
            key: key.clone(),
            allow: group["allow"].as_u64().ok_or_else(Error::shape)?,
            refuse: group["refuse"].as_u64().ok_or_else(Error::shape)?,
            citations: serde_json::from_value(group["citations"].clone())
                .map_err(|_| Error::shape())?,
        })
    };
    let mut verdict = {
        match execute_command::checks::learned_exact_match(request, &key, learned.as_ref())
            .map_err(|_| Error::shape())?
        {
            MatchEvaluation::Decided(verdict) => *verdict,
            MatchEvaluation::Undecided { .. } => {
                super::agent::judge(policy, request, key.class.as_str(), &group["history"])?
            }
        }
    };
    let would_do = serde_json::to_value(verdict.judgement).map_err(|_| Error::shape())?;
    let mut evidence: Vec<Text> = serde_json::from_value(
        serde_json::to_value(&verdict.evidence).map_err(|_| Error::shape())?,
    )
    .map_err(|_| Error::shape())?;
    evidence.push(text(&format!(
        "mode:{};would_do:{would_do}",
        selected.as_str()
    ))?);
    if selected == DoorMode::Audit && verdict.judgement != Judgement::Refer {
        let tier = verdict.tier;
        let correction = verdict.correction.take();
        verdict = referral(
            request.binding(),
            Scope::Loop,
            verdict.status,
            verdict.reason,
        );
        verdict.tier = tier;
        verdict.correction = correction;
        if let Some(escalation) = &mut verdict.escalation {
            escalation.requires_current_review = true;
        }
    } else if selected == DoorMode::Allow && verdict.scope.as_str() == "loop" {
        verdict.judgement = Judgement::Allow;
        verdict.correction = None;
        verdict.escalation = None;
    }
    verdict.evidence = evidence.try_into().map_err(|_| Error::shape())?;
    verdict.validate().map_err(|_| Error::shape())?;
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use execute_command::snapshot::Source;

    fn request(command: &str) -> Request {
        Request::from_json(&serde_json::to_vec(&json!({
            "schema":1,
            "binding":{"request_id":"fixture-request","context_digest":"fixture-context"},
            "command":{"representation":"bytes","bytes":command.as_bytes()},
            "context":{"cwd":"/fixture","requester":"fixture","loop_id":"fixture","lane":null,"run":null,"purpose":"policy fixture","deadline_unix_ms":4_102_444_800_000_u64,"snapshot":"fixture","registration":"fixture","resources":[],"authority":"caller-loop","checks":[],"rubric":"caller cannot select this","mode":"allow","floor":"allow","policy":"caller cannot select this"},
            "implications":{"effects":[],"resources":[],"principals":[],"reversibility":"unknown","scope_uncertainty":"unresolved","evidence":[]}
        })).expect("fixture JSON")).expect("request shape")
    }

    fn source(value: Value) -> Source {
        Source::new("fixture-revision".into(), value).expect("source evidence")
    }

    fn policy(floor: &str, request: &Request, learned: bool) -> PolicySnapshot {
        let key = key(request).expect("key");
        let index = json!([key.class, key.operation, key.shape_key]).to_string();
        PolicySnapshot {
            schema: 1,
            loop_name: "fixture".into(),
            loop_uid: 41001,
            written_at: "1".into(),
            door: true,
            registry: source(json!({"floor":floor})),
            modes: source(json!({"ledger":{"loop_settings":[],"classes":[]},"effective":{}})),
            learned: source(if learned {
                json!({"groups":{index:{"allow":1,"refuse":0,"citations":["reviewed-fixture"]}}})
            } else {
                json!({"groups":{}})
            }),
            rubric: source(json!({"agent":null})),
        }
    }

    /// ´claim:command:direct-policy-observations-override-request-text-and-preserve-pending-audit´
    /// ´test:unit:direct-policy-observations-override-request-text-and-preserve-pending-audit´
    #[test]
    fn direct_policy_observations_override_request_text_and_preserve_pending_audit() {
        let request = request("printf fixture");
        let mut policy = policy("audit", &request, true);
        let verdict = judge(&policy, &request).expect("audit judgement");
        assert_eq!(verdict.judgement, Judgement::Refer);
        assert_eq!(
            verdict.escalation.expect("review").target,
            ReferralTarget::LoopReview
        );
        policy.registry = source(json!({"floor":"enforce"}));
        assert_eq!(
            judge(&policy, &request)
                .expect("enforce judgement")
                .judgement,
            Judgement::Allow
        );
        policy.modes = source(
            json!({"ledger":{"loop_settings":[],"classes":[]},"effective":{"command":{"correction_pending":true}}}),
        );
        assert_eq!(
            judge(&policy, &request).expect("pending audit").judgement,
            Judgement::Refer
        );
    }

    /// ´claim:command:direct-allow-mode-cannot-grant-estate-agent-failure-or-hygiene-refusal´
    /// ´test:unit:direct-allow-mode-cannot-grant-estate-agent-failure-or-hygiene-refusal´
    #[test]
    fn direct_allow_mode_cannot_grant_estate_agent_failure_or_hygiene_refusal() {
        let miss = request("printf fixture");
        let policy = policy("allow", &miss, false);
        let verdict = judge(&policy, &miss).expect("unconfigured profile");
        assert_eq!(verdict.judgement, Judgement::Refer);
        assert_eq!(verdict.scope.as_str(), "estate");
        assert_eq!(verdict.status, VerdictStatus::AgentFailure);
        let unsafe_request = request("rm -rf \"$TARGET\"");
        let verdict = judge(&policy, &unsafe_request).expect("hygiene refusal");
        assert_eq!(verdict.judgement, Judgement::Refuse);
        assert!(verdict.correction.is_some());
    }
}
